use anyhow::{bail, Context, Result};
use clap::Parser;
// use std::net::SocketAddr;
// use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tls_parser::{parse_tls_plaintext, TlsMessage};

mod xdr;
#[cfg(test)]
mod tests;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on (e.g. 0.0.0.0:2049)
    #[arg(long, default_value = "0.0.0.0:2049")]
    listen: String,

    /// Upstream kernel nfsd address (e.g. 127.0.0.1:20000)
    #[arg(long, default_value = "127.0.0.1:20000")]
    upstream: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let listener = TcpListener::bind(&args.listen).await
        .context(format!("Failed to bind to {}", args.listen))?;

    log::info!("NFS-over-TLS Proxy listening on {}", args.listen);
    log::info!("Proxying to upstream {}", args.upstream);

    let upstream_addr = args.upstream.clone();

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        log::debug!("Accepted connection from {}", client_addr);

        let upstream_target = upstream_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_socket, upstream_target).await {
                log::error!("Connection error from {}: {}", client_addr, e);
            }
        });
    }
}

async fn handle_connection(mut client_socket: TcpStream, upstream_addr: String) -> Result<()> {
    // 1. Connect to upstream
    let mut upstream_socket = TcpStream::connect(&upstream_addr).await
        .context("Failed to connect to upstream nfsd")?;

    // Enable TCP_NODELAY for latency
    client_socket.set_nodelay(true)?;
    upstream_socket.set_nodelay(true)?;

    // =======================================================================
    // Phase 1: Validating STARTTLS XDR Request
    // =======================================================================
    
    // Read RPC Fragment Header (4 bytes)
    let mut fragment_header = [0u8; 4];
    client_socket.read_exact(&mut fragment_header).await
        .context("Failed to read RPC fragment header")?;

    // RPC over TCP: 
    // Bit 0: Last Fragment Flag (0x80000000)
    // Bits 1-31: Fragment Length
    let header_val = u32::from_be_bytes(fragment_header);
    let len = (header_val & 0x7FFFFFFF) as usize;

    if len > 1024 {
        bail!("RPC Fragment length too large for STARTTLS sanity check: {}", len);
    }

    let mut xdr_payload = vec![0u8; len];
    client_socket.read_exact(&mut xdr_payload).await
        .context("Failed to read RPC body")?;

    // Check if it's a valid STARTTLS
    xdr::validate_starttls_header(&xdr_payload)
        .context("XDR Validation Failed")?;

    log::debug!("Phase 1: Valid XDR STARTTLS command detected");

    // Forward logic to upstream
    // We must send the *original* header and payload.
    upstream_socket.write_all(&fragment_header).await?;
    upstream_socket.write_all(&xdr_payload).await?;

    // Now read the reply from upstream and forward to client.
    // We expect an RPC Reply. For simplicity, we just shuttle the *next* PDU back.
    // We have to parse the length to know how much to read/write properly if we want to stay synchronized, 
    // OR we can just do a single read-write if we assume strict lock-step (which STARTTLS is).
    
    let mut reply_header = [0u8; 4];
    upstream_socket.read_exact(&mut reply_header).await
        .context("Failed to read RPC reply header from upstream")?;
    
    let reply_val = u32::from_be_bytes(reply_header);
    let reply_len = (reply_val & 0x7FFFFFFF) as usize;
    
    if reply_len > 65536 {
         bail!("RPC Reply fragment length suspiciously large: {}", reply_len);
    }
    
    let mut reply_payload = vec![0u8; reply_len];
    upstream_socket.read_exact(&mut reply_payload).await
        .context("Failed to read RPC reply body")?;

    // Forward reply to client
    client_socket.write_all(&reply_header).await?;
    client_socket.write_all(&reply_payload).await?;

    log::debug!("Phase 1: Forwarded STARTTLS Reply to client");

    // =======================================================================
    // Phase 2: Validating TLS Handshake
    // =======================================================================

    // Client should now send ClientHello.
    // Read the TLS record header (5 bytes).
    // ContentType(1) + Version(2) + Length(2)
    let mut tls_header = [0u8; 5];
    client_socket.read_exact(&mut tls_header).await
        .context("Failed to read TLS record header")?;

    let content_type = tls_header[0];
    // Handshake is 22 (0x16)
    if content_type != 0x16 {
        bail!("Expected TLS Handshake (0x16), got 0x{:02X}", content_type);
    }

    let tls_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;
    if tls_len > 16384 {
        bail!("TLS record length too large: {}", tls_len);
    }

    let mut tls_payload = vec![0u8; tls_len];
    client_socket.read_exact(&mut tls_payload).await
        .context("Failed to read TLS payload")?;

    // Combine header and payload for the parser
    let mut full_tls_record = Vec::with_capacity(5 + tls_len);
    full_tls_record.extend_from_slice(&tls_header);
    full_tls_record.extend_from_slice(&tls_payload);

    match parse_tls_plaintext(&full_tls_record) {
        Ok((rem, plaintext)) => {
            if !rem.is_empty() {
                // This implies we read more than one record, or sizing was off. 
                // But we read exactly `tls_len` + 5.
                // It should be consumed entirely if it is a single valid record.
                log::warn!("TLS Parser had remaining bytes, potentially check logic");
            }
            // Verify it is a handshake
            let is_handshake = plaintext.msg.iter().any(|m| matches!(m, TlsMessage::Handshake(_)));
            if !is_handshake {
                 bail!("Inner TLS message was not a Handshake");
            }
        },
        Err(e) => {
             bail!("TLS parsing failed: {:?}", e);
        }
    }

    log::debug!("Phase 2: Valid TLS ClientHello detected");

    // Forward TLS ClientHello to upstream
    upstream_socket.write_all(&full_tls_record).await?;

    // =======================================================================
    // Phase 3: Splicing
    // =======================================================================
    
    log::info!("Phase 3: Splicing connection");

    // We can't reuse the previous buffers/socket handle easily if we just `io::copy`.
    // But `tokio-splice` (zero_copy_bidirectional) takes the TcpStreams.
    
    // Note: tokio-splice might need the raw fd. 
    // And standard `tokio::io::copy_bidirectional` is safer if `splice` isn't strictly required, 
    // but the user REQUESTED `tokio-splice`.
    
    // `tokio_splice2::copy_bidirectional` works on the streams directly.
    tokio_splice2::copy_bidirectional(
        &mut client_socket, 
        &mut upstream_socket
    ).await?;

    Ok(())
}
