use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tls_parser::parse_tls_plaintext;

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
    upstream_socket.write_all(&fragment_header).await?;
    upstream_socket.write_all(&xdr_payload).await?;

    // Now read the reply from upstream and forward to client.
    let mut reply_header = [0u8; 4];
    upstream_socket.read_exact(&mut reply_header).await
        .context("Failed to read RPC reply header from upstream")?;
    
    let reply_val = u32::from_be_bytes(reply_header);
    let reply_len = (reply_val & 0x7FFFFFFF) as usize;
    
    // Forward reply to client (header)
    client_socket.write_all(&reply_header).await?;

    // We can't use splice yet because the *next* thing on the wire is ClientHello.
    // We have to forward the rest of the RPC reply though.
    // Let's just read/write it. It's small.
    // Wait, the client expects the reply body BEFORE it sends ClientHello.
    
    if reply_len > 0 {
        let mut reply_payload = vec![0u8; reply_len];
        upstream_socket.read_exact(&mut reply_payload).await
            .context("Failed to read RPC reply body")?;
        client_socket.write_all(&reply_payload).await?;
    }
    
    log::debug!("Phase 1: Forwarded STARTTLS Reply to client. Entering Handshake Loop.");

    // =======================================================================
    // Phase 2: Validating TLS Handshake Bidirectionally
    // =======================================================================

    // We need to continuously read records from both sides until we see Application Data.
    let mut client_buf = Vec::with_capacity(4096);
    let mut upstream_buf = Vec::with_capacity(4096);
    loop {
        let mut client_temp_buf = [0u8; 4096];
        let mut upstream_temp_buf = [0u8; 4096];

        tokio::select! {
            res = client_socket.read(&mut client_temp_buf) => {
                let n = res.context("Client read failed")?;
                if n == 0 {
                    bail!("Client closed connection during handshake");
                }
                client_buf.extend_from_slice(&client_temp_buf[..n]);
                
                // Process client buffer
                let (consumed, hit_app_data) = process_tls_buffer(&client_buf, "Client")?;
                
                // Forward consumed bytes to upstream
                if consumed > 0 {
                    upstream_socket.write_all(&client_buf[..consumed]).await?;
                    let remaining = client_buf.split_off(consumed);
                    client_buf = remaining;
                }
                
                if hit_app_data {
                    log::info!("Client sent Application Data. Still waiting for Upstream to confirm established session...");
                    // We don't break here! We continue validating headers for both sides.
                }
            }
            res = upstream_socket.read(&mut upstream_temp_buf) => {
                let n = res.context("Upstream read failed")?;
                if n == 0 {
                     bail!("Upstream closed connection during handshake");
                }
                upstream_buf.extend_from_slice(&upstream_temp_buf[..n]);
                
                let (consumed, hit_app_data) = process_tls_buffer(&upstream_buf, "Upstream")?;
                
                if consumed > 0 {
                    client_socket.write_all(&upstream_buf[..consumed]).await?;
                    let remaining = upstream_buf.split_off(consumed);
                    upstream_buf = remaining;
                }
                
                if hit_app_data {
                    log::info!("Upstream sent Application Data. Handshake considered established by server.");
                    break;
                }
            }
        }
    }

    // Flush any remaining buffered data that we might have read but not processed?
    // loop above ensures we consume FULL records. 
    // What if there is a partial record in client_buf?
    // We need to forward it before splicing.
    // Splice takes the FD. If we have bytes in user-space `client_buf`, we must write them to `upstream_socket`.
    if !client_buf.is_empty() {
        upstream_socket.write_all(&client_buf).await?;
    }
    if !upstream_buf.is_empty() {
        client_socket.write_all(&upstream_buf).await?;
    }

    // =======================================================================
    // Phase 3: Splicing
    // =======================================================================
    
    log::info!("Phase 3: Splicing connection");

    // Use tokio_splice2::copy_bidirectional for efficiency
    tokio_splice2::copy_bidirectional(
        &mut client_socket, 
        &mut upstream_socket
    ).await?;

    Ok(())
}

/// Parses TLS records from the buffer.
/// Returns (bytes_consumed, found_app_data).
/// Validates that records are Handshake, Alert, CCS, or AppData.
fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, bool)> {
    let mut offset = 0;
    let mut found_app_data = false;

    loop {
        // Check if we have enough for a header
        if buf.len() - offset < 5 {
            break; // Need more data
        }

        let header = &buf[offset..offset+5];
        let content_type = header[0];
        let version_major = header[1];
        let _version_minor = header[2];
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Sanity check header
        // ContentType: 20=CCS, 21=Alert, 22=Handshake, 23=AppData
        if ![20, 21, 22, 23].contains(&content_type) {
             bail!("{} sent invalid TLS ContentType: {}", source, content_type);
        }
        
        // Check version (roughly 3.x)
        if version_major != 3 {
             // TLS 1.0=3.1, 1.1=3.2, 1.2=3.3, 1.3 uses 3.3 for legacy record version usually
            // bail!("{} sent invalid TLS Version: {}.{}", source, version_major, version_minor);
        }

        if len > 16384 + 2048 {
            bail!("{} sent over-sized TLS record: {}", source, len);
        }

        // Do we have the full record?
        let total_record_len = 5 + len;
        if buf.len() - offset < total_record_len {
            break; // Need more data
        }

        // We have a full record.
        log::debug!("Parsed {} record: Type={}, Len={}", source, content_type, len);

        if content_type == 23 {
            found_app_data = true; // Signal to switch to splicing
        } else if content_type == 22 {
            // It is a handshake message.
            // If it is NOT encrypted, we could validate it.
            // But tracking encryption state is hard.
            // basic check: parse_tls_plaintext might fail if it's encrypted data.
            // We just ignore the error if it fails to parse (assumed encrypted).
            // BUT, if it DOES parse, we should check it.
            match parse_tls_plaintext(&buf[offset..offset+total_record_len]) {
                Ok((_, _plaintext)) => {
                    // It was a valid plaintext handshake
                },
                Err(_) => {
                    // Likely encrypted handshake (Finished, etc)
                }
            }
        }

        offset += total_record_len;
        
        // If we found app data, we typically want to stop parsing *immediately* after this record?
        // Or keep going? 
        // Logic says: return immediately so we can forward this and maybe break loop.
        if found_app_data {
            return Ok((offset, true));
        }
    }

    Ok((offset, false))
}
