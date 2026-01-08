use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tls_parser::{parse_tls_plaintext, parse_tls_record_header, TlsRecordType};
use bytes::BytesMut;
use std::time::Duration;
use tokio::time::timeout;

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
        tokio::select! {
            res = listener.accept() => {
                let (client_socket, client_addr) = res?;
                log::debug!("Accepted connection from {}", client_addr);

                let upstream_target = upstream_addr.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(client_socket, upstream_target).await {
                        log::error!("Connection error from {}: {}", client_addr, e);
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Shutting down proxy...");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_connection(mut client_socket: TcpStream, upstream_addr: String) -> Result<()> {
    // 1. Connect to upstream with timeout
    let mut upstream_socket = timeout(Duration::from_secs(5), TcpStream::connect(&upstream_addr))
        .await
        .map_err(|_| anyhow::anyhow!("Timeout connecting to upstream"))?
        .context("Failed to connect to upstream nfsd")?;

    // Enable TCP_NODELAY for latency
    client_socket.set_nodelay(true)?;
    upstream_socket.set_nodelay(true)?;

    // Phase 1: STARTTLS Negotiation
    timeout(Duration::from_secs(10), negotiate_starttls(&mut client_socket, &mut upstream_socket))
        .await
        .map_err(|_| anyhow::anyhow!("Timeout during STARTTLS negotiation"))??;

    // Phase 2: TLS Handshake Validation
    let (client_buf, upstream_buf) = timeout(Duration::from_secs(30), validate_tls_handshake(&mut client_socket, &mut upstream_socket))
        .await
        .map_err(|_| anyhow::anyhow!("Timeout during TLS handshake"))??;

    // Phase 3: Splicing
    log::info!("Phase 3: Splicing connection");

    // Forward any leftover data buffered during handshake
    if !client_buf.is_empty() {
        upstream_socket.write_all(&client_buf).await?;
    }
    if !upstream_buf.is_empty() {
        client_socket.write_all(&upstream_buf).await?;
    }

    // Use tokio_splice2::copy_bidirectional for efficiency
    tokio_splice2::copy_bidirectional(
        &mut client_socket, 
        &mut upstream_socket
    ).await?;

    Ok(())
}

async fn negotiate_starttls(client: &mut TcpStream, upstream: &mut TcpStream) -> Result<()> {
    // Read RPC Fragment Header (4 bytes)
    let mut fragment_header = [0u8; 4];
    client.read_exact(&mut fragment_header).await
        .context("Failed to read RPC fragment header")?;

    let header_val = u32::from_be_bytes(fragment_header);
    let len = (header_val & 0x7FFFFFFF) as usize;
    let is_last = (header_val & 0x80000000) != 0;

    if !is_last {
        bail!("Multi-fragment RPC calls not supported for STARTTLS");
    }

    if len > 1024 {
        bail!("RPC Fragment length too large for STARTTLS sanity check: {}", len);
    }

    let mut xdr_payload = vec![0u8; len];
    client.read_exact(&mut xdr_payload).await
        .context("Failed to read RPC body")?;

    // Check if it's a valid STARTTLS
    xdr::validate_starttls_header(&xdr_payload)
        .context("XDR Validation Failed")?;

    log::debug!("Phase 1: Valid XDR STARTTLS command detected");

    // Forward logic to upstream
    upstream.write_all(&fragment_header).await?;
    upstream.write_all(&xdr_payload).await?;

    // Now read the reply from upstream and forward to client.
    let mut reply_header = [0u8; 4];
    upstream.read_exact(&mut reply_header).await
        .context("Failed to read RPC reply header from upstream")?;
    
    let reply_val = u32::from_be_bytes(reply_header);
    let reply_len = (reply_val & 0x7FFFFFFF) as usize;
    
    // Forward reply to client (header)
    client.write_all(&reply_header).await?;

    if reply_len > 0 {
        let mut reply_payload = vec![0u8; reply_len];
        upstream.read_exact(&mut reply_payload).await
            .context("Failed to read RPC reply body")?;
        client.write_all(&reply_payload).await?;
    }
    
    log::debug!("Phase 1: Forwarded STARTTLS Reply to client.");
    Ok(())
}

async fn validate_tls_handshake(client_socket: &mut TcpStream, upstream_socket: &mut TcpStream) -> Result<(BytesMut, BytesMut)> {
    let mut client_buf = BytesMut::with_capacity(4096);
    let mut upstream_buf = BytesMut::with_capacity(4096);

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
                
                let (consumed, hit_app_data) = process_tls_buffer(&client_buf, "Client")?;
                
                if consumed > 0 {
                    let data = client_buf.split_to(consumed);
                    upstream_socket.write_all(&data).await?;
                }
                
                if hit_app_data {
                    log::info!("Client sent Application Data.");
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
                    let data = upstream_buf.split_to(consumed);
                    client_socket.write_all(&data).await?;
                }
                
                if hit_app_data {
                    log::info!("Upstream sent Application Data. Handshake established.");
                    return Ok((client_buf, upstream_buf));
                }
            }
        }
    }
}

fn process_tls_buffer(buf: &[u8], source: &str) -> Result<(usize, bool)> {
    let mut offset = 0;
    let mut found_app_data = false;

    loop {
        let remaining = &buf[offset..];
        if remaining.is_empty() {
            break;
        }

        // Try to parse as plaintext first (to inspect handshake messages)
        match parse_tls_plaintext(remaining) {
            Ok((rem, plaintext)) => {
                let consumed = remaining.len() - rem.len();
                log::debug!("Parsed {} record: Type={:?}, Len={}", source, plaintext.hdr.record_type, plaintext.hdr.len);
                
                if plaintext.hdr.record_type == TlsRecordType::ApplicationData {
                    found_app_data = true;
                }
                
                offset += consumed;
                
                if found_app_data {
                    return Ok((offset, true));
                }
            }
            Err(tls_parser::Err::Incomplete(_)) => {
                break; // Need more data
            }
            Err(_) => {
                // Background: if parse_tls_plaintext fails, it might be an encrypted record (e.g. TLS 1.3 after ServerHello).
                // We fallback to just parsing the record header to advance and check for ApplicationData.
                match parse_tls_record_header(remaining) {
                    Ok((_, hdr)) => {
                        let total_record_len = 5 + hdr.len as usize;
                        if remaining.len() < total_record_len {
                            break; // Need more data for the full record
                        }
                        
                        log::debug!("Forwarding {} encrypted record: Type={:?}, Len={}", source, hdr.record_type, hdr.len);
                        
                        if hdr.record_type == TlsRecordType::ApplicationData {
                            found_app_data = true;
                        }
                        
                        offset += total_record_len;
                        
                        if found_app_data {
                            return Ok((offset, true));
                        }
                    }
                    Err(e) => {
                        bail!("{} sent truly invalid TLS data: {:?}", source, e);
                    }
                }
            }
        }
    }

    Ok((offset, false))
}
