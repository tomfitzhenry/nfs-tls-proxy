use super::*;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use byteorder::{BigEndian, WriteBytesExt};
use std::sync::Arc;
use tokio_rustls::rustls::{ServerConfig, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_rustls::TlsAcceptor;
use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, PrivatePkcs8KeyDer};

#[tokio::test]
async fn test_full_proxy_flow_real_tls() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    // 1. Setup TLS Certs
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    
    // Server Config
    let certs = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let server_config = Arc::new(server_config);
    let acceptor = TlsAcceptor::from(server_config);

    // Client Config
    let mut root_store = RootCertStore::empty();
    root_store.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client_config = Arc::new(client_config);
    let connector = TlsConnector::from(client_config);

    // 2. Start Dummy Upstream (Real TLS Server)
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?.to_string();
    
    let upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.unwrap();
        
        // Expect STARTTLS XDR
        let mut frag_header = [0u8; 4];
        socket.read_exact(&mut frag_header).await.unwrap();
        let len = (u32::from_be_bytes(frag_header) & 0x7FFFFFFF) as usize;
        let mut buf = vec![0u8; len];
        socket.read_exact(&mut buf).await.unwrap();
        
        // Reply with SUCCESS
        let reply_data = [0u8; 16]; 
        let len_val: u32 = 16 | 0x80000000;
        socket.write_all(&len_val.to_be_bytes()).await.unwrap();
        socket.write_all(&reply_data).await.unwrap();

        // Perform TLS Handshake (Server Side)
        let mut tls_stream = acceptor.accept(socket).await.unwrap();

        // Echo Loop
        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).await.unwrap();
        tls_stream.write_all(&buf[..n]).await.unwrap();
    });

    // 3. Start Proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?.to_string();

    let proxy_handle = tokio::spawn(async move {
        let (client_socket, _) = proxy_listener.accept().await.unwrap();
        handle_connection(client_socket, upstream_addr).await.unwrap();
    });

    // 4. Client Interaction
    let mut client = TcpStream::connect(&proxy_addr).await?;

    // Send STARTTLS XDR
    let mut xdr_frame = Vec::new();
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0xCAFEBABE)?; 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0)?; 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 2)?; 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 100235)?; 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 1)?; 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0)?; 

    let len = xdr_frame.len() as u32 | 0x80000000;
    AsyncWriteExt::write_u32(&mut client, len).await?;
    client.write_all(&xdr_frame).await?;

    // Read Reply
    let mut reply_header = [0u8; 4];
    client.read_exact(&mut reply_header).await?;
    let reply_len = (u32::from_be_bytes(reply_header) & 0x7FFFFFFF) as usize;
    let mut reply_buf = vec![0u8; reply_len];
    client.read_exact(&mut reply_buf).await?;

    // Perform TLS Handshake (Client Side)
    let domain = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(domain, client).await?;

    // Send Data
    tls_stream.write_all(b"Hello World").await?;
    
    // Read Echo
    let mut buf = [0u8; 1024];
    let n = tls_stream.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"Hello World");

    // Cleanup
    let _ = upstream_handle.await;
    let _ = proxy_handle.await;
    
    Ok(())
}
