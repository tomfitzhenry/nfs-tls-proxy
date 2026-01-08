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
    
    let (acceptor, connector) = setup_tls_configs();

    // 1. Start Dummy Upstream (Real TLS Server)
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

    // 2. Start Proxy
    let proxy_addr = spawn_proxy(upstream_addr).await?;

    // 3. Client Interaction
    let mut client = TcpStream::connect(&proxy_addr).await?;

    // Send STARTTLS XDR
    let xdr_frame = encode_starttls_rpc(100235);
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

    // Explicitly shutdown to end splicing and trigger handles to finish
    tls_stream.get_mut().0.shutdown().await?;
    
    let _ = upstream_handle.await;
    Ok(())
}

#[tokio::test]
async fn test_abort_on_invalid_starttls() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Start Dummy Upstream (just to accept proxy connection)
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?.to_string();
    
    let _upstream_handle = tokio::spawn(async move {
        let _ = upstream_listener.accept().await;
    });

    // 2. Start Proxy
    let proxy_addr = spawn_proxy(upstream_addr).await?;

    // 3. Client Interaction: Send INVALID STARTTLS (wrong program ID)
    let mut client = TcpStream::connect(&proxy_addr).await?;

    let xdr_frame = encode_starttls_rpc(999999); // WRONG PROGRAM
    let len = xdr_frame.len() as u32 | 0x80000000;
    AsyncWriteExt::write_u32(&mut client, len).await?;
    client.write_all(&xdr_frame).await?;

    // 4. Verify Proxy Aborted
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await?;
    assert_eq!(n, 0, "Proxy should have closed the connection due to invalid XDR");

    Ok(())
}

#[tokio::test]
async fn test_abort_on_wonky_tls_handshake() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup Dummy Upstream
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
        
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
    });

    // 2. Start Proxy
    let proxy_addr = spawn_proxy(upstream_addr).await?;

    // 3. Client Interaction
    let mut client = TcpStream::connect(&proxy_addr).await?;

    // Send Valid STARTTLS XDR
    let xdr_frame = encode_starttls_rpc(100235);
    let len = xdr_frame.len() as u32 | 0x80000000;
    AsyncWriteExt::write_u32(&mut client, len).await?;
    client.write_all(&xdr_frame).await?;

    // Read STARTTLS Reply
    let mut reply_header = [0u8; 4];
    client.read_exact(&mut reply_header).await?;
    let reply_len = (u32::from_be_bytes(reply_header) & 0x7FFFFFFF) as usize;
    let mut reply_buf = vec![0u8; reply_len];
    client.read_exact(&mut reply_buf).await?;

    // 4. Send WONKY TLS record (invalid ContentType 0xFF)
    let wonky_record = [
        0xFF,       // Invalid Record Type
        0x03, 0x03, // TLS 1.2 record version
        0x00, 0x05, // Length: 5
        0x01, 0x02, 0x03, 0x04, 0x05, // Junk data
    ];
    client.write_all(&wonky_record).await?;

    // 5. Verify Proxy Aborted
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await?;
    assert_eq!(n, 0, "Proxy should have closed connection due to wonky TLS record");

    let _ = upstream_handle.await;
    Ok(())
}

fn setup_tls_configs() -> (TlsAcceptor, TlsConnector) {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    
    let certs = vec![CertificateDer::from(cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut root_store = RootCertStore::empty();
    root_store.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    (acceptor, connector)
}

async fn spawn_proxy(upstream_addr: String) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();

    tokio::spawn(async move {
        if let Ok((client_socket, _)) = listener.accept().await {
            let _ = handle_connection(client_socket, upstream_addr).await;
        }
    });

    Ok(addr)
}

fn encode_starttls_rpc(program: u32) -> Vec<u8> {
    let mut xdr_frame = Vec::new();
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0xCAFEBABE).unwrap(); // XID
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0).unwrap(); // CALL
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 2).unwrap(); // RPC v2
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, program).unwrap(); 
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 1).unwrap(); // v1
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0).unwrap(); // proc 0
    xdr_frame
}
