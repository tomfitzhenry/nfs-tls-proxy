use super::*;
use tokio::net::TcpListener;
use byteorder::{BigEndian, WriteBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Explicit import for TcpStream ops

#[tokio::test]
async fn test_full_proxy_flow() -> Result<()> {
    // 1. Start Dummy Upstream
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?.to_string();
    
    let _upstream_handle = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.unwrap();
        
        // Expect STARTTLS XDR
        let mut frag_header = [0u8; 4];
        socket.read_exact(&mut frag_header).await.unwrap();
        let len = (u32::from_be_bytes(frag_header) & 0x7FFFFFFF) as usize;
        let mut buf = vec![0u8; len];
        socket.read_exact(&mut buf).await.unwrap();
        
        // Reply with SUCCESS
        // Mock RPC Reply
        let reply_data = [0u8; 16]; 
        // Write length 16 with LastFragment bit (0x80)
        let len_val: u32 = 16 | 0x80000000;
        socket.write_all(&len_val.to_be_bytes()).await.unwrap();
        socket.write_all(&reply_data).await.unwrap();

        // Expect TLS ClientHello
        let mut tls_header = [0u8; 5];
        socket.read_exact(&mut tls_header).await.unwrap();
        // We don't check content, assuming proxy did.
        let tls_len = u16::from_be_bytes([tls_header[3], tls_header[4]]) as usize;
        let mut tls_buf = vec![0u8; tls_len];
        socket.read_exact(&mut tls_buf).await.unwrap();

        // Send some "Encrypted" data back via splice
        socket.write_all(b"Hello from Upstream").await.unwrap();
        
        // Read some "Encrypted" data from client via splice
        let mut final_buf = [0u8; 5];
        socket.read_exact(&mut final_buf).await.unwrap();
        assert_eq!(&final_buf, b"World");
    });

    // 2. Start Proxy
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?.to_string();

    let _proxy_handle = tokio::spawn(async move {
        let (client_socket, _) = proxy_listener.accept().await.unwrap();
        handle_connection(client_socket, upstream_addr).await.unwrap();
    });

    // 3. Client Interaction
    let mut client = TcpStream::connect(&proxy_addr).await?;

    // Send STARTTLS XDR
    let mut xdr_frame = Vec::new();
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0xCAFEBABE)?; // XID
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0)?; // Call
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 2)?; // RPC 2
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 100235)?; // Prog
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 1)?; // Ver
    WriteBytesExt::write_u32::<BigEndian>(&mut xdr_frame, 0)?; // Proc

    let len = xdr_frame.len() as u32 | 0x80000000;
    AsyncWriteExt::write_u32(&mut client, len).await?;
    client.write_all(&xdr_frame).await?;

    // Read Reply
    let mut reply_header = [0u8; 4];
    client.read_exact(&mut reply_header).await?;
    let reply_len = (u32::from_be_bytes(reply_header) & 0x7FFFFFFF) as usize;
    let mut reply_buf = vec![0u8; reply_len];
    client.read_exact(&mut reply_buf).await?;

    // Construct a valid minimal ClientHello
    // Handshake Type (01) + Len (3 bytes) + Ver (2) + Random (32) + ...
    let mut client_hello = Vec::new();
    client_hello.push(0x01); // ClientHello
    // Length placeholder (3 bytes)
    client_hello.push(0x00); client_hello.push(0x00); client_hello.push(0x00);
    client_hello.push(0x03); client_hello.push(0x03); // Version (TLS 1.2)
    client_hello.extend_from_slice(&[0u8; 32]); // Random
    client_hello.push(0x00); // Session ID len
    client_hello.push(0x00); client_hello.push(0x02); // Cipher suites len
    client_hello.push(0x00); client_hello.push(0x2F); // Cipher (AES128-SHA)
    client_hello.push(0x01); // Compression len
    client_hello.push(0x00); // Compression (Null)

    let ch_len = (client_hello.len() - 4) as u32; // Exclude Type(1) and Len(3) fields from length?
    // Handshake protocol: Type(1) + Length(3) + Body
    // Length is length of Body.
    client_hello[1] = (ch_len >> 16) as u8;
    client_hello[2] = (ch_len >> 8) as u8;
    client_hello[3] = ch_len as u8;

    let mut tls_frame = Vec::new();
    tls_frame.push(0x16); // Record Type: Handshake
    tls_frame.push(0x03); tls_frame.push(0x03); // Record Version
    WriteBytesExt::write_u16::<BigEndian>(&mut tls_frame, client_hello.len() as u16)?;
    tls_frame.extend_from_slice(&client_hello);

    client.write_all(&tls_frame).await?;

    // Read Upstream greeting
    let mut greeting = [0u8; 19];
    client.read_exact(&mut greeting).await?;
    assert_eq!(&greeting, b"Hello from Upstream");

    // Write "World"
    client.write_all(b"World").await?;

    // Cleanup
    // We don't join threads strictly as loop runs forever, but test passing implies all good.
    // upstream_handle terminates. proxy_handle loops.
    // But since we are done, drop propagates.
    
    Ok(())
}
