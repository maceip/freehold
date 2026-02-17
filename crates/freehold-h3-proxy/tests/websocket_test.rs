use std::sync::Arc;

use bytes::{Buf, Bytes};
use freehold_h3_proxy::{generate_self_signed_cert, H3Proxy, H3ProxyConfig};
use h3::ext::Protocol;
use http::{Method, Request};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

/// A mock WebSocket backend that accepts upgrade requests and echoes data.
async fn mock_ws_backend(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();

    // Read the HTTP upgrade request
    let mut buf = vec![0u8; 4096];
    let mut len = 0;
    loop {
        let n = stream.read(&mut buf[len..]).await.unwrap();
        assert!(n > 0, "client closed before sending full headers");
        len += n;
        if buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let req_str = std::str::from_utf8(&buf[..len]).unwrap();
    assert!(req_str.contains("Upgrade: websocket"));
    assert!(req_str.contains("Connection: Upgrade"));

    // Send 101 Switching Protocols
    let response = "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: dummy\r\n\
                     \r\n";
    stream.write_all(response.as_bytes()).await.unwrap();

    // Echo loop: read data and send it back
    let mut echo_buf = vec![0u8; 4096];
    loop {
        match stream.read(&mut echo_buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&echo_buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn websocket_over_h3_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Start mock WebSocket backend on a random port
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    tokio::spawn(mock_ws_backend(backend_listener));

    // Find a free UDP port for the proxy
    let temp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let proxy_addr = temp_socket.local_addr().unwrap();
    drop(temp_socket);

    // Generate self-signed cert (one generation for both server and client trust)
    let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();
    let client_cert = certs[0].clone();

    let config = H3ProxyConfig {
        bind_addr: proxy_addr,
        backend: backend_addr,
        certs,
        key,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy = H3Proxy::new(config);

    let proxy_handle = tokio::spawn(async move {
        proxy.run(shutdown_rx).await.unwrap();
    });

    // Give proxy time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Build quinn client that trusts our self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(client_cert).unwrap();

    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_config = QuicClientConfig::try_from(client_tls).expect("QUIC client config");

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client_config)));

    // Connect to proxy
    let conn = endpoint
        .connect(proxy_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Build H3 connection with Extended CONNECT enabled
    let (_driver, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(conn))
        .await
        .unwrap();

    // Send CONNECT request with :protocol websocket
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://localhost/ws")
        .extension(Protocol::WEBSOCKET)
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(request).await.unwrap();

    // Read the 200 OK response
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);

    // Send test data through the WebSocket tunnel
    let test_data = b"hello websocket over h3";
    stream
        .send_data(Bytes::from_static(test_data))
        .await
        .unwrap();

    // Read echoed data back
    let mut received = Vec::new();
    if let Some(mut chunk) = stream.recv_data().await.unwrap() {
        received.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    assert_eq!(received, test_data);

    // Cleanup
    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    proxy_handle.abort();
}
