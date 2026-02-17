//! Freehold H3 Proxy - HTTP/3 to HTTP/1.1 reverse proxy
//!
//! Accepts QUIC/H3 connections from Alice's browser and forwards
//! requests to Bob's local HTTP backend. Supports WebSocket over
//! HTTP/3 via RFC 9220 Extended CONNECT.
//!
//! ```text
//! Alice (Chrome) --H3/QUIC--> Bob's H3Proxy --HTTP/1.1--> Bob's Backend
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3::quic::BidiStream;
use h3::server::RequestStream;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

mod certs;
pub use certs::generate_self_signed_cert;

// Re-export rustls types for downstream crates
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Configuration for the H3 proxy.
#[derive(Debug)]
pub struct H3ProxyConfig {
    /// Address to bind the QUIC server.
    pub bind_addr: SocketAddr,
    /// Backend HTTP server address.
    pub backend: SocketAddr,
    /// TLS certificate chain (DER).
    pub certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// TLS private key (DER).
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

/// H3 reverse proxy server.
pub struct H3Proxy {
    config: H3ProxyConfig,
}

impl H3Proxy {
    pub fn new(config: H3ProxyConfig) -> Self {
        Self { config }
    }

    /// Run the proxy until shutdown is signaled (standalone mode — creates its own endpoint).
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        // Install crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        let server_config = make_quinn_server_config(self.config.certs, self.config.key)?;

        let endpoint = quinn::Endpoint::server(server_config, self.config.bind_addr)
            .context("bind endpoint")?;

        info!(
            "H3 proxy listening on {} -> backend {}",
            self.config.bind_addr, self.config.backend
        );

        serve_h3(endpoint, self.config.backend, shutdown).await
    }
}

/// Build a Quinn `ServerConfig` from TLS cert/key for H3.
pub fn make_quinn_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS config")?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.max_early_data_size = u32::MAX;

    let quic_config = QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("QUIC config: {}", e))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
}

/// Accept H3 connections on a pre-built Quinn endpoint and proxy to backend.
pub async fn serve_h3(
    endpoint: quinn::Endpoint,
    backend: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("H3 proxy shutting down");
                    break;
                }
            }
            incoming = endpoint.accept() => {
                if let Some(conn) = incoming {
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(conn, backend).await {
                            debug!("Connection error: {:?}", e);
                        }
                    });
                } else {
                    break;
                }
            }
        }
    }

    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming, backend: SocketAddr) -> Result<()> {
    let connection = incoming.await.context("accept connection")?;
    let remote = connection.remote_address();
    info!("H3 connection from {}", remote);

    let mut h3_conn = h3::server::builder()
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(connection))
        .await
        .context("H3 handshake")?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = handle_request(request, stream, backend, remote).await {
                                warn!("Request error: {:?}", e);
                            }
                        }
                        Err(e) => warn!("Resolve request: {:?}", e),
                    }
                });
            }
            Ok(None) => {
                debug!("Connection closed gracefully");
                break;
            }
            Err(e) => {
                debug!("Connection ended: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request<S>(
    request: Request<()>,
    stream: RequestStream<S, Bytes>,
    backend: SocketAddr,
    remote: SocketAddr,
) -> Result<()>
where
    S: BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send + 'static,
    S::RecvStream: Send + 'static,
{
    // Check for WebSocket Extended CONNECT (RFC 9220)
    if request.method() == Method::CONNECT {
        if let Some(protocol) = request.extensions().get::<Protocol>() {
            if *protocol == Protocol::WEBSOCKET {
                info!("WebSocket CONNECT {} from {}", request.uri(), remote);
                return handle_websocket(request, stream, backend).await;
            }
        }
    }

    handle_http_request(request, stream, backend, remote).await
}

async fn handle_websocket<S>(
    request: Request<()>,
    mut stream: RequestStream<S, Bytes>,
    backend: SocketAddr,
) -> Result<()>
where
    S: BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send + 'static,
    S::RecvStream: Send + 'static,
{
    // Connect to backend via TCP
    let mut tcp = TcpStream::connect(backend)
        .await
        .context("connect to backend for WebSocket")?;

    // Build the WebSocket upgrade path from the request URI
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Generate a Sec-WebSocket-Key (16 random bytes, base64-encoded)
    let mut key_bytes = [0u8; 16];
    for b in key_bytes.iter_mut() {
        *b = fastrand::u8(..);
    }
    use base64::Engine;
    let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    // Send HTTP/1.1 WebSocket upgrade request to backend
    let upgrade_req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path, backend, ws_key
    );

    tcp.write_all(upgrade_req.as_bytes()).await?;

    // Read the HTTP/1.1 101 response from backend
    let mut resp_buf = vec![0u8; 4096];
    let mut resp_len = 0;
    loop {
        let n = tcp.read(&mut resp_buf[resp_len..]).await?;
        if n == 0 {
            anyhow::bail!("backend closed before completing WebSocket handshake");
        }
        resp_len += n;

        if let Some(pos) = find_header_end(&resp_buf[..resp_len]) {
            let header_str = std::str::from_utf8(&resp_buf[..pos])
                .context("invalid UTF-8 in backend response")?;
            if !header_str.starts_with("HTTP/1.1 101") {
                anyhow::bail!("backend rejected WebSocket upgrade: {}", header_str);
            }
            break;
        }

        if resp_len >= resp_buf.len() {
            anyhow::bail!("backend WebSocket response headers too large");
        }
    }

    // Send 200 OK back on the H3 stream (per RFC 9220, the response to
    // a successful Extended CONNECT is 200, not 101)
    let response = Response::builder().status(StatusCode::OK).body(())?;
    stream.send_response(response).await?;

    // Split both sides for bidirectional piping
    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // H3 -> TCP: read from H3 client, write to backend TCP
    let h3_to_tcp = tokio::spawn(async move {
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(mut buf)) => {
                    let data = buf.chunk().to_vec();
                    buf.advance(buf.remaining());
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        tcp_write.shutdown().await.ok();
    });

    // TCP -> H3: read from backend TCP, write to H3 client
    let tcp_to_h3 = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if h3_send
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        h3_send.finish().await.ok();
    });

    // Wait for both directions to complete
    let _ = tokio::try_join!(h3_to_tcp, tcp_to_h3);
    debug!("WebSocket session ended");

    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

async fn handle_http_request<S>(
    request: Request<()>,
    mut stream: RequestStream<S, Bytes>,
    backend: SocketAddr,
    remote: SocketAddr,
) -> Result<()>
where
    S: BidiStream<Bytes>,
{
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    info!("{} {} from {}", method, uri, remote);

    // Read request body
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    // Build backend request
    let backend_uri = format!(
        "http://{}{}",
        backend,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );

    let mut backend_req = Request::builder().method(method.clone()).uri(&backend_uri);

    // Forward headers (skip pseudo-headers and host)
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str.starts_with(':') || name_str.eq_ignore_ascii_case("host") {
            continue;
        }
        backend_req = backend_req.header(name, value);
    }

    // Set correct host and proxy headers
    backend_req = backend_req
        .header("host", backend.to_string())
        .header("x-forwarded-for", remote.ip().to_string())
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", remote.port().to_string());

    let backend_body = if body.is_empty() {
        Full::new(Bytes::new()).boxed()
    } else {
        Full::new(Bytes::from(body)).boxed()
    };

    let backend_req = backend_req.body(backend_body)?;

    // Forward to backend
    let client: Client<_, _> = Client::builder(TokioExecutor::new()).build_http();

    let backend_resp = match client.request(backend_req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Backend error: {}", e);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from(format!("Bad Gateway: {}", e)))
                .await?;
            stream.finish().await.ok();
            return Ok(());
        }
    };

    let status = backend_resp.status();
    let resp_headers = backend_resp.headers().clone();

    // Build H3 response
    let mut h3_response = Response::builder().status(status);

    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str();
        // Skip hop-by-hop headers
        if name_str.eq_ignore_ascii_case("connection")
            || name_str.eq_ignore_ascii_case("keep-alive")
            || name_str.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        h3_response = h3_response.header(name, value);
    }

    let h3_response = h3_response.body(())?;

    // Send response
    stream.send_response(h3_response).await?;

    // Stream body
    let resp_body = backend_resp.into_body().collect().await?.to_bytes();
    if !resp_body.is_empty() {
        const CHUNK_SIZE: usize = 16384;
        for chunk in resp_body.chunks(CHUNK_SIZE) {
            stream.send_data(Bytes::copy_from_slice(chunk)).await?;
        }
    }

    if let Err(e) = stream.finish().await {
        debug!("Stream finish: {} (client may have closed)", e);
    }

    debug!(
        "{} {} -> {} ({} bytes)",
        method,
        uri,
        status.as_u16(),
        resp_body.len()
    );

    Ok(())
}
