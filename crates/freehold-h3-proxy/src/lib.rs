//! Freehold H3 Proxy - HTTP/3 to HTTP/1.1 reverse proxy
//!
//! Accepts QUIC/H3 connections from Alice's browser and forwards
//! requests to Bob's local HTTP backend.
//!
//! ```text
//! Alice (Chrome) --H3/QUIC--> Bob's H3Proxy --HTTP/1.1--> Bob's Backend
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use h3::quic::BidiStream;
use h3::server::RequestStream;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use quinn::crypto::rustls::QuicServerConfig;
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

    /// Run the proxy until shutdown is signaled.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        // Install crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // TLS config
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.config.certs, self.config.key)
            .context("TLS config")?;

        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        tls_config.max_early_data_size = u32::MAX;

        // QUIC config
        let quic_config = QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("QUIC config: {}", e))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

        // Bind
        let endpoint = quinn::Endpoint::server(server_config, self.config.bind_addr)
            .context("bind endpoint")?;

        info!(
            "H3 proxy listening on {} -> backend {}",
            self.config.bind_addr, self.config.backend
        );

        // Accept loop
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
                        let backend = self.config.backend;
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
}

async fn handle_connection(incoming: quinn::Incoming, backend: SocketAddr) -> Result<()> {
    let connection = incoming.await.context("accept connection")?;
    let remote = connection.remote_address();
    info!("H3 connection from {}", remote);

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .context("H3 handshake")?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let backend = backend;
                let remote = remote;
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

    debug!("{} {} -> {} ({} bytes)", method, uri, status.as_u16(), resp_body.len());

    Ok(())
}
