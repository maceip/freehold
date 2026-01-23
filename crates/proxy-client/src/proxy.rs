//! HTTPS Reverse Proxy with TLS termination.
//!
//! Features:
//! - HTTPS frontend (accepts TLS connections)
//! - HTTP/1.1 or HTTP/2 backend (proxies to target)
//! - Heartbeat loop for relay registration
//! - TLS with ACME or self-signed certificates

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::crypto::{generate_self_signed, CertBundle};

/// Configuration for the proxy
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub domain: String,
    pub target: String,
    pub listen_addr: SocketAddr,
    pub use_self_signed: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            domain: "localhost".into(),
            target: "127.0.0.1:8080".into(),
            listen_addr: "[::]:443".parse().unwrap(),
            use_self_signed: true,
        }
    }
}

/// Start the Specular proxy
pub async fn start_proxy(domain: &str, target: &str, listen: &str) -> Result<()> {
    let listen_addr: SocketAddr = listen.parse()
        .unwrap_or_else(|_| "[::]:443".parse().unwrap());

    let config = ProxyConfig {
        domain: domain.to_string(),
        target: target.to_string(),
        listen_addr,
        ..Default::default()
    };

    info!("Starting Specular proxy");
    info!("  Domain: {}", config.domain);
    info!("  Target: {}", config.target);
    info!("  Listen: {}", config.listen_addr);

    // 1. Get or generate TLS certificate
    let cert_bundle = get_certificate(&config).await?;

    // 2. Build TLS configuration
    let tls_acceptor = build_tls_acceptor(cert_bundle)?;

    // 3. Create TCP listener
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!("HTTPS server listening on {}", config.listen_addr);

    // 4. Start heartbeat loop in background
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let heartbeat_handle = tokio::spawn(heartbeat_loop(config.domain.clone(), shutdown_rx.clone()));

    // 5. Accept connections
    let result = accept_connections(listener, tls_acceptor, config, shutdown_rx).await;

    // Cleanup
    let _ = shutdown_tx.send(true);
    let _ = heartbeat_handle.await;

    result
}

/// Get TLS certificate (load existing, generate self-signed, or ACME)
async fn get_certificate(config: &ProxyConfig) -> Result<CertBundle> {
    // Try loading existing certificate
    if let Some(bundle) = CertBundle::load(&config.domain)? {
        info!("Using existing certificate for {}", config.domain);
        return Ok(bundle);
    }

    if config.use_self_signed {
        info!("Generating self-signed certificate for {}", config.domain);
        return generate_self_signed(&config.domain);
    }

    // TODO: ACME DNS-01 flow
    // For now, fall back to self-signed
    warn!("ACME not implemented, using self-signed certificate");
    generate_self_signed(&config.domain)
}

/// Build TLS acceptor
fn build_tls_acceptor(cert_bundle: CertBundle) -> Result<TlsAcceptor> {
    // Install ring as the default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_bundle.cert_chain, cert_bundle.private_key)?;

    // Only advertise HTTP/1.1 (h2 support would require hyper's auto builder)
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Accept incoming TLS connections
async fn accept_connections(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    config: ProxyConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Shutdown signal received");
                    break;
                }
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, remote_addr)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let config = config.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, tls_acceptor, remote_addr, config).await {
                                debug!("Connection error from {}: {}", remote_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a single TLS connection
async fn handle_connection(
    stream: tokio::net::TcpStream,
    tls_acceptor: TlsAcceptor,
    remote_addr: SocketAddr,
    config: ProxyConfig,
) -> Result<()> {
    // TLS handshake
    let tls_stream = tls_acceptor.accept(stream).await?;
    debug!("TLS connection established from {}", remote_addr);

    let io = TokioIo::new(tls_stream);
    let target = config.target.clone();

    // Serve HTTP/1.1 (can upgrade to H2 via ALPN)
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let target = target.clone();
                async move { proxy_request(req, &target).await }
            }),
        )
        .await?;

    Ok(())
}

/// Proxy a request to the target backend
async fn proxy_request(
    req: Request<Incoming>,
    target: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    debug!("{} {}", method, uri);

    // Build target URL
    let target_url = format!(
        "http://{}{}",
        target,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );

    // Create HTTP client for backend
    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    // Collect the incoming body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    // Build backend request
    let mut backend_req = http::Request::builder()
        .method(method)
        .uri(&target_url);

    // Copy headers (except host)
    for (name, value) in headers.iter() {
        if name != http::header::HOST {
            backend_req = backend_req.header(name, value);
        }
    }

    let backend_req = match backend_req.body(Full::new(body_bytes)) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to build backend request: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(empty_body())
                .unwrap());
        }
    };

    // Send to backend
    match client.request(backend_req).await {
        Ok(backend_resp) => {
            let (parts, body) = backend_resp.into_parts();

            // Convert body
            let body = body.map_err(|e| e).boxed();

            Ok(Response::from_parts(parts, body))
        }
        Err(e) => {
            error!("Backend request failed: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body("Backend unavailable"))
                .unwrap())
        }
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(content: &'static str) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(content))
        .map_err(|never| match never {})
        .boxed()
}

/// Heartbeat loop to maintain relay registration
async fn heartbeat_loop(domain: String, mut shutdown: watch::Receiver<bool>) {
    let interval = Duration::from_secs(30);

    info!("Starting heartbeat loop for {}", domain);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Heartbeat loop shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                if let Err(e) = send_heartbeat(&domain).await {
                    warn!("Heartbeat failed: {}", e);
                } else {
                    debug!("Heartbeat sent for {}", domain);
                }
            }
        }
    }
}

/// Send heartbeat to relay network
async fn send_heartbeat(domain: &str) -> Result<()> {
    // TODO: Implement actual relay heartbeat protocol
    // This would typically:
    // 1. Connect to known relay nodes
    // 2. Send registration/heartbeat packet
    // 3. Receive acknowledgment

    // For now, this is a placeholder
    debug!("Heartbeat: {} is alive", domain);
    Ok(())
}

/// Check connectivity to relay network
pub async fn check_relay_status() -> Result<RelayStatus> {
    // TODO: Implement actual relay status check
    // This would:
    // 1. Ping known relay nodes
    // 2. Check latency and availability
    // 3. Return aggregate status

    Ok(RelayStatus {
        connected: false,
        relay_count: 0,
        avg_latency_ms: 0,
    })
}

#[derive(Debug)]
pub struct RelayStatus {
    pub connected: bool,
    pub relay_count: usize,
    pub avg_latency_ms: u64,
}

impl std::fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.connected {
            write!(
                f,
                "Connected to {} relays (avg latency: {}ms)",
                self.relay_count, self.avg_latency_ms
            )
        } else {
            write!(f, "Not connected to relay network")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_status() {
        let status = check_relay_status().await.unwrap();
        // Currently returns disconnected placeholder
        assert!(!status.connected);
    }
}
