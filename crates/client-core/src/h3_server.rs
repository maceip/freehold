//! HTTP/3 reverse proxy server using quinn.
//!
//! Accepts QUIC/H3 connections and proxies requests to a TCP backend
//! (HTTP/1.1 or HTTP/2).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use h3::quic::BidiStream;
use h3::server::RequestStream;
use bytes::Buf;
use http::{Request, Response};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::tcp_proxy::{ProxyRequest, ProxyResponse, TcpProxyClient};
use crate::ClientError;

/// Configuration for the H3 reverse proxy server.
#[derive(Debug)]
pub struct H3ProxyConfig {
    /// Local address to bind QUIC socket.
    pub bind_addr: SocketAddr,
    /// Backend address to proxy HTTP requests to.
    pub backend: SocketAddr,
    /// TLS certificate chain (DER encoded).
    pub certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// TLS private key (DER encoded).
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
    /// Idle timeout in seconds.
    pub idle_timeout_secs: u64,
}

/// Statistics for the H3 proxy server.
#[derive(Debug, Clone, Default)]
pub struct H3ProxyStats {
    pub connections_total: u64,
    pub connections_active: u64,
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

/// HTTP/3 reverse proxy server.
///
/// Accepts QUIC/H3 connections and forwards requests to a TCP backend.
pub struct H3ProxyServer {
    config: H3ProxyConfig,
}

impl H3ProxyServer {
    /// Create a new H3 proxy server.
    pub fn new(config: H3ProxyConfig) -> Self {
        Self { config }
    }

    /// Run the H3 proxy server.
    ///
    /// This consumes the server and blocks until shutdown is signaled.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<(), ClientError> {
        let bind_addr = self.config.bind_addr;
        let backend = self.config.backend;

        // Install crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create TLS config
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.config.certs, self.config.key)
            .map_err(|e| ClientError::Tls(format!("Failed to create TLS config: {}", e)))?;

        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        tls_config.max_early_data_size = u32::MAX;

        // Create QUIC server config
        let quic_config = QuicServerConfig::try_from(tls_config)
            .map_err(|e| ClientError::Tls(format!("Failed to create QUIC config: {}", e)))?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

        // Bind endpoint
        let endpoint = quinn::Endpoint::server(server_config, bind_addr)
            .map_err(|e| ClientError::Network(format!("Failed to bind: {}", e)))?;

        info!("H3 proxy listening on {} -> backend {}", bind_addr, backend);

        // Accept connections
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("H3 proxy shutdown requested");
                        break;
                    }
                }
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(conn) => {
                            let conn_backend = backend;
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(conn, conn_backend).await {
                                    debug!("Connection error: {:?}", e);
                                }
                            });
                        }
                        None => {
                            info!("Endpoint closed");
                            break;
                        }
                    }
                }
            }
        }

        endpoint.close(0u32.into(), b"shutdown");
        Ok(())
    }

    /// Get the bind address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.config.bind_addr
    }

    /// Get the backend address.
    pub fn backend(&self) -> SocketAddr {
        self.config.backend
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    backend: SocketAddr,
) -> Result<(), ClientError> {
    let connection = incoming
        .await
        .map_err(|e| ClientError::Connection(format!("Failed to accept: {}", e)))?;

    let remote = connection.remote_address();
    info!("New H3 connection from {}", remote);

    // Create H3 connection
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| ClientError::Connection(format!("H3 handshake failed: {}", e)))?;

    // Handle requests
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let backend = backend;
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = handle_request(request, stream, backend).await {
                                warn!("Request error: {:?}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to resolve request: {:?}", e);
                        }
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
) -> Result<(), ClientError>
where
    S: BidiStream<Bytes>,
{
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    info!("{} {} -> {}", method, uri, backend);

    // Read request body (if any)
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| ClientError::Connection(format!("Failed to read body: {}", e)))?
    {
        body.extend_from_slice(chunk.chunk());
        chunk.advance(chunk.remaining());
    }

    // Build proxy request
    let mut proxy_req = ProxyRequest::new(method.clone(), uri.clone());
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            proxy_req = proxy_req.with_header(name.as_str(), v);
        }
    }
    if !body.is_empty() {
        proxy_req = proxy_req.with_body(Bytes::from(body));
    }

    // Forward to backend
    let tcp_client = TcpProxyClient::for_target(backend);
    let proxy_resp = match tcp_client.forward(proxy_req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Backend error: {}", e);
            ProxyResponse::bad_gateway(e.to_string())
        }
    };

    // Build H3 response
    let mut response = Response::builder().status(proxy_resp.status);

    for (name, value) in &proxy_resp.headers {
        response = response.header(name.as_str(), value.as_str());
    }

    let response = response
        .body(())
        .map_err(|e| ClientError::Connection(format!("Failed to build response: {}", e)))?;

    // Send response headers
    stream
        .send_response(response)
        .await
        .map_err(|e| ClientError::Connection(format!("Failed to send response: {}", e)))?;

    // Send response body in chunks
    if !proxy_resp.body.is_empty() {
        const CHUNK_SIZE: usize = 16384;
        for chunk in proxy_resp.body.chunks(CHUNK_SIZE) {
            stream
                .send_data(Bytes::copy_from_slice(chunk))
                .await
                .map_err(|e| ClientError::Connection(format!("Failed to send body: {}", e)))?;
        }
    }

    // Finish stream (ignore errors - client may have closed)
    if let Err(e) = stream.finish().await {
        debug!("Stream finish: {} (client may have closed)", e);
    }

    debug!(
        "{} {} -> {} ({} bytes)",
        method,
        uri,
        proxy_resp.status.as_u16(),
        proxy_resp.body.len()
    );

    Ok(())
}

/// Generate a self-signed certificate for testing.
pub fn generate_self_signed_cert(
    domain: &str,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    ClientError,
> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair =
        KeyPair::generate().map_err(|e| ClientError::Tls(format!("Key generation failed: {}", e)))?;

    let params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| ClientError::Tls(format!("Cert params failed: {}", e)))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ClientError::Tls(format!("Self-signing failed: {}", e)))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| ClientError::Tls(format!("Key conversion failed: {:?}", e)))?;

    Ok((vec![cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert("localhost");
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_generate_self_signed_cert_custom_domain() {
        let result = generate_self_signed_cert("test.example.com");
        assert!(result.is_ok());
    }
}
