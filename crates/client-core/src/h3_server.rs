//! HTTP/3 server using tquic with multipath support.
//!
//! Accepts QUIC connections from the reflector and proxies requests
//! to local TCP services.
//!
//! Note: This is a scaffold implementation. The actual tquic integration
//! requires matching the exact API of the library version being used.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::tcp_proxy::{ProxyRequest, ProxyResponse, TcpProxyClient};
use crate::ClientError;

/// Multipath algorithm for path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H3MultipathAlgorithm {
    /// Use the path with minimum RTT.
    #[default]
    MinRtt,
    /// Round-robin across all paths.
    RoundRobin,
    /// Redundant - send on all paths.
    Redundant,
}

/// Configuration for the H3 server.
#[derive(Debug, Clone)]
pub struct H3ServerConfig {
    /// Local address to bind QUIC socket.
    pub bind_addr: SocketAddr,
    /// Target address to proxy HTTP requests to (e.g., 127.0.0.1:8080).
    pub proxy_target: SocketAddr,
    /// TLS certificate PEM.
    pub cert_pem: Vec<u8>,
    /// TLS private key PEM.
    pub key_pem: Vec<u8>,
    /// Enable multipath QUIC.
    pub enable_multipath: bool,
    /// Multipath scheduling algorithm.
    pub multipath_algorithm: H3MultipathAlgorithm,
    /// Idle timeout in seconds.
    pub idle_timeout_secs: u64,
    /// Maximum concurrent streams per connection.
    pub max_streams: u64,
}

impl Default for H3ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4433".parse().unwrap(),
            proxy_target: "127.0.0.1:8080".parse().unwrap(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            enable_multipath: false,
            multipath_algorithm: H3MultipathAlgorithm::MinRtt,
            idle_timeout_secs: 30,
            max_streams: 100,
        }
    }
}

/// Statistics for an H3 server.
#[derive(Debug, Clone, Default)]
pub struct H3ServerStats {
    pub connections_total: u64,
    pub connections_active: u64,
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

/// Information about a QUIC connection path.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub rtt_ms: u64,
    pub active: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// HTTP/3 server that proxies to local TCP services.
///
/// This server:
/// 1. Accepts QUIC/H3 connections
/// 2. Parses HTTP/3 requests
/// 3. Proxies them to a local TCP service
/// 4. Returns responses via H3
///
/// Multipath support allows the server to handle connections
/// arriving from multiple network paths (e.g., WiFi + cellular).
pub struct H3Server {
    config: H3ServerConfig,
    stats: Arc<RwLock<H3ServerStats>>,
    tcp_proxy: TcpProxyClient,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl H3Server {
    /// Create a new H3 server with the given configuration.
    pub fn new(config: H3ServerConfig) -> Result<Self, ClientError> {
        let tcp_proxy = TcpProxyClient::for_target(config.proxy_target);

        Ok(Self {
            config,
            stats: Arc::new(RwLock::new(H3ServerStats::default())),
            tcp_proxy,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Create with default config.
    pub fn with_defaults(
        bind_addr: SocketAddr,
        proxy_target: SocketAddr,
    ) -> Result<Self, ClientError> {
        Self::new(H3ServerConfig {
            bind_addr,
            proxy_target,
            ..Default::default()
        })
    }

    /// Get the server configuration.
    pub fn config(&self) -> &H3ServerConfig {
        &self.config
    }

    /// Check if multipath is enabled.
    pub fn multipath_enabled(&self) -> bool {
        self.config.enable_multipath
    }

    /// Get current server statistics.
    pub async fn stats(&self) -> H3ServerStats {
        self.stats.read().await.clone()
    }

    /// Check if the server is running.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Start the H3 server.
    ///
    /// This spawns the server loop in a background task.
    /// Returns immediately after binding the socket.
    pub async fn start(&self) -> Result<(), ClientError> {
        if self.is_running() {
            return Err(ClientError::Connection("Server already running".to_string()));
        }

        // Verify TLS config
        if self.config.cert_pem.is_empty() || self.config.key_pem.is_empty() {
            return Err(ClientError::Tls("Certificate or key not provided".to_string()));
        }

        // Bind UDP socket
        let socket = UdpSocket::bind(self.config.bind_addr)
            .await
            .map_err(|e| ClientError::Connection(format!("Failed to bind: {}", e)))?;

        info!(
            "H3 server starting on {} -> {}",
            self.config.bind_addr, self.config.proxy_target
        );

        if self.config.enable_multipath {
            info!(
                "Multipath enabled with algorithm: {:?}",
                self.config.multipath_algorithm
            );
        }

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // TODO: Implement actual tquic server loop
        // The implementation would:
        // 1. Create tquic Config and TlsConfig
        // 2. Create Endpoint with TransportHandler
        // 3. Poll for incoming packets
        // 4. Process H3 requests
        // 5. Proxy to TCP backend
        // 6. Send H3 responses

        let running = self.running.clone();
        let stats = self.stats.clone();
        let bind_addr = self.config.bind_addr;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                // Placeholder: receive UDP packets
                match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((len, from))) => {
                        trace!("Received {} bytes from {}", len, from);
                        let mut s = stats.write().await;
                        s.bytes_received += len as u64;
                        // TODO: Process QUIC packet through tquic
                    }
                    Ok(Err(e)) => {
                        warn!("Socket recv error: {}", e);
                    }
                    Err(_) => {
                        // Timeout - continue loop
                    }
                }
            }

            info!("H3 server stopped on {}", bind_addr);
        });

        Ok(())
    }

    /// Stop the H3 server.
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        info!("H3 server stop requested");
    }

    /// Process an HTTP/3 request and return the response.
    ///
    /// This is called internally when a complete H3 request is received.
    pub async fn handle_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<ProxyResponse, ClientError> {
        debug!("Handling H3 request: {} {}", method, path);

        // Convert to proxy request
        let http_method: http::Method = method
            .parse()
            .map_err(|_| ClientError::Connection(format!("Invalid method: {}", method)))?;

        let uri: http::Uri = path
            .parse()
            .map_err(|_| ClientError::Connection(format!("Invalid path: {}", path)))?;

        let mut request = ProxyRequest::new(http_method, uri);

        for (name, value) in headers {
            request = request.with_header(name.clone(), value.clone());
        }

        if !body.is_empty() {
            request = request.with_body(body);
        }

        // Forward to TCP backend
        let response = self.tcp_proxy.forward(request).await?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.requests_total += 1;
            if response.status.is_success() {
                stats.requests_success += 1;
            } else {
                stats.requests_failed += 1;
            }
        }

        Ok(response)
    }
}

/// Builder for H3ServerConfig.
pub struct H3ServerConfigBuilder {
    config: H3ServerConfig,
}

impl H3ServerConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: H3ServerConfig::default(),
        }
    }

    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.config.bind_addr = addr;
        self
    }

    pub fn proxy_target(mut self, target: SocketAddr) -> Self {
        self.config.proxy_target = target;
        self
    }

    pub fn cert_pem(mut self, cert: Vec<u8>) -> Self {
        self.config.cert_pem = cert;
        self
    }

    pub fn key_pem(mut self, key: Vec<u8>) -> Self {
        self.config.key_pem = key;
        self
    }

    pub fn enable_multipath(mut self, enable: bool) -> Self {
        self.config.enable_multipath = enable;
        self
    }

    pub fn multipath_algorithm(mut self, alg: H3MultipathAlgorithm) -> Self {
        self.config.multipath_algorithm = alg;
        self
    }

    pub fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.config.idle_timeout_secs = secs;
        self
    }

    pub fn max_streams(mut self, max: u64) -> Self {
        self.config.max_streams = max;
        self
    }

    pub fn build(self) -> H3ServerConfig {
        self.config
    }
}

impl Default for H3ServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h3_server_config_default() {
        let config = H3ServerConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(config.proxy_target, "127.0.0.1:8080".parse().unwrap());
        assert!(!config.enable_multipath);
        assert_eq!(config.idle_timeout_secs, 30);
        assert_eq!(config.max_streams, 100);
    }

    #[test]
    fn test_h3_server_config_multipath() {
        let config = H3ServerConfig {
            enable_multipath: true,
            multipath_algorithm: H3MultipathAlgorithm::RoundRobin,
            ..Default::default()
        };
        assert!(config.enable_multipath);
        assert_eq!(config.multipath_algorithm, H3MultipathAlgorithm::RoundRobin);
    }

    #[test]
    fn test_h3_server_config_builder() {
        let config = H3ServerConfigBuilder::new()
            .bind_addr("0.0.0.0:8443".parse().unwrap())
            .proxy_target("127.0.0.1:3000".parse().unwrap())
            .enable_multipath(true)
            .multipath_algorithm(H3MultipathAlgorithm::Redundant)
            .idle_timeout_secs(60)
            .max_streams(200)
            .build();

        assert_eq!(config.bind_addr, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(config.proxy_target, "127.0.0.1:3000".parse().unwrap());
        assert!(config.enable_multipath);
        assert_eq!(config.multipath_algorithm, H3MultipathAlgorithm::Redundant);
        assert_eq!(config.idle_timeout_secs, 60);
        assert_eq!(config.max_streams, 200);
    }

    #[test]
    fn test_h3_server_stats_default() {
        let stats = H3ServerStats::default();
        assert_eq!(stats.connections_total, 0);
        assert_eq!(stats.connections_active, 0);
        assert_eq!(stats.requests_total, 0);
    }

    #[test]
    fn test_path_info() {
        let path = PathInfo {
            local_addr: "192.168.1.100:12345".parse().unwrap(),
            remote_addr: "10.0.0.1:4433".parse().unwrap(),
            rtt_ms: 25,
            active: true,
            bytes_sent: 1000,
            bytes_received: 2000,
        };
        assert!(path.active);
        assert_eq!(path.rtt_ms, 25);
    }

    #[test]
    fn test_multipath_algorithm_default() {
        let alg = H3MultipathAlgorithm::default();
        assert_eq!(alg, H3MultipathAlgorithm::MinRtt);
    }

    #[tokio::test]
    async fn test_h3_server_new() {
        let config = H3ServerConfig::default();
        let server = H3Server::new(config).unwrap();
        assert!(!server.is_running());
        assert!(!server.multipath_enabled());
    }

    #[tokio::test]
    async fn test_h3_server_with_defaults() {
        let server = H3Server::with_defaults(
            "127.0.0.1:4433".parse().unwrap(),
            "127.0.0.1:8080".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(server.config().bind_addr, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(
            server.config().proxy_target,
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn test_h3_server_stats() {
        let config = H3ServerConfig::default();
        let server = H3Server::new(config).unwrap();

        let stats = server.stats().await;
        assert_eq!(stats.connections_total, 0);
        assert_eq!(stats.requests_total, 0);
    }

    #[tokio::test]
    async fn test_h3_server_start_no_tls() {
        let config = H3ServerConfig::default();
        let server = H3Server::new(config).unwrap();

        // Should fail without TLS config
        let result = server.start().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Certificate"));
    }
}
