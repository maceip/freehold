//! Shared networking and business logic for the client.
//!
//! This crate provides:
//! - H3/QUIC server with multipath support (via tquic)
//! - TCP reverse proxy for forwarding to local services
//! - Connection state management
//! - Platform-agnostic client callbacks

pub mod h3_server;
pub mod tcp_proxy;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("TLS error: {0}")]
    Tls(String),
}

/// Connection state shared across platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { server: String },
    Error(String),
}

/// Multipath configuration for the client.
#[derive(Debug, Clone)]
pub struct MultipathConfig {
    /// Enable multipath QUIC.
    pub enabled: bool,
    /// Network interfaces to use (empty = auto-detect).
    pub interfaces: Vec<String>,
    /// Scheduling algorithm.
    pub algorithm: MultipathAlgorithm,
}

/// Multipath scheduling algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultipathAlgorithm {
    /// Use the path with minimum RTT.
    #[default]
    MinRtt,
    /// Round-robin across all paths.
    RoundRobin,
    /// Redundant - send on all paths.
    Redundant,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            algorithm: MultipathAlgorithm::default(),
        }
    }
}

/// Core client handling proxy connections.
pub struct ProxyClient {
    state: ConnectionState,
    multipath: MultipathConfig,
}

impl ProxyClient {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            multipath: MultipathConfig::default(),
        }
    }

    /// Create with multipath configuration.
    pub fn with_multipath(multipath: MultipathConfig) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            multipath,
        }
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub fn multipath_config(&self) -> &MultipathConfig {
        &self.multipath
    }

    pub async fn connect(&mut self, server: &str) -> Result<(), ClientError> {
        self.state = ConnectionState::Connecting;

        tracing::info!("Connecting to {}", server);

        // TODO: Implement actual QUIC connection logic using tquic
        self.state = ConnectionState::Connected {
            server: server.to_string(),
        };

        Ok(())
    }

    pub async fn disconnect(&mut self) {
        tracing::info!("Disconnecting");
        self.state = ConnectionState::Disconnected;
    }

    /// Set multipath configuration.
    pub fn set_multipath(&mut self, config: MultipathConfig) {
        self.multipath = config;
    }

    /// Enable or disable multipath.
    pub fn enable_multipath(&mut self, enable: bool) {
        self.multipath.enabled = enable;
    }
}

impl Default for ProxyClient {
    fn default() -> Self {
        Self::new()
    }
}

/// UI callback trait that platforms implement.
pub trait ClientCallback: Send + Sync {
    fn on_state_changed(&self, state: &ConnectionState);
    fn on_multipath_status(&self, paths: &[PathInfo]) {
        // Default no-op
        let _ = paths;
    }
}

/// Information about a network path (for multipath status).
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Local interface name.
    pub interface: String,
    /// Local address.
    pub local_addr: std::net::SocketAddr,
    /// Remote address.
    pub remote_addr: std::net::SocketAddr,
    /// Round-trip time in milliseconds.
    pub rtt_ms: u64,
    /// Whether this path is active.
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state() {
        let state = ConnectionState::Connected {
            server: "example.com".to_string(),
        };
        assert!(matches!(state, ConnectionState::Connected { .. }));
    }

    #[test]
    fn test_multipath_config_default() {
        let config = MultipathConfig::default();
        assert!(!config.enabled);
        assert!(config.interfaces.is_empty());
        assert_eq!(config.algorithm, MultipathAlgorithm::MinRtt);
    }

    #[test]
    fn test_multipath_algorithm_values() {
        assert_eq!(MultipathAlgorithm::default(), MultipathAlgorithm::MinRtt);

        let rr = MultipathAlgorithm::RoundRobin;
        assert_eq!(rr, MultipathAlgorithm::RoundRobin);

        let redundant = MultipathAlgorithm::Redundant;
        assert_eq!(redundant, MultipathAlgorithm::Redundant);
    }

    #[test]
    fn test_proxy_client_new() {
        let client = ProxyClient::new();
        assert!(matches!(client.state(), ConnectionState::Disconnected));
        assert!(!client.multipath_config().enabled);
    }

    #[test]
    fn test_proxy_client_with_multipath() {
        let config = MultipathConfig {
            enabled: true,
            interfaces: vec!["eth0".to_string(), "wlan0".to_string()],
            algorithm: MultipathAlgorithm::RoundRobin,
        };
        let client = ProxyClient::with_multipath(config);
        assert!(client.multipath_config().enabled);
        assert_eq!(client.multipath_config().interfaces.len(), 2);
    }

    #[test]
    fn test_proxy_client_enable_multipath() {
        let mut client = ProxyClient::new();
        assert!(!client.multipath_config().enabled);
        client.enable_multipath(true);
        assert!(client.multipath_config().enabled);
    }

    #[test]
    fn test_path_info() {
        let path = PathInfo {
            interface: "eth0".to_string(),
            local_addr: "192.168.1.100:12345".parse().unwrap(),
            remote_addr: "10.0.0.1:4433".parse().unwrap(),
            rtt_ms: 25,
            active: true,
        };
        assert_eq!(path.interface, "eth0");
        assert!(path.active);
        assert_eq!(path.rtt_ms, 25);
    }

    #[tokio::test]
    async fn test_proxy_client_connect_disconnect() {
        let mut client = ProxyClient::new();

        client.connect("reflector.example.com").await.unwrap();
        assert!(matches!(client.state(), ConnectionState::Connected { .. }));

        client.disconnect().await;
        assert!(matches!(client.state(), ConnectionState::Disconnected));
    }
}
