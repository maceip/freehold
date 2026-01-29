//! Shared networking and business logic for the heartbeat client.
//!
//! This crate provides:
//! - H3/QUIC reverse proxy server (via quinn)
//! - TCP proxy client for forwarding to local backends
//! - Connection state management
//! - ACME DNS-01 certificate automation

pub mod acme;
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

/// UI callback trait that platforms implement.
pub trait ClientCallback: Send + Sync {
    fn on_state_changed(&self, state: &ConnectionState);
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
}
