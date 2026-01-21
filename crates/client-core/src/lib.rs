//! Shared networking and business logic for the client.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Connection failed: {0}")]
    Connection(String),
}

/// Connection state shared across platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected { server: String },
    Error(String),
}

/// Core client handling proxy connections.
pub struct ProxyClient {
    state: ConnectionState,
    http: reqwest::Client,
}

impl ProxyClient {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            http: reqwest::Client::new(),
        }
    }

    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub async fn connect(&mut self, server: &str) -> Result<(), ClientError> {
        self.state = ConnectionState::Connecting;

        // TODO: Implement actual connection logic
        tracing::info!("Connecting to {}", server);

        self.state = ConnectionState::Connected {
            server: server.to_string(),
        };

        Ok(())
    }

    pub async fn disconnect(&mut self) {
        tracing::info!("Disconnecting");
        self.state = ConnectionState::Disconnected;
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
}
