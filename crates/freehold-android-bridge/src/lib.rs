//! Freehold Android Bridge
//!
//! UniFFI bindings for the Freehold client on Android.
//! Provides a Kotlin-accessible API for:
//! - QUIC tunnel management via Quinn
//! - H3 to H2/H1 proxy
//! - VPN packet processing
//!
//! # Architecture
//!
//! ```text
//! Android App (Kotlin)
//!     |
//!     v
//! VpnService (tun interface)
//!     |
//!     v
//! FreeholdTunnel (this crate via UniFFI)
//!     |
//!     +-- Engine (registration/heartbeat)
//!     |
//!     +-- H3Proxy (QUIC -> HTTP/1.1)
//!     |
//!     v
//! UDP Socket -> Relay Network
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use freehold_client_core::{
    generate_self_signed_cert, H3Proxy, H3ProxyConfig, RelayState, StatusUpdate,
};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};

// UniFFI scaffolding
uniffi::include_scaffolding!("freehold_android");

/// Global Tokio runtime
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Initialize the Rust runtime - call once at app start
pub fn init_runtime() {
    // Initialize Android logging
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("Freehold"),
    );

    let _ = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("freehold-worker")
            .build()
            .expect("Failed to create Tokio runtime")
    });

    tracing::info!("Freehold runtime initialized");
}

/// Shutdown the runtime
pub fn shutdown_runtime() {
    tracing::info!("Freehold runtime shutdown requested");
    // Runtime cleanup happens on drop
}

fn get_runtime() -> &'static Runtime {
    RUNTIME
        .get()
        .expect("Runtime not initialized - call init_runtime() first")
}

/// Connection state visible to Kotlin
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

impl From<RelayState> for ConnectionState {
    fn from(state: RelayState) -> Self {
        match state {
            RelayState::Disconnected => ConnectionState::Disconnected,
            RelayState::Pending => ConnectionState::Connecting,
            RelayState::Connected => ConnectionState::Connected,
        }
    }
}

/// Tunnel errors
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TunnelError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Runtime error: {0}")]
    RuntimeError(String),
    #[error("Proxy error: {0}")]
    ProxyError(String),
    #[error("Tunnel already running")]
    AlreadyRunning,
    #[error("Tunnel not running")]
    NotRunning,
}

impl From<anyhow::Error> for TunnelError {
    fn from(err: anyhow::Error) -> Self {
        TunnelError::RuntimeError(err.to_string())
    }
}

/// Status callback interface for Kotlin
#[uniffi::export(callback_interface)]
pub trait StatusCallback: Send + Sync {
    fn on_state_changed(&self, state: ConnectionState, message: String);
    fn on_port_assigned(&self, port: u16);
    fn on_neighbor_discovered(&self, ip: String);
    fn on_error(&self, error: String);
    fn on_bytes_transferred(&self, rx: u64, tx: u64);
}

/// Wrapper to make callback Arc-compatible for async use
struct CallbackWrapper(Box<dyn StatusCallback>);

// Safety: StatusCallback requires Send + Sync
unsafe impl Send for CallbackWrapper {}
unsafe impl Sync for CallbackWrapper {}

impl CallbackWrapper {
    fn on_state_changed(&self, state: ConnectionState, message: String) {
        self.0.on_state_changed(state, message);
    }
    fn on_port_assigned(&self, port: u16) {
        self.0.on_port_assigned(port);
    }
    fn on_neighbor_discovered(&self, ip: String) {
        self.0.on_neighbor_discovered(ip);
    }
    fn on_error(&self, error: String) {
        self.0.on_error(error);
    }
    fn on_bytes_transferred(&self, rx: u64, tx: u64) {
        self.0.on_bytes_transferred(rx, tx);
    }
}

/// Tunnel configuration from Kotlin
#[derive(Debug, Clone, uniffi::Record)]
pub struct TunnelConfig {
    pub relay_address: String,
    pub relay_port: u16,
    pub local_port: u16,
    pub backend_address: String,
    pub auto_discover: bool,
}

/// The main Freehold tunnel - wraps Engine and handles VPN integration
#[derive(uniffi::Object)]
pub struct FreeholdTunnel {
    config: TunnelConfig,
    callback: Arc<CallbackWrapper>,
    running: Arc<AtomicBool>,
    state: Mutex<ConnectionState>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
}

#[uniffi::export]
impl FreeholdTunnel {
    /// Create a new tunnel instance
    #[uniffi::constructor]
    pub fn new(config: TunnelConfig, callback: Box<dyn StatusCallback>) -> Self {
        Self {
            config,
            callback: Arc::new(CallbackWrapper(callback)),
            running: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(ConnectionState::Disconnected),
            shutdown_tx: Mutex::new(None),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            tx_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the tunnel
    /// `vpn_fd` is the file descriptor from Android VpnService
    pub fn start(&self, vpn_fd: i32) -> Result<(), TunnelError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(TunnelError::AlreadyRunning);
        }

        let relay_addr: SocketAddr = format!("{}:{}", self.config.relay_address, 9999)
            .parse()
            .map_err(|e| TunnelError::ConfigError(format!("Invalid relay address: {}", e)))?;

        let h3_bind: SocketAddr = format!("0.0.0.0:{}", self.config.local_port)
            .parse()
            .map_err(|e| TunnelError::ConfigError(format!("Invalid bind address: {}", e)))?;

        let backend: SocketAddr = self
            .config
            .backend_address
            .parse()
            .map_err(|e| TunnelError::ConfigError(format!("Invalid backend address: {}", e)))?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        // Create status channel
        let (status_tx, mut status_rx) = mpsc::channel::<StatusUpdate>(100);

        // Clone callback for status updates
        let callback = Arc::clone(&self.callback);
        let state_ref = self.state.lock().unwrap();
        drop(state_ref);

        // Spawn status handler
        let callback_clone = Arc::clone(&self.callback);
        let _running = Arc::clone(&self.running);
        get_runtime().spawn(async move {
            while let Some(update) = status_rx.recv().await {
                match update {
                    StatusUpdate::RelayState { addr, state } => {
                        let conn_state = ConnectionState::from(state);
                        callback_clone
                            .on_state_changed(conn_state, format!("Relay {} -> {:?}", addr, state));
                    }
                    StatusUpdate::NeighborDiscovered(ip) => {
                        callback_clone.on_neighbor_discovered(ip.to_string());
                    }
                    StatusUpdate::Error(msg) => {
                        callback_clone.on_error(msg);
                    }
                    StatusUpdate::Traffic { sent, received } => {
                        callback_clone.on_bytes_transferred(received, sent);
                    }
                    StatusUpdate::PortChanged { port } => {
                        callback_clone.on_port_assigned(port);
                    }
                    StatusUpdate::SubdomainAssigned(_) | StatusUpdate::AcmeCertReady => {}
                }
            }
        });

        // Generate self-signed cert for H3 proxy
        let domain = format!("{}.freehold.local", self.config.relay_port);
        let (certs, key) = generate_self_signed_cert(&[&domain])
            .map_err(|e| TunnelError::ConfigError(format!("Cert generation failed: {}", e)))?;

        // Create and run the service
        let service = freehold_client_core::Service::new(
            freehold_client_core::ServiceConfig {
                relay: relay_addr,
                relay_port: self.config.relay_port,
                h3_bind,
                backend,
                certs,
                key,
                auto_discover: self.config.auto_discover,
                acme_cache_dir: None,
                dns_zone: None,
            },
            status_tx,
        )
        .map_err(|e| TunnelError::RuntimeError(format!("Service creation failed: {}", e)))?;

        callback.on_state_changed(ConnectionState::Connecting, "Starting tunnel...".into());
        callback.on_port_assigned(self.config.relay_port);

        // Run service in background
        let callback_final = Arc::clone(&self.callback);
        let running_flag = Arc::new(AtomicBool::new(true));
        let running_clone = running_flag.clone();

        get_runtime().spawn(async move {
            match service.run(shutdown_rx).await {
                Ok(_) => {
                    callback_final
                        .on_state_changed(ConnectionState::Disconnected, "Tunnel stopped".into());
                }
                Err(e) => {
                    callback_final.on_error(format!("Tunnel error: {}", e));
                    callback_final.on_state_changed(ConnectionState::Error, e.to_string());
                }
            }
            running_clone.store(false, Ordering::SeqCst);
        });

        tracing::info!("Tunnel started with VPN fd: {}", vpn_fd);
        Ok(())
    }

    /// Stop the tunnel
    pub fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(true);
        }
        self.running.store(false, Ordering::SeqCst);
        *self.state.lock().unwrap() = ConnectionState::Disconnected;
        self.callback
            .on_state_changed(ConnectionState::Disconnected, "Stopped".into());
        tracing::info!("Tunnel stopped");
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get current connection state
    pub fn get_state(&self) -> ConnectionState {
        *self.state.lock().unwrap()
    }

    /// Get assigned relay port
    pub fn get_port(&self) -> u16 {
        self.config.relay_port
    }

    /// Process outbound packet from VPN interface
    /// The VPN service reads packets from the TUN and passes them here
    pub fn process_outbound(&self, packet: Vec<u8>) -> Result<Vec<u8>, TunnelError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(TunnelError::NotRunning);
        }

        self.tx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        // In a "fake VPN" setup, we intercept the packet and could:
        // 1. Parse IP headers to determine destination
        // 2. Route through our QUIC tunnel
        // For now, we pass through - the H3 proxy handles the actual proxying
        Ok(packet)
    }

    /// Process inbound packet from QUIC tunnel
    pub fn process_inbound(&self, packet: Vec<u8>) -> Result<Vec<u8>, TunnelError> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(TunnelError::NotRunning);
        }

        self.rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Ok(packet)
    }

    /// Get statistics [rx_bytes, tx_bytes]
    pub fn get_stats(&self) -> Vec<u64> {
        vec![
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
        ]
    }
}

/// H3 Proxy bridge for direct proxy access
#[derive(uniffi::Object)]
pub struct H3ProxyBridge {
    bind_address: SocketAddr,
    backend_address: SocketAddr,
    domain: String,
    running: Arc<AtomicBool>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
}

#[uniffi::export]
impl H3ProxyBridge {
    /// Create proxy with self-signed certificate
    #[uniffi::constructor]
    pub fn new(
        bind_address: String,
        backend_address: String,
        domain: String,
    ) -> Result<Self, TunnelError> {
        let bind_addr: SocketAddr = bind_address
            .parse()
            .map_err(|e| TunnelError::ConfigError(format!("Invalid bind address: {}", e)))?;

        let backend_addr: SocketAddr = backend_address
            .parse()
            .map_err(|e| TunnelError::ConfigError(format!("Invalid backend address: {}", e)))?;

        Ok(Self {
            bind_address: bind_addr,
            backend_address: backend_addr,
            domain,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: Mutex::new(None),
        })
    }

    /// Start the proxy
    pub fn start(&self) -> Result<(), TunnelError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(TunnelError::AlreadyRunning);
        }

        let (certs, key) = generate_self_signed_cert(&[&self.domain])
            .map_err(|e| TunnelError::ConfigError(format!("Cert generation failed: {}", e)))?;

        let proxy = H3Proxy::new(H3ProxyConfig {
            bind_addr: self.bind_address,
            backend: self.backend_address,
            certs,
            key,
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        let running = Arc::clone(&self.running);
        get_runtime().spawn(async move {
            if let Err(e) = proxy.run(shutdown_rx).await {
                tracing::error!("H3 proxy error: {}", e);
            }
            running.store(false, Ordering::SeqCst);
        });

        tracing::info!("H3 proxy started on {}", self.bind_address);
        Ok(())
    }

    /// Stop the proxy
    pub fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(true);
        }
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("H3 proxy stopped");
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}
