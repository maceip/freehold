//! Freehold Android Bridge
//!
//! UniFFI bindings for the Freehold client on Android.
//! Provides a Kotlin-accessible API for:
//! - QUIC tunnel management via Quinn
//! - H3 to H2/H1 proxy
//! - VPN packet processing
//! - WebTransport client (direct QUIC/H3 bidirectional streaming)
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
//!     +-- WebTransportClient (QUIC/H3 bidi streams)
//!     |
//!     v
//! UDP Socket -> Relay Network
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// AndroidSocket — UDP socket wrapper that skips ECN (IP_TOS cmsg)
//
// Android denies sendmsg with IP_TOS unless the app has CAP_NET_ADMIN.
// Quinn sets ECN bits via cmsg, which triggers EPERM.  This wrapper uses
// plain send_to/recv_from so ECN is never attempted.
// ---------------------------------------------------------------------------

mod android_socket {
    use std::fmt;
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{ready, Context, Poll};

    use quinn::udp::RecvMeta;
    use quinn::{AsyncUdpSocket, UdpPoller};

    pub(crate) struct AndroidSocket {
        io: Arc<tokio::net::UdpSocket>,
    }

    impl fmt::Debug for AndroidSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AndroidSocket")
                .field("local_addr", &self.io.local_addr())
                .finish()
        }
    }

    impl AndroidSocket {
        pub(crate) fn new(io: Arc<tokio::net::UdpSocket>) -> Self {
            Self { io }
        }
    }

    impl AsyncUdpSocket for AndroidSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            let io = self.io.clone();
            Box::pin(Poller { io, fut: None })
        }

        fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
            // Plain send_to — no cmsg, no ECN, no EPERM
            let result = self.io
                .try_send_to(transmit.contents, transmit.destination);
            match &result {
                Ok(n) => tracing::info!(
                    "AndroidSocket: SENT {} bytes to {} (payload {})",
                    n, transmit.destination, transmit.contents.len()
                ),
                Err(e) => tracing::warn!(
                    "AndroidSocket: SEND FAILED to {}: {:?}",
                    transmit.destination, e
                ),
            }
            result.map(|_| ())
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            loop {
                ready!(self.io.poll_recv_ready(cx))?;
                match self.io.try_recv_from(&mut bufs[0]) {
                    Ok((len, addr)) => {
                        tracing::debug!(
                            "AndroidSocket: RECV {} bytes from {}",
                            len, addr
                        );
                        meta[0] = RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.io.local_addr()
        }
    }

    struct Poller {
        io: Arc<tokio::net::UdpSocket>,
        #[allow(clippy::type_complexity)]
        fut: Option<Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + Sync>>>,
    }

    impl fmt::Debug for Poller {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Poller").finish_non_exhaustive()
        }
    }

    impl UdpPoller for Poller {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.fut.is_none() {
                let io = this.io.clone();
                this.fut = Some(Box::pin(async move { io.writable().await }));
            }
            let result = this.fut.as_mut().unwrap().as_mut().poll(cx);
            if result.is_ready() {
                this.fut = None;
            }
            result
        }
    }
}

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

// ---------------------------------------------------------------------------
// WebTransportClient — QUIC/H3 bidi streaming for Kotlin
// ---------------------------------------------------------------------------

/// Callback interface for WebTransport events (Kotlin side)
#[uniffi::export(callback_interface)]
pub trait WebTransportCallback: Send + Sync {
    fn on_connected(&self);
    fn on_message(&self, data: String);
    fn on_disconnected(&self, reason: String);
    fn on_error(&self, error: String);
}

struct WtCallbackWrapper(Box<dyn WebTransportCallback>);
unsafe impl Send for WtCallbackWrapper {}
unsafe impl Sync for WtCallbackWrapper {}

impl WtCallbackWrapper {
    fn on_connected(&self) { self.0.on_connected(); }
    fn on_message(&self, data: String) { self.0.on_message(data); }
    fn on_disconnected(&self, reason: String) { self.0.on_disconnected(reason); }
    fn on_error(&self, error: String) { self.0.on_error(error); }
}

/// WebTransport client — connects to a WT server over QUIC/H3.
///
/// Usage from Kotlin:
/// ```kotlin
/// val client = WebTransportClient(callback)
/// client.connect("https://huqm733bnbdp.freehold.lit.app:55126/wt")
/// client.send("{\"agent\":\"gemini\",\"action\":\"create_note\"}")
/// client.close()
/// ```
#[derive(uniffi::Object)]
pub struct WebTransportClient {
    callback: Arc<WtCallbackWrapper>,
    connected: Arc<AtomicBool>,
    /// Sender for outbound messages to the bidi stream writer task
    msg_tx: Mutex<Option<tokio::sync::mpsc::Sender<String>>>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
}

#[uniffi::export]
impl WebTransportClient {
    #[uniffi::constructor]
    pub fn new(callback: Box<dyn WebTransportCallback>) -> Self {
        Self {
            callback: Arc::new(WtCallbackWrapper(callback)),
            connected: Arc::new(AtomicBool::new(false)),
            msg_tx: Mutex::new(None),
            shutdown_tx: Mutex::new(None),
        }
    }

    /// Connect to a WebTransport server.
    ///
    /// `url` should be like `https://host:port/path`
    pub fn connect(&self, url: String) -> Result<(), TunnelError> {
        if self.connected.load(Ordering::SeqCst) {
            return Err(TunnelError::AlreadyRunning);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.shutdown_tx.lock().unwrap() = Some(shutdown_tx);

        let (msg_tx, msg_rx) = tokio::sync::mpsc::channel::<String>(64);
        *self.msg_tx.lock().unwrap() = Some(msg_tx);

        let callback = Arc::clone(&self.callback);
        let connected = Arc::clone(&self.connected);
        let url_clone = url.clone();

        get_runtime().spawn(async move {
            match wt_connect_and_run(url_clone, callback.clone(), msg_rx, shutdown_rx).await {
                Ok(()) => {
                    connected.store(false, Ordering::SeqCst);
                    callback.on_disconnected("closed".into());
                }
                Err(e) => {
                    connected.store(false, Ordering::SeqCst);
                    callback.on_error(format!("{:?}", e));
                    callback.on_disconnected(format!("error: {}", e));
                }
            }
        });

        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Send a text message on the bidi stream.
    pub fn send(&self, data: String) -> Result<(), TunnelError> {
        let tx = self.msg_tx.lock().unwrap();
        if let Some(tx) = tx.as_ref() {
            tx.try_send(data)
                .map_err(|e| TunnelError::NetworkError(format!("send failed: {}", e)))?;
            Ok(())
        } else {
            Err(TunnelError::NotRunning)
        }
    }

    /// Disconnect from the server.
    pub fn disconnect(&self) {
        if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(true);
        }
        *self.msg_tx.lock().unwrap() = None;
        self.connected.store(false, Ordering::SeqCst);
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }
}

/// Internal: connect to WT server, open bidi stream, pump messages.
async fn wt_connect_and_run(
    url: String,
    callback: Arc<WtCallbackWrapper>,
    mut msg_rx: tokio::sync::mpsc::Receiver<String>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    use anyhow::Context;
    use std::future::poll_fn;

    // Parse URL
    let parsed: http::Uri = url.parse().context("invalid URL")?;
    let host = parsed.host().context("no host in URL")?;
    let port = parsed.port_u16().unwrap_or(443);
    let path = parsed
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Resolve relay address — try subdomain first, fall back to parent domain
    // (carrier DNS may cache NXDOMAIN for newly created subdomains)
    let addr: SocketAddr = match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
        Ok(mut addrs) => {
            let a = addrs.next().context("no addresses resolved")?;
            tracing::info!("DNS resolved {} -> {}", host, a);
            a
        }
        Err(e) => {
            tracing::warn!("DNS lookup for {} failed: {}, trying parent domain", host, e);
            // Extract parent domain (e.g. "freehold.lit.app" from "xyz.freehold.lit.app")
            let parent = host.find('.').map(|i| &host[i + 1..]).unwrap_or(host);
            let fallback: SocketAddr = tokio::net::lookup_host(format!("{}:{}", parent, port))
                .await
                .context(format!("DNS fallback lookup for {} also failed", parent))?
                .next()
                .context("no addresses in fallback")?;
            tracing::info!("DNS fallback {} -> {}", parent, fallback);
            fallback
        }
    };

    // Resolve the .home. subdomain to get the server's direct IP + NAT port.
    // ALWAYS query the relay's HTTPS SVCB record for the correct NAT-mapped port,
    // since system DNS A records don't include port info and the URL port (55126)
    // won't match the server's actual NAT-mapped external port.
    let home_addr: Option<SocketAddr> = if let Some(dot_pos) = host.find('.') {
        let id = &host[..dot_pos];
        let rest = &host[dot_pos + 1..];
        let home_host = format!("{}.home.{}", id, rest);
        let home_fqdn = format!("{}.freehold.lit.app", id);

        // Query relay's HTTPS record for the correct port
        let svcb = dns_query_https(&home_fqdn, addr.ip()).await;
        let svcb_port = svcb.as_ref().and_then(|(_, p)| *p);
        let svcb_ip = svcb.as_ref().and_then(|(ip, _)| *ip);

        // Get IP: prefer SVCB ipv4hint, then system DNS, then relay A record
        let home_ip = if let Some(ip) = svcb_ip {
            Some(ip)
        } else {
            match tokio::net::lookup_host(format!("{}:{}", home_host, port)).await {
                Ok(mut addrs) => addrs.next().and_then(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                }),
                Err(_) => dns_query_a(&home_host, addr.ip()).await,
            }
        };

        match home_ip {
            Some(ip) => {
                let home_port = svcb_port.unwrap_or(port);
                let sa = SocketAddr::new(ip.into(), home_port);
                tracing::info!("Home resolved {} -> {} (SVCB port: {:?})", home_host, sa, svcb_port);
                Some(sa)
            }
            None => {
                tracing::debug!("Home DNS failed for {} (continuing without)", home_host);
                None
            }
        }
    } else {
        None
    };

    // Build rustls client config that trusts everything (for self-signed certs)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| anyhow::anyhow!("QUIC client config: {}", e))?,
    ));

    // Transport config: keep-alive and reasonable timeout for mobile
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .map_err(|e| anyhow::anyhow!("idle timeout: {}", e))?,
    ));
    client_config.transport_config(Arc::new(transport));

    // NAT hole-punch connection strategy:
    //
    // Alice (phone) connects to BOTH relay and .home simultaneously using
    // SEPARATE UDP sockets.  This is critical because:
    //
    // 1. The relay does XDP DNAT — rewrites destination to Bob but preserves
    //    Alice's source IP.  Bob's response comes from Bob's IP directly.
    //
    // 2. If Alice uses ONE socket, her carrier NAT creates a mapping like:
    //    (Alice:60655 → relay:55126).  Bob's response from a different IP
    //    gets dropped by endpoint-dependent filtering.
    //
    // 3. With SEPARATE sockets, Alice's .home socket creates its own mapping:
    //    (Alice:XXXXX → Bob:47547).  When Bob responds from Bob:47547,
    //    Alice's NAT accepts it because Alice initiated to that exact IP:port.
    //
    // The relay-path packet triggers the Punch mechanism (relay tells Bob to
    // poke Alice, opening Bob's NAT).  The .home-path keeps retransmitting
    // QUIC Initials until Bob's NAT opens.
    let connection = {
        let timeout = std::time::Duration::from_secs(60);
        tracing::info!("QUIC connecting to relay {} and home {:?}", addr, home_addr);

        if let Some(home) = home_addr {
            // Create separate endpoints with AndroidSocket (no ECN — avoids EPERM)
            let relay_endpoint = make_android_endpoint(client_config.clone())?;
            let home_endpoint = make_android_endpoint(client_config)?;

            let relay_connecting = relay_endpoint.connect(addr, host)
                .map_err(|e| anyhow::anyhow!("relay connect: {}", e))?;
            let home_connecting = home_endpoint.connect(home, host)
                .map_err(|e| anyhow::anyhow!("home connect: {}", e))?;

            tokio::pin!(relay_connecting);
            tokio::pin!(home_connecting);

            let mut relay_done = false;
            let mut home_done = false;
            let deadline = tokio::time::Instant::now() + timeout;

            loop {
                tokio::select! {
                    result = &mut relay_connecting, if !relay_done => {
                        match result {
                            Ok(conn) => {
                                tracing::info!("Connected via relay {}", addr);
                                break conn;
                            }
                            Err(e) => {
                                tracing::debug!("Relay path failed: {:?} (expected — waiting for .home)", e);
                                relay_done = true;
                                if home_done {
                                    return Err(anyhow::anyhow!("both relay and home connections failed"));
                                }
                            }
                        }
                    }
                    result = &mut home_connecting, if !home_done => {
                        match result {
                            Ok(conn) => {
                                tracing::info!("Connected directly to home {}", home);
                                break conn;
                            }
                            Err(e) => {
                                tracing::debug!("Home path failed: {:?}", e);
                                home_done = true;
                                if relay_done {
                                    return Err(anyhow::anyhow!("both relay and home connections failed"));
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(anyhow::anyhow!("connection timed out after {}s (relay_done={}, home_done={})",
                            timeout.as_secs(), relay_done, home_done));
                    }
                }
            }
        } else {
            // No home address — relay only
            let endpoint = make_android_endpoint(client_config)?;
            let relay_connecting = endpoint.connect(addr, host)
                .map_err(|e| anyhow::anyhow!("relay connect: {}", e))?;
            tokio::time::timeout(timeout, relay_connecting)
                .await
                .map_err(|_| anyhow::anyhow!("QUIC connect timeout ({}s) to {}", timeout.as_secs(), addr))?
                .map_err(|e| anyhow::anyhow!("QUIC connect: {}", e))?
        }
    };

    tracing::info!("QUIC connection established");

    // Build H3 client connection — advertise WT + datagram + extended-connect
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_webtransport(true)
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| anyhow::anyhow!("H3 handshake: {:?}", e))?;

    // Drive the H3 connection in background
    tokio::spawn(async move {
        let _err = poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::debug!("H3 connection closed");
    });

    // Send CONNECT request for WebTransport (needs full URI with authority)
    let wt_uri = format!("https://{}:{}{}", host, port, path);
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(wt_uri)
        .header("sec-webtransport-http3-draft", "draft02")
        .extension(h3::ext::Protocol::WEB_TRANSPORT)
        .body(())
        .context("build CONNECT request")?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| anyhow::anyhow!("send CONNECT: {:?}", e))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("recv response: {:?}", e))?;

    if response.status() != http::StatusCode::OK {
        anyhow::bail!("Server rejected WebTransport: {}", response.status());
    }

    tracing::info!("WebTransport session established");
    callback.on_connected();

    // Use the CONNECT stream as a bidi channel
    let (mut h3_send, mut h3_recv) = stream.split();

    loop {
        tokio::select! {
            // Read from server
            data = h3_recv.recv_data() => {
                match data {
                    Ok(Some(mut buf)) => {
                        use bytes::Buf;
                        let data = buf.chunk().to_vec();
                        buf.advance(buf.remaining());
                        if let Ok(text) = String::from_utf8(data) {
                            callback.on_message(text);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("Read error: {:?}", e);
                        break;
                    }
                }
            }
            // Send to server
            msg = msg_rx.recv() => {
                match msg {
                    Some(text) => {
                        if h3_send.send_data(bytes::Bytes::from(text)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            // Shutdown
            _ = shutdown_rx.changed() => {
                break;
            }
        }
    }

    h3_send.finish().await.ok();
    Ok(())
}

/// Send a raw DNS query and return the response buffer.
async fn dns_raw_query(name: &str, qtype: u16, dns_server: std::net::IpAddr) -> Option<(Vec<u8>, usize)> {
    use tokio::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(SocketAddr::new(dns_server, 53)).await.ok()?;

    let mut pkt = Vec::with_capacity(512);
    // Header: ID=0xABCD, flags=0x0100 (standard query, RD=1), QDCOUNT=1
    pkt.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    sock.send(&pkt).await.ok()?;

    let mut buf = vec![0u8; 512];
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf)).await;
    let n = timeout.ok()?.ok()?;
    if n < 12 { return None; }
    Some((buf, n))
}

/// Skip a DNS wire-format name, return new position.
fn dns_skip_name(buf: &[u8], mut pos: usize, n: usize) -> usize {
    while pos < n {
        let len = buf[pos] as usize;
        if len == 0 { return pos + 1; }
        if len >= 0xC0 { return pos + 2; } // pointer
        pos += 1 + len;
    }
    pos
}

/// Minimal DNS A record query — sends a UDP query to `dns_server:53` and
/// parses the response to extract the first A record.
async fn dns_query_a(name: &str, dns_server: std::net::IpAddr) -> Option<std::net::Ipv4Addr> {
    let (buf, n) = dns_raw_query(name, 1, dns_server).await?; // QTYPE=A=1
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 { return None; }

    // Skip header + question
    let mut pos = dns_skip_name(&buf, 12, n);
    pos += 4; // QTYPE + QCLASS

    for _ in 0..ancount {
        if pos + 12 > n { break; }
        pos = dns_skip_name(&buf, pos, n); // skip NAME
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlength == 4 && pos + 4 <= n {
            return Some(std::net::Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]));
        }
        pos += rdlength;
    }
    None
}

/// Query HTTPS/SVCB record (type 65) to extract the port from SvcParams.
/// Returns (ip_from_ipv4hint, port) if available.
async fn dns_query_https(name: &str, dns_server: std::net::IpAddr) -> Option<(Option<std::net::Ipv4Addr>, Option<u16>)> {
    let (buf, n) = dns_raw_query(name, 65, dns_server).await?; // QTYPE=HTTPS=65
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 { return None; }

    // Skip header + question
    let mut pos = dns_skip_name(&buf, 12, n);
    pos += 4; // QTYPE + QCLASS

    for _ in 0..ancount {
        if pos + 12 > n { break; }
        pos = dns_skip_name(&buf, pos, n); // skip NAME
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        let rdata_end = pos + rdlength;
        if rtype == 65 && rdata_end <= n {
            // SVCB RDATA: 2 bytes priority + TargetName + SvcParams
            let _priority = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            // Skip TargetName
            pos = dns_skip_name(&buf, pos, n);
            // Parse SvcParams: key(2) + length(2) + value(length)
            let mut port = None;
            let mut ipv4 = None;
            while pos + 4 <= rdata_end {
                let key = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                let vlen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
                pos += 4;
                if pos + vlen > rdata_end { break; }
                match key {
                    3 if vlen == 2 => { // port
                        port = Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
                    }
                    4 if vlen >= 4 => { // ipv4hint
                        ipv4 = Some(std::net::Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]));
                    }
                    _ => {}
                }
                pos += vlen;
            }
            return Some((ipv4, port));
        }
        pos = rdata_end;
    }
    None
}

/// Create a Quinn client endpoint using AndroidSocket (no ECN, no EPERM).
fn make_android_endpoint(
    client_config: quinn::ClientConfig,
) -> anyhow::Result<quinn::Endpoint> {
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    std_socket.set_nonblocking(true)?;
    let tokio_socket = Arc::new(
        tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|e| anyhow::anyhow!("tokio socket: {}", e))?,
    );
    let socket = Arc::new(android_socket::AndroidSocket::new(tokio_socket));
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None, // client only
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| anyhow::anyhow!("quinn endpoint: {}", e))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Accepts any TLS certificate (for self-signed certs during development).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
