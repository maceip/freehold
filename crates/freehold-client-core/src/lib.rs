//! Freehold Client Core - The headless "Engine"
//!
//! Handles registration, heartbeat, neighbor discovery, H3 proxy, and
//! automatic ACME certificate management with dual-path DNS.
//! Platform-specific UI crates call into this.
//!
//! When `acme` feature + `dns_zone` are set, the ACME task constructs
//! three FQDNs from the relay-assigned subdomain hash and obtains a
//! multi-SAN TLS certificate covering the primary, `.relay`, and `.home`
//! subdomains.
//!
//! # Architecture
//!
//! When using `Service`, Engine and Quinn share a single UDP socket via
//! `DemuxSocket`.  Packets with magic byte `0x46` go to Engine; everything
//! else (QUIC) goes to Quinn.  One port, one registration, zero mux code
//! in the customer's app.
//!
//! ```text
//! Alice (Browser) --H3/QUIC--> Relay --UDP--> DemuxSocket
//!                                                 |
//!                                     +-----------+-----------+
//!                                     |                       |
//!                                 0x46 msgs               QUIC pkts
//!                                     |                       |
//!                                  Engine              Quinn/H3Proxy
//!                                (heartbeat)            (HTTP proxy)
//!                                     |                       |
//!                                     +--------> Backend <----+
//! ```

pub mod state;

#[cfg(feature = "acme")]
pub mod acme;

use anyhow::Result;
use freehold_api::{timing, ConfirmAction, Message, COOKIE_SIZE};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Instant;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

#[cfg(feature = "h3-proxy")]
pub use freehold_h3_proxy::{
    generate_self_signed_cert, make_quinn_server_config, serve_h3, CertificateDer, H3Proxy,
    H3ProxyConfig, PrivateKeyDer,
};

// ---------------------------------------------------------------------------
// DemuxSocket — shared UDP socket that filters Freehold protocol from QUIC
// ---------------------------------------------------------------------------

#[cfg(feature = "h3-proxy")]
mod demux {
    use std::fmt;
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{ready, Context, Poll};

    use quinn::udp::RecvMeta;
    use quinn::{AsyncUdpSocket, UdpPoller};
    use tokio::sync::mpsc;

    /// A UDP socket that filters Freehold protocol messages (magic `0x46`),
    /// diverting them to the Engine channel while passing QUIC packets to Quinn.
    pub(crate) struct DemuxSocket {
        io: Arc<tokio::net::UdpSocket>,
        freehold_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    }

    impl fmt::Debug for DemuxSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DemuxSocket")
                .field("local_addr", &self.io.local_addr())
                .finish()
        }
    }

    impl DemuxSocket {
        pub(crate) fn new(
            io: Arc<tokio::net::UdpSocket>,
            freehold_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
        ) -> Self {
            Self { io, freehold_tx }
        }
    }

    impl AsyncUdpSocket for DemuxSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            let io = self.io.clone();
            Box::pin(DemuxPoller { io, fut: None })
        }

        fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
            self.io
                .try_send_to(transmit.contents, transmit.destination)
                .map(|_| ())
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            loop {
                ready!(self.io.poll_recv_ready(cx))?;
                // Receive into caller's buffer, then inspect byte 0
                match self.io.try_recv_from(&mut bufs[0]) {
                    Ok((len, addr)) => {
                        if len > 0 && bufs[0][0] == 0x46 {
                            // Freehold protocol — send to Engine, keep reading
                            let _ = self.freehold_tx.send((bufs[0][..len].to_vec(), addr));
                            continue;
                        }
                        // QUIC packet — return to Quinn
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

    // -- Poller for write-readiness ------------------------------------------

    struct DemuxPoller {
        io: Arc<tokio::net::UdpSocket>,
        #[allow(clippy::type_complexity)]
        fut: Option<Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + Sync>>>,
    }

    impl fmt::Debug for DemuxPoller {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DemuxPoller").finish_non_exhaustive()
        }
    }

    impl UdpPoller for DemuxPoller {
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

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Relay connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    Disconnected,
    Pending,
    Connected,
}

/// Status update sent to UI
#[derive(Debug, Clone)]
pub enum StatusUpdate {
    RelayState {
        addr: SocketAddr,
        state: RelayState,
    },
    NeighborDiscovered(Ipv4Addr),
    Error(String),
    /// Traffic stats update (bytes sent, bytes received)
    Traffic {
        sent: u64,
        received: u64,
    },
    /// Port changed (new endpoint requested)
    PortChanged {
        port: u16,
    },
    /// Subdomain assigned by relay (e.g. "a7xk2m.freehold.lit.app")
    SubdomainAssigned(String),
    /// ACME certificate obtained and hot-swapped
    AcmeCertReady,
}

/// Command sent from UI/ACME task to engine
#[derive(Debug, Clone)]
pub enum EngineCommand {
    /// Request a new endpoint (change port)
    NewEndpoint,
    /// Shutdown the engine
    Shutdown,
    /// Request DNS A + HTTPS record creation (send CreateRecords to relay)
    RequestDns,
    /// Set ACME DNS-01 TXT record (send SetTxt to relay)
    SetAcmeTxt(Vec<u8>),
    /// Clear ACME DNS-01 TXT record (send ClearTxt to relay)
    ClearAcmeTxt,
}

/// Relay connection tracking
struct Relay {
    addr: SocketAddr,
    state: RelayState,
    cookie: Option<[u8; COOKIE_SIZE]>,
    subdomain: Option<String>,
    last_activity: Instant,
}

/// The Freehold client engine
pub struct Engine {
    socket: UdpSocket,
    port: u16,
    relays: Vec<Relay>,
    neighbors: HashSet<Ipv4Addr>,
    status_tx: mpsc::Sender<StatusUpdate>,
    command_rx: Option<mpsc::Receiver<EngineCommand>>,
    /// When set, Engine receives protocol messages from the DemuxSocket channel
    /// instead of reading the socket directly.
    msg_rx: Option<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    auto_discover: bool,
    bytes_sent: u64,
    bytes_received: u64,
    /// Watch channel for notifying ACME task of subdomain assignment
    subdomain_tx: watch::Sender<Option<String>>,
    /// Track last notified subdomain to avoid duplicate notifications
    last_subdomain: Option<String>,
}

impl Engine {
    /// Create a new engine (standalone — binds its own socket).
    pub fn new(
        initial_relay: SocketAddr,
        port: u16,
        auto_discover: bool,
        status_tx: mpsc::Sender<StatusUpdate>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;

        Ok(Self::from_parts(
            socket,
            initial_relay,
            port,
            auto_discover,
            status_tx,
            None,
        ))
    }

    /// Create an engine that shares a socket with a DemuxSocket.
    ///
    /// `send_socket` is a `try_clone()`-d handle to the same OS socket that
    /// DemuxSocket reads from.  Engine uses it **only** for sending.
    /// Incoming Freehold messages arrive via `msg_rx` (fed by DemuxSocket).
    pub fn new_demuxed(
        send_socket: UdpSocket,
        initial_relay: SocketAddr,
        port: u16,
        auto_discover: bool,
        status_tx: mpsc::Sender<StatusUpdate>,
        msg_rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    ) -> Self {
        Self::from_parts(
            send_socket,
            initial_relay,
            port,
            auto_discover,
            status_tx,
            Some(msg_rx),
        )
    }

    fn from_parts(
        socket: UdpSocket,
        initial_relay: SocketAddr,
        port: u16,
        auto_discover: bool,
        status_tx: mpsc::Sender<StatusUpdate>,
        msg_rx: Option<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    ) -> Self {
        let (subdomain_tx, _) = watch::channel(None);
        Self {
            socket,
            port,
            relays: vec![Relay {
                addr: initial_relay,
                state: RelayState::Disconnected,
                cookie: None,
                subdomain: None,
                last_activity: Instant::now() - timing::HEARTBEAT_INTERVAL,
            }],
            neighbors: HashSet::new(),
            status_tx,
            command_rx: None,
            msg_rx,
            auto_discover,
            bytes_sent: 0,
            bytes_received: 0,
            subdomain_tx,
            last_subdomain: None,
        }
    }

    /// Get a watch receiver for subdomain assignments (used by ACME task)
    pub fn subdomain_rx(&self) -> watch::Receiver<Option<String>> {
        self.subdomain_tx.subscribe()
    }

    /// Create a new engine with command channel
    pub fn with_commands(
        initial_relay: SocketAddr,
        port: u16,
        auto_discover: bool,
        status_tx: mpsc::Sender<StatusUpdate>,
        command_rx: mpsc::Receiver<EngineCommand>,
    ) -> Result<Self> {
        let mut engine = Self::new(initial_relay, port, auto_discover, status_tx)?;
        engine.command_rx = Some(command_rx);
        Ok(engine)
    }

    /// Set command receiver (allows injection after creation)
    pub fn set_command_rx(&mut self, rx: mpsc::Receiver<EngineCommand>) {
        self.command_rx = Some(rx);
    }

    /// Feed a protocol message from an external demuxer.
    pub async fn process_incoming(&mut self, data: &[u8], from: SocketAddr) {
        self.bytes_received += data.len() as u64;
        self.process(data, from).await;
    }

    /// Run the engine (blocking).
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1500];
        let mut last_traffic_update = Instant::now();
        let traffic_update_interval = std::time::Duration::from_secs(1);

        loop {
            // Check for commands - collect first to avoid borrow issues
            let commands: Vec<_> = if let Some(ref mut rx) = self.command_rx {
                std::iter::from_fn(|| rx.try_recv().ok()).collect()
            } else {
                Vec::new()
            };

            for cmd in commands {
                match cmd {
                    EngineCommand::NewEndpoint => {
                        self.request_new_endpoint();
                    }
                    EngineCommand::Shutdown => {
                        info!("Engine shutdown requested");
                        return Ok(());
                    }
                    EngineCommand::RequestDns => {
                        if let Some(idx) = self
                            .relays
                            .iter()
                            .position(|r| r.state == RelayState::Connected)
                        {
                            info!("Sending CreateRecords to relay");
                            self.send_confirm(idx, ConfirmAction::CreateRecords);
                        } else {
                            warn!("RequestDns: no connected relay");
                        }
                    }
                    EngineCommand::SetAcmeTxt(data) => {
                        if let Some(idx) = self
                            .relays
                            .iter()
                            .position(|r| r.state == RelayState::Connected)
                        {
                            info!("Sending SetTxt to relay");
                            self.send_confirm(idx, ConfirmAction::SetTxt(data));
                        } else {
                            warn!("SetAcmeTxt: no connected relay");
                        }
                    }
                    EngineCommand::ClearAcmeTxt => {
                        if let Some(idx) = self
                            .relays
                            .iter()
                            .position(|r| r.state == RelayState::Connected)
                        {
                            info!("Sending ClearTxt to relay");
                            self.send_confirm(idx, ConfirmAction::ClearTxt);
                        } else {
                            warn!("ClearAcmeTxt: no connected relay");
                        }
                    }
                }
            }

            // Process incoming — either from DemuxSocket channel or own socket
            if self.msg_rx.is_some() {
                // Demux mode: temporarily take the receiver to avoid borrow conflict
                let mut rx = self.msg_rx.take().unwrap();
                while let Ok((data, from)) = rx.try_recv() {
                    self.bytes_received += data.len() as u64;
                    self.process(&data, from).await;
                }
                self.msg_rx = Some(rx);
            } else {
                while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
                    self.bytes_received += len as u64;
                    self.process(&buf[..len], from).await;
                }
            }

            // Maintain relays
            let now = Instant::now();
            for i in 0..self.relays.len() {
                let (state, elapsed, addr) = {
                    let relay = &self.relays[i];
                    (
                        relay.state,
                        now.duration_since(relay.last_activity),
                        relay.addr,
                    )
                };

                match state {
                    RelayState::Disconnected => {
                        self.send_register(i);
                    }
                    RelayState::Pending if elapsed > timing::REGISTER_TIMEOUT => {
                        warn!("Timeout for {}, retrying", addr);
                        self.relays[i].state = RelayState::Disconnected;
                        let _ = self.status_tx.try_send(StatusUpdate::RelayState {
                            addr,
                            state: RelayState::Disconnected,
                        });
                    }
                    RelayState::Connected if elapsed >= timing::HEARTBEAT_INTERVAL => {
                        self.send_heartbeat(i);
                    }
                    _ => {}
                }
            }

            // Send traffic update periodically
            if now.duration_since(last_traffic_update) >= traffic_update_interval {
                let _ = self.status_tx.try_send(StatusUpdate::Traffic {
                    sent: self.bytes_sent,
                    received: self.bytes_received,
                });
                last_traffic_update = now;
            }

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Request a new endpoint (change port and re-register)
    fn request_new_endpoint(&mut self) {
        use rand::Rng;

        // Generate a new random port in the ephemeral range
        let new_port = rand::rng().random_range(49152u16..65535u16);
        info!("Switching to new port: {} -> {}", self.port, new_port);

        self.port = new_port;

        // Notify UI of port change
        let _ = self
            .status_tx
            .try_send(StatusUpdate::PortChanged { port: new_port });

        // Reset all relays to disconnected
        for relay in &mut self.relays {
            relay.state = RelayState::Disconnected;
            relay.cookie = None;
            relay.last_activity = Instant::now() - timing::HEARTBEAT_INTERVAL;
        }

        // Notify UI of relay state changes
        for relay in &self.relays {
            let _ = self.status_tx.try_send(StatusUpdate::RelayState {
                addr: relay.addr,
                state: RelayState::Disconnected,
            });
        }
    }

    fn send_register(&mut self, idx: usize) {
        let msg = Message::Register { port: self.port };
        let data = msg.to_bytes();
        let addr = self.relays[idx].addr;
        if self.socket.send_to(&data, addr).is_ok() {
            self.bytes_sent += data.len() as u64;
            self.relays[idx].last_activity = Instant::now();
            debug!("REGISTER -> {}", addr);
        }
    }

    fn send_confirm(&mut self, idx: usize, action: ConfirmAction) {
        if let Some(cookie) = self.relays[idx].cookie {
            let msg = Message::Confirm {
                port: self.port,
                cookie,
                action,
            };
            let data = msg.to_bytes();
            let addr = self.relays[idx].addr;
            if self.socket.send_to(&data, addr).is_ok() {
                self.bytes_sent += data.len() as u64;
                debug!("CONFIRM -> {}", addr);
            }
        }
    }

    fn send_heartbeat(&mut self, idx: usize) {
        let msg = Message::Heartbeat { port: self.port };
        let data = msg.to_bytes();
        let addr = self.relays[idx].addr;
        if self.socket.send_to(&data, addr).is_ok() {
            self.bytes_sent += data.len() as u64;
            self.relays[idx].last_activity = Instant::now();
            debug!("HEARTBEAT -> {}", addr);
        }

        // Open NAT mapping for the registered port so the relay's XDP
        // forward path (src=relay_ip:registered_port) passes through
        // port-restricted cone NATs.  Without this, Bob's NAT only
        // allows relay_ip:control_port and drops forwarded traffic.
        let relay_data_addr = SocketAddr::new(addr.ip(), self.port);
        if relay_data_addr != addr {
            let _ = self.socket.send_to(&[0x00], relay_data_addr);
            self.bytes_sent += 1;
        }
    }

    async fn process(&mut self, data: &[u8], from: SocketAddr) {
        let msg = match Message::parse(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        // Match by port (server may respond from different IP due to anycast)
        let idx = match self
            .relays
            .iter()
            .position(|r| r.addr.port() == from.port())
        {
            Some(i) => i,
            None => return,
        };

        match msg {
            Message::Challenge { port, cookie } if port == self.port => {
                self.relays[idx].cookie = Some(cookie);
                self.relays[idx].state = RelayState::Pending;
                info!("CHALLENGE from {}", from);
                self.send_confirm(idx, ConfirmAction::None);
            }

            Message::Neighbors { addrs, subdomain } => {
                if let Some(ref sub) = subdomain {
                    self.relays[idx].subdomain = subdomain.clone();
                    // Notify if this is a new subdomain
                    if self.last_subdomain.as_ref() != Some(sub) {
                        self.last_subdomain = Some(sub.clone());
                        let _ = self.subdomain_tx.send(Some(sub.clone()));
                        let _ = self
                            .status_tx
                            .try_send(StatusUpdate::SubdomainAssigned(sub.clone()));
                    }
                }
                if self.relays[idx].state == RelayState::Pending {
                    self.relays[idx].state = RelayState::Connected;
                    info!("CONNECTED to {} for port {}", from, self.port);
                    let _ = self.status_tx.try_send(StatusUpdate::RelayState {
                        addr: from,
                        state: RelayState::Connected,
                    });

                    // Open NAT mapping for the registered port immediately.
                    // The relay's XDP forwards traffic with src=relay_ip:registered_port;
                    // port-restricted NATs need a prior outbound to that port.
                    let relay_data_addr = SocketAddr::new(from.ip(), self.port);
                    if relay_data_addr.port() != from.port() {
                        let _ = self.socket.send_to(&[0x00], relay_data_addr);
                        self.bytes_sent += 1;
                        debug!("NAT open: sent to {} (data port)", relay_data_addr);
                    }
                }
                self.relays[idx].last_activity = Instant::now();

                if self.auto_discover {
                    for ip in addrs {
                        if self.neighbors.insert(ip) {
                            let new_addr = SocketAddr::new(ip.into(), from.port());
                            if !self.relays.iter().any(|r| r.addr == new_addr) {
                                info!("Discovered neighbor {}", ip);
                                self.relays.push(Relay {
                                    addr: new_addr,
                                    state: RelayState::Disconnected,
                                    cookie: None,
                                    subdomain: None,
                                    last_activity: Instant::now() - timing::HEARTBEAT_INTERVAL,
                                });
                                let _ = self
                                    .status_tx
                                    .try_send(StatusUpdate::NeighborDiscovered(ip));
                            }
                        }
                    }
                }
            }

            Message::Punch { addr, spray_range } => {
                // Only accept Punch from a known relay
                if self.relays.iter().any(|r| r.addr.port() == from.port()) {
                    if spray_range > 0 {
                        let base_port = addr.port();
                        let half = spray_range / 2;
                        let start = base_port.saturating_sub(half);
                        let end = base_port.saturating_add(half).min(65535);
                        for port in start..=end {
                            let target = SocketAddr::new(addr.ip(), port);
                            let _ = self.socket.send_to(&[0x00], target);
                        }
                        let count = (end - start + 1) as u64;
                        self.bytes_sent += count;
                        debug!("NAT spray: {} ports around {}:{}", count, addr.ip(), base_port);
                    } else {
                        if let Err(e) = self.socket.send_to(&[0x00], addr) {
                            warn!("NAT punch failed to {}: {}", addr, e);
                        } else {
                            self.bytes_sent += 1;
                            debug!("NAT punch: sent UDP to {}", addr);
                        }
                    }
                }
            }

            Message::Error { port } if port == self.port => {
                warn!("ERROR from {}", from);
                self.relays[idx].state = RelayState::Disconnected;
                self.relays[idx].cookie = None;
                let _ = self
                    .status_tx
                    .try_send(StatusUpdate::Error(format!("Relay {} rejected", from)));
            }

            _ => {}
        }
    }

    /// Get current relay states
    pub fn relay_states(&self) -> Vec<(SocketAddr, RelayState)> {
        self.relays.iter().map(|r| (r.addr, r.state)).collect()
    }

    /// Get claimed port
    pub fn port(&self) -> u16 {
        self.port
    }
}

// ---------------------------------------------------------------------------
// Service — one-call setup: Engine + H3 Proxy on a single shared socket
// ---------------------------------------------------------------------------

/// Configuration for exposing a local service through Freehold.
#[cfg(feature = "h3-proxy")]
#[derive(Debug)]
pub struct ServiceConfig {
    /// Relay server address.
    pub relay: SocketAddr,
    /// Port to claim on the relay (where Alice connects).
    pub relay_port: u16,
    /// Local address to bind the shared socket.
    pub h3_bind: SocketAddr,
    /// Local HTTP backend to proxy to.
    pub backend: SocketAddr,
    /// TLS certificate chain.
    pub certs: Vec<CertificateDer<'static>>,
    /// TLS private key.
    pub key: PrivateKeyDer<'static>,
    /// Auto-discover and register with neighbor relays.
    pub auto_discover: bool,
    /// ACME cert cache directory. When Some, spawns ACME task for automatic
    /// Let's Encrypt certificates. When None, uses self-signed only.
    pub acme_cache_dir: Option<std::path::PathBuf>,
    /// DNS zone for constructing FQDNs from the subdomain hash
    /// (e.g. "freehold.lit.app"). Required when `acme_cache_dir` is set.
    pub dns_zone: Option<String>,
}

/// A complete Freehold service: registration + H3 proxy on a shared socket.
///
/// Internally uses a `DemuxSocket` so that Engine and Quinn share one OS
/// socket.  Packets with magic byte `0x46` go to Engine; everything else
/// (QUIC) goes to Quinn.  The customer writes `Service::new(config)` +
/// `service.run()` and it just works.
#[cfg(feature = "h3-proxy")]
pub struct Service {
    config: ServiceConfig,
    status_tx: mpsc::Sender<StatusUpdate>,
}

#[cfg(feature = "h3-proxy")]
impl Service {
    /// Create a new service from config.
    pub fn new(config: ServiceConfig, status_tx: mpsc::Sender<StatusUpdate>) -> Result<Self> {
        Ok(Self { config, status_tx })
    }

    /// Run the service — binds a single shared socket, wires up DemuxSocket,
    /// and runs Engine + H3 proxy concurrently.
    pub async fn run(self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        use std::sync::Arc;

        // 1. Bind ONE UDP socket
        let std_socket = UdpSocket::bind(self.config.h3_bind)?;
        std_socket.set_nonblocking(true)?;

        // Clone the FD — Engine uses this handle for sending only
        let engine_send_socket = std_socket.try_clone()?;

        // 2. Convert to tokio and create DemuxSocket + channel
        let tokio_socket = Arc::new(
            tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| anyhow::anyhow!("tokio socket: {}", e))?,
        );
        let (freehold_tx, freehold_rx) = mpsc::unbounded_channel();
        let demux_socket = Arc::new(demux::DemuxSocket::new(tokio_socket, freehold_tx));

        // 3. Build Quinn endpoint on the DemuxSocket
        let server_config = make_quinn_server_config(self.config.certs, self.config.key)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            demux_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| anyhow::anyhow!("quinn endpoint: {}", e))?;

        let local_addr = endpoint.local_addr()?;
        info!(
            "Service on {} (Engine + H3) -> backend {}",
            local_addr, self.config.backend
        );

        // 4. Create command channel for ACME -> Engine communication
        let (_cmd_tx, cmd_rx) = mpsc::channel::<EngineCommand>(16);
        #[cfg(feature = "acme")]
        let cmd_tx = _cmd_tx;

        // 5. Create Engine in demux mode (sends via cloned FD, receives via channel)
        let mut engine = Engine::new_demuxed(
            engine_send_socket,
            self.config.relay,
            self.config.relay_port,
            self.config.auto_discover,
            self.status_tx.clone(),
            freehold_rx,
        );
        engine.set_command_rx(cmd_rx);

        // 6. Spawn ACME task if cache dir and dns_zone are configured
        #[cfg(feature = "acme")]
        if let (Some(cache_dir), Some(dns_zone)) =
            (self.config.acme_cache_dir, self.config.dns_zone)
        {
            let subdomain_rx = engine.subdomain_rx();
            let acme_endpoint = endpoint.clone();
            let status_tx = self.status_tx.clone();

            tokio::spawn(async move {
                if let Err(e) = run_acme_task(
                    cache_dir, dns_zone, cmd_tx, subdomain_rx, acme_endpoint, status_tx,
                )
                .await
                {
                    warn!("ACME task failed: {:?}", e);
                }
            });
        }

        // 7. Run Engine + H3 accept loop concurrently
        let proxy_shutdown = shutdown.clone();
        let backend = self.config.backend;

        tokio::select! {
            result = engine.run() => {
                info!("Engine stopped: {:?}", result);
                result
            }
            result = serve_h3(endpoint, backend, proxy_shutdown) => {
                info!("H3 proxy stopped: {:?}", result);
                result
            }
        }
    }
}

/// ACME background task: waits for subdomain, obtains cert, hot-swaps into endpoint.
#[cfg(feature = "acme")]
async fn run_acme_task(
    cache_dir: std::path::PathBuf,
    dns_zone: String,
    cmd_tx: mpsc::Sender<EngineCommand>,
    mut subdomain_rx: watch::Receiver<Option<String>>,
    endpoint: quinn::Endpoint,
    status_tx: mpsc::Sender<StatusUpdate>,
) -> Result<()> {
    use anyhow::Context as _;

    // Wait for subdomain assignment (receives the 12-char hash)
    loop {
        subdomain_rx
            .changed()
            .await
            .context("subdomain channel closed")?;
        if subdomain_rx.borrow().is_some() {
            break;
        }
    }
    let hash = subdomain_rx.borrow().clone().unwrap();
    info!("ACME: subdomain hash assigned: {}", hash);

    // Construct all three FQDNs from the hash
    let primary = format!("{}.{}", hash, dns_zone);
    let relay = format!("{}.relay.{}", hash, dns_zone);
    let home = format!("{}.home.{}", hash, dns_zone);
    let domains = vec![primary.clone(), relay, home];
    info!("ACME: domains: {:?}", domains);

    let mgr = acme::AcmeManager::new(cache_dir, cmd_tx.clone());

    // Check disk cache first (keyed on primary domain)
    if let Some((certs, key)) = mgr.load_cached(&primary) {
        let server_config = make_quinn_server_config(certs, key)?;
        endpoint.set_server_config(Some(server_config));
        info!("ACME: hot-swapped cached cert for {}", primary);
        let _ = status_tx.try_send(StatusUpdate::AcmeCertReady);
        return Ok(());
    }

    // Request DNS records from relay
    cmd_tx
        .send(EngineCommand::RequestDns)
        .await
        .context("send RequestDns")?;

    // Wait for DNS propagation
    info!("ACME: waiting 5s for DNS A/HTTPS records...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Run ACME flow with all three domains
    let (certs, key) = mgr.obtain(&domains).await?;

    // Hot-swap cert into Quinn endpoint
    let server_config = make_quinn_server_config(certs, key)?;
    endpoint.set_server_config(Some(server_config));
    info!("ACME: hot-swapped new cert for {:?}", domains);
    let _ = status_tx.try_send(StatusUpdate::AcmeCertReady);

    Ok(())
}

/// Helper to generate a self-signed cert and create a service.
#[cfg(feature = "h3-proxy")]
pub fn create_service_with_self_signed_cert(
    relay: SocketAddr,
    relay_port: u16,
    h3_bind: SocketAddr,
    backend: SocketAddr,
    domain: &str,
    auto_discover: bool,
    status_tx: mpsc::Sender<StatusUpdate>,
) -> Result<Service> {
    let (certs, key) = generate_self_signed_cert(&[domain])?;

    Service::new(
        ServiceConfig {
            relay,
            relay_port,
            h3_bind,
            backend,
            certs,
            key,
            auto_discover,
            acme_cache_dir: None,
            dns_zone: None,
        },
        status_tx,
    )
}
