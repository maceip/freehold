//! Freehold Client Core - The headless "Engine"
//!
//! Handles registration, heartbeat, neighbor discovery, and H3 proxy.
//! Platform-specific UI crates call into this.
//!
//! # Architecture
//!
//! ```text
//! Alice (Browser) --H3/QUIC--> Relay --UDP--> Bob's H3Proxy --HTTP--> Backend
//!                                              ^
//!                                              |
//!                                     Engine (registration)
//! ```

pub mod state;

use anyhow::Result;
use freehold_api::{timing, Message, COOKIE_SIZE};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[cfg(feature = "h3-proxy")]
pub use freehold_h3_proxy::{
    generate_self_signed_cert, CertificateDer, H3Proxy, H3ProxyConfig, PrivateKeyDer,
};

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
}

/// Command sent from UI to engine
#[derive(Debug, Clone)]
pub enum EngineCommand {
    /// Request a new endpoint (change port)
    NewEndpoint,
    /// Shutdown the engine
    Shutdown,
}

/// Relay connection tracking
struct Relay {
    addr: SocketAddr,
    state: RelayState,
    cookie: Option<[u8; COOKIE_SIZE]>,
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
    auto_discover: bool,
    bytes_sent: u64,
    bytes_received: u64,
}

impl Engine {
    /// Create a new engine
    pub fn new(
        initial_relay: SocketAddr,
        port: u16,
        auto_discover: bool,
        status_tx: mpsc::Sender<StatusUpdate>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            socket,
            port,
            relays: vec![Relay {
                addr: initial_relay,
                state: RelayState::Disconnected,
                cookie: None,
                last_activity: Instant::now() - timing::HEARTBEAT_INTERVAL,
            }],
            neighbors: HashSet::new(),
            status_tx,
            command_rx: None,
            auto_discover,
            bytes_sent: 0,
            bytes_received: 0,
        })
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

    /// Run the engine (blocking)
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
                }
            }

            // Process incoming
            while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
                self.bytes_received += len as u64;
                self.process(&buf[..len], from).await;
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

    fn send_confirm(&mut self, idx: usize) {
        if let Some(cookie) = self.relays[idx].cookie {
            let msg = Message::Confirm {
                port: self.port,
                cookie,
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
                self.send_confirm(idx);
            }

            Message::Neighbors { addrs } => {
                if self.relays[idx].state == RelayState::Pending {
                    self.relays[idx].state = RelayState::Connected;
                    info!("CONNECTED to {} for port {}", from, self.port);
                    let _ = self.status_tx.try_send(StatusUpdate::RelayState {
                        addr: from,
                        state: RelayState::Connected,
                    });
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

/// Configuration for exposing a local service through Freehold.
#[cfg(feature = "h3-proxy")]
#[derive(Debug)]
pub struct ServiceConfig {
    /// Relay server address.
    pub relay: SocketAddr,
    /// Port to claim on the relay (where Alice connects).
    pub relay_port: u16,
    /// Local address to bind H3 server (should match where relay forwards).
    pub h3_bind: SocketAddr,
    /// Local HTTP backend to proxy to.
    pub backend: SocketAddr,
    /// TLS certificate chain.
    pub certs: Vec<CertificateDer<'static>>,
    /// TLS private key.
    pub key: PrivateKeyDer<'static>,
    /// Auto-discover and register with neighbor relays.
    pub auto_discover: bool,
}

/// A complete Freehold service: registration + H3 proxy.
#[cfg(feature = "h3-proxy")]
pub struct Service {
    engine: Engine,
    proxy: H3Proxy,
}

#[cfg(feature = "h3-proxy")]
impl Service {
    /// Create a new service from config.
    pub fn new(config: ServiceConfig, status_tx: mpsc::Sender<StatusUpdate>) -> Result<Self> {
        let engine = Engine::new(
            config.relay,
            config.relay_port,
            config.auto_discover,
            status_tx,
        )?;

        let proxy = H3Proxy::new(H3ProxyConfig {
            bind_addr: config.h3_bind,
            backend: config.backend,
            certs: config.certs,
            key: config.key,
        });

        Ok(Self { engine, proxy })
    }

    /// Run both the registration engine and H3 proxy.
    pub async fn run(mut self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let proxy_shutdown = shutdown.clone();

        // Run both concurrently
        tokio::select! {
            result = self.engine.run() => {
                info!("Engine stopped: {:?}", result);
                result
            }
            result = self.proxy.run(proxy_shutdown) => {
                info!("H3 proxy stopped: {:?}", result);
                result
            }
        }
    }
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
        },
        status_tx,
    )
}
