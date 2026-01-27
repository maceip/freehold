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
    RelayState { addr: SocketAddr, state: RelayState },
    NeighborDiscovered(Ipv4Addr),
    Error(String),
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
    auto_discover: bool,
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
            auto_discover,
        })
    }

    /// Run the engine (blocking)
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1500];

        loop {
            // Process incoming
            while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
                self.process(&buf[..len], from).await;
            }

            // Maintain relays
            let now = Instant::now();
            for i in 0..self.relays.len() {
                let (state, elapsed, addr) = {
                    let relay = &self.relays[i];
                    (relay.state, now.duration_since(relay.last_activity), relay.addr)
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

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    fn send_register(&mut self, idx: usize) {
        let msg = Message::Register { port: self.port };
        let addr = self.relays[idx].addr;
        if self.socket.send_to(&msg.to_bytes(), addr).is_ok() {
            self.relays[idx].last_activity = Instant::now();
            debug!("REGISTER -> {}", addr);
        }
    }

    fn send_confirm(&mut self, idx: usize) {
        if let Some(cookie) = self.relays[idx].cookie {
            let msg = Message::Confirm { port: self.port, cookie };
            let addr = self.relays[idx].addr;
            if self.socket.send_to(&msg.to_bytes(), addr).is_ok() {
                debug!("CONFIRM -> {}", addr);
            }
        }
    }

    fn send_heartbeat(&mut self, idx: usize) {
        let msg = Message::Heartbeat { port: self.port };
        let addr = self.relays[idx].addr;
        if self.socket.send_to(&msg.to_bytes(), addr).is_ok() {
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
        let idx = match self.relays.iter().position(|r| r.addr.port() == from.port()) {
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
                                let _ = self.status_tx.try_send(StatusUpdate::NeighborDiscovered(ip));
                            }
                        }
                    }
                }
            }

            Message::Error { port } if port == self.port => {
                warn!("ERROR from {}", from);
                self.relays[idx].state = RelayState::Disconnected;
                self.relays[idx].cookie = None;
                let _ = self.status_tx.try_send(StatusUpdate::Error(format!("Relay {} rejected", from)));
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
