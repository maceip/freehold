//! End-to-End Tests for Freehold
//!
//! These tests verify the complete Freehold stack.
//! Some tests require root privileges and eBPF support.
//!
//! Run E2E tests with:
//! ```bash
//! sudo cargo test --package freehold-e2e-tests --features e2e
//! ```

use anyhow::{Context, Result};
use freehold_api::Message;
use freehold_client_core::state::{Action, RelayState, StateMachine};
use freehold_server::cookie::CookieAuth;
use freehold_server::quota::QuotaTracker;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Test helper that simulates a server without eBPF
pub struct TestServer {
    socket: UdpSocket,
    cookie_auth: CookieAuth,
    quotas: QuotaTracker,
    neighbors: Vec<Ipv4Addr>,
    max_ports_per_ip: u32,
    registered_ports: Vec<(u16, Ipv4Addr)>,
}

impl TestServer {
    pub fn new(bind_addr: &str, secret: [u8; 32]) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).context("bind server socket")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .context("set read timeout")?;

        Ok(Self {
            socket,
            cookie_auth: CookieAuth::new(secret),
            quotas: QuotaTracker::default(),
            neighbors: vec![],
            max_ports_per_ip: 8,
            registered_ports: Vec::new(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn set_neighbors(&mut self, neighbors: Vec<Ipv4Addr>) {
        self.neighbors = neighbors;
    }

    /// Process one message (blocking with timeout)
    pub fn process_one(&mut self) -> Result<Option<(SocketAddr, Message)>> {
        let mut buf = [0u8; 1500];

        match self.socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let msg = Message::parse(&buf[..len]).context("parse message")?;
                let response = self.handle(&msg, from);

                if let Some(ref resp) = response {
                    self.socket
                        .send_to(&resp.to_bytes(), from)
                        .context("send response")?;
                }

                Ok(Some((from, msg)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn handle(&mut self, msg: &Message, from: SocketAddr) -> Option<Message> {
        let ip = match from {
            SocketAddr::V4(a) => *a.ip(),
            _ => return None,
        };

        // Use bucket 0 for tests
        let bucket = 0u64;

        match msg {
            Message::Register { port } => {
                let count = self.quotas.count(&ip);
                if count >= self.max_ports_per_ip {
                    return Some(Message::Error { port: *port });
                }

                let cookie = self.cookie_auth.generate(ip, *port, bucket);
                Some(Message::Challenge {
                    port: *port,
                    cookie,
                })
            }

            Message::Confirm { port, cookie } => {
                if !self.cookie_auth.verify(ip, *port, cookie, &[0, 1]) {
                    return Some(Message::Error { port: *port });
                }

                self.quotas.register(ip, *port);
                self.registered_ports.push((*port, ip));

                Some(Message::Neighbors {
                    addrs: self.neighbors.clone(),
                })
            }

            Message::Heartbeat { port } => {
                if self.registered_ports.iter().any(|(p, i)| *p == *port && *i == ip) {
                    Some(Message::Neighbors {
                        addrs: self.neighbors.clone(),
                    })
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    pub fn registered_count(&self) -> usize {
        self.registered_ports.len()
    }
}

/// Test client that drives the state machine with real UDP
pub struct TestClient {
    socket: UdpSocket,
    state_machine: StateMachine,
    #[allow(dead_code)]
    server_addr: SocketAddr,
}

impl TestClient {
    pub fn new(server_addr: SocketAddr, port: u16, auto_discover: bool) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").context("bind client socket")?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .context("set read timeout")?;

        let state_machine = StateMachine::new(server_addr, port, auto_discover);

        Ok(Self {
            socket,
            state_machine,
            server_addr,
        })
    }

    /// Run one tick of the client, handling any messages
    pub fn tick(&mut self) -> Result<Vec<Action>> {
        let now = Instant::now();
        let mut all_actions = Vec::new();

        // Process tick actions
        let actions = self.state_machine.tick(now);
        for action in &actions {
            self.execute_action(action)?;
        }
        all_actions.extend(actions);

        // Receive and process any messages
        let mut buf = [0u8; 1500];
        while let Ok((len, from)) = self.socket.recv_from(&mut buf) {
            if let Ok(msg) = Message::parse(&buf[..len]) {
                let actions = self.state_machine.handle_message(msg, from, now);
                for action in &actions {
                    self.execute_action(action)?;
                }
                all_actions.extend(actions);
            }
        }

        Ok(all_actions)
    }

    fn execute_action(&mut self, action: &Action) -> Result<()> {
        match action {
            Action::SendRegister { relay_idx } => {
                let relay = self.state_machine.get_relay(*relay_idx);
                if let Some(relay) = relay {
                    let msg = Message::Register {
                        port: self.state_machine.port,
                    };
                    self.socket.send_to(&msg.to_bytes(), relay.addr)?;
                    self.state_machine.mark_activity(*relay_idx, Instant::now());
                }
            }
            Action::SendConfirm { relay_idx } => {
                let relay = self.state_machine.get_relay(*relay_idx);
                if let Some(relay) = relay {
                    if let Some(cookie) = relay.cookie {
                        let msg = Message::Confirm {
                            port: self.state_machine.port,
                            cookie,
                        };
                        self.socket.send_to(&msg.to_bytes(), relay.addr)?;
                    }
                }
            }
            Action::SendHeartbeat { relay_idx } => {
                let relay = self.state_machine.get_relay(*relay_idx);
                if let Some(relay) = relay {
                    let msg = Message::Heartbeat {
                        port: self.state_machine.port,
                    };
                    self.socket.send_to(&msg.to_bytes(), relay.addr)?;
                    self.state_machine.mark_activity(*relay_idx, Instant::now());
                }
            }
            Action::AddRelay { addr } => {
                self.state_machine.add_relay(*addr);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn relay_state(&self, idx: usize) -> Option<RelayState> {
        self.state_machine.get_relay(idx).map(|r| r.state)
    }

    pub fn is_connected(&self) -> bool {
        self.state_machine
            .relays
            .iter()
            .any(|r| r.state == RelayState::Connected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_server_registration() {
        let secret = [0x42; 32];

        // Start test server
        let mut server = TestServer::new("127.0.0.1:0", secret).unwrap();
        let server_addr = server.local_addr();

        // Create client
        let mut client = TestClient::new(server_addr, 8080, false).unwrap();

        // Run until connected or timeout
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !client.is_connected() {
            // Client tick
            let _ = client.tick();

            // Server process messages (process ALL pending, not just one)
            while let Ok(Some(_)) = server.process_one() {}

            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(client.is_connected(), "Client should be connected");
        assert_eq!(server.registered_count(), 1, "Server should have 1 registration");
    }

    #[test]
    fn test_multiple_clients() {
        let secret = [0x42; 32];

        let mut server = TestServer::new("127.0.0.1:0", secret).unwrap();
        let server_addr = server.local_addr();

        // Create multiple clients with different ports
        let mut clients: Vec<_> = (0..3)
            .map(|i| TestClient::new(server_addr, 8080 + i, false).unwrap())
            .collect();

        // Run until all connected or timeout
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !clients.iter().all(|c| c.is_connected()) {
            for client in &mut clients {
                let _ = client.tick();
            }

            // Process multiple server messages per tick
            for _ in 0..10 {
                let _ = server.process_one();
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            clients.iter().all(|c| c.is_connected()),
            "All clients should be connected"
        );
        assert_eq!(
            server.registered_count(),
            3,
            "Server should have 3 registrations"
        );
    }

    #[test]
    fn test_client_auto_discovery() {
        let secret = [0x42; 32];

        let mut server = TestServer::new("127.0.0.1:0", secret).unwrap();
        let server_addr = server.local_addr();

        // Set up neighbors
        server.set_neighbors(vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        ]);

        // Create client with auto-discovery enabled
        let mut client = TestClient::new(server_addr, 8080, true).unwrap();

        // Run until connected
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !client.is_connected() {
            let _ = client.tick();
            let _ = server.process_one();
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(client.is_connected(), "Client should be connected");

        // Verify neighbors were discovered
        assert!(
            client.state_machine.neighbors.len() >= 2,
            "Should have discovered neighbors"
        );
    }

    #[test]
    fn test_heartbeat_maintains_connection() {
        use freehold_api::timing;

        let secret = [0x42; 32];

        let mut server = TestServer::new("127.0.0.1:0", secret).unwrap();
        let server_addr = server.local_addr();

        let mut client = TestClient::new(server_addr, 8080, false).unwrap();

        // Connect
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !client.is_connected() {
            let _ = client.tick();
            let _ = server.process_one();
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(client.is_connected());

        // Simulate time passing by manipulating last_activity
        // (In real tests, we'd wait for HEARTBEAT_INTERVAL)
        client.state_machine.relays[0].last_activity =
            Instant::now() - timing::HEARTBEAT_INTERVAL - Duration::from_secs(1);

        // Tick should send heartbeat
        let actions = client.tick().unwrap();
        assert!(
            actions.iter().any(|a| matches!(a, Action::SendHeartbeat { .. })),
            "Should have sent heartbeat"
        );

        // Server should respond
        let _ = server.process_one();
    }

    #[test]
    fn test_registration_timeout_and_retry() {
        // Create client pointing to non-existent server
        let fake_addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        let mut client = TestClient::new(fake_addr, 8080, false).unwrap();

        // First tick sends register
        let actions = client.tick().unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::SendRegister { .. })));

        // Simulate timeout by manipulating last_activity
        client.state_machine.relays[0].last_activity =
            Instant::now() - freehold_api::timing::REGISTER_TIMEOUT - Duration::from_secs(1);
        client.state_machine.relays[0].state = RelayState::Pending;

        // Tick should detect timeout and transition to Disconnected
        let actions = client.tick().unwrap();
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::NotifyStateChange {
                state: RelayState::Disconnected,
                ..
            }
        )));

        // Next tick should retry
        let actions = client.tick().unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::SendRegister { .. })));
    }
}

/// E2E tests that require root and network namespaces
#[cfg(all(test, feature = "e2e"))]
mod e2e_tests {
    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    #[test]
    #[ignore = "requires root and network namespace support"]
    fn test_with_network_namespaces() {
        if !is_root() {
            eprintln!("Skipping: requires root");
            return;
        }

        // This test would set up network namespaces and test with real eBPF
        // For now, placeholder - see tests/e2e/run_e2e.sh for full implementation
        eprintln!("E2E infrastructure available - run tests/e2e/run_e2e.sh with sudo for full test");
    }
}
