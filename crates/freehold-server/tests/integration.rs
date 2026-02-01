//! Integration tests for the Freehold server
//!
//! These tests verify the server's message handling logic without eBPF.
//! They test the full registration protocol flow using UDP sockets.
//!
//! Uses the `MessageHandler` trait to avoid duplicating protocol logic.

use freehold_api::{Message, COOKIE_SIZE};
use freehold_server::cookie::CookieAuth;
use freehold_server::handler::{HandlerContext, MessageHandler};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Timeout for socket operations in tests.
/// 5 seconds is long enough to handle slow CI environments
/// but short enough to fail quickly on actual hangs.
const TEST_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Test helper implementing MessageHandler trait.
///
/// Uses fixed time bucket for deterministic testing and in-memory
/// storage for registrations.
struct MockServer {
    context: HandlerContext,
    /// Track registered (IP, port) pairs - proper data structure (#14 fix)
    registered: HashSet<(Ipv4Addr, u16)>,
    /// Fixed time bucket for deterministic tests (#13 fix)
    fixed_bucket: u64,
}

impl MockServer {
    fn new(secret: [u8; 32]) -> Self {
        Self {
            context: HandlerContext::new(
                secret,
                8,
                vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            ),
            registered: HashSet::new(),
            fixed_bucket: 0,
        }
    }

    /// Advance to next time bucket (for testing cookie expiration)
    #[allow(dead_code)]
    fn advance_bucket(&mut self) {
        self.fixed_bucket += 1;
    }

    /// Convenience wrapper to get Option<Message>
    fn handle(&mut self, msg: Message, from_ip: Ipv4Addr) -> Option<Message> {
        MessageHandler::handle(self, msg, from_ip).into_option()
    }
}

impl MessageHandler for MockServer {
    fn context(&self) -> &HandlerContext {
        &self.context
    }

    fn context_mut(&mut self) -> &mut HandlerContext {
        &mut self.context
    }

    fn time_bucket(&self) -> u64 {
        self.fixed_bucket
    }

    fn valid_buckets(&self) -> Vec<u64> {
        vec![self.fixed_bucket, self.fixed_bucket.saturating_sub(1)]
    }

    fn is_registered(&self, ip: Ipv4Addr, port: u16) -> bool {
        self.registered.contains(&(ip, port))
    }

    fn register(&mut self, ip: Ipv4Addr, port: u16) {
        self.registered.insert((ip, port));
    }
}

#[test]
fn full_registration_flow() {
    let secret = [0xAB; 32];
    let mut server = MockServer::new(secret);
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);
    let port = 8080;

    // Step 1: Client sends REGISTER
    let register = Message::Register { port };
    let response = server
        .handle(register, client_ip)
        .expect("should get challenge");

    // Step 2: Server responds with CHALLENGE
    let cookie = match response {
        Message::Challenge { port: p, cookie } => {
            assert_eq!(p, port);
            cookie
        }
        _ => panic!("Expected CHALLENGE, got {:?}", response),
    };

    // Step 3: Client sends CONFIRM with cookie
    let confirm = Message::Confirm { port, cookie };
    let response = server
        .handle(confirm, client_ip)
        .expect("should get neighbors");

    // Step 4: Server responds with NEIGHBORS
    match response {
        Message::Neighbors { addrs } => {
            assert_eq!(addrs.len(), 2);
            assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 1)));
            assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 2)));
        }
        _ => panic!("Expected NEIGHBORS, got {:?}", response),
    }

    // Verify registration was recorded
    assert!(server.is_registered(client_ip, port));
}

#[test]
fn invalid_cookie_rejected() {
    let secret = [0xAB; 32];
    let mut server = MockServer::new(secret);
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);
    let port = 8080;

    // Send CONFIRM with bogus cookie
    let bogus_cookie = [0xFF; COOKIE_SIZE];
    let confirm = Message::Confirm {
        port,
        cookie: bogus_cookie,
    };
    let response = server.handle(confirm, client_ip).expect("should get error");

    match response {
        Message::Error { port: p } => {
            assert_eq!(p, port);
        }
        _ => panic!("Expected ERROR, got {:?}", response),
    }

    // Verify not registered
    assert!(!server.is_registered(client_ip, port));
}

#[test]
fn quota_exceeded() {
    let secret = [0xAB; 32];
    let mut server = MockServer::new(secret);
    server.context.max_ports_per_ip = 2; // Low quota for testing
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);

    // Register two ports (should succeed)
    for port in [8080, 8081] {
        let register = Message::Register { port };
        let response = server
            .handle(register, client_ip)
            .expect("should get challenge");

        let cookie = match response {
            Message::Challenge { cookie, .. } => cookie,
            _ => panic!("Expected CHALLENGE"),
        };

        let confirm = Message::Confirm { port, cookie };
        let response = server.handle(confirm, client_ip);
        assert!(matches!(response, Some(Message::Neighbors { .. })));
    }

    // Third registration should fail
    let register = Message::Register { port: 8082 };
    let response = server
        .handle(register, client_ip)
        .expect("should get error");

    match response {
        Message::Error { port } => {
            assert_eq!(port, 8082);
        }
        _ => panic!("Expected ERROR, got {:?}", response),
    }
}

#[test]
fn different_ips_get_different_cookies() {
    let secret = [0xAB; 32];
    let cookie_auth = CookieAuth::new(secret);
    let port = 8080;
    let bucket = 0;

    let ip1 = Ipv4Addr::new(192, 168, 1, 1);
    let ip2 = Ipv4Addr::new(192, 168, 1, 2);

    let cookie1 = cookie_auth.generate(ip1, port, bucket);
    let cookie2 = cookie_auth.generate(ip2, port, bucket);

    assert_ne!(
        cookie1, cookie2,
        "Different IPs should get different cookies"
    );

    // Verify cross-usage fails
    assert!(!cookie_auth.verify(ip1, port, &cookie2, &[bucket]));
    assert!(!cookie_auth.verify(ip2, port, &cookie1, &[bucket]));
}

#[test]
fn different_ports_get_different_cookies() {
    let secret = [0xAB; 32];
    let cookie_auth = CookieAuth::new(secret);
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let bucket = 0;

    let cookie1 = cookie_auth.generate(ip, 8080, bucket);
    let cookie2 = cookie_auth.generate(ip, 8081, bucket);

    assert_ne!(
        cookie1, cookie2,
        "Different ports should get different cookies"
    );

    // Verify cross-usage fails
    assert!(!cookie_auth.verify(ip, 8080, &cookie2, &[bucket]));
    assert!(!cookie_auth.verify(ip, 8081, &cookie1, &[bucket]));
}

#[test]
fn heartbeat_only_responds_to_registered() {
    let secret = [0xAB; 32];
    let mut server = MockServer::new(secret);
    let client_ip = Ipv4Addr::new(192, 168, 1, 100);

    // Heartbeat for unregistered port should be ignored
    let heartbeat = Message::Heartbeat { port: 9999 };
    let response = server.handle(heartbeat, client_ip);
    assert!(response.is_none());

    // Register a port
    let register = Message::Register { port: 8080 };
    let challenge = server.handle(register, client_ip).unwrap();
    let cookie = match challenge {
        Message::Challenge { cookie, .. } => cookie,
        _ => panic!("Expected CHALLENGE"),
    };
    server
        .handle(Message::Confirm { port: 8080, cookie }, client_ip)
        .unwrap();

    // Now heartbeat should work
    let heartbeat = Message::Heartbeat { port: 8080 };
    let response = server.handle(heartbeat, client_ip);
    assert!(matches!(response, Some(Message::Neighbors { .. })));
}

#[test]
fn message_roundtrip_udp() {
    // Test actual UDP message serialization/parsing
    let socket1 = UdpSocket::bind("127.0.0.1:0").expect("bind socket1");
    let socket2 = UdpSocket::bind("127.0.0.1:0").expect("bind socket2");

    socket1.set_read_timeout(Some(TEST_SOCKET_TIMEOUT)).unwrap();
    socket2.set_read_timeout(Some(TEST_SOCKET_TIMEOUT)).unwrap();

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    // Send a REGISTER message
    let msg = Message::Register { port: 12345 };
    socket1.send_to(&msg.to_bytes(), addr2).unwrap();

    // Receive and parse
    let mut buf = [0u8; 1500];
    let (len, from) = socket2.recv_from(&mut buf).unwrap();
    assert_eq!(from, addr1);

    let received = Message::parse(&buf[..len]).unwrap();
    assert_eq!(received, msg);

    // Send a CHALLENGE back
    let cookie = [0x42; COOKIE_SIZE];
    let response = Message::Challenge {
        port: 12345,
        cookie,
    };
    socket2.send_to(&response.to_bytes(), addr1).unwrap();

    // Receive and verify
    let (len, _) = socket1.recv_from(&mut buf).unwrap();
    let received = Message::parse(&buf[..len]).unwrap();
    assert_eq!(received, response);
}

#[test]
fn multiple_clients_different_ips() {
    let secret = [0xAB; 32];
    let mut server = MockServer::new(secret);

    // Different clients can register the same port
    let clients = [
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(10, 0, 1, 2),
        Ipv4Addr::new(10, 0, 1, 3),
    ];

    for client_ip in clients {
        let register = Message::Register { port: 8080 };
        let response = server
            .handle(register, client_ip)
            .expect("should get challenge");

        let cookie = match response {
            Message::Challenge { cookie, .. } => cookie,
            _ => panic!("Expected CHALLENGE"),
        };

        let confirm = Message::Confirm { port: 8080, cookie };
        let response = server.handle(confirm, client_ip);
        assert!(
            matches!(response, Some(Message::Neighbors { .. })),
            "Client {} should be able to register port 8080",
            client_ip
        );
    }
}

/// Test that simulates the client state machine interacting with server
mod client_server_integration {
    use super::*;
    use freehold_client_core::state::{Action, RelayState, StateMachine};
    use std::time::Instant;

    #[test]
    fn state_machine_with_mock_server() {
        let secret = [0xAB; 32];
        let mut server = MockServer::new(secret);
        let server_addr: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let port = 8080;

        let mut client = StateMachine::new(server_addr, port, false);
        let now = Instant::now();

        // Client tick should produce SendRegister
        let actions = client.tick(now);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendRegister { .. })));

        // Simulate sending REGISTER and getting CHALLENGE
        let register = Message::Register { port };
        let challenge = server.handle(register, client_ip).unwrap();
        let cookie = match challenge {
            Message::Challenge { cookie, .. } => cookie,
            _ => panic!("Expected CHALLENGE"),
        };

        // Client handles CHALLENGE
        let actions = client.handle_message(challenge, server_addr, now);
        assert_eq!(client.relays[0].state, RelayState::Pending);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SendConfirm { .. })));

        // Simulate sending CONFIRM and getting NEIGHBORS
        let confirm = Message::Confirm { port, cookie };
        let neighbors = server.handle(confirm, client_ip).unwrap();

        // Client handles NEIGHBORS
        let actions = client.handle_message(neighbors, server_addr, now);
        assert_eq!(client.relays[0].state, RelayState::Connected);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::NotifyStateChange {
                state: RelayState::Connected,
                ..
            }
        )));
    }

    #[test]
    fn state_machine_auto_discovery() {
        let secret = [0xAB; 32];
        let mut server = MockServer::new(secret);
        let server_addr: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let client_ip = Ipv4Addr::new(192, 168, 1, 100);
        let port = 8080;

        // Enable auto-discovery
        let mut client = StateMachine::new(server_addr, port, true);
        let now = Instant::now();

        // Complete registration
        let register = Message::Register { port };
        let challenge = server.handle(register, client_ip).unwrap();
        client.handle_message(challenge.clone(), server_addr, now);

        let cookie = match challenge {
            Message::Challenge { cookie, .. } => cookie,
            _ => panic!("Expected CHALLENGE"),
        };

        let confirm = Message::Confirm { port, cookie };
        let neighbors = server.handle(confirm, client_ip).unwrap();

        // Handle NEIGHBORS - should discover new relays
        let actions = client.handle_message(neighbors, server_addr, now);

        // Should have discovered neighbors 10.0.0.1 and 10.0.0.2
        let neighbor_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::NotifyNeighbor { .. }))
            .collect();

        // 10.0.0.1 is already our server, so only 10.0.0.2 should be new
        assert!(!neighbor_actions.is_empty());

        let add_relay_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::AddRelay { .. }))
            .collect();
        assert!(!add_relay_actions.is_empty());
    }
}
