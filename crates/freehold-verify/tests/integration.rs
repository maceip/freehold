//! Integration tests for freehold-verify
//!
//! These tests run a mock attestation server and verify against it.

use freehold_api::{Message, ATTESTATION_NONCE_SIZE};
use freehold_enclave::{extract_mrenclave, extract_nonce, Enclave, MrEnclave};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Mock attestation server for testing
struct MockServer {
    socket: UdpSocket,
    enclave: Enclave,
    running: Arc<AtomicBool>,
}

impl MockServer {
    fn new(mrenclave: MrEnclave) -> (Self, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = socket.local_addr().unwrap();

        let secret = [0xAB; 32];
        let mut enclave = Enclave::new(&secret).unwrap();
        enclave.set_mock_mrenclave(mrenclave);

        let server = Self {
            socket,
            enclave,
            running: Arc::new(AtomicBool::new(true)),
        };

        (server, addr)
    }

    fn run(&self) {
        let mut buf = [0u8; 65535];
        while self.running.load(Ordering::Relaxed) {
            match self.socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    if let Ok(msg) = Message::parse(&buf[..len]) {
                        let response = self.handle_message(msg);
                        let _ = self.socket.send_to(&response.to_bytes(), from);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout, check if still running
                    continue;
                }
                Err(_) => break,
            }
        }
    }

    fn handle_message(&self, msg: Message) -> Message {
        match msg {
            Message::AttestationRequest { nonce } => {
                let attestation = self.enclave.generate_quote(&nonce).unwrap();
                Message::AttestationResponse {
                    quote: attestation.quote,
                    collateral: attestation.collateral,
                }
            }
            _ => Message::Error { port: 0 },
        }
    }

    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[test]
fn test_verify_against_mock_server() {
    let expected_mrenclave: MrEnclave = [0xDE; 32];
    let (server, addr) = MockServer::new(expected_mrenclave);

    // Start server in background
    let running = server.running.clone();
    let server_thread = thread::spawn(move || {
        server.run();
    });

    // Give server time to start
    thread::sleep(Duration::from_millis(50));

    // --- Client verification ---
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

    // Generate nonce
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = rand::random();

    // Send request
    let request = Message::AttestationRequest { nonce };
    client.send_to(&request.to_bytes(), addr).unwrap();

    // Receive response
    let mut buf = [0u8; 65535];
    let (len, _) = client.recv_from(&mut buf).unwrap();
    let response = Message::parse(&buf[..len]).unwrap();

    match response {
        Message::AttestationResponse { quote, collateral: _ } => {
            // Verify nonce
            let extracted_nonce = extract_nonce(&quote).unwrap();
            assert_eq!(extracted_nonce, nonce);

            // Verify MRENCLAVE
            let actual = extract_mrenclave(&quote).unwrap();
            assert_eq!(actual, expected_mrenclave);
        }
        _ => panic!("Expected AttestationResponse"),
    }

    // Cleanup
    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();
}

#[test]
fn test_detect_wrong_mrenclave() {
    // Server has different MRENCLAVE than expected
    let server_mrenclave: MrEnclave = [0xAA; 32];
    let expected_mrenclave: MrEnclave = [0xBB; 32];

    let (server, addr) = MockServer::new(server_mrenclave);

    let running = server.running.clone();
    let server_thread = thread::spawn(move || {
        server.run();
    });

    thread::sleep(Duration::from_millis(50));

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

    let nonce: [u8; ATTESTATION_NONCE_SIZE] = rand::random();
    let request = Message::AttestationRequest { nonce };
    client.send_to(&request.to_bytes(), addr).unwrap();

    let mut buf = [0u8; 65535];
    let (len, _) = client.recv_from(&mut buf).unwrap();
    let response = Message::parse(&buf[..len]).unwrap();

    match response {
        Message::AttestationResponse { quote, .. } => {
            let actual = extract_mrenclave(&quote).unwrap();
            // This should NOT match
            assert_ne!(actual, expected_mrenclave);
        }
        _ => panic!("Expected AttestationResponse"),
    }

    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();
}

#[test]
fn test_multiple_concurrent_verifications() {
    let mrenclave: MrEnclave = [0xCC; 32];
    let (server, addr) = MockServer::new(mrenclave);

    let running = server.running.clone();
    let server_thread = thread::spawn(move || {
        server.run();
    });

    thread::sleep(Duration::from_millis(50));

    // Spawn multiple clients
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let addr = addr;
            thread::spawn(move || {
                let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

                let nonce: [u8; ATTESTATION_NONCE_SIZE] = [i as u8; ATTESTATION_NONCE_SIZE];
                let request = Message::AttestationRequest { nonce };
                client.send_to(&request.to_bytes(), addr).unwrap();

                let mut buf = [0u8; 65535];
                let (len, _) = client.recv_from(&mut buf).unwrap();
                let response = Message::parse(&buf[..len]).unwrap();

                match response {
                    Message::AttestationResponse { quote, .. } => {
                        let extracted_nonce = extract_nonce(&quote).unwrap();
                        assert_eq!(extracted_nonce, nonce);
                        true
                    }
                    _ => false,
                }
            })
        })
        .collect();

    // All should succeed
    for handle in handles {
        assert!(handle.join().unwrap());
    }

    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();
}
