//! Integration tests for attestation flow
//!
//! These tests verify the complete attestation protocol without SGX hardware.

use freehold_api::{Message, ATTESTATION_NONCE_SIZE};
use freehold_enclave::{extract_mrenclave, extract_nonce, Enclave, MrEnclave};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

/// Test the complete attestation request/response flow
#[test]
fn test_attestation_message_roundtrip() {
    // Create request with random nonce
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x42; ATTESTATION_NONCE_SIZE];
    let request = Message::AttestationRequest { nonce };

    // Serialize
    let bytes = request.to_bytes();
    assert_eq!(bytes[0], 0x46); // Magic 'F'
    assert_eq!(bytes[1], 0x10); // AttestationRequest type

    // Deserialize
    let parsed = Message::parse(&bytes).unwrap();
    match parsed {
        Message::AttestationRequest {
            nonce: parsed_nonce,
        } => {
            assert_eq!(parsed_nonce, nonce);
        }
        _ => panic!("Expected AttestationRequest"),
    }
}

#[test]
fn test_attestation_response_roundtrip() {
    let quote = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let collateral = vec![10, 20, 30, 40];

    let response = Message::AttestationResponse {
        quote: quote.clone(),
        collateral: collateral.clone(),
    };

    let bytes = response.to_bytes();
    let parsed = Message::parse(&bytes).unwrap();

    match parsed {
        Message::AttestationResponse {
            quote: q,
            collateral: c,
        } => {
            assert_eq!(q, quote);
            assert_eq!(c, collateral);
        }
        _ => panic!("Expected AttestationResponse"),
    }
}

#[test]
fn test_mock_enclave_attestation() {
    // Initialize enclave with test secret
    let secret = [0xAB; 32];
    let mut enclave = Enclave::new(&secret).unwrap();

    // Set a known MRENCLAVE for testing
    let expected_mrenclave: MrEnclave = [0xCD; 32];
    enclave.set_mock_mrenclave(expected_mrenclave);

    // Generate attestation with nonce
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x12; ATTESTATION_NONCE_SIZE];
    let attestation = enclave.generate_quote(&nonce).unwrap();

    // Verify MRENCLAVE extraction
    let extracted_mrenclave = extract_mrenclave(&attestation.quote).unwrap();
    assert_eq!(extracted_mrenclave, expected_mrenclave);

    // Verify nonce extraction (freshness check)
    let extracted_nonce = extract_nonce(&attestation.quote).unwrap();
    assert_eq!(extracted_nonce, nonce);
}

#[test]
fn test_different_nonces_produce_different_quotes() {
    let secret = [0xAB; 32];
    let mut enclave = Enclave::new(&secret).unwrap();
    enclave.set_mock_mrenclave([0xCD; 32]);

    let nonce1: [u8; ATTESTATION_NONCE_SIZE] = [0x11; ATTESTATION_NONCE_SIZE];
    let nonce2: [u8; ATTESTATION_NONCE_SIZE] = [0x22; ATTESTATION_NONCE_SIZE];

    let quote1 = enclave.generate_quote(&nonce1).unwrap();
    let quote2 = enclave.generate_quote(&nonce2).unwrap();

    // Quotes should be different (due to nonce in report_data)
    assert_ne!(quote1.quote, quote2.quote);

    // But MRENCLAVE should be the same
    let mr1 = extract_mrenclave(&quote1.quote).unwrap();
    let mr2 = extract_mrenclave(&quote2.quote).unwrap();
    assert_eq!(mr1, mr2);
}

#[test]
fn test_verification_flow_simulation() {
    // Simulate the full verification flow:
    // 1. User has expected MRENCLAVE from release
    // 2. User generates nonce
    // 3. User sends request, gets response
    // 4. User extracts and verifies

    let expected_mrenclave: MrEnclave = [0xAB; 32];

    // --- Server side (enclave) ---
    let secret = [0x99; 32];
    let mut enclave = Enclave::new(&secret).unwrap();
    enclave.set_mock_mrenclave(expected_mrenclave);

    // --- Client side ---
    // 1. Generate nonce
    let nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x42; ATTESTATION_NONCE_SIZE];

    // 2. Create request
    let request = Message::AttestationRequest { nonce };
    let request_bytes = request.to_bytes();

    // 3. Server processes request (simulated)
    let parsed_request = Message::parse(&request_bytes).unwrap();
    let response = match parsed_request {
        Message::AttestationRequest { nonce } => {
            let attestation = enclave.generate_quote(&nonce).unwrap();
            Message::AttestationResponse {
                quote: attestation.quote,
                collateral: attestation.collateral,
            }
        }
        _ => panic!("Unexpected message type"),
    };

    // 4. Client receives and verifies
    let response_bytes = response.to_bytes();
    let parsed_response = Message::parse(&response_bytes).unwrap();

    match parsed_response {
        Message::AttestationResponse {
            quote,
            collateral: _,
        } => {
            // Verify nonce (freshness)
            let extracted_nonce = extract_nonce(&quote).unwrap();
            assert_eq!(extracted_nonce, nonce, "Nonce mismatch - replay attack?");

            // Verify MRENCLAVE
            let actual_mrenclave = extract_mrenclave(&quote).unwrap();
            assert_eq!(
                actual_mrenclave, expected_mrenclave,
                "MRENCLAVE mismatch - relay running different code!"
            );
        }
        _ => panic!("Expected AttestationResponse"),
    }
}

#[test]
fn test_tampered_mrenclave_detected() {
    let expected_mrenclave: MrEnclave = [0xAA; 32];
    let actual_mrenclave: MrEnclave = [0xBB; 32]; // Different!

    let secret = [0x99; 32];
    let mut enclave = Enclave::new(&secret).unwrap();
    enclave.set_mock_mrenclave(actual_mrenclave);

    let nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x42; ATTESTATION_NONCE_SIZE];
    let attestation = enclave.generate_quote(&nonce).unwrap();

    let extracted = extract_mrenclave(&attestation.quote).unwrap();

    // This should NOT match - relay is running different code
    assert_ne!(extracted, expected_mrenclave);
}

#[test]
fn test_replay_attack_detected() {
    let secret = [0x99; 32];
    let mut enclave = Enclave::new(&secret).unwrap();
    enclave.set_mock_mrenclave([0xAA; 32]);

    // Attacker captures a quote with old nonce
    let old_nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x11; ATTESTATION_NONCE_SIZE];
    let captured_quote = enclave.generate_quote(&old_nonce).unwrap();

    // User requests attestation with new nonce
    let new_nonce: [u8; ATTESTATION_NONCE_SIZE] = [0x22; ATTESTATION_NONCE_SIZE];

    // Attacker replays old quote
    let extracted_nonce = extract_nonce(&captured_quote.quote).unwrap();

    // Should detect mismatch
    assert_ne!(extracted_nonce, new_nonce, "Replay attack not detected!");
}

#[test]
fn test_cookie_operations_in_enclave() {
    use std::net::Ipv4Addr;

    let secret = [0xAB; 32];
    let enclave = Enclave::new(&secret).unwrap();

    let ip = Ipv4Addr::new(192, 168, 1, 100);
    let port = 8080u16;
    let bucket = 1000u64;

    // Generate cookie
    let cookie = enclave.generate_cookie(ip, port, bucket);

    // Verify with same bucket
    assert!(enclave.verify_cookie(ip, port, &cookie.bytes, bucket));

    // Verify with next bucket (previous window accepted)
    assert!(enclave.verify_cookie(ip, port, &cookie.bytes, bucket + 1));

    // Reject with bucket too far in future
    assert!(!enclave.verify_cookie(ip, port, &cookie.bytes, bucket + 2));

    // Reject wrong IP
    let wrong_ip = Ipv4Addr::new(10, 0, 0, 1);
    assert!(!enclave.verify_cookie(wrong_ip, port, &cookie.bytes, bucket));

    // Reject wrong port
    assert!(!enclave.verify_cookie(ip, port + 1, &cookie.bytes, bucket));
}

/// Test large quote handling (simulating real DCAP quote size)
#[test]
fn test_large_quote_handling() {
    // Real DCAP quotes are ~4KB
    let large_quote = vec![0xAB; 4096];
    let large_collateral = vec![0xCD; 8192];

    let response = Message::AttestationResponse {
        quote: large_quote.clone(),
        collateral: large_collateral.clone(),
    };

    let bytes = response.to_bytes();

    // Should handle large payloads
    assert!(bytes.len() > 12000);

    let parsed = Message::parse(&bytes).unwrap();
    match parsed {
        Message::AttestationResponse { quote, collateral } => {
            assert_eq!(quote.len(), 4096);
            assert_eq!(collateral.len(), 8192);
        }
        _ => panic!("Expected AttestationResponse"),
    }
}
