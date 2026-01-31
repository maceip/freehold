//! Freehold Enclave - SGX enclave for secret management and attestation
//!
//! This crate provides:
//! - Secure HMAC secret storage (never leaves enclave memory)
//! - Cookie generation and verification
//! - SGX quote generation for remote attestation
//!
//! When compiled without SGX, provides mock implementations for testing.

use freehold_api::{ATTESTATION_NONCE_SIZE, COOKIE_SIZE};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::Ipv4Addr;

type HmacSha256 = Hmac<Sha256>;

/// Errors from enclave operations
#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("enclave not initialized")]
    NotInitialized,
    #[error("invalid secret length: expected 32, got {0}")]
    InvalidSecretLength(usize),
    #[error("quote generation failed: {0}")]
    QuoteGenerationFailed(String),
    #[error("attestation not available (SGX not enabled)")]
    AttestationNotAvailable,
}

/// Result type for enclave operations
pub type Result<T> = std::result::Result<T, EnclaveError>;

/// MRENCLAVE measurement (32 bytes)
pub type MrEnclave = [u8; 32];

/// Attestation quote with collateral
#[derive(Debug, Clone)]
pub struct AttestationQuote {
    /// DCAP ECDSA quote containing MRENCLAVE and report_data (with nonce)
    pub quote: Vec<u8>,
    /// Verification collateral (PCK certs, TCB info, QE identity)
    pub collateral: Vec<u8>,
}

/// Cookie operations result
#[derive(Debug, Clone)]
pub struct Cookie {
    pub bytes: [u8; COOKIE_SIZE],
}

/// Enclave state - holds the HMAC secret securely
///
/// In SGX mode, this memory is encrypted and inaccessible to the host.
/// The secret never leaves the enclave.
pub struct Enclave {
    secret: [u8; 32],
    #[cfg(feature = "mock-attestation")]
    mock_mrenclave: MrEnclave,
}

impl Enclave {
    /// Initialize enclave with HMAC secret
    ///
    /// The secret is copied into enclave memory and the original should be zeroed.
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() != 32 {
            return Err(EnclaveError::InvalidSecretLength(secret.len()));
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(secret);

        Ok(Self {
            secret: secret_array,
            #[cfg(feature = "mock-attestation")]
            mock_mrenclave: [0u8; 32],
        })
    }

    /// Generate a cookie for the given IP, port, and time bucket
    ///
    /// Cookie = HMAC-SHA256(secret, IP || port || bucket)[..16]
    pub fn generate_cookie(&self, ip: Ipv4Addr, port: u16, time_bucket: u64) -> Cookie {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&ip.octets());
        mac.update(&port.to_be_bytes());
        mac.update(&time_bucket.to_be_bytes());

        let mut bytes = [0u8; COOKIE_SIZE];
        bytes.copy_from_slice(&mac.finalize().into_bytes()[..COOKIE_SIZE]);
        Cookie { bytes }
    }

    /// Verify a cookie against the given IP, port, and time buckets
    ///
    /// Accepts cookies from current and previous time bucket for clock skew tolerance.
    pub fn verify_cookie(
        &self,
        ip: Ipv4Addr,
        port: u16,
        cookie: &[u8; COOKIE_SIZE],
        current_bucket: u64,
    ) -> bool {
        // Check current and previous bucket (30-second windows)
        [current_bucket, current_bucket.saturating_sub(1)]
            .iter()
            .any(|&bucket| &self.generate_cookie(ip, port, bucket).bytes == cookie)
    }

    /// Generate an SGX attestation quote with the given nonce
    ///
    /// The nonce is included in the quote's report_data field to prove freshness.
    /// Returns the quote and verification collateral.
    #[cfg(all(feature = "sgx", target_os = "linux"))]
    pub fn generate_quote(&self, nonce: &[u8; ATTESTATION_NONCE_SIZE]) -> Result<AttestationQuote> {
        use dcap_ql::quote::{Quote, Report};

        // Create report_data with nonce in first 32 bytes
        let mut report_data = [0u8; 64];
        report_data[..ATTESTATION_NONCE_SIZE].copy_from_slice(nonce);

        // Generate quote using DCAP
        let quote = Quote::generate(&report_data)
            .map_err(|e| EnclaveError::QuoteGenerationFailed(e.to_string()))?;

        // Fetch collateral for offline verification
        let collateral = dcap_ql::collateral::get_collateral(&quote)
            .map_err(|e| EnclaveError::QuoteGenerationFailed(format!("collateral: {}", e)))?;

        let collateral_json = serde_json::to_vec(&collateral)
            .map_err(|e| EnclaveError::QuoteGenerationFailed(format!("serialize: {}", e)))?;

        Ok(AttestationQuote {
            quote: quote.as_bytes().to_vec(),
            collateral: collateral_json,
        })
    }

    /// Mock quote generation for testing without SGX hardware
    #[cfg(feature = "mock-attestation")]
    pub fn generate_quote(&self, nonce: &[u8; ATTESTATION_NONCE_SIZE]) -> Result<AttestationQuote> {
        // Create report_data with nonce in first 32 bytes
        let mut report_data = [0u8; 64];
        report_data[..ATTESTATION_NONCE_SIZE].copy_from_slice(nonce);

        // Create a mock quote structure for testing
        let mock_quote = MockQuote {
            mr_enclave_hex: hex::encode(self.mock_mrenclave),
            mr_signer_hex: hex::encode([0u8; 32]),
            report_data_hex: hex::encode(report_data),
            isv_prod_id: 0,
            isv_svn: 0,
        };

        let quote = serde_json::to_vec(&mock_quote)
            .map_err(|e| EnclaveError::QuoteGenerationFailed(e.to_string()))?;

        let collateral = serde_json::to_vec(&MockCollateral {
            pck_cert_chain: "mock-pck-cert-chain".to_string(),
            tcb_info: "mock-tcb-info".to_string(),
            qe_identity: "mock-qe-identity".to_string(),
        })
        .map_err(|e| EnclaveError::QuoteGenerationFailed(e.to_string()))?;

        Ok(AttestationQuote { quote, collateral })
    }

    /// No-op quote generation when neither SGX nor mock is enabled
    #[cfg(not(any(feature = "sgx", feature = "mock-attestation")))]
    pub fn generate_quote(&self, _nonce: &[u8; ATTESTATION_NONCE_SIZE]) -> Result<AttestationQuote> {
        Err(EnclaveError::AttestationNotAvailable)
    }

    /// Set mock MRENCLAVE for testing
    #[cfg(feature = "mock-attestation")]
    pub fn set_mock_mrenclave(&mut self, mrenclave: MrEnclave) {
        self.mock_mrenclave = mrenclave;
    }
}

/// Mock quote structure for testing
#[cfg(feature = "mock-attestation")]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MockQuote {
    /// MRENCLAVE as hex string (32 bytes)
    pub mr_enclave_hex: String,
    /// MRSIGNER as hex string (32 bytes)
    pub mr_signer_hex: String,
    /// Report data as hex string (64 bytes, first 32 contain nonce)
    pub report_data_hex: String,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
}

#[cfg(feature = "mock-attestation")]
impl MockQuote {
    pub fn mr_enclave(&self) -> Option<[u8; 32]> {
        let bytes = hex::decode(&self.mr_enclave_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    pub fn report_data(&self) -> Option<[u8; 64]> {
        let bytes = hex::decode(&self.report_data_hex).ok()?;
        if bytes.len() != 64 {
            return None;
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }
}

/// Mock collateral for testing
#[cfg(feature = "mock-attestation")]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct MockCollateral {
    pub pck_cert_chain: String,
    pub tcb_info: String,
    pub qe_identity: String,
}

/// Extract MRENCLAVE from a quote
///
/// Works with both real DCAP quotes and mock quotes.
pub fn extract_mrenclave(quote: &[u8]) -> Result<MrEnclave> {
    // Try to parse as mock quote first (for testing)
    #[cfg(feature = "mock-attestation")]
    if let Ok(mock) = serde_json::from_slice::<MockQuote>(quote) {
        return mock.mr_enclave().ok_or_else(|| {
            EnclaveError::QuoteGenerationFailed("invalid mock MRENCLAVE".to_string())
        });
    }

    // Parse real DCAP quote
    // Quote structure: header (48 bytes) + report_body (384 bytes)
    // MRENCLAVE is at offset 112 in the report_body (offset 160 from start)
    if quote.len() < 192 {
        return Err(EnclaveError::QuoteGenerationFailed(
            "quote too short".to_string(),
        ));
    }

    let mut mrenclave = [0u8; 32];
    mrenclave.copy_from_slice(&quote[160..192]);
    Ok(mrenclave)
}

/// Extract nonce from quote's report_data
pub fn extract_nonce(quote: &[u8]) -> Result<[u8; ATTESTATION_NONCE_SIZE]> {
    // Try mock quote first
    #[cfg(feature = "mock-attestation")]
    if let Ok(mock) = serde_json::from_slice::<MockQuote>(quote) {
        let report_data = mock.report_data().ok_or_else(|| {
            EnclaveError::QuoteGenerationFailed("invalid mock report_data".to_string())
        })?;
        let mut nonce = [0u8; ATTESTATION_NONCE_SIZE];
        nonce.copy_from_slice(&report_data[..ATTESTATION_NONCE_SIZE]);
        return Ok(nonce);
    }

    // Real quote: report_data starts at offset 368 (48 + 320)
    if quote.len() < 400 {
        return Err(EnclaveError::QuoteGenerationFailed(
            "quote too short for report_data".to_string(),
        ));
    }

    let mut nonce = [0u8; ATTESTATION_NONCE_SIZE];
    nonce.copy_from_slice(&quote[368..368 + ATTESTATION_NONCE_SIZE]);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_cookie_generation() {
        let enclave = Enclave::new(&test_secret()).unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie1 = enclave.generate_cookie(ip, port, bucket);
        let cookie2 = enclave.generate_cookie(ip, port, bucket);

        // Same inputs produce same cookie
        assert_eq!(cookie1.bytes, cookie2.bytes);

        // Different bucket produces different cookie
        let cookie3 = enclave.generate_cookie(ip, port, bucket + 1);
        assert_ne!(cookie1.bytes, cookie3.bytes);
    }

    #[test]
    fn test_cookie_verification() {
        let enclave = Enclave::new(&test_secret()).unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie = enclave.generate_cookie(ip, port, bucket);

        // Verify with current bucket
        assert!(enclave.verify_cookie(ip, port, &cookie.bytes, bucket));

        // Verify with next bucket (previous window)
        assert!(enclave.verify_cookie(ip, port, &cookie.bytes, bucket + 1));

        // Fail with wrong IP
        let wrong_ip = Ipv4Addr::new(10, 0, 0, 1);
        assert!(!enclave.verify_cookie(wrong_ip, port, &cookie.bytes, bucket));

        // Fail with wrong port
        assert!(!enclave.verify_cookie(ip, port + 1, &cookie.bytes, bucket));

        // Fail with bucket too far in future
        assert!(!enclave.verify_cookie(ip, port, &cookie.bytes, bucket + 2));
    }

    #[test]
    fn test_invalid_secret_length() {
        let short_secret = [0u8; 16];
        assert!(matches!(
            Enclave::new(&short_secret),
            Err(EnclaveError::InvalidSecretLength(16))
        ));
    }

    #[cfg(feature = "mock-attestation")]
    #[test]
    fn test_mock_attestation() {
        let mut enclave = Enclave::new(&test_secret()).unwrap();
        let expected_mrenclave = [0xABu8; 32];
        enclave.set_mock_mrenclave(expected_mrenclave);

        let nonce = [0x12u8; ATTESTATION_NONCE_SIZE];
        let attestation = enclave.generate_quote(&nonce).unwrap();

        // Verify MRENCLAVE
        let mrenclave = extract_mrenclave(&attestation.quote).unwrap();
        assert_eq!(mrenclave, expected_mrenclave);

        // Verify nonce
        let extracted_nonce = extract_nonce(&attestation.quote).unwrap();
        assert_eq!(extracted_nonce, nonce);
    }

    #[cfg(feature = "mock-attestation")]
    #[test]
    fn test_mock_quote_serialization() {
        let mock = MockQuote {
            mr_enclave_hex: hex::encode([0xABu8; 32]),
            mr_signer_hex: hex::encode([0u8; 32]),
            report_data_hex: hex::encode([0x12u8; 64]),
            isv_prod_id: 1,
            isv_svn: 2,
        };

        let json = serde_json::to_string(&mock).unwrap();
        let parsed: MockQuote = serde_json::from_str(&json).unwrap();

        assert_eq!(mock.mr_enclave_hex, parsed.mr_enclave_hex);
        assert_eq!(parsed.mr_enclave().unwrap(), [0xABu8; 32]);
    }
}
