//! ACME DNS-01 certificate management.
//!
//! This module provides automatic certificate provisioning using the ACME protocol
//! with DNS-01 challenges. This is required for QUIC/H3 servers since HTTP-01
//! challenges require port 80 which QUIC doesn't use.
//!
//! # DNS-01 Challenge Flow
//!
//! 1. Create an ACME account (or restore from saved credentials)
//! 2. Request a certificate order for your domain
//! 3. Get the DNS-01 challenge token
//! 4. Set a TXT record at `_acme-challenge.yourdomain.com`
//! 5. ACME server validates the TXT record
//! 6. Submit a CSR (Certificate Signing Request)
//! 7. Download the signed certificate

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Errors from ACME operations.
#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(String),
    #[error("DNS provider error: {0}")]
    DnsProvider(String),
    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),
    #[error("Certificate generation error: {0}")]
    CertGeneration(String),
    #[error("Order timeout")]
    Timeout,
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
}

/// Trait for DNS providers that can set TXT records for DNS-01 challenges.
///
/// Implementations should handle the specifics of their DNS provider's API.
/// Use the `#[async_trait]` macro when implementing this trait.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Set a TXT record for the DNS-01 challenge.
    ///
    /// The record should be set at `_acme-challenge.{domain}` with the given value.
    async fn set_txt_record(&self, domain: &str, value: &str) -> Result<(), AcmeError>;

    /// Remove the TXT record after challenge completion.
    async fn clear_txt_record(&self, domain: &str) -> Result<(), AcmeError>;

    /// Wait for DNS propagation (optional, default 30s delay).
    async fn wait_for_propagation(&self) -> Result<(), AcmeError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(())
    }
}

/// A certificate and its private key.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// The domain this certificate is for.
    pub domain: String,
}

impl Certificate {
    /// Get the certificate as DER bytes.
    pub fn cert_der(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, AcmeError> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut self.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AcmeError::CertGeneration(format!("Failed to parse cert: {}", e)))?;
        Ok(certs)
    }

    /// Get the private key as DER.
    pub fn key_der(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>, AcmeError> {
        rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .map_err(|e| AcmeError::CertGeneration(format!("Failed to parse key: {}", e)))?
            .ok_or_else(|| AcmeError::CertGeneration("No private key in PEM".to_string()))
    }
}

/// ACME certificate manager for DNS-01 challenges.
///
/// This manager handles the full ACME workflow for obtaining TLS certificates
/// using the DNS-01 challenge type, which is required for QUIC/H3 servers.
pub struct AcmeCertManager<D: DnsProvider> {
    account: Arc<RwLock<Account>>,
    dns_provider: D,
    #[allow(dead_code)]
    directory_url: String,
}

impl<D: DnsProvider> AcmeCertManager<D> {
    /// Create a new ACME certificate manager.
    ///
    /// # Arguments
    ///
    /// * `directory_url` - ACME directory URL (use `LETS_ENCRYPT_STAGING` for testing)
    /// * `contact_email` - Email for account registration and notifications
    /// * `dns_provider` - Your DNS provider implementation
    pub async fn new(
        directory_url: &str,
        contact_email: &str,
        dns_provider: D,
    ) -> Result<Self, AcmeError> {
        info!("Creating ACME account with {}", directory_url);

        let contact = format!("mailto:{}", contact_email);
        let new_account = NewAccount {
            contact: &[&contact],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let (account, _credentials) = Account::builder()
            .map_err(|e| AcmeError::Protocol(format!("Failed to create builder: {}", e)))?
            .create(&new_account, directory_url.to_string(), None)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to create account: {}", e)))?;

        info!("ACME account created successfully");

        Ok(Self {
            account: Arc::new(RwLock::new(account)),
            dns_provider,
            directory_url: directory_url.to_string(),
        })
    }

    /// Create from existing account credentials.
    ///
    /// Use this to restore a previously created account.
    pub async fn from_credentials(
        credentials: AccountCredentials,
        dns_provider: D,
        directory_url: &str,
    ) -> Result<Self, AcmeError> {
        let account = Account::builder()
            .map_err(|e| AcmeError::Protocol(format!("Failed to create builder: {}", e)))?
            .from_credentials(credentials)
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to restore account: {}", e)))?;

        Ok(Self {
            account: Arc::new(RwLock::new(account)),
            dns_provider,
            directory_url: directory_url.to_string(),
        })
    }

    /// Obtain a certificate for the given domain using DNS-01 challenge.
    ///
    /// This will:
    /// 1. Create a new order for the domain
    /// 2. Get the DNS-01 challenge
    /// 3. Set the TXT record via the DNS provider
    /// 4. Wait for validation
    /// 5. Finalize and get the certificate
    pub async fn obtain_certificate(&self, domain: &str) -> Result<Certificate, AcmeError> {
        info!("Requesting certificate for {}", domain);

        // Validate domain
        if domain.is_empty() || domain.contains(' ') {
            return Err(AcmeError::InvalidDomain(domain.to_string()));
        }

        // Create order
        let account = self.account.read().await;
        let identifiers = [Identifier::Dns(domain.to_string())];

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to create order: {}", e)))?;

        debug!("Order created, getting authorizations");

        // Process authorizations
        let mut authorizations = order.authorizations();
        while let Some(auth_result) = authorizations.next().await {
            let mut auth = auth_result
                .map_err(|e| AcmeError::Protocol(format!("Failed to get authorization: {}", e)))?;

            // Find DNS-01 challenge
            let mut challenge = auth
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| {
                    AcmeError::ChallengeFailed("No DNS-01 challenge available".to_string())
                })?;

            // Get the DNS TXT value
            let dns_value = challenge.key_authorization().dns_value();

            info!("Setting DNS TXT record for _acme-challenge.{}", domain);
            debug!("TXT value: {}", dns_value);

            // Set the TXT record
            self.dns_provider
                .set_txt_record(domain, &dns_value)
                .await?;

            // Wait for DNS propagation
            info!("Waiting for DNS propagation...");
            self.dns_provider.wait_for_propagation().await?;

            // Tell ACME to validate
            challenge
                .set_ready()
                .await
                .map_err(|e| AcmeError::Protocol(format!("Failed to set challenge ready: {}", e)))?;
        }

        // Wait for order to be ready
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 20;

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let state = order
                .refresh()
                .await
                .map_err(|e| AcmeError::Protocol(format!("Failed to refresh order: {}", e)))?;

            debug!("Order status: {:?}", state.status);

            match state.status {
                OrderStatus::Ready => {
                    info!("Order ready, finalizing");
                    break;
                }
                OrderStatus::Invalid => {
                    let _ = self.dns_provider.clear_txt_record(domain).await;
                    return Err(AcmeError::ChallengeFailed(
                        "Order became invalid".to_string(),
                    ));
                }
                OrderStatus::Valid => {
                    break;
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        let _ = self.dns_provider.clear_txt_record(domain).await;
                        return Err(AcmeError::Timeout);
                    }
                }
            }
        }

        // Finalize and get the certificate
        // The finalize() method generates the key pair internally
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::Protocol(format!("Failed to finalize order: {}", e)))?;

        // Wait for certificate
        let mut attempts = 0;
        let cert_pem = loop {
            tokio::time::sleep(Duration::from_secs(2)).await;

            match order.certificate().await {
                Ok(Some(cert)) => break cert,
                Ok(None) => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        let _ = self.dns_provider.clear_txt_record(domain).await;
                        return Err(AcmeError::Timeout);
                    }
                }
                Err(e) => {
                    let _ = self.dns_provider.clear_txt_record(domain).await;
                    return Err(AcmeError::Protocol(format!(
                        "Failed to download certificate: {}",
                        e
                    )));
                }
            }
        };

        // Clean up DNS record
        if let Err(e) = self.dns_provider.clear_txt_record(domain).await {
            warn!("Failed to clear DNS TXT record: {}", e);
        }

        info!("Certificate obtained successfully for {}", domain);

        Ok(Certificate {
            cert_pem,
            key_pem,
            domain: domain.to_string(),
        })
    }

    /// Let's Encrypt production directory URL.
    pub const LETS_ENCRYPT_PRODUCTION: &'static str =
        "https://acme-v02.api.letsencrypt.org/directory";

    /// Let's Encrypt staging directory URL (for testing).
    pub const LETS_ENCRYPT_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

/// A manual DNS provider that prompts the user to set records.
///
/// Use this for testing or when automatic DNS updates aren't available.
pub struct ManualDnsProvider;

#[async_trait]
impl DnsProvider for ManualDnsProvider {
    async fn set_txt_record(&self, domain: &str, value: &str) -> Result<(), AcmeError> {
        println!("\n=== MANUAL DNS ACTION REQUIRED ===");
        println!("Create a TXT record:");
        println!("  Name:  _acme-challenge.{}", domain);
        println!("  Value: {}", value);
        println!("Press Enter after setting the record...");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| {
            AcmeError::DnsProvider(format!("Failed to read input: {}", e))
        })?;

        Ok(())
    }

    async fn clear_txt_record(&self, domain: &str) -> Result<(), AcmeError> {
        println!("\n=== MANUAL DNS ACTION REQUIRED ===");
        println!("Remove the TXT record for: _acme-challenge.{}", domain);
        Ok(())
    }
}

/// A no-op DNS provider for testing (records are not actually set).
pub struct MockDnsProvider {
    records: Arc<RwLock<Vec<(String, String)>>>,
}

impl MockDnsProvider {
    /// Create a new mock DNS provider.
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get all recorded TXT records.
    pub async fn records(&self) -> Vec<(String, String)> {
        self.records.read().await.clone()
    }
}

impl Default for MockDnsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn set_txt_record(&self, domain: &str, value: &str) -> Result<(), AcmeError> {
        self.records
            .write()
            .await
            .push((domain.to_string(), value.to_string()));
        Ok(())
    }

    async fn clear_txt_record(&self, domain: &str) -> Result<(), AcmeError> {
        self.records
            .write()
            .await
            .retain(|(d, _)| d != domain);
        Ok(())
    }

    async fn wait_for_propagation(&self) -> Result<(), AcmeError> {
        // No delay in mock
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_struct() {
        let cert = Certificate {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            domain: "example.com".to_string(),
        };

        assert_eq!(cert.domain, "example.com");
    }

    #[test]
    fn test_acme_error_display() {
        let err = AcmeError::InvalidDomain("bad domain".to_string());
        assert!(err.to_string().contains("bad domain"));

        let err = AcmeError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn test_mock_dns_provider() {
        let provider = MockDnsProvider::new();

        provider
            .set_txt_record("example.com", "test-value")
            .await
            .unwrap();

        let records = provider.records().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "example.com");
        assert_eq!(records[0].1, "test-value");

        provider.clear_txt_record("example.com").await.unwrap();

        let records = provider.records().await;
        assert!(records.is_empty());
    }

    #[test]
    fn test_lets_encrypt_urls() {
        assert!(AcmeCertManager::<MockDnsProvider>::LETS_ENCRYPT_PRODUCTION.contains("acme-v02"));
        assert!(AcmeCertManager::<MockDnsProvider>::LETS_ENCRYPT_STAGING.contains("staging"));
    }

    #[tokio::test]
    async fn test_mock_provider_no_propagation_delay() {
        let provider = MockDnsProvider::new();

        // Should return immediately
        let start = std::time::Instant::now();
        provider.wait_for_propagation().await.unwrap();
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
