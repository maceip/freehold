//! ACME certificate management via DNS-01 challenge.
//!
//! The client drives the entire ACME flow:
//! 1. Wait for subdomain assignment from relay
//! 2. Check disk cache for a valid cert
//! 3. If none/expired, request DNS records via Engine, then run ACME DNS-01
//! 4. Hot-swap the cert into the running Quinn endpoint

use std::path::PathBuf;

use anyhow::{Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::EngineCommand;

/// Cached certificate on disk
#[derive(Serialize, Deserialize)]
struct CertCache {
    cert_pem: String,
    key_pem: String,
    expiry: i64,
    domain: String,
}

/// ACME certificate manager
pub struct AcmeManager {
    cache_dir: PathBuf,
    cmd_tx: mpsc::Sender<EngineCommand>,
}

impl AcmeManager {
    pub fn new(cache_dir: PathBuf, cmd_tx: mpsc::Sender<EngineCommand>) -> Self {
        Self { cache_dir, cmd_tx }
    }

    /// Load a cached certificate if it exists and is valid (not within 7 days of expiry).
    pub fn load_cached(
        &self,
        domain: &str,
    ) -> Option<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        let path = self.cache_path(domain);
        let data = std::fs::read_to_string(&path).ok()?;
        let cache: CertCache = serde_json::from_str(&data).ok()?;

        if cache.domain != domain {
            return None;
        }

        // Check expiry (must have >7 days remaining)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let seven_days = 7 * 24 * 3600;
        if cache.expiry - now < seven_days {
            info!("Cached cert for {} expires soon, will renew", domain);
            return None;
        }

        // Parse PEM
        let certs = Self::parse_cert_pem(&cache.cert_pem)?;
        let key = Self::parse_key_pem(&cache.key_pem)?;

        info!("Loaded cached ACME cert for {}", domain);
        Some((certs, key))
    }

    /// Run the full ACME DNS-01 flow to obtain a certificate.
    pub async fn obtain(
        &self,
        domain: &str,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        info!("Starting ACME DNS-01 flow for {}", domain);

        // 1. Create/load account
        let account = self.get_or_create_account().await?;

        // 2. Create new order
        let identifier = Identifier::Dns(domain.to_string());
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
            .context("ACME new order")?;

        // 3. Get authorizations and find DNS-01 challenge
        let authorizations = order.authorizations().await.context("get authorizations")?;
        let auth = authorizations
            .into_iter()
            .next()
            .context("no authorizations")?;

        if !matches!(auth.status, AuthorizationStatus::Pending) {
            debug!("Authorization already valid, skipping challenge");
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .context("no DNS-01 challenge")?;

        let dns_value = order.key_authorization(challenge).dns_value();
        debug!("DNS-01 challenge value: {}", dns_value);

        // 4. Set TXT record via Engine
        self.cmd_tx
            .send(EngineCommand::SetAcmeTxt(dns_value.as_bytes().to_vec()))
            .await
            .context("send SetAcmeTxt command")?;

        // 5. Wait for DNS propagation
        info!("Waiting 10s for DNS propagation...");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // 6. Tell ACME to validate
        order
            .set_challenge_ready(&challenge.url)
            .await
            .context("set challenge ready")?;

        // 7. Poll order status
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if tokio::time::Instant::now() > deadline {
                // Clean up TXT record before failing
                let _ = self.cmd_tx.send(EngineCommand::ClearAcmeTxt).await;
                anyhow::bail!("ACME order timed out");
            }

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let state = order.refresh().await.context("refresh order")?;
            match state.status {
                OrderStatus::Ready => {
                    info!("ACME order ready, finalizing");
                    break;
                }
                OrderStatus::Valid => {
                    info!("ACME order already valid");
                    break;
                }
                OrderStatus::Invalid => {
                    let _ = self.cmd_tx.send(EngineCommand::ClearAcmeTxt).await;
                    anyhow::bail!("ACME order invalid");
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    debug!("ACME order status: {:?}, polling...", state.status);
                }
            }
        }

        // 8. Generate key and CSR
        let key_pair = KeyPair::generate().context("generate key pair")?;
        let csr_params =
            CertificateParams::new(vec![domain.to_string()]).context("CSR params")?;
        let csr = csr_params
            .serialize_request(&key_pair)
            .context("serialize CSR")?;
        let csr_der = csr.der();

        // Finalize order
        order.finalize(csr_der).await.context("finalize order")?;

        // Poll for certificate
        let cert_chain_pem = loop {
            if tokio::time::Instant::now() > deadline {
                let _ = self.cmd_tx.send(EngineCommand::ClearAcmeTxt).await;
                anyhow::bail!("ACME certificate download timed out");
            }
            match order.certificate().await.context("get certificate")? {
                Some(cert) => break cert,
                None => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };

        // 9. Clear TXT record
        let _ = self.cmd_tx.send(EngineCommand::ClearAcmeTxt).await;

        // 10. Parse and cache
        let key_pem = key_pair.serialize_pem();

        let certs = Self::parse_cert_pem(&cert_chain_pem)
            .context("parse ACME cert chain")?;
        let private_key = Self::parse_key_pem(&key_pem)
            .context("parse ACME private key")?;

        // Calculate expiry (approximate: 90 days from now for LE)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expiry = now_secs + 90 * 24 * 3600;

        // Save to disk
        self.save_cache(domain, &cert_chain_pem, &key_pem, expiry)?;

        info!("ACME cert obtained for {}", domain);
        Ok((certs, private_key))
    }

    async fn get_or_create_account(&self) -> Result<Account> {
        let account_path = self.cache_dir.join("account.json");

        if account_path.exists() {
            let data = std::fs::read_to_string(&account_path)
                .context("read account cache")?;
            let credentials: instant_acme::AccountCredentials =
                serde_json::from_str(&data).context("parse account cache")?;
            let account = Account::from_credentials(credentials)
                .await
                .context("restore ACME account")?;
            info!("Loaded cached ACME account");
            return Ok(account);
        }

        // Create new account
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // Use Let's Encrypt production
            "https://acme-v02.api.letsencrypt.org/directory",
            None,
        )
        .await
        .context("create ACME account")?;

        // Cache credentials
        std::fs::create_dir_all(&self.cache_dir).context("create cache dir")?;
        let json = serde_json::to_string_pretty(&credentials)
            .context("serialize account")?;
        std::fs::write(&account_path, json).context("write account cache")?;
        info!("Created new ACME account");

        Ok(account)
    }

    fn cache_path(&self, domain: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", domain))
    }

    fn save_cache(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        expiry: i64,
    ) -> Result<()> {
        std::fs::create_dir_all(&self.cache_dir).context("create cache dir")?;
        let cache = CertCache {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            expiry,
            domain: domain.to_string(),
        };
        let json = serde_json::to_string_pretty(&cache).context("serialize cache")?;
        std::fs::write(self.cache_path(domain), json).context("write cert cache")?;
        debug!("Saved cert cache for {}", domain);
        Ok(())
    }

    fn parse_cert_pem(
        pem: &str,
    ) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        if certs.is_empty() {
            None
        } else {
            Some(certs)
        }
    }

    fn parse_key_pem(pem: &str) -> Option<rustls::pki_types::PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut pem.as_bytes()).ok()?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_cached_missing_file() {
        let (tx, _rx) = mpsc::channel(1);
        let mgr = AcmeManager::new(PathBuf::from("/tmp/nonexistent-acme-test"), tx);
        assert!(mgr.load_cached("example.com").is_none());
    }

    #[test]
    fn load_cached_expired() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let mgr = AcmeManager::new(dir.path().to_path_buf(), tx);

        // Write a cache entry that expired yesterday
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cache = CertCache {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"
                .to_string(),
            expiry: now - 86400, // expired yesterday
            domain: "example.com".to_string(),
        };
        let json = serde_json::to_string(&cache).unwrap();
        std::fs::write(dir.path().join("example.com.json"), json).unwrap();

        assert!(mgr.load_cached("example.com").is_none());
    }

    #[test]
    fn load_cached_wrong_domain() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let mgr = AcmeManager::new(dir.path().to_path_buf(), tx);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cache = CertCache {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            expiry: now + 30 * 86400,
            domain: "other.com".to_string(),
        };
        let json = serde_json::to_string(&cache).unwrap();
        std::fs::write(dir.path().join("example.com.json"), json).unwrap();

        assert!(mgr.load_cached("example.com").is_none());
    }
}
