//! Cryptographic utilities for TLS certificates and ACME DNS-01 challenges.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::PathBuf;
use tracing::info;

/// Directory where certificates and keys are stored
fn cert_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("specular")
        .join("certs")
}

/// Stored certificate bundle
#[derive(Debug)]
pub struct CertBundle {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl CertBundle {
    /// Load certificates from disk
    pub fn load(domain: &str) -> Result<Option<Self>> {
        let dir = cert_dir();
        let cert_path = dir.join(format!("{}.crt", domain));
        let key_path = dir.join(format!("{}.key", domain));

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_pem = std::fs::read(&cert_path)
            .with_context(|| format!("Failed to read cert: {}", cert_path.display()))?;
        let key_pem = std::fs::read(&key_path)
            .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

        let cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .filter_map(|r| r.ok())
                .collect();

        let private_key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;

        info!("Loaded existing certificate for {}", domain);
        Ok(Some(CertBundle {
            cert_chain,
            private_key,
        }))
    }

    /// Save certificates to disk
    pub fn save(&self, domain: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
        let dir = cert_dir();
        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join(format!("{}.crt", domain));
        let key_path = dir.join(format!("{}.key", domain));

        std::fs::write(&cert_path, cert_pem)?;
        std::fs::write(&key_path, key_pem)?;

        // Restrict permissions on key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!("Saved certificate to {}", cert_path.display());
        Ok(())
    }
}

/// ACME DNS-01 challenge info that needs to be provisioned
#[derive(Debug, Clone)]
pub struct DnsChallenge {
    pub record_name: String, // _acme-challenge.example.com
    pub record_value: String, // The TXT record value
}

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed(domain: &str) -> Result<CertBundle> {
    info!("Generating self-signed certificate for {}", domain);

    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, domain);
    params
        .subject_alt_names
        .push(SanType::DnsName(domain.try_into()?));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();

    let private_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("Failed to parse generated private key"))?;

    let bundle = CertBundle {
        cert_chain,
        private_key,
    };

    // Save to disk for reuse
    bundle.save(domain, cert_pem.as_bytes(), key_pem.as_bytes())?;

    Ok(bundle)
}

// TODO: ACME DNS-01 implementation
// The ACME module would include:
// - Account creation/loading
// - Order creation
// - DNS-01 challenge handling
// - Certificate finalization
// For now, use self-signed certificates for development

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_signed() {
        let bundle = generate_self_signed("test.local").unwrap();
        assert!(!bundle.cert_chain.is_empty());
    }
}
