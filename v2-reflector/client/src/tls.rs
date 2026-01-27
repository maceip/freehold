//! TLS certificate management

use std::path::PathBuf;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

/// Load existing certificate or generate a self-signed one
pub fn load_or_generate_cert(
    data_dir: &PathBuf,
    domain: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = data_dir.join(format!("{}.crt", domain));
    let key_path = data_dir.join(format!("{}.key", domain));

    // Try to load existing
    if cert_path.exists() && key_path.exists() {
        info!("Loading existing certificate for {}", domain);

        let cert_pem = std::fs::read(&cert_path)
            .with_context(|| format!("Failed to read {}", cert_path.display()))?;
        let key_pem = std::fs::read(&key_path)
            .with_context(|| format!("Failed to read {}", key_path.display()))?;

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .filter_map(|r| r.ok())
            .collect();

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

        return Ok((certs, key));
    }

    // Generate new self-signed cert
    info!("Generating self-signed certificate for {}", domain);

    let key_pair = KeyPair::generate()?;
    let params = CertificateParams::new(vec![domain.to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Save to disk
    std::fs::write(&cert_path, cert_pem.as_bytes())?;
    std::fs::write(&key_path, key_pem.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!("Saved certificate to {}", cert_path.display());

    // Parse back
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("Failed to parse generated key"))?;

    Ok((certs, key))
}
