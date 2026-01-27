//! Certificate generation utilities.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};

/// Generate a self-signed certificate for testing/development.
///
/// For production, use certificates from Let's Encrypt or another CA.
pub fn generate_self_signed_cert(
    domains: &[&str],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let key_pair = KeyPair::generate().context("generate key pair")?;

    let subject_alt_names: Vec<String> = domains.iter().map(|s| s.to_string()).collect();

    let params = CertificateParams::new(subject_alt_names).context("cert params")?;

    let cert = params.self_signed(&key_pair).context("self-sign")?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("key conversion: {:?}", e))?;

    Ok((vec![cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cert() {
        let result = generate_self_signed_cert(&["localhost"]);
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_generate_cert_multiple_domains() {
        let result = generate_self_signed_cert(&["localhost", "127.0.0.1", "example.com"]);
        assert!(result.is_ok());
    }
}
