//! Cookie generation and verification for registration handshake
//!
//! This module implements stateless cookie-based verification to prevent
//! IP spoofing during port registration.

use freehold_api::COOKIE_SIZE;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::Ipv4Addr;

type HmacSha256 = Hmac<Sha256>;

/// Cookie generator/verifier using HMAC-SHA256
#[derive(Clone)]
pub struct CookieAuth {
    secret: [u8; 32],
}

impl CookieAuth {
    /// Create a new CookieAuth with the given secret
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Generate a cookie for an IP, port, and time bucket
    pub fn generate(&self, ip: Ipv4Addr, port: u16, bucket: u64) -> [u8; COOKIE_SIZE] {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&ip.octets());
        mac.update(&port.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&mac.finalize().into_bytes()[..COOKIE_SIZE]);
        cookie
    }

    /// Verify a cookie against IP, port, and a set of valid time buckets
    pub fn verify(
        &self,
        ip: Ipv4Addr,
        port: u16,
        cookie: &[u8; COOKIE_SIZE],
        valid_buckets: &[u64],
    ) -> bool {
        valid_buckets
            .iter()
            .any(|&bucket| &self.generate(ip, port, bucket) == cookie)
    }

    /// Verify a cookie using current and previous time bucket
    pub fn verify_with_grace(
        &self,
        ip: Ipv4Addr,
        port: u16,
        cookie: &[u8; COOKIE_SIZE],
        current_bucket: u64,
    ) -> bool {
        self.verify(
            ip,
            port,
            cookie,
            &[current_bucket, current_bucket.saturating_sub(1)],
        )
    }

    /// Derive a stable subdomain for an IP/port pair.
    ///
    /// Computes HMAC-SHA256(secret, ip || port) (no time bucket),
    /// base32-encodes the result, and takes the first 12 characters lowercased.
    pub fn subdomain(&self, ip: Ipv4Addr, port: u16) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&ip.octets());
        mac.update(&port.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        let encoded = data_encoding::BASE32_NOPAD.encode(&hash);
        encoded[..12].to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn generate_deterministic() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie1 = auth.generate(ip, port, bucket);
        let cookie2 = auth.generate(ip, port, bucket);

        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn generate_different_inputs_different_outputs() {
        let auth = CookieAuth::new(test_secret());
        let bucket = 12345u64;

        let c1 = auth.generate(Ipv4Addr::new(10, 0, 0, 1), 8080, bucket);
        let c2 = auth.generate(Ipv4Addr::new(10, 0, 0, 2), 8080, bucket); // Different IP
        let c3 = auth.generate(Ipv4Addr::new(10, 0, 0, 1), 8081, bucket); // Different port
        let c4 = auth.generate(Ipv4Addr::new(10, 0, 0, 1), 8080, bucket + 1); // Different bucket

        // All should be different
        assert_ne!(c1, c2);
        assert_ne!(c1, c3);
        assert_ne!(c1, c4);
        assert_ne!(c2, c3);
        assert_ne!(c2, c4);
        assert_ne!(c3, c4);
    }

    #[test]
    fn generate_different_secrets_different_outputs() {
        let auth1 = CookieAuth::new([0x42; 32]);
        let auth2 = CookieAuth::new([0x43; 32]);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let bucket = 12345u64;

        let c1 = auth1.generate(ip, port, bucket);
        let c2 = auth2.generate(ip, port, bucket);

        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_valid_cookie() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie = auth.generate(ip, port, bucket);
        assert!(auth.verify(ip, port, &cookie, &[bucket]));
    }

    #[test]
    fn verify_invalid_cookie() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie = auth.generate(ip, port, bucket);

        // Wrong IP
        assert!(!auth.verify(Ipv4Addr::new(10, 0, 0, 2), port, &cookie, &[bucket]));

        // Wrong port
        assert!(!auth.verify(ip, 8081, &cookie, &[bucket]));

        // Wrong bucket
        assert!(!auth.verify(ip, port, &cookie, &[bucket + 2]));

        // Tampered cookie
        let mut bad_cookie = cookie;
        bad_cookie[0] ^= 0xFF;
        assert!(!auth.verify(ip, port, &bad_cookie, &[bucket]));
    }

    #[test]
    fn verify_multiple_buckets() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let bucket = 12345u64;

        let cookie = auth.generate(ip, port, bucket);

        // Should match when bucket is in the valid set
        assert!(auth.verify(ip, port, &cookie, &[bucket - 1, bucket, bucket + 1]));
        assert!(auth.verify(ip, port, &cookie, &[bucket + 100, bucket]));

        // Should not match when bucket is not in valid set
        assert!(!auth.verify(ip, port, &cookie, &[bucket - 1, bucket + 1]));
    }

    #[test]
    fn verify_with_grace_current_bucket() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let current_bucket = 12345u64;

        let cookie = auth.generate(ip, port, current_bucket);
        assert!(auth.verify_with_grace(ip, port, &cookie, current_bucket));
    }

    #[test]
    fn verify_with_grace_previous_bucket() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let current_bucket = 12345u64;

        // Cookie generated in previous bucket
        let cookie = auth.generate(ip, port, current_bucket - 1);
        assert!(auth.verify_with_grace(ip, port, &cookie, current_bucket));
    }

    #[test]
    fn verify_with_grace_old_bucket_fails() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let current_bucket = 12345u64;

        // Cookie from 2 buckets ago should fail
        let cookie = auth.generate(ip, port, current_bucket - 2);
        assert!(!auth.verify_with_grace(ip, port, &cookie, current_bucket));
    }

    #[test]
    fn verify_with_grace_future_bucket_fails() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let current_bucket = 12345u64;

        // Cookie from future bucket should fail
        let cookie = auth.generate(ip, port, current_bucket + 1);
        assert!(!auth.verify_with_grace(ip, port, &cookie, current_bucket));
    }

    #[test]
    fn verify_with_grace_bucket_zero() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;

        // Edge case: bucket 0 should not underflow
        let cookie = auth.generate(ip, port, 0);
        assert!(auth.verify_with_grace(ip, port, &cookie, 0));
        assert!(auth.verify_with_grace(ip, port, &cookie, 1));
    }

    #[test]
    fn cookie_size_is_correct() {
        let auth = CookieAuth::new(test_secret());
        let cookie = auth.generate(Ipv4Addr::LOCALHOST, 8080, 0);
        assert_eq!(cookie.len(), COOKIE_SIZE);
        assert_eq!(COOKIE_SIZE, 16);
    }

    #[test]
    fn subdomain_deterministic() {
        let auth = CookieAuth::new(test_secret());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let port = 8080;
        let s1 = auth.subdomain(ip, port);
        let s2 = auth.subdomain(ip, port);
        assert_eq!(s1, s2);
    }

    #[test]
    fn subdomain_is_12_chars_lowercase() {
        let auth = CookieAuth::new(test_secret());
        let sub = auth.subdomain(Ipv4Addr::new(10, 0, 0, 1), 8080);
        assert_eq!(sub.len(), 12);
        assert!(sub.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn subdomain_different_inputs_different_outputs() {
        let auth = CookieAuth::new(test_secret());
        let s1 = auth.subdomain(Ipv4Addr::new(10, 0, 0, 1), 8080);
        let s2 = auth.subdomain(Ipv4Addr::new(10, 0, 0, 2), 8080);
        let s3 = auth.subdomain(Ipv4Addr::new(10, 0, 0, 1), 8081);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s2, s3);
    }

    #[test]
    fn subdomain_different_secrets() {
        let auth1 = CookieAuth::new([0x42; 32]);
        let auth2 = CookieAuth::new([0x43; 32]);
        let s1 = auth1.subdomain(Ipv4Addr::LOCALHOST, 443);
        let s2 = auth2.subdomain(Ipv4Addr::LOCALHOST, 443);
        assert_ne!(s1, s2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn secret_strategy() -> impl Strategy<Value = [u8; 32]> {
        prop::array::uniform32(any::<u8>())
    }

    fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    proptest! {
        /// Cookies should always be exactly COOKIE_SIZE bytes
        #[test]
        fn prop_cookie_size(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket in any::<u64>()
        ) {
            let auth = CookieAuth::new(secret);
            let cookie = auth.generate(ip, port, bucket);
            prop_assert_eq!(cookie.len(), COOKIE_SIZE);
        }

        /// Same inputs should always produce same cookie
        #[test]
        fn prop_deterministic(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket in any::<u64>()
        ) {
            let auth = CookieAuth::new(secret);
            let c1 = auth.generate(ip, port, bucket);
            let c2 = auth.generate(ip, port, bucket);
            prop_assert_eq!(c1, c2);
        }

        /// Generated cookies should verify with same inputs
        #[test]
        fn prop_roundtrip_verify(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket in any::<u64>()
        ) {
            let auth = CookieAuth::new(secret);
            let cookie = auth.generate(ip, port, bucket);
            prop_assert!(auth.verify(ip, port, &cookie, &[bucket]));
        }

        /// Different IPs should produce different cookies
        #[test]
        fn prop_different_ips_different_cookies(
            secret in secret_strategy(),
            ip1 in ipv4_strategy(),
            ip2 in ipv4_strategy(),
            port in any::<u16>(),
            bucket in any::<u64>()
        ) {
            prop_assume!(ip1 != ip2);
            let auth = CookieAuth::new(secret);
            let c1 = auth.generate(ip1, port, bucket);
            let c2 = auth.generate(ip2, port, bucket);
            prop_assert_ne!(c1, c2);
        }

        /// Different ports should produce different cookies
        #[test]
        fn prop_different_ports_different_cookies(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port1 in any::<u16>(),
            port2 in any::<u16>(),
            bucket in any::<u64>()
        ) {
            prop_assume!(port1 != port2);
            let auth = CookieAuth::new(secret);
            let c1 = auth.generate(ip, port1, bucket);
            let c2 = auth.generate(ip, port2, bucket);
            prop_assert_ne!(c1, c2);
        }

        /// Different buckets should produce different cookies
        #[test]
        fn prop_different_buckets_different_cookies(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket1 in any::<u64>(),
            bucket2 in any::<u64>()
        ) {
            prop_assume!(bucket1 != bucket2);
            let auth = CookieAuth::new(secret);
            let c1 = auth.generate(ip, port, bucket1);
            let c2 = auth.generate(ip, port, bucket2);
            prop_assert_ne!(c1, c2);
        }

        /// Different secrets should produce different cookies
        #[test]
        fn prop_different_secrets_different_cookies(
            secret1 in secret_strategy(),
            secret2 in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket in any::<u64>()
        ) {
            prop_assume!(secret1 != secret2);
            let auth1 = CookieAuth::new(secret1);
            let auth2 = CookieAuth::new(secret2);
            let c1 = auth1.generate(ip, port, bucket);
            let c2 = auth2.generate(ip, port, bucket);
            prop_assert_ne!(c1, c2);
        }

        /// verify_with_grace should accept current and previous bucket
        #[test]
        fn prop_grace_accepts_valid_buckets(
            secret in secret_strategy(),
            ip in ipv4_strategy(),
            port in any::<u16>(),
            bucket in 1u64..u64::MAX  // Start at 1 to allow previous bucket
        ) {
            let auth = CookieAuth::new(secret);

            // Current bucket should work
            let cookie_current = auth.generate(ip, port, bucket);
            prop_assert!(auth.verify_with_grace(ip, port, &cookie_current, bucket));

            // Previous bucket should work
            let cookie_prev = auth.generate(ip, port, bucket - 1);
            prop_assert!(auth.verify_with_grace(ip, port, &cookie_prev, bucket));
        }
    }
}
