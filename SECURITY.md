# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Do NOT open a public issue for security vulnerabilities.**

Instead, please email security concerns to: **ryan.macarthur@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Resolution Timeline:** Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

### Disclosure Policy

- We follow coordinated disclosure
- We'll work with you on timing
- Credit will be given (unless you prefer anonymity)

## Security Considerations

### Server (freehold-server)

The relay server runs with elevated privileges (eBPF/XDP requires root). Key security measures:

- **Stateless authentication:** HMAC cookies prevent state exhaustion attacks
- **Rate limiting:** Per-IP quota enforcement in eBPF
- **Input validation:** All packets validated before processing
- **Privilege separation:** eBPF handles packets, userspace handles registration

### Client (freehold-client)

- Cookies are memory-only, never persisted
- No credentials stored on disk
- TLS certificate validation for H3 proxy

### Protocol Security

- Registration uses HMAC-SHA256 with 16-byte truncated cookies
- Time-bucketed cookies prevent replay attacks
- Challenge-response prevents IP spoofing

## Known Limitations

- UDP registration can be blocked by strict firewalls
- Self-signed certificates require client trust configuration
- Anycast may route to suboptimal relay under network issues

## Security Updates

Security updates are released as patch versions and announced via:
- GitHub releases
- Repository security advisories
