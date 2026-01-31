# Freehold Remote Attestation Specification

## Overview

This document specifies how users can verify that a Freehold relay is running
authentic, unmodified code. The MRENCLAVE (enclave measurement hash) is **not**
stamped in packets—that would be wasteful. Instead, clients fetch and verify
an attestation quote on-demand.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RELAY SERVER                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │                    SGX ENCLAVE (Gramine)                               ││
│  │  ┌──────────────────────┐  ┌──────────────────────┐                   ││
│  │  │  HMAC Secret Store   │  │  Quote Generation    │                   ││
│  │  │  - 32-byte key       │  │  - DCAP ECDSA quote  │                   ││
│  │  │  - Never leaves      │  │  - Includes nonce    │                   ││
│  │  └──────────────────────┘  └──────────────────────┘                   ││
│  │  ┌──────────────────────┐                                             ││
│  │  │  Cookie Operations   │                                             ││
│  │  │  - generate(ip,port) │                                             ││
│  │  │  - verify(ip,port,c) │                                             ││
│  │  └──────────────────────┘                                             ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                     ↑ ECALL                     ↓ Quote                    │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │                    USERSPACE (Untrusted)                               ││
│  │  - UDP listener (port 9999)                                            ││
│  │  - eBPF map management                                                 ││
│  │  - Attestation request handler                                         ││
│  └────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ UDP Protocol
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CLIENT                                           │
│  1. Send AttestationRequest with nonce                                      │
│  2. Receive AttestationResponse with quote                                  │
│  3. Verify quote using DCAP library (no SGX HW needed)                      │
│  4. Extract MRENCLAVE from quote                                            │
│  5. Compare to expected value from GitHub release                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Protocol Extension

### New Message Types

Added to the existing Freehold protocol:

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| AttestationRequest | 0x10 | C→S | Request quote with nonce |
| AttestationResponse | 0x11 | S→C | Quote + collateral |

### AttestationRequest (0x10)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic     |     0x10      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                        Nonce (32 bytes)                       +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Magic**: 0x46 ('F')
- **Type**: 0x10 (AttestationRequest)
- **Nonce**: 32-byte random value for freshness

### AttestationResponse (0x11)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic     |     0x11      |         Quote Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    SGX Quote (variable)                       +
|                       (includes nonce in report_data)         |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Collateral Length      |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                  Collateral JSON (variable)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Quote**: DCAP ECDSA quote (typically ~4KB)
- **Collateral**: JSON with PCK cert chain, TCB info, QE identity

## Quote Structure

The SGX quote contains (simplified):

```rust
struct Quote3 {
    header: QuoteHeader,
    report_body: ReportBody,  // Contains MRENCLAVE, MRSIGNER, report_data
    signature: EcdsaSignature,
    auth_data: AuthData,      // Certification data
}

struct ReportBody {
    cpu_svn: [u8; 16],
    misc_select: u32,
    attributes: [u8; 16],
    mr_enclave: [u8; 32],     // ← THE MEASUREMENT
    mr_signer: [u8; 32],
    isv_prod_id: u16,
    isv_svn: u16,
    report_data: [u8; 64],    // ← CONTAINS CLIENT NONCE
}
```

## Verification Flow

### Client-Side Verification

```rust
fn verify_relay(relay: &str, expected_mrenclave: &[u8; 32]) -> Result<bool> {
    // 1. Generate random nonce
    let nonce: [u8; 32] = rand::random();

    // 2. Request attestation
    let response = send_attestation_request(relay, nonce)?;

    // 3. Parse quote
    let quote = Quote3::parse(&response.quote)?;

    // 4. Verify nonce is in report_data (freshness)
    if &quote.report_body.report_data[..32] != &nonce {
        return Err("Quote is stale or replayed");
    }

    // 5. Verify quote signature chain (Intel root of trust)
    let result = dcap_verify(&response.quote, &response.collateral)?;
    if result.status != VerificationStatus::Ok {
        return Err("Quote verification failed");
    }

    // 6. Compare MRENCLAVE
    if &quote.report_body.mr_enclave != expected_mrenclave {
        return Err("MRENCLAVE mismatch - relay running different code");
    }

    Ok(true)
}
```

### Expected MRENCLAVE Distribution

Published in multiple locations for redundancy:

1. **GitHub Releases**: `attestation/mrenclave.txt` artifact
2. **DNS TXT Record**: `_mrenclave.freehold.example.com`
3. **Signed File**: `releases/v1.0.0/mrenclave.sig` (GPG signed)

Format:
```
# Freehold v1.0.0 MRENCLAVE
# Built from commit: abc123...
# Build date: 2024-01-15
0xdb718ecdcec7b7db2cd7206b7599b2472c02376195b70629fa72690e377ba69c
```

## Reproducible Build

### Dockerfile

```dockerfile
FROM gramineproject/gramine:v1.8

# Use exact versions for reproducibility
RUN apt-get update && apt-get install -y \
    curl=7.88.1-10+deb12u4 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain (pinned)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain 1.75.0
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy only what's needed (ordered by change frequency)
COPY Cargo.toml Cargo.lock ./
COPY crates/freehold-common ./crates/freehold-common
COPY crates/freehold-api ./crates/freehold-api
COPY crates/freehold-enclave ./crates/freehold-enclave

# Build with locked deps
RUN cargo build --release --locked -p freehold-enclave

# Generate SGX artifacts
COPY gramine/freehold.manifest.template ./
RUN gramine-sgx-gen-private-key
RUN gramine-manifest \
    -Dlog_level=error \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    freehold.manifest.template freehold.manifest
RUN gramine-sgx-sign --manifest freehold.manifest --output freehold.manifest.sgx

# Extract MRENCLAVE for verification
RUN gramine-sgx-sigstruct-view freehold.sig | tee sigstruct.txt
```

### GitHub Actions Workflow

```yaml
name: Build Attestable Enclave

on:
  release:
    types: [published]
  workflow_dispatch:

jobs:
  build-enclave:
    runs-on: ubuntu-latest
    container:
      image: gramineproject/gramine:v1.8

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        run: |
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
            sh -s -- -y --default-toolchain 1.75.0
          echo "$HOME/.cargo/bin" >> $GITHUB_PATH

      - name: Build enclave
        run: |
          cargo build --release --locked -p freehold-enclave
          gramine-sgx-gen-private-key
          gramine-manifest freehold.manifest.template freehold.manifest
          gramine-sgx-sign --manifest freehold.manifest --output freehold.manifest.sgx

      - name: Extract MRENCLAVE
        id: mrenclave
        run: |
          MRENCLAVE=$(gramine-sgx-sigstruct-view freehold.sig | grep mr_enclave | awk '{print $2}')
          echo "mrenclave=$MRENCLAVE" >> $GITHUB_OUTPUT
          echo "## MRENCLAVE" >> $GITHUB_STEP_SUMMARY
          echo "\`$MRENCLAVE\`" >> $GITHUB_STEP_SUMMARY

      - name: Create attestation artifact
        run: |
          mkdir -p attestation
          echo "# Freehold ${{ github.ref_name }} MRENCLAVE" > attestation/mrenclave.txt
          echo "# Commit: ${{ github.sha }}" >> attestation/mrenclave.txt
          echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> attestation/mrenclave.txt
          echo "${{ steps.mrenclave.outputs.mrenclave }}" >> attestation/mrenclave.txt

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: enclave-${{ github.ref_name }}
          path: |
            freehold.manifest.sgx
            freehold.sig
            attestation/
```

## Collateral Caching

The server caches collateral (PCK certs, TCB info) to avoid per-request Intel PCS calls:

```rust
struct CollateralCache {
    pck_cert_chain: Vec<u8>,
    tcb_info: Vec<u8>,
    qe_identity: Vec<u8>,
    fetched_at: Instant,
    ttl: Duration,  // Typically 24 hours
}

impl Server {
    async fn get_collateral(&self) -> Result<Collateral> {
        let cache = self.collateral_cache.read().await;
        if cache.fetched_at.elapsed() < cache.ttl {
            return Ok(cache.clone());
        }
        drop(cache);

        // Fetch fresh collateral from local PCCS or Intel PCS
        let fresh = self.pccs_client.fetch_collateral().await?;
        *self.collateral_cache.write().await = fresh.clone();
        Ok(fresh)
    }
}
```

## Security Considerations

### What Attestation Proves

1. **Code identity**: MRENCLAVE proves the exact code running
2. **Freshness**: Nonce in report_data prevents replay attacks
3. **Hardware genuineness**: Intel's signature chain proves real SGX

### What Attestation Does NOT Prove

1. **Kernel integrity**: XDP can still be replaced by root
2. **Network security**: Packets are unencrypted at relay
3. **Future behavior**: Code could change after attestation
4. **Side-channel resistance**: SGX has known vulnerabilities

### Threat Model

| Adversary | Attestation Prevents | Does Not Prevent |
|-----------|---------------------|------------------|
| Remote attacker | N/A | N/A |
| Malicious operator | Running modified code | Traffic analysis |
| Malicious cloud | Reading HMAC secret | Replacing XDP |
| Intel | Nothing (they're the root of trust) | N/A |

## Implementation Checklist

- [ ] `freehold-enclave` crate with Gramine manifest
- [ ] ECALL interface for cookie operations
- [ ] Quote generation with nonce
- [ ] Protocol messages (0x10, 0x11)
- [ ] Server attestation handler
- [ ] Collateral caching
- [ ] `freehold-verify` CLI tool
- [ ] Reproducible Dockerfile
- [ ] GitHub Actions workflow
- [ ] DNS TXT record setup
- [ ] Documentation updates
