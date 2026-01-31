# Intel SGX Investigation for Freehold eBPF Relay

## Executive Summary

This document investigates using Intel SGX enclaves to secure the Freehold relay, addressing:
1. **Can eBPF/XDP run inside an SGX enclave?** — No, not directly
2. **High-performance networking options inside enclaves** — DPDK-SGX and RAKIS exist, with significant performance tradeoffs
3. **Attestation strategy for trust** — DCAP-based reproducible builds with MRENCLAVE verification
4. **Self-hosted attestation without Intel/Google** — Possible using open-source tooling

---

## 1. Can eBPF Run Inside Intel SGX Enclaves?

### Short Answer: **No**

eBPF programs are designed to run **inside the Linux kernel**. SGX enclaves are **isolated user-space** execution environments. These are fundamentally incompatible:

| Aspect | eBPF/XDP | SGX Enclave |
|--------|----------|-------------|
| Execution domain | Kernel space | User space (ring 3) |
| Memory access | Full kernel memory | Isolated encrypted memory |
| System calls | N/A (is kernel code) | Forbidden (must OCALL) |
| Network stack | Pre-driver (XDP) | No direct NIC access |

From Intel's documentation:
> "Enclaves are statically linked self-contained execution domains... In order to access [system] resources the enclave has to do an OCALL to temporarily exit the enclave."

### What About Userspace eBPF?

Projects like [bpftime](https://github.com/eunomia-bpf/bpftime) run eBPF in userspace without kernel support. However:
- They can't intercept packets at NIC level (no XDP equivalent)
- Would require DPDK or similar for packet I/O
- Not designed for SGX integration

### Conclusion

**You cannot run XDP packet processing inside an SGX enclave.** The entire premise of XDP is kernel-bypass at the NIC driver level—SGX provides the opposite guarantee (isolation from the kernel).

---

## 2. High-Performance Networking Inside SGX Enclaves

### Option A: DPDK-SGX (DPDK inside enclave)

There exists [SGX-DPDK](https://github.com/InNetworkFiltering/SGX-DPDK), a firewall implementation using DPDK for performance and SGX for security.

**How it works:**
```
NIC → DPDK (userspace driver) → SGX Enclave (packet processing) → DPDK → NIC
```

**Performance impact is severe:**
- SGX enclave entry/exit: **8,200-17,000 cycles** (vs 150 for syscall)
- Memory encryption overhead on every packet
- Research shows **10.5% of baseline throughput** (2.28 Mpps → 0.24 Mpps)
- Up to **79% performance degradation** in high-bandwidth scenarios

### Option B: RAKIS (EuroSys '25)

[RAKIS](https://taesoo.kim/pubs/2025/alharthi:rakis.pdf) is a recent research system providing Fast I/O Kernel Primitives for SGX:

**Architecture:**
```
Host XDP → Shared Untrusted Memory → RAKIS → Enclave Trusted Memory
```

**Key features:**
- Uses host OS XDP to direct UDP packets into shared memory
- Enclave securely retrieves packets from shared memory
- No specialized hardware required (just XDP + io_uring support)
- Better than pure DPDK-SGX but still has enclave crossing overhead

### Option C: Don't Put Networking in Enclave

Given the performance constraints, consider:
1. **XDP stays in kernel** (current design, line-rate)
2. **Only secrets/verification in enclave** (cookie generation, HMAC key)
3. **Attestation proves enclave code** matches published source

This is similar to how Signal and other production systems work—the enclave handles cryptographic operations and secrets, not bulk data processing.

---

## 3. Architecture Recommendation

### Hybrid Approach: Enclave for Secrets, XDP for Speed

```
┌─────────────────────────────────────────────────────────────┐
│                    SGX ENCLAVE                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  • HMAC-SHA256 cookie generation                    │   │
│  │  • Secret key storage (32-byte HMAC key)            │   │
│  │  • Registration validation                          │   │
│  │  • MRENCLAVE = hash of this code                    │   │
│  └─────────────────────────────────────────────────────┘   │
│              ↑ ECALL                    ↓ Result           │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 USERSPACE (Untrusted)                       │
│  • UDP listener for registration protocol                   │
│  • eBPF map management                                      │
│  • Calls enclave for cookie generation/verification         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 KERNEL (XDP/eBPF)                           │
│  • Line-rate packet forwarding                              │
│  • Rate limiting (token bucket)                             │
│  • IP/port rewriting                                        │
│  • No secrets (just registration data from userspace)       │
└─────────────────────────────────────────────────────────────┘
```

### Security Properties

| Component | Protected By | Threat Model |
|-----------|-------------|--------------|
| HMAC secret | SGX enclave | Even root can't read |
| Cookie generation | SGX enclave | Attested code only |
| Packet forwarding | Kernel XDP | Root compromise = game over |
| Registration data | Kernel memory | Integrity via eBPF map |

### What This Protects Against

1. **Root compromise reading secrets**: HMAC key in enclave memory is encrypted
2. **Binary tampering**: MRENCLAVE changes if enclave code changes
3. **Malicious operator**: Cannot forge cookies without enclave cooperation

### What This Doesn't Protect Against

1. **Kernel compromise**: XDP can be detached/replaced by root
2. **Side-channel attacks**: SGX has known vulnerabilities
3. **Traffic analysis**: Packet metadata visible to host

---

## 4. Remote Attestation Without Intel/Google

### The Problem

Intel's legacy attestation (EPID/IAS) is EOL. DCAP allows self-hosting, but you still need Intel's Provisioning Certification Service (PCS) to bootstrap trust.

### Solution: DCAP with Self-Hosted PCCS

**Architecture:**
```
┌─────────────────────┐     ┌─────────────────────┐
│  Your PCCS Server   │ ←── │  Intel PCS          │
│  (cache collateral) │     │  (one-time fetch)   │
└─────────────────────┘     └─────────────────────┘
         ↓
┌─────────────────────┐     ┌─────────────────────┐
│  Quote Generation   │     │  Quote Verification │
│  (enclave on Vultr) │ ──→ │  (anyone)           │
└─────────────────────┘     └─────────────────────┘
```

**Key insight**: You only need Intel PCS to fetch platform collateral (certificates). Once cached, verification is entirely local.

### Setting Up Self-Hosted Attestation

1. **Run your own PCCS** ([Intel DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives))
   - Caches PCK certificates and TCB info
   - One-time fetch from Intel PCS
   - After that, fully offline operation

2. **Quote generation** (on Vultr SGX server)
   - Use Gramine or EGo to wrap your enclave app
   - Generates ECDSA quote containing MRENCLAVE

3. **Quote verification** (by anyone)
   - Use standalone libraries (no SGX hardware needed!)
   - Intel provides [SGX-TDX-DCAP-QuoteVerificationLibrary](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary)
   - QVS can run without SGX hardware

### Open Source Verification Libraries

| Library | Language | License | Link |
|---------|----------|---------|------|
| `intel_tee_quote_verification_rs` | Rust | Intel | [crates.io](https://intel.github.io/SGXDataCenterAttestationPrimitives/docs/rust-qvl-doc/intel_tee_quote_verification_rs/index.html) |
| `mc_attestation_verifier` | Rust | Apache 2.0 | [docs.rs](https://docs.rs/mc-attestation-verifier/latest/mc_attestation_verifier/) |
| `echeck` | Go | MIT | [GitHub](https://pkg.go.dev/github.com/KarpelesLab/echeck) |
| `gramine-ratls-golang` | Go | - | [GitHub](https://pkg.go.dev/github.com/konvera/gramine-ratls-golang) |

---

## 5. Reproducible Builds & MRENCLAVE Verification

### Why This Matters

MRENCLAVE is a SHA-256 hash of the enclave's initial state (code + data). If your builds are reproducible, anyone can:
1. Clone your repo at a specific commit
2. Build the enclave
3. Compute MRENCLAVE
4. Verify it matches the quote from your server

### Reproducible Build Strategy

**Using Gramine (recommended):**

```dockerfile
FROM gramineproject/gramine:v1.8

# Copy only deterministic inputs
COPY --chown=gramine:gramine ./src /app/src
COPY --chown=gramine:gramine ./Cargo.toml /app/

# Build with fixed toolchain
RUN cargo build --release --locked

# Generate SGX artifacts
RUN gramine-sgx-gen-private-key
RUN gramine-manifest -Dlog_level=error app.manifest.template app.manifest
RUN gramine-sgx-sign --manifest app.manifest --output app.manifest.sgx
```

**Extract MRENCLAVE:**
```bash
gramine-sgx-sigstruct-view app.sig | grep mr_enclave
# Output: mr_enclave: 0xdb718ecdcec7b7db2cd7206b7599b2472c02376195b70629fa72690e377ba69c
```

### CI/CD Pipeline for Attestation

```yaml
# .github/workflows/build-enclave.yml
name: Build SGX Enclave

on:
  release:
    types: [published]

jobs:
  build:
    runs-on: ubuntu-latest
    container: gramineproject/gramine:v1.8

    steps:
      - uses: actions/checkout@v4

      - name: Build enclave
        run: |
          cargo build --release --locked
          gramine-manifest app.manifest.template app.manifest
          gramine-sgx-sign --manifest app.manifest --output app.manifest.sgx

      - name: Extract MRENCLAVE
        run: |
          gramine-sgx-sigstruct-view app.sig > sigstruct.txt
          grep mr_enclave sigstruct.txt >> $GITHUB_STEP_SUMMARY

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: enclave-${{ github.ref_name }}
          path: |
            app.manifest.sgx
            app.sig
            sigstruct.txt
```

### Publishing Expected MRENCLAVE

Options for where to publish the expected hash:

1. **GitHub Releases**: Attach `sigstruct.txt` to each release
2. **DNS TXT record**: `mrenclave.freehold.example.com TXT "db718ecd..."`
3. **Signed file in repo**: `attestation/expected-mrenclave.txt` (GPG signed)
4. **Smart contract**: For blockchain-based verification

---

## 6. Verification Flow for End Users

### Simple CLI Tool

```rust
// Example: freehold-verify
use intel_tee_quote_verification_rs::*;

fn verify_relay(relay_addr: &str, expected_mrenclave: &[u8; 32]) -> Result<bool> {
    // 1. Fetch quote from relay's attestation endpoint
    let quote = fetch_quote(relay_addr)?;

    // 2. Verify quote signature (uses cached collateral)
    let result = tee_verify_quote(&quote, None)?;

    // 3. Check MRENCLAVE matches expected
    let report = parse_quote(&quote)?;
    if report.mr_enclave != expected_mrenclave {
        return Err("MRENCLAVE mismatch - enclave code differs from expected");
    }

    // 4. Check quote is not revoked
    if result.tcb_status != TcbStatus::UpToDate {
        warn!("TCB not up to date: {:?}", result.tcb_status);
    }

    Ok(true)
}
```

### User Verification Steps

1. **Get expected MRENCLAVE** from GitHub release
2. **Run verification tool** against relay address
3. **Tool fetches quote** from relay's `/attestation` endpoint
4. **Tool verifies**:
   - Quote signature is valid (Intel root of trust)
   - MRENCLAVE matches expected value
   - Quote is fresh (includes nonce)

---

## 7. Vultr SGX Setup

### Available Hardware

Vultr bare metal supports SGX on:
- Intel Xeon E-2286G (6 cores, 4.0 GHz)
- Intel Xeon E-2388G (Rocket Lake, newer)

Available in: Amsterdam, Atlanta, London, Miami, New Jersey, Silicon Valley, Singapore, Sydney, Tokyo

### BIOS Configuration Required

SGX is disabled by default. To enable:
1. Access BIOS via Vultr web console (press DEL on boot)
2. Navigate: Advanced → Chipset Configuration
3. Enable "SW Guard Extensions (SGX)"
4. Set SGX memory size (128MB+ recommended)

### Software Stack

```bash
# Install SGX driver and SDK
wget https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin
chmod +x sgx_linux_x64_driver_*.bin
sudo ./sgx_linux_x64_driver_*.bin

# Install DCAP packages
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | \
  sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt update
sudo apt install libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-quote-ex

# Install Gramine
sudo apt install gramine
```

---

## 8. Implementation Roadmap

### Phase 1: Enclave for Secrets (Recommended First Step)

1. Create minimal enclave with Gramine containing:
   - HMAC-SHA256 cookie generation
   - Secret key storage
   - Simple ECALL interface

2. Modify `freehold-server` to:
   - Load enclave on startup
   - Call enclave for cookie generation (lines 134-142 of main.rs)
   - Keep XDP path unchanged

3. Set up reproducible build pipeline

### Phase 2: Attestation Infrastructure

1. Deploy self-hosted PCCS
2. Add `/attestation` endpoint to server
3. Create `freehold-verify` CLI tool
4. Publish expected MRENCLAVE with releases

### Phase 3: Enhanced Security (Optional)

1. Move registration validation into enclave
2. Investigate Intel TDX for full VM protection
3. Add quote freshness via nonce challenge

---

## 9. Alternatives Considered

### Intel TDX (Trust Domain Extensions)

VM-level confidential computing. Entire guest OS runs encrypted.
- **Pro**: Kernel + eBPF would run protected
- **Con**: Not widely available, requires newer CPUs (Sapphire Rapids+)
- **Con**: Vultr doesn't appear to support TDX yet

### AMD SEV-SNP

AMD's confidential VM technology.
- **Pro**: Similar to TDX, full VM protection
- **Pro**: Better performance for networking (no enclave transitions)
- **Con**: Different attestation infrastructure
- **Con**: Check Vultr availability

### No Enclave (Status Quo + Transparency)

- Publish server code
- Use reproducible builds
- Rely on operational security + reputation

---

## 10. References

### Official Documentation
- [Intel SGX Developer Guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_Developer_Guide.pdf)
- [Intel DCAP Orientation Guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/DCAP_ECDSA_Orientation.pdf)
- [Gramine SGX Documentation](https://gramine.readthedocs.io/en/stable/sgx-intro.html)

### Research Papers
- [RAKIS: Secure Fast I/O Primitives Across Trust Boundaries](https://taesoo.kim/pubs/2025/alharthi:rakis.pdf) (EuroSys '25)
- [SGX-LKL: Securing the Host OS Interface](https://arxiv.org/pdf/1908.11143)
- [eBPF and Confidential Computing](http://oldvger.kernel.org/bpfconf2023_material/eBPF-and-Confidential-Computing-lsfmmbpf.pdf) (LSF/MM/BPF '23)

### Open Source Projects
- [Intel DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- [Gramine](https://github.com/gramineproject/gramine)
- [EGo](https://github.com/edgelesssys/ego)
- [SGX-DPDK](https://github.com/InNetworkFiltering/SGX-DPDK)

### Production Examples
- [Signal SGX Attestation](https://signal.org/blog/private-contact-discovery/)
- [Flashbots Block Building in SGX](https://writings.flashbots.net/block-building-inside-sgx)
- [Gramine Reproducible Build Demo](https://github.com/amiller/gramine-rsademo)

---

## Appendix A: Current Freehold Architecture

From codebase analysis:

```
crates/
├── freehold-ebpf/      # XDP packet forwarder (C, runs in kernel)
│   └── src/main.bpf.c  # Wire-speed UDP forwarding, rate limiting
├── freehold-server/    # Registration server (Rust, runs in userspace)
│   └── src/main.rs     # HMAC cookies, eBPF map management
├── freehold-common/    # Shared types (Rust/C interop)
└── freehold-api/       # Protocol definitions
```

### Security-Critical Code Locations

| Function | File | Lines | Move to Enclave? |
|----------|------|-------|------------------|
| Cookie generation | `freehold-server/src/main.rs` | 134-142 | Yes |
| Cookie verification | `freehold-server/src/main.rs` | 146-149 | Yes |
| HMAC secret storage | `freehold-server/src/main.rs` | 411 | Yes |
| XDP forwarding | `freehold-ebpf/src/main.bpf.c` | all | No (kernel) |
