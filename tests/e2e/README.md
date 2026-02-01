# End-to-End Tests

These tests verify the complete Freehold stack including eBPF packet processing.

## Requirements

- Linux with kernel 5.15+ (for eBPF support)
- Root privileges (for network namespaces and eBPF)
- Built eBPF program at `target/bpfel-unknown-none/release/freehold-ebpf`

## Running Locally

```bash
# Build everything first
cargo build --release
cargo xtask build-ebpf --release

# Run E2E tests (requires sudo)
sudo ./tests/e2e/run_e2e.sh
```

## What's Tested

1. **Network Setup**: Creates veth pair connecting two network namespaces
2. **Server**: Runs freehold-server with eBPF in server namespace
3. **Client**: Runs client state machine in client namespace
4. **Protocol**: Full Register → Challenge → Confirm → Neighbors flow
5. **Packet Forwarding**: Verifies XDP forwards packets correctly

## Test Topology

```
┌─────────────────────┐     veth pair     ┌─────────────────────┐
│  Client Namespace   │◄─────────────────►│  Server Namespace   │
│                     │                   │                     │
│  freehold-client    │   10.99.0.0/24    │  freehold-server    │
│  10.99.0.2          │                   │  10.99.0.1          │
│                     │                   │  + eBPF/XDP         │
└─────────────────────┘                   └─────────────────────┘
```
