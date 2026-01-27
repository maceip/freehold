# v2-reflector: Specular Sovereign Proxy

Clean-room implementation of the Specular relay network.

## Architecture

```
                         INTERNET
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    RELAY NODE (eBPF/XDP)                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  specular_ingress (XDP program)                     │   │
│  │  - Challenge-response registration                   │   │
│  │  - Token bucket rate limiting                        │   │
│  │  - UDP reflection with header rewrite                │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  specular_userspace (Registration service)          │   │
│  │  - Handles registration protocol                     │   │
│  │  - Manages pending/confirmed state                   │   │
│  │  - Generates challenges, verifies responses          │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Sovereign Proxy)                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  H3 Server (quinn)                                   │   │
│  │  - Accepts QUIC/H3 from reflected traffic            │   │
│  │  - TLS termination with ACME certs                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Local Proxy                                         │   │
│  │  - HTTP/1.1 and HTTP/2 to local services             │   │
│  │  - WebSocket upgrade support (RFC 9220)              │   │
│  │  - X-Forwarded-For injection                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│                    localhost:8080 (your app)                │
└─────────────────────────────────────────────────────────────┘
```

## Registration Protocol

```
Client                          Relay (userspace)              Relay (eBPF)
   │                                   │                           │
   │  1. REGISTER(port, pubkey, sig)   │                           │
   │──────────────────────────────────>│                           │
   │                                   │  2. Insert PENDING        │
   │                                   │─────────────────────────> │
   │                                   │                           │
   │  3. CHALLENGE(nonce)              │                           │
   │<──────────────────────────────────│                           │
   │                                   │                           │
   │  4. RESPONSE(nonce, sig)          │                           │
   │──────────────────────────────────>│                           │
   │                                   │  5. Mark CONFIRMED        │
   │                                   │─────────────────────────> │
   │                                   │                           │
   │  6. ACK(port, ttl)                │                           │
   │<──────────────────────────────────│                           │
   │                                   │                           │
   │         ... traffic flows ...     │                           │
   │                                   │                           │
   │  7. HEARTBEAT (every 30s)         │                           │
   │──────────────────────────────────>│  8. Refresh TTL           │
   │                                   │─────────────────────────> │
```

## Directory Structure

```
v2-reflector/
├── ebpf/           # XDP/eBPF programs for the relay
├── relay/          # Userspace relay daemon (registration, control plane)
├── client/         # Sovereign Proxy (runs on user's machine)
└── common/         # Shared protocol definitions
```

## Building

```bash
# Build eBPF (requires clang, llvm)
cd ebpf && cargo xtask build-ebpf

# Build relay daemon
cd relay && cargo build --release

# Build client
cd client && cargo build --release
```
