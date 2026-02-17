# Freehold Examples

## What is this, really?

Imagine you have a laptop running a web app in your apartment. Your phone
is on the subway. You want them to talk to each other — not through some
company's cloud, not through a tunnel service, just *directly*.

The problem is NAT. Your laptop is behind a router that won't let strangers
in. Your phone is behind a cell tower that does the same thing. Neither of
them has a real address on the internet. They're both hiding.

Freehold solves this with one simple trick and one big optimization.

### The trick

There's a relay server on the public internet with a real IP. Your laptop
sends a UDP packet to it and says "I'm here, give me port 8443." The relay
remembers your laptop's real address (the one the NAT translated to) and
programs a tiny eBPF filter in the kernel. Now, when *anyone* sends a
packet to the relay on port 8443, the kernel rewrites the destination
address to your laptop — at wire speed, before the packet even reaches
userspace. It's not proxying. It's address rewriting, like a mail
forwarding service.

### The optimization

After Alice's first packet reaches your laptop (through the relay), your
laptop sees Alice's real IP address. It sends the response *directly back
to Alice*, bypassing the relay completely. Alice's NAT accepts this because
she started the conversation — that's how NATs work, they let replies in.
From that point on, the relay is out of the picture. It's as if they were
on the same network.

If your laptop is behind a tricky NAT that blocks packets from unknown
sources, the relay tells your laptop "hey, send a UDP packet to Alice
first." That pokes a hole in your NAT. Now Alice's packets get through.
This is hole-punching, and QUIC's built-in retransmission covers the 1-2
second delay while the hole opens.

### The protocol (30-second version)

```
1. Bob  → Relay:  "Register me on port 8443"              (UDP)
2. Relay → Bob:   "Prove it — sign this cookie"            (HMAC challenge)
3. Bob  → Relay:  "Here's my signed cookie"                (UDP)
4. Relay:          XDP map updated: port 8443 → Bob's IP
5. Alice → Relay:  QUIC ClientHello to port 8443           (UDP)
6. Relay:          Kernel rewrites dst → Bob, preserves Alice's src
7. Bob  → Alice:  QUIC ServerHello directly back           (bypasses relay)
```

That's it. Five message types total: `Register`, `Challenge`, `Confirm`,
`Heartbeat`, `Punch`. Each one is a small UDP packet starting with the
byte `0x46` (ASCII "F" for Freehold).

### What about TLS certificates?

When Bob registers, the relay computes an HMAC-derived subdomain hash —
something like `a7xk2m` — and returns it in the Neighbors response.
DNS records are **not** created yet.

To get a real TLS certificate, Bob's client:
1. Sends `CreateRecords` — the relay checks that Bob is actually
   reachable (eBPF map lookup), then creates **dual-path DNS records**:
   - `a7xk2m.freehold.lit.app` A → relay IP (fallback)
   - `a7xk2m.freehold.lit.app` HTTPS → relay endpoint (SVCB)
   - `a7xk2m.freehold.lit.app` HTTPS → home/direct endpoint (SVCB)
   - `a7xk2m.relay.freehold.lit.app` A + HTTPS → relay only
   - `a7xk2m.home.freehold.lit.app` A + HTTPS → home/direct only
2. Runs ACME DNS-01 for all three domain names (multi-SAN certificate)
3. Hot-swaps the new cert into the running QUIC endpoint (zero downtime)

When `acme_cache_dir` is set, this all happens automatically in the
background. On restart, cached certs load in milliseconds — no round-trip
to Let's Encrypt unless the cert is expiring.

### Dual-path DNS: how the phone learns Bob's real IP

When Bob registers, the relay sees Bob's public IP as the UDP source
address. When Bob sends `CreateRecords`, the relay creates DNS records
using **both** IPs:

| DNS name | A record | Who uses it |
|----------|----------|-------------|
| `a7xk2m.relay.freehold.lit.app` | `142.248.222.1` (relay) | Guaranteed path — XDP forwards to Bob |
| `a7xk2m.home.freehold.lit.app` | `176.2.178.102` (Bob's real IP) | Direct path — skips relay entirely |
| `a7xk2m.freehold.lit.app` | relay IP + two SVCB records | Browsers race both paths |

This is the key: **the `.home` A record contains Bob's real public IP,
not the relay's.** The relay knows this IP because Bob sent it a UDP
packet — the source address is Bob's NAT-mapped public endpoint.

### How a phone uses this

1. **Phone resolves DNS.** It gets two IPs: the relay (from `.relay`)
   and Bob's real IP (from `.home`).

2. **Phone connects via relay.** Sends QUIC to
   `a7xk2m.relay.freehold.lit.app:8443`. This always works — the
   relay's XDP rewrites the destination to Bob.

3. **Phone probes Bob directly.** Simultaneously, the phone sends a
   UDP packet to Bob's real IP (from the `.home` A record). This
   packet probably gets dropped by Bob's NAT, but it opens the
   **phone's own NAT** — the phone's router now expects replies from
   Bob's IP.

4. **Bob responds directly.** When Bob's response arrives (from Bob's
   real IP, not the relay's), the phone's NAT lets it through because
   step 3 opened the mapping. QUIC doesn't care that the source IP
   changed — it uses connection IDs, not IP tuples.

5. **Relay drops out.** After the first direct response succeeds, all
   subsequent packets flow directly between phone and Bob. The relay
   is no longer in the path.

If Bob is behind CGNAT or restrictive NAT, the direct probe in step 3
fails silently. The relay path keeps working. No fallback logic needed
— the phone just never gets a direct response, so all traffic stays
on the relay path.

### SVCB racing (browsers)

SVCB-aware browsers (Chrome, Edge) see two HTTPS records on the primary
domain — one pointing to the relay, one pointing to Bob's home IP. The
browser **races** both connections and uses whichever responds first:

- If Bob has a public IP or permissive NAT → direct path wins, zero
  relay involvement
- If Bob is behind CGNAT → direct path fails silently, relay path wins
- Legacy browsers without SVCB → fall back to A record (relay), always
  works

### SDK clients

SDK clients that want explicit control can connect to:
- `a7xk2m.relay.freehold.lit.app` — always via relay (guaranteed)
- `a7xk2m.home.freehold.lit.app` — direct to Bob (may fail if NATted)

This is useful for testing, debugging, or when you know the NAT
situation on both sides.

All three names are covered by the same multi-SAN TLS certificate.
No certificate warnings regardless of which path the client takes.

### What about HTTP and WebSocket?

Your backend speaks HTTP. Browsers speak HTTP. But this protocol is all
UDP. So there's an H3 proxy: it accepts QUIC/HTTP3 connections (which run
over UDP), and translates them to plain HTTP/1.1 requests to your backend.
For WebSocket, it uses HTTP/3 Extended CONNECT (RFC 9220) — the browser
says "upgrade this stream to a WebSocket," and the proxy opens a normal
WebSocket connection to your backend. Your backend code doesn't change at
all. It just sees regular HTTP requests on localhost.

```
Phone (QUIC/H3) ──relay──► Your laptop (DemuxSocket)
                                    │
                            ┌───────┴───────┐
                            │               │
                        0x46 bytes      QUIC packets
                            │               │
                         Engine         H3 Proxy
                      (registration)    (HTTP/3 → HTTP/1.1)
                            │               │
                            └───► your app ◄─┘
                              (flask / next / anything)
```

The DemuxSocket is the only clever bit of plumbing: Engine and the QUIC
stack share one UDP socket. The demuxer peeks at the first byte — if it's
`0x46`, that's a Freehold control message (registration, heartbeat, punch),
and it goes to Engine. Everything else is QUIC and goes to Quinn. One
socket, one OS port, zero configuration.

---

## Use cases

**Your laptop is your server.** Run `freehold --backend 127.0.0.1:3000`
and your Next.js or Flask app is reachable from any browser on the
internet. No deploy, no Dockerfile, no Vercel. You're developing locally
and testing from your phone at the same time.

**Phone ↔ laptop.** The iOS or Android app connects to your laptop's
heartbeat server through the relay. Real-time WebSocket, over QUIC,
through two layers of NAT, with no infrastructure except one small relay.

**Phone ↔ server.** Same thing, but your backend runs on a VPS. Register
the VPS with the relay and your phone talks to it over H3. The relay gives
you a subdomain (`<hash>.freehold.lit.app`) and DNS records automatically.

**Device mesh.** Multiple devices register on different ports. Each one
can reach the others through the relay. After the first packet, they talk
directly — the relay is only for introduction.

---

## Examples

### `heartbeat-ws` — WebSocket heartbeat server (Rust)

A minimal backend that sends `{"ts": ..., "seq": ...}` every second over
WebSocket. Runs behind Freehold's H3 proxy, which converts HTTP/3
Extended CONNECT (RFC 9220) into a plain HTTP/1.1 WebSocket upgrade.

```sh
# Local mode (no relay, self-signed cert)
cargo run -p heartbeat-ws -- --port 8443

# With relay (self-signed cert)
cargo run -p heartbeat-ws -- --relay freehold.lit.app:9999 --relay-port 55126

# With relay + automatic ACME TLS (dual-path DNS, real cert)
cargo run -p heartbeat-ws -- \
  --relay freehold.lit.app:9999 --relay-port 55126 \
  --acme-cache /tmp/acme-cache
```

With `--acme-cache`, the server automatically creates dual-path DNS
records and obtains a multi-SAN Let's Encrypt certificate. Uses `Service`
internally — a single UDP socket shared between Engine and Quinn via
`DemuxSocket`. Zero mux code needed.

### `ios-ws-client` — iOS QUIC/H3 WebSocket client (Rust + SwiftUI)

An iPhone app that connects to heartbeat-ws through Freehold. Networking
is in Rust (quinn + h3 for full QUIC/HTTP3 control), UI is SwiftUI,
bridged via C FFI (cbindgen). Includes a **path selector** (Auto / Relay /
Direct) to demonstrate dual-path DNS — enter just the subdomain hash and
pick which path to test.

```sh
cd examples/ios-ws-client
./build-rust.sh          # cross-compile Rust → iOS xcframework
# Then open in Xcode, add App/ sources + xcframework
```

Why Rust for the client? iOS's URLSession supports H3 but doesn't expose
Extended CONNECT for WebSocket-over-H3. Quinn does.

### `android-ws-client` — Android Cronet HTTP/3 WebSocket client

A Compose app that connects to heartbeat-ws through Freehold using
Cronet's native QUIC stack + OkHttp for WebSocket framing. Includes a
**path selector** (Auto / Relay / Direct) to test dual-path DNS — enter
the subdomain hash, pick a connection path, and watch the message log.

```sh
cd examples/android-ws-client
./gradlew :app:assembleDebug
```

### `nextjs-app` — Next.js frontend + API routes

A full Next.js app exposed through Freehold's H3 proxy. Includes a React
client calling `/api/time` and `/api/hello`. No changes to your Next.js
code — Freehold just sits in front of `next dev`.

```sh
cd examples/nextjs-app
npm install
npm run freehold:local   # local mode (self-signed, localhost)
npm run freehold         # with relay (public internet, self-signed)
npm run freehold:acme    # with relay + ACME TLS (dual-path DNS, real cert)
```

### `python-backend` — Flask API backend

A minimal Python backend (Flask) exposed through Freehold. Health check,
server time, JSON echo — the basics.

```sh
cd examples/python-backend
pip install -r requirements.txt
./run.sh                                                   # local
./run.sh --relay freehold.lit.app:9999 --relay-port 55126  # with relay
./run.sh --relay freehold.lit.app:9999 --relay-port 55126 \
         --acme-cache /tmp/acme                            # with relay + ACME
```

---

## The whole picture

```
                    ┌─────────────────────┐
                    │   Freehold Relay     │
                    │  (eBPF/XDP kernel)   │
                    └──────┬──────────────┘
                           │ UDP address rewrite
              ┌────────────┼────────────────┐
              │            │                │
     ┌────────▼───┐  ┌─────▼─────┐  ┌──────▼──────┐
     │ iOS client │  │  Android  │  │   Browser   │
     │ (Rust+Swift)│  │ (Cronet)  │  │  (any)      │
     │  quinn/h3  │  │  OkHttp   │  │  fetch()    │
     └────────────┘  └───────────┘  └─────────────┘
              │            │                │
              │       QUIC / HTTP/3         │
              │            │                │
     ┌────────▼────────────▼────────────────▼──────┐
     │              Your laptop / server            │
     │  DemuxSocket ──► Engine (registration)       │
     │              ──► H3 Proxy (HTTP/3 → HTTP/1)  │
     │                       │                      │
     │              Flask / Next.js / anything       │
     └──────────────────────────────────────────────┘
```

---

## The protocol, explained for golden retrievers

You are a golden retriever named Bob. You live in an apartment (behind NAT).
You want your friend Alice (a browser) to visit, but she doesn't know
your apartment number, and the doorman won't let strangers in.

Here's what happens. On the left, what it *feels* like. On the right,
the actual bytes on the wire.

### 1. Bob goes to the park (REGISTER)

> *"I'm Bob! I want apartment 8443!"*

Bob trots up to the relay (the park ranger) and says hi.

```
Bob → Relay:  [0x46, 0x01, 0x20, 0xFB]
               magic  REG   port 8443 (big-endian)
```

### 2. The ranger checks Bob's collar (CHALLENGE)

> *"Hmm, prove you're really Bob. Sniff this cookie."*

The relay sends back a 16-byte HMAC cookie. Only a dog at Bob's real
IP address will receive it — that's the whole point.

```
Relay → Bob:  [0x46, 0x02, 0x20, 0xFB, cookie_16_bytes...]
               magic  CHAL  port 8443   the cookie to sniff
```

### 3. Bob returns the cookie (CONFIRM)

> *"I sniffed it! Here it is! Same cookie!"*

Bob echoes the cookie back. The relay verifies the HMAC. If it checks
out, Bob gets added to the eBPF map. The park now knows where Bob lives.

```
Bob → Relay:  [0x46, 0x03, 0x20, 0xFB, same_cookie_16_bytes...]
               magic  CONF  port 8443   proof of sniffing
```

### 4. The ranger tells Bob about the neighborhood (NEIGHBORS)

> *"Welcome! Here are the other park rangers, and your park name is a7xk2m."*

```
Relay → Bob:  [0x46, 0x05, 0x02, 10,0,0,1, 10,0,0,2, 0x06, "a7xk2m"]
               magic  NEIGH count  relay1     relay2    len   subdomain
```

Bob now has a subdomain (`a7xk2m.freehold.lit.app`) but no DNS records yet.
The ranger doesn't put up a sign until Bob proves he actually lives there.

### 5. Bob asks for a sign on the door (CreateRecords)

> *"I've been here a while. Can you put my name on the mailbox?"*

Bob sends another Confirm with action byte `0x03`. The ranger checks
the eBPF map — yep, Bob is still there, heartbeating, reachable. Sign goes up.

```
Bob → Relay:  [0x46, 0x03, 0x20, 0xFB, cookie..., 0x03, 0x00]
               magic  CONF  port 8443   cookie     CREATE len=0
```

DNS records created (the ranger uses Bob's real address for the home sign):
- `a7xk2m.relay.freehold.lit.app` A → **142.248.222.1** (the park's address)
- `a7xk2m.home.freehold.lit.app` A → **176.2.178.102** (Bob's real apartment building)
- `a7xk2m.freehold.lit.app` A → park IP + SVCB records for both paths

### 6. Bob gets a real name tag (ACME)

> *"I want a REAL name tag from the AKC, not a handwritten one!"*

Bob's ACME module sends `SetAcmeTxt` with the Let's Encrypt challenge:

```
Bob → Relay:  [0x46, 0x03, port, cookie..., 0x01, 0x2B, "dGVzdC1h..."]
               magic  CONF                   SET   len=43  base64 token
```

Let's Encrypt checks the TXT record, approves. Bob sends `ClearAcmeTxt`:

```
Bob → Relay:  [0x46, 0x03, port, cookie..., 0x02, 0x00]
               magic  CONF                   CLR   len=0
```

Bob now has a real TLS certificate. He hot-swaps it into his QUIC
endpoint. No downtime. Very good boy.

### 7. Bob keeps wagging (HEARTBEAT)

> *"I'm still here! Still here! Still here!"*

Every 25 seconds, Bob sends a tiny heartbeat so the ranger doesn't
erase him from the map.

```
Bob → Relay:  [0x46, 0x04, 0x20, 0xFB]
               magic  BEAT  port 8443
```

### 8. Alice shows up (QUIC + dual-path)

> *"Hi, is Bob here?" (Alice doesn't know any of this happened)*

Alice resolves `a7xk2m.freehold.lit.app` and gets two paths: the park
(relay at 142.248.222.1) and Bob's real building (176.2.178.102).

**Via the park (relay) — always works:**
```
Alice → Relay:  QUIC ClientHello to port 8443
Kernel:         rewrites dst_ip → Bob's real IP (XDP, wire speed)
Bob → Alice:    QUIC ServerHello directly back (bypasses relay)
```

**Meanwhile, Alice probes Bob's building directly:**
```
Alice → Bob:    UDP packet to 176.2.178.102:8443 (from .home A record)
                Bob's NAT drops it, BUT Alice's NAT now expects replies
                from Bob's IP. When Bob responds directly (above), Alice's
                NAT lets it through.
```

If Alice is a phone app (SDK client), she resolves `.home` to get
Bob's real IP and sends a probe packet. This opens her NAT for Bob's
direct responses. If Alice is a browser, SVCB racing does this
automatically — the browser tries both the relay and Bob's IP, and
the first response wins.

Either way, after the first successful exchange, the relay is out of
the picture. Alice and Bob talk directly.

Alice pets Bob. Bob wags. The end.
