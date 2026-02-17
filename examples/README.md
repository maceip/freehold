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

When Bob registers, the relay computes an HMAC-derived subdomain —
something like `a7xk2m.freehold.lit.app` — and returns it in the
Neighbors response. DNS records are **not** created yet.

To get a real TLS certificate, Bob's client:
1. Sends `CreateRecords` — the relay checks that Bob is actually
   reachable (eBPF map lookup), then creates DNS A + HTTPS records
2. Sends `SetAcmeTxt` with the ACME challenge token — the relay sets
   `_acme-challenge.<subdomain>` TXT record
3. Let's Encrypt validates the domain
4. Sends `ClearAcmeTxt` to clean up
5. Hot-swaps the new cert into the running QUIC endpoint (zero downtime)

When `acme_cache_dir` is set, this all happens automatically in the
background. On restart, cached certs load in milliseconds — no round-trip
to Let's Encrypt unless the cert is expiring.

Clients connect using the subdomain (`https://a7xk2m.freehold.lit.app:8443`),
which gives them correct TLS SNI matching. No certificate warnings.

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

# With relay
cargo run -p heartbeat-ws -- --relay freehold.lit.app:9999 --relay-port 55126
```

Uses `Service` internally — a single UDP socket shared between Engine
and Quinn via `DemuxSocket`. Zero mux code needed.

### `ios-ws-client` — iOS QUIC/H3 WebSocket client (Rust + SwiftUI)

An iPhone app that connects to heartbeat-ws through Freehold. Networking
is in Rust (quinn + h3 for full QUIC/HTTP3 control), UI is SwiftUI,
bridged via C FFI (cbindgen).

```sh
cd examples/ios-ws-client
./build-rust.sh          # cross-compile Rust → iOS xcframework
# Then open in Xcode, add App/ sources + xcframework
```

Why Rust for the client? iOS's URLSession supports H3 but doesn't expose
Extended CONNECT for WebSocket-over-H3. Quinn does.

### `android-ws-client` — Android Cronet HTTP/3 WebSocket client

A Compose app that connects to heartbeat-ws through Freehold using
Cronet's native QUIC stack + OkHttp for WebSocket framing.

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
npm run freehold         # with relay (public internet)
```

### `python-backend` — Flask API backend

A minimal Python backend (Flask) exposed through Freehold. Health check,
server time, JSON echo — the basics.

```sh
cd examples/python-backend
pip install -r requirements.txt
./run.sh                                                   # local
./run.sh --relay freehold.lit.app:9999 --relay-port 55126  # with relay
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

DNS records created: `a7xk2m.freehold.lit.app → relay IP, port 8443`

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

### 8. Alice shows up (QUIC)

> *"Hi, is Bob here?" (Alice doesn't know any of this happened)*

Alice's browser sends QUIC to `a7xk2m.freehold.lit.app:8443`. The
XDP kernel program rewrites the destination to Bob's real IP. Alice's
source IP is preserved. Bob responds directly to Alice. The relay is
out of the loop. Alice sees a valid Let's Encrypt cert. Everyone is happy.

```
Alice → Relay:  QUIC ClientHello to port 8443
Kernel:         rewrites dst_ip → Bob's IP (XDP, wire speed)
Bob → Alice:    QUIC ServerHello directly back (bypasses relay)
```

Alice pets Bob. Bob wags. The end.
