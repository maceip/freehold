# Freehold Examples

End-to-end examples showing how to expose a local service through Freehold
and connect to it from a client.

## Architecture

```
Android (Cronet H3) ──QUIC──► Freehold Relay ──UDP──► DemuxSocket
                                                          │
                                                  ┌───────┴───────┐
                                                  │               │
                                              0x46 msgs      QUIC pkts
                                                  │               │
                                               Engine        Quinn/H3Proxy
                                             (heartbeat)      (WebSocket)
                                                  │               │
                                                  └───► Backend ◄─┘
                                                    (heartbeat-ws)
```

## `heartbeat-ws` — WebSocket heartbeat server (Rust)

A minimal backend that sends `{"ts": ..., "seq": ...}` every second over
WebSocket.  Runs behind Freehold's H3 proxy, which converts HTTP/3
Extended CONNECT (RFC 9220) into a plain HTTP/1.1 WebSocket upgrade.

### Local mode (no relay)

```sh
cargo run -p heartbeat-ws -- --port 8443
# Then from another terminal:
# curl --http3-only -k -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
#   https://127.0.0.1:8443/ws
```

### With relay

```sh
cargo run -p heartbeat-ws -- --relay freehold.lit.app:9999 --relay-port 55126
```

Uses `Service` internally — a single UDP socket is shared between Engine
(registration/heartbeat) and Quinn (H3/QUIC) via `DemuxSocket`.  Zero mux
code needed.

## `android-ws-client` — Android Cronet HTTP/3 WebSocket client

A Compose app that connects to the heartbeat server through Freehold using
Cronet's native QUIC stack.

Open in Android Studio, set the server URL, and tap Connect.  Heartbeats
will stream in over WebSocket-over-H3.

### Dependencies

- **Cronet** (`org.chromium.net:cronet-embedded`) — HTTP/3 engine
- **OkHttp** — WebSocket API
- **cronet-okhttp** — bridges OkHttp to Cronet transport

### Building

```sh
cd examples/android-ws-client
./gradlew :app:assembleDebug
```

## `nextjs-app` — Next.js frontend + API routes

A full Next.js app exposed through Freehold's H3 proxy. Includes a React
client that calls API routes (`/api/time`, `/api/hello`).

```sh
cd examples/nextjs-app
npm install
npm run freehold:local   # local mode
npm run freehold         # with relay
```

## `python-backend` — Flask API backend

A minimal Python backend (Flask) exposed through Freehold. Includes health
check, time, and echo endpoints.

```sh
cd examples/python-backend
pip install -r requirements.txt
./run.sh                                           # local mode
./run.sh --relay freehold.lit.app:9999 --relay-port 55126  # with relay
```
