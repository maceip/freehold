# Python (Flask) + Freehold

Expose a Flask API to the internet through Freehold's H3/QUIC relay.

## How it works

```
Browser ──H3/QUIC──> Freehold Relay ──UDP──> DemuxSocket ──HTTP/1.1──> Flask
                                                                       :5000
```

Freehold's H3 proxy converts HTTP/3 to HTTP/1.1 and forwards to your
Flask dev server. You change nothing in your Flask code.

## Quick start

```bash
pip install -r requirements.txt

# Local only (no relay, self-signed cert)
./run.sh

# With relay registration (public internet, self-signed cert)
./run.sh --relay freehold.lit.app:9999 --relay-port 55126

# With relay + automatic ACME TLS (dual-path DNS, real cert)
./run.sh --relay freehold.lit.app:9999 --relay-port 55126 --acme-cache /tmp/acme
```

Then open `https://localhost:8443` (local) or `https://<hash>.freehold.lit.app:8443` (relay).

### Dual-path DNS

With `--acme-cache`, Freehold creates three DNS records for your server:

| FQDN | A record | Purpose |
|------|----------|---------|
| `<hash>.freehold.lit.app` | relay IP | Primary — browsers race relay + direct via SVCB |
| `<hash>.relay.freehold.lit.app` | relay IP | Guaranteed relay path (always works) |
| `<hash>.home.freehold.lit.app` | **your server's real IP** | Direct path (lowest latency) |

The `.home` record contains your server's actual public IP address (learned
from the UDP registration). SVCB-aware browsers (Chrome, Edge) automatically
race both paths on the primary domain. If you're behind permissive NAT or
have a public IP, the browser connects directly — zero relay involvement.

## API endpoints

| Method | Path          | Description        |
|--------|---------------|--------------------|
| GET    | `/`           | HTML landing page  |
| GET    | `/api/health` | Health check + uptime |
| GET    | `/api/time`   | Server time (UTC + Unix) |
| POST   | `/api/echo`   | Echo JSON body     |

## Manual setup

If you prefer to run things separately:

```bash
# Terminal 1: Flask
python3 app.py

# Terminal 2: Freehold (with ACME for real TLS certs)
freehold --relay freehold.lit.app:9999 --port 8443 --backend 127.0.0.1:5000 \
         --acme-cache /tmp/acme --headless
```
