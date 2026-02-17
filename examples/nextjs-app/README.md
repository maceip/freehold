# Next.js + Freehold

Expose a Next.js app to the internet through Freehold's H3/QUIC relay.
No tunnel URLs, no cloud deploy — just your laptop.

## How it works

```
Browser ──H3/QUIC──> Freehold Relay ──UDP──> DemuxSocket ──HTTP/1.1──> Next.js
                                                                       :3000
```

Freehold's H3 proxy converts HTTP/3 to HTTP/1.1 and forwards to your
Next.js dev server. You change nothing in your Next.js code.

## Quick start

```bash
npm install

# Local only (no relay, self-signed cert)
npm run freehold:local

# With relay registration (public internet, self-signed cert)
npm run freehold

# With relay + automatic ACME TLS (dual-path DNS, real cert)
npm run freehold:acme
```

Then open `https://localhost:8443` (local) or `https://<hash>.freehold.lit.app:8443` (relay).

### Dual-path DNS

With `freehold:acme`, Freehold creates three DNS records for your server:

| FQDN | A record | Purpose |
|------|----------|---------|
| `<hash>.freehold.lit.app` | relay IP | Primary — browsers race relay + direct via SVCB |
| `<hash>.relay.freehold.lit.app` | relay IP | Guaranteed relay path (always works) |
| `<hash>.home.freehold.lit.app` | **your server's real IP** | Direct path (lowest latency) |

The `.home` record contains your server's actual public IP address (learned
from the UDP registration). SVCB-aware browsers (Chrome, Edge) automatically
race both paths on the primary domain. If you're behind permissive NAT or
have a public IP, the browser connects directly — zero relay involvement.

## What's in the box

- `app/page.js` — React client that calls the API routes
- `app/api/time/route.js` — returns server time
- `app/api/hello/route.js` — GET/POST echo endpoint
- `package.json` — `freehold`, `freehold:local`, and `freehold:acme` scripts

## Manual setup

If you prefer to run things separately:

```bash
# Terminal 1: Next.js
npm run dev

# Terminal 2: Freehold (with ACME for real TLS certs)
freehold --relay freehold.lit.app:9999 --port 8443 --backend 127.0.0.1:3000 \
         --acme-cache /tmp/acme --headless
```

## Using with production builds

```bash
npm run build
npm start  # starts Next.js on :3000

# In another terminal
freehold --relay freehold.lit.app:9999 --port 443 --backend 127.0.0.1:3000 \
         --acme-cache /tmp/acme --headless
```
