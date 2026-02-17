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

# With relay registration (public internet)
npm run freehold
```

Then open `https://localhost:8443` (local) or `https://<subdomain>.freehold.lit.app:8443` (relay).

## What's in the box

- `app/page.js` — React client that calls the API routes
- `app/api/time/route.js` — returns server time
- `app/api/hello/route.js` — GET/POST echo endpoint
- `package.json` — `freehold` and `freehold:local` scripts

## Manual setup

If you prefer to run things separately:

```bash
# Terminal 1: Next.js
npm run dev

# Terminal 2: Freehold
freehold --relay freehold.lit.app:9999 --port 8443 --backend 127.0.0.1:3000 --headless
```

## Using with production builds

```bash
npm run build
npm start  # starts Next.js on :3000

# In another terminal
freehold --relay freehold.lit.app:9999 --port 443 --backend 127.0.0.1:3000 --headless
```
