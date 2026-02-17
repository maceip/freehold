#!/usr/bin/env bash
# Start Flask + Freehold together.
# Usage:
#   ./run.sh                          # local mode (self-signed, no relay)
#   ./run.sh --relay freehold.lit.app:9999 --relay-port 55126  # with relay
#   ./run.sh --relay freehold.lit.app:9999 --relay-port 55126 \
#            --acme-cache /tmp/acme     # with relay + automatic ACME TLS
#
# With --acme-cache, Freehold automatically:
#   1. Registers with the relay and gets a subdomain hash
#   2. Creates dual-path DNS records (SVCB racing for browsers + .relay/.home)
#   3. Obtains a multi-SAN Let's Encrypt certificate for all three FQDNs
#   4. Hot-swaps the cert into the running QUIC endpoint (zero downtime)
#
# Browsers connecting to https://<hash>.freehold.lit.app:<port> will race
# both the relay and direct paths via SVCB — if you're behind permissive
# NAT, the browser connects directly with zero relay involvement.

set -e

PORT="${PORT:-8443}"
BACKEND="${BACKEND:-127.0.0.1:5000}"

echo "==> Starting Flask on $BACKEND"
python3 app.py &
FLASK_PID=$!

trap "kill $FLASK_PID 2>/dev/null" EXIT

# Wait for Flask to start
sleep 1

if [ "$1" = "--relay" ]; then
    RELAY="$2"
    shift 2
    echo "==> Starting Freehold (relay: $RELAY, port: $PORT -> $BACKEND)"
    echo "    Dual-path DNS: <hash>.freehold.lit.app (SVCB racing)"
    echo "                   <hash>.relay.freehold.lit.app (explicit relay)"
    echo "                   <hash>.home.freehold.lit.app (explicit direct)"
    exec freehold --relay "$RELAY" --port "$PORT" --backend "$BACKEND" --headless "$@"
else
    echo "==> Starting Freehold (local mode, port: $PORT -> $BACKEND)"
    exec freehold --local --port "$PORT" --backend "$BACKEND"
fi
