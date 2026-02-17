#!/usr/bin/env bash
# Start Flask + Freehold together.
# Usage:
#   ./run.sh                          # local mode (self-signed, no relay)
#   ./run.sh --relay freehold.lit.app:9999 --relay-port 55126  # with relay

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
    exec freehold --relay "$RELAY" --port "$PORT" --backend "$BACKEND" --headless "$@"
else
    echo "==> Starting Freehold (local mode, port: $PORT -> $BACKEND)"
    exec freehold --local --port "$PORT" --backend "$BACKEND"
fi
