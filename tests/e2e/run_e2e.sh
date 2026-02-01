#!/bin/bash
# End-to-End test for Freehold with real eBPF on virtual network
#
# This script:
# 1. Creates network namespaces with veth pair
# 2. Starts freehold-server with eBPF in server namespace
# 3. Runs protocol test client in client namespace
# 4. Verifies the full registration flow works

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Kill any running processes
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    # Delete namespaces (this also removes veth)
    ip netns del fh_server 2>/dev/null || true
    ip netns del fh_client 2>/dev/null || true

    log_info "Cleanup complete"
}

trap cleanup EXIT

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (requires network namespaces and eBPF)"
    exit 1
fi

# Check for required binaries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SERVER_BIN="$PROJECT_ROOT/target/release/freehold-server"
EBPF_OBJ="$PROJECT_ROOT/target/bpfel-unknown-none/release/freehold-ebpf"

if [ ! -f "$SERVER_BIN" ]; then
    log_error "Server binary not found at $SERVER_BIN"
    log_info "Build with: cargo build --release -p freehold-server"
    exit 1
fi

if [ ! -f "$EBPF_OBJ" ]; then
    log_warn "eBPF object not found at $EBPF_OBJ"
    log_info "Build with: cargo xtask build-ebpf --release"
    log_info "Continuing without eBPF (server-only mode)..."
    SKIP_EBPF=1
else
    SKIP_EBPF=0
fi

# Configuration
SERVER_IP="10.99.0.1"
CLIENT_IP="10.99.0.2"
RELAY_PORT=9999
CLIENT_PORT=8080
SECRET="e2e_test_secret_key_32_bytes_!"

log_info "=== Freehold E2E Test ==="
log_info "Server: $SERVER_IP:$RELAY_PORT"
log_info "Client: $CLIENT_IP"

# Create network namespaces
log_info "Creating network namespaces..."
ip netns add fh_server
ip netns add fh_client

# Create veth pair
log_info "Creating veth pair..."
ip link add veth_server type veth peer name veth_client

# Move interfaces to namespaces
ip link set veth_server netns fh_server
ip link set veth_client netns fh_client

# Configure server namespace
log_info "Configuring server namespace..."
ip netns exec fh_server bash -c "
    ip addr add $SERVER_IP/24 dev veth_server
    ip link set veth_server up
    ip link set lo up
"

# Configure client namespace
log_info "Configuring client namespace..."
ip netns exec fh_client bash -c "
    ip addr add $CLIENT_IP/24 dev veth_client
    ip link set veth_client up
    ip link set lo up
"

# Test connectivity
log_info "Testing connectivity..."
if ip netns exec fh_client ping -c 1 -W 1 "$SERVER_IP" > /dev/null 2>&1; then
    log_info "Network connectivity OK"
else
    log_error "Network connectivity failed"
    exit 1
fi

# Create server config
CONFIG_FILE=$(mktemp)
cat > "$CONFIG_FILE" << EOF
# E2E Test Server Config
interface = "veth_server"
port = $RELAY_PORT
ebpf_path = "$EBPF_OBJ"
neighbors = []

[anycast]
primary_ip = "$SERVER_IP"

[limits]
max_ports_per_ip = 8
cleanup_interval_secs = 60
verbose_events = true

[logging]
filter = "info"

[auth]
secret = "$SECRET"
EOF

log_info "Starting server..."
if [ "$SKIP_EBPF" -eq 1 ]; then
    log_warn "Skipping eBPF - server will not process packets"
    # Just verify the server binary works
    ip netns exec fh_server "$SERVER_BIN" validate-config "$CONFIG_FILE" || {
        log_error "Server config validation failed"
        exit 1
    }
    log_info "Server config validated (eBPF not available for full test)"
else
    # Start server in background
    ip netns exec fh_server "$SERVER_BIN" --config "$CONFIG_FILE" &
    SERVER_PID=$!

    # Wait for server to start
    sleep 2

    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_error "Server failed to start"
        exit 1
    fi
    log_info "Server started (PID: $SERVER_PID)"
fi

# Run protocol test from client namespace
log_info "Running protocol test..."

# Create a simple test that sends UDP messages and verifies responses
ip netns exec fh_client bash -c "
    # Test: Send REGISTER and expect CHALLENGE
    # Message format: type(1) + port(2) = 3 bytes
    # Register = 0x00 + port_be16

    PORT_HI=\$(printf '%02x' \$((CLIENT_PORT >> 8)))
    PORT_LO=\$(printf '%02x' \$((CLIENT_PORT & 0xFF)))

    echo 'Sending REGISTER...'
    RESPONSE=\$(echo -n -e '\x00\x${PORT_HI}\x${PORT_LO}' | nc -u -w 2 $SERVER_IP $RELAY_PORT | xxd -p | head -c 40)

    if [ -z \"\$RESPONSE\" ]; then
        echo 'ERROR: No response from server'
        exit 1
    fi

    # Check response type (0x01 = CHALLENGE)
    RESP_TYPE=\$(echo \$RESPONSE | cut -c1-2)
    if [ \"\$RESP_TYPE\" = '01' ]; then
        echo 'SUCCESS: Received CHALLENGE response'
        echo \"Response: \$RESPONSE\"
    else
        echo \"ERROR: Expected CHALLENGE (01), got: \$RESP_TYPE\"
        echo \"Full response: \$RESPONSE\"
        exit 1
    fi
"

E2E_RESULT=$?

rm -f "$CONFIG_FILE"

if [ $E2E_RESULT -eq 0 ]; then
    log_info "=== E2E Test PASSED ==="
    exit 0
else
    log_error "=== E2E Test FAILED ==="
    exit 1
fi
