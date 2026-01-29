#!/bin/bash
# check-deps.sh - Check for outdated dependencies and potential upgrades
# This script is used by CI to analyze dependency status

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS_FILE="$REPO_ROOT/.github/deps.md"

echo "=== Freehold Dependency Check ==="
echo ""

# Check for cargo
if ! command -v cargo &> /dev/null; then
    echo "ERROR: cargo is not installed"
    exit 1
fi

# Install cargo-outdated if not present
if ! cargo outdated --version &> /dev/null 2>&1; then
    echo "Installing cargo-outdated..."
    cargo install cargo-outdated --locked
fi

echo "Checking for outdated dependencies..."
echo ""

# Run cargo outdated
OUTDATED_OUTPUT=$(cargo outdated --workspace 2>/dev/null || echo "")

if echo "$OUTDATED_OUTPUT" | grep -q "->"; then
    echo "=== Outdated Dependencies Found ==="
    echo ""
    echo "$OUTDATED_OUTPUT"
    echo ""

    # Count outdated packages
    OUTDATED_COUNT=$(echo "$OUTDATED_OUTPUT" | grep -c "->" || echo "0")
    echo "Total outdated packages: $OUTDATED_COUNT"

    # Extract package names
    echo ""
    echo "=== Packages that can be upgraded ==="
    echo "$OUTDATED_OUTPUT" | grep "->" | awk '{print $1}' | sort -u

    exit 0
else
    echo "All dependencies are up to date!"
    exit 0
fi
