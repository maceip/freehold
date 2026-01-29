#!/bin/bash
# force-upgrade.sh - Force upgrade dependencies based on deps.md
# This script is used by CD pipeline to apply verified upgrades

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS_FILE="$REPO_ROOT/.github/deps.md"

echo "=== Freehold Force Dependency Upgrade ==="
echo ""

if [ ! -f "$DEPS_FILE" ]; then
    echo "No deps.md found at $DEPS_FILE"
    echo "Skipping force upgrade"
    exit 0
fi

echo "Reading verified upgrades from deps.md..."
echo ""

# Extract package names from the markdown table
# Format: | Package | From Version | To Version | Verified Date | Commit |
PACKAGES=$(grep "^|" "$DEPS_FILE" | grep -v "Package" | grep -v "---" | awk -F'|' '{print $2}' | tr -d ' ' | grep -v "^$" || true)

if [ -z "$PACKAGES" ]; then
    echo "No packages listed in deps.md"
    echo "Running general cargo update instead..."
    cargo update
    exit 0
fi

echo "Packages to upgrade:"
echo "$PACKAGES"
echo ""

UPGRADED=0
FAILED=0

for pkg in $PACKAGES; do
    if [ -n "$pkg" ]; then
        echo "Upgrading: $pkg"
        if cargo update -p "$pkg" 2>/dev/null; then
            echo "  ✓ Success"
            ((UPGRADED++)) || true
        else
            echo "  ✗ Failed (may not exist or already at latest)"
            ((FAILED++)) || true
        fi
    fi
done

echo ""
echo "=== Upgrade Summary ==="
echo "Upgraded: $UPGRADED"
echo "Failed: $FAILED"
echo ""

# Show current dependency status
echo "Current dependency tree (depth 1):"
cargo tree --workspace --depth 1 2>/dev/null | head -50 || true
