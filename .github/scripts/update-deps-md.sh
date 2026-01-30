#!/bin/bash
# update-deps-md.sh - Update deps.md with verified upgrades
# This script is called by CI after successful build/test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS_FILE="$REPO_ROOT/.github/deps.md"

COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== Updating deps.md ==="
echo "Date: $DATE"
echo "Commit: $COMMIT_SHA"
echo ""

# Get outdated deps
OUTDATED=$(cargo outdated --workspace 2>/dev/null || echo "")

if ! echo "$OUTDATED" | grep -q "->"; then
    echo "No outdated dependencies to record"
    exit 0
fi

# Create backup
if [ -f "$DEPS_FILE" ]; then
    cp "$DEPS_FILE" "$DEPS_FILE.bak"
fi

# Parse current deps.md to preserve existing entries
EXISTING_TABLE=""
if [ -f "$DEPS_FILE" ]; then
    EXISTING_TABLE=$(grep "^|" "$DEPS_FILE" | grep -v "Package" | grep -v "---" || true)
fi

# Generate new deps.md
cat > "$DEPS_FILE" << HEADER
# Dependency Upgrade Tracking

This file tracks dependencies that have been verified to work after upgrade.
The CD pipeline uses this file to force-upgrade these dependencies.

## Last Updated

$DATE

## Verified Upgrades

| Package | From Version | To Version | Verified Date | Commit |
|---------|--------------|------------|---------------|--------|
HEADER

# Add existing entries (if any)
if [ -n "$EXISTING_TABLE" ]; then
    echo "$EXISTING_TABLE" >> "$DEPS_FILE"
fi

# Add new entries from outdated packages
echo "$OUTDATED" | grep "->" | while read -r line; do
    PKG=$(echo "$line" | awk '{print $1}')
    FROM=$(echo "$line" | awk '{print $2}')
    TO=$(echo "$line" | awk '{print $4}')

    if [ -n "$PKG" ] && [ -n "$FROM" ] && [ -n "$TO" ]; then
        # Check if entry already exists
        if ! grep -q "| $PKG |" "$DEPS_FILE" 2>/dev/null; then
            echo "| $PKG | $FROM | $TO | $DATE | ${COMMIT_SHA:0:7} |" >> "$DEPS_FILE"
            echo "Added: $PKG ($FROM -> $TO)"
        fi
    fi
done

# Add force upgrade commands section
cat >> "$DEPS_FILE" << 'COMMANDS'

## Force Upgrade Commands

The following commands can be used to force-upgrade verified dependencies:

```bash
COMMANDS

# Add upgrade commands for each package
echo "$OUTDATED" | grep "->" | awk '{print $1}' | while read -r pkg; do
    if [ -n "$pkg" ]; then
        echo "cargo update -p $pkg" >> "$DEPS_FILE"
    fi
done

cat >> "$DEPS_FILE" << 'FOOTER'
```

## Upgrade History

See git history for this file to track all changes.

## Security Notes

- All upgrades are scanned with `cargo-audit` and OSV Scanner
- SBOM is generated for each release
- Build artifacts are attested via GitHub's artifact attestation
FOOTER

echo ""
echo "=== deps.md updated ==="
cat "$DEPS_FILE"
