#!/usr/bin/env bash
# Build the Rust QUIC/H3 WebSocket client for iOS targets.
#
# Produces FreeholdWSClient.xcframework containing:
#   - aarch64-apple-ios          (device)
#   - aarch64-apple-ios-sim      (simulator, Apple Silicon)
#   - x86_64-apple-ios           (simulator, Intel)
#
# Usage:
#   ./build-rust.sh              # debug
#   ./build-rust.sh --release    # release

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$SCRIPT_DIR/FreeholdWSClient"
BUILD_DIR="$SCRIPT_DIR/build"

PROFILE="debug"
CARGO_FLAGS=""
if [ "${1:-}" = "--release" ]; then
    PROFILE="release"
    CARGO_FLAGS="--release"
fi

TARGETS=(
    aarch64-apple-ios
    aarch64-apple-ios-sim
    x86_64-apple-ios
)

echo "==> Checking Rust iOS targets"
for target in "${TARGETS[@]}"; do
    rustup target add "$target" 2>/dev/null || true
done

echo "==> Building Rust library ($PROFILE)"
for target in "${TARGETS[@]}"; do
    echo "    $target"
    cargo build $CARGO_FLAGS --target "$target" --manifest-path "$RUST_DIR/Cargo.toml"
done

echo "==> Creating fat simulator library"
mkdir -p "$BUILD_DIR/sim"
lipo -create \
    "$RUST_DIR/../../target/aarch64-apple-ios-sim/$PROFILE/libfreehold_ws_client.a" \
    "$RUST_DIR/../../target/x86_64-apple-ios/$PROFILE/libfreehold_ws_client.a" \
    -output "$BUILD_DIR/sim/libfreehold_ws_client.a"

echo "==> Creating XCFramework"
rm -rf "$BUILD_DIR/FreeholdWSClient.xcframework"

xcodebuild -create-xcframework \
    -library "$RUST_DIR/../../target/aarch64-apple-ios/$PROFILE/libfreehold_ws_client.a" \
    -headers "$RUST_DIR/include" \
    -library "$BUILD_DIR/sim/libfreehold_ws_client.a" \
    -headers "$RUST_DIR/include" \
    -output "$BUILD_DIR/FreeholdWSClient.xcframework"

echo "==> Done: $BUILD_DIR/FreeholdWSClient.xcframework"
