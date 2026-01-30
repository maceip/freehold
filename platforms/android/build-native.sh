#!/bin/bash
# Build Freehold native library for Android
#
# Prerequisites:
# - Rust toolchain with Android targets:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
# - cargo-ndk:
#   cargo install cargo-ndk
# - Android NDK (set ANDROID_NDK_HOME or NDK_HOME)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BRIDGE_CRATE="$PROJECT_ROOT/crates/freehold-android-bridge"
OUTPUT_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

# Android targets
TARGETS=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "x86_64-linux-android:x86_64"
    "i686-linux-android:x86"
)

echo "Building Freehold native library for Android..."
echo "Bridge crate: $BRIDGE_CRATE"
echo "Output: $OUTPUT_DIR"

# Ensure output directories exist
for target_pair in "${TARGETS[@]}"; do
    abi="${target_pair#*:}"
    mkdir -p "$OUTPUT_DIR/$abi"
done

# Build for each target
for target_pair in "${TARGETS[@]}"; do
    target="${target_pair%:*}"
    abi="${target_pair#*:}"

    echo ""
    echo "=== Building for $target ($abi) ==="

    cd "$BRIDGE_CRATE"

    # Use cargo-ndk if available, otherwise raw cargo
    if command -v cargo-ndk &> /dev/null; then
        cargo ndk -t "$target" build --release
    else
        # Fallback to raw cargo with linker config
        CARGO_TARGET_DIR="$PROJECT_ROOT/target" \
        cargo build --target "$target" --release
    fi

    # Copy the built library
    LIB_PATH="$PROJECT_ROOT/target/$target/release/libfreehold_android.so"
    if [ -f "$LIB_PATH" ]; then
        cp "$LIB_PATH" "$OUTPUT_DIR/$abi/"
        echo "Copied to $OUTPUT_DIR/$abi/libfreehold_android.so"
    else
        echo "Warning: Library not found at $LIB_PATH"
    fi
done

echo ""
echo "=== Generating Kotlin bindings ==="

cd "$BRIDGE_CRATE"
KOTLIN_OUT="$SCRIPT_DIR/app/src/main/kotlin/uniffi/freehold_android"
mkdir -p "$KOTLIN_OUT"

# Generate bindings using uniffi-bindgen
if command -v uniffi-bindgen &> /dev/null; then
    uniffi-bindgen generate src/freehold_android.udl \
        --language kotlin \
        --out-dir "$(dirname "$KOTLIN_OUT")"
else
    echo "uniffi-bindgen not found. Install with: cargo install uniffi_bindgen"
    echo "Or generate manually from the Rust crate."
fi

echo ""
echo "Build complete!"
echo ""
echo "Next steps:"
echo "1. Open platforms/android in Android Studio"
echo "2. Sync Gradle"
echo "3. Build and run"
