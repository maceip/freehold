#!/bin/bash
# Build Rust library for iOS
#
# This script compiles the Freehold FFI library for iOS targets
# and creates a universal XCFramework.
#
# Prerequisites:
#   - Rust with iOS targets: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   - Xcode Command Line Tools
#   - cbindgen: cargo install cbindgen
#
# Usage:
#   ./build-rust.sh [debug|release]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FFI_CRATE="$SCRIPT_DIR/FreeholdFFI"
OUTPUT_DIR="$SCRIPT_DIR/build"
FRAMEWORK_NAME="FreeholdFFI"

# Build configuration
BUILD_MODE="${1:-release}"
if [[ "$BUILD_MODE" == "debug" ]]; then
    CARGO_FLAGS=""
    TARGET_DIR="debug"
else
    CARGO_FLAGS="--release"
    TARGET_DIR="release"
fi

# iOS targets
IOS_DEVICE_TARGET="aarch64-apple-ios"
IOS_SIM_ARM_TARGET="aarch64-apple-ios-sim"
IOS_SIM_X86_TARGET="x86_64-apple-ios"

echo "=========================================="
echo "Freehold iOS Build Script"
echo "=========================================="
echo "Build mode: $BUILD_MODE"
echo "Project root: $PROJECT_ROOT"
echo "FFI crate: $FFI_CRATE"
echo "Output dir: $OUTPUT_DIR"
echo ""

# Check prerequisites
check_prereqs() {
    echo "Checking prerequisites..."

    if ! command -v rustc &> /dev/null; then
        echo "Error: Rust is not installed"
        exit 1
    fi

    if ! command -v cbindgen &> /dev/null; then
        echo "Installing cbindgen..."
        cargo install cbindgen
    fi

    # Check for iOS targets
    local missing_targets=()
    for target in $IOS_DEVICE_TARGET $IOS_SIM_ARM_TARGET $IOS_SIM_X86_TARGET; do
        if ! rustup target list --installed | grep -q "$target"; then
            missing_targets+=("$target")
        fi
    done

    if [[ ${#missing_targets[@]} -gt 0 ]]; then
        echo "Installing missing Rust targets: ${missing_targets[*]}"
        for target in "${missing_targets[@]}"; do
            rustup target add "$target"
        done
    fi

    echo "Prerequisites OK"
    echo ""
}

# Generate C headers
generate_headers() {
    echo "Generating C headers..."
    cd "$FFI_CRATE"
    cbindgen --config cbindgen.toml --crate freehold-ios-ffi --output include/freehold_ffi.h
    echo "Headers generated at: $FFI_CRATE/include/freehold_ffi.h"
    echo ""
}

# Build for a specific target
build_target() {
    local target="$1"
    echo "Building for $target..."

    cd "$FFI_CRATE"
    cargo build $CARGO_FLAGS --target "$target"

    local lib_path="$FFI_CRATE/target/$target/$TARGET_DIR/libfreehold_ffi.a"
    if [[ -f "$lib_path" ]]; then
        echo "Built: $lib_path"
    else
        echo "Error: Failed to build for $target"
        exit 1
    fi
}

# Create fat library for simulator (arm64 + x86_64)
create_sim_fat_library() {
    echo "Creating fat library for iOS Simulator..."

    local arm_lib="$FFI_CRATE/target/$IOS_SIM_ARM_TARGET/$TARGET_DIR/libfreehold_ffi.a"
    local x86_lib="$FFI_CRATE/target/$IOS_SIM_X86_TARGET/$TARGET_DIR/libfreehold_ffi.a"
    local fat_lib="$OUTPUT_DIR/sim/libfreehold_ffi.a"

    mkdir -p "$OUTPUT_DIR/sim"

    lipo -create "$arm_lib" "$x86_lib" -output "$fat_lib"

    echo "Created: $fat_lib"
    echo ""
}

# Create XCFramework
create_xcframework() {
    echo "Creating XCFramework..."

    local device_lib="$FFI_CRATE/target/$IOS_DEVICE_TARGET/$TARGET_DIR/libfreehold_ffi.a"
    local sim_lib="$OUTPUT_DIR/sim/libfreehold_ffi.a"
    local framework_output="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"

    # Remove existing framework
    rm -rf "$framework_output"

    # Create header directory structure
    local headers_dir="$OUTPUT_DIR/Headers"
    mkdir -p "$headers_dir"
    cp "$FFI_CRATE/include/freehold_ffi.h" "$headers_dir/"
    cp "$FFI_CRATE/include/module.modulemap" "$headers_dir/"

    # Create XCFramework
    xcodebuild -create-xcframework \
        -library "$device_lib" \
        -headers "$headers_dir" \
        -library "$sim_lib" \
        -headers "$headers_dir" \
        -output "$framework_output"

    echo "Created: $framework_output"
    echo ""
}

# Copy to Xcode project
copy_to_project() {
    echo "Copying to Xcode project..."

    local xcode_frameworks="$SCRIPT_DIR/Freehold/Frameworks"
    mkdir -p "$xcode_frameworks"

    # Copy XCFramework
    rm -rf "$xcode_frameworks/$FRAMEWORK_NAME.xcframework"
    cp -R "$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework" "$xcode_frameworks/"

    echo "Copied to: $xcode_frameworks/$FRAMEWORK_NAME.xcframework"
    echo ""
}

# Main
main() {
    check_prereqs
    generate_headers

    echo "Building Rust libraries..."
    echo ""

    build_target "$IOS_DEVICE_TARGET"
    build_target "$IOS_SIM_ARM_TARGET"
    build_target "$IOS_SIM_X86_TARGET"

    echo ""
    create_sim_fat_library
    create_xcframework
    copy_to_project

    echo "=========================================="
    echo "Build complete!"
    echo ""
    echo "To use in Xcode:"
    echo "1. Add FreeholdFFI.xcframework to your project"
    echo "2. Link against the framework in Build Phases"
    echo "3. Import in Swift: import FreeholdFFI"
    echo "=========================================="
}

main
