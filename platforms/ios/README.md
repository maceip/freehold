# Freehold iOS

iOS client for the Freehold anycast relay network.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Freehold iOS App                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   SwiftUI    │  │  VPNManager  │  │ FreeholdClient   │  │
│  │   Views      │  │  (NEVPNMgr)  │  │ (Swift wrapper)  │  │
│  └──────────────┘  └──────────────┘  └────────┬─────────┘  │
│                                                │            │
│  ┌─────────────────────────────────────────────┴──────────┐ │
│  │                    C FFI Bridge                        │ │
│  │              (freehold_ffi.h / libfreehold_ffi.a)      │ │
│  └─────────────────────────────────────────────┬──────────┘ │
└────────────────────────────────────────────────┼────────────┘
                                                 │
┌────────────────────────────────────────────────┼────────────┐
│              Rust Core (freehold-ios-ffi)      │            │
│  ┌─────────────────────────────────────────────┴──────────┐ │
│  │              freehold-client-core                      │ │
│  │  ┌─────────────────┐  ┌────────────────────────────┐   │ │
│  │  │     Engine      │  │      freehold-h3-proxy     │   │ │
│  │  │  (Registration) │  │  (QUIC/H3 → HTTP/1.1)      │   │ │
│  │  └─────────────────┘  └────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│            Network Extension (VPN Mode)                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           NEPacketTunnelProvider                      │  │
│  │  - Intercepts device network traffic                  │  │
│  │  - Routes Freehold traffic through QUIC tunnel        │  │
│  │  - Integrates with iOS VPN settings                   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## QUIC Implementation

This iOS app uses **Quinn** (Rust QUIC implementation) via C FFI bindings rather than Apple's native `Network.framework` QUIC. This approach was chosen for:

1. **Code Consistency**: Same QUIC/H3 implementation as other platforms
2. **Full H3 Support**: Quinn + h3 crate provides complete HTTP/3 with H3-to-H1 proxying
3. **Proven Stack**: Quinn is battle-tested and used in production systems

### Alternatives Considered

| Option | Pros | Cons |
|--------|------|------|
| **Quinn via FFI** (chosen) | Same code as other platforms, full H3 support | Build complexity |
| Apple Network.framework | Native, no FFI overhead | No H3 protocol layer, different codebase |
| SwiftQuic | Pure Swift | Not production-ready, incomplete |

## Building

### Prerequisites

1. **Rust with iOS targets**:
   ```bash
   rustup target add aarch64-apple-ios
   rustup target add aarch64-apple-ios-sim
   rustup target add x86_64-apple-ios
   ```

2. **cbindgen** (for generating C headers):
   ```bash
   cargo install cbindgen
   ```

3. **Xcode** (14.0+ recommended)

### Build Steps

1. **Build the Rust FFI library**:
   ```bash
   cd platforms/ios
   ./build-rust.sh release
   ```

   This will:
   - Compile for iOS device (arm64)
   - Compile for iOS Simulator (arm64 + x86_64)
   - Generate C headers
   - Create XCFramework

2. **Open in Xcode**:
   - Open `platforms/ios/Freehold.xcodeproj` (or create from Package.swift)
   - Select your development team
   - Build and run

### Manual Xcode Project Setup

If creating a new Xcode project:

1. Create new iOS App project
2. Add FreeholdFFI.xcframework to "Frameworks, Libraries, and Embedded Content"
3. Add Network Extension target (Packet Tunnel Provider)
4. Configure entitlements for both targets
5. Add Swift source files

## Project Structure

```
platforms/ios/
├── FreeholdFFI/              # Rust FFI crate
│   ├── Cargo.toml
│   ├── cbindgen.toml
│   ├── build.rs
│   ├── src/
│   │   └── lib.rs            # FFI exports
│   └── include/
│       ├── freehold_ffi.h    # Generated C header
│       └── module.modulemap
│
├── Freehold/                 # Main iOS app
│   ├── FreeholdApp.swift     # App entry point
│   ├── ContentView.swift     # Main UI
│   ├── FreeholdClient.swift  # Swift wrapper for FFI
│   ├── VPNManager.swift      # VPN configuration manager
│   ├── VPNView.swift         # VPN settings UI
│   ├── Info.plist
│   └── Freehold.entitlements
│
├── FreeholdNetworkExtension/ # VPN Network Extension
│   ├── PacketTunnelProvider.swift
│   ├── Info.plist
│   └── FreeholdNetworkExtension.entitlements
│
├── Package.swift             # Swift Package Manager
├── build-rust.sh             # Build script
└── README.md
```

## VPN / Network Extension

The app includes an optional VPN mode using iOS's Network Extension framework:

### How It Works

1. **NEPacketTunnelProvider**: Runs as a system extension, intercepting network traffic
2. **Packet Processing**: Reads packets from the tunnel interface, routes Freehold traffic through QUIC
3. **Integration**: Appears in iOS Settings → VPN

### Entitlements Required

- `com.apple.developer.networking.networkextension` with `packet-tunnel-provider`
- App Groups for data sharing between app and extension
- Requires Apple Developer Program membership

### Limitations

- VPN entitlement requires Apple Developer Program ($99/year)
- Must be distributed via App Store or enterprise distribution
- Cannot be tested in Simulator (device only)

## API Usage

### Basic Usage (without VPN)

```swift
import FreeholdClient

// Configure
let config = FreeholdConfiguration(
    relayHost: "relay.freehold.network",
    relayPort: 443,
    claimPort: 8443,
    backendHost: "127.0.0.1",
    backendPort: 8080
)

// Start
let client = FreeholdClient.shared
try client.start(with: config)

// Monitor status
client.$currentState.sink { state in
    print("State: \(state)")
}

// Stop
client.stop()
```

### VPN Mode

```swift
import NetworkExtension

// Configure VPN
let vpnManager = VPNManager.shared
try await vpnManager.configure(
    relayHost: "relay.freehold.network",
    relayPort: 443,
    claimPort: 8443
)

// Connect
try vpnManager.connect()

// Disconnect
vpnManager.disconnect()
```

## FFI Reference

See `FreeholdFFI/include/freehold_ffi.h` for the complete C API:

```c
// Initialize
int32_t freehold_init(void);

// Start/stop service
int32_t freehold_start(const FreeholdConfig *config);
int32_t freehold_stop(void);
int32_t freehold_is_running(void);

// Status polling
FreeholdStatusUpdate *freehold_poll_status(void);
void freehold_free_status_update(FreeholdStatusUpdate *update);

// VPN mode
int32_t freehold_vpn_init(PacketCallback callback, void *context);
int32_t freehold_vpn_process_packet(const uint8_t *data, size_t len);
int32_t freehold_vpn_stop(void);
```

## Troubleshooting

### Build Errors

**"Missing iOS targets"**:
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

**"cbindgen not found"**:
```bash
cargo install cbindgen
```

**"Library not found"**:
- Ensure `build-rust.sh` completed successfully
- Check that XCFramework is in `Freehold/Frameworks/`

### Runtime Errors

**"Failed to initialize FFI"**:
- Check that the library is properly linked
- Verify architecture matches (device vs simulator)

**VPN not appearing in Settings**:
- Ensure entitlements are configured correctly
- Check that the extension bundle identifier is correct
- VPN requires actual device, not simulator

## License

Apache-2.0 - See repository root for details.
