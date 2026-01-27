# Freehold Android Client

Android VPN client for the Freehold anycast relay network. Uses Android's VpnService to create a "fake VPN" that tunnels traffic through QUIC to Freehold relays.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Android Device                                          │
│                                                         │
│  ┌─────────────────┐    ┌─────────────────────────────┐│
│  │ App (HTTP)      │───>│ Local Backend (127.0.0.1)   ││
│  └─────────────────┘    └──────────────┬──────────────┘│
│                                        │               │
│  ┌─────────────────────────────────────┼───────────────┤
│  │ FreeholdVpnService                  │               │
│  │                                     ▼               │
│  │  ┌─────────────┐    ┌─────────────────────────────┐│
│  │  │ TUN        │    │ H3 Proxy (Quinn + h3)       ││
│  │  │ Interface   │───>│ HTTP/3 ←→ HTTP/1.1          ││
│  │  └─────────────┘    └──────────────┬──────────────┘│
│  │                                     │               │
│  │  ┌─────────────────────────────────┴──────────────┐│
│  │  │ Engine (Registration, Heartbeat, Discovery)    ││
│  │  └──────────────────────┬─────────────────────────┘│
│  └─────────────────────────│───────────────────────────┤
│                            │ UDP (QUIC)                │
└────────────────────────────│───────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Freehold Relay  │
                    │ (Anycast)       │
                    └─────────────────┘
```

## The "Fake VPN" Approach

Unlike a traditional VPN that encrypts and tunnels all traffic, Freehold's VPN service:

1. **Creates a TUN interface** via Android's VpnService
2. **Intercepts traffic** destined for specific ports/addresses
3. **Tunnels via QUIC** to the Freehold relay network
4. **Runs an H3 proxy** locally that converts HTTP/3 ↔ HTTP/1.1

This allows remote browsers to access local services via HTTP/3 through the relay network.

## Requirements

- Android 10+ (API 29) minimum
- Android 16 (API 36) target
- Internet permission
- VPN service permission (granted by user)

## Building

### Prerequisites

1. **Rust toolchain with Android targets**:
   ```bash
   rustup target add aarch64-linux-android
   rustup target add armv7-linux-androideabi
   rustup target add x86_64-linux-android
   rustup target add i686-linux-android
   ```

2. **cargo-ndk** for easier Android builds:
   ```bash
   cargo install cargo-ndk
   ```

3. **Android NDK** (via Android Studio SDK Manager)

4. **uniffi-bindgen** for Kotlin bindings:
   ```bash
   cargo install uniffi_bindgen
   ```

### Build Steps

1. **Build native library**:
   ```bash
   ./build-native.sh
   ```

2. **Open in Android Studio**:
   - Open `platforms/android` as project
   - Sync Gradle
   - Build and run

### Manual Build

```bash
# Build for arm64 (most common)
cd crates/freehold-android-bridge
cargo ndk -t aarch64-linux-android build --release

# Copy to jniLibs
cp target/aarch64-linux-android/release/libfreehold_android.so \
   platforms/android/app/src/main/jniLibs/arm64-v8a/

# Generate Kotlin bindings
uniffi-bindgen generate src/freehold_android.udl \
    --language kotlin \
    --out-dir platforms/android/app/src/main/kotlin/
```

## Project Structure

```
platforms/android/
├── app/
│   ├── src/main/
│   │   ├── kotlin/com/freehold/client/
│   │   │   ├── MainActivity.kt       # Compose UI
│   │   │   ├── FreeholdVpnService.kt # VPN service + tunnel
│   │   │   ├── FreeholdApplication.kt # App lifecycle
│   │   │   └── ui/theme/Theme.kt     # Material3 theme
│   │   ├── jniLibs/                  # Native .so files
│   │   ├── res/                      # Android resources
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
├── build-native.sh
└── README.md

crates/freehold-android-bridge/
├── src/
│   ├── lib.rs                        # Rust bridge implementation
│   └── freehold_android.udl          # UniFFI interface definition
├── build.rs
└── Cargo.toml
```

## Kotlin/Rust Bridge (UniFFI)

The native library is exposed to Kotlin via [UniFFI](https://mozilla.github.io/uniffi-rs/). Key interfaces:

```kotlin
// Create tunnel with configuration
val tunnel = FreeholdTunnel(
    TunnelConfig(
        relayAddress = "relay.freehold.network",
        relayPort = 443u,
        localPort = 8443u,
        backendAddress = "127.0.0.1:8080",
        autoDiscover = true
    ),
    statusCallback
)

// Start with VPN file descriptor
tunnel.start(vpnFd)

// Process packets
val response = tunnel.processOutbound(packet)
val incoming = tunnel.processInbound(quicPacket)

// Stop
tunnel.stop()
```

## Why Quinn (Rust) Instead of Pure Kotlin?

1. **No production QUIC libraries in Kotlin** - KNet uses Cronet (C++), Kuikku is experimental
2. **Code reuse** - Same Quinn-based implementation as desktop clients
3. **Performance** - Native Rust is faster than JVM for crypto/networking
4. **Proven** - Quinn is battle-tested, used by many production systems

## Network Flow

1. User starts VPN from app
2. Android grants VPN permission
3. VpnService creates TUN interface at `10.255.255.1`
4. All traffic routes through TUN
5. `FreeholdVpnService` reads packets from TUN
6. Packets are processed through the native tunnel:
   - Registration with Freehold relay (UDP)
   - H3 proxy handles HTTP/3 ↔ HTTP/1.1 conversion
7. Remote browsers connect via `https://relay:port`
8. Traffic flows: Browser → Relay → Device → Local backend

## Testing

1. Install app on device/emulator
2. Configure relay address (use test relay or local server)
3. Set backend to your local HTTP server
4. Connect VPN
5. From another device, access `https://<relay>:<port>/`

## License

Apache 2.0 - See repository root LICENSE file.
