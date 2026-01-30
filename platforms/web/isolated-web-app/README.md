# Freehold Isolated Web App (IWA)

A browser-based Freehold client using the Direct Sockets API and quinn-wasm for native QUIC protocol support.

## Overview

This Isolated Web App (IWA) provides:

- **Direct TCP/UDP socket access** via the Direct Sockets API
- **QUIC protocol support** via quinn-wasm (WebAssembly)
- **Secure signed web bundle** deployment

## Prerequisites

- Node.js v18 or higher
- Chrome/Chromium browser (with IWA support)
- OpenSSL (for key generation)

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Generate Signing Key

```bash
npm run keygen
```

This creates an Ed25519 private key (`ed25519key.pem`) used to sign the web bundle.

### 3. Build the Signed Web Bundle

```bash
npm run build
```

This generates `signed.swbn` - the signed web bundle ready for installation.

### 4. Configure Chrome

1. Launch Chrome with Direct Sockets enabled:
   ```bash
   chrome --enable-features=DirectSockets
   ```

2. Enable Isolated Web Apps:
   - Navigate to `chrome://flags`
   - Search for "Isolated Web Apps"
   - Enable the flag
   - Restart Chrome

### 5. Install the IWA

1. Navigate to `chrome://web-app-internals`
2. Click "Install from Signed Web Bundle"
3. Select the generated `signed.swbn` file
4. Note the assigned App ID

## Project Structure

```
isolated-web-app/
├── assets/
│   ├── .well-known/
│   │   └── manifest.webmanifest  # IWA manifest with Direct Sockets permissions
│   ├── index.html                # Main application UI
│   ├── script.js                 # Direct Sockets implementation
│   ├── quinn.html                # QUIC test interface
│   ├── quinn-client.js           # quinn-wasm integration
│   └── tcp.html                  # TCP server socket demo
├── index.js                      # Web bundle signing script
├── rollup.config.mjs             # Rollup bundler configuration
├── package.json
└── README.md
```

## Features

### Direct Sockets API

The IWA has access to:

- `TCPSocket` - Create TCP client connections
- `UDPSocket` - Create UDP sockets
- `TCPServerSocket` - Create TCP server sockets

These APIs are only available in Isolated Web Apps with the `direct-sockets` permission declared in the manifest.

### QUIC via quinn-wasm

The app integrates quinn-wasm for native QUIC protocol support:

```javascript
import init, { connect_quic_direct_sockets } from './quinn_wasm_direct_sockets.js';

await init();
const response = await connect_quic_direct_sockets('127.0.0.1:4433', 'Hello');
```

## Development

### Alternative Build with Rollup

For more advanced bundling with tree-shaking:

```bash
npm run bundle
```

This uses `rollup-plugin-webbundle` for the build process.

### Environment Variables

Create a `.env` file for key configuration:

```bash
ED25519KEY="-----BEGIN PRIVATE KEY-----\nMC4CAQAw...\n-----END PRIVATE KEY-----"
```

## Manifest Configuration

The IWA manifest (`assets/.well-known/manifest.webmanifest`) declares the required permissions:

```json
{
  "permissions_policy": {
    "cross-origin-isolated": ["self"],
    "direct-sockets": ["self"],
    "direct-sockets-private": ["self"]
  }
}
```

## Security Considerations

- **Development keys**: The generated `ed25519key.pem` is for development only
- **Production**: Use properly secured keys and a secure signing process
- **CSP**: The bundle includes strict Content Security Policy headers
- **CORS**: Cross-origin policies are enforced for security

## Troubleshooting

### Direct Sockets API Not Available

Ensure:
1. Chrome is launched with `--enable-features=DirectSockets`
2. IWA flag is enabled in `chrome://flags`
3. The app is installed as an IWA (not loaded as a regular web page)

### Bundle Signing Errors

Ensure:
1. `ed25519key.pem` exists and is valid
2. Node.js crypto module supports Ed25519
3. All dependencies are installed

### QUIC Connection Failures

Ensure:
1. The QUIC server is running and accessible
2. Certificates are properly configured
3. Firewall allows UDP traffic on the target port

## Resources

- [Direct Sockets API Specification](https://github.com/nicokrauss/nicokrauss.gitub.io/blob/main/nicokrauss-de/Direktes_Sockets_API.md)
- [Isolated Web Apps Explainer](https://nicokrauss.github.io/nicokrauss-de/nicokrauss-de/Isolierte-Webanwendungen.html)
- [quinn-wasm](https://github.com/nicokrauss/nicokrauss.gitub.io/blob/main/nicokrauss-de/direct_sockets_api.md)
- [webbundle-plugins](https://nicokrauss.github.io/nicokrauss-de/nicokrauss-de/Direct_Sockets_und_WebTransport_API.html)

## License

Apache-2.0
