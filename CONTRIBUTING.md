# Contributing to Freehold

Thank you for your interest in contributing to Freehold! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.75+ (stable)
- For eBPF development: Linux with kernel 5.15+, clang, llvm
- For platform builds:
  - macOS: Xcode 15+
  - Windows: Visual Studio 2022 with C++ workload
  - Linux: GTK4, libadwaita development packages
  - Android: Android Studio, NDK r26+
  - iOS: Xcode 15+, CocoaPods

### Development Setup

```bash
# Clone the repository
git clone https://github.com/maceip/freehold
cd freehold

# Build all crates (excluding platform-specific ones)
cargo build --workspace \
  --exclude freehold-platform-windows \
  --exclude freehold-android-bridge \
  --exclude freehold-ebpf

# Run tests
cargo test --workspace \
  --exclude freehold-platform-windows \
  --exclude freehold-android-bridge \
  --exclude freehold-ebpf

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings
```

### Building eBPF (Linux only)

```bash
# Install dependencies
sudo apt-get install clang llvm libelf-dev

# Build the XDP program
cargo xtask build-ebpf --release
```

## Making Changes

### Code Style

- Run `cargo fmt` before committing
- Ensure `cargo clippy -- -D warnings` passes
- Write tests for new functionality
- Keep commits focused and atomic

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`

Examples:
- `feat(client): add automatic reconnection`
- `fix(server): handle malformed packets gracefully`
- `docs: update installation instructions`

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Ensure CI passes locally:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test --workspace
   ```
5. Push and open a PR against `main`
6. Respond to review feedback

### What We're Looking For

- Bug fixes with regression tests
- Performance improvements with benchmarks
- Documentation improvements
- Platform support enhancements
- Security hardening

## Project Structure

```
freehold-network/
├── crates/
│   ├── freehold-api/          # Wire protocol (publish to crates.io)
│   ├── freehold-common/       # Shared eBPF/userspace types
│   ├── freehold-ebpf/         # XDP kernel program
│   ├── freehold-server/       # Relay daemon
│   ├── freehold-client-core/  # Headless client engine
│   ├── freehold-client/       # Desktop CLI + tray
│   ├── freehold-h3-proxy/     # HTTP/3 reverse proxy
│   ├── freehold-android-bridge/ # Android FFI bindings
│   └── freehold-e2e-tests/    # Integration tests
├── platforms/
│   ├── macos/                 # Swift menu bar app
│   ├── windows/               # C# system tray
│   ├── linux/                 # GTK4 indicator
│   ├── android/               # Kotlin VPN service
│   ├── ios/                   # Swift VPN app
│   └── web/                   # Isolated Web App
└── tests/
    └── e2e/                   # Network namespace tests
```

## Testing

### Unit Tests

```bash
cargo test --workspace
```

### Integration Tests

```bash
cargo test --package freehold-server --test integration
cargo test --package freehold-e2e-tests
```

### E2E Tests with eBPF (requires root)

```bash
sudo ./tests/e2e/run_e2e.sh
```

## Questions?

- Open an issue for bugs or feature requests
- See [SECURITY.md](SECURITY.md) for security vulnerabilities

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.
