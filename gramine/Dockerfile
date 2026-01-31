# Reproducible build environment for Freehold SGX enclave
#
# This Dockerfile creates a deterministic build environment to produce
# the same MRENCLAVE hash that the CI produces.
#
# Usage:
#   docker build -t freehold-enclave-build -f gramine/Dockerfile .
#   docker run --rm -v $(pwd)/output:/output freehold-enclave-build
#
# The MRENCLAVE will be printed and artifacts copied to ./output/

FROM gramineproject/gramine:v1.8

# Pin Rust version for reproducibility
ENV RUST_VERSION=1.75.0
ENV CARGO_HOME=/root/.cargo
ENV PATH="${CARGO_HOME}/bin:${PATH}"

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} && \
    rustup component add rustfmt clippy

WORKDIR /build

# Copy dependency files first (for layer caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/freehold-common/Cargo.toml ./crates/freehold-common/
COPY crates/freehold-api/Cargo.toml ./crates/freehold-api/
COPY crates/freehold-enclave/Cargo.toml ./crates/freehold-enclave/

# Create dummy source files for dependency compilation
RUN mkdir -p crates/freehold-common/src && echo "pub fn dummy() {}" > crates/freehold-common/src/lib.rs && \
    mkdir -p crates/freehold-api/src && echo "pub fn dummy() {}" > crates/freehold-api/src/lib.rs && \
    mkdir -p crates/freehold-enclave/src && \
    echo "pub fn dummy() {}" > crates/freehold-enclave/src/lib.rs && \
    echo "fn main() {}" > crates/freehold-enclave/src/main.rs

# Build dependencies only
RUN cargo build --release --locked -p freehold-enclave 2>/dev/null || true

# Copy actual source code
COPY crates/freehold-common ./crates/freehold-common
COPY crates/freehold-api ./crates/freehold-api
COPY crates/freehold-enclave ./crates/freehold-enclave

# Build enclave binary
RUN cargo build --release --locked -p freehold-enclave

# Copy Gramine manifest
COPY gramine/freehold-enclave.manifest.template ./gramine/

# Generate SGX artifacts
RUN gramine-sgx-gen-private-key && \
    cd gramine && \
    gramine-manifest \
        -Dlog_level=error \
        -Darch_libdir=/lib/x86_64-linux-gnu \
        freehold-enclave.manifest.template \
        freehold-enclave.manifest && \
    gramine-sgx-sign \
        --manifest freehold-enclave.manifest \
        --output freehold-enclave.manifest.sgx

# Extract and display MRENCLAVE
RUN cd gramine && \
    gramine-sgx-sigstruct-view freehold-enclave.sig > sigstruct.txt && \
    echo "========================================" && \
    echo "MRENCLAVE:" && \
    grep mr_enclave sigstruct.txt && \
    echo "========================================"

# Default command: copy artifacts to /output and show MRENCLAVE
CMD cd gramine && \
    MRENCLAVE=$(grep mr_enclave sigstruct.txt | awk '{print $2}') && \
    echo "" && \
    echo "========================================" && \
    echo "Build complete!" && \
    echo "" && \
    echo "MRENCLAVE: $MRENCLAVE" && \
    echo "" && \
    echo "To verify a relay:" && \
    echo "  freehold-verify verify --relay <ADDR>:9999 --mrenclave $MRENCLAVE" && \
    echo "========================================" && \
    if [ -d /output ]; then \
        cp freehold-enclave.manifest.sgx freehold-enclave.sig sigstruct.txt /output/ && \
        echo "$MRENCLAVE" > /output/mrenclave.txt && \
        echo "Artifacts copied to /output/"; \
    fi
