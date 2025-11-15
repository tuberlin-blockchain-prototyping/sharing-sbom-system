# Build stage
FROM rust:1.87-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    curl \
    git \
    bash \
    ca-certificates \
    cmake \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the entire verifier-service directory
COPY verifier-service ./verifier-service

WORKDIR /app/verifier-service

# Install Risc0 using official installer
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install rust && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm && \
    /root/.risc0/bin/rzup install cargo-risczero

# Set PATH to include Risc0 binaries
ENV PATH="/root/.risc0/bin:${PATH}"

# Install Rust 1.88.0 (required by dependencies)
RUN rustup toolchain install 1.88.0 && \
    rustup default 1.88.0

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/verifier-service/target/release/verifier-service /app/verifier-service

EXPOSE 8080

ENV PORT=8080
ENV RUST_LOG=info

CMD ["./verifier-service"]

