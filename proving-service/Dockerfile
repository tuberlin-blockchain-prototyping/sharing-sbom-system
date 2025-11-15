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

# Copy the entire proving-service directory
COPY proving-service ./proving-service

WORKDIR /app/proving-service

# Install Risc0 using official installer
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install rust && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm && \
    /root/.risc0/bin/rzup install cargo-risczero

# Set PATH to include Risc0 binaries
ENV PATH="/root/.risc0/bin:${PATH}"

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the proving service binary
COPY --from=builder /app/proving-service/target/release/proving-service /app/proving-service

# Copy Risc0 runtime binaries (needed for default_prover)
COPY --from=builder /root/.risc0 /root/.risc0

EXPOSE 8080

ENV PORT=8080
ENV RUST_LOG=info
ENV PATH="/root/.risc0/bin:${PATH}"

CMD ["./proving-service"]

