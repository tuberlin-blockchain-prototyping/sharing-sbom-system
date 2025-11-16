# Single-stage build for AMD64
FROM rust:1.87-slim

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

# Copy the proving-service code
COPY proving-service ./proving-service

WORKDIR /app/proving-service

# Install RISC Zero toolchain
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install rust && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm && \
    /root/.risc0/bin/rzup install cargo-risczero

# Set PATH to include RISC Zero binaries
ENV PATH="/root/.risc0/bin:${PATH}"

# Build the application
RUN cargo build --release

EXPOSE 8080

ENV PORT=8080
ENV RUST_LOG=info

CMD ["target/release/proving-service"]
