# Build stage
FROM rust:latest as builder

# Install Risc0 toolchain installer
RUN cargo install --locked rzup

# Install Risc0 Rust toolchain
RUN rzup install rust

WORKDIR /app

# Copy methods first (needed for build)
COPY proving-service/methods ./proving-service/methods
COPY proving-service/Cargo.toml ./proving-service/
COPY proving-service/src ./proving-service/src

WORKDIR /app/proving-service

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/proving-service/target/release/proving-service /app/proving-service

EXPOSE 8080

ENV PORT=8080
ENV RUST_LOG=info

CMD ["./proving-service"]

