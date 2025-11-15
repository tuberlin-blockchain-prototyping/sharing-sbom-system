# Build stage
FROM rust:latest as builder

# Install Risc0 toolchain installer
RUN cargo install --locked rzup

# Install Risc0 Rust toolchain
RUN rzup install rust

WORKDIR /app

# Copy methods first (needed for build)
COPY verifier-service/methods ./verifier-service/methods
COPY verifier-service/Cargo.toml ./verifier-service/
COPY verifier-service/src ./verifier-service/src

WORKDIR /app/verifier-service

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

