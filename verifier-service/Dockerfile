# Multi-platform: AMD64 uses rzup, ARM64 builds from source

FROM rust:1.87-slim AS build-amd64

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
COPY verifier-service ./verifier-service
WORKDIR /app/verifier-service

RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install rust && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm && \
    /root/.risc0/bin/rzup install cargo-risczero

ENV PATH="/root/.risc0/bin:${PATH}"
RUN cargo build --release

# ARM64: Build RISC Zero toolchain from source
FROM --platform=linux/arm64 arm64v8/ubuntu:22.04 AS arm64-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git \
    clang \
    cmake \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

ENV PATH="/root/.cargo/bin:$PATH"

ARG RISC0_VERSION=release-3.0

RUN git clone --branch ${RISC0_VERSION} --single-branch https://github.com/risc0/risc0.git /opt/risc0

WORKDIR /opt/risc0

RUN cargo install --path rzup

RUN rzup build --path . rust

RUN rzup build --path . cpp

RUN cargo install --path cargo-risczero

# ARM64: Build application with RISC Zero toolchain
FROM --platform=linux/arm64 arm64v8/ubuntu:22.04 AS build-arm64

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=arm64-builder /root/.cargo/bin/ /root/.cargo/bin/
COPY --from=arm64-builder /root/.rustup/ /root/.rustup/
COPY --from=arm64-builder /root/.risc0/ /root/.risc0/

ENV RUSTUP_HOME="/root/.rustup"
ENV CARGO_HOME="/root/.cargo"
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"

WORKDIR /app
COPY verifier-service ./verifier-service
WORKDIR /app/verifier-service

RUN cargo build --release

ARG TARGETARCH
FROM build-${TARGETARCH} AS final

EXPOSE 8080
ENV PORT=8080
ENV RUST_LOG=info

CMD ["/app/verifier-service/target/release/verifier-service"]
