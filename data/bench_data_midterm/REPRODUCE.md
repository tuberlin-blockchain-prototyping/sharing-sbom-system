# Running Proving Service Locally with Metal Acceleration

This guide explains how to set up and run the proving service locally with GPU acceleration (metal feature) on macOS, while keeping the proof orchestrator in the kind cluster configured to call the local service.

## Prerequisites

- macOS with Apple Silicon or Intel Mac with Metal support
- Xcode and Xcode Command Line Tools installed
- Rust toolchain
- kind cluster running with the sharing-sbom-system deployed
- Docker and kubectl configured

## Step 1: Install Xcode and Metal Support

1. **Install Xcode from the App Store** (required for Metal compiler)
   - Open App Store and search for "Xcode"
   - Install and launch Xcode at least once
   - Accept the license agreement

2. **Install Xcode Command Line Tools**:
   ```bash
   xcode-select --install
   ```

3. **Accept Xcode license**:
   ```bash
   sudo xcodebuild -license accept
   ```

4. **Verify Metal compiler is available**:
   ```bash
   xcrun -sdk macosx metal --version
   ```

## Step 2: Install Rust and RISC Zero Toolchain

Follow the installation instructions from the official documentation:

- **Rust**: https://www.rust-lang.org/tools/install
- **RISC Zero**: https://risczero.com/install

After installation, ensure the tools are available in your shell PATH by restarting your terminal or running:
```bash
source ~/.zshrc  # or source ~/.bashrc for Bash
```

## Step 3: Configure the Proving Service

1. **Navigate to the proving service directory**:
   ```bash
   cd proving-service
   ```

2. **Create proofs directory**:
   ```bash
   mkdir -p proofs
   ```

**Note:** The `Cargo.toml` is already configured with the metal feature enabled in the repository.

## Step 4: Build the Proving Service

Build the service in release mode with optimizations:

```bash
cargo build --release
```

This takes approximately 2-5 minutes and produces the binary at `target/release/proving-service`.

## Step 5: Run the Proving Service Locally

Start the service with the following environment variables:

```bash
PORT=8081 \
PROOFS_DIR=./proofs \
RUST_LOG=info \
./target/release/proving-service
```

### Parameters Explained:

- **PORT=8081**: The port the service will listen on (8081 avoids conflicts with other services)
- **PROOFS_DIR=./proofs**: Directory where generated proofs will be stored
- **RUST_LOG=info**: Logging level (can be `debug` for more verbose output)

The service will start and display:
```
INFO proving_service: Starting proving-service on port 8081
INFO proving_service: Proofs directory: ./proofs
INFO actix_server::server: starting service: "actix-web-service-0.0.0.0:8081", workers: 16, listening on: 0.0.0.0:8081
```

## Step 6: Configure Proof Orchestrator in Kind Cluster

1. **Update the proof orchestrator deployment** to point to the local service:

   Edit `k8s/sharing-sbom-system/proof-orchestrator-service-deployment.yaml`:
   ```yaml
   - name: PROVING_SERVICE_URL
     value: "http://host.docker.internal:8081"
   ```

2. **Apply the configuration**:
   ```bash
   kubectl apply -f k8s/sharing-sbom-system/proof-orchestrator-service-deployment.yaml
   ```

3. **Wait for rollout to complete**:
   ```bash
   kubectl rollout status deployment/proof-orchestrator-service -n sharing-sbom-system
   ```
