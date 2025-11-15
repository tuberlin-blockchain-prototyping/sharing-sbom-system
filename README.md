# Sharing SBOM System

A GitOps-based SBOM (Software Bill of Materials) sharing system with Zero-Knowledge Proofs (ZKP), IPFS storage, and blockchain verification.

## Overview

This project demonstrates a complete CI/CD pipeline that:
1. Builds Docker images
2. Generates SBOMs (using Syft)
3. Fetches banned component lists from CVE databases
4. Generates ZKP proofs that verify SBOMs don't contain banned components (without revealing the full SBOM)
5. Stores proofs on IPFS
6. Records SBOM hashes on a Hardhat blockchain

## Architecture

### Components

- **proving-service**: Rust microservice that generates Risc0 ZKP proofs
- **verifier-service**: Rust microservice that verifies ZKP proofs
- **ipfs-service**: Python microservice for storing and retrieving proofs on IPFS
- **Hardhat Blockchain**: Local blockchain for storing SBOM hashes
- **GitHub Runner**: Self-hosted runner for CI/CD execution
- **ArgoCD**: GitOps tool for automated deployment

### Namespaces

- `blockchain`: Hardhat node deployment
- `github-runner`: Self-hosted GitHub Actions runner
- `sharing-sbom-system`: Microservices (proving, verifier, IPFS)

## Prerequisites

- Docker
- Kind (Kubernetes in Docker)
- kubectl
- Git

## Quick Start

### 1. Setup Kind Cluster with ArgoCD

```bash
./scripts/setup-kind-cluster-with-argoCD.sh
```

This will:
- Create a Kind cluster named `sharing-sbom-system`
- Install ArgoCD
- Deploy the ArgoCD application pointing to the `k8s/` folder


### 2. Configure GitHub Runner Name

Each person can customize their GitHub runner name. Edit `k8s/github-runner/configmap.yaml`:

```yaml
data:
  RUNNER_NAME: "your-unique-runner-name"  # Change this to your name
  RUNNER_LABELS: "self-hosted,kind-cluster,blockchain"  # Keep labels matching workflows
```

**Important**: The `RUNNER_LABELS` must match the `runs-on` labels in your GitHub Actions workflows (e.g., `runs-on: [self-hosted, kind-cluster, blockchain]`).

### 3. Setup Blockchain and GitHub Runner

```bash
./scripts/setup-blockchain-runner.sh
```

This will:
- Deploy Hardhat node to the `blockchain` namespace
- Auto-deploy SBOMRegistry contract (address: `0x5FbDB2315678afecb367f032d93F642f64180aa3`)
- Deploy GitHub Actions runner (will wait for secret if not present)

### 4. Create GitHub Runner Secret

After the namespace is created, create the GitHub Personal Access Token (PAT) secret:

```bash
kubectl create secret generic github-runner-secret \
  --from-literal=GITHUB_TOKEN='your-github-pat-token' \
  -n github-runner
```

Get a token from: https://github.com/settings/tokens/new (needs `repo` and `workflow` scopes)


## CI/CD Workflow

The GitHub Actions workflow (`.github/workflows/ci-cd.yaml`) performs:

1. **Build**: Builds Docker image and pushes to registry
2. **SBOM Generation**: Generates CycloneDX SBOM using Syft
3. **CVE Fetching**: Fetches banned component list from CVE databases during CI/CD
4. **Proof Generation**: Calls proving-service to generate ZKP proof (sends SBOM and banned list)
5. **IPFS Storage**: Stores proof on IPFS via ipfs-service
6. **Blockchain Recording**: Writes SBOM hash to blockchain