#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"


command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "kind is required" >&2; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "helm is required" >&2; exit 1; }

if [ "$(kind get clusters 2>/dev/null | wc -l)" -eq 0 ]; then
    echo "No kind cluster found. Run setup-kind-cluster-with-argoCD.sh first"
    exit 1
fi

if ! kubectl cluster-info &>/dev/null; then
    echo "Cannot access cluster with kubectl"
    exit 1
fi

kubectl create namespace blockchain --dry-run=client -o yaml | kubectl apply -f -

GITOPS_REPO="${GITOPS_REPO:-tuberlin-blockchain-prototyping/sharing-sbom-system-gitops}"
GITOPS_BRANCH="${GITOPS_BRANCH:-main}"
GITOPS_REPO_URL="https://github.com/${GITOPS_REPO}.git"
TEMP_GITOPS_DIR=$(mktemp -d)

echo "Fetching blockchain manifests from GitOps repo..."
if command -v git >/dev/null 2>&1 && git clone --depth 1 --branch "${GITOPS_BRANCH}" "${GITOPS_REPO_URL}" "${TEMP_GITOPS_DIR}" 2>/dev/null; then
    BLOCKCHAIN_DIR="${TEMP_GITOPS_DIR}/k8s/blockchain"
    if [ -d "${BLOCKCHAIN_DIR}" ]; then
        echo "Applying blockchain manifests from GitOps repo..."
        kubectl apply -f "${BLOCKCHAIN_DIR}/configmap.yaml"
        kubectl apply -f "${BLOCKCHAIN_DIR}/deployment.yaml"
        kubectl apply -f "${BLOCKCHAIN_DIR}/service.yaml"
    else
        echo "ERROR: blockchain directory not found in GitOps repo"
        echo "Expected path: ${BLOCKCHAIN_DIR}"
        exit 1
    fi
    rm -rf "${TEMP_GITOPS_DIR}"
else
    echo "ERROR: Failed to fetch blockchain manifests from GitOps repo."
    exit 1
fi

# Restart deployment to pick up ConfigMap changes if pod already exists
kubectl rollout restart deployment/hardhat-node -n blockchain || true

kubectl wait --for=condition=ready pod -l app=hardhat-node -n blockchain --timeout=120s

HARDHAT_POD=$(kubectl get pod -n blockchain -l app=hardhat-node -o jsonpath="{.items[0].metadata.name}")
sleep 5
kubectl exec -n blockchain "$HARDHAT_POD" -- wget -q -O- http://localhost:8545 || true

kubectl exec -n blockchain "$HARDHAT_POD" -- ls -la /workspace/contracts/SBOMRegistryV2.sol > /dev/null
kubectl exec -n blockchain "$HARDHAT_POD" -- ls -la /workspace/store_smt_root.js > /dev/null
kubectl exec -n blockchain "$HARDHAT_POD" -- ls -la /workspace/store_merkle_proof.js > /dev/null

CONTRACT_ADDRESS="0x5FbDB2315678afecb367f032d93F642f64180aa3"
sleep 15

CONTRACT_CHECK=$(kubectl exec -n blockchain "$HARDHAT_POD" -- sh -c 'cat > /tmp/check.js << "EOFJS"
const { ethers } = require("hardhat");
async function main() {
  const code = await ethers.provider.getCode("0x5FbDB2315678afecb367f032d93F642f64180aa3");
  console.log(code.length > 2 ? "DEPLOYED" : "NOT_DEPLOYED");
}
main().catch(() => console.log("ERROR"));
EOFJS
cd /workspace && npx hardhat run /tmp/check.js --network localhost 2>&1 | tail -1')

kubectl create configmap sbom-contract-config \
  --from-literal=contract-address="$CONTRACT_ADDRESS" \
  -n blockchain \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "Contract address: $CONTRACT_ADDRESS"
echo "Hardhat node: http://hardhat-node.blockchain.svc.cluster.local:8545"

if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "ERROR: .env file not found"
    echo "Please create .env file from .env.example:"
    echo "  cp .env.example .env"
    echo "  # Then edit .env and add your GitHub App credentials"
    exit 1
fi

source "$PROJECT_ROOT/.env"

if [ -z "${ABP_ACTIONS_RUNNER_APP_ID:-}" ]; then
    echo "ERROR: ABP_ACTIONS_RUNNER_APP_ID not set in .env file"
    exit 1
fi

if [ -z "${ABP_ACTIONS_RUNNER_APP_INSTALLATION_ID:-}" ]; then
    echo "ERROR: ABP_ACTIONS_RUNNER_APP_INSTALLATION_ID not set in .env file"
    exit 1
fi

if [ -z "${PRIVATE_KEY_FILE:-}" ]; then
    echo "ERROR: PRIVATE_KEY_FILE not set in .env file"
    exit 1
fi

PRIVATE_KEY_PATH="$PROJECT_ROOT/$PRIVATE_KEY_FILE"
if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    if [ -f "$PRIVATE_KEY_FILE" ]; then
        PRIVATE_KEY_PATH="$PRIVATE_KEY_FILE"
    else
        echo "ERROR: Private key file not found: $PRIVATE_KEY_FILE"
        echo "Expected at: $PROJECT_ROOT/$PRIVATE_KEY_FILE or $PRIVATE_KEY_FILE"
        exit 1
    fi
fi

echo ""
echo "Setting up Actions Runner Controller..."

helm repo add actions-runner-controller https://actions-runner-controller.github.io/actions-runner-controller
helm repo update

kubectl create namespace arc-systems --dry-run=client -o yaml | kubectl apply -f -

if ! kubectl get secret controller-manager -n arc-systems &>/dev/null; then
    echo "Creating controller-manager secret..."
    kubectl create secret generic controller-manager \
      -n arc-systems \
      --from-literal=github_app_id="$ABP_ACTIONS_RUNNER_APP_ID" \
      --from-literal=github_app_installation_id="$ABP_ACTIONS_RUNNER_APP_INSTALLATION_ID" \
      --from-file=github_app_private_key="$PRIVATE_KEY_PATH"
else
    echo "controller-manager secret already exists, updating..."
    kubectl create secret generic controller-manager \
      -n arc-systems \
      --from-literal=github_app_id="$ABP_ACTIONS_RUNNER_APP_ID" \
      --from-literal=github_app_installation_id="$ABP_ACTIONS_RUNNER_APP_INSTALLATION_ID" \
      --from-file=github_app_private_key="$PRIVATE_KEY_PATH" \
      --dry-run=client -o yaml | kubectl apply -f -
fi

helm repo add jetstack https://charts.jetstack.io
helm repo update

if ! helm list -n cert-manager | grep -q cert-manager; then
    echo "Installing cert-manager..."
    helm install cert-manager jetstack/cert-manager \
      --namespace cert-manager \
      --create-namespace \
      --set crds.enabled=true \
      --wait --timeout=5m
else
    echo "cert-manager already installed"
fi

if ! helm list -n arc-systems | grep -q arc; then
    echo "Installing Actions Runner Controller..."
    helm install arc \
      actions-runner-controller/actions-runner-controller \
      --namespace arc-systems \
      --set authSecret.create=false \
      --set authSecret.name=controller-manager \
      --wait --timeout=5m
else
    echo "Actions Runner Controller already installed"
fi

kubectl create namespace arc-runners --dry-run=client -o yaml | kubectl apply -f -

GITOPS_REPO="${GITOPS_REPO:-tuberlin-blockchain-prototyping/sharing-sbom-system-gitops}"
GITOPS_BRANCH="${GITOPS_BRANCH:-main}"
GITOPS_REPO_URL="https://github.com/${GITOPS_REPO}.git"
TEMP_GITOPS_DIR=$(mktemp -d)

echo "Fetching runner manifests from GitOps repo..."
if command -v git >/dev/null 2>&1 && git clone --depth 1 --branch "${GITOPS_BRANCH}" "${GITOPS_REPO_URL}" "${TEMP_GITOPS_DIR}" 2>/dev/null; then
    GITHUB_RUNNER_DIR="${TEMP_GITOPS_DIR}/k8s/github-runner"
    if [ -d "${GITHUB_RUNNER_DIR}" ]; then
        echo "Applying runner deployment and RBAC..."
        kubectl apply -f "${GITHUB_RUNNER_DIR}/runner-deployment.yaml"
        kubectl apply -f "${GITHUB_RUNNER_DIR}/runner-rbac.yaml"
    else
        echo "ERROR: github-runner directory not found in GitOps repo"
        echo "Expected path: ${GITHUB_RUNNER_DIR}"
        exit 1
    fi
    rm -rf "${TEMP_GITOPS_DIR}"
else
    echo "ERROR: Failed to fetch runner manifests from GitOps repo."
    exit 1
fi

echo ""
echo "Setup complete!"
echo "Contract address: $CONTRACT_ADDRESS"
echo "Hardhat node: http://hardhat-node.blockchain.svc.cluster.local:8545"
