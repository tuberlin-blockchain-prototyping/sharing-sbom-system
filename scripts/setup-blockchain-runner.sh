#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "kind is required" >&2; exit 1; }

if [ "$(kind get clusters 2>/dev/null | wc -l)" -eq 0 ]; then
    echo "No kind cluster found. Run setup-kind-cluster-with-argoCD.sh first"
    exit 1
fi

if ! kubectl cluster-info &>/dev/null; then
    echo "Cannot access cluster with kubectl"
    exit 1
fi

kubectl create namespace blockchain --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$PROJECT_ROOT/k8s/blockchain/configmap.yaml"
kubectl apply -f "$PROJECT_ROOT/k8s/blockchain/deployment.yaml"
kubectl apply -f "$PROJECT_ROOT/k8s/blockchain/service.yaml"

kubectl wait --for=condition=ready pod -l app=hardhat-node -n blockchain --timeout=120s

HARDHAT_POD=$(kubectl get pod -n blockchain -l app=hardhat-node -o jsonpath="{.items[0].metadata.name}")
sleep 5
kubectl exec -n blockchain "$HARDHAT_POD" -- wget -q -O- http://localhost:8545 || true

kubectl exec -n blockchain "$HARDHAT_POD" -- ls -la /workspace/contracts/ > /dev/null

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

kubectl create namespace github-runner --dry-run=client -o yaml | kubectl apply -f -
sleep 2

if ! kubectl get namespace github-runner &>/dev/null; then
    echo "Failed to create github-runner namespace"
    exit 1
fi

if ! kubectl get secret github-runner-secret -n github-runner &>/dev/null; then
    echo "GitHub runner secret not found"
    echo ""
    echo "Create secret:"
    echo "  kubectl create secret generic github-runner-secret \\"
    echo "    --from-literal=GITHUB_TOKEN='your-token' \\"
    echo "    -n github-runner"
    echo ""
    echo "Get token: https://github.com/settings/tokens/new"
    read -p "Press Enter after creating the secret..."
    
    if ! kubectl get secret github-runner-secret -n github-runner &>/dev/null; then
        echo "Secret not found. Deploy manually:"
        echo "  kubectl apply -f k8s/github-runner/configmap.yaml"
        echo "  kubectl apply -f k8s/github-runner/runner-rbac.yaml"
        echo "  kubectl apply -f k8s/github-runner/deployment.yaml"
        exit 0
    fi
fi

kubectl apply -f "$PROJECT_ROOT/k8s/github-runner/configmap.yaml"
kubectl apply -f "$PROJECT_ROOT/k8s/github-runner/runner-rbac.yaml"
kubectl apply -f "$PROJECT_ROOT/k8s/github-runner/deployment.yaml"

kubectl wait --for=condition=ready pod -l app=github-runner -n github-runner --timeout=180s

echo ""
echo "Contract address: $CONTRACT_ADDRESS"
echo "Hardhat node: http://hardhat-node.blockchain.svc.cluster.local:8545"
