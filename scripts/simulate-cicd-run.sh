#!/usr/bin/env bash
# Simulates a CI/CD pipeline run:
# 1. Calculates SBOM hash
# 2. Builds SMT from SBOM via merkle-proof-service
# 3. Stores SMT root hash on blockchain
# Usage: ./simulate-cicd-run.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SBOM_FILE="${PROJECT_ROOT}/merkle-proof-service/examples/sbom.json"
CONTRACT_ADDR="0x5FbDB2315678afecb367f032d93F642f64180aa3"

[ ! -f "$SBOM_FILE" ] && { echo "ERROR: SBOM file not found: $SBOM_FILE"; exit 1; }

echo "=== Simulating CI/CD Run ==="
echo "SBOM: $SBOM_FILE"
echo ""

echo "Step 1: Calculate SBOM hash..."
SBOM_HASH=$(sha256sum "$SBOM_FILE" | awk '{print $1}')
echo "SBOM Hash: $SBOM_HASH"
echo ""

echo "Step 2: Build SMT from SBOM..."
kubectl wait --for=condition=available --timeout=300s deployment/merkle-proof-service -n sharing-sbom-system || true

MERKLE_URL="http://merkle-proof-service.sharing-sbom-system.svc.cluster.local:8090"
POD_NAME="curl-temp-$(date +%s)"

kubectl run "$POD_NAME" -n sharing-sbom-system --image=curlimages/curl:latest --restart=Never --command -- sleep 3600 > /dev/null 2>&1
kubectl wait --for=condition=ready pod/$POD_NAME -n sharing-sbom-system --timeout=60s || { kubectl delete pod $POD_NAME -n sharing-sbom-system --ignore-not-found=true; exit 1; }
kubectl cp "$SBOM_FILE" "sharing-sbom-system/$POD_NAME:/tmp/sbom.json" || { kubectl delete pod $POD_NAME -n sharing-sbom-system --ignore-not-found=true; exit 1; }

sleep 5
RESPONSE=$(kubectl exec -n sharing-sbom-system $POD_NAME -- curl -X POST "$MERKLE_URL/build" \
    -H "Content-Type: application/json" \
    -H "Expect:" \
    --data-binary @/tmp/sbom.json \
    --max-time 1800 \
    --silent \
    --write-out "\nHTTP_CODE:%{http_code}")

kubectl delete pod $POD_NAME -n sharing-sbom-system --ignore-not-found=true > /dev/null 2>&1

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2 | tr -d '\r\n ')
RESPONSE_BODY=$(echo "$RESPONSE" | grep -oE '\{"root":"[^"]+","depth":[0-9]+\}' | head -1)

[ "$HTTP_CODE" != "201" ] && { echo "ERROR: SMT build failed (HTTP $HTTP_CODE)"; echo "$RESPONSE"; exit 1; }
[ -z "$RESPONSE_BODY" ] && { echo "ERROR: Empty response"; exit 1; }

ROOT_HASH=$(echo "$RESPONSE_BODY" | jq -r '.root')
[ -z "$ROOT_HASH" ] && { echo "ERROR: Root hash not found"; exit 1; }

echo "SMT Root Hash: $ROOT_HASH"
echo ""

echo "Step 3: Store SMT root on blockchain..."
SOFTWARE_DIGEST=$(echo -n "$SBOM_HASH" | sha256sum | awk '{print $1}')
IDENT="local-test-$(date +%s)"

HARDHAT_POD=$(kubectl get pods -n blockchain -l app=hardhat-node -o jsonpath='{.items[0].metadata.name}')
[ -z "$HARDHAT_POD" ] && { echo "ERROR: Hardhat pod not found"; exit 1; }

TX_OUTPUT=$(kubectl exec -n blockchain "$HARDHAT_POD" -- sh -c "
    cd /workspace && \
    ADDR='$CONTRACT_ADDR' \
    ROOT_HASH='$ROOT_HASH' \
    SOFTWARE_DIGEST='$SOFTWARE_DIGEST' \
    SBOM_HASH='$SBOM_HASH' \
    IDENT='$IDENT' \
    npx hardhat run store_smt_root.js --network localhost 2>&1
")

TX_HASH=$(echo "$TX_OUTPUT" | tail -n1)
[[ ! "$TX_HASH" =~ ^0x[0-9a-fA-F]{64}$ ]] && { echo "ERROR: Invalid transaction hash"; echo "$TX_OUTPUT"; exit 1; }

echo "Transaction Hash: $TX_HASH"
echo ""
echo "=== Complete ==="
echo "Root Hash: $ROOT_HASH"
echo "TX Hash: $TX_HASH"
echo ""
echo "export ROOT_HASH=$ROOT_HASH"
