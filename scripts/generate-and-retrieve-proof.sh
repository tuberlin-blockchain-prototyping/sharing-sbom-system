#!/usr/bin/env bash
# Generates a ZK proof for a given root hash and banned list:
# 1. Calls proof-orchestrator-service to generate proof
# 2. Retrieves proof from IPFS
# 3. Saves proof to data/proof_examples/
# Usage: ROOT_HASH=<hash> ./generate-and-retrieve-proof.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BANNED_LIST="${PROJECT_ROOT}/merkle-proof-service/examples/banned-packages.txt"
OUTPUT_DIR="${PROJECT_ROOT}/data/proof_examples"

[ -z "${ROOT_HASH:-}" ] && { echo "ERROR: ROOT_HASH not set"; echo "Usage: ROOT_HASH=<hash> $0"; exit 1; }
[ ! -f "$BANNED_LIST" ] && { echo "ERROR: Banned list not found: $BANNED_LIST"; exit 1; }

echo "=== Generate and Retrieve Proof ==="
echo "Root Hash: $ROOT_HASH"
echo ""

echo "Step 1: Prepare banned list..."
BANNED_ARRAY=$(grep -v '^#' "$BANNED_LIST" | grep -v '^$' | jq -R . | jq -s .)
echo "Found $(echo "$BANNED_ARRAY" | jq 'length') packages"
echo ""

echo "Step 2: Generate proof..."
kubectl wait --for=condition=available --timeout=300s deployment/proof-orchestrator-service -n sharing-sbom-system || true

kubectl port-forward -n sharing-sbom-system svc/proof-orchestrator-service 8080:8080 > /dev/null 2>&1 &
ORCH_PID=$!
trap "kill $ORCH_PID 2>/dev/null" EXIT

sleep 3
for i in {1..30}; do
    curl -s --max-time 5 "http://localhost:8080/health" > /dev/null 2>&1 && break
    [ $i -eq 30 ] && { echo "ERROR: Orchestrator not available"; kill $ORCH_PID 2>/dev/null; exit 1; }
    sleep 2
done

RESPONSE=$(curl -X POST "http://localhost:8080/generate-proof" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg h "$ROOT_HASH" --argjson l "$BANNED_ARRAY" '{root_hash: $h, banned_list: $l}')" \
    --max-time 1800 \
    --silent)

IPFS_CID=$(echo "$RESPONSE" | jq -r '.ipfs_cid // empty')
TX_HASH=$(echo "$RESPONSE" | jq -r '.tx_hash // empty')
COMPLIANT=$(echo "$RESPONSE" | jq -r '.compliance_status // false')
COMPOSITE_HASH=$(echo "$RESPONSE" | jq -r '.composite_hash // empty')

[ -z "$IPFS_CID" ] && { echo "ERROR: IPFS CID not found"; echo "$RESPONSE"; kill $ORCH_PID 2>/dev/null; exit 1; }
[ -z "$COMPOSITE_HASH" ] && { echo "ERROR: Composite hash not found"; echo "$RESPONSE"; kill $ORCH_PID 2>/dev/null; exit 1; }

echo "Proof generated!"
echo "IPFS CID: $IPFS_CID"
echo "TX Hash: $TX_HASH"
echo "Compliant: $COMPLIANT"
echo "Composite Hash: $COMPOSITE_HASH"
echo ""

echo "Step 3: Retrieve from IPFS..."
kubectl port-forward -n sharing-sbom-system svc/ipfs-service 8081:80 > /dev/null 2>&1 &
IPFS_PID=$!
trap "kill $IPFS_PID $ORCH_PID 2>/dev/null" EXIT

sleep 2
PROOF_RESPONSE=$(curl -s --max-time 300 "http://localhost:8081/retrieve/$COMPOSITE_HASH")
PROOF_BASE64=$(echo "$PROOF_RESPONSE" | jq -r '.proof // empty')

[ -z "$PROOF_BASE64" ] && { echo "ERROR: Failed to retrieve proof"; echo "$PROOF_RESPONSE"; kill $IPFS_PID $ORCH_PID 2>/dev/null; exit 1; }

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/proof_${COMPOSITE_HASH}.json"
echo "$PROOF_BASE64" | base64 -d | jq . > "$OUTPUT_FILE"

echo "Proof saved: $OUTPUT_FILE"
echo ""
echo "=== Complete ==="
echo "Root Hash: $ROOT_HASH"
echo "Composite Hash: $COMPOSITE_HASH"
echo "IPFS CID: $IPFS_CID"
echo "Compliant: $COMPLIANT"
echo "Proof: $OUTPUT_FILE"

kill $IPFS_PID $ORCH_PID 2>/dev/null || true
trap - EXIT
