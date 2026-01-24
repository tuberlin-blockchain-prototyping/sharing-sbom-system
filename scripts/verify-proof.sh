#!/usr/bin/env bash
# Verifies a ZK proof using verifier-service:
# 1. Validates proof file structure
# 2. Sends proof to verifier-service
# 3. Displays verification results
# Usage: ./verify-proof.sh [proof-file.json] (defaults to latest proof)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROOFS_DIR="${PROJECT_ROOT}/data/proof_examples"

if [ -n "${1:-}" ]; then
    PROOF_FILE="$1"
else
    [ ! -d "$PROOFS_DIR" ] && { echo "ERROR: Proofs directory not found"; exit 1; }
    PROOF_FILE=$(ls -t "$PROOFS_DIR"/proof_*.json 2>/dev/null | head -1)
    [ -z "$PROOF_FILE" ] && { echo "ERROR: No proof files found"; exit 1; }
fi

[ ! -f "$PROOF_FILE" ] && { echo "ERROR: Proof file not found: $PROOF_FILE"; exit 1; }

echo "=== Verify Proof ==="
echo "Proof: $PROOF_FILE"
[ -z "${1:-}" ] && echo "Using latest proof"
echo ""

echo "Step 1: Validate proof structure..."
REQUIRED_FIELDS=("proof" "image_id" "root_hash" "banned_list_hash" "compliant")
for field in "${REQUIRED_FIELDS[@]}"; do
    jq -e "has(\"$field\")" "$PROOF_FILE" > /dev/null 2>&1 || { echo "ERROR: Missing field: $field"; exit 1; }
done
echo "Valid"
echo ""

echo "Step 2: Verify proof..."
kubectl wait --for=condition=available --timeout=300s deployment/verifier-service -n sharing-sbom-system || true

kubectl port-forward -n sharing-sbom-system svc/verifier-service 8082:80 > /dev/null 2>&1 &
VERIFIER_PID=$!
trap "kill $VERIFIER_PID 2>/dev/null" EXIT

sleep 2
for i in {1..30}; do
    curl -s --max-time 5 "http://localhost:8082/health" > /dev/null 2>&1 && break
    [ $i -eq 30 ] && { echo "ERROR: Verifier not available"; kill $VERIFIER_PID 2>/dev/null; exit 1; }
    sleep 2
done

RESPONSE=$(curl -X POST "http://localhost:8082/verify" \
    -H "Content-Type: application/json" \
    --data-binary @"$PROOF_FILE" \
    --max-time 300 \
    --silent)

VERIFIED=$(echo "$RESPONSE" | jq -r '.proof_verified // false')
[ "$VERIFIED" != "true" ] && { echo "ERROR: Verification failed"; echo "$RESPONSE" | jq .; kill $VERIFIER_PID 2>/dev/null; exit 1; }

echo "✓ Verified!"
echo ""
echo "$RESPONSE" | jq '{root_hash, banned_list_hash, compliant}'

kill $VERIFIER_PID 2>/dev/null || true
trap - EXIT
