#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_URL="${SERVICE_URL:-http://localhost:8090}"

echo "Testing service at $SERVICE_URL"

# health check
curl -s "$SERVICE_URL/health" | jq .

# build smt
echo "Building SMT..."
BUILD_RESPONSE=$(curl -s -X POST "$SERVICE_URL/build" \
  -H "Content-Type: application/json" \
  -d @"$SCRIPT_DIR/sample-sbom.json")

ROOT=$(echo "$BUILD_RESPONSE" | jq -r '.root')
echo "Root: $ROOT"

# generate proofs
echo "Generating proofs..."
echo "$BUILD_RESPONSE" | jq '.smt' > /tmp/smt-state.json
PURLS=$(cat "$SCRIPT_DIR/banned-packages.txt" | jq -R . | jq -s .)

PROVE_REQUEST=$(jq -n \
  --argjson smt "$(cat /tmp/smt-state.json)" \
  --argjson purls "$PURLS" \
  '{smt: $smt, purls: $purls, compress: true}')

PROVE_RESPONSE=$(curl -s -X POST "$SERVICE_URL/prove-batch" \
  -H "Content-Type: application/json" \
  -d "$PROVE_REQUEST")

echo "$PROVE_RESPONSE" | jq -r '.merkle_proofs[] | "\(.purl): \(if .value == "0" then "not found" else "found" end)"'

rm /tmp/smt-state.json
echo "Done"

