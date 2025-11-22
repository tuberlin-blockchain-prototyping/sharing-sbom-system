#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
SERVICE_URL="${SERVICE_URL:-http://localhost:8090}"

mkdir -p "$OUTPUT_DIR"

echo "Testing service at $SERVICE_URL"
echo "Output will be saved to $OUTPUT_DIR"

# health check
curl -s "$SERVICE_URL/health" | jq .

# build smt
echo "Building SMT..."
BUILD_RESPONSE=$(curl -s -X POST "$SERVICE_URL/build" \
  -H "Content-Type: application/json" \
  -d @"$SCRIPT_DIR/sample-sbom.json")

echo "$BUILD_RESPONSE" | jq . > "$OUTPUT_DIR/build-response.json"

ROOT=$(echo "$BUILD_RESPONSE" | jq -r '.root')
echo "Root: $ROOT"

# generate proofs
echo "Generating proofs..."
echo "$BUILD_RESPONSE" | jq '.smt' > "$OUTPUT_DIR/smt-state.json"
PURLS=$(cat "$SCRIPT_DIR/banned-packages.txt" | jq -R . | jq -s .)

PROVE_REQUEST=$(jq -n \
  --argjson smt "$(cat $OUTPUT_DIR/smt-state.json)" \
  --argjson purls "$PURLS" \
  '{smt: $smt, purls: $purls, compress: true}')

echo "$PROVE_REQUEST" | jq . > "$OUTPUT_DIR/prove-request.json"

PROVE_RESPONSE=$(curl -s -X POST "$SERVICE_URL/prove-batch" \
  -H "Content-Type: application/json" \
  -d "$PROVE_REQUEST")

echo "$PROVE_RESPONSE" | jq . > "$OUTPUT_DIR/prove-response.json"

echo "$PROVE_RESPONSE" | jq -r '.merkle_proofs[] | "\(.purl): \(if .value == "0" then "not found" else "found" end)"'

echo "Done - Results saved in $OUTPUT_DIR/"

