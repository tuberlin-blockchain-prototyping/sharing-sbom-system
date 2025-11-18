#!/usr/bin/env bash
set -euo pipefail

# Run the proving-service in a single Docker container locally (outside Kubernetes)
# Forces linux/amd64 to match RISC Zero requirements on Apple Silicon
# Automatically removes any previously running proving-service container.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="proving-service"
TIMESTAMP_TAG="local-$(date +%Y%m%d-%H%M%S)"
IMAGE_TAG="${TIMESTAMP_TAG}"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

# Stop old running container (if any)
OLD_CID=$(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' | grep "${IMAGE_NAME}:local" | awk '{print $1}' || true)
if [[ -n "${OLD_CID}" ]]; then
  echo "Stopping previously running proving-service container: ${OLD_CID}";
  docker stop "${OLD_CID}" >/dev/null || true;
fi

echo "Building local image (linux/amd64) ${FULL_IMAGE_NAME} ..."
cd "$PROJECT_ROOT"

docker build --platform linux/amd64 -f proving-service/Dockerfile -t "$FULL_IMAGE_NAME" .

echo "Running container on port 8080 ..."
docker run --rm -d \
  --name proving-service-local \
  --platform linux/amd64 \
  -e PORT=8080 \
  -e RUST_LOG=info \
  -p 8080:8080 \
  "$FULL_IMAGE_NAME"

echo "Container started: proving-service-local"

echo "Waiting for health endpoint..."
for i in {1..30}; do
  if curl -s http://localhost:8080/health | grep -q '"healthy"'; then
    echo "Service is healthy."; break; fi; sleep 1; done

echo "You can now test endpoints:";
echo "  curl http://localhost:8080/health";
echo "  curl -X POST http://localhost:8080/prove-merkle -H 'Content-Type: application/json' -d '{\"root\":\"<hex>\",\"merkle_proofs\":[{\"purl\":\"pkg:cargo/example@1.0.0\",\"value\":\"0\",\"siblings\":[\"<256 hex hashes>\"]}]}'";
echo "Or run the helper script: ./proving-service/test-merkle-endpoint.sh";
