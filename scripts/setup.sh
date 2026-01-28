#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$SCRIPT_DIR/../.env" ]; then
    echo "ERROR: .env file not found"
    echo "Please create .env file from .env.example:"
    echo "  cp .env.example .env"
    echo "  # Then edit .env and add your GITHUB_TOKEN"
    exit 1
fi

source "$SCRIPT_DIR/../.env"

echo "=== Step 1: Setting up Kind cluster with ArgoCD ==="
"$SCRIPT_DIR/setup-kind-cluster-with-argoCD.sh"

echo ""
echo "=== Step 2: Setting up Blockchain and GitHub Runner ==="
"$SCRIPT_DIR/setup-blockchain-runner.sh"
