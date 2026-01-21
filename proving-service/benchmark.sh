#!/bin/bash
# Usage: ./benchmark.sh [proof_counts...]
# Example: ./benchmark.sh 2 5 10

set -e

cd "$(dirname "$0")"

if [ $# -eq 0 ]; then
    echo "Running benchmark for all proof counts (2 to 200)..."
    docker compose run --rm benchmark uv run benchmark.py 2 5 10 20 50 100 200
else
    echo "Running benchmark for proof counts: $*"
    docker compose run --rm benchmark uv run benchmark.py "$@"
fi
