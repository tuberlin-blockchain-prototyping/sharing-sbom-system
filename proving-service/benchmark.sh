#!/bin/bash

set -e

cd "$(dirname "$0")"

TIMES=${1:-1}

if [ "$TIMES" -gt 1 ]; then
    echo "Number of runs: $TIMES"
fi

docker compose run --rm benchmark uv run benchmark.py --times "$TIMES" 2 5 10 20 50 100 200
