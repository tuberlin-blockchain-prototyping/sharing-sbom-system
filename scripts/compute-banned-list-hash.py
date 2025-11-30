#!/usr/bin/env python3
"""
Compute the hash of a banned packages list file.
This matches the hash computation done in the Rust proving service.

The Rust service:
1. Converts the banned list (Vec<String>) to JSON using serde_json::to_string
2. Hashes the JSON bytes with SHA256

Usage:
    python3 compute-banned-list-hash.py [banned-list-file]

If no file is provided, defaults to merkle-proof-service/examples/banned-packages.txt
"""

import json
import hashlib
import sys
from pathlib import Path


def compute_banned_list_hash(banned_list_file: Path) -> str:
    """
    Compute the hash of a banned list file.

    This matches the Rust implementation in proving-service/methods/guest/src/main.rs:
    - Filters out comments (lines starting with #) and empty lines
    - Converts to JSON array format
    - Hashes the JSON string bytes with SHA256

    Args:
        banned_list_file: Path to the banned packages text file

    Returns:
        Hex-encoded SHA256 hash of the JSON array representation
    """
    if not banned_list_file.exists():
        raise FileNotFoundError(f"Banned list file not found: {banned_list_file}")

    banned_list = []
    with open(banned_list_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                banned_list.append(line)

    json_str = json.dumps(banned_list, separators=(",", ":"))
    json_bytes = json_str.encode("utf-8")

    hasher = hashlib.sha256()
    hasher.update(json_bytes)
    return hasher.hexdigest()


def main():
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    if len(sys.argv) > 1:
        banned_list_file = Path(sys.argv[1])
    else:
        banned_list_file = (
            project_root / "merkle-proof-service" / "examples" / "banned-packages.txt"
        )

    try:
        hash_value = compute_banned_list_hash(banned_list_file)
        print(hash_value)
        return 0
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
