import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import requests

PROVING_SERVICE_URL = os.getenv(
    "PROVING_SERVICE_URL", "http://proving-service:8080")
MERKLEPROOFS_DIR = Path("/benchmark/data/merkleproofs")
OUTPUT_BASE_DIR = Path("/benchmark/data")


def send_proof_request(merkle_proof_data: Dict[str, Any], proof_count: int) -> Dict[str, Any]:
    url = f"{PROVING_SERVICE_URL}/prove-merkle-compact"

    print(f"[{datetime.now().isoformat()}] Sending proof request with {proof_count} merkle proofs...")
    start_time = time.time()

    try:
        # Send request without timeout as requested
        response = requests.post(
            url,
            json=merkle_proof_data,
            headers={"Content-Type": "application/json"},
            timeout=None  # No timeout
        )

        elapsed_time = time.time() - start_time

        if response.status_code == 200:
            result = response.json()
            print(
                f"[{datetime.now().isoformat()}] Proof generated successfully in {elapsed_time:.2f}s")
            print(
                f"  - Generation duration: {result.get('generation_duration_ms', 0)/1000:.2f}s")
            print(
                f"  - Verification duration: {result.get('verification_duration_ms', 0)/1000:.2f}s")
            print(f"  - Proof size: {result.get('proof_size_bytes', 0)} bytes")
            return result
        else:
            print(
                f"[{datetime.now().isoformat()}] Request failed with status {response.status_code}")
            print(f"  Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        elapsed_time = time.time() - start_time
        print(
            f"[{datetime.now().isoformat()}] Request failed after {elapsed_time:.2f}s: {e}")
        return None


def save_proof(proof_data: Dict[str, Any], proof_count: int, output_dir: Path):
    timestamp = int(time.time())
    filename = f"proof_{proof_count}_{timestamp}.json"
    filepath = output_dir / filename

    with open(filepath, 'w') as f:
        json.dump(proof_data, f, indent=2)

    print(f"[{datetime.now().isoformat()}] Saved proof to: {filepath}")


def process_merkle_proof_file(filepath: Path, output_dir: Path) -> bool:
    # Extract proof count from filename (e.g., batch_proof_2.json -> 2)
    filename = filepath.stem
    proof_count = int(filename.split('_')[-1])

    print(f"Processing: {filepath.name} (proof count: {proof_count})")

    try:
        # Read the merkle proof file
        with open(filepath, 'r') as f:
            merkle_proof_data = json.load(f)

        # Send to proving service
        proof_data = send_proof_request(merkle_proof_data, proof_count)

        if proof_data:
            # Save the proof
            save_proof(proof_data, proof_count, output_dir)
            return True
        else:
            print(
                f"[{datetime.now().isoformat()}] Failed to generate proof for {filepath.name}")
            return False

    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Error processing {filepath.name}: {e}")
        import traceback
        traceback.print_exc()
        return False


def wait_for_service(max_attempts=30, delay=2):
    print(f"Waiting for proving service at {PROVING_SERVICE_URL}...")
    health_url = f"{PROVING_SERVICE_URL}/health"

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(health_url, timeout=5)
            if response.status_code == 200:
                print(f"Proving service is healthy")
                return True
        except Exception as e:
            if attempt < max_attempts:
                print(
                    f"Attempt {attempt}/{max_attempts}: Service not ready yet, retrying in {delay}s...")
                time.sleep(delay)
            else:
                print(
                    f"Failed to connect to proving service after {max_attempts} attempts: {e}")
                return False

    return False


def main():
    # Parse command line arguments
    if len(sys.argv) > 1:
        # Specific proof counts provided
        proof_counts = [int(x) for x in sys.argv[1:]]
    else:
        # Default: process 2, 5, 10, 20, 50, 100, 200
        proof_counts = [2, 5, 10, 20, 50, 100, 200]

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = OUTPUT_BASE_DIR / f"proofs_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Benchmark started at {datetime.now().isoformat()}")
    print(f"Proving service URL: {PROVING_SERVICE_URL}")
    print(f"Merkle proofs directory: {MERKLEPROOFS_DIR}")
    print(f"Output directory: {output_dir}")
    print("")

    # Wait for proving service to be ready
    if not wait_for_service():
        print("Exiting due to service unavailability")
        sys.exit(1)

    print("")

    # Process each proof count
    results = []
    successful = 0
    failed = 0

    overall_start = time.time()

    for count in proof_counts:
        proof_file = MERKLEPROOFS_DIR / f"batch_proof_{count}.json"

        if not proof_file.exists():
            print(f"Warning: File not found: {proof_file}")
            print("")
            failed += 1
            results.append({
                "file": proof_file.name,
                "success": False,
                "error": "File not found"
            })
            continue

        success = process_merkle_proof_file(proof_file, output_dir)
        results.append({
            "file": proof_file.name,
            "success": success
        })

        if success:
            successful += 1
        else:
            failed += 1

    overall_elapsed = time.time() - overall_start

    # Print summary
    print(f"Total files processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total time: {overall_elapsed:.2f}s")
    print(f"Output directory: {output_dir}")

    # Save summary
    summary_file = output_dir / "benchmark_summary.json"
    with open(summary_file, 'w') as f:
        json.dump({
            "timestamp": timestamp,
            "total_files": len(results),
            "successful": successful,
            "failed": failed,
            "total_time_seconds": overall_elapsed,
            "results": results
        }, f, indent=2)

    print(f"\nSummary saved to: {summary_file}")

    # Exit with error code if any failed
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
