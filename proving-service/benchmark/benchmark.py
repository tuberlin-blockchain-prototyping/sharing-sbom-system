import json
import os
import sys
import time
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import requests

PROVING_SERVICE_URL = os.getenv(
    "PROVING_SERVICE_URL", "http://proving-service:8080")
MERKLEPROOFS_DIR = Path("/benchmark/data/merkleproofs")
OUTPUT_BASE_DIR = Path("/benchmark/data")


def send_proof_request(merkle_proof_data: Dict[str, Any], proof_count: int) -> Optional[Dict[str, Any]]:
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


def save_proof(proof_data: Dict[str, Any], proof_count: int, output_dir: Path, run_number: Optional[int] = None):
    timestamp = int(time.time())
    if run_number is not None:
        filename = f"proof_{proof_count}_run{run_number}_{timestamp}.json"
    else:
        filename = f"proof_{proof_count}_{timestamp}.json"
    filepath = output_dir / filename

    with open(filepath, 'w') as f:
        json.dump(proof_data, f, indent=2)

    print(f"[{datetime.now().isoformat()}] Saved proof to: {filepath}")


def process_merkle_proof_file(filepath: Path, output_dir: Path, run_number: Optional[int] = None) -> Optional[Dict[str, Any]]:
    # Extract proof count from filename (e.g., batch_proof_2.json -> 2)
    filename = filepath.stem
    proof_count = int(filename.split('_')[-1])

    run_prefix = f"[Run {run_number}] " if run_number is not None else ""
    print(f"{run_prefix}Processing: {filepath.name} (proof count: {proof_count})")

    try:
        # Read the merkle proof file
        with open(filepath, 'r') as f:
            merkle_proof_data = json.load(f)

        # Send to proving service
        proof_data = send_proof_request(merkle_proof_data, proof_count)

        if proof_data:
            # Save the proof
            save_proof(proof_data, proof_count, output_dir, run_number)
            return proof_data
        else:
            print(
                f"[{datetime.now().isoformat()}] Failed to generate proof for {filepath.name}")
            return None

    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Error processing {filepath.name}: {e}")
        import traceback
        traceback.print_exc()
        return None


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


def aggregate_results(all_runs: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Aggregate results across multiple runs, calculating stats for each proof count."""
    # Group results by file name
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    
    for run_results in all_runs:
        for result in run_results:
            file_name = result["file"]
            if file_name not in by_file:
                by_file[file_name] = []
            by_file[file_name].append(result)
    
    aggregated = []
    for file_name, runs in by_file.items():
        successful_runs = [r for r in runs if r.get("success", False)]
        
        if not successful_runs:
            # All runs failed
            aggregated.append({
                "file": file_name,
                "success": False,
                "runs": len(runs),
                "successful_runs": 0,
                "failed_runs": len(runs)
            })
            continue
        
        # Extract timing data
        gen_durations = [r["generation_duration_ms"] for r in successful_runs]
        verif_durations = [r["verification_duration_ms"] for r in successful_runs]
        proof_sizes = [r["proof_size_bytes"] for r in successful_runs]
        
        aggregated.append({
            "file": file_name,
            "success": True,
            "runs": len(runs),
            "successful_runs": len(successful_runs),
            "failed_runs": len(runs) - len(successful_runs),
            "generation_duration_ms": {
                "min": min(gen_durations),
                "max": max(gen_durations),
                "mean": sum(gen_durations) / len(gen_durations),
                "values": gen_durations
            },
            "verification_duration_ms": {
                "min": min(verif_durations),
                "max": max(verif_durations),
                "mean": sum(verif_durations) / len(verif_durations),
                "values": verif_durations
            },
            "proof_size_bytes": {
                "min": min(proof_sizes),
                "max": max(proof_sizes),
                "mean": sum(proof_sizes) / len(proof_sizes),
                "values": proof_sizes
            }
        })
    
    return aggregated


def main():
    parser = argparse.ArgumentParser(description="Benchmark proving service")
    parser.add_argument(
        "--times", "-t",
        type=int,
        default=1,
        help="Number of times to run the benchmark (default: 1)"
    )
    parser.add_argument(
        "proof_counts",
        nargs="*",
        type=int,
        help="Proof counts to benchmark (default: 2 5 10 20 50 100 200)"
    )
    
    args = parser.parse_args()
    
    # Determine proof counts
    if args.proof_counts:
        proof_counts = args.proof_counts
    else:
        proof_counts = [2, 5, 10, 20, 50, 100, 200]
    
    num_runs = args.times

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = OUTPUT_BASE_DIR / f"proofs_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Benchmark started at {datetime.now().isoformat()}")
    print(f"Proving service URL: {PROVING_SERVICE_URL}")
    print(f"Merkle proofs directory: {MERKLEPROOFS_DIR}")
    print(f"Output directory: {output_dir}")
    print(f"Number of runs: {num_runs}")
    print(f"Proof counts: {proof_counts}")
    print("")

    # Wait for proving service to be ready
    if not wait_for_service():
        print("Exiting due to service unavailability")
        sys.exit(1)

    print("")

    # Run benchmark multiple times
    all_runs_results: List[List[Dict[str, Any]]] = []
    overall_start = time.time()

    for run_num in range(1, num_runs + 1):
        if num_runs > 1:
            print(f"{'='*60}")
            print(f"Run {run_num}/{num_runs}")
            print(f"{'='*60}")
            print("")

        run_results = []
        successful = 0
        failed = 0

        for count in proof_counts:
            proof_file = MERKLEPROOFS_DIR / f"batch_proof_{count}.json"

            if not proof_file.exists():
                print(f"Warning: File not found: {proof_file}")
                print("")
                failed += 1
                run_results.append({
                    "file": proof_file.name,
                    "success": False,
                    "error": "File not found"
                })
                continue

            proof_data = process_merkle_proof_file(proof_file, output_dir, run_num if num_runs > 1 else None)

            if proof_data:
                successful += 1
                run_results.append({
                    "file": proof_file.name,
                    "success": True,
                    "generation_duration_ms": proof_data.get("generation_duration_ms", 0),
                    "verification_duration_ms": proof_data.get("verification_duration_ms", 0),
                    "proof_size_bytes": proof_data.get("proof_size_bytes", 0)
                })
            else:
                failed += 1
                run_results.append({
                    "file": proof_file.name,
                    "success": False,
                    "error": "Proof generation failed"
                })

        all_runs_results.append(run_results)

        if num_runs > 1:
            print(f"\nRun {run_num} summary: {successful} successful, {failed} failed")
            print("")

    overall_elapsed = time.time() - overall_start

    # Aggregate results if multiple runs
    if num_runs > 1:
        aggregated_results = aggregate_results(all_runs_results)
        total_successful = sum(1 for r in aggregated_results if r.get("success", False))
        total_failed = len(aggregated_results) - total_successful
    else:
        aggregated_results = all_runs_results[0]
        total_successful = sum(1 for r in aggregated_results if r.get("success", False))
        total_failed = len(aggregated_results) - total_successful

    # Print summary
    print(f"{'='*60}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*60}")
    print(f"Total runs: {num_runs}")
    print(f"Total files processed per run: {len(proof_counts)}")
    print(f"Successful: {total_successful}")
    print(f"Failed: {total_failed}")
    print(f"Total time: {overall_elapsed:.2f}s")
    print(f"Output directory: {output_dir}")
    print("")

    # Save summary
    summary_file = output_dir / "benchmark_summary.json"
    summary_data = {
        "timestamp": timestamp,
        "num_runs": num_runs,
        "proof_counts": proof_counts,
        "total_files_per_run": len(proof_counts),
        "successful": total_successful,
        "failed": total_failed,
        "total_time_seconds": overall_elapsed,
        "results": aggregated_results
    }
    
    with open(summary_file, 'w') as f:
        json.dump(summary_data, f, indent=2)

    print(f"Summary saved to: {summary_file}")

    # Exit with error code if any failed
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
