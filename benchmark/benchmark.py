#!/usr/bin/env python3
import json
import subprocess
import time
import signal
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import httpx
import click


SCRIPT_DIR = Path(__file__).parent
BANNED_LIST_FILE = SCRIPT_DIR / "banned_list_bench.txt"
OUTPUT_DIR = SCRIPT_DIR / "output"
NAMESPACE = "sharing-sbom-system"
SERVICES = [
    "proof-orchestrator-service",
    "merkle-proof-service",
    "proving-service",
    "ipfs-service",
]


class PortForwardManager:
    def __init__(self, service: str, local_port: int, remote_port: int, namespace: str):
        self.service = service
        self.local_port = local_port
        self.remote_port = remote_port
        self.namespace = namespace
        self.process: Optional[subprocess.Popen] = None

    def start(self):
        cmd = [
            "kubectl",
            "port-forward",
            "-n",
            self.namespace,
            f"svc/{self.service}",
            f"{self.local_port}:{self.remote_port}",
        ]
        self.process = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        for i in range(30):
            try:
                response = httpx.get(
                    f"http://localhost:{self.local_port}/health", timeout=5
                )
                if response.status_code == 200:
                    return
            except Exception:
                pass
            if i == 29:
                raise RuntimeError(
                    f"Service {self.service} not available after port-forward"
                )
            time.sleep(2)

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None


def get_container_id(service_name: str, namespace: str) -> Optional[str]:
    try:
        cmd = [
            "kubectl",
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            f"app={service_name}",
            "-o",
            "jsonpath='{.items[0].status.containerStatuses[0].imageID}'",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=10
        )
        image_id = result.stdout.strip().strip("'\"")
        return image_id if image_id else None
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        return None


def get_all_container_ids(namespace: str) -> Dict[str, Optional[str]]:
    image_ids = {}
    for service in SERVICES:
        image_ids[service] = get_container_id(service, namespace)
    return image_ids


def read_banned_list(file_path: Path) -> List[str]:
    if not file_path.exists():
        raise FileNotFoundError(f"Banned list file not found: {file_path}")

    banned_items = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                banned_items.append(line)

    if not banned_items:
        raise ValueError(f"No valid entries found in {file_path}")

    return banned_items


class TimeLimitChecker:
    def __init__(self, end_time: Optional[float], check_interval: int = 60):
        self.end_time = end_time
        self.check_interval = check_interval
        self.should_abort = False
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        if self.end_time is None:
            return
        self._thread = threading.Thread(target=self._check_loop, daemon=True)
        self._thread.start()

    def _check_loop(self):
        while not self._stop_event.is_set():
            if self.end_time and time.time() >= self.end_time:
                with self._lock:
                    self.should_abort = True
                break
            self._stop_event.wait(self.check_interval)

    def check(self) -> bool:
        with self._lock:
            return self.should_abort

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)


def call_orchestrator(
    url: str,
    root_hash: str,
    banned_list: List[str],
    timeout: int = 1800,
    time_checker: Optional[TimeLimitChecker] = None,
) -> Dict[str, Any]:
    payload = {"root_hash": root_hash, "banned_list": banned_list}

    if time_checker and time_checker.check():
        raise TimeoutError("Time limit reached before starting orchestrator call")

    with httpx.Client(timeout=timeout) as client:
        response = client.post(f"{url}/generate-proof", json=payload)
        response.raise_for_status()
        return response.json()


def validate_root_hash(ctx, param, value):
    if len(value) != 64:
        raise click.BadParameter("Root hash must be exactly 64 hex characters")
    try:
        int(value, 16)
    except ValueError:
        raise click.BadParameter("Root hash must be hexadecimal")
    return value


def write_metadata(
    output_path: Path,
    benchmark_config: Dict[str, Any],
    start_time: datetime,
    image_ids: Dict[str, Optional[str]],
    results: List[Dict[str, Any]],
):
    end_time_dt = datetime.now()
    metadata = {
        "benchmark_config": benchmark_config,
        "start_time": start_time.isoformat(),
        "end_time": end_time_dt.isoformat(),
        "duration_seconds": (end_time_dt - start_time).total_seconds(),
        "image_ids": image_ids,
        "iterations": results,
        "total_iterations": len(results),
    }
    metadata_file = output_path / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump(metadata, f, indent=2)


@click.command()
@click.option(
    "--runtime",
    type=int,
    default=None,
    help="Total benchmark runtime in minutes",
)
@click.option(
    "--total-cases",
    type=int,
    default=None,
    help="Maximum number of iterations to run",
)
@click.option(
    "--increment",
    type=int,
    required=True,
    help="Step size for increasing banned list size per iteration",
)
@click.option(
    "--start-size",
    type=int,
    default=None,
    help="Number of packages to start with from banned list (defaults to increment value)",
)
@click.option(
    "--root-hash",
    type=str,
    required=True,
    callback=validate_root_hash,
    help="Root hash to use for all proof generations (64 hex characters)",
)
@click.option(
    "--orchestrator-url",
    type=str,
    default=None,
    help="Orchestrator service URL (defaults to localhost:8080 with port-forward)",
)
def main(
    runtime: Optional[int],
    total_cases: Optional[int],
    increment: int,
    start_size: Optional[int],
    root_hash: str,
    orchestrator_url: Optional[str],
):
    if runtime is None and total_cases is None:
        raise click.BadParameter(
            "At least one of --runtime or --total-cases must be specified"
        )
    if runtime is not None and runtime <= 0:
        raise click.BadParameter("Runtime must be positive")
    if total_cases is not None and total_cases <= 0:
        raise click.BadParameter("Total cases must be positive")
    if increment <= 0:
        raise click.BadParameter("Increment must be positive")
    if start_size is not None and start_size <= 0:
        raise click.BadParameter("Start size must be positive")

    if start_size is None:
        start_size = increment

    start_time = datetime.now()
    timestamp = start_time.strftime("%Y-%m-%dT%H-%M-%S")
    output_path = OUTPUT_DIR / timestamp
    output_path.mkdir(parents=True, exist_ok=True)

    end_time = start_time.timestamp() + (runtime * 60) if runtime else None

    print(f"=== Benchmark Proving Service ===")
    print(f"Start time: {start_time.isoformat()}")
    if runtime:
        print(f"Runtime: {runtime} minutes")
    if total_cases:
        print(f"Total cases: {total_cases}")
    print(f"Start size: {start_size} packages")
    print(f"Increment: {increment} packages per iteration")
    print(f"Root hash: {root_hash}")
    print(f"Output directory: {output_path}")
    print()

    banned_list = read_banned_list(BANNED_LIST_FILE)
    print(f"Loaded {len(banned_list)} packages from banned list")
    print()

    port_forward: Optional[PortForwardManager] = None
    if orchestrator_url is None:
        print("Setting up port-forward for orchestrator service...")
        port_forward = PortForwardManager(
            "proof-orchestrator-service", 8080, 8080, NAMESPACE
        )
        port_forward.start()
        orchestrator_url = "http://localhost:8080"
        print("Port-forward established")
        print()

    benchmark_config = {
        "runtime_minutes": runtime,
        "total_cases": total_cases,
        "start_size": start_size,
        "increment": increment,
        "root_hash": root_hash,
        "orchestrator_url": orchestrator_url or "http://localhost:8080",
    }

    time_checker: Optional[TimeLimitChecker] = None

    def cleanup():
        if port_forward:
            port_forward.stop()
        if time_checker:
            time_checker.stop()

    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(1)))

    try:
        iteration = 0
        current_size = start_size
        results = []
        image_ids = get_all_container_ids(NAMESPACE)

        print(f"Image IDs at start:")
        for service, img_id in image_ids.items():
            print(f"  {service}: {img_id or 'N/A'}")
        print()

        time_checker = TimeLimitChecker(end_time)
        time_checker.start()

        write_metadata(output_path, benchmark_config, start_time, image_ids, results)

        while True:
            if total_cases is not None and iteration >= total_cases:
                print(f"Reached total cases limit ({total_cases})")
                break

            if end_time and time.time() >= end_time:
                print(f"Reached runtime limit ({runtime} minutes)")
                break

            if current_size > len(banned_list):
                print(f"Reached end of banned list ({len(banned_list)} packages)")
                break

            if time_checker.check():
                print("Time limit reached, aborting current iteration")
                break

            test_list = banned_list[:current_size]
            print(f"Iteration {iteration}: Testing with {current_size} packages...")

            call_start = time.time()
            try:
                response = call_orchestrator(
                    orchestrator_url, root_hash, test_list, time_checker=time_checker
                )
                call_end = time.time()
                call_duration = call_end - call_start

                if time_checker.check():
                    print("Time limit reached during call, wrapping up...")
                    result = {
                        "iteration": iteration,
                        "banned_list_size": current_size,
                        "call_time_seconds": call_duration,
                        "error": "Time limit reached during call",
                        "aborted": True,
                    }
                    results.append(result)
                    write_metadata(
                        output_path,
                        benchmark_config,
                        start_time,
                        image_ids,
                        results,
                    )
                    break

                composite_hash = response.get("composite_hash", "unknown")
                proof_file = (
                    output_path / f"proof_{iteration}_{composite_hash[:16]}.json"
                )

                with open(proof_file, "w") as f:
                    json.dump(response, f, indent=2)

                proving_service_metrics = response.get("proving_service_metrics")

                result = {
                    "iteration": iteration,
                    "banned_list_size": current_size,
                    "call_time_seconds": call_duration,
                    "composite_hash": composite_hash,
                    "ipfs_cid": response.get("ipfs_cid"),
                    "tx_hash": response.get("tx_hash"),
                    "compliance_status": response.get("compliance_status"),
                    "root_hash": response.get("root_hash"),
                    "warning": response.get("warning"),
                    "proving_service_metrics": proving_service_metrics,
                }

                if proving_service_metrics:
                    print(
                        f"  Proving metrics: gen={proving_service_metrics.get('generation_duration_ms', 'N/A')}ms, "
                        f"proof_size={proving_service_metrics.get('proof_size_bytes', 'N/A')}B, "
                        f"segments={proving_service_metrics.get('segments_count', 'N/A')}, "
                        f"cycles={proving_service_metrics.get('total_cycles', 'N/A')}"
                    )
                results.append(result)
                write_metadata(
                    output_path, benchmark_config, start_time, image_ids, results
                )

                print(f"  ✓ Completed in {call_duration:.2f}s")
                print(f"  Composite hash: {composite_hash[:16]}...")
                print(f"  IPFS CID: {response.get('ipfs_cid', 'N/A')}")
                print()

            except Exception as e:
                call_end = time.time()
                call_duration = call_end - call_start
                print(f"  ✗ Failed after {call_duration:.2f}s: {e}")
                print()

                result = {
                    "iteration": iteration,
                    "banned_list_size": current_size,
                    "call_time_seconds": call_duration,
                    "error": str(e),
                }
                results.append(result)
                write_metadata(
                    output_path, benchmark_config, start_time, image_ids, results
                )

            iteration += 1
            current_size += increment

            if end_time:
                remaining_time = end_time - time.time()
                if remaining_time > 0:
                    print(f"Remaining time: {remaining_time / 60:.1f} minutes")
                print()

        time_checker.stop()
        write_metadata(output_path, benchmark_config, start_time, image_ids, results)

        print("=== Benchmark Complete ===")
        print(f"Total iterations: {len(results)}")
        print(f"Metadata saved to: {output_path / 'metadata.json'}")

    finally:
        cleanup()


if __name__ == "__main__":
    main()
