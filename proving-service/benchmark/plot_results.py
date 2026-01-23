import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import matplotlib.pyplot as plt
import matplotlib

matplotlib.use('Agg')


def extract_proof_count(filename: str) -> int:
    """Extract proof count from filename like 'batch_proof_2.json' -> 2"""
    return int(filename.split('_')[-1].replace('.json', ''))


def extract_duration_data(result: Dict[str, Any], duration_type: str) -> Tuple[List[int], float, float, float]:
    """
    Extract duration data from a result entry.
    Returns: (values, mean, min, max)
    """
    duration_data = result.get(duration_type, {})
    
    if isinstance(duration_data, dict):
        # Multi-run aggregated data
        values = duration_data.get("values", [])
        mean = duration_data.get("mean", 0.0)
        min_val = duration_data.get("min", 0.0)
        max_val = duration_data.get("max", 0.0)
    else:
        # Single-run direct value
        values = [duration_data] if duration_data else []
        mean = duration_data if duration_data else 0.0
        min_val = mean
        max_val = mean
    
    return values, mean, min_val, max_val


def load_benchmark_summary(summary_path: Path) -> Dict[str, Any]:
    """Load and parse the benchmark summary JSON file."""
    with open(summary_path, 'r') as f:
        return json.load(f)


def create_side_by_side_plots(
    proof_counts: List[int],
    gen_means: List[float],
    gen_mins: List[float],
    gen_maxs: List[float],
    gen_values_list: List[List[float]],
    verif_means: List[float],
    verif_mins: List[float],
    verif_maxs: List[float],
    verif_values_list: List[List[float]],
    num_runs: int,
    x_scale: str = 'linear',
    y_scale: str = 'linear',
    suffix: str = ''
) -> plt.Figure:
    """Create side-by-side plots for generation and verification durations."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Plot 1: Generation Duration
    ax1.plot(proof_counts, gen_means, 'o-', label='Mean', linewidth=2, markersize=8, color='#2E86AB')
    if num_runs > 1:
        ax1.fill_between(proof_counts, gen_mins, gen_maxs, alpha=0.3, label='Min-Max Range', color='#2E86AB')
        # Plot individual values as scatter if we have them
        for i, (pc, values) in enumerate(zip(proof_counts, gen_values_list)):
            if values:
                ax1.scatter([pc] * len(values), values, alpha=0.4, s=20, color='#2E86AB', zorder=1)
    
    ax1.set_xlabel('Proof Count', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Generation Duration (seconds)', fontsize=12, fontweight='bold')
    ax1.set_title('Generation Duration vs Proof Count', fontsize=14, fontweight='bold')
    ax1.grid(True, alpha=0.3, linestyle='--')
    ax1.legend(fontsize=10)
    
    if x_scale == 'log':
        ax1.set_xscale('log', base=2)
    if y_scale == 'log':
        ax1.set_yscale('log')
    
    # Plot 2: Verification Duration
    ax2.plot(proof_counts, verif_means, 'o-', label='Mean', linewidth=2, markersize=8, color='#A23B72')
    if num_runs > 1:
        ax2.fill_between(proof_counts, verif_mins, verif_maxs, alpha=0.3, label='Min-Max Range', color='#A23B72')
        # Plot individual values as scatter if we have them
        for i, (pc, values) in enumerate(zip(proof_counts, verif_values_list)):
            if values:
                ax2.scatter([pc] * len(values), values, alpha=0.4, s=20, color='#A23B72', zorder=1)
    
    ax2.set_xlabel('Proof Count', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Verification Duration (seconds)', fontsize=12, fontweight='bold')
    ax2.set_title('Verification Duration vs Proof Count', fontsize=14, fontweight='bold')
    ax2.grid(True, alpha=0.3, linestyle='--')
    ax2.legend(fontsize=10)
    
    if x_scale == 'log':
        ax2.set_xscale('log', base=2)
    if y_scale == 'log':
        ax2.set_yscale('log')
    
    plt.tight_layout()
    return fig


def create_combined_plot(
    proof_counts: List[int],
    gen_means: List[float],
    gen_mins: List[float],
    gen_maxs: List[float],
    verif_means: List[float],
    verif_mins: List[float],
    verif_maxs: List[float],
    num_runs: int,
    x_scale: str = 'linear',
    y_scale: str = 'linear',
    suffix: str = ''
) -> plt.Figure:
    """Create a combined plot with both generation and verification durations."""
    fig, ax3 = plt.subplots(1, 1, figsize=(10, 6))
    
    ax3.plot(proof_counts, gen_means, 'o-', label='Generation (Mean)', linewidth=2, markersize=8, color='#2E86AB')
    ax3.plot(proof_counts, verif_means, 's-', label='Verification (Mean)', linewidth=2, markersize=8, color='#A23B72')
    
    if num_runs > 1:
        ax3.fill_between(proof_counts, gen_mins, gen_maxs, alpha=0.2, color='#2E86AB')
        ax3.fill_between(proof_counts, verif_mins, verif_maxs, alpha=0.2, color='#A23B72')
    
    ax3.set_xlabel('Proof Count', fontsize=12, fontweight='bold')
    ax3.set_ylabel('Duration (seconds)', fontsize=12, fontweight='bold')
    ax3.set_title('Generation and Verification Duration vs Proof Count', fontsize=14, fontweight='bold')
    ax3.grid(True, alpha=0.3, linestyle='--')
    ax3.legend(fontsize=10)
    
    if x_scale == 'log':
        ax3.set_xscale('log', base=2)
    if y_scale == 'log':
        ax3.set_yscale('log')
    
    plt.tight_layout()
    return fig


def plot_durations(summary: Dict[str, Any], output_dir: Path):
    """Create plots for generation and verification durations with different scale combinations."""
    results = summary.get("results", [])
    num_runs = summary.get("num_runs", 1)
    
    # Filter successful results and extract data
    proof_counts = []
    gen_means = []
    gen_mins = []
    gen_maxs = []
    gen_values_list = []
    
    verif_means = []
    verif_mins = []
    verif_maxs = []
    verif_values_list = []
    
    for result in results:
        if not result.get("success", False):
            continue
        
        filename = result["file"]
        proof_count = extract_proof_count(filename)
        
        # Extract generation duration data
        gen_values, gen_mean, gen_min, gen_max = extract_duration_data(
            result, "generation_duration_ms"
        )
        
        # Extract verification duration data
        verif_values, verif_mean, verif_min, verif_max = extract_duration_data(
            result, "verification_duration_ms"
        )
        
        proof_counts.append(proof_count)
        gen_means.append(gen_mean / 1000.0)  # Convert to seconds
        gen_mins.append(gen_min / 1000.0)
        gen_maxs.append(gen_max / 1000.0)
        gen_values_list.append([v / 1000.0 for v in gen_values])  # Convert to seconds
        
        verif_means.append(verif_mean / 1000.0)  # Convert to seconds
        verif_mins.append(verif_min / 1000.0)
        verif_maxs.append(verif_max / 1000.0)
        verif_values_list.append([v / 1000.0 for v in verif_values])  # Convert to seconds
    
    if not proof_counts:
        print("No successful results to plot")
        return
    
    # Sort by proof count
    sorted_data = sorted(zip(proof_counts, gen_means, gen_mins, gen_maxs, gen_values_list,
                             verif_means, verif_mins, verif_maxs, verif_values_list))
    proof_counts, gen_means, gen_mins, gen_maxs, gen_values_list, \
        verif_means, verif_mins, verif_maxs, verif_values_list = zip(*sorted_data)
    
    proof_counts = list(proof_counts)
    gen_means = list(gen_means)
    gen_mins = list(gen_mins)
    gen_maxs = list(gen_maxs)
    verif_means = list(verif_means)
    verif_mins = list(verif_mins)
    verif_maxs = list(verif_maxs)
    
    plot_configs = [
        ('linear', 'linear', '_normal'),
        ('log', 'linear', '_logx'),
        ('linear', 'log', '_logy'),
        ('log', 'log', '_logx_logy'),
    ]
    
    # Generate side-by-side plots for each configuration
    for x_scale, y_scale, suffix in plot_configs:
        fig = create_side_by_side_plots(
            proof_counts, gen_means, gen_mins, gen_maxs, gen_values_list,
            verif_means, verif_mins, verif_maxs, verif_values_list,
            num_runs, x_scale, y_scale, suffix
        )
        output_path = output_dir / f"duration_plots{suffix}.png"
        fig.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close(fig)
        print(f"Side-by-side plots saved to: {output_path}")
    
    # Generate combined plots for each configuration
    for x_scale, y_scale, suffix in plot_configs:
        fig = create_combined_plot(
            proof_counts, gen_means, gen_mins, gen_maxs,
            verif_means, verif_mins, verif_maxs,
            num_runs, x_scale, y_scale, suffix
        )
        output_path = output_dir / f"duration_combined{suffix}.png"
        fig.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close(fig)
        print(f"Combined plot saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot benchmark results from a benchmark_summary.json file"
    )
    parser.add_argument(
        "summary_file",
        type=Path,
        help="Path to benchmark_summary.json file"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to save plots (default: same directory as summary file)"
    )
    
    args = parser.parse_args()
    
    summary_path = args.summary_file
    if not summary_path.exists():
        print(f"Error: Summary file not found: {summary_path}")
        sys.exit(1)
    
    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = summary_path.parent
    
    # Load and plot
    print(f"Loading benchmark summary from: {summary_path}")
    summary = load_benchmark_summary(summary_path)
    
    print(f"Plotting results...")
    print(f"  Number of runs: {summary.get('num_runs', 1)}")
    print(f"  Successful results: {summary.get('successful', 0)}")
    
    plot_durations(summary, output_dir)
    
    print("Done!")


if __name__ == "__main__":
    import sys
    main()
