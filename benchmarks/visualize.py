#!/usr/bin/env python3
"""
visualize.py - Scheduler benchmark visualization.

Reads CSV files produced by collect.py and generates comparison plots.

Dependencies: matplotlib, pandas

Usage:
    python3 visualize.py results/default_*.csv results/s3+_*.csv --output plots/
"""

import argparse
import sys
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Color scheme per scheduler
# ---------------------------------------------------------------------------

SCHED_COLORS = {
    "default": "#1f77b4",  # blue
    "s3":      "#ff7f0e",  # orange
    "s3+":     "#2ca02c",  # green
    "s4":      "#d62728",  # red
}

SCHED_ORDER = ["default", "s3", "s3+", "s4"]


def color_for(sched):
    return SCHED_COLORS.get(sched, "#7f7f7f")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(csv_files):
    """Load and concatenate CSV files, return DataFrame grouped by scheduler."""
    frames = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            frames.append(df)
        except Exception as e:
            print(f"Warning: skipping {f}: {e}", file=sys.stderr)

    if not frames:
        print("Error: no valid CSV files loaded", file=sys.stderr)
        sys.exit(1)

    data = pd.concat(frames, ignore_index=True)

    # Convert elapsed_s to float
    if "elapsed_s" in data.columns:
        data["elapsed_s"] = pd.to_numeric(data["elapsed_s"], errors="coerce")

    return data


def schedulers_in(data):
    """Return scheduler names in display order."""
    present = set(data["scheduler"].unique())
    return [s for s in SCHED_ORDER if s in present] + sorted(
        present - set(SCHED_ORDER)
    )


# ---------------------------------------------------------------------------
# Plot 1: Latency time series (2x2 grid)
# ---------------------------------------------------------------------------

def plot_latency_timeseries(data, scheds, output_dir):
    lat_types = [
        ("sched_delay", "Schedule Delay"),
        ("runqueue", "Runqueue Latency"),
        ("wakeup", "Wakeup Latency"),
        ("preemption", "Preemption Latency"),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10), sharex=True)
    fig.suptitle("Latency Over Time (ns)", fontsize=14)

    for ax, (prefix, title) in zip(axes.flat, lat_types):
        has_data = False
        for sched in scheds:
            sdf = data[data["scheduler"] == sched]
            x = sdf["elapsed_s"]

            for pct, ls in [("p50", "-"), ("p95", "--"), ("p99", ":")]:
                col = f"{prefix}_{pct}_ns"
                if col in sdf.columns:
                    vals = pd.to_numeric(sdf[col], errors="coerce")
                    if vals.notna().any():
                        ax.plot(x, vals, ls, color=color_for(sched),
                                label=f"{sched} {pct}", alpha=0.8)
                        has_data = True

        ax.set_title(title)
        ax.set_ylabel("ns")
        if has_data:
            ax.legend(fontsize=7, ncol=2)
        else:
            ax.text(0.5, 0.5, "No data",
                    transform=ax.transAxes, ha="center", va="center",
                    fontsize=11, color="gray", style="italic")
        ax.grid(True, alpha=0.3)

    axes[1][0].set_xlabel("Elapsed (s)")
    axes[1][1].set_xlabel("Elapsed (s)")
    fig.tight_layout()
    save(fig, output_dir, "latency_timeseries")


# ---------------------------------------------------------------------------
# Plot 2: CPU utilization over time
# ---------------------------------------------------------------------------

def plot_cpu_util(data, scheds, output_dir):
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_title("CPU Utilization Over Time")
    ax.set_ylabel("CPU %")
    ax.set_xlabel("Elapsed (s)")

    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        if "cpu_util_pct" in sdf.columns:
            vals = pd.to_numeric(sdf["cpu_util_pct"], errors="coerce")
            ax.plot(sdf["elapsed_s"], vals, color=color_for(sched),
                    label=sched, alpha=0.8)

    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 105)
    fig.tight_layout()
    save(fig, output_dir, "cpu_utilization")


# ---------------------------------------------------------------------------
# Plot 3: Context switch rate over time
# ---------------------------------------------------------------------------

def plot_ctx_switches(data, scheds, output_dir):
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_title("Context Switch Rate Over Time")
    ax.set_ylabel("Switches/sec")
    ax.set_xlabel("Elapsed (s)")

    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        if "ctx_switches_per_sec" in sdf.columns:
            vals = pd.to_numeric(sdf["ctx_switches_per_sec"], errors="coerce")
            ax.plot(sdf["elapsed_s"], vals, color=color_for(sched),
                    label=sched, alpha=0.8)

    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    save(fig, output_dir, "ctx_switches")


# ---------------------------------------------------------------------------
# Plot 4: Power consumption over time
# ---------------------------------------------------------------------------

def plot_power(data, scheds, output_dir):
    col = "power_watts"
    if col not in data.columns:
        return

    vals = pd.to_numeric(data[col], errors="coerce")
    if vals.notna().sum() == 0:
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_title("Power Consumption Over Time")
    ax.set_ylabel("Watts")
    ax.set_xlabel("Elapsed (s)")

    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        v = pd.to_numeric(sdf[col], errors="coerce")
        if v.notna().any():
            ax.plot(sdf["elapsed_s"], v, color=color_for(sched),
                    label=sched, alpha=0.8)

    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    save(fig, output_dir, "power")


# ---------------------------------------------------------------------------
# Plot 5: Fairness comparison (bar chart)
# ---------------------------------------------------------------------------

def plot_fairness(data, scheds, output_dir):
    col = "jain_fairness_index"
    if col not in data.columns:
        return
    if not pd.to_numeric(data[col], errors="coerce").notna().any():
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.set_title("Jain's Fairness Index by Scheduler")
    ax.set_ylabel("Fairness Index (1.0 = perfect)")

    values = []
    labels = []
    colors = []
    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        v = pd.to_numeric(sdf[col], errors="coerce").dropna()
        if len(v) > 0:
            values.append(v.mean())
            labels.append(sched)
            colors.append(color_for(sched))

    if not values:
        plt.close(fig)
        return

    bars = ax.bar(labels, values, color=colors, alpha=0.8, edgecolor="black")
    ax.set_ylim(0, 1.05)
    ax.axhline(y=1.0, color="gray", linestyle="--", alpha=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.4f}", ha="center", va="bottom", fontsize=9)

    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    save(fig, output_dir, "fairness")


# ---------------------------------------------------------------------------
# Plot 6: Throughput comparison (grouped bars)
# ---------------------------------------------------------------------------

def plot_throughput(data, scheds, output_dir):
    candidates = []
    if "hackbench_time_sec" in data.columns:
        candidates.append(("hackbench_time_sec", "hackbench time (s)", True))
    if "sysbench_events_per_sec" in data.columns:
        candidates.append(("sysbench_events_per_sec", "sysbench (events/s)", False))

    # Only include metrics that actually have data
    metrics = [
        m for m in candidates
        if pd.to_numeric(data[m[0]], errors="coerce").notna().any()
    ]

    if not metrics:
        return

    fig, axes = plt.subplots(1, len(metrics), figsize=(6 * len(metrics), 5))
    if len(metrics) == 1:
        axes = [axes]
    fig.suptitle("Throughput Comparison", fontsize=14)

    for ax, (col, ylabel, lower_better) in zip(axes, metrics):
        values = []
        labels = []
        colors = []
        for sched in scheds:
            sdf = data[data["scheduler"] == sched]
            v = pd.to_numeric(sdf[col], errors="coerce").dropna()
            if len(v) > 0:
                values.append(v.mean())
                labels.append(sched)
                colors.append(color_for(sched))

        if values:
            bars = ax.bar(labels, values, color=colors, alpha=0.8,
                          edgecolor="black")
            for bar, val in zip(bars, values):
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() * 1.02,
                        f"{val:.2f}", ha="center", va="bottom", fontsize=9)

        note = " (lower is better)" if lower_better else " (higher is better)"
        ax.set_ylabel(ylabel + note)
        ax.grid(True, alpha=0.3, axis="y")

    fig.tight_layout()
    save(fig, output_dir, "throughput")


# ---------------------------------------------------------------------------
# Plot 7: Summary dashboard (3x2 grid)
# ---------------------------------------------------------------------------

def plot_summary(data, scheds, output_dir):
    fig, axes = plt.subplots(3, 2, figsize=(14, 14))
    fig.suptitle("Benchmark Summary Dashboard", fontsize=16, y=0.98)

    # (0,0) - Schedule delay p50
    ax = axes[0][0]
    ax.set_title("Schedule Delay p50 (ns)")
    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        col = "sched_delay_p50_ns"
        if col in sdf.columns:
            v = pd.to_numeric(sdf[col], errors="coerce")
            if v.notna().any():
                ax.plot(sdf["elapsed_s"], v, color=color_for(sched),
                        label=sched)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # (0,1) - Schedule delay p99
    ax = axes[0][1]
    ax.set_title("Schedule Delay p99 (ns)")
    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        col = "sched_delay_p99_ns"
        if col in sdf.columns:
            v = pd.to_numeric(sdf[col], errors="coerce")
            if v.notna().any():
                ax.plot(sdf["elapsed_s"], v, color=color_for(sched),
                        label=sched)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # (1,0) - CPU utilization
    ax = axes[1][0]
    ax.set_title("CPU Utilization (%)")
    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        if "cpu_util_pct" in sdf.columns:
            v = pd.to_numeric(sdf["cpu_util_pct"], errors="coerce")
            ax.plot(sdf["elapsed_s"], v, color=color_for(sched), label=sched)
    ax.set_ylim(0, 105)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # (1,1) - Context switches
    ax = axes[1][1]
    ax.set_title("Context Switches/sec")
    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        if "ctx_switches_per_sec" in sdf.columns:
            v = pd.to_numeric(sdf["ctx_switches_per_sec"], errors="coerce")
            ax.plot(sdf["elapsed_s"], v, color=color_for(sched), label=sched)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    # (2,0) - Fairness
    ax = axes[2][0]
    ax.set_title("Jain's Fairness Index")
    col = "jain_fairness_index"
    if col in data.columns:
        values, labels, colors = [], [], []
        for sched in scheds:
            v = pd.to_numeric(
                data[data["scheduler"] == sched][col], errors="coerce"
            ).dropna()
            if len(v) > 0:
                values.append(v.mean())
                labels.append(sched)
                colors.append(color_for(sched))
        if values:
            ax.bar(labels, values, color=colors, alpha=0.8, edgecolor="black")
            ax.set_ylim(0, 1.05)
            ax.axhline(y=1.0, color="gray", linestyle="--", alpha=0.5)
    ax.grid(True, alpha=0.3, axis="y")

    # (2,1) - Throughput
    ax = axes[2][1]
    ax.set_title("Throughput")
    tp_col = None
    if "sysbench_events_per_sec" in data.columns:
        tp_col = "sysbench_events_per_sec"
        ax.set_ylabel("events/sec")
    elif "hackbench_time_sec" in data.columns:
        tp_col = "hackbench_time_sec"
        ax.set_ylabel("seconds (lower=better)")
    if tp_col:
        values, labels, colors = [], [], []
        for sched in scheds:
            v = pd.to_numeric(
                data[data["scheduler"] == sched][tp_col], errors="coerce"
            ).dropna()
            if len(v) > 0:
                values.append(v.mean())
                labels.append(sched)
                colors.append(color_for(sched))
        if values:
            ax.bar(labels, values, color=colors, alpha=0.8, edgecolor="black")
    ax.grid(True, alpha=0.3, axis="y")

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    save(fig, output_dir, "summary_dashboard")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def save(fig, output_dir, name):
    for ext in ["png", "pdf"]:
        path = output_dir / f"{name}.{ext}"
        fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {name}.png/pdf")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Visualize scheduler benchmark results"
    )
    parser.add_argument(
        "csv_files", nargs="+",
        help="CSV files from collect.py"
    )
    parser.add_argument(
        "--output", default="plots",
        help="Output directory for plots (default: plots/)"
    )

    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(args.csv_files)
    scheds = schedulers_in(data)
    print(f"Schedulers: {', '.join(scheds)}")
    print(f"Total rows: {len(data)}")
    print(f"Generating plots in {output_dir}/...")

    plot_latency_timeseries(data, scheds, output_dir)
    plot_cpu_util(data, scheds, output_dir)
    plot_ctx_switches(data, scheds, output_dir)
    plot_power(data, scheds, output_dir)
    plot_fairness(data, scheds, output_dir)
    plot_throughput(data, scheds, output_dir)
    plot_summary(data, scheds, output_dir)

    print("Done.")


if __name__ == "__main__":
    main()
