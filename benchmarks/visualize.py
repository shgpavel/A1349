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
LATENCY_PERCENTILES = [("p50", "-"), ("p95", "--"), ("p99", ":")]
LATENCY_PLOTS = [
    ("sched_delay", "Schedule Delay", "latency_sched_delay"),
    ("runqueue", "Runqueue Latency", "latency_runqueue"),
    ("wakeup", "Wakeup Latency", "latency_wakeup"),
    ("preemption", "Preemption Latency", "latency_preemption"),
]
THROUGHPUT_PLOTS = [
    (
        "hackbench_time_sec",
        "throughput_hackbench",
        "Hackbench Time",
        "hackbench time (s)",
        True,
    ),
    (
        "sysbench_events_per_sec",
        "throughput_sysbench",
        "Sysbench Throughput",
        "sysbench (events/s)",
        False,
    ),
]
SUMMARY_LINE_PLOTS = [
    (
        "summary_sched_delay_p50",
        "Schedule Delay p50 (ns)",
        "ns",
        "sched_delay_p50_ns",
        None,
    ),
    (
        "summary_sched_delay_p99",
        "Schedule Delay p99 (ns)",
        "ns",
        "sched_delay_p99_ns",
        None,
    ),
    (
        "summary_cpu_utilization",
        "CPU Utilization (%)",
        "CPU %",
        "cpu_util_pct",
        (0, 105),
    ),
    (
        "summary_ctx_switches",
        "Context Switches/sec",
        "Switches/sec",
        "ctx_switches_per_sec",
        None,
    ),
    (
        "summary_power",
        "Power (Watts)",
        "Watts",
        "power_watts",
        None,
    ),
]


def color_for(sched):
    return SCHED_COLORS.get(sched, "#7f7f7f")


def add_no_data(ax):
    ax.text(
        0.5,
        0.5,
        "No data",
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=11,
        color="gray",
        style="italic",
    )


def add_legend(ax, **kwargs):
    handles, labels = ax.get_legend_handles_labels()
    if handles:
        ax.legend(handles, labels, **kwargs)


def metric_series(frame, column):
    if column not in frame.columns:
        return None
    return pd.to_numeric(frame[column], errors="coerce")


def metric_has_data(frame, column):
    vals = metric_series(frame, column)
    return vals is not None and vals.notna().any()


def iter_scheduler_series(data, scheds, column):
    if column not in data.columns:
        return

    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        vals = metric_series(sdf, column)
        if vals is not None and vals.notna().any():
            yield sched, sdf, vals


def scheduler_metric_means(data, scheds, column):
    for sched, _, vals in iter_scheduler_series(data, scheds, column):
        yield sched, vals.dropna().mean()


def plot_line_metric(
    data,
    scheds,
    output_dir,
    name,
    title,
    ylabel,
    column,
    *,
    ylim=None,
    legend_fontsize=8,
):
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Elapsed (s)")

    has_data = False
    for sched, sdf, vals in iter_scheduler_series(data, scheds, column):
        ax.plot(
            sdf["elapsed_s"],
            vals,
            color=color_for(sched),
            label=sched,
            alpha=0.8,
        )
        has_data = True

    if ylim is not None:
        ax.set_ylim(*ylim)

    if has_data:
        add_legend(ax, fontsize=legend_fontsize)
    else:
        add_no_data(ax)

    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    save(fig, output_dir, name)
    return has_data


def plot_bar_metric(
    data,
    scheds,
    output_dir,
    name,
    title,
    ylabel,
    column,
    *,
    lower_better=False,
):
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.set_title(title)
    note = " (lower is better)" if lower_better else " (higher is better)"
    ax.set_ylabel(ylabel + note)

    values = []
    labels = []
    colors = []

    for sched, mean_value in scheduler_metric_means(data, scheds, column):
        values.append(mean_value)
        labels.append(sched)
        colors.append(color_for(sched))

    if values:
        bars = ax.bar(labels, values, color=colors, alpha=0.8, edgecolor="black")
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.02,
                f"{val:.2f}",
                ha="center",
                va="bottom",
                fontsize=9,
            )
    else:
        add_no_data(ax)

    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    save(fig, output_dir, name)
    return bool(values)


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
# Plot 1: Latency time series
# ---------------------------------------------------------------------------

def plot_latency_timeseries(data, scheds, output_dir):
    for prefix, title, name in LATENCY_PLOTS:
        fig, ax = plt.subplots(figsize=(10, 5))
        has_data = False
        for sched in scheds:
            sdf = data[data["scheduler"] == sched]
            for pct, linestyle in LATENCY_PERCENTILES:
                col = f"{prefix}_{pct}_ns"
                vals = metric_series(sdf, col)
                if vals is None or not vals.notna().any():
                    continue
                ax.plot(
                    sdf["elapsed_s"],
                    vals,
                    linestyle=linestyle,
                    color=color_for(sched),
                    label=f"{sched} {pct}",
                    alpha=0.8,
                )
                has_data = True

        ax.set_title(f"{title} Over Time")
        ax.set_ylabel("ns")
        ax.set_xlabel("Elapsed (s)")
        if has_data:
            add_legend(ax, fontsize=7, ncol=2)
        else:
            add_no_data(ax)
        ax.grid(True, alpha=0.3)

        fig.tight_layout()
        save(fig, output_dir, name)


# ---------------------------------------------------------------------------
# Plot 2: CPU utilization over time
# ---------------------------------------------------------------------------

def plot_cpu_util(data, scheds, output_dir):
    plot_line_metric(
        data,
        scheds,
        output_dir,
        "cpu_utilization",
        "CPU Utilization Over Time",
        "CPU %",
        "cpu_util_pct",
        ylim=(0, 105),
    )


# ---------------------------------------------------------------------------
# Plot 3: Context switch rate over time
# ---------------------------------------------------------------------------

def plot_ctx_switches(data, scheds, output_dir):
    plot_line_metric(
        data,
        scheds,
        output_dir,
        "ctx_switches",
        "Context Switch Rate Over Time",
        "Switches/sec",
        "ctx_switches_per_sec",
    )


# ---------------------------------------------------------------------------
# Plot 4: Power consumption over time
# ---------------------------------------------------------------------------

def plot_power(data, scheds, output_dir):
    col = "power_watts"
    if not metric_has_data(data, col):
        return

    plot_line_metric(
        data,
        scheds,
        output_dir,
        "power",
        "Power Consumption Over Time",
        "Watts",
        col,
    )


# ---------------------------------------------------------------------------
# Plot 5: Throughput comparison
# ---------------------------------------------------------------------------

def plot_throughput(data, scheds, output_dir):
    for col, name, title, ylabel, lower_better in THROUGHPUT_PLOTS:
        if not metric_has_data(data, col):
            continue
        plot_bar_metric(
            data,
            scheds,
            output_dir,
            name,
            title,
            ylabel,
            col,
            lower_better=lower_better,
        )


# ---------------------------------------------------------------------------
# Plot 6: Summary outputs
# ---------------------------------------------------------------------------

def plot_summary(data, scheds, output_dir):
    for name, title, ylabel, column, ylim in SUMMARY_LINE_PLOTS:
        if not metric_has_data(data, column):
            continue
        plot_line_metric(
            data,
            scheds,
            output_dir,
            name,
            title,
            ylabel,
            column,
            ylim=ylim,
        )

    summary_throughput = next(
        (
            (column, ylabel, lower_better)
            for column, _, _, ylabel, lower_better in reversed(THROUGHPUT_PLOTS)
            if metric_has_data(data, column)
        ),
        None,
    )
    if summary_throughput is None:
        return

    column, ylabel, lower_better = summary_throughput
    plot_bar_metric(
        data,
        scheds,
        output_dir,
        "summary_throughput",
        "Throughput",
        ylabel,
        column,
        lower_better=lower_better,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def save(fig, output_dir, name):
    path = output_dir / f"{name}.pdf"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {name}.pdf")


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
    plot_throughput(data, scheds, output_dir)
    plot_summary(data, scheds, output_dir)

    print("Done.")


if __name__ == "__main__":
    main()
