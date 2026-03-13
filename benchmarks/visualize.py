#!/usr/bin/env python3
"""
visualize.py - Scheduler benchmark visualization.

Reads CSV files produced by collect.py and generates comparison plots.

Dependencies: matplotlib, pandas

Usage:
    python3 visualize.py results/default_*.csv results/s3+_*.csv --output plots/
"""

import argparse
import json
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
LATENCY_PERCENTILES = [("avg", "-"), ("p99", ":")]
LATENCY_PLOTS = [
    ("sched_delay",  "Schedule Delay",     "latency_sched_delay"),
    ("runqueue",     "Runqueue Latency",   "latency_runqueue"),
    ("wakeup",       "Wakeup Latency",     "latency_wakeup"),
    ("preemption",   "Preemption Latency", "latency_preemption"),
    ("idle_wakeup",  "Idle CPU Wakeup",    "latency_idle_wakeup"),
    ("migration",    "Migration Latency",  "latency_migration"),
    ("slice",        "Slice Duration",     "latency_slice"),
    ("sleep",        "Sleep Duration",     "latency_sleep"),
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


def scheduler_has_metric_data(data, sched, column):
    frame = data[data["scheduler"] == sched]
    return metric_has_data(frame, column)


def require_metric_comparison(data, scheds, columns, plot_name):
    missing = []
    for sched in scheds:
        if isinstance(columns, str):
            has_data = scheduler_has_metric_data(data, sched, columns)
        else:
            has_data = all(scheduler_has_metric_data(data, sched, column) for column in columns)
        if not has_data:
            missing.append(sched)

    if missing:
        print(
            f"Skipping {plot_name}: missing comparison data for {', '.join(missing)}",
            file=sys.stderr,
        )
        return False
    return True


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
    log_scale=False,
    legend_fontsize=8,
    require_all_scheds=False,
):
    if require_all_scheds and not require_metric_comparison(data, scheds, column, name):
        return False

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

    if log_scale:
        ax.set_yscale("log")
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
    require_all_scheds=False,
):
    if require_all_scheds and not require_metric_comparison(data, scheds, column, name):
        return False

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
                bar.get_height(),
                f"{val:.2f}",
                ha="center",
                va="bottom",
                fontsize=7,
            )
        # Add top margin so labels don't clip
        ymin, ymax = ax.get_ylim()
        ax.set_ylim(ymin, ymax * 1.1)
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


def load_metadata(csv_files):
    """Load metadata JSON files adjacent to CSV files."""
    meta = {}
    for csv_path in csv_files:
        p = Path(csv_path)
        # Try matching meta file: same stem with .meta.json
        meta_path = p.with_suffix("").with_suffix(".meta.json")
        if not meta_path.exists():
            # Try alternative: replace .csv with .meta.json
            meta_path = p.parent / (p.stem + ".meta.json")
        if meta_path.exists():
            try:
                with open(meta_path) as f:
                    m = json.load(f)
                sched = m.get("scheduler", "unknown")
                meta[sched] = m
            except (OSError, json.JSONDecodeError):
                pass
    return meta


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
        for pct, linestyle in LATENCY_PERCENTILES:
            col = f"{prefix}_{pct}_ns"
            plot_name = f"{name}_{pct}"
            if not require_metric_comparison(data, scheds, col, plot_name):
                continue

            fig, ax = plt.subplots(figsize=(10, 5))
            has_data = False
            for sched in scheds:
                sdf = data[data["scheduler"] == sched]
                vals = metric_series(sdf, col)
                if vals is None or not vals.notna().any():
                    continue
                ax.plot(
                    sdf["elapsed_s"],
                    vals,
                    color=color_for(sched),
                    label=sched,
                    alpha=0.8,
                )
                has_data = True

            ax.set_title(f"{title} {pct.upper()} Over Time")
            ax.set_ylabel("ns")
            ax.set_xlabel("Elapsed (s)")
            if has_data:
                add_legend(ax, fontsize=8)
            else:
                add_no_data(ax)
            ax.grid(True, alpha=0.3)

            fig.tight_layout()
            save(fig, output_dir, plot_name)


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
        require_all_scheds=True,
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
        require_all_scheds=True,
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
        require_all_scheds=True,
    )


# ---------------------------------------------------------------------------
# Plot 5: Throughput comparison
# ---------------------------------------------------------------------------

def plot_throughput(data, scheds, output_dir, metadata=None):
    # Plot from time-series CSV if columns present (legacy support)
    for col, name, title, ylabel, lower_better in THROUGHPUT_PLOTS:
        if metric_has_data(data, col):
            plot_bar_metric(
                data,
                scheds,
                output_dir,
                name,
                title,
                ylabel,
                col,
                lower_better=lower_better,
                require_all_scheds=True,
            )

    # Plot from metadata one-shot results
    if not metadata:
        return

    for col, name, title, ylabel, lower_better in THROUGHPUT_PLOTS:
        values = []
        labels = []
        colors = []
        for sched in scheds:
            val = metadata.get(sched, {}).get("oneshot", {}).get(col)
            if val is not None:
                values.append(val)
                labels.append(sched)
                colors.append(color_for(sched))

        if len(values) < 2:
            continue

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.set_title(title)
        note = " (lower is better)" if lower_better else " (higher is better)"
        ax.set_ylabel(ylabel + note)

        bars = ax.bar(labels, values, color=colors, alpha=0.8, edgecolor="black")
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{val:.2f}",
                ha="center", va="bottom", fontsize=7,
            )

        # Add top margin so labels don't clip
        ymin, ymax = ax.get_ylim()
        ax.set_ylim(ymin, ymax * 1.1)

        ax.grid(True, alpha=0.3, axis="y")
        fig.tight_layout()
        save(fig, output_dir, name)


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

SUMMARY_METRICS = [
    ("cpu_util_pct",          "CPU Utilization (%)",      False),
    ("ctx_switches_per_sec",  "Context Switches/s",       None),
    ("power_watts",           "Power (W)",                True),
    ("sched_delay_avg_ns",    "Sched Delay avg (ns)",     True),
    ("sched_delay_p99_ns",    "Sched Delay p99 (ns)",     True),
    ("runqueue_avg_ns",       "Runqueue avg (ns)",        True),
    ("runqueue_p99_ns",       "Runqueue p99 (ns)",        True),
    ("wakeup_avg_ns",         "Wakeup avg (ns)",          True),
    ("wakeup_p99_ns",         "Wakeup p99 (ns)",          True),
    ("preemption_avg_ns",     "Preemption avg (ns)",      True),
    ("preemption_p99_ns",     "Preemption p99 (ns)",      True),
    ("idle_wakeup_avg_ns",    "Idle Wakeup avg (ns)",     True),
    ("idle_wakeup_p99_ns",    "Idle Wakeup p99 (ns)",     True),
    ("migration_avg_ns",      "Migration avg (ns)",       True),
    ("migration_p99_ns",      "Migration p99 (ns)",       True),
    ("slice_avg_ns",          "Slice Duration avg (ns)",  None),
    ("slice_p99_ns",          "Slice Duration p99 (ns)",  None),
    ("sleep_avg_ns",          "Sleep Duration avg (ns)",  None),
    ("sleep_p99_ns",          "Sleep Duration p99 (ns)",  None),
]


def write_summary(data, scheds, metadata, output_dir):
    """Write a PDF summary table with per-scheduler stats and relative %."""
    if not scheds:
        return

    baseline = scheds[0]

    # One-shot benchmarks from metadata
    oneshot_metrics = [
        ("hackbench_time_sec", "Hackbench (s)", True),
        ("sysbench_events_per_sec", "Sysbench (ev/s)", False),
    ]

    # Build table rows: each row = [metric_label, val_sched1, val_sched2, ...]
    col_headers = ["Metric"] + scheds
    table_rows = []

    # Time-series metrics
    for col, label, lower_better in SUMMARY_METRICS:
        if col not in data.columns:
            continue
        vals_by_sched = {}
        for s in scheds:
            sdf = data[data["scheduler"] == s]
            v = pd.to_numeric(sdf[col], errors="coerce").dropna()
            if len(v) > 0:
                vals_by_sched[s] = v

        if not vals_by_sched:
            continue

        baseline_mean = vals_by_sched[baseline].mean() if baseline in vals_by_sched else None
        row = [label]
        for s in scheds:
            if s in vals_by_sched:
                v = vals_by_sched[s]
                mean = v.mean()
                std = v.std()
                cell = f"{mean:.1f} +/- {std:.1f}"
                if s != baseline and baseline_mean is not None and baseline_mean != 0:
                    pct = (mean - baseline_mean) / abs(baseline_mean) * 100
                    cell += f"\n({pct:+.1f}%)"
                row.append(cell)
            else:
                row.append("N/A")

        table_rows.append(row)

    # One-shot metrics from metadata
    for m_key, label, lower_better in oneshot_metrics:
        has_data = any(
            m_key in metadata.get(s, {}).get("oneshot", {})
            for s in scheds
        )
        if not has_data:
            continue

        baseline_val = metadata.get(baseline, {}).get("oneshot", {}).get(m_key)
        row = [label]
        for s in scheds:
            val = metadata.get(s, {}).get("oneshot", {}).get(m_key)
            if val is not None:
                cell = f"{val:.2f}"
                if s != baseline and baseline_val is not None and baseline_val != 0:
                    pct = (val - baseline_val) / abs(baseline_val) * 100
                    cell += f"\n({pct:+.1f}%)"
                row.append(cell)
            else:
                row.append("N/A")

        table_rows.append(row)

    if not table_rows:
        return

    # Render as PDF table
    fig, ax = plt.subplots(figsize=(10, 0.4 * len(table_rows) + 1.5))
    ax.axis("off")
    ax.set_title("Benchmark Summary", fontsize=12, pad=10)

    table = ax.table(
        cellText=table_rows,
        colLabels=col_headers,
        loc="center",
        cellLoc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1, 1.4)

    # Style header row
    for j in range(len(col_headers)):
        cell = table[0, j]
        cell.set_facecolor("#d9e2f3")
        cell.set_text_props(weight="bold")

    # Left-align metric names
    for i in range(len(table_rows)):
        table[i + 1, 0].set_text_props(ha="left")

    fig.tight_layout()
    save(fig, output_dir, "summary")


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
    parser.add_argument(
        "--schedulers", nargs="+", default=None,
        help="Explicit scheduler order to compare"
    )
    parser.add_argument(
        "--require-schedulers", action="store_true",
        help="Fail if any explicitly requested scheduler is missing from the input CSVs"
    )

    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    data = load_data(args.csv_files)
    metadata = load_metadata(args.csv_files)
    present = set(data["scheduler"].unique())
    if args.schedulers:
        missing = [sched for sched in args.schedulers if sched not in present]
        if missing and args.require_schedulers:
            print(
                f"Error: missing scheduler data for {', '.join(missing)}",
                file=sys.stderr,
            )
            return 1
        scheds = [sched for sched in args.schedulers if sched in present]
    else:
        scheds = schedulers_in(data)
    print(f"Schedulers: {', '.join(scheds)}")
    print(f"Total rows: {len(data)}")
    print(f"Generating plots in {output_dir}/...")

    plot_latency_timeseries(data, scheds, output_dir)
    plot_cpu_util(data, scheds, output_dir)
    plot_ctx_switches(data, scheds, output_dir)
    plot_power(data, scheds, output_dir)
    plot_throughput(data, scheds, output_dir, metadata=metadata)
    write_summary(data, scheds, metadata, output_dir)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
