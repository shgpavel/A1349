#!/usr/bin/env python3
"""
figure_combined.py - Generate a single multi-panel summary figure for publication.

Combines the most relevant benchmark plots into one compact figure suitable
for a research article.

Usage:
    python3 figure_combined.py results/default_*.csv results/s3_*.csv results/s3+_*.csv results/LAVD_*.csv \
        --output figures/combined.pdf
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
matplotlib.rcParams["text.usetex"] = True
matplotlib.rcParams["font.family"] = "serif"
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["pdf.fonttype"] = 42
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

# ---------------------------------------------------------------------------
# Reuse core helpers from visualize.py
# ---------------------------------------------------------------------------

SCHED_COLORS = {
    "default": "#404040",
    "s3":      "#A0A0A0",
    "s3+":     "#A0A0A0",
    "LAVD":    "#000000",
    "s4":      "#707070",
}

# Theme colors
BG_COLOR = "#FFFFFF"
TEXT_COLOR = "#000000"
ACCENT_COLOR = "#000000"
GRID_COLOR = "#CCCCCC"
SCHED_LABELS = {
    "default": "EEVDF",
    "s3":      r"sched\_ext EEVDF",
    "s3+":     r"sched\_ext EEVDF",
    "LAVD":    "LAVD",
    "s4":      "S4",
}
SCHED_ORDER = ["default", "s3", "s3+", "LAVD", "s4"]


def color_for(sched):
    return SCHED_COLORS.get(sched, "#7f7f7f")


def label_for(sched):
    return SCHED_LABELS.get(sched, sched)


def load_data(csv_files):
    frames = []
    for f in csv_files:
        try:
            frames.append(pd.read_csv(f))
        except Exception as e:
            print(f"Warning: skipping {f}: {e}", file=sys.stderr)
    if not frames:
        print("Error: no valid CSV files loaded", file=sys.stderr)
        sys.exit(1)
    data = pd.concat(frames, ignore_index=True)
    if "elapsed_s" in data.columns:
        data["elapsed_s"] = pd.to_numeric(data["elapsed_s"], errors="coerce")
    return data


def load_metadata(csv_files):
    meta = {}
    for csv_path in csv_files:
        p = Path(csv_path)
        meta_path = p.with_suffix("").with_suffix(".meta.json")
        if not meta_path.exists():
            meta_path = p.parent / (p.stem + ".meta.json")
        if meta_path.exists():
            try:
                with open(meta_path) as f:
                    m = json.load(f)
                meta[m.get("scheduler", "unknown")] = m
            except (OSError, json.JSONDecodeError):
                pass
    return meta


def schedulers_in(data):
    present = set(data["scheduler"].unique())
    return [s for s in SCHED_ORDER if s in present] + sorted(
        present - set(SCHED_ORDER)
    )


def metric_series(frame, column):
    if column not in frame.columns:
        return None
    return pd.to_numeric(frame[column], errors="coerce")


# ---------------------------------------------------------------------------
# Panel definitions
# ---------------------------------------------------------------------------

# Time-series panels: (column, title, ylabel)
TIMESERIES_PANELS = [
    ("sched_delay_p99_ns",  "Schedule Delay (p99)",  "Latency (ns)"),
]

# Bar panels: (metadata_key, title, ylabel, lower_is_better)
BAR_PANELS = [
    ("hackbench_time_sec",      "Hackbench",    "Time (s)",      True),
    ("sysbench_events_per_sec", "Sysbench",     "Events/s",      False),
]


def style_ax(ax):
    """Apply dark theme to axes."""
    ax.set_facecolor(BG_COLOR)
    ax.tick_params(colors=TEXT_COLOR, labelsize=7)
    ax.xaxis.label.set_color(TEXT_COLOR)
    ax.yaxis.label.set_color(TEXT_COLOR)
    ax.title.set_color(TEXT_COLOR)
    for spine in ax.spines.values():
        spine.set_color(ACCENT_COLOR)


def plot_timeseries_panel(ax, data, scheds, column, title, ylabel):
    """Plot a single time-series panel on the given axes."""
    ax.set_title(title, fontsize=9, fontweight="bold")
    ax.set_ylabel(ylabel, fontsize=8)
    ax.set_xlabel("Elapsed (s)", fontsize=8)

    for sched in scheds:
        sdf = data[data["scheduler"] == sched]
        vals = metric_series(sdf, column)
        if vals is None or not vals.notna().any():
            continue
        ax.plot(
            sdf["elapsed_s"], vals,
            color=color_for(sched),
            label=label_for(sched),
            alpha=0.85,
            linewidth=1.2,
        )

    ax.ticklabel_format(style="plain", axis="y")
    ax.grid(True, alpha=0.25, linewidth=0.5, color=GRID_COLOR)
    style_ax(ax)


def plot_bar_panel(ax, data, scheds, metadata, col_key, title, ylabel, lower_better):
    """Plot a single bar-chart panel on the given axes."""
    ax.set_title(title, fontsize=9, fontweight="bold")

    note = "\n(lower is better)" if lower_better else "\n(higher is better)"
    ax.set_ylabel(ylabel + note, fontsize=8)

    values, labels, colors = [], [], []

    # Try metadata oneshot first
    for sched in scheds:
        val = metadata.get(sched, {}).get("oneshot", {}).get(col_key)
        if val is not None:
            values.append(val)
            labels.append(label_for(sched))
            colors.append(color_for(sched))

    # Fall back to CSV column means
    if not values and col_key in data.columns:
        for sched in scheds:
            sdf = data[data["scheduler"] == sched]
            vals = metric_series(sdf, col_key)
            if vals is not None and vals.notna().any():
                values.append(vals.dropna().mean())
                labels.append(label_for(sched))
                colors.append(color_for(sched))

    if not values:
        ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                ha="center", va="center", fontsize=9, color="gray", style="italic")
        return

    bars = ax.bar(labels, values, color=colors, alpha=0.85, edgecolor=ACCENT_COLOR,
                  linewidth=0.5, width=0.6)

    # Value annotations
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{val:.2f}",
            ha="center", va="bottom", fontsize=7, fontweight="bold",
            color=TEXT_COLOR,
        )

    # Relative % vs baseline
    if len(values) >= 2:
        baseline_val = values[0]
        for i, (bar, val) in enumerate(zip(bars, values)):
            if i == 0 or baseline_val == 0:
                continue
            pct = (val - baseline_val) / abs(baseline_val) * 100
            color = "#000000"
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 0.5,
                f"{pct:+.1f}\\%",
                ha="center", va="center", fontsize=7,
                color=color, fontweight="bold",
            )

    ymin, ymax = ax.get_ylim()
    ax.set_ylim(ymin, ymax * 1.15)
    ax.grid(True, alpha=0.25, linewidth=0.5, axis="y", color=GRID_COLOR)
    style_ax(ax)


# ---------------------------------------------------------------------------
# Main figure assembly
# ---------------------------------------------------------------------------

def generate_combined_figure(data, scheds, metadata, output_path):
    """Build the combined 2×3 figure."""

    # Filter to panels that have data
    active_ts = []
    for col, title, ylabel in TIMESERIES_PANELS:
        if col in data.columns and data[col].notna().any():
            active_ts.append((col, title, ylabel))

    active_bar = []
    for col_key, title, ylabel, lower in BAR_PANELS:
        has_meta = any(col_key in metadata.get(s, {}).get("oneshot", {}) for s in scheds)
        has_csv = col_key in data.columns and data[col_key].notna().any()
        if has_meta or has_csv:
            active_bar.append((col_key, title, ylabel, lower))

    n_ts = len(active_ts)
    n_bar = len(active_bar)
    total = n_ts + n_bar

    if total == 0:
        print("No data for combined figure.", file=sys.stderr)
        return

    # Layout: top row = 2 bar charts (50/50), bottom row = centered time-series
    fig = plt.figure(figsize=(10, 7.5))
    fig.patch.set_facecolor(BG_COLOR)
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.35, wspace=0.3)

    # Top row: Hackbench (left), Sysbench (right)
    bar_idx = 0
    for col_key, title, ylabel, lower in active_bar:
        ax = fig.add_subplot(gs[0, bar_idx])
        plot_bar_panel(ax, data, scheds, metadata, col_key, title, ylabel, lower)
        bar_idx += 1

    # Bottom row: schedule delay centered (span middle half)
    gs_bottom = gridspec.GridSpecFromSubplotSpec(1, 4, subplot_spec=gs[1, :])
    ax_ts = fig.add_subplot(gs_bottom[0, 1:3])
    for col, title, ylabel in active_ts:
        plot_timeseries_panel(ax_ts, data, scheds, col, title, ylabel)

    # Shared legend at top
    handles, labels = [], []
    for sched in scheds:
        handles.append(plt.Line2D([0], [0], color=color_for(sched), linewidth=2))
        labels.append(label_for(sched))

    fig.legend(
        handles, labels,
        loc="upper center",
        ncol=len(scheds),
        fontsize=9,
        frameon=True,
        fancybox=True,
        shadow=False,
        borderpad=0.4,
        bbox_to_anchor=(0.5, 1.02),
        facecolor=BG_COLOR,
        edgecolor=ACCENT_COLOR,
        labelcolor=TEXT_COLOR,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save combined as EPS
    eps_path = output_path.with_suffix(".eps")
    fig.savefig(eps_path, format="eps", bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"Saved combined EPS: {eps_path}")

    # Also save as PDF
    fig.savefig(output_path, bbox_inches="tight", dpi=300, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Saved combined PDF: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate combined summary figure for publication"
    )
    parser.add_argument("csv_files", nargs="+", help="CSV files from collect.py")
    parser.add_argument(
        "--output", default="plots/combined.pdf",
        help="Output file path (default: plots/combined.pdf)"
    )
    parser.add_argument(
        "--schedulers", nargs="+", default=None,
        help="Explicit scheduler order"
    )

    args = parser.parse_args()
    data = load_data(args.csv_files)
    metadata = load_metadata(args.csv_files)
    scheds = args.schedulers or schedulers_in(data)

    print(f"Schedulers: {', '.join(scheds)}")
    print(f"Total rows: {len(data)}")

    generate_combined_figure(data, scheds, metadata, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
