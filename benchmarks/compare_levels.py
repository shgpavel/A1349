#!/usr/bin/env python3
"""
compare_levels.py - Cross-workload-level comparative plots.

Reads aggregates from results/<session>/<level>/<sched>_aggregate.csv and
oneshot_summary.json; produces:
  - Grouped bar charts: metric per scheduler, grouped by level (with CI err bars)
  - Line plots: metric vs level ordinal, one line per scheduler
  - Summary table PDF: scheduler × level × metric grid
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd
from scipy import stats

matplotlib.use("Agg")
# TrueType font embedding — default Type 3 fonts crash some PDF viewers.
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt

CI_LEVEL = 0.95
WORKLOAD_PHASES = ("hackbench", "sysbench", "schbench")

# Cache raw run frames per (level_dir, sched) so we only parse CSVs once
# across all metrics. Keyed by resolved str(path).
_RUN_CACHE: dict[tuple[str, str], list[pd.DataFrame]] = {}

SCHED_COLORS = {
    "default": "#1f77b4",
    "s3": "#ff7f0e",
    "LAVD": "#8c564b",
    "s4": "#d62728",
}
SCHED_LABELS = {
    "default": "Linux EEVDF (baseline)",
    "s3": "scx_EEVDF",
    "LAVD": "scx_LAVD",
    "s4": "scx_auction",
}
SCHED_ORDER = ["default", "s3", "LAVD", "s4"]
LEVEL_ORDER = ["light", "moderate", "stress"]

# Metrics to compare across levels.
# (base column, label, lower_is_better or None)
TS_METRICS = [
    ("sched_delay_avg_ns", "Sched Delay avg (ns)", True),
    ("sched_delay_p99_ns", "Sched Delay p99 (ns)", True),
    ("runqueue_avg_ns", "Runqueue avg (ns)", True),
    ("runqueue_p99_ns", "Runqueue p99 (ns)", True),
    ("wakeup_p99_ns", "Wakeup p99 (ns)", True),
    ("preemption_p99_ns", "Preemption p99 (ns)", True),
    ("idle_wakeup_p99_ns", "Idle Wakeup p99 (ns)", True),
    ("migration_p99_ns", "Migration p99 (ns)", True),
    ("slice_avg_ns", "Slice Duration avg (ns)", None),
    ("cpu_util_pct", "CPU Utilization (%)", None),
    ("ctx_switches_per_sec", "Context Switches/s", None),
    ("power_watts", "Power (W)", True),
]

ONESHOT_METRICS = [
    ("total_energy_joules", "Total CPU Energy (J)", True),
    ("hackbench_time_sec", "Hackbench time (s)", True),
    ("sysbench_tps", "Sysbench OLTP tps", False),
    ("sysbench_qps", "Sysbench OLTP qps", False),
    ("schbench_wakeup_p99_0_usec", "schbench Wakeup p99 (us)", True),
    ("schbench_wakeup_p99_9_usec", "schbench Wakeup p99.9 (us)", True),
    ("schbench_request_p99_0_usec", "schbench Request p99 (us)", True),
    ("schbench_avg_rps", "schbench avg RPS", False),
]


def color_for(s):
    return SCHED_COLORS.get(s, "#7f7f7f")


def label_for(s):
    return SCHED_LABELS.get(s, s)


def discover(session_root):
    """Return {level: {sched: aggregate_csv_path}}, {level: oneshot_summary dict}."""
    aggs = {}
    oneshots = {}
    for lvl_dir in session_root.iterdir():
        if not lvl_dir.is_dir():
            continue
        lvl = lvl_dir.name
        csvs = sorted(lvl_dir.glob("*_aggregate.csv"))
        if not csvs:
            continue
        aggs[lvl] = {}
        for c in csvs:
            sched = c.stem[: -len("_aggregate")]
            aggs[lvl][sched] = c
        sp = lvl_dir / "oneshot_summary.json"
        if sp.exists():
            try:
                oneshots[lvl] = json.loads(sp.read_text())
            except json.JSONDecodeError:
                oneshots[lvl] = {}
    return aggs, oneshots


def levels_present(aggs):
    present = set(aggs)
    return [lv for lv in LEVEL_ORDER if lv in present] + sorted(present - set(LEVEL_ORDER))


def scheds_present(aggs):
    s = set()
    for per_sched in aggs.values():
        s.update(per_sched.keys())
    return [x for x in SCHED_ORDER if x in s] + sorted(s - set(SCHED_ORDER))


def _load_run_frames(level_dir, sched):
    """Return cached list of raw per-run DataFrames (workload phases only)."""
    key = (str(level_dir), sched)
    if key in _RUN_CACHE:
        return _RUN_CACHE[key]

    frames = []
    for run_dir in sorted(level_dir.glob("run*")):
        sched_dir = run_dir / sched
        if not sched_dir.is_dir():
            continue
        csvs = sorted(sched_dir.glob("*.csv"))
        if not csvs:
            continue
        try:
            df = pd.read_csv(csvs[-1])
        except Exception:
            continue
        if "phase" in df.columns:
            df = df[df["phase"].isin(WORKLOAD_PHASES)].copy()
        frames.append(df)

    _RUN_CACHE[key] = frames
    return frames


def time_mean_ci(csv_path, base_col):
    """Per-run workload-phase means of base_col → t-interval across runs.

    Honest cross-level summary: for each run, compute the mean of base_col over
    workload-phase rows (one scalar per run), then t 95% CI across those N
    per-run scalars. Replaces the previous mean-of-per-timepoint-CIs which
    mixed within-run and between-run variance arbitrarily.

    The `csv_path` argument is still the aggregate CSV (kept for back-compat
    with existing callers); we derive `level_dir` and `sched` from it.
    """
    csv_path = Path(csv_path)
    level_dir = csv_path.parent
    sched = csv_path.stem[: -len("_aggregate")] if csv_path.stem.endswith("_aggregate") else csv_path.stem

    frames = _load_run_frames(level_dir, sched)
    if not frames:
        return None, None, None

    per_run_means = []
    for df in frames:
        if base_col not in df.columns:
            continue
        vals = pd.to_numeric(df[base_col], errors="coerce").dropna()
        if vals.empty:
            continue
        per_run_means.append(float(vals.mean()))

    if not per_run_means:
        return None, None, None

    arr = np.asarray(per_run_means, dtype=float)
    mean = float(arr.mean())
    if arr.size < 2:
        return mean, mean, mean
    std = float(arr.std(ddof=1))
    sem = std / np.sqrt(arr.size)
    lo, hi = stats.t.interval(CI_LEVEL, df=arr.size - 1, loc=mean, scale=sem)
    return mean, float(lo), float(hi)


# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------


BASELINE_SCHED = "default"


def grouped_bar(ax, scheds, levels, values, errs_lo, errs_hi, title, ylabel, lower_better):
    """values[sched][level] = float; errs_* same shape.

    Annotates each bar with its value on top, plus a %-diff-vs-baseline
    (Linux EEVDF / `default`) inside the bar — same style as figure_combined.
    """
    n_lvl = len(levels)
    width = 0.8 / n_lvl
    x = np.arange(len(scheds))

    lvl_colors = plt.cm.viridis(np.linspace(0.15, 0.85, n_lvl))

    bar_specs = []  # (rect, sched, lvl, val)
    for i, lvl in enumerate(levels):
        vals = [values[s].get(lvl, np.nan) for s in scheds]
        elo = [errs_lo[s].get(lvl, 0) for s in scheds]
        ehi = [errs_hi[s].get(lvl, 0) for s in scheds]
        offsets = x - 0.4 + width * (i + 0.5)
        rects = ax.bar(
            offsets,
            vals,
            width,
            color=lvl_colors[i],
            label=lvl,
            edgecolor="black",
            linewidth=0.4,
            yerr=[elo, ehi],
            capsize=3,
            error_kw={"elinewidth": 0.8},
        )
        for rect, s, v in zip(rects, scheds, vals, strict=True):
            bar_specs.append((rect, s, lvl, v))

    # Value on top + %-diff-vs-baseline inside non-baseline bars.
    fontsize_val = max(5, 7 - n_lvl // 2)
    for rect, sched, lvl, val in bar_specs:
        if val is None or (isinstance(val, float) and np.isnan(val)):
            continue
        h = rect.get_height()
        cx = rect.get_x() + rect.get_width() / 2
        # Value label on top
        ax.text(
            cx,
            h,
            f"{val:.2f}" if abs(val) < 1000 else f"{val:.0f}",
            ha="center",
            va="bottom",
            fontsize=fontsize_val,
            fontweight="bold",
            color="#000000",
        )
        # %-diff vs baseline at same level
        if sched == BASELINE_SCHED:
            continue
        base = values.get(BASELINE_SCHED, {}).get(lvl)
        if base is None or (isinstance(base, float) and (np.isnan(base) or base == 0)):
            continue
        pct = (val - base) / abs(base) * 100
        ax.text(
            cx,
            h * 0.5,
            f"{pct:+.1f}%",
            ha="center",
            va="center",
            fontsize=fontsize_val,
            fontweight="bold",
            color="#000000",
        )

    # Headroom for top labels.
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(ymin, ymax * 1.15)

    note = (
        " (lower is better)"
        if lower_better
        else (" (higher is better)" if lower_better is False else "")
    )
    ax.set_title(title + note, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels([label_for(s) for s in scheds], rotation=0, fontsize=8)
    ax.grid(True, alpha=0.3, axis="y")
    ax.legend(title=f"Level (% vs {label_for(BASELINE_SCHED)})", fontsize=7, title_fontsize=8)


def plot_grouped_bar_metric(
    aggs, oneshots, scheds, levels, metric_kind, base_col, label, lower_better, output_dir, fname
):
    values = {s: {} for s in scheds}
    errs_lo = {s: {} for s in scheds}
    errs_hi = {s: {} for s in scheds}

    any_data = False
    for lvl in levels:
        if metric_kind == "ts":
            per_sched = aggs.get(lvl, {})
            for s in scheds:
                if s not in per_sched:
                    continue
                m, lo, hi = time_mean_ci(per_sched[s], base_col)
                if m is None:
                    continue
                values[s][lvl] = m
                errs_lo[s][lvl] = max(0, m - lo)
                errs_hi[s][lvl] = max(0, hi - m)
                any_data = True
        else:  # oneshot
            per_sched = oneshots.get(lvl, {})
            for s in scheds:
                entry = per_sched.get(s, {}).get(base_col)
                if not entry or entry.get("mean") is None:
                    continue
                m = entry["mean"]
                lo = entry.get("ci_lo", m)
                hi = entry.get("ci_hi", m)
                values[s][lvl] = m
                errs_lo[s][lvl] = max(0, m - lo)
                errs_hi[s][lvl] = max(0, hi - m)
                any_data = True

    if not any_data:
        return

    fig, ax = plt.subplots(figsize=(9, 5))
    grouped_bar(ax, scheds, levels, values, errs_lo, errs_hi, label, label, lower_better)
    fig.tight_layout()
    path = output_dir / f"{fname}.pdf"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {path.name}")


def plot_line_vs_level(
    aggs, oneshots, scheds, levels, metric_kind, base_col, label, lower_better, output_dir, fname
):
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(levels))
    any_data = False

    for s in scheds:
        ys, los, his = [], [], []
        for lvl in levels:
            if metric_kind == "ts":
                agg = aggs.get(lvl, {}).get(s)
                if agg:
                    m, lo, hi = time_mean_ci(agg, base_col)
                else:
                    m = lo = hi = None
            else:
                entry = oneshots.get(lvl, {}).get(s, {}).get(base_col)
                if entry and entry.get("mean") is not None:
                    m = entry["mean"]
                    lo = entry.get("ci_lo", m)
                    hi = entry.get("ci_hi", m)
                else:
                    m = lo = hi = None
            ys.append(m if m is not None else np.nan)
            los.append(lo if lo is not None else np.nan)
            his.append(hi if hi is not None else np.nan)

        if not any(v is not None and not np.isnan(v) for v in ys):
            continue

        ax.plot(x, ys, marker="o", color=color_for(s), label=label_for(s), linewidth=1.5)

        # fill_between emits warnings on NaN pairs; mask them out. Masked
        # segments are simply skipped, the line plot still shows the point.
        los_arr = np.asarray(los, dtype=float)
        his_arr = np.asarray(his, dtype=float)
        valid = ~(np.isnan(los_arr) | np.isnan(his_arr))
        if valid.any():
            ax.fill_between(
                x[valid],
                los_arr[valid],
                his_arr[valid],
                color=color_for(s),
                alpha=0.12,
                linewidth=0,
            )
        any_data = True

    if not any_data:
        plt.close(fig)
        return

    note = (
        " (lower is better)"
        if lower_better
        else (" (higher is better)" if lower_better is False else "")
    )
    ax.set_title(label + note, fontsize=10)
    ax.set_ylabel(label, fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(levels, fontsize=9)
    ax.set_xlabel("Workload Level", fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    path = output_dir / f"{fname}.pdf"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {path.name}")


def write_summary_table(aggs, oneshots, scheds, levels, output_dir):
    """One PDF: rows = metric, cols = per (level, sched) cell with mean (CI)."""
    rows = []
    headers = ["Metric"] + [f"{lv}\n{label_for(s)}" for lv in levels for s in scheds]

    def fmt(m, lo, hi):
        if m is None or np.isnan(m):
            return "—"
        if lo is None or hi is None:
            return f"{m:.1f}"
        return f"{m:.1f}\n[{lo:.1f},{hi:.1f}]"

    for base, label, _lower in TS_METRICS:
        row = [label]
        any_cell = False
        for lvl in levels:
            for s in scheds:
                agg = aggs.get(lvl, {}).get(s)
                if agg:
                    m, lo, hi = time_mean_ci(agg, base)
                    cell = fmt(m, lo, hi)
                    if cell != "—":
                        any_cell = True
                else:
                    cell = "—"
                row.append(cell)
        if any_cell:
            rows.append(row)

    for base, label, _lower in ONESHOT_METRICS:
        row = [label]
        any_cell = False
        for lvl in levels:
            for s in scheds:
                entry = oneshots.get(lvl, {}).get(s, {}).get(base)
                if entry and entry.get("mean") is not None:
                    cell = fmt(entry["mean"], entry.get("ci_lo"), entry.get("ci_hi"))
                    any_cell = True
                else:
                    cell = "—"
                row.append(cell)
        if any_cell:
            rows.append(row)

    if not rows:
        return

    fig_w = max(12, 1.2 * len(headers))
    fig_h = 0.55 * len(rows) + 2
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.axis("off")
    ax.set_title("Cross-Level Benchmark Summary (mean [95% CI])", fontsize=11, pad=12)
    tbl = ax.table(cellText=rows, colLabels=headers, loc="center", cellLoc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(7)
    tbl.scale(1, 1.5)

    for j in range(len(headers)):
        c = tbl[0, j]
        c.set_facecolor("#d9e2f3")
        c.set_text_props(weight="bold")
    for i in range(len(rows)):
        tbl[i + 1, 0].set_text_props(ha="left")

    fig.tight_layout()
    path = output_dir / "summary_grid.pdf"
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved {path.name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_root", help="Path to results/<session>/")
    ap.add_argument("--output", default="plots/comparative")
    args = ap.parse_args()

    root = Path(args.session_root).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    aggs, oneshots = discover(root)
    if not aggs:
        print(f"No aggregates under {root}", file=sys.stderr)
        return 1

    levels = levels_present(aggs)
    scheds = scheds_present(aggs)

    print(f"Levels: {levels}")
    print(f"Schedulers: {scheds}")
    print(f"Output: {output_dir}")

    # Grouped bars + line-vs-level for each metric
    for base, label, lower in TS_METRICS:
        plot_grouped_bar_metric(
            aggs, oneshots, scheds, levels, "ts", base, label, lower, output_dir, f"bar_{base}"
        )
        plot_line_vs_level(
            aggs, oneshots, scheds, levels, "ts", base, label, lower, output_dir, f"line_{base}"
        )

    for base, label, lower in ONESHOT_METRICS:
        plot_grouped_bar_metric(
            aggs, oneshots, scheds, levels, "oneshot", base, label, lower, output_dir, f"bar_{base}"
        )
        plot_line_vs_level(
            aggs,
            oneshots,
            scheds,
            levels,
            "oneshot",
            base,
            label,
            lower,
            output_dir,
            f"line_{base}",
        )

    write_summary_table(aggs, oneshots, scheds, levels, output_dir)
    print("Comparative plots done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
