#!/usr/bin/env python3
"""
aggregate.py - Aggregate N runs per (level, scheduler) into mean/std/CI.

Input layout:
    results/<session>/<level>/run<NN>/<sched>/{*.csv,*.meta.json}

Output (written into <level>/):
    <sched>_aggregate.csv   - time series with *_mean/*_std/*_ci_lo/*_ci_hi
    oneshot_summary.json    - per-sched hackbench/sysbench mean/std/CI

Student's t 95% CI (honest small-N; bootstrap under-dispersed at N=3).
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

CI_LEVEL = 0.95


# Columns that are time-varying; we align by (phase, iter, phase_elapsed) and
# aggregate per row. Everything except these is ignored for time-series
# aggregation.
NON_NUMERIC_COLS = {"timestamp", "scheduler", "phase"}
KEY_COL = "elapsed_s"

# Only these phases carry workload signal. warmup + cooldown dilute means.
WORKLOAD_PHASES = ("hackbench", "sysbench", "schbench")


def t_ci(values):
    """Return (mean, std, ci_lo, ci_hi) via Student's t 95% interval.

    Student's t is the honest small-sample choice: with N=3 runs, percentile
    bootstrap just replays the sample values and reports a narrower CI than
    is justified. t-interval respects the degrees-of-freedom penalty.
    For N<2, CI collapses to the point estimate.
    """
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    n = values.size
    if n == 0:
        return np.nan, np.nan, np.nan, np.nan
    mean = float(values.mean())
    if n < 2:
        return mean, 0.0, mean, mean
    std = float(values.std(ddof=1))
    sem = std / np.sqrt(n)
    lo, hi = stats.t.interval(CI_LEVEL, df=n - 1, loc=mean, scale=sem)
    return mean, std, float(lo), float(hi)


def aggregate_timeseries(run_csvs):
    """Align by (phase, iter, phase_elapsed) across runs; per-cell mean/std/CI.

    Filters out warmup + cooldown so their idle noise doesn't bias workload
    means. Within each (run, iter, phase), elapsed_s is offset to 0 and
    snapped to integer seconds so grouping across runs is phase-relative —
    "second 3 of hackbench iter 1" aggregates cleanly even when prior phase
    durations varied per scheduler.

    Emits a synthetic monotonic `elapsed_s` (phases concatenated in canonical
    order with a 1s visual gap) so downstream plotters that key on elapsed_s
    keep working without change.
    """
    frames = []
    intervals = []
    for i, path in enumerate(run_csvs):
        try:
            df = pd.read_csv(path)
        except Exception as e:
            print(f"  skip {path}: {e}", file=sys.stderr)
            continue
        df["_run"] = i
        frames.append(df)

        # Read sibling meta.json for the sampling interval so cross-run
        # grouping works at any interval, not just 1s.
        csv_path = Path(path)
        meta_path = csv_path.with_suffix("").with_suffix(".meta.json")
        if not meta_path.exists():
            # Fallback: match by stem prefix so composed dirs with multiple
            # scheduler metas don't hand us the wrong one.
            stem_prefix = csv_path.stem
            candidates = sorted(csv_path.parent.glob(f"{stem_prefix}*.meta.json"))
            meta_path = candidates[-1] if candidates else None
        if meta_path and meta_path.exists():
            try:
                with open(meta_path) as f:
                    intervals.append(float(json.load(f).get("interval") or 1))
            except (OSError, json.JSONDecodeError, TypeError):
                intervals.append(1.0)
        else:
            intervals.append(1.0)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    if KEY_COL not in combined.columns or "phase" not in combined.columns:
        return pd.DataFrame()

    combined[KEY_COL] = pd.to_numeric(combined[KEY_COL], errors="coerce")
    combined = combined.dropna(subset=[KEY_COL])
    combined = combined[combined["phase"].isin(WORKLOAD_PHASES)].copy()
    if combined.empty:
        return pd.DataFrame()

    if "iter" in combined.columns:
        combined["iter"] = (
            pd.to_numeric(combined["iter"], errors="coerce").fillna(1).astype(int)
        )
    else:
        combined["iter"] = 1

    # Phase-relative tick, expressed in sample units (not seconds) so intervals
    # of 0.5s, 2s etc. still align row-for-row across runs. Requires all runs
    # in one (level, sched) group to use the same interval — enforce that.
    if intervals and len(set(round(i, 6) for i in intervals)) > 1:
        print(
            f"  WARN: mixed sampling intervals {intervals} — aggregate may align wrong",
            file=sys.stderr,
        )
    interval = intervals[0] if intervals else 1.0

    combined["phase_elapsed"] = (
        combined.groupby(["_run", "iter", "phase"])[KEY_COL]
        .transform(lambda s: (s - s.min()) / interval)
        .round()
        .astype(int)
    )

    reserved = {"_run", KEY_COL, "phase", "iter", "phase_elapsed"} | NON_NUMERIC_COLS
    numeric_cols = [c for c in combined.columns if c not in reserved]

    out_rows = []
    grouped = combined.groupby(["phase", "iter", "phase_elapsed"], sort=False)
    for (phase, it, pe), grp in grouped:
        row = {"phase": phase, "iter": int(it), "phase_elapsed": int(pe)}
        for col in numeric_cols:
            vals = pd.to_numeric(grp[col], errors="coerce").to_numpy()
            m, s, lo, hi = t_ci(vals)
            row[f"{col}_mean"] = m
            row[f"{col}_std"] = s
            row[f"{col}_ci_lo"] = lo
            row[f"{col}_ci_hi"] = hi
        out_rows.append(row)

    out = pd.DataFrame(out_rows)
    phase_rank = {p: i for i, p in enumerate(WORKLOAD_PHASES)}
    out["_phase_rank"] = out["phase"].map(phase_rank).astype(int)
    out = out.sort_values(["iter", "_phase_rank", "phase_elapsed"]).reset_index(drop=True)

    # Synthetic elapsed_s in seconds: stack phases with a 1-tick gap between
    # them for plots. phase_elapsed is in sample ticks, so multiply by
    # interval to recover seconds.
    elapsed = []
    accum = 0.0
    prev_key = None
    last_pe = 0
    for _, r in out.iterrows():
        key = (r["iter"], r["_phase_rank"])
        if prev_key is not None and key != prev_key:
            accum += (last_pe + 1) * interval
        elapsed.append(accum + r["phase_elapsed"] * interval)
        last_pe = r["phase_elapsed"]
        prev_key = key
    out[KEY_COL] = elapsed
    return out.drop(columns=["_phase_rank"])


def aggregate_oneshot(meta_files):
    """Per-key mean/std/CI across N runs from meta.json oneshot_runs blocks.

    collect.py writes `oneshot_runs`: list of dicts (one per iteration), each
    with scalar throughput keys (hackbench_time_sec, sysbench_tps, sysbench_qps,
    schbench_*). We flatten across runs × iterations per key.
    """
    per_key = {}
    for mf in meta_files:
        try:
            with open(mf) as f:
                m = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for entry in m.get("oneshot_runs", []):
            if not isinstance(entry, dict):
                continue
            for k, v in entry.items():
                if k == "iter" or not isinstance(v, (int, float)):
                    continue
                per_key.setdefault(k, []).append(float(v))

    result = {}
    for k, vals in per_key.items():
        m, s, lo, hi = t_ci(np.asarray(vals, dtype=float))
        result[k] = {
            "n": len(vals),
            "mean": m,
            "std": s,
            "ci_lo": lo,
            "ci_hi": hi,
        }
    return result


def discover_level_dirs(session_root):
    return sorted([d for d in session_root.iterdir() if d.is_dir() and not d.name.startswith(".")])


def process_level(level_dir):
    """Aggregate every scheduler under a level dir."""
    # Map sched -> [run CSV paths], [meta paths]
    sched_csvs = {}
    sched_metas = {}
    for run_dir in sorted(level_dir.glob("run*")):
        if not run_dir.is_dir():
            continue
        for sched_dir in run_dir.iterdir():
            if not sched_dir.is_dir():
                continue
            csvs = sorted(sched_dir.glob("*.csv"))
            metas = sorted(sched_dir.glob("*.meta.json"))
            if csvs:
                sched_csvs.setdefault(sched_dir.name, []).append(csvs[-1])
            if metas:
                sched_metas.setdefault(sched_dir.name, []).append(metas[-1])

    oneshot_summary = {}
    for sched, csvs in sched_csvs.items():
        print(f"  [{level_dir.name}] {sched}: {len(csvs)} runs")
        agg = aggregate_timeseries(csvs)
        if not agg.empty:
            out = level_dir / f"{sched}_aggregate.csv"
            agg.to_csv(out, index=False)
            print(f"    -> {out.name}")

        metas = sched_metas.get(sched, [])
        oneshot_summary[sched] = aggregate_oneshot(metas)

    with open(level_dir / "oneshot_summary.json", "w") as f:
        json.dump(oneshot_summary, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session_root", help="Path to results/<session>/ directory")
    args = ap.parse_args()

    root = Path(args.session_root).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 1

    level_dirs = [d for d in discover_level_dirs(root) if any(d.glob("run*"))]
    if not level_dirs:
        print(f"No run* subdirs under {root}", file=sys.stderr)
        return 1

    for ld in level_dirs:
        print(f"Aggregating {ld.name}")
        process_level(ld)

    print("Aggregation done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
