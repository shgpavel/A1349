#!/usr/bin/env python3
"""
Run scheduler benchmark comparison: N runs × M workload levels × K schedulers.

Per run, scheduler order is randomized to avoid temporal bias (thermals,
background daemons). After all runs, per-(level,sched) CSVs are aggregated
into mean/std/Student's t 95% CI. Per-level plots + cross-level comparative
plots are generated.
"""

import argparse
import atexit
import os
import random
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

DEFAULT_LEVELS = ["light", "moderate", "stress"]

SCHEDULERS = [
    ("default", None),
    ("s3", "impl/s3/build/scheds/c/scx_eevdf"),
    ("s3+", "impl/s3+/build/scheds/c/scx_eevdf"),
    ("LAVD", None),  # filled in from --lavd-bin
    ("s4", "impl/s4/build/scheds/c/scx_auction"),
]


def run(cmd):
    print("+", " ".join(str(part) for part in cmd), flush=True)
    subprocess.run(cmd, check=True)


def prime_sudo():
    """Prompt once for sudo password, then keep credentials alive for the
    duration of the suite. Privileged subprocesses (scx scheduler +
    sched_latency) invoke sudo themselves; this avoids re-prompting mid-run.
    """
    if os.geteuid() == 0:
        return  # already root, nothing to do

    rc = subprocess.call(["sudo", "-v"])
    if rc != 0:
        print("sudo authentication failed", file=sys.stderr)
        sys.exit(1)

    stop = threading.Event()

    def refresh():
        while not stop.wait(60):
            subprocess.call(
                ["sudo", "-n", "-v"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    t = threading.Thread(target=refresh, daemon=True)
    t.start()
    atexit.register(stop.set)


def newest_csv(output_dir):
    csvs = sorted(output_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime)
    if not csvs:
        raise FileNotFoundError(f"no CSV in {output_dir}")
    return csvs[-1]


def resolve(repo_root, s):
    p = Path(s).expanduser()
    if not p.is_absolute():
        p = repo_root / p
    return p.resolve()


def collect_one(
    py,
    collect_py,
    sched_latency_bin,
    label,
    sched_bin,
    level,
    phase_repeats,
    phase_cooldown,
    sysbench_duration,
    schbench_duration,
    interval,
    warmup,
    output_dir,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        py,
        str(collect_py),
        "--scheduler", label,
        "--interval", str(interval),
        "--warmup", str(warmup),
        "--workload-level", level,
        "--phase-repeats", str(phase_repeats),
        "--phase-cooldown", str(phase_cooldown),
        "--sysbench-duration", str(sysbench_duration),
        "--schbench-duration", str(schbench_duration),
        "--output", str(output_dir),
        "--sched-latency-bin", str(sched_latency_bin),
    ]
    if sched_bin is not None:
        cmd.extend(["--sched-bin", str(sched_bin)])
    run(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument(
        "--levels", default=",".join(DEFAULT_LEVELS), help="Comma-separated workload levels"
    )
    ap.add_argument("--phase-repeats", type=int, default=1,
                    help="Repetitions of hackbench→sysbench→schbench per run")
    ap.add_argument("--phase-cooldown", type=float, default=3.0,
                    help="Cooldown seconds between phases and iterations")
    ap.add_argument("--sysbench-duration", type=int, default=10,
                    help="sysbench cpu --time seconds")
    ap.add_argument("--schbench-duration", type=int, default=30,
                    help="schbench -r runtime seconds")
    ap.add_argument("--interval", type=int, default=1)
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--cooldown", type=int, default=3,
                    help="Cooldown between schedulers within a run")
    ap.add_argument("--lavd-bin", default="../scx/target/release/scx_lavd")
    ap.add_argument("--results-root", default="results")
    ap.add_argument("--plots-root", default="plots")
    ap.add_argument(
        "--scheds", default=None, help="Comma-separated subset of schedulers (default: all)"
    )
    ap.add_argument("--seed", type=int, default=None, help="Random seed for scheduler ordering")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    repo_root = Path(__file__).resolve().parent.parent
    bench_dir = repo_root / "benchmarks"
    collect_py = bench_dir / "collect.py"
    aggregate_py = bench_dir / "aggregate.py"
    visualize_py = bench_dir / "visualize.py"
    compare_py = bench_dir / "compare_levels.py"
    sl_bin = bench_dir / "build" / "sched_latency"
    lavd_bin = resolve(repo_root, args.lavd_bin)

    # Build scheduler list with resolved paths
    scheds = []
    for label, relpath in SCHEDULERS:
        if label == "LAVD":
            path = lavd_bin
        elif relpath is None:
            path = None
        else:
            path = repo_root / relpath
        scheds.append((label, path))

    if args.scheds:
        wanted = set(args.scheds.split(","))
        scheds = [s for s in scheds if s[0] in wanted]

    levels = [lv.strip() for lv in args.levels.split(",") if lv.strip()]

    # Sanity: binaries exist
    missing = [str(p) for _, p in scheds if p is not None and not p.is_file()]
    if not sl_bin.is_file():
        missing.append(str(sl_bin))
    if missing:
        print("Missing binaries:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        print("Run `make benchmarks-build` first.", file=sys.stderr)
        return 1

    session = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_root = (repo_root / args.results_root / session).resolve()
    plots_root = (repo_root / args.plots_root / session).resolve()

    print(f"Session:     {session}")
    print(f"Runs:        {args.runs}")
    print(f"Levels:      {levels}")
    print(f"Schedulers:  {[s[0] for s in scheds]}")
    print(f"Results:     {results_root}")
    print(f"Plots:       {plots_root}")

    prime_sudo()

    # Counter-balance level order across runs: randomize the full
    # (level, run_idx) sequence so thermal drift / background daemons
    # don't correlate with any single level. Within each (level, run),
    # the scheduler order is separately randomized.
    session_plan = [(lv, r) for lv in levels for r in range(1, args.runs + 1)]
    rng.shuffle(session_plan)

    for plan_idx, (level, run_idx) in enumerate(session_plan, start=1):
        level_dir = results_root / level
        order = list(scheds)
        rng.shuffle(order)
        print(
            f"\n=== [{plan_idx}/{len(session_plan)}] "
            f"level={level}  run={run_idx}/{args.runs}  "
            f"order={[s[0] for s in order]} ==="
        )

        for i, (label, sched_bin) in enumerate(order):
            if i > 0 and args.cooldown > 0:
                print(f"Cooldown {args.cooldown}s...", flush=True)
                time.sleep(args.cooldown)

            out = level_dir / f"run{run_idx:02d}" / label
            collect_one(
                sys.executable,
                collect_py,
                sl_bin,
                label,
                sched_bin,
                level,
                args.phase_repeats,
                args.phase_cooldown,
                args.sysbench_duration,
                args.schbench_duration,
                args.interval,
                args.warmup,
                out,
            )

    # Aggregation
    print("\n=== Aggregating ===")
    run([sys.executable, str(aggregate_py), str(results_root)])

    # Per-level visualization (reads aggregate CSVs)
    for level in levels:
        print(f"\n=== Plotting level={level} ===")
        level_dir = results_root / level
        plot_dir = plots_root / level
        plot_dir.mkdir(parents=True, exist_ok=True)
        agg_csvs = sorted(level_dir.glob("*_aggregate.csv"))
        if not agg_csvs:
            print(f"  (no aggregates for {level})")
            continue
        run(
            [
                sys.executable,
                str(visualize_py),
                *[str(p) for p in agg_csvs],
                "--output",
                str(plot_dir),
            ]
        )

    # Cross-level comparative plots
    print("\n=== Comparative plots ===")
    comp_dir = plots_root / "comparative"
    comp_dir.mkdir(parents=True, exist_ok=True)
    run([sys.executable, str(compare_py), str(results_root), "--output", str(comp_dir)])

    print("\nSuite complete.")
    print(f"Results: {results_root}")
    print(f"Plots:   {plots_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
