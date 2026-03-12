#!/usr/bin/env python3
"""
Run the benchmark comparison suite for default, s3, and s3+ schedulers.
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def run(cmd, sudo=False):
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", "--preserve-env=PATH", *cmd]
    print("+", " ".join(str(part) for part in cmd), flush=True)
    subprocess.run(cmd, check=True)


def newest_csv(output_dir: Path) -> Path:
    csvs = sorted(output_dir.glob("*.csv"), key=lambda path: path.stat().st_mtime)
    if not csvs:
        raise FileNotFoundError(f"no CSV files found in {output_dir}")
    return csvs[-1]


def main():
    parser = argparse.ArgumentParser(
        description="Run the benchmark comparison suite for default, s3, and s3+"
    )
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--interval", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--cooldown", type=int, default=30,
                        help="Seconds to wait between scheduler runs (default: 30)")
    parser.add_argument("--results-root", default="results")
    parser.add_argument("--plots-root", default="plots")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    collect_py = repo_root / "benchmarks" / "collect.py"
    visualize_py = repo_root / "benchmarks" / "visualize.py"
    sched_latency_bin = repo_root / "benchmarks" / "build" / "sched_latency"

    schedulers = [
        ("default", None),
        ("s3", repo_root / "impl" / "s3" / "build" / "scheds" / "c" / "scx_eevdf"),
        ("s3+", repo_root / "impl" / "s3+" / "build" / "scheds" / "c" / "scx_eevdf"),
    ]

    missing_bins = [
        str(path) for _, path in schedulers if path is not None and not path.is_file()
    ]
    if not sched_latency_bin.is_file():
        missing_bins.append(str(sched_latency_bin))
    if missing_bins:
        print("Missing benchmark binaries:", file=sys.stderr)
        for path in missing_bins:
            print(f"  {path}", file=sys.stderr)
        print("Run `make benchmarks-build` first.", file=sys.stderr)
        return 1

    session = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = (repo_root / args.results_root / session).resolve()
    plots_dir = (repo_root / args.plots_root / session).resolve()
    csv_paths = []

    print(f"Session: {session}")
    print(f"Results: {results_dir}")
    print(f"Plots:   {plots_dir}")

    for idx, (label, sched_bin) in enumerate(schedulers):
        # Cooldown between runs to reduce temporal bias
        if idx > 0 and args.cooldown > 0:
            print(f"Cooldown: waiting {args.cooldown}s before next run...", flush=True)
            time.sleep(args.cooldown)

        output_dir = results_dir / label
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            str(collect_py),
            "--scheduler",
            label,
            "--duration",
            str(args.duration),
            "--interval",
            str(args.interval),
            "--warmup",
            str(args.warmup),
            "--output",
            str(output_dir),
            "--sched-latency-bin",
            str(sched_latency_bin),
        ]
        if sched_bin is not None:
            cmd.extend(["--sched-bin", str(sched_bin)])

        run(cmd, sudo=True)

        # Fix ownership of results created by sudo back to the invoking user.
        real_uid = os.environ.get("SUDO_UID")
        real_gid = os.environ.get("SUDO_GID")
        if real_uid is None and os.geteuid() != 0:
            real_uid = str(os.getuid())
            real_gid = str(os.getgid())
        if real_uid is not None:
            run(
                ["chown", "-R", f"{real_uid}:{real_gid or real_uid}", str(output_dir)],
                sudo=True,
            )

        csv_paths.append(newest_csv(output_dir))

    plots_dir.mkdir(parents=True, exist_ok=True)
    run(
        [
            sys.executable,
            str(visualize_py),
            *[str(path) for path in csv_paths],
            "--output",
            str(plots_dir),
            "--schedulers",
            "default",
            "s3",
            "s3+",
            "--require-schedulers",
        ]
    )

    print("Benchmark suite complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
