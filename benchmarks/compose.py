#!/usr/bin/env python3
"""
compose.py - Regenerate the newest plot session from the newest available
per-scheduler results across all benchmark sessions.

Example:
  results/
    20260420_195755/light/{default,s3}_aggregate.csv
    20260420_211928/light/{s4}_aggregate.csv

The composed light plots for 20260420_211928 will include default+s3 from the
older session and s4 from the newer session. If s3 also exists in the newer
session, that newer s3 replaces the older one.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

SESSION_RE = re.compile(r"^\d{8}_\d{6}$")
LEVEL_ORDER = ["light", "moderate", "stress"]
SCHED_ORDER = ["default", "scx_EEVDF", "LAVD", "scx_A1349"]


@dataclass(frozen=True)
class SchedulerSelection:
    session: Path
    level_dir: Path
    aggregate_csv: Path


def run(cmd: list[str]) -> None:
    print("+", shlex.join([str(part) for part in cmd]), flush=True)
    subprocess.run(cmd, check=True)


def session_dirs(results_root: Path) -> list[Path]:
    return sorted(
        [
            path
            for path in results_root.iterdir()
            if path.is_dir() and SESSION_RE.match(path.name)
        ],
        key=lambda path: path.name,
    )


def level_sort_key(name: str) -> tuple[int, str]:
    try:
        return LEVEL_ORDER.index(name), name
    except ValueError:
        return len(LEVEL_ORDER), name


def sched_sort_key(name: str) -> tuple[int, str]:
    try:
        return SCHED_ORDER.index(name), name
    except ValueError:
        return len(SCHED_ORDER), name


def read_oneshot_summary(level_dir: Path) -> dict:
    summary_path = level_dir / "oneshot_summary.json"
    if not summary_path.is_file():
        return {}
    try:
        return json.loads(summary_path.read_text())
    except json.JSONDecodeError:
        return {}


def select_latest_sources(results_root: Path) -> tuple[list[Path], dict[str, dict[str, SchedulerSelection]]]:
    sessions = session_dirs(results_root)
    if not sessions:
        raise FileNotFoundError(f"No benchmark sessions under {results_root}")

    selected: dict[str, dict[str, SchedulerSelection]] = {}
    for session in sessions:
        for level_dir in sorted(
            [path for path in session.iterdir() if path.is_dir() and not path.name.startswith(".")],
            key=lambda path: level_sort_key(path.name),
        ):
            for aggregate_csv in sorted(level_dir.glob("*_aggregate.csv")):
                sched = aggregate_csv.stem[: -len("_aggregate")]
                selected.setdefault(level_dir.name, {})[sched] = SchedulerSelection(
                    session=session,
                    level_dir=level_dir,
                    aggregate_csv=aggregate_csv,
                )

    return sessions, selected


def symlink_path(target: Path, link_path: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.symlink_to(target)


def build_composed_session(
    composed_root: Path, selections: dict[str, dict[str, SchedulerSelection]]
) -> dict[str, dict[str, str]]:
    manifest: dict[str, dict[str, str]] = {}

    for level_name, per_sched in sorted(selections.items(), key=lambda item: level_sort_key(item[0])):
        level_out = composed_root / level_name
        level_out.mkdir(parents=True, exist_ok=True)

        merged_summary = {}
        manifest[level_name] = {}

        for sched, selection in sorted(per_sched.items(), key=lambda item: sched_sort_key(item[0])):
            manifest[level_name][sched] = selection.session.name
            symlink_path(selection.aggregate_csv, level_out / selection.aggregate_csv.name)

            oneshot_summary = read_oneshot_summary(selection.level_dir)
            if sched in oneshot_summary:
                merged_summary[sched] = oneshot_summary[sched]

            for run_dir in sorted(selection.level_dir.glob("run*")):
                sched_dir = run_dir / sched
                if sched_dir.is_dir():
                    symlink_path(sched_dir, level_out / run_dir.name / sched)

        if merged_summary:
            (level_out / "oneshot_summary.json").write_text(json.dumps(merged_summary, indent=2))

    return manifest


def reset_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def render_plots(repo_root: Path, composed_root: Path, plots_root: Path) -> None:
    bench_dir = repo_root / "benchmarks"
    visualize_py = bench_dir / "visualize.py"
    compare_py = bench_dir / "compare_levels.py"

    for level_dir in sorted(
        [path for path in composed_root.iterdir() if path.is_dir()],
        key=lambda path: level_sort_key(path.name),
    ):
        aggregate_csvs = sorted(level_dir.glob("*_aggregate.csv"))
        if not aggregate_csvs:
            continue

        output_dir = plots_root / level_dir.name
        reset_output_dir(output_dir)
        run([
            sys.executable,
            str(visualize_py),
            *[str(path) for path in aggregate_csvs],
            "--output",
            str(output_dir),
        ])

    comparative_dir = plots_root / "comparative"
    reset_output_dir(comparative_dir)
    run([sys.executable, str(compare_py), str(composed_root), "--output", str(comparative_dir)])


def main() -> int:
    parser = argparse.ArgumentParser(description="Compose the newest plots from the newest scheduler runs")
    parser.add_argument("--results-root", default="results")
    parser.add_argument("--plots-root", default="plots")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    results_root = (repo_root / args.results_root).resolve()
    plots_root = (repo_root / args.plots_root).resolve()
    if not results_root.is_dir():
        print(f"Results root does not exist: {results_root}", file=sys.stderr)
        return 1

    sessions, selections = select_latest_sources(results_root)
    if not selections:
        print(f"No aggregate CSVs found under {results_root}", file=sys.stderr)
        return 1

    latest_session = sessions[-1]
    latest_plots_root = plots_root / latest_session.name
    latest_plots_root.mkdir(parents=True, exist_ok=True)

    print(f"Latest session: {latest_session.name}")
    for level_name, per_sched in sorted(selections.items(), key=lambda item: level_sort_key(item[0])):
        sources = ", ".join(
            f"{sched}<-{selection.session.name}"
            for sched, selection in sorted(per_sched.items(), key=lambda item: sched_sort_key(item[0]))
        )
        print(f"  {level_name}: {sources}")

    with tempfile.TemporaryDirectory(prefix="compose-benchmarks-") as tmpdir:
        composed_root = Path(tmpdir) / latest_session.name
        manifest = build_composed_session(composed_root, selections)
        (latest_plots_root / "composed_sources.json").write_text(json.dumps(manifest, indent=2))
        render_plots(repo_root, composed_root, latest_plots_root)

    print(f"Composed plots: {latest_plots_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
