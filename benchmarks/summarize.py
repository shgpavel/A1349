#!/usr/bin/env python3
"""
summarize.py - Per-level comparison table for an aggregated session.

Input: a session aggregated by aggregate.py (run_suite.py output, or a
tune.py stage), i.e. <root>/<level>/oneshot_summary.json and
<root>/<level>/<sched>_aggregate.csv.

For every scheduler and level: mean ± 95% CI half-width of the five headline
metrics, the ratio vs the baseline scheduler oriented so > 1 is better, average
RAPL power, and the balanced score (geomean of the five ratios). The overall
score is the geomean over levels.

Usage:
    summarize.py results/<session> [BASELINE]     (BASELINE default: default)
"""

import json
import math
import sys
from pathlib import Path

import pandas as pd

METRICS = [
    ("hackbench_time_sec", -1, "hackbench s"),
    ("sysbench_tps", +1, "sysbench tps"),
    ("schbench_avg_rps", +1, "schbench rps"),
    ("schbench_request_p99_0_usec", -1, "req p99 us"),
    ("schbench_wakeup_p99_0_usec", -1, "wake p99 us"),
]
LEVELS = ("light", "moderate", "stress")


def gmean(xs):
    xs = [x for x in xs if x and x > 0 and not math.isnan(x)]
    return math.exp(sum(map(math.log, xs)) / len(xs)) if xs else float("nan")


def avg_power(level_dir, sched):
    p = level_dir / f"{sched}_aggregate.csv"
    if not p.exists():
        return float("nan")
    df = pd.read_csv(p)
    return df["power_watts_mean"].mean() if "power_watts_mean" in df else float("nan")


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    base = sys.argv[2] if len(sys.argv) > 2 else "default"
    overall = {}
    for lv in LEVELS:
        f = root / lv / "oneshot_summary.json"
        if not f.exists():
            continue
        d = json.loads(f.read_text())
        if base not in d:
            print(f"[{lv}] no '{base}' runs to compare against", file=sys.stderr)
            continue
        print(f"\n[{lv}]")
        print(f"{'sched':<16}" + "".join(f"{m[2]:>26}" for m in METRICS)
              + f"{'W avg':>8}{'score':>8}")
        for s in d:
            cells, ratios = [], []
            for key, sign, _ in METRICS:
                v, b = d[s].get(key), d[base].get(key)
                if not v or not b:
                    cells.append(f"{'-':>26}")
                    continue
                hw = (v["ci_hi"] - v["ci_lo"]) / 2
                r = v["mean"] / b["mean"] if sign > 0 else b["mean"] / v["mean"]
                ratios.append(r)
                cells.append(f"{v['mean']:>10.1f} ±{hw:>7.1f} ({r:4.2f})")
            sc = gmean(ratios)
            overall.setdefault(s, []).append(sc)
            print(f"{s:<16}" + "".join(cells) + f"{avg_power(root / lv, s):>8.1f}{sc:>8.3f}")
    print(f"\n[overall balanced score, geomean over levels; >1 = better than {base}]")
    for s, v in overall.items():
        print(f"  {s:<16}{gmean(v):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
