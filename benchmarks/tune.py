#!/usr/bin/env python3
"""
tune.py - Staged hyperparameter sweep for scx_A1349 against the default scheduler.

Each stage runs a set of A1349 flag configs plus the kernel default, interleaved
in a fresh random order every round, through collect.py (the same measurement
path as run_suite.py) with shortened phases by default.

Score per (config, level): geomean over five metrics of the median-over-rounds
ratio vs the reference (the kernel default unless --ref), oriented so > 1 is
better. Overall score: geomean over levels. Medians of a few short rounds hide
bimodal tails; validate a finalist with full-length phases (--sysbench 10
--schbench 30 --cooldown 3 --rounds 5) and look at the per-run values.

Usage:
    tune.py STAGE --bin BIN --cfg label='--flags ...' [--cfg ...]
            [--rounds 3] [--levels light,moderate,stress]
    tune.py STAGE --report          re-score an existing stage

A --cfg value starting with '@/path/to/bin' runs that binary instead of --bin.
Stage data lands in results/tune/STAGE/<level>/run<NN>/<label>/ (aggregate.py
can read it). hackbench and sysbench must be on PATH; attaching needs sudo.
"""

import argparse
import json
import math
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COLLECT = REPO / "benchmarks" / "collect.py"
SL_BIN = REPO / "benchmarks" / "build" / "sched_latency"
TUNE_ROOT = REPO / "results" / "tune"

METRICS = [
    ("hackbench_time_sec", -1),
    ("sysbench_tps", +1),
    ("schbench_avg_rps", +1),
    ("schbench_request_p99_0_usec", -1),
    ("schbench_wakeup_p99_0_usec", -1),
]
COUNTERS = ("enq_p", "enq_e", "enq_starved", "spill", "steal",
            "exile", "keep_prev", "starved_aged", "demote")
STAT_RE = re.compile(r"(\w+)=([\d.]+)")


def wrapper(stage_dir, label, binary, flags):
    """collect.py runs --sched-bin without arguments: bake the flags into a script."""
    if flags.startswith("@"):
        binary, _, flags = flags[1:].partition(" ")
    w = stage_dir / "wrappers" / f"{label}.sh"
    w.parent.mkdir(parents=True, exist_ok=True)
    w.write_text(f"#!/bin/sh\nexec {Path(binary).resolve()} {flags}\n")
    w.chmod(0o755)
    return w


def collect(out, label, level, sched_bin, a):
    cmd = [
        sys.executable, str(COLLECT),
        "--scheduler", label,
        "--interval", "1", "--warmup", "0",
        "--workload-level", level,
        "--phase-cooldown", str(a.cooldown),
        "--sysbench-duration", str(a.sysbench),
        "--schbench-duration", str(a.schbench),
        "--output", str(out),
        "--sched-latency-bin", str(SL_BIN),
    ]
    if sched_bin:
        cmd += ["--sched-bin", str(sched_bin), "--sched-ops", "scx_A1349"]
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "collect.log", "w") as log:
        return subprocess.call(cmd, stdout=log, stderr=subprocess.STDOUT)


def load_run(d):
    """One-shot results of a complete run, plus A1349's exit counters if logged."""
    metas = sorted(d.glob("*.meta.json"))
    if not metas:
        return None
    m = json.loads(metas[-1].read_text())
    if not (m.get("complete") and m.get("sched_ext_ok")) or not m["oneshot_runs"]:
        return None
    r = dict(m["oneshot_runs"][0])
    log = d / "scheduler.log"
    if log.exists():
        lines = [ln for ln in log.read_text(errors="replace").splitlines()
                 if ln.startswith("scx_A1349 stats:")]
        if lines:
            r["stats"] = {k: float(v) for k, v in STAT_RE.findall(lines[-1])}
    return r


def gmean(xs):
    xs = [x for x in xs if x and x > 0]
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else float("nan")


def report(stage_dir):
    plan = json.loads((stage_dir / "plan.json").read_text())
    ref = plan.get("ref", "default")
    labels = ([] if plan.get("no_default") else ["default"]) + [c[0] for c in plan["cfgs"]]
    levels = plan["levels"]
    data = {}
    for lv in levels:
        for lb in labels:
            runs = []
            for d in sorted((stage_dir / lv).glob(f"r*/{lb}")):
                r = load_run(d)
                if r:
                    runs.append(r)
            data[(lv, lb)] = runs

    def med(lv, lb, key):
        vals = [r[key] for r in data[(lv, lb)] if key in r]
        return statistics.median(vals) if vals else None

    out = {"levels": {}, "overall": {}}
    print(f"\n### stage {stage_dir.name}  ({plan['rounds']} rounds, ratios vs {ref})")
    for lv in levels:
        print(f"\n[{lv}]")
        print(f"{'config':<14}{'n':>3}" + "".join(f"{m[0][:22]:>24}" for m in METRICS)
              + f"{'score':>8}")
        out["levels"][lv] = {}
        for lb in labels:
            cells, ratios = [], []
            for key, sign in METRICS:
                v, b = med(lv, lb, key), med(lv, ref, key)
                if not v or not b:
                    cells.append(f"{'-':>24}")
                    continue
                ratio = (v / b) if sign > 0 else (b / v)
                ratios.append(ratio)
                cells.append(f"{v:>14.2f} ({ratio:5.2f})")
            sc = gmean(ratios)
            out["levels"][lv][lb] = {"score": sc, "n": len(data[(lv, lb)]),
                                     **{k: med(lv, lb, k) for k, _ in METRICS}}
            print(f"{lb:<14}{len(data[(lv, lb)]):>3}" + "".join(cells) + f"{sc:>8.3f}")
    print("\n[overall]  geomean of per-level scores")
    for lb in labels:
        sc = gmean([out["levels"][lv][lb]["score"] for lv in levels])
        out["overall"][lb] = sc
        print(f"  {lb:<14}{sc:7.3f}")
    counters = {}
    for lb in labels:
        st = [r["stats"] for lv in levels for r in data[(lv, lb)] if "stats" in r]
        if st:
            counters[lb] = {k: statistics.median(s.get(k, 0) for s in st) for k in COUNTERS}
    if counters:
        print("\n[A1349 counters, median per run]")
        for lb, c in counters.items():
            print(f"  {lb:<14}" + " ".join(f"{k}={int(v)}" for k, v in c.items()))
    (stage_dir / "report.json").write_text(json.dumps(out, indent=2))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Staged hyperparameter sweep for scx_A1349 against the default scheduler.")
    ap.add_argument("stage")
    ap.add_argument("--bin", help="scx_A1349 binary the --cfg flags apply to")
    ap.add_argument("--cfg", action="append", default=[], metavar="LABEL=FLAGS")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--levels", default="light,moderate,stress")
    ap.add_argument("--sysbench", type=int, default=6, help="sysbench seconds")
    ap.add_argument("--schbench", type=int, default=12, help="schbench seconds")
    ap.add_argument("--cooldown", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=1349)
    ap.add_argument("--ref", default="default", help="label the ratios are taken against")
    ap.add_argument("--no-default", action="store_true",
                    help="don't run the kernel default (use with --ref)")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()

    stage_dir = TUNE_ROOT / a.stage
    if a.report:
        report(stage_dir)
        return 0
    if not a.bin and any(not fl.startswith("@") for _, fl in
                         (c.split("=", 1) for c in a.cfg)):
        ap.error("--bin is required unless every --cfg names its own binary with '@'")

    cfgs = [c.split("=", 1) for c in a.cfg]
    levels = a.levels.split(",")
    stage_dir.mkdir(parents=True, exist_ok=True)
    (stage_dir / "plan.json").write_text(json.dumps(
        {"bin": a.bin, "cfgs": cfgs, "levels": levels, "rounds": a.rounds,
         "ref": a.ref, "no_default": a.no_default}, indent=2))
    entries = ([] if a.no_default else [("default", None)]) + [
        (lb, wrapper(stage_dir, lb, a.bin, fl)) for lb, fl in cfgs]

    rng = random.Random(a.seed)
    jobs = [(rd, lv) for rd in range(1, a.rounds + 1) for lv in levels]
    total = len(jobs) * len(entries)
    n = 0
    t0 = time.monotonic()
    for rd, lv in jobs:
        order = list(entries)
        rng.shuffle(order)
        for lb, sb in order:
            n += 1
            out = stage_dir / lv / f"run{rd:02d}" / lb
            rc = collect(out, lb, lv, sb, a)
            el = time.monotonic() - t0
            print(f"[{n}/{total}] r{rd} {lv:<9}{lb:<14} rc={rc}  "
                  f"elapsed={el/60:.1f}m eta={el/n*(total-n)/60:.1f}m", flush=True)
            time.sleep(2)
    report(stage_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
