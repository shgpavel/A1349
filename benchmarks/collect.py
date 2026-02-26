#!/usr/bin/env python3
"""
collect.py - Scheduler benchmark data collection orchestrator.

Polls multiple metric sources each interval and writes unified CSV output.
All metric sources degrade gracefully if unavailable.

Usage:
    sudo python3 collect.py --scheduler default --duration 300 --interval 1 --output results/
    sudo python3 collect.py --scheduler s3+ --sched-bin ../impl/s3+/build/scheds/c/scx_eevdf --duration 300
    sudo python3 collect.py --probe
"""

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# CSV column definitions
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "timestamp",
    "elapsed_s",
    "scheduler",
    # /proc/stat
    "cpu_util_pct",
    "ctx_switches_per_sec",
    "nr_running",
    # /proc/schedstat
    "timeslices_per_sec",
    "wait_ns_per_sec",
    # RAPL power
    "power_watts",
    # BPF latency (sched_delay)
    "sched_delay_count", "sched_delay_avg_ns",
    "sched_delay_p50_ns", "sched_delay_p95_ns", "sched_delay_p99_ns",
    # BPF latency (runqueue)
    "runqueue_count", "runqueue_avg_ns",
    "runqueue_p50_ns", "runqueue_p95_ns", "runqueue_p99_ns",
    # BPF latency (wakeup)
    "wakeup_count", "wakeup_avg_ns",
    "wakeup_p50_ns", "wakeup_p95_ns", "wakeup_p99_ns",
    # BPF latency (preemption)
    "preemption_count", "preemption_avg_ns",
    "preemption_p50_ns", "preemption_p95_ns", "preemption_p99_ns",
    # BPF context switch counters
    "total_csw_per_sec",
    "voluntary_csw_per_sec",
    "involuntary_csw_per_sec",
    # Throughput
    "hackbench_time_sec",
    "sysbench_events_per_sec",
    # Fairness
    "jain_fairness_index",
]


# ---------------------------------------------------------------------------
# Metric source: /proc/stat
# ---------------------------------------------------------------------------

class ProcStatSource:
    """Reads CPU utilization, context switches, and nr_running from /proc/stat."""

    def __init__(self):
        self.prev_cpu = None
        self.prev_ctxt = None
        self.prev_time = None

    def available(self):
        return os.path.exists("/proc/stat")

    def name(self):
        return "/proc/stat"

    def read(self, interval):
        result = {}
        try:
            with open("/proc/stat") as f:
                lines = f.readlines()
        except OSError:
            return result

        now = time.monotonic()

        for line in lines:
            if line.startswith("cpu "):
                fields = list(map(int, line.split()[1:]))
                # user, nice, system, idle, iowait, irq, softirq, steal
                total = sum(fields[:8]) if len(fields) >= 8 else sum(fields)
                idle = fields[3] if len(fields) > 3 else 0
                if self.prev_cpu is not None:
                    d_total = total - self.prev_cpu[0]
                    d_idle = idle - self.prev_cpu[1]
                    if d_total > 0:
                        result["cpu_util_pct"] = round(
                            100.0 * (1.0 - d_idle / d_total), 2
                        )
                self.prev_cpu = (total, idle)

            elif line.startswith("ctxt "):
                ctxt = int(line.split()[1])
                if self.prev_ctxt is not None and self.prev_time is not None:
                    dt = now - self.prev_time
                    if dt > 0:
                        result["ctx_switches_per_sec"] = round(
                            (ctxt - self.prev_ctxt) / dt, 1
                        )
                self.prev_ctxt = ctxt

            elif line.startswith("procs_running "):
                result["nr_running"] = int(line.split()[1])

        self.prev_time = now
        return result


# ---------------------------------------------------------------------------
# Metric source: /proc/schedstat
# ---------------------------------------------------------------------------

class SchedstatSource:
    """Reads timeslices and wait time from /proc/schedstat."""

    def __init__(self):
        self.prev = None
        self.prev_time = None

    def available(self):
        return os.path.exists("/proc/schedstat")

    def name(self):
        return "/proc/schedstat"

    def read(self, interval):
        result = {}
        try:
            with open("/proc/schedstat") as f:
                lines = f.readlines()
        except OSError:
            return result

        now = time.monotonic()
        total_slices = 0
        total_wait = 0

        for line in lines:
            if line.startswith("cpu"):
                parts = line.split()
                if len(parts) >= 9:
                    # field 8 = timeslices, field 7 = time spent waiting
                    total_slices += int(parts[8])
                    total_wait += int(parts[7])

        if self.prev is not None and self.prev_time is not None:
            dt = now - self.prev_time
            if dt > 0:
                result["timeslices_per_sec"] = round(
                    (total_slices - self.prev[0]) / dt, 1
                )
                result["wait_ns_per_sec"] = round(
                    (total_wait - self.prev[1]) / dt, 0
                )

        self.prev = (total_slices, total_wait)
        self.prev_time = now
        return result


# ---------------------------------------------------------------------------
# Metric source: RAPL power
# ---------------------------------------------------------------------------

class RaplSource:
    """Reads package power from Intel RAPL sysfs."""

    def __init__(self):
        self.paths = []
        self.prev = None
        self.prev_time = None
        self._discover()

    def _discover(self):
        base = Path("/sys/class/powercap")
        if not base.exists():
            return
        for d in sorted(base.iterdir()):
            if d.name.startswith("intel-rapl:") and ":" not in d.name[len("intel-rapl:"):]:
                ej = d / "energy_uj"
                if ej.exists():
                    self.paths.append(ej)

    def available(self):
        return len(self.paths) > 0

    def name(self):
        return "RAPL energy"

    def read(self, interval):
        result = {}
        now = time.monotonic()
        total_uj = 0
        try:
            for p in self.paths:
                with open(p) as f:
                    total_uj += int(f.read().strip())
        except OSError:
            return result

        if self.prev is not None and self.prev_time is not None:
            dt = now - self.prev_time
            if dt > 0:
                d_uj = total_uj - self.prev
                if d_uj < 0:
                    # counter wrapped
                    d_uj += (1 << 32)
                watts = d_uj / (dt * 1e6)
                result["power_watts"] = round(watts, 2)

        self.prev = total_uj
        self.prev_time = now
        return result


# ---------------------------------------------------------------------------
# Metric source: BPF sched_latency subprocess
# ---------------------------------------------------------------------------

class SchedLatencySource:
    """Runs sched_latency -c as a subprocess and parses CSV output."""

    def __init__(self, sched_latency_bin):
        self.bin = sched_latency_bin
        self.proc = None
        self.latest = {}

    def available(self):
        return os.path.isfile(self.bin) and os.access(self.bin, os.X_OK)

    def name(self):
        return "BPF sched_latency"

    def start(self, interval, fairness_file=None):
        if not self.available():
            return
        cmd = [self.bin, "-c", "-i", str(interval)]
        if fairness_file:
            cmd += ["-f", fairness_file]
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            # Skip CSV header
            if self.proc.stdout:
                self.proc.stdout.readline()
        except OSError:
            self.proc = None

    def stop(self):
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def poll(self):
        """Read all available lines and parse the latest batch."""
        if not self.proc or not self.proc.stdout:
            return {}

        result = {}
        # Read available lines (non-blocking via readline with poll)
        import select
        while True:
            rlist, _, _ = select.select([self.proc.stdout], [], [], 0.0)
            if not rlist:
                break
            line = self.proc.stdout.readline()
            if not line:
                break
            self._parse_line(line.strip(), result)

        self.latest = result
        return result

    def _parse_line(self, line, result):
        """Parse one CSV line from sched_latency -c output."""
        # Format: timestamp,type,count,avg_ns,min_ns,max_ns,p50_ns,p95_ns,p99_ns,total_csw,voluntary_csw,involuntary_csw
        parts = line.split(",")
        if len(parts) < 9:
            return

        lat_type = parts[1]
        try:
            count = int(parts[2])
            avg = int(parts[3])
            p50 = int(parts[6])
            p95 = int(parts[7])
            p99 = int(parts[8])
        except (ValueError, IndexError):
            return

        prefix = lat_type  # sched_delay, runqueue, wakeup, preemption
        result[f"{prefix}_count"] = count
        result[f"{prefix}_avg_ns"] = avg
        result[f"{prefix}_p50_ns"] = p50
        result[f"{prefix}_p95_ns"] = p95
        result[f"{prefix}_p99_ns"] = p99

        # Context switch counters (from any latency type row — they're the same)
        if len(parts) >= 12:
            try:
                result["total_csw_per_sec"] = int(parts[9]) if parts[9] else ""
                result["voluntary_csw_per_sec"] = int(parts[10]) if parts[10] else ""
                result["involuntary_csw_per_sec"] = int(parts[11]) if parts[11] else ""
            except ValueError:
                pass

    def read(self, interval):
        return self.poll()


# ---------------------------------------------------------------------------
# Metric source: hackbench throughput
# ---------------------------------------------------------------------------

class HackbenchSource:
    """Runs hackbench once and captures total time."""

    def available(self):
        return shutil.which("hackbench") is not None

    def name(self):
        return "hackbench"

    def run_once(self):
        try:
            r = subprocess.run(
                ["hackbench", "-l", "1000"],
                capture_output=True, text=True, timeout=120
            )
            # Output: "Time: 1.234\n"
            for line in r.stdout.splitlines():
                m = re.search(r"Time:\s+([\d.]+)", line)
                if m:
                    return {"hackbench_time_sec": float(m.group(1))}
        except (OSError, subprocess.TimeoutExpired):
            pass
        return {}


# ---------------------------------------------------------------------------
# Metric source: sysbench throughput
# ---------------------------------------------------------------------------

class SysbenchSource:
    """Runs sysbench cpu and captures events/sec."""

    def available(self):
        return shutil.which("sysbench") is not None

    def name(self):
        return "sysbench"

    def run_once(self, duration=10):
        try:
            r = subprocess.run(
                ["sysbench", "cpu", "--time=" + str(duration), "run"],
                capture_output=True, text=True, timeout=duration + 30
            )
            for line in r.stdout.splitlines():
                m = re.search(r"events per second:\s+([\d.]+)", line)
                if m:
                    return {"sysbench_events_per_sec": float(m.group(1))}
        except (OSError, subprocess.TimeoutExpired):
            pass
        return {}


# ---------------------------------------------------------------------------
# Metric source: fairness harness
# ---------------------------------------------------------------------------

class FairnessSource:
    """Runs fairness_harness and computes Jain's fairness index."""

    def __init__(self, harness_bin):
        self.bin = harness_bin

    def available(self):
        return os.path.isfile(self.bin) and os.access(self.bin, os.X_OK)

    def name(self):
        return "fairness_harness"

    def run_once(self, nprocs=None, duration=5):
        if nprocs is None:
            nprocs = min(os.cpu_count() or 4, 16)
        try:
            r = subprocess.run(
                [self.bin, "-n", str(nprocs), "-t", str(duration)],
                capture_output=True, text=True, timeout=duration + 30
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}

        runtimes = []
        for line in r.stdout.splitlines():
            if line.startswith("pid"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    runtimes.append(int(parts[1]))
                except ValueError:
                    pass

        if len(runtimes) < 2:
            return {}

        return {"jain_fairness_index": round(jain_index(runtimes), 6)}


def jain_index(values):
    """Compute Jain's fairness index: (sum(x))^2 / (n * sum(x^2))."""
    n = len(values)
    if n == 0:
        return 0.0
    s = sum(values)
    s2 = sum(x * x for x in values)
    if s2 == 0:
        return 1.0
    return (s * s) / (n * s2)


# ---------------------------------------------------------------------------
# Probe mode
# ---------------------------------------------------------------------------

def run_probe(args):
    """Test each metric source and report availability."""
    sched_lat = SchedLatencySource(args.sched_latency_bin)
    sources = [
        ProcStatSource(),
        SchedstatSource(),
        RaplSource(),
        sched_lat,
        HackbenchSource(),
        SysbenchSource(),
        FairnessSource(args.fairness_bin),
    ]

    print("Metric source availability:")
    print("-" * 50)
    for src in sources:
        status = "OK" if src.available() else "NOT FOUND"
        print(f"  {src.name():30s} {status}")

    # Check enqueue hook availability
    funcs_path = Path("/sys/kernel/debug/tracing/available_filter_functions")
    if funcs_path.exists():
        try:
            funcs = funcs_path.read_text()
            for sym, label in [
                ("enqueue_task_fair", "enqueue_task_fair (CFS/EEVDF)"),
                ("scx_ops_enqueue_task", "scx_ops_enqueue (sched_ext)"),
            ]:
                if sym in funcs:
                    print(f"  {label:30s} OK")
                else:
                    print(f"  {label:30s} NOT AVAILABLE")
        except OSError:
            print(f"  {'enqueue hooks':30s} UNKNOWN (cannot read)")
    else:
        print(f"  {'enqueue hooks':30s} UNKNOWN (no debugfs)")


# ---------------------------------------------------------------------------
# Main collection loop
# ---------------------------------------------------------------------------

def collect(args):
    """Main data collection loop."""
    scheduler = args.scheduler
    duration = args.duration
    interval = args.interval
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = output_dir / f"{scheduler}_{ts_str}.csv"
    meta_path = output_dir / f"{scheduler}_{ts_str}.meta.json"

    # Initialize sources
    proc_stat = ProcStatSource()
    schedstat = SchedstatSource()
    rapl = RaplSource()
    sched_lat = SchedLatencySource(args.sched_latency_bin)
    hackbench = HackbenchSource()
    sysbench = SysbenchSource()
    fairness = FairnessSource(args.fairness_bin)

    # Manage sched_ext scheduler subprocess
    sched_proc = None
    if args.sched_bin:
        print(f"Starting scheduler: {args.sched_bin}")
        try:
            sched_proc = subprocess.Popen(
                [args.sched_bin],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(2)  # Let scheduler attach
        except OSError as e:
            print(f"Failed to start scheduler: {e}", file=sys.stderr)
            return 1

    # Fairness file for BPF per-PID data
    fairness_csv = str(output_dir / f"{scheduler}_{ts_str}_fairness.csv")

    # Start BPF latency tool
    sched_lat.start(interval, fairness_file=fairness_csv if fairness.available() else None)

    # Priming read (for delta-based sources)
    proc_stat.read(interval)
    schedstat.read(interval)
    rapl.read(interval)

    # Write metadata
    meta = {
        "scheduler": scheduler,
        "start_time": datetime.now().isoformat(),
        "duration": duration,
        "interval": interval,
        "hostname": os.uname().nodename,
        "cpu_count": os.cpu_count(),
        "sources": {
            "/proc/stat": proc_stat.available(),
            "/proc/schedstat": schedstat.available(),
            "RAPL": rapl.available(),
            "sched_latency": sched_lat.available(),
            "hackbench": hackbench.available(),
            "sysbench": sysbench.available(),
            "fairness_harness": fairness.available(),
        },
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata: {meta_path}")

    # Open CSV
    csvfile = open(csv_path, "w", newline="")
    writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    print(f"CSV output: {csv_path}")
    print(f"Collecting for {duration}s at {interval}s intervals...")

    exit_req = [False]

    def handle_sig(sig, frame):
        exit_req[0] = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    start_time = time.monotonic()
    elapsed = 0

    # Run one-shot benchmarks at the start
    oneshot_results = {}
    if hackbench.available():
        print("  Running hackbench...", flush=True)
        oneshot_results.update(hackbench.run_once())
    if sysbench.available():
        print("  Running sysbench...", flush=True)
        oneshot_results.update(sysbench.run_once(duration=min(10, duration)))
    if fairness.available():
        print("  Running fairness harness...", flush=True)
        oneshot_results.update(fairness.run_once())

    try:
        while not exit_req[0]:
            time.sleep(interval)
            elapsed = time.monotonic() - start_time

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "elapsed_s": round(elapsed, 1),
                "scheduler": scheduler,
            }

            # Periodic sources
            row.update(proc_stat.read(interval))
            row.update(schedstat.read(interval))
            row.update(rapl.read(interval))
            row.update(sched_lat.read(interval))

            # Include one-shot results in every row for easier plotting
            row.update(oneshot_results)

            writer.writerow(row)
            csvfile.flush()

            if int(elapsed) % 10 == 0:
                cpu = row.get("cpu_util_pct", "N/A")
                csw = row.get("ctx_switches_per_sec", "N/A")
                print(f"  [{int(elapsed):4d}s] cpu={cpu}%  csw={csw}/s", flush=True)

            if duration and elapsed >= duration:
                break
    finally:
        sched_lat.stop()
        csvfile.close()

        if sched_proc:
            print("Stopping scheduler...")
            sched_proc.send_signal(signal.SIGTERM)
            try:
                sched_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sched_proc.kill()

    print(f"\nDone. Results: {csv_path}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(
        description="Scheduler benchmark data collection"
    )
    parser.add_argument(
        "--probe", action="store_true",
        help="Check metric source availability and exit"
    )
    parser.add_argument(
        "--scheduler", default="default",
        help="Scheduler name label (default, s3, s3+, s4)"
    )
    parser.add_argument(
        "--sched-bin", default=None,
        help="Path to sched_ext scheduler binary to run"
    )
    parser.add_argument(
        "--duration", type=int, default=300,
        help="Collection duration in seconds (default: 300)"
    )
    parser.add_argument(
        "--interval", type=int, default=1,
        help="Sampling interval in seconds (default: 1)"
    )
    parser.add_argument(
        "--output", default="results",
        help="Output directory (default: results/)"
    )
    parser.add_argument(
        "--sched-latency-bin",
        default=str(script_dir / "build" / "sched_latency"),
        help="Path to sched_latency binary"
    )
    parser.add_argument(
        "--fairness-bin",
        default=str(script_dir / "workloads" / "build" / "fairness_harness"),
        help="Path to fairness_harness binary"
    )

    args = parser.parse_args()

    if args.probe:
        run_probe(args)
        return 0

    return collect(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
