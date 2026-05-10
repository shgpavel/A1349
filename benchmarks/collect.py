#!/usr/bin/env python3
"""
collect.py - Scheduler benchmark data collection orchestrator.

Polls multiple metric sources each interval and writes unified CSV output.
Runs as a normal user; the two privileged subprocesses (the sched_ext
scheduler binary and the sched_latency BPF tool) are spawned under sudo.

Usage:
    python3 collect.py --scheduler default --duration 300 --interval 1 --output results/
    python3 collect.py --scheduler s3+ --sched-bin ../impl/s3+/build/scheds/c/scx_eevdf --duration 300
    python3 collect.py --probe
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
import threading
import time
from datetime import datetime
from pathlib import Path


def sudo_prefix():
    """Return ['sudo', '--preserve-env=PATH'] if we aren't already root."""
    if os.geteuid() == 0:
        return []
    return ["sudo", "--preserve-env=PATH"]


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
    "energy_joules",
    # BPF latency (sched_delay)
    "sched_delay_count",
    "sched_delay_avg_ns",
    "sched_delay_p99_ns",
    # BPF latency (runqueue)
    "runqueue_count",
    "runqueue_avg_ns",
    "runqueue_p99_ns",
    # BPF latency (wakeup)
    "wakeup_count",
    "wakeup_avg_ns",
    "wakeup_p99_ns",
    # BPF latency (preemption)
    "preemption_count",
    "preemption_avg_ns",
    "preemption_p99_ns",
    # BPF latency (idle_wakeup)
    "idle_wakeup_count",
    "idle_wakeup_avg_ns",
    "idle_wakeup_p99_ns",
    # BPF latency (migration)
    "migration_count",
    "migration_avg_ns",
    "migration_p99_ns",
    # BPF latency (slice duration)
    "slice_count",
    "slice_avg_ns",
    "slice_p99_ns",
    # BPF latency (sleep duration)
    "sleep_count",
    "sleep_avg_ns",
    "sleep_p99_ns",
    # BPF context switch counters
    "total_csw_per_sec",
    "voluntary_csw_per_sec",
    "involuntary_csw_per_sec",
    # schbench per-phase throughput (repeated values across rows of the phase)
    "schbench_wakeup_p50_0_usec",
    "schbench_wakeup_p99_0_usec",
    "schbench_wakeup_p99_9_usec",
    "schbench_request_p50_0_usec",
    "schbench_request_p99_0_usec",
    "schbench_request_p99_9_usec",
    "schbench_rps_p50_0_reqs",
    "schbench_rps_p99_0_reqs",
    "schbench_avg_rps",
    # hackbench / sysbench one-shot throughput (stamped on the final row of the phase)
    "hackbench_time_sec",
    "sysbench_tps",
    "sysbench_qps",
    # Phase: hackbench | sysbench | schbench | cooldown | warmup
    "phase",
    "iter",
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
                        result["cpu_util_pct"] = round(100.0 * (1.0 - d_idle / d_total), 2)
                self.prev_cpu = (total, idle)

            elif line.startswith("ctxt "):
                ctxt = int(line.split()[1])
                if self.prev_ctxt is not None and self.prev_time is not None:
                    dt = now - self.prev_time
                    if dt > 0:
                        result["ctx_switches_per_sec"] = round((ctxt - self.prev_ctxt) / dt, 1)
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
                result["timeslices_per_sec"] = round((total_slices - self.prev[0]) / dt, 1)
                result["wait_ns_per_sec"] = round((total_wait - self.prev[1]) / dt, 0)

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
        self.max_energy_range = 0
        self.prev = None
        self.prev_time = None
        self._discover()

    def _discover(self):
        base = Path("/sys/class/powercap")
        if not base.exists():
            return
        for d in sorted(base.iterdir()):
            if d.name.startswith("intel-rapl:") and ":" not in d.name[len("intel-rapl:") :]:
                ej = d / "energy_uj"
                if ej.exists():
                    self.paths.append(ej)
                    # Read platform-specific max range for wrap correction
                    mr = d / "max_energy_range_uj"
                    try:
                        self.max_energy_range += int(mr.read_text().strip())
                    except (OSError, ValueError):
                        self.max_energy_range += 1 << 32

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
                    d_uj += self.max_energy_range
                joules = d_uj / 1e6
                watts = joules / dt
                result["power_watts"] = round(watts, 2)
                result["energy_joules"] = round(joules, 4)

        self.prev = total_uj
        self.prev_time = now
        return result


# ---------------------------------------------------------------------------
# Metric source: BPF sched_latency subprocess
# ---------------------------------------------------------------------------


class SchedLatencySource:
    """Runs sched_latency -c as a subprocess and parses CSV output."""

    def __init__(self, sched_latency_bin, log_dir=None):
        self.bin = sched_latency_bin
        self.proc = None
        self.latest = {}
        self._lock = threading.Lock()
        self._reader_thread = None
        self._log_dir = log_dir
        self._log_fh = None

    def available(self):
        return os.path.isfile(self.bin) and os.access(self.bin, os.X_OK)

    def name(self):
        return "BPF sched_latency"

    def start(self, interval):
        if not self.available():
            return
        cmd = [*sudo_prefix(), self.bin, "-c", "-i", str(interval)]
        if self._log_dir is not None:
            self._log_fh = open(Path(self._log_dir) / "sched_latency.log", "w")
            err = self._log_fh
        else:
            err = subprocess.DEVNULL
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=err,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            # Skip CSV header
            if self.proc.stdout:
                self.proc.stdout.readline()
        except OSError:
            self.proc = None
            return

        # Start background reader thread for reliable line consumption
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def _reader_loop(self):
        """Continuously read lines from subprocess stdout."""
        while self.proc and self.proc.stdout:
            line = self.proc.stdout.readline()
            if not line:
                break
            parsed = {}
            self._parse_line(line.strip(), parsed)
            if parsed:
                with self._lock:
                    self.latest.update(parsed)

    def stop(self):
        if self.proc:
            # Kill the whole process group — sudo is the direct child, the
            # actual sched_latency tool is its child and would outlive a
            # signal sent only to sudo.
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    self.proc.kill()
            self.proc = None
        if self._reader_thread:
            self._reader_thread.join(timeout=2)
            self._reader_thread = None
        if self._log_fh:
            self._log_fh.close()
            self._log_fh = None

    def _parse_line(self, line, result):
        """Parse one CSV line from sched_latency -c output."""
        # Format: timestamp,type,count,avg_ns,min_ns,max_ns,p99_ns,total_csw,voluntary_csw,involuntary_csw
        parts = line.split(",")
        if len(parts) < 7:
            return

        lat_type = parts[1]
        try:
            count = int(parts[2])
            avg = int(parts[3])
            # parts[4] = min_ns, parts[5] = max_ns (not stored in CSV)
            p99 = int(parts[6])
        except (ValueError, IndexError):
            return

        prefix = lat_type  # sched_delay, runqueue, wakeup, preemption, ...
        result[f"{prefix}_count"] = count
        result[f"{prefix}_avg_ns"] = avg
        result[f"{prefix}_p99_ns"] = p99

        # Context switch counters: per-second rate (sched_latency already
        # divides its interval delta by the -i interval before emitting).
        # Parse atomically — a partial assignment leaves inconsistent state.
        if len(parts) >= 10:
            try:
                total = int(parts[7]) if parts[7] else ""
                vol   = int(parts[8]) if parts[8] else ""
                invol = int(parts[9]) if parts[9] else ""
            except ValueError:
                pass
            else:
                result["total_csw_per_sec"] = total
                result["voluntary_csw_per_sec"] = vol
                result["involuntary_csw_per_sec"] = invol

    def read(self, interval):
        with self._lock:
            result = dict(self.latest)
            self.latest = {}
            return result


# ---------------------------------------------------------------------------
# Metric source: hackbench throughput
# ---------------------------------------------------------------------------


class HackbenchSource:
    """Runs hackbench and captures total time. Supports async start+wait so
    samplers can record metrics while it runs."""

    def __init__(self, args=None):
        self.args = args or ["-l", "1000"]

    def available(self):
        return shutil.which("hackbench") is not None

    def name(self):
        return "hackbench"

    def start(self):
        return subprocess.Popen(
            ["hackbench", *self.args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def parse(self, stdout):
        for line in stdout.splitlines():
            m = re.search(r"Time:\s+([\d.]+)", line)
            if m:
                return {"hackbench_time_sec": float(m.group(1))}
        return {}

    def run_once(self):
        try:
            p = self.start()
            out, _ = p.communicate(timeout=300)
            return self.parse(out)
        except (OSError, subprocess.TimeoutExpired):
            return {}


# ---------------------------------------------------------------------------
# Metric source: sysbench throughput
# ---------------------------------------------------------------------------


class SysbenchSource:
    """Runs sysbench OLTP (read-only) against a PostgreSQL backend.

    DB must be provisioned out-of-band (server running, user + database
    created, TCP reachable). We probe reachability; if the server is not
    reachable or prep fails, sysbench is marked unavailable and the phase
    is skipped so the rest of the suite keeps running.

    prep() seeds --tables × --table-size rows once per collect() invocation.
    If sbtest1 already has at least --table-size rows we skip prep to avoid
    the cost of reseeding on every run.
    """

    OLTP_SCRIPT = "oltp_read_only"

    def __init__(
        self,
        threads=1,
        db_driver="pgsql",
        db_host="127.0.0.1",
        db_port=5432,
        db_user="sbtest",
        db_password="sbtest",
        db_name="sbtest",
        tables=4,
        table_size=100000,
    ):
        self.threads = threads
        self.db_driver = db_driver
        self.db_host = db_host
        self.db_port = db_port
        self.db_user = db_user
        self.db_password = db_password
        self.db_name = db_name
        self.tables = tables
        self.table_size = table_size
        self._prepped = False

    def _db_args(self):
        return [
            f"--db-driver={self.db_driver}",
            f"--pgsql-host={self.db_host}",
            f"--pgsql-port={self.db_port}",
            f"--pgsql-user={self.db_user}",
            f"--pgsql-password={self.db_password}",
            f"--pgsql-db={self.db_name}",
            f"--tables={self.tables}",
            f"--table-size={self.table_size}",
        ]

    def _db_reachable(self):
        """pg_isready probe — cheap + doesn't require auth."""
        if self.db_driver != "pgsql":
            return False
        if shutil.which("pg_isready") is None:
            return True  # can't probe; assume OK and let sysbench fail loud
        try:
            rc = subprocess.call(
                [
                    "pg_isready",
                    "-h", str(self.db_host),
                    "-p", str(self.db_port),
                    "-U", self.db_user,
                    "-d", self.db_name,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return rc == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def available(self):
        if shutil.which("sysbench") is None:
            return False
        return self._db_reachable()

    def name(self):
        return f"sysbench oltp ({self.db_driver})"

    def _already_seeded(self):
        """Cheap: ask sysbench to count rows via prewarm; if it errors, reseed."""
        if shutil.which("psql") is None:
            return False
        env = os.environ.copy()
        env["PGPASSWORD"] = self.db_password
        try:
            out = subprocess.check_output(
                [
                    "psql",
                    "-h", str(self.db_host),
                    "-p", str(self.db_port),
                    "-U", self.db_user,
                    "-d", self.db_name,
                    "-t", "-A",
                    "-c", "SELECT COUNT(*) FROM sbtest1",
                ],
                stderr=subprocess.DEVNULL,
                env=env,
                timeout=10,
            ).decode().strip()
            return int(out) >= self.table_size
        except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

    def prep(self, log_dir=None):
        """Seed sbtest tables if missing. Safe to call multiple times."""
        if self._prepped:
            return True
        if not shutil.which("sysbench"):
            return False
        if self._already_seeded():
            self._prepped = True
            return True

        cmd = [
            "sysbench",
            *self._db_args(),
            f"--threads={max(1, self.threads)}",
            self.OLTP_SCRIPT,
            "prepare",
        ]
        log_fh = None
        stdout = subprocess.DEVNULL
        if log_dir is not None:
            log_fh = open(Path(log_dir) / "sysbench_prep.log", "w")
            stdout = log_fh
        try:
            rc = subprocess.call(cmd, stdout=stdout, stderr=subprocess.STDOUT, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            rc = -1
        finally:
            if log_fh is not None:
                log_fh.close()
        self._prepped = rc == 0
        return self._prepped

    def start(self, duration=10):
        return subprocess.Popen(
            [
                "sysbench",
                *self._db_args(),
                f"--threads={self.threads}",
                f"--time={duration}",
                "--report-interval=0",
                self.OLTP_SCRIPT,
                "run",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def parse(self, stdout):
        out = {}
        for line in stdout.splitlines():
            m = re.search(r"transactions:\s+\d+\s+\(([\d.]+)\s+per sec\.\)", line)
            if m:
                out["sysbench_tps"] = float(m.group(1))
            m = re.search(r"queries:\s+\d+\s+\(([\d.]+)\s+per sec\.\)", line)
            if m:
                out["sysbench_qps"] = float(m.group(1))
        return out

    def run_once(self, duration=10):
        try:
            p = self.start(duration)
            out, _ = p.communicate(timeout=duration + 30)
            return self.parse(out)
        except (OSError, subprocess.TimeoutExpired):
            return {}


SCHBENCH_BIN_DEFAULT = str(Path(__file__).resolve().parent / "third_party" / "schbench" / "schbench")


class SchbenchSource:
    """Runs schbench (Facebook wakeup latency benchmark) for a fixed duration.

    Parses wakeup p50/p99/p99.9 and average RPS from stdout.
    Level controls -m (message threads) and -t (workers per msg thread).
    """

    def __init__(self, level, bin_path=None):
        self.level = level
        self.bin = bin_path or SCHBENCH_BIN_DEFAULT

    def available(self):
        return Path(self.bin).is_file() and os.access(self.bin, os.X_OK)

    def name(self):
        return "schbench"

    def _sizing(self):
        n = _nproc()
        if self.level == "light":
            return 1, max(1, n // 4)
        if self.level == "moderate":
            return 2, n
        if self.level == "stress":
            return 4, max(2, n * 2)
        raise ValueError(f"unknown workload level: {self.level}")

    def start(self, duration_s):
        m, t = self._sizing()
        return subprocess.Popen(
            [self.bin, "-m", str(m), "-t", str(t), "-r", str(duration_s)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def parse(self, stdout):
        """Extract percentile + rps metrics."""
        out = {}
        section = None  # (name, suffix)
        for raw in stdout.splitlines():
            line = raw.strip()
            if line.startswith("Wakeup Latencies"):
                section = ("wakeup", "usec")
                continue
            if line.startswith("Request Latencies"):
                section = ("request", "usec")
                continue
            if line.startswith("RPS percentiles"):
                section = ("rps", "reqs")
                continue
            if section:
                m = re.match(r"\*?\s*(\d+\.\d+)th:\s+(\d+)", line)
                if m:
                    pct = m.group(1).replace(".", "_")
                    out[f"schbench_{section[0]}_p{pct}_{section[1]}"] = int(m.group(2))
            m = re.match(r"average rps:\s+([\d.]+)", line)
            if m:
                out["schbench_avg_rps"] = float(m.group(1))
        return out


# ---------------------------------------------------------------------------
# Workload levels: background load + oneshot bench sizing.
# ---------------------------------------------------------------------------


def _nproc():
    return os.cpu_count() or 1


def workload_profile(level):
    """Return (hackbench_args, sysbench_threads) for given level.

    Hackbench loops are sized so the phase runs long enough (~10s on a 20-core
    box at ~2M hackbench ops/s) for interval=1s sampling to collect a usable
    latency time series. Groups control *load*; loops control *duration*.

    schbench sizing is derived inside SchbenchSource from the level.
    """
    n = _nproc()
    if level == "light":
        return ["-l", "10000"], 1
    if level == "moderate":
        return ["-g", "4", "-l", "120000"], 4
    if level == "stress":
        return ["-g", "10", "-l", "50000"], n
    raise ValueError(f"unknown workload level: {level}")


def _kill_proc_tree(proc, timeout=5):
    """SIGTERM process group, SIGKILL on timeout."""
    if not proc:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()


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
        SchbenchSource(level="light"),
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
    interval = args.interval
    warmup = args.warmup
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = output_dir / f"{scheduler}_{ts_str}.csv"
    meta_path = output_dir / f"{scheduler}_{ts_str}.meta.json"

    level = getattr(args, "workload_level", "light") or "light"
    hb_args, sb_threads = workload_profile(level)
    repeats = max(1, getattr(args, "phase_repeats", 1))
    cooldown = max(0.0, getattr(args, "phase_cooldown", 3.0))
    sysbench_dur = max(1, getattr(args, "sysbench_duration", 10))
    schbench_dur = max(1, getattr(args, "schbench_duration", 30))
    schbench_bin = getattr(args, "schbench_bin", None) or SCHBENCH_BIN_DEFAULT

    # Initialize sources
    proc_stat = ProcStatSource()
    schedstat = SchedstatSource()
    rapl = RaplSource()
    sched_lat = SchedLatencySource(args.sched_latency_bin, log_dir=output_dir)
    hackbench = HackbenchSource(args=hb_args)
    sysbench = SysbenchSource(
        threads=sb_threads,
        db_driver=getattr(args, "sysbench_db_driver", "pgsql"),
        db_host=getattr(args, "sysbench_db_host", "127.0.0.1"),
        db_port=getattr(args, "sysbench_db_port", 5432),
        db_user=getattr(args, "sysbench_db_user", "sbtest"),
        db_password=getattr(args, "sysbench_db_password", "sbtest"),
        db_name=getattr(args, "sysbench_db_name", "sbtest"),
        tables=getattr(args, "sysbench_tables", 4),
        table_size=getattr(args, "sysbench_table_size", 100000),
    )
    schbench = SchbenchSource(level=level, bin_path=schbench_bin)

    # sysbench OLTP needs a seeded DB. Prep once before phases start so
    # the seed cost isn't charged to the scheduler under test.
    if sysbench.available():
        if not sysbench.prep(log_dir=output_dir):
            print("sysbench prep failed; OLTP phase will be skipped", file=sys.stderr)

    # Manage sched_ext scheduler subprocess (needs root).
    sched_proc = None
    sched_log_fh = None
    if args.sched_bin:
        print(f"Starting scheduler: {args.sched_bin}")
        sched_log_fh = open(output_dir / "scheduler.log", "w")
        try:
            sched_proc = subprocess.Popen(
                [*sudo_prefix(), args.sched_bin],
                stdout=sched_log_fh,
                stderr=sched_log_fh,
                start_new_session=True,
            )
            time.sleep(2)  # Let scheduler attach
        except OSError as e:
            print(f"Failed to start scheduler: {e}", file=sys.stderr)
            sched_log_fh.close()
            return 1

        # Verify scheduler is still alive — sudo failure, missing binary, or
        # attach failure would exit the process before we start sampling.
        rc = sched_proc.poll()
        if rc is not None:
            print(f"Scheduler exited with code {rc} before attach; "
                  f"see {output_dir / 'scheduler.log'}", file=sys.stderr)
            sched_log_fh.close()
            return 1

    # Start BPF latency tool
    sched_lat.start(interval)

    # Priming read (for delta-based sources)
    proc_stat.read(interval)
    schedstat.read(interval)
    rapl.read(interval)

    # Write metadata (oneshot results filled in after phases run)
    meta = {
        "scheduler": scheduler,
        "workload_level": level,
        "hackbench_args": hb_args,
        "sysbench_threads": sb_threads,
        "sysbench_duration": sysbench_dur,
        "schbench_duration": schbench_dur,
        "phase_repeats": repeats,
        "phase_cooldown": cooldown,
        "start_time": datetime.now().isoformat(),
        "interval": interval,
        "warmup": warmup,
        "hostname": os.uname().nodename,
        "cpu_count": os.cpu_count(),
        "sources": {
            "/proc/stat": proc_stat.available(),
            "/proc/schedstat": schedstat.available(),
            "RAPL": rapl.available(),
            "sched_latency": sched_lat.available(),
            "hackbench": hackbench.available(),
            "sysbench": sysbench.available(),
            "schbench": schbench.available(),
        },
        "oneshot_runs": [],
    }

    # Open CSV
    csvfile = open(csv_path, "w", newline="")
    writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    print(f"CSV output: {csv_path}")

    exit_req = [False]

    def handle_sig(sig, frame):
        exit_req[0] = True

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    start_time = time.monotonic()

    def sample_row(phase, iter_idx):
        elapsed = time.monotonic() - start_time
        row = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "elapsed_s": round(elapsed, 2),
            "scheduler": scheduler,
            "phase": phase,
            "iter": iter_idx,
        }
        row.update(proc_stat.read(interval))
        row.update(schedstat.read(interval))
        row.update(rapl.read(interval))
        row.update(sched_lat.read(interval))
        return row

    def drain_metrics():
        """Discard pending deltas so the next phase starts clean."""
        proc_stat.read(interval)
        schedstat.read(interval)
        rapl.read(interval)
        sched_lat.read(interval)

    def run_proc_phase(phase_name, iter_idx, proc, parser, max_wait):
        """Sample every `interval` while proc runs; return parsed throughput.

        Drain stdout in a background thread — stdout=PIPE with an unread
        pipe deadlocks when a bench fills the 64 KiB kernel buffer.

        Caller is expected to call drain_metrics() right before invoking us
        so delta-based sources have a fresh baseline. We do NOT emit a row
        at t=0 — deltas over microseconds are garbage (cpu_util pinning to
        0 or 100, ctx_switches near-zero). Short-lived phases still yield
        a summary row with parsed throughput (see below).
        """
        stdout_chunks = []

        def _drain():
            if proc.stdout is None:
                return
            try:
                for chunk in iter(lambda: proc.stdout.read(4096), ""):
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)
            except (OSError, ValueError):
                pass

        drainer = threading.Thread(target=_drain, daemon=True)
        drainer.start()

        rows = []
        deadline = time.monotonic() + max_wait
        while proc.poll() is None and not exit_req[0]:
            time.sleep(interval)
            row = sample_row(phase_name, iter_idx)
            writer.writerow(row)
            csvfile.flush()
            rows.append(row)
            if time.monotonic() > deadline:
                _kill_proc_tree(proc, timeout=5)
                break

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_proc_tree(proc, timeout=5)

        drainer.join(timeout=5)
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass

        parsed = parser("".join(stdout_chunks)) if stdout_chunks else {}

        # Stamp throughput onto a synthetic summary row so CSV consumers
        # (visualize.py) can read it without cross-referencing meta.json.
        # Emit even when `rows` is empty — short phases (hackbench <1s)
        # would otherwise have no CSV trace at all.
        if parsed:
            if rows:
                last_ts = rows[-1]["timestamp"]
                last_elapsed = rows[-1]["elapsed_s"]
                rows[-1].update(parsed)
            else:
                last_ts = datetime.now().isoformat(timespec="seconds")
                last_elapsed = round(time.monotonic() - start_time, 2)
            summary = {
                "timestamp": last_ts,
                "elapsed_s": last_elapsed,
                "scheduler": scheduler,
                "phase": phase_name,
                "iter": iter_idx,
                **parsed,
            }
            writer.writerow(summary)
            csvfile.flush()

        return parsed

    def run_cooldown(iter_idx):
        if cooldown <= 0:
            return
        print(f"    cooldown {cooldown}s", flush=True)
        end = time.monotonic() + cooldown
        while time.monotonic() < end and not exit_req[0]:
            time.sleep(interval)
            row = sample_row("cooldown", iter_idx)
            writer.writerow(row)
            csvfile.flush()

    try:
        # Warmup: run + sample but tag phase=warmup so downstream can filter.
        if warmup > 0:
            print(f"Warming up for {warmup}s...", flush=True)
            drain_metrics()
            end = time.monotonic() + warmup
            while time.monotonic() < end and not exit_req[0]:
                time.sleep(interval)
                row = sample_row("warmup", 0)
                writer.writerow(row)
                csvfile.flush()
            print("  Warmup complete.", flush=True)

        # Phased runs: hackbench → cooldown → sysbench → cooldown → schbench → cooldown.
        for it in range(1, repeats + 1):
            if exit_req[0]:
                break
            if repeats > 1:
                print(f"\n[iter {it}/{repeats}] workload_level={level}", flush=True)
            run_result = {"iter": it}

            if hackbench.available():
                print("  hackbench...", flush=True)
                drain_metrics()
                run_result.update(run_proc_phase(
                    "hackbench", it, hackbench.start(), hackbench.parse, max_wait=300,
                ))
            run_cooldown(it)

            if sysbench.available():
                print(f"  sysbench ({sysbench_dur}s)...", flush=True)
                drain_metrics()
                run_result.update(run_proc_phase(
                    "sysbench", it, sysbench.start(sysbench_dur), sysbench.parse,
                    max_wait=sysbench_dur + 30,
                ))
            run_cooldown(it)

            if schbench.available():
                print(f"  schbench ({schbench_dur}s, level={level})...", flush=True)
                drain_metrics()
                run_result.update(run_proc_phase(
                    "schbench", it, schbench.start(schbench_dur), schbench.parse,
                    max_wait=schbench_dur + 30,
                ))
            else:
                print(f"  schbench not found at {schbench_bin}; skipping phase", flush=True)
            run_cooldown(it)

            meta["oneshot_runs"].append(run_result)

        # Aggregate throughput stats across iterations
        if meta["oneshot_runs"]:
            keys = set()
            for r in meta["oneshot_runs"]:
                keys.update(k for k in r if k != "iter")
            agg = {}
            for k in keys:
                vals = [r[k] for r in meta["oneshot_runs"] if k in r]
                if vals:
                    n = len(vals)
                    mean = sum(vals) / n
                    # Sample variance (ddof=1) to match aggregate.py t_ci;
                    # for n=1 std is undefined → report 0.
                    if n >= 2:
                        var = sum((v - mean) ** 2 for v in vals) / (n - 1)
                        std = var ** 0.5
                    else:
                        std = 0.0
                    agg[f"{k}_mean"] = mean
                    agg[f"{k}_stddev"] = std
            meta["oneshot_agg"] = agg
    finally:
        sched_lat.stop()
        csvfile.close()

        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
        print(f"Metadata: {meta_path}")

        if sched_proc:
            print("Stopping scheduler...")
            _kill_proc_tree(sched_proc, timeout=10)

        if sched_log_fh:
            sched_log_fh.close()

    print(f"\nDone. Results: {csv_path}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    script_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description="Scheduler benchmark data collection")
    parser.add_argument(
        "--probe", action="store_true", help="Check metric source availability and exit"
    )
    parser.add_argument(
        "--scheduler", default="default", help="Scheduler name label (default, s3, s3+, LAVD, s4)"
    )
    parser.add_argument(
        "--sched-bin", default=None, help="Path to sched_ext scheduler binary to run"
    )
    parser.add_argument(
        "--interval", type=int, default=1, help="Sampling interval in seconds (default: 1)"
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Warmup period in seconds before phased runs (default: 5)",
    )
    parser.add_argument("--output", default="results", help="Output directory (default: results/)")
    parser.add_argument(
        "--sched-latency-bin",
        default=str(script_dir / "build" / "sched_latency"),
        help="Path to sched_latency binary",
    )
    parser.add_argument(
        "--workload-level",
        choices=["light", "moderate", "stress"],
        default="moderate",
        help="schbench + hackbench/sysbench sizing (default: moderate)",
    )
    parser.add_argument(
        "--phase-repeats", type=int, default=1,
        help="Repetitions of hackbench→sysbench→schbench sequence (default: 1)",
    )
    parser.add_argument(
        "--phase-cooldown", type=float, default=3.0,
        help="Cooldown seconds between phases and iterations (default: 3.0)",
    )
    parser.add_argument(
        "--sysbench-duration", type=int, default=10,
        help="sysbench oltp_read_only --time seconds (default: 10)",
    )
    parser.add_argument("--sysbench-db-driver", default="pgsql")
    parser.add_argument("--sysbench-db-host", default="127.0.0.1")
    parser.add_argument("--sysbench-db-port", type=int, default=5432)
    parser.add_argument("--sysbench-db-user", default="sbtest")
    parser.add_argument("--sysbench-db-password", default="sbtest")
    parser.add_argument("--sysbench-db-name", default="sbtest")
    parser.add_argument("--sysbench-tables", type=int, default=4)
    parser.add_argument("--sysbench-table-size", type=int, default=100000)
    parser.add_argument(
        "--schbench-duration", type=int, default=30,
        help="schbench -r runtime seconds (default: 30)",
    )
    parser.add_argument(
        "--schbench-bin", default=None,
        help=f"Path to schbench binary (default: {SCHBENCH_BIN_DEFAULT})",
    )
    args = parser.parse_args()

    if args.probe:
        run_probe(args)
        return 0

    return collect(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
