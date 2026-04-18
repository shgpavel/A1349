# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Repository purpose

Scheduler research: LaTeX papers in `theory/` paired with sched_ext (SCX) BPF scheduler implementations in `impl/`. Benchmarks compare impls against baselines (default CFS/EEVDF, and `scx_lavd` from an external `../scx` checkout).

## Layout

- `impl/s3`  — homogeneous EEVDF baseline (reference, untouched).
- `impl/s3+` — A1349 capacity-aware EEVDF. Adds `max_capacity` to `eevdf_ctx`, reads `/sys/.../cpu_capacity` into a BPF map at load, scales virtual deadlines/consumption by capacity.
- `impl/s4`  — `scx_auction` VCG auction scheduler. Two DSQs (P=high-cap, E=low-cap) plus a starved queue; token-bucket budget per task. CLI: `scx_auction [-p COST_P] [-e COST_E]`, defaults 512/256.
- `benchmarks/` — `sched_latency` BPF tool + Python harness (`run_suite.py`, `collect.py`, `visualize.py`, `figure_combined.py`).
- `theory/{s1..s4}/main.tex` — papers paired with each impl.
- `results/`, `plots/`, `events/`, `cache/` — benchmark outputs.

`impl/s4/{scheds/include,scheds/vmlinux,lib}` are symlinks into `impl/s3+`. Shared BPF lib headers live in `impl/s3+/scheds/include` and `impl/s3+/lib`.

## Build

Top-level `Makefile` orchestrates s3 + s3+ (not s4) and benchmarks.

```
make                     # builds impl/s3 and impl/s3+
make clean
make install             # copies schedulers to /usr/local/bin
make benchmarks          # builds everything + scx_lavd + runs run_suite.py
```

Per-impl (out-of-source into `./build/`):

```
cd impl/s3+ && make       # → build/scheds/c/scx_eevdf, scx_simple
cd impl/s4  && make       # → build/scheds/c/scx_auction
cd impl/s3+ && make scx_eevdf     # single scheduler target
cd impl/s3+ && make EEVDF_TELEMETRY=1   # enable telemetry build flag
```

Each per-impl `Makefile` re-execs itself inside `./build/` via `KBUILD_OUTPUT` + `ROOT_SRC_DIR`. The `vmlinux-link` target symlinks `/lib/modules/$(uname -r)/build/vmlinux.h` into `scheds/vmlinux/vmlinux.h` — required before BPF compile. Build deps: `clang`, `bpftool`, `libbpf` (pkg-config), `libelf`, `zlib`, `zstd`.

## Benchmarks

```
make benchmarks BENCH_INTERVAL=1
```

Runs `benchmarks/run_suite.py` across default/s3/s3+/LAVD, each with warmup + cooldown. Requires `../scx` sibling checkout for `scx_lavd` (override via `SCX_DIR=` / `SCX_LAVD_BIN=`). `run_suite.py` calls `collect.py` (drives the `sched_latency` BPF tool; needs root) and `visualize.py`. Outputs land in `results/` and `plots/`.

Run single benchmark directly:

```
sudo ./benchmarks/build/sched_latency -d 10 -i 1    # under current active sched
```

## Running schedulers

All scheds require root and a kernel with `sched_ext` enabled. Only one SCX scheduler can be active at a time; the previous one must exit first.

```
sudo build/scheds/c/scx_eevdf       # from impl/s3+/
sudo build/scheds/c/scx_auction -p 512 -e 256   # from impl/s4/
```

## A1349 algorithm (s3+) reference

`CAPACITY_SCALE = 1024`. On enqueue: `q_max = max_cap * SCX_SLICE_DFL / CAPACITY_SCALE`, `vd = ve + q_max * SCALE / weight`. On stopping: `ve += consumed * cap * SCALE / (weight * CAPACITY_SCALE)`. Result: homogeneous (all cap=1024) reduces exactly to stock EEVDF; heterogeneous (e.g. Intel hybrid) gets capacity-weighted virtual time. Capacity map populated by `load_cpu_capacities()` in `scx_eevdf.c` before BPF load.

## s4 auction reference

`φ_P = weight - C_P*l`, `φ_E = weight - C_E*ceil(l*σ)` where `σ = max_cap/min_cap`, `l` = pending load estimate. Budget is a token bucket: deducted on stopping, replenished on wake ∝ `idle_ns * weight`. Exhausted tasks go to `DSQ_STARVED`. See `impl/s4/hetero_scheduler_model.md` for full model.

## Conventions

- BPF sources: `scx_<name>.bpf.c`; userspace loader: `scx_<name>.c`; skeleton header auto-generated as `scx_<name>.bpf.skel.h` in `$OBJ_DIR`.
- Files are GPL-2.0, `Copyright (c) 2025 Pavel Shago` (and Meta where inherited from scx upstream).
- Do not commit anything into `build/`, `results/`, `plots/`, `cache/`, `events/`, or `scheds/vmlinux/vmlinux.h` (symlink).
