# AGENTS.md

Guidance for AI agents working in this repo.

## What this repo is

Scheduler research: LaTeX papers in `theory/` paired with `sched_ext`
(SCX) BPF scheduler implementations in `impl/`. Benchmarks compare
impls against stock CFS/EEVDF and `scx_lavd` from an external `../scx`
checkout.

## Layout

- `impl/s3`  — homogeneous EEVDF baseline (reference, untouched)
- `impl/s3+` — capacity-aware EEVDF (`scx_eevdf`)
- `impl/s4`  — VCG auction scheduler (`scx_auction`)
- `theory/{s1..s4}/main.tex` — papers paired with each impl
- `models/VCG_s4.md` — canonical s4 formal model (MDP + φ + VCG-pivot + IC)
- `models/VCG_s4_impl.md` — s4 implementation deviations from theory
- `events/{0212,0904,2104,2904}` — dated presentations
- `benchmarks/` — `sched_latency` BPF tool + Python harness
- `tasks/` — open research / engineering tasks
- `results/`, `plots/`, `cache/` — benchmark outputs (gitignored)

`impl/s4/{scheds/include,scheds/vmlinux,lib}` are symlinks into
`impl/s3+`. Shared BPF headers live under `impl/s3+/scheds/include` and
`impl/s3+/lib`.

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
cd impl/s3+ && make                    # → scx_eevdf, scx_simple
cd impl/s4  && make                    # → scx_auction
cd impl/s3+ && make EEVDF_TELEMETRY=1  # telemetry build flag
```

Each per-impl `Makefile` re-execs itself inside `./build/` via
`KBUILD_OUTPUT` + `ROOT_SRC_DIR`. `vmlinux-link` symlinks
`/lib/modules/$(uname -r)/build/vmlinux.h` into
`scheds/vmlinux/vmlinux.h` — required before BPF compile. Build deps:
`clang`, `bpftool`, `libbpf` (pkg-config), `libelf`, `zlib`, `zstd`.

## Running

Root + kernel with `sched_ext`. Only one SCX scheduler active at a time.

```
sudo build/scheds/c/scx_eevdf                    # from impl/s3+/
sudo build/scheds/c/scx_auction -p 1024 -e 560   # from impl/s4/
```

## Benchmarks

```
make benchmarks BENCH_INTERVAL=1
```

Runs `benchmarks/run_suite.py` across default / s3+ / LAVD with warmup
+ cooldown. Needs `../scx` sibling checkout for `scx_lavd` (override
via `SCX_DIR=` / `SCX_LAVD_BIN=`). `run_suite.py` → `collect.py` (drives
`sched_latency` BPF tool, root required) → `visualize.py`. Outputs in
`results/` and `plots/`.

Single bench:
```
sudo ./benchmarks/build/sched_latency -d 10 -i 1
```

## Test hardware

Intel Core Ultra 7 265K, 8 P-cores + 12 E-cores, Linux 7.0.
`max_cap=1024`, `min_cap=791`, `σ = max_cap/min_cap ≈ 1.29`.

## s3+ algorithm (capacity-aware EEVDF)

`CAPACITY_SCALE = 1024`. On enqueue:
```
q_max = max_cap * SCX_SLICE_DFL / CAPACITY_SCALE
vd    = ve + q_max * SCALE / weight
```
On stopping:
```
ve += consumed * cap * SCALE / (weight * CAPACITY_SCALE)
```
Homogeneous (all cap=1024) reduces exactly to stock EEVDF.
Heterogeneous gets capacity-weighted virtual time. Capacity map is
populated by `load_cpu_capacities()` in `scx_eevdf.c` before BPF load.

## s4 auction (brief — see `models/VCG_s4{,_impl}.md` for full)

Effective value on core type κ:
```
φ_P = v_i − c_P·l_i
φ_E = v_i − c_E·⌈l_i·σ⌉
```
Budget-ratio routing `ρ = B_i / B_max` with hysteresis:
- `ρ ≥ 70%` → `AUCTION_DSQ_P` (bursty / interactive)
- `ρ < 30%` → `AUCTION_DSQ_E` (CPU-bound)
- `30% ≤ ρ < 70%` → sticky, no flip-flop
- `B_i < B_max/10` → `AUCTION_DSQ_STARVED` (demotion)

Payment is currently `p_i = c_κ · t_consumed / s` (posted-price) —
not full VCG-pivot. See `tasks/posted_prices_vcg.md`.

## Conventions

- BPF sources: `scx_<name>.bpf.c`; userspace loader: `scx_<name>.c`;
  skeleton header auto-generated as `scx_<name>.bpf.skel.h` in
  `$OBJ_DIR`.
- Files GPL-2.0, `Copyright (c) 2025 Pavel Shago` (and Meta where
  inherited from upstream scx).
- Do not commit anything into `build/`, `results/`, `plots/`, `cache/`,
  `events/`, or `scheds/vmlinux/vmlinux.h` (symlink).
