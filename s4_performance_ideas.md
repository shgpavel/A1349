# Promising Ideas to Increase s4 Scheduler Performance

Based on the theoretical models (`VCG_s4.md`) and implementation notes (`VCG_s4_impl.md`), here is a list of promising performance optimizations and algorithmic tweaks for the `s4` (VCG Auction) scheduler. These ideas aim to improve system metrics like latency, throughput, and fairness while respecting the mathematical VCG constraints.

## 1. Adaptive Budget-Ratio Hysteresis Thresholds (Refining §I2)
* **Current State:** `BURST_HIGH_PCT` (70%) and `BURST_LOW_PCT` (30%) are fixed constants.
* **Optimization:** Dynamically adjust the deadband `[rho_L, rho_H]` based on P-core queue depth and global utilization. If P-cores are heavily contended, raise `rho_H` (e.g., to 80-85%) to enforce stricter requirements for P-core access. If P-cores are underutilized, lower `rho_H` to allow more tasks to opportunistically run faster.
* **Expected Impact:** Better throughput and reduced P-core saturation without relying heavily on hard spillovers.

## 2. Continuous Wake-Latency Boost (Refining §I5)
* **Current State:** The virtual deadline gap is halved (a discontinuous step) if a task's budget ratio $\rho_i \geq \rho_H$.
* **Optimization:** Replace the binary step with a continuous scaling factor proportional to the utility ratio or $\rho_i$. For example, the deadline gap multiplier could scale smoothly from $1.0$ (at $\rho_i \le \rho_L$) to $0.5$ (at $\rho_i = 1.0$).
* **Expected Impact:** Smoother latency guarantees for tasks hovering around the threshold and removal of cliff-edge performance behaviors.

## 3. Adaptive EWMA Decay for VCG-Pivot Estimator (Refining §I4.1)
* **Current State:** The per-cluster high-watermark $\varphi_{hi,\kappa}$ uses a fixed $\alpha=1/16$ EWMA for decay.
* **Optimization:** Implement a dynamic or adaptive $\alpha$ (similar to TCP RTT variance tracking). When a queue drains rapidly or variance in $\phi_\kappa$ is high, increase the decay rate to prevent stale "high-watermarks" from overcharging subsequent tasks and artificially depleting their budgets.
* **Expected Impact:** Improved incentive compatibility (closer adherence to true VCG payments) and better fairness in highly bursty workloads.

## 4. Cache-Aware Cross-Cluster Work Stealing (Refining §I6)
* **Current State:** Cross-cluster work-stealing is unconditional to prevent idle quanta (strict welfare loss).
* **Optimization:** Introduce a cache-migration penalty. Only steal a task across clusters if its effective value $\phi_\kappa^{steal}$ minus the estimated migration overhead (e.g., L3 cache miss penalty) remains positive.
* **Expected Impact:** Improved cache locality and reduced thermal/migration overheads, translating to better overall instruction throughput (IPC) without violating social welfare principles.

## 5. Probabilistic P-Cluster Saturation Spill (Refining §I7.2)
* **Current State:** When `AUCTION_DSQ_P` length $\ge K_P$, tasks are hard-spilled to E-cores.
* **Optimization:** Use probabilistic spilling (similar to AQM/RED queues). As the P-queue length approaches $K_P$, spill tasks with an increasing probability. Furthermore, prioritize spilling the tasks with the lowest $\phi_P$ rather than simply the most recently enqueued task.
* **Expected Impact:** Reduces the herd effect and migration churn when hovering near the saturation point. 

## 6. Percentile-Based Task Length Estimation (Refining §I1)
* **Current State:** The task length $l_{ns}$ is estimated using a simple EWMA of measured runtime.
* **Optimization:** A single anomalous long burst can heavily skew the EWMA. Track a lightweight running percentile (e.g., 90th percentile) or variance to better predict the true required quanta. 
* **Expected Impact:** More accurate $\phi$ value calculations, preventing interactive tasks that experience a one-off long execution from being unfairly routed to E-cores.

## 7. Non-Linear Budget Replenishment (Refining §I8)
* **Current State:** Budget replenishment is linear with idle time (up to 1 second).
* **Optimization:** Apply a decaying or logarithmic replenishment curve for long-sleeping tasks. 
* **Expected Impact:** Prevents background tasks from accumulating massive budgets over long idle periods, which can cause disproportionate disruption (latency spikes for steady-state workloads) when they wake up.

## 8. Load-Dependent Starvation Penalty Scaling (Refining §I3)
* **Current State:** The starvation penalty divider $D_{starve} = 1000$ is a fixed scaling constant.
* **Optimization:** Scale $D_{starve}$ dynamically based on system load. Under light load, the penalty can be relaxed (higher $D_{starve}$) so starved tasks get serviced sooner. Under heavy load, the penalty should be stricter to strongly enforce VCG budget boundaries.
* **Expected Impact:** Improved resource isolation during heavy contention while maximizing utilization during off-peak periods.

---

## Iteration log — passmark CPU SUMM_CPU (default `-r 1 -d 1 -i 1`, intel 265K, 8P/12E, kernel 7.0.0-1)

**Bench protocol:** rebuild s4, restart scheduler, drop 1 warmup run, take N measured runs. Score = `Results.SUMM_CPU` from `/tmp/results_cpu.yml`.

**Stock kernel (no s4) — N=3:** mean 63332, σ 95. Tight.

**Bench noise floor (s4):** Bimodal between ~58.8k and ~62.2k. Per-run σ ≈ 1300–1700 (~2.5–3%). Cause is system-level — `intel_pstate` `powersave` governor + EPP `balance_performance`, not thermals (CPU stays <40°C). Locking governor to `performance` was denied; cannot remove this noise floor in-loop. **Detection threshold ≈ ±2σ/√N ≈ ±900 at N=10**; smaller deltas indistinguishable from noise.

### N=20 sequential batch (subject to session-drift confound)

| # | Patch | N | Median | Mean | σ | hi(>61k) |
|---|-------|---|--------|------|---|----------|
| 0 | baseline                                 | 20 | 59670 | 60822 | 1625 | 8/20 |
| 5 | probabilistic P-spill (RED 50→100%)      | 20 | 59586 | 60820 | 1653 | 8/20 |
| 8 | load-dependent `STARVE_PHI_DIV`          | 20 | 60485 | 61032 | 1656 | 10/20 |
| 4 | cache-aware steal (gate `q_other ≥ 2`)   | 20 | 62624 | 61286 | 1652 | 11/20 |

Idea 4 looked like a +2954 median win — but ran last in the batch so the trend tracks session drift more than the patch.

### Idea 4 — interleaved retest (4 windows × {baseline, idea4} × 5 runs)

| Variant  | N | Mean  | Median | σ     | hi(>61k) |
|----------|---|-------|--------|-------|----------|
| baseline | 20 | 60937 | 59748 | 1591 | 9/20 |
| idea 4   | 20 | 60514 | 59610 | 1488 | 7/20 |

Δmean −423, Δmedian −138. Idea 4 apparent win was session drift, **not real**.

### Verdicts

| # | Idea | Verdict |
|---|------|---------|
| 5 | probabilistic P-spill         | revert (Δ ≈ 0) |
| 8 | load-dependent STARVE_PHI_DIV | revert (Δ within 1σ noise) |
| 4 | cache-aware cross-cluster steal | revert (interleaved retest contradicts seq-batch result) |
| –  | cluster migration cooldown 2ms→20ms (sanity test) | revert (regression) |

**Untested (homogeneous CPU-bound passmark predicted to be insensitive):**
- 1 — Adaptive hysteresis fires only on wake; passmark workers rarely wake.
- 2 — Continuous wake-boost: same wake-path argument.
- 3 — Adaptive EWMA decay for `phi_hi`: passmark `phi` ≈ constant across tasks, decay rate irrelevant.
- 6 — Percentile length estimation: passmark consumes ≈ full slice every activation, no outliers to robustify against.
- 7 — Non-linear replenishment: triggers only on `SCX_ENQ_WAKEUP`; passmark doesn't sleep.

**Working hypothesis for the s4 vs stock gap (~5%):** with 20 identical CPU-burn processes, the auction's main mechanisms (cluster routing, budget tracking, VCG payment, wake-boost gating) all fire on a workload they're not designed to optimize. The cost is in hot-path work per enqueue/stopping; the benefit (mixed-workload separation, latency vs throughput trade) is absent. Listed ideas refine knobs *inside* mechanisms that don't help here — none target the hot-path overhead itself.

### Diagnostic: freq distribution traces (per-CPU 250ms sample, full passmark CPU run)

|              | P-cores idle/1-2/2-3/max bins | E-cores idle/1-2/2-3/4.5-5 bins |
|--------------|--------------------------------|--------------------------------|
| stock kernel | 44% / 10% / 7% / 38%           | 9% / **5%**  / 13% / **52%**  |
| s4 baseline  | 26% / 21% / 11% / 41%          | 6% / **21%** / 14% / 49%      |

5s timeline (mean MHz across all CPUs):
- t = 0–25 s (heavy MT subtests: integer/FP/prime/sort/encryption): both schedulers ~5000 MHz max boost — equivalent.
- t = 25–40 s (compression/single-thread/physics transition): both step down (3000–4500 MHz).
- **t = 45–90 s (SSE/MM/FMA/AVX suite, lighter or partial-thread):** stock holds ~2300 MHz, s4 settles ~1900 MHz.

The ~5% SUMM_CPU gap lives in the **last-third subtest window**, not the heavy-MT first window where both run at max boost. Cause is intel_pstate util sampling: stock CFS keeps each active task pinned to a single CPU (runqueue stickiness + load balancer hysteresis) → that CPU shows continuous high util → pstate holds boost. s4's cluster-shared DSQ model rotates tasks across CPUs in the cluster every quantum (each CPU pulls "next task" from shared DSQ when local empties); per-CPU util is fragmented; pstate samples a fragmented duty cycle and picks a mid P-state.

**Verified** (failed attempts):
- Self-pin via `SCX_DSQ_LOCAL_ON | bpf_get_smp_processor_id()` on preempt re-enqueue: median tanked to ~52k. Pinning every preempt re-enqueue removes the rotation but breaks balance — initial cluster-DSQ-driven distribution is uneven, pinned tasks pile on subset of CPUs, others go idle.
- Self-pin gated on `nr_queued(cluster_dsq) == 0`: still tanked (mean 53.8k). Rare to fire under load; when it does fire it makes the imbalance worse.
- STARVED pulled by both clusters (was E-only): freq pattern unchanged, score within noise.

**Per-CPU local DSQ surgery — tried, also regresses.**

Implementation:
1. Create one DSQ per CPU at init (`AUCTION_DSQ_PERCPU_BASE + cpu`).
2. Preempt re-enqueue (no `WAKEUP`, non-`STARVED`) → insert to per-CPU DSQ of current CPU instead of cluster DSQ.
3. Dispatch: pull per-CPU DSQ first, then existing chain (cluster local → cluster other → STARVED).
4. Optional steal loop: when all local-side empty, scan peer per-CPU DSQs in same cluster.

Results (N=5 each):

| Variant | Mean | Median | Note |
|---------|------|--------|------|
| baseline (cluster DSQ only)        | 60822 | 59670 | reference |
| per-CPU DSQ + 32-peer steal scan   | 47834 | 47142 | steal scan in dispatch hot path = expensive |
| per-CPU DSQ, no steal              | 50790 | 50893 | balance breaks: idle peer CPUs can't see tasks pinned on busy peers |

Freq trace for the no-steal variant: P-core max-boost residency dropped from 41 % → 27 %. Per-CPU stickiness without active load-balance leaves P-cores idle while pinned tasks pile on a subset of peers. Worse than baseline.

**Why it's hard to fix without breaking the auction model:**
- Stock CFS = per-CPU runqueue + periodic load-balancer that re-distributes when CPU idle.
- s4 cluster DSQ has no per-CPU runqueue — single shared queue per cluster, drained by any cluster member. Tasks rotate by construction.
- Adding per-CPU DSQs gives the stickiness *but loses the cheap "any peer drains" property*. Need an explicit balance/steal pass — and a cheap one that doesn't tank dispatch latency.
- The steal pass also breaks `EEVDF` deadline ordering: task pinned on CPU X may have lowest vtime globally but CPU Y's pull won't see it until steal fires.

### Per-CPU sticky DSQ — final form **v9** applied (+2.4 % CPU / 0 % MEM)

**v5 wins CPU but tanks MEM** — a CPU-only paired test missed it.  Re-run with `passmark -r 3` (CPU + Memory) showed v5 lost ~31 % MEM median while gaining +3.7 % CPU median.  Not acceptable.

**Diagnosis path:**
- v6 = per-CPU + `BATCH=8`: CPU win disappears (-1424 mean), MEM still hurt → both ingredients required for the CPU win.
- v7 = `BATCH=1` only, no per-CPU: ~baseline CPU, MEM still hurt → BATCH=1 by itself loses the CPU win and still costs MEM.
- v8 = per-CPU + two-phase dispatch (BATCH=8): CPU baseline, MEM **+703 vs baseline** — two-phase recovers mem but loses CPU win.
- v9 = `BATCH=1` + per-CPU **gated to long-running tasks** (`tctx->len_est_ns ≥ AUCTION_SLICE_P`): CPU win restored, MEM neutral.

The mem hurt was not from `BATCH=1` per se — it was from short-quanta tasks (memory-bandwidth threads, schbench-style workers) being pinned via the per-CPU sticky DSQ when they actually need cross-CPU mobility for parallelism.  Gating sticky on `len_est_ns ≥ SLICE_P` (full-quantum CPU-bound pattern) routes long tasks to per-CPU stickiness while leaving short tasks on the cluster DSQ.

**Final v9 paired bench (`-r 3`, 4 windows × 5 runs each, N=20):**

| Metric          | baseline mean / median | v9 mean / median | Δmean        | Δmed         |
|-----------------|-----------------------:|-----------------:|-------------:|-------------:|
| **CPU SUMM_CPU** | 61111 / 60689          | 62580 / 63498    | **+1470 (+2.4 %)** | **+2809 (+4.6 %)** |
| **MEM SUMM_ME**  | 3028 / 2487            | 3017 / 2380      | -11 (~0 %)   | -106 (-4 %, within σ) |

Per-window CPU deltas: +2285 / +1365 / +1330 / +898 — all four windows v9 ahead. MEM per-window mixed (-302 / +304 / +122 / -166), no consistent regression.

**v9 final patch summary (vs `036d111` baseline):**
1. Create per-CPU DSQs at init (`AUCTION_DSQ_PERCPU_BASE + cpu`).
2. Enqueue: preempt re-enqueue (no `WAKEUP`, `last_stop_ns` set, `len_est_ns ≥ AUCTION_SLICE_P`) → per-CPU DSQ of `bpf_get_smp_processor_id()`.  Else fall through to existing cluster DSQ / wake pin paths.
3. Dispatch order: per-CPU DSQ → cluster local → cluster other → STARVED.  Drop the `is_e_local` STARVED-only-on-E gate.
4. `DISPATCH_BATCH_MAX` 8 → 1.

### Original "8 ideas" verdicts (passmark CPU only)

Final form that lands a real win:

1. **Per-CPU DSQs** created at `auction_init` (`AUCTION_DSQ_PERCPU_BASE + cpu`), one per CPU.
2. **Enqueue**: preempt re-enqueue (no `WAKEUP`, task has `last_stop_ns`) routes to `AUCTION_DSQ_PERCPU_BASE + bpf_get_smp_processor_id()` instead of cluster DSQ.  Includes `STARVED` tasks — without that, passmark's saturated steady-state (all budgets drained) skips the sticky path entirely.  WAKEUP path unchanged (cluster DSQ + cache-warm pin via `LOCAL_ON | prev_cpu`).
3. **Dispatch**: per-CPU DSQ → cluster local → cluster other → STARVED.  No steal loop.
4. **Drop the `is_e_local` STARVED gate**: both clusters pull STARVED inline (the previous E-only rule made P-cores idle until the saturation fallback fired).
5. **`DISPATCH_BATCH_MAX` 8 → 1**: was the silent killer.  With BATCH=8 a single dispatch could pull up to 8 tasks from the cluster DSQ before peer CPUs got a chance, producing the same "tasks pile on subset of CPUs" failure that broke the no-steal variant.  BATCH=1 forces fair drain per dispatch — peer CPUs always get to claim from the cluster DSQ.

Paired bench (4 alternating windows × {baseline, v5} × 5 runs, N=20 each):

| Variant   | N  | Mean  | Median | σ    | min   | max   | hi (>61k) |
|-----------|----|-------|--------|------|-------|-------|-----------|
| baseline  | 20 | 60509 | 59569  | 1446 | 59341 | 62872 | 7/20      |
| **v5**    | 20 | **61998** | **61729** | 1676 | **60243** | 63849 | 10/20 |

**Δmean +1489 (+2.5 %), Δmed +2160 (+3.6 %).** v5's worst run (60243) beats the baseline median.  All four paired windows show v5 ahead (Δmean per window +927 / +1512 / +2552 / +967).  Closes most of the ~5 % stock-vs-s4 gap.

Why both ingredients are required:
- **Per-CPU DSQ alone** (BATCH=8): regresses to ~50–60k.  BATCH=8 lets one CPU monopolize cluster DSQ drain → tasks pile on a subset → idle peers, freq drops.
- **BATCH=1 alone** (cluster DSQ only, no per-CPU): tasks still rotate every quantum, freq fragmentation persists.
- **Per-CPU + BATCH=1 together**: tasks distribute one-per-CPU on initial cluster drain, then stay sticky on per-CPU DSQ across slice expiries.

**Suggested next directions (outside listed ideas):**
- Hot-path bypass: when all queued tasks have similar `phi`, skip the per-task auction recompute (cache the routing decision).
- Increase `BUDGET_MUL` to keep CPU-bound tasks out of `STARVED` longer (avoids extra dispatch fallback).
- Lock `cpufreq` governor to `performance` to halve bench noise and unlock smaller-effect-size signal.
