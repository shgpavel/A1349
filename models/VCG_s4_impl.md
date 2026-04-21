# VCG Auction Scheduler — Implementation Notes (scx_auction, s4/A1349)

This document records deviations and refinements from the abstract model (see `VCG_s4.md`) in the concrete BPF scheduler implementation. Theory and implementation are kept in separate files so the model remains canonical and the implementation can evolve independently.

Cross-references of the form §N.N refer to sections of `VCG_s4.md` unless otherwise stated; references of the form §IN refer to sections of this document.

---

## I1. Continuous φ Formula (No Quantization)

The theoretical model (§5.2) computes φ in "quantum" units:

$$\phi_P = v_i - c_P \cdot \lceil l_i / s \rceil, \qquad \phi_E = v_i - c_E \cdot \lceil l_i \sigma / s \rceil$$

Problem: all tasks with $l_i < s$ give $\lceil l_i/s \rceil = 1$, so short tasks have identical $\phi$ regardless of actual length (up to 50× precision loss).

The implementation uses a continuous nanosecond formulation, scaling $v_i$ by $s$:

$$\phi_P = v_i \cdot s - c_P \cdot l_{ns}, \qquad \phi_E = v_i \cdot s - c_E \cdot l_{ns} \cdot \sigma$$

where $l_{ns}$ is the EWMA of measured runtime (ns), $\sigma = \mathtt{max\_cap} / \mathtt{min\_cap}$.

**Key observation:** the P/E routing decision reduces to $c_E \cdot \sigma \geq c_P$ and is independent of $l_{ns}$ in the linear model. However, $\phi$ now continuously reflects "value minus cost" — $\phi < 0$ means a task consumes more resources than it creates value, which is directly used for differentiated starvation strategy (§I3).

---

## I2. Budget-Ratio Task Routing with Hysteresis

In the abstract model, allocation is solved via $\arg\max_\kappa \phi_\kappa(\theta_i)$. Since this reduces to comparing $c_E \sigma$ vs $c_P$ (independent of $l_i$), all tasks under a given topology would be routed to the same DSQ under pure φ-argmax.

The implementation uses a **budget ratio** as a behavioral proxy:

$$\rho_i = \frac{B_i}{B_i^{\max}} \in [0, 1]$$

with **two-sided hysteresis** (not a single threshold):

- $\rho_i \geq \rho_H$ (`BURST_HIGH_PCT` = 70%): task is "bursty" (sleep-heavy, budget replenished) → `AUCTION_DSQ_P`
- $\rho_i < \rho_L$ (`BURST_LOW_PCT` = 30%): task is "CPU-bound" (budget depleted) → `AUCTION_DSQ_E`
- $\rho_L \leq \rho_i < \rho_H$ (deadband): keep the previous cluster choice (`tctx->on_p_type` sticky).

Routing is re-evaluated **only on wake-up** (`SCX_ENQ_WAKEUP`). Preempt re-enqueues always keep the existing cluster to prevent P↔E flip-flop during a running stretch.

**Economic interpretation:** budget accumulates proportional to task idle time ($\Delta t_{\text{idle}} \cdot v_i$), so $\rho_i$ reflects the ratio of idle to active time — a proxy for "how urgently the task needs a fast resource". High $\rho_i$ → interactive, latency-sensitive; low $\rho_i$ → batch, better suited for E-core. The hysteresis deadband is analogous to the **threshold policy with inaction region** in one-dimensional contract auctions: small fluctuations in $\rho_i$ around the midpoint do not trigger re-allocation, preventing migration churn.

---

## I3. Proportional Delay for Starved Tasks

Tasks with $B_i < B_i^{\max} / \mathtt{STARVE\_FRAC}$ are placed in `AUCTION_DSQ_STARVED`. Virtual deadline $v_d$ is shifted proportionally to the $\phi$ deficit:

$$v_d \mathrel{+}= \frac{\max(0,\; -\phi_\kappa)}{D_{\text{starve}}}$$

where $\kappa$ is the core type the task would otherwise be routed to, and $D_{\text{starve}} = 1000$ is a scaling constant.

**Property:** tasks with $\phi < 0$ (cost exceeds value) wait longer than tasks with $\phi \geq 0$; tasks with a deeper deficit wait longer within `AUCTION_DSQ_STARVED`. This approximates the VCG payment: a "more expensive" task bears greater consequences for budget exhaustion.

---

## I4. VCG-Pivot Payment (Vickrey Reserve Form)

Theoretical pivot (§6.2):

$$p_i^t = W_{-i}(s^t) - \bigl[W(s^t) - \phi_\kappa(\theta_i)\bigr]$$

In the single-free-core slot (§9), this collapses to

$$p_i = \phi_\kappa(\theta_j) + (\delta^{m_\kappa(l_j)} - \delta^{m_\kappa(l_i)}) \bar{W}_\kappa,$$

i.e. the winning task pays approximately the effective value of the *second*-best competing type. Computing $W_{-i}$ exactly in a BPF hook is infeasible; the implementation carries an $O(1)$ local approximation.

### I4.1 Per-Cluster $\varphi_{\text{hi}}$ Estimator

For each cluster $\kappa \in \{P, E\}$ a global field $\varphi_{\text{hi},\kappa}$ tracks the running positive maximum of $\phi_\kappa$ observed at enqueue-time. Update on every non-starved enqueue to DSQ $\kappa$:

$$\varphi_{\text{hi},\kappa} \leftarrow \begin{cases} \phi_\kappa(\theta_i) & \text{if } \phi_\kappa(\theta_i) > \varphi_{\text{hi},\kappa} \\ \tfrac{15\,\varphi_{\text{hi},\kappa} + \max(0, \phi_\kappa(\theta_i))}{16} & \text{otherwise (EWMA, } \alpha = 1/16\text{)} \end{cases}$$

Climb-fast / decay-slow: a new high is picked up instantly, but absent reinforcement the estimator relaxes toward zero so a stale burst does not overcharge later tasks. Under stationary workloads this converges to (a smoothed estimate of) the maximum competing $\phi$ — the local statistic that $W_{-i}$ reduces to under Myerson's regular-distribution equivalence for single-item auctions.

### I4.2 Payment Formula

At `auction_stopping`, in place of the linear posted price:

$$p_i = \max\bigl(c_\kappa \cdot \tfrac{t_{\text{consumed}}}{s},\;\; \varphi_{\text{hi},\kappa} \cdot \tfrac{t_{\text{consumed}}}{s^2}\bigr)$$

where $s = \mathtt{SCX\_SLICE\_DFL}$ (5 ms) and $t_{\text{consumed}} = s - \mathtt{p->scx.slice}$. The two terms normalise to the same budget units: $\varphi_{\text{hi},\kappa}$ carries units of weight·ns, so dividing by $s^2$ rescales to per-ns weight, then $\cdot\,t_{\text{consumed}}$ yields weight-equivalent payment per slice — the same order as $c_\kappa \cdot t_{\text{consumed}}/s$.

This is the **Vickrey reserve form**: $c_\kappa$ acts as a Myerson reserve price (posted cost of occupying cluster $\kappa$), and the pivot term lifts the payment toward the externality whenever competing tasks are queued.

### I4.3 Properties

- **IR preserved.** The cost-based floor guarantees $p_i \geq c_\kappa \cdot t_{\text{consumed}}/s$, matching the pre-pivot posted-price; a task never pays less than it did before.
- **Cold-queue degeneracy.** When cluster $\kappa$ is idle or has only negative-$\phi$ tasks, $\varphi_{\text{hi},\kappa} \to 0$ and $p_i$ reduces to the linear posted price — the previous behaviour is the zero-pivot limit of the new formula.
- **IC in the limit.** Under stationary arrivals and monotone hazard rate (Sano Thm 1 preconditions, §8.1), $\varphi_{\text{hi},\kappa}$ converges to the top-order statistic of $\phi_\kappa$ over the stationary type distribution, so $p_i$ approaches the second-price/pivot regime and the mechanism recovers incentive compatibility asymptotically.
- **First-quantum penalty still eliminated.** Both terms scale with $t_{\text{consumed}}$, so short tasks are not overcharged.
- **$O(1)$ in the hook.** One load from global state, two multiplies, one compare — no queue scan, no per-task externality computation.

---

## I5. Wake-Latency Boost (VCG Budget ↔ EEVDF Deadline Link)

The virtual deadline for task $i$ in the standard EEVDF formulation is:

$$v_d = v_e + \frac{q_{\max} \cdot \mathtt{SCALE}}{w_i}$$

where $q_{\max} = \mathtt{max\_cap} \cdot s / \mathtt{CAPACITY\_SCALE}$ is the capacity-normalised quantum and $w_i$ is the task's weight (Linux nice-scaled).

On wake-up, if the task has $\rho_i \geq \rho_H$ (high-budget / bursty / interactive), the deadline gap is **halved**:

$$v_d = v_e + \frac{q_{\max} \cdot \mathtt{SCALE}}{2 \cdot w_i} \qquad \text{(wake + } \rho_i \geq \rho_H\text{)}$$

**Economic semantics.** A task with high $\rho_i$ has accumulated budget without spending — in auction terms, its virtual valuation $\varphi(\theta_i)$ is **above** its recent payments $\sum p_i^t$. The utility balance $u_i = v_i - \sum p_i$ is positive and growing. The boost mechanises a step of the social cost minimisation (§4.2):

$$\mathrm{SC}(\pi) = W(\pi) - \lambda_F \cdot \mathrm{Var}_i\!\left[u_i / v_i\right]$$

Pulling a task with large $u_i / v_i$ forward in the dispatch order reduces the variance term: tasks "behind schedule" on their v_i-share get priority, shrinking the fairness gap. Preempt re-enqueues are excluded — a running task extending its own stay would not satisfy "behind schedule".

**Fairness properties preserved.** The boost is bounded (half-gap, never below $v_e$), budget-gated (CPU-bound tasks get no boost), and reverts to baseline once $\rho_i$ falls below $\rho_H$. It does not alter φ, payment, or budget accounting.

---

## I6. Dispatch Order and Cross-Cluster Work-Stealing

Each CPU runs `ops.dispatch()` when it needs a task. The local DSQ is the one matching the CPU's cluster ($\kappa(\text{cpu}) \in \{P, E\}$ via 90%-of-max-cap classification). Dispatch priority:

$$\text{local cluster DSQ} \;\succ\; \text{cross-cluster DSQ} \;\succ\; \mathtt{AUCTION\_DSQ\_STARVED}$$

Cross-cluster work-stealing is **unconditional** in both directions. This follows directly from §1.1: *"unused quanta are lost"* — an idle slot is a strict welfare loss. A P-core consuming an E-queued task runs it faster, strengthening φ_E realisation; an E-core consuming a P-queued task is suboptimal per §5.2 but strictly preferable to waste. Cluster preference is maintained upstream at enqueue-time routing (§I2), not by dispatch gating.

---

## I7. Work-Conservation Overrides

Three mechanisms short-circuit the §I2 routing rule when idle capacity is available.

### I7.1 Idle-Wake Local Dispatch

`ops.select_cpu()` calls `scx_bpf_select_cpu_dfl()`, which returns an idle CPU if any exists in the task's allowed set (with prev_cpu/waker affinity preference). If the returned CPU's cluster matches the task's preferred DSQ (§I2), the task is inserted into `SCX_DSQ_LOCAL` directly — it bypasses the global DSQs and runs immediately. If the cluster does not match, a single probe is made for an idle CPU in the preferred cluster; if found, the task is swapped to that CPU. If not found, the original (wrong-cluster) idle CPU is used anyway.

Rationale: §1.1 welfare loss applies equally to cluster-purity violations. An idle E-core running a P-preferred task is strictly better than that task queueing behind a busy P-core. The one-probe cluster preference adds minimal overhead while restoring affinity on the common case.

### I7.2 P-Cluster Saturation Spill

At enqueue, if the §I2 routing rule selects `AUCTION_DSQ_P` and the current queue depth is at or above the P-core count:

$$\mathtt{scx\_bpf\_dsq\_nr\_queued}(\mathtt{AUCTION\_DSQ\_P}) \geq K_P$$

the task is spilled to `AUCTION_DSQ_E`. This enforces the feasibility constraint $\sum_i a_{i,P}^t \leq K_P^t$ (§2.2) at enqueue time rather than letting the P-queue grow unbounded while E-cores starve. $K_P$ is populated by userspace from `/sys/devices/system/cpu/cpu*/cpu_capacity` (90% threshold).

### I7.3 Kick-on-Enqueue

After `scx_bpf_dsq_insert_vtime()`, the enqueue path probes for any idle CPU in the task's allowed set and sends `SCX_KICK_IDLE` if one is found. Without this, deeply-idle CPUs (common for E-cores under P-dominated workloads) would not run `ops.dispatch()` until the next timer tick, stranding queued tasks. The probe is self-gating: when no idle CPU exists, `scx_bpf_pick_idle_cpu()` returns $-1$ and no IPI fires — moderate workloads pay only the probe cost.

---

## I8. Implementation Parameters

| Constant | Value | Meaning |
|----------|-------|---------|
| `C_P_DEF` | 512 | Default P-core cost $c_P$ (overridden by CLI `-p`) |
| `C_E_DEF` | 256 | Default E-core cost $c_E$ (overridden by CLI `-e`) |
| `BURST_HIGH_PCT` | 70 | Upper routing threshold $\rho_H$ — bursty → P |
| `BURST_LOW_PCT` | 30 | Lower routing threshold $\rho_L$ — CPU-bound → E |
| `BUDGET_MUL` | 2000 | $B_i^{\max} = w_i \cdot \mathtt{BUDGET\_MUL}$ |
| `REPLENISH_DIV` | 5,000,000 | Budget replenishment divisor (ns per unit) |
| `REPLENISH_IDLE_CAP` | $10^9$ | Max idle interval counted for replenishment (1 s) |
| `STARVE_FRAC` | 10 | Starvation threshold: $B_i < B_i^{\max}/10$ |
| `STARVE_PHI_DIV` | 1000 | φ deficit → $v_d$ units divisor |
| `P_CAP_PCT` | 90 | P-core classification threshold (% of max\_cap) |
| `DISPATCH_BATCH_MAX` | 8 | Max tasks moved to local per `dispatch()` call |
| `SCALE` | 100 | Virtual-time fixed-point numerator (matches s3+) |
| `INV_SHIFT` | 20 | Inverse-weight fixed-point shift |

Runtime context (`auction_ctx`, populated by userspace):

| Field | Meaning |
|-------|---------|
| `max_capacity` | $\max_k \mathtt{cpu\_capacity}[k]$ — highest core capacity |
| `min_capacity` | $\min_k \mathtt{cpu\_capacity}[k]$ — used for $\sigma = \mathtt{max}/\mathtt{min}$ |
| `cost_p`, `cost_e` | Runtime-tuned $c_P, c_E$ (CLI overrides) |
| `p_core_count`, `e_core_count` | Per-cluster CPU counts (for §I7.2 spill) |
| `vtime_now`, `total_weight` | Global EEVDF virtual-time and weight sum |

---

## I9. Mapping: Implementation → Model

Quick reference from source-code artefacts back to the abstract model.

| Code artefact | Model symbol / section |
|---------------|------------------------|
| `p->scx.weight` | $v_i$ (valuation) — §1.2 |
| `tctx->len_est_ns` | $l_{ns}$ — proxy for $l_i$ — §I1 |
| `tctx->budget`, `tctx->budget_max` | $B_i, B_i^{\max}$ — §1.3 |
| `gdata->cost_p`, `cost_e` | $c_P, c_E$ — §3.2 |
| `compute_phi()` | $\phi_P, \phi_E$ — §5.2, §I1 |
| `auction_enqueue()` routing | allocation $a^t$ — §2.2, §I2, §I7 |
| `scx_bpf_dsq_insert_vtime(... vd ...)` | EEVDF deadline ordering ≈ argmax selection — §5.1 |
| `auction_stopping()` budget update | VCG-pivot payment $p_i^t$ — §6.2, §I4 |
| `gdata->dsq_phi_hi_p/e` | $\varphi_{\text{hi},\kappa}$ pivot estimator — §I4.1 |
| `AUCTION_DSQ_STARVED` | budget-feasibility rejection — §8.3, §I3 |
| `auction_running()` / `auction_stopping()` vtime | capacity-weighted virtual time — §I1 |
