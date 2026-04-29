# ML-Guided Layered Topology-Aware Scheduler (s5)

## 1. System Model

### 1.1 Hardware Topology

The CPU is modelled as a finite set of cores $\mathcal{C} = \{1, \ldots, K\}$ partitioned into **topological domains**:

$$\mathcal{C} = \bigsqcup_{d \in \mathcal{D}} \mathcal{C}_d$$

where $\mathcal{D}$ is the set of domains. A domain captures any of the relevant hardware boundaries:

- core class (P-core, E-core, mixed),
- last-level cache (LLC),
- NUMA node,
- SMT sibling group,
- thermal/power island.

A domain $d \in \mathcal{D}$ carries static descriptors $\eta_d = (\text{cap}_d,\; \text{energy}_d,\; \text{llc}_d,\; \text{numa}_d)$ and dynamic descriptors $\omega_d^t = (\text{load}_d^t,\; \text{thermal}_d^t,\; \text{freq}_d^t)$.

Time is discrete: $t = 1, 2, \ldots$

### 1.2 Tasks

At time $t$ the system contains active tasks $\mathcal{N}^t$. Each task $i$ has an unobservable behavioural type:

$$\theta_i = (\beta_i,\; \mu_i,\; \tau_i) \in \Theta$$

where $\beta_i$ is the burstiness/voluntary-ctxsw rate, $\mu_i$ is memory-bandwidth pressure (LLC-miss, MPKI), and $\tau_i$ is the latency sensitivity. $\theta_i$ is **not** declared by the task; it is inferred from runtime signals.

Observable per-task signals at time $t$:

$$o_i^t = (r_i^t,\; \text{vcs}_i^t,\; \text{ipc}_i^t,\; \text{mpki}_i^t,\; \text{cgroup}_i,\; \text{nice}_i)$$

— recent runtime, voluntary context-switch rate, IPC, LLC-miss-per-kilo-instr, cgroup id, nice value.

### 1.3 Layers (Task Classes)

Tasks are mapped to a finite layer set $\mathcal{L}$:

$$\mathcal{L} = \{\text{INT},\; \text{FG},\; \text{NRM},\; \text{BAT},\; \text{BG},\; \text{MEM}\}$$

(interactive, foreground, normal, batch, background, memory-bound). The classifier $\chi: \Theta \to \mathcal{L}$ is realised by the userspace advisor (§7); the kernel never re-derives $\chi$ from raw signals.

### 1.4 Layer × Domain Product

The fundamental scheduling unit is a (layer, domain) pair:

$$\mathcal{Q} = \mathcal{L} \times \mathcal{D}$$

Each $(\ell, d) \in \mathcal{Q}$ has a **dispatch queue (DSQ)** $Q_{\ell,d}$ with a queue id

$$\text{dsq}(\ell, d) = (\ell \ll 32) \mid d.$$

---

## 2. State and Action

### 2.1 State

$$s^t = \bigl(\mathbf{x}^t,\; \mathbf{q}^t,\; \boldsymbol{\omega}^t,\; \pi^t\bigr)$$

- $\mathbf{x}^t \in (\mathcal{N}^t \cup \{\bot\})^K$ — current task on each core ($\bot$ for idle),
- $\mathbf{q}^t = (Q_{\ell,d}^t)_{(\ell,d) \in \mathcal{Q}}$ — DSQ contents,
- $\boldsymbol{\omega}^t = (\omega_d^t)_{d \in \mathcal{D}}$ — domain-level dynamic descriptors,
- $\pi^t$ — currently active policy (§4), updated only by the control plane.

### 2.2 Action

A control step at time $t$ on core $k \in \mathcal{C}_d$:

$$a_k^t = (i,\; \ell,\; \Delta_k^t),\quad i \in Q_{\ell,d}^t \cup \{\bot\},\quad \Delta_k^t \in \mathbb{R}_{>0}$$

— pick task $i$ from layer $\ell$ on local domain $d$ (or work-steal, §6.2) and grant slice $\Delta_k^t$. The slice is drawn from the layer policy: $\Delta_k^t = \text{slice}_\ell(\pi^t)$.

Policy updates by the control plane are a separate, low-frequency action

$$A^{\text{ctl},t} \in \{\text{noop},\; \text{commit}(\pi')\}$$

constrained by §8.

### 2.3 Transition

$$s^{t+1} = G(s^t,\; \mathbf{a}^t,\; A^{\text{ctl},t},\; N_{t+1},\; \xi_{t+1})$$

with $N_{t+1}$ stochastic task arrivals/wakeups and $\xi_{t+1}$ exogenous topology dynamics (frequency, thermal, hotplug).

---

## 3. Two-Timescale Architecture

The scheduler splits decisions across two clocks.

| Plane | Tool | Frequency | Decisions |
|-------|------|-----------|-----------|
| Data plane | BPF / `sched_ext` callbacks | per wakeup / tick (µs) | `select_cpu`, `enqueue`, `dispatch`, `stopping`, slice grant |
| Control plane | userspace advisor (ML) | epoch (10 ms – 1 s) | $\chi$ (classification), $\pi$ (policy maps) |

Let $\Delta_{\text{ctl}}$ be the control epoch and $\Delta_{\text{data}}$ a typical scheduling tick. The architecture **requires**

$$\Delta_{\text{ctl}} \gg \Delta_{\text{data}},\qquad \frac{\Delta_{\text{ctl}}}{\Delta_{\text{data}}} \geq M$$

with $M$ large enough that the data plane sees $\pi$ as constant within an epoch (i.e. policy never changes inside a hot path).

**Communication channel.** All control→data signalling uses BPF maps (§4.5). The data plane never blocks on userspace; if the advisor stalls, $\pi^t = \pi^{t-1}$ remains in force (§9.1).

---

## 4. Policy

### 4.1 Class Policy

For each layer $\ell \in \mathcal{L}$:

$$\pi_\ell = (w_\ell,\; \underline{s}_\ell,\; \overline{s}_\ell,\; \Delta_\ell,\; \rho_\ell,\; M_\ell^{\text{pref}},\; M_\ell^{\text{fall}},\; \text{mode}_\ell,\; T_\ell^{\text{starve}})$$

| Symbol | Meaning |
|--------|---------|
| $w_\ell$ | layer weight (inter-layer fairness) |
| $\underline{s}_\ell, \overline{s}_\ell$ | min / max share of total CPU (∈ $[0,1]$) |
| $\Delta_\ell$ | base slice |
| $\rho_\ell$ | preempt priority |
| $M_\ell^{\text{pref}} \subseteq \mathcal{D}$ | preferred domain mask |
| $M_\ell^{\text{fall}} \subseteq \mathcal{D}$ | fallback domain mask |
| $\text{mode}_\ell \in \{\text{pack}, \text{spread}\}$ | placement mode |
| $T_\ell^{\text{starve}}$ | starvation deadline |

### 4.2 Domain Policy

For each domain $d \in \mathcal{D}$:

$$\pi_d = (\text{cap}_d,\; \text{e-cost}_d,\; \overline{\text{load}}_d,\; \text{allow}_d \subseteq \mathcal{L})$$

— scaled capacity, energy cost, load ceiling, set of layers allowed to occupy $d$.

### 4.3 Task Policy

For each task $i$:

$$\pi_i = (\ell_i,\; M_i^{\text{pref}},\; M_i^{\text{fall}},\; \Delta_i,\; w_i,\; \text{pen}_i^{\text{mig}},\; \text{bias}_i^{\text{lat}},\; T_i^{\text{valid}})$$

Per-task entries override class defaults. $T_i^{\text{valid}}$ is a TTL: once $t > T_i^{\text{valid}}$, the data plane falls back to $\pi_{\ell_i}$ derived from a deterministic kernel-resident classifier (§9.1).

### 4.4 Effective Policy

The data plane reads policy at each callback as

$$\pi^t(i,\; d,\; k) = \text{merge}\bigl(\pi_{\ell_i}^t,\; \pi_d^t,\; \pi_i^t\bigr)$$

with task overrides dominating class, class dominating domain.

### 4.5 Map Schema

| Map | Key | Value |
|-----|-----|-------|
| `class_policy` | $\ell$ | $\pi_\ell$ |
| `domain_policy` | $d$ | $\pi_d$ |
| `task_policy` | pid / tgid / cgroup id | $\pi_i$ |
| `cpu_info` | $k$ | $(\text{class}_k, d_k, \text{cap}_k)$ |
| `global_policy` | $0$ | epoch, feature flags |
| `stats` | various | counters exported to userspace |

---

## 5. Scheduling Discipline

### 5.1 Inter-Layer Selection

Across layers, the dispatcher picks by **priority with a budget guard**. Let $u_\ell^t \in [0,1]$ be the running CPU share of layer $\ell$. The set of dispatchable layers on domain $d$ at time $t$:

$$\mathcal{L}_d^t = \bigl\{\ell \in \mathcal{L} : Q_{\ell,d}^t \neq \emptyset,\; \ell \in \text{allow}_d,\; u_\ell^t < \overline{s}_\ell\bigr\}$$

Add starving layers regardless of cap:

$$\mathcal{L}_d^{t,\star} = \mathcal{L}_d^t \;\cup\; \bigl\{\ell : u_\ell^t < \underline{s}_\ell\bigr\}$$

Pick

$$\ell^* = \arg\max_{\ell \in \mathcal{L}_d^{t,\star}} \rho_\ell.$$

### 5.2 Intra-Layer Discipline

Inside DSQ $Q_{\ell,d}$ tasks are ordered by **weighted virtual time** (EEVDF-style):

$$v_i^{t+1} = v_i^t + \frac{\Delta_i^t}{w_i \cdot w_\ell},\qquad d_i = v_i + \frac{\Delta_i}{w_i \cdot w_\ell}$$

Pick the task with smallest virtual deadline $d_i$ subject to $v_i \leq V_{\ell,d}^t + \epsilon$, where $V_{\ell,d}^t$ is the layer-domain virtual clock.

Pure FIFO is admissible only for $\ell = \text{BG}$.

### 5.3 Placement and Migration

A migration $i: d_1 \to d_2$ incurs penalty $\text{pen}_i^{\text{mig}}$. A task migrates only if

$$\phi_i(d_2) - \phi_i(d_1) \geq \text{pen}_i^{\text{mig}} + \epsilon^{\text{hyst}}$$

where $\phi_i(d) = \text{bias}_i^{\text{lat}} \cdot \text{cap}_d - \text{load-cost}(d)$. The hysteresis term $\epsilon^{\text{hyst}}$ prevents flip-flop (§8.2).

---

## 6. Data-Plane Callbacks

### 6.1 `select_cpu(i, k_{\text{prev}}, \text{wake-flags})`

```
π = effective_policy(i)
if  k_prev ∈ allowed(i)  ∧  k_prev ∈ M_i^pref
    ∧ cache_hot(i, k_prev) ∧ ¬overloaded(k_prev):
        return k_prev
k = idle_in(M_i^pref)
if k ≠ ∅:    return k
k = idle_in(M_i^fall)
if k ≠ ∅:    return k
return scx_bpf_select_cpu_dfl(i, k_prev, wake_flags)
```

The returned CPU is a **hint**: the kernel may override it if the cpumask of $i$ excludes it. If a strong-confidence idle hit is found, the task may be inserted directly into `SCX_DSQ_LOCAL_ON | k`.

### 6.2 `enqueue(i)`

```
π = effective_policy(i)
ℓ = π.layer
d = choose_domain(π, prev_d, ω^t)
Q = DSQ(ℓ, d)
if uses_vtime(ℓ):
    insert_vtime(i, Q, deadline=d_i)
else:
    insert_fifo(i, Q)
```

### 6.3 `dispatch(k)` on $k \in \mathcal{C}_d$

```
ℓ* = inter_layer_pick(d)        // §5.1
i  = intra_layer_pick(ℓ*, d)    // §5.2
if i = ∅:
    i = work_steal(d)           // §6.4
grant_slice(i, Δ_ℓ*)
```

### 6.4 Work-Stealing

If $\bigcup_\ell Q_{\ell,d} = \emptyset$, attempt to pull from $d' \in M_\ell^{\text{fall}}$ in priority order; respect $\text{allow}_{d}$ and the migration penalty (§5.3).

### 6.5 `stopping(i, runtime)`

Update $v_i$, EWMA of slice utilisation, and exported counters in `stats`.

---

## 7. Control-Plane ML Advisor

### 7.1 Observation Window

Over an epoch $[t, t + \Delta_{\text{ctl}})$ the advisor aggregates:

$$O^t = \bigl(\{o_i^\tau\}_{i,\tau},\; \{\omega_d^\tau\}_{d,\tau},\; \text{stats}^t\bigr)$$

### 7.2 Classifier

$$\chi_\psi : O^t \to \prod_{i \in \mathcal{N}^t} \mathcal{L}$$

parameterised by $\psi$ (small neural net, GBM, or rule cascade). Output layer ids are pushed via `task_policy`.

### 7.3 Policy Generator

$$g_\theta : O^t \to (\pi_\ell^{t+1})_{\ell \in \mathcal{L}} \times (\pi_d^{t+1})_{d \in \mathcal{D}}$$

Optimisation objective is the operational utility

$$U(\pi) = \mathbb{E}\!\left[\sum_{\ell} \alpha_\ell \cdot \text{SLO}_\ell - \beta \cdot E_{\text{energy}} - \gamma \cdot \sum_\ell \mathbb{1}[\text{starve}_\ell]\right]$$

— SLO satisfaction per layer (latency for INT/FG, throughput for BAT, etc.) minus energy cost minus starvation count.

### 7.4 Epoch Double-Buffer Commit

Two policy banks $\pi[0], \pi[1]$ live in BPF maps with epoch counter $e^t$.

```
inactive  = 1 - e^t
write π'  → π[inactive]
mb()
WRITE_ONCE(epoch, inactive)
```

The data plane reads `epoch` once per callback and uses the corresponding bank; therefore no callback ever observes a half-updated $\pi$.

### 7.5 Deterministic Fallback Classifier

A small kernel-resident rule cascade $\chi^{\text{fb}}$ runs whenever $\pi_i$ is missing or stale:

$$\chi^{\text{fb}}(i) = \begin{cases}
\text{INT} & \text{vcs}_i > \tau_{\text{vcs}} \\
\text{MEM} & \text{mpki}_i > \tau_{\text{mpki}} \\
\text{BG}  & \text{cgroup}_i \in \mathcal{G}_{\text{bg}} \\
\text{NRM} & \text{otherwise}
\end{cases}$$

This guarantees the data plane never depends on advisor liveness for correctness (§9.1).

---

## 8. Stability Constraints

The closed loop {ML advisor → policy → kernel → telemetry → ML advisor} is the principal failure mode. The following constraints bound feedback:

### 8.1 Bounded Update Step

For every numeric policy field $x$:

$$\bigl| x^{t+1} - x^t \bigr| \leq \eta \cdot |x^t|,\qquad \eta < 1$$

— per-epoch relative change is capped (e.g. $\eta = 0.25$).

### 8.2 Hysteresis

Routing or migration decisions use a two-sided threshold $(\tau_L, \tau_H)$ with $\tau_L < \tau_H$; the deadband prevents oscillation under noise.

### 8.3 Cooldown

After a commit at $t$, no further commit before $t + T_{\text{cool}}$. Emergency overrides (overload, runaway) bypass cooldown but log the event.

### 8.4 Confidence Gate

Each generator output carries a confidence $c \in [0, 1]$. Commit only if $c \geq c_{\min}$; otherwise re-emit the previous policy ($\pi^{t+1} = \pi^t$).

### 8.5 Last-Known-Good

A persisted policy $\pi^{\text{LKG}}$ — the most recent policy that produced non-degraded telemetry — is restored on watchdog trip (§9.3).

---

## 9. Safety Properties

### 9.1 Liveness Without Advisor

$$\forall t,\ \pi^t \text{ defined} \;\implies\; \text{advisor crash} \Rightarrow \pi^{t+1} = \pi^t.$$

The data plane operates indefinitely on the last policy bank. New tasks classify under $\chi^{\text{fb}}$.

### 9.2 Starvation Bound

For every task $i$ in DSQ $Q_{\ell,d}$:

$$\text{wait}_i \leq T_\ell^{\text{starve}}$$

Enforced by promoting tasks past $T_\ell^{\text{starve}}$ to a high-priority emergency DSQ that bypasses inter-layer caps (§5.1, $u_\ell^t < \underline{s}_\ell$ branch).

### 9.3 Watchdog and Rollback

`sched_ext` provides a runnable-stall watchdog. On trip:

```
1. revert epoch → previous bank
2. if stall persists: install π^LKG
3. if stall persists: scx_bpf_error → fall back to fair class
```

### 9.4 Partial Switch (Development)

`SCX_OPS_SWITCH_PARTIAL` confines the scheduler to tasks with `policy = SCHED_EXT`, leaving `SCHED_NORMAL/BATCH/IDLE` on CFS/EEVDF. Used for staged rollout (test cgroups → all normal → production).

---

## 10. Existing Reference Schedulers

The model takes structural inspiration from three sched_ext schedulers:

| Reference | Borrowed concept |
|-----------|------------------|
| `scx_layered` | layer abstraction + per-layer policy |
| `scx_rusty` | userspace control plane / BPF data plane split with domain balancing |
| `scx_bpfland` | BPF-side interactive detection as deterministic fallback |

s5 differs from each by combining (i) layered classes, (ii) topology-aware domains beyond LLC, and (iii) a learned policy generator with epoch double-buffering and stability constraints.

---

## 11. MVP

A minimal instance of the model:

- $\mathcal{L} = \{\text{INT},\; \text{NRM},\; \text{BG}\}$
- $\mathcal{D} = \{\text{BIG},\; \text{LITTLE}\}$
- DSQs: $\{Q_{\text{INT,BIG}},\; Q_{\text{INT,LITTLE}},\; Q_{\text{NRM,BIG}},\; Q_{\text{NRM,LITTLE}},\; Q_{\text{BG,LITTLE}}\}$
- $\chi$: rule-based (foreground cgroup → INT, system.slice → BG, else NRM)
- intra-layer: weighted vtime (§5.2)
- placement: $\text{INT} \to \text{BIG}$ preferred; $\text{BG} \to \text{LITTLE}$ only; $\text{NRM} \to \text{LITTLE}$ first, $\text{BIG}$ on saturation.

Subsequent milestones add: PMU-driven $\chi$, learned $g_\theta$, MEM layer, energy/thermal terms in $U$, cgroup quotas, automated tuning of $w_\ell, \overline{s}_\ell$.

---

> **Theory ends here.** Sections §1–§9 are the abstract model (topology, state, two-timescale architecture, policy, discipline, ML advisor, stability, safety). Concrete BPF realisation — map layouts, exact thresholds, classifier features, training pipeline — belongs in a separate `s5_ML_impl.md`.
>
> Changes to §1–§9 require re-derivation; changes to implementation notes do not.

---

## 12. Notation Summary

| Symbol | Meaning |
|--------|---------|
| $\mathcal{C}, K$ | Cores; $K = |\mathcal{C}|$ |
| $\mathcal{D}$ | Topological domains |
| $\mathcal{C}_d$ | Cores in domain $d$ |
| $\eta_d, \omega_d^t$ | Static / dynamic domain descriptors |
| $\mathcal{N}^t$ | Active tasks at $t$ |
| $\theta_i$ | Behavioural type (burstiness, memory pressure, latency sensitivity) |
| $o_i^t$ | Observable per-task signal vector |
| $\mathcal{L}$ | Layer (class) set |
| $\chi$ | Classifier $\Theta \to \mathcal{L}$ |
| $\chi^{\text{fb}}$ | Deterministic kernel fallback classifier |
| $\mathcal{Q} = \mathcal{L} \times \mathcal{D}$ | DSQ index space |
| $Q_{\ell,d}$ | Dispatch queue for layer $\ell$, domain $d$ |
| $\pi_\ell, \pi_d, \pi_i$ | Class / domain / task policy |
| $w_\ell, \rho_\ell, \Delta_\ell$ | Layer weight, preempt priority, slice |
| $\underline{s}_\ell, \overline{s}_\ell$ | Min / max CPU share of layer |
| $M_\ell^{\text{pref}}, M_\ell^{\text{fall}}$ | Preferred / fallback domain masks |
| $u_\ell^t$ | Running share of layer $\ell$ |
| $v_i, d_i$ | Virtual time, virtual deadline |
| $V_{\ell,d}^t$ | Layer-domain virtual clock |
| $\Delta_{\text{ctl}}, \Delta_{\text{data}}$ | Control / data epoch length |
| $e^t$ | Epoch counter (double-buffer index) |
| $g_\theta$ | Policy generator (parameters $\theta$) |
| $U(\pi)$ | Operational utility |
| $\eta$ | Bounded-update step cap |
| $\tau_L, \tau_H$ | Hysteresis thresholds |
| $T_{\text{cool}}$ | Commit cooldown |
| $c_{\min}$ | Minimum confidence to commit |
| $\pi^{\text{LKG}}$ | Last-known-good policy |
| $T_\ell^{\text{starve}}$ | Layer starvation deadline |
