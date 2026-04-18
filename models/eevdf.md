# EEVDF — Earliest Eligible Virtual Deadline First

Mathematical model of the proportional-share scheduler proposed by Ion Stoica
and Hussein Abdel-Wahab (ODU TR-95-22, revised Jan 1996). Source: `eevdf_fixed.pdf`.

EEVDF is the theoretical foundation for the Linux `SCHED_NORMAL` class (since
kernel 6.6) and for this repo's `impl/s3` baseline and `impl/s3+` capacity-aware
variant. It unifies **proportional-share** allocation with **real-time-style
deadline guarantees** on top of a shared, quantized resource (CPU, link, etc.).

---

## 1. System Model

### 1.1 Resource and quanta
- A single time-shared resource allocated in quanta of size at most `q`.
- At the start of each quantum, the scheduler picks one client.
- A client may release the quantum early (e.g. blocks on I/O).

### 1.2 Clients, weights, shares
Each client `i` carries a weight `w_i > 0`. Let `A(t)` be the set of active
clients at time `t` (active ≡ has a pending request). The ideal instantaneous
share is

```
f_i(t) = w_i / Σ_{j ∈ A(t)} w_j           (Eq. 1)
```

### 1.3 Ideal (fluid-flow) service
In the idealized fluid-flow system (`q → 0`), the service owed to client `i`
while continuously active over `[t_0, t_1]` is

```
S_i(t_0, t_1) = ∫_{t_0}^{t_1} f_i(τ) dτ    (Eq. 2)
```

### 1.4 Service-time lag
Let `t_0^i` be the time `i` became active and `s_i(t_0^i, t)` the real service
received. The **lag** — the central fairness metric — is

```
lag_i(t) = S_i(t_0^i, t) − s_i(t_0^i, t)   (Eq. 3)
```

- `lag > 0` → client was under-served (owed time).
- `lag < 0` → client was over-served.

---

## 2. Virtual Time

### 2.1 System virtual time
```
V(t) = ∫_0^t  1 / Σ_{j ∈ A(τ)} w_j  dτ     (Eq. 5)
```
Rate of `V` is inverse to total active weight: competition increases → `V`
slows. In one virtual-time unit each active client accumulates exactly `w_i`
real-time units of entitlement.

### 2.2 Service in terms of V
Combining Eqs. 1, 2, 5:
```
S_i(t_1, t_2) = w_i · ( V(t_2) − V(t_1) )  (Eq. 6)
```
Entitlement is linear in virtual time with slope `w_i`.

---

## 3. Per-Request Quantities: Eligible Time and Deadline

Each request `k` from client `i` carries length `r^(k)` (service needed),
virtual eligible time `ve^(k)`, and virtual deadline `vd^(k)`.

### 3.1 Eligible time
A request is **eligible** at time `t` iff `ve ≤ V(t)`. Construction: pick `e`
such that, in the fluid-flow model, the entitlement up to `e` equals the real
service already delivered, `S_i(t_0^i, e) = s_i(t_0^i, t)`. Via Eq. 6:

```
V(e) = ve = V(t_0^i) + s_i(t_0^i, t) / w_i (Eq. 7)
```

Effect:
- Client with **negative lag** (over-served) → `ve > V(t)` → request held back
  until the fluid system "catches up". Other clients get preferred access.
- Client with **positive lag** (under-served) → `ve < V(t)` → immediately
  eligible.

At the moment a request becomes eligible, `lag_i(e) ≥ 0` always.

### 3.2 Virtual deadline
Pick `d` s.t. the fluid system would deliver exactly `r` over `[e, d]`:
`S_i(e, d) = r`. Via Eq. 6:
```
vd = ve + r / w_i                          (Eq. 8)
```
Lighter weight → later deadline. Longer request → later deadline.

### 3.3 Request recurrence
If the client consumes its full request each time:
```
ve^(1)   = V(t_0^i)
vd^(k)   = ve^(k) + r^(k) / w_i            (Eqs. 9, 10)
ve^(k+1) = vd^(k)                          (Eq. 11)
```
If the client used only `u^(k) ≤ r^(k)` (blocked early), the update becomes
```
ve^(k+1) = ve^(k) + u^(k) / w_i            (Eq. 12)
```
The "unused" quantum is not forfeited — eligible time of the next request is
simply pushed less far forward, keeping lag near zero.

---

## 4. The EEVDF Rule

> **At every scheduling decision, pick the eligible request with the earliest
> virtual deadline.**

Two-stage test per candidate:
1. **Eligibility filter:** `ve ≤ V(now)`.
2. **Selection:** among eligible, minimum `vd`.

`V` is not explicitly maintained in most real implementations — the Linux
`cfs_rq->min_vruntime` / augmented RB-tree serves that role via comparisons.

---

## 5. Dynamic Operations — Join, Leave, Reweight

Conservation law (Lemma 2): `Σ_{i ∈ A(t)} lag_i(t) = 0` at all times.

`A(t⁺)` = active set **after** the event (leaver excluded / joiner included).

### 5.1 Client leaves at time `t`
```
V(t⁺) = V(t) + lag_j(t) / Σ_{i ∈ A(t⁺)} w_i   (Eq. 18)
```

### 5.2 Client joins at time `t` with lag `lag_j(t)`
```
V(t⁺) = V(t) − lag_j(t) / Σ_{i ∈ A(t⁺)} w_i   (Eq. 19)
```

### 5.3 Weight change `w_j → w_j'`
Equivalent to leave+rejoin at same instant:
```
V(t⁺) = V(t)
      + lag_j(t) / ( Σ_{i ∈ A(t)} w_i − w_j )
      − lag_j(t) / ( Σ_{i ∈ A(t)} w_i − w_j + w_j' )   (Eq. 20)
```
If the changing client has zero lag, `V` does not change. If all dynamic events
happen at zero-lag moments, `V` is continuous.

### 5.4 Implementation strategies
| Strategy | Rule for dynamic event | Notes |
|---|---|---|
| **1** | Lag preserved across leave/rejoin; `V` updated per Eqs. 18–20 | Best long-run fairness across activity periods |
| **2** | Lag dropped on leave; rejoin with lag = 0 | Fits event-driven workloads (independent events) |
| **3** | Events only allowed when lag = 0 | Continuous `V`; simpler analysis, needs delay machinery for negative-lag leavers |

Linux EEVDF follows Strategy 1 in spirit (re-weights the virtual-time baseline
on enqueue/dequeue via `avg_vruntime` / `avg_load`).

---

## 6. Fairness — Bounds

### Lemma 1
If `lag_k(t) ≥ 0` for active client `k`, then `k` has an **eligible** pending
request at `t`. (Positive lag ⇒ eligibility is not blocked.)

### Lemma 2
`Σ_{i ∈ A(t)} lag_i(t) = 0` always — conservation of service across the active
set. Gain for one client is loss for another.

### Corollary (work-conserving)
Combining Lemmas 1–2: while the active set is non-empty, at least one eligible
request exists ⇒ EEVDF is **work-conserving** (resource never idles under load).

### Lemma 3 — Steady-system deadline bound
In a steady system, any request with deadline `d` is fulfilled no later than
`d + q`. Same bound shape as Parekh–Gallager's GPS (max-packet lateness).

### Theorem 1 — Tight lag bounds (steady)
For any active client `k`:
```
−r_max < lag_k(d) < max(r_max, q)          (Eq. 35)
```
where `r_max` is the max request length issued by `k`. Bounds are
asymptotically tight.

### Corollary 2 — Uniform-quantum bound
If every request is no larger than `q`:
```
−q < lag_k(t) < q                          (Eq. 42)
```

### Lemma 5 — Optimality
For any proportional-share algorithm over quanta of size `q`, lag is bounded
by `−q` and `q`. EEVDF meets this bound ⇒ **optimal** among proportional-share
schedulers for uniform quanta.

Trade-off exposed by Theorem 1: shorter requests → tighter fairness; longer
requests → less scheduling overhead. The client/scheduler picks the point.

---

## 7. Data Structure

Implemented as an **augmented binary search tree** keyed on `vd`, with each
subtree node annotated by `min_vd_of_subtree_with_ve ≤ V(now)`. Lookup of the
earliest-deadline eligible request: `O(log n)`. Insert / delete / reweight:
`O(log n)`. Linux uses an RB-tree augmented with `min_vruntime` /
`deadline` info (`fair.c` since 6.6).

---

## 8. Worked Example (Fig. 1 of the paper)

Two clients, `w_1 = w_2 = 2`, quantum `q = 1`, request lengths `r_1 = 2`,
`r_2 = 1`. Client 1 joins at `t = 0`, client 2 joins at `t = 1`.

| t (real) | V(t)  | Event                           | Allocated |
|---------:|------:|---------------------------------|-----------|
| 0        | 0     | c1 request `(ve=0, vd=1)`       | c1        |
| 1        | 0.5   | c2 joins, request `(0.5, 1)`; tie on `vd=1` broken for c2 | c2 |
| 2        | 0.75  | c2 new request `(1, 1.5)`; c2 `ve=1 > V`, only c1 eligible (`ve=1`, `vd=2`) | c1 |
| 3        | 1.00  | c2 becomes eligible; `vd=1.5` < c1's `vd=2` | c2 |
| 4        | 1.25  | c2 issues `(1.5, 2)`; only c1 eligible | c1 |
| 5        | 1.50  | c2 eligible at `vd=2`; tie with c1 | c2 |

Slope of `V` halves from `1/w_1 = 0.5` to `1/(w_1+w_2) = 0.25` at `t = 1`.
Paper Fig. 1 maps real→virtual: 1→0.5, 3→1, 5→1.5, 7→2.

---

## 9. Relationship to This Repo

### 9.1 `impl/s3` (homogeneous EEVDF baseline)
Direct port of §§2–4. Single weight per task, identical CPU capacity assumed.

### 9.2 `impl/s3+` (capacity-aware EEVDF, A1349)
Extends the deadline and stopping math with per-CPU capacity `C_p` (Linux
`SCHED_CAPACITY_SCALE = 1024`). Let `κ_p = C_p / CAPACITY_SCALE ∈ (0, 1]`:
- Quantum (capacity-scaled): `q_max = κ_max · SCX_SLICE_DFL`
- Deadline: `vd = ve + q_max / w_i`
- Stopping (virtual-time advance on dequeue):
  `ve += (κ_p · consumed) / w_i`

`κ_p = 1` on big cores, `κ_p < 1` on small cores — time on a weak CPU
consumes less virtual budget. Reduces to classical EEVDF when all `κ_p = 1`
(homogeneous). On hybrid CPUs (e.g. Intel P/E) it produces capacity-weighted
virtual time.

### 9.3 `impl/s4` (VCG auction, `scx_auction`)
Departs from pure EEVDF: two DSQs `(P, E)` priced by
`φ_P = w − C_P · ℓ`, `φ_E = w − C_E · ⌈ℓ σ⌉`, with `σ = C_max / C_min`, plus a
token-bucket budget. Uses EEVDF's virtual-time intuition for tie-breaking only.

---

## 10. References

- Stoica, Abdel-Wahab. *Earliest Eligible Virtual Deadline First: A Flexible
  and Accurate Mechanism for Proportional Share Resource Allocation.* ODU
  TR-95-22, 1996. (`eevdf_fixed.pdf` in repo root.)
- Parekh, Gallager. *A Generalized Processor Sharing Approach to Flow Control
  in Integrated Services Networks.* IEEE/ACM ToN, 1993.
- Peter Zijlstra. *Linux EEVDF scheduler* (kernel ≥ 6.6).
