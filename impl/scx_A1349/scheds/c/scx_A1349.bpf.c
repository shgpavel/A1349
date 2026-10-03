/* SPDX-License-Identifier: GPL-2.0
 *
 * scx_A1349 — Pure VCG Auction Scheduler for Heterogeneous CPUs (A1349).
 *
 * Direct mapping of the A1349 mathematical model (theory §2.4) onto sched_ext.
 * Unlike the legacy hybrid s4 implementation, this contains NO virtual time
 * machinery (V(t), ve, vd, lag).  Tasks are ordered inside per-cluster DSQs
 * by their effective auction value φ_κ; the VCG payment is computed exactly
 * from a peek of the top-1 / top-2 candidates at dispatch time, per the
 * single-slot formula (eq:single-unit-payment):
 *
 *   p_{i*} = φ_κ(θ_j) + (δ^{m_κ(l_j)} − δ^{m_κ(l_{i*})}) · \bar W_κ
 *
 * where:
 *   φ_κ(θ_i)  effective value of task i on cluster κ ∈ {P, E}, as coded:
 *               φ_P = 2·v_i           − c_P · l_q
 *               φ_E = 2·v_i · η_E/η_P − c_E · l_q
 *             (theory eq:phi uses the unscaled v_i on both clusters and
 *             charges ⌈l_i · σ⌉ quanta on E; see compute_phi())
 *   l_q         task length in P-quanta, from the CPU burst estimate
 *   j           runner-up task in the same cluster queue
 *   m_κ(l)      contract length in quanta on cluster κ
 *   δ           discount factor (model §2.4, MDP Bellman)
 *   \bar W_κ    EWMA of realised φ_κ on cluster κ — proxy for the expected
 *               future welfare when the core returns to the free pool
 *
 * Budget discipline (theory Proposition 1):  if p_{i*} > B_{i*}^t, the
 * winner cannot afford the auction.  i* is moved to AUCTION_DSQ_STARVED;
 * the core falls through to j and re-runs the auction.  STARVED is FIFO by
 * exile time and its head is served once it has waited STARVED_MAX_WAIT_NS,
 * so a budget-exhausted task always makes progress.
 */

#include <scx/common.bpf.h>
#include "scx_A1349.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* ── tuneables ───────────────────────────────────────────────────────────── */

#define CAPACITY_SCALE      1024u

/* Fallback per-quantum costs c_P, c_E if userspace left them unset. */
#define C_P_DEF             COST_P_DEF
#define C_E_DEF             (COST_P_DEF / 2)

/*
 * φ value-term scale shift: v_i = p->scx.weight << PHI_VALUE_SHIFT.
 *
 * p->scx.weight is on the cgroup scale (nice 0 = 100, range 1..10000), not
 * the 1024-based CFS scale.  With the default c_P = 1024 a nice-0 task
 * therefore has φ_P = 200 − 1024 · l_q: positive only while l_q = 0
 * (burst < SLICE_P/2), negative for anything longer.
 */
#define PHI_VALUE_SHIFT     1u


/*
 * Budget token bucket (theory §2.4 budget mechanism).
 *   B_i^max     = w_i · BUDGET_MUL
 *   replenish   = min(sleep_ns, REPLENISH_IDLE_CAP) · w_i / REPLENISH_DIV
 *
 * Only sleep earns credit: time spent running or waiting in a queue does
 * not.  Credited once per wake-up.
 */
const volatile u64 budget_mul       = BUDGET_MUL_DEF;
const volatile u64 replenish_div    = REPLENISH_DIV_DEF;
const volatile u32 starve_floor_pct = STARVE_FLOOR_PCT_DEF;

#define BUDGET_MUL          budget_mul
#define REPLENISH_DIV       replenish_div
#define REPLENISH_IDLE_CAP  1000000000ULL

/*
 * Cluster-conditioned slice grants (same dual-slice rationale as s4).
 *   SLICE_P  20 ms.
 *   SLICE_E  1.5× larger, amortises preempt overhead on slower cores.
 */
const volatile u64 slice_p_ns  = SLICE_P_US_DEF * 1000ULL;
const volatile u32 slice_e_pct = SLICE_E_PCT_DEF;

#define AUCTION_SLICE_P     slice_p_ns
#define AUCTION_SLICE_E     (slice_p_ns * slice_e_pct / 100)

/*
 * φ encoding for the kernel DSQ (which sorts by ascending u64 vtime).
 *
 *   key = PHI_BIAS − φ           if φ ≥ 0   (smaller key ⇒ higher priority)
 *   key = PHI_BIAS + |φ|         if φ < 0
 *
 * PHI_BIAS = 1<<62 keeps the result inside u64 for any |φ| ≤ 2^62.  |φ| is
 * bounded by 2 · 10000 + c_P · MAX_CONTRACT_LENGTH, far inside that range.
 */
#define PHI_BIAS            (1ULL << 62)

/*
 * Burst lengths above L quanta are clamped: l_i ∈ {1, …, L} in the model,
 * and δ^m has floored long before that.
 */
#define LEN_CAP_NS          ((u64)MAX_CONTRACT_LENGTH * AUCTION_SLICE_P)

/* \bar W_κ EWMA: \bar W ← ((W_BAR_EWMA_DEN − 1) · \bar W + W_realised) / DEN. */
const volatile u32 w_bar_ewma_den = W_BAR_EWMA_DEN_DEF;

#define W_BAR_EWMA_DEN      w_bar_ewma_den

/* DSQ identifiers. */
#define AUCTION_DSQ_P       1ULL
#define AUCTION_DSQ_E       2ULL
#define AUCTION_DSQ_STARVED 3ULL

/*
 * Bound on how long the head of AUCTION_DSQ_STARVED may wait before it is
 * served ahead of the auction.  Without it STARVED only ran when both
 * cluster DSQs were empty, and sustained load starved it until the
 * sched_ext watchdog ejected the scheduler.
 */
const volatile u32 starved_wait_slices = STARVED_WAIT_SLICES_DEF;

#define STARVED_MAX_WAIT_NS ((u64)starved_wait_slices * AUCTION_SLICE_P)

/*
 * Bound on how long a task may keep losing the auction in a cluster DSQ.
 * Cluster DSQs are strict φ priority and a winner whose runner-up has
 * φ ≤ 0 pays nothing, so budgets alone cannot stop a set of higher-φ tasks
 * (or a task stranded in the cluster its affinity excludes) from starving
 * a queued task forever.  Past the bound the task is demoted to STARVED,
 * keyed by its original enqueue time, where STARVED_MAX_WAIT_NS applies.
 * Cluster DSQs are scanned at most once per AGE_SCAN_PERIOD_NS system-wide.
 */
const volatile u32 cluster_wait_slices = CLUSTER_WAIT_SLICES_DEF;

#define CLUSTER_MAX_WAIT_NS ((u64)cluster_wait_slices * AUCTION_SLICE_P)
#define AGE_SCAN_PERIOD_NS  AUCTION_SLICE_P

/* Upper bound for the P-core idle scan in select_cpu. */
#define AUCTION_NCPU_MAX        64

const volatile u32 idle_pick = IDLE_PICK_PSCAN;

/* Maximum auction retries per dispatch tick (top, runner, …). */
#define DISPATCH_AUCTION_TRIES 3

/* ── maps ────────────────────────────────────────────────────────────────── */

/*
 * BPF-owned runtime estimator state.  Userspace must NOT update.
 *   w_bar_p, w_bar_e — EWMA of realised φ_κ per cluster, fixed point
 *                      (× DELTA_SCALE).  Approximates the Bellman
 *                      expectation \bar W_κ of theory §2.4.  Kept in fixed
 *                      point so that small samples move it: in plain φ
 *                      units (15·W̄ + r)/16 never leaves 0 for r ≤ 15.
 */
struct auction_runtime {
	u64 w_bar_p;
	u64 w_bar_e;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct auction_ctx));
} global_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct auction_runtime));
} runtime_data SEC(".maps");

/*
 * Precomputed discount table.  delta_table[m] = round(δ^m · DELTA_SCALE).
 * Populated by userspace before attach; BPF treats it as RO.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CONTRACT_LENGTH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} delta_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cpu_capacity SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u8));
} cpu_is_p SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_NR);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} stats SEC(".maps");

/*
 * Per-task auction state.
 *
 *   budget         remaining B_i^t (theory §2.4)
 *   budget_max     B_i (w_i · BUDGET_MUL)
 *   sleep_start_ns bpf_ktime when the task last blocked; 0 once the sleep
 *                  has been credited to the budget
 *   exec_at_run    p->se.sum_exec_runtime when the current run was last
 *                  accounted (ops.running, or a keep_prev() extension)
 *   burst_ns       CPU time consumed since the task last woke up
 *   len_est_ns     EWMA of completed bursts (wake-up → sleep) — proxy for l_i
 *   enq_at_ns      bpf_ktime of the last insert into a cluster DSQ
 *   phi_enq        φ_κ chosen at enqueue; the runner-up value j in payments
 *   m_enq          contract length m_κ(l_i) used in the VCG payment
 *   weight_cached  stale-safe copy of p->scx.weight
 *   wake_prev_cpu  prev_cpu captured in select_cpu (cache-warm hint)
 *   ran_on_p       1 if the current/last run is on a P-core
 *   on_cpu         1 between ops.running and ops.stopping
 *   ran            1 once the task has stopped at least once
 *   yielded        1 after sched_yield() until the task next runs
 */
struct auction_task_ctx {
	u64 budget;
	u64 budget_max;
	u64 sleep_start_ns;
	u64 exec_at_run;
	u64 burst_ns;
	u64 len_est_ns;
	u64 enq_at_ns;
	s64 phi_enq;
	u32 m_enq;
	u32 weight_cached;
	s32 wake_prev_cpu;
	u8  ran_on_p;
	u8  on_cpu;
	u8  ran;
	u8  yielded;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct auction_task_ctx);
} task_ctx_map SEC(".maps");

/* bpf_ktime of the last cluster DSQ age scan (see CLUSTER_MAX_WAIT_NS). */
static u64 age_scan_last;

private(A1349) struct bpf_cpumask __kptr *p_cpumask;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static __always_inline struct auction_ctx *
get_ctx(void)
{
	u32 key = 0;
	return bpf_map_lookup_elem(&global_data, &key);
}

static __always_inline struct auction_runtime *
get_rt(void)
{
	u32 key = 0;
	return bpf_map_lookup_elem(&runtime_data, &key);
}

/* Task storage is allocated in ops.init_task; hot paths only look it up. */
static __always_inline struct auction_task_ctx *
get_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_map, p, 0, 0);
}

static __always_inline void
stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		(*cnt)++;
}

static __always_inline bool
cpu_is_p_type(u32 cpu)
{
	u8 *flag = bpf_map_lookup_elem(&cpu_is_p, &cpu);
	return flag && *flag;
}

/*
 * Encode signed φ into an unsigned DSQ vtime key such that a larger φ
 * yields a smaller key (kernel DSQ sorts ascending → highest φ served first).
 */
static __always_inline u64
encode_phi(s64 phi)
{
	if (phi >= 0)
		return PHI_BIAS - (u64)phi;
	return PHI_BIAS + (u64)(-phi);
}

/*
 * Length l_i used for φ and m.  The completed-burst EWMA lags a task whose
 * current burst is already longer, so the running burst is a lower bound:
 * a CPU hog that never sleeps is priced by how long it has actually held
 * the CPU, not by a stale estimate.
 */
static __always_inline u64
len_with_burst(const struct auction_task_ctx *tctx, u64 burst)
{
	u64 len = tctx->len_est_ns > burst ? tctx->len_est_ns : burst;

	return len < LEN_CAP_NS ? len : LEN_CAP_NS;
}

static __always_inline u64
task_len_ns(const struct auction_task_ctx *tctx)
{
	return len_with_burst(tctx, tctx->burst_ns);
}

/*
 * Compute φ_P and φ_E for a task (eq:phi, rescaled to weight-units).
 *
 *   l_q  = round(len_ns / SLICE_P)     (length in P-quanta, integer)
 *   φ_P = 2·w           − c_P · l_q
 *   φ_E = 2·w · η_E/η_P − c_E · l_q
 *
 * Earlier (weight × ns) formulation produced |φ| ≈ 1e10, which dominated
 * the budget scale and pushed VCG payments to either clamp at zero (free)
 * or drain the bucket in a single dispatch.  Dividing by SLICE_P
 * normalises φ to the same magnitude as the weight, making the budget and
 * replenishment constants from s4 directly reusable.
 *
 * Integer-only: cost_κ · len_ns is rounded by adding SLICE_P/2 before the
 * division to avoid systematic truncation bias on sub-quantum tasks.
 */
static __always_inline void
compute_phi(u32 weight, u64 len_ns,
	    u32 max_cap, u32 min_cap,
	    u32 cost_p, u32 cost_e,
	    s64 *phi_p_out, s64 *phi_e_out)
{
	u32 mx = max_cap ? max_cap : CAPACITY_SCALE;
	u32 mc = min_cap ? min_cap : mx;
	u64 w_e = (u64)weight * (u64)mc / (u64)mx;
	/*
	 * Integer-quantum discretisation of the cost term.  Sub-quantum
	 * tasks collapse to l_q=0 (cost=0), so same-weight short tasks
	 * share a single φ key and the DSQ falls back to insertion order
	 * within that bucket — restores hackbench's natural FIFO producer-
	 * consumer pairing that the original ns-precision cost destroyed.
	 * Long-running tasks (l_q ≥ 1) still rank by integer quanta.
	 */
	u64 l_q_int = (len_ns + AUCTION_SLICE_P / 2) / AUCTION_SLICE_P;
	u64 cost_p_q = (u64)cost_p * l_q_int;
	u64 cost_e_q = (u64)cost_e * l_q_int;

	/*
	 * v_i scaled by PHI_VALUE_SHIFT; cost stays at native scale, so the
	 * sign of φ still flips once the contract dominates the value.
	 */
	*phi_p_out = ((s64)weight << PHI_VALUE_SHIFT) - (s64)cost_p_q;
	*phi_e_out = ((s64)w_e    << PHI_VALUE_SHIFT) - (s64)cost_e_q;
}

/*
 * Contract length in quanta:  m_P(l) = l,  m_E(l) = ⌈l · σ⌉.
 * Saturates at MAX_CONTRACT_LENGTH − 1 (lookup-table bound).
 *
 *   l (in P-quanta) = ⌈len_ns / SLICE_P⌉,  l ≥ 1.
 *   m_E(l) = ⌈l · max_cap / min_cap⌉.
 */
static __always_inline u32
contract_length(u64 len_ns, bool on_p, u32 max_cap, u32 min_cap)
{
	u64 mx = max_cap ? max_cap : CAPACITY_SCALE;
	u64 mc = min_cap ? min_cap : mx;
	u64 l_p;
	u64 m;

	l_p = (len_ns + AUCTION_SLICE_P - 1) / AUCTION_SLICE_P;
	if (l_p < 1)
		l_p = 1;

	if (on_p)
		m = l_p;
	else
		m = (l_p * mx + mc - 1) / mc;

	if (m >= MAX_CONTRACT_LENGTH)
		m = MAX_CONTRACT_LENGTH - 1;
	return (u32)m;
}

/* φ_κ and m_κ of a task on one cluster, with the loader's configuration. */
static __always_inline s64
phi_on(const struct auction_ctx *gdata, u32 weight, u64 len_ns, bool on_p,
       u32 *m_out)
{
	u32 max_cap = gdata->max_capacity ?: CAPACITY_SCALE;
	u32 min_cap = gdata->min_capacity ?: max_cap;
	s64 phi_p, phi_e;

	compute_phi(weight, len_ns, max_cap, min_cap,
		    gdata->cost_p ?: C_P_DEF, gdata->cost_e ?: C_E_DEF,
		    &phi_p, &phi_e);
	if (m_out)
		*m_out = contract_length(len_ns, on_p, max_cap, min_cap);
	return on_p ? phi_p : phi_e;
}

static __always_inline u64
delta_pow(u32 m)
{
	u32 key = (m < MAX_CONTRACT_LENGTH) ? m : (MAX_CONTRACT_LENGTH - 1);
	u64 *v = bpf_map_lookup_elem(&delta_table, &key);
	/* Fallback δ^? ≈ 1 if userspace forgot to populate. */
	return v ? *v : DELTA_SCALE;
}

/*
 * Credit the last sleep to the budget.  Token bucket capped at budget_max.
 * Mirrors theory §2.4 "Аллокация задаче … допустима, если p_i ≤ B_i^t":
 * sleep accrues credit; the budget cap prevents permanent stockpiling.
 *
 * sleep_start_ns is set only when the task blocks (ops.stopping with
 * runnable=false) and cleared here, so each sleep is credited exactly once
 * whichever path woke the task (ops.enqueue, or ops.running after a
 * select_cpu direct dispatch that skipped enqueue).  Time spent running or
 * waiting in a DSQ is never credited.
 */
static __always_inline void
budget_replenish(struct auction_task_ctx *tctx, u64 now)
{
	u64 idle_ns, add;

	if (!tctx->sleep_start_ns)
		return;
	if (now <= tctx->sleep_start_ns) {
		tctx->sleep_start_ns = 0;
		return;
	}

	idle_ns = now - tctx->sleep_start_ns;
	if (idle_ns > REPLENISH_IDLE_CAP)
		idle_ns = REPLENISH_IDLE_CAP;

	add = idle_ns * (u64)(tctx->weight_cached ?: 1) / REPLENISH_DIV;
	tctx->budget += add;
	if (tctx->budget > tctx->budget_max)
		tctx->budget = tctx->budget_max;

	tctx->sleep_start_ns = 0;
}

/* Deduct a VCG payment.  Negative payments are clamped: VCG never credits. */
static __always_inline void
budget_charge(struct auction_task_ctx *tctx, s64 payment)
{
	u64 charge = payment > 0 ? (u64)payment : 0;

	if (tctx->budget >= charge)
		tctx->budget -= charge;
	else
		tctx->budget = 0;
}

/*
 * VCG payment in the single-slot regime (eq:single-unit-payment):
 *
 *   p = φ_j  +  (δ^{m_j} − δ^{m_i}) · \bar W_κ
 *
 * with δ^m and \bar W_κ both in DELTA_SCALE fixed point, so the product is
 * shifted down by 2 · DELTA_SHIFT.  |diff| ≤ 2^20 and \bar W ≤ 2·10^4 · 2^20,
 * so the product stays below 2^55.
 *
 * If the runner-up j is absent, φ_j ≡ 0 and m_j ≡ 0 (so δ^0 = 1), which
 * collapses the payment to the "lonely winner" form
 *   p = (1 − δ^{m_i}) · \bar W_κ.
 * (The single-task fast path in auction_dispatch() does not run the
 * auction, so a lone queued task is not charged it.)
 *
 * Returned as a signed s64.  A negative payment (the externality benefits
 * the rest of the system, e.g. when m_i < m_j) is clamped to zero at the
 * budget check — we never credit budget.
 */
static __always_inline s64
vcg_payment(s64 phi_j, u32 m_j, u32 m_i, u64 w_bar_fp)
{
	u64 dj = m_j ? delta_pow(m_j) : DELTA_SCALE;   /* δ^0 = 1 */
	u64 di = delta_pow(m_i);
	s64 diff = (s64)dj - (s64)di;
	s64 ext;

	/* (diff · w_bar_fp) >> 2·DELTA_SHIFT, sign-preserving. */
	if (diff >= 0)
		ext = (s64)(((u64)diff * w_bar_fp) >> (2 * DELTA_SHIFT));
	else
		ext = -(s64)(((u64)(-diff) * w_bar_fp) >> (2 * DELTA_SHIFT));

	return phi_j + ext;
}

/*
 * Fold the CPU time since exec_at_run into the current burst and into
 * \bar W_κ of the cluster the task is running on, and restart the
 * measurement.  sum_exec_runtime is brought up to date by update_curr_scx()
 * before both callers (ops.stopping, and ops.dispatch for @prev), so this
 * is correct on every dispatch path and across kernel slice refills.
 *
 * \bar W_κ sample = max(φ_κ, 0) · min(ran, SLICE_P) / SLICE_P (fixed
 * point, × DELTA_SCALE), with φ_κ
 * evaluated at the length the task was running with.  A φ < 0 task adds no
 * welfare: the core could have idled instead (free disposal), so \bar W_κ
 * stays ≥ 0 and bounded by the largest φ.
 */
static __always_inline void
account_run(struct task_struct *p, struct auction_task_ctx *tctx,
	    struct auction_runtime *rt, const struct auction_ctx *gdata)
{
	u64 exec = p->se.sum_exec_runtime;
	u64 ran = exec > tctx->exec_at_run ? exec - tctx->exec_at_run : 0;
	bool on_p = tctx->ran_on_p != 0;
	s64 phi = phi_on(gdata, tctx->weight_cached ?: 1, task_len_ns(tctx),
			 on_p, NULL);
	u64 frac = ran < AUCTION_SLICE_P ? ran : AUCTION_SLICE_P;
	u64 phi_realised = phi > 0 ?
		((u64)phi << DELTA_SHIFT) * frac / AUCTION_SLICE_P : 0;
	u64 *w_bar_slot = on_p ? &rt->w_bar_p : &rt->w_bar_e;

	*w_bar_slot = ((*w_bar_slot) * (W_BAR_EWMA_DEN - 1) + phi_realised) /
		      W_BAR_EWMA_DEN;

	tctx->burst_ns   += ran;
	tctx->exec_at_run = exec;
}

/*
 * True for CPUs the loader classified: it only writes cpu_capacity for CPUs
 * online at attach (hotplug restarts the scheduler with fresh maps), so a
 * zero entry is an offline or absent CPU whose cpu_is_p would read as E.
 */
static __always_inline bool
cpu_known(u32 cpu)
{
	u32 *cap = bpf_map_lookup_elem(&cpu_capacity, &cpu);

	return cap && *cap;
}

/*
 * Clusters @p may run on: bit 0 = P, bit 1 = E.  Unrestricted tasks are
 * the common case and skip the scan; per-CPU tasks resolve in O(1).
 */
#define CLUSTER_P  1u
#define CLUSTER_E  2u

static __always_inline u32
task_clusters(struct task_struct *p)
{
	u32 mask = 0;
	s32 c;

	if (p->nr_cpus_allowed >= (int)scx_bpf_nr_cpu_ids())
		return CLUSTER_P | CLUSTER_E;

	if (p->nr_cpus_allowed == 1) {
		u32 only = bpf_cpumask_first(p->cpus_ptr);

		if (!cpu_known(only))
			return CLUSTER_P | CLUSTER_E;
		return cpu_is_p_type(only) ? CLUSTER_P : CLUSTER_E;
	}

	bpf_for(c, 0, AUCTION_NCPU_MAX) {
		if (!bpf_cpumask_test_cpu(c, p->cpus_ptr) || !cpu_known((u32)c))
			continue;
		mask |= cpu_is_p_type((u32)c) ? CLUSTER_P : CLUSTER_E;
		if (mask == (CLUSTER_P | CLUSTER_E))
			break;
	}
	return mask ?: CLUSTER_P | CLUSTER_E;
}

/*
 * A task just moved to STARVED: make sure a CPU that may run it looks at
 * STARVED soon, rather than waiting for one of its CPUs to dispatch for
 * some other reason (a pinned task's only CPU may be idle).
 */
static __always_inline void
kick_for(struct task_struct *p)
{
	s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/* ── sched_ext ops ───────────────────────────────────────────────────────── */

s32
BPF_STRUCT_OPS(auction_select_cpu,
	       struct task_struct *p,
	       s32                 prev_cpu,
	       u64                 wake_flags)
{
	struct auction_task_ctx *tctx;
	bool is_idle = false;
	s32 cpu = -1;
	s32 c;

	tctx = get_task_ctx(p);
	if (tctx)
		tctx->wake_prev_cpu = prev_cpu;

	if (idle_pick == IDLE_PICK_CORE) {
		const struct cpumask *pm = cast_mask(p_cpumask);

		if (pm) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
						     pm, SCX_PICK_IDLE_CORE);
			if (cpu < 0)
				cpu = scx_bpf_select_cpu_and(p, prev_cpu,
							     wake_flags,
							     p->cpus_ptr,
							     SCX_PICK_IDLE_CORE);
			if (cpu < 0)
				cpu = scx_bpf_select_cpu_and(p, prev_cpu,
							     wake_flags,
							     p->cpus_ptr, 0);
			if (cpu < 0)
				return prev_cpu;
			is_idle = true;
			goto have_cpu;
		}
	}

	/*
	 * P-bias scan (model §2.4 Allocation rule, refined):  prefer an idle
	 * P-cluster CPU first — "land on the strongest core that's free".
	 * Avoids the select_cpu_dfl bias toward prev_cpu which routinely
	 * strands single-threaded passmark workers on E-cores.
	 *
	 * Fast path: cache-warm prev_cpu wins if it is an idle P-core.
	 */
	if (prev_cpu >= 0 && cpu_is_p_type((u32)prev_cpu) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		is_idle = true;
		goto have_cpu;
	}

	/* Scan for any idle P-core.  AUCTION_NCPU_MAX bounds the loop. */
	bpf_for(c, 0, AUCTION_NCPU_MAX) {
		if (!cpu_is_p_type((u32)c))
			continue;
		if (!bpf_cpumask_test_cpu(c, p->cpus_ptr))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(c)) {
			cpu = c;
			is_idle = true;
			break;
		}
	}

	/* No idle P: fall back to default selector (lets idle E be picked). */
	if (cpu < 0)
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

have_cpu:
	if (cpu >= 0 && is_idle) {
		stat_inc(STAT_DIRECT_IDLE);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   cpu_is_p_type((u32)cpu) ? AUCTION_SLICE_P
							   : AUCTION_SLICE_E,
				   0);
	}

	return cpu;
}

void
BPF_STRUCT_OPS(auction_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct auction_ctx      *gdata = get_ctx();
	struct auction_task_ctx *tctx  = get_task_ctx(p);
	u32 weight, clusters;
	u64 now, len_ns, slice_ns, dsq_id, vtime;
	s64 phi_p, phi_e;
	u32 m_p, m_e;
	bool on_p, is_wakeup;

	/*
	 * ops.enqueue must always hand the task to some DSQ; returning
	 * without inserting leaves it runnable but unqueued until the
	 * watchdog ejects the scheduler.
	 */
	if (!gdata || !tctx) {
		stat_inc(STAT_NO_CTX);
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, AUCTION_SLICE_P,
				   enq_flags);
		return;
	}

	now     = bpf_ktime_get_ns();
	weight  = p->scx.weight       ?: 1;
	tctx->weight_cached = weight;
	is_wakeup = (enq_flags & SCX_ENQ_WAKEUP) || !tctx->ran;

	/* Credits the preceding sleep; no-op for preempt re-enqueues. */
	budget_replenish(tctx, now);

	/*
	 * Cluster routing: κ* = argmax_κ φ_κ, re-evaluated on every enqueue.
	 * Within one burst l_i only grows, so φ only falls and a preempted
	 * task crosses from P to E at most once per burst — no ping-pong.
	 * A task whose affinity excludes a cluster is never queued there:
	 * that cluster's CPUs could not run it and the other cluster's CPUs
	 * only look at it when their own DSQ is empty.
	 */
	len_ns   = task_len_ns(tctx);
	phi_p    = phi_on(gdata, weight, len_ns, true,  &m_p);
	phi_e    = phi_on(gdata, weight, len_ns, false, &m_e);
	clusters = task_clusters(p);
	on_p     = phi_p >= phi_e;
	if (!(clusters & (on_p ? CLUSTER_P : CLUSTER_E)))
		on_p = !on_p;

	/*
	 * Budget admissibility (theory Proposition 1), cheap conservative
	 * form: a task whose bucket is below starve_floor_pct of B_i^max goes
	 * straight to STARVED instead of wasting a dispatch tick on an auction
	 * it will probably lose.  The exact p ≤ B check happens at dispatch.
	 */
	if (tctx->budget_max &&
	    tctx->budget * 100 < tctx->budget_max * starve_floor_pct) {
		tctx->phi_enq = on_p ? phi_p : phi_e;
		tctx->m_enq   = on_p ? m_p : m_e;
		dsq_id   = AUCTION_DSQ_STARVED;
		slice_ns = AUCTION_SLICE_P;
		vtime    = now;               /* STARVED is FIFO by exile time */
		stat_inc(STAT_ENQ_STARVED);
		goto insert;
	}

	/*
	 * Asymmetric P→E spill (extension §X.1 mirrored from s4).  When the
	 * P queue is saturated and relatively more crowded than E in
	 * normalised depth, route the would-be P task to E to keep all cores
	 * busy on big-P / small-E and big-E / small-P silicon alike.
	 * Cross-multiplied to avoid a 64-bit divide on the hot path:
	 *   Q_P · K_E > Q_E · K_P  ⇒  P is the bottleneck, spill to E.
	 */
	if (on_p && (clusters & CLUSTER_E)) {
		u32 p_cc = gdata->p_core_count;
		u32 e_cc = gdata->e_core_count;
		u64 p_q  = scx_bpf_dsq_nr_queued(AUCTION_DSQ_P);
		u64 e_q  = scx_bpf_dsq_nr_queued(AUCTION_DSQ_E);

		if (p_cc && e_cc && p_q >= p_cc &&
		    (e_q < e_cc || p_q * e_cc > e_q * p_cc)) {
			on_p = false;
			stat_inc(STAT_SPILL);
		}
	}

	tctx->phi_enq = on_p ? phi_p : phi_e;
	tctx->m_enq   = on_p ? m_p : m_e;
	dsq_id   = on_p ? AUCTION_DSQ_P : AUCTION_DSQ_E;
	slice_ns = on_p ? AUCTION_SLICE_P : AUCTION_SLICE_E;
	vtime    = encode_phi(tctx->phi_enq);

	/*
	 * Cache-warm pin on wake-up (extension §X.5 mirrored from s4).  If
	 * the task is waking and its previously-used CPU is in the chosen
	 * cluster and currently idle, dispatch directly to that CPU's local
	 * DSQ — bypasses the auction queue but only when the resource is
	 * uncontested (consistent with theory §2.4: φ-argmax binds only when
	 * K_κ^t < |eligible tasks|).  Empirically saves a queue-trip + an
	 * IPI when the prev_cpu is already hot.
	 */
	if (is_wakeup) {
		s32 prev_cpu = tctx->wake_prev_cpu;
		tctx->wake_prev_cpu = -1;
		/* select_task_rq() skips ops.select_cpu for single-CPU tasks. */
		if (prev_cpu < 0 && p->nr_cpus_allowed == 1)
			prev_cpu = scx_bpf_task_cpu(p);
		if (prev_cpu >= 0) {
			bool prev_is_p = cpu_is_p_type((u32)prev_cpu);
			bool cluster_match = on_p ? prev_is_p : !prev_is_p;

			if (cluster_match &&
			    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
			    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				stat_inc(STAT_PIN);
				scx_bpf_dsq_insert(p,
					SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					slice_ns, enq_flags);
				if ((s32)bpf_get_smp_processor_id() != prev_cpu)
					scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
				return;
			}
		}
	}

	stat_inc(on_p ? STAT_ENQ_P : STAT_ENQ_E);
	tctx->enq_at_ns = now;

insert:
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, enq_flags);

	/*
	 * Work-conservation kick: wake any idle CPU in the task's allowed set
	 * so a newly queued task does not wait for a peer's slice expiry.
	 */
	{
		s32 idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (idle_cpu >= 0 &&
		    idle_cpu != (s32)bpf_get_smp_processor_id())
			scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
	}

}

/*
 * Run one auction round on `src_dsq`.  Reads the top-1 and top-2 entries via
 * a DSQ iterator, computes the VCG payment for the top-1 candidate, and:
 *   - dispatches it to SCX_DSQ_LOCAL if the payment fits the budget; or
 *   - moves it to AUCTION_DSQ_STARVED otherwise.
 *
 * Returns true if a task was dispatched (SCX_DSQ_LOCAL got something) and
 * the caller should stop trying.
 *
 * MUST be __always_inline:  (1) the BPF verifier requires non-inlined
 * subprograms to return scalar int, not bool; (2) more importantly, the
 * bpf_iter_scx_dsq_* reference must be released along every control-flow
 * path of the enclosing function, which is awkward to express across a
 * subprogram boundary.
 */
static __always_inline bool
auction_try_round(u64 src_dsq, u64 w_bar, s32 cpu)
{
	struct bpf_iter_scx_dsq it;
	struct task_struct *p_top = NULL, *p_runner;
	struct auction_task_ctx *t_top, *t_runner;
	s64 phi_runner = 0;
	s64 payment;
	u32 m_top = 0, m_runner = 0;
	bool dispatched = false;
	int err;

	/*
	 * Allocate the iter unconditionally — BPF verifier tracks the
	 * reference even on failure, so destroy MUST be called on every path.
	 */
	err = bpf_iter_scx_dsq_new(&it, src_dsq, 0);
	if (err)
		goto out;

	p_top = bpf_iter_scx_dsq_next(&it);
	if (!p_top)
		goto out;

	/*
	 * CPU-affinity guard.  scx_bpf_dsq_move(&it, p, SCX_DSQ_LOCAL, 0)
	 * unconditionally targets the *calling* CPU's local DSQ; the kernel
	 * crashes with "SCX_DSQ_LOCAL[_ON] target CPU N not allowed" if p is
	 * pinned away from us (typical case: per-CPU kworkers).  Redirect
	 * such tasks to an allowed CPU's local DSQ and treat this round as a
	 * non-dispatch so the calling bpf_for proceeds to the next top.
	 *
	 * Auction math is intentionally skipped here — the task was never a
	 * legitimate candidate for the current core, so it never competed.
	 * Routing to an idle peer is pure work conservation and does not
	 * touch budget or \bar W_κ.
	 */
	if (!bpf_cpumask_test_cpu((u32)cpu, p_top->cpus_ptr)) {
		s32 dst = scx_bpf_pick_idle_cpu(p_top->cpus_ptr, 0);
		if (dst < 0)
			dst = scx_bpf_pick_any_cpu(p_top->cpus_ptr, 0);
		if (dst >= 0) {
			scx_bpf_dsq_move(&it, p_top,
					 SCX_DSQ_LOCAL_ON | (u64)dst, 0);
			scx_bpf_kick_cpu(dst, SCX_KICK_IDLE);
		}
		goto out;
	}

	t_top = get_task_ctx(p_top);
	if (!t_top)
		goto out;

	m_top = t_top->m_enq;

	p_runner = bpf_iter_scx_dsq_next(&it);
	if (p_runner) {
		t_runner = get_task_ctx(p_runner);
		if (t_runner) {
			phi_runner = t_runner->phi_enq;
			m_runner   = t_runner->m_enq;
		}
	}

	payment = vcg_payment(phi_runner, m_runner, m_top, w_bar);

	/*
	 * Budget check (theory §2.4, Proposition 1).
	 * Negative payments are clamped to zero: VCG never credits budget.
	 */
	if (payment <= 0 || (u64)payment <= t_top->budget) {
		/*
		 * SCX_DSQ_LOCAL is a built-in per-CPU FIFO queue — kernel
		 * rejects vtime ordering on it, so the bare move() is correct.
		 * The cluster DSQ is shared: another CPU may have taken p_top
		 * since the iterator saw it, in which case the move fails and
		 * nothing is charged.
		 */
		if (scx_bpf_dsq_move(&it, p_top, SCX_DSQ_LOCAL, 0)) {
			budget_charge(t_top, payment);
			stat_inc(STAT_AUCTION_WIN);
			dispatched = true;
		}
	} else {
		/*
		 * Cannot afford the auction — exile to STARVED.
		 *
		 * STARVED is a PRIQ DSQ (every insert uses a vtime), so a bare
		 * scx_bpf_dsq_move() would FIFO-insert and crash with "DSQ
		 * already had PRIQ-enqueued tasks".  The vtime is the exile
		 * time: STARVED is FIFO so its head is always the task that
		 * has waited longest, which is what the age bound in
		 * auction_dispatch() relies on.
		 */
		scx_bpf_dsq_move_set_vtime(&it, bpf_ktime_get_ns());
		if (scx_bpf_dsq_move_vtime(&it, p_top, AUCTION_DSQ_STARVED, 0)) {
			stat_inc(STAT_EXILE);
			kick_for(p_top);
		}
	}

out:
	bpf_iter_scx_dsq_destroy(&it);
	return dispatched;
}

/*
 * True once the head of STARVED has waited longer than STARVED_MAX_WAIT_NS.
 * STARVED is ordered by exile time, so the head's vtime is its exile stamp,
 * and if the head has not expired nothing behind it has.  Lockless peek:
 * cheap enough for every dispatch.
 */
static __always_inline bool
starved_head_expired(u64 now)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(AUCTION_DSQ_STARVED);
	u64 since;

	if (!p)
		return false;
	since = p->scx.dsq_vtime;
	return now > since && now - since > STARVED_MAX_WAIT_NS;
}

/*
 * Serve the oldest STARVED task this CPU may run, if it has itself waited
 * longer than STARVED_MAX_WAIT_NS.  The expired head may be pinned
 * elsewhere; move_to_local() would then hand this CPU the first runnable
 * task behind it whether or not that one had expired.
 */
static __always_inline bool
serve_expired_starved(s32 cpu, u64 now)
{
	struct task_struct *p;
	bool served = false;

	if (!starved_head_expired(now))
		return false;

	bpf_for_each(scx_dsq, p, AUCTION_DSQ_STARVED, 0) {
		u64 since = p->scx.dsq_vtime;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (now > since && now - since > STARVED_MAX_WAIT_NS)
			served = scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
						  SCX_DSQ_LOCAL, 0);
		break;
	}
	return served;
}

/*
 * Move every task that has waited in cluster DSQ @dsq_id for longer than
 * CLUSTER_MAX_WAIT_NS to STARVED, keyed by its original enqueue time so it
 * lands ahead of later exiles and is picked up by the STARVED age bound.
 */
static __always_inline void
demote_expired(u64 dsq_id, u64 now)
{
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		struct auction_task_ctx *t = get_task_ctx(p);
		u64 at;

		if (!t)
			continue;
		at = t->enq_at_ns;
		if (!at || now <= at || now - at <= CLUSTER_MAX_WAIT_NS)
			continue;
		scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER, at);
		if (scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, p,
					   AUCTION_DSQ_STARVED, 0)) {
			stat_inc(STAT_DEMOTE);
			kick_for(p);
		}
	}
}

/* Rate-limited: one CPU scans both cluster DSQs per AGE_SCAN_PERIOD_NS. */
static __always_inline void
age_cluster_dsqs(u64 now)
{
	u64 last = age_scan_last;

	if (now - last < AGE_SCAN_PERIOD_NS)
		return;
	if (__sync_val_compare_and_swap(&age_scan_last, last, now) != last)
		return;

	demote_expired(AUCTION_DSQ_P, now);
	demote_expired(AUCTION_DSQ_E, now);
}

/*
 * Incumbent continuation.  @prev has used up its slice but is still
 * runnable; it competes with the head of this CPU's cluster DSQ as if it
 * were queued there.  If its φ is strictly higher and it can afford the
 * VCG payment with the head as runner-up, extend its slice and keep it on
 * the CPU (cache-warm, no queue round-trip).  Ties go to the queue, so
 * equal-φ tasks still round-robin; a task that called sched_yield() always
 * gives way.
 *
 * A kept task gets no ops.stopping/ops.running pair, so it is priced by
 * its live burst (including the run in progress) — its φ must fall as the
 * burst grows, or one incumbent could hold the core indefinitely on a
 * stale length — and that run is folded into the accounting only if it is
 * actually kept (otherwise ops.stopping does it).
 */
static __always_inline bool
keep_prev(struct task_struct *prev, u64 dsq_id, bool is_p, u64 w_bar,
	  struct auction_runtime *rt, const struct auction_ctx *gdata)
{
	struct auction_task_ctx *tp, *th;
	struct task_struct *head;
	s64 phi_prev, phi_head = 0, payment;
	u32 m_prev, m_head = 0;
	u64 exec, burst;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return false;

	tp = get_task_ctx(prev);
	if (!tp || tp->yielded)
		return false;

	head = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	if (!head)
		return false;

	exec  = prev->se.sum_exec_runtime;
	burst = tp->burst_ns;
	if (tp->on_cpu && exec > tp->exec_at_run)
		burst += exec - tp->exec_at_run;

	phi_prev = phi_on(gdata, prev->scx.weight ?: 1, len_with_burst(tp, burst),
			  is_p, &m_prev);
	if (encode_phi(phi_prev) >= head->scx.dsq_vtime)
		return false;

	th = get_task_ctx(head);
	if (th) {
		phi_head = th->phi_enq;
		m_head   = th->m_enq;
	}

	payment = vcg_payment(phi_head, m_head, m_prev, w_bar);
	if (payment > 0 && (u64)payment > tp->budget)
		return false;

	if (tp->on_cpu)
		account_run(prev, tp, rt, gdata);
	budget_charge(tp, payment);
	tp->phi_enq = phi_prev;
	tp->m_enq   = m_prev;
	prev->scx.slice = is_p ? AUCTION_SLICE_P : AUCTION_SLICE_E;
	return true;
}

void
BPF_STRUCT_OPS(auction_dispatch, s32 cpu, struct task_struct *prev)
{
	struct auction_runtime *rt = get_rt();
	struct auction_ctx *gdata = get_ctx();
	bool is_p;
	u64 self_dsq, other_dsq, w_bar_self;
	int attempt;

	if (!rt || !gdata)
		return;

	is_p = cpu_is_p_type((u32)cpu);

	if (is_p) {
		self_dsq    = AUCTION_DSQ_P;
		other_dsq   = AUCTION_DSQ_E;
		w_bar_self  = rt->w_bar_p;
	} else {
		self_dsq    = AUCTION_DSQ_E;
		other_dsq   = AUCTION_DSQ_P;
		w_bar_self  = rt->w_bar_e;
	}

	/*
	 * Phase 0 — liveness.  Tasks that have lost the cluster auction for
	 * CLUSTER_MAX_WAIT_NS are demoted to STARVED, and the STARVED head
	 * gets the CPU once it has waited STARVED_MAX_WAIT_NS, whatever the
	 * load on the auction queues.
	 */
	{
		u64 now = bpf_ktime_get_ns();

		age_cluster_dsqs(now);
		if (serve_expired_starved(cpu, now)) {
			stat_inc(STAT_STARVED_AGED);
			return;
		}
	}

	/* Phase 0b — the incumbent defends its core against the queue head. */
	if (keep_prev(prev, self_dsq, is_p, w_bar_self, rt, gdata)) {
		stat_inc(STAT_KEEP_PREV);
		return;
	}

	/*
	 * Phase 1 — auction on the local cluster.  Run up to N rounds: each
	 * losing round (STARVED exile) consumes the current top, so the next
	 * round operates on the previous runner-up.  Bounded by
	 * DISPATCH_AUCTION_TRIES for the BPF verifier.  Fast-path: when there
	 * is at most one queued task the auction is degenerate (no runner-up)
	 * — short-circuit via move_to_local, saving an iter alloc + destroy
	 * round-trip.  move_to_local silently skips a task this CPU may not
	 * run; the auction round's affinity guard then redirects it.
	 */
	{
		u64 nr = scx_bpf_dsq_nr_queued(self_dsq);

		if (nr == 1 && scx_bpf_dsq_move_to_local(self_dsq, 0))
			return;
		if (nr >= 1) {
			bpf_for(attempt, 0, DISPATCH_AUCTION_TRIES) {
				if (!scx_bpf_dsq_nr_queued(self_dsq))
					break;
				if (auction_try_round(self_dsq, w_bar_self, cpu))
					return;
			}
			/*
			 * Every round was spent on redirects or exiles.  Do not
			 * leave this CPU idle while its own cluster still has a
			 * task it may run (e.g. one pinned here, queued behind
			 * tasks pinned elsewhere): take the best such task.
			 */
			if (scx_bpf_dsq_nr_queued(self_dsq) &&
			    scx_bpf_dsq_move_to_local(self_dsq, 0))
				return;
		}
	}

	/*
	 * Phase 2 — cross-cluster steal (theory §2.4 work-conservation:
	 * an unused quantum is lost forever).  Use the plain FIFO drain on
	 * the foreign DSQ — the auction was already evaluated when those
	 * tasks were enqueued for THAT cluster, so re-running VCG with the
	 * wrong \bar W_κ would introduce noise.  move_to_local skips tasks
	 * incompatible with the calling CPU's affinity automatically.
	 */
	if (scx_bpf_dsq_move_to_local(other_dsq, 0)) {
		stat_inc(STAT_STEAL);
		return;
	}

	/*
	 * Phase 3 — STARVED queue, when both clusters have nothing for this
	 * CPU.  Bypasses the VCG check entirely: tasks here have already
	 * been rejected once.  Oldest exile first.
	 */
	if (scx_bpf_dsq_move_to_local(AUCTION_DSQ_STARVED, 0))
		stat_inc(STAT_STARVED_IDLE);
}

void
BPF_STRUCT_OPS(auction_running, struct task_struct *p)
{
	struct auction_task_ctx *tctx = get_task_ctx(p);

	if (!tctx)
		return;

	/* Wake-ups placed by select_cpu skip ops.enqueue; credit them here. */
	budget_replenish(tctx, bpf_ktime_get_ns());

	tctx->exec_at_run = p->se.sum_exec_runtime;
	tctx->ran_on_p    = cpu_is_p_type((u32)scx_bpf_task_cpu(p));
	tctx->on_cpu      = 1;
	tctx->yielded     = 0;
}

void
BPF_STRUCT_OPS(auction_stopping, struct task_struct *p, bool runnable)
{
	struct auction_ctx      *gdata = get_ctx();
	struct auction_runtime  *rt    = get_rt();
	struct auction_task_ctx *tctx  = get_task_ctx(p);

	if (!gdata || !rt || !tctx)
		return;

	if (tctx->on_cpu) {
		account_run(p, tctx, rt, gdata);
		tctx->on_cpu = 0;
	}
	tctx->ran = 1;
}

/*
 * l_i is the length of a CPU burst: runtime accumulated from wake-up to the
 * next sleep, across any number of preemptions.  Only a completed burst
 * feeds the EWMA, l̂ ← (7·l̂ + min(burst, L)) / 8 (α = 1/8 — same as s4); an
 * ongoing one is visible through task_len_ns().
 *
 * Keyed on SCX_DEQ_SLEEP rather than ops.stopping(runnable=false), which
 * also fires when a running task is dequeued for a property change
 * (affinity, nice, …) and immediately re-enqueued.  ops.stopping, and with
 * it the final account_run(), runs before this.
 */
void
BPF_STRUCT_OPS(auction_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct auction_task_ctx *tctx;
	u64 burst;

	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	tctx = get_task_ctx(p);
	if (!tctx)
		return;

	burst = tctx->burst_ns < LEN_CAP_NS ? tctx->burst_ns : LEN_CAP_NS;
	tctx->len_est_ns     = (tctx->len_est_ns * 7 + burst) >> 3;
	tctx->burst_ns       = 0;
	tctx->sleep_start_ns = bpf_ktime_get_ns();
}

/*
 * sched_yield(): with ops.yield implemented the kernel no longer zeroes the
 * slice itself.  Do that, and flag the task so keep_prev() does not hand
 * the CPU straight back to it.  yield_to() (@to != NULL) is not supported.
 */
bool
BPF_STRUCT_OPS(auction_yield, struct task_struct *from, struct task_struct *to)
{
	struct auction_task_ctx *tctx;

	if (to)
		return false;

	tctx = get_task_ctx(from);
	if (tctx)
		tctx->yielded = 1;
	from->scx.slice = 0;
	return false;
}

s32
BPF_STRUCT_OPS(auction_set_weight, struct task_struct *p, u32 new_weight)
{
	struct auction_task_ctx *tctx = get_task_ctx(p);
	u64 bmax_new;

	if (!tctx)
		return 0;
	if (!new_weight)
		new_weight = 1;

	bmax_new = (u64)new_weight * BUDGET_MUL;

	/* Proportionally scale residual budget so a re-nice does not strip credit. */
	if (tctx->budget_max && tctx->budget) {
		u64 ratio = tctx->budget * bmax_new / tctx->budget_max;
		tctx->budget = ratio > bmax_new ? bmax_new : ratio;
	} else {
		tctx->budget = bmax_new;
	}
	tctx->budget_max    = bmax_new;
	tctx->weight_cached = new_weight;
	return 0;
}

/*
 * Allocate per-task storage where failure can be reported: ops.init_task
 * may sleep and its error aborts the fork / scheduler load cleanly, while
 * an allocation failure on a hot path would lose the task.
 */
s32
BPF_STRUCT_OPS_SLEEPABLE(auction_init_task, struct task_struct *p,
			 struct scx_init_task_args *args)
{
	if (!bpf_task_storage_get(&task_ctx_map, p, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -ENOMEM;
	return 0;
}

/*
 * (Re)entering sched_ext: reset the auction state.  Storage is kept across
 * disable/enable cycles (e.g. SCHED_FIFO and back) and freed with the task.
 */
void
BPF_STRUCT_OPS(auction_enable, struct task_struct *p)
{
	struct auction_task_ctx *tctx = get_task_ctx(p);
	u32 weight;

	if (!tctx)
		return;

	weight = p->scx.weight ?: 1;
	tctx->weight_cached  = weight;
	tctx->budget_max     = (u64)weight * BUDGET_MUL;
	tctx->budget         = tctx->budget_max;          /* fully funded at admission */
	tctx->len_est_ns     = AUCTION_SLICE_P;           /* one P-quantum prior       */
	tctx->burst_ns       = 0;
	tctx->sleep_start_ns = 0;
	tctx->exec_at_run    = 0;
	tctx->wake_prev_cpu  = -1;
	tctx->phi_enq        = 0;
	tctx->m_enq          = 0;
	tctx->enq_at_ns      = 0;
	tctx->ran_on_p       = 0;
	tctx->on_cpu         = 0;
	tctx->ran            = 0;
	tctx->yielded        = 0;
}

s32
BPF_STRUCT_OPS_SLEEPABLE(auction_init)
{
	struct auction_ctx *gdata = get_ctx();
	struct bpf_cpumask *pm;
	s32 ret;
	s32 c;

	pm = bpf_cpumask_create();
	if (!pm)
		return -ENOMEM;
	bpf_for(c, 0, AUCTION_NCPU_MAX)
		if (cpu_known((u32)c) && cpu_is_p_type((u32)c))
			bpf_cpumask_set_cpu((u32)c, pm);
	pm = bpf_kptr_xchg(&p_cpumask, pm);
	if (pm)
		bpf_cpumask_release(pm);

	if (gdata) {
		if (!gdata->max_capacity)
			gdata->max_capacity = CAPACITY_SCALE;
		if (!gdata->min_capacity)
			gdata->min_capacity = CAPACITY_SCALE;
		if (!gdata->cost_p)
			gdata->cost_p = C_P_DEF;
		if (!gdata->cost_e)
			gdata->cost_e = C_E_DEF;
	}

	ret = scx_bpf_create_dsq(AUCTION_DSQ_P, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(AUCTION_DSQ_E, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(AUCTION_DSQ_STARVED, -1);
}

void
BPF_STRUCT_OPS(auction_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(auction_ops,
	       .select_cpu = (void *)auction_select_cpu,
	       .enqueue    = (void *)auction_enqueue,
	       .dispatch   = (void *)auction_dispatch,
	       .running    = (void *)auction_running,
	       .stopping   = (void *)auction_stopping,
	       .quiescent  = (void *)auction_quiescent,
	       .yield      = (void *)auction_yield,
	       .set_weight = (void *)auction_set_weight,
	       .init_task  = (void *)auction_init_task,
	       .enable     = (void *)auction_enable,
	       .init       = (void *)auction_init,
	       .exit       = (void *)auction_exit,
	       .name       = "scx_A1349");
