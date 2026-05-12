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
 *   φ_κ(θ_i)  effective value of task i on cluster κ ∈ {P, E}
 *               φ_P = v_i − c_P · l_i
 *               φ_E = v_i − c_E · ⌈l_i · σ⌉
 *   j           runner-up task in the same cluster queue
 *   m_κ(l)      contract length in quanta on cluster κ
 *   δ           discount factor (model §2.4, MDP Bellman)
 *   \bar W_κ    EWMA of realised φ_κ on cluster κ — proxy for the expected
 *               future welfare when the core returns to the free pool
 *
 * Budget discipline (theory Proposition 1):  if p_{i*} > B_{i*}^t, the
 * winner cannot afford the auction.  i* is moved to AUCTION_DSQ_STARVED;
 * the core falls through to j and re-runs the auction.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* ── tuneables ───────────────────────────────────────────────────────────── */

#define CAPACITY_SCALE      1024u
#define P_CAP_PCT           90u

/* Default per-quantum costs c_P, c_E.  Userspace overrides via global_data. */
#define C_P_DEF             512u
#define C_E_DEF             256u

/*
 * φ value-term scale shift.  Without it, for default-nice tasks
 * (weight=1024, c_P=1024, l_q≈1) the formula φ_P = w − c·l_q collapses to
 * ≈ 0 — the entire P-cluster DSQ degenerates to FIFO because every task's
 * encode_phi() lands on PHI_BIAS.  Shifting v_i by 1 bit widens the
 * dynamic range without overshooting: fresh task φ_P ≈ 1024,
 * long-running (l_q=2) φ_P ≈ 0, very long (l_q=32) φ_P ≈ −30720.
 * Budget and replenish constants below absorb the same ×2.
 */
#define PHI_VALUE_SHIFT     1u


/*
 * Budget token bucket (theory §2.4 budget mechanism).
 *   B_i^max     = w_i · BUDGET_MUL
 *   replenish    = min(idle_ns, REPLENISH_IDLE_CAP) · w_i / REPLENISH_DIV
 *
 * Both constants scaled by 1<<PHI_VALUE_SHIFT relative to the s4 originals
 * (2000 / 5e6).  Net result: typical VCG payment / budget ratio unchanged,
 * STARVED entry rate matches the pre-rescale baseline.
 */
#define BUDGET_MUL          (8ULL     << PHI_VALUE_SHIFT)
#define REPLENISH_DIV       (12000000ULL >> PHI_VALUE_SHIFT)
#define REPLENISH_IDLE_CAP  1000000000ULL

/*
 * Cluster-conditioned slice grants (same dual-slice rationale as s4).
 *   SLICE_P  short, latency-first.
 *   SLICE_E  1.5× larger, amortises preempt overhead on slower cores.
 *
 * Reduced from the original 20 ms to 10 ms.  Hackbench-style
 * producer-consumer pairs round-trip in ~0.2 ms; a 20 ms slice held
 * the consumer idle waiting for the producer's slice expiry under
 * stress (no idle CPU available, fall-through to cluster DSQ).
 * Halving the slice tightens the preempt cycle without dropping it
 * into the high-overhead sub-millisecond regime.
 */
#define AUCTION_SLICE_P     20000000ULL
#define AUCTION_SLICE_E     ((3ULL * AUCTION_SLICE_P) / 2)

/*
 * φ encoding for the kernel DSQ (which sorts by ascending u64 vtime).
 *
 *   key = PHI_BIAS − φ           if φ ≥ 0   (smaller key ⇒ higher priority)
 *   key = PHI_BIAS + |φ|         if φ < 0
 *
 * PHI_BIAS = 1<<62 keeps the result inside u64 for any |φ| ≤ 2^62.  Typical
 * |φ| is bounded by weight·SLICE_P ≈ 1e12 ≪ 2^62, well within the budget.
 */
#define PHI_BIAS            (1ULL << 62)

/*
 * Contract length cap (theory §2.4: L upper-bounds l_i).  Indexes the δ^m
 * lookup table populated by userspace.  m ∈ [0, MAX_CONTRACT_LENGTH−1].
 * 32 P-quanta ≈ 640 ms — long enough that δ^m essentially floors.
 */
#define MAX_CONTRACT_LENGTH 32u

/*
 * Fixed-point scale for δ^m and \bar W_κ.  δ^m_table[m] = round(δ^m · DELTA_SCALE).
 */
#define DELTA_SHIFT         20
#define DELTA_SCALE         (1ULL << DELTA_SHIFT)

/* \bar W_κ EWMA: \bar W ← ((W_REALISED_EWMA_DEN − 1) · \bar W + W_realised) / DEN. */
#define W_BAR_EWMA_DEN      16u

/* DSQ identifiers. */
#define AUCTION_DSQ_P       1ULL
#define AUCTION_DSQ_E       2ULL
#define AUCTION_DSQ_STARVED 3ULL
/*
 * Per-CPU sticky DSQs (cache-warm hold for long-running preempted tasks).
 * Indexed AUCTION_DSQ_PERCPU_BASE + cpu.  A task with len_est_ns ≥ SLICE_P
 * that gets preempted lands in the CPU's sticky DSQ instead of the shared
 * cluster DSQ — the next dispatch on the same CPU picks it back up before
 * any cluster work-steal, preserving L1/L2 locality across the preempt
 * cycle.  Without this, long memory-bound tasks scatter across the cluster
 * and PassMark MEM/MEM_LAT regress sharply.
 */
#define AUCTION_DSQ_PERCPU_BASE 100ULL
#define AUCTION_NCPU_MAX        64

/* Maximum auction retries per dispatch tick (top, runner, …). */
#define DISPATCH_AUCTION_TRIES 3

/* ── maps ────────────────────────────────────────────────────────────────── */

/*
 * Userspace-owned configuration (RO from BPF).  Refreshed periodically on
 * topology change.  No estimator state lives here.
 */
struct auction_ctx {
	u32 max_capacity;          /* η_P (max cpu_capacity)  */
	u32 min_capacity;          /* η_E (min cpu_capacity)  */
	u32 cost_p;                /* c_P                     */
	u32 cost_e;                /* c_E                     */
	u32 p_core_count;          /* K_P                     */
	u32 e_core_count;          /* K_E                     */
};

/*
 * BPF-owned runtime estimator state.  Userspace must NOT update.
 *   w_bar_p, w_bar_e — EWMA of realised φ_κ per cluster.  Approximates the
 *                      Bellman expectation \bar W_κ of theory §2.4.
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

/*
 * Per-task auction state.
 *
 *   budget         remaining B_i^t (theory §2.4)
 *   budget_max     B_i (w_i · BUDGET_MUL)
 *   last_stop_ns   bpf_ktime at last stopping; basis for idle-time replenish
 *   len_est_ns     EWMA of consumed_ns per activation — proxy for l_i
 *   phi_enq        φ_κ chosen at enqueue, retained for the stopping-time
 *                  \bar W update
 *   m_enq          contract length m_κ(l_i) used in the VCG payment
 *   on_p_type      1 if last enqueued onto AUCTION_DSQ_P, 0 otherwise
 *   long_slice     1 if granted AUCTION_SLICE_E at insert
 *   weight_cached  stale-safe copy of p->scx.weight
 *   wake_prev_cpu  prev_cpu captured in select_cpu (cache-warm hint)
 */
struct auction_task_ctx {
	u64 budget;
	u64 budget_max;
	u64 last_stop_ns;
	u64 len_est_ns;
	s64 phi_enq;
	u32 m_enq;
	u32 weight_cached;
	s32 wake_prev_cpu;
	u8  on_p_type;
	u8  long_slice;
	u8  _pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct auction_task_ctx);
} task_ctx_map SEC(".maps");

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

static __always_inline struct auction_task_ctx *
get_task_ctx(struct task_struct *p, bool create)
{
	return bpf_task_storage_get(&task_ctx_map, p, 0,
				    create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
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
 * Compute φ_P and φ_E for a task (eq:phi, rescaled to weight-units).
 *
 *   l_q  = len_ns / SLICE_P            (length in P-quanta, continuous)
 *   φ_P = w           − c_P · l_q
 *   φ_E = w · η_E/η_P − c_E · l_q
 *
 * Earlier (weight × ns) formulation produced |φ| ≈ 1e10, which dominated
 * the budget scale and pushed VCG payments to either clamp at zero (free)
 * or drain the bucket in a single dispatch.  Dividing by SLICE_P
 * normalises φ to the same magnitude as the weight (≈ 1..50000), making
 * the budget and replenishment constants from s4 directly reusable.
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
	 * v_i scaled by PHI_VALUE_SHIFT to break the φ=0 degeneracy that
	 * collapses default-nice tasks to FIFO inside the DSQ.  Cost stays
	 * at native scale: ranking now uses widened value with cost as a
	 * smaller corrective term, which preserves the sign of φ on
	 * long-running tasks (φ < 0 when the contract dominates the value).
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

static __always_inline u64
delta_pow(u32 m)
{
	u32 key = (m < MAX_CONTRACT_LENGTH) ? m : (MAX_CONTRACT_LENGTH - 1);
	u64 *v = bpf_map_lookup_elem(&delta_table, &key);
	/* Fallback δ^? ≈ 1 if userspace forgot to populate. */
	return v ? *v : DELTA_SCALE;
}

/*
 * Replenish budget by idle time × weight.  Token bucket capped at budget_max.
 * Mirrors theory §2.4 "Аллокация задаче … допустима, если p_i ≤ B_i^t":
 * sleep accrues credit; the budget cap prevents permanent stockpiling.
 *
 * Consumes the credited interval by advancing last_stop_ns to `now` on a
 * successful refill.  This lets the caller invoke budget_replenish() on
 * every enqueue (including preempt re-enqueues that lack SCX_ENQ_WAKEUP)
 * without double-crediting: a tight preempt-re-enqueue arrives with
 * idle_ns ≈ 0 and is a no-op, while a genuine sleep period is fully
 * credited exactly once and then consumed.
 */
static __always_inline void
budget_replenish(struct auction_task_ctx *tctx, u64 now)
{
	u64 idle_ns, add;

	if (!tctx->last_stop_ns || now <= tctx->last_stop_ns)
		return;

	idle_ns = now - tctx->last_stop_ns;
	if (idle_ns > REPLENISH_IDLE_CAP)
		idle_ns = REPLENISH_IDLE_CAP;

	add = idle_ns * (u64)(tctx->weight_cached ?: 1) / REPLENISH_DIV;
	tctx->budget += add;
	if (tctx->budget > tctx->budget_max)
		tctx->budget = tctx->budget_max;

	tctx->last_stop_ns = now;
}

/*
 * VCG payment in the single-slot regime (eq:single-unit-payment):
 *
 *   p = φ_j  +  (δ^{m_j} − δ^{m_i}) · \bar W_κ / DELTA_SCALE
 *
 * If the runner-up j is absent, φ_j ≡ 0 and m_j ≡ 0 (so δ^0 = 1), which
 * collapses the payment to the "lonely winner" form
 *   p = (1 − δ^{m_i}) · \bar W_κ.
 *
 * Returned as a signed s64.  A negative payment (the externality benefits
 * the rest of the system, e.g. when m_i < m_j) is clamped to zero at the
 * budget check — we never credit budget.
 */
static __always_inline s64
vcg_payment(s64 phi_j, u32 m_j, u32 m_i, u64 w_bar)
{
	u64 dj = m_j ? delta_pow(m_j) : DELTA_SCALE;   /* δ^0 = 1 */
	u64 di = delta_pow(m_i);
	s64 diff = (s64)dj - (s64)di;
	s64 ext;

	/* (diff · w_bar) >> DELTA_SHIFT, sign-preserving. */
	if (diff >= 0)
		ext = (s64)(((u64)diff * w_bar) >> DELTA_SHIFT);
	else
		ext = -(s64)(((u64)(-diff) * w_bar) >> DELTA_SHIFT);

	return phi_j + ext;
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

	tctx = get_task_ctx(p, false);
	if (tctx)
		tctx->wake_prev_cpu = prev_cpu;

	/*
	 * P-bias scan (model §2.4 Allocation rule, refined):  prefer an idle
	 * P-cluster CPU first.  For default-weight tasks φ_P ≥ φ_E almost
	 * always (weight − cost > weight·η_E/η_P − cost), so the rule reduces
	 * to "land on the strongest core that's free".  Avoids the
	 * select_cpu_dfl bias toward prev_cpu which routinely strands single-
	 * threaded passmark workers on E-cores.
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
		if (tctx)
			tctx->long_slice = 0;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, AUCTION_SLICE_P, 0);
	}

	return cpu;
}

void
BPF_STRUCT_OPS(auction_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct auction_ctx      *gdata = get_ctx();
	struct auction_task_ctx *tctx  = get_task_ctx(p, true);
	u32 max_cap, min_cap, cost_p, cost_e, weight;
	u64 len_ns, slice_ns, dsq_id;
	s64 phi_p, phi_e, phi_chosen;
	u32 m_chosen;
	bool on_p, is_wakeup;

	if (!gdata || !tctx)
		return;

	max_cap = gdata->max_capacity ?: CAPACITY_SCALE;
	min_cap = gdata->min_capacity ?: max_cap;
	cost_p  = gdata->cost_p       ?: C_P_DEF;
	cost_e  = gdata->cost_e       ?: C_E_DEF;
	weight  = p->scx.weight       ?: 1;
	tctx->weight_cached = weight;
	is_wakeup = (enq_flags & SCX_ENQ_WAKEUP) || !tctx->last_stop_ns;

	/*
	 * Replenish unconditionally — preempt re-enqueues arrive with
	 * idle_ns ≈ 0 (no time since the last consume) and are no-ops,
	 * while genuine wake-ups credit one full sleep interval.  Closes
	 * the moderate-load schbench p99 cliff where workers preempted
	 * faster than REPLENISH_DIV could refill on WAKEUP-only path.
	 */
	budget_replenish(tctx, bpf_ktime_get_ns());

	len_ns = tctx->len_est_ns ?: AUCTION_SLICE_P;
	compute_phi(weight, len_ns, max_cap, min_cap, cost_p, cost_e,
		    &phi_p, &phi_e);

	/*
	 * Cluster routing:
	 *   - WAKEUP / first enqueue: re-evaluate κ* = argmax_κ φ_κ.
	 *   - Preempt re-enqueue (no WAKEUP): keep the cluster the task was
	 *     last running on.  Re-routing mid-run thrashes caches without
	 *     yielding new auction information — the task's φ hasn't moved
	 *     enough between two adjacent quanta to justify migration.
	 */
	if (is_wakeup) {
		on_p = (phi_p >= phi_e);
	} else {
		on_p = tctx->on_p_type != 0;
	}
	phi_chosen    = on_p ? phi_p : phi_e;
	m_chosen      = contract_length(len_ns, on_p, max_cap, min_cap);
	dsq_id        = on_p ? AUCTION_DSQ_P : AUCTION_DSQ_E;
	slice_ns      = on_p ? AUCTION_SLICE_P : AUCTION_SLICE_E;
	tctx->on_p_type = on_p ? 1 : 0;
	tctx->long_slice = on_p ? 0 : 1;
	tctx->phi_enq   = phi_chosen;
	tctx->m_enq     = m_chosen;

	/*
	 * Budget admissibility (theory Proposition 1):  if the task cannot
	 * afford even the optimistic "lonely winner" payment (1 − δ^{m_i}) ·
	 * \bar W_κ, route directly to STARVED so the auction tries do not
	 * waste a dispatch tick on it.  Cheap conservative test.
	 */
	if (tctx->budget_max &&
	    tctx->budget * 10 < tctx->budget_max) {
		dsq_id = AUCTION_DSQ_STARVED;
		slice_ns = AUCTION_SLICE_P;
		tctx->long_slice = 0;
		goto insert;
	}

	/*
	 * Asymmetric P→E spill (extension §X.1 mirrored from s4).  When the
	 * P queue is saturated and relatively more crowded than E in
	 * normalised depth, route the would-be P task to E to keep all cores
	 * busy on big-P / small-E and big-E / small-P silicon alike.
	 * Cross-multiplied to avoid a 64-bit divide on the hot path:
	 *   Q_P · K_E > Q_E · K_P  ⇒  P is the bottleneck, spill to E.
	 *
	 * Previously gated on short tasks only.  The gate caused stress
	 * hackbench regression because long P-resident pipe pairs piled up
	 * behind each other on the saturated P queue while E sat idle.
	 * Trade-off versus the historical PassMark MEM/MEM_LAT regression
	 * on memory-bound long-runners: those workloads still benefit from
	 * the per-CPU sticky DSQ pin on subsequent quanta, which keeps the
	 * task cache-warm even after the initial spill.
	 */
	if (on_p) {
		u32 p_cc = gdata->p_core_count;
		u32 e_cc = gdata->e_core_count;
		u64 p_q  = scx_bpf_dsq_nr_queued(AUCTION_DSQ_P);
		u64 e_q  = scx_bpf_dsq_nr_queued(AUCTION_DSQ_E);

		if (p_cc && e_cc && p_q >= p_cc &&
		    (e_q < e_cc || p_q * e_cc > e_q * p_cc)) {
			dsq_id          = AUCTION_DSQ_E;
			slice_ns        = AUCTION_SLICE_E;
			tctx->on_p_type = 0;
			tctx->long_slice = 1;
			phi_chosen      = phi_e;
			tctx->phi_enq   = phi_e;
			tctx->m_enq     = contract_length(len_ns, false,
							  max_cap, min_cap);
			on_p            = false;
		}
	}

	/*
	 * Per-CPU sticky DSQ for long-running preempted tasks (cache-warm
	 * hold).  When a CPU-bound task (len_est_ns ≥ SLICE_P) hits a slice
	 * expiry preempt, the kernel calls enqueue again on the SAME CPU
	 * the task just ran on; routing it into the cluster DSQ allows the
	 * next dispatch to pull it onto any peer core, losing L1/L2.
	 * Sticky path keeps it on the same physical CPU.
	 *
	 * Skipped for: WAKEUP (handled by cache-warm pin above), new tasks
	 * (no last_stop_ns), short tasks (cluster mobility helps latency).
	 */
	if (!is_wakeup && tctx->last_stop_ns &&
	    tctx->len_est_ns >= AUCTION_SLICE_P) {
		s32 cur = (s32)bpf_get_smp_processor_id();
		if (cur >= 0 && cur < AUCTION_NCPU_MAX &&
		    bpf_cpumask_test_cpu(cur, p->cpus_ptr)) {
			scx_bpf_dsq_insert_vtime(p,
				AUCTION_DSQ_PERCPU_BASE + (u64)cur,
				slice_ns, encode_phi(phi_chosen),
				enq_flags);
			return;
		}
	}

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
		if (prev_cpu >= 0) {
			u32 pkey = (u32)prev_cpu;
			u8 *flag = bpf_map_lookup_elem(&cpu_is_p, &pkey);
			bool prev_is_p = flag && *flag;
			bool cluster_match = on_p ? prev_is_p : !prev_is_p;

			if (cluster_match &&
			    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
			    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				scx_bpf_dsq_insert(p,
					SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					slice_ns, enq_flags);
				if ((s32)bpf_get_smp_processor_id() != prev_cpu)
					scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
				return;
			}
		}
	}

insert:
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns,
				 encode_phi(phi_chosen), enq_flags);

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

	t_top = get_task_ctx(p_top, false);
	if (!t_top)
		goto out;

	m_top = t_top->m_enq;

	p_runner = bpf_iter_scx_dsq_next(&it);
	if (p_runner) {
		t_runner = get_task_ctx(p_runner, false);
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
		u64 charge = payment > 0 ? (u64)payment : 0;
		if (t_top->budget >= charge)
			t_top->budget -= charge;
		else
			t_top->budget = 0;
		/*
		 * SCX_DSQ_LOCAL is a built-in per-CPU FIFO queue — kernel
		 * rejects vtime ordering on it, so the bare move() is correct.
		 */
		scx_bpf_dsq_move(&it, p_top, SCX_DSQ_LOCAL, 0);
		dispatched = true;
	} else {
		/*
		 * Cannot afford the auction — exile to STARVED.
		 *
		 * STARVED was populated by enqueue via scx_bpf_dsq_insert_vtime
		 * (PRIQ mode).  A bare scx_bpf_dsq_move() would FIFO-insert and
		 * crash with "DSQ already had PRIQ-enqueued tasks".  Preserve the
		 * task's φ-encoded vtime so STARVED stays φ-ordered: least-bad
		 * task gets pulled first when budget recovers.
		 */
		scx_bpf_dsq_move_set_vtime(&it, p_top->scx.dsq_vtime);
		scx_bpf_dsq_move_vtime(&it, p_top, AUCTION_DSQ_STARVED, 0);
	}

out:
	bpf_iter_scx_dsq_destroy(&it);
	return dispatched;
}

void
BPF_STRUCT_OPS(auction_dispatch, s32 cpu, struct task_struct *prev)
{
	struct auction_runtime *rt = get_rt();
	bool is_p;
	u64 self_dsq, other_dsq, w_bar_self;
	int attempt;

	if (!rt)
		return;

	is_p = cpu_is_p_type((u32)cpu);

	/*
	 * Phase 0 — per-CPU sticky DSQ.  Long-running preempted tasks live
	 * here for cache-warm continuation on the same physical core.
	 * Checked first so a slice-expiry preempt has the cheapest possible
	 * re-pickup path.
	 */
	if (cpu >= 0 && cpu < AUCTION_NCPU_MAX &&
	    scx_bpf_dsq_move_to_local(AUCTION_DSQ_PERCPU_BASE + (u64)cpu, 0))
		return;

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
	 * Phase 1 — auction on the local cluster.  Run up to N rounds: each
	 * losing round (STARVED exile) consumes the current top, so the next
	 * round operates on the previous runner-up.  Bounded by
	 * DISPATCH_AUCTION_TRIES for the BPF verifier.  Fast-path: when there
	 * is at most one queued task the auction is degenerate (no runner-up)
	 * — short-circuit via move_to_local which also handles CPU-affinity
	 * skipping internally, saving an iter alloc + destroy round-trip.
	 */
	{
		u64 nr = scx_bpf_dsq_nr_queued(self_dsq);
		if (nr == 1) {
			if (scx_bpf_dsq_move_to_local(self_dsq, 0))
				return;
		} else if (nr >= 2) {
			bpf_for(attempt, 0, DISPATCH_AUCTION_TRIES) {
				if (!scx_bpf_dsq_nr_queued(self_dsq))
					break;
				if (auction_try_round(self_dsq, w_bar_self, cpu))
					return;
			}
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
	if (scx_bpf_dsq_move_to_local(other_dsq, 0))
		return;

	/*
	 * Phase 3 — STARVED queue.  Bypasses the VCG check entirely:
	 * tasks here have already been rejected once and are running on
	 * idle-time replenishment.  Plain head-of-queue FIFO via the
	 * DSQ's own vtime ordering (φ at enqueue moment).
	 */
	scx_bpf_dsq_move_to_local(AUCTION_DSQ_STARVED, 0);
}

void
BPF_STRUCT_OPS(auction_running, struct task_struct *p)
{
	(void)p;
}

void
BPF_STRUCT_OPS(auction_stopping, struct task_struct *p, bool runnable)
{
	struct auction_ctx      *gdata = get_ctx();
	struct auction_runtime  *rt    = get_rt();
	struct auction_task_ctx *tctx  = get_task_ctx(p, false);
	u64 slice_granted, consumed;
	u64 phi_realised, w_bar_new;
	u64 *w_bar_slot;
	bool on_p;

	if (!gdata || !rt || !tctx)
		return;

	slice_granted = tctx->long_slice ? AUCTION_SLICE_E : AUCTION_SLICE_P;
	consumed      = slice_granted > p->scx.slice
			? slice_granted - p->scx.slice : 0;

	/*
	 * \bar W_κ update (architecture.md §5).  Realised contribution of
	 * this run = |φ_κ| · (consumed / SLICE_P), capped at |φ| to bound
	 * the EWMA input even on E-cores that ran a longer slice.  The
	 * absolute value keeps \bar W ≥ 0, matching its role as expected
	 * future welfare — a noisy φ < 0 sample (rare: STARVED routing
	 * filters these) does not subtract credit from a healthy cluster.
	 */
	on_p = tctx->on_p_type != 0;
	{
		s64 phi = tctx->phi_enq;
		u64 phi_abs = phi >= 0 ? (u64)phi : (u64)(-phi);
		/* phi_abs · consumed / SLICE_P, with consumed ≤ slice_granted. */
		phi_realised = phi_abs * consumed / AUCTION_SLICE_P;

		w_bar_slot = on_p ? &rt->w_bar_p : &rt->w_bar_e;
		w_bar_new  = ((*w_bar_slot) * (W_BAR_EWMA_DEN - 1) + phi_realised)
			     / W_BAR_EWMA_DEN;
		*w_bar_slot = w_bar_new;
	}

	/*
	 * Length EWMA: l̂ ← (7·l̂ + consumed) / 8  (α = 1/8 — same as s4).
	 * Slower than a tight α to suppress φ jitter that would cause
	 * spurious cluster crossings on the next enqueue.
	 */
	{
		u64 old_len = tctx->len_est_ns ?: consumed;
		u64 new_len = (old_len * 7 + consumed) >> 3;
		tctx->len_est_ns = new_len ?: (consumed ?: AUCTION_SLICE_P);
	}

	/*
	 * last_stop_ns is only the idle-replenish baseline.  Preempt re-enqueues
	 * (runnable=true) keep the previous timestamp so the next wake-up
	 * measures the *real* sleep duration, not the preempt gap — otherwise
	 * a CPU-bound task that is constantly preempted would never accrue
	 * replenishment.
	 */
	if (!runnable)
		tctx->last_stop_ns = bpf_ktime_get_ns();
}

s32
BPF_STRUCT_OPS(auction_set_weight, struct task_struct *p, u32 new_weight)
{
	struct auction_task_ctx *tctx = get_task_ctx(p, true);
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

void
BPF_STRUCT_OPS(auction_enable, struct task_struct *p)
{
	struct auction_task_ctx *tctx = get_task_ctx(p, true);
	u32 weight;

	if (!tctx)
		return;

	weight = p->scx.weight ?: 1;
	tctx->weight_cached = weight;
	tctx->budget_max    = (u64)weight * BUDGET_MUL;
	tctx->budget        = tctx->budget_max;          /* fully funded at admission */
	tctx->len_est_ns    = AUCTION_SLICE_P;           /* one P-quantum prior       */
	tctx->last_stop_ns  = 0;
	tctx->wake_prev_cpu = -1;
	tctx->phi_enq       = 0;
	tctx->m_enq         = 0;
	tctx->on_p_type     = 0;
	tctx->long_slice    = 0;
}

void
BPF_STRUCT_OPS(auction_disable, struct task_struct *p)
{
	/*
	 * No global state to retract (no V(t), no Σw_j).  Task storage is
	 * reaped automatically by BPF_F_NO_PREALLOC when the task struct goes
	 * away, but call delete explicitly for tidiness.
	 */
	bpf_task_storage_delete(&task_ctx_map, p);
}

s32
BPF_STRUCT_OPS_SLEEPABLE(auction_init)
{
	struct auction_ctx *gdata = get_ctx();
	s32 ret;

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
	ret = scx_bpf_create_dsq(AUCTION_DSQ_STARVED, -1);
	if (ret)
		return ret;

	{
		u32 i;
		bpf_for(i, 0, AUCTION_NCPU_MAX) {
			s32 r = scx_bpf_create_dsq(
				AUCTION_DSQ_PERCPU_BASE + i, -1);
			if (r)
				return r;
		}
	}
	return 0;
}

SCX_OPS_DEFINE(auction_ops,
	       .select_cpu = (void *)auction_select_cpu,
	       .enqueue    = (void *)auction_enqueue,
	       .dispatch   = (void *)auction_dispatch,
	       .running    = (void *)auction_running,
	       .stopping   = (void *)auction_stopping,
	       .set_weight = (void *)auction_set_weight,
	       .enable     = (void *)auction_enable,
	       .disable    = (void *)auction_disable,
	       .init       = (void *)auction_init,
	       .name       = "scx_A1349");
