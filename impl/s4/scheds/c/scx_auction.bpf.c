/* SPDX-License-Identifier: GPL-2.0
 *
 * scx_auction — Dynamic VCG Auction Scheduler for Heterogeneous CPUs (s4/A1349)
 *
 * Maps the Vickrey auction model (hetero_scheduler_model.md) to sched_ext:
 *
 *   Model symbol            Implementation
 *   ──────────────────────  ────────────────────────────────────────────────────
 *   valuation v_i           task->scx.weight  (Linux nice/priority)
 *   length l_i              EWMA of observed run-time ns per activation
 *   effective value φ_P     v*slice - C_P * l_ns       (ns units, no quantization)
 *   effective value φ_E     v*slice - C_E * l_ns * σ   (σ = max_cap/min_cap)
 *   allocation κ ∈ {P,E}    DSQ chosen by argmax φ_κ
 *   VCG payment p_i         posted price: C_κ * consumed_ns / slice (§6.3 approx.)
 *   budget B_i              token bucket; time-based replenishment ∝ weight
 *   budget-depleted task    → AUCTION_DSQ_STARVED (lowest priority)
 *
 * Core DSQ structure:
 *   AUCTION_DSQ_P      — high-capacity (P-core) run queue
 *   AUCTION_DSQ_E      — low-capacity  (E-core) run queue
 *   AUCTION_DSQ_STARVED— budget-exhausted fallback (runs last)
 *
 * P/E crossover: φ_P ≥ φ_E iff C_E * σ ≥ C_P (length-independent).
 * φ magnitude varies continuously with l_ns — enables proportional starvation
 * ordering.  On homogeneous (σ=1): all tasks go to DSQ_E; work-stealing serves
 * both DSQs so behaviour degenerates to EEVDF-equivalent.
 *
 * Virtual-time accounting (stopping callback) is taken directly from s3+:
 *   svc_vtime = consumed_ns * cpu_cap * SCALE / CAPACITY_SCALE
 * so faster cores advance a task's virtual time faster — correct for fairness
 * across P-cores and E-cores.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* ── tuneable constants ──────────────────────────────────────────────────── */

#define CAPACITY_SCALE      1024   /* Linux SCHED_CAPACITY_SCALE              */
#define P_CAP_PCT           90     /* CPU with cap ≥ 90% of max = P-core      */

/*
 * Per-ns costs (§3.2 of model, continuous formulation).
 * φ_P = weight*slice - C_P*len_ns,  φ_E = weight*slice - C_E*len_ns*σ.
 * C_P > C_E: P-core faster, higher opportunity cost per ns.
 */
#define C_P_DEF             512    /* default cost on P-core                  */
#define C_E_DEF             256    /* default cost on E-core                  */

/*
 * Budget (§1.3 / §3.3): token-bucket mechanism.
 *   budget_max  = weight * BUDGET_MUL
 *   payment     = C_κ * consumed_ns / slice  (proportional, no ceiling)
 *   replenish   = idle_ns * weight / REPLENISH_DIV  (per enqueue, on wake-up)
 *   starved     = budget < budget_max / STARVE_FRAC
 */
#define BUDGET_MUL          2000ULL    /* budget_max = weight * BUDGET_MUL   */
#define REPLENISH_DIV       5000000ULL /* replenish rate divisor (ns/unit)   */
#define REPLENISH_IDLE_CAP  1000000000ULL /* cap idle_ns at 1 s to prevent overflow */
#define STARVE_FRAC         10     /* starved if budget < budget_max/10       */

/*
 * Budget-ratio routing with hysteresis (§impl): tasks with budget ≥ HIGH% of
 * max are bursty (sleep-heavy) → DSQ_P; tasks below LOW% are CPU-bound →
 * DSQ_E; in the deadband, the previous cluster choice sticks.  Hysteresis
 * prevents cross-cluster migration storms when budget oscillates around 50%.
 * Routing is re-evaluated only on wake-up; preempt re-enqueues always keep
 * the existing cluster to eliminate P↔E flip-flop during a running stretch.
 */
#define BURST_HIGH_PCT      70     /* ≥ 70% budget → bursty → P-core         */
#define BURST_LOW_PCT       30     /* < 30% budget → cpu-bound → E-core      */

/*
 * Starvation vd penalty divisor for proportional ordering within DSQ_STARVED.
 * φ deficit is in ns-scale units (up to ~5e9); dividing by STARVE_PHI_DIV
 * maps it to ~0–10 slice-equivalents of extra vd delay.
 */
#define STARVE_PHI_DIV      1000ULL /* ns-φ deficit → vd penalty units        */

/* virtual-time arithmetic (matches s3+) */
#define SCALE               100
#define INV_SHIFT           20
#define DISPATCH_BATCH_MAX  8

/* DSQ ids */
#define AUCTION_DSQ_P       1
#define AUCTION_DSQ_E       2
#define AUCTION_DSQ_STARVED 3

/* ── BPF maps ────────────────────────────────────────────────────────────── */

/*
 * Global scheduler context.  Populated by userspace before attach.
 *   max_capacity — highest cpu_capacity value across online CPUs
 *   min_capacity — lowest cpu_capacity value (used to compute σ)
 *   cost_p / cost_e — per-quantum costs (override C_P_DEF / C_E_DEF at runtime)
 */
struct auction_ctx {
	u64 vtime_now;
	u64 total_weight;
	u32 max_capacity;
	u32 min_capacity;
	u32 cost_p;
	u32 cost_e;
	u32 p_core_count;   /* #CPUs classified as P-cluster (cap ≥ 90% max)    */
	u32 e_core_count;   /* #CPUs classified as E-cluster                    */
	/*
	 * Per-cluster running estimator of max positive φ observed at enqueue.
	 * Feeds VCG-pivot approximation in auction_stopping (§I4):
	 *   payment = max(cost_based, pivot_based), pivot_based ∝ φ_hi_κ.
	 * Updated on every enqueue: climb instantly, decay by EWMA (α=1/16).
	 */
	u64 dsq_phi_hi_p;
	u64 dsq_phi_hi_e;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct auction_ctx));
} global_data SEC(".maps");

/* Per-CPU capacity, populated from /sys/.../cpu_capacity by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cpu_capacity SEC(".maps");

/*
 * Per-task auction state:
 *   budget        — remaining budget (model §1.3)
 *   budget_max    — ceiling for budget (weight * BUDGET_MUL)
 *   last_stop_ns  — ktime at last stopping; used for replenishment delta
 *   len_est_ns    — EWMA of run-time ns per activation (proxy for l_i)
 *   weight_cached — stale-safe weight copy
 *   inv_weight    — fixed-point reciprocal for fast division
 *   on_p_type     — 1 if last enqueued to AUCTION_DSQ_P
 */
struct auction_task_ctx {
	u64 budget;
	u64 budget_max;
	u64 last_stop_ns;
	u64 len_est_ns;
	u32 weight_cached;
	u32 inv_weight;
	u8  on_p_type;
	u8  _pad[7];
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

static __always_inline struct auction_task_ctx *
get_task_ctx(struct task_struct *p, bool create)
{
	return bpf_task_storage_get(&task_ctx_map, p, 0,
				    create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}

static __always_inline u32
get_cpu_cap(u32 cpu)
{
	u32 *cap = bpf_map_lookup_elem(&cpu_capacity, &cpu);
	if (cap && *cap)
		return *cap;
	return CAPACITY_SCALE;
}

/* Returns true if this CPU is a P-core (high-capacity cluster). */
static __always_inline bool
cpu_is_p_type(u32 cpu, u32 max_cap)
{
	u32 cap = get_cpu_cap(cpu);
	if (!max_cap)
		max_cap = CAPACITY_SCALE;
	return (u64)cap * 100 >= (u64)max_cap * P_CAP_PCT;
}

static __always_inline u64
dsq_for_cpu(u32 cpu, u32 max_cap)
{
	return cpu_is_p_type(cpu, max_cap) ? AUCTION_DSQ_P : AUCTION_DSQ_E;
}

/* Refresh the cached weight reciprocal.  Division by weight is frequent. */
static __always_inline void
refresh_inv_weight(struct auction_task_ctx *tctx, u32 weight)
{
	u64 inv;

	if (!tctx || !weight)
		return;
	if (tctx->weight_cached == weight && tctx->inv_weight)
		return;

	inv = ((1ULL << INV_SHIFT) + weight / 2) / weight;
	if (!inv)
		inv = 1;
	tctx->weight_cached = weight;
	tctx->inv_weight    = (u32)inv;
}

static __always_inline u64
div_by_weight(u64 val, u32 weight, struct auction_task_ctx *tctx)
{
	if (!weight)
		weight = 1;
	refresh_inv_weight(tctx, weight);

	if (tctx && tctx->inv_weight && val <= 0xffffffffULL)
		return ((u64)(u32)val * (u64)tctx->inv_weight) >> INV_SHIFT;
	return val / weight;
}

static __always_inline u64
abs_s64(s64 v)
{
	if (v >= 0)
		return (u64)v;
	return (u64)(-(v + 1)) + 1;
}

static __always_inline s64
signed_div(s64 num, u64 den)
{
	u64 q;

	if (!den)
		return 0;
	q = abs_s64(num) / den;
	return (num < 0) ? -(s64)q : (s64)q;
}

static __always_inline void
add_vtime(struct auction_ctx *gdata, s64 delta)
{
	if (delta >= 0) {
		u64 add = (u64)delta;
		gdata->vtime_now = (gdata->vtime_now > (~0ULL - add))
				   ? ~0ULL
				   : gdata->vtime_now + add;
	} else {
		u64 sub = abs_s64(delta);
		gdata->vtime_now = (gdata->vtime_now > sub)
				   ? gdata->vtime_now - sub
				   : 0;
	}
}

/*
 * Compute per-task effective values φ_P and φ_E (model §5.2).
 *
 * Continuous ns formulation — no quantization to integer quanta:
 *
 *   φ_P = weight * slice - C_P * len_est_ns
 *   φ_E = weight * slice - C_E * len_est_ns * σ    σ = max_cap / min_cap
 *
 * weight is scaled by slice so both terms share nanosecond units.
 * φ > 0: task has positive net value on that core type.
 * φ < 0: cost exceeds value — task is consuming more than it contributes.
 *
 * P/E allocation decision: φ_P ≥ φ_E iff C_E * σ ≥ C_P (length cancels
 * in the comparison, so the crossover is set by topology + cost parameters).
 * The magnitude of φ now varies continuously with len_est_ns, enabling
 * proportional starvation ordering and future priority modulation.
 *
 * Overflow: max(weight)=49152, slice=5e6 → weight*slice ≈ 2.5e11 < s64_max.
 *           max(C_E * len * max_cap) = 256 * 5e6 * 2048 ≈ 2.6e12 < u64_max.
 */
static __always_inline void
compute_phi(u32 weight, u64 len_est_ns,
	    u32 max_cap, u32 min_cap,
	    u32 cost_p, u32 cost_e,
	    s64 *phi_p_out, s64 *phi_e_out)
{
	u64 slice = SCX_SLICE_DFL ?: 5000000;
	u32 mc    = min_cap ? min_cap : CAPACITY_SCALE;

	u64 w_slice    = (u64)weight * slice;
	u64 cost_p_ns  = (u64)cost_p * len_est_ns;
	/* C_E * len_ns * σ = C_E * len_ns * max_cap / min_cap */
	u64 cost_e_ns  = (u64)cost_e * len_est_ns * (u64)max_cap / (u64)mc;

	*phi_p_out = (s64)w_slice - (s64)cost_p_ns;
	*phi_e_out = (s64)w_slice - (s64)cost_e_ns;
}

/*
 * Replenish budget on task wake-up (task was sleeping = "idle" in model terms).
 * add = min(idle_ns, REPLENISH_IDLE_CAP) * weight / REPLENISH_DIV
 *
 * Intuition: while the task held no core, it accrues "credit" proportional to
 * its priority weight — higher-weight tasks refill faster.
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

	add = idle_ns * (u64)tctx->weight_cached / REPLENISH_DIV;
	tctx->budget += add;
	if (tctx->budget > tctx->budget_max)
		tctx->budget = tctx->budget_max;
}

/* ── sched_ext ops ───────────────────────────────────────────────────────── */

s32
BPF_STRUCT_OPS(auction_select_cpu,
	       struct task_struct *p,
	       s32                 prev_cpu,
	       u64                 wake_flags)
{
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx = get_task_ctx(p, false);
	bool is_idle = false;
	s32 cpu;
	u32 max_cap;
	bool want_p;
	u64 desired_dsq, cpu_dsq;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	/*
	 * If dfl didn't find an idle CPU, enqueue path will handle routing.
	 * Skip cluster-preference work; there's nothing to improve.
	 */
	if (!(cpu >= 0 && is_idle) || !gdata)
		return cpu;

	max_cap     = gdata->max_capacity ?: CAPACITY_SCALE;
	want_p      = (tctx && tctx->last_stop_ns) ? tctx->on_p_type : true;
	desired_dsq = want_p ? AUCTION_DSQ_P : AUCTION_DSQ_E;
	cpu_dsq     = dsq_for_cpu((u32)cpu, max_cap);

	/*
	 * Soft cluster preference.  dfl returned an idle CPU; if the cluster
	 * matches the task's auction-preferred DSQ, use it as-is.  If it's
	 * the wrong cluster (e.g. bursty P-class task landed on idle E),
	 * probe once for an idle CPU in the desired cluster.  If found, swap.
	 * If not, keep dfl's idle hit — work conservation beats spinning on
	 * a busy same-cluster CPU.
	 *
	 * Differs from the pre-fix policy: that one fell through to a
	 * non-idle return when the second probe missed, leaving the idle
	 * CPU unkicked.  We always dispatch to LOCAL on an idle CPU.
	 */
	if (desired_dsq != cpu_dsq) {
		s32 alt = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (alt >= 0 && dsq_for_cpu((u32)alt, max_cap) == desired_dsq)
			cpu = alt;
		/* else: second pick consumed an idle bit in a cluster we
		 * don't want (or nothing), and that CPU will get stolen on
		 * its next dispatch() — acceptable cost. */
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	return cpu;
}

void
BPF_STRUCT_OPS(auction_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx = get_task_ctx(p, true);
	u32 max_cap, weight;
	u64 v_now, ve, q_max, min_ve, vd;
	u64 dsq_id;

	if (!gdata || !tctx)
		return;

	max_cap = gdata->max_capacity ?: CAPACITY_SCALE;
	weight  = p->scx.weight       ?: 1;

	/*
	 * Replenish budget from idle time — only meaningful when the task is
	 * waking from sleep.  Preempted/migrated tasks haven't been idle, so
	 * skip the ktime_get_ns() call entirely.
	 */
	if (enq_flags & SCX_ENQ_WAKEUP)
		budget_replenish(tctx, bpf_ktime_get_ns());

	/*
	 * Virtual-time eligibility and deadline (EEVDF kernel, same as s3+).
	 * q_max = max_cap * slice / CAPACITY_SCALE  (capacity-normalised quantum)
	 */
	v_now  = gdata->vtime_now;
	ve     = p->scx.dsq_vtime;
	q_max  = (u64)max_cap * SCX_SLICE_DFL / CAPACITY_SCALE;
	min_ve = (v_now > q_max) ? (v_now - q_max) : 0;

	if (time_before(ve, min_ve))
		ve = min_ve;

	refresh_inv_weight(tctx, weight);

	/*
	 * Wake-latency boost (links VCG budget-ratio to EEVDF deadline).
	 * A task waking from sleep with budget ≥ BURST_HIGH_PCT has not
	 * consumed recent resources — in auction terms, its virtual
	 * valuation is high relative to its recent payments.  Give it a
	 * half-gap vd so it preempts long-queued CPU-bound tasks.
	 *   - Only on SCX_ENQ_WAKEUP (not preempt re-enqueue — that would
	 *     let running tasks monopolise).
	 *   - Gated on high budget ratio — CPU-bound tasks (low budget)
	 *     get normal gap and fall in line behind bursty tasks.
	 * This is how §4.2 fairness penalty Ψ(π) = Var(u_i/v_i) gets
	 * mechanised: tasks whose u_i is "behind" their v_i (high ρ, low
	 * recent consumption) get boosted, shrinking the variance.
	 */
	/*
	 * Wake-latency boost disabled: on moderate load it caused preempt
	 * storm.  Many sleep-heavy tasks stay above BURST_HIGH_PCT, so every
	 * wake halved the gap and preempted the running task, tanking rps.
	 */
	u64 gap_num = q_max * SCALE;

	vd             = ve + div_by_weight(gap_num, weight, tctx);
	p->scx.dsq_vtime = ve;

	/*
	 * φ_P / φ_E once — used for (a) proportional starvation ordering,
	 * and (b) VCG-pivot estimator update (see §I4).  Hoisted above the
	 * starved/normal branch so both code paths reuse it.
	 */
	u32 en_min_cap = gdata->min_capacity ?: CAPACITY_SCALE;
	u32 en_cost_p  = gdata->cost_p       ?: C_P_DEF;
	u32 en_cost_e  = gdata->cost_e       ?: C_E_DEF;
	u64 en_len_est = tctx->len_est_ns ?: (u64)(SCX_SLICE_DFL ?: 5000000);
	s64 phi_p, phi_e;

	compute_phi(weight, en_len_est, max_cap, en_min_cap,
		    en_cost_p, en_cost_e, &phi_p, &phi_e);

	/*
	 * Budget check: exhausted tasks → AUCTION_DSQ_STARVED.
	 * budget_max may be 0 if enable() hasn't run yet; treat as not starved.
	 *
	 * Proportional starvation ordering: tasks with φ < 0 (cost > value)
	 * get an extra vd penalty proportional to their deficit so that heavier
	 * CPU offenders wait longer within STARVED before being dispatched.
	 * (Static 1<<32 bump was a uniform shift — no differentiation.)
	 */
	if (tctx->budget_max &&
	    tctx->budget * STARVE_FRAC < tctx->budget_max) {
		s64 phi = (phi_p < phi_e) ? phi_p : phi_e; /* worst-case φ */
		if (phi < 0)
			vd += (u64)(-phi) / STARVE_PHI_DIV;
		dsq_id = AUCTION_DSQ_STARVED;
		tctx->on_p_type = 0;
		goto insert;
	}

	/*
	 * Routing with hysteresis + stickiness:
	 *   - On preempt re-enqueue (no WAKEUP), keep previous cluster — avoids
	 *     migrations while a task is simply time-slicing.
	 *   - On wake-up, re-route only if budget has crossed HIGH or LOW band;
	 *     inside the 30–70% deadband, keep previous cluster.
	 *   - First enqueue (last_stop_ns==0): treat as wake-up; default P.
	 */
	bool is_wakeup  = (enq_flags & SCX_ENQ_WAKEUP) || !tctx->last_stop_ns;
	bool want_p_enq = tctx->on_p_type; /* sticky default */

	if (is_wakeup && tctx->budget_max) {
		u64 num = tctx->budget * 100;
		u64 hi  = (u64)tctx->budget_max * BURST_HIGH_PCT;
		u64 lo  = (u64)tctx->budget_max * BURST_LOW_PCT;

		if (num >= hi)
			want_p_enq = true;
		else if (num < lo)
			want_p_enq = false;
		/* else keep sticky on_p_type */
	} else if (is_wakeup) {
		/* No budget info yet (new task) — prefer P. */
		want_p_enq = true;
	}

	if (want_p_enq) {
		/*
		 * Saturation spill: if DSQ_P already has ≥ #P-cores queued,
		 * routing one more there just deepens the P backlog while
		 * E-cores sit idle.  Flip to DSQ_E so an E-core dispatch()
		 * picks it up directly (its local DSQ is E).  Only applies
		 * when userspace has populated p_core_count.
		 */
		u32 p_cc = gdata->p_core_count;
		if (p_cc && scx_bpf_dsq_nr_queued(AUCTION_DSQ_P) >= p_cc) {
			dsq_id          = AUCTION_DSQ_E;
			tctx->on_p_type = 0;
		} else {
			dsq_id          = AUCTION_DSQ_P;
			tctx->on_p_type = 1;
		}
	} else {
		dsq_id          = AUCTION_DSQ_E;
		tctx->on_p_type = 0;
	}

	/*
	 * VCG-pivot estimator update (§I4).  Feed the chosen cluster's φ_hi
	 * with this task's φ_κ.  Climb instantly on a new maximum, decay by
	 * EWMA (α = 1/16) otherwise — absent reinforcement, the estimator
	 * relaxes toward zero so a stale burst doesn't overcharge later tasks.
	 * Only the normal (non-starved) path feeds the estimator: starved
	 * tasks don't compete for the pivot slot.
	 */
	{
		s64 phi_k   = (dsq_id == AUCTION_DSQ_P) ? phi_p : phi_e;
		u64 phi_new = (phi_k > 0) ? (u64)phi_k : 0;
		u64 *phi_hi = (dsq_id == AUCTION_DSQ_P)
			      ? &gdata->dsq_phi_hi_p
			      : &gdata->dsq_phi_hi_e;

		if (phi_new > *phi_hi)
			*phi_hi = phi_new;
		else
			*phi_hi = (*phi_hi * 15 + phi_new) >> 4;
	}

insert:
	scx_bpf_dsq_insert_vtime(p, dsq_id, SCX_SLICE_DFL, vd, enq_flags);

	/*
	 * Kick idle CPU only on WAKEUP enqueue.  Probing pick_idle_cpu on
	 * every preempt re-enqueue was a per-CPU scan storm under moderate
	 * load (250k ctx/s × 20-CPU scan).  Preempt-path rarely finds idle
	 * anyway since the system is under pressure.
	 */
	if (enq_flags & SCX_ENQ_WAKEUP) {
		s32 idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (idle_cpu >= 0)
			scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
	}
}

void
BPF_STRUCT_OPS(auction_dispatch, s32 cpu, struct task_struct *prev)
{
	struct auction_ctx *gdata = get_ctx();
	u32 max_cap = gdata && gdata->max_capacity ? gdata->max_capacity
						   : CAPACITY_SCALE;
	u64 local_dsq = dsq_for_cpu((u32)cpu, max_cap);
	u64 other_dsq = (local_dsq == AUCTION_DSQ_P) ? AUCTION_DSQ_E
						      : AUCTION_DSQ_P;
	u32 slots = scx_bpf_dispatch_nr_slots();

	if (!slots)
		slots = 1;
	if (slots > DISPATCH_BATCH_MAX)
		slots = DISPATCH_BATCH_MAX;

	/*
	 * Dispatch order (unconditional work conservation):
	 *   1. local cluster DSQ (tasks assigned to this core type).
	 *   2. cross-cluster work-steal (either direction).  Any queued
	 *      task beats an idle slot — model §1.1 "unused quanta are
	 *      lost" directly motivates aggressive stealing.  Cluster
	 *      preference is enforced upstream at enqueue-time routing;
	 *      the dispatch path must never leave work stranded.
	 *   3. starved tasks (budget exhausted).
	 */
#pragma unroll
	for (u32 i = 0; i < DISPATCH_BATCH_MAX; i++) {
		if (i >= slots)
			break;
		if (scx_bpf_dsq_move_to_local(local_dsq))
			continue;
		if (scx_bpf_dsq_move_to_local(other_dsq))
			continue;
		if (scx_bpf_dsq_move_to_local(AUCTION_DSQ_STARVED))
			continue;
		break;
	}
}

void
BPF_STRUCT_OPS(auction_running, struct task_struct *p)
{
	struct auction_ctx *gdata = get_ctx();

	if (!gdata)
		return;

	/* Advance global vtime floor (same as s3+). */
	if (time_before(gdata->vtime_now, p->scx.dsq_vtime))
		gdata->vtime_now = p->scx.dsq_vtime;
}

void
BPF_STRUCT_OPS(auction_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu    = bpf_get_smp_processor_id();
	u32 cap    = get_cpu_cap(cpu);
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx = get_task_ctx(p, false);
	u64 consumed, svc_vtime;
	u32 weight;
	u32 cost_p, cost_e;

	consumed = SCX_SLICE_DFL - p->scx.slice;
	weight   = p->scx.weight ?: 1;

	if (!gdata)
		goto update_len;

	cost_p = gdata->cost_p ?: C_P_DEF;
	cost_e = gdata->cost_e ?: C_E_DEF;

	/*
	 * Virtual-time advance (s3+ formula, capacity-weighted):
	 *   svc = consumed * cap / CAPACITY_SCALE
	 * Faster cores advance task vtime more, keeping virtual-time fair.
	 */
	svc_vtime = consumed * cap * SCALE / CAPACITY_SCALE;
	p->scx.dsq_vtime += div_by_weight(svc_vtime, weight, tctx);

	if (gdata->total_weight)
		gdata->vtime_now += svc_vtime / gdata->total_weight;

	/*
	 * Budget payment — VCG-pivot approximation (§6.2 / §I4).
	 *
	 *   pay = max(cost_based, pivot_based)
	 *   cost_based  = c_κ * consumed / slice          — Myerson-reserve floor
	 *   pivot_based = φ_hi_κ * consumed / slice / slice
	 *                 — externality imposed on the best alternative task
	 *                 still queued in cluster κ, normalised to budget units
	 *
	 * φ_hi_κ is maintained at enqueue (EWMA of positive φ observed on
	 * cluster κ).  In a single-free-core slot it approximates φ_{second}
	 * from model §9; in heavier loads it tracks the running distribution
	 * of competing types, which is the local statistic W_{-i} reduces to
	 * under Myerson's regular-distribution single-item equivalence.
	 *
	 * The max(·,·) realises the Vickrey reserve-price form:
	 *   - empty/cold queue → φ_hi ≈ 0 → pay = cost_based (posted-price
	 *     degenerates to the Myerson reserve, preserving IR);
	 *   - hot queue with high-φ alternatives → pay climbs toward second-
	 *     best φ, pulling the mechanism into the VCG-pivot regime (IC
	 *     recovered in the limit of stationary workloads).
	 *
	 * Minimum of 1 prevents free rides for sub-µs slices.
	 */
	if (tctx) {
		u64 slice = SCX_SLICE_DFL ?: 5000000;
		u32 cost_kappa;
		u32 max_cap = gdata->max_capacity ?: CAPACITY_SCALE;
		bool is_p   = (u64)cap * 100 >= (u64)max_cap * P_CAP_PCT;

		cost_kappa = is_p ? cost_p : cost_e;

		u64 cost_based = (u64)cost_kappa * consumed / slice;

		u64 phi_hi     = is_p ? gdata->dsq_phi_hi_p : gdata->dsq_phi_hi_e;
		/*
		 * φ_hi has units of weight·slice (ns weighted).  Normalise to
		 * per-quantum budget units:
		 *   pivot_based = (φ_hi / slice) * (consumed / slice)
		 * Rearranged to preserve precision with integer arithmetic:
		 *   pivot_based = φ_hi * consumed / (slice * slice)
		 * Typical magnitudes (weight=100, slice=5e6): φ_hi ≤ 5e8 →
		 * pivot_based ≤ weight * consumed/slice, the same order as
		 * cost_based; safe against u64 overflow (5e8 * 5e6 = 2.5e15).
		 */
		u64 pivot_based = phi_hi * consumed / slice / slice;

		u64 payment = cost_based > pivot_based ? cost_based : pivot_based;
		if (!payment && consumed)
			payment = 1;

		if (tctx->budget >= payment)
			tctx->budget -= payment;
		else
			tctx->budget = 0;

		/*
		 * Only stamp when the task is actually going to sleep
		 * (runnable=false).  Preempts keep the prior sleep timestamp so
		 * the next wake-up measures the real idle interval, not the
		 * tiny preempt-gap.  This was the source of premature starvation
		 * for CPU-bound tasks: replenish saw idle≈0 on every wake-up
		 * because last_stop_ns was reset on every slice.
		 */
		if (!runnable)
			tctx->last_stop_ns = bpf_ktime_get_ns();
	}

update_len:
	if (!tctx)
		return;

	/*
	 * EWMA length update: l̂ = (3*l̂ + consumed_ns) / 4
	 * This gives α = 0.25 (responds within ~4 activations to changes).
	 * len_est_ns is the model's l_i in nanoseconds.
	 */
	u64 old_len = tctx->len_est_ns ?: consumed;
	tctx->len_est_ns = (old_len * 3 + consumed) >> 2;
	if (!tctx->len_est_ns)
		tctx->len_est_ns = consumed ?: 1;
}

s32
BPF_STRUCT_OPS(auction_set_weight, struct task_struct *p, u32 new_weight)
{
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx;
	u32 old_weight;
	u64 old_sum;
	s64 lag, diff;

	if (!gdata)
		return 0;

	old_weight = p->scx.weight ?: 1;
	if (!new_weight)
		new_weight = 1;

	old_sum = gdata->total_weight;

	if (gdata->total_weight >= old_weight)
		gdata->total_weight -= old_weight;
	gdata->total_weight += new_weight;

	tctx = get_task_ctx(p, true);
	if (tctx) {
		/* Scale budget_max with new weight. */
		tctx->budget_max = (u64)new_weight * BUDGET_MUL;
		if (tctx->budget > tctx->budget_max)
			tctx->budget = tctx->budget_max;
		refresh_inv_weight(tctx, new_weight);
	}

	u64 new_sum = gdata->total_weight;
	if (!old_sum || !new_sum)
		return 0;

	lag  = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	diff = signed_div(lag, old_sum) - signed_div(lag, new_sum);
	add_vtime(gdata, diff);

	return 0;
}

void
BPF_STRUCT_OPS(auction_enable, struct task_struct *p)
{
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx;
	u32 weight;
	u64 new_sum;
	s64 lag;

	if (!gdata)
		return;

	weight = p->scx.weight ?: 1;

	if (!p->scx.dsq_vtime)
		p->scx.dsq_vtime = gdata->vtime_now;

	lag     = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	new_sum = gdata->total_weight + weight;
	if (new_sum)
		add_vtime(gdata, -signed_div(lag, new_sum));
	gdata->total_weight = new_sum;

	/* Initialise task auction state. */
	tctx = get_task_ctx(p, true);
	if (tctx) {
		u64 bmax    = (u64)weight * BUDGET_MUL;
		tctx->budget_max  = bmax;
		tctx->budget      = bmax; /* start with full budget */
		tctx->len_est_ns  = (u64)(SCX_SLICE_DFL ?: 5000000); /* 1 quantum */
		tctx->last_stop_ns = 0;
		refresh_inv_weight(tctx, weight);
	}
}

void
BPF_STRUCT_OPS(auction_disable, struct task_struct *p)
{
	struct auction_ctx *gdata = get_ctx();
	u32 weight;
	u64 new_sum;
	s64 lag;

	if (!gdata)
		return;

	weight  = p->scx.weight ?: 1;
	lag     = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	new_sum = (gdata->total_weight >= weight)
		  ? gdata->total_weight - weight : 0;
	gdata->total_weight = new_sum;

	if (new_sum)
		add_vtime(gdata, signed_div(lag, new_sum));

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
	return scx_bpf_create_dsq(AUCTION_DSQ_STARVED, -1);
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
	       .name       = "auction");
