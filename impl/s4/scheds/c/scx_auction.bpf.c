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
 *   effective value φ_P     v - C_P * l/slice   (P-core, l quanta at full speed)
 *   effective value φ_E     v - C_E * l*σ/slice (E-core, σ = max_cap/min_cap)
 *   allocation κ ∈ {P,E}    DSQ chosen by argmax φ_κ
 *   VCG payment p_i         posted price: C_κ * consumed_quanta  (§6.3 approx.)
 *   budget B_i              token bucket; time-based replenishment ∝ weight
 *   budget-depleted task    → AUCTION_DSQ_STARVED (lowest priority)
 *
 * Core DSQ structure:
 *   AUCTION_DSQ_P      — high-capacity (P-core) run queue
 *   AUCTION_DSQ_E      — low-capacity  (E-core) run queue
 *   AUCTION_DSQ_STARVED— budget-exhausted fallback (runs last)
 *
 * On homogeneous CPUs (all capacities = 1024): σ = 1, C_E ≥ C_P/2 ⇒ φ_P ≥ φ_E
 * for all tasks, so all tasks queue to AUCTION_DSQ_P.  Both DSQs are served by
 * all CPUs (work-stealing), so behaviour degenerates to EEVDF-equivalent.
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
 * Per-quantum costs (§3.2 of model).  In "phi units" = weight units.
 * C_P > C_E: P-core is faster but more expensive per quantum.
 * At default nice=0 weight=1024, a task is net-positive on P-core only if
 * its estimated length < weight / C_P = 1 quantum (very short burst).
 * Adjust C_P / C_E to tune the crossover point.
 */
#define C_P_DEF             512    /* default cost/quantum on P-core          */
#define C_E_DEF             256    /* default cost/quantum on E-core          */

/*
 * Budget (§1.3 / §3.3): token-bucket mechanism.
 *   budget_max  = weight * BUDGET_MUL
 *   payment     = C_κ per quantum consumed
 *   replenish   = idle_ns * weight / REPLENISH_DIV  (per enqueue, on wake-up)
 *   starved     = budget < budget_max / STARVE_FRAC
 */
#define BUDGET_MUL          2000ULL    /* budget_max = weight * BUDGET_MUL   */
#define REPLENISH_DIV       5000000ULL /* replenish rate divisor (ns/unit)   */
#define REPLENISH_IDLE_CAP  1000000000ULL /* cap idle_ns at 1 s to prevent overflow */
#define STARVE_FRAC         10     /* starved if budget < budget_max/10       */

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
	u32 _pad;
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
 *   φ_P = weight - C_P * len_quanta
 *   φ_E = weight - C_E * ceil(len_quanta * σ)   σ = max_cap / min_cap
 *
 * We work in "weight units"; len_quanta = len_est_ns / SCX_SLICE_DFL.
 * Returned as signed 64-bit integers; negative means "net cost > net value".
 */
static __always_inline void
compute_phi(u32 weight, u64 len_est_ns,
	    u32 max_cap, u32 min_cap,
	    u32 cost_p, u32 cost_e,
	    s64 *phi_p_out, s64 *phi_e_out)
{
	u64 slice = SCX_SLICE_DFL;

	if (!slice)
		slice = 5000000; /* 5 ms fallback */

	/* l_P = ceil(len_est_ns / slice) */
	u64 len_p = (len_est_ns + slice - 1) / slice;
	if (!len_p)
		len_p = 1;

	/*
	 * l_E = ceil(l_P * σ) = ceil(len_est_ns * max_cap / (min_cap * slice))
	 * Use ceiling division to be conservative (E-core might be slower).
	 */
	u32 mc = min_cap ? min_cap : CAPACITY_SCALE;
	u64 len_e_num = len_est_ns * (u64)max_cap;
	u64 len_e_den = (u64)mc * slice;
	u64 len_e     = (len_e_num + len_e_den - 1) / len_e_den;
	if (!len_e)
		len_e = 1;

	*phi_p_out = (s64)(u64)weight - (s64)((u64)cost_p * len_p);
	*phi_e_out = (s64)(u64)weight - (s64)((u64)cost_e * len_e);
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
	struct auction_ctx *gdata = get_ctx();
	struct auction_task_ctx *tctx;
	u32 max_cap, min_cap, weight;
	u32 cost_p, cost_e;
	bool is_idle = false;
	s32 cpu;
	s64 phi_p, phi_e;
	bool want_p;
	u64 desired_dsq, cpu_dsq;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (!is_idle)
		return cpu;

	if (!gdata)
		return cpu;

	max_cap  = gdata->max_capacity  ?: CAPACITY_SCALE;
	min_cap  = gdata->min_capacity  ?: CAPACITY_SCALE;
	cost_p   = gdata->cost_p        ?: C_P_DEF;
	cost_e   = gdata->cost_e        ?: C_E_DEF;
	weight   = p->scx.weight        ?: 1;

	tctx = get_task_ctx(p, false);
	u64 len_est = tctx ? tctx->len_est_ns : (u64)SCX_SLICE_DFL;

	compute_phi(weight, len_est, max_cap, min_cap, cost_p, cost_e,
		    &phi_p, &phi_e);
	want_p      = (phi_p >= phi_e);
	desired_dsq = want_p ? AUCTION_DSQ_P : AUCTION_DSQ_E;
	cpu_dsq     = dsq_for_cpu((u32)cpu, max_cap);

	if (cpu >= 0 && desired_dsq == cpu_dsq) {
		/* Idle CPU matches the desired cluster — dispatch locally. */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return cpu;
	}

	/*
	 * Preferred cluster CPU isn't idle (or wrong cluster).
	 * Try to find an idle CPU in the desired cluster.
	 */
	s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0 && dsq_for_cpu((u32)idle, max_cap) == desired_dsq) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return idle;
	}

	return cpu;
}

void
BPF_STRUCT_OPS(auction_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct auction_ctx     *gdata = get_ctx();
	struct auction_task_ctx *tctx = get_task_ctx(p, true);
	u32 max_cap, min_cap, weight;
	u32 cost_p, cost_e;
	u64 v_now, ve, q_max, min_ve, vd;
	s64 phi_p, phi_e;
	u64 dsq_id;

	if (!gdata || !tctx)
		return;

	max_cap = gdata->max_capacity ?: CAPACITY_SCALE;
	min_cap = gdata->min_capacity ?: CAPACITY_SCALE;
	cost_p  = gdata->cost_p       ?: C_P_DEF;
	cost_e  = gdata->cost_e       ?: C_E_DEF;
	weight  = p->scx.weight       ?: 1;

	/* Replenish budget from idle time (model §6.1 step 5 analogue). */
	budget_replenish(tctx, bpf_ktime_get_ns());

	/*
	 * Compute effective values φ_P and φ_E.
	 * Use EWMA length estimate; fall back to one quantum if uninitialized.
	 */
	u64 len_est = tctx->len_est_ns ?: (u64)(SCX_SLICE_DFL ?: 5000000);
	compute_phi(weight, len_est, max_cap, min_cap, cost_p, cost_e,
		    &phi_p, &phi_e);

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
	vd             = ve + div_by_weight(q_max * SCALE, weight, tctx);
	p->scx.dsq_vtime = ve;

	/*
	 * Budget check: exhausted tasks → AUCTION_DSQ_STARVED.
	 * budget_max may be 0 if enable() hasn't run yet; treat as not starved.
	 */
	if (tctx->budget_max &&
	    tctx->budget < tctx->budget_max / STARVE_FRAC) {
		/*
		 * Push vd far into the future so starved tasks run last.
		 * We still preserve relative ordering among starved tasks.
		 */
		vd += (u64)1 << 32;
		dsq_id = AUCTION_DSQ_STARVED;
		tctx->on_p_type = 0;
		goto insert;
	}

	/*
	 * Auction decision (model §6.1 step 3 / §5.2):
	 * Assign to whichever cluster type maximises φ_κ.
	 *
	 * If φ_P = φ_E (homogeneous or identical costs for this task), prefer
	 * AUCTION_DSQ_P as the convention.
	 */
	if (phi_p >= phi_e) {
		dsq_id          = AUCTION_DSQ_P;
		tctx->on_p_type = 1;
	} else {
		dsq_id          = AUCTION_DSQ_E;
		tctx->on_p_type = 0;
	}

insert:
	scx_bpf_dsq_insert_vtime(p, dsq_id, SCX_SLICE_DFL, vd, enq_flags);
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
	 * Dispatch order:
	 *   1. local cluster DSQ (tasks assigned to this core type)
	 *   2. cross-cluster work-steal
	 *   3. starved tasks (last resort — budget exhausted)
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
	 * Budget payment (model §6.1 step 5 / §6.2 posted-price approximation):
	 *   payment = C_κ * consumed_quanta
	 * P-core payment is larger than E-core (c_P > c_E), reflecting higher
	 * opportunity cost of occupying a fast core.
	 */
	if (tctx) {
		u64 slice = SCX_SLICE_DFL ?: 5000000;
		u32 cost_kappa;
		u64 max_cap = gdata->max_capacity ?: CAPACITY_SCALE;

		/* Determine whether this CPU is P-type or E-type. */
		cost_kappa = cpu_is_p_type(cpu, (u32)max_cap) ? cost_p : cost_e;

		u64 quanta = (consumed + slice - 1) / slice; /* ceiling */
		if (!quanta)
			quanta = 1;
		u64 payment = (u64)cost_kappa * quanta;

		if (tctx->budget >= payment)
			tctx->budget -= payment;
		else
			tctx->budget = 0;

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
