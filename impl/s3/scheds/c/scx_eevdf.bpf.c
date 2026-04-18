#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * EEVDF sched_ext scheduler.
 *
 * Maps models/eevdf.md onto sched_ext:
 *   - Per-task ve (eligible vtime), vd (deadline) in task storage.
 *   - SHARED_DSQ ordered by vd (insert vtime).
 *   - Dispatch iterates vd-ordered DSQ and picks earliest vd with ve <= V(now)
 *     — the two-stage EEVDF selection (eligibility filter + min vd).
 *   - V(t) advances at rate 1/Σw: on every stopping event, V += consumed/Σw.
 *   - Join/leave/reweight shift V per Eqs. 18–20.
 */

struct eevdf_ctx {
	u64 vtime_now;		/* system virtual time V(t), scaled by SCALE */
	u64 total_weight;	/* Σ w_i over active set */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct eevdf_ctx));
} global_data SEC(".maps");

struct task_ctx {
	u64 ve;		/* virtual eligible time, scaled by SCALE */
	u64 vd;		/* virtual deadline,     scaled by SCALE */
	bool on_rq;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_data SEC(".maps");

#define SHARED_DSQ 0
#define SCALE      1000ULL

/* Stat slots. */
enum {
	STAT_DIRECT_IDLE = 0,
	STAT_ENQUEUE     = 1,
	STAT_PICK_ELIG   = 2,
	STAT_PICK_FB     = 3,
	STAT_NR,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_NR);
} stats SEC(".maps");

static void
stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static struct eevdf_ctx *
get_ctx(void)
{
	u32 key = 0;
	return bpf_map_lookup_elem(&global_data, &key);
}

static struct task_ctx *
get_tctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_data, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * q_max_v: per-request virtual quantum contribution = slice/w (scaled).
 * In homogeneous EEVDF this is r/w (Eq. 8).
 */
static inline u64
q_max_v(u32 weight)
{
	if (!weight)
		weight = 1;
	return (u64)SCX_SLICE_DFL * SCALE / weight;
}

s32
BPF_STRUCT_OPS(eevdf_select_cpu,
               struct task_struct *p,
               s32                 prev_cpu,
               u64                 wake_flags)
{
	bool is_idle = false;
	s32  cpu     = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	/*
	 * Do NOT direct-dispatch to SCX_DSQ_LOCAL on idle — it would bypass the
	 * eligibility filter and vd ordering of SHARED_DSQ and violate EEVDF.
	 * Let eevdf_enqueue place the task on SHARED_DSQ; dispatch will pull it.
	 */
	(void)is_idle;
	return cpu;
}

void
BPF_STRUCT_OPS(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct eevdf_ctx *gdata = get_ctx();
	struct task_ctx  *tctx  = get_tctx(p);
	if (!gdata || !tctx)
		return;

	stat_inc(STAT_ENQUEUE);

	u32 weight = p->scx.weight;
	if (!weight)
		weight = 1;

	u64 v_now  = gdata->vtime_now;
	u64 qv     = q_max_v(weight);		/* virtual cost of one slice */
	u64 ve     = tctx->ve;

	/*
	 * Two-sided lag clamp (Thm. 1: |lag| bounded by r_max ↔ qv in vtime).
	 * Prevents long-sleeper monopoly (floor) and excessive hold-back (ceiling).
	 * Guarded against u64 underflow.
	 */
	if (v_now > qv && ve + qv < v_now)
		ve = v_now - qv;
	if (ve > v_now + qv)
		ve = v_now + qv;

	u64 vd = ve + qv;

	tctx->ve    = ve;
	tctx->vd    = vd;
	tctx->on_rq = true;

	/* DSQ ordered by vd; dispatch applies the ve <= V(now) filter. */
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vd, enq_flags);
}

void
BPF_STRUCT_OPS(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	u64 v_now = gdata->vtime_now;
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, SHARED_DSQ, 0) {
		struct task_ctx *tctx = bpf_task_storage_get(&task_data, p, 0, 0);
		if (!tctx)
			continue;
		if (tctx->ve <= v_now) {
			if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
			                     SCX_DSQ_LOCAL, 0)) {
				stat_inc(STAT_PICK_ELIG);
				return;
			}
		}
	}

	/*
	 * No eligible task (or iterator unavailable): fall back to earliest-vd.
	 * Work-conserving — corollary of Lemmas 1–2 says this path shouldn't
	 * normally trigger, but the iterator can miss in-flight races.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		stat_inc(STAT_PICK_FB);
}

void
BPF_STRUCT_OPS(eevdf_running, struct task_struct *p)
{
	/* V is advanced in stopping based on real service (Eq. 5 rate). */
}

void
BPF_STRUCT_OPS(eevdf_stopping, struct task_struct *p, bool runnable)
{
	struct eevdf_ctx *gdata = get_ctx();
	struct task_ctx  *tctx  = get_tctx(p);
	if (!gdata || !tctx)
		return;

	u64 consumed = SCX_SLICE_DFL - p->scx.slice;
	u32 weight   = p->scx.weight;
	if (!weight)
		weight = 1;

	/* Eq. 12: ve += u/w_i (partial-use recurrence). */
	u64 dve = consumed * SCALE / weight;
	tctx->ve += dve;
	tctx->vd  = tctx->ve + q_max_v(weight);

	/*
	 * Eq. 5: V advances at 1/Σw per unit of real service.
	 * Advance V by consumed/Σw. Read total_weight once (atomicity-lite).
	 */
	u64 tw = gdata->total_weight;
	if (tw) {
		u64 dv = consumed * SCALE / tw;
		if (dv)
			__sync_fetch_and_add(&gdata->vtime_now, dv);
	}

	tctx->on_rq = !!runnable;
}

static inline s64
s64_div_nz(s64 n, u64 d)
{
	if (!d)
		return 0;
	u64 abs_n = n < 0 ? (u64)(-n) : (u64)n;
	u64 q     = abs_n / d;
	return n < 0 ? -(s64)q : (s64)q;
}

static inline void
vtime_add_signed(struct eevdf_ctx *gdata, s64 delta)
{
	if (delta > 0)
		__sync_fetch_and_add(&gdata->vtime_now, (u64)delta);
	else if (delta < 0)
		__sync_fetch_and_sub(&gdata->vtime_now, (u64)(-delta));
}

s32
BPF_STRUCT_OPS(eevdf_set_weight, struct task_struct *p, u32 new_weight)
{
	struct eevdf_ctx *gdata = get_ctx();
	struct task_ctx  *tctx  = get_tctx(p);
	if (!gdata || !tctx)
		return 0;

	u32 old_weight = p->scx.weight;
	if (!old_weight)
		old_weight = 1;
	if (!new_weight)
		new_weight = 1;

	/*
	 * Eq. 20 (reweight ≡ leave + rejoin):
	 *   V(t+) = V(t) + lag/(Σw − w_old) − lag/(Σw − w_old + w_new)
	 * lag in this impl's convention = V − ve  (positive ⇒ under-served).
	 */
	u64 total  = gdata->total_weight;
	u64 denom1 = total > old_weight ? total - old_weight : 0;
	u64 denom2 = denom1 + new_weight;
	s64 lag    = (s64)gdata->vtime_now - (s64)tctx->ve;
	s64 delta  = s64_div_nz(lag, denom1) - s64_div_nz(lag, denom2);

	vtime_add_signed(gdata, delta);

	__sync_fetch_and_sub(&gdata->total_weight, old_weight);
	__sync_fetch_and_add(&gdata->total_weight, new_weight);
	return 0;
}

void
BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	struct task_ctx  *tctx  = get_tctx(p);
	if (!gdata || !tctx)
		return;

	u32 w = p->scx.weight ? p->scx.weight : 1;

	/*
	 * Joiner with lag = 0 ⇒ Eq. 19 leaves V unchanged. Set ve = V(t).
	 */
	tctx->ve    = gdata->vtime_now;
	tctx->vd    = tctx->ve + q_max_v(w);
	tctx->on_rq = false;

	__sync_fetch_and_add(&gdata->total_weight, w);
}

void
BPF_STRUCT_OPS(eevdf_disable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	struct task_ctx  *tctx  = get_tctx(p);
	if (!gdata || !tctx)
		return;

	u32 w = p->scx.weight ? p->scx.weight : 1;

	/*
	 * Eq. 18 (leave): V(t+) = V(t) + lag/Σw_after.
	 * Σw_after = total − w_leaver.
	 */
	u64 total = gdata->total_weight;
	u64 after = total > w ? total - w : 0;
	s64 lag   = (s64)gdata->vtime_now - (s64)tctx->ve;
	s64 delta = s64_div_nz(lag, after);

	vtime_add_signed(gdata, delta);

	__sync_fetch_and_sub(&gdata->total_weight, w);
}

s32
BPF_STRUCT_OPS_SLEEPABLE(eevdf_init_task, struct task_struct *p,
                         struct scx_init_task_args *args)
{
	struct task_ctx *tctx = bpf_task_storage_get(
		&task_data, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	return 0;
}

s32
BPF_STRUCT_OPS_SLEEPABLE(eevdf_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void
BPF_STRUCT_OPS(eevdf_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(eevdf_ops,
               .select_cpu = (void *)eevdf_select_cpu,
               .enqueue    = (void *)eevdf_enqueue,
               .dispatch   = (void *)eevdf_dispatch,
               .running    = (void *)eevdf_running,
               .stopping   = (void *)eevdf_stopping,
               .set_weight = (void *)eevdf_set_weight,
               .enable     = (void *)eevdf_enable,
               .disable    = (void *)eevdf_disable,
               .init_task  = (void *)eevdf_init_task,
               .init       = (void *)eevdf_init,
               .exit       = (void *)eevdf_exit,
               .name       = "eevdf");
