#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#ifndef EEVDF_TELEMETRY
#define EEVDF_TELEMETRY 0
#endif

#define CAPACITY_SCALE   1024   /* Linux SCHED_CAPACITY_SCALE */
#define EEVDF_DSQ_BIG    1      /* high-capacity cluster queue */
#define EEVDF_DSQ_LITTLE 2      /* low-capacity cluster queue */
#define BIG_CAP_PCT      90     /* cap >= 90% of max is treated as high-capacity */
#define LAG_BOOST_DIV    4      /* boost if lag exceeds Qmax/LAG_BOOST_DIV */
#define DISPATCH_BATCH_MAX 8
#define INV_SHIFT        20

struct eevdf_ctx {
	u64 vtime_now;
	u64 total_weight;
	u32 max_capacity;   /* max ρ_c across online CPUs, set by userspace */
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct eevdf_ctx));
} global_data SEC(".maps");

/* Populated by userspace from /sys/devices/system/cpu/cpuN/cpu_capacity */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} cpu_capacity SEC(".maps");

#define SCALE      100

#if EEVDF_TELEMETRY
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 4);
} stats SEC(".maps");

static void
stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}
#else
static __always_inline void
stat_inc(u32 idx)
{
	(void)idx;
}
#endif

static struct eevdf_ctx *
get_ctx()
{
	u32 key = 0;
	return bpf_map_lookup_elem(&global_data, &key);
}

static u32
get_cpu_cap(u32 cpu)
{
	u32 *cap = bpf_map_lookup_elem(&cpu_capacity, &cpu);
	if (cap && *cap)
		return *cap;
	return CAPACITY_SCALE;   /* default: homogeneous */
}

struct eevdf_task_ctx {
	u32 weight_cached;
	u32 inv_weight;
#if EEVDF_TELEMETRY
	u64 enq_ns;
#endif
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct eevdf_task_ctx);
} task_ctx_map SEC(".maps");

static struct eevdf_task_ctx *
get_task_ctx(struct task_struct *p, bool create)
{
	return bpf_task_storage_get(&task_ctx_map, p, 0,
				    create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}

static u64
class_dsq_id(u32 cap, u32 max_cap)
{
	if (!max_cap)
		max_cap = CAPACITY_SCALE;
	if ((u64)cap * 100 >= (u64)max_cap * BIG_CAP_PCT)
		return EEVDF_DSQ_BIG;
	return EEVDF_DSQ_LITTLE;
}

static u64
desired_dsq_for_task(struct task_struct *p, struct eevdf_ctx *gdata, u32 max_cap)
{
	u64 q_max = (u64)max_cap * SCX_SLICE_DFL / CAPACITY_SCALE;
	u64 lag_boost = (q_max / LAG_BOOST_DIV) + 1;
	s64 lag = 0;

	if (!gdata)
		return EEVDF_DSQ_BIG;

	lag = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	if (lag > (s64)lag_boost)
		return EEVDF_DSQ_BIG;
	if (lag < -(s64)lag_boost)
		return EEVDF_DSQ_LITTLE;

	/* Near-neutral lag follows CPU class chosen by default picker. */
	return class_dsq_id(get_cpu_cap((u32)scx_bpf_task_cpu(p)), max_cap);
}

static void
refresh_weight_cache(struct eevdf_task_ctx *tctx, u32 weight)
{
	u64 inv;

	if (!tctx)
		return;
	if (!weight)
		weight = 1;
	if (tctx->weight_cached == weight && tctx->inv_weight)
		return;

	inv = ((1ULL << INV_SHIFT) + (weight / 2)) / weight;
	if (!inv)
		inv = 1;
	tctx->weight_cached = weight;
	tctx->inv_weight    = (u32)inv;
}

static u64
div_by_weight_cached(u64 val, u32 weight, struct eevdf_task_ctx *tctx)
{
	if (!weight)
		weight = 1;
	refresh_weight_cache(tctx, weight);

	if (tctx && tctx->inv_weight && val <= 0xffffffffULL)
		return ((u64)(u32)val * tctx->inv_weight) >> INV_SHIFT;
	return val / weight;
}

static u64
abs_s64_to_u64(s64 v)
{
	if (v >= 0)
		return (u64)v;
	/* Avoid signed overflow when v == S64_MIN. */
	return (u64)(-(v + 1)) + 1;
}

static s64
div_signed_u64(s64 num, u64 den)
{
	u64 abs_q;

	if (!den)
		return 0;
	abs_q = abs_s64_to_u64(num) / den;
	if (num < 0)
		return -(s64)abs_q;
	return (s64)abs_q;
}

static void
add_signed_vtime(struct eevdf_ctx *gdata, s64 delta)
{
	if (delta >= 0) {
		u64 add = (u64)delta;
		if (gdata->vtime_now > (~0ULL - add))
			gdata->vtime_now = ~0ULL;
		else
			gdata->vtime_now += add;
		return;
	}

	u64 sub = abs_s64_to_u64(delta);
	if (gdata->vtime_now > sub)
		gdata->vtime_now -= sub;
	else
		gdata->vtime_now = 0;
}

#if EEVDF_TELEMETRY
#define LAT_BUCKETS 64
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, LAT_BUCKETS);
} latency_hist SEC(".maps");
#endif

s32
BPF_STRUCT_OPS(eevdf_select_cpu,
               struct task_struct *p,
               s32                 prev_cpu,
               u64                 wake_flags)
{
	bool is_idle = false;
	s32  cpu     = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	struct eevdf_ctx *gdata = get_ctx();
	u32 max_cap = gdata && gdata->max_capacity ? gdata->max_capacity : CAPACITY_SCALE;
	u32 cpu_cap = CAPACITY_SCALE;
	u64 selected_dsq;
	u64 desired_dsq;

	if (cpu >= 0)
		cpu_cap = get_cpu_cap((u32)cpu);
	selected_dsq = class_dsq_id(cpu_cap, max_cap);
	desired_dsq = desired_dsq_for_task(p, gdata, max_cap);

	if (!is_idle && desired_dsq != selected_dsq) {
		s32 idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

		if (idle_cpu >= 0) {
			u64 idle_dsq = class_dsq_id(get_cpu_cap((u32)idle_cpu), max_cap);

			if (idle_dsq == desired_dsq) {
				cpu = idle_cpu;
				is_idle = true;
				selected_dsq = idle_dsq;
			}
		}
	}

	if (is_idle) {
		/* Keep locality fast-path only when CPU class matches desired class. */
		if (desired_dsq == selected_dsq) {
			stat_inc(0);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		}
	}
	return cpu;
}

void
BPF_STRUCT_OPS(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);

	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	u64 v_now = gdata->vtime_now;
	u64 ve    = p->scx.dsq_vtime;
	struct eevdf_task_ctx *tctx = get_task_ctx(p, true);
	u64 dsq_id;

	/* Work quantum in virtual-time units: Q_max = ρ_max * slice / CAPACITY_SCALE */
	u32 max_cap = gdata->max_capacity ? gdata->max_capacity : CAPACITY_SCALE;
	u64 q_max   = (u64)max_cap * SCX_SLICE_DFL / CAPACITY_SCALE;
	u64 min_ve  = (v_now > q_max) ? (v_now - q_max) : 0;

	/* Clamp: prevent more than one max-quantum of lag */
	if (time_before(ve, min_ve))
		ve = min_ve;

	u32 weight = p->scx.weight;
	if (!weight)
		weight = 1;
	refresh_weight_cache(tctx, weight);

	/* Virtual deadline: vd = ve + Q_max/w_i */
	u64 vd           = ve + div_by_weight_cached(q_max * SCALE, weight, tctx);
	p->scx.dsq_vtime = ve;

	dsq_id = desired_dsq_for_task(p, gdata, max_cap);

	scx_bpf_dsq_insert_vtime(p, dsq_id, SCX_SLICE_DFL, vd, enq_flags);

#if EEVDF_TELEMETRY
	if (tctx)
		tctx->enq_ns = bpf_ktime_get_ns();
#endif
}

void
BPF_STRUCT_OPS(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
	struct eevdf_ctx *gdata = get_ctx();
	u32 max_cap = gdata && gdata->max_capacity ? gdata->max_capacity : CAPACITY_SCALE;
	u32 cap = get_cpu_cap((u32)cpu);
	u64 local_dsq = class_dsq_id(cap, max_cap);
	u64 other_dsq = local_dsq == EEVDF_DSQ_BIG ? EEVDF_DSQ_LITTLE : EEVDF_DSQ_BIG;
	u32 slots = scx_bpf_dispatch_nr_slots();

	if (!slots)
		slots = 1;
	if (slots > DISPATCH_BATCH_MAX)
		slots = DISPATCH_BATCH_MAX;

#pragma unroll
	for (u32 i = 0; i < DISPATCH_BATCH_MAX; i++) {
		if (i >= slots)
			break;
		if (!scx_bpf_dsq_move_to_local(local_dsq) &&
		    !scx_bpf_dsq_move_to_local(other_dsq))
			break;
	}
}

void
BPF_STRUCT_OPS(eevdf_running, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	if (time_before(gdata->vtime_now, p->scx.dsq_vtime))
		gdata->vtime_now = p->scx.dsq_vtime;

#if EEVDF_TELEMETRY
	struct eevdf_task_ctx *tctx = get_task_ctx(p, false);
	if (!tctx || !tctx->enq_ns)
		return;
	u64 now = bpf_ktime_get_ns();
	if (now >= tctx->enq_ns) {
		u64 delta = now - tctx->enq_ns;
		u32 b = log2_u64(delta);
		if (b >= LAT_BUCKETS)
			b = LAT_BUCKETS - 1;
		u64 *cnt = bpf_map_lookup_elem(&latency_hist, &b);
		if (cnt)
			(*cnt)++;
		stat_inc(2);
	}
	tctx->enq_ns = 0;
#endif
}

void
BPF_STRUCT_OPS(eevdf_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 cap = get_cpu_cap(cpu);
	struct eevdf_ctx *gdata = get_ctx();
	struct eevdf_task_ctx *tctx = get_task_ctx(p, false);

	u64 consumed = SCX_SLICE_DFL - p->scx.slice;
	u32 weight   = p->scx.weight;
	u64 svc_vtime;
	if (!weight)
		weight = 1;

	/* Service measured in A1349 virtual-time units. */
	svc_vtime = consumed * cap * SCALE / CAPACITY_SCALE;
	p->scx.dsq_vtime += div_by_weight_cached(svc_vtime, weight, tctx);

	/* Approximate dV = C/W by adding delivered service over active weight. */
	if (gdata && gdata->total_weight)
		gdata->vtime_now += svc_vtime / gdata->total_weight;
}

s32
BPF_STRUCT_OPS(eevdf_set_weight, struct task_struct *p, u32 new_weight)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return 0;

	u32 old_weight = p->scx.weight;
	u64 old_sum    = gdata->total_weight;
	s64 lag, diff;

	if (!old_weight)
		old_weight = 1;
	if (!new_weight)
		new_weight = 1;
	refresh_weight_cache(get_task_ctx(p, true), new_weight);

	if (gdata->total_weight >= old_weight)
		gdata->total_weight -= old_weight;

	gdata->total_weight += new_weight;
	u64 new_sum          = gdata->total_weight;

	if (!old_sum || !new_sum)
		return 0;

	lag  = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	diff = div_signed_u64(lag, old_sum) - div_signed_u64(lag, new_sum);
	add_signed_vtime(gdata, diff);

	return 0;
}

void
BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	u32 weight;
	u64 new_sum;
	s64 lag;

	if (!gdata)
		return;

	weight = p->scx.weight;
	if (!weight)
		weight = 1;

	/* New tasks don't have a meaningful service history yet. */
	if (!p->scx.dsq_vtime)
		p->scx.dsq_vtime = gdata->vtime_now;

	lag = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	new_sum = gdata->total_weight + weight;
	if (new_sum)
		add_signed_vtime(gdata, -div_signed_u64(lag, new_sum));

	gdata->total_weight = new_sum;
}

void
BPF_STRUCT_OPS(eevdf_disable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	u32 weight;
	u64 new_sum;
	s64 lag;

	if (!gdata)
		return;

	weight = p->scx.weight;
	if (!weight)
		weight = 1;

	lag = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	new_sum = (gdata->total_weight >= weight) ? (gdata->total_weight - weight) : 0;
	gdata->total_weight = new_sum;

	if (new_sum)
		add_signed_vtime(gdata, div_signed_u64(lag, new_sum));

	bpf_task_storage_delete(&task_ctx_map, p);
}

s32
BPF_STRUCT_OPS_SLEEPABLE(eevdf_init)
{
	struct eevdf_ctx *gdata = get_ctx();
	s32 ret;

	if (gdata && !gdata->max_capacity)
		gdata->max_capacity = CAPACITY_SCALE;
	ret = scx_bpf_create_dsq(EEVDF_DSQ_BIG, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(EEVDF_DSQ_LITTLE, -1);
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
               .init       = (void *)eevdf_init,
               .name       = "eevdf");
