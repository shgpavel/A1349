#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct eevdf_ctx {
	u64 vtime_now;
	u64 total_weight;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct eevdf_ctx));
} global_data SEC(".maps");

#define SHARED_DSQ 0
#define SCALE      100

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

static void
stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static struct eevdf_ctx *
get_ctx()
{
	u32 key = 0;
	return bpf_map_lookup_elem(&global_data, &key);
}

s32
BPF_STRUCT_OPS(eevdf_select_cpu,
               struct task_struct *p,
               s32                 prev_cpu,
               u64                 wake_flags)
{
	bool is_idle = false;
	s32  cpu     = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
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

	u64 slice = SCX_SLICE_DFL;
	u64 v_now = gdata->vtime_now;
	u64 ve    = p->scx.dsq_vtime;

	if (ve < v_now - slice) {
		ve = v_now - slice;
	}

	u32 weight = p->scx.weight;
	if (!weight)
		weight = 1;

	u64 vd           = ve + (slice * SCALE / weight);
	p->scx.dsq_vtime = ve;

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vd, enq_flags);
}

void
BPF_STRUCT_OPS(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void
BPF_STRUCT_OPS(eevdf_running, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	if (p->scx.dsq_vtime > gdata->vtime_now) {
		if (p->scx.dsq_vtime > gdata->vtime_now)
			gdata->vtime_now = p->scx.dsq_vtime;
	}
}

void
BPF_STRUCT_OPS(eevdf_stopping, struct task_struct *p, bool runnable)
{
	u64 consumed = SCX_SLICE_DFL - p->scx.slice;

	u32 weight   = p->scx.weight;
	if (!weight)
		weight = 1;

	p->scx.dsq_vtime += consumed * SCALE / weight;
}

s32
BPF_STRUCT_OPS(eevdf_set_weight, struct task_struct *p, u32 new_weight)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return 0;

	u32 old_weight = p->scx.weight;
	u64 old_sum    = gdata->total_weight;

	if (gdata->total_weight >= old_weight)
		gdata->total_weight -= old_weight;

	gdata->total_weight += new_weight;
	u64 new_sum          = gdata->total_weight;

	if (!old_sum || !new_sum || !old_weight) {
		return 0;
	}

	s64 lag        = (s64)gdata->vtime_now - (s64)p->scx.dsq_vtime;
	u64 abs_lag    = (lag < 0) ? -lag : lag;
	s64 sign       = (lag < 0) ? -1 : 1;

	s64 adjust_old = (s64)(abs_lag / old_sum) * sign;
	s64 adjust_new = (s64)(abs_lag / new_sum) * sign;
	s64 diff       = adjust_old - adjust_new;

	if (diff >= 0)
		gdata->vtime_now += (u64)diff;
	else
		gdata->vtime_now -= (u64)-diff;

	return 0;
}

void
BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	p->scx.dsq_vtime     = gdata->vtime_now;
	gdata->total_weight += p->scx.weight;
}

void
BPF_STRUCT_OPS(eevdf_disable, struct task_struct *p)
{
	struct eevdf_ctx *gdata = get_ctx();
	if (!gdata)
		return;

	if (gdata->total_weight >= p->scx.weight)
		gdata->total_weight -= p->scx.weight;
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
               .init       = (void *)eevdf_init,
               .exit       = (void *)eevdf_exit,
               .name       = "eevdf");
