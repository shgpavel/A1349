void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SCX_DSQ_GLOBAL);
}

s32 BPF_STRUCT_OPS(simple_init)
{
	scx_bpf_switch_all();
	return 0;
}

SEC(".struct_ops.link");
struct sched_ext_ops simple_ops = {
	.enqueue   = (void *)simple_enqueue,
	.dispatch  = (void *)simple_dispatch,
	.init      = (void *)simple_init,
	.name      = "simple",
};
