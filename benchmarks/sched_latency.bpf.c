/*
 * sched_latency.bpf.c - BPF scheduler latency measurement
 *
 * Measures four latency categories via tracepoints:
 *   - Schedule delay:     sched_wakeup → sched_switch (task starts running)
 *   - Runqueue latency:   enqueue → sched_switch (time on runqueue)
 *   - Wakeup latency:     sched_wakeup → enqueue
 *   - Preemption latency: stopping(runnable) → next running
 *
 * Enqueue is detected via two optional fentry hooks (whichever is available):
 *   - enqueue_task_fair:    default CFS/EEVDF scheduler
 *   - scx_ops_enqueue_task: sched_ext schedulers
 *
 * Each category is recorded into a per-CPU log2 histogram for efficient
 * percentile estimation in userspace.
 */

#ifdef LSP
#define __bpf__
#include "../scheds/vmlinux/vmlinux.h"
#else
#include "vmlinux.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define MAX_CPUS      512
#define HIST_BUCKETS  32   /* log2 buckets: 0=<1ns .. 31=~2s */
#define MAX_FAIRNESS_PIDS 4096

enum latency_type {
	LAT_SCHED_DELAY  = 0,  /* wakeup → running */
	LAT_RUNQUEUE     = 1,  /* enqueue → running */
	LAT_WAKEUP       = 2,  /* wakeup → enqueue */
	LAT_PREEMPTION   = 3,  /* stopping(runnable) → running */
	NR_LAT_TYPES     = 4,
};

struct hist {
	u64 bucket[HIST_BUCKETS];
	u64 count;
	u64 total_ns;
	u64 min_ns;
	u64 max_ns;
};

/* Context switch counters (per-CPU). */
struct csw_counters {
	u64 total;
	u64 voluntary;
	u64 involuntary;
};

/* Per-CPU histograms for each latency type. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct hist));
	__uint(max_entries, NR_LAT_TYPES);
} hists SEC(".maps");

/* Per-CPU context switch counters (single entry, index 0). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct csw_counters));
	__uint(max_entries, 1);
} csw_counters SEC(".maps");

/* Per-PID cumulative runtime (for fairness mode). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));  /* pid */
	__uint(value_size, sizeof(u64)); /* cumulative runtime ns */
	__uint(max_entries, MAX_FAIRNESS_PIDS);
} pid_runtime SEC(".maps");

/* Per-task timestamps for each latency event. */
struct task_ts {
	u64 wakeup_ts;    /* last sched_wakeup timestamp */
	u64 enqueue_ts;   /* last enqueue timestamp */
	u64 preempt_ts;   /* last preempted (stopping while runnable) timestamp */
	u64 switch_in_ts; /* timestamp when task was switched in (for runtime) */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	__type(value, struct task_ts);
} task_timestamps SEC(".maps");

/* Filter: 0 = all tasks, nonzero = only this tgid */
const volatile __u32 tgid_filter = 0;

/* Fairness mode: when nonzero, track per-PID runtime in pid_runtime map */
const volatile __u32 fairness_mode = 0;

static __always_inline bool
filter_task(struct task_struct *p)
{
	if (!tgid_filter)
		return false;
	return BPF_CORE_READ(p, tgid) != tgid_filter;
}

static __always_inline u32
log2_bucket(u64 val)
{
	if (!val)
		return 0;

	u32 bit = 0;

	/* manual log2 - count leading zeros */
	#pragma unroll
	for (int i = 31; i >= 0; i--) {
		if (val & (1ULL << i)) {
			bit = i;
			break;
		}
	}

	return bit < HIST_BUCKETS ? bit : HIST_BUCKETS - 1;
}

static __always_inline void
record_latency(u32 type, u64 delta_ns)
{
	struct hist *h;

	h = bpf_map_lookup_elem(&hists, &type);
	if (!h)
		return;

	u32 slot = log2_bucket(delta_ns);
	if (slot < HIST_BUCKETS)
		h->bucket[slot]++;
	h->count++;
	h->total_ns += delta_ns;

	if (!h->min_ns || delta_ns < h->min_ns)
		h->min_ns = delta_ns;
	if (delta_ns > h->max_ns)
		h->max_ns = delta_ns;
}

static __always_inline struct task_ts *
get_ts(struct task_struct *p)
{
	return bpf_task_storage_get(&task_timestamps, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Tracepoint: sched_wakeup
 * Record wakeup timestamp.
 */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	if (filter_task(p))
		return 0;

	struct task_ts *ts = get_ts(p);
	if (!ts)
		return 0;

	ts->wakeup_ts = bpf_ktime_get_ns();
	return 0;
}

/*
 * Tracepoint: sched_wakeup_new
 * Also record for newly created tasks.
 */
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	if (filter_task(p))
		return 0;

	struct task_ts *ts = get_ts(p);
	if (!ts)
		return 0;

	ts->wakeup_ts = bpf_ktime_get_ns();
	return 0;
}

/*
 * Tracepoint: sched_switch
 *
 * For the incoming task (next):
 *   - Measure schedule delay (wakeup → running)
 *   - Measure preemption latency (preempt → running)
 *
 * For the outgoing task (prev):
 *   - If still runnable, record preemption timestamp
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
	     bool preempt,
	     struct task_struct *prev,
	     struct task_struct *next)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ts *ts;

	/* Increment context switch counters */
	u32 csw_key = 0;
	struct csw_counters *csw = bpf_map_lookup_elem(&csw_counters, &csw_key);
	if (csw) {
		csw->total++;
		if (preempt)
			csw->involuntary++;
		else
			csw->voluntary++;
	}

	/* Outgoing: if still runnable, mark as preempted */
	if (!filter_task(prev)) {
		u64 prev_state = BPF_CORE_READ(prev, __state);
		if (prev_state == 0) {  /* TASK_RUNNING */
			ts = get_ts(prev);
			if (ts)
				ts->preempt_ts = now;
		}

		/* Track runtime for fairness mode */
		if (fairness_mode) {
			ts = get_ts(prev);
			if (ts && ts->switch_in_ts) {
				u64 runtime = now - ts->switch_in_ts;
				u32 pid = BPF_CORE_READ(prev, pid);
				u64 *cum = bpf_map_lookup_elem(&pid_runtime, &pid);
				if (cum) {
					*cum += runtime;
				} else {
					bpf_map_update_elem(&pid_runtime, &pid,
							    &runtime, BPF_ANY);
				}
				ts->switch_in_ts = 0;
			}
		}
	}

	/* Incoming: measure latencies */
	if (filter_task(next))
		return 0;

	ts = get_ts(next);
	if (!ts)
		return 0;

	/* Record switch-in timestamp for runtime tracking */
	ts->switch_in_ts = now;

	/* Schedule delay: wakeup → now */
	if (ts->wakeup_ts) {
		u64 delta = now - ts->wakeup_ts;
		record_latency(LAT_SCHED_DELAY, delta);
		ts->wakeup_ts = 0;
	}

	/* Runqueue latency: enqueue → now */
	if (ts->enqueue_ts) {
		u64 delta = now - ts->enqueue_ts;
		record_latency(LAT_RUNQUEUE, delta);
		ts->enqueue_ts = 0;
	}

	/* Preemption latency: preempt → now */
	if (ts->preempt_ts) {
		u64 delta = now - ts->preempt_ts;
		record_latency(LAT_PREEMPTION, delta);
		ts->preempt_ts = 0;
	}

	return 0;
}

/*
 * Common enqueue logic shared by both CFS and sched_ext hooks.
 * Records enqueue timestamp and measures wakeup latency.
 */
static __always_inline void
handle_enqueue(struct task_struct *p)
{
	if (filter_task(p))
		return;

	struct task_ts *ts = get_ts(p);
	if (!ts)
		return;

	u64 now = bpf_ktime_get_ns();

	/* Wakeup latency: wakeup → enqueue */
	if (ts->wakeup_ts) {
		u64 delta = now - ts->wakeup_ts;
		record_latency(LAT_WAKEUP, delta);
		/* Don't clear wakeup_ts - schedule delay still needs it */
	}

	ts->enqueue_ts = now;
}

/*
 * CFS/EEVDF enqueue hook.
 * Fires when the default fair scheduler enqueues a task.
 * ? prefix = optional: silently skipped if unavailable.
 */
SEC("?fentry/enqueue_task_fair")
int BPF_PROG(handle_cfs_enqueue, struct rq *rq, struct task_struct *p,
	     int flags)
{
	handle_enqueue(p);
	return 0;
}

/*
 * sched_ext enqueue hook.
 * Fires when any sched_ext scheduler enqueues a task.
 * ? prefix = optional: silently skipped if no sched_ext loaded.
 */
SEC("?fentry/scx_ops_enqueue_task")
int BPF_PROG(handle_scx_enqueue, struct task_struct *p)
{
	handle_enqueue(p);
	return 0;
}
