/*
 * sched_latency.bpf.c - BPF scheduler latency measurement
 *
 * Measures eight latency categories via tracepoints:
 *   - Schedule delay:     sched_wakeup → sched_switch (task starts running)
 *   - Runqueue latency:   enqueue → sched_switch (time on runqueue)
 *   - Wakeup latency:     sched_wakeup → enqueue
 *   - Preemption latency: stopping(runnable) → next running
 *   - Idle wakeup:        CPU goes idle → CPU picks up next task
 *   - Migration latency:  runqueue latency for tasks that ran on a
 *                         different CPU than where they were enqueued
 *   - Slice duration:     time a task ran continuously before switch-out
 *   - Sleep duration:     time a task spent voluntarily blocked before wakeup
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

enum latency_type {
	LAT_SCHED_DELAY  = 0,  /* wakeup → running */
	LAT_RUNQUEUE     = 1,  /* enqueue → running */
	LAT_WAKEUP       = 2,  /* wakeup → enqueue */
	LAT_PREEMPTION   = 3,  /* stopping(runnable) → running */
	LAT_IDLE_WAKEUP  = 4,  /* CPU idle → CPU running real task */
	LAT_MIGRATION    = 5,  /* runqueue lat for tasks that migrated CPUs */
	LAT_SLICE        = 6,  /* time task ran before being switched out */
	LAT_SLEEP        = 7,  /* time voluntarily blocked before wakeup */
	NR_LAT_TYPES     = 8,
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

/* Per-task timestamps for each latency event. */
struct task_ts {
	u64 wakeup_ts;       /* last sched_wakeup timestamp */
	u64 enqueue_ts;      /* last enqueue timestamp */
	u64 preempt_ts;      /* last preempted (stopping while runnable) timestamp */
	u64 run_start_ts;    /* when task last started running (for slice duration) */
	u64 sleep_start_ts;  /* when task last voluntarily blocked (for sleep duration) */
	u32 enqueue_cpu;     /* CPU where task was last enqueued (for migration detection) */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	__type(value, struct task_ts);
} task_timestamps SEC(".maps");

/*
 * Per-CPU idle start timestamps.
 * Set when CPU goes idle (next==idle task), cleared when CPU picks up work.
 * Used to measure LAT_IDLE_WAKEUP.  Not a histogram — persistent state only.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} idle_ts SEC(".maps");

/* Filter: 0 = all tasks, nonzero = only this tgid */
const volatile __u32 tgid_filter = 0;

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
 * Record wakeup timestamp and measure sleep duration.
 */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	if (filter_task(p))
		return 0;

	struct task_ts *ts = get_ts(p);
	if (!ts)
		return 0;

	u64 now = bpf_ktime_get_ns();

	/* Sleep duration: time spent voluntarily blocked */
	if (ts->sleep_start_ts) {
		record_latency(LAT_SLEEP, now - ts->sleep_start_ts);
		ts->sleep_start_ts = 0;
	}

	ts->wakeup_ts = now;
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
 * For the outgoing task (prev):
 *   - Measure slice duration (run_start_ts → now)
 *   - If still runnable (preempted): record preemption timestamp
 *   - If going to sleep (voluntary): record sleep start timestamp
 *
 * For CPU idle transitions (based on idle task pid==0):
 *   - next==idle: CPU going idle, record timestamp
 *   - prev==idle: CPU coming back from idle, measure LAT_IDLE_WAKEUP
 *
 * For the incoming task (next):
 *   - Measure migration latency if task ran on a different CPU than enqueued
 *   - Measure schedule delay (wakeup → running)
 *   - Measure runqueue latency (enqueue → running)
 *   - Measure preemption latency (preempt → running)
 *   - Record run_start_ts for next slice duration measurement
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

	u32 prev_pid = BPF_CORE_READ(prev, pid);
	u32 next_pid = BPF_CORE_READ(next, pid);

	/* Idle wakeup: CPU was idle (prev is idle task), now running real work */
	u32 idle_key = 0;
	u64 *idle_val = bpf_map_lookup_elem(&idle_ts, &idle_key);
	if (idle_val && prev_pid == 0 && *idle_val) {
		record_latency(LAT_IDLE_WAKEUP, now - *idle_val);
		*idle_val = 0;
	}

	/* Outgoing: measure slice, then set next timestamp for prev task */
	if (!filter_task(prev) && prev_pid != 0) {
		ts = get_ts(prev);
		if (ts) {
			/* Slice duration: how long did this task run? */
			if (ts->run_start_ts) {
				record_latency(LAT_SLICE, now - ts->run_start_ts);
				ts->run_start_ts = 0;
			}

			u64 prev_state = BPF_CORE_READ(prev, __state);
			if (prev_state == 0) {  /* TASK_RUNNING — preempted */
				ts->preempt_ts     = now;
				ts->sleep_start_ts = 0;
			} else {                /* going to sleep voluntarily */
				ts->sleep_start_ts = now;
				ts->preempt_ts     = 0;
			}
		}
	}

	/* CPU going idle: next is idle task, record timestamp */
	if (idle_val && next_pid == 0)
		*idle_val = now;

	/* Incoming: skip idle task and filtered tasks */
	if (filter_task(next) || next_pid == 0)
		return 0;

	ts = get_ts(next);
	if (!ts)
		return 0;

	/* Migration latency: task ran on different CPU than it was enqueued on */
	if (ts->enqueue_ts) {
		u32 curr_cpu = bpf_get_smp_processor_id();
		if (ts->enqueue_cpu != curr_cpu)
			record_latency(LAT_MIGRATION, now - ts->enqueue_ts);
	}

	/* Schedule delay: wakeup → now */
	if (ts->wakeup_ts) {
		record_latency(LAT_SCHED_DELAY, now - ts->wakeup_ts);
		ts->wakeup_ts = 0;
	}

	/* Runqueue latency: enqueue → now */
	if (ts->enqueue_ts) {
		record_latency(LAT_RUNQUEUE, now - ts->enqueue_ts);
		ts->enqueue_ts = 0;
	}

	/* Preemption latency: preempt → now */
	if (ts->preempt_ts) {
		record_latency(LAT_PREEMPTION, now - ts->preempt_ts);
		ts->preempt_ts = 0;
	}

	/* Record run start for slice duration on next switch-out */
	ts->run_start_ts = now;

	return 0;
}

/*
 * Common enqueue logic shared by both CFS and sched_ext hooks.
 * Records enqueue timestamp, enqueue CPU, and measures wakeup latency.
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

	ts->enqueue_ts  = now;
	ts->enqueue_cpu = bpf_get_smp_processor_id();
}

/*
 * CFS/EEVDF enqueue hook.
 * Fires when the default fair scheduler enqueues a task.
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
