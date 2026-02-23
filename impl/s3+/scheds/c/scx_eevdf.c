/* A1349: EEVDF extended for heterogeneous processors (Intel P-core/E-core).
 * On homogeneous systems (all cpu_capacity == 1024) this is identical to
 * classic EEVDF.  On hybrid CPUs the scheduler accounts for per-core
 * computational capacity ρ_c when advancing virtual time and computing
 * virtual deadlines.
 */

#include <bpf/bpf.h>
#include <scx/common.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "scx_eevdf.bpf.skel.h"

#ifndef EEVDF_TELEMETRY
#define EEVDF_TELEMETRY 0
#endif

#if EEVDF_TELEMETRY
#define LAT_BUCKETS 64
#endif

static volatile int exit_req;

static void
sigint_handler(int dummy)
{
	exit_req = 1;
}

struct eevdf_ctx {
	__u64 vtime_now;
	__u64 total_weight;
	__u32 max_capacity;
	__u32 _pad;
};

static bool
refresh_cpu_capacities(struct scx_eevdf *skel, bool force_log)
{
	int map_fd  = bpf_map__fd(skel->maps.cpu_capacity);
	int gmap_fd = bpf_map__fd(skel->maps.global_data);
	__u32 max_cap = 0;
	bool changed = false;

	int ncpu = libbpf_num_possible_cpus();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
		FILE *f = fopen(path, "r");
		__u32 cap = 1024;   /* default for homogeneous */
		if (f) {
			fscanf(f, "%u", &cap);
			fclose(f);
		}
		__u32 key = (__u32)cpu;
		__u32 old_cap = 0;
		if (bpf_map_lookup_elem(map_fd, &key, &old_cap) != 0 || old_cap != cap) {
			bpf_map_update_elem(map_fd, &key, &cap, BPF_ANY);
			changed = true;
		}
		if (cap > max_cap)
			max_cap = cap;
	}

	if (!max_cap)
		max_cap = 1024;

	/* Write max_capacity into global_data[0] */
	__u32 key = 0;
	struct eevdf_ctx ctx = {};
	if (bpf_map_lookup_elem(gmap_fd, &key, &ctx) != 0)
		memset(&ctx, 0, sizeof(ctx));
	if (ctx.max_capacity != max_cap) {
		ctx.max_capacity = max_cap;
		bpf_map_update_elem(gmap_fd, &key, &ctx, BPF_ANY);
		changed = true;
	}

	if (force_log || changed) {
		printf("A1349: max_capacity=%u (%s)%s\n", max_cap,
		       max_cap == 1024 ? "homogeneous" : "heterogeneous",
		       changed ? " [updated]" : "");
	}

	return changed;
}

#if EEVDF_TELEMETRY
static void
read_latency_p95(struct scx_eevdf *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 *percpu_vals = malloc(sizeof(__u64) * ncpu);
	__u64 buckets[LAT_BUCKETS];
	__u64 total = 0;
	__u64 cum = 0;
	int i, c;
	if (!percpu_vals)
		return;

	memset(buckets, 0, sizeof(buckets));

	for (i = 0; i < LAT_BUCKETS; i++) {
		__u32 key = i;
		memset(percpu_vals, 0, sizeof(__u64) * ncpu);
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.latency_hist),
					&key, percpu_vals) != 0)
			continue;
		for (c = 0; c < ncpu; c++)
			buckets[i] += percpu_vals[c];
		total += buckets[i];
	}

	if (!total) {
		printf("samples: 0\n");
		free(percpu_vals);
		return;
	}

	printf("samples: %llu\n", (unsigned long long)total);

	for (i = 0; i < LAT_BUCKETS; i++) {
		cum += buckets[i];
		if (cum * 100 >= total * 95) {
			double us = (double)(1ULL << i) / 1000.0;
			printf("p95 scheduler latency: %.2f us (bucket %d)\n", us, i);
			break;
		}
	}

	free(percpu_vals);
}

static void
read_stats(struct scx_eevdf *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 *percpu = calloc(ncpu, sizeof(__u64));
	if (!percpu) return;
	for (int idx = 0; idx < 4; idx++) {
		memset(percpu, 0, ncpu * sizeof(__u64));
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, percpu) == 0) {
			__u64 sum = 0;
			for (int c = 0; c < ncpu; c++)
				sum += percpu[c];
			printf("stat[%d] = %llu\n", idx, (unsigned long long)sum);
		} else {
			printf("stat[%d] = (err)\n", idx);
		}
	}
	free(percpu);
}

static void
reset_latency_hist(struct scx_eevdf *skel)
{
	int ncpu = libbpf_num_possible_cpus();
	__u64 *zeros = calloc(ncpu, sizeof(__u64));
	__u32 i;
	if (!zeros)
		return;
	for (i = 0; i < LAT_BUCKETS; i++) {
		__u32 key = i;
		bpf_map_update_elem(bpf_map__fd(skel->maps.latency_hist),
				    &key, zeros, BPF_ANY);
	}
	free(zeros);
}
#endif

int
main(int argc, char **argv)
{
	struct scx_eevdf *skel;
	struct bpf_link  *link;
	int               opt;
	unsigned int      cap_refresh_tick = 0;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		default:
			fprintf(stderr,
				"Usage: %s\n"
				"\n"
				"A1349 scheduler: EEVDF extended for heterogeneous processors.\n"
				"Reads per-CPU capacity from /sys/devices/system/cpu/cpuN/cpu_capacity\n"
				"and scales virtual-time accounting by each core's computational\n"
				"capacity (ρ_c).  On homogeneous systems this is identical to EEVDF.\n",
				basename(argv[0]));
			return opt != 'h';
		}
	}

	skel = scx_eevdf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* SCX_DSQ_* and other sched_ext constants are weak in BPF and must be
	 * populated from the running kernel before loading. */
	skel->struct_ops.eevdf_ops->hotplug_seq = scx_hotplug_seq();
	SCX_ENUM_INIT(skel);

	if (scx_eevdf__load(skel)) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		scx_eevdf__destroy(skel);
		return 1;
	}

	/* Must be after load (maps exist) and before attach (init overwrites
	 * max_capacity only when it is still zero). */
	refresh_cpu_capacities(skel, true);

	link = bpf_map__attach_struct_ops(skel->maps.eevdf_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach struct ops\n");
		scx_eevdf__destroy(skel);
		return 1;
	}

	printf("A1349 scheduler attached. Ctrl+C exits.\n");

	while (!exit_req) {
		sleep(1);
		if ((cap_refresh_tick++ % 5) == 0)
			refresh_cpu_capacities(skel, false);
#if EEVDF_TELEMETRY
		read_latency_p95(skel);
		reset_latency_hist(skel);
		read_stats(skel);
#endif
	}

	bpf_link__destroy(link);
	scx_eevdf__destroy(skel);
	return 0;
}
