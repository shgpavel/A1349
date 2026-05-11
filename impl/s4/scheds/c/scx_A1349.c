/* SPDX-License-Identifier: GPL-2.0
 *
 * scx_A1349 — userspace manager for the VCG auction scheduler (s4/A1349).
 *
 * Responsibilities:
 *   1. Read per-CPU capacities from sysfs and populate BPF maps
 *      (cpu_capacity, global_data.max_capacity, global_data.min_capacity).
 *   2. Optionally tune cost_p / cost_e via CLI flags.
 *   3. Periodically refresh capacities (hotplug support).
 *   4. Print telemetry: budget stats, phi distribution, core utilisation.
 */

#include <bpf/bpf.h>
#include <scx/common.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "scx_A1349.bpf.skel.h"

static volatile int exit_req;

static void
sigint_handler(int dummy)
{
	exit_req = 1;
}

/*
 * Must mirror the BPF auction_ctx struct (config-only, no runtime state).
 * Runtime state (vtime_now, total_weight, dsq_phi_hi_κ) lives in a separate
 * BPF map (runtime_data) and is owned exclusively by BPF — userspace must
 * never read-modify-write it, otherwise periodic refreshes race-stomp the
 * φ_hi EWMA and vtime floor.
 */
struct auction_ctx {
	__u32 max_capacity;
	__u32 min_capacity;
	__u32 cost_p;
	__u32 cost_e;
	__u32 p_core_count;
	__u32 e_core_count;
};

#define P_CAP_PCT 90

/*
 * Read cpu_capacity for every possible CPU from sysfs.
 * Populate:
 *   - cpu_capacity[cpu]      = capacity value
 *   - global_data.max_capacity = max across all CPUs
 *   - global_data.min_capacity = min across all CPUs (used for σ = max/min)
 *
 * Returns true if any value changed.
 */
static bool
refresh_cpu_capacities(struct scx_A1349 *skel,
		       __u32 cost_p, __u32 cost_e,
		       bool force_log)
{
	int cap_fd  = bpf_map__fd(skel->maps.cpu_capacity);
	int gmap_fd = bpf_map__fd(skel->maps.global_data);
	int isp_fd  = bpf_map__fd(skel->maps.cpu_is_p);
	__u32 max_cap = 0;
	__u32 min_cap = 0;
	bool changed  = false;

	int ncpu = libbpf_num_possible_cpus();

	/* Two-pass: first find max_cap so we can classify P vs E on pass 2. */
	__u32 caps[512] = {0};
	if (ncpu > 512)
		ncpu = 512;

	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);

		__u32 cap = 1024; /* homogeneous default */
		FILE *f = fopen(path, "r");
		if (f) {
			fscanf(f, "%u", &cap);
			fclose(f);
		}
		caps[cpu] = cap;

		__u32 key = (__u32)cpu;
		__u32 old_cap = 0;
		if (bpf_map_lookup_elem(cap_fd, &key, &old_cap) != 0 ||
		    old_cap != cap) {
			bpf_map_update_elem(cap_fd, &key, &cap, BPF_ANY);
			changed = true;
		}

		if (cap > max_cap)
			max_cap = cap;
		if (!min_cap || cap < min_cap)
			min_cap = cap;
	}

	/* Classify each CPU into P / E cluster (cap ≥ 90% max → P). */
	__u32 p_cc = 0, e_cc = 0;
	for (int cpu = 0; cpu < ncpu; cpu++) {
		__u8 is_p = ((__u64)caps[cpu] * 100 >= (__u64)max_cap * P_CAP_PCT);
		__u32 key = (__u32)cpu;
		__u8 old_flag = 0xff;
		if (bpf_map_lookup_elem(isp_fd, &key, &old_flag) != 0 ||
		    old_flag != is_p) {
			bpf_map_update_elem(isp_fd, &key, &is_p, BPF_ANY);
			changed = true;
		}
		if (is_p) p_cc++; else e_cc++;
	}

	if (!max_cap)
		max_cap = 1024;
	if (!min_cap)
		min_cap = max_cap;

	/* Update global_data (config-only — runtime state lives elsewhere). */
	__u32 gkey = 0;
	struct auction_ctx ctx = {};
	if (bpf_map_lookup_elem(gmap_fd, &gkey, &ctx) != 0)
		memset(&ctx, 0, sizeof(ctx));

	if (ctx.max_capacity != max_cap || ctx.min_capacity != min_cap ||
	    ctx.cost_p != cost_p || ctx.cost_e != cost_e ||
	    ctx.p_core_count != p_cc || ctx.e_core_count != e_cc) {
		ctx.max_capacity = max_cap;
		ctx.min_capacity = min_cap;
		ctx.cost_p       = cost_p;
		ctx.cost_e       = cost_e;
		ctx.p_core_count = p_cc;
		ctx.e_core_count = e_cc;
		bpf_map_update_elem(gmap_fd, &gkey, &ctx, BPF_ANY);
		changed = true;
	}

	if (force_log || changed) {
		double sigma = (min_cap > 0) ? (double)max_cap / min_cap : 1.0;
		printf("auction: max_cap=%u min_cap=%u sigma=%.2f "
		       "cost_p=%u cost_e=%u p_cores=%u e_cores=%u (%s)%s\n",
		       max_cap, min_cap, sigma, cost_p, cost_e, p_cc, e_cc,
		       (max_cap == min_cap) ? "homogeneous" : "heterogeneous",
		       changed ? " [updated]" : "");
	}

	return changed;
}

/*
 * Pre-scan sysfs to discover max/min cpu_capacity *before* loading the BPF
 * skeleton.  Used to auto-derive cost_e = cost_p * min_cap / max_cap so the
 * cost ratio matches σ on whatever silicon the scheduler runs on (Intel 265K,
 * Pixel 6, etc.) instead of being hardcoded to one machine.
 */
static void
scan_caps(__u32 *max_out, __u32 *min_out)
{
	int ncpu = libbpf_num_possible_cpus();
	__u32 max_cap = 0, min_cap = 0;

	if (ncpu > 512)
		ncpu = 512;

	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
		__u32 cap = 1024;
		FILE *f = fopen(path, "r");
		if (f) {
			if (fscanf(f, "%u", &cap) != 1)
				cap = 1024;
			fclose(f);
		}
		if (cap > max_cap)
			max_cap = cap;
		if (!min_cap || cap < min_cap)
			min_cap = cap;
	}

	if (!max_cap)
		max_cap = 1024;
	if (!min_cap)
		min_cap = max_cap;
	*max_out = max_cap;
	*min_out = min_cap;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-p COST_P] [-e COST_E] [-h]\n"
		"\n"
		"  -p COST_P   per-quantum cost on P-core (default 1024)\n"
		"  -e COST_E   per-quantum cost on E-core (auto-derived from σ\n"
		"              if omitted: cost_e = cost_p * min_cap / max_cap)\n"
		"\n"
		"VCG auction scheduler for heterogeneous CPUs (s4/A1349).\n"
		"Reads per-CPU capacity from /sys/.../cpu_capacity and assigns\n"
		"tasks to P-cores or E-cores based on their effective auction\n"
		"value phi_kappa = weight - cost_kappa * estimated_length.\n"
		"\n"
		"Budget token-bucket enforces VCG-inspired payments; depleted\n"
		"tasks fall back to a lowest-priority starved queue.\n",
		basename((char *)prog));
}

int
main(int argc, char **argv)
{
	struct scx_A1349 *skel;
	struct bpf_link    *link;
	int                 opt;
	/*
	 * Cost ratio MUST equal σ = max_cap/min_cap (user constraint —
	 * drain-rate symmetry across clusters).  Userspace auto-derives
	 * cost_e from detected topology so the ratio is correct on whatever
	 * silicon runs the scheduler, not just Intel 265K.
	 */
	__u32               cost_p = 1024;
	__u32               cost_e = 0;          /* 0 = auto-derive from σ */
	bool                cost_e_set = false;
	unsigned int        refresh_tick = 0;

	signal(SIGINT,  sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "p:e:h")) != -1) {
		switch (opt) {
		case 'p':
			cost_p = (__u32)atoi(optarg);
			break;
		case 'e':
			cost_e = (__u32)atoi(optarg);
			cost_e_set = true;
			break;
		default:
			usage(argv[0]);
			return opt != 'h';
		}
	}

	if (cost_p == 0) {
		fprintf(stderr, "Error: cost_p must be > 0.\n");
		return 1;
	}

	/* Auto-derive cost_e = cost_p * min_cap / max_cap when not set. */
	if (!cost_e_set) {
		__u32 mx, mn;
		scan_caps(&mx, &mn);
		__u64 derived = (__u64)cost_p * mn / mx;
		if (derived == 0)
			derived = 1;
		cost_e = (__u32)derived;
		printf("auction: cost_e auto-derived: cost_p=%u cost_e=%u "
		       "(σ=%.3f, max_cap=%u min_cap=%u)\n",
		       cost_p, cost_e, (double)mx / (double)mn, mx, mn);
	}

	if (cost_e == 0 || cost_e >= cost_p) {
		fprintf(stderr,
			"Error: need cost_p > cost_e > 0 "
			"(P-core must be strictly more expensive).\n");
		return 1;
	}

	skel = scx_A1349__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->struct_ops.auction_ops->hotplug_seq = scx_hotplug_seq();
	SCX_ENUM_INIT(skel);

	if (scx_A1349__load(skel)) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		scx_A1349__destroy(skel);
		return 1;
	}

	/*
	 * Populate capacity maps before attach so that auction_init() (which
	 * runs in BPF init hook) sees correct max_capacity / min_capacity.
	 */
	refresh_cpu_capacities(skel, cost_p, cost_e, true);

	link = bpf_map__attach_struct_ops(skel->maps.auction_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach struct ops\n");
		scx_A1349__destroy(skel);
		return 1;
	}

	printf("auction scheduler attached (cost_p=%u cost_e=%u). "
	       "Ctrl+C exits.\n", cost_p, cost_e);

	while (!exit_req) {
		sleep(1);
		/* Refresh every 5 seconds to handle CPU hotplug. */
		if ((refresh_tick++ % 5) == 0)
			refresh_cpu_capacities(skel, cost_p, cost_e, false);
	}

	bpf_link__destroy(link);
	scx_A1349__destroy(skel);
	return 0;
}
