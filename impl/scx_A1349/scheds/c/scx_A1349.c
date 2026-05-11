/* SPDX-License-Identifier: GPL-2.0
 *
 * scx_A1349 — userspace agent for the pure-auction VCG scheduler (A1349 s4+).
 *
 * Responsibilities:
 *   1. Discover per-CPU capacities from /sys/.../cpu_capacity, derive
 *      max_capacity (η_P), min_capacity (η_E), classify P vs E cores.
 *   2. Auto-derive c_E = c_P · η_E / η_P so γ = c_P/c_E = σ unless the
 *      operator overrides via -e.
 *   3. Precompute δ^m · DELTA_SCALE for m ∈ [0, MAX_CONTRACT_LENGTH) and
 *      ship it to BPF via the delta_table map.  Avoids BPF-side fp math.
 *   4. Periodic refresh for hotplug.
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
#include <math.h>
#include <getopt.h>

#include "scx_A1349.bpf.skel.h"

static volatile int exit_req;

static void
sigint_handler(int dummy)
{
	(void)dummy;
	exit_req = 1;
}

#define MAX_CONTRACT_LENGTH 32u
#define DELTA_SHIFT         20
#define DELTA_SCALE         (1ULL << DELTA_SHIFT)
#define P_CAP_PCT           90u

/* Mirrors the BPF auction_ctx layout — config-only, no runtime estimator state. */
struct auction_ctx {
	__u32 max_capacity;
	__u32 min_capacity;
	__u32 cost_p;
	__u32 cost_e;
	__u32 p_core_count;
	__u32 e_core_count;
};

/*
 * Populate the δ^m lookup table.  Computed in double precision; written as
 * fixed-point u64 with DELTA_SCALE = 2^20.  The table is RO from BPF and is
 * refreshed only on δ change (not on every hotplug tick).
 */
static void
populate_delta_table(struct scx_A1349 *skel, double delta)
{
	int fd = bpf_map__fd(skel->maps.delta_table);
	double cur = 1.0;

	for (__u32 m = 0; m < MAX_CONTRACT_LENGTH; m++) {
		__u64 fp = (__u64)llround(cur * (double)DELTA_SCALE);
		__u32 key = m;
		bpf_map_update_elem(fd, &key, &fp, BPF_ANY);
		cur *= delta;
	}
}

/*
 * Refresh per-CPU capacity-derived data:
 *   cpu_capacity[cpu], cpu_is_p[cpu], global_data.{max,min,cost,p_cc,e_cc}.
 * Caller picks cost_p; cost_e is either operator-provided or auto-derived.
 */
static bool
refresh_cpu_capacities(struct scx_A1349 *skel,
		       __u32 cost_p, __u32 cost_e_in, bool cost_e_user,
		       bool force_log)
{
	int cap_fd  = bpf_map__fd(skel->maps.cpu_capacity);
	int gmap_fd = bpf_map__fd(skel->maps.global_data);
	int isp_fd  = bpf_map__fd(skel->maps.cpu_is_p);
	__u32 max_cap = 0, min_cap = 0;
	__u32 cost_e;
	bool changed = false;

	int ncpu = libbpf_num_possible_cpus();
	__u32 caps[512] = {0};
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

	if (cost_e_user) {
		cost_e = cost_e_in;
	} else {
		__u64 derived = (__u64)cost_p * min_cap / max_cap;
		if (!derived)
			derived = 1;
		cost_e = (__u32)derived;
	}

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
		printf("scx_A1349: max_cap=%u min_cap=%u sigma=%.3f "
		       "cost_p=%u cost_e=%u p_cores=%u e_cores=%u (%s)%s\n",
		       max_cap, min_cap, sigma, cost_p, cost_e, p_cc, e_cc,
		       (max_cap == min_cap) ? "homogeneous" : "heterogeneous",
		       changed ? " [updated]" : "");
	}

	return changed;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-p COST_P] [-e COST_E] [-d DELTA] [-h]\n"
		"\n"
		"  -p COST_P   per-quantum cost on P-core (default 1024)\n"
		"  -e COST_E   per-quantum cost on E-core (default: auto-derive\n"
		"              cost_p * min_cap / max_cap to keep γ = σ)\n"
		"  -d DELTA    MDP discount factor δ ∈ (0,1) (default 0.98)\n"
		"\n"
		"Pure VCG auction scheduler for heterogeneous CPUs (A1349 s4+).\n"
		"No virtual time / no EEVDF — tasks ranked by φ_κ = v − c_κ · l\n"
		"and paid the single-slot VCG payment\n"
		"  p = φ(j) + (δ^{m_j} − δ^{m_i}) · \\bar W_κ\n"
		"computed from a top-1 / top-2 peek of the cluster DSQ at\n"
		"dispatch time.  Tasks that cannot afford the payment fall back\n"
		"to AUCTION_DSQ_STARVED until idle-time replenishment refills\n"
		"their budget.\n",
		basename((char *)prog));
}

int
main(int argc, char **argv)
{
	struct scx_A1349 *skel;
	struct bpf_link   *link;
	int                opt;
	__u32              cost_p = 1024;
	__u32              cost_e = 0;
	bool               cost_e_user = false;
	double             delta = 0.98;
	unsigned int       refresh_tick = 0;

	signal(SIGINT,  sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "p:e:d:h")) != -1) {
		switch (opt) {
		case 'p':
			cost_p = (__u32)atoi(optarg);
			break;
		case 'e':
			cost_e = (__u32)atoi(optarg);
			cost_e_user = true;
			break;
		case 'd':
			delta = atof(optarg);
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
	if (!(delta > 0.0 && delta < 1.0)) {
		fprintf(stderr,
			"Error: delta must satisfy 0 < δ < 1 "
			"(got %.6f).\n", delta);
		return 1;
	}
	if (cost_e_user && (cost_e == 0 || cost_e >= cost_p)) {
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
	 * Order matters: delta_table and capacity data must be in place
	 * before attach so that auction_init() observes consistent config
	 * the moment the struct_ops becomes active.
	 */
	populate_delta_table(skel, delta);
	refresh_cpu_capacities(skel, cost_p, cost_e, cost_e_user, true);

	printf("scx_A1349: delta=%.4f (table[1]=%.6f, table[%u]=%.6f)\n",
	       delta, pow(delta, 1.0), MAX_CONTRACT_LENGTH - 1,
	       pow(delta, (double)(MAX_CONTRACT_LENGTH - 1)));

	link = bpf_map__attach_struct_ops(skel->maps.auction_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach struct ops\n");
		scx_A1349__destroy(skel);
		return 1;
	}

	printf("scx_A1349 auction scheduler attached.  Ctrl+C exits.\n");

	while (!exit_req) {
		sleep(1);
		if ((refresh_tick++ % 5) == 0)
			refresh_cpu_capacities(skel, cost_p, cost_e,
					       cost_e_user, false);
	}

	bpf_link__destroy(link);
	scx_A1349__destroy(skel);
	return 0;
}
