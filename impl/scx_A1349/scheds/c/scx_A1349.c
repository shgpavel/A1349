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
 *   4. Periodic capacity refresh.  CPU hotplug makes the kernel eject the
 *      scheduler with a restart request; the agent re-opens and re-attaches.
 *   5. Notice when the kernel ejects the scheduler (watchdog, runtime
 *      error), print the reason and exit non-zero.
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

#include "scx_A1349.h"
#include "scx_A1349.bpf.skel.h"

static volatile int exit_req;

static void
sigint_handler(int dummy)
{
	(void)dummy;
	exit_req = 1;
}

#define P_CAP_PCT           90u

static const char *const stat_names[STAT_NR] = {
	[STAT_ENQ_P]        = "enq_p",
	[STAT_ENQ_E]        = "enq_e",
	[STAT_ENQ_STARVED]  = "enq_starved",
	[STAT_SPILL]        = "spill",
	[STAT_PIN]          = "pin",
	[STAT_DIRECT_IDLE]  = "direct_idle",
	[STAT_AUCTION_WIN]  = "auction_win",
	[STAT_EXILE]        = "exile",
	[STAT_KEEP_PREV]    = "keep_prev",
	[STAT_STEAL]        = "steal",
	[STAT_STARVED_AGED] = "starved_aged",
	[STAT_STARVED_IDLE] = "starved_idle",
	[STAT_NO_CTX]       = "no_ctx",
};

/*
 * Populate the δ^m lookup table.  Computed in double precision; written as
 * fixed-point u64 with DELTA_SCALE = 2^20.  The table is RO from BPF.
 */
static int
populate_delta_table(struct scx_A1349 *skel, double delta)
{
	int fd = bpf_map__fd(skel->maps.delta_table);
	double cur = 1.0;

	for (__u32 m = 0; m < MAX_CONTRACT_LENGTH; m++) {
		__u64 fp = (__u64)llround(cur * (double)DELTA_SCALE);
		__u32 key = m;
		if (bpf_map_update_elem(fd, &key, &fp, BPF_ANY)) {
			fprintf(stderr, "delta_table[%u] update failed: %s\n",
				m, strerror(errno));
			return -1;
		}
		cur *= delta;
	}
	return 0;
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

/* Sum the per-CPU stats map and print one line. */
static void
print_stats(struct scx_A1349 *skel)
{
	int fd = bpf_map__fd(skel->maps.stats);
	int ncpu = libbpf_num_possible_cpus();
	__u64 vals[ncpu > 0 ? ncpu : 1];

	printf("scx_A1349 stats:");
	for (__u32 i = 0; i < STAT_NR; i++) {
		__u64 sum = 0;

		if (ncpu > 0 && !bpf_map_lookup_elem(fd, &i, vals))
			for (int c = 0; c < ncpu; c++)
				sum += vals[c];
		printf(" %s=%llu", stat_names[i], (unsigned long long)sum);
	}
	printf("\n");
	fflush(stdout);
}

static bool
parse_u32(const char *s, __u32 *out)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s || *end || v > UINT32_MAX)
		return false;
	*out = (__u32)v;
	return true;
}

static void
usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-p COST_P] [-e COST_E] [-d DELTA] [-v] [-h]\n"
		"\n"
		"  -p COST_P   per-quantum cost on P-core (default %u)\n"
		"  -e COST_E   per-quantum cost on E-core (default: auto-derive\n"
		"              cost_p * min_cap / max_cap to keep γ = σ)\n"
		"  -d DELTA    MDP discount factor δ ∈ (0,1) (default 0.98)\n"
		"  -v          print event counters every 5 s (always on exit)\n"
		"\n"
		"Pure VCG auction scheduler for heterogeneous CPUs (A1349 s4+).\n"
		"No virtual time / no EEVDF — tasks ranked by φ_κ = v − c_κ · l\n"
		"and paid the single-slot VCG payment\n"
		"  p = φ(j) + (δ^{m_j} − δ^{m_i}) · \\bar W_κ\n"
		"computed from a top-1 / top-2 peek of the cluster DSQ at\n"
		"dispatch time.  Tasks that cannot afford the payment fall back\n"
		"to AUCTION_DSQ_STARVED, which is served oldest-first once its\n"
		"head has waited long enough or the clusters run dry.\n",
		basename((char *)prog), COST_P_DEF);
}

int
main(int argc, char **argv)
{
	struct scx_A1349 *skel;
	struct bpf_link   *link;
	int                opt;
	__u32              cost_p = COST_P_DEF;
	__u32              cost_e = 0;
	bool               cost_e_user = false;
	bool               verbose = false;
	double             delta = 0.98;
	char              *end;
	unsigned int       refresh_tick;
	__u64              ecode;

	signal(SIGINT,  sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "p:e:d:vh")) != -1) {
		switch (opt) {
		case 'p':
			if (!parse_u32(optarg, &cost_p)) {
				fprintf(stderr, "Error: bad -p value '%s'.\n", optarg);
				return 1;
			}
			break;
		case 'e':
			if (!parse_u32(optarg, &cost_e)) {
				fprintf(stderr, "Error: bad -e value '%s'.\n", optarg);
				return 1;
			}
			cost_e_user = true;
			break;
		case 'd':
			errno = 0;
			delta = strtod(optarg, &end);
			if (errno || end == optarg || *end) {
				fprintf(stderr, "Error: bad -d value '%s'.\n", optarg);
				return 1;
			}
			break;
		case 'v':
			verbose = true;
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

restart:
	skel = scx_A1349__open();
	SCX_BUG_ON(!skel, "Failed to open BPF skeleton");

	skel->struct_ops.auction_ops->hotplug_seq = scx_hotplug_seq();
	SCX_ENUM_INIT(skel);

	SCX_OPS_LOAD(skel, auction_ops, scx_A1349, uei);

	/*
	 * Order matters: delta_table and capacity data must be in place
	 * before attach so that auction_init() observes consistent config
	 * the moment the struct_ops becomes active.
	 */
	if (populate_delta_table(skel, delta)) {
		scx_A1349__destroy(skel);
		return 1;
	}
	refresh_cpu_capacities(skel, cost_p, cost_e, cost_e_user, true);

	printf("scx_A1349: delta=%.4f (table[1]=%.6f, table[%u]=%.6f)\n",
	       delta, pow(delta, 1.0), MAX_CONTRACT_LENGTH - 1,
	       pow(delta, (double)(MAX_CONTRACT_LENGTH - 1)));

	link = SCX_OPS_ATTACH(skel, auction_ops, scx_A1349);

	printf("scx_A1349 auction scheduler attached.  Ctrl+C exits.\n");
	fflush(stdout);

	refresh_tick = 0;
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
		if ((++refresh_tick % 5) == 0) {
			refresh_cpu_capacities(skel, cost_p, cost_e,
					       cost_e_user, false);
			if (verbose)
				print_stats(skel);
		}
	}

	print_stats(skel);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_A1349__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	/* Ejected by the kernel rather than stopped by the operator. */
	return exit_req ? 0 : 1;
}
