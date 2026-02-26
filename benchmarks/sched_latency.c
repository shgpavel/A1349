/*
 * sched_latency.c - Userspace latency measurement tool for sched_ext
 *
 * Attaches BPF tracepoints to measure scheduler latencies and reports
 * percentile statistics (p50, p95, p99) for:
 *   - Schedule delay    (wakeup → running)
 *   - Runqueue latency  (enqueue → running)
 *   - Wakeup latency    (wakeup → enqueue)
 *   - Preemption latency (preempted → re-running)
 *
 * Also tracks context switch counters (total, voluntary, involuntary)
 * and optionally per-PID runtime for fairness analysis (-f flag).
 *
 * Usage: sched_latency [-d duration] [-i interval] [-p tgid] [-c] [-f]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <libgen.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sched_latency.bpf.skel.h"

#define HIST_BUCKETS  32
#define NR_LAT_TYPES  4
#define MAX_FAIRNESS_PIDS 4096

static const char *lat_names[NR_LAT_TYPES] = {
	"sched_delay",
	"runqueue",
	"wakeup",
	"preemption",
};

struct hist {
	__u64 bucket[HIST_BUCKETS];
	__u64 count;
	__u64 total_ns;
	__u64 min_ns;
	__u64 max_ns;
};

struct csw_counters {
	__u64 total;
	__u64 voluntary;
	__u64 involuntary;
};

static volatile int exit_req;
static int  interval_s    = 1;
static int  duration_s    = 0;
static int  csv_mode      = 0;
static int  fairness_mode = 0;
static char fairness_csv[256] = "";

static const char help_fmt[] =
"sched_ext latency measurement tool.\n"
"\n"
"Measures scheduling latency via BPF tracepoints and reports percentiles.\n"
"\n"
"Usage: %s [-d duration] [-i interval] [-p tgid] [-c] [-f [file]] [-h]\n"
"\n"
"  -d SEC        Run for SEC seconds then exit (0 = unlimited)\n"
"  -i SEC        Report interval in seconds (default: 1)\n"
"  -p TGID       Filter to a specific process group\n"
"  -c            CSV output mode\n"
"  -f FILE       Enable fairness tracking; dump per-PID runtime CSV to FILE on exit\n"
"  -h            Display this help and exit\n";

static void
sigint_handler(int dummy)
{
	exit_req = 1;
}

/*
 * Aggregate per-CPU histograms into a single combined histogram.
 */
static int
read_hist(int map_fd, __u32 type, struct hist *out, int nr_cpus)
{
	struct hist per_cpu[nr_cpus];
	int ret;

	memset(out, 0, sizeof(*out));
	ret = bpf_map_lookup_elem(map_fd, &type, per_cpu);
	if (ret < 0)
		return ret;

	for (int cpu = 0; cpu < nr_cpus; cpu++) {
		struct hist *h = &per_cpu[cpu];
		for (int b = 0; b < HIST_BUCKETS; b++)
			out->bucket[b] += h->bucket[b];
		out->count    += h->count;
		out->total_ns += h->total_ns;

		if (h->min_ns && (!out->min_ns || h->min_ns < out->min_ns))
			out->min_ns = h->min_ns;
		if (h->max_ns > out->max_ns)
			out->max_ns = h->max_ns;
	}

	return 0;
}

/*
 * Read aggregated context switch counters from per-CPU map.
 */
static int
read_csw(int map_fd, struct csw_counters *out, int nr_cpus)
{
	struct csw_counters per_cpu[nr_cpus];
	__u32 key = 0;
	int ret;

	memset(out, 0, sizeof(*out));
	ret = bpf_map_lookup_elem(map_fd, &key, per_cpu);
	if (ret < 0)
		return ret;

	for (int cpu = 0; cpu < nr_cpus; cpu++) {
		out->total       += per_cpu[cpu].total;
		out->voluntary   += per_cpu[cpu].voluntary;
		out->involuntary += per_cpu[cpu].involuntary;
	}

	return 0;
}

/*
 * Estimate a percentile from a log2 histogram.
 * Returns the upper bound of the bucket containing the target count.
 */
static __u64
hist_percentile(struct hist *h, double pct)
{
	if (!h->count)
		return 0;

	__u64 target = (__u64)(h->count * pct / 100.0);
	__u64 cumul  = 0;

	for (int b = 0; b < HIST_BUCKETS; b++) {
		cumul += h->bucket[b];
		if (cumul >= target)
			return 1ULL << (b + 1); /* upper bound of bucket */
	}

	return 1ULL << HIST_BUCKETS;
}

static const char *
fmt_ns(__u64 ns, char *buf, size_t len)
{
	if (ns < 1000ULL)
		snprintf(buf, len, "%lluns", (unsigned long long)ns);
	else if (ns < 1000000ULL)
		snprintf(buf, len, "%.1fus", ns / 1000.0);
	else if (ns < 1000000000ULL)
		snprintf(buf, len, "%.2fms", ns / 1000000.0);
	else
		snprintf(buf, len, "%.3fs", ns / 1000000000.0);
	return buf;
}

static void
print_header(void)
{
	if (csv_mode) {
		printf("timestamp,type,count,avg_ns,min_ns,max_ns,"
		       "p50_ns,p95_ns,p99_ns,"
		       "total_csw,voluntary_csw,involuntary_csw\n");
	}
}

static void
print_report(int hist_fd, int csw_fd, int nr_cpus)
{
	struct hist h;
	struct csw_counters csw;
	char b1[32], b2[32], b3[32], b4[32], b5[32];
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char ts[32];

	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	/* Read context switch counters once per interval */
	int csw_ok = (read_csw(csw_fd, &csw, nr_cpus) == 0);

	if (!csv_mode) {
		printf("\n--- %s ---\n", ts);
		if (csw_ok) {
			printf("  context switches: total=%llu  voluntary=%llu  involuntary=%llu\n",
			       (unsigned long long)csw.total,
			       (unsigned long long)csw.voluntary,
			       (unsigned long long)csw.involuntary);
		}
	}

	for (__u32 t = 0; t < NR_LAT_TYPES; t++) {
		if (read_hist(hist_fd, t, &h, nr_cpus) < 0)
			continue;

		if (!h.count) {
			if (!csv_mode)
				printf("  %-14s (no samples)\n", lat_names[t]);
			continue;
		}

		__u64 avg = h.total_ns / h.count;
		__u64 p50 = hist_percentile(&h, 50.0);
		__u64 p95 = hist_percentile(&h, 95.0);
		__u64 p99 = hist_percentile(&h, 99.0);

		if (csv_mode) {
			printf("%s,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu",
			       ts, lat_names[t],
			       (unsigned long long)h.count,
			       (unsigned long long)avg,
			       (unsigned long long)h.min_ns,
			       (unsigned long long)h.max_ns,
			       (unsigned long long)p50,
			       (unsigned long long)p95,
			       (unsigned long long)p99);
			if (csw_ok)
				printf(",%llu,%llu,%llu",
				       (unsigned long long)csw.total,
				       (unsigned long long)csw.voluntary,
				       (unsigned long long)csw.involuntary);
			else
				printf(",,,");
			printf("\n");
		} else {
			printf("  %-14s  n=%-8llu  avg=%-10s  "
			       "p50=%-10s  p95=%-10s  p99=%-10s  "
			       "min=%-10s  max=%-10s\n",
			       lat_names[t],
			       (unsigned long long)h.count,
			       fmt_ns(avg, b1, sizeof(b1)),
			       fmt_ns(p50, b2, sizeof(b2)),
			       fmt_ns(p95, b3, sizeof(b3)),
			       fmt_ns(p99, b4, sizeof(b4)),
			       fmt_ns(h.min_ns, b5, sizeof(b5)),
			       fmt_ns(h.max_ns, ts, sizeof(ts)));
		}
	}

	fflush(stdout);
}

/*
 * Print a visual histogram for a single latency type.
 */
static void
print_histogram(struct hist *h, const char *name)
{
	__u64 max_val = 0;

	for (int b = 0; b < HIST_BUCKETS; b++) {
		if (h->bucket[b] > max_val)
			max_val = h->bucket[b];
	}

	if (!max_val)
		return;

	printf("\n  %s distribution (n=%llu):\n", name,
	       (unsigned long long)h->count);

	for (int b = 0; b < HIST_BUCKETS; b++) {
		if (!h->bucket[b])
			continue;

		char lo[32], hi[32];
		__u64 lo_ns = (b == 0) ? 0 : 1ULL << b;
		__u64 hi_ns = 1ULL << (b + 1);

		fmt_ns(lo_ns, lo, sizeof(lo));
		fmt_ns(hi_ns, hi, sizeof(hi));

		int bar_len = (int)(h->bucket[b] * 40 / max_val);
		if (bar_len == 0 && h->bucket[b] > 0)
			bar_len = 1;

		printf("    [%8s, %8s)  %8llu |",
		       lo, hi, (unsigned long long)h->bucket[b]);
		for (int i = 0; i < bar_len; i++)
			putchar('#');
		putchar('\n');
	}
}

static void
print_final_report(int hist_fd, int csw_fd, int nr_cpus)
{
	struct hist h;
	struct csw_counters csw;

	printf("\n========== FINAL REPORT ==========\n");

	if (read_csw(csw_fd, &csw, nr_cpus) == 0) {
		printf("\n  Context switches: total=%llu  voluntary=%llu  involuntary=%llu\n",
		       (unsigned long long)csw.total,
		       (unsigned long long)csw.voluntary,
		       (unsigned long long)csw.involuntary);
	}

	for (__u32 t = 0; t < NR_LAT_TYPES; t++) {
		if (read_hist(hist_fd, t, &h, nr_cpus) < 0)
			continue;
		if (!h.count)
			continue;

		print_histogram(&h, lat_names[t]);
	}

	printf("\n");
}

/*
 * Dump per-PID runtime data to a CSV file (fairness mode).
 */
static void
dump_fairness_csv(int runtime_fd)
{
	FILE *fp;
	__u32 pid, next_pid;
	__u64 runtime_ns;

	if (!fairness_csv[0])
		return;

	fp = fopen(fairness_csv, "w");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s\n",
			fairness_csv, strerror(errno));
		return;
	}

	fprintf(fp, "pid,runtime_ns\n");

	/* Iterate all keys in the pid_runtime hash map */
	if (bpf_map_get_next_key(runtime_fd, NULL, &pid) != 0) {
		fclose(fp);
		return;
	}

	do {
		if (bpf_map_lookup_elem(runtime_fd, &pid, &runtime_ns) == 0)
			fprintf(fp, "%u,%llu\n", pid,
				(unsigned long long)runtime_ns);
	} while (bpf_map_get_next_key(runtime_fd, &pid, &next_pid) == 0
		 && (pid = next_pid, 1));

	fclose(fp);
	printf("Fairness data written to %s\n", fairness_csv);
}

int
main(int argc, char **argv)
{
	struct sched_latency *skel;
	__u32 tgid = 0;
	int   opt;

	while ((opt = getopt(argc, argv, "d:i:p:cf:h")) != -1) {
		switch (opt) {
		case 'd':
			duration_s = atoi(optarg);
			break;
		case 'i':
			interval_s = atoi(optarg);
			break;
		case 'p':
			tgid = (__u32)atoi(optarg);
			break;
		case 'c':
			csv_mode = 1;
			break;
		case 'f':
			fairness_mode = 1;
			snprintf(fairness_csv, sizeof(fairness_csv),
				 "%s", optarg);
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	skel = sched_latency__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->tgid_filter = tgid;
	skel->rodata->fairness_mode = fairness_mode ? 1 : 0;

	if (sched_latency__load(skel)) {
		fprintf(stderr, "Failed to load BPF program\n");
		sched_latency__destroy(skel);
		return 1;
	}

	if (sched_latency__attach(skel)) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		sched_latency__destroy(skel);
		return 1;
	}

	int nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus <= 0) {
		fprintf(stderr, "Failed to get CPU count\n");
		sched_latency__destroy(skel);
		return 1;
	}

	int hist_fd = bpf_map__fd(skel->maps.hists);
	int csw_fd  = bpf_map__fd(skel->maps.csw_counters);
	int rt_fd   = bpf_map__fd(skel->maps.pid_runtime);

	if (tgid)
		printf("Tracing scheduler latencies for tgid %u...\n", tgid);
	else
		printf("Tracing scheduler latencies (all tasks)...\n");

	if (fairness_mode)
		printf("Fairness tracking enabled → %s\n", fairness_csv);

	print_header();

	int elapsed = 0;

	while (!exit_req) {
		sleep(interval_s);
		elapsed += interval_s;

		print_report(hist_fd, csw_fd, nr_cpus);

		if (duration_s && elapsed >= duration_s)
			break;
	}

	print_final_report(hist_fd, csw_fd, nr_cpus);

	if (fairness_mode)
		dump_fairness_csv(rt_fd);

	sched_latency__destroy(skel);
	return 0;
}
