/* EEVDF-like sched_ext scheduler based on scx_simple */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include "scx_eevdf.bpf.skel.h"

const char help_fmt[] =
"A simple EEVDF sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s\n"
"\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void
sigint_handler(int dummy)
{
	exit_req = 1;
}

int
main(int argc, char **argv)
{
	struct scx_eevdf *skel;
	struct bpf_link  *link;
	__u32             opt;
	__u64             ecode;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(eevdf_ops, scx_eevdf);

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, eevdf_ops, scx_eevdf, uei);
	link = SCX_OPS_ATTACH(skel, eevdf_ops, scx_eevdf);

	printf("EEVDF scheduler attached. Press Ctrl+C to exit.\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_eevdf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
