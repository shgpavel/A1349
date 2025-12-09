/* EEVDF-like sched_ext scheduler based on scx_simple */

#include <scx/common.h>
#include <signal.h>
#include <libgen.h>

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
	skel = scx_eevdf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	if (scx_eevdf__load(skel)) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		scx_eevdf__destroy(skel);
		return 1;
	}

	link = bpf_map__attach_struct_ops(skel->maps.eevdf_ops);
	if (!link) {
		fprintf(stderr, "Failed to attach struct ops\n");
		scx_eevdf__destroy(skel);
		return 1;
	}

	printf("EEVDF scheduler attached. Press Ctrl+C to exit.\n");

	while (!exit_req) {
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = 0;
	scx_eevdf__destroy(skel);

	return 0;
}
