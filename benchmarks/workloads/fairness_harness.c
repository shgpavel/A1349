/*
 * fairness_harness.c - CPU fairness test workload
 *
 * Forks N identical CPU-bound children that busy-loop for T seconds.
 * Parent waits for all children and reports per-child wall-clock runtime.
 *
 * Usage: fairness_harness [-n NPROCS] [-t SECONDS]
 *
 * Output (stdout):
 *   pid,elapsed_ns
 *   1234,5000123456
 *   1235,5000234567
 *   ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>

static volatile int stop;

static void
alarm_handler(int sig)
{
	stop = 1;
}

static unsigned long long
timespec_to_ns(struct timespec *ts)
{
	return (unsigned long long)ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

/*
 * Child: busy-loop until SIGALRM fires, then exit.
 */
static void __attribute__((noreturn))
child_work(int duration_s)
{
	signal(SIGALRM, alarm_handler);
	alarm(duration_s);

	volatile unsigned long long counter = 0;
	while (!stop)
		counter++;

	_exit(0);
}

int
main(int argc, char **argv)
{
	int nprocs = 4;
	int duration_s = 5;
	int opt;

	while ((opt = getopt(argc, argv, "n:t:h")) != -1) {
		switch (opt) {
		case 'n':
			nprocs = atoi(optarg);
			if (nprocs < 1 || nprocs > 1024) {
				fprintf(stderr, "nprocs must be 1..1024\n");
				return 1;
			}
			break;
		case 't':
			duration_s = atoi(optarg);
			if (duration_s < 1) {
				fprintf(stderr, "duration must be >= 1\n");
				return 1;
			}
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-n NPROCS] [-t SECONDS]\n",
				argv[0]);
			return opt != 'h';
		}
	}

	pid_t *pids = malloc(nprocs * sizeof(pid_t));
	struct timespec *starts = malloc(nprocs * sizeof(struct timespec));
	if (!pids || !starts) {
		perror("malloc");
		return 1;
	}

	printf("pid,elapsed_ns\n");

	for (int i = 0; i < nprocs; i++) {
		clock_gettime(CLOCK_MONOTONIC, &starts[i]);
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			return 1;
		}
		if (pid == 0)
			child_work(duration_s);
		pids[i] = pid;
	}

	for (int i = 0; i < nprocs; i++) {
		int status;
		waitpid(pids[i], &status, 0);
		struct timespec end;
		clock_gettime(CLOCK_MONOTONIC, &end);
		unsigned long long elapsed = timespec_to_ns(&end) -
					     timespec_to_ns(&starts[i]);
		printf("%d,%llu\n", pids[i], elapsed);
	}

	free(pids);
	free(starts);
	return 0;
}
