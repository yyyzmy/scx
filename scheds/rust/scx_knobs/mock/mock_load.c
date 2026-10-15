// SPDX-License-Identifier: GPL-2.0
/*
 * mock_load: synthetic workload generator for scx_knobs testing.
 *
 *   mock_load cpu [n]           n CPU-bound threads (slice-end stop source)
 *   mock_load io  [n]           n threads: 200us compute + 5ms sleep per cycle
 *                               (voluntary stop + wakeup-preemption source)
 *   mock_load mix [ncpu] [nio]  both; defaults ncpu=nproc, nio=max(1, nproc/2)
 *
 * The io threads are the interesting part: each 5ms sleep banks ~5ms of
 * vtime credit (capped at one slice), which under the default wakeup_gran
 * (1ms) lets every wakeup preempt a running CPU-bound victim. Raising gran
 * to >= one slice (e.g. `gran 20000`) must stop that.
 *
 * SIGINT/SIGTERM stop all threads gracefully.
 */
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAXT 512

static atomic_bool running = true;
static volatile double sink;

static void handle_sig(int sig)
{
	(void)sig;
	atomic_store(&running, false);
}

/* busy-burn approximately us microseconds (clock-based, arch-independent) */
static void burn_us(long us)
{
	struct timespec now;
	long target;

	clock_gettime(CLOCK_MONOTONIC, &now);
	target = now.tv_sec * 1000000L + now.tv_nsec / 1000 + us;
	do {
		unsigned long x = 0;

		for (int i = 0; i < 1000; i++)
			x += (unsigned long)i;
		sink = (double)x;
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec * 1000000L + now.tv_nsec / 1000 < target);
}

static void *cpu_thread(void *arg)
{
	(void)arg;
	while (atomic_load(&running))
		burn_us(100000);	/* 100ms compute bursts, never sleeps */
	return NULL;
}

static void *io_thread(void *arg)
{
	(void)arg;
	while (atomic_load(&running)) {
		burn_us(200);		/* short compute */
		usleep(5000);		/* 5ms sleep -> wakeup with banked credit */
	}
	return NULL;
}

static void spawn(pthread_t *tids, int n, void *(*fn)(void *))
{
	for (int i = 0; i < n; i++) {
		if (pthread_create(&tids[i], NULL, fn, NULL)) {
			perror("pthread_create");
			exit(1);
		}
	}
}

static void join_all(pthread_t *tids, int n)
{
	for (int i = 0; i < n; i++)
		pthread_join(tids[i], NULL);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "mix";
	int ncpu_sys = (int)sysconf(_SC_NPROCESSORS_ONLN);
	pthread_t ctids[MAXT], itids[MAXT];
	int ncpu, nio;

	signal(SIGINT, handle_sig);
	signal(SIGTERM, handle_sig);
	if (ncpu_sys < 1)
		ncpu_sys = 1;

	if (!strcmp(mode, "cpu")) {
		ncpu = argc > 2 ? atoi(argv[2]) : ncpu_sys;
		if (ncpu < 1) ncpu = 1;
		if (ncpu > MAXT) ncpu = MAXT;
		fprintf(stderr, "mock_load: %d cpu threads\n", ncpu);
		spawn(ctids, ncpu, cpu_thread);
		join_all(ctids, ncpu);
	} else if (!strcmp(mode, "io")) {
		nio = argc > 2 ? atoi(argv[2]) : ncpu_sys / 2;
		if (nio < 1) nio = 1;
		if (nio > MAXT) nio = MAXT;
		fprintf(stderr, "mock_load: %d io threads\n", nio);
		spawn(itids, nio, io_thread);
		join_all(itids, nio);
	} else if (!strcmp(mode, "mix")) {
		ncpu = argc > 2 ? atoi(argv[2]) : ncpu_sys;
		nio = argc > 3 ? atoi(argv[3]) : ncpu_sys / 2;
		if (ncpu < 1) ncpu = 1;
		if (nio < 1) nio = 1;
		if (ncpu > MAXT) ncpu = MAXT;
		if (nio > MAXT) nio = MAXT;
		fprintf(stderr, "mock_load: %d cpu + %d io threads\n", ncpu, nio);
		spawn(ctids, ncpu, cpu_thread);
		spawn(itids, nio, io_thread);
		join_all(ctids, ncpu);
		join_all(itids, nio);
	} else {
		fprintf(stderr, "usage: %s [cpu|io|mix] [n] [nio]\n", argv[0]);
		return 1;
	}

	(void)sink;
	return 0;
}
