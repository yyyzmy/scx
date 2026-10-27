/* SPDX-License-Identifier: GPL-2.0 */
/*
 * opt_in_ext: move threads onto the SCHED_EXT policy (7) via sched_setattr(2),
 * so that a partial-takeover scx scheduler (SCX_OPS_SWITCH_PARTIAL, e.g.
 * `scx_knobs --partial`) takes them over. Everything else keeps running on
 * CFS.
 *
 * Usage:
 *   opt_in_ext <tid>...        each argument is a TID
 *   opt_in_ext -a <pid>...     each argument is a PID; opt in all its threads
 *
 * Requires root / CAP_SYS_NICE, CONFIG_SCHED_CLASS_EXT, and a running scx
 * scheduler with SCX_OPS_SWITCH_PARTIAL -- otherwise the kernel rejects the
 * policy change with EINVAL.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

/*
 * struct sched_attr as of ABI version 0 (ends at sched_period, 48 bytes on
 * 64-bit). Using the smallest version keeps this working on any kernel that
 * supports SCHED_EXT.
 */
struct sched_attr_v0 {
	uint32_t size;
	uint32_t sched_policy;
	uint64_t sched_flags;
	int32_t sched_nice;
	uint32_t sched_priority;
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;
};

static int opt_in(pid_t tid)
{
	struct sched_attr_v0 attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_EXT;

	if (syscall(SYS_sched_setattr, tid, &attr, 0) == 0) {
		printf("tid %d -> SCHED_EXT\n", tid);
		return 0;
	}

	err = errno;
	fprintf(stderr, "tid %d -> failed: %s\n", tid, strerror(err));
	if (err == EINVAL)
		fprintf(stderr, "  hint: needs CONFIG_SCHED_CLASS_EXT and a running "
				"scx scheduler with SCX_OPS_SWITCH_PARTIAL (--partial)\n");
	else if (err == EPERM)
		fprintf(stderr, "  hint: needs root or CAP_SYS_NICE\n");
	else if (err == ESRCH)
		fprintf(stderr, "  hint: thread is gone\n");
	return -1;
}

static int opt_in_pid(pid_t pid)
{
	char path[64];
	struct dirent *de;
	int failures = 0;
	DIR *dir;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "pid %d -> cannot open %s: %s\n",
			pid, path, strerror(errno));
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		pid_t tid;

		if (de->d_name[0] == '.')
			continue;
		tid = (pid_t)atoi(de->d_name);
		if (tid > 0 && opt_in(tid))
			failures++;
	}
	closedir(dir);
	return failures ? -1 : 0;
}

int main(int argc, char **argv)
{
	int all_threads = 0;
	int failures = 0;
	int i = 1;

	if (i < argc && strcmp(argv[i], "-a") == 0) {
		all_threads = 1;
		i++;
	}
	if (i >= argc) {
		fprintf(stderr, "usage: %s [-a] <tid|pid>...\n", argv[0]);
		return 2;
	}

	for (; i < argc; i++) {
		pid_t id = (pid_t)atoi(argv[i]);

		if (id <= 0) {
			fprintf(stderr, "invalid id: %s\n", argv[i]);
			failures++;
			continue;
		}
		if (all_threads ? opt_in_pid(id) : opt_in(id))
			failures++;
	}
	return failures ? 1 : 0;
}
