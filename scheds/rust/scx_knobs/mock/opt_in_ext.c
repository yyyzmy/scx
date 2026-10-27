/* SPDX-License-Identifier: GPL-2.0 */
/*
 * opt_in_ext: move threads in and out of the SCHED_EXT policy (7) with
 * sched_setattr(2).
 *
 *   (default)  opt in: set SCHED_EXT so that a partial-takeover scx
 *              scheduler (SCX_OPS_SWITCH_PARTIAL, e.g. `scx_knobs --partial`)
 *              manages the thread; everything else stays on CFS.
 *   -r         restore: set SCHED_NORMAL again, handing the thread back to
 *              CFS. The current nice value is preserved.
 *   -a         treat each argument as a PID and act on all of its threads
 *              (otherwise every argument is taken as a TID).
 *
 * Usage:
 *   opt_in_ext [-r] <tid>...
 *   opt_in_ext [-r] -a <pid>...
 *
 * Opting in requires root / CAP_SYS_NICE, CONFIG_SCHED_CLASS_EXT, and a
 * running scx scheduler with SCX_OPS_SWITCH_PARTIAL -- otherwise the kernel
 * rejects the policy change with EINVAL.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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

static int set_policy(pid_t tid, int restore)
{
	const char *name = restore ? "SCHED_OTHER" : "SCHED_EXT";
	struct sched_attr_v0 attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);

	if (restore) {
		int nice;

		errno = 0;
		nice = getpriority(PRIO_PROCESS, (id_t)tid);
		if (nice == -1 && errno)
			nice = 0;	/* thread is gone; let the call report it */
		attr.sched_policy = SCHED_OTHER;	/* SCHED_NORMAL, value 0 */
		attr.sched_nice = nice;
	} else {
		attr.sched_policy = SCHED_EXT;
	}

	if (syscall(SYS_sched_setattr, tid, &attr, 0) == 0) {
		printf("tid %d -> %s\n", tid, name);
		return 0;
	}

	err = errno;
	fprintf(stderr, "tid %d -> %s failed: %s\n", tid, name, strerror(err));
	if (err == EINVAL)
		fprintf(stderr, "  hint: opting in needs CONFIG_SCHED_CLASS_EXT and a "
				"running scx scheduler with SCX_OPS_SWITCH_PARTIAL (--partial)\n");
	else if (err == EPERM)
		fprintf(stderr, "  hint: needs root or CAP_SYS_NICE\n");
	else if (err == ESRCH)
		fprintf(stderr, "  hint: thread is gone\n");
	return -1;
}

static int act_on_pid(pid_t pid, int restore)
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
		if (tid > 0 && set_policy(tid, restore))
			failures++;
	}
	closedir(dir);
	return failures ? -1 : 0;
}

int main(int argc, char **argv)
{
	int all_threads = 0;
	int failures = 0;
	int restore = 0;
	int i = 1;

	for (; i < argc; i++) {
		if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--restore"))
			restore = 1;
		else if (!strcmp(argv[i], "-a"))
			all_threads = 1;
		else
			break;
	}
	if (i >= argc) {
		fprintf(stderr, "usage: %s [-r] [-a] <tid|pid>...\n", argv[0]);
		return 2;
	}

	for (; i < argc; i++) {
		pid_t id = (pid_t)atoi(argv[i]);

		if (id <= 0) {
			fprintf(stderr, "invalid id: %s\n", argv[i]);
			failures++;
			continue;
		}
		if (all_threads ? act_on_pid(id, restore) : set_policy(id, restore))
			failures++;
	}
	return failures ? 1 : 0;
}
