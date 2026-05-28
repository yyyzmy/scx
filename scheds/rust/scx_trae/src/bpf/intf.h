/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned short u16;
typedef int s32;
typedef unsigned u32;
typedef long long s64;
typedef unsigned long long u64;
#endif

#define CACHELINE_SIZE		64

#define TRAE_CPU_ID_MAX		512
#define TRAE_CPDOM_MAX_NR	128
#define TRAE_NUMA_MAX_NR	32
#define TRAE_CPDOM_MAX_DIST	3
#define TRAE_CPDOM_MAX_NR_PER_DIST 16

#define TRAE_SHIFT		10
#define TRAE_SCALE		(1ULL << TRAE_SHIFT)

#define TRAE_TIME_ONE_SEC	(1000ULL * 1000 * 1000)

#define TRAE_SLICE_MIN_NS	(500ULL * 1000)
#define TRAE_SLICE_MAX_NS	(5ULL * 1000 * 1000)

#define TRAE_DSQ_TYPE_SHFT	48
#define TRAE_DSQ_TYPE_DOM	2
#define TRAE_DSQ_TYPE_GLOBAL	3

#define TRAE_GLOBAL_DSQ		((u64)TRAE_DSQ_TYPE_GLOBAL << TRAE_DSQ_TYPE_SHFT)

struct sys_stat {
	u64	last_update_clk;
	u64	avg_util_wall;
	u64	avg_util_invr;
	u64	avg_svc_time_iwgt;
	u64	nr_queued_task;
	u64	slice_wall;
	u32	avg_lat_cri;
	u32	max_lat_cri;
	u32	thr_lat_cri;
	u32	min_perf_cri;
	u32	avg_perf_cri;
	u32	max_perf_cri;
	u32	thr_perf_cri;
	u32	nr_stealee;
	u32	nr_active;
	u32	nr_active_cpdoms;
	u64	nr_sched;
	u64	nr_preempt;
	u64	nr_perf_cri;
	u64	nr_lat_cri;
	u64	nr_x_migration;
	u64	nr_big;
	u64	nr_pc_on_big;
	u64	nr_lc_on_big;
	u64	nr_idle_select;
	u64	nr_nonidle_select;
	u64	nr_enqueue_local;
	u64	nr_enqueue_cpdom;
	u64	nr_enqueue_global;
};

#endif /* __INTF_H */
