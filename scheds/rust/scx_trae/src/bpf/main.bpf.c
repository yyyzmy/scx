/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_trae: Topology-aware scheduler
 *
 * Step 1: Topology-aware initialization
 *   - Compute domain (cpdom) = same NUMA + same LLC + same core type (big/little)
 *   - Distance-based neighbor relationships between cpdoms
 *   - Alternative cpdom ID (big <-> little counterpart in same NUMA+LLC)
 *   - SMT sibling detection
 *   - Per-cpdom DSQ creation on associated NUMA node
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define min(X, Y) (((X) < (Y)) ? (X) : (Y))

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u32 nr_cpu_ids;
const volatile u32 nr_cpus_onln;
const volatile u32 nr_cpdoms;
const volatile u32 nr_numas;

const volatile u16 cpu_capacity[TRAE_CPU_ID_MAX];
const volatile u8  cpu_big[TRAE_CPU_ID_MAX];
const volatile u32 cpu_sibling[TRAE_CPU_ID_MAX];
const volatile bool is_smt_active;

const volatile u64 slice_min_ns = TRAE_SLICE_MIN_NS;
const volatile u64 slice_max_ns = TRAE_SLICE_MAX_NS;

struct cpdom_ctx {
	u64	id;
	u64	alt_id;
	u8	numa_id;
	u8	llc_id;
	u8	is_big;
	u8	is_valid;
	u8	nr_neighbors[TRAE_CPDOM_MAX_DIST];
	u64	__cpumask[TRAE_CPU_ID_MAX / 64];
	u8	neighbor_ids[TRAE_CPDOM_MAX_DIST * TRAE_CPDOM_MAX_NR_PER_DIST];

	u8	is_stealer __attribute__((aligned(CACHELINE_SIZE)));
	u8	is_stealee;
	u16	nr_active_cpus;
	u32	load_invr;
	u32	nr_queued_task;
	u32	avg_util_wall_sum;
	u32	avg_util_invr_sum;
	u32	cap_sum_active_cpus;
};

struct cpdom_ctx cpdom_ctxs[TRAE_CPDOM_MAX_NR];

struct cpu_ctx {
	u32	cpu_id;
	u8	cpdom_id;
	u8	cpdom_alt_id;
	u8	numa_id;
	u8	llc_id;
	bool	is_online;
	bool	is_idle;
	bool	big_core;
	u16	max_capacity;
	u16	effective_capacity;

	volatile u64 est_stopping_clk;

	u64	avg_util_wall;
	u64	avg_util_invr;

	u64	tot_task_time_wall;
	u64	tot_task_time_invr;

	u64	idle_start_clk;
	u64	idle_total_wall;

	struct bpf_cpumask __kptr *tmp_a_mask;
	struct bpf_cpumask __kptr *tmp_o_mask;
	struct bpf_cpumask __kptr *tmp_l_mask;
	struct bpf_cpumask __kptr *tmp_i_mask;
	struct bpf_cpumask __kptr *tmp_t_mask;
	struct bpf_cpumask __kptr *tmp_t2_mask;
};

struct sys_stat {
	u64	avg_util_wall;
	u64	avg_util_invr;
	u64	slice_wall;
	u32	nr_queued_task;
	u32	nr_active;
	u32	nr_active_cpdoms;
	u32	nr_stealee;
	u64	last_update_clk;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct sys_stat);
	__uint(max_entries, 1);
} sys_stat_stor SEC(".maps");

struct update_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct update_timer);
} update_timer SEC(".maps");

private(TRAE) struct bpf_cpumask cpdom_cpumask[TRAE_CPDOM_MAX_NR];

private(TRAE) struct bpf_cpumask __kptr *active_cpumask;
private(TRAE) struct bpf_cpumask __kptr *ovrflw_cpumask;
private(TRAE) struct bpf_cpumask __kptr *big_cpumask;

static struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
}

static struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu_id);
}

static struct cpdom_ctx *get_cpdom_ctx(u32 cpdom_id)
{
	if (cpdom_id >= TRAE_CPDOM_MAX_NR)
		return NULL;
	return MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
}

static struct sys_stat *get_sys_stat(void)
{
	const u32 idx = 0;
	return bpf_map_lookup_elem(&sys_stat_stor, &idx);
}

static u64 trae_time_delta(u64 now, u64 prev)
{
	return now > prev ? now - prev : 0;
}

static __always_inline int cpumask_next_set_bit(u64 *cpumask)
{
	if (!*cpumask)
		return -ENOENT;
	int bit = ctzll(*cpumask);
	*cpumask &= *cpumask - 1;
	return bit;
}

static s64 get_neighbor_id(struct cpdom_ctx *cpdomc, int d, int i)
{
	if (d >= TRAE_CPDOM_MAX_DIST || i >= TRAE_CPDOM_MAX_NR_PER_DIST)
		return -ENOENT;
	return (s64)cpdomc->neighbor_ids[d * TRAE_CPDOM_MAX_NR_PER_DIST + i];
}

static u64 dom_to_dsq(u32 cpdom_id)
{
	return (u64)cpdom_id | ((u64)TRAE_DSQ_TYPE_DOM << TRAE_DSQ_TYPE_SHFT);
}

static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;
	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	return 0;
}

static int init_cpumasks(void)
{
	struct bpf_cpumask *active;
	int err = 0;

	bpf_rcu_read_lock();

	err = calloc_cpumask(&active_cpumask);
	active = active_cpumask;
	if (err || !active)
		goto out;

	err = calloc_cpumask(&ovrflw_cpumask);
	if (err)
		goto out;

	err = calloc_cpumask(&big_cpumask);
	if (err)
		goto out;

out:
	bpf_rcu_read_unlock();
	return err;
}

static int init_per_cpu_ctx(void)
{
	const struct cpumask *online_cpumask;
	struct cpdom_ctx *cpdomc;
	struct bpf_cpumask *active, *ovrflw, *big, *cd_cpumask;
	struct cpu_ctx *cpuc;
	int cpu, i, j, k, err = 0;

	bpf_rcu_read_lock();
	online_cpumask = scx_bpf_get_online_cpumask();

	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	big = big_cpumask;
	if (!active || !ovrflw || !big) {
		scx_bpf_error("Failed to prepare cpumasks.");
		err = -ENOMEM;
		goto unlock_out;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= TRAE_CPU_ID_MAX)
			break;

		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			err = -ESRCH;
			goto unlock_out;
		}

		err = calloc_cpumask(&cpuc->tmp_a_mask);
		if (err) goto unlock_out;
		err = calloc_cpumask(&cpuc->tmp_o_mask);
		if (err) goto unlock_out;
		err = calloc_cpumask(&cpuc->tmp_l_mask);
		if (err) goto unlock_out;
		err = calloc_cpumask(&cpuc->tmp_i_mask);
		if (err) goto unlock_out;
		err = calloc_cpumask(&cpuc->tmp_t_mask);
		if (err) goto unlock_out;
		err = calloc_cpumask(&cpuc->tmp_t2_mask);
		if (err) goto unlock_out;

		cpuc->cpu_id = cpu;
		cpuc->is_online = bpf_cpumask_test_cpu(cpu, online_cpumask);
		cpuc->max_capacity = cpu_capacity[cpu];
		cpuc->effective_capacity = cpuc->max_capacity;
		cpuc->big_core = cpu_big[cpu];
		cpuc->est_stopping_clk = 0;

		if (cpuc->big_core) {
			bpf_cpumask_set_cpu(cpu, big);
		}

		if (cpuc->is_online)
			bpf_cpumask_set_cpu(cpu, active);
	}

	bpf_for(i, 0, nr_cpdoms) {
		if (i >= TRAE_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [i]);
		cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [i]);
		if (!cpdomc || !cd_cpumask) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %d", i);
			err = -ESRCH;
			goto unlock_out;
		}
		if (!cpdomc->is_valid)
			continue;

		bpf_for(j, 0, TRAE_CPU_ID_MAX / 64) {
			u64 cpumask = cpdomc->__cpumask[j];
			bpf_for(k, 0, 64) {
				int bit = cpumask_next_set_bit(&cpumask);
				if (bit < 0)
					break;
				cpu = (j * 64) + bit;
				if (cpu >= nr_cpu_ids)
					break;

				cpuc = get_cpu_ctx_id(cpu);
				if (!cpuc) {
					scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
					err = -ESRCH;
					goto unlock_out;
				}
				cpuc->cpdom_id = (u8)cpdomc->id;
				cpuc->cpdom_alt_id = (u8)cpdomc->alt_id;
				cpuc->numa_id = cpdomc->numa_id;
				cpuc->llc_id = cpdomc->llc_id;

				if (bpf_cpumask_test_cpu(cpu, online_cpumask)) {
					bpf_cpumask_set_cpu(cpu, cd_cpumask);
					cpdomc->nr_active_cpus++;
					cpdomc->cap_sum_active_cpus += cpuc->effective_capacity;
				}
			}
		}
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= TRAE_CPU_ID_MAX)
			break;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			continue;
		bpf_printk("trae: cpu[%d] cpdom=%u alt=%u numa=%u llc=%u big=%d cap=%u",
			   cpu, cpuc->cpdom_id, cpuc->cpdom_alt_id,
			   cpuc->numa_id, cpuc->llc_id, cpuc->big_core,
			   cpuc->max_capacity);
	}

unlock_out:
	scx_bpf_put_cpumask(online_cpumask);
	bpf_rcu_read_unlock();
	return err;
}

static int init_cpdoms(void)
{
	struct cpdom_ctx *cpdomc;
	int i, err;

	bpf_for(i, 0, nr_cpdoms) {
		if (i >= TRAE_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [i]);
		if (!cpdomc) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %d", i);
			return -ESRCH;
		}
		if (!cpdomc->is_valid)
			continue;

		err = scx_bpf_create_dsq(dom_to_dsq(cpdomc->id),
					 cpdomc->numa_id);
		if (err) {
			scx_bpf_error("Failed to create DSQ for cpdom %llu on NUMA %d",
				      cpdomc->id, cpdomc->numa_id);
			return err;
		}
	}

	return 0;
}

static int update_timer_cb(void *map, int *key, struct bpf_timer *timer);

static int init_sys_stat(void)
{
	struct sys_stat *ss = get_sys_stat();
	struct update_timer *timer;
	u32 key = 0;
	int err;

	if (!ss)
		return -EINVAL;

	ss->last_update_clk = scx_bpf_now();
	ss->slice_wall = slice_max_ns;

	timer = bpf_map_lookup_elem(&update_timer, &key);
	if (!timer)
		return -EINVAL;

	err = bpf_timer_init(&timer->timer, &update_timer, CLOCK_MONOTONIC);
	if (err)
		return err;

	err = bpf_timer_set_callback(&timer->timer, update_timer_cb);
	if (err)
		return err;

	err = bpf_timer_start(&timer->timer, 10000000ULL, 0);
	return err;
}

static u32 dsq_to_cpdom(u64 dsq_id)
{
	return (u32)(dsq_id & ((1ULL << TRAE_DSQ_TYPE_SHFT) - 1));
}

s32 BPF_STRUCT_OPS(trae_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *cd_cpumask, *a_cpumask, *i_cpumask;
	const struct cpumask *idle_cpumask;
	s32 cpu_id = -1;

	if (p->flags & PF_KTHREAD) {
		cpu_id = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
		return cpu_id >= 0 ? cpu_id : prev_cpu;
	}

	cpuc = get_cpu_ctx_id(prev_cpu);
	if (!cpuc)
		return prev_cpu;

	bpf_rcu_read_lock();

	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpuc->cpdom_id]);
	a_cpumask = cpuc->tmp_a_mask;
	i_cpumask = cpuc->tmp_i_mask;
	if (!cd_cpumask || !a_cpumask || !i_cpumask) {
		bpf_rcu_read_unlock();
		return prev_cpu;
	}

	idle_cpumask = scx_bpf_get_idle_cpumask();

	bpf_cpumask_and(a_cpumask, cast_mask(cd_cpumask), p->cpus_ptr);
	bpf_cpumask_and(i_cpumask, cast_mask(a_cpumask), idle_cpumask);

	if (!bpf_cpumask_empty(cast_mask(i_cpumask))) {
		cpu_id = scx_bpf_pick_any_cpu(cast_mask(i_cpumask), 0);
		if (cpu_id >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max_ns, 0);
			scx_bpf_put_idle_cpumask(idle_cpumask);
			bpf_rcu_read_unlock();
			return cpu_id;
		}
	}

	if (!bpf_cpumask_empty(cast_mask(a_cpumask))) {
		cpu_id = scx_bpf_pick_any_cpu(cast_mask(a_cpumask), 0);
	}

	scx_bpf_put_idle_cpumask(idle_cpumask);
	bpf_rcu_read_unlock();

	if (cpu_id >= 0)
		return cpu_id;

	cpu_id = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
	return cpu_id >= 0 ? cpu_id : prev_cpu;
}

void BPF_STRUCT_OPS(trae_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc;
	struct bpf_cpumask *cd_cpumask;
	u32 cpdom_id;
	u64 dsq_id;
	s32 prev_cpu = scx_bpf_task_cpu(p);

	if (p->flags & PF_KTHREAD) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max_ns, enq_flags);
		return;
	}

	cpuc = get_cpu_ctx_id(prev_cpu);
	if (!cpuc) {
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_max_ns, enq_flags);
		return;
	}

	cpdom_id = cpuc->cpdom_id;

	bpf_rcu_read_lock();
	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (cd_cpumask &&
	    bpf_cpumask_intersects(cast_mask(cd_cpumask), p->cpus_ptr)) {
		bpf_rcu_read_unlock();
		dsq_id = dom_to_dsq(cpdom_id);
		scx_bpf_dsq_insert(p, dsq_id, slice_max_ns, enq_flags);
		return;
	}
	bpf_rcu_read_unlock();

	if (nr_cpdoms > 0) {
		int i;
		u32 limit = min(nr_cpdoms, TRAE_CPDOM_MAX_NR);
		bpf_rcu_read_lock();
		for (i = 0; i < TRAE_CPDOM_MAX_NR; i++) {
			if (i >= limit)
				break;
			cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [i]);
			if (!cd_cpumask)
				continue;
			if (bpf_cpumask_intersects(cast_mask(cd_cpumask), p->cpus_ptr)) {
				bpf_rcu_read_unlock();
				scx_bpf_dsq_insert(p, dom_to_dsq(i), slice_max_ns, enq_flags);
				return;
			}
		}
		bpf_rcu_read_unlock();
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_max_ns, enq_flags);
}

void BPF_STRUCT_OPS(trae_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cpuc;
	struct cpdom_ctx *cpdomc;
	u64 dsq_id;
	int d, i;
	s64 nr_nbr, nid;

	cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc) {
		scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL, 0);
		return;
	}

	dsq_id = dom_to_dsq(cpuc->cpdom_id);
	if (scx_bpf_dsq_move_to_local(dsq_id, 0))
		return;

	if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL, 0))
		return;

	cpdomc = get_cpdom_ctx(cpuc->cpdom_id);
	if (!cpdomc)
		return;

	for (d = 0; d < TRAE_CPDOM_MAX_DIST; d++) {
		nr_nbr = min(cpdomc->nr_neighbors[d], TRAE_CPDOM_MAX_NR_PER_DIST);
		if (nr_nbr == 0)
			break;

		for (i = 0; i < TRAE_CPDOM_MAX_NR_PER_DIST; i++) {
			if (i >= nr_nbr)
				break;

			nid = get_neighbor_id(cpdomc, d, i);
			if (nid < 0)
				continue;

			dsq_id = dom_to_dsq((u32)nid);
			if (scx_bpf_dsq_move_to_local(dsq_id, 0))
				return;
		}
	}
}

void BPF_STRUCT_OPS(trae_running, struct task_struct *p)
{
	struct cpu_ctx *cpuc;

	cpuc = get_cpu_ctx();
	if (!cpuc)
		return;

	cpuc->is_idle = false;
	cpuc->est_stopping_clk = scx_bpf_now();
}

void BPF_STRUCT_OPS(trae_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cpuc;
	u64 now, dur;

	cpuc = get_cpu_ctx();
	if (!cpuc)
		return;

	now = scx_bpf_now();
	dur = trae_time_delta(now, cpuc->est_stopping_clk);

	cpuc->tot_task_time_wall += dur;
	cpuc->est_stopping_clk = 0;
}

void BPF_STRUCT_OPS(trae_tick, struct task_struct *p)
{
}

void BPF_STRUCT_OPS(trae_enable, struct task_struct *p)
{
}

void BPF_STRUCT_OPS(trae_cpu_online, s32 cpu)
{
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
	struct bpf_cpumask *cd_cpumask, *active;

	if (!cpuc)
		return;

	cpuc->is_online = true;

	bpf_rcu_read_lock();

	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpuc->cpdom_id]);
	active = active_cpumask;
	if (cd_cpumask)
		bpf_cpumask_set_cpu(cpu, cd_cpumask);
	if (active)
		bpf_cpumask_set_cpu(cpu, active);

	bpf_rcu_read_unlock();
}

void BPF_STRUCT_OPS(trae_cpu_offline, s32 cpu)
{
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
	struct bpf_cpumask *cd_cpumask, *active;

	if (!cpuc)
		return;

	cpuc->is_online = false;

	bpf_rcu_read_lock();

	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpuc->cpdom_id]);
	active = active_cpumask;
	if (cd_cpumask)
		bpf_cpumask_clear_cpu(cpu, cd_cpumask);
	if (active)
		bpf_cpumask_clear_cpu(cpu, active);

	bpf_rcu_read_unlock();
}

void BPF_STRUCT_OPS(trae_update_idle, s32 cpu, bool idle)
{
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
	if (!cpuc)
		return;

	if (idle) {
		cpuc->is_idle = true;
		cpuc->idle_start_clk = scx_bpf_now();
	} else {
		cpuc->is_idle = false;
		if (cpuc->idle_start_clk) {
			u64 dur = trae_time_delta(scx_bpf_now(), cpuc->idle_start_clk);
			__sync_fetch_and_add(&cpuc->idle_total_wall, dur);
			cpuc->idle_start_clk = 0;
		}
	}
}

void BPF_STRUCT_OPS(trae_set_cpumask, struct task_struct *p,
		     const struct cpumask *cpumask)
{
}

s32 BPF_STRUCT_OPS_SLEEPABLE(trae_init_task, struct task_struct *p,
			      struct task_struct *parent)
{
	return 0;
}

void BPF_STRUCT_OPS(trae_exit_task, struct task_struct *p)
{
}

static int update_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	struct sys_stat *ss = get_sys_stat();
	struct cpu_ctx *cpuc;
	struct cpdom_ctx *cpdomc;
	u64 now, total_wall = 0, total_idle = 0;
	u32 nr_active = 0, nr_active_cpdoms = 0, nr_stealee = 0;
	int cpu, i;

	if (!ss)
		goto out;

	now = scx_bpf_now();

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= TRAE_CPU_ID_MAX)
			break;

		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc || !cpuc->is_online)
			continue;

		total_wall += ss->slice_wall;
		total_idle += cpuc->idle_total_wall;
		cpuc->idle_total_wall = 0;

		if (cpuc->tot_task_time_wall > 0)
			nr_active++;
	}

	if (total_wall > 0)
		ss->avg_util_wall = (total_wall - total_idle) * 100 / total_wall;
	else
		ss->avg_util_wall = 0;

	ss->nr_active = nr_active;

	bpf_for(i, 0, nr_cpdoms) {
		if (i >= TRAE_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [i]);
		if (!cpdomc || !cpdomc->is_valid)
			continue;

		if (cpdomc->nr_active_cpus > 0)
			nr_active_cpdoms++;

		cpdomc->is_stealer = false;
		cpdomc->is_stealee = false;

		if (cpdomc->nr_queued_task > 0 &&
		    cpdomc->avg_util_wall_sum > 50)
			cpdomc->is_stealee = true;

		if (cpdomc->nr_queued_task == 0 &&
		    cpdomc->avg_util_wall_sum < 50)
			cpdomc->is_stealer = true;

		if (cpdomc->is_stealee)
			nr_stealee++;
	}

	ss->nr_active_cpdoms = nr_active_cpdoms;
	ss->nr_stealee = nr_stealee;
	ss->last_update_clk = now;

out:
	bpf_timer_start(timer, 10000000ULL, 0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(trae_init)
{
	int err;

	err = init_cpumasks();
	if (err)
		return err;

	err = init_per_cpu_ctx();
	if (err)
		return err;

	err = init_cpdoms();
	if (err)
		return err;

	err = init_sys_stat();
	if (err)
		return err;

	bpf_printk("trae: topology initialized - %d cpdoms, %d cpus, %d numas, smt=%d",
		   nr_cpdoms, nr_cpus_onln, nr_numas, is_smt_active);

	return 0;
}

void BPF_STRUCT_OPS(trae_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(trae_ops,
	       .select_cpu		= (void *)trae_select_cpu,
	       .enqueue			= (void *)trae_enqueue,
	       .dispatch		= (void *)trae_dispatch,
	       .running			= (void *)trae_running,
	       .stopping		= (void *)trae_stopping,
	       .tick			= (void *)trae_tick,
	       .cpu_online		= (void *)trae_cpu_online,
	       .cpu_offline		= (void *)trae_cpu_offline,
	       .update_idle		= (void *)trae_update_idle,
	       .set_cpumask		= (void *)trae_set_cpumask,
	       .enable			= (void *)trae_enable,
	       .init_task		= (void *)trae_init_task,
	       .exit_task		= (void *)trae_exit_task,
	       .init			= (void *)trae_init,
	       .exit			= (void *)trae_exit,
	       .timeout_ms		= 30000U,
	       .name			= "trae",
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE);
