/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cluster: cluster-aware scheduler based on scx_bpfland.
 * Distributes processes evenly across LLC (L3) clusters.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

const volatile bool debug;

#define MAX_TASK_WEIGHT		10000
#define MAX_WAKEUP_FREQ		1024
#define SHARED_DSQ		0
#define MAX_CLUSTERS		64

const volatile u64 slice_max = 20ULL * NSEC_PER_MSEC;
const volatile u64 slice_min = 1ULL * NSEC_PER_MSEC;
const volatile s64 slice_lag = 20ULL * NSEC_PER_MSEC;
const volatile bool no_preempt;
const volatile bool local_kthreads;
const volatile bool local_pcpu;
volatile s64 cpufreq_perf_lvl;

volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;
volatile u64 nr_running;
volatile u64 nr_online_cpus;
static u64 nr_cpu_ids;

UEI_DEFINE(uei);

/*
 * Number of clusters (LLC domains). Set from user space.
 */
const volatile u32 nr_clusters;

private(SCX_CLUSTER) struct bpf_cpumask __kptr *primary_cpumask;
const volatile bool smt_enabled = true;
static u64 vtime_now;

/*
 * Per-CPU cluster id. Indexed by cpu_id, value is cluster_id (0..nr_clusters-1).
 * Populated from user space at init.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 512);
} cpu_to_cluster_map SEC(".maps");

/*
 * Per-cluster running task count. Updated in running/stopping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CLUSTERS);
} cluster_load_map SEC(".maps");

/*
 * Per-cluster cpumask. Populated from user space at init.
 */
struct cluster_ctx {
	struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cluster_ctx);
	__uint(max_entries, MAX_CLUSTERS);
} cluster_ctx_stor SEC(".maps");

struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *l2_cpumask;
	struct bpf_cpumask __kptr *l3_cpumask;
	struct bpf_cpumask __kptr *scratch_cpumask; /* for cluster restriction in pick_idle_cpu */
	u64 exec_runtime;
	u64 last_run_at;
	u64 deadline;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static bool is_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask = bpf_cpumask_create();

	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);
	return 0;
}

static u64 nr_tasks_waiting(void)
{
	return scx_bpf_dsq_nr_queued(SHARED_DSQ) + 1;
}

static u64 scale_inverse_fair(const struct task_struct *p, u64 value)
{
	return value * 100 / p->scx.weight;
}

static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min = vtime_now - slice_max;

	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;
	tctx->deadline += scale_inverse_fair(p, tctx->exec_runtime);
	return tctx->deadline;
}

static void task_set_domain(struct task_struct *p, s32 cpu,
			    const struct cpumask *cpumask)
{
	struct bpf_cpumask *primary, *l2_domain, *l3_domain;
	struct bpf_cpumask *p_mask, *l2_mask, *l3_mask;
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;

	tctx = try_lookup_task_ctx(p);
	cctx = try_lookup_cpu_ctx(cpu);
	primary = primary_cpumask;
	if (!tctx || !cctx || !primary)
		return;

	l2_domain = cctx->l2_cpumask;
	l3_domain = cctx->l3_cpumask;
	if (!l2_domain)
		l2_domain = primary;
	if (!l3_domain)
		l3_domain = primary;

	p_mask = tctx->cpumask;
	l2_mask = tctx->l2_cpumask;
	l3_mask = tctx->l3_cpumask;
	if (!p_mask || !l2_mask || !l3_mask)
		return;

	bpf_cpumask_and(p_mask, cpumask, cast_mask(primary));
	bpf_cpumask_and(l2_mask, cast_mask(p_mask), cast_mask(l2_domain));
	bpf_cpumask_and(l3_mask, cast_mask(p_mask), cast_mask(l3_domain));
}

static bool is_wake_sync(const struct task_struct *p,
			 const struct task_struct *current,
			 s32 prev_cpu, s32 cpu, u64 wake_flags)
{
	if (wake_flags & SCX_WAKE_SYNC)
		return true;
	if (is_kthread(current) && (p->nr_cpus_allowed == 1) && (prev_cpu == cpu))
		return true;
	return false;
}

/*
 * Find the cluster id with minimum load among clusters that have at least
 * one CPU in the task's allowed set. Returns -1 if no valid cluster.
 */
static s32 find_least_loaded_cluster(const struct task_struct *p)
{
	u32 min_load = (u32)-1;
	s32 best_cluster = -1;
	s32 cpu;

	if (nr_clusters == 0)
		return -1;

	bpf_for(cpu, 0, nr_cpu_ids) {
		u32 *cid_ptr, *load_ptr;
		u32 cid, load;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		cid_ptr = bpf_map_lookup_elem(&cpu_to_cluster_map, (const u32 *)&cpu);
		if (!cid_ptr)
			continue;
		cid = *cid_ptr;
		if (cid >= nr_clusters)
			continue;

		load_ptr = bpf_map_lookup_elem(&cluster_load_map, &cid);
		if (!load_ptr)
			continue;
		load = *load_ptr;
		if (load < min_load) {
			min_load = load;
			best_cluster = (s32)cid;
		}
	}
	return best_cluster;
}

/*
 * Get the cpumask for a cluster. Returns NULL if invalid.
 */
static const struct cpumask *get_cluster_cpumask(u32 cluster_id)
{
	struct cluster_ctx *cctx;

	if (cluster_id >= nr_clusters)
		return NULL;
	cctx = bpf_map_lookup_elem(&cluster_ctx_stor, &cluster_id);
	if (!cctx || !cctx->cpumask)
		return NULL;
	return cast_mask(cctx->cpumask);
}

/*
 * Find an idle CPU, optionally restricted to preferred_cluster_mask.
 * When preferred_cluster_mask is non-NULL, we restrict the search to that cluster.
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle,
			 const struct cpumask *preferred_cluster_mask)
{
	const struct cpumask *idle_smtmask, *idle_cpumask;
	const struct cpumask *primary, *p_mask, *l2_mask, *l3_mask;
	const struct cpumask *eff_p_mask, *eff_l2_mask, *eff_l3_mask;
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;
	struct bpf_cpumask *scratch;
	bool is_prev_llc_affine = false;
	s32 cpu;

	*is_idle = false;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -ENOENT;

	primary = cast_mask(primary_cpumask);
	if (!primary)
		return -EINVAL;

	idle_smtmask = scx_bpf_get_idle_smtmask();
	idle_cpumask = scx_bpf_get_idle_cpumask();

	p_mask = cast_mask(tctx->cpumask);
	l2_mask = cast_mask(tctx->l2_cpumask);
	l3_mask = cast_mask(tctx->l3_cpumask);
	if (!p_mask || !l2_mask || !l3_mask) {
		cpu = -EINVAL;
		goto out_put_cpumask;
	}

	/* Optionally restrict to preferred cluster for load balancing */
	scratch = tctx->scratch_cpumask;
	if (preferred_cluster_mask && scratch) {
		bpf_cpumask_and(scratch, p_mask, preferred_cluster_mask);
		eff_p_mask = bpf_cpumask_empty(cast_mask(scratch)) ? p_mask : cast_mask(scratch);
		bpf_cpumask_and(scratch, l2_mask, preferred_cluster_mask);
		eff_l2_mask = bpf_cpumask_empty(cast_mask(scratch)) ? l2_mask : cast_mask(scratch);
		bpf_cpumask_and(scratch, l3_mask, preferred_cluster_mask);
		eff_l3_mask = bpf_cpumask_empty(cast_mask(scratch)) ? l3_mask : cast_mask(scratch);
	} else {
		eff_p_mask = p_mask;
		eff_l2_mask = l2_mask;
		eff_l3_mask = l3_mask;
	}

	cpu = bpf_get_smp_processor_id();
	if (is_wake_sync(p, current, cpu, prev_cpu, wake_flags)) {
		const struct cpumask *curr_l3_domain;
		struct cpu_ctx *cctx;
		bool share_llc, has_idle;

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx) {
			cpu = -EINVAL;
			goto out_put_cpumask;
		}
		curr_l3_domain = cast_mask(cctx->l3_cpumask);
		if (!curr_l3_domain)
			curr_l3_domain = primary;

		share_llc = bpf_cpumask_test_cpu(prev_cpu, curr_l3_domain);
		if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}
		if (!share_llc)
			task_set_domain(p, cpu, p->cpus_ptr);

		has_idle = bpf_cpumask_intersects(curr_l3_domain, idle_cpumask);
		if (has_idle && bpf_cpumask_test_cpu(cpu, eff_p_mask) &&
		    !(current->flags & PF_EXITING) &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	is_prev_llc_affine = bpf_cpumask_test_cpu(prev_cpu, eff_l3_mask);

	if (smt_enabled) {
		if (is_prev_llc_affine &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			*is_idle = true;
			goto out_put_cpumask;
		}
		cpu = scx_bpf_pick_idle_cpu(eff_l2_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
		cpu = scx_bpf_pick_idle_cpu(eff_l3_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
		cpu = scx_bpf_pick_idle_cpu(eff_p_mask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			*is_idle = true;
			goto out_put_cpumask;
		}
	}

	if (is_prev_llc_affine && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		*is_idle = true;
		goto out_put_cpumask;
	}

	cpu = scx_bpf_pick_idle_cpu(eff_l2_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}
	cpu = scx_bpf_pick_idle_cpu(eff_l3_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}
	cpu = scx_bpf_pick_idle_cpu(eff_p_mask, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
		*is_idle = true;
		goto out_put_cpumask;
	}

	if (is_prev_llc_affine) {
		cpu = prev_cpu;
		goto out_put_cpumask;
	}
	cpu = bpf_cpumask_any_distribute(eff_l3_mask);
	if (cpu >= nr_cpu_ids)
		cpu = prev_cpu;

out_put_cpumask:
	scx_bpf_put_cpumask(idle_cpumask);
	scx_bpf_put_cpumask(idle_smtmask);
	if (cpu < 0)
		cpu = prev_cpu;
	return cpu;
}

s32 BPF_STRUCT_OPS(cluster_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;
	s32 best_cluster;
	const struct cpumask *cluster_mask = NULL;

	/* Prefer the least-loaded cluster to evenly distribute processes */
	best_cluster = find_least_loaded_cluster(p);
	if (best_cluster >= 0)
		cluster_mask = get_cluster_cpumask((u32)best_cluster);

	cpu = pick_idle_cpu(p, prev_cpu, wake_flags, &is_idle, cluster_mask);
	if (is_idle && (local_pcpu || !scx_bpf_dsq_nr_queued(SHARED_DSQ))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, 0);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
	}
	return cpu;
}

static void kick_idle_cpu(const struct task_struct *p, const struct task_ctx *tctx)
{
	const struct cpumask *idle_cpumask;
	s32 cpu;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, idle_cpumask);
	scx_bpf_put_cpumask(idle_cpumask);
	if (cpu < nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static bool try_direct_dispatch(struct task_struct *p, struct task_ctx *tctx,
				u64 slice, u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_REENQ)
		return false;

	if (local_kthreads && is_kthread(p)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_max, enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return true;
	}

	if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
		s32 prev_cpu = scx_bpf_task_cpu(p);
		struct rq *rq = scx_bpf_cpu_rq(prev_cpu);

		if (!no_preempt && tctx->deadline < rq->curr->scx.dsq_vtime) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
					   slice, enq_flags | SCX_ENQ_PREEMPT);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return true;
		}
		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cpu) &&
		    (local_pcpu || !scx_bpf_dsq_nr_queued(SHARED_DSQ))) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice_max, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return true;
		}
		if (local_pcpu && p->nr_cpus_allowed == 1) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return true;
		}
	}
	return false;
}

void BPF_STRUCT_OPS(cluster_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 slice, deadline;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	deadline = task_deadline(p, tctx);
	slice = CLAMP(slice_max / nr_tasks_waiting(), slice_min, slice_max);

	if (try_direct_dispatch(p, tctx, slice, enq_flags))
		return;

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, deadline, enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
	kick_idle_cpu(p, tctx);
}

void BPF_STRUCT_OPS(cluster_dispatch, s32 cpu, struct task_struct *prev)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);

	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		return;
	if (prev && is_queued(prev) &&
	    primary && bpf_cpumask_test_cpu(cpu, primary))
		prev->scx.slice = slice_max;
}

static void update_cpuperf_target(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = scx_bpf_now();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_runtime, delta_t;
	struct cpu_ctx *cctx;

	if (cpufreq_perf_lvl >= 0)
		return;
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;
	delta_t = now - cctx->last_running;
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = delta_runtime * SCX_CPUPERF_ONE / delta_t;
	perf_lvl = MIN(perf_lvl, SCX_CPUPERF_ONE);
	scx_bpf_cpuperf_set(cpu, perf_lvl);
	cctx->last_running = scx_bpf_now();
	cctx->prev_runtime = cctx->tot_runtime;
}

void BPF_STRUCT_OPS(cluster_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	u32 cluster_id;
	u32 *cid_ptr, *load_ptr;

	__sync_fetch_and_add(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	tctx->last_run_at = scx_bpf_now();

	/* Update per-cluster load for even distribution */
	cid_ptr = bpf_map_lookup_elem(&cpu_to_cluster_map, (const u32 *)&cpu);
	if (cid_ptr) {
		cluster_id = *cid_ptr;
		if (cluster_id < nr_clusters) {
			load_ptr = bpf_map_lookup_elem(&cluster_load_map, &cluster_id);
			if (load_ptr)
				__sync_fetch_and_add(load_ptr, 1);
		}
	}

	update_cpuperf_target(p, tctx);
	if (time_before(vtime_now, tctx->deadline))
		vtime_now = tctx->deadline;
}

void BPF_STRUCT_OPS(cluster_stopping, struct task_struct *p, bool runnable)
{
	u64 now = scx_bpf_now(), slice;
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	u32 cluster_id;
	u32 *cid_ptr, *load_ptr;

	if (cpufreq_perf_lvl < 0) {
		cctx = try_lookup_cpu_ctx(cpu);
		if (cctx)
			cctx->tot_runtime += now - cctx->last_running;
	}

	/* Decrement per-cluster load */
	cid_ptr = bpf_map_lookup_elem(&cpu_to_cluster_map, (const u32 *)&cpu);
	if (cid_ptr) {
		cluster_id = *cid_ptr;
		if (cluster_id < nr_clusters) {
			load_ptr = bpf_map_lookup_elem(&cluster_load_map, &cluster_id);
			if (load_ptr)
				__sync_fetch_and_sub(load_ptr, 1);
		}
	}

	__sync_fetch_and_sub(&nr_running, 1);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	slice = bpf_ktime_get_ns() - tctx->last_run_at;
	if (tctx->exec_runtime < 10 * slice_max)
		tctx->exec_runtime += slice;
	tctx->deadline += scale_inverse_fair(p, slice);
}

void BPF_STRUCT_OPS(cluster_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (tctx)
		tctx->exec_runtime = 0;
}

void BPF_STRUCT_OPS(cluster_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

void BPF_STRUCT_OPS(cluster_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();

	task_set_domain(p, cpu, cpumask);
}

void BPF_STRUCT_OPS(cluster_enable, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (tctx)
		tctx->deadline = vtime_now;
}

s32 BPF_STRUCT_OPS(cluster_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l2_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->l3_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&tctx->scratch_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	task_set_domain(p, cpu, p->cpus_ptr);
	return 0;
}

s32 get_nr_online_cpus(void)
{
	const struct cpumask *online_cpumask = scx_bpf_get_online_cpumask();
	int cpus = bpf_cpumask_weight(online_cpumask);

	scx_bpf_put_cpumask(online_cpumask);
	return cpus;
}

static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask = *cpumask;

	if (mask)
		return 0;
	if (calloc_cpumask(cpumask))
		return -ENOMEM;
	return 0;
}

SEC("syscall")
int enable_cluster_cpu(struct cluster_cpu_arg *input)
{
	struct cluster_ctx *cctx;
	struct bpf_cpumask *mask;
	int err = 0;

	if (input->cluster_id < 0 || (u32)input->cluster_id >= nr_clusters)
		return -EINVAL;

	cctx = bpf_map_lookup_elem(&cluster_ctx_stor, (const u32 *)&input->cluster_id);
	if (!cctx)
		return -ENOENT;

	if (!cctx->cpumask) {
		mask = bpf_cpumask_create();
		if (!mask)
			return -ENOMEM;
		mask = bpf_kptr_xchg(&cctx->cpumask, mask);
		if (mask)
			bpf_cpumask_release(mask);
	}
	bpf_rcu_read_lock();
	mask = cctx->cpumask;
	if (mask && input->cpu_id >= 0)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();
	return err;
}

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;
	switch (input->lvl_id) {
	case 2:
		pmask = &cctx->l2_cpumask;
		break;
	case 3:
		pmask = &cctx->l3_cpumask;
		break;
	default:
		return -EINVAL;
	}
	err = init_cpumask(pmask);
	if (err)
		return err;
	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();
	return err;
}

SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;
	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask) {
		s32 cpu = input->cpu_id;

		if (cpu < 0)
			bpf_cpumask_clear(mask);
		else
			bpf_cpumask_set_cpu(cpu, mask);
	}
	bpf_rcu_read_unlock();
	return err;
}

static void init_cpuperf_target(void)
{
	const struct cpumask *online_cpumask;
	u64 perf_lvl;
	s32 cpu;

	if (cpufreq_perf_lvl < 0)
		return;
	online_cpumask = scx_bpf_get_online_cpumask();
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;
		perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cluster_init)
{
	int err;
	u32 i;
	struct cluster_ctx *cctx;
	struct bpf_cpumask *cpumask;

	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	init_cpuperf_target();

	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err) {
		scx_bpf_error("failed to create shared DSQ: %d", err);
		return err;
	}
	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	/* Create cpumask for each cluster (user space will fill them via enable_cluster_cpu) */
	bpf_for(i, 0, nr_clusters) {
		cctx = bpf_map_lookup_elem(&cluster_ctx_stor, &i);
		if (!cctx)
			continue;
		cpumask = bpf_cpumask_create();
		if (!cpumask)
			continue;
		cpumask = bpf_kptr_xchg(&cctx->cpumask, cpumask);
		if (cpumask)
			bpf_cpumask_release(cpumask);
	}
	return 0;
}

void BPF_STRUCT_OPS(cluster_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cluster_ops,
	       .select_cpu   = (void *)cluster_select_cpu,
	       .enqueue      = (void *)cluster_enqueue,
	       .dispatch     = (void *)cluster_dispatch,
	       .running      = (void *)cluster_running,
	       .stopping     = (void *)cluster_stopping,
	       .runnable     = (void *)cluster_runnable,
	       .cpu_release  = (void *)cluster_cpu_release,
	       .set_cpumask  = (void *)cluster_set_cpumask,
	       .enable       = (void *)cluster_enable,
	       .init_task    = (void *)cluster_init_task,
	       .init         = (void *)cluster_init,
	       .exit         = (void *)cluster_exit,
	       .flags        = SCX_OPS_ENQ_EXITING,
	       .timeout_ms   = 5000,
	       .name         = "cluster");
