/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cluster: cluster-aware sched_ext scheduler based on scx_bpfland.
 * Distributes processes evenly across LLC (L3) clusters.
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include "intf.h"

/*
 * Maximum time a task can wait in the scheduler's queue before triggering
 * a stall.
 */
#define STARVATION_MS	5000ULL

#define MAX_CPUS	1024
#define MAX_WAKEUP_FREQ		64ULL
#define MAX_CLUSTERS		64

char _license[] SEC("license") = "GPL";

#define dbg_msg(_fmt, ...) do {				\
	if (debug)					\
		bpf_printk(_fmt, ##__VA_ARGS__);	\
} while(0)

const volatile bool debug;
const volatile u64 slice_max = 1ULL * NSEC_PER_MSEC;
const volatile u64 slice_min;
const volatile u64 slice_lag = 40ULL * NSEC_PER_MSEC;
const volatile bool no_wake_sync;
const volatile bool sticky_tasks = true;
const volatile bool local_kthreads = true;
const volatile bool local_pcpu = true;
volatile s64 cpufreq_perf_lvl;
const volatile bool preferred_idle_scan;
const volatile u64 preferred_cpus[MAX_CPUS];
const volatile u64 cpu_capacity[MAX_CPUS];
volatile u64 nr_kthread_dispatches, nr_direct_dispatches, nr_shared_dispatches;
volatile u64 nr_running;
volatile u64 nr_online_cpus;
static u64 nr_cpu_ids;
const volatile u64 throttle_ns;
static volatile bool cpus_throttled;
UEI_DEFINE(uei);

private(SCX_CLUSTER) struct bpf_cpumask __kptr *primary_cpumask;
const volatile bool primary_all = true;
const volatile u32 nr_clusters;
const volatile bool smt_enabled = true;
const volatile bool numa_enabled = true;
static u64 vtime_now;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 512);
} cpu_to_cluster_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_CLUSTERS);
} cluster_load_map SEC(".maps");

struct cluster_ctx {
	struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cluster_ctx);
	__uint(max_entries, MAX_CLUSTERS);
} cluster_ctx_stor SEC(".maps");

struct throttle_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct throttle_timer);
} throttle_timer SEC(".maps");

struct cpu_ctx {
	u64 tot_runtime;
	u64 prev_runtime;
	u64 last_running;
	u64 perf_lvl;
	struct bpf_cpumask __kptr *smt;
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
	u64 awake_vtime;
	u64 last_run_at;
	u64 wakeup_freq;
	u64 last_woke_at;
	u64 avg_runtime;
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

static inline u64 cpu_dsq(s32 cpu) { return cpu; }
static inline u64 node_dsq(s32 cpu)
{
	return nr_cpu_ids + __COMPAT_scx_bpf_cpu_node(cpu);
}

static inline bool is_kthread(const struct task_struct *p)
{
	return p->flags & PF_KTHREAD;
}

static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static inline bool is_deadline_min(const struct task_struct *p1, const struct task_struct *p2)
{
	if (!p1) return false;
	if (!p2) return true;
	return p1->scx.dsq_vtime < p2->scx.dsq_vtime;
}

static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_cpumask();
	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

static inline const struct cpumask *get_idle_smtmask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_smtmask();
	return __COMPAT_scx_bpf_get_idle_smtmask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

static inline bool is_cpu_valid(s32 cpu)
{
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);
	if (cpu < 0 || cpu >= max_cpu) {
		scx_bpf_error("invalid CPU id: %d", cpu);
		return false;
	}
	return true;
}

static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
	if (this_cpu == that_cpu) return true;
	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu)) return false;
	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}

static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
	if (this_cpu == that_cpu) return false;
	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu)) return false;
	return cpu_capacity[this_cpu] > cpu_capacity[that_cpu];
}

static s32 smt_sibling(s32 cpu)
{
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
	const struct cpumask *smt;
	if (!cctx) return cpu;
	smt = cast_mask(cctx->smt);
	if (!smt) return cpu;
	return bpf_cpumask_first(smt);
}

static bool is_smt_contended(s32 cpu)
{
	if (!smt_enabled) return false;
	const struct cpumask *idle_mask = get_idle_cpumask(cpu);
	bool is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
			    !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);
	return is_contended;
}

static inline bool is_wakeup(u64 wake_flags) { return wake_flags & SCX_WAKE_TTWU; }

static s32 find_least_loaded_cluster(const struct task_struct *p)
{
	u32 min_load = (u32)-1;
	s32 best_cluster = -1;
	s32 cpu;

	if (nr_clusters == 0) return -1;
	bpf_for(cpu, 0, nr_cpu_ids) {
		u32 *cid_ptr, *load_ptr;
		u32 cid, load;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		cid_ptr = bpf_map_lookup_elem(&cpu_to_cluster_map, (const u32 *)&cpu);
		if (!cid_ptr) continue;
		cid = *cid_ptr;
		if (cid >= nr_clusters) continue;
		load_ptr = bpf_map_lookup_elem(&cluster_load_map, &cid);
		if (!load_ptr) continue;
		load = *load_ptr;
		if (load < min_load) {
			min_load = load;
			best_cluster = (s32)cid;
		}
	}
	return best_cluster;
}

static const struct cpumask *get_cluster_cpumask(u32 cluster_id)
{
	struct cluster_ctx *cctx;
	if (cluster_id >= nr_clusters) return NULL;
	cctx = bpf_map_lookup_elem(&cluster_ctx_stor, &cluster_id);
	if (!cctx || !cctx->cpumask) return NULL;
	return cast_mask(cctx->cpumask);
}

static inline bool is_throttled(void) { return READ_ONCE(cpus_throttled); }
static inline void set_throttled(bool state) { WRITE_ONCE(cpus_throttled, state); }

static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
				  const struct cpumask *primary, const struct cpumask *smt)
{
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	bpf_for(i, 0, max_cpus) {
		s32 cpu = preferred_cpus[i];
		if ((cpu == prev_cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if ((!primary || bpf_cpumask_test_cpu(cpu, primary)) &&
		    (!smt || bpf_cpumask_test_cpu(cpu, smt)) &&
		    scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}
	return -EBUSY;
}

static s32 pick_idle_cpu_scan(struct task_struct *p, s32 prev_cpu,
			      const struct cpumask *restrict_cpumask)
{
	const struct cpumask *smt, *primary;
	bool is_prev_allowed = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	s32 cpu;

	primary = restrict_cpumask ? restrict_cpumask :
		  (!primary_all ? cast_mask(primary_cpumask) : NULL);
	smt = smt_enabled ? get_idle_smtmask(prev_cpu) : NULL;

	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out;
		}
	}

	if (primary) {
		if (smt_enabled) {
			cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);
			if (cpu >= 0) goto out;
		}
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, NULL);
		if (cpu >= 0) goto out;
	}

	if (smt_enabled) {
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, smt);
		if (cpu >= 0) goto out;
	}
	cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, NULL);

out:
	if (smt) scx_bpf_put_cpumask(smt);
	return cpu;
}

static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask = bpf_cpumask_create();
	if (!cpumask) return -ENOMEM;
	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask) bpf_cpumask_release(cpumask);
	return 0;
}

static u64 task_dl(struct task_struct *p, s32 cpu, struct task_ctx *tctx)
{
	const u64 STARVATION_THRESH = STARVATION_MS * NSEC_PER_MSEC / 10;
	const u64 q_thresh = MAX(STARVATION_THRESH / slice_max, 1);
	u64 nr_queued = scx_bpf_dsq_nr_queued(cpu_dsq(cpu)) + scx_bpf_dsq_nr_queued(node_dsq(cpu));
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 awake_max = scale_by_task_weight_inverse(p, slice_lag);
	u64 vtime_min;

	if (nr_queued * slice_max >= STARVATION_THRESH)
		lag_scale = 1;
	else
		lag_scale = MAX(lag_scale * q_thresh / (q_thresh + nr_queued), 1);
	vtime_min = vtime_now - scale_by_task_weight(p, slice_lag * lag_scale);
	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;
	if (time_after(tctx->awake_vtime, awake_max))
		tctx->awake_vtime = awake_max;
	return p->scx.dsq_vtime + tctx->awake_vtime;
}

static u64 task_slice(const struct task_struct *p, s32 cpu)
{
	u64 nr_wait = scx_bpf_dsq_nr_queued(cpu_dsq(cpu)) + scx_bpf_dsq_nr_queued(node_dsq(cpu));
	u64 slice = scale_by_task_weight(p, slice_max) / MAX(nr_wait, 1);
	return MAX(slice, slice_min);
}

static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags, bool from_enqueue,
			 const struct cpumask *restrict_cpumask)
{
	const struct cpumask *primary = cast_mask(primary_cpumask);
	s32 cpu;

	if (preferred_idle_scan)
		return pick_idle_cpu_scan(p, prev_cpu, restrict_cpumask);

	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	if (!restrict_cpumask && primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
	    is_cpu_faster(this_cpu, prev_cpu)) {
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    !is_smt_contended(prev_cpu) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
		prev_cpu = this_cpu;
	}

	if (!bpf_ksym_exists(scx_bpf_select_cpu_and)) {
		bool is_idle = false;
		if (from_enqueue) return -EBUSY;
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		return is_idle ? cpu : -EBUSY;
	}

	if (restrict_cpumask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, restrict_cpumask, 0);
		if (cpu >= 0) return cpu;
		return prev_cpu;
	}

	if (!primary_all && primary) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, primary, 0);
		if (cpu >= 0) return cpu;
	}
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

s32 BPF_STRUCT_OPS(cluster_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);
	s32 best_cluster;
	const struct cpumask *cluster_mask = NULL;

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	best_cluster = find_least_loaded_cluster(p);
	if (best_cluster >= 0)
		cluster_mask = get_cluster_cpumask((u32)best_cluster);

	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false, cluster_mask);
	if (cpu >= 0) {
		struct task_ctx *tctx = try_lookup_task_ctx(p);
		if (tctx) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), 0);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
		}
		return cpu;
	}
	return prev_cpu;
}

static bool is_task_sticky(const struct task_ctx *tctx)
{
	return sticky_tasks && tctx->avg_runtime < 10 * NSEC_PER_USEC;
}

static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) &&
	       (!sticky_tasks || !scx_bpf_task_running(p));
}

void BPF_STRUCT_OPS(cluster_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (!tctx) return;
	if (is_task_sticky(tctx)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}
	if (local_kthreads && is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		__sync_fetch_and_add(&nr_kthread_dispatches, 1);
		return;
	}
	if (is_pcpu_task(p)) {
		if (local_pcpu)
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p, prev_cpu), enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(prev_cpu),
						 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
		__sync_fetch_and_add(&nr_direct_dispatches, 1);
		return;
	}
	if (task_should_migrate(p, enq_flags)) {
		s32 cpu = is_pcpu_task(p) ?
			(scx_bpf_test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY) :
			pick_idle_cpu(p, prev_cpu, -1, 0, true, NULL);
		if (cpu >= 0) {
			scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu),
						 task_slice(p, cpu), task_dl(p, cpu, tctx), enq_flags);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			if (prev_cpu != cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}
	scx_bpf_dsq_insert_vtime(p, node_dsq(prev_cpu),
				 task_slice(p, prev_cpu), task_dl(p, prev_cpu, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_dispatches, 1);
	if (task_should_migrate(p, enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

static bool keep_running(const struct task_struct *p, s32 cpu)
{
	if (!is_task_queued(p)) return false;
	if (is_pcpu_task(p)) return true;
	if (is_smt_contended(cpu)) return false;
	return true;
}

static bool consume_first_task(u64 dsq_id, struct task_struct *p)
{
	if (!p) return false;
	return scx_bpf_dsq_move_to_local(dsq_id);
}

void BPF_STRUCT_OPS(cluster_dispatch, s32 cpu, struct task_struct *prev)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq(cpu));
	struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node_dsq(cpu));

	if (is_throttled()) return;
	if (!is_deadline_min(q, p)) {
		if (consume_first_task(cpu_dsq(cpu), p) || consume_first_task(node_dsq(cpu), q))
			return;
	} else {
		if (consume_first_task(node_dsq(cpu), q) || consume_first_task(cpu_dsq(cpu), p))
			return;
	}
	if (prev && keep_running(prev, cpu))
		prev->scx.slice = task_slice(prev, cpu);
}

static void update_cpu_load(struct task_struct *p, struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);
	u64 perf_lvl, delta_runtime, delta_t;

	if (!cctx) return;
	delta_t = now > cctx->last_running ? now - cctx->last_running : 1;
	delta_runtime = cctx->tot_runtime - cctx->prev_runtime;
	perf_lvl = MIN(delta_runtime * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	if (perf_lvl >= SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)
		perf_lvl = SCX_CPUPERF_ONE;
	cctx->perf_lvl = perf_lvl;
	if (cpufreq_perf_lvl < 0)
		scx_bpf_cpuperf_set(cpu, cctx->perf_lvl);
	cctx->last_running = now;
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
	if (!tctx) return;
	tctx->last_run_at = bpf_ktime_get_ns();

	cid_ptr = bpf_map_lookup_elem(&cpu_to_cluster_map, (const u32 *)&cpu);
	if (cid_ptr) {
		cluster_id = *cid_ptr;
		if (cluster_id < nr_clusters) {
			load_ptr = bpf_map_lookup_elem(&cluster_load_map, &cluster_id);
			if (load_ptr)
				__sync_fetch_and_add(load_ptr, 1);
		}
	}

	update_cpu_load(p, tctx);
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(cluster_stopping, struct task_struct *p, bool runnable)
{
	u64 now = bpf_ktime_get_ns(), slice, delta_vtime, delta_runtime;
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	struct cpu_ctx *cctx;
	u32 cluster_id;
	u32 *cid_ptr, *load_ptr;

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
	if (!tctx) return;
	slice = now - tctx->last_run_at;
	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);
	delta_vtime = scale_by_task_weight_inverse(p, slice);
	p->scx.dsq_vtime += delta_vtime;
	tctx->awake_vtime += delta_vtime;
	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx) return;
	delta_runtime = now - cctx->last_running;
	cctx->tot_runtime += delta_runtime;
}

void BPF_STRUCT_OPS(cluster_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (!tctx) return;
	tctx->awake_vtime = 0;
	delta_t = now > tctx->last_woke_at ? now - tctx->last_woke_at : 1;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, MAX_WAKEUP_FREQ);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(cluster_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(cluster_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
						     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx) return -ENOMEM;
	return 0;
}

static s32 get_nr_online_cpus(void)
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
	pmask = &cctx->smt;
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
	const struct cpumask *online_cpumask = scx_bpf_get_online_cpumask();
	u64 perf_lvl;
	s32 cpu;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, online_cpumask))
			continue;
		if (cpufreq_perf_lvl < 0)
			perf_lvl = SCX_CPUPERF_ONE;
		else
			perf_lvl = MIN(cpufreq_perf_lvl, SCX_CPUPERF_ONE);
		scx_bpf_cpuperf_set(cpu, perf_lvl);
	}
	scx_bpf_put_cpumask(online_cpumask);
}

static int throttle_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	bool throttled = is_throttled();
	u64 flags = throttled ? SCX_KICK_IDLE : SCX_KICK_PREEMPT;
	u64 duration = throttled ? slice_max : throttle_ns;
	s32 cpu;
	int err;

	set_throttled(!throttled);
	bpf_for(cpu, 0, nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, flags);
	err = bpf_timer_start(timer, duration, 0);
	if (err)
		scx_bpf_error("Failed to re-arm duty cycle timer");
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cluster_init)
{
	struct bpf_timer *timer;
	int err, i;
	u32 key = 0;

	nr_online_cpus = get_nr_online_cpus();
	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	init_cpuperf_target();

	bpf_for(i, 0, nr_cpu_ids) {
		int node = __COMPAT_scx_bpf_cpu_node(i);
		err = scx_bpf_create_dsq(i, node);
		if (err) {
			scx_bpf_error("failed to create DSQ %d: %d", i, err);
			return err;
		}
	}
	bpf_for(i, 0, __COMPAT_scx_bpf_nr_node_ids()) {
		u64 dsq_id = nr_cpu_ids + i;
		err = scx_bpf_create_dsq(dsq_id, i);
		if (err) {
			scx_bpf_error("failed to create DSQ %llu: %d", dsq_id, err);
			return err;
		}
	}

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	bpf_for(i, 0, nr_clusters) {
		struct cluster_ctx *cctx = bpf_map_lookup_elem(&cluster_ctx_stor, &i);
		struct bpf_cpumask *cpumask;

		if (!cctx) continue;
		cpumask = bpf_cpumask_create();
		if (!cpumask) continue;
		cpumask = bpf_kptr_xchg(&cctx->cpumask, cpumask);
		if (cpumask)
			bpf_cpumask_release(cpumask);
	}

	timer = bpf_map_lookup_elem(&throttle_timer, &key);
	if (timer && throttle_ns) {
		bpf_timer_init(timer, &throttle_timer, CLOCK_BOOTTIME);
		bpf_timer_set_callback(timer, throttle_timerfn);
		err = bpf_timer_start(timer, slice_max, 0);
		if (err)
			scx_bpf_error("Failed to arm throttle timer");
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
	       .enable       = (void *)cluster_enable,
	       .init_task    = (void *)cluster_init_task,
	       .init         = (void *)cluster_init,
	       .exit         = (void *)cluster_exit,
	       .timeout_ms   = STARVATION_MS,
	       .name         = "cluster");
