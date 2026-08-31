/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_partial: Partial scheduler that only takes over specific tasks
 *              and restricts them to run on CPU 80-87.
 *
 * Goal: minimize context switches for managed tasks.
 *  - Very long time slice (tunable, default 100ms)
 *  - Per-CPU DSQ for strong prev_cpu affinity (no migration)
 *  - No cross-CPU stealing
 *  - Stop-reason statistics for observability
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC (1000ULL * 1000ULL)
#endif

/* CPU range for restricted tasks: 80-87 */
#define PARTIAL_CPU_MIN 80
#define PARTIAL_CPU_MAX 87

/* DSQ layout: per-CPU DSQs for strong affinity, shared DSQ as fallback */
#define SHARED_DSQ 0
#define CPU_DSQ_BASE 1

static __always_inline u64 cpu_dsq_id(s32 cpu)
{
	return (u64)CPU_DSQ_BASE + (u64)cpu;
}

static __always_inline bool cpu_in_range(s32 cpu)
{
	return cpu >= PARTIAL_CPU_MIN && cpu <= PARTIAL_CPU_MAX;
}

struct task_ctx {
	u64 last_run_at;
	u64 avg_runtime;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

struct partial_stats {
	u32 nr_managed;
	u32 nr_init;
	u32 nr_exit;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct partial_stats);
} partial_stats_stor SEC(".maps");

/*
 * Stop-reason counters (read from userspace via BSS):
 *  - nr_sleep_stop:     voluntary sleep (runnable=false)
 *  - nr_slice_end_stop: time slice exhausted
 *  - nr_preempt_stop:   preempted early (slice > 0)
 */
u64 nr_sleep_stop;
u64 nr_slice_end_stop;
u64 nr_preempt_stop;
u64 nr_dispatches;

/*
 * Tunables:
 *  - partial_slice_ns: time slice for managed tasks (default 100ms).
 *    Very long to minimize slice-expiry context switches.
 */
const volatile u64 partial_slice_ns = 100ULL * NSEC_PER_MSEC;

UEI_DEFINE(uei);

static __always_inline struct partial_stats *get_partial_stats(void)
{
	u32 key = 0;
	return bpf_map_lookup_elem(&partial_stats_stor, &key);
}

static __always_inline struct task_ctx *get_or_create_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(partial_init_task, struct task_struct *p,
                             struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct partial_stats *stats;

	tctx = get_or_create_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	tctx->avg_runtime = SCX_SLICE_DFL;
	tctx->last_run_at = 0;

	stats = get_partial_stats();
	if (stats) {
		__sync_fetch_and_add(&stats->nr_managed, 1);
		__sync_fetch_and_add(&stats->nr_init, 1);
	}

	return 0;
}

/*
 * Select CPU: strong prev_cpu affinity to avoid migration.
 * Only pick a different CPU if prev_cpu is unavailable.
 */
s32 BPF_STRUCT_OPS(partial_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	/* Validate prev_cpu: must be in range and allowed for this task */
	if (prev_cpu < 0 || !cpu_in_range(prev_cpu) ||
	    !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		/* Scan 80-87 for an idle CPU */
		bpf_for(cpu, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			if (scx_bpf_test_and_clear_cpu_idle(cpu))
				return cpu;
		}
		/* No idle CPU found, return first allowed in range */
		bpf_for(cpu, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
			if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				return cpu;
		}
		return prev_cpu;
	}

	/* prev_cpu is valid and in range: reuse it if idle */
	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	/* Not idle but still in range: keep it (no migration) */
	return prev_cpu;
}

void BPF_STRUCT_OPS(partial_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;

	tctx->last_run_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(partial_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now, slice;

	/* Classify stop reason for statistics */
	if (!runnable)
		__sync_fetch_and_add(&nr_sleep_stop, 1);
	else if (p->scx.slice == 0)
		__sync_fetch_and_add(&nr_slice_end_stop, 1);
	else
		__sync_fetch_and_add(&nr_preempt_stop, 1);

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	if (tctx->last_run_at) {
		slice = now - tctx->last_run_at;
		tctx->avg_runtime = (tctx->avg_runtime - (tctx->avg_runtime >> 2)) + (slice >> 2);
	}
}

void BPF_STRUCT_OPS(partial_enable, struct task_struct *p)
{
}

void BPF_STRUCT_OPS(partial_disable, struct task_struct *p)
{
	struct partial_stats *stats = get_partial_stats();
	if (stats) {
		__sync_fetch_and_sub(&stats->nr_managed, 1);
		__sync_fetch_and_add(&stats->nr_exit, 1);
	}
}

/*
 * Enqueue: insert into prev_cpu's per-CPU DSQ for strong affinity.
 * The long time slice keeps the task running without frequent re-enqueues.
 */
void BPF_STRUCT_OPS(partial_enqueue, struct task_struct *p, u64 enq_flags)
{
	bool cpu_selected;
	s32 prev_cpu, cpu;
	u64 slice;

	cpu_selected = __COMPAT_is_enq_cpu_selected(enq_flags);

	prev_cpu = scx_bpf_task_cpu(p);
	slice = partial_slice_ns ? partial_slice_ns : SCX_SLICE_DFL;

	/* Normal path: per-CPU DSQ on prev_cpu → only prev_cpu pulls it */
	if (prev_cpu >= 0 && cpu_in_range(prev_cpu) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		scx_bpf_dsq_insert(p, cpu_dsq_id(prev_cpu), slice, enq_flags);
		if (!cpu_selected && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		return;
	}

	/*
	 * First entry (prev_cpu out of range): scan 80-87 in order and
	 * take the first idle CPU → deterministic placement, no shared DSQ.
	 */
	bpf_for(cpu, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (!scx_bpf_test_and_clear_cpu_idle(cpu))
			continue;
		scx_bpf_dsq_insert(p, cpu_dsq_id(cpu), slice, enq_flags);
		if (!cpu_selected)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	/*
	 * No idle CPU in range: queue in order on the first allowed CPU
	 * (task waits for that CPU instead of migrating to a busy one).
	 */
	bpf_for(cpu, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		scx_bpf_dsq_insert(p, cpu_dsq_id(cpu), slice, enq_flags);
		if (!cpu_selected)
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	/* Affinity excludes 80-87 entirely: last-resort shared DSQ */
	scx_bpf_dsq_insert(p, SHARED_DSQ, slice, enq_flags);
}

/*
 * Dispatch: own CPU's DSQ first (strong affinity), then shared DSQ.
 * No cross-CPU stealing → tasks never migrate.
 */
void BPF_STRUCT_OPS(partial_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!cpu_in_range(cpu))
		return;

	__sync_fetch_and_add(&nr_dispatches, 1);

	/* 1) Own per-CPU queue (task stays here) */
	if (scx_bpf_dsq_move_to_local(cpu_dsq_id(cpu), 0))
		return;

	/* 2) Shared DSQ fallback */
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(partial_init)
{
	s32 cpu, err;

	/* Shared DSQ as fallback */
	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err)
		return err;

	/* Per-CPU DSQs for strong affinity */
	bpf_for(cpu, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
		err = scx_bpf_create_dsq(cpu_dsq_id(cpu), -1);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(partial_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(partial_ops,
               .select_cpu     = (void *)partial_select_cpu,
               .enqueue        = (void *)partial_enqueue,
               .dispatch       = (void *)partial_dispatch,
               .running        = (void *)partial_running,
               .stopping       = (void *)partial_stopping,
               .enable         = (void *)partial_enable,
               .disable        = (void *)partial_disable,
               .init_task      = (void *)partial_init_task,
               .init           = (void *)partial_init,
               .exit           = (void *)partial_exit,
               .timeout_ms     = 5000,
               .name           = "partial");
