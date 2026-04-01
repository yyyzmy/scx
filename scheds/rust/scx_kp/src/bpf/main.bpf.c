/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_kp: Short-task dense scheduler (independent implementation).
 *
 * Goal: improve throughput and turnaround time in short-burst intensive
 * workloads by using a cheap SRPT-like priority:
 *   - Maintain per-task avg_runtime via EWMA (updated on stopping).
 *   - Maintain per-task last_stop timestamp.
 *   - On enqueue, compute:
 *       rem_est_adj = clamp(avg_runtime + aging(wait), MAX_REM_EST)
 *       deadline_vtime = vtime_now + scale_by_task_weight_inverse(rem_est_adj)
 *     and insert into a global DSQ using deadline_vtime ordering.
 *
 * kp_enqueue_simple: 1 => minimal path (FIFO insert, local-first, no steal).
 * kp_simple_softirq_isolate: in simple mode, ksoftirqd -> SHARED_DSQ only.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Some schedulers rely on these time constants; ensure they exist here too. */
#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC 1000ULL
#endif
#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC (1000ULL * NSEC_PER_USEC)
#endif

/*
 * Two-level queueing for short-task-dense workloads:
 *  - per-CPU DSQ: first-choice for short bursts (improves cache locality and
 *    reduces global queue contention)
 *  - shared DSQ: fallback and long-task queue
 */
#define SHARED_DSQ 0
#define CPU_DSQ_BASE 1
#define MAX_CPUS 4096
static u64 nr_cpu_ids;

static __always_inline u64 cpu_dsq_id(s32 cpu)
{
	return (u64)CPU_DSQ_BASE + (u64)cpu;
}

/* EWMA parameters: new_avg = old*0.75 + new*0.25 */
static __always_inline u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

struct task_ctx {
	u64 last_run_at;
	u64 last_stop_at;
	u64 avg_runtime;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Global vtime baseline used for DSQ vtime accounting.
 * Updated on ops.running.
 */
static u64 vtime_now;

UEI_DEFINE(uei);

/* Tunables (runtime configurable from userspace via rodata). */
const volatile u64 kp_aging_div = 8ULL;
const volatile u64 kp_max_rem_est_ns = 200ULL * NSEC_PER_MSEC;
const volatile u64 kp_short_task_ns = 80ULL * NSEC_PER_USEC;
/* 0: default (avg/aging/vtime + steal); 1: simple minimal */
const volatile u64 kp_enqueue_simple = 0ULL;
/* simple mode: 1 => ksoftirqd never uses per-CPU DSQ (shared only) */
const volatile u64 kp_simple_softirq_isolate = 1ULL;

static __always_inline bool task_is_ksoftirqd(const struct task_struct *p)
{
	const char *c;

	if (!(p->flags & PF_KTHREAD))
		return false;
	c = p->comm;
	/* "ksoftirqd/…" */
	return c[0] == 'k' && c[1] == 's' && c[2] == 'o' && c[3] == 'f' &&
	       c[4] == 't' && c[5] == 'i' && c[6] == 'r' && c[7] == 'q' &&
	       c[8] == 'd';
}

static __always_inline struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static __always_inline struct task_ctx *get_or_create_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Ensure per-task state exists and initialize.
 */
s32 BPF_STRUCT_OPS(kp_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *tctx = get_or_create_task_ctx(p);

	if (!tctx)
		return -ENOMEM;

	/* Initialize to a reasonable default so the first enqueue has a rem_est. */
	if (!tctx->avg_runtime)
		tctx->avg_runtime = SCX_SLICE_DFL;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(kp_init)
{
	int err, cpu;

	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err)
		return err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > MAX_CPUS)
		nr_cpu_ids = MAX_CPUS;

	/* Create per-CPU DSQs to increase parallel enqueue/dequeue capacity. */
	bpf_for(cpu, 0, nr_cpu_ids) {
		err = scx_bpf_create_dsq(cpu_dsq_id(cpu), __COMPAT_scx_bpf_cpu_node(cpu));
		if (err)
			return err;
	}

	vtime_now = 0;

	return 0;
}

/*
 * Pick a CPU: prefer last cpu if it's idle, otherwise fall back to default.
 */
s32 BPF_STRUCT_OPS(kp_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	/* Ensure prev_cpu is usable for this task. */
	if (prev_cpu < 0 || !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = bpf_cpumask_first(p->cpus_ptr);

	if (prev_cpu >= 0 && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	return cpu;
}

/*
 * Update last stop timestamp and avg_runtime (EWMA) when the task leaves CPU.
 */
void BPF_STRUCT_OPS(kp_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now, slice;

	if (kp_enqueue_simple) {
		p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
		return;
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	now = bpf_ktime_get_ns();
	slice = now - tctx->last_run_at;
	tctx->avg_runtime = calc_avg(tctx->avg_runtime, slice);
	tctx->last_stop_at = now;
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

/*
 * Record run start time and advance vtime baseline.
 */
void BPF_STRUCT_OPS(kp_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	if (kp_enqueue_simple) {
		if (time_before(vtime_now, p->scx.dsq_vtime))
			vtime_now = p->scx.dsq_vtime;
		return;
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_run_at = bpf_ktime_get_ns();
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(kp_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

/*
 * Enqueue: compute an SRPT-like "predicted remaining" and use it as
 * ordering key via DSQ insert_vtime().
 */
void BPF_STRUCT_OPS(kp_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now, rem_est, wait, aging, rem_est_adj, deadline;
	u64 aging_div, max_rem_est_ns, short_task_ns;
	s32 prev_cpu;
	bool is_short;
	bool cpu_selected;

	if (kp_enqueue_simple) {
		if (kp_simple_softirq_isolate && task_is_ksoftirqd(p)) {
			scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
			return;
		}
		cpu_selected = __COMPAT_is_enq_cpu_selected(enq_flags);
		prev_cpu = scx_bpf_task_cpu(p);
		if (prev_cpu < 0 || !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
			prev_cpu = bpf_cpumask_first(p->cpus_ptr);
		if (prev_cpu >= 0 && (u64)prev_cpu < nr_cpu_ids) {
			scx_bpf_dsq_insert(p, cpu_dsq_id(prev_cpu), SCX_SLICE_DFL, enq_flags);
			if (!cpu_selected)
				scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
			return;
		}
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
		return;
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	now = bpf_ktime_get_ns();

	rem_est = tctx->avg_runtime;
	if (!rem_est)
		rem_est = SCX_SLICE_DFL;

	/* Aging: older tasks get effectively larger rem_est to avoid starvation. */
	wait = tctx->last_stop_at ? (now - tctx->last_stop_at) : 0;
	aging_div = kp_aging_div ? kp_aging_div : 1;
	max_rem_est_ns = kp_max_rem_est_ns ? kp_max_rem_est_ns : (200ULL * NSEC_PER_MSEC);
	short_task_ns = kp_short_task_ns ? kp_short_task_ns : (80ULL * NSEC_PER_USEC);

	aging = wait / aging_div;
	rem_est_adj = rem_est + aging;

	/* Clamp rem_est_adj to keep arithmetic bounded for verifier. */
	if (rem_est_adj > max_rem_est_ns)
		rem_est_adj = max_rem_est_ns;

	deadline = vtime_now + scale_by_task_weight_inverse(p, rem_est_adj);
	is_short = rem_est_adj <= short_task_ns;

	/*
	 * Short-burst tasks prefer per-CPU DSQs to reduce global queue
	 * contention and improve locality. Long(er) tasks go through the
	 * shared queue.
	 */
	if (is_short) {
		prev_cpu = scx_bpf_task_cpu(p);
		if (prev_cpu < 0 || !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
			prev_cpu = bpf_cpumask_first(p->cpus_ptr);
		if (prev_cpu >= 0 && (u64)prev_cpu < nr_cpu_ids) {
			scx_bpf_dsq_insert_vtime(
				p,
				cpu_dsq_id(prev_cpu),
				SCX_SLICE_DFL,
				deadline,
				enq_flags
			);
			if (!__COMPAT_is_enq_cpu_selected(enq_flags))
				scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
			return;
		}
	}

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, deadline, enq_flags);
}

/*
 * Dispatch: move best task from shared DSQ to local DSQ for this CPU.
 */
void BPF_STRUCT_OPS(kp_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 src;

	/* 1) Own per-CPU queue first. */
	if ((u64)cpu < nr_cpu_ids && scx_bpf_dsq_move_to_local(cpu_dsq_id(cpu), 0))
		return;

	/* 2) Then shared queue. */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ, 0))
		return;

	if (kp_enqueue_simple)
		return;

	/* 3) Lightweight steal from other per-CPU queues. */
	bpf_for(src, 0, nr_cpu_ids) {
		if ((s32)src == cpu)
			continue;
		if (scx_bpf_dsq_move_to_local(cpu_dsq_id((s32)src), 0))
			return;
	}
}

/*
 * Runnable hook is not needed here: we use enqueue/stopping for burst
 * estimation and aging, keeping the ops set smaller.
 */

/*
 * Scheduler exit callback.
 */
void BPF_STRUCT_OPS(kp_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(kp_ops,
	       .select_cpu		= (void *)kp_select_cpu,
	       .enqueue			= (void *)kp_enqueue,
	       .dispatch		= (void *)kp_dispatch,
	       .running			= (void *)kp_running,
	       .stopping		= (void *)kp_stopping,
	       .enable			= (void *)kp_enable,
	       .init_task		= (void *)kp_init_task,
	       .init			= (void *)kp_init,
	       .exit			= (void *)kp_exit,
	       .timeout_ms		= 5000,
	       .name			= "kp");
