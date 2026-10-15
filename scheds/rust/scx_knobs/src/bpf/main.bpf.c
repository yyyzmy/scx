/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_knobs: the CFS tuning trio, rebuilt on sched_ext.
 *
 * Based on scx_simple's global weighted vtime scheduling: every task is
 * queued on one shared vtime-priority DSQ (weighted fair, sleeper bonus
 * capped at one slice); select_cpu() only direct-dispatches to an idle CPU.
 *
 * Three runtime-tunable knobs (BSS, writable by userspace at any time):
 *
 *   slice_ns       ~ sched_min_granularity_ns
 *                   Base time slice (0 => SCX_SLICE_DFL) and the floor for
 *                   period mode.
 *
 *   period_ns      ~ sched_latency_ns
 *                   Scheduling period (0 => static slice mode). When set,
 *                   slice = period / (nr_queued + 1), clamped to
 *                   [slice_ns, period_ns]: deeper queues shrink per-task
 *                   slices so everyone runs once per period (the CFS
 *                   latency target), at the price of more switches.
 *
 *   wakeup_gran_ns ~ sched_wakeup_granularity_ns
 *                   A task banks vtime credit while it sleeps (capped at
 *                   one slice). A waking task may preempt the current
 *                   runner (SCX_ENQ_PREEMPT) only if its banked credit
 *                   exceeds this threshold. 0 => eager preemption (close
 *                   to CFS default); >= one slice => wakeup preemption
 *                   fully off (fewest involuntary switches).
 *
 * Switch attribution counters (userspace prints per-interval deltas):
 *   nr_sleep_stop / nr_slice_end_stop / nr_preempt_stop: voluntary vs
 *     involuntary split, aligned with /proc/<pid>/status semantics
 *   nr_wakeup_preempt: enqueues that carried SCX_ENQ_PREEMPT
 *   nr_local_q / nr_global_q: direct-dispatched vs shared-DSQ queued
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

volatile u64 slice_ns;       /* ~ sched_min_granularity_ns, 0 => SCX_SLICE_DFL */
volatile u64 period_ns;      /* ~ sched_latency_ns, 0 => static slice mode */
volatile u64 wakeup_gran_ns; /* ~ sched_wakeup_granularity_ns */

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

u64 nr_sleep_stop;      /* voluntary: blocked */
u64 nr_slice_end_stop;  /* involuntary: slice exhausted */
u64 nr_preempt_stop;    /* involuntary: preempted early (slice > 0 left) */
u64 nr_wakeup_preempt;  /* enqueues that carried SCX_ENQ_PREEMPT */
u64 nr_local_q;         /* direct-dispatched to an idle CPU */
u64 nr_global_q;        /* queued on the shared DSQ */

/* exact vtime charging needs the slice actually assigned to the task */
struct task_ctx {
	u64 slice_assigned;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static __always_inline u64 eff_slice(void)
{
	u64 slice = slice_ns ? slice_ns : SCX_SLICE_DFL;

	if (period_ns) {
		u64 nr = scx_bpf_dsq_nr_queued(SHARED_DSQ) + 1;
		u64 dyn_slice = period_ns / nr;

		if (dyn_slice < slice)		/* min-granularity floor */
			dyn_slice = slice;
		if (dyn_slice > period_ns)
			dyn_slice = period_ns;
		slice = dyn_slice;
	}
	return slice;
}

static __always_inline void note_assigned_slice(struct task_struct *p, u64 slice)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (tctx)
		tctx->slice_assigned = slice;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(knobs_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
						    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->slice_assigned = SCX_SLICE_DFL;
	return 0;
}

s32 BPF_STRUCT_OPS(knobs_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		u64 slice = eff_slice();

		__sync_fetch_and_add(&nr_local_q, 1);
		note_assigned_slice(p, slice);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(knobs_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 slice = eff_slice();
	u64 vtime = p->scx.dsq_vtime;
	u64 credit;

	__sync_fetch_and_add(&nr_global_q, 1);

	/* cap sleeper bonus at one slice (scx_simple behavior) */
	if (time_before(vtime, vtime_now - slice))
		vtime = vtime_now - slice;

	/*
	 * Wakeup granularity gate: a waking task may preempt the current
	 * runner only if the vtime credit it banked while sleeping exceeds
	 * the threshold. Credit is <= one slice, so a threshold >= one
	 * slice turns wakeup preemption off entirely. The s64 casts make
	 * recently-charged tasks (vtime > vtime_now) compare negative.
	 */
	credit = vtime_now - vtime;
	if ((enq_flags & SCX_ENQ_WAKEUP) && (s64)credit > (s64)wakeup_gran_ns) {
		enq_flags |= SCX_ENQ_PREEMPT;
		__sync_fetch_and_add(&nr_wakeup_preempt, 1);
	}

	note_assigned_slice(p, slice);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}

void BPF_STRUCT_OPS(knobs_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(knobs_running, struct task_struct *p)
{
	/*
	 * Global vtime progresses as tasks start executing. Racy on multiple
	 * CPUs; any error is contained and temporary (scx_simple semantics).
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(knobs_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	u64 assigned;

	/* switch attribution (global) */
	if (!runnable) {
		__sync_fetch_and_add(&nr_sleep_stop, 1);
	} else if (p->scx.slice == 0) {
		__sync_fetch_and_add(&nr_slice_end_stop, 1);
	} else {
		__sync_fetch_and_add(&nr_preempt_stop, 1);
	}

	/*
	 * Weight-scaled vtime charging (scx_simple formula), but based on
	 * the slice actually assigned instead of SCX_SLICE_DFL, so partial
	 * runs (preempted victims) are charged exactly. A yielding task has
	 * slice zeroed by the kernel and is charged a full slice, same
	 * tradeoff scx_simple documents.
	 */
	assigned = tctx ? tctx->slice_assigned : SCX_SLICE_DFL;
	if (assigned > p->scx.slice)
		p->scx.dsq_vtime +=
			(assigned - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(knobs_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(knobs_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(knobs_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(knobs_ops,
	       .select_cpu	= (void *)knobs_select_cpu,
	       .enqueue		= (void *)knobs_enqueue,
	       .dispatch	= (void *)knobs_dispatch,
	       .running		= (void *)knobs_running,
	       .stopping		= (void *)knobs_stopping,
	       .enable		= (void *)knobs_enable,
	       .init_task	= (void *)knobs_init_task,
	       .init		= (void *)knobs_init,
	       .exit		= (void *)knobs_exit,
	       .timeout_ms	= 30000,
	       .name		= "knobs");
