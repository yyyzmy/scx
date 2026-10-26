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
 *   always_preempt  1 => every enqueue carrying SCX_ENQ_WAKEUP preempts the
 *                   current runner unconditionally, bypassing the credit
 *                   gate below. The eager end of the spectrum: a task that
 *                   wakes up kicks whatever is running no matter how short
 *                   its sleep was (EEVDF-like immediate wakeup preemption).
 *                   Note this needs an explicit scx_bpf_kick_cpu() below:
 *                   SCX_ENQ_PREEMPT on its own only pends the target rq for
 *                   resched, and a task spinning in userspace sees that at
 *                   its next tick (up to 1/HZ) -- indistinguishable from
 *                   "waiting for the slice to end". The kick sends the IPI
 *                   and switches right away.
 *
 *   no_switch       1 => run-to-completion experiment: SCX_SLICE_INF and
 *                   wakeup preemption never armed. A task keeps its CPU
 *                   until it blocks or yields -- zero involuntary
 *                   switches, at the price of starving everything queued
 *                   behind it (the degenerate corner the three knobs
 *                   above exist to avoid). ops.tick rewrites the slice of
 *                   already-running tasks, so the freeze (and unfreeze)
 *                   takes effect within one kernel tick, not one slice.
 *
 * Switch attribution counters (userspace prints per-interval deltas):
 *   nr_sleep_stop / nr_slice_end_stop / nr_preempt_stop: voluntary vs
 *     involuntary split, aligned with /proc/<pid>/status semantics
 *   nr_wakeup_preempt: enqueues that carried SCX_ENQ_PREEMPT
 *   nr_kick: explicit SCX_KICK_PREEMPT IPIs sent to force the switch now
 *   nr_local_q / nr_global_q: direct-dispatched vs shared-DSQ queued
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

volatile u64 slice_ns;       /* ~ sched_min_granularity_ns, 0 => SCX_SLICE_DFL */
volatile u64 period_ns;      /* ~ sched_latency_ns, 0 => static slice mode */
volatile u64 wakeup_gran_ns; /* ~ sched_wakeup_granularity_ns */
volatile u64 always_preempt; /* 1 = every waking task preempts (gate bypassed) */
volatile u64 no_switch;      /* 1 = run-to-completion: SCX_SLICE_INF, no preempt */

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

u64 nr_sleep_stop;      /* voluntary: blocked */
u64 nr_slice_end_stop;  /* involuntary: slice exhausted */
u64 nr_preempt_stop;    /* involuntary: preempted early (slice > 0 left) */
u64 nr_wakeup_preempt;  /* enqueues that carried SCX_ENQ_PREEMPT */
u64 nr_kick;            /* explicit SCX_KICK_PREEMPT IPIs */
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

	if (no_switch)
		return SCX_SLICE_INF;

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

	if (no_switch) {
		/*
		 * Run-to-completion: infinite slice, FIFO order, and never
		 * SCX_ENQ_PREEMPT. The task owns its CPU until it blocks,
		 * yields, or the load goes away. Skip the vtime clamp and
		 * preempt gate below -- the credit cap uses slice arithmetic
		 * that would underflow with SCX_SLICE_INF.
		 */
		note_assigned_slice(p, slice);
		scx_bpf_dsq_insert(p, SHARED_DSQ, slice, enq_flags);
		return;
	}

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
	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    (always_preempt || (s64)credit > (s64)wakeup_gran_ns)) {
		enq_flags |= SCX_ENQ_PREEMPT;
		__sync_fetch_and_add(&nr_wakeup_preempt, 1);
	}

	note_assigned_slice(p, slice);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);

	/*
	 * A shared-DSQ insert only pends the target rq for resched. A task
	 * spinning in userspace does not check TIF_NEED_RESCHED until its
	 * next tick, so the "preemption" would land at the next tick or slice
	 * boundary -- i.e. it would look exactly like no preemption at all.
	 * Kick the target CPU to send the resched IPI and switch right now.
	 * The kick must come *after* the insert: the target CPU dispatches
	 * from SHARED_DSQ as soon as it handles the IPI, and must find the
	 * task already queued.
	 */
	if (enq_flags & SCX_ENQ_PREEMPT) {
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&nr_kick, 1);
	}
}

void BPF_STRUCT_OPS(knobs_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(knobs_tick, struct task_struct *p)
{
	/*
	 * Zero-latency knob application. A task's slice is stamped at enqueue
	 * time, so a knob change otherwise waits for the current slice to
	 * expire (up to one old slice). Rewrite the *remaining* slice of the
	 * running task every tick instead:
	 *
	 *   no_switch=1  -> extend to SCX_SLICE_INF: the freeze takes effect
	 *                   within one kernel tick instead of one slice.
	 *   no_switch=0  -> any task still carrying a (near-)INF remaining
	 *                   slice was frozen earlier; hand it a fresh normal
	 *                   slice so the off-transition is reversible too.
	 *                   (Detection by value: nothing legitimate exceeds
	 *                   SCX_SLICE_INF/2, and decrements since the last
	 *                   tick can only shave a tick's worth off INF.)
	 */
	if (no_switch) {
		p->scx.slice = SCX_SLICE_INF;
	} else if (p->scx.slice > SCX_SLICE_INF / 2) {
		p->scx.slice = slice_ns ? slice_ns : SCX_SLICE_DFL;
	}
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
	if (!no_switch && assigned > p->scx.slice)
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
	       .tick		= (void *)knobs_tick,
	       .running		= (void *)knobs_running,
	       .stopping		= (void *)knobs_stopping,
	       .enable		= (void *)knobs_enable,
	       .init_task	= (void *)knobs_init_task,
	       .init		= (void *)knobs_init,
	       .exit		= (void *)knobs_exit,
	       .timeout_ms	= 30000,
	       .name		= "knobs");
