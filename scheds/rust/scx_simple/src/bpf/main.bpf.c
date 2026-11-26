/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

/* base fallback slice default: 2.8ms (comm_slice entries override per task) */
#define SLICE_BASE_DFL_NS 2800000ULL

/* runtime-adjustable base slice (BSS, non-static for skeleton visibility) */
u64 slice_base_ns;

/* BSS counters, read live by userspace through the skeleton (non-static). */
u64 nr_local_q;         /* direct-dispatched to an idle CPU */
u64 nr_global_q;        /* queued on the shared DSQ */
u64 nr_wakeup_preempt;  /* enqueues that armed SCX_ENQ_PREEMPT via the gate */
u64 nr_kick;            /* SCX_KICK_PREEMPT IPIs sent */

/* Wakeup preemption knobs (BSS, runtime-adjustable from userspace). */
u64 preempt_en;         /* 1 = waking tasks with credit may preempt */
u64 preempt_gran_ns;    /* wakeup granularity gate in wall ns (0 = eager) */
u64 vtrace;             /* 1 = print vtime decisions (enqueue/running/stopping) */
u64 nr_tick;            /* ops.tick invocations; VM steal makes this rate sag */
u64 tick_cpu;           /* with vtrace on, only this CPU prints TCK lines */

/*
 * Per-comm custom slices: exact task comm (16B, NUL-padded) -> slice in ns.
 * Set from userspace at runtime; lookup miss falls back to SCX_SLICE_DFL.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[16]);
	__type(value, u64);
	__uint(max_entries, 64);
} comm_slice SEC(".maps");

static u64 eff_slice(struct task_struct *p)
{
	char comm[16];

	__builtin_memcpy(comm, p->comm, sizeof(comm));
	u64 *v = bpf_map_lookup_elem(&comm_slice, comm);
	if (v)
		return *v;
	return slice_base_ns ? slice_base_ns : SLICE_BASE_DFL_NS;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		__sync_fetch_and_add(&nr_local_q, 1);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, eff_slice(p), 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 slice = eff_slice(p);

	__sync_fetch_and_add(&nr_global_q, 1);

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, slice, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can
		 * accumulate to one slice. The floor must use the same
		 * scaled units as vtime charges (a full slice costs
		 * slice * 100 / weight in stopping); using the raw slice
		 * value here banked ~10x one slice of credit at nice-0
		 * (weight 1024), letting sleepers stay parked behind the
		 * runner for ~10 slices after waking.
		 */
		u64 floor = vtime_now - slice * 100 / p->scx.weight;

		if (time_before(vtime, floor))
			vtime = floor;

		if (vtrace) {
			char comm[16];

			__builtin_memcpy(comm, p->comm, sizeof(comm));
			bpf_printk("ENQ %c%c %s old=%llu now=%llu floor=%llu new=%llu sl=%llu w=%u",
				   (enq_flags & SCX_ENQ_WAKEUP) ? 'W' : '-',
				   (enq_flags & SCX_ENQ_REENQ) ? 'R' : '-',
				   comm, p->scx.dsq_vtime, vtime_now, floor,
				   vtime, slice, p->scx.weight);
		}

		/*
		 * Wakeup preemption: a waking task with banked vtime
		 * credit may preempt the runner it lands on instead of
		 * waiting for that runner's slice to end. The credit is
		 * capped at one slice by the clamp above; multiplying by
		 * weight / 100 converts the scaled vtime credit back to
		 * wall-time ns, so the gate matches CFS wakeup
		 * granularity semantics.
		 */
		if (preempt_en && (enq_flags & SCX_ENQ_WAKEUP)) {
			u64 credit = vtime_now - vtime;

			if ((s64)credit > 0 &&
			    credit * p->scx.weight / 100 > preempt_gran_ns) {
				enq_flags |= SCX_ENQ_PREEMPT;
				__sync_fetch_and_add(&nr_wakeup_preempt, 1);
			}
		}

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime,
					 enq_flags);

		/*
		 * A DSQ insert only pends the target rq's resched; a task
		 * spinning in userspace does not act on it until its next
		 * tick. Kick the target CPU so the switch happens now.
		 * The kick must come after the insert: the IPI'd CPU
		 * dispatches from the DSQ immediately and must find the
		 * task already queued.
		 */
		if (enq_flags & SCX_ENQ_PREEMPT) {
			scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
			__sync_fetch_and_add(&nr_kick, 1);
		}
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	/* compat macro: newer kernels take (dsq_id, enq_flags); 0 = old behavior */
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	if (vtrace) {
		char comm[16];

		__builtin_memcpy(comm, p->comm, sizeof(comm));
		bpf_printk("RUN %s v=%llu now=%llu",
			   comm, p->scx.dsq_vtime, vtime_now);
	}

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 * Charge against the slice that was actually assigned (per-comm entry
	 * may have changed between insert and stop); guard against underflow.
	 */
	{
		u64 slice = eff_slice(p);

		if (p->scx.slice < slice) {
			u64 charge = (slice - p->scx.slice) * 100 /
				     p->scx.weight;

			p->scx.dsq_vtime += charge;
			if (vtrace) {
				char comm[16];

				__builtin_memcpy(comm, p->comm, sizeof(comm));
				bpf_printk("STP %s remain=%llu sl=%llu charge=%llu newv=%llu",
					   comm, (u64)p->scx.slice, slice,
					   charge, p->scx.dsq_vtime);
			}
		}
	}
}

/*
 * Tick probe. nr_tick counts every CPU's tick unconditionally: on a
 * healthy machine that is nr_cpus * HZ per second, and any shortfall is
 * wall time the guest never saw (VM steal / stalled vCPU). With vtrace
 * on, the one CPU named by tick_cpu also prints each tick with the
 * current task and its remaining slice: a multi-tick gap with a frozen
 * sl=, bracketed by RUN/STP for the same task, means the vCPU went away
 * mid-stint and the slice countdown froze with it.
 */
void BPF_STRUCT_OPS(simple_tick, s32 cpu, struct task_struct *idle)
{
	__sync_fetch_and_add(&nr_tick, 1);

	if (vtrace && cpu == (s32)tick_cpu) {
		struct task_struct *p = bpf_get_current_task_btf();
		char comm[16];
		u64 sl = p->scx.slice;

		__builtin_memcpy(comm, p->comm, sizeof(comm));
		bpf_printk("TCK %d cur=%s sl=%llu", cpu, comm, sl);
	}
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue		= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running		= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .tick			= (void *)simple_tick,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
