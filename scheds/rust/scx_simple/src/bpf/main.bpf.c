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

/* BSS counters, read live by userspace through the skeleton (non-static). */
u64 nr_local_q;         /* direct-dispatched to an idle CPU */
u64 nr_global_q;        /* queued on the shared DSQ */

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
	u64 *v = bpf_map_lookup_elem(&comm_slice, p->comm);
	return v ? *v : SCX_SLICE_DFL;
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
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (time_before(vtime, vtime_now - slice))
			vtime = vtime_now - slice;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime,
					 enq_flags);
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

		if (p->scx.slice < slice)
			p->scx.dsq_vtime += (slice - p->scx.slice) * 100 /
					     p->scx.weight;
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
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
