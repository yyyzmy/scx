/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_knobs: the CFS tuning trio, rebuilt on sched_ext.
 *
 * Based on scx_simple's global weighted vtime scheduling (weighted fair,
 * sleeper bonus capped at one slice); select_cpu() only direct-dispatches to
 * an idle CPU. With group_size set (the default), the global queue is split
 * into one vtime DSQ per group_size-CPU island, each drained only by its own
 * CPUs; group_size=0 keeps the single shared queue.
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
 *   preempt_comm    Non-empty => a waking task whose comm starts with this
 *                   string preempts the current runner immediately,
 *                   regardless of its banked vtime credit (the granularity
 *                   gate below is bypassed). Prefix match, so one value can
 *                   cover a thread family ("mock_io" matches mock_io0..3).
 *                   Empty => disabled. Like always_preempt this needs the
 *                   explicit kick below to take effect before the next tick.
 *
 *   group_size      Placement-group width in CPUs (0 => disabled, default 8).
 *                   Every group owns a private DSQ and only the CPUs of that
 *                   group drain it, so a queued task can only run inside its
 *                   own group -- the group is a scheduling island with its
 *                   own vtime queue, no cross-group lock contention. A waking
 *                   task prefers an idle CPU inside the group it last ran in,
 *                   and one group is learned per process from its first
 *                   thread so all threads of that process stay together.
 *                   There is no spillover: when the home group is full the
 *                   task waits in the group's DSQ (isolation over throughput).
 *                   Only a task whose affinity excludes its whole home group
 *                   falls back to the plain select_cpu_dfl placement.
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
 *   nr_wakeup_preempt: enqueues that carried SCX_ENQ_PREEMPT via the credit gate
 *   nr_named_preempt: wakeups by a preempt_comm-matching task (gate bypassed)
 *   nr_kick: explicit SCX_KICK_PREEMPT IPIs sent to force the switch now
 *   nr_local_q / nr_global_q: direct-dispatched vs shared-DSQ queued
 */
#include <scx/common.bpf.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char _license[] SEC("license") = "GPL";

volatile u64 slice_ns;       /* ~ sched_min_granularity_ns, 0 => SCX_SLICE_DFL */
volatile u64 period_ns;      /* ~ sched_latency_ns, 0 => static slice mode */
volatile u64 wakeup_gran_ns; /* ~ sched_wakeup_granularity_ns */
volatile u64 always_preempt; /* 1 = every waking task preempts (gate bypassed) */
volatile u64 no_switch;      /* 1 = run-to-completion: SCX_SLICE_INF, no preempt */
volatile char preempt_comm[TASK_COMM_LEN]; /* comm prefix allowed to preempt on wakeup */
volatile u64 group_size;     /* CPUs per placement group, 0 => plain dfl placement */

#define GROUP_MAX 64
#define GROUPS_MAX 128		/* group DSQs created at init (1024 CPUs @ 8) */

/*
 * Preferred placement group per process, learned from its first thread.
 * The value stores a representative *home CPU*, not a group index: a
 * group index silently re-means something else every time group_size is
 * changed at runtime (e.g. an index learned under g=4 from CPU 76 maps to
 * nonexistent CPUs 152-159 once g=8), pinning the whole process to a group
 * it can never run on. Storing the CPU and dividing by the *current* gsize
 * on every lookup re-derives a group that always contains a real CPU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);	/* tgid */
	__type(value, u32);	/* home cpu (divided by current gsize on read) */
	__uint(max_entries, 65536);
} proc_group SEC(".maps");

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
/*
 * Named-thread wakeups go here instead of the per-group DSQ, and dispatch
 * drains it first. SCX_ENQ_PREEMPT only pends the target rq -- when it
 * finally reschedules, it picks whatever sits at the head of its queue by
 * vtime, which is often not the task that asked to preempt. A separate DSQ
 * that every CPU drains makes the kick land on the named task instead of on
 * some starved by-stander.
 */
#define PREEMPT_DSQ 1

/*
 * One DSQ per group_size-CPU island: group g owns GROUP_DSQ_BASE + g and
 * only the CPUs of group g pull from it. Tasks are queued in the group of
 * the CPU the kernel assigned them to, so a wakeup/requeue never waits for
 * CPUs that are not in its group -- and groups stop sharing a queue lock.
 * Groups past what init created (small group_size on a huge machine) fall
 * back to SHARED_DSQ, as does grouping-off mode.
 */
#define GROUP_DSQ_BASE 2

static u32 nr_group_dsqs;	/* group DSQs actually created, <= GROUPS_MAX */
static u32 nr_possible_cpus;	/* nr_cpu_ids, cached by knobs_init */
/*
 * Running tasks per group == busy CPUs in group g, maintained incrementally
 * by ops.running(+1) / ops.stopping(-1). Nothing consumes it yet -- this is
 * the load signal for placement decisions, added first so it can be watched
 * (userspace reads it live from the skeleton bss) before any policy starts
 * using it.
 *
 * NOT static on purpose: the skeleton's bss struct is generated from BTF and
 * only carries global-linkage variables (see slice_ns / the nr_* counters
 * for the pattern); static ones (vtime_now, nr_group_dsqs) are invisible to
 * userspace. Userspace zeroes this array on a group_size change -- entries
 * keyed under an old group width are meaningless (and the running/stopping
 * pair would otherwise drift on width changes).
 */
u32 group_load[GROUPS_MAX];

static __always_inline u64 group_dsq(u32 grp)
{
	return (u64)GROUP_DSQ_BASE + grp;
}

/* Queue that group @grp pulls from; SHARED_DSQ when that group has none. */
static __always_inline u64 queue_of(u32 grp)
{
	return grp < nr_group_dsqs ? group_dsq(grp) : (u64)SHARED_DSQ;
}

/* Effective group size: 0 => grouping disabled, otherwise clamped to 1..64. */
static __always_inline u64 gsize(void)
{
	u64 g = group_size;

	if (!g)
		return 0;
	return g > GROUP_MAX ? GROUP_MAX : g;
}

/* Number of groups that actually own CPUs under the current group_size. */
static __always_inline u32 nr_groups(void)
{
	u64 g = gsize();

	return (u32)((nr_possible_cpus + (u32)g - 1) / (u32)g);
}

u64 nr_sleep_stop;      /* voluntary: blocked */
u64 nr_slice_end_stop;  /* involuntary: slice exhausted */
u64 nr_preempt_stop;    /* involuntary: preempted early (slice > 0 left) */
u64 nr_wakeup_preempt;  /* enqueues that carried SCX_ENQ_PREEMPT via the gate */
u64 nr_named_preempt;   /* wakeups by a preempt_comm-matching task */
u64 nr_kick;            /* explicit SCX_KICK_PREEMPT IPIs */
u64 nr_local_q;         /* direct-dispatched to an idle CPU */
u64 nr_global_q;        /* queued on a DSQ (group queue or shared) */

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

/*
 * Slice for a task about to sit on @dsq: period mode divides the period by
 * the depth of the queue the task is actually queued on, which is now the
 * group queue instead of one global queue.
 */
static __always_inline u64 eff_slice_dsq(u64 dsq)
{
	u64 slice = slice_ns ? slice_ns : SCX_SLICE_DFL;

	if (no_switch)
		return SCX_SLICE_INF;

	if (period_ns) {
		u64 nr = scx_bpf_dsq_nr_queued(dsq) + 1;
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

/* Does @p's comm start with preempt_comm? Empty preempt_comm => never. */
static __always_inline bool is_preempt_task(struct task_struct *p)
{
	char comm[TASK_COMM_LEN];
	int i;

	if (!preempt_comm[0])
		return false;

	__builtin_memset(comm, 0, sizeof(comm));
	bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);

#pragma unroll
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (!preempt_comm[i])
			return i != 0;
		if (comm[i] != preempt_comm[i])
			return false;
	}
	return true;
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

/*
 * Idle CPU allowed for @p inside @grp, or -1 if the group is full.
 * @prev_cpu is tried first: cache-warm, and without it every wake scans
 * from the group head and all threads herd onto the group's low CPUs
 * (the first idle one wins), leaving the tail of the group unused.
 */
static __always_inline s32 pick_idle_in_group(struct task_struct *p, s32 prev_cpu,
					       u32 grp)
{
	u64 g = gsize();
	s32 base = (s32)(grp * g);
	int i;

	if (prev_cpu >= 0 && (u32)prev_cpu / (u32)g == grp) {
		if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
			bpf_printk("knobs: pid=%d(%s) prev-fast grp=%u prev=%d affinity-no",
				   p->pid, p->comm, grp, prev_cpu);
		} else if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			bpf_printk("knobs: pid=%d(%s) prev-fast grp=%u prev=%d IDLE->TAKE",
				   p->pid, p->comm, grp, prev_cpu);
			return prev_cpu;
		} else {
			bpf_printk("knobs: pid=%d(%s) prev-fast grp=%u prev=%d busy",
				   p->pid, p->comm, grp, prev_cpu);
		}
	} else if (prev_cpu >= 0) {
		bpf_printk("knobs: pid=%d(%s) prev-fast grp=%u prev=%d prev-not-in-grp",
			   p->pid, p->comm, grp, prev_cpu);
	}

	bpf_for(i, 0, GROUP_MAX) {
		s32 cpu;

		if (i >= (int)g)
			break;

		cpu = base + i;
		/* false for out-of-range CPUs too */
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			bpf_printk("knobs: pid=%d(%s) scan grp=%u cpu=%d no-affinity",
				   p->pid, p->comm, grp, cpu);
			continue;
		}
		if (!scx_bpf_test_and_clear_cpu_idle(cpu)) {
			bpf_printk("knobs: pid=%d(%s) scan grp=%u cpu=%d busy",
				   p->pid, p->comm, grp, cpu);
			continue;
		}
		bpf_printk("knobs: pid=%d(%s) scan grp=%u cpu=%d IDLE->TAKE",
			   p->pid, p->comm, grp, cpu);
		return cpu;
	}
	bpf_printk("knobs: pid=%d(%s) grp=%u group-full (-1)",
		   p->pid, p->comm, grp);
	return -1;
}

/*
 * Any CPU allowed for @p inside @grp, busy or idle. Used to pin a task to
 * its home group when no CPU there is idle: select_cpu returns it so that
 * enqueue queues the task on the group's own DSQ, where only the group's
 * CPUs can pick it up. -1 when the affinity mask has no overlap with the
 * group at all, in which case the caller must fall back to dfl placement
 * (a task that cannot run anywhere in its group cannot be held there).
 */
static __always_inline s32 any_cpu_in_group(struct task_struct *p, u32 grp)
{
	u64 g = gsize();
	s32 base = (s32)(grp * g);
	int i;

	bpf_for(i, 0, GROUP_MAX) {
		s32 cpu;

		if (i >= (int)g)
			break;

		cpu = base + i;
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}
	return -1;
}

/*
 * Group remembered for @p's process, learned from @cpu the first time the
 * process is seen so all of its unbound threads converge on one group.
 * The map stores @cpu itself; the group is re-derived with the *current*
 * gsize on every call so runtime group_size changes re-interpret it
 * sanely instead of mapping to a different (possibly empty) CPU range.
 */
static __always_inline u32 proc_group_of(struct task_struct *p, s32 cpu)
{
	u32 tgid = p->tgid;
	u32 home, *homep;

	homep = bpf_map_lookup_elem(&proc_group, &tgid);
	if (homep) {
		bpf_printk("knobs: pid=%d(%s) grp-lookup tgid=%d home_cpu=%d g=%llu grp=%u",
			   p->pid, p->comm, tgid, *homep, gsize(),
			   *homep / (u32)gsize());
		return *homep / (u32)gsize();
	}

	/*
	 * Learn in the group with the fewest busy CPUs (group_load[], O(1)
	 * reads maintained by ops.running/stopping) *among the groups the
	 * affinity mask can actually run in*, so processes forked in a
	 * burst do not all pile into one group. prev_cpu's group is the
	 * seeded tie winner (switching needs strictly more idleness), so a
	 * uniformly idle machine learns exactly where prev ran, as before.
	 *
	 * Two passes, for the verifier: pass 1 is a single plain bounded
	 * loop over CPUs building a 128-bit feasible-group bitmap, at most
	 * one cpumask kfunc per trip -- the same shape as the RELEARN loop
	 * that verifies fine; a kfunc inside a per-group loop is what blew
	 * the complexity limit in earlier attempts. Pass 2 scans groups
	 * touching only that bitmap and group_load[] -- zero kfuncs.
	 */
	home = (u32)cpu;
	{
		u64 g = gsize();
		u32 ng = nr_groups();
		u32 best_load = 0xffffffffU;
		s64 best_grp = -1;
		s64 seed_grp = -1;
		u64 feas_lo = 0, feas_hi = 0;
		u32 scan_end, nr_cpus;
		u64 grp;
		int i;

		/* pass 1: feasible-group bitmap (>= 1 allowed CPU each) */
		scan_end = ng * (u32)g;		/* CPUs owned by candidate groups */
		nr_cpus = (u32)scx_bpf_nr_cpu_ids();
		if (scan_end > nr_cpus)
			scan_end = nr_cpus;
		for (i = 0; i < 1024; i++) {		/* NR_CPUS hard bound */
			u64 grp_i;

			if (i >= (s32)scan_end)
				break;
			grp_i = (u64)i / g;
			if (grp_i >= GROUPS_MAX)
				break;
			/*
			 * one test per group: once a group's bit is set the
			 * rest of its CPUs cost nothing (common case: the
			 * mask is wide, the group's first CPU already matches)
			 */
			if (grp_i < 64) {
				if (feas_lo & (1ULL << grp_i))
					continue;
			} else {
				if (feas_hi & (1ULL << (grp_i - 64)))
					continue;
			}
			if (bpf_cpumask_test_cpu(i, p->cpus_ptr)) {
				if (grp_i < 64)
					feas_lo |= 1ULL << grp_i;
				else
					feas_hi |= 1ULL << (grp_i - 64);
			}
		}

		if (cpu >= 0 && bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			u64 pg = (u64)(u32)cpu / g;

			if (pg < ng && pg < nr_group_dsqs && pg < GROUPS_MAX) {
				seed_grp = (s64)pg;
				best_grp = seed_grp;
				best_load = group_load[pg & (GROUPS_MAX - 1)];
			}
		}

		/*
		 * pass 2: lightest feasible group. The & (GROUPS_MAX-1)
		 * mask re-establishes a full-register bound even where the
		 * 32-bit division above lost verifier precision: the AND is
		 * 64-bit, so the array index gets var_off=(0, 0x7f) no
		 * matter what the compare alone could prove.
		 */
		for (grp = 0; grp < GROUPS_MAX; grp++) {
			bool feas;
			u32 load;

			if (grp >= ng || grp >= nr_group_dsqs)
				break;		/* no candidate groups beyond */
			feas = grp < 64 ? (feas_lo & (1ULL << grp)) != 0 :
					  (feas_hi & (1ULL << (grp - 64))) != 0;
			load = group_load[grp & (GROUPS_MAX - 1)];
			if (feas && load < best_load) {
				best_load = load;
				best_grp = (s64)grp;
			}
		}

		if (best_grp >= 0 && best_grp != seed_grp) {
			s32 c = any_cpu_in_group(p, (u32)best_grp);

			if (c >= 0)
				home = (u32)c;
			/* winner is always feasible here; guard for safety */
		}
		/* best_grp == seed_grp: home stays prev_cpu, cache-warm */
	}

	/*
	 * prev_cpu can still be outside the affinity mask (a taskset'd
	 * child forked by an unbound shell inherits the shell's fork CPU
	 * as prev_cpu), which used to pin the whole process to a group it
	 * can never run on: every later wakeup then burned a full
	 * no-affinity scan before falling back to dfl. Fall back to the
	 * first affinity-allowed CPU instead.
	 */
	if (!bpf_cpumask_test_cpu((s32)home, p->cpus_ptr)) {
		s32 i, ok = -1;

		for (i = 0; i < 1024; i++) {		/* NR_CPUS hard bound */
			if (i >= (s32)scx_bpf_nr_cpu_ids())
				break;
			if (bpf_cpumask_test_cpu(i, p->cpus_ptr)) {
				ok = i;
				break;
			}
		}
		if (ok >= 0)
			home = (u32)ok;
	}

	{
		/*
		 * index masked (see pass 2): the compiler narrows the
		 * division to 32-bit ops, which lose verifier precision;
		 * the mask restores a full-register bound for the access
		 */
		u64 hgrp = (u64)home / gsize();
		u32 hload = 0;

		if (hgrp < GROUPS_MAX)
			hload = group_load[hgrp & (GROUPS_MAX - 1)];

		bpf_printk("knobs: pid=%d(%s) grp-LEARN tgid=%d from_cpu=%d home=%u g=%llu grp=%llu load=%u",
			   p->pid, p->comm, tgid, cpu, home, gsize(), hgrp, hload);
	}
	bpf_map_update_elem(&proc_group, &tgid, &home, BPF_NOEXIST);
	return home / (u32)gsize();
}

/* Hand @p to the CPU select_cpu returned, synchronously. */
static __always_inline void dispatch_local(struct task_struct *p, u64 dsq)
{
	u64 slice = eff_slice_dsq(dsq);

	__sync_fetch_and_add(&nr_local_q, 1);
	note_assigned_slice(p, slice);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
}

s32 BPF_STRUCT_OPS(knobs_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 dfl, cpu;
	u64 g = gsize();
	u32 grp;

	/*
	 * Group stickiness (hard isolation): keep a task inside the group of
	 * @g CPUs it last ran in, and keep all threads of one process inside
	 * the same group. The group is learned from the first thread's CPU and
	 * remembered per tgid, so unbound threads converge instead of
	 * scattering over the machine. There is no spillover: when the home
	 * group is full the task is pinned to a group CPU anyway and waits in
	 * the group's own DSQ, so a group behaves as a fixed little machine of
	 * its own and load never leaks across groups.
	 *
	 * Order matters: prev_cpu is probed alone *first*, so the common
	 * cache-warm hit never lets dfl claim (and possibly waste) an idle
	 * bit. dfl only runs when prev is busy, and its topology-aware pick is
	 * accepted only when it lands inside the home group; anything else it
	 * claims gets discarded, so the last resort is our own group scan.
	 */
	if (g && prev_cpu >= 0) {
		grp = proc_group_of(p, prev_cpu);

		/* 1. prev_cpu alone: cache-warm, no dfl claim when it hits */
		if ((u32)prev_cpu / (u32)g == grp &&
		    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			bpf_printk("knobs: pid=%d(%s) prev-first grp=%u prev=%d IDLE->TAKE",
				   p->pid, p->comm, grp, prev_cpu);
			dispatch_local(p, queue_of(grp));
			return prev_cpu;
		}

		/* 2. dfl: topology-aware, accepted only inside the group */
		dfl = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		if (is_idle && dfl >= 0 && (u32)dfl / (u32)g == grp) {
			bpf_printk("knobs: pid=%d(%s) select dfl-in-grp dfl=%d",
				   p->pid, p->comm, dfl);
			dispatch_local(p, queue_of(grp));
			return dfl;
		}

		/* 3. our own group scan (prev fast path re-prints busy) */
		cpu = pick_idle_in_group(p, prev_cpu, grp);
		if (cpu >= 0) {
			dispatch_local(p, queue_of(grp));
			return cpu;
		}

		/*
		 * Home group full: stay. Return a CPU inside the group
		 * so enqueue queues the task on the group's DSQ -- it
		 * waits for one of the group's CPUs instead of spilling
		 * to whatever idle CPU the rest of the machine has.
		 * prev_cpu if it is already home (cache-warm), else the
		 * first CPU of the group the affinity allows.
		 */
		if ((u32)prev_cpu / (u32)g == grp) {
			bpf_printk("knobs: pid=%d(%s) home-full stay prev=%d",
				   p->pid, p->comm, prev_cpu);
			return prev_cpu;
		}
		cpu = any_cpu_in_group(p, grp);
		if (cpu >= 0) {
			bpf_printk("knobs: pid=%d(%s) home-full first-legal cpu=%d",
				   p->pid, p->comm, cpu);
			return cpu;
		}
		/*
		 * Affinity excludes the whole home group (e.g. the
		 * task was re-taskset'ed to another group's CPUs):
		 * the old home is unreachable, every wakeup would burn
		 * a full no-affinity scan before falling back to dfl.
		 * Re-learn the home from the first CPU the affinity
		 * still allows, so the whole process converges on the
		 * new range instead. prev_cpu cannot be used here --
		 * it may be the fork CPU of an unbound shell, which
		 * is exactly how the unreachable home was learned in
		 * the first place.
		 */
		if (prev_cpu >= 0) {
			s32 i, ok = -1;

			bpf_for(i, 0, 1024) {		/* NR_CPUS hard bound */
				if (i >= (s32)scx_bpf_nr_cpu_ids())
					break;
				if (bpf_cpumask_test_cpu(i, p->cpus_ptr)) {
					ok = i;
					break;
				}
			}
			if (ok >= 0) {
				u32 tgid = p->tgid;
				u32 newhome = (u32)ok;

				bpf_map_update_elem(&proc_group, &tgid,
						    &newhome, BPF_ANY);
				bpf_printk("knobs: pid=%d(%s) home-RELEARN tgid=%d old_grp=%u new_home=%u grp=%u",
					   p->pid, p->comm, tgid, grp,
					   newhome, newhome / (u32)g);
				/*
				 * Pick an idle CPU in the new group
				 * right away; fall through to the
				 * normal full-group path when the
				 * new group is busy too, so the task
				 * still never lands on a CPU the
				 * affinity forbids.
				 */
				cpu = pick_idle_in_group(p, prev_cpu,
							 newhome / (u32)g);
				if (cpu >= 0) {
					dispatch_local(p,
						queue_of(newhome / (u32)g));
					return cpu;
				}
				if ((u32)prev_cpu / (u32)g == newhome / (u32)g) {
					bpf_printk("knobs: pid=%d(%s) home-full stay prev=%d (relearned)",
						   p->pid, p->comm, prev_cpu);
					return prev_cpu;
				}
				bpf_printk("knobs: pid=%d(%s) home-full first-legal cpu=%d (relearned)",
					   p->pid, p->comm, ok);
				return ok;
			}
		}
		/*
		 * affinity-excludes-home and relearn both failed (mask
		 * empty?): fall back to plain dfl placement, computed in
		 * step 2 above.
		 */
		bpf_printk("knobs: pid=%d(%s) affinity-excludes-home dfl=%d",
			   p->pid, p->comm, dfl);
		if (is_idle)
			dispatch_local(p, queue_of((u32)dfl / (u32)g));
		return dfl;
	}

	/* grouping off or no prev_cpu: plain dfl placement */
	dfl = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		dispatch_local(p, SHARED_DSQ);
	return dfl;
}

void BPF_STRUCT_OPS(knobs_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 g = gsize();
	u64 dsq = SHARED_DSQ;
	u64 slice, vtime = p->scx.dsq_vtime;
	u64 credit;

	/*
	 * Queue the task on the island holding its CPU: only that group's CPUs
	 * pull from it, so it can never be woken onto a group that does not
	 * have it, and each group gets its own DSQ lock instead of every CPU
	 * hammering one global queue.
	 */
	if (g)
		dsq = queue_of((u32)scx_bpf_task_cpu(p) / (u32)g);

	slice = eff_slice_dsq(dsq);
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
		scx_bpf_dsq_insert(p, dsq, slice, enq_flags);
		return;
	}

	/* cap sleeper bonus at one slice (scx_simple behavior) */
	if (time_before(vtime, vtime_now - slice))
		vtime = vtime_now - slice;

	/*
	 * Named-thread fast path: a waking task whose comm matches
	 * preempt_comm takes the CPU right away, no matter how much vtime
	 * credit it has banked. It goes to PREEMPT_DSQ (drained first by every
	 * CPU) so the kick below hands the CPU to *this* task rather than to
	 * whoever happens to have the lowest vtime in the target queue.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) && is_preempt_task(p)) {
		enq_flags |= SCX_ENQ_PREEMPT;
		__sync_fetch_and_add(&nr_named_preempt, 1);

		note_assigned_slice(p, slice);
		scx_bpf_dsq_insert(p, PREEMPT_DSQ, slice, enq_flags);
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&nr_kick, 1);
		return;
	}

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
	scx_bpf_dsq_insert_vtime(p, dsq, slice, vtime, enq_flags);

	/*
	 * Wake an idle group CPU to come collect. Idle CPUs do not poll the
	 * group DSQ: a CPU that went idle before this task was queued sleeps
	 * until something kicks it, so the task can only be picked up by one
	 * of the group's *busy* CPUs at their next dispatch point -- queued
	 * tasks herd between the busy CPUs while the idle ones sleep right
	 * through it. This matters most for SCX_ENQ_REENQ (slice-expiry
	 * re-enqueue), which never goes through select_cpu and thus never
	 * gets a chance at the idle CPUs. The picker's test_and_clear claims
	 * the CPU atomically, so concurrent enqueues wake different CPUs.
	 */
	if (g) {
		s32 idle = pick_idle_in_group(p, scx_bpf_task_cpu(p),
					      (u32)scx_bpf_task_cpu(p) / (u32)g);

		if (idle >= 0) {
			scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
			__sync_fetch_and_add(&nr_kick, 1);
		}
	}

	/*
	 * A DSQ insert only pends the target rq for resched. A task
	 * spinning in userspace does not check TIF_NEED_RESCHED until its
	 * next tick, so the "preemption" would land at the next tick or slice
	 * boundary -- i.e. it would look exactly like no preemption at all.
	 * Kick the target CPU to send the resched IPI and switch right now.
	 * The kick must come *after* the insert: the target CPU dispatches
	 * from the DSQ as soon as it handles the IPI, and must find the
	 * task already queued.
	 */
	if (enq_flags & SCX_ENQ_PREEMPT) {
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&nr_kick, 1);
	}
}

/*
 * Leftover queues with no CPU under the current group_size: raising the knob
 * at runtime merges groups and strands the higher-indexed queues, whose tasks
 * no CPU would ever pull again. Let any CPU drain them so those tasks run once
 * more and then requeue into a live queue. Costs one comparison when there is
 * nothing stranded, which is the normal case.
 */
static __always_inline bool drain_orphans(void)
{
	u32 live = nr_groups();
	u32 q;

	if (live >= nr_group_dsqs)
		return false;

	bpf_for(q, 0, GROUPS_MAX) {
		if (q >= nr_group_dsqs)
			break;
		if (q < live)
			continue;
		if (scx_bpf_dsq_move_to_local(group_dsq(q), 0))
			return true;
	}
	return false;
}

void BPF_STRUCT_OPS(knobs_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 g = gsize();

	/* Preemption targets first, they must never wait behind a queue. */
	if (scx_bpf_dsq_move_to_local(PREEMPT_DSQ, 0))
		return;

	/*
	 * Then the island's own queue. A CPU only ever pulls its own group's
	 * tasks, which is what pins the group to these CPUs. If that queue is
	 * empty, fall back to the shared queue (grouping-off mode, tasks whose
	 * group has no DSQ, and overflow from ineligible groups).
	 */
	if (g) {
		u64 dsq = queue_of((u32)cpu / (u32)g);

		if (dsq != SHARED_DSQ && scx_bpf_dsq_move_to_local(dsq, 0))
			return;
		if (drain_orphans())
			return;
	}
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
	u64 g = gsize();

	/*
	 * Busy-CPUs-per-group counter. Pairs with the dec in ops.stopping;
	 * task_cpu is the CPU the task is starting on, so this tracks
	 * running tasks per group.
	 *
	 * grp is computed and bounds-checked in full 64-bit registers on
	 * purpose: with 32-bit arithmetic the subreg division + compare
	 * bound only the low half of the register, and the array index
	 * scaling (a 64-bit shift) then sees unbounded upper bits --
	 * "math between map_value pointer and register with unbounded
	 * min value". Staying 64-bit end to end lets the branch bound the
	 * whole register before the scaled array access.
	 */
	if (g) {
		u64 grp = (u64)scx_bpf_task_cpu(p) / g;

		if (grp < GROUPS_MAX)
			__sync_fetch_and_add(&group_load[grp], 1);
	}

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
	u64 g = gsize();
	u64 assigned;

	/*
	 * pairs with the inc in ops.running; 64-bit grp for the verifier
	 * (see the comment there)
	 */
	if (g) {
		u64 grp = (u64)scx_bpf_task_cpu(p) / g;

		/*
		 * Guard against underflow: a task already running when the
		 * scheduler attaches (or when the array is zeroed on a
		 * group_size change) stops without a matching running. A
		 * missed dec leaves the count slightly high (harmless for a
		 * load heuristic); wrapping to 2^32-1 would make the group
		 * look permanently full.
		 */
		if (grp < GROUPS_MAX && group_load[grp])
			__sync_fetch_and_add(&group_load[grp], -1);
	}

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
	u32 nr_cpus = scx_bpf_nr_cpu_ids();
	u32 want = nr_cpus < GROUPS_MAX ? nr_cpus : GROUPS_MAX;
	s32 ret, i;

	nr_possible_cpus = nr_cpus;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;

	ret = scx_bpf_create_dsq(PREEMPT_DSQ, -1);
	if (ret)
		return ret;

	/*
	 * One DSQ per CPU here; runtime group_size then decides how many of
	 * them are actually used (nr_cpu_ids / group_size islands). Creating
	 * one per CPU caps small group_size on big machines without needing to
	 * know the knob's final value at load time -- groups past the created
	 * ones simply fall back to SHARED_DSQ.
	 */
	bpf_for(i, 0, GROUPS_MAX) {
		if (i >= (s32)want)
			break;
		ret = scx_bpf_create_dsq(group_dsq(i), -1);
		if (ret)
			return ret;
		nr_group_dsqs = i + 1;
	}
	return 0;
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
