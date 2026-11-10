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

/* Preferred placement group per process, learned from its first thread. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);	/* tgid */
	__type(value, u32);	/* group id = cpu / group_size */
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

	if (prev_cpu >= 0 && (u32)prev_cpu / (u32)g == grp &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	bpf_for(i, 0, GROUP_MAX) {
		s32 cpu;

		if (i >= (int)g)
			break;

		cpu = base + i;
		/* false for out-of-range CPUs too */
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (!scx_bpf_test_and_clear_cpu_idle(cpu))
			continue;
		return cpu;
	}
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
 */
static __always_inline u32 proc_group_of(struct task_struct *p, s32 cpu)
{
	u32 tgid = p->tgid;
	u32 grp, *grpp;

	grpp = bpf_map_lookup_elem(&proc_group, &tgid);
	if (grpp)
		return *grpp;

	grp = (u32)cpu / (u32)gsize();
	bpf_map_update_elem(&proc_group, &tgid, &grp, BPF_NOEXIST);
	return grp;
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

	dfl = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	/*
	 * Group stickiness (hard isolation): keep a task inside the group of
	 * @g CPUs it last ran in, and keep all threads of one process inside
	 * the same group. The group is learned from the first thread's CPU and
	 * remembered per tgid, so unbound threads converge instead of
	 * scattering over the machine. There is no spillover: when the home
	 * group is full the task is pinned to a group CPU anyway and waits in
	 * the group's own DSQ, so a group behaves as a fixed little machine of
	 * its own and load never leaks across groups.
	 */
	if (g && prev_cpu >= 0) {
		grp = proc_group_of(p, prev_cpu);

		/* dfl already gave us an idle CPU in the wanted group */
		if (!(is_idle && dfl >= 0 && (u32)dfl / (u32)g == grp)) {
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
			if ((u32)prev_cpu / (u32)g == grp)
				return prev_cpu;
			cpu = any_cpu_in_group(p, grp);
			if (cpu >= 0)
				return cpu;
			/*
			 * Affinity excludes the whole home group: the task
			 * cannot be held there, fall back to dfl placement.
			 */
		}
	}

	if (is_idle)
		dispatch_local(p, g ? queue_of((u32)dfl / (u32)g) : SHARED_DSQ);
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
