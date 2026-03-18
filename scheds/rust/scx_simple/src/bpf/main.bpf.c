/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/* Grouping: 8 CPUs per group for balancing */
#define MAX_CPUS	1024
#define GROUP_SIZE	8
#define MAX_GROUPS	(MAX_CPUS / GROUP_SIZE)

static u64 nr_cpu_ids;
static u32 nr_groups;
static volatile u32 rr_next_group;

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

/* Per-group DSQ IDs start from 1 (0 is SHARED_DSQ). */
#define GROUP_DSQ_BASE	1
static inline u64 group_dsq_id(u32 gid) { return (u64)GROUP_DSQ_BASE + gid; }

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

/* current running tasks per group */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_GROUPS);
} group_load SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static s32 get_group_id(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return -1;
	/* clang bpf backend doesn't support signed div; use unsigned. */
	return (s32)(((u32)cpu) / GROUP_SIZE);
}

static void inc_group_load_for_cpu(s32 cpu)
{
	s32 gid = get_group_id(cpu);
	u32 key = (u32)gid;
	u32 *val;

	if (gid < 0 || gid >= MAX_GROUPS)
		return;
	val = bpf_map_lookup_elem(&group_load, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
}

static void dec_group_load_for_cpu(s32 cpu)
{
	s32 gid = get_group_id(cpu);
	u32 key = (u32)gid;
	u32 *val;

	if (gid < 0 || gid >= MAX_GROUPS)
		return;
	val = bpf_map_lookup_elem(&group_load, &key);
	if (val)
		__sync_fetch_and_sub(val, 1);
}

/* Only balance tasks whose comm starts with \"redis-server\". */
static bool is_redis_task(const struct task_struct *p)
{
	char comm[TASK_COMM_LEN];
	int i;

	if (bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm) <= 0)
		return false;

	/* Match prefix \"redis-server\" */
	const char pat[] = "redis-server";

	for (i = 0; i < (int)sizeof(pat) - 1; i++) {
		if (comm[i] != pat[i])
			return false;
	}
	return true;
}

/* Return first idle CPU in given group intersecting p->cpus_ptr, or -1. */
static s32 pick_idle_cpu_in_group(struct task_struct *p, s32 group_id)
{
	u32 i;
	u32 base, cpu;
	u64 max = nr_cpu_ids < MAX_CPUS ? nr_cpu_ids : MAX_CPUS;

	if (group_id < 0)
		return -1;

	base = ((u32)group_id) * GROUP_SIZE;

	/* Only scan CPUs in this group (max GROUP_SIZE iterations). */
	bpf_for(i, 0, GROUP_SIZE) {
		cpu = base + i;
		if (cpu >= (u32)max)
			break;
		if (!bpf_cpumask_test_cpu((s32)cpu, p->cpus_ptr))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle((s32)cpu))
			return (s32)cpu;
	}
	return -1;
}

static bool group_has_allowed_cpu(struct task_struct *p, u32 g)
{
	u32 i;
	u32 cpu = g * GROUP_SIZE;
	u64 max = nr_cpu_ids < MAX_CPUS ? nr_cpu_ids : MAX_CPUS;

	bpf_for(i, 0, GROUP_SIZE) {
		u32 c = cpu + i;
		if (c >= (u32)max)
			break;
		if (bpf_cpumask_test_cpu((s32)c, p->cpus_ptr))
			return true;
	}
	return false;
}

/* Strict round-robin group assignment; probe forward only if not allowed. */
static s32 pick_rr_group(struct task_struct *p)
{
	u32 start;
	u32 i;

	if (nr_groups == 0)
		return -1;

	start = __sync_fetch_and_add(&rr_next_group, 1);
	start %= nr_groups;

	if (group_has_allowed_cpu(p, start))
		return (s32)start;

	/* Probe up to nr_groups in order, bounded by MAX_GROUPS for verifier friendliness. */
	bpf_for(i, 1, MAX_GROUPS) {
		u32 next;

		if (i >= nr_groups)
			break;
		next = start + i;
		if (next >= nr_groups)
			next -= nr_groups;
		if (group_has_allowed_cpu(p, next))
			return (s32)next;
	}

	return -1;
}

/* Prefer previous CPU's group if allowed, otherwise round-robin. */
static s32 pick_group_for_task(struct task_struct *p, s32 prev_cpu)
{
	s32 gid = get_group_id(prev_cpu);

	if (gid >= 0 && group_has_allowed_cpu(p, (u32)gid))
		return gid;
	return pick_rr_group(p);
}

static s32 pick_best_cpu_in_group(struct task_struct *p, s32 prev_cpu, s32 group_id)
{
	u64 max = nr_cpu_ids < MAX_CPUS ? nr_cpu_ids : MAX_CPUS;
	u32 base, i, cpu;

	if (group_id < 0)
		return -1;

	/* Prefer prev_cpu if it belongs to this group and is idle. */
	if (prev_cpu >= 0 &&
	    ((s32)(((u32)prev_cpu) / GROUP_SIZE) == group_id) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	/* Otherwise, pick the first idle CPU in the group. */
	base = ((u32)group_id) * GROUP_SIZE;
	bpf_for(i, 0, GROUP_SIZE) {
		cpu = base + i;
		if (cpu >= (u32)max)
			break;
		if (!bpf_cpumask_test_cpu((s32)cpu, p->cpus_ptr))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle((s32)cpu))
			return (s32)cpu;
	}

	return -1;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;
	s32 gid;

	/* Non redis-server tasks: don't interfere, let kernel pick. */
	if (!is_redis_task(p)) {
		bool is_idle = false;
		return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	}

	/* Ensure prev_cpu is usable; otherwise pick first allowed CPU as a hint. */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = bpf_cpumask_first(p->cpus_ptr);

	/* 1) Round-robin pick a scheduling domain (group). */
	gid = pick_rr_group(p);

	/* 2) Pick the best CPU within the selected group. */
	if (gid >= 0) {
		cpu = pick_best_cpu_in_group(p, prev_cpu, gid);
		if (cpu >= 0) {
			stat_inc(0); /* count local queueing (direct dispatch) */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			return cpu;
		}
	}

	/* 3) Fallback: let the kernel pick a CPU, without direct dispatch. */
	{
		bool is_idle = false;
		return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	}
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	/* Non redis-server tasks: always use shared DSQ. */
	if (!is_redis_task(p)) {
		if (fifo_sched) {
			scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
		} else {
			u64 vtime = p->scx.dsq_vtime;

			if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
				vtime = vtime_now - SCX_SLICE_DFL;
			scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
						 enq_flags);
		}
		return;
	}

	/* stress-ng tasks: use per-group DSQs with balancing. */
	{
		s32 prev_cpu = scx_bpf_task_cpu(p);
		s32 gid = pick_group_for_task(p, prev_cpu);
		u64 dsq = (gid >= 0) ? group_dsq_id((u32)gid) : (u64)SHARED_DSQ;

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, dsq, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

			if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
				vtime = vtime_now - SCX_SLICE_DFL;
			scx_bpf_dsq_insert_vtime(p, dsq, SCX_SLICE_DFL, vtime,
						 enq_flags);
		}
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 gid = get_group_id(cpu);

	/* Prefer tasks queued to this CPU's group DSQ. */
	if (gid >= 0)
		scx_bpf_dsq_move_to_local(group_dsq_id((u32)gid));

	/* Fallback: consume from shared DSQ if any. */
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	/* Track per-group running load for balancing. */
	inc_group_load_for_cpu(scx_bpf_task_cpu(p));

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

	/* Update per-group running load. */
	dec_group_load_for_cpu(scx_bpf_task_cpu(p));

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	s32 err;
	u32 g;

	err = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (err)
		return err;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > MAX_CPUS)
		nr_cpu_ids = MAX_CPUS;
	nr_groups = (nr_cpu_ids + GROUP_SIZE - 1) / GROUP_SIZE;
	if (nr_groups > MAX_GROUPS)
		nr_groups = MAX_GROUPS;

	/* Create per-group DSQs. */
	bpf_for(g, 0, MAX_GROUPS) {
		if (g >= nr_groups)
			break;
		err = scx_bpf_create_dsq(group_dsq_id(g), -1);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");

