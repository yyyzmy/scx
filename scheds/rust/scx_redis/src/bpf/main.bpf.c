/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
/* Main thread gets main_slice_mult * SCX_SLICE_DFL (0 or 1 => same as default). */
const volatile u32 main_slice_mult = 4;
/* Softer vtime charge for main thread (higher = softer). */
const volatile u32 main_vtime_div = 2;

static u64 vtime_now;
UEI_DEFINE(uei);

#define MAX_CPUS	1024
#define GROUP_SIZE	8
#define MAX_GROUPS	(MAX_CPUS / GROUP_SIZE)
#define PROC_FIXED_UNSET	0xffffffffU
#define SMT_MAX_SIBLINGS 2

#define STAT_LOCAL	0
#define STAT_ENQ	1
#define STAT_REDIS_STOP	2
#define STAT_MAIN_PIN	3
#define STAT_MAIN_OFF	4
#define STAT_MAX	8

static u64 nr_cpu_ids;
static u32 nr_groups;
static volatile u32 rr_next_group;

#define SHARED_DSQ 0
#define GROUP_DSQ_BASE	1
static inline u64 group_dsq_id(u32 gid) { return (u64)GROUP_DSQ_BASE + gid; }

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_GROUPS);
} group_load SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 16384);
} proc_group SEC(".maps");

/* Mark tgid as redis process so non-main comm (e.g. iou-sqp-*) is included. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, 16384);
} redis_tgid SEC(".maps");

/* redis-server main thread (tgid): pinned logical CPU */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 16384);
} proc_fixed_cpu SEC(".maps");

/* SMT: for each logical CPU, store thread_siblings_list (limited by SMT_MAX_SIBLINGS). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_CPUS);
} cpu_smt_n SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32) * SMT_MAX_SIBLINGS);
	__uint(max_entries, MAX_CPUS);
} cpu_smt_sibs SEC(".maps");

/* Dynamic marker: CPU currently running a redis main thread. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u8));
	__uint(max_entries, MAX_CPUS);
} cpu_main_busy SEC(".maps");

static inline u32 task_tgid(const struct task_struct *p);

static void stat_inc(u32 idx)
{
	u64 *cnt_p;

	if (idx >= STAT_MAX)
		return;
	cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static s32 get_group_id(s32 cpu)
{
	if (cpu < 0 || cpu >= MAX_CPUS)
		return -1;
	return (s32)(((u32)cpu) / GROUP_SIZE);
}

static __always_inline bool is_kthread(const struct task_struct *p)
{
	return !!(BPF_CORE_READ(p, flags) & PF_KTHREAD);
}

static __always_inline bool is_pcpu_kthread(const struct task_struct *p)
{
	return is_kthread(p) && BPF_CORE_READ(p, nr_cpus_allowed) == 1;
}

static __always_inline bool is_main_busy_cpu(s32 cpu)
{
	u32 key;
	u8 *v;

	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return false;
	key = (u32)cpu;
	v = bpf_map_lookup_elem(&cpu_main_busy, &key);
	return v && *v;
}

static bool is_redis_task(const struct task_struct *p);
static inline u32 task_tgid(const struct task_struct *p);

static __always_inline void cleanup_redis_proc_state(struct task_struct *p)
{
	u32 tgid, pid;

	/* Cleanup only when redis main thread is exiting. */
	if (!is_redis_task(p))
		return;
	pid = (u32)BPF_CORE_READ(p, pid);
	tgid = task_tgid(p);
	if (pid != tgid)
		return;
	if (!(BPF_CORE_READ(p, flags) & PF_EXITING))
		return;

	bpf_map_delete_elem(&proc_fixed_cpu, &tgid);
	bpf_map_delete_elem(&proc_group, &tgid);
	bpf_map_delete_elem(&redis_tgid, &tgid);
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

static bool is_redis_task(const struct task_struct *p)
{
	char comm[TASK_COMM_LEN];
	int i;
	u32 tgid;
	u8 one = 1;
	u8 *tagp;

	if (bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm) <= 0)
		goto check_tag;

	const char pat[] = "redis-server";

	for (i = 0; i < (int)sizeof(pat) - 1; i++) {
		if (comm[i] != pat[i])
			goto check_tag;
	}
	/* Learn this redis process once we see its main comm. */
	tgid = task_tgid(p);
	bpf_map_update_elem(&redis_tgid, &tgid, &one, BPF_ANY);
	return true;

check_tag:
	tgid = task_tgid(p);
	tagp = bpf_map_lookup_elem(&redis_tgid, &tgid);
	return tagp && *tagp;
}

/* Thread group leader: main event-loop thread in typical Redis builds. */
static bool is_redis_main_thread(const struct task_struct *p)
{
	u32 pid, tgid;

	if (!is_redis_task(p))
		return false;
	pid = (u32)BPF_CORE_READ(p, pid);
	tgid = (u32)BPF_CORE_READ(p, tgid);
	return pid == tgid;
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

static inline u32 task_tgid(const struct task_struct *p)
{
	return (u32)BPF_CORE_READ(p, tgid);
}

static s32 pick_group_for_task(struct task_struct *p, s32 prev_cpu)
{
	u32 tgid = task_tgid(p);
	u32 *gidp;
	s32 gid;

	gidp = bpf_map_lookup_elem(&proc_group, &tgid);
	if (gidp) {
		gid = (s32)*gidp;
		if (gid >= 0 && (u32)gid < nr_groups && group_has_allowed_cpu(p, (u32)gid))
			return gid;
	}

	/* First-time assignment: prefer cross-process RR to achieve group spreading. */
	gid = pick_rr_group(p);
	if (gid >= 0) {
		u32 ugid = (u32)gid;

		bpf_map_update_elem(&proc_group, &tgid, &ugid, BPF_ANY);
		return gid;
	}

	/* RR fallback: if it failed, keep previous CPU group as a best-effort hint. */
	gid = get_group_id(prev_cpu);
	if (gid >= 0 && (u32)gid < nr_groups && group_has_allowed_cpu(p, (u32)gid)) {
		u32 ugid = (u32)gid;
		bpf_map_update_elem(&proc_group, &tgid, &ugid, BPF_ANY);
		return gid;
	}
	return gid;
}

static u32 pick_first_allowed_in_group(struct task_struct *p, s32 group_id)
{
	u64 max = nr_cpu_ids < MAX_CPUS ? nr_cpu_ids : MAX_CPUS;
	u32 base, i, cpu;

	if (group_id < 0)
		return PROC_FIXED_UNSET;

	base = ((u32)group_id) * GROUP_SIZE;
	bpf_for(i, 0, GROUP_SIZE) {
		cpu = base + i;
		if (cpu >= (u32)max)
			break;
		if (bpf_cpumask_test_cpu((s32)cpu, p->cpus_ptr))
			return cpu;
	}
	return PROC_FIXED_UNSET;
}

/*
 * Assign per-process fixed CPU for redis main thread (first time only).
 * Workers do not use this map for selection.
 */
static s32 assign_redis_main_fixed_cpu(struct task_struct *p, s32 prev_cpu)
{
	u32 tgid = task_tgid(p);
	u32 *fp = bpf_map_lookup_elem(&proc_fixed_cpu, &tgid);
	u32 fixed_u;
	s32 gid;

	if (fp && *fp != PROC_FIXED_UNSET)
		return (s32)*fp;

	gid = pick_group_for_task(p, prev_cpu);
	if (gid < 0)
		return -1;

	if (prev_cpu >= 0 &&
	    get_group_id(prev_cpu) == gid &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		fixed_u = (u32)prev_cpu;
	else
		fixed_u = pick_first_allowed_in_group(p, gid);

	if (fixed_u == PROC_FIXED_UNSET)
		return -1;

	bpf_map_update_elem(&proc_fixed_cpu, &tgid, &fixed_u, BPF_ANY);
	return (s32)fixed_u;
}

static __always_inline bool is_cpu_in_smt_siblings(u32 fixed_cpu, s32 candidate_cpu)
{
	u32 *n_p;
	u32 *sib_p;
	u32 n;
	u32 i;

	if (candidate_cpu < 0)
		return false;

	/* Always exclude the fixed CPU itself. */
	if ((u32)candidate_cpu == fixed_cpu)
		return true;

	n_p = bpf_map_lookup_elem(&cpu_smt_n, &fixed_cpu);
	sib_p = bpf_map_lookup_elem(&cpu_smt_sibs, &fixed_cpu);
	if (!n_p || !sib_p)
		return false;

	n = *n_p;
	bpf_for(i, 0, SMT_MAX_SIBLINGS) {
		if (i >= n)
			break;
		if (sib_p[i] == (u32)candidate_cpu)
			return true;
	}
	return false;
}

static s32 pick_best_cpu_in_group(struct task_struct *p, s32 prev_cpu, s32 group_id)
{
	u64 max = nr_cpu_ids < MAX_CPUS ? nr_cpu_ids : MAX_CPUS;
	u32 base, i, cpu;
	u32 tgid;
	u32 *fp;
	s32 fixed_cpu;
	u32 fixed_cpu_u;
	bool prev_excluded;

	if (group_id < 0)
		return -1;

	/* Hard isolation: workers must not run on redis main thread fixed CPU. */
	fixed_cpu = -1;
	tgid = task_tgid(p);
	fp = bpf_map_lookup_elem(&proc_fixed_cpu, &tgid);
	if (fp && *fp != PROC_FIXED_UNSET)
		fixed_cpu = (s32)*fp;
	fixed_cpu_u = fixed_cpu >= 0 ? (u32)fixed_cpu : 0;
	prev_excluded = (prev_cpu >= 0 && fixed_cpu >= 0)
		? is_cpu_in_smt_siblings(fixed_cpu_u, prev_cpu)
		: false;

	if (prev_cpu >= 0 &&
	    ((s32)(((u32)prev_cpu) / GROUP_SIZE) == group_id) &&
	    !prev_excluded &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	base = ((u32)group_id) * GROUP_SIZE;
	bpf_for(i, 0, GROUP_SIZE) {
		cpu = base + i;
		if (cpu >= (u32)max)
			break;
		if (!bpf_cpumask_test_cpu((s32)cpu, p->cpus_ptr))
			continue;
		/* Skip main thread fixed CPU and its SMT siblings. */
		if (fixed_cpu >= 0 && is_cpu_in_smt_siblings(fixed_cpu_u, (s32)cpu))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle((s32)cpu))
			return (s32)cpu;
	}

	return -1;
}

static __always_inline u64 effective_main_slice(void)
{
	if (!main_slice_mult || main_slice_mult == 1)
		return SCX_SLICE_DFL;
	return (u64)main_slice_mult * (u64)SCX_SLICE_DFL;
}

static __always_inline void kick_target_cpu(s32 cpu)
{
	if (cpu >= 0 && (u32)cpu < nr_cpu_ids)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

s32 BPF_STRUCT_OPS(redis_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;
	s32 gid;
	s32 fixed;

	/*
	 * Model from bpfland/flash: per-CPU kthreads are dispatched quickly.
	 * But avoid kicking them onto a CPU currently occupied by redis main thread.
	 */
	if (is_pcpu_kthread(p)) {
		if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
			prev_cpu = bpf_cpumask_first(p->cpus_ptr);
		if (!is_main_busy_cpu(prev_cpu)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
				kick_target_cpu(prev_cpu);
			}
			return prev_cpu;
		}
	}

	if (!is_redis_task(p)) {
		bool is_idle = false;

		return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	}

	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = bpf_cpumask_first(p->cpus_ptr);

	/* Main thread: always pin to proc_fixed_cpu (assigned on first need). */
	if (is_redis_main_thread(p)) {
		fixed = assign_redis_main_fixed_cpu(p, prev_cpu);
		if (fixed >= 0 && bpf_cpumask_test_cpu(fixed, p->cpus_ptr)) {
			if (scx_bpf_test_and_clear_cpu_idle(fixed)) {
				stat_inc(STAT_LOCAL);
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, effective_main_slice(), 0);
				kick_target_cpu(fixed);
				return fixed;
			}
			/* Busy pinned CPU: still return it to avoid roaming. */
			return fixed;
		}
		{
			bool is_idle = false;

			return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
		}
	}

	/* Background / IO threads: balance inside same tgid group only. */
	gid = pick_group_for_task(p, prev_cpu);
	if (gid >= 0) {
		cpu = pick_best_cpu_in_group(p, prev_cpu, gid);
		if (cpu >= 0) {
			stat_inc(STAT_LOCAL);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			kick_target_cpu(cpu);
			return cpu;
		}
	}

	{
		bool is_idle = false;

		return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	}
}

static void insert_redis_dsq(struct task_struct *p, u64 dsq, u64 enq_flags)
{
	u64 slice = is_redis_main_thread(p) ? effective_main_slice() : SCX_SLICE_DFL;

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, dsq, slice, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - slice))
			vtime = vtime_now - slice;
		scx_bpf_dsq_insert_vtime(p, dsq, slice, vtime, enq_flags);
	}
}

void BPF_STRUCT_OPS(redis_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* Prioritize per-CPU kthreads, but avoid redis main busy CPUs. */
	if (is_pcpu_kthread(p)) {
		s32 cpu = scx_bpf_task_cpu(p);

		if (cpu >= 0 && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) && !is_main_busy_cpu(cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, enq_flags);
			kick_target_cpu(cpu);
			return;
		}
	}

	stat_inc(STAT_ENQ);

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

	{
		s32 prev_cpu = scx_bpf_task_cpu(p);
		s32 gid = pick_group_for_task(p, prev_cpu);
		u64 dsq = (gid >= 0) ? group_dsq_id((u32)gid) : (u64)SHARED_DSQ;
		s32 kick_cpu = -1;

		if (gid >= 0) {
			if (is_redis_main_thread(p)) {
				s32 fixed = assign_redis_main_fixed_cpu(p, prev_cpu);

				if (fixed >= 0 && bpf_cpumask_test_cpu(fixed, p->cpus_ptr) &&
				    scx_bpf_test_and_clear_cpu_idle(fixed))
					kick_cpu = fixed;
			} else {
				kick_cpu = pick_best_cpu_in_group(p, prev_cpu, gid);
			}
			if (kick_cpu >= 0)
				kick_target_cpu(kick_cpu);
		}

		insert_redis_dsq(p, dsq, enq_flags);
	}
}

void BPF_STRUCT_OPS(redis_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 gid = get_group_id(cpu);

	/*
	 * Avoid starving non-redis kernel/user tasks in SHARED_DSQ
	 * (e.g. ksoftirqd, iou-sqp) under heavy redis per-group traffic.
	 */
	scx_bpf_dsq_move_to_local(SHARED_DSQ);

	if (gid >= 0)
		scx_bpf_dsq_move_to_local(group_dsq_id((u32)gid));
}

void BPF_STRUCT_OPS(redis_running, struct task_struct *p)
{
	u8 one = 1;

	if (is_redis_main_thread(p)) {
		u32 key = (u32)scx_bpf_task_cpu(p);

		if (key < nr_cpu_ids)
			bpf_map_update_elem(&cpu_main_busy, &key, &one, BPF_ANY);
	}

	if (fifo_sched)
		return;

	if (is_redis_task(p))
		inc_group_load_for_cpu(scx_bpf_task_cpu(p));

	if (is_redis_main_thread(p)) {
		u32 tgid = task_tgid(p);
		u32 *fp = bpf_map_lookup_elem(&proc_fixed_cpu, &tgid);
		u32 unset = PROC_FIXED_UNSET;
		s32 cur = scx_bpf_task_cpu(p);

		if (fp && *fp != unset) {
			if ((s32)*fp == cur)
				stat_inc(STAT_MAIN_PIN);
			else
				stat_inc(STAT_MAIN_OFF);
		}
	}

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(redis_stopping, struct task_struct *p, bool runnable)
{
	u64 slice_grant;
	u64 numer;
	u8 zero = 0;

	if (is_redis_main_thread(p)) {
		u32 key = (u32)scx_bpf_task_cpu(p);

		if (key < nr_cpu_ids)
			bpf_map_update_elem(&cpu_main_busy, &key, &zero, BPF_ANY);
	}
	cleanup_redis_proc_state(p);

	if (fifo_sched)
		return;

	if (is_redis_task(p)) {
		dec_group_load_for_cpu(scx_bpf_task_cpu(p));
		stat_inc(STAT_REDIS_STOP);
	}

	slice_grant = is_redis_main_thread(p) ? effective_main_slice() : SCX_SLICE_DFL;
	/* Match simple scheduler: charge by (granted - remaining_slice). */
	if (p->scx.slice >= slice_grant)
		numer = 0;
	else
		numer = (slice_grant - p->scx.slice) * 100;
	if (is_redis_main_thread(p)) {
		u32 div = main_vtime_div ? main_vtime_div : 1;

		p->scx.dsq_vtime += numer / (p->scx.weight * div);
	} else {
		p->scx.dsq_vtime += numer / p->scx.weight;
	}
}

void BPF_STRUCT_OPS(redis_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(redis_init)
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

	bpf_for(g, 0, MAX_GROUPS) {
		if (g >= nr_groups)
			break;
		err = scx_bpf_create_dsq(group_dsq_id(g), -1);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(redis_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(redis_ops,
	       .select_cpu		= (void *)redis_select_cpu,
	       .enqueue			= (void *)redis_enqueue,
	       .dispatch		= (void *)redis_dispatch,
	       .running			= (void *)redis_running,
	       .stopping		= (void *)redis_stopping,
	       .enable			= (void *)redis_enable,
	       .init			= (void *)redis_init,
	       .exit			= (void *)redis_exit,
	       .name			= "redis");
