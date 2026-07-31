/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_partial: Partial scheduler that only takes over specific tasks
 *              and restricts them to run on CPU 0-7.
 *
 * Features:
 * 1. Partial takeover mode: Only tasks with PID >= PARTIAL_PID_THRESHOLD are taken over
 * 2. CPU restriction: Taken over tasks can only run on CPU 0-7
 * 3. Simple FIFO scheduling within the restricted CPU set
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* CPU range for restricted tasks: 0-7 */
#define PARTIAL_CPU_MIN 0
#define PARTIAL_CPU_MAX 7

/*
 * Check if a CPU is within the allowed range (0-7).
 */
static __always_inline bool cpu_in_range(s32 cpu)
{
    return cpu >= PARTIAL_CPU_MIN && cpu <= PARTIAL_CPU_MAX;
}

/*
 * Try to find an idle CPU within the restricted range (0-7).
 */
static __always_inline s32 pick_idle_cpu_in_range(struct task_struct *p, s32 prev_cpu)
{
    s32 c;

    /* First try previous CPU if it's in range and usable */
    if (prev_cpu >= 0 && cpu_in_range(prev_cpu) &&
        bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;

    /* Otherwise scan CPUs 0-7 for an idle one */
    bpf_for(c, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
        if (!bpf_cpumask_test_cpu(c, p->cpus_ptr))
            continue;
        if (scx_bpf_test_and_clear_cpu_idle(c))
            return c;
    }

    return -1;
}

/*
 * Try to find any available CPU within the restricted range (0-7).
 */
static __always_inline s32 pick_cpu_in_range(struct task_struct *p, s32 prev_cpu)
{
    s32 c;

    /* First try previous CPU if it's in range and usable */
    if (prev_cpu >= 0 && cpu_in_range(prev_cpu) &&
        bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
        return prev_cpu;

    /* Otherwise pick the first usable CPU in range */
    bpf_for(c, PARTIAL_CPU_MIN, PARTIAL_CPU_MAX + 1) {
        if (bpf_cpumask_test_cpu(c, p->cpus_ptr))
            return c;
    }

    return -1;
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

UEI_DEFINE(uei);

static __always_inline struct task_ctx *get_or_create_task_ctx(struct task_struct *p)
{
    return bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(partial_init_task, struct task_struct *p,
                             struct scx_init_task_args *args)
{
    struct task_ctx *tctx;

    /* Allocate and initialize task context */
    tctx = get_or_create_task_ctx(p);
    if (!tctx)
        return -ENOMEM;

    tctx->avg_runtime = SCX_SLICE_DFL;
    tctx->last_run_at = 0;

    return 0;
}

s32 BPF_STRUCT_OPS(partial_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;

    /* Ensure prev_cpu is valid */
    if (prev_cpu < 0 || !bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
        prev_cpu = bpf_cpumask_first(p->cpus_ptr);

    /* Try to find an idle CPU within the restricted range */
    cpu = pick_idle_cpu_in_range(p, prev_cpu);
    if (cpu >= 0)
        return cpu;

    /* Fall back to any CPU in range */
    cpu = pick_cpu_in_range(p, prev_cpu);
    if (cpu >= 0)
        return cpu;

    /* Last resort: use default selection but clamp to range */
    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, NULL);
    if (cpu_in_range(cpu))
        return cpu;

    /* Return first CPU in range as final fallback */
    return PARTIAL_CPU_MIN;
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

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    now = bpf_ktime_get_ns();
    if (tctx->last_run_at) {
        slice = now - tctx->last_run_at;
        /* Simple moving average: new = old * 0.75 + new * 0.25 */
        tctx->avg_runtime = (tctx->avg_runtime - (tctx->avg_runtime >> 2)) + (slice >> 2);
    }
}

void BPF_STRUCT_OPS(partial_enable, struct task_struct *p)
{
    /* Task is entering sched_ext control */
}

void BPF_STRUCT_OPS(partial_enqueue, struct task_struct *p, u64 enq_flags)
{
    bool cpu_selected;
    s32 cpu;

    cpu_selected = __COMPAT_is_enq_cpu_selected(enq_flags);

    /* Always use the shared DSQ for simplicity */
    scx_bpf_dsq_insert(p, 0, SCX_SLICE_DFL, enq_flags);

    /* If CPU not selected, try to find one and kick it */
    if (!cpu_selected) {
        cpu = pick_idle_cpu_in_range(p, scx_bpf_task_cpu(p));
        if (cpu >= 0)
            scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
    }
}

void BPF_STRUCT_OPS(partial_dispatch, s32 cpu, struct task_struct *prev)
{
    /*
     * Only dispatch if this CPU is in our restricted range.
     * This prevents tasks from running on CPUs outside 0-7.
     */
    if (!cpu_in_range(cpu)) {
        /* Don't dispatch on CPUs outside our range */
        return;
    }

    /* Move a task from the shared DSQ to this CPU's local queue */
    scx_bpf_dsq_move_to_local(0, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(partial_init)
{
    /* Create a single shared DSQ for all restricted tasks */
    return scx_bpf_create_dsq(0, -1);
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
               .init_task      = (void *)partial_init_task,
               .init           = (void *)partial_init,
               .exit           = (void *)partial_exit,
               .timeout_ms     = 5000,
               .name           = "partial");