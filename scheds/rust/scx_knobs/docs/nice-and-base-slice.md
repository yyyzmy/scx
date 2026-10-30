# nice 与 base_slice_ns

一句话概括：**nice 决定"谁的份额更大"，base_slice 决定"一次默认跑多久"。**
前者管长期比例公平，后者管单次连续运行的长度，也就是切换频率的下限。

---

## 1. nice 如何变成 weight

nice 是用户视角的优先级，范围 `-20 .. 19`，越小越优先。内核内部把它翻译成权重
（weight），相邻两档权重比约 **1.25 倍**，即每差一档约 10% 的 CPU 份额。

`kernel/sched/core.c` 里的 `sched_prio_to_weight[]` 是这张换算表：

| nice | weight | 相对 nice 0 |
| ---- | ------ | ----------- |
| -20  | 88761  | 86.7 倍     |
| -15  | 29154  | 28.5 倍     |
| -10  | 9548   | 9.3 倍      |
| -5   | 3121   | 3.05 倍     |
| 0    | 1024   | 1.0（基准） |
| 5    | 335    | 0.33 倍     |
| 10   | 110    | 0.11 倍     |
| 15   | 36     | 0.035 倍    |
| 19   | 15     | 0.015 倍    |

`set_load_weight()` 把查表结果写进 `p->se.load.weight`，并在 64 位内核上左移
`SCHED_FIXEDPOINT_SHIFT`（=10）位做定点放大，于是基准值变成
`NICE_0_LOAD = 1024 << 10 = 2^20 = 1048576`（`kernel/sched/sched.h`）。

CFS/EEVDF 记账都用这个公式（`calc_delta_fair()`）：

```
Δvruntime = Δexec * NICE_0_LOAD / weight
```

所以同样跑 1ms，nice 0 任务记 1ms 虚拟时间，nice 5 任务记约 3.06ms，nice -5 任务
只记 0.33ms。**跑得越久欠得越多，权重大的欠得慢** —— 这就是份额的来源。

举例：一个 nice 0（1024）和一个 nice 5（335）在同一核上竞争，总权重 1359，
长期份额约为 `1024/1359 ≈ 75%` 与 `335/1359 ≈ 25%`。

---

## 2. base_slice_ns 是什么

EEVDF（Linux 6.6 起接管 fair 类）不再用"周期 × 权重占比"算片，而是给每个任务
一个默认片，基准就是 `base_slice_ns`：

- 内核对 nice 0 任务的默认片 ≈ **3ms**（`sysctl_sched_base_slice`，默认 3000000 ns）；
- 其它 nice 的片按权重线性缩放：`slice ≈ base_slice * weight / NICE_0_LOAD`；
  nice 5 约 1ms，nice -5 约 9ms，nice 19 只剩几十微秒；
- 6.12 起应用可以用 `sched_setattr()` 的 `sched_runtime` 给单个任务指定片，
  这是 EEVDF 给延迟敏感型应用留的口子。

运行时查看（需要 debugfs，且内核开了 `CONFIG_SCHED_DEBUG`）：

```bash
cat /sys/kernel/debug/sched/base_slice_ns      # 我的机器上是 3000000
```

**片短 ⇒ 虚拟截止期限（VD）近 ⇒ 更快被选中 ⇒ 延迟低、切换多**；
**片长 ⇒ 切换少 ⇒ 吞吐高、但单次等待可能变长**。EEVDF 的 VD 大致是：

```
VD = vruntime + slice 折算成的虚拟时间增量
```

选下一个任务时，在"合格（lag >= 0）"的任务里挑 VD 最小的。所以片不只是"跑多久"，
它同时是**延迟调节旋钮**。

两个硬边界：

1. `base_slice` 小于一个 tick（`TICK_NSEC`）时，效果基本被时钟中断吃掉 —— 官方
   CFS 文档对这一点有明确说明；
2. 片只规定"最多连续跑多久"，唤醒抢占仍会提前把它换下，实际片长还要看负载。

---

## 3. 5.10（CFS）里的对应关系

| 参数（5.10）                   | 作用                       | 6.6 起的状态                  |
| ------------------------------ | -------------------------- | ----------------------------- |
| `sched_latency_ns`             | 调度周期，决定一轮最长多长 | 已删除（EEVDF 不做周期分摊）   |
| `sched_min_granularity_ns`     | 单次运行下限               | 改名/演化为 `base_slice_ns`    |
| `sched_wakeup_granularity_ns`  | 唤醒抢占门槛               | 已删除（改为比较 VD/lag）       |

5.10 的片是这样算的：

```
slice_i = period * weight_i / Σweight     # period 默认 6ms
slice_i = max(slice_i, min_granularity)   # min_granularity 默认 0.75ms
```

任务数超过 `sched_nr_latency`（8）时，周期自动膨胀为 `nr_running * min_granularity`，
所以重负载下所有任务的片最终都被压到下限 —— 和我们自己实现里 `period/nr` 撞下限
是同一回事。

---

## 4. sched_ext 里的映射（重点）

切到 sched_ext 后，内核**不再维护片**，只维护权重：

- `p->scx.weight`：nice 0 对应 **100**（`SCX_WEIGHT_DFL`）。内核按同一张 nice 表
  换算，例如 nice -15 ≈ 2847、nice 19 ≈ 1（上限 10000）；cgroup 的 `cpu.weight`
  也会反映到这个值上。BPF 侧直接读它即可，不需要自己查表。
- 片由调度器自己决定：`scx_bpf_dsq_insert(p, dsq, slice, flags)` 传多少就是多少，
  `p->scx.slice` 随之递减，**耗尽判定发生在周期 tick 里**（1/HZ 量化）。

对照 scx_knobs 的三个旋钮：

| scx_knobs 旋钮   | 5.10 对应                     | 6.6 对应                        |
| ---------------- | ----------------------------- | ------------------------------- |
| `--slice-ms`     | `sched_min_granularity_ns`    | `base_slice_ns`（基准片）        |
| `--period-ms`    | `sched_latency_ns`            | 无对应（EEVDF 不做周期分摊）      |
| `--gran-us`      | `sched_wakeup_granularity_ns` | 无对应（EEVDF 用 VD/lag 比较）    |

代码里权重刻度是 100，所以记账公式写作
`vtime += (实际运行时间) * 100 / p->scx.weight`（见 `knobs_stopping`）。
`scx_knobs` 现在**没有**做片长按权重缩放：最好把它理解为"全局片"，与权重无关，
只是记账按权重区分份额。

---

## 5. 观察与验证

```bash
# EEVDF 基准片（6.6+）
cat /sys/kernel/debug/sched/base_slice_ns

# 线程 nice 与策略
ps -o pid,ni,comm -L -p <pid>
chrt -p <tid>
```

实验建议：

1. 同一个 nice 0 压力的两个任务，把 `base_slice_ns` 从 3ms 调到 20ms，用 trace 看
   切换间隔是否跟着变 —— 若两者都在 tick 网格上，说明量化在起作用而不是片；
2. 用 `nice -n -10` 起一个任务和一个 nice 0 任务对比 CPU 占比，验证 ≈ 9:1；
3. 在 scx_knobs 下重复实验 1、2，观察结论会变：
   - nice 仍然生效（`p->scx.weight` 变了），但**片不会跟着缩放**（片是你传的常量）；
   - `slice-ms` 小于一个 tick 时，实际片长不会缩短 —— 需要 bpf_timer 才能突破。

---

## 6. 常见误区

- **"nice 在 scx 下失效了"**：没有失效，只是它只影响 `p->scx.weight`（份额），
  不再影响片长；片完全由调度器决定。
- **"把 slice 设得很小就能高频切换"**：片到期判定挂在周期 tick 上，实际片长是
  `ceil(slice / tick) * tick`，小于 tick 的值会被四舍五入到一个 tick。
- **"base_slice 等于实际切换间隔"**：不等于。它只是片的上限，唤醒抢占、tick 相位、
  以及队列深度都会改变实际间隔。
- **"权重缩放总是可见"**：权重差异要超过 tick 的量化粒度才看得出来。nice 19 的片
  只有几十微秒，实际还是按一个 tick 跑。
