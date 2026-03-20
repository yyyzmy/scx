# scx_redis

面向 `redis-server` 的 sched_ext 调度器（Rust 用户态 + BPF）。

## 行为概要

- **8 CPU 一组**（与常见 LLC 粒度接近；真实 L3 拓扑因机型而异）。
- **仅** `comm` 前缀为 `redis-server` 的任务走专用路径；其它任务走默认 `SHARED_DSQ`。
- **主线程**（`pid == tgid`）：首次调度时在组内**固定一颗 CPU**，`select_cpu` 始终倾向该核；**更长 time slice**、**更轻的 vtime 记账**，减少被同组工作线程抢占。
- **同进程其它线程**：与主线程共享 `proc_group`（按 `tgid`），仅在**同一组 8 核**内挑 idle / 均衡。
- **不同 redis 进程**：新进程通过 **RR 选组**，实现组间分散。

## 指标（BPF `stats` per-CPU 数组，用户态可 `--stats-interval` 汇总）

| 索引 | 含义 |
|------|------|
| 0 | 主路径上 `SCX_DSQ_LOCAL` 直派次数 |
| 1 | 入队总次数（含共享队列） |
| 2 | redis 任务 `stopping` 次数（**上下文切换/让出 CPU 的粗代理**） |
| 3 | 主线程在**固定核**上 `running` |
| 4 | 主线程在**非固定核**上 `running`（迁移 / 尚未绑定） |

**真实 LLC / 缓存命中率**需配合 `perf` 等 PMU；可把网卡 IRQ 与用户态文档中的固定核对齐到同一 NUMA/LLC。

## 运行

```bash
cargo build --release -p scx_redis
sudo ./target/release/scx_redis --main-slice-mult 4 --stats-interval 5 --monitor-redis 2
```

## 与中断/网络同 LLC

本调度器在 BPF 内不读 PCI/IRQ 拓扑。建议在部署时：

1. 用 `lscpu` / `/sys/devices/system/cpu/cpu*/cache` 确认 LLC 与 CPU 对应关系。
2. 将 **Redis 主线程固定核**（由调度器自动选择，也可后续扩展为用户态写 map）与 **网卡队列 IRQ affinity** 设到**同一 LLC 覆盖的 CPU 集合**内。
