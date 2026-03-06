# scx_cluster

scx_cluster 是基于 scx_bpfland 的 sched_ext 调度器，在保留 vruntime 与交互式优先的基础上，**按 cluster（LLC/L3 域）均分进程**，使各 cluster 上的运行任务数尽量均衡。

## 行为概述

- **Cluster 定义**：以拓扑中的 LLC（Last Level Cache，即 L3）域为一个 cluster。
- **均分策略**：在 `select_cpu` 中优先选择**当前运行任务数最少**的 cluster，在该 cluster 内再按 scx_bpfland 的规则（idle CPU、L2/L3 亲和等）选 CPU。
- **负载统计**：在 BPF 中维护每个 cluster 的 `cluster_load`（正在运行的任务数），在 `running` 时加一、在 `stopping` 时减一。

## 与 scx_bpfland 的差异

- 增加 per-cluster 负载统计与「选负载最小 cluster」的逻辑。
- 选 CPU 时先按 cluster 负载均衡，再在选中的 cluster 内沿用 bpfland 的 idle/cache 亲和策略。
- 其余（slice、preempt、primary domain、L2/L3、cpufreq 等）与 scx_bpfland 一致。

## 构建与运行

与其它 Rust 调度器相同，在仓库根目录：

```bash
cargo build -p scx_cluster --release
```

运行（需 root 及 sched_ext 支持）：

```bash
sudo ./target/release/scx_cluster [选项]
```

常用选项与 scx_bpfland 一致，例如 `-s`（slice）、`-p`（local_pcpu）、`-m`（primary_domain）等。

## 依赖

与 scx_bpfland 相同：Rust 工具链、libbpf、scx_utils、scx_stats 等（见仓库根目录及 `Cargo.toml`）。
