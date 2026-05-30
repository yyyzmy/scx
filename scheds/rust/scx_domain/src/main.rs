// SPDX-License-Identifier: GPL-2.0
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{OpenObject, PrintLevel, MapCore, MapFlags};
use log::{info, warn, debug};
use scx_utils::{
    build_id, init_libbpf_logging, libbpf_clap_opts::LibbpfOpts,
    scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity,
    uei_exited, uei_report, UserExitInfo,
};

mod bpf_intf {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

mod bpf_skel {
    #![allow(dead_code)]
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}

use bpf_intf::*;
use bpf_skel::*;

const SCHEDULER_NAME: &str = "scx_domain";

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    _link: libbpf_rs::Link,
    shutdown: Arc<AtomicBool>,
    nr_cpus: u32,
    nr_llc: usize,
    nr_node: usize,
    cpu_llcs: Vec<u32>,
    cpu_nodes: Vec<u32>,
    prev_stats: Vec<u64>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let print_level = if opts.verbose > 0 {
            PrintLevel::Debug
        } else {
            PrintLevel::Info
        };
        init_libbpf_logging(Some(print_level));

        let skel_builder = BpfSkelBuilder::default();
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut open_skel = scx_ops_open!(skel_builder, open_object, domain_ops, open_opts)?;

        let nr_cpus = Self::init_globals(&mut open_skel, opts)?;
        let cpu_llcs = Self::detect_cpu_llc_mapping(nr_cpus as usize)?;
        let cpu_nodes = Self::detect_cpu_node_mapping(nr_cpus as usize)?;
        let nr_llc = *cpu_llcs.iter().max().unwrap_or(&0) as usize + 1;
        let nr_node = *cpu_nodes.iter().max().unwrap_or(&0) as usize + 1;
        let mut skel = scx_ops_load!(open_skel, domain_ops, uei)?;
        Self::init_topology(&mut skel, nr_cpus, nr_llc, nr_node)?;
        let link = scx_ops_attach!(skel, domain_ops)?;

        info!("{} scheduler initialized", SCHEDULER_NAME);
        Ok(Self {
            skel,
            _link: link,
            shutdown: Arc::new(AtomicBool::new(false)),
            nr_cpus,
            nr_llc,
            nr_node,
            cpu_llcs,
            cpu_nodes,
            prev_stats: vec![0u64; MAX_CPUS as usize * 3],
        })
    }

    fn detect_cpu_llc_mapping(nr_cpus: usize) -> Result<Vec<u32>> {
        let mut map = vec![0u32; nr_cpus];
        for cpu in 0..nr_cpus {
            let path = format!("/sys/devices/system/cpu/cpu{}/topology/cluster_id", cpu);
            if !std::path::Path::new(&path).exists() {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            let cluster_id = content.trim().parse::<u32>().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
            })?;
            map[cpu] = cluster_id;
        }
        Ok(map)
    }

    fn detect_cpu_node_mapping(nr_cpus: usize) -> Result<Vec<u32>> {
        let mut map = vec![0u32; nr_cpus];
        for node in 0..MAX_NUMA_NODES {
            let path = format!("/sys/devices/system/node/node{}/cpulist", node);
            if !std::path::Path::new(&path).exists() {
                break;
            }
            let content = std::fs::read_to_string(&path)?;
            for range in content.trim().split(',') {
                let parts: Vec<&str> = range.split('-').collect();
                if parts.len() == 1 {
                    let cpu = parts[0].parse::<usize>()?;
                    if cpu < nr_cpus {
                        map[cpu] = node;
                    }
                } else if parts.len() == 2 {
                    let start = parts[0].parse::<usize>()?;
                    let end = parts[1].parse::<usize>()?;
                    for cpu in start..=end {
                        if cpu < nr_cpus {
                            map[cpu] = node;
                        }
                    }
                }
            }
        }
        Ok(map)
    }

    fn init_globals(skel: &mut OpenBpfSkel, opts: &Opts) -> Result<u32> {
        let rodata = skel.maps.rodata_data.as_mut().unwrap();

        let nr_cpus = num_cpus::get() as u32;
        if nr_cpus > MAX_CPUS as u32 {
            warn!("System has {} CPUs, but BPF supports max {}", nr_cpus, MAX_CPUS);
        }
        rodata.max_cpus = nr_cpus.min(MAX_CPUS as u32);
        rodata.allowed_node = opts.allowed_node.unwrap_or(-1);

        let comm_bytes = opts.target_comm.as_bytes();
        let len = comm_bytes.len().min((TASK_COMM_LEN - 1) as usize);
        for i in 0..len {
            rodata.target_comm[i] = comm_bytes[i] as i8;
        }
        rodata.target_comm[len] = 0;

        debug!("Global variables set: max_cpus={}, allowed_node={}, target_comm={}",
               rodata.max_cpus, rodata.allowed_node, opts.target_comm);
        Ok(rodata.max_cpus)
    }

    fn init_topology(skel: &mut BpfSkel, nr_cpus: u32, nr_llc: usize, nr_node: usize) -> Result<()> {
        let nr_cpus = nr_cpus as usize;
        eprintln!("[INIT] Initializing topology for {} CPUs", nr_cpus);

        let mut cpu_node = vec![0u32; nr_cpus];
        let mut cpu_llc = vec![0u32; nr_cpus];
        let mut node_cpus = vec![Vec::new(); MAX_CPUS as usize];

        for cpu in 0..nr_cpus {
            let node_id = read_sysfs_node_id(cpu).unwrap_or(0);
            let llc_id = read_sysfs_llc_id(cpu).unwrap_or(cpu as u32);
            cpu_node[cpu] = node_id;
            cpu_llc[cpu] = llc_id;
            node_cpus[node_id as usize].push(cpu);
        }

        let mut unique_llc_ids = HashSet::new();
        for &llc in &cpu_llc {
            unique_llc_ids.insert(llc);
        }
        let mut llc_list: Vec<u32> = unique_llc_ids.into_iter().collect();
        llc_list.sort();
        let llc_id_to_idx: std::collections::HashMap<u32, usize> = llc_list
            .iter()
            .enumerate()
            .map(|(idx, &id)| (id, idx))
            .collect();
        let nr_llcs = llc_list.len();

        for cpu in 0..nr_cpus {
            let ctx = cpu_ctx {
                cpu: cpu as u32,
                node_id: cpu_node[cpu],
                llc_id: cpu_llc[cpu],
                task_pid:0,
            };
            let key = (cpu as u32).to_ne_bytes();
            let value = unsafe {
                std::slice::from_raw_parts(
                    &ctx as *const _ as *const u8,
                    std::mem::size_of_val(&ctx),
                )
            };
            skel.maps.cpu_ctxs.update(&key, value, MapFlags::ANY)
                .with_context(|| format!("Failed to update cpu_ctx for CPU {}", cpu))?;
        }

        let nr_nodes = node_cpus.iter().filter(|v| !v.is_empty()).count();
        for node in 0..nr_nodes {
            let mut mask = [0u8; CPUMASK_BYTES as usize];
            let mut nr_cpus_in_node = 0;
            for &cpu in &node_cpus[node] {
                if cpu < nr_cpus {
                    set_cpu_in_mask(cpu, &mut mask);
                    nr_cpus_in_node += 1;
                }
            }
            let node_ctx = node_ctx {
                id: node as u32,
                nr_llcs: (nr_llcs / nr_nodes) as u32,
                nr_cpus: nr_cpus_in_node,
                last_cpu_id: 0,
                last_llc_idx: 0,
                cpumask: mask,
                bpf_cpumask: std::ptr::null_mut(),
            };
            let key = (node as u32).to_ne_bytes();
            let value = unsafe {
                std::slice::from_raw_parts(
                    &node_ctx as *const _ as *const u8,
                    std::mem::size_of_val(&node_ctx),
                )
            };
            skel.maps.node_ctxs.update(&key, value, MapFlags::ANY)
                .with_context(|| format!("Failed to update node_ctx for node {}", node))?;
        }

        let mut llc_cpus_list = vec![Vec::new(); nr_llcs];
        for cpu in 0..nr_cpus {
            let llc_id = cpu_llc[cpu];
            let idx = llc_id_to_idx[&llc_id];
            llc_cpus_list[idx].push(cpu);
        }
        for (idx, &llc_id) in llc_list.iter().enumerate() {
            let mut mask = [0u8; CPUMASK_BYTES as usize];
            let mut nr_cpus_in_llc = 0;
            for &cpu in &llc_cpus_list[idx] {
                if cpu < nr_cpus {
                    set_cpu_in_mask(cpu, &mut mask);
                    nr_cpus_in_llc += 1;
                }
            }
            let llc_ctx = llc_ctx {
                id: llc_id,
                nr_cpus: nr_cpus_in_llc,
                last_cpu_id: 0,
                cpumask: mask,
                bpf_cpumask: std::ptr::null_mut(),
            };
            let key = (idx as u32).to_ne_bytes();
            let value = unsafe {
                std::slice::from_raw_parts(
                    &llc_ctx as *const _ as *const u8,
                    std::mem::size_of_val(&llc_ctx),
                )
            };
            skel.maps.llc_ctxs.update(&key, value, MapFlags::ANY)
                .with_context(|| format!("Failed to update llc_ctx for llc index {}", idx))?;
        }

        let topo = topo_ctx {
            nr_cpus: nr_cpus as u32,
            nr_nodes: nr_nodes as u32,
            nr_llcs: nr_llcs as u32,
            last_cpu_id: 0,
            last_llc_id: 0,
            last_node_id: 0,
        };
        let key = 0u32.to_ne_bytes();
        let value = unsafe {
            std::slice::from_raw_parts(
                &topo as *const _ as *const u8,
                std::mem::size_of_val(&topo),
            )
        };
        skel.maps.topo_ctxs.update(&key, value, MapFlags::ANY)
            .context("Failed to update topo_ctxs")?;

        for llc in 0..nr_llc {
            let key = (llc as u32).to_ne_bytes();
            let zero = 0u32.to_ne_bytes();
            skel.maps.llc_sched_idx.update(&key, &zero, MapFlags::ANY)
                .context("Failed to init llc_sched_idx")?;
        }

        for llc in 0..nr_llc {
            for idx in 0..MAX_CPUS {
                let map_key = (llc as u32) * MAX_CPUS_PER_LLC as u32 + idx as u32;
                let val = 0u32.to_ne_bytes();
                let _ = skel.maps.llc_sorted_cpu_map.update(&map_key.to_ne_bytes(), &val, MapFlags::ANY);
            }
        }

        for node in 0..nr_node {
            let key = (node as u32).to_ne_bytes();
            let zero = 0u32.to_ne_bytes();
            skel.maps.node_sched_idx.update(&key, &zero, MapFlags::ANY)
                .context("Failed to init node_sched_idx")?;
        }

        for node in 0..nr_node {
            for idx in 0..MAX_CPUS {
                let map_key = (node as u32) * MAX_CPUS_PER_NODE as u32 + idx as u32;
                let val = 0u32.to_ne_bytes();
                let _ = skel.maps.node_sorted_cpu_map.update(&map_key.to_ne_bytes(), &val, MapFlags::ANY);
            }
        }

        Ok(())
    }

    fn update_cpu_loads(&mut self) {
        let nr_cpus = self.nr_cpus as usize;

        let curr_stats = match read_cpu_stats() {
            Ok(stats) => stats,
            Err(e) => {
                debug!("Failed to read CPU stats: {}", e);
                return;
            }
        };

        if self.prev_stats.iter().all(|&v| v == 0) {
            self.prev_stats = curr_stats;
            return;
        }

        let mut loads = vec![0u32; MAX_CPUS as usize];
        let mut irq_heavy = vec![0u32; MAX_CPUS as usize];
        for cpu in 0..nr_cpus {
            let prev_total = self.prev_stats[cpu * 3];
            let prev_idle = self.prev_stats[cpu * 3 + 1];
            let prev_irq = self.prev_stats[cpu * 3 + 2];
            let curr_total = curr_stats[cpu * 3];
            let curr_idle = curr_stats[cpu * 3 + 1];
            let curr_irq = curr_stats[cpu * 3 + 2];

            let total_diff = curr_total.saturating_sub(prev_total);
            let idle_diff = curr_idle.saturating_sub(prev_idle);
            let irq_diff = curr_irq.saturating_sub(prev_irq);

            if total_diff > 0 {
                let busy = total_diff.saturating_sub(idle_diff);
                loads[cpu] = ((busy as u64 * 1024) / total_diff) as u32;
                loads[cpu] = loads[cpu].min(1024);

                irq_heavy[cpu] = ((irq_diff as u64 * 1024) / total_diff) as u32;
                irq_heavy[cpu] = irq_heavy[cpu].min(1024);
            }
        }

        for cpu in 0..nr_cpus {
            let key = (cpu as u32).to_ne_bytes();
            let val = loads[cpu].to_ne_bytes();
            let val_irq = irq_heavy[cpu].to_ne_bytes();
            if let Err(e) = self.skel.maps.cpu_load_map.update(&key, &val, MapFlags::ANY) {
                debug!("Failed to update cpu_load_map[{}]: {}", cpu, e);
            }
            let _ = self.skel.maps.cpu_load_irq_map.update(&key, &val_irq, MapFlags::ANY);
        }

        let mut cpu_load_pairs: Vec<(u32, u32)> = (0..nr_cpus as u32)
            .map(|cpu| (cpu, loads[cpu as usize]))
            .collect();
        cpu_load_pairs.sort_by_key(|(_, load)| *load);


        let mut llc_cpus: Vec<Vec<u32>> = vec![Vec::new(); self.nr_llc];
        for cpu in 0..self.nr_cpus {
            let llc = self.cpu_llcs[cpu as usize] as usize;
            llc_cpus[llc].push(cpu as u32);
        }
        for llc in 0..self.nr_llc {
            llc_cpus[llc].sort_by_key(|&cpu| loads[cpu as usize]);

            for (idx, &cpu) in llc_cpus[llc].iter().enumerate() {
                let map_key = (llc as u32) * MAX_CPUS_PER_LLC as u32 + (idx as u32);
                let val = (cpu as u32).to_ne_bytes();
                let _ = self.skel.maps.llc_sorted_cpu_map.update(&map_key.to_ne_bytes(), &val, MapFlags::ANY);
            }

            let llc_key = (llc as u32).to_ne_bytes();
            let zero = 0u32.to_ne_bytes();
            let _ = self.skel.maps.llc_sched_idx.update(&llc_key, &zero, MapFlags::ANY);
        }

        let mut node_cpus: Vec<Vec<u32>> = vec![Vec::new(); self.nr_node];
        for cpu in 0..self.nr_cpus {
            let node = self.cpu_nodes[cpu as usize] as usize;
            node_cpus[node].push(cpu as u32);
        }

        for node in 0..self.nr_node {
            node_cpus[node].sort_by_key(|&cpu| loads[cpu as usize]);

            for (idx, &cpu) in node_cpus[node].iter().enumerate() {
                let map_key = (node as u32) * MAX_CPUS_PER_NODE as u32 + (idx as u32);
                let val = (cpu as u32).to_ne_bytes();
                let _ = self.skel.maps.node_sorted_cpu_map.update(&map_key.to_ne_bytes(), &val, MapFlags::ANY);
            }

            let node_key = (node as u32).to_ne_bytes();
            let zero = 0u32.to_ne_bytes();
            let _ = self.skel.maps.node_sched_idx.update(&node_key, &zero, MapFlags::ANY);
        }

        debug!(
            "Updated CPU loads: node0 min={}, max={}; node1 min={}, max={}",
            loads[node_cpus[0][0] as usize],
            loads[*node_cpus[0].last().unwrap() as usize],
            loads[node_cpus[1][0] as usize],
            loads[*node_cpus[1].last().unwrap() as usize]
        );

        self.prev_stats = curr_stats;
    }


    fn run(&mut self, _opts: &Opts) -> Result<UserExitInfo> {
        let shutdown = self.shutdown.clone();
        self.update_cpu_loads();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(Duration::from_millis(100));
            self.update_cpu_loads();
            if log::log_enabled!(log::Level::Debug) {
                debug!("Scheduler is running");
            }
        }
        uei_report!(&self.skel, uei)
    }
}

fn read_cpu_stats() -> Result<Vec<u64>> {
    let file = File::open("/proc/stat")?;
    let reader = BufReader::new(file);
    let mut stats = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("cpu ") {
            continue;
        }
        if !line.starts_with("cpu") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let user: u64 = parts[1].parse().unwrap_or(0);
        let nice: u64 = parts[2].parse().unwrap_or(0);
        let system: u64 = parts[3].parse().unwrap_or(0);
        let idle: u64 = parts[4].parse().unwrap_or(0);
        let iowait: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
        let irq: u64 = parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
        let softirq: u64 = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
        let steal: u64 = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);

        let total = user + nice + system + idle + iowait + irq + softirq + steal;
        stats.push(total);
        stats.push(idle);
        stats.push(irq + softirq);
    }
    Ok(stats)
}

fn read_sysfs_node_id(cpu: usize) -> Option<u32> {
    let cpu_path = format!("/sys/devices/system/cpu/cpu{}", cpu);
    if let Ok(entries) = std::fs::read_dir(&cpu_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().into_string().unwrap_or_default();
            if let Some(node_str) = name.strip_prefix("node") {
                if entry.path().is_dir() {
                    if let Ok(node_id) = node_str.parse::<u32>() {
                        return Some(node_id);
                    }
                }
            }
        }
    }
    let path = format!("/sys/devices/system/cpu/cpu{}/node", cpu);
    if let Ok(link) = std::fs::read_link(&path) {
        let name = link.file_name()?.to_string_lossy();
        let node_str = name.strip_prefix("node")?;
        return node_str.parse().ok();
    }
    Some(0)
}

fn read_sysfs_llc_id(cpu: usize) -> Option<u32> {
    let path = format!("/sys/devices/system/cpu/cpu{}/topology/cluster_id", cpu);
    if let Ok(content) = std::fs::read_to_string(&path) {
        content.trim().parse().ok()
    } else {
        Some(cpu as u32)
    }
}

fn set_cpu_in_mask(cpu: usize, mask: &mut [u8]) {
    let byte = cpu / 8;
    let bit = cpu % 8;
    if byte < mask.len() {
        mask[byte] |= 1 << bit;
    }
}

#[derive(Debug, Parser)]
struct Opts {
    #[clap(short = 'i', long, default_value = "1")]
    stat_interval: u64,

    #[clap(short = 'l', long)]
    allowed_node: Option<i32>,

    #[clap(short = 'P', long, default_value = "")]
    target_comm: String,

    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[clap(short = 'V', long)]
    version: bool,

    #[clap(flatten)]
    libbpf: LibbpfOpts,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, build_id::full_version(env!("CARGO_PKG_VERSION")));
        return Ok(());
    }

    let log_level = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut log_config = simplelog::ConfigBuilder::new();
    log_config.set_time_offset_to_local().unwrap();
    simplelog::TermLogger::init(
        log_level,
        log_config.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
        eprintln!("Received Ctrl+C, exiting...");
        std::process::exit(0);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        info!("{} scheduler started", SCHEDULER_NAME);
        if !sched.run(&opts)?.should_restart() {
            break;
        }
        info!("Restarting scheduler...");
    }
    Ok(())
}
