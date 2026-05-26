mod bpf_intf;
mod bpf_skel;
pub use bpf_intf::*;

use bpf_skel::*;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::OpenObject;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Hash)]
struct CpdomKey {
    numa_id: usize,
    llc_id: usize,
    is_big: bool,
}

#[derive(Debug, Clone)]
struct Cpdom {
    cpdom_id: usize,
    cpdom_alt_id: Cell<usize>,
    numa_id: usize,
    llc_id: usize,
    is_big: bool,
    cpu_ids: Vec<usize>,
    neighbor_map: BTreeMap<usize, Vec<usize>>,
}

fn cpdom_dist(from: &CpdomKey, to: &CpdomKey) -> usize {
    let mut d = 0;
    if from.is_big != to.is_big {
        d += 100;
    }
    if from.numa_id != to.numa_id {
        d += 10;
    } else if from.llc_id != to.llc_id {
        d += 1;
    }
    d
}

fn circular_sort(start: usize, list: &[usize]) -> Vec<usize> {
    let mut full = list.to_vec();
    full.push(start);
    full.sort();

    let s = full.binary_search(&start).expect("start must be in list");
    let n = full.len();

    let dist = |x: usize| {
        let d = (x + n - s) % n;
        d.min(n - d)
    };

    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&x| (dist(x), x));

    let sorted: Vec<usize> = order.iter().map(|&i| full[i]).collect();
    sorted[1..].to_vec()
}

fn build_cpdoms(topo: &Topology) -> BTreeMap<CpdomKey, Cpdom> {
    let mut cpdom_id_counter = 0usize;
    let mut cpdom_map: BTreeMap<CpdomKey, Cpdom> = BTreeMap::new();

    for (&node_id, node) in topo.nodes.iter() {
        for (&llc_id, llc) in node.llcs.iter() {
            let mut big_cpus: Vec<usize> = Vec::new();
            let mut little_cpus: Vec<usize> = Vec::new();

            for (&cpu_id, cpu) in llc.all_cpus.iter() {
                match cpu.core_type {
                    CoreType::Big { .. } => big_cpus.push(cpu_id),
                    CoreType::Little => little_cpus.push(cpu_id),
                }
            }

            for (is_big, cpus) in [(true, big_cpus), (false, little_cpus)] {
                if cpus.is_empty() {
                    continue;
                }

                let key = CpdomKey {
                    numa_id: node_id,
                    llc_id,
                    is_big,
                };

                let cpdom_id = cpdom_id_counter;
                cpdom_id_counter += 1;

                cpdom_map.insert(
                    key,
                    Cpdom {
                        cpdom_id,
                        cpdom_alt_id: Cell::new(cpdom_id),
                        numa_id: node_id,
                        llc_id,
                        is_big,
                        cpu_ids: cpus,
                        neighbor_map: BTreeMap::new(),
                    },
                );
            }
        }
    }

    for (from_k, from_v) in cpdom_map.iter() {
        for (to_k, to_v) in cpdom_map.iter() {
            if from_k == to_k {
                continue;
            }
            let d = cpdom_dist(from_k, to_k);
            from_v
                .neighbor_map
                .entry(d)
                .or_default()
                .push(to_v.cpdom_id);
        }
    }

    for (_, cpdom) in cpdom_map.iter_mut() {
        for (_, neighbors) in cpdom.neighbor_map.iter_mut() {
            *neighbors = circular_sort(cpdom.cpdom_id, neighbors);
        }
    }

    for (k, v) in cpdom_map.iter() {
        let mut alt_key = k.clone();
        alt_key.is_big = !k.is_big;

        if let Some(alt_v) = cpdom_map.get(&alt_key) {
            v.cpdom_alt_id.set(alt_v.cpdom_id);
        } else {
            'outer: for (_, neighbors) in v.neighbor_map.iter() {
                for &nid in neighbors.iter() {
                    for (_, nv) in cpdom_map.iter() {
                        if nv.cpdom_id == nid && nv.is_big == alt_key.is_big {
                            v.cpdom_alt_id.set(nv.cpdom_id);
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    cpdom_map
}

#[derive(Debug, Parser)]
struct Opts {
    #[clap(short = 's', long, default_value = "5.0")]
    slice_max_us: f64,

    #[clap(short = 'S', long, default_value = "0.5")]
    slice_min_us: f64,

    #[clap(short = 't', long, default_value = "true")]
    print_topology: bool,
}

struct Scheduler<'a> {
    skel: TraeSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let topo = Topology::new().context("Failed to build topology")?;
        let cpdom_map = build_cpdoms(&topo);
        let nr_cpdoms = cpdom_map.len();

        if opts.print_topology {
            Self::print_topology(&topo, &cpdom_map);
        }

        if *NR_CPU_IDS > TRAE_CPU_ID_MAX as usize {
            bail!(
                "Too many CPU IDs: {} (max {})",
                *NR_CPU_IDS,
                TRAE_CPU_ID_MAX
            );
        }

        if nr_cpdoms > TRAE_CPDOM_MAX_NR as usize {
            bail!(
                "Too many compute domains: {} (max {})",
                nr_cpdoms,
                TRAE_CPDOM_MAX_NR
            );
        }

        let mut skel_builder = TraeSkelBuilder::default();
        skel_builder.obj_builder.open_object(open_object);

        let mut skel = scx_ops_open!(skel_builder, open_object, trae_ops, None)?;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
        rodata.nr_cpus_onln = topo.all_cpus.len() as u32;
        rodata.nr_cpdoms = nr_cpdoms as u32;
        rodata.nr_numas = topo.nodes.len() as u32;
        rodata.is_smt_active = topo.smt_enabled;
        rodata.slice_max_ns = (opts.slice_max_us * 1000.0) as u64;
        rodata.slice_min_ns = (opts.slice_min_us * 1000.0) as u64;

        for (cpu_id, cpu) in topo.all_cpus.iter() {
            if *cpu_id < TRAE_CPU_ID_MAX as usize {
                rodata.cpu_capacity[*cpu_id] = cpu.cpu_capacity as u16;
                rodata.cpu_big[*cpu_id] =
                    if cpu.core_type != CoreType::Little { 1 } else { 0 };
            }
        }

        if topo.smt_enabled {
            let siblings = topo.sibling_cpus();
            for cpu_id in 0..TRAE_CPU_ID_MAX as usize {
                if cpu_id < siblings.len() {
                    rodata.cpu_sibling[cpu_id] =
                        if siblings[cpu_id] >= 0 { siblings[cpu_id] as u32 } else { cpu_id as u32 };
                }
            }
        }

        let bss = skel.maps.bss_data.as_mut().unwrap();
        for (_, cpdom) in cpdom_map.iter() {
            let id = cpdom.cpdom_id;
            if id >= TRAE_CPDOM_MAX_NR as usize {
                continue;
            }

            bss.cpdom_ctxs[id].id = id as u64;
            bss.cpdom_ctxs[id].alt_id = cpdom.cpdom_alt_id.get() as u64;
            bss.cpdom_ctxs[id].numa_id = cpdom.numa_id as u8;
            bss.cpdom_ctxs[id].llc_id = cpdom.llc_id as u8;
            bss.cpdom_ctxs[id].is_big = cpdom.is_big as u8;
            bss.cpdom_ctxs[id].is_valid = 1;

            for &cpu_id in cpdom.cpu_ids.iter() {
                if cpu_id >= TRAE_CPU_ID_MAX as usize {
                    continue;
                }
                let i = cpu_id / 64;
                let j = cpu_id % 64;
                bss.cpdom_ctxs[id].__cpumask[i] |= 1u64 << j;
            }

            if cpdom.neighbor_map.len() > TRAE_CPDOM_MAX_DIST as usize {
                panic!(
                    "cpdom {} has {} distance levels, exceeding max {}",
                    id,
                    cpdom.neighbor_map.len(),
                    TRAE_CPDOM_MAX_DIST
                );
            }

            for (dist_idx, neighbors) in cpdom.neighbor_map.iter().enumerate() {
                if dist_idx >= TRAE_CPDOM_MAX_DIST as usize {
                    break;
                }
                let (_, neighbor_ids) = neighbors;
                let nr = neighbor_ids.len().min(TRAE_CPDOM_MAX_NR_PER_DIST as usize);
                bss.cpdom_ctxs[id].nr_neighbors[dist_idx] = nr as u8;
                for (i, &nid) in neighbor_ids.iter().take(nr).enumerate() {
                    let idx = dist_idx * TRAE_CPDOM_MAX_NR_PER_DIST as usize + i;
                    bss.cpdom_ctxs[id].neighbor_ids[idx] = nid as u8;
                }
            }
        }

        let mut skel = scx_ops_load!(skel, trae_ops, uei)?;

        let struct_ops = Some(scx_ops_attach!(skel, trae_ops)?);

        Ok(Self {
            skel,
            struct_ops,
        })
    }

    fn print_topology(topo: &Topology, cpdom_map: &BTreeMap<CpdomKey, Cpdom>) {
        println!("===== scx_trae: Topology Overview =====");
        println!(
            "  CPUs: {} online, {} possible, SMT: {}",
            topo.all_cpus.len(),
            *NR_CPU_IDS,
            if topo.smt_enabled { "yes" } else { "no" }
        );
        println!("  NUMA nodes: {}", topo.nodes.len());
        println!("  Compute domains (cpdoms): {}", cpdom_map.len());
        println!();

        println!("----- NUMA Nodes -----");
        for (&node_id, node) in topo.nodes.iter() {
            println!("  NUMA {}:", node_id);
            for (&llc_id, llc) in node.llcs.iter() {
                let llc_cpus: Vec<usize> = llc.all_cpus.keys().copied().collect();
                println!(
                    "    LLC {}: CPUs {:?}",
                    llc_id,
                    llc_cpus
                );
            }
        }
        println!();

        println!("----- Compute Domains (cpdoms) -----");
        for (_, cpdom) in cpdom_map.iter() {
            let core_type = if cpdom.is_big { "big" } else { "little" };
            println!(
                "  cpdom {} [NUMA={}, LLC={}, {}]",
                cpdom.cpdom_id, cpdom.numa_id, cpdom.llc_id, core_type
            );
            println!(
                "    alt_id={}  CPUs: {:?}",
                cpdom.cpdom_alt_id.get(),
                cpdom.cpu_ids
            );

            for (dist_idx, neighbors) in cpdom.neighbor_map.iter().enumerate() {
                let (_, neighbor_ids) = neighbors;
                if !neighbor_ids.is_empty() {
                    let neighbor_details: Vec<String> = neighbor_ids
                        .iter()
                        .map(|&nid| {
                            for (_, nv) in cpdom_map.iter() {
                                if nv.cpdom_id == nid {
                                    let t = if nv.is_big { "big" } else { "lit" };
                                    return format!(
                                        "{}(N{}L{}{})",
                                        nid, nv.numa_id, nv.llc_id, t
                                    );
                                }
                            }
                            format!("{}", nid)
                        })
                        .collect();
                    println!(
                        "    dist[{}]: [{}]",
                        dist_idx,
                        neighbor_details.join(", ")
                    );
                }
            }
        }

        println!();

        println!("----- CPU -> cpdom Mapping -----");
        let mut cpu_cpdom: Vec<(usize, usize, bool)> = Vec::new();
        for (_, cpdom) in cpdom_map.iter() {
            for &cpu_id in cpdom.cpu_ids.iter() {
                cpu_cpdom.push((cpu_id, cpdom.cpdom_id, cpdom.is_big));
            }
        }
        cpu_cpdom.sort_by_key(|&(c, _, _)| c);
        for (cpu_id, cpdom_id, is_big) in cpu_cpdom.iter() {
            let t = if *is_big { "B" } else { "L" };
            print!("  CPU{:3}->cpdom{:3}[{}] ", cpu_id, cpdom_id, t);
            if (cpu_id + 1) % 4 == 0 {
                println!();
            }
        }
        if !cpu_cpdom.is_empty() && cpu_cpdom.len() % 4 != 0 {
            println!();
        }

        if topo.smt_enabled {
            println!();
            println!("----- SMT Siblings -----");
            let siblings = topo.sibling_cpus();
            for cpu_id in 0..siblings.len() {
                if siblings[cpu_id] >= 0 && (cpu_id as i32) < siblings[cpu_id] {
                    println!("  CPU{} <-> CPU{}", cpu_id, siblings[cpu_id]);
                }
            }
        }

        println!();
        println!("===== End of Topology =====");
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        while !shutdown.load(Ordering::Relaxed)
            && !uei_exited!(&self.skel, uei)
        {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei);
        Ok(())
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(link) = self.struct_ops.take() {
            drop(link);
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    sched.run(shutdown)
}
