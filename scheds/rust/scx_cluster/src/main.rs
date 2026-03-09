// SPDX-License-Identifier: GPL-2.0
//
// scx_cluster: cluster-aware sched_ext scheduler based on scx_bpfland.
// Evenly distributes processes across LLC (L3) clusters.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::{c_int, c_ulong};
use std::fmt::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cluster";

#[derive(PartialEq)]
enum Powermode {
    Turbo,
    Performance,
    Powersave,
    Any,
}

fn get_primary_cpus(mode: Powermode) -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match (&mode, &cpu.core_type) {
            (Powermode::Performance, CoreType::Big { .. })
            | (Powermode::Powersave, CoreType::Little) => Some(*cpu_id),
            (Powermode::Any, ..) => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

fn cpus_to_cpumask(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return String::from("none");
    }

    let max_cpu_id = *cpus.iter().max().unwrap();

    let mut bitmask = vec![0u8; (max_cpu_id + 1 + 7) / 8];

    for cpu_id in cpus {
        let byte_index = cpu_id / 8;
        let bit_index = cpu_id % 8;
        bitmask[byte_index] |= 1 << bit_index;
    }

    let hex_str: String = bitmask.iter().rev().fold(String::new(), |mut f, byte| {
        let _ = write!(&mut f, "{:02x}", byte);
        f
    });

    format!("0x{}", hex_str)
}

/// Build per-CPU cluster id (dense index 0..nr_clusters-1) and cluster_id -> list of cpus.
/// Cluster = LLC (L3) domain from topology.
fn build_cluster_topo(topo: &Topology) -> (Vec<u32>, BTreeMap<u32, Vec<usize>>, u32) {
    let mut cpu_llc: BTreeMap<usize, usize> = BTreeMap::new();
    for core in topo.all_cores.values() {
        let llc_id = core.llc_id;
        for cpu_id in core.cpus.keys() {
            cpu_llc.insert(*cpu_id, llc_id);
        }
    }
    let unique_llcs: Vec<usize> = cpu_llc
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let nr_clusters = unique_llcs.len() as u32;
    let llc_to_dense: BTreeMap<usize, u32> = unique_llcs
        .into_iter()
        .enumerate()
        .map(|(i, llc)| (llc, i as u32))
        .collect();
    let mut cpu_to_cluster: Vec<u32> = vec![0; *NR_CPU_IDS];
    let mut cluster_cpus: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (cpu_id, &llc_id) in &cpu_llc {
        let cid = *llc_to_dense.get(&llc_id).unwrap_or(&0);
        if *cpu_id < cpu_to_cluster.len() {
            cpu_to_cluster[*cpu_id] = cid;
        }
        cluster_cpus.entry(cid).or_default().push(*cpu_id);
    }
    (cpu_to_cluster, cluster_cpus, nr_clusters)
}

#[derive(Debug, Parser)]
struct Opts {
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    #[clap(short = 'L', long, default_value = "0")]
    slice_min_us: u64,

    #[clap(short = 'l', long, default_value = "40000")]
    slice_us_lag: u64,

    #[clap(short = 't', long, default_value = "0")]
    throttle_us: u64,

    #[clap(short = 'I', long, allow_hyphen_values = true, default_value = "-1")]
    idle_resume_us: i64,

    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    local_pcpu: bool,

    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    sticky_tasks: bool,

    #[clap(short = 'm', long, default_value = "auto")]
    primary_domain: String,

    #[clap(short = 'P', long, action = clap::ArgAction::SetTrue)]
    preferred_idle_scan: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    cpufreq: bool,

    #[clap(long)]
    stats: Option<f64>,

    #[clap(long)]
    monitor: Option<f64>,

    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
    topo: Topology,
    power_profile: PowerProfile,
    stats_server: StatsServer<(), Metrics>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let topo = Topology::new().unwrap();

        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

        let (cpu_to_cluster, cluster_cpus, nr_clusters) = build_cluster_topo(&topo);
        info!("scx_cluster: {} clusters (LLC domains)", nr_clusters);
        for (cluster_id, cpus) in &cluster_cpus {
            let mut cpus_sorted = cpus.clone();
            cpus_sorted.sort_unstable();
            info!(
                "cluster {}: cpus={:?} mask={}",
                cluster_id,
                cpus_sorted,
                cpus_to_cpumask(&cpus_sorted)
            );
        }

        let power_profile = Self::power_profile();
        let domain =
            Self::resolve_energy_domain(&opts.primary_domain, power_profile).map_err(|err| {
                anyhow!(
                    "failed to resolve primary domain '{}': {}",
                    &opts.primary_domain,
                    err
                )
            })?;

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        if opts.idle_resume_us >= 0 {
            if !cpu_idle_resume_latency_supported() {
                warn!("idle resume latency not supported");
            } else {
                info!("Setting idle QoS to {} us", opts.idle_resume_us);
                for cpu in topo.all_cpus.values() {
                    update_cpu_idle_resume_latency(
                        cpu.id,
                        opts.idle_resume_us.try_into().unwrap(),
                    )?;
                }
            }
        }

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, cluster_ops, open_opts)?;

        skel.struct_ops.cluster_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.debug = opts.debug;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.local_pcpu = opts.local_pcpu;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.sticky_tasks = opts.sticky_tasks;
        rodata.slice_max = opts.slice_us * 1000;
        rodata.slice_min = opts.slice_min_us * 1000;
        rodata.slice_lag = opts.slice_us_lag * 1000;
        rodata.throttle_ns = opts.throttle_us * 1000;
        rodata.primary_all = domain.weight() == *NR_CPU_IDS;
        rodata.nr_clusters = nr_clusters;

        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        for (i, cpu) in cpus.iter().enumerate() {
            rodata.cpu_capacity[cpu.id] = cpu.cpu_capacity as c_ulong;
            rodata.preferred_cpus[i] = cpu.id as u64;
        }
        if opts.preferred_idle_scan {
            info!(
                "Preferred CPUs: {:?}",
                &rodata.preferred_cpus[0..cpus.len()]
            );
        }
        rodata.preferred_idle_scan = opts.preferred_idle_scan;
        rodata.local_kthreads = opts.local_kthreads || opts.throttle_us > 0;

        skel.struct_ops.cluster_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_enabled {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            } else {
                0
            };
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cluster_ops_mut().flags
        );

        let mut skel = scx_ops_load!(skel, cluster_ops, uei)?;

        Self::fill_cpu_to_cluster_map(&mut skel, &cpu_to_cluster)?;

        Self::init_energy_domain(&mut skel, &domain).map_err(|err| {
            anyhow!(
                "failed to initialize primary domain 0x{:x}: {}",
                domain,
                err
            )
        })?;

        if let Err(err) = Self::init_cpufreq_perf(&mut skel, &opts.primary_domain, opts.cpufreq) {
            bail!(
                "failed to initialize cpufreq performance level: error {}",
                err
            );
        }

        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        let struct_ops = Some(scx_ops_attach!(skel, cluster_ops)?);

        Self::enable_cluster_cpus(&mut skel, &cluster_cpus)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            opts,
            topo,
            power_profile,
            stats_server,
            user_restart: false,
        })
    }

    fn fill_cpu_to_cluster_map(
        skel: &mut BpfSkel<'_>,
        cpu_to_cluster: &[u32],
    ) -> Result<()> {
        for (cpu_id, &cluster_id) in cpu_to_cluster.iter().enumerate() {
            if cpu_id >= *NR_CPU_IDS {
                break;
            }
            let key = (cpu_id as u32).to_ne_bytes();
            let val = cluster_id.to_ne_bytes();
            skel.maps
                .cpu_to_cluster_map
                .update(&key, &val, MapFlags::ANY)?;
        }
        Ok(())
    }

    fn enable_cluster_cpus(
        skel: &mut BpfSkel<'_>,
        cluster_cpus: &BTreeMap<u32, Vec<usize>>,
    ) -> Result<()> {
        let prog = &mut skel.progs.enable_cluster_cpu;
        for (&cluster_id, cpus) in cluster_cpus {
            for &cpu_id in cpus {
                let mut args = cluster_cpu_arg {
                    cluster_id: cluster_id as i32,
                    cpu_id: cpu_id as i32,
                };
                let input = ProgramInput {
                    context_in: Some(unsafe {
                        std::slice::from_raw_parts_mut(
                            &mut args as *mut _ as *mut u8,
                            std::mem::size_of_val(&args),
                        )
                    }),
                    ..Default::default()
                };
                let out = prog.test_run(input).unwrap();
                if out.return_value != 0 {
                    warn!(
                        "enable_cluster_cpu(cluster={}, cpu={}) failed: {}",
                        cluster_id, cpu_id, out.return_value
                    );
                }
            }
        }
        Ok(())
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn epp_to_cpumask(profile: Powermode) -> Result<Cpumask> {
        let mut cpus = get_primary_cpus(profile).unwrap_or_default();
        if cpus.is_empty() {
            cpus = get_primary_cpus(Powermode::Any).unwrap_or_default();
        }
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    }

    fn resolve_energy_domain(primary_domain: &str, power_profile: PowerProfile) -> Result<Cpumask> {
        let domain = match primary_domain {
            "powersave" => Self::epp_to_cpumask(Powermode::Powersave)?,
            "performance" => Self::epp_to_cpumask(Powermode::Performance)?,
            "turbo" => Self::epp_to_cpumask(Powermode::Turbo)?,
            "auto" => match power_profile {
                PowerProfile::Powersave => Self::epp_to_cpumask(Powermode::Powersave)?,
                PowerProfile::Balanced { .. }
                | PowerProfile::Performance
                | PowerProfile::Unknown => Self::epp_to_cpumask(Powermode::Any)?,
            },
            "all" => Self::epp_to_cpumask(Powermode::Any)?,
            _ => Cpumask::from_str(primary_domain)?,
        };

        Ok(domain)
    }

    fn init_energy_domain(skel: &mut BpfSkel<'_>, domain: &Cpumask) -> Result<()> {
        info!("primary CPU domain = 0x{:x}", domain);

        if let Err(err) = Self::enable_primary_cpu(skel, -1) {
            bail!("failed to reset primary domain: error {}", err);
        }

        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
    }

    fn init_cpufreq_perf(
        skel: &mut BpfSkel<'_>,
        primary_domain: &str,
        auto: bool,
    ) -> Result<()> {
        let perf_lvl: i64 = match primary_domain {
            "powersave" => 0,
            _ if auto => -1,
            _ => 1024,
        };
        info!(
            "cpufreq performance level: {}",
            match perf_lvl {
                1024 => "max".into(),
                0 => "min".into(),
                n if n < 0 => "auto".into(),
                _ => perf_lvl.to_string(),
            }
        );
        skel.maps.bss_data.as_mut().unwrap().cpufreq_perf_lvl = perf_lvl;

        Ok(())
    }

    fn power_profile() -> PowerProfile {
        let profile = fetch_power_profile(true);
        if profile == PowerProfile::Unknown {
            fetch_power_profile(false)
        } else {
            profile
        }
    }

    fn refresh_sched_domain(&mut self) -> bool {
        if self.power_profile != PowerProfile::Unknown {
            let power_profile = Self::power_profile();
            if power_profile != self.power_profile {
                self.power_profile = power_profile;

                if self.opts.primary_domain == "auto" {
                    return true;
                }
                if let Err(err) = Self::init_cpufreq_perf(
                    &mut self.skel,
                    &self.opts.primary_domain,
                    self.opts.cpufreq,
                ) {
                    warn!("failed to refresh cpufreq performance level: error {}", err);
                }
            }
        }

        false
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn init_smt_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        let smt_siblings = topo.sibling_cpus();

        info!("SMT sibling CPUs: {:?}", smt_siblings);
        for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).unwrap();
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            nr_cpus: bss_data.nr_online_cpus,
            nr_kthread_dispatches: bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_dispatches: bss_data.nr_shared_dispatches,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if self.refresh_sched_domain() {
                self.user_restart = true;
                break;
            }
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");

        if self.opts.idle_resume_us >= 0 {
            if cpu_idle_resume_latency_supported() {
                for cpu in self.topo.all_cpus.values() {
                    update_cpu_idle_resume_latency(
                        cpu.id,
                        cpu.pm_qos_resume_latency_us as i32,
                    )
                    .unwrap();
                }
            }
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => debug!("stats monitor thread finished successfully"),
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            if sched.user_restart {
                continue;
            }
            break;
        }
    }

    Ok(())
}
