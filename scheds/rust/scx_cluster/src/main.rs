// SPDX-License-Identifier: GPL-2.0
//
// scx_cluster: cluster-aware scheduler based on scx_bpfland.
// Evenly distributes processes across LLC (L3) clusters.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::c_int;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapFlags;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::import_enums;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &'static str = "scx_cluster";

#[derive(PartialEq)]
enum Powermode {
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

fn cpus_to_cpumask(cpus: &Vec<usize>) -> String {
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
    let hex_str: String = bitmask.iter().rev().map(|byte| format!("{:02x}", byte)).collect();
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
    let unique_llcs: Vec<usize> = cpu_llc.values().cloned().collect::<BTreeSet<_>>().into_iter().collect();
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

    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    #[clap(short = 'S', long, default_value = "1000")]
    slice_us_min: u64,

    #[clap(short = 'l', long, allow_hyphen_values = true, default_value = "20000")]
    slice_us_lag: i64,

    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    no_preempt: bool,

    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    local_pcpu: bool,

    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    #[clap(short = 'm', long, default_value = "auto")]
    primary_domain: String,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l2: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_l3: bool,

    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    cpufreq: bool,

    #[clap(short = 'c', long, default_value = "10", hide = true)]
    nvcsw_max_thresh: u64,

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
}

fn is_smt_active() -> std::io::Result<i32> {
    let mut file = File::open("/sys/devices/system/cpu/smt/active")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents.trim().parse().unwrap_or(0))
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
    power_profile: PowerProfile,
    stats_server: StatsServer<(), Metrics>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        set_rlimit_infinity();
        assert!(opts.slice_us >= opts.slice_us_min);

        let smt_enabled = match is_smt_active() {
            Ok(value) => value == 1,
            Err(_) => false,
        };
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        let topo = Topology::new().unwrap();
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

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, cluster_ops)?;

        skel.struct_ops.cluster_ops_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.debug = opts.debug;
        skel.maps.rodata_data.smt_enabled = smt_enabled;
        skel.maps.rodata_data.local_pcpu = opts.local_pcpu;
        skel.maps.rodata_data.local_kthreads = opts.local_kthreads;
        skel.maps.rodata_data.no_preempt = opts.no_preempt;
        skel.maps.rodata_data.slice_max = opts.slice_us * 1000;
        skel.maps.rodata_data.slice_min = opts.slice_us_min * 1000;
        skel.maps.rodata_data.slice_lag = opts.slice_us_lag * 1000;
        skel.maps.rodata_data.nr_clusters = nr_clusters;

        let mut skel = scx_ops_load!(skel, cluster_ops, uei)?;

        let power_profile = fetch_power_profile(false);
        if let Err(err) = Self::init_energy_domain(&mut skel, &opts.primary_domain, power_profile) {
            warn!("failed to initialize primary domain: error {}", err);
        }
        if let Err(err) = Self::init_cpufreq_perf(&mut skel, &opts.primary_domain, opts.cpufreq) {
            warn!("failed to initialize cpufreq performance level: error {}", err);
        }

        if !opts.disable_l2 {
            Self::init_l2_cache_domains(&mut skel, &topo)?;
        }
        if !opts.disable_l3 {
            Self::init_l3_cache_domains(&mut skel, &topo)?;
        }

        Self::fill_cpu_to_cluster_map(&mut skel, &cpu_to_cluster)?;

        let struct_ops = Some(scx_ops_attach!(skel, cluster_ops)?);

        /* After attach, cluster_init has created per-cluster cpumasks; fill them via enable_cluster_cpu */
        Self::enable_cluster_cpus(&mut skel, &cluster_cpus)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            opts,
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
            skel.maps.cpu_to_cluster_map.update(&key, &val, MapFlags::ANY)?;
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
        let mut args = cpu_arg { cpu_id: cpu as c_int };
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

    fn init_energy_domain(
        skel: &mut BpfSkel<'_>,
        primary_domain: &str,
        power_profile: PowerProfile,
    ) -> Result<()> {
        let domain = match primary_domain {
            "powersave" => Self::epp_to_cpumask(Powermode::Powersave)?,
            "performance" => Self::epp_to_cpumask(Powermode::Performance)?,
            "auto" => match power_profile {
                PowerProfile::Powersave => Self::epp_to_cpumask(Powermode::Powersave)?,
                PowerProfile::Performance | PowerProfile::Balanced => {
                    Self::epp_to_cpumask(Powermode::Performance)?
                }
                PowerProfile::Unknown => Self::epp_to_cpumask(Powermode::Any)?,
            },
            "all" => Self::epp_to_cpumask(Powermode::Any)?,
            _ => Cpumask::from_str(primary_domain)?,
        };

        info!("primary CPU domain = 0x{:x}", domain);

        if let Err(err) = Self::enable_primary_cpu(skel, -1) {
            warn!("failed to reset primary domain: error {}", err);
        }
        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu as i32) {
                    warn!("failed to add CPU {} to primary domain: error {}", cpu, err);
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
        skel.maps.bss_data.cpufreq_perf_lvl = perf_lvl;
        Ok(())
    }

    fn refresh_sched_domain(&mut self) -> bool {
        if self.power_profile != PowerProfile::Unknown {
            let power_profile = fetch_power_profile(false);
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
        lvl: usize,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            lvl_id: lvl as c_int,
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

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), u32>,
    ) -> Result<(), std::io::Error> {
        let mut cache_id_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for core in topo.all_cores.values() {
            for (cpu_id, cpu) in &core.cpus {
                let cache_id = match cache_lvl {
                    2 => cpu.l2_id,
                    3 => cpu.llc_id,
                    _ => panic!("invalid cache level {}", cache_lvl),
                };
                cache_id_map.entry(cache_id).or_default().push(*cpu_id);
            }
        }
        for (cache_id, cpus) in cache_id_map {
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    if let Err(_) = enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu) {
                        warn!(
                            "L{} cache ID {}: failed to set CPU {} sibling {}",
                            cache_lvl, cache_id, *cpu, *sibling_cpu
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn init_l2_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 2, &|s, l, c, sc| Self::enable_sibling_cpu(s, l, c, sc))
    }

    fn init_l3_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 3, &|s, l, c, sc| Self::enable_sibling_cpu(s, l, c, sc))
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            nr_running: self.skel.maps.bss_data.nr_running,
            nr_cpus: self.skel.maps.bss_data.nr_online_cpus,
            nr_kthread_dispatches: self.skel.maps.bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: self.skel.maps.bss_data.nr_direct_dispatches,
            nr_shared_dispatches: self.skel.maps.bss_data.nr_shared_dispatches,
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
        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
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
    lcfg.set_time_level(simplelog::LevelFilter::Error)
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
                Err(e) => warn!("stats monitor thread finished with error {}", e),
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
