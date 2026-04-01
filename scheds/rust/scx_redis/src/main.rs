// SPDX-License-Identifier: GPL-2.0
//
// scx_redis: Redis-oriented sched_ext BPF backend (Rust userspace).

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use log::{debug, info};
use procfs::process::all_processes;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const SCHEDULER_NAME: &str = "scx_redis";
const SMT_MAX_SIBLINGS: usize = 2;
/// Must match `TASK_COMM_LEN` in the kernel / BPF object (16).
const TARGET_COMM_BYTES: usize = 16;

fn parse_cpu_list(list: &str) -> Vec<u32> {
    let mut out = Vec::<u32>::new();
    for part in list.trim().split(',').filter(|p| !p.trim().is_empty()) {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (a.parse::<u32>(), b.parse::<u32>()) {
                let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
                for v in lo..=hi {
                    out.push(v);
                }
            }
        } else if let Ok(v) = part.parse::<u32>() {
            out.push(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn load_smt_topology_to_bpf(skel: &mut BpfSkel<'_>) -> Result<()> {
    // Typical path: /sys/devices/system/cpu/cpu*/topology/thread_siblings_list
    let cpu_root = Path::new("/sys/devices/system/cpu");
    let Ok(entries) = fs::read_dir(cpu_root) else {
        // If sysfs isn't accessible, fall back to "fixed CPU only" isolation.
        return Ok(());
    };

    for ent in entries {
        let Ok(ent) = ent else { continue };
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("cpu") {
            continue;
        }
        let Ok(cpu_id) = name[3..].parse::<u32>() else { continue };
        if cpu_id >= 1024 {
            continue; // matches MAX_CPUS in BPF
        }

        let sib_path = cpu_root.join(format!(
            "{}/topology/thread_siblings_list",
            name
        ));
        let Ok(sib_str) = fs::read_to_string(&sib_path) else {
            continue;
        };

        let sibs = parse_cpu_list(&sib_str);
        let n = (sibs.len() as usize).min(SMT_MAX_SIBLINGS);

        let key = cpu_id.to_ne_bytes();
        let n_bytes = (n as u32).to_ne_bytes();
        skel.maps
            .cpu_smt_n
            .update(&key, &n_bytes, libbpf_rs::MapFlags::ANY)?;

        let mut sib_arr = [0u32; SMT_MAX_SIBLINGS];
        for (i, &sid) in sibs.iter().take(SMT_MAX_SIBLINGS).enumerate() {
            sib_arr[i] = sid;
        }
        let sib_val = unsafe {
            std::slice::from_raw_parts(
                sib_arr.as_ptr() as *const u8,
                std::mem::size_of_val(&sib_arr),
            )
        };
        skel.maps
            .cpu_smt_sibs
            .update(&key, sib_val, libbpf_rs::MapFlags::ANY)?;
    }

    Ok(())
}

#[derive(Clone, Debug, Parser)]
struct Opts {
    /// Enable FIFO scheduling instead of weighted vtime.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    fifo: bool,

    /// Main-thread time slice multiplier (vs SCX_SLICE_DFL).
    #[clap(long, default_value_t = 4)]
    main_slice_mult: u32,

    /// Extra divisor on main-thread vtime charge (higher => less penalty / relative priority).
    #[clap(long, default_value_t = 2)]
    main_vtime_div: u32,

    /// Task `comm` prefix for the workload main thread (same semantics as before for `redis-server`).
    /// Longer than 15 bytes is truncated. Used to tag the whole thread group via `redis_tgid`.
    #[clap(long, default_value = "redis-server")]
    target_comm: String,

    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Monitor workload threads (same prefix as `--target-comm`): CPU, group, main vs worker.
    #[clap(long)]
    monitor_redis: Option<f64>,

    /// Log aggregated BPF stats (per-CPU sums) every N seconds.
    #[clap(long)]
    stats_interval: Option<f64>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
}

fn sum_stat_map(skel: &BpfSkel<'_>, key: u32) -> u64 {
    let key_b = key.to_ne_bytes();
    let Ok(Some(percpu_vals)) = skel
        .maps
        .stats
        .lookup_percpu(&key_b, libbpf_rs::MapFlags::ANY)
    else {
        return 0;
    };
    let mut sum = 0u64;
    for cpu_val in &percpu_vals {
        if cpu_val.len() >= std::mem::size_of::<u64>() {
            let v: u64 = unsafe { std::ptr::read_unaligned(cpu_val.as_ptr() as *const u64) };
            sum = sum.saturating_add(v);
        }
    }
    sum
}

fn log_redis_stats(skel: &BpfSkel<'_>) {
    let local = sum_stat_map(skel, 0);
    let enq = sum_stat_map(skel, 1);
    let redis_stop = sum_stat_map(skel, 2);
    let main_pin = sum_stat_map(skel, 3);
    let main_off = sum_stat_map(skel, 4);
    info!(
        "stats: local_dispatch={local} enqueue={enq} redis_stopping~ctx={redis_stop} \
         main_on_pinned_cpu={main_pin} main_off_pinned={main_off}"
    );
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            scx_utils::build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, redis_ops, open_opts)?;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.fifo_sched = opts.fifo;
        rodata.main_slice_mult = opts.main_slice_mult;
        rodata.main_vtime_div = opts.main_vtime_div;
        write_target_comm_rodata(rodata, &opts.target_comm)?;

        let mut skel = scx_ops_load!(skel, redis_ops, uei)?;

        // Populate SMT siblings info so workers can exclude the whole physical core.
        load_smt_topology_to_bpf(&mut skel)?;
        let struct_ops = Some(scx_ops_attach!(skel, redis_ops)?);

        Ok(Self { skel, struct_ops, opts })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let stats_iv = self
            .opts
            .stats_interval
            .map(|s| Duration::from_secs_f64(s.max(0.1)));
        let mut last_stats = std::time::Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Some(iv) = stats_iv {
                if last_stats.elapsed() >= iv {
                    log_redis_stats(&self.skel);
                    last_stats = std::time::Instant::now();
                }
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn write_target_comm_rodata(
    rodata: &mut bpf_skel::types::rodata,
    s: &str,
) -> Result<()> {
    if s.is_empty() {
        anyhow::bail!("--target-comm must not be empty");
    }
    let mut buf = [0i8; TARGET_COMM_BYTES];
    let take = s.len().min(TARGET_COMM_BYTES - 1);
    for (i, &b) in s.as_bytes()[..take].iter().enumerate() {
        buf[i] = b as i8;
    }
    rodata.target_comm = buf;
    Ok(())
}

fn monitor_redis_groups(prefix: &str) -> Result<()> {
    const GROUP_SIZE: usize = 8;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    for proc_res in all_processes()? {
        let Ok(proc) = proc_res else { continue };
        let Ok(stat) = proc.stat() else { continue };
        if !stat.comm.starts_with(prefix) {
            continue;
        }
        let pid = stat.pid;

        let Ok(tasks) = proc.tasks() else { continue };
        for t_res in tasks {
            let Ok(t) = t_res else { continue };
            let Ok(tstat) = t.stat() else { continue };
            let tid = tstat.pid;
            let Some(cpu_i32) = tstat.processor else { continue };
            if cpu_i32 < 0 {
                continue;
            }
            let cpu: usize = (cpu_i32 as u32) as usize;
            let group = cpu / GROUP_SIZE;
            let role = if tid == pid { "main" } else { "worker" };
            println!(
                "{ts:.3} [redis pid={pid} tid={tid} {role}] cpu={cpu} group={group}"
            );
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            scx_utils::build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let loglevel = if opts.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let mut lcfg = ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Off)
        .set_thread_level(LevelFilter::Off);
    TermLogger::init(
        loglevel,
        lcfg.build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor_redis {
        let shutdown_copy = shutdown.clone();
        let prefix = opts.target_comm.clone();
        std::thread::spawn(move || {
            let intv = Duration::from_secs_f64(intv);
            loop {
                if shutdown_copy.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = monitor_redis_groups(&prefix) {
                    debug!("redis monitor error: {e:#}");
                }
                std::thread::sleep(intv);
            }
        });
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;

        let uei = sched.run(shutdown.clone())?;
        if !uei.should_restart() {
            break;
        }
        debug!("Scheduler requested restart");
    }

    Ok(())
}
