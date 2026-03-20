// SPDX-License-Identifier: GPL-2.0
//
// scx_redis: Redis-oriented sched_ext BPF backend (Rust userspace).

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
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

    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Monitor redis-server threads: CPU, group, main vs worker.
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

        let mut skel = scx_ops_load!(skel, redis_ops, uei)?;
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

fn monitor_redis_groups() -> Result<()> {
    const GROUP_SIZE: usize = 8;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    for proc_res in all_processes()? {
        let Ok(proc) = proc_res else { continue };
        let Ok(stat) = proc.stat() else { continue };
        if !stat.comm.starts_with("redis-server") {
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
        std::thread::spawn(move || {
            let intv = Duration::from_secs_f64(intv);
            loop {
                if shutdown_copy.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = monitor_redis_groups() {
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
