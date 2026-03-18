// SPDX-License-Identifier: GPL-2.0
//
// scx_simple: Rust userspace wrapper around the simple sched_ext BPF backend.

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
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

const SCHEDULER_NAME: &str = "scx_simple";

#[derive(Clone, Debug, Parser)]
struct Opts {
    /// Enable FIFO scheduling instead of weighted vtime.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    fifo: bool,

    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Monitor redis-server threads and print their CPU and group (CPUs/8).
    #[clap(long)]
    monitor_redis: Option<f64>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    opts: &'a Opts,
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
        let mut skel = scx_ops_open!(skel_builder, open_object, simple_ops, open_opts)?;

        // Configure rodata.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.fifo_sched = opts.fifo;

        // Load and attach.
        let mut skel = scx_ops_load!(skel, simple_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, simple_ops)?);

        Ok(Self { skel, struct_ops, opts })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(std::time::Duration::from_millis(100));
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
    // CPUs-per-group must match GROUP_SIZE in BPF.
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

        // Iterate threads of this redis-server.
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
            println!(
                "{ts:.3} [redis pid={pid} tid={tid}] cpu={cpu} group={group}"
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

    // Optional redis monitor thread.
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

