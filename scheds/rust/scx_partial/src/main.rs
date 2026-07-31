// SPDX-License-Identifier: GPL-2.0
//
// scx_partial: Partial scheduler that only takes over specific tasks
//              and restricts them to run on CPU 0-7.

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{MapCore, OpenObject};
use log::{debug, info};
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const SCHEDULER_NAME: &str = "scx_partial";

#[derive(Clone, Debug, Parser)]
struct Opts {
    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

#[repr(C)]
struct PartialStats {
    nr_managed: u32,
    nr_init: u32,
    nr_exit: u32,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
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
        let mut skel = scx_ops_open!(skel_builder, open_object, partial_ops, open_opts)?;

        // Configure scheduler flags BEFORE loading
        // Enable SCX_OPS_SWITCH_PARTIAL to enable partial takeover mode
        // With this flag, only tasks with SCHED_EXT policy are taken over
        skel.struct_ops.partial_ops_mut().flags = *compat::SCX_OPS_SWITCH_PARTIAL
            | *compat::SCX_OPS_KEEP_BUILTIN_IDLE;

        info!("Partial scheduler initialized");
        info!("Only tasks with SCHED_EXT policy will be taken over and restricted to CPU 0-7");
        info!("Use `chrt -E <pid>` to move a task to SCHED_EXT policy");

        // Load the BPF program
        let mut skel = scx_ops_load!(skel, partial_ops, uei)?;

        // Attach the scheduler
        let struct_ops = Some(scx_ops_attach!(skel, partial_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut tick = 0u64;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(std::time::Duration::from_secs(1));
            tick += 1;

            // Read stats from BPF map (reference scx_trae's implementation)
            let stats_data = self.skel.maps.partial_stats_stor.lookup(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY);
            match stats_data {
                Ok(Some(data)) => {
                    if data.len() >= std::mem::size_of::<PartialStats>() {
                        let stats: &PartialStats = unsafe { &*(data.as_ptr() as *const PartialStats) };
                        info!(
                            "[{:5}] Managed tasks: {}, Initialized: {}, Exited: {}",
                            tick,
                            stats.nr_managed,
                            stats.nr_init,
                            stats.nr_exit
                        );
                    } else {
                        info!("[{:5}] Managed tasks: N/A (stats data too short)", tick);
                    }
                }
                _ => {
                    info!("[{:5}] Managed tasks: N/A (stats lookup failed)", tick);
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