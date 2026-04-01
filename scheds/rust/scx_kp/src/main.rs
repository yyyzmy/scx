// SPDX-License-Identifier: GPL-2.0
//
// scx_kp: a new scheduler line based on scx_beerland.

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use libbpf_rs::OpenObject;
use log::{debug, info};
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const SCHEDULER_NAME: &str = "scx_kp";

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum EnqueueMode {
    /// FIFO dsq_insert, local-first, no avg/aging in enqueue, no steal in dispatch.
    Simple,
    /// Full: avg + aging + vtime insert, short->local, shared + per-CPU steal.
    #[default]
    Full,
}

#[derive(Clone, Debug, Parser)]
struct Opts {
    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Short-task threshold in microseconds.
    /// Tasks with estimated remaining <= this threshold prefer per-CPU DSQs.
    #[clap(long, default_value_t = 80)]
    short_task_us: u64,

    /// Aging divisor used in enqueue priority:
    /// rem_est_adj = avg_runtime + wait / aging_div (minimum 1).
    #[clap(long, default_value_t = 8)]
    aging_div: u64,

    /// Maximum estimated remaining runtime (milliseconds).
    #[clap(long, default_value_t = 200)]
    max_rem_est_ms: u64,

    /// full: avg/aging/vtime + steal; simple: minimal hot path.
    #[clap(long, value_enum, default_value_t = EnqueueMode::Full)]
    enqueue_mode: EnqueueMode,

    /// simple mode only: enqueue ksoftirqd to shared DSQ only (0=off, 1=on).
    #[clap(long, default_value_t = 1)]
    simple_softirq_isolate: u64,

    /// Print version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
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
        let mut skel = scx_ops_open!(skel_builder, open_object, kp_ops, open_opts)?;
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.kp_short_task_ns = opts.short_task_us * 1000;
        rodata.kp_aging_div = opts.aging_div.max(1);
        rodata.kp_max_rem_est_ns = opts.max_rem_est_ms * 1000 * 1000;
        rodata.kp_enqueue_simple = match opts.enqueue_mode {
            EnqueueMode::Simple => 1,
            EnqueueMode::Full => 0,
        };
        rodata.kp_simple_softirq_isolate = if opts.simple_softirq_isolate == 0 {
            0
        } else {
            1
        };
        let mut skel = scx_ops_load!(skel, kp_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, kp_ops)?);

        Ok(Self { skel, struct_ops })
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
