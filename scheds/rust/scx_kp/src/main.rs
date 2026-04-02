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

fn parse_u64_token(tok: &str) -> anyhow::Result<u64> {
    let t = tok.trim();
    if t.is_empty() {
        return Ok(0);
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(t.parse()?)
    }
}

/// Five u64 words: CPUs 0–63, 64–127, …, 256–319. Single token without comma sets word 0 only (compat).
fn parse_kthread_cpu_mask(s: &str) -> anyhow::Result<[u64; 5]> {
    let mut out = [0u64; 5];
    let t = s.trim();
    if t.is_empty() {
        return Ok(out);
    }
    if !t.contains(',') {
        out[0] = parse_u64_token(t)?;
        return Ok(out);
    }
    let parts: Vec<&str> = t.split(',').collect();
    if parts.len() > 5 {
        anyhow::bail!("simple-kthread-mask: at most 5 comma-separated chunks (320 CPUs)");
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = parse_u64_token(p)?;
    }
    Ok(out)
}

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

    /// full mode only: max per-CPU steal attempts per dispatch (1-16, ring from cpu+1).
    #[clap(long, default_value_t = 16)]
    steal_max_cpus: u64,

    /// full: learned priority switch (wait high + wake freq high => LEARN_DSQ).
    #[clap(long, default_value_t = 0)]
    full_learn_prio: u64,

    /// full: minimum waiting time (us) to be considered learned-high priority.
    #[clap(long, default_value_t = 500)]
    full_wait_thr_us: u64,

    /// full: maximum enqueue interval (us) between two consecutive enqueues to be high wake frequency.
    #[clap(long, default_value_t = 100)]
    full_wake_interval_thr_us: u64,

    /// full: avg/aging/vtime + steal; simple: minimal hot path.
    #[clap(long, value_enum, default_value_t = EnqueueMode::Full)]
    enqueue_mode: EnqueueMode,

    /// simple mode only: enqueue ksoftirqd to shared DSQ only (0=off, 1=on).
    #[clap(long, default_value_t = 1)]
    simple_softirq_isolate: u64,

    /// simple mode: kthread-dedicated CPUs as up to five u64 words (CPUs 0..320).
    /// Format: "c0,c1,c2,c3,c4" (hex 0x.. or decimal); omit trailing zeros. One value without comma sets CPUs 0–63 only.
    /// Example last 20 CPUs (300–319): "0,0,0,0,0xfffff00000000000"
    #[clap(long)]
    simple_kthread_mask: Option<String>,

    /// simple: learned priority switch (wait high + wake freq high => enqueue to LEARN_DSQ).
    #[clap(long, default_value_t = 0)]
    simple_learn_prio: u64,

    /// simple: minimum waiting time (us) to be considered learned-high priority.
    #[clap(long, default_value_t = 500)]
    simple_wait_thr_us: u64,

    /// simple: maximum enqueue interval (us) between two consecutive enqueues to be considered high wake frequency.
    #[clap(long, default_value_t = 100)]
    simple_wake_interval_thr_us: u64,

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
        rodata.kp_steal_max_cpus = opts.steal_max_cpus.clamp(1, 16);
        rodata.kp_full_learn_prio = if opts.full_learn_prio == 0 { 0 } else { 1 };
        rodata.kp_full_wait_thr_ns = opts.full_wait_thr_us * 1000;
        rodata.kp_full_wake_interval_thr_ns = opts.full_wake_interval_thr_us * 1000;
        rodata.kp_enqueue_simple = match opts.enqueue_mode {
            EnqueueMode::Simple => 1,
            EnqueueMode::Full => 0,
        };
        rodata.kp_simple_softirq_isolate = if opts.simple_softirq_isolate == 0 {
            0
        } else {
            1
        };
        rodata.kp_simple_learn_prio = if opts.simple_learn_prio == 0 { 0 } else { 1 };
        rodata.kp_simple_wait_thr_ns = opts.simple_wait_thr_us * 1000;
        rodata.kp_simple_wake_interval_thr_ns = opts.simple_wake_interval_thr_us * 1000;
        let km = parse_kthread_cpu_mask(opts.simple_kthread_mask.as_deref().unwrap_or(""))?;
        for i in 0..5 {
            rodata.kp_simple_kthread_cpu_mask[i] = km[i];
        }
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
