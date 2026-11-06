// SPDX-License-Identifier: GPL-2.0
//
// scx_knobs: the CFS tuning trio rebuilt on sched_ext (see src/bpf/main.bpf.c
// for the knob semantics). Based on scx_simple's global weighted vtime
// scheduling; takes over ALL tasks by default, or only SCHED_EXT tasks
// with --partial (SCX_OPS_SWITCH_PARTIAL, restart required to toggle).
//
//   --slice-ms   ~ sched_min_granularity_ns   (base slice, floor for period)
//   --period-ms  ~ sched_latency_ns            (0 = static, >0 = period/n)
//   --gran-us    ~ sched_wakeup_granularity_ns (wakeup preempt threshold)
//   --preempt-comm NAME                        (threads with this comm prefix
//                                               preempt on wakeup, gate bypassed)
//   --group-size N                             (keep unbound threads inside
//                                               N-CPU placement groups, 0 = off)
//
// All knobs are plain BSS variables, writable at runtime through stdin
// commands (`slice MS`, `period MS`, `gran US`, `pcomm NAME`, `group N`).

mod bpf_skel;
pub use bpf_skel::*;

use std::io::BufRead;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const SCHEDULER_NAME: &str = "scx_knobs";
const MSEC: u64 = 1_000_000;
const USEC: u64 = 1_000;

#[derive(Clone, Debug, Parser)]
struct Opts {
    /// Enable verbose logging.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// ~ CFS sched_min_granularity_ns: base time slice in ms, and the floor
    /// for period mode (default 20, 0 = kernel default SCX_SLICE_DFL).
    /// Runtime-tunable: send `slice <ms>` on stdin.
    #[clap(long, default_value_t = 20)]
    slice_ms: u64,

    /// ~ CFS sched_latency_ns: scheduling period in ms. 0 = static slice.
    /// When > 0: slice = period / (nr_queued + 1), clamped to [slice, period]
    /// -- deeper queues shrink slices so everyone runs once per period.
    /// Runtime-tunable: send `period <ms>` on stdin.
    #[clap(long, default_value_t = 0)]
    period_ms: u64,

    /// ~ CFS sched_wakeup_granularity_ns: in us. A waking task may preempt
    /// the current runner only if the vtime credit it banked while sleeping
    /// (capped at one slice) exceeds this. 0 = eager preemption (most
    /// CFS-like); >= --slice-ms * 1000 = wakeup preemption off (fewest
    /// involuntary switches).
    /// Runtime-tunable: send `gran <us>` on stdin.
    #[clap(long, default_value_t = 1000)]
    gran_us: u64,

    /// Eager wakeup preemption: every waking task kicks the current runner
    /// immediately, ignoring --gran-us. Runtime-tunable: `preempt on|off`.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    always_preempt: bool,

    /// Name-based wakeup preemption: a waking task whose comm starts with
    /// this string preempts the current runner immediately, ignoring
    /// --gran-us. Prefix match, so "mock_io" covers mock_io0..3. Empty =
    /// disabled. Runtime-tunable: `pcomm NAME` (bare `pcomm` clears it).
    #[clap(long, default_value = "")]
    preempt_comm: String,

    /// Placement-group width in CPUs (default 8, 0 = disabled). A waking
    /// task prefers an idle CPU in its own group; one group is learned per
    /// process so all threads of a process stay together. Runtime-tunable:
    /// `group N`.
    #[clap(long, default_value_t = 8)]
    group_size: u64,

    /// Partial takeover (SCX_OPS_SWITCH_PARTIAL): only tasks explicitly moved
    /// to the SCHED_EXT policy are scheduled by this BPF scheduler, everything
    /// else stays on CFS. Opt in with `chrt -E -a -p <pid>`. Note that the ext
    /// class ranks BELOW fair, so these tasks cannot preempt CFS tasks.
    /// Fixed at load time -- restart the scheduler to toggle.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    partial: bool,

    /// Stats printing interval in ms (default 1000).
    #[clap(long, default_value_t = 1000)]
    interval_ms: u64,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

/* Runtime commands accepted on stdin */
enum Cmd {
    SliceMs(u64),
    PeriodMs(u64),
    GranUs(u64),
    NoSwitch(bool),
    AlwaysPreempt(bool),
    PreemptComm(String),
    GroupSize(u64),
}

fn spawn_stdin_thread() -> mpsc::Receiver<Cmd> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.is_empty() {
                continue;
            }
            let cmd = match t[0] {
                "slice" => t
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Cmd::SliceMs),
                "period" => t
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Cmd::PeriodMs),
                "gran" => t
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Cmd::GranUs),
                "noswitch" => match t.get(1) {
                    Some(&"on") => Some(Cmd::NoSwitch(true)),
                    Some(&"off") => Some(Cmd::NoSwitch(false)),
                    _ => None,
                },
                "preempt" => match t.get(1) {
                    Some(&"on") => Some(Cmd::AlwaysPreempt(true)),
                    Some(&"off") => Some(Cmd::AlwaysPreempt(false)),
                    _ => None,
                },
                "pcomm" => Some(Cmd::PreemptComm(
                    t.get(1).map(|s| s.to_string()).unwrap_or_default(),
                )),
                "group" => t
                    .get(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Cmd::GroupSize),
                _ => None,
            };
            match cmd {
                Some(cmd) => {
                    if tx.send(cmd).is_err() {
                        break;
                    }
                }
                None => eprintln!(
                        "unknown command: {line}  (try: slice MS | period MS | gran US | noswitch on|off | preempt on|off | pcomm NAME | group N)"
                    ),
            }
        }
    });
    rx
}

fn ms_str(ms: u64, zero: &str) -> String {
    if ms > 0 {
        format!("{ms}ms")
    } else {
        zero.to_string()
    }
}

/// Copy @name into a TASK_COMM_LEN BSS buffer: NUL-padded, truncated to
/// TASK_COMM_LEN-1 bytes so the value always stays a valid C string.
/// Its type comes from the BPF BTF: `char[N]` -> `[i8; N]`.
fn store_comm(dst: &mut [i8], name: &str) {
    let max = dst.len().saturating_sub(1);
    dst.fill(0);
    for (d, s) in dst.iter_mut().zip(name.bytes().take(max)) {
        *d = s as i8;
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        if opts.partial {
            info!(
                "{} takes over SCHED_EXT tasks only (SCX_OPS_SWITCH_PARTIAL); \
                 opt in with `chrt -E -a -p <pid>`",
                SCHEDULER_NAME
            );
        } else {
            info!(
                "{} takes over ALL tasks (scx_simple-style global vtime scheduling)",
                SCHEDULER_NAME
            );
        }
        info!(
            "knobs: slice={} period={} gran={}us preempt={} pcomm={} group={}",
            ms_str(opts.slice_ms, "dfl"),
            ms_str(opts.period_ms, "off"),
            opts.gran_us,
            if opts.always_preempt { "always" } else { "gated" },
            if opts.preempt_comm.is_empty() {
                "off"
            } else {
                opts.preempt_comm.as_str()
            },
            if opts.group_size > 0 {
                format!("{}cpus", opts.group_size)
            } else {
                "off".to_string()
            }
        );
        info!(
            "stdin commands: slice MS | period MS | gran US | noswitch on|off | preempt on|off | pcomm NAME | group N"
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, knobs_ops, open_opts)?;

        // Fixed at load time: only tasks carrying the SCHED_EXT policy are
        // handed to us; everything else remains on CFS.
        if opts.partial {
            skel.struct_ops.knobs_ops_mut().flags |= *compat::SCX_OPS_SWITCH_PARTIAL;
        }

        // Write BSS before load so the knobs are effective from the first
        // callback; stdin commands update the same variables.
        {
            let bss = skel.maps.bss_data.as_mut().unwrap();
            bss.slice_ns = if opts.slice_ms > 0 {
                opts.slice_ms * MSEC
            } else {
                0
            };
            bss.period_ns = opts.period_ms * MSEC;
            bss.wakeup_gran_ns = opts.gran_us * USEC;
            bss.always_preempt = u64::from(opts.always_preempt);
            store_comm(&mut bss.preempt_comm, &opts.preempt_comm);
            bss.group_size = opts.group_size;
        }

        let mut skel = scx_ops_load!(skel, knobs_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, knobs_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(
        &mut self,
        shutdown: Arc<AtomicBool>,
        opts: &Opts,
        cmd_rx: &mpsc::Receiver<Cmd>,
    ) -> Result<UserExitInfo> {
        let interval = Duration::from_millis(opts.interval_ms.max(100));
        let mut tick = 0u64;
        // sleep, slice_end, preempt, wake-preempt, exp-preempt, kick, q-local, q-global
        let mut last = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        let mut cur_slice_ms = opts.slice_ms;
        let mut cur_period_ms = opts.period_ms;
        let mut cur_gran_us = opts.gran_us;
        let mut cur_noswitch = false;
        let mut cur_preempt = opts.always_preempt;
        let mut cur_pcomm = opts.preempt_comm.clone();
        let mut cur_group = opts.group_size;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(interval);
            tick += 1;

            // Apply pending stdin commands
            while let Ok(cmd) = cmd_rx.try_recv() {
                let bss = self.skel.maps.bss_data.as_mut().unwrap();
                match cmd {
                    Cmd::SliceMs(v) => {
                        bss.slice_ns = if v > 0 { v * MSEC } else { 0 };
                        cur_slice_ms = v;
                        println!("slice -> {}", ms_str(v, "kernel default"));
                    }
                    Cmd::PeriodMs(v) => {
                        bss.period_ns = v * MSEC;
                        cur_period_ms = v;
                        println!("period -> {}", ms_str(v, "off"));
                    }
                    Cmd::GranUs(v) => {
                        bss.wakeup_gran_ns = v * USEC;
                        cur_gran_us = v;
                        println!("wakeup_gran -> {v} us");
                    }
                    Cmd::NoSwitch(on) => {
                        bss.no_switch = u64::from(on);
                        cur_noswitch = on;
                        println!(
                            "no_switch -> {}",
                            if on { "ON (run-to-completion)" } else { "off" }
                        );
                    }
                    Cmd::AlwaysPreempt(on) => {
                        bss.always_preempt = u64::from(on);
                        cur_preempt = on;
                        println!(
                            "always_preempt -> {}",
                            if on { "ON (every wakeup preempts)" } else { "off" }
                        );
                    }
                    Cmd::PreemptComm(name) => {
                        store_comm(&mut bss.preempt_comm, &name);
                        println!(
                            "preempt_comm -> {}",
                            if name.is_empty() { "off" } else { name.as_str() }
                        );
                        cur_pcomm = name;
                    }
                    Cmd::GroupSize(v) => {
                        bss.group_size = v;
                        cur_group = v;
                        println!(
                            "group_size -> {}",
                            if v > 0 {
                                format!("{v} cpus")
                            } else {
                                "off".to_string()
                            }
                        );
                    }
                }
            }

            // Global counters, printed as per-interval deltas
            let bss = self.skel.maps.bss_data.as_ref().unwrap();
            let cur = (
                bss.nr_sleep_stop,
                bss.nr_slice_end_stop,
                bss.nr_preempt_stop,
                bss.nr_wakeup_preempt,
                bss.nr_named_preempt,
                bss.nr_kick,
                bss.nr_local_q,
                bss.nr_global_q,
            );
            let d = (
                cur.0 - last.0,
                cur.1 - last.1,
                cur.2 - last.2,
                cur.3 - last.3,
                cur.4 - last.4,
                cur.5 - last.5,
                cur.6 - last.6,
                cur.7 - last.7,
            );
            last = cur;

            println!(
                "[{tick:5}] slice={} period={} gran={}us noswitch={} preempt={} pcomm={} group={} | stops: sleep={} slice_end={} preempt={} | wake-preempt={} name-pm={} kick={} | queue: local={} global={}",
                ms_str(cur_slice_ms, "dfl"),
                ms_str(cur_period_ms, "off"),
                cur_gran_us,
                if cur_noswitch { "on" } else { "off" },
                if cur_preempt { "always" } else { "gated" },
                if cur_pcomm.is_empty() { "off" } else { cur_pcomm.as_str() },
                cur_group,
                d.0,
                d.1,
                d.2,
                d.3,
                d.4,
                d.5,
                d.6,
                d.7,
            );
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

    let loglevel = if opts.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let mut lcfg = ConfigBuilder::new();
    lcfg
        .set_time_offset_to_local()
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

    let cmd_rx = spawn_stdin_thread();

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        let uei = sched.run(shutdown.clone(), &opts, &cmd_rx)?;
        if !uei.should_restart() {
            break;
        }
        info!("Scheduler requested restart");
    }

    Ok(())
}
