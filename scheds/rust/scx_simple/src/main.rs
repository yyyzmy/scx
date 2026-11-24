// SPDX-License-Identifier: GPL-2.0
//
// scx_simple: minimal global weighted vtime scheduler, measurement baseline.
//
// Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2022 Tejun Heo <tj@kernel.org>
// Copyright (c) 2022 David Vernet <dvernet@meta.com>

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::OpenObject;
use libbpf_rs::MapFlags;
use log::info;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use scx_utils::{scx_ops_attach, scx_ops_load, scx_ops_open};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

const SCHEDULER_NAME: &str = "scx_simple";

#[derive(Parser, Debug)]
struct Opts {
    /// Enable FIFO scheduling instead of vtime.
    #[arg(long)]
    fifo_sched: bool,

    /// Enable verbose logging, including libbpf logs.
    #[arg(short = 'v', long)]
    verbose: bool,

    #[command(flatten)]
    libbpf_opts: LibbpfOpts,
}

fn sum_percpu(skel: &BpfSkel<'_>, idx: u32) -> u64 {
    let key = idx.to_ne_bytes();
    match skel
        .maps
        .stats
        .lookup_percpu(&key, MapFlags::ANY)
    {
        Ok(Some(vals)) => vals
            .iter()
            .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap()))
            .sum(),
        _ => 0,
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, simple_ops, open_opts)?;

        skel.rodata_mut().fifo_sched = opts.fifo_sched;

        let mut skel = scx_ops_load!(skel, simple_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, simple_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut last = (0u64, 0u64);
        let mut tick = 0u64;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            std::thread::sleep(Duration::from_secs(1));
            tick += 1;

            let local = sum_percpu(&self.skel, 0);
            let global = sum_percpu(&self.skel, 1);
            println!(
                "[{tick:5}] local={} global={} | d local={} d global={}",
                local,
                global,
                local - last.0,
                global - last.1
            );
            last = (local, global);
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

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        let uei = sched.run(shutdown.clone())?;
        if !uei.should_restart() {
            break;
        }
        info!("Scheduler requested restart");
    }

    Ok(())
}
