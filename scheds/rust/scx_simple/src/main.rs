// SPDX-License-Identifier: GPL-2.0
//
// scx_simple: minimal global weighted vtime scheduler, measurement baseline.
//
// Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
// Copyright (c) 2022 Tejun Heo <tj@kernel.org>
// Copyright (c) 2022 David Vernet <dvernet@meta.com>

mod bpf_skel;
pub use bpf_skel::*;

use std::io::BufRead;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, OpenObject};
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

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf_opts.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, simple_ops, open_opts)?;

        skel.maps.rodata_data.as_mut().unwrap().fifo_sched = opts.fifo_sched;
        skel.maps.bss_data.as_mut().unwrap().slice_base_ns = 2_800_000;
        skel.maps.bss_data.as_mut().unwrap().preempt_en = 1;
        skel.maps.bss_data.as_mut().unwrap().tick_cpu = 2;

        let mut skel = scx_ops_load!(skel, simple_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, simple_ops)?);

        Ok(Self { skel, struct_ops })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let mut last = (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut tick = 0u64;
        let mut slices: Vec<(String, u64)> = Vec::new(); /* userspace-side record for display */

        let (tx, rx): (Sender<String>, Receiver<String>) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        println!(
            "commands: 'slice NAME US' | 'unslice NAME' | 'base US' | 'preempt on|off' | 'gran US' | 'vtrace on|off' | 'tickcpu N'  (US = microseconds)"
        );

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(line) => self.handle_command(&line, &mut slices),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            tick += 1;

            let bss = self.skel.maps.bss_data.as_mut().unwrap();
            let local = bss.nr_local_q;
            let global = bss.nr_global_q;
            let wpre = bss.nr_wakeup_preempt;
            let kick = bss.nr_kick;
            let n_tick = bss.nr_tick;
            let base_us = bss.slice_base_ns / 1000;
            let slices_str = if slices.is_empty() {
                String::new()
            } else {
                format!(
                    " | slices: {}",
                    slices
                        .iter()
                        .map(|(n, ns)| format!("{n}={}", ns / 1000))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            println!(
                "[{tick:5}] base={base_us}us | local={} global={} | d local={} d global={} | d pre={} d kick={} | d tick={}{slices_str}",
                local,
                global,
                local - last.0,
                global - last.1,
                wpre - last.2,
                kick - last.3,
                n_tick - last.4
            );
            last = (local, global, wpre, kick, n_tick);
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }

    fn handle_command(&mut self, line: &str, slices: &mut Vec<(String, u64)>) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["slice", name, us] => match (comm_key(name), us.parse::<u64>()) {
                (Ok(key), Ok(us)) => {
                    let ns = us * 1000;
                    match self.skel.maps.comm_slice.update(
                        &key,
                        &ns.to_ne_bytes(),
                        MapFlags::ANY,
                    )
                    {
                        Ok(()) => {
                            slices.retain(|(n, _)| n != name);
                            slices.push((name.to_string(), ns));
                            println!("slice: {name} = {us}us");
                        }
                        Err(e) => println!("slice: map update failed: {e}"),
                    }
                }
                (Err(e), _) => println!("slice: {e}"),
                (_, Err(_)) => println!("slice: invalid microseconds '{us}'"),
            },
            ["unslice", name] => match comm_key(name) {
                Ok(key) => {
                    let _ = self.skel.maps.comm_slice.delete(&key);
                    slices.retain(|(n, _)| n != name);
                    println!("slice: {name} -> default");
                }
                Err(e) => println!("unslice: {e}"),
            },
            ["base", us] => match us.parse::<u64>() {
                Ok(us) => {
                    self.skel.maps.bss_data.as_mut().unwrap().slice_base_ns = us * 1000;
                    println!("base slice: {us}us");
                }
                Err(_) => println!("base: invalid microseconds '{us}'"),
            },
            ["preempt", "on"] => {
                self.skel.maps.bss_data.as_mut().unwrap().preempt_en = 1;
                println!("wakeup preempt: on");
            }
            ["preempt", "off"] => {
                self.skel.maps.bss_data.as_mut().unwrap().preempt_en = 0;
                println!("wakeup preempt: off");
            }
            ["gran", us] => match us.parse::<u64>() {
                Ok(us) => {
                    self.skel.maps.bss_data.as_mut().unwrap().preempt_gran_ns = us * 1000;
                    println!("wakeup gran: {us}us");
                }
                Err(_) => println!("gran: invalid microseconds '{us}'"),
            },
            ["vtrace", "on"] => {
                self.skel.maps.bss_data.as_mut().unwrap().vtrace = 1;
                println!("vtime trace: on (read /sys/kernel/tracing/trace_pipe)");
            }
            ["vtrace", "off"] => {
                self.skel.maps.bss_data.as_mut().unwrap().vtrace = 0;
                println!("vtime trace: off");
            }
            ["tickcpu", cpu] => match cpu.parse::<i64>() {
                Ok(c) => {
                    self.skel.maps.bss_data.as_mut().unwrap().tick_cpu = c as u64;
                    println!("tick trace cpu: {c}");
                }
                Err(_) => println!("tickcpu: invalid cpu '{cpu}'"),
            },
            [] => {}
            _ => println!(
                "unknown command, try: 'slice NAME US' | 'unslice NAME' | 'base US' | 'preempt on|off' | 'gran US' | 'vtrace on|off' | 'tickcpu N'"
            ),
        }
    }
}

fn comm_key(name: &str) -> Result<[u8; 16]> {
    let bytes = name.as_bytes();
    anyhow::ensure!(bytes.len() < 16, "comm too long (max 15 chars)");
    let mut key = [0u8; 16];
    key[..bytes.len()].copy_from_slice(bytes);
    Ok(key)
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
