// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}