// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.

use std::path::PathBuf;

fn main() {
    scx_cargo::build(PathBuf::from("./src/bpf"));
}