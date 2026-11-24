// SPDX-License-Identifier: GPL-2.0

fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
