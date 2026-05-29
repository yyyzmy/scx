fn main() {
    if std::env::var("CARGO_FEATURE_STATS").is_ok() {
        std::env::set_var("BPF_EXTRA_CFLAGS_PRE_INCL", "-DTRAE_STATS");
    }

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
