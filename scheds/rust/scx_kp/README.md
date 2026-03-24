# scx_kp

`scx_kp` is a new scheduler line for Kunpeng-class many-core servers.

Current status:

- v0 baseline reuses `scx_beerland` BPF scheduling core.
- Rust userspace loader is simplified and packaged as `scx_kp`.

Next planned steps:

- LLC-domain-aware dispatch cost model.
- Thread classification (compute-heavy vs cache-heavy).
- Cross-LLC migration throttling and lock-pressure reduction.
