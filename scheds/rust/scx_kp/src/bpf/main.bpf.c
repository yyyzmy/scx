/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_kp v0 baseline:
 * reuse scx_beerland BPF scheduling core as the starting point.
 * Subsequent iterations will add Kunpeng-specific LLC-aware classification.
 */
#include "../../../scx_beerland/src/bpf/main.bpf.c"
