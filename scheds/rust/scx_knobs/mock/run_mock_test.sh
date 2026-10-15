#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# scx_knobs mock A/B test: run synthetic load under different knob settings
# and compare the switch-attribution counters printed by scx_knobs.
#
# Usage (as root, on the sched_ext box):
#   bash run_mock_test.sh [duration_s] [mock_load args...]
#     e.g. bash run_mock_test.sh 10              # mix workload, default sizes
#          bash run_mock_test.sh 10 mix 8 4       # explicit thread counts
#
# Env:
#   BIN  path to scx_knobs (default hardcoded below)
#
# Phases (each 2x duration_s; halves are reported separately):
#   A  defaults, then at half-time `gran 20000` is sent on stdin
#      -> 1st half: wake_preempt/preempt > 0 (io wakeups preempt cpu threads)
#      -> 2nd half: both collapse to ~0 (wakeup preemption disabled live)
#   B  --slice-ms 100
#      -> slice_end stops drop ~5x vs phase A (100ms vs 20ms slices)
#   C  --period-ms 100 --slice-ms 1
#      -> period mode: slice = 100ms/(nr_queued+1), 1ms floor
#      -> slice_end stops highest of all phases
#
# Cross-check: sleep+slice_end+preempt should track /proc/stat ctxt delta
# (scx_knobs takes over ALL tasks; saturated CPUs keep idle switches low).
#
# WARNING: saturates all CPUs while running. Test box only.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DUR=${1:-10}
BIN=${BIN:-/home/y3/scx/target/release/scx_knobs}
if [ $# -gt 0 ]; then shift; fi
if [ $# -gt 0 ]; then MODE_ARGS=("$@"); else MODE_ARGS=(mix); fi

OUT=/tmp/scx_knobs_mock
SUMMARY="$OUT/summary.txt"
MOCK="$OUT/mock_load"
mkdir -p "$OUT"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root"; exit 1; }
[ -x "$BIN" ] || { echo "ERROR: scheduler not found: $BIN (cargo build --release -p scx_knobs)"; exit 1; }
[ -d /sys/kernel/sched_ext ] || echo "WARNING: /sys/kernel/sched_ext missing; sched_ext kernel?"

echo "building mock_load..."
cc -O2 -pthread "$SCRIPT_DIR/mock_load.c" -o "$MOCK"
: > "$SUMMARY"

# Sum the per-interval deltas from a scx_knobs stats log.
summarize() {
	awk '
		/stops:/ {
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^sleep=/)          { sub(/^sleep=/, "", $i);          sl += $i }
				else if ($i ~ /^slice_end=/) { sub(/^slice_end=/, "", $i);      se += $i }
				else if ($i ~ /^preempt=/)   { sub(/^preempt=/, "", $i);        pr += $i }
				else if ($i ~ /^wake-preempt=/) { sub(/^wake-preempt=/, "", $i); wp += $i }
				else if ($i ~ /^local=/)     { sub(/^local=/, "", $i);          lo += $i }
				else if ($i ~ /^global=/)    { sub(/^global=/, "", $i);         gl += $i }
			}
		}
		END { printf "sleep=%d slice_end=%d preempt=%d wake_preempt=%d local=%d global=%d",
			     sl, se, pr, wp, lo, gl }
	' "$1"
}

# sleep + slice_end + preempt = total task stops under scx
stops_total() {
	summarize "$1" | awk '{ gsub(/[a-z_]+=/, ""); s += $1 + $2 + $3 } END { print s + 0 }'
}

ctxt_total() { awk '/^ctxt /{print $2}' /proc/stat; }

run_phase() {
	local name="$1"; shift
	local fifo="$OUT/$name.fifo" log="$OUT/$name.log"
	local h1="$OUT/$name.h1" h2="$OUT/$name.h2"
	local sched_pid load_pid ctxt_before ctxt_after mid=""

	rm -f "$fifo" "$log" "$h1" "$h2"
	mkfifo "$fifo"

	# scheduler reads commands from the fifo; fd 3 keeps a writer open
	"$BIN" "$@" < "$fifo" > "$log" 2>&1 &
	sched_pid=$!
	exec 3>"$fifo"
	sleep 1
	if ! kill -0 "$sched_pid" 2>/dev/null; then
		echo "ERROR: scx_knobs exited during startup; log:"
		cat "$log"
		exit 1
	fi

	ctxt_before=$(ctxt_total)
	"$MOCK" "${MODE_ARGS[@]}" &
	load_pid=$!

	sleep "$DUR"
	if [ "$name" = "A_defaults" ]; then
		echo "gran 20000" >&3	# runtime knob: wakeup preemption off
		mid="   mid-run stdin cmd: gran 20000"
	fi
	sleep "$DUR"

	kill -TERM "$load_pid" 2>/dev/null || true
	wait "$load_pid" 2>/dev/null || true
	exec 3>&-
	kill -INT "$sched_pid" 2>/dev/null || true
	wait "$sched_pid" 2>/dev/null || true

	ctxt_after=$(ctxt_total)

	# split into halves (stats interval is 1s -> ~DUR lines each)
	head -n "$DUR" "$log" > "$h1"
	tail -n +"$((DUR + 1))" "$log" > "$h2"

	{
		echo
		echo "===== phase $name (args: $*) =====$mid"
		echo "  1st half: $(summarize "$h1")"
		echo "  2nd half: $(summarize "$h2")"
		echo "  total   : $(summarize "$log")"
		echo "  cross-check: scx stops=$(stops_total "$log")  /proc/stat ctxt delta=$((ctxt_after - ctxt_before))"
		echo "  full log: $log"
	} | tee -a "$SUMMARY"
}

run_phase A_defaults
run_phase B_slice100 --slice-ms 100
run_phase C_period --period-ms 100 --slice-ms 1

{
	echo
	echo "===== expected patterns ====="
	echo "A 1st half : wake_preempt > 0, preempt > 0   (io wakeups preempt cpu victims)"
	echo "A 2nd half : wake_preempt = 0, preempt ~ 0   (gran >= slice disables it live)"
	echo "B          : slice_end ~5x lower than phase A (100ms vs 20ms slices)"
	echo "C          : slice_end highest of all        (period mode shrinks slices)"
	echo "cross-check: scx stops close to ctxt delta   (saturated -> few idle switches)"
} | tee -a "$SUMMARY"

echo
echo "done. summary: $SUMMARY"
