#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Move threads in/out of the SCHED_EXT policy (7) with sched_setattr(2), so
# that a partial-takeover scheduler such as `scx_knobs --partial` manages them
# while every other task stays on CFS.
#
# Usage (as root):
#   bash opt_in_ext.sh <tid>...          # opt in explicit TIDs
#   bash opt_in_ext.sh -a <pid>...       # opt in all threads of each PID
#   bash opt_in_ext.sh                   # opt in all threads of every mock_load
#   bash opt_in_ext.sh -r                # restore every mock_load to SCHED_NORMAL
#   bash opt_in_ext.sh -r -a <pid>       # restore all threads of a PID
#
# Env:
#   OUT  build dir for the helper (default /tmp/scx_knobs_mock)
#
# Notes:
#   - Opting in requires the scheduler to run with SCX_OPS_SWITCH_PARTIAL,
#     otherwise sched_setattr() fails with EINVAL.
#   - Restoring (-r) sets SCHED_NORMAL and keeps the current nice value, so
#     the thread goes back to CFS. No scheduler restart is needed.
#   - Verify with `chrt -p <tid>`.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/scx_knobs_mock}
BIN="$OUT/opt_in_ext"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (needs CAP_SYS_NICE)"; exit 1; }
command -v gcc >/dev/null || { echo "ERROR: gcc not found"; exit 1; }

mkdir -p "$OUT"
gcc -O2 -Wall -o "$BIN" "$SCRIPT_DIR/opt_in_ext.c"

FLAGS=()
ARGS=()
for a in "$@"; do
	case "$a" in
	-r | --restore) FLAGS=(-r) ;;
	*) ARGS+=("$a") ;;
	esac
done

if [ ${#ARGS[@]} -eq 0 ]; then
	PIDS=$(pgrep -x mock_load || true)
	[ -n "$PIDS" ] || { echo "ERROR: no mock_load running; pass TIDs/PIDs explicitly"; exit 1; }
	echo "targets (mock_load): $PIDS"
	# shellcheck disable=SC2206
	ARGS=(-a $PIDS)
fi

exec "$BIN" ${FLAGS[@]+"${FLAGS[@]}"} "${ARGS[@]}"
