#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Opt threads into the SCHED_EXT policy (7) with sched_setattr(2), so that a
# partial-takeover scheduler such as `scx_knobs --partial` manages them while
# every other task stays on CFS.
#
# Usage (as root):
#   bash opt_in_ext.sh <tid>...          # explicit TIDs
#   bash opt_in_ext.sh -a <pid>...       # all threads of each PID
#   bash opt_in_ext.sh                   # all threads of every mock_load
#
# Env:
#   OUT  build dir for the helper (default /tmp/scx_knobs_mock)
#
# Notes:
#   - The scheduler must already be running with SCX_OPS_SWITCH_PARTIAL,
#     otherwise sched_setattr() fails with EINVAL.
#   - Verify with `chrt -p <tid>` (policy should read SCHED_EXT).
#   - Toggling --partial needs a scheduler restart; the policy sticks to the
#     threads until they exit.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/scx_knobs_mock}
BIN="$OUT/opt_in_ext"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root (needs CAP_SYS_NICE)"; exit 1; }
command -v gcc >/dev/null || { echo "ERROR: gcc not found"; exit 1; }

mkdir -p "$OUT"
gcc -O2 -Wall -o "$BIN" "$SCRIPT_DIR/opt_in_ext.c"

if [ $# -eq 0 ]; then
	PIDS=$(pgrep -x mock_load || true)
	[ -n "$PIDS" ] || { echo "ERROR: no mock_load running; pass TIDs/PIDs explicitly"; exit 1; }
	echo "opt-in mock_load: $PIDS"
	# shellcheck disable=SC2086
	set -- -a $PIDS
fi

exec "$BIN" "$@"
