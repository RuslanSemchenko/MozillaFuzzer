#!/usr/bin/env bash
# Replay a crash or testcase with Grizzly.
#
# Usage:
#   ./replay.sh <path-to-testcase> [flags...]
#
# Examples:
#   ./replay.sh results/testcase.html
#   ./replay.sh results/testcase.html --rr            # Record with rr for debugging
#   ./replay.sh results/testcase.html --repeat 10     # Test intermittent crashes
#   ./replay.sh results/testcase.html --display headless
set -euo pipefail

DEFAULT_BROWSER="/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
BROWSER="${FIREFOX_BIN:-$DEFAULT_BROWSER}"
PYTHON="${PYTHON_BIN:-python3}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <testcase-or-dir> [extra-grizzly-flags...]"
    exit 1
fi

INPUT="$1"
shift

exec "$PYTHON" -m grizzly.replay "$BROWSER" "$INPUT" "$@"
