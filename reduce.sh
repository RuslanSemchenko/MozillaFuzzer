#!/usr/bin/env bash
# Reduce a crash testcase to a minimal reproducer with Grizzly.
#
# Usage:
#   ./reduce.sh <path-to-testcase> [flags...]
#
# Examples:
#   ./reduce.sh results/testcase.html
#   ./reduce.sh results/testcase.html --display headless
#   ./reduce.sh results/testcase.html -o results/minimized.html
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

exec "$PYTHON" -m grizzly.reduce "$BROWSER" "$INPUT" "$@"
