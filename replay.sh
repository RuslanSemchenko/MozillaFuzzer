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

ROOT="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
fi

BROWSER="${FIREFOX_BIN:-}"
if [[ -z "${PYTHON_BIN:-}" && -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON="$ROOT/.venv/bin/python"
else
    PYTHON="${PYTHON_BIN:-python3}"
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <testcase-or-dir> [extra-grizzly-flags...]"
    exit 1
fi
if [[ -z $BROWSER ]]; then
    SRC="${FIREFOX_SRC:-$HOME/firefox}"
    for cand in "$SRC"/obj-*/dist/bin/firefox; do
        [[ -x $cand ]] || continue
        BROWSER="$cand"
        break
    done
fi
if [[ -z $BROWSER ]]; then
    echo "Firefox binary not set. Set FIREFOX_BIN or build under \$FIREFOX_SRC/obj-*/dist/bin/firefox" >&2
    exit 1
elif [[ ! -x $BROWSER ]]; then
    echo "Not an executable: $BROWSER" >&2
    exit 1
fi

INPUT="$1"
shift

exec "$PYTHON" -m grizzly.replay "$BROWSER" "$INPUT" "$@"
