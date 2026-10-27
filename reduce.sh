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

ROOT="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
fi

BROWSER="${FIREFOX_BIN:-}"
PYTHON="${PYTHON_BIN:-python3}"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <testcase-or-dir> [extra-grizzly-flags...]"
    exit 1
fi
if [[ -z $BROWSER ]]; then
    echo "Firefox binary not set. Set FIREFOX_BIN or copy .env.example -> .env" >&2
    exit 1
fi

INPUT="$1"
shift

exec "$PYTHON" -m grizzly.reduce "$BROWSER" "$INPUT" "$@"
