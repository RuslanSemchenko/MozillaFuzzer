#!/usr/bin/env bash
# Linux port of fuzz.bat.
#
#   ./fuzz.sh [firefox-binary] [runtime-seconds] [grizzly-flags...]
#
# Positional args come first; from the first argument starting with '-'
# everything is passed to grizzly untouched.
#   ./fuzz.sh                                    # default browser, 360000s
#   ./fuzz.sh "" 7200 --time-limit 60            # default browser, 2h
#   ./fuzz.sh /path/to/firefox 3600 --relaunch 500 -v
#   ./fuzz.sh --smoke-test                       # flags only
set -euo pipefail

DEFAULT_BROWSER="/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
RUNTIME_DEFAULT=360000

pos=()
extra=()
seen_flag=0
for arg in "$@"; do
    if (( seen_flag )); then
        extra+=("$arg")
    elif [[ $arg == -* ]]; then
        seen_flag=1
        extra+=("$arg")
    else
        pos+=("$arg")
    fi
done

BROWSER="${pos[0]:-}"
[[ -n $BROWSER ]] || BROWSER="${FIREFOX_BIN:-$DEFAULT_BROWSER}"
RUNTIME="${pos[1]:-$RUNTIME_DEFAULT}"

OUT="$(dirname "$(readlink -f "$0")")/results"
PYTHON="${PYTHON_BIN:-python3}"
mkdir -p "$OUT"

echo "Grizzly + Domato fuzzing"
echo "Python:  $PYTHON"
echo "Browser: $BROWSER"
echo "Runtime: ${RUNTIME}s (stop via Ctrl+C)"
echo "Output:  $OUT"
echo "Extra:   ${extra[*]-}"
echo

exec "$PYTHON" -m grizzly --runtime "$RUNTIME" -o "$OUT" ${extra[@]+"${extra[@]}"} "$BROWSER" domato
