#!/usr/bin/env bash
# Linux port of fuzz.bat with stress profile support.
#
#   ./fuzz.sh [firefox-binary] [runtime-seconds] [fuzzing-flags...]
#
# Built-in stress flags:
#   --chaos[=HEX]     Enable Firefox MOZ_CHAOSMODE (default: 0xfb)
#   --zeal[=MODE]     Enable SpiderMonkey JS_GC_ZEAL (default: 2,100)
#   --stress          Enable both Chaos Mode and GC Zeal
#   --asan            Export hardened ASAN_OPTIONS for leak/crash detection
#
# All other arguments and Grizzly options (e.g. --rr, --smoke-test,
# --relaunch, --time-limit) are forwarded to Grizzly untouched.
#
# Examples:
#   ./fuzz.sh                                     # default browser, 360000s
#   ./fuzz.sh --stress                            # run with Chaos Mode + GC Zeal
#   ./fuzz.sh --chaos --smoke-test                # quick sanity run under chaos mode
#   ./fuzz.sh "" 7200 --relaunch 200 --rr         # 2h run with rr recording
set -euo pipefail

DEFAULT_BROWSER="/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
RUNTIME_DEFAULT=360000

pos=()
extra=()
seen_flag=0

for arg in "$@"; do
    case "$arg" in
        --chaos)
            export MOZ_CHAOSMODE="${MOZ_CHAOSMODE:-0xfb}"
            ;;
        --chaos=*)
            export MOZ_CHAOSMODE="${arg#*=}"
            ;;
        --zeal)
            export JS_GC_ZEAL="${JS_GC_ZEAL:-2,100}"
            ;;
        --zeal=*)
            export JS_GC_ZEAL="${arg#*=}"
            ;;
        --stress)
            export MOZ_CHAOSMODE="${MOZ_CHAOSMODE:-0xfb}"
            export JS_GC_ZEAL="${JS_GC_ZEAL:-2,100}"
            ;;
        --asan)
            export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:symbolize=1:handle_segv=1}"
            ;;
        -*)
            seen_flag=1
            extra+=("$arg")
            ;;
        *)
            if (( seen_flag )); then
                extra+=("$arg")
            else
                pos+=("$arg")
            fi
            ;;
    esac
done

BROWSER="${pos[0]:-}"
[[ -n $BROWSER ]] || BROWSER="${FIREFOX_BIN:-$DEFAULT_BROWSER}"
RUNTIME="${pos[1]:-$RUNTIME_DEFAULT}"

OUT="$(dirname "$(readlink -f "$0")")/results"
PYTHON="${PYTHON_BIN:-python3}"
mkdir -p "$OUT"

echo "=================================================="
echo "Grizzly + Domato DOM/WebIDL Fuzzing"
echo "=================================================="
echo "Python:     $PYTHON"
echo "Browser:    $BROWSER"
echo "Runtime:    ${RUNTIME}s (stop via Ctrl+C)"
echo "Output:     $OUT"
echo "Chaos Mode: ${MOZ_CHAOSMODE:-disabled}"
echo "GC Zeal:    ${JS_GC_ZEAL:-disabled}"
if [[ -n "${ASAN_OPTIONS:-}" ]]; then
    echo "ASan Opts:  $ASAN_OPTIONS"
fi
echo "Grizzly:    ${extra[*]:-(default flags)}"
echo "=================================================="
echo

exec "$PYTHON" -m grizzly --runtime "$RUNTIME" -o "$OUT" ${extra[@]+"${extra[@]}"} "$BROWSER" domato
