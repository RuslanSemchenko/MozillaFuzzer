#!/usr/bin/env bash
# Linux runner with stress profile support.
#
#   ./fuzz.sh [firefox-binary] [runtime-seconds] [fuzzing-flags...]
#
# Built-in flags:
#   headless, --headless  Run Firefox with -headless (no window, same browser)
#   headful, --headful    Force a visible browser window (default)
#   xvfb, --xvfb          Run Firefox under Xvfb
#   --chaos[=HEX]     Enable Firefox MOZ_CHAOSMODE (default: 0xfb)
#   --zeal[=MODE]     Enable SpiderMonkey JS_GC_ZEAL (default: 2,100)
#   --stress          Enable both Chaos Mode and GC Zeal
#   --asan            Export hardened ASAN_OPTIONS for leak/crash detection
#
# All other arguments and Grizzly options (e.g. --rr, --smoke-test,
# --relaunch, --time-limit) are forwarded to Grizzly untouched.
#
# Examples:
#   ./fuzz.sh                                     # FIREFOX_BIN / .env, 360000s
#   ./fuzz.sh headless                            # no window, crashes still hunted
#   ./fuzz.sh --stress                            # run with Chaos Mode + GC Zeal
#   ./fuzz.sh --chaos --smoke-test                # quick sanity run under chaos mode
#   ./fuzz.sh "" 7200 --relaunch 200 --rr         # 2h run with rr recording
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
fi

RUNTIME_DEFAULT=360000

pos=()
extra=()
seen_flag=0
display_mode=""

for arg in "$@"; do
    case "$arg" in
        headless|--headless)
            display_mode="headless"
            ;;
        headful|--headful)
            display_mode="default"
            ;;
        xvfb|--xvfb)
            display_mode="xvfb"
            ;;
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
[[ -n $BROWSER ]] || BROWSER="${FIREFOX_BIN:-}"
if [[ -z $BROWSER ]]; then
    echo "Firefox binary not set. Pass it as the first argument, set FIREFOX_BIN, or copy .env.example -> .env" >&2
    exit 1
fi
RUNTIME="${pos[1]:-$RUNTIME_DEFAULT}"
[[ -z $display_mode ]] || extra+=(--display "$display_mode")

OUT="$ROOT/results"
PYTHON="${PYTHON_BIN:-python3}"
mkdir -p "$OUT"

echo "=================================================="
echo "Grizzly + Domato DOM/WebIDL Fuzzing"
echo "=================================================="
echo "Python:     $PYTHON"
echo "Browser:    $BROWSER"
echo "Runtime:    ${RUNTIME}s (stop via Ctrl+C)"
echo "Display:    ${display_mode:-default}"
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
