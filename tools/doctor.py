#!/usr/bin/env python3
"""
Environment doctor for grz_domato.

Checks:
- Firefox source tree + StaticPrefList.yaml
- Built Firefox binary (obj-*/dist/bin/firefox)
- Required tools scripts exist
- Python deps (domato/grz_domato)
- results/ dir
- Grizzly prefs presence hints
"""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TOOLS = ROOT / "tools"
RULES = ROOT / "domato" / "rules"
GRZ = ROOT / "grz_domato"

class C:
    OK = "\033[92m[OK]\033[0m"
    WARN = "\033[93m[WARN]\033[0m"
    FAIL = "\033[91m[FAIL]\033[0m"
    INFO = "\033[94m[INFO]\033[0m"

def check(label: str, cond: bool, ok: str, bad: str):
    if cond:
        print(f"{C.OK} {label}: {ok}")
        return True
    else:
        print(f"{C.FAIL} {label}: {bad}")
        return False

def warn(label: str, cond: bool, ok: str, w: str):
    if cond:
        print(f"{C.OK} {label}: {ok}")
        return True
    else:
        print(f"{C.WARN} {label}: {w}")
        return False

def main():
    p = argparse.ArgumentParser(description="Check grz_domato environment")
    p.add_argument("--source", default=os.environ.get("FIREFOX_SRC", "/home/ruslan/firefox"), help="Firefox source tree")
    p.add_argument("--firefox", default=os.environ.get("FIREFOX_BIN"), help="Path to firefox binary")
    p.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    args = p.parse_args()

    src = Path(args.source).expanduser().resolve()
    fx = Path(args.firefox).expanduser().resolve() if args.firefox else None

    print(f"{C.INFO} grz_domato doctor")
    print(f"  ROOT: {ROOT}")
    print(f"  FIREFOX_SRC: {src}")
    if fx:
        print(f"  FIREFOX_BIN: {fx}")
    print()

    ok_all = True

    # Firefox source
    ok_all &= check("Firefox source exists", src.is_dir(), str(src), f"Not found: {src}")

    pref = src / "modules" / "libpref" / "init" / "StaticPrefList.yaml"
    ok_all &= check("StaticPrefList.yaml", pref.is_file(), str(pref), f"Missing (needed by audit_rules.py): {pref}")

    dom_webidl = src / "dom" / "webidl"
    ok_all &= check("dom/webidl exists", dom_webidl.is_dir(), str(dom_webidl), f"Missing: {dom_webidl}")

    # Firefox binary
    if fx is None:
        # try common obj dirs
        candidates = []
        for d in src.glob("obj-*"):
            c = d / "dist" / "bin" / "firefox"
            if c.is_file():
                candidates.append(c)
        if candidates:
            print(f"{C.WARN} FIREFOX_BIN not specified. Candidates found:")
            for c in candidates[:5]:
                print(f"    - {c}")
            print("  Use: --firefox <path> or export FIREFOX_BIN=...")
            if args.strict: ok_all = False
        else:
            print(f"{C.WARN} No obj-*/dist/bin/firefox found. probe_apis.py/check_reads.py/scan_cases.py need a built binary.")
            if args.strict: ok_all = False
    else:
        ok_all &= check("Firefox binary", fx.is_file(), str(fx), f"Not found: {fx}")
        if fx.is_file():
            warn("Firefox binary executable", os.access(fx, os.X_OK), "yes", "not executable?")

    print()

    # Project layout
    for name, path in [
        ("domato/", ROOT / "domato"),
        ("grz_domato/", GRZ),
        ("tools/", TOOLS),
        ("domato/rules/", RULES),
    ]:
        ok_all &= check(name, path.is_dir(), str(path), f"Missing: {path}")

    print()

    # Key tools
    for name in ["extract_idl.py", "audit_rules.py", "probe_apis.py", "check_reads.py", "check_rules.py", "check_wgsl.py", "scan_cases.py", "gen_webidl_rules.py"]:
        pth = TOOLS / name
        ok_all &= check(f"tools/{name}", pth.is_file(), "present", "missing")

    print()

    # Rules count
    if RULES.is_dir():
        txts = list(RULES.rglob("*.txt")) + list(RULES.rglob("*.wgsl"))
        print(f"{C.INFO} Rules files: {len(txts)} (*.txt + *.wgsl under domato/rules)")

    # results/
    res = ROOT / "results"
    if not res.exists():
        res.mkdir(parents=True, exist_ok=True)
        print(f"{C.WARN} results/ created (gitignored)")
    else:
        print(f"{C.OK} results/: exists")

    print()

    # Python imports
    try:
        import domato  # type: ignore
        print(f"{C.OK} import domato: ok")
    except Exception as e:
        print(f"{C.FAIL} import domato: {e}")
        ok_all = False

    try:
        import grz_domato  # type: ignore
        print(f"{C.OK} import grz_domato: ok ({getattr(grz_domato,'__file__','?')})")
    except Exception as e:
        print(f"{C.FAIL} import grz_domato: {e}")
        ok_all = False

    print()
    if ok_all and not args.strict:
        print(f"{C.OK} All required checks passed")
    elif ok_all and args.strict:
        print(f"{C.OK} All checks passed (strict)")
    else:
        print(f"{C.FAIL} Some checks failed. Fix above and re-run.")
        sys.exit(1)

if __name__ == "__main__":
    main()
