#!/usr/bin/env python3
import argparse
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def default_wpt() -> Path:
    src = Path(os.environ.get("FIREFOX_SRC") or (Path.home() / "firefox")).expanduser()
    return src / "testing" / "web-platform" / "tests"

def main():
    p = argparse.ArgumentParser(description="Grep WPT for API usage patterns")
    p.add_argument("name", help="Interface or method name")
    p.add_argument("--wpt", default=os.environ.get("WPT_DIR") or str(default_wpt()), help="Path to WPT tests")
    p.add_argument("-n", "--max", type=int, default=15)
    args = p.parse_args()

    wpt = Path(args.wpt).expanduser().resolve()
    if not wpt.is_dir():
        print(f"[ERR] WPT dir not found: {wpt}")
        print("Set WPT_DIR or pass --wpt /path/to/testing/web-platform/tests")
        raise SystemExit(1)

    name = args.name
    # search for interface or new Interface or .method(
    pat = re.compile(rf"(new\s+{re.escape(name)}\b|{re.escape(name)}\.|{re.escape(name)}\s*\(|\b{re.escape(name)}\b.*\()", re.I)
    hits = []
    for f in wpt.rglob("*.html"):
        try:
            txt = f.read_text(errors="ignore")
        except Exception:
            continue
        if pat.search(txt):
            # get first few lines with match
            for i,l in enumerate(txt.splitlines()):
                if pat.search(l) and "script" in txt.lower():
                    rel = f.relative_to(wpt)
                    hits.append((str(rel), i+1, l.strip()[:140]))
                    break
        if len(hits) >= args.max * 2:
            break

    # dedupe by file
    seen = set()
    out = []
    for h in hits:
        if h[0] in seen:
            continue
        seen.add(h[0])
        out.append(h)
        if len(out) >= args.max:
            break

    print(f"# wpt_grep: '{name}' in {wpt}")
    if not out:
        print("[no matches found]")
        raise SystemExit(0)
    for rel,line,s in out:
        print(f"- {rel}:{line}: {s}")

if __name__ == "__main__":
    main()
