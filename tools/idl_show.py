#!/usr/bin/env python3
import argparse
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def find_idl(src: Path, name: str):
    # try exact
    p = src / "dom" / "webidl" / f"{name}.webidl"
    if p.exists():
        return p
    # case-insensitive
    for f in (src / "dom" / "webidl").glob("*.webidl"):
        if f.stem.lower() == name.lower():
            return f
    return None

def read_with_includes(src: Path, path: Path, seen=None):
    if seen is None:
        seen = set()
    if path in seen:
        return ""
    seen.add(path)
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return ""
    out = []
    for m in re.finditer(r'^\s*#include\s+"([^"]+)"', text, re.M):
        inc = m.group(1)
        ipath = path.parent / inc
        if ipath.exists():
            out.append(read_with_includes(src, ipath, seen))
        else:
            ipath2 = src / "dom" / "webidl" / inc
            if ipath2.exists():
                out.append(read_with_includes(src, ipath2, seen))
    out.append(text)
    return "\n".join(out)

def extract_block(text: str, name: str):
    # find interface/interface mixin/namespace/partial
    pattern = rf'^\s*(?:\[\s*[^\]]*\]\s*)*(partial\s+)?(interface\s+mixin|interface|namespace)\s+{re.escape(name)}\b'
    m = re.search(pattern, text, re.M)
    if not m:
        return None
    start = m.start()
    # naive: find matching braces roughly
    brace = text.find('{', m.end())
    if brace == -1:
        return text[start:start+2000]
    depth = 0
    i = brace
    end = len(text)
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        elif text[i] == '"' and (i == 0 or text[i-1] != '\\'):
            # skip string
            i += 1
            while i < len(text) and not (text[i] == '"' and text[i-1] != '\\'):
                i += 1
        i += 1
    return text[start:end]

def main():
    p = argparse.ArgumentParser(description="Show WebIDL for an interface")
    p.add_argument("name")
    p.add_argument("--source", default=os.environ.get("FIREFOX_SRC", "/home/ruslan/firefox"))
    args = p.parse_args()

    src = Path(args.source).expanduser().resolve()
    pth = find_idl(src, args.name)
    if not pth:
        print(f"[ERR] {args.name}.webidl not found under {src}/dom/webidl")
        raise SystemExit(1)

    full = read_with_includes(src, pth)
    block = extract_block(full, args.name)
    if not block:
        print(f"[ERR] could not extract block for {args.name}")
        print(f"[INFO] file: {pth}")
        raise SystemExit(1)

    print(f"# {args.name} @ {pth}")
    print(block)
    print("\n# --- END ---")

if __name__ == "__main__":
    main()
