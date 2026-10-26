#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUEUE = ROOT / "results" / "audit" / "QUEUE.md"

REFUSE_HINTS = [
    "refused",
    "no receiver",
    "outside server_map",
    "prompt",
    "user input",
    "user activation",
    "transient activation",
    "permission",
    "microphone",
    "camera",
    "security key",
    "not exposed",
    "undefined here",
    "undefined on this build",
    "chrome-only",
    "browser-created",
    "handed to a permission-prompt",
    "only handed out",
    "only handed to",
    "only exists",
    "only delivered",
    "only reachable",
    "only granted",
    "no content constructor",
    "navigate away",
    "does not exist here",
    "not a gap",
    "no prompt-free producer",
    "no silent receiver",
    "no voice",
    "needs a live http/3",
    "service worker",
    "credentials.create/get",
    "cannot close",
    "popup",
    "webtransport",
]

def main():
    p = argparse.ArgumentParser(description="Show top missing from QUEUE.md")
    p.add_argument("-n", "--top", type=int, default=20)
    p.add_argument("--all", action="store_true", help="Show all, including likely refused")
    args = p.parse_args()

    if not QUEUE.exists():
        print(f"[ERR] {QUEUE} not found. Run: python3 tools/audit_rules.py --show-blocked")
        raise SystemExit(1)

    text = QUEUE.read_text(errors="ignore")
    blocks = re.split(r"^##\s+", text, flags=re.M)

    items = []
    for b in blocks[1:]:
        lines = b.splitlines()
        if not lines:
            continue
        header = lines[0]
        m = re.match(r"(.+?)\s+->\s+(.+?)\s+\(missing\s+(\d+)\s+of\s+(\d+)", header)
        if not m:
            continue
        name = m.group(1).strip()
        dest = m.group(2).strip()
        miss = int(m.group(3))
        total = int(m.group(4))
        note = ""
        missing_list = []
        for l in lines[1:]:
            if l.strip().startswith("- NOTE:"):
                note = l.strip()
            if l.strip().startswith("- missing"):
                # collect until next section
                pass
        # extract missing names
        for l in lines:
            mm = re.match(r"- missing\s+\(\d+\):\s*(.+)", l)
            if mm:
                missing_list = [x.strip() for x in mm.group(1).split(",")]
                break
        blob = header + "\n" + "\n".join(lines)
        is_refuse = any(h in blob.lower() for h in REFUSE_HINTS)
        items.append({
            "name": name,
            "dest": dest,
            "miss": miss,
            "total": total,
            "note": note,
            "missing": missing_list,
            "refuse": is_refuse,
            "blob": blob,
        })

    items.sort(key=lambda x: x["miss"], reverse=True)
    if not args.all:
        items = [x for x in items if not x["refuse"]]

    print(f"# queue_top (showing {min(len(items), args.top)} / {len(items)} likely feasible)")
    print(f"# use --all to include NOTE: refused/prompt/no-receiver/etc\n")
    for i, it in enumerate(items[:args.top], 1):
        print(f"{i:02d}. {it['name']} -> {it['dest']}  missing {it['miss']}/{it['total']}")
        if it["note"]:
            print(f"    {it['note']}")
        if it["missing"]:
            print(f"    missing: {', '.join(it['missing'][:12])}{' ...' if len(it['missing'])>12 else ''}")
        print()

if __name__ == "__main__":
    main()
