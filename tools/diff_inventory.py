"""Compare two WebIDL inventory JSON files to highlight API changes.

When pulling or building a new Firefox revision (e.g. Nightly updates), this tool
computes the exact delta:
  * Newly introduced interfaces and types
  * Newly added members (methods, attributes) to existing interfaces
  * Removed interfaces or members
  * Gating changes (e.g. a [Pref] was removed because a feature graduated to default-on)

Usage:
  python3 tools/diff_inventory.py old_inventory.json new_inventory.json
  python3 tools/diff_inventory.py --baseline results/audit/idl_inventory.json.bak
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_inventory(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"Inventory file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(f"Failed to parse {path}: {e}")


def compare_inventories(old_inv: dict, new_inv: dict) -> int:
    old_types: dict[str, dict] = old_inv.get("types", {})
    new_types: dict[str, dict] = new_inv.get("types", {})

    old_names = set(old_types.keys())
    new_names = set(new_types.keys())

    added_types = sorted(new_names - old_names)
    removed_types = sorted(old_names - new_names)
    common_types = sorted(old_names & new_names)

    added_members: dict[str, list[str]] = {}
    removed_members: dict[str, list[str]] = {}
    gating_changes: dict[str, list[str]] = {}

    for name in common_types:
        ot = old_types[name]
        nt = new_types[name]

        # Check members
        om_dict = ot.get("members", {})
        nm_dict = nt.get("members", {})
        om_names = set(om_dict.keys())
        nm_names = set(nm_dict.keys())

        new_m = sorted(nm_names - om_names)
        if new_m:
            added_members[name] = new_m

        del_m = sorted(om_names - nm_names)
        if del_m:
            removed_members[name] = del_m

        # Check member gating/attrs changes
        for m in (om_names & nm_names):
            o_attrs = om_dict[m].get("attrs", {})
            n_attrs = nm_dict[m].get("attrs", {})
            if o_attrs != n_attrs:
                diffs = []
                for k in set(o_attrs.keys()) | set(n_attrs.keys()):
                    ov = o_attrs.get(k)
                    nv = n_attrs.get(k)
                    if ov != nv:
                        diffs.append(f"[{k}: {ov} -> {nv}]")
                if diffs:
                    gating_changes.setdefault(name, []).append(f"{m} " + ", ".join(diffs))

    total_changes = (
        len(added_types)
        + len(removed_types)
        + sum(len(v) for v in added_members.values())
        + sum(len(v) for v in removed_members.values())
        + sum(len(v) for v in gating_changes.values())
    )

    print("=" * 65)
    print("Firefox WebIDL Inventory Delta")
    print("=" * 65)
    print(f"Old inventory: {len(old_types)} types")
    print(f"New inventory: {len(new_types)} types")
    print(f"Total delta entries: {total_changes}")
    print()

    if added_types:
        print(f"[+] Added Interfaces / Types ({len(added_types)}):")
        for t in added_types:
            kind = new_types[t].get("kind", "unknown")
            print(f"    + {t} ({kind})")
        print()

    if removed_types:
        print(f"[-] Removed Interfaces / Types ({len(removed_types)}):")
        for t in removed_types:
            kind = old_types[t].get("kind", "unknown")
            print(f"    - {t} ({kind})")
        print()

    if added_members:
        count = sum(len(v) for v in added_members.values())
        print(f"[+] Added Members in Existing Interfaces ({count} in {len(added_members)} types):")
        for iface, members in added_members.items():
            print(f"    {iface}:")
            for m in members:
                attrs = new_types[iface]["members"][m].get("attrs", {})
                attr_str = f" {attrs}" if attrs else ""
                print(f"      + {m}{attr_str}")
        print()

    if removed_members:
        count = sum(len(v) for v in removed_members.values())
        print(f"[-] Removed Members from Existing Interfaces ({count} in {len(removed_members)} types):")
        for iface, members in removed_members.items():
            print(f"    {iface}:")
            for m in members:
                print(f"      - {m}")
        print()

    if gating_changes:
        count = sum(len(v) for v in gating_changes.values())
        print(f"[*] Gating / Extended Attribute Changes ({count}):")
        for iface, changes in gating_changes.items():
            print(f"    {iface}:")
            for c in changes:
                print(f"      * {c}")
        print()

    if total_changes == 0:
        print("No differences found between the two inventories.")

    return 0 if total_changes == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "old_inventory",
        nargs="?",
        default="results/audit/idl_inventory.json.bak",
        help="Path to baseline idl_inventory.json (default: results/audit/idl_inventory.json.bak)",
    )
    parser.add_argument(
        "new_inventory",
        nargs="?",
        default="results/audit/idl_inventory.json",
        help="Path to target idl_inventory.json (default: results/audit/idl_inventory.json)",
    )
    args = parser.parse_args()

    old_path = Path(args.old_inventory)
    new_path = Path(args.new_inventory)

    if not old_path.exists():
        if old_path.name.endswith(".bak") and new_path.exists():
            print(f"No baseline backup found at {old_path}.")
            print(f"Creating baseline backup from {new_path} ...")
            old_path.write_bytes(new_path.read_bytes())
            print("Baseline created. Re-run diff_inventory after updating Firefox.")
            return 0
        sys.exit(f"Baseline file does not exist: {old_path}")

    old_inv = load_inventory(old_path)
    new_inv = load_inventory(new_path)
    compare_inventories(old_inv, new_inv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
