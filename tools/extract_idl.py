"""Extract the content-facing WebIDL surface of a Firefox source tree.

Reads dom/webidl/*.webidl (and any extra dirs given with --dir) and writes a
JSON inventory of interfaces, mixins, dictionaries, enums and their members,
together with the extended attributes that decide whether a content fuzzer can
reach them at all.

dom/chrome-webidl is deliberately not read by default: those bindings are
chrome-only and unreachable from a served page.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# declaration: an optional run of [attrs] blocks, then the kind, then the name
_ATTR_BLOCK = r"(?:\[[^\]]*\]\s*)*"
_KINDS = r"interface\ mixin|interface|namespace|dictionary|callback\ interface|callback|enum|typedef"
_DECL = re.compile(rf"({_ATTR_BLOCK})({_KINDS})\s+([A-Za-z0-9_]+)")
_MEMBER_ATTR = re.compile(r"^\s*((?:\[[^\]]*\]\s*)+)")
_ATTR_SPLIT = re.compile(r"\s*,\s*(?![^\[\(]*[\]\)])")
# The trailing ';' is optional because parse_file() splits the body on ';' before
# matching, so an anchored one never matches and drops every attribute: the
# inventory silently held only methods and consts. `readonly attribute (A or B)? x`
# then fell through to _OPERATION, which read `attribute` as the member name.
_ATTRIBUTE = re.compile(
    r"\b(?:readonly\s+|inherit\s+)?attribute\s+(?:[^;]*?\s)?([A-Za-z0-9_]+)"
    r"\s*(?:\[[^\]]*\])?\s*(?:;|\Z)"
)
_OPERATION = re.compile(r"(?:^|\s)(?:static\s+|stringifier\s+|getter\s+|setter\s+|deleter\s+|creator\s+)*([A-Za-z0-9_<>?\[\]]+(?:\s+nullable)?|any|void|undefined)\s+([A-Za-z0-9_]+)\s*\(")
_CONSTRUCTOR = re.compile(r"\bconstructor\s*\(")
# A special operation declares how [] / String() behave, not a callable name:
# `getter nsISupports (DOMString name)` has no member called nsISupports. Matching
# its return type as a member put impossible work in the queue (UTF8String,
# CSSUnparsedSegment, GleanMetric).
_SPECIAL_OP = re.compile(r"^(?:static\s+)?(?:getter|setter|deleter|stringifier|legacycaller)\b")
_CONST = re.compile(r"\bconst\s+\S.*?\s+([A-Za-z0-9_]+)\s*=")
_REL = re.compile(r"([A-Za-z0-9_]+)\s+(?:includes|implements)\s+([A-Za-z0-9_]+)\s*;")
_ENUM_VALUE = re.compile(r'^\s*"([^"]+)"')


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def parse_attrs(raw: str) -> dict:
    """Turn '[Pref="x.y", Exposed=(Window,Worker)]' into a dict of names."""
    out: dict[str, object] = {}
    for block in re.findall(r"\[([^\]]*)\]", raw):
        for item in _ATTR_SPLIT.split(block.strip()):
            item = item.strip()
            if not item:
                continue
            name, _, value = item.partition("=")
            name = name.strip()
            value = value.strip().strip('"')
            if name in ("Pref", "Func", "AllowedPrefName", "SystemPrincipal", "ChromeOnly"):
                if name in ("SystemPrincipal", "ChromeOnly"):
                    out[name] = True
                else:
                    prev = out.get(name)
                    out[name] = ([prev] if isinstance(prev, str) and prev else []) + ([value] if value else [""])
            else:
                out.setdefault(name, value or True)
    return out


def merge_attrs(dst: dict, src: dict) -> None:
    """Merge one extended-attribute set into another across overloads/partials.

    A member declared twice (overload, partial interface, mixin) is reachable if
    any declaration is, so Pref/Func lists accumulate instead of overwrite.
    """
    for key, value in src.items():
        if key in ("Pref", "Func") and isinstance(value, list):
            prev = dst.get(key)
            prev = prev if isinstance(prev, list) else ([prev] if isinstance(prev, str) else [])
            dst[key] = sorted(set(prev) | set(value))
        elif key not in dst:
            dst[key] = value


def find_body(text: str, start: int) -> tuple[str, int]:
    """Return the brace-matched body starting at/after `start` and its end index."""
    open_at = text.find("{", start)
    close_at = text.find(";", start)
    if open_at == -1 or (close_at != -1 and close_at < open_at):
        end = close_at if close_at != -1 else len(text)
        return "", end
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : index], index + 1
    return text[open_at + 1 :], len(text)


def parse_file(path: Path) -> dict:
    text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
    types: dict[str, dict] = {}
    includes: dict[str, list[str]] = {}
    position = 0
    while True:
        header = _DECL.search(text, position)
        if not header:
            break
        attrs = parse_attrs(header.group(1) or "")
        kind, name = header.group(2), header.group(3)
        body, end = find_body(text, header.end())
        between = text[header.end() : end].replace(body, "", 1)
        entry = types.setdefault(
            name,
            {
                "name": name,
                "kind": kind,
                "source": path.name,
                "attrs": {},
                "members": {},
                "partial": False,
                "parent": None,
                "values": [],
            },
        )
        parent = re.search(r":\s*([A-Za-z0-9_]+)", between)
        if parent:
            entry["parent"] = parent.group(1)
        entry["attrs"].update(attrs)
        preceding = text[max(0, header.start() - 40) : header.start()]
        if "Partial" in attrs or re.search(r"\bpartial\b", preceding):
            entry["partial"] = True
        if kind == "enum":
            entry["values"] = sorted(
                set(entry["values"])
                | {value.group(1) for value in (_ENUM_VALUE.match(line.strip()) for line in body.split(",")) if value}
            )
        else:
            for member in body.split(";"):
                member = member.strip()
                if not member:
                    continue
                lead = _MEMBER_ATTR.match(member)
                member_attrs = parse_attrs(lead.group(1)) if lead else {}
                if lead:
                    member = member[lead.end() :].strip()
                for pattern, mkind, group in ((_ATTRIBUTE, "attribute", 1), (_OPERATION, "method", 2), (_CONST, "const", 1)):
                    if pattern is _OPERATION and _SPECIAL_OP.match(member):
                        continue
                    found = pattern.search(member)
                    if found:
                        slot = entry["members"].setdefault(found.group(group), {"kinds": set(), "attrs": {}})
                        slot["kinds"].add(mkind)
                        merge_attrs(slot["attrs"], member_attrs)
                        break
                if _CONSTRUCTOR.search(member):
                    slot = entry["members"].setdefault("constructor", {"kinds": set(), "attrs": {}})
                    slot["kinds"].add("constructor")
                    merge_attrs(slot["attrs"], member_attrs)
        position = end
        if position >= len(text):
            break
    for target, mixin in _REL.findall(text):
        includes.setdefault(target, []).append(mixin)
    return {"types": types, "includes": includes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="/home/ruslan/firefox", help="Firefox source root")
    parser.add_argument("--dir", action="append", default=None, help="IDL directory, relative to --source")
    parser.add_argument("--out", default="results/audit/idl_inventory.json")
    args = parser.parse_args()

    root = Path(args.source)
    dirs = args.dir or ["dom/webidl"]
    missing = [rel for rel in dirs if not (root / rel).is_dir()]
    if missing:
        raise SystemExit(f"no IDL directory {', '.join(missing)} under {root} - pass --source <firefox checkout>")
    types: dict[str, dict] = {}
    includes: dict[str, list[str]] = {}
    files = 0
    for rel in dirs:
        for path in sorted((root / rel).rglob("*.webidl")):
            files += 1
            parsed = parse_file(path)
            for name, entry in parsed["types"].items():
                target = types.setdefault(name, {**entry, "members": {}, "attrs": {}, "values": []})
                for member, slot in entry["members"].items():
                    merged = target["members"].setdefault(member, {"kinds": set(), "attrs": {}})
                    merged["kinds"] |= slot["kinds"]
                    merge_attrs(merged["attrs"], slot["attrs"])
                merge_attrs(target["attrs"], entry["attrs"])
                target["values"] = sorted(set(target["values"]) | set(entry["values"]))
                target["partial"] = target["partial"] or entry["partial"]
                target["parent"] = target["parent"] or entry["parent"]
            for name, mixin in parsed["includes"].items():
                includes.setdefault(name, []).extend(mixin)

    # mixins contribute their members to every interface that includes them
    for target, mixins in includes.items():
        entry = types.get(target)
        if not entry:
            continue
        for mixin in mixins:
            source = types.get(mixin)
            if not source:
                continue
            for member, slot in source["members"].items():
                merged = entry["members"].setdefault(member, {"kinds": set(), "attrs": {}})
                merged["kinds"] |= slot["kinds"]
                merge_attrs(merged["attrs"], slot["attrs"])

    for entry in types.values():
        entry["members"] = {k: {"kinds": sorted(v["kinds"]), "attrs": v["attrs"]} for k, v in sorted(entry["members"].items())}
        entry["values"] = sorted(entry["values"])
        entry["includes"] = sorted(set(includes.get(entry["name"], ())))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"files": files, "includes": {k: sorted(set(v)) for k, v in includes.items()}, "types": types}, indent=1, sort_keys=True),
        encoding="utf-8",
    )
    interfaces = sum(1 for t in types.values() if t["kind"].startswith("interface"))
    members = sum(len(t["members"]) for t in types.values())
    print(f"{files} files, {len(types)} types ({interfaces} interfaces), {members} members -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
