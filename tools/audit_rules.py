"""Join the Firefox WebIDL inventory against what the Domato grammars can
actually emit, so the rules work queue is built on facts rather than on
"text appears somewhere in a .txt file".

Two different questions are answered separately and never conflated:

  mentioned  the name appears in some parsed rule, reachable or not
  reachable  the name appears in a rule that the generator can actually select,
             i.e. reachable from the grammar's live entry points

Only "reachable" means the API is being fuzzed. Gating is read from the real
sources: StaticPrefList.yaml for [Pref] defaults and Grizzly's own fuzzing
prefs template, because a pref that is off by default but on while fuzzing is
reachable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent

from grz_domato import DOMATO_DIR, _load_domato, _parse_grammar  # noqa: E402

ENTRY_POINTS = {
    "html": ("rules/html.txt", ("line", "bodyelements")),
    "css": ("rules/css.txt", ("line", "rules")),
    "js": ("rules/js.txt", ("line",)),
    "canvas": ("canvas/canvas.txt", ("line",)),
    "webgl": ("webgl/webgl.txt", ("line",)),
}
# IDL kind/name patterns that decide which rules file should own an interface.
# Graphics APIs each have their own grammar and template, so they must not be
# routed into the DOM rules just because they are Web APIs.
API_ROUTING = (
    (re.compile(r"^GPU"), "webgpu/webgpu.txt"),
    # WebGL extension namespaces (EXT_*, OES_*, WEBGL_*) are object bags reached
    # through gl.getExtension(), so their members belong to the webgl grammar.
    (re.compile(r"^(WebGL|EXT_|OES_|WEBGL_|ANGLE_|MOZ_WEBGL|WEBKIT_WEBGL)"), "webgl/webgl.txt"),
    (
        re.compile(
            r"^(CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D|CanvasGradient|CanvasPattern"
            r"|Path2D|ImageData|ImageBitmap|TextMetrics|ImageTrack|ImageFrame|CanvasDrawContext)$"
        ),
        "canvas/canvas.txt",
    ),
)
ROUTING = (
    (re.compile(r"^SVG"), "svg.txt"),
    (re.compile(r"^MML"), "mathml.txt"),
    (re.compile(r"^(CSS|.*CSS.*|Style.*|.*Style)$"), "css.txt"),
    (re.compile(r".*Element$|^(HTMLElement|HTML.*Element)$"), "tagattributes.txt"),
)
DEFAULT_TARGET = "webapis.txt"
SKIP_KINDS = ("typedef", "callback")
# Queue entries whose gap is real but whose fix is a decision, not a rule to write.
NOTES = {
    "FuzzingFunctions": (
        "reachable only because Grizzly sets fuzzing.enabled; crash/killGPUProcess/memoryPressure "
        "end the session and must never be emitted"
    ),
}


def rule_text(rule) -> str:
    parts = []
    for part in rule["parts"]:
        parts.append(part["text"] if part["type"] == "text" else f"<{part['tagname']}>")
    return "".join(parts)


# A member counts as emitted only where a member can syntactically appear: after
# a property access, inside a bracket-string lookup, or as a direct call. Matching
# bare identifiers instead reports a keyword as coverage - `<Window>.print()` is
# commented out in js.txt, yet "print" appears in reachable text as a CSS media
# type and "cm" as a CSS unit. The call form matters because globals are fuzzed
# that way: `setTimeout(...)` in js.txt:6129 and `fetch(...)` in wasm.txt:321 are
# real Window members.
MEMBER_POSITIONS = (
    re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]"),
    re.compile(r"(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\("),
)


def reachable_text(grammar, seeds) -> str:
    """Concatenate the text of every rule the generator can reach from seeds."""
    seen_rules: set[int] = set()
    queue = list(seeds)
    seen_syms = set(queue)
    out = []
    while queue:
        symbol = queue.pop()
        for rule in grammar._creators.get(symbol, ()):
            if id(rule) not in seen_rules:
                seen_rules.add(id(rule))
                out.append(rule_text(rule))
            for part in rule["parts"]:
                if part["type"] != "text":
                    tag = part["tagname"]
                    if tag not in seen_syms:
                        seen_syms.add(tag)
                        queue.append(tag)
    return "\n".join(out)


def all_text(grammar) -> str:
    return "\n".join(rule_text(rule) for rule in grammar._all_rules)


def load_prefs(source_root: Path) -> dict[str, bool]:
    """Pref name -> enabled, from StaticPrefList.yaml defaults."""
    path = source_root / "modules" / "libpref" / "init" / "StaticPrefList.yaml"
    prefs: dict[str, bool] = {}
    if not path.exists():
        return prefs
    name = None
    value = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        found = re.match(r"^- name: (\S+)", line)
        if found:
            if name is not None:
                prefs[name] = bool(value)
            name, value = found.group(1), None
            continue
        found = re.match(r"^\s+value: (\S+)", line)
        if found and name is not None and value is None:
            value = found.group(1).lower() in ("true", "1")
    if name is not None:
        prefs[name] = bool(value)
    return prefs


def load_fuzzing_prefs() -> dict[str, bool]:
    """Prefs Grizzly itself applies, from prefpicker's template.

    Only the `default:` variant counts. A pref that is true in the `vr:` or
    `a11y:` variant is off in a normal session, and a lone `null` means "leave
    the StaticPrefList default alone", which is not an override.
    """
    try:
        from prefpicker import PrefPicker
    except ImportError:
        return {}
    path = Path(PrefPicker.lookup_template("browser-fuzzing.yml"))
    prefs: dict[str, bool] = {}
    if not path.exists():
        return prefs
    in_pref_block = False
    pref = None
    variant = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_pref_block = line.strip() == "pref:"
            continue
        if not in_pref_block:
            continue
        found = re.match(r"^  ([a-zA-Z0-9_.\-]+):\s*$", line)
        if found:
            pref, variant = found.group(1), None
            continue
        found = re.match(r"^ {6}([a-z-]+):\s*$", line)
        if found and pref is not None:
            variant = found.group(1)
            continue
        found = re.match(r"^ {6}- (.+)$", line)
        if found and pref is not None and variant == "default":
            value = found.group(1).strip()
            if value in ("true", "1"):
                prefs[pref] = True
            elif value in ("false", "0"):
                prefs.setdefault(pref, False)
    return prefs


def pref_enabled(pref: str, defaults: dict[str, bool], fuzzing: dict[str, bool]) -> bool:
    """Whether a pref is on in a Grizzly session: Grizzly's own value wins,
    otherwise the StaticPrefList default applies."""
    if pref in fuzzing:
        return fuzzing[pref]
    return defaults.get(pref, False)


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def gate_reason(entry: dict, prefs: dict[str, bool], fuzzing: dict[str, bool]) -> str | None:
    """Why a content fuzzer cannot reach this type at all, if it cannot."""
    attrs = entry["attrs"]
    if attrs.get("ChromeOnly") or attrs.get("SystemPrincipal"):
        return "chrome-only"
    exposed = attrs.get("Exposed")
    if exposed:
        # [Exposed=*] and [Exposed=(Window,Worker)] both reach a content fuzzer;
        # only a list that names no Window-ish scope is a real gate.
        values = [
            item.strip().strip("()")
            for group in _as_list(exposed)
            for item in str(group).split(",")
        ]
        if not any(item in ("*", "Window") for item in values):
            return f"not exposed to Window ({exposed})"
    for pref in (p for p in _as_list(attrs.get("Pref", "")) if p):
        if not pref_enabled(pref, prefs, fuzzing):
            return f"pref off: {pref}"
    return None


def suggest_target(name: str, entry: dict) -> str:
    for pattern, target in API_ROUTING:
        if pattern.match(name):
            return target
    if name == "CSS":
        # the CSS *object*'s members are JS statics (CSS.cm, CSS.supports) and a
        # css.txt rule emits declaration text, where such a name cannot appear
        return DEFAULT_TARGET
    for pattern, target in ROUTING:
        if pattern.match(name):
            return target
    if entry["parent"] and entry["parent"].endswith("Element"):
        return "tagattributes.txt"
    return DEFAULT_TARGET


def member_target(base: str, kinds: list[str]) -> str:
    """Which file a member of an interface routed to `base` belongs to.

    Only `*Element` splits: its attributes can be set as HTML attributes, which is
    what tagattributes.txt is for, while its methods (moveBefore, setCapture,
    getAttributeNames) are ordinary DOM calls and belong to the JS rules."""
    if base == "tagattributes.txt" and "attribute" not in kinds:
        return DEFAULT_TARGET
    return base


def member_positions(text: str) -> frozenset[str]:
    """Names used where a property can be read or written, one pass over text."""
    found: set[str] = set()
    for pattern in MEMBER_POSITIONS:
        found.update(pattern.findall(text))
    return frozenset(found)


def write_work_orders(report: list[dict], probe_path: Path, out_dir: Path) -> list[Path]:
    """Join the queue with the browser's verdicts, one file per destination grammar.

    A missing member is only work if the binding exists, and only probe_apis.py can
    say that per member. An interface the page had no receiver for - a WebGL
    extension object, a worker-only interface - reports every member as not-exposed,
    which is a fact about the probe rather than the API, so those are filed apart
    instead of being mistaken for a closed gap.
    """
    if not probe_path.exists():
        return []
    probe = json.load(open(probe_path, encoding="utf-8"))
    present: dict[str, set[str]] = {}
    absent: dict[str, set[str]] = {}
    for row in probe["probed"]:
        if row["state"].startswith("present:"):
            present.setdefault(row["iface"], set()).add(row["member"])
        elif row["state"] == "not-exposed":
            absent.setdefault(row["iface"], set()).add(row["member"])
    no_receiver = set(probe.get("unprobeable", ()))
    # probe.json files written before the page reported that as data only say it in prose
    no_receiver |= {
        error.split(":", 1)[0]
        for error in probe.get("errors", ())
        if "no page object" in error or "no such global" in error
    }

    orders: dict[str, dict[str, list[str]]] = {}
    for entry in report:
        if entry["blocked"]:
            continue
        # every destination gets a file even when its queue empties, so closing a
        # target cannot leave a stale work order behind to be read as open work
        orders.setdefault(entry["target"], {})
        for target, members in entry["missing_by_target"].items():
            for member in members:
                name = entry["name"]
                if name in no_receiver:
                    verdict = "no receiver"
                elif member in present.get(name, ()):
                    verdict = "present"
                elif member in absent.get(name, ()):
                    verdict = "not-exposed"
                else:
                    verdict = "unprobed"
                orders.setdefault(target, {}).setdefault(verdict, []).append(f"{name}.{member}")

    legend = [
        "Members still missing, split by what tools/probe_apis.py answered about them.",
        "Re-derive with `py -3.14 tools/audit_rules.py` after both it and probe_apis.py ran.",
        "",
        "- present: the browser has the binding. This is the work list.",
        "- not-exposed: the browser does not have it, so every generated call would throw",
        "  and the per-line guard would swallow it. Not a gap; do not write rules for it.",
        "- no receiver: the probe had no page object to read (WebGL extension objects are",
        "  only reachable through getExtension(), worker-only interfaces have no window).",
        "  Add a receiver to tools/probe_apis.py before treating these either way.",
        "- unprobed: probe.json has no row for the member. Probe before writing rules.",
    ]
    written = []
    for target, verdicts in sorted(orders.items(), key=lambda kv: -sum(len(v) for v in kv[1].values())):
        path = out_dir / f"work_{target.replace('/', '_')}.md"
        lines = [f"# Work order: {target}", ""] + legend + [""]
        if not verdicts:
            lines += [
                "## nothing missing",
                "",
                "No content-reachable member routed to this file is unemitted.",
                "",
            ]
        for verdict, rows in sorted(verdicts.items()):
            lines += [f"## {verdict} ({len(rows)})", ""] + [f"- {row}" for row in sorted(rows)] + [""]
        path.write_text("\n".join(lines), encoding="utf-8")
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=r"C:\mozilla-source\firefox")
    parser.add_argument("--inventory", default="results/audit/idl_inventory.json")
    parser.add_argument("--out", default="results/audit/coverage.json")
    parser.add_argument("--queue", default="results/audit/QUEUE.md")
    parser.add_argument(
        "--probe",
        default="results/audit/probe.json",
        help="probe_apis.py output to join with the queue for the per-file work orders",
    )
    parser.add_argument("--top", type=int, default=40, help="interfaces to list in the queue")
    parser.add_argument("--target", default=None, help="only queue entries routed to this rules file")
    parser.add_argument("--name", default=None, help="only queue entries whose interface name contains this")
    parser.add_argument(
        "--show-blocked",
        action="store_true",
        help="list interface-level gates too, so an absent interface is not mistaken for an absent API",
    )
    args = parser.parse_args()

    source = Path(args.source)
    gen = _load_domato()
    reachable = {}
    mentioned = {}
    for label, (filename, seeds) in ENTRY_POINTS.items():
        grammar = _parse_grammar(gen, DOMATO_DIR / filename)
        reachable[label] = reachable_text(grammar, seeds)
        mentioned[label] = all_text(grammar)
    # the WebGPU grammar needs shader-derived symbols, so it is scanned via the
    # adapter's own builder rather than parsed standalone
    adapter_grammar = _parse_grammar(gen, DOMATO_DIR / "webgpu" / "webgpu.txt", "")
    reachable["webgpu"] = reachable_text(adapter_grammar, ("line",))
    mentioned["webgpu"] = all_text(adapter_grammar)
    # one pass per grammar beats a word-boundary regex per member over ~10MB of
    # rule text, and member position (not bare-identifier presence) decides
    # coverage - see MEMBER_POSITIONS above
    reachable_at = {label: member_positions(text) for label, text in reachable.items()}
    mentioned_at = {label: member_positions(text) for label, text in mentioned.items()}
    reachable_ids = frozenset().union(*reachable_at.values())
    mentioned_ids = frozenset().union(*mentioned_at.values())
    reachable_words = frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", "\n".join(reachable.values())))

    types = json.load(open(args.inventory, encoding="utf-8"))["types"]
    # a mixin that some interface includes has already had its members folded
    # into that interface, so listing it again would double-count the same work
    folded = {m for entry in types.values() for m in entry.get("includes", ())}
    prefs = load_prefs(source)
    fuzzing = load_fuzzing_prefs()

    report = []
    for name, entry in sorted(types.items()):
        if entry["kind"] in SKIP_KINDS or entry["kind"] == "enum" or not entry["members"]:
            continue
        if entry["kind"] == "interface mixin" and name in folded:
            continue
        blocked = gate_reason(entry, prefs, fuzzing)
        # const members are numeric aliases a fuzzer reaches through the API
        # itself, so they are counted apart and never queued as work
        standard, gated, chrome_only, pref_off, consts = [], [], [], [], []
        for member, slot in entry["members"].items():
            kinds, attrs = slot["kinds"], slot["attrs"]
            if "const" in kinds or member == "constructor":
                consts.append(member)
            elif any(key in attrs for key in ("SystemPrincipal", "ChromeOnly", "MozSystem")):
                chrome_only.append(member)
            elif attrs.get("Pref") and not any(
                pref_enabled(p, prefs, fuzzing) for p in _as_list(attrs["Pref"])
            ):
                pref_off.append(member)
            elif attrs.get("Func"):
                gated.append(member)
            else:
                standard.append(member)
        # coverage is decided first, then split by bucket: a [Func]-gated member
        # the grammar already emits is not work, and must not appear as a gap
        missing, reachable_members, mentioned_only, name_only = [], [], [], []
        covered_by, probe, missing_by_target = {}, [], {}
        base = suggest_target(name, entry)
        for member in standard + gated:
            if member in reachable_ids:
                reachable_members.append(member)
                covered_by[member] = sorted(
                    label for label, ids in reachable_at.items() if member in ids
                )
            elif member in mentioned_ids:
                mentioned_only.append(member)
            elif member in gated:
                # [Func] needs the browser to answer, presence in text proves nothing
                probe.append(member)
            elif member in reachable_words:
                # the word is in live rules, but never as a property of anything:
                # a CSS keyword, an ARIA role, an attribute name. Not this API.
                name_only.append(member)
            else:
                missing.append(member)
                missing_by_target.setdefault(
                    member_target(base, entry["members"][member]["kinds"]), []
                ).append(member)
        report.append(
            {
                "name": name,
                "kind": entry["kind"],
                "source": entry["source"],
                "parent": entry["parent"],
                "target": base,
                "blocked": blocked,
                "members": len(standard),
                "consts": len(consts),
                "chrome_only": sorted(chrome_only),
                "pref_off": sorted(pref_off),
                "needs_probe": sorted(probe),
                "reachable": sorted(reachable_members),
                "covered_by": covered_by,
                "mentioned_only": sorted(mentioned_only),
                "name_only": sorted(name_only),
                "missing": sorted(missing),
                "missing_by_target": {
                    key: sorted(value) for key, value in sorted(missing_by_target.items())
                },
            }
        )

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=1), encoding="utf-8")

    live = [r for r in report if not r["blocked"]]
    queue = [r for r in live if r["missing"]]
    spread_by_target: dict[str, int] = {}
    for entry in queue:
        for target, members in entry["missing_by_target"].items():
            spread_by_target[target] = spread_by_target.get(target, 0) + len(members)
    spread = ", ".join(
        f"{target}: {count}"
        for target, count in sorted(spread_by_target.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    if args.target:
        queue = [r for r in queue if args.target in r["missing_by_target"]]
    if args.name:
        wanted = args.name.lower()
        queue = [r for r in queue if wanted in r["name"].lower()]
    queue.sort(key=lambda r: (-len(r["missing"]), r["name"]))

    lines = [
        "# Rules work queue",
        "",
        f"Generated by `tools/audit_rules.py` from {len(types)} WebIDL types against 6 grammars.",
        "",
        "How a number here is produced, and what it is not:",
        "- covered means the member name appears in a rule reachable from the grammar's live",
        "  entry points AND in a position where a property is read or written (`X.name`,",
        "  `X[\"name\"]`). `parsed but unreachable` names are in rules the generator cannot select;",
        "  `word only` names appear in live rules as a keyword, ARIA role or attribute name and",
        "  say nothing about this API. None of them is coverage.",
        "- member names are matched, never executed: this says nothing about whether the call does",
        "  anything useful at runtime. Only tools/probe_apis.py can settle that.",
        "- excluded before queuing: const aliases (numeric enums reachable via the API itself),",
        "  [SystemPrincipal]/[ChromeOnly] members, members whose [Pref] is off in both",
        "  StaticPrefList.yaml and Grizzly's own fuzzing prefs, and mixins already folded into the",
        "  interface that includes them.",
        "- `needs probe` members carry [Func=...], i.e. a C++ reachability predicate this script",
        "  cannot evaluate; they are listed apart and must be probed before being added.",
        "",
        f"- types considered: {len(report)}, not gated off at interface level: {len(live)}",
        f"- gated off at interface level: {len(report) - len(live)}",
        f"- interfaces/objects with at least one missing content-reachable member: {len(queue)}",
        f"- missing members by destination rules file: {spread}",
        "",
    ]
    for entry in queue[: args.top]:
        owned = entry["missing_by_target"]
        routed = " or ".join(sorted(owned)) if len(owned) > 1 else entry["target"]
        lines.append(
            f"## {entry['name']} -> {routed} "
            f"(missing {len(entry['missing'])} of {entry['members']} content-reachable members) [{entry['source']}]"
        )
        if entry["name"] in NOTES:
            lines.append(f"- NOTE: {NOTES[entry['name']]}")
        if entry["parent"]:
            lines.append(f"- inherits: {entry['parent']}")
        if entry["mentioned_only"]:
            lines.append(f"- parsed but unreachable ({len(entry['mentioned_only'])}): {', '.join(entry['mentioned_only'][:12])}")
        # the full missing list is the work order, so it is never truncated; the
        # informational buckets below are
        for target, members in owned.items():
            label = "missing" if len(owned) == 1 else f"missing for {target}"
            lines.append(f"- {label} ({len(members)}): {', '.join(members)}")
        for label, key in (("needs probe", "needs_probe"), ("word only", "name_only"), ("excluded chrome-only", "chrome_only"), ("excluded pref-off", "pref_off")):
            if entry[key]:
                lines.append(f"- {label} ({len(entry[key])}): {', '.join(entry[key][:30])}")
        lines.append("")
    if args.show_blocked:
        lines.append("# Gated off at interface level (not work the rules can fix)")
        lines.append("")
        for entry in sorted((r for r in report if r["blocked"]), key=lambda r: r["name"]):
            lines.append(f"- {entry['name']} [{entry['source']}]: {entry['blocked']}")
        lines.append("")
    Path(args.queue).write_text("\n".join(lines), encoding="utf-8")

    probe_path = Path(args.probe)
    if not probe_path.is_absolute():
        probe_path = ROOT / probe_path
    orders = write_work_orders(report, probe_path, Path(args.queue).parent)

    print(f"{len(report)} types, {len(live)} ungated, {len(queue)} with missing members")
    print(f"queue -> {args.queue}  detail -> {args.out}")
    if orders:
        print("work orders -> " + ", ".join(path.name for path in orders))
    else:
        print(f"work orders -> skipped, no {probe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
