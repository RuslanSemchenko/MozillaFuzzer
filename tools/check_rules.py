"""Validation gate for the Domato grammars. Run it after every rules edit.

It answers three questions that diffing a rules file cannot answer:

  parse    every grammar, and every !include it pulls in, loads silently
  resolve  every symbol some rule references can actually be produced
  generate real cases come out of the adapter end to end, repeatedly

Domato reports a broken rule by printing to stdout and carrying on, so a run
can look fine while the grammar has quietly dropped rules and the new coverage
never appears in a case. That is why this check is fail-closed on every
Domato diagnostic and on any placeholder left in the output.

Usage:
  py -3.14 tools/check_rules.py
  py -3.14 tools/check_rules.py --samples 20 --keep
"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from grizzly.common.storage import TestCase  # noqa: E402
from grz_domato import DomatoAdapter  # noqa: E402
from sapphire import ServerMap  # noqa: E402

# Printed by domato/grammar.py and domato/generator.py when a rule is broken.
DIAGNOSTICS = (
    "Error parsing line",
    "Unknown command",
    "Error reading",
    "No creators for type",
    "Error: No root element defined",
    "There were errors parsing",
    "Warning:",
)
# Placeholders the adapter is responsible for filling in.
PLACEHOLDERS = (
    "cssfuzzer",
    "htmlfuzzer",
    "jsfuzzer",
    "canvasfuzz",
    "glfuzz",
    "webgpufuzz",
)
# Tags the generator handles itself, so they need no rule of their own.
GENERATOR_TAGS = ("import", "lines", "any", "call")


def case_file(case: TestCase) -> Path:
    """The entry point as written to disk by the adapter."""
    relative = case.entry_point.lstrip("/").replace("/", os.sep)
    return case.root / relative


def unresolved_symbols(grammar, origin: str) -> list[str]:
    """Symbols a rule references that nothing in this grammar can produce.

    A rule with an unresolvable symbol is generated as an error at runtime, so
    the branch is dead: it looks like coverage in the rules file and is not."""
    known = (
        set(grammar._creators)
        | set(grammar._built_in_types)
        | set(grammar._constant_types)
        | set(grammar._imports)
        | set(grammar._functions)
        | set(GENERATOR_TAGS)
    )
    bad = {
        part["tagname"]
        for rule in grammar._all_rules
        for part in rule["parts"]
        if part["type"] != "text" and "new" not in part and part["tagname"] not in known
    }
    return [
        f"{origin}: no rule produces <{symbol}> (grep rules/ for its definition)"
        for symbol in sorted(bad)
    ]


def unfilled(html: str) -> list[str]:
    """Placeholders that survived into a generated case."""
    found = [f"<{name}>" for name in PLACEHOLDERS if f"<{name}>" in html]
    found += [match.group(0) for match in re.finditer(r"<shader\d+>", html)]
    return [f"case still contains {text} - the adapter never replaced it" for text in found]


def strip_js_literals(source: str) -> str:
    """Blank out comments and string literals, leaving only code syntax."""
    result: list[str] = []
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "/":
                state, index = "line", index + 2
                continue
            if char == "/" and following == "*":
                state, index = "block", index + 2
                continue
            if char in "'\"`":
                state, quote, index = "string", char, index + 1
                continue
            result.append(char)
            index += 1
            continue
        if state == "line":
            if char == "\n":
                state = "code"
                result.append(char)
            index += 1
            continue
        if state == "block":
            if char == "*" and following == "/":
                state, index = "code", index + 2
                continue
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1
    return "".join(result)


def js_hazards(html: str) -> list[str]:
    """Generated script bodies that cannot parse.

    grammar.py cuts everything after a literal # in a rule line, so a rule writes a
    hash sign as Domato's <hash> constant type. That is only safe inside a string:
    in expression position the generated # is a syntax error, and one syntax error
    takes the whole <script> down rather than the one line that caused it."""
    problems = []
    for script in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.I | re.S):
        body = script.group(1)
        code = strip_js_literals(body)
        for match in re.finditer(r"#", code):
            start = max(0, match.start() - 60)
            problems.append(
                "generated JS has a # outside a string literal: "
                f"...{body[start:match.start() + 20].strip()}..."
            )
            break
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=int, default=5, help="cases to generate (default: 5)")
    parser.add_argument("--keep", action="store_true", help="copy the generated cases into --outdir")
    parser.add_argument("--outdir", default="results/check")
    args = parser.parse_args()

    problems: list[str] = []
    log = io.StringIO()
    adapter = DomatoAdapter()
    sizes: list[int] = []
    kept: list[Path] = []
    started = time.monotonic()

    with contextlib.redirect_stdout(log):
        adapter.setup(None, ServerMap())
        grammars = {
            "rules/html.txt": adapter._grammars[0],
            "rules/css.txt": adapter._grammars[1],
            "rules/js.txt": adapter._grammars[2],
            **{f"{key}.txt": g for key, g in adapter._api_grammars.items()},
        }
        for origin, grammar in grammars.items():
            problems += unresolved_symbols(grammar, origin)

        for index in range(args.samples):
            case = TestCase("/test.html", "domato")
            try:
                adapter.generate(case, ServerMap())
                html = case_file(case).read_text(encoding="utf-8", errors="replace")
                sizes.append(len(html))
                problems += unfilled(html)
                problems += js_hazards(html)
                if args.keep:
                    out = Path(args.outdir)
                    out.mkdir(parents=True, exist_ok=True)
                    target = out / f"case{index:02d}.html"
                    target.write_text(html, encoding="utf-8")
                    kept.append(target)
            except Exception as exc:  # a generator crash is the failure being guarded against
                problems.append(f"case {index}: {type(exc).__name__}: {exc}")
            finally:
                case.cleanup()

    echoed = log.getvalue()
    for line in echoed.splitlines():
        if any(marker in line for marker in DIAGNOSTICS):
            problems.append(f"domato diagnostic: {line.strip()}")

    rules = sum(len(grammar._all_rules) for grammar in grammars.values())
    print(f"grammars: {len(grammars)} loaded, {rules} rules")
    if sizes:
        print(
            f"cases: {len(sizes)} in {time.monotonic() - started:.1f}s, "
            f"{min(sizes):,}-{max(sizes):,} bytes (mean {sum(sizes) // len(sizes):,})"
        )
    if kept:
        print(f"written: {kept[0].parent} ({len(kept)} files)")
    if echoed.strip():
        print("--- captured stdout ---")
        print(echoed.strip())
    if problems:
        print(f"FAIL ({len(problems)} problem(s)):")
        for problem in dict.fromkeys(problems):
            print(f"  - {problem}")
        return 1
    print("OK: every grammar parses, resolves and generates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
