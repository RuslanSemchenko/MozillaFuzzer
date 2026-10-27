"""Run generated cases in Firefox and report what the lineguards swallow.

`check_rules.py` proves a case *generates*; it cannot tell whether a generated line *runs*.
Every statement is wrapped in `try { <line> } catch(e) { }`, so a rule that throws on every
case produces no output, no diagnostic and no crash - it is invisible. This script makes the
invisible visible:

  * generates N cases through the same DomatoAdapter a fuzzing session uses (or scans files
    given with --input, e.g. a saved crash testcase),
  * replaces each grammar's empty lineguard catch with a collector, so a thrown rule is
    recorded with its stack instead of discarded,
  * installs window error/unhandledrejection hooks for errors thrown asynchronously,
  * calls eventhandler1..5 explicitly, because those 5 x 500 statements only run when a
    generated on* attribute happens to fire,
  * serves the instrumented case to the built Firefox with Grizzly's fuzzing prefs, waits
    for the page to POST its findings, then navigates to the next case in the same browser,
  * maps each stack frame back to the served HTML line, so the report names the rule text.

What it does *not* answer: whether a line that does not throw does anything useful, whether a
receiver is null (a TypeError is reported, a silent no-op is not), or whether a silent
early return hid the interesting path. It is a detector for the guaranteed-throw class
(document.createEvent names, observer callbacks, enum arguments), not a coverage tool.

Expected throws are part of the corpus - `insertRule('@import ...')` is deliberately refused
elsewhere in the rules - so the default exit status is 0. Use --strict when every reported
error is considered a failure, and read the counts: a rule that throws in every case is dead
text; a rule that throws once in fifty is doing its job.

Usage (opens a Firefox window):
  python3 tools/scan_cases.py --samples 10
  python3 tools/scan_cases.py --input results/check --samples 3
  python3 tools/scan_cases.py --samples 20 --strict --dump results/audit/scan_cases.json
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fx_paths import require_firefox_bin  # noqa: E402

# Injected at the top of <head>: the collector the replaced catches call, plus global hooks.
# The collectors themselves use `catch (x)` with a space so instrument() cannot match them.
HEAD = """<script>
window.__fz = [];
window.__fz_err = function (e) {
  try {
    if (window.__fz.length < 5000) {
      window.__fz.push({
        kind: "caught",
        name: String((e && e.name) || "Error"),
        message: String(e && e.message !== undefined ? e.message : e),
        // a DOMException from a promise has no stack; the collector's own
        // stack still names the lineguard that caught it
        stack: String((e && e.stack) || (new Error("collector")).stack || "")
      });
    }
  } catch (x) {}
};
window.addEventListener("error", function (ev) {
  try {
    var e = ev.error;
    window.__fz.push({
      kind: "uncaught",
      name: String((e && e.name) || "Error"),
      message: String(e && e.message !== undefined ? e.message : (ev.message || "")),
      stack: String((e && e.stack) || "")
    });
  } catch (x) {}
});
window.addEventListener("unhandledrejection", function (ev) {
  try {
    var e = ev.reason;
    window.__fz.push({
      kind: "rejection",
      name: String((e && e.name) || "Error"),
      message: String(e && e.message !== undefined ? e.message : e),
      stack: String((e && e.stack) || "")
    });
  } catch (x) {}
});
try {
  var __fz_console_error = console.error;
  console.error = function () {
    try {
      // A generated console.error() with no arguments is an API call under
      // fuzz, not a page error; a real report always carries a message.
      if (arguments.length && window.__fz.length < 5000) {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) { parts.push(String(arguments[i])); }
        window.__fz.push({kind: "console", name: "console.error",
                          message: parts.join(" "), stack: ""});
      }
    } catch (x) {}
    return __fz_console_error.apply(console, arguments);
  };
} catch (x) {}
</script>"""

# Injected before </body>. The timers are the safety net: a generated <img src> that never
# loads must not stop the reporter, and runHandlers() must not depend on the load event.
END = """<script>
(function () {
  var caseIndex = __CASE__;
  var settle = __SETTLE__;
  var hard = __HARD__;
  var done = false;
  function runHandlers() {
    if (!__FORCE__) { return; }
    for (var i = 1; i <= 5; i++) {
      try {
        if (typeof window["eventhandler" + i] === "function") { window["eventhandler" + i](); }
      } catch (e) { window.__fz_err(e); }
    }
  }
  function report() {
    if (done) { return; }
    done = true;
    var body = JSON.stringify({case: caseIndex, errors: window.__fz});
    try {
      fetch("/report", {method: "POST", body: body}).then(function () {
        location = "__NEXT__";
      }, function () { location = "__NEXT__"; });
    } catch (e) { location = "__NEXT__"; }
  }
  function beacon() {
    if (done) { return; }
    done = true;
    try {
      var body = JSON.stringify({case: caseIndex, errors: window.__fz.slice(0, 200)});
      navigator.sendBeacon("/report", new Blob([body], {type: "application/json"}));
    } catch (e) {}
  }
  window.addEventListener("pagehide", beacon);
  window.addEventListener("load", function () {
    setTimeout(function () { runHandlers(); setTimeout(report, settle); }, 0);
  });
  setTimeout(function () { runHandlers(); report(); }, hard);
})();
</script>"""

# The three lineguard shapes in the tree (js/jshelpers, canvas, webgl, webgpu). Longest first:
# "catch(e) { }" is a prefix of nothing here, but "catch(e) { console.log(...) }" must win.
GUARDS = (
    "catch(e) { console.log(e.message) }",
    "catch(e) { }",
    "catch(e) {}",
)
REPLACEMENT = "catch(e) { window.__fz_err(e); }"

STACK_SITE = re.compile(r"case\d+\.html(?:[?#][^:\s]*)?:(\d+):\d+")

# A null/undefined receiver is the symptom of a creator that failed earlier in the case. Those
# rows are real, but they are counted apart: the actionable line is the creator, not its effects.
CASCADE = re.compile(r"can't access property .* (?:is null|is undefined)|can't convert (?:null|undefined) to object")


def instrument(html: str, index: int, next_url: str, settle_ms: int, hard_ms: int, force: bool) -> str:
    """Make a case report its swallowed exceptions.

    Line numbers stay consistent because the two injected scripts are inserted whole and the
    catch replacement changes bytes only within a line.
    """
    end = (
        END.replace("__CASE__", str(index))
        .replace("__SETTLE__", str(settle_ms))
        .replace("__HARD__", str(hard_ms))
        .replace("__FORCE__", "true" if force else "false")
        .replace("__NEXT__", next_url)
    )
    if "</head>" in html:
        html = html.replace("</head>", HEAD + "\n</head>", 1)
    else:
        html = HEAD + html
    # The generated markup may contain its own </body> (an SVG foreignObject nests an HTML
    # body), so the reporter belongs before the *last* one - the real end of the document.
    close = html.rfind("</body>")
    if close >= 0:
        html = html[:close] + end + "\n" + html[close:]
    else:
        html += end
    for guard in GUARDS:
        html = html.replace(guard, REPLACEMENT)
    return html


def build_pages(raw_cases: list[str], settle_ms: int, hard_ms: int, force: bool) -> list[str]:
    pages = []
    for index, html in enumerate(raw_cases):
        next_url = f"/case{index + 1}.html" if index + 1 < len(raw_cases) else "about:blank"
        pages.append(instrument(html, index, next_url, settle_ms, hard_ms, force))
    return pages


def write_prefs(profile: Path, variant: str) -> None:
    from prefpicker import PrefPicker

    profile.mkdir(parents=True, exist_ok=True)
    template = PrefPicker.load_template(PrefPicker.lookup_template("browser-fuzzing.yml"))
    template.create_prefsjs(profile / "prefs.js", variant=variant)


def collect(pages: list[str], firefox: Path, profile: Path, case_timeout: int, log_path: Path) -> tuple[dict, str]:
    """Serve the chain of cases and wait for each page to POST its errors.

    Returns {case index: [error rows]} plus a status line for cases that never reported.
    The browser is driven by the pages themselves (report -> location = next case), so no
    Marionette dependency is needed and the whole scan is one browser launch.
    """
    results: dict[int, list[dict]] = {}
    unexpected: list[str] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            match = re.fullmatch(r"/case(\d+)\.html", self.path)
            if match and int(match.group(1)) < len(pages):
                body = pages[int(match.group(1))].encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path in ("/favicon.ico", "/"):
                self.send_response(204)
                self.end_headers()
            else:
                unexpected.append(f"GET {self.path}")
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/report":
                unexpected.append(f"POST {self.path}")
                self.send_response(404)
                self.end_headers()
                return
            length = min(int(self.headers.get("Content-Length", 0)), 8_000_000)
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                index = int(payload["case"])
                rows = list(payload.get("errors") or [])
            except (ValueError, KeyError, TypeError):
                self.send_response(400)
                self.end_headers()
                return
            with lock:
                results.setdefault(index, rows)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/case0.html"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("wt", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [str(firefox), "--no-remote", "--profile", str(profile), url],
        stdout=subprocess.DEVNULL,
        stderr=log,
    )
    deadline = time.monotonic() + case_timeout * len(pages) + 30
    last_activity = time.monotonic()
    cursor = 0
    stalls: list[str] = []

    def launch(index: int) -> subprocess.Popen:
        page_url = f"http://127.0.0.1:{httpd.server_address[1]}/case{index}.html"
        return subprocess.Popen(
            [str(firefox), "--no-remote", "--profile", str(profile), page_url],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )

    try:
        while cursor < len(pages) and time.monotonic() < deadline:
            if proc.poll() is not None:
                stalls.append(f"browser exited with status {proc.returncode} at case {cursor}")
                break
            with lock:
                rows = results.get(cursor)
            if rows is not None:
                print(f"  case {cursor + 1}/{len(pages)}: {len(rows)} error row(s)", flush=True)
                last_activity = time.monotonic()
                cursor += 1
                continue
            if time.monotonic() - last_activity > case_timeout:
                # A page that hangs in generated JS never reaches its report timer, and
                # without a restart the remaining cases would never be scanned.
                stalls.append(f"case {cursor} never reported (timeout {case_timeout}s)")
                print(
                    f"  case {cursor + 1}/{len(pages)} timed out - restarting at the next case",
                    flush=True,
                )
                proc.kill()
                proc.wait()
                cursor += 1
                if cursor >= len(pages):
                    break
                proc = launch(cursor)
                deadline += case_timeout
                last_activity = time.monotonic()
                continue
            time.sleep(0.2)
        else:
            if cursor < len(pages) and time.monotonic() >= deadline:
                stalls.append(f"deadline reached at case {cursor}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd.shutdown()
        log.close()
    if unexpected:
        sample = sorted(set(unexpected))[:10]
        print(f"unexpected request(s) - page navigated or fetched elsewhere: {', '.join(sample)}", file=sys.stderr)
    with lock:
        return dict(results), "; ".join(stalls)


def read_cases(adapter, samples: int, seed: int | None, outdir: Path) -> tuple[list[str], list[str]]:
    """Generate cases through the adapter, save the raw HTML, return it in order."""
    from grizzly.common.storage import TestCase
    from sapphire import ServerMap

    cases: list[str] = []
    diagnostics: list[str] = []
    if seed is not None:
        random.seed(seed)
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        adapter.setup(None, ServerMap())
        for index in range(samples):
            case = TestCase("/test.html", "domato")
            try:
                adapter.generate(case, ServerMap())
                relative = case.entry_point.lstrip("/").replace("/", os.sep)
                html = (case.root / relative).read_text(encoding="utf-8", errors="replace")
                outdir.mkdir(parents=True, exist_ok=True)
                (outdir / f"case{index:02d}.html").write_text(html, encoding="utf-8")
                cases.append(html)
            finally:
                case.cleanup()
    for line in log.getvalue().splitlines():
        if any(marker in line for marker in ("Error parsing", "No creators for type", "Warning:")):
            diagnostics.append(line.strip())
    return cases, diagnostics


def read_inputs(paths: list[Path]) -> list[str]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.html")))
        else:
            files.append(path)
    return [path.read_text(encoding="utf-8", errors="replace") for path in files]


def site_line(stack: str) -> int | None:
    """The first frame in the case file - the line that threw."""
    for frame in (stack or "").splitlines():
        # a DOMException with no stack of its own carries the collector's
        # stack, whose first frame is the collector itself; the caller is next
        if "__fz_err" in frame:
            continue
        match = STACK_SITE.search(frame)
        if match:
            return int(match.group(1))
    return None


def normalize(text: str) -> str:
    """Collapse the per-case random parts of a line so the same rule groups together."""
    text = re.sub(r"0x[0-9a-fA-F]+", "0x#", text or "")
    text = re.sub(r"\b(?:html|svg|mathml|fuzz)?var\d+\b", lambda m: re.sub(r"\d+$", "#", m.group(0)), text)
    text = re.sub(r"\b\d+\b", "#", text)
    return re.sub(r"\s+", " ", text).strip()


def analyse(results: dict[int, list[dict]], pages: list[str]) -> list[dict]:
    lines = [page.splitlines() for page in pages]
    emitted: collections.Counter = collections.Counter()
    pages_with: collections.Counter = collections.Counter()
    for page_lines in lines:
        seen = set()
        for line in page_lines:
            key = normalize(line)
            emitted[key] += 1
            seen.add(key)
        for key in seen:
            pages_with[key] += 1
    rows: list[dict] = []
    for index, errors in results.items():
        for error in errors:
            stack = str(error.get("stack") or "")
            line_no = site_line(stack)
            source = ""
            if line_no and 0 < line_no <= len(lines[index]):
                source = lines[index][line_no - 1].strip()
            key = normalize(source)[:220] if source else ""
            rows.append(
                {
                    "case": index,
                    "kind": error.get("kind", "?"),
                    "name": error.get("name", "?"),
                    "message": str(error.get("message", "")),
                    "line": line_no,
                    "source": source,
                    "source_key": key,
                    "emitted": emitted.get(key, 0),
                    "pages_with": pages_with.get(key, 0),
                    "stack": stack,
                }
            )
    return rows


def report(rows: list[dict], total_cases: int, top: int) -> None:
    groups: dict[tuple, dict] = {}
    for row in rows:
        key = (row["kind"], row["name"], normalize(row["message"]), row.get("source_key") or normalize(row.get("source", ""))[:220])
        entry = groups.setdefault(
            key,
            {"count": 0, "cases": set(), "name": row["name"], "kind": row["kind"],
             "message": row["message"], "source": row.get("source", ""), "line": row.get("line"),
             "emitted": row.get("emitted", 0), "pages_with": row.get("pages_with", 0)},
        )
        entry["count"] += 1
        entry["cases"].add(row["case"])

    items = list(groups.values())
    for item in items:
        item["spread"] = len(item["cases"])
        item["ratio"] = item["spread"] / item["pages_with"] if item["pages_with"] else None
        item["cascade"] = bool(CASCADE.search(item["message"]))
        item["creator"] = "/* newvar{" in (item["source"] or "")
    items.sort(key=lambda item: (-(item["ratio"] or 0), -item["spread"], -item["count"]))

    creators = [item for item in items if item["creator"] and not item["cascade"]]
    roots = [item for item in items if not item["creator"] and not item["cascade"] and item["source"]]
    cascades = [item for item in items if item["cascade"]]
    asyncs = [item for item in items if not item["source"]]
    systematic = sum(1 for item in items if item["ratio"] == 1 and item["pages_with"] >= 2)

    print(
        f"errors: {len(rows)} row(s), {len(items)} group(s); "
        f"{systematic} systematic (threw in every case that emitted the rule)"
    )
    print(
        f"  creators {len(creators)} | roots {len(roots)} | cascades {len(cascades)} | "
        f"async/no-line {len(asyncs)}"
    )

    def section(title: str, entries: list[dict]) -> None:
        if not entries:
            return
        print(f"\n== {title} ({len(entries)}) ==")
        for item in entries[:top]:
            when = f"{item['spread']}/{item['pages_with']}" if item["pages_with"] else f"{item['spread']}/?"
            flag = "  ALL" if item["ratio"] == 1 and item["pages_with"] >= 2 else ""
            print(f"{when:>6s} {item['count']:4d}x{flag}  {item['kind']} {item['name']}: {item['message'][:140]}")
            if item["source"]:
                print(f"          line {item['line']}: {item['source'][:200]}")
        if len(entries) > top:
            print(f"  ... {len(entries) - top} more")

    section("creator rules that throw (the variable is never created)", creators)
    section("other caught errors", roots)
    section("async errors with no line in the case", asyncs)
    section("cascades - a null receiver from an earlier failure", cascades)
    if not items:
        print("no errors reported")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=int, default=5, help="cases to generate (default: 5)")
    parser.add_argument("--input", type=Path, nargs="+", help="scan existing HTML file(s)/dir(s) instead of generating")
    parser.add_argument("--seed", type=int, help="seed Domato's RNG for a reproducible batch")
    parser.add_argument("--firefox", type=Path, default=None)
    parser.add_argument("--profile", type=Path, default=ROOT / "results" / "scan_prof")
    parser.add_argument("--outdir", type=Path, default=ROOT / "results" / "scan", help="where raw and instrumented cases are written")
    parser.add_argument("--variant", default="fuzzing", help="Grizzly prefs template variant")
    parser.add_argument("--settle", type=int, default=1500, help="ms to let async API work finish after load (default: 1500)")
    parser.add_argument("--hard", type=int, default=15000, help="ms before the page reports even if load never fires (default: 15000)")
    parser.add_argument("--case-timeout", type=int, default=25, help="seconds a single case may take before the scan stops (default: 25)")
    parser.add_argument("--no-force-handlers", action="store_true", help="do not call eventhandler1..5 explicitly")
    parser.add_argument("--top", type=int, default=25, help="groups printed per section (default: 25)")
    parser.add_argument("--dump", type=Path, help="write raw rows as JSON here")
    parser.add_argument("--report-only", type=Path, help="re-print a previous --dump without starting Firefox")
    parser.add_argument("--strict", action="store_true", help="exit 1 if any caught/uncaught/rejection row was reported")
    args = parser.parse_args()
    if args.report_only is None:
        args.firefox = args.firefox or require_firefox_bin()

    if args.report_only is not None:
        payload = json.loads(args.report_only.read_text(encoding="utf-8"))
        report(payload["rows"], payload.get("cases", 0), args.top)
        return 0

    problems: list[str] = []
    if args.input:
        raw_cases = read_inputs(args.input)
        origin = f"{len(raw_cases)} input file(s)"
    else:
        from grz_domato import DomatoAdapter

        raw_cases, problems = read_cases(DomatoAdapter(), args.samples, args.seed, args.outdir)
        origin = f"{len(raw_cases)} generated case(s)"
    if not raw_cases:
        print("no cases to scan", file=sys.stderr)
        return 1
    print(f"scanning {origin} with {args.firefox}")
    for problem in problems:
        print(f"  domato diagnostic: {problem}", file=sys.stderr)

    pages = build_pages(raw_cases, args.settle, args.hard, not args.no_force_handlers)
    args.outdir.mkdir(parents=True, exist_ok=True)
    for index, page in enumerate(pages):
        (args.outdir / f"case{index:02d}.scan.html").write_text(page, encoding="utf-8")

    write_prefs(args.profile, args.variant)
    started = time.monotonic()
    results, status = collect(pages, args.firefox, args.profile, args.case_timeout, args.outdir / "firefox.log")
    print(f"finished in {time.monotonic() - started:.1f}s: {len(results)}/{len(pages)} case(s) reported")
    if status:
        print(f"STOPPED: {status}", file=sys.stderr)

    rows = analyse(results, pages)
    report(rows, len(pages), args.top)
    if args.dump:
        args.dump.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "firefox": str(args.firefox),
            "seed": args.seed,
            "cases": len(pages),
            "reported": len(results),
            "status": status,
            "rows": rows,
        }
        args.dump.write_text(json.dumps(payload, indent=1), encoding="utf-8")
        print(f"written: {args.dump}")

    if status:
        return 1
    if args.strict and any(row["kind"] != "console" for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
