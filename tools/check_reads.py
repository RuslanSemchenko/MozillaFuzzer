"""Answer, at runtime, whether an expression a rules candidate needs actually *runs*.

probe_apis.py answers "is this property on the object" with `name in obj`, which never calls a
getter. That is the right question for a [Func] gate and the wrong question for a rule: a property
can sit on a prototype and still be unreachable, because the receiver content can make is null,
because the only producer is async, or because the class has an illegal constructor. Every case
below is a member that probe_apis.py reported `present` and a real evaluation then refused:
`new ResizeObserverSize(...)` (Illegal constructor), `document.createEvent("WheelEvent")`
(NotSupportedError), `ac.createMediaStreamSource(new MediaStream())` (InvalidStateError).

So this script does the other half: it evaluates named JS expressions in the built Firefox and
reports which ones threw. Write one expression per member, self-contained, and read the message -
`ok` means the rule belongs in the grammar, `THREW` means it does not.

Usage (run it yourself - it opens a Firefox window):
  python3 tools/check_reads.py exprs.json
  python3 tools/check_reads.py --dump exprs.json > results/audit/reads.json

exprs.json is {"name": "expression"}; the expression is evaluated with eval(), so a `var` inside
it is allowed and each one runs in its own scope. Expressions that resolve asynchronously should
report through a side channel and be read back in a second run.

eval() here is the point, not an accident: the strings are JS the operator wrote into the JSON
file, the page is served from 127.0.0.1 to a Firefox this script starts and stops, and nothing
from outside the file reaches the evaluator. Do not feed it a rules file, a fetched page or any
other value someone else controls.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIREFOX = Path("/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox")

PAGE = """<!doctype html><meta charset=utf-8><title>read check</title><body><script>
const results = [];
for (const cand of %TARGETS%) {
  let value = null, status = "ok";
  try { value = String(eval(cand.expr)); } catch (err) { status = "THREW " + err.name + ": " + err.message; }
  results.push({name: cand.name, expr: cand.expr, status, value});
}
fetch("/report", {method: "POST", body: JSON.stringify(results)});
</script></body>"""


def build_page(expressions: dict[str, str]) -> str:
    payload = [{"name": name, "expr": expr} for name, expr in expressions.items()]
    return PAGE.replace("%TARGETS%", json.dumps(payload))


def collect(expressions: dict[str, str], firefox: Path, profile: Path, timeout: int) -> list[dict] | None:
    """Serve the page and wait for the browser to post the verdicts back."""
    result: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = build_page(expressions).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            result["data"] = json.loads(self.rfile.read(length).decode("utf-8"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/readcheck.html"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    proc = subprocess.Popen(
        [str(firefox), "--no-remote", "--profile", str(profile), url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + timeout
    while "data" not in result and time.monotonic() < deadline:
        time.sleep(0.2)
    # only ever stop the instance this script started
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    httpd.shutdown()
    if "data" not in result:
        print(f"NO CALLBACK after {timeout}s - the page never reported to {url}", file=sys.stderr)
        return None
    return result["data"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("expressions", help="JSON object of name -> expression")
    parser.add_argument("--firefox", type=Path, default=FIREFOX)
    parser.add_argument("--profile", type=Path, default=ROOT / "results" / "readcheck_prof")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--variant", default="fuzzing", help="Grizzly prefs template variant")
    parser.add_argument("--dump", type=Path, help="also write the raw verdicts as JSON here")
    args = parser.parse_args()

    expressions = json.loads(Path(args.expressions).read_text(encoding="utf-8"))

    from prefpicker import PrefPicker

    args.profile.mkdir(parents=True, exist_ok=True)
    template = PrefPicker.load_template(PrefPicker.lookup_template("browser-fuzzing.yml"))
    template.create_prefsjs(args.profile / "prefs.js", variant=args.variant)

    rows = collect(expressions, args.firefox, args.profile, args.timeout)
    if rows is None:
        return 1
    if args.dump:
        args.dump.parent.mkdir(parents=True, exist_ok=True)
        args.dump.write_text(json.dumps(rows, indent=1), encoding="utf-8")

    threw = [row for row in rows if row["status"] != "ok"]
    for row in rows:
        mark = "ok  " if row["status"] == "ok" else "BAD "
        detail = row["value"][:60] if row["status"] == "ok" else row["status"]
        print(f"{mark} {row['name']:36s} {detail[:90]}")
    print(f"--- {len(threw)} of {len(rows)} threw ---")
    return 1 if threw else 0


if __name__ == "__main__":
    raise SystemExit(main())
