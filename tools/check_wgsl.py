"""Compile every domato/rules/wgsl/*.wgsl in one foreground Firefox page.

The corpus is the ceiling on what the WebGPU grammar can say, so a module that does
not compile is worse than a missing module: the grammar pairs entry points by stage
name and never learns the shader was rejected. Each module is compiled with
getCompilationInfo(), then given a render pipeline and a compute pipeline built from
the stage entry points it actually declares, collected through a validation error
scope - a pipeline that only "did not throw" is not a verdict.

Usage: python3 tools/check_wgsl.py [--timeout 150]
It opens one Firefox window on one page and closes it again; nothing is fuzzed.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fx_paths import require_firefox_bin  # noqa: E402

WGSL_DIR = ROOT / "domato" / "rules" / "wgsl"
PROFILE = ROOT / "results" / "wgsl_check_prof"

PAGE = """<!doctype html><html><body><script>
async function report(body) {
  await fetch("/result", { method: "POST", body: JSON.stringify(body) });
}

async function main() {
  const out = { shaders: [], fatal: null };
  let adapter = null;
  try {
    adapter = await navigator.gpu.requestAdapter();
  } catch (e) {
    out.fatal = "requestAdapter threw: " + e;
    await report(out);
    return;
  }
  if (!adapter) {
    out.fatal = "no adapter";
    await report(out);
    return;
  }
  const device = await adapter.requestDevice();
  device.addEventListener("uncapturederror", (ev) => {
    out.uncaptured = (out.uncaptured || []).concat([ev.error.name + ": " + ev.error.message]);
  });
  // createRenderPipeline never throws for a bad entry point or a mismatched stage -
  // WebGPU reports validation errors asynchronously, so "did not throw" is not a
  // verdict. The error scope collects the real answer for exactly one call.
  async function scoped(make) {
    await device.queue.onSubmittedWorkDone();
    await device.pushErrorScope("validation");
    try {
      make();
    } catch (e) {
      await device.popErrorScope();
      return String(e);
    }
    const err = await device.popErrorScope();
    await device.queue.onSubmittedWorkDone();
    return err === null ? "ok" : err.name + ": " + err.message;
  }

  // the stage contract is read from the module, the same way the grammar reads it:
  // asking a compute-only shader for 'vs' would test the checker, not the corpus
  const stages = (code) => {
    const found = {};
    const re = /@(vertex|fragment|compute)(?:\\s+@[\\w]+(?:\\([^)]*\\))?)*\\s+fn\\s+(\\w+)/g;
    for (const m of code.matchAll(re)) if (!found[m[1]]) found[m[1]] = m[2];
    return found;
  };

  for (const src of %SOURCES%) {
    const entry = { name: src.name, errors: [], warnings: [], pipeline: null, compute: null };
    out.shaders.push(entry);
    let module;
    try {
      module = device.createShaderModule({ code: src.code });
    } catch (e) {
      entry.errors.push("createShaderModule: " + e);
      continue;
    }
    const info = await module.getCompilationInfo();
    for (const msg of info.messages) {
      const line = src.code.split("\\n")[Math.max(0, msg.lineNum - 1)] || "";
      const text = msg.type + " @" + msg.lineNum + ":" + msg.linePos + " " + msg.message + " | " + line.trim();
      if (msg.type === "error") entry.errors.push(text);
      else entry.warnings.push(text);
    }
    if (entry.errors.length) continue;
    const stage = stages(src.code);
    entry.pipeline = (stage.vertex && stage.fragment) ? await scoped(() => device.createRenderPipeline({
      layout: "auto",
      vertex: { module, entryPoint: stage.vertex },
      fragment: { module, entryPoint: stage.fragment, targets: [{ format: "rgba8unorm" }] },
    })) : "skipped (no " + (stage.vertex ? "fragment" : "vertex") + " stage)";
    entry.compute = stage.compute ? await scoped(() => device.createComputePipeline({
      layout: "auto",
      compute: { module, entryPoint: stage.compute },
    })) : "skipped (no compute stage)";
  }
  await report(out);
}
main().catch((e) => report({ fatal: String(e), shaders: [] }));
</script></body></html>
"""


def build_page(sources: list[dict]) -> str:
    return PAGE.replace(
        "%SOURCES%", json.dumps([{"name": s["name"], "code": s["code"]} for s in sources])
    )


def write_prefs(profile: Path, variant: str) -> None:
    from prefpicker import PrefPicker

    profile.mkdir(parents=True, exist_ok=True)
    template = PrefPicker.load_template(PrefPicker.lookup_template("browser-fuzzing.yml"))
    template.create_prefsjs(profile / "prefs.js", variant=variant)


def collect(sources: list[dict], firefox: Path, profile: Path, timeout: int) -> dict | None:
    result: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/wgsl.html"):
                body = build_page(sources).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            result["data"] = json.loads(self.rfile.read(length).decode("utf-8"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/wgsl.html"
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
        print(f"NO CALLBACK after {timeout}s", file=sys.stderr)
        return None
    return result["data"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--variant", default="default")
    parser.add_argument("--firefox", type=Path, default=None)
    parser.add_argument("--out", default="results/audit/wgsl_check.json")
    args = parser.parse_args()
    firefox = args.firefox or require_firefox_bin()

    sources = []
    for path in sorted(WGSL_DIR.glob("*.wgsl")):
        sources.append({"name": path.name, "code": path.read_text(encoding="utf-8")})
    if not sources:
        print(f"no shaders under {WGSL_DIR}", file=sys.stderr)
        return 1

    write_prefs(PROFILE, args.variant)
    data = collect(sources, firefox, PROFILE, args.timeout)
    if data is None:
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")

    if data.get("fatal"):
        print(f"FATAL: {data['fatal']}")
        return 1

    failed = 0
    for entry in data["shaders"]:
        bad = [entry["pipeline"], entry["compute"]]
        unmet = [text for text in bad if text and not text.startswith(("ok", "skipped"))]
        failed += bool(entry["errors"]) + bool(unmet)
        print(f"{('OK' if not entry['errors'] and not unmet else 'FAIL'):4} "
              f"{entry['name']:28} render={entry['pipeline']} compute={entry['compute']} "
              f"warn={len(entry['warnings'])}")
        for message in entry["errors"] + unmet:
            print(f"     {message}")
    for message in data.get("uncaptured", []):
        print(f"UNCAPTURED {message}")
    print(f"{len(data['shaders'])} modules, {failed} with compile or pipeline failures -> {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
