"""Answer, at runtime, whether a binding a rules candidate needs is actually
exposed to content in this build.

Why this exists: [Func] and [Pref] gate the *binding*, not just the behaviour.
When the gate is false the property is missing from the object, so a generated
call throws on every iteration and the rules written for it are wasted. The
gate is a C++ predicate this repo cannot evaluate, but presence is directly
observable - so the question goes to the browser.

Nothing is ever called. `name in obj` does not invoke a getter and walking the
prototype chain is enough to decide whether a method or attribute is exposed,
which matters because most candidates here would crash, hang or open a dialog
if executed. A member is checked on the prototype (instance members), on the
constructor (statics such as DOMMatrix.fromFloat32Array), on the namespace
object (CSS, console) and on a live instance where one is free to take.

Usage (run it yourself - it opens a Firefox window):
  python3 tools/probe_apis.py
  python3 tools/probe_apis.py --bucket all --only Document Window

Use the built binary, not the distro package: the Debian /usr/lib/firefox is a release
build with navigator.gpu compiled off, so a WebGPU probe run against it is a verdict
about the wrong browser.
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

FIREFOX = Path(
    "/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox"
)
# IDL names that are WebGL extension object bags rather than page globals. This is the
# set of extension interfaces declared in WebGLRenderingContext.webidl: ANGLE_*, EXT_*,
# OES_*, OVR_*, WEBGL_*, WEBKIT_WEBGL_* and the Firefox-only MOZ_debug. Missing one puts
# the interface in `unprobeable` instead of giving it an answer.
EXTENSION_PREFIXES = ("EXT_", "OES_", "OVR_", "WEBGL_", "ANGLE_", "MOZ_", "WEBKIT_WEBGL_")
PAGE = """<!doctype html><meta charset=utf-8><title>rules probe</title><body><script>
const out = {env: {}, probed: [], unprobeable: [], errors: []};
// Interfaces whose members can also land as own-properties of a live object.
// Each of these just reads something the page already has: none of them
// constructs, navigates or otherwise exercises an API.
const INSTANCES = {
  Window: () => window,
  Document: () => document,
  Navigator: () => navigator,
  Location: () => window.location,
  History: () => window.history,
  Performance: () => window.performance,
  Screen: () => window.screen,
};

// getContext returns the cached context per name per canvas, so one canvas per
// requested name keeps webgl and webgl2 answers independent of each other
const glCanvases = {};
function glContext(name) {
  if (!(name in glCanvases)) {
    glCanvases[name] = document.createElement("canvas");
  }
  let ctx = null;
  try {
    ctx = glCanvases[name].getContext(name);
  } catch (err) {
    ctx = null;
  }
  return ctx;
}

function exists(obj, member) {
  try {
    return member in obj;
  } catch (err) {
    return false;
  }
}

// A member is exposed if any of the objects the IDL puts it on carries the
// name: prototype for instance members, constructor for statics, the value
// itself for namespaces such as CSS and console.
// WebGL extensions have no window global at all - the IDL interface names the
// object that getExtension() hands back - so those are probed on the object.
function probe(iface, members, isExtension, windowGlobal) {
  const global = window[iface];
  const scopes = [];
  // a type the IDL exposes to Window is looked up by name, so "no such property" is
  // an answer; only a type with no window-side receiver is a question this page
  // cannot ask, and that is the difference between not-exposed and unprobeable
  let asked = !!global || !!windowGlobal;
  if (global && global.prototype) {
    scopes.push(["prototype", global.prototype], ["static", global]);
  } else if (global) {
    scopes.push(["namespace", global]);
  }
  if (isExtension) {
    for (const name of ["webgl2", "webgl"]) {
      const ctx = glContext(name);
      if (!ctx) {
        continue;
      }
      // reaching a context means the question was asked, whatever comes back:
      // getExtension() returning null IS the answer about an extension object
      asked = true;
      let ext = null;
      try {
        ext = ctx.getExtension(iface);
      } catch (err) {
        ext = null;
      }
      if (ext) {
        scopes.push(["getExtension(" + name + ")", ext]);
      }
    }
  }
  let instance;
  if (INSTANCES[iface]) {
    try {
      instance = INSTANCES[iface]();
    } catch (err) {
      instance = null;
    }
  }
  if (instance) {
    asked = true;
    scopes.push(["instance", instance]);
  }
  for (const member of members) {
    let state = "not-exposed";
    for (const [label, obj] of scopes) {
      if (exists(obj, member)) {
        state = "present:" + label;
        break;
      }
    }
    out.probed.push({iface, member, state});
  }
  if (!asked && members.length) {
    // structured, so audit_rules.py does not have to read prose to know that
    // these members' not-exposed rows mean nothing
    out.unprobeable.push(iface);
    out.errors.push(iface + ": no page object carries this interface");
  }
}

const targets = %TARGETS%;
for (const target of targets) {
  probe(target.iface, target.members, !!target.ext, !!target.windowGlobal);
}

try {
  const canvas = document.createElement("canvas");
  out.env.ctx2d = !!canvas.getContext("2d");
  // which context name this build actually hands out, and what it is called:
  // asking only for 'webgl' once reported the API dead while 'webgl2' worked
  for (const name of ["webgl2", "webgl", "experimental-webgl"]) {
    const ctx = glContext(name);
    out.env[name] = ctx ? ctx.constructor.name : "null";
  }
  out.env.gpu_in_navigator = "gpu" in navigator;
} catch (err) {
  out.errors.push("env: " + err.name + " " + err.message);
}
// adapter acquisition is asynchronous, so the report goes out once it has run
(async () => {
  if (out.env.gpu_in_navigator) {
    try {
      const adapter = await navigator.gpu.requestAdapter();
      out.env.adapter = adapter ? "OK" : "null";
      if (adapter) {
        const device = await adapter.requestDevice();
        out.env.device = device ? "OK" : "null";
        if (device) {
          out.env.maxBindGroups = device.limits.maxBindGroups;
          device.destroy();
        }
      }
    } catch (err) {
      out.errors.push("gpu: " + err.name + " " + err.message);
    }
  }
  await fetch("/report", {method: "POST", body: JSON.stringify(out)});
  document.title = "probed";
})();
</script></body>
"""


def build_page(targets: list[dict]) -> str:
    """Render the probe page with the interface list inlined."""
    payload = [
        {
            "iface": target["iface"],
            "members": sorted(target["members"]),
            "ext": bool(target.get("ext")),
            "windowGlobal": bool(target.get("windowGlobal")),
        }
        for target in targets
    ]
    return PAGE.replace("%TARGETS%", json.dumps(payload))


def write_prefs(profile: Path, variant: str) -> None:
    """Rebuild prefs.js from Grizzly's own template, so the probe sees the
    conditions of a fuzzing session rather than the browser's defaults."""
    from prefpicker import PrefPicker

    profile.mkdir(parents=True, exist_ok=True)
    template = PrefPicker.load_template(PrefPicker.lookup_template("browser-fuzzing.yml"))
    template.create_prefsjs(profile / "prefs.js", variant=variant)


def collect(page_targets: list[dict], firefox: Path, profile: Path, timeout: int) -> dict | None:
    """Serve the page and wait for the browser to post the result back."""
    result: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/probe.html"):
                body = build_page(page_targets).encode("utf-8")
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
    url = f"http://127.0.0.1:{httpd.server_address[1]}/probe.html"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    proc = subprocess.Popen(
        [str(firefox), "--no-remote", "--profile", str(profile), url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + timeout
    while "data" not in result and time.monotonic() < deadline:
        time.sleep(0.2)
    # only ever stop the instance this script started; a wider taskkill would
    # take out the user's browser and any fuzzing session already running
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


def window_global(attrs: dict) -> bool:
    """Whether the IDL says this type has a window-side global to look up by name.

    A binding the build compiled out is simply absent from `window`, and that absence
    is the verdict - `FuzzingFunctions` is the case in point, since the namespace only
    exists in an --enable-fuzzing build. A type the IDL never exposes to Window
    (worker-only, LegacyNoInterfaceObject, WebGL extension objects, prompt-handed
    objects) has no receiver here at all, and its rows mean nothing.
    """
    if attrs.get("LegacyNoInterfaceObject") or attrs.get("ChromeOnly") or attrs.get("SystemPrincipal"):
        return False
    exposed = attrs.get("Exposed")
    if not exposed:
        return True
    values = [
        item.strip().strip("()")
        for group in (exposed if isinstance(exposed, list) else [exposed])
        for item in str(group).split(",")
    ]
    return any(item in ("*", "Window") for item in values)


def selected_members(entry: dict, bucket: str) -> list[str]:
    if bucket == "probe":
        return list(entry["needs_probe"])
    if bucket == "missing":
        return list(entry["missing"])
    return list(entry["needs_probe"]) + list(entry["missing"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--coverage", default="results/audit/coverage.json")
    parser.add_argument(
        "--inventory",
        default="results/audit/idl_inventory.json",
        help="extract_idl.py output, for the extended attributes coverage.json does not carry",
    )
    parser.add_argument("--out", default="results/audit/probe.json")
    parser.add_argument(
        "--bucket",
        choices=("probe", "missing", "all"),
        default="all",
        help="which audit buckets to verify (default: all queued candidates)",
    )
    parser.add_argument("--only", nargs="*", default=None, help="limit to these interfaces")
    parser.add_argument("--variant", default="default", help="prefpicker variant to probe under")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--firefox", type=Path, default=FIREFOX)
    parser.add_argument("--page", default=None, help="write the probe page here instead of running it")
    args = parser.parse_args()

    coverage = Path(args.coverage)
    if not coverage.is_absolute():
        coverage = ROOT / coverage
    inventory = Path(args.inventory)
    if not inventory.is_absolute():
        inventory = ROOT / inventory
    if not inventory.exists():
        raise SystemExit(f"no {inventory} - run tools/extract_idl.py first")
    idl = json.load(open(inventory, encoding="utf-8"))["types"]
    report = json.load(open(coverage, encoding="utf-8"))
    targets = []
    for entry in report:
        members = selected_members(entry, args.bucket)
        if not members or (args.only and entry["name"] not in args.only):
            continue
        attrs = idl.get(entry["name"], {}).get("attrs", {})
        targets.append(
            {
                "iface": entry["name"],
                "members": members,
                # an extension interface has no global: the name is the query
                # string that getExtension() answers
                "ext": entry["name"].startswith(EXTENSION_PREFIXES),
                "windowGlobal": window_global(attrs),
            }
        )
    if not targets:
        print("nothing to probe - the selected bucket is empty")
        return 1

    total = sum(len(target["members"]) for target in targets)
    print(f"probing {total} members across {len(targets)} interfaces")
    if args.page:
        Path(args.page).write_text(build_page(targets), encoding="utf-8")
        print(f"page -> {args.page}")
        return 0
    if not args.firefox.exists():
        print(f"no firefox at {args.firefox} - pass --firefox <path>", file=sys.stderr)
        return 1

    profile = ROOT / "results" / "probe_prof"
    write_prefs(profile, args.variant)
    data = collect(targets, args.firefox, profile, args.timeout)
    if data is None:
        return 1

    counts: dict[str, int] = {}
    for item in data["probed"]:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    print(f"env: {json.dumps(data['env'])}")
    for error in data["errors"]:
        print(f"  error: {error}")
    print("states: " + ", ".join(f"{state}={count}" for state, count in sorted(counts.items())))
    for state in sorted(counts):
        if state.startswith("present"):
            continue
        for item in data["probed"]:
            if item["state"] == state:
                print(f"  {state:>14}  {item['iface']}.{item['member']}")
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    print(f"detail -> {out}")
    print("not-exposed means the gate is closed in this build: do not write rules for it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
