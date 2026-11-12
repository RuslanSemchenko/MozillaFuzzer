#!/usr/bin/env python3
"""Model Context Protocol (MCP) server for MozillaFuzzer (grz_domato).

Enables AI agents (Cursor, Claude Desktop, Antigravity, VS Code, etc.) to directly
interact with the MozillaFuzzer toolchain:
  - Run diagnostics and environment checks (doctor)
  - Validate and verify Domato grammars and WGSL shaders (check_rules, check_wgsl)
  - Generate DOM/JS/Canvas/WebGL/WebGPU testcases (generate_case)
  - Audit WebIDL coverage and query the missing-API queue (audit_rules, get_queue)
  - Inspect Firefox WebIDL definitions and WPT usage examples (show_idl, wpt_grep)
  - Evaluate expressions and scan test cases in Firefox (check_reads, scan_cases)
  - Monitor fuzzing status and reproducers (fuzz_status)

Implements JSON-RPC 2.0 over standard I/O (newline-delimited JSON). Zero external
dependencies outside standard library and MozillaFuzzer.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
PYTHON = str(VENV_PYTHON) if VENV_PYTHON.is_file() else sys.executable

# Ensure tools/ and repo root are in python path
for p in (str(ROOT), str(TOOLS)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _run_tool_command(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    """Execute a python tool command in the project environment."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{ROOT}:{TOOLS}:{env.get('PYTHONPATH', '')}".rstrip(":")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out after {timeout} seconds: {' '.join(cmd)}"
    except Exception as e:
        return 1, f"Failed to run command {' '.join(cmd)}: {e}"


# ==============================================================================
# Tool Implementations
# ==============================================================================

def tool_doctor(_args: dict[str, Any]) -> str:
    """Run doctor.py checks."""
    rc, out = _run_tool_command([PYTHON, str(TOOLS / "doctor.py")], timeout=30)
    return out.strip()


def tool_check_rules(args: dict[str, Any]) -> str:
    """Validate Domato grammars and check for code hazards."""
    samples = int(args.get("samples", 10))
    keep = bool(args.get("keep", False))
    cmd = [PYTHON, str(TOOLS / "check_rules.py"), "--samples", str(samples)]
    if keep:
        cmd.append("--keep")
    rc, out = _run_tool_command(cmd, timeout=60)
    return out.strip()


def tool_generate_case(args: dict[str, Any]) -> str:
    """Generate a sample testcase using DomatoAdapter."""
    count = min(max(int(args.get("count", 1)), 1), 5)
    max_chars = int(args.get("max_chars", 15000))
    save_to = args.get("save_to")

    try:
        from grz_domato import DomatoAdapter
        from sapphire import ServerMap

        adapter = DomatoAdapter()
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            adapter.setup(None, ServerMap())
        finally:
            sys.stdout = old_stdout

        class MockTestCase:
            def __init__(self):
                self.entry_point = "case.html"
                self.bytes_data = b""

            def add_from_bytes(self, b: bytes, _entry: str, required: bool = True):
                self.bytes_data = b

        cases = []
        for i in range(count):
            tc = MockTestCase()
            adapter.generate(tc, ServerMap())
            cases.append(tc.bytes_data.decode("utf-8", errors="replace"))

        output_summary = [f"Generated {count} testcase(s) successfully."]
        if save_to:
            save_path = Path(save_to)
            if not save_path.is_absolute():
                save_path = ROOT / save_path
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(cases[0], encoding="utf-8")
            output_summary.append(f"Saved primary case to: {save_path} ({len(cases[0])} bytes)")

        output_summary.append(f"Primary testcase length: {len(cases[0])} bytes.")
        snippet = cases[0][:max_chars]
        if len(cases[0]) > max_chars:
            snippet += f"\n... [truncated, {len(cases[0]) - max_chars} more characters] ..."
        output_summary.append("\n=== Testcase Content Preview ===\n" + snippet)
        return "\n".join(output_summary)

    except Exception as e:
        return f"Error generating testcase: {e}"


def tool_check_wgsl(args: dict[str, Any]) -> str:
    """Validate WGSL shaders."""
    module = args.get("module")
    cmd = [PYTHON, str(TOOLS / "check_wgsl.py")]
    rc, out = _run_tool_command(cmd, timeout=45)
    if module:
        lines = [line for line in out.splitlines() if module in line or "modules" in line]
        return "\n".join(lines) if lines else f"Module '{module}' not found in output:\n{out}"
    return out.strip()


def tool_audit_rules(args: dict[str, Any]) -> str:
    """Audit rules against WebIDL inventory."""
    cmd = [PYTHON, str(TOOLS / "audit_rules.py")]
    if args.get("show_blocked"):
        cmd.append("--show-blocked")
    if args.get("target"):
        cmd.extend(["--target", str(args["target"])])
    if args.get("name"):
        cmd.extend(["--name", str(args["name"])])
    if args.get("top"):
        cmd.extend(["--top", str(args["top"])])
    rc, out = _run_tool_command(cmd, timeout=60)
    return out.strip()


def tool_get_queue(args: dict[str, Any]) -> str:
    """Inspect results/audit/QUEUE.md."""
    queue_file = ROOT / "results" / "audit" / "QUEUE.md"
    if not queue_file.is_file():
        return f"Queue file not found at {queue_file}. Run audit_rules first."

    content = queue_file.read_text(encoding="utf-8", errors="replace")
    filter_name = (args.get("name") or "").lower()
    top = int(args.get("top", 10))
    include_notes = bool(args.get("include_notes", True))

    blocks = re.split(r"^##\s+", content, flags=re.M)
    header = blocks[0].strip()
    entries = blocks[1:]

    matching = []
    for entry in entries:
        title = entry.splitlines()[0]
        if filter_name and filter_name not in title.lower():
            continue
        if not include_notes and "- NOTE:" in entry:
            continue
        matching.append(entry.strip())
        if len(matching) >= top:
            break

    res = [f"### Queue Summary (matching {len(matching)} / {len(entries)} entries)\n"]
    res.append(header)
    res.append("\n" + "=" * 60 + "\n")
    for m in matching:
        res.append("## " + m + "\n")
    return "\n".join(res)


def tool_show_idl(args: dict[str, Any]) -> str:
    """Inspect WebIDL definition."""
    name = args.get("name")
    if not name:
        return "Error: 'name' parameter is required (e.g. 'CanvasRenderingContext2D')"
    cmd = [PYTHON, str(TOOLS / "idl_show.py"), str(name)]
    rc, out = _run_tool_command(cmd, timeout=15)
    return out.strip()


def tool_wpt_grep(args: dict[str, Any]) -> str:
    """Grep WPT for real-world API usage patterns."""
    query = args.get("query")
    if not query:
        return "Error: 'query' parameter is required"
    max_res = int(args.get("max_results", 10))
    cmd = [PYTHON, str(TOOLS / "wpt_grep.py"), str(query), "-n", str(max_res)]
    rc, out = _run_tool_command(cmd, timeout=30)
    return out.strip()


def tool_check_reads(args: dict[str, Any]) -> str:
    """Evaluate JavaScript expressions in Firefox."""
    exprs = args.get("expressions")
    if not exprs:
        return "Error: 'expressions' array is required"
    timeout = int(args.get("timeout", 20))

    if isinstance(exprs, str):
        try:
            exprs = json.loads(exprs)
        except Exception:
            exprs = [exprs]

    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(exprs, f)
        tmp_name = f.name

    try:
        cmd = [PYTHON, str(TOOLS / "check_reads.py"), "--timeout", str(timeout), "--headless", tmp_name]
        rc, out = _run_tool_command(cmd, timeout=timeout + 15)
        return out.strip()
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def tool_scan_cases(args: dict[str, Any]) -> str:
    """Generate and scan test cases inside Firefox."""
    samples = min(max(int(args.get("samples", 3)), 1), 10)
    case_timeout = int(args.get("case_timeout", 30))
    cmd = [
        PYTHON,
        str(TOOLS / "scan_cases.py"),
        "--samples",
        str(samples),
        "--case-timeout",
        str(case_timeout),
    ]
    env = os.environ.copy()
    env["MOZ_HEADLESS"] = "1"
    rc, out = _run_tool_command(cmd, timeout=(case_timeout * samples) + 30)
    return out.strip()


def tool_fuzz_status(_args: dict[str, Any]) -> str:
    """Inspect results directory for crashes, reproducers, and sessions."""
    results_dir = ROOT / "results"
    if not results_dir.is_dir():
        return "results/ directory does not exist yet."

    files = list(results_dir.glob("**/*"))
    html_cases = [f for f in files if f.suffix == ".html"]
    log_files = [f for f in files if f.suffix == ".log"]

    lines = [
        f"Fuzzing workspace: {results_dir}",
        f"Total items in results/: {len(files)}",
        f"Saved HTML testcases/reproducers: {len(html_cases)}",
        f"Log files: {len(log_files)}",
    ]
    if html_cases:
        lines.append("\nRecent testcases:")
        for c in sorted(html_cases, key=lambda p: p.stat().st_mtime, reverse=True)[:10]:
            lines.append(f"  - {c.relative_to(results_dir)} ({c.stat().st_size} bytes)")
    if log_files:
        lines.append("\nRecent logs:")
        for lg in sorted(log_files, key=lambda p: p.stat().st_mtime, reverse=True)[:5]:
            lines.append(f"  - {lg.relative_to(results_dir)} ({lg.stat().st_size} bytes)")
    return "\n".join(lines)


# ==============================================================================
# MCP Definitions
# ==============================================================================

TOOLS_REGISTRY: dict[str, dict[str, Any]] = {
    "doctor": {
        "description": "Run MozillaFuzzer environment checks: verify Firefox source, binary, StaticPrefList, Domato grammars, and imports.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "handler": tool_doctor,
    },
    "check_rules": {
        "description": "Validate Domato CFG grammars: parse rules, resolve symbols, generate sample cases, and detect syntax hazards (# outside string, leaked p=, doubled quotes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "samples": {
                    "type": "integer",
                    "description": "Number of sample test cases to generate (default: 10)",
                    "default": 10,
                },
                "keep": {
                    "type": "boolean",
                    "description": "Whether to keep generated test cases in results/check",
                    "default": False,
                },
            },
        },
        "handler": tool_check_rules,
    },
    "generate_case": {
        "description": "Generate one or more fresh fuzzing testcases from the Domato grammars and return HTML content or save to file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "description": "Number of testcases to generate (1-5, default: 1)",
                    "default": 1,
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum characters of generated HTML to return in the response preview (default: 15000)",
                    "default": 15000,
                },
                "save_to": {
                    "type": "string",
                    "description": "Optional file path (relative to repo or absolute) to save the generated testcase",
                },
            },
        },
        "handler": tool_generate_case,
    },
    "check_wgsl": {
        "description": "Validate WGSL shader files against Firefox WebGPU / naga pipeline compiler.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Optional specific shader name to filter (e.g. 'basic-render.wgsl')",
                },
            },
        },
        "handler": tool_check_wgsl,
    },
    "audit_rules": {
        "description": "Audit Domato rules against Firefox WebIDL inventory and StaticPrefList.yaml. Updates results/audit/QUEUE.md and coverage.json.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "show_blocked": {
                    "type": "boolean",
                    "description": "List interface-level gates as well",
                    "default": False,
                },
                "target": {
                    "type": "string",
                    "description": "Filter by destination rules file (e.g. 'webapis.txt', 'rules_webgl.txt')",
                },
                "name": {
                    "type": "string",
                    "description": "Filter by interface name substring",
                },
                "top": {
                    "type": "integer",
                    "description": "Number of interfaces to list in queue output (default: 15)",
                },
            },
        },
        "handler": tool_audit_rules,
    },
    "get_queue": {
        "description": "Read and search the Domato rules work queue (results/audit/QUEUE.md).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Filter for a specific interface or API name",
                },
                "top": {
                    "type": "integer",
                    "description": "Maximum queue entries to display (default: 10)",
                    "default": 10,
                },
                "include_notes": {
                    "type": "boolean",
                    "description": "Whether to include adjudicated refusal notes (default: true)",
                    "default": True,
                },
            },
        },
        "handler": tool_get_queue,
    },
    "show_idl": {
        "description": "Inspect WebIDL definitions, methods, attributes, and comments for an interface from Firefox dom/webidl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Interface or type name (e.g. 'TextEncoder', 'HTMLCanvasElement')",
                },
            },
            "required": ["name"],
        },
        "handler": tool_show_idl,
    },
    "wpt_grep": {
        "description": "Search Web Platform Tests (WPT) for JavaScript usage patterns of a given API.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Interface or method name to search in WPT",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum search hits to return (default: 10)",
                    "default": 10,
                },
            },
            "required": ["query"],
        },
        "handler": tool_wpt_grep,
    },
    "check_reads": {
        "description": "Execute JavaScript expressions inside Firefox content process to verify if an API getter/method runs or throws.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expressions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of JavaScript expressions to evaluate in Firefox",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Browser timeout in seconds (default: 20)",
                    "default": 20,
                },
            },
            "required": ["expressions"],
        },
        "handler": tool_check_reads,
    },
    "scan_cases": {
        "description": "Generate test cases and run them in headless Firefox to catch syntax errors and systematic runtime exceptions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "samples": {
                    "type": "integer",
                    "description": "Number of test cases to generate and scan (1-10, default: 3)",
                    "default": 3,
                },
                "case_timeout": {
                    "type": "integer",
                    "description": "Timeout per test case in seconds (default: 30)",
                    "default": 30,
                },
            },
        },
        "handler": tool_scan_cases,
    },
    "fuzz_status": {
        "description": "Report recent fuzzing activity, crashes, and reproducers saved in results/.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "handler": tool_fuzz_status,
    },
}

RESOURCES_REGISTRY = [
    {
        "uri": "fuzzer://queue",
        "name": "Rules Work Queue",
        "description": "Current WebIDL rules work queue with coverage stats and adjudicated notes",
        "mimeType": "text/markdown",
        "path": ROOT / "results" / "audit" / "QUEUE.md",
    },
    {
        "uri": "fuzzer://agents",
        "name": "Agents Guide",
        "description": "Guidelines, failure modes, line budgeting, and rules syntax rules (AGENTS.md)",
        "mimeType": "text/markdown",
        "path": ROOT / "AGENTS.md",
    },
    {
        "uri": "fuzzer://readme",
        "name": "Project README",
        "description": "MozillaFuzzer documentation and quick start",
        "mimeType": "text/markdown",
        "path": ROOT / "README.md",
    },
    {
        "uri": "fuzzer://coverage",
        "name": "Coverage Details",
        "description": "JSON report of WebIDL interfaces and member coverage status",
        "mimeType": "application/json",
        "path": ROOT / "results" / "audit" / "coverage.json",
    },
]

PROMPTS_REGISTRY = [
    {
        "name": "implement-queue-item",
        "description": "Step-by-step guidance to implement Domato rules for a missing WebIDL interface from QUEUE.md.",
        "arguments": [
            {
                "name": "interface_name",
                "description": "Name of the interface to implement (e.g. 'CompressionStream')",
                "required": True,
            }
        ],
        "template": (
            "You are working on the Mozilla Firefox Domato fuzzer (grz_domato).\n"
            "Goal: Add coverage for interface '{interface_name}'.\n\n"
            "Workflow according to AGENTS.md:\n"
            "1. Inspect WebIDL definition: call MCP tool `show_idl(name='{interface_name}')`\n"
            "2. Search realistic usage: call MCP tool `wpt_grep(query='{interface_name}')`\n"
            "3. Verify callability in Firefox: call MCP tool `check_reads(expressions=['...'])`\n"
            "4. Route correctly:\n"
            "   - GPU* -> domato/rules/webgpu.txt\n"
            "   - WebGL* -> domato/rules/webgl.txt\n"
            "   - Canvas/Path2D -> domato/rules/canvas.txt\n"
            "   - CSS -> domato/rules/css.txt\n"
            "   - Markup -> domato/rules/html.txt\n"
            "   - Everything else -> domato/rules/webapis.txt or stateful.txt\n"
            "5. Respect AGENTS.md syntax:\n"
            "   - Synchronous only inside try/catch; NEVER `await`.\n"
            "   - NEVER `const`/`let` in statement lines; use `var`.\n"
            "   - `#` is comment marker; write `<hash>` in CSS / string literals.\n"
            "   - `<new Type> = ...` on LHS; never on RHS of its own creator.\n"
            "6. Verify with `check_rules(samples=25)`.\n"
        ),
    },
    {
        "name": "diagnose-scan-failure",
        "description": "Analyze errors found by scan_cases and produce the appropriate rule fix.",
        "arguments": [
            {
                "name": "error_log",
                "description": "The error output snippet from scan_cases",
                "required": True,
            }
        ],
        "template": (
            "Analyze this error report from `scan_cases`:\n\n{error_log}\n\n"
            "Follow AGENTS.md rules:\n"
            "- A throwing creator poisons variable registration and cascades failures down.\n"
            "- If an API requires user activation or permissions, record a NOTE in tools/audit_rules.py.\n"
            "- If a method throws due to state preconditions (e.g. RTCDataChannel not open), check whether\n"
            "  it belongs in stateful.txt with proper sequencing or is an accepted systematic throw.\n"
            "- Ensure no bare `#` or doubled quotes appear in generated statements.\n"
        ),
    },
]


# ==============================================================================
# JSON-RPC / MCP Server Loop
# ==============================================================================

class MCPServer:
    def __init__(self, in_stream: io.TextIOBase, out_stream: io.TextIOBase):
        self.in_stream = in_stream
        self.out_stream = out_stream

    def send_response(self, response: dict[str, Any]) -> None:
        raw = json.dumps(response, ensure_ascii=False)
        self.out_stream.write(raw + "\n")
        self.out_stream.flush()

    def send_error(self, req_id: Any, code: int, message: str, data: Any = None) -> None:
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self.send_response({"jsonrpc": "2.0", "id": req_id, "error": err})

    def handle_request(self, req: dict[str, Any]) -> None:
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params") or {}

        # Handle notifications (no id)
        if req_id is None:
            if method == "notifications/initialized":
                # client acknowledgment, nothing to return
                return
            return

        if method == "initialize":
            self.send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "mozillafuzzer-mcp",
                        "version": "1.0.0",
                    },
                },
            })

        elif method == "ping":
            self.send_response({"jsonrpc": "2.0", "id": req_id, "result": {}})

        elif method == "tools/list":
            tools_list = []
            for name, meta in TOOLS_REGISTRY.items():
                tools_list.append({
                    "name": name,
                    "description": meta["description"],
                    "inputSchema": meta["inputSchema"],
                })
            self.send_response({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}})

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") or {}

            if tool_name not in TOOLS_REGISTRY:
                self.send_error(req_id, -32601, f"Unknown tool: '{tool_name}'")
                return

            handler: Callable[[dict[str, Any]], str] = TOOLS_REGISTRY[tool_name]["handler"]
            try:
                result_text = handler(tool_args)
                self.send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": str(result_text)}],
                        "isError": False,
                    },
                })
            except Exception as e:
                self.send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Tool error in '{tool_name}': {e}"}],
                        "isError": True,
                    },
                })

        elif method == "resources/list":
            res_list = [
                {
                    "uri": r["uri"],
                    "name": r["name"],
                    "description": r["description"],
                    "mimeType": r["mimeType"],
                }
                for r in RESOURCES_REGISTRY
            ]
            self.send_response({"jsonrpc": "2.0", "id": req_id, "result": {"resources": res_list}})

        elif method == "resources/read":
            uri = params.get("uri")
            found = None
            for r in RESOURCES_REGISTRY:
                if r["uri"] == uri:
                    found = r
                    break
            if not found:
                self.send_error(req_id, -32602, f"Resource not found: {uri}")
                return

            path = found["path"]
            if not path.is_file():
                content = f"[File {path.name} not found. Run relevant tool first.]"
            else:
                content = path.read_text(encoding="utf-8", errors="replace")

            self.send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": found["mimeType"],
                            "text": content,
                        }
                    ]
                },
            })

        elif method == "prompts/list":
            p_list = [
                {
                    "name": p["name"],
                    "description": p["description"],
                    "arguments": p.get("arguments", []),
                }
                for p in PROMPTS_REGISTRY
            ]
            self.send_response({"jsonrpc": "2.0", "id": req_id, "result": {"prompts": p_list}})

        elif method == "prompts/get":
            p_name = params.get("name")
            p_args = params.get("arguments") or {}
            found = None
            for p in PROMPTS_REGISTRY:
                if p["name"] == p_name:
                    found = p
                    break
            if not found:
                self.send_error(req_id, -32601, f"Unknown prompt: {p_name}")
                return

            template = found["template"]
            try:
                formatted = template.format(**p_args)
            except KeyError as e:
                self.send_error(req_id, -32602, f"Missing required prompt argument: {e}")
                return

            self.send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": found["description"],
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": formatted,
                            },
                        }
                    ],
                },
            })

        else:
            self.send_error(req_id, -32601, f"Method not found: {method}")

    def run(self) -> None:
        """Read newline-delimited JSON-RPC messages from stdin."""
        while True:
            line = self.in_stream.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as e:
                self.send_error(None, -32700, f"Parse error: {e}")
                continue
            self.handle_request(req)


# ==============================================================================
# Self-Test Mode
# ==============================================================================

def run_self_test() -> int:
    """Run an in-memory simulation of client-server MCP interaction."""
    print("Testing MCP server JSON-RPC protocol...")
    test_in = io.StringIO()
    test_out = io.StringIO()

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "test"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list"},
        {"jsonrpc": "2.0", "id": 5, "method": "prompts/list"},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "doctor"}},
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "show_idl", "arguments": {"name": "TextEncoder"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "get_queue", "arguments": {"top": 3}},
        },
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "resources/read",
            "params": {"uri": "fuzzer://agents"},
        },
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "prompts/get",
            "params": {"name": "implement-queue-item", "arguments": {"interface_name": "TestInterface"}},
        },
    ]

    for req in requests:
        test_in.write(json.dumps(req) + "\n")
    test_in.seek(0)

    server = MCPServer(test_in, test_out)
    server.run()

    responses = [json.loads(line) for line in test_out.getvalue().splitlines() if line.strip()]
    print(f"Received {len(responses)} JSON-RPC responses (expected 10 - notifications have no response).")
    assert len(responses) == 10, f"Expected 10 responses, got {len(responses)}"

    # Check initialize
    init_res = responses[0]
    assert init_res["id"] == 1
    assert init_res["result"]["serverInfo"]["name"] == "mozillafuzzer-mcp"
    print("  [OK] initialize")

    # Check ping
    ping_res = responses[1]
    assert ping_res["id"] == 2
    print("  [OK] ping")

    # Check tools/list
    tools_res = responses[2]
    assert tools_res["id"] == 3
    tool_names = [t["name"] for t in tools_res["result"]["tools"]]
    print(f"  [OK] tools/list ({len(tool_names)} tools registered: {', '.join(tool_names)})")

    # Check resources/list
    res_res = responses[3]
    assert res_res["id"] == 4
    uris = [r["uri"] for r in res_res["result"]["resources"]]
    print(f"  [OK] resources/list ({len(uris)} resources: {', '.join(uris)})")

    # Check prompts/list
    prompts_res = responses[4]
    assert prompts_res["id"] == 5
    print("  [OK] prompts/list")

    # Check doctor call
    doc_res = responses[5]
    assert doc_res["id"] == 6
    assert not doc_res["result"]["isError"]
    assert "doctor" in doc_res["result"]["content"][0]["text"].lower()
    print("  [OK] tools/call: doctor")

    # Check show_idl call
    idl_res = responses[6]
    assert idl_res["id"] == 7
    assert not idl_res["result"]["isError"]
    print("  [OK] tools/call: show_idl")

    # Check get_queue call
    q_res = responses[7]
    assert q_res["id"] == 8
    assert not q_res["result"]["isError"]
    assert "queue" in q_res["result"]["content"][0]["text"].lower()
    print("  [OK] tools/call: get_queue")

    # Check resources/read call
    r_res = responses[8]
    assert r_res["id"] == 9
    assert not r_res.get("error")
    assert "Domato" in r_res["result"]["contents"][0]["text"]
    print("  [OK] resources/read: fuzzer://agents")

    # Check prompts/get call
    p_res = responses[9]
    assert p_res["id"] == 10
    assert not p_res.get("error")
    assert "TestInterface" in p_res["result"]["messages"][0]["content"]["text"]
    print("  [OK] prompts/get: implement-queue-item")

    print("\nAll MCP server self-tests PASSED successfully!")
    return 0


def main():
    if "--test" in sys.argv:
        sys.exit(run_self_test())

    server = MCPServer(sys.stdin, sys.stdout)
    server.run()


if __name__ == "__main__":
    main()
