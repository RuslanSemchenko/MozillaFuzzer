# MozillaFuzzer (Grizzly + Domato for Firefox)

A specialized DOM & WebIDL fuzzing environment tailored for **Mozilla Firefox**, integrating Mozilla's [Grizzly](https://github.com/MozillaSecurity/grizzly) orchestration framework with an adapted [Domato](https://github.com/googleprojectzero/domato) grammar generation engine.

> **For rules work (WebIDL coverage, audits, probes):** see [`AGENTS.md`](AGENTS.md) — it contains the full, enforced workflow and gotchas for this repo.

## Overview

- **`grz_domato/`**: In-process Grizzly adapter (`DomatoAdapter`) driving test case generation with isolated line budgets for DOM/JS, Canvas 2D, WebGL 1/2, and WebGPU.
- **`domato/rules/`**: Context-free grammar rules built against real Firefox WebIDL definitions:
  - `webapis.txt`: Generated WebIDL interfaces, method calls, constructors, getters, setters.
  - `stateful.txt`: Hand-crafted multi-step scenarios (IndexedDB, Streams, WebCrypto, OPFS, Workers, Detached iframes).
  - `wasm.txt`: WebAssembly JS API, module corpus, SIMD, atomics, and parser fuzzing.
  - `canvas.txt`, `webgl.txt`, `webgpu.txt`: Separate graphics grammars and execution contexts.
  - `wgsl/*.wgsl`: WebGPU WGSL shader corpus.
- **`tools/`**: Verification, audit, and generation toolchain:
  - `extract_idl.py`: Extracts Firefox WebIDL from source checkout into JSON inventory.
  - `gen_webidl_rules.py`: Programmatically generates rules directly from the IDL inventory.
  - `audit_rules.py`: Audits reachable grammar rules against IDL coverage and pref gates.
  - `probe_apis.py`: In-browser probe for `[Func]`-gated APIs and global object availability.
  - `check_rules.py`: Verifies grammar parsing, symbol resolution, and generation end-to-end.
  - `check_wgsl.py`: Validates WGSL shader compilation and pipeline creation via WebGPU.
  - `scan_cases.py`: Detects and reports lineguard exceptions swallowed by test cases.
  - `diff_inventory.py`: Computes WebIDL API deltas between Firefox Nightly updates.
- **`fuzz.sh`**: Linux runner with stress profile support (`--stress`, `--chaos`, `--zeal`, `--asan`).
- **`replay.sh` / `reduce.sh`**: Turnkey scripts for reproducing and minimizing crashes with Grizzly.

## Quick Start

1. **Clone/setup deps** (Python **3.14+**)
   ```bash
   pip install -e .
   ```

2. **Configure paths** (optional — copy example and edit)
   ```bash
   cp .env.example .env
   # set FIREFOX_SRC and FIREFOX_BIN (no machine-specific defaults in the repo)
   # a build under $FIREFOX_SRC/obj-*/dist/bin/firefox is found without .env
   ```

3. **Check environment**
   ```bash
   make doctor
   # or: python3 tools/doctor.py
   ```

4. **Start fuzzing**
   ```bash
   ./fuzz.sh        # headful/default
   ./fuzz.sh headless
   ./fuzz.sh --stress
   ```

Verify adapter:
```bash
grizzly --list-adapters  # should include "domato"
```

## Usage

### 1. Fuzzing (`fuzz.sh`)

Run with default Firefox binary:

```bash
./fuzz.sh
```

Run in headless mode (ideal for servers or background runs):

```bash
./fuzz.sh headless
```

Run with stress profiles enabled:

```bash
# Chaos mode: randomizes thread scheduling, timers, hash iteration
./fuzz.sh --chaos

# Aggressive GC Zeal mode in SpiderMonkey (frequent GC triggers UAFs)
./fuzz.sh --zeal

# Full stress mode (Chaos Mode + GC Zeal)
./fuzz.sh --stress
```

Run a quick smoke-test (10 iterations):

```bash
./fuzz.sh --smoke-test
```

### 2. Reproducing Crashes (`replay.sh`)

Replay a crash testcase saved in `results/`:

```bash
./replay.sh results/testcase.html
./replay.sh results/testcase.html --repeat 10
./replay.sh results/testcase.html --rr            # Record trace with Mozilla rr
```

### 3. Testcase Reduction (`reduce.sh`)

Minimize a crash testcase down to a concise reproducer:

```bash
./reduce.sh results/testcase.html
```

### 4. Updating Grammar Rules After Firefox Upgrades

When pulling or building a new Firefox revision (see [`AGENTS.md`](AGENTS.md) for the full disciplined loop):

```bash
# 1. Extract updated WebIDL inventory
make extract  # or: python3 tools/extract_idl.py --source $FIREFOX_SRC

# 2. Inspect new APIs added in this revision
python3 tools/diff_inventory.py

# 3. Audit, probe and verify
make audit      # python3 tools/audit_rules.py --show-blocked
make probe      # python3 tools/probe_apis.py
make check-rules
make wgsl        # if WGSL changed
```

## Model Context Protocol (MCP) Server

MozillaFuzzer provides a built-in MCP server (`tools/mcp_server.py`) adhering to the [Model Context Protocol](https://modelcontextprotocol.io/) (JSON-RPC 2.0 over `stdio`). This allows AI assistants (Cursor, Claude Desktop, Antigravity, VS Code) to directly interact with the fuzzing pipeline:

```bash
make mcp        # Start the MCP server
make mcp-test   # Run JSON-RPC protocol self-tests
```

### Configuration

- **Cursor**: Automatically configured via [`.cursor/mcp.json`](.cursor/mcp.json).
- **Claude Desktop / Claude Code**: Point to `tools/mcp_server.py`:
  ```json
  {
    "mcpServers": {
      "mozillafuzzer": {
        "command": "python3",
        "args": ["/path/to/MozillaFuzzer/tools/mcp_server.py"]
      }
    }
  }
  ```

### Exposed Capabilities

- **Tools**:
  - `doctor`: Run environment diagnostics (`doctor.py`).
  - `check_rules`: Parse grammars, resolve symbols, generate samples, and check for code hazards.
  - `generate_case`: Generate a full testcase and return HTML preview or save to disk.
  - `check_wgsl`: Validate WGSL shaders via WebGPU pipeline compiler.
  - `audit_rules`: Audit Domato rules against Firefox WebIDL inventory and `StaticPrefList.yaml`.
  - `get_queue`: Search and filter the rules work queue (`QUEUE.md`).
  - `show_idl`: Inspect WebIDL interfaces and signatures from `dom/webidl`.
  - `wpt_grep`: Search Web Platform Tests for real-world JS usage of an API.
  - `check_reads`: Evaluate JS expressions inside Firefox content process.
  - `scan_cases`: Run generated cases in headless Firefox to catch syntax and runtime errors.
  - `fuzz_status`: Inspect recent crashes and reproducers in `results/`.
- **Resources**:
  - `fuzzer://queue`: Read current work queue (`QUEUE.md`).
  - `fuzzer://agents`: Read rule authoring guidelines (`AGENTS.md`).
  - `fuzzer://coverage`: Inspect detailed coverage JSON (`coverage.json`).
  - `fuzzer://readme`: Read project documentation.
- **Prompts**:
  - `implement-queue-item`: Guided workflow to implement rules for a missing interface.
  - `diagnose-scan-failure`: Guided workflow to analyze and triage runtime errors from `scan_cases`.

## Findings

- **`SpeechRecognition.start()`** (Nightly / diagnostic-assert builds): installs
  the speech model and crashes the content process at shutdown with
  `MOZ_CRASH(MozPromise::ThenValue created from 'StartImpl' destroyed without
  being either disconnected, resolved, or rejected)` (`MozillaPromise.h`).
  Reproduced from a generated case; `start` / `install` are refused in
  `DENY_MEMBERS`. This is `MOZ_DIAGNOSTIC_ASSERT` (live on Nightly), not ASan
  memory corruption — Beta/Release compile the check out. Also a microphone
  surface, so it stays denied.

## CI

GitHub Actions runs `tools/check_rules.py --samples 25` on Python 3.14 for every
push/PR (no Firefox required). Browser-backed tools (`probe_apis`, `check_reads`,
`check_wgsl`, `scan_cases`) stay local.

## License

- Adapter code (`grz_domato/`): Mozilla Public License 2.0 (MPL-2.0)
- Domato generator (`domato/`): Apache License 2.0
