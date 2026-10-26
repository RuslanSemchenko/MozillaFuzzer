# MozillaFuzzer (Grizzly + Domato for Firefox)

A specialized DOM & WebIDL fuzzing environment tailored for **Mozilla Firefox**, integrating Mozilla's [Grizzly](https://github.com/MozillaSecurity/grizzly) orchestration framework with an adapted [Domato](https://github.com/googleprojectzero/domato) grammar generation engine.

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

## Installation

Install `grz-domato` in editable mode:

```bash
pip install -e .
```

Verify that the Grizzly adapter is recognized:

```bash
grizzly --list-adapters
```

You should see `domato` listed among available adapters.

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

When pulling or building a new Firefox revision:

```bash
# 1. Extract updated WebIDL inventory
python3 tools/extract_idl.py --source /path/to/firefox

# 2. Inspect new APIs added in this revision
python3 tools/diff_inventory.py

# 3. Check and probe API exposure
python3 tools/audit_rules.py
python3 tools/probe_apis.py

# 4. Regenerate rules and verify
python3 tools/gen_webidl_rules.py
python3 tools/check_rules.py --samples 25
```

## License

- Adapter code (`grz_domato/`): Mozilla Public License 2.0 (MPL-2.0)
- Domato generator (`domato/`): Apache License 2.0
