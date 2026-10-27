# Working on the Domato rules

Grizzly adapter (`grz_domato`) around Domato. The fuzzable surface is
`domato/**.txt` — CFG rules for HTML/CSS/JS/Canvas/WebGL/WebGPU against real
Firefox WebIDL. Growing coverage means editing those files; nothing else.

## Layout

| file | owns |
|---|---|
| `rules/html.txt` | markup tags/attrs (includes `common`) |
| `rules/js.txt` | DOM/JS statements (`!begin lines`); includes common, helpers, webidl_values, webapis, stateful, wasm; sets `!lineguard` |
| `rules/webapis.txt` | Web API calls (from `gen_webidl_rules.py`) |
| `rules/webidl_values.txt` | WebIDL value/dictionary generators |
| `rules/stateful.txt` | multi-step scenarios (IDB, Streams, WebCrypto, OPFS, Workers, …) |
| `rules/wasm.txt` | WebAssembly API & bytecodes |
| `rules/jshelpers.txt` | value helpers; ends in `!begin helperlines` |
| `rules/css.txt` | CSS (`rules` is a live entry point) |
| `rules/canvas.txt` (+ helpers) | Canvas 2D; own `!lineguard` / `!varformat` |
| `rules/webgl.txt` (+ helpers) | WebGL 1/2; separate grammar |
| `rules/webgpu.txt` (+ helpers) | WebGPU; entry points / binds from `wgsl/*.wgsl` |
| `rules/wgsl/*.wgsl` | WGSL corpus (`domato/wgsl_grammar.py`) |

One rules directory; graphics grammars are still separate `Grammar` objects so
their `<line>` pools and directives do not merge. Includes are sibling names,
never `../rules/...`.

`grz_domato/template.html` owns harness globals (`freememory`, `GetVariable`,
`SetVariable`, `fuzzervars`, per-API scripts). A missing harness variable is a
template change. `fuzzall()` calls `freememory()` at the end (GC/CC while the
case is still attributable).

Paths: set `FIREFOX_SRC` / `FIREFOX_BIN` in `.env` (see `.env.example`). Tools
and the Makefile read that; there are no machine-specific defaults.

## The loop

```
python3 tools/extract_idl.py --source "$FIREFOX_SRC"
python3 tools/audit_rules.py --show-blocked          # -> QUEUE.md
# pick ONE interface from results/audit/QUEUE.md
python3 tools/check_rules.py --samples 25            # must exit 0
python3 tools/check_wgsl.py                          # if wgsl/ changed
python3 tools/probe_apis.py                          # [Func]/trial exposure
python3 tools/check_reads.py exprs.json              # does the expression run?
```

- Use the **built** Firefox (`obj-*/dist/bin/firefox`), not distro packages
  (Debian's has `navigator.gpu` compiled off).
- `probe_apis.py` = `name in obj` (exposure). `check_reads.py` = `eval` of the
  expression the rule will emit (callability). You need both.
- `probe_apis.py --only NAME` **rewrites the whole** `probe.json`. After any
  targeted probe, re-run the full probe before `gen_webidl_rules.py`.
- `audit_rules.py` needs `StaticPrefList.yaml` under `--source`; a bad source
  silently gates interfaces off. The audit refuses to run without that file.

## Reading the queue

Audit matches member *names* only in member position (`X.name`, `X["name"]`,
`name(`). Buckets:

- **reachable** — generator can select it. Real coverage.
- **word only** — word appears, never as a property (`cm`, ARIA `alert`). Not coverage.
- **parsed but unreachable** — under `!begin helperlines` or dead symbols.
- **missing** — content-reachable, nothing emits. Work queue (often already has a NOTE).
- **needs probe** — `[Func]` / `[Trial]`; verify with `probe_apis.py` first.

Coverage is across all six grammars. Quote the command that produced a number,
or quote nothing. Never claim coverage from the audit alone — `check_rules.py`
+ `probe_apis.py` produce a claim.

Many queue blocks are adjudicated refusals (prompts, no receiver, chrome-only,
network, WebAuthn, `FuzzingFunctions.crash`/…). Read the NOTE before writing
rules. Present ≠ obtainable (`'Geolocation' in window` can be true while
`navigator.geolocation` is undefined).

## Routing

1. `GPU*` → `webgpu.txt`; `WebGL*` / `EXT_*` / `OES_*` / … → `webgl.txt`;
   Canvas 2D / `Path2D` / `ImageData` / … → `canvas.txt`.
2. CSS → `css.txt`; SVG/MathML *markup* → `html.txt`.
3. Everything else → `webapis.txt`.

Route by what the grammar can *say*. SVG/MathML DOM methods and element
attribute *reads* are JS statements → `webapis.txt`. Do not merge graphics
grammars into one object (dilutes emission; directives fight).

## Rules syntax that bites

- `!begin lines` = statements; `!begin helperlines` = values only (never selected as lines).
- Directives belong on the **root** file (`js.txt`). A second `!lineguard` in an
  include silently replaces the first.
- `js.txt` / `webapis.txt` lines are synchronous inside `try/catch`. `await` is a
  SyntaxError that kills the whole `<script>`. Async → `webgpu.txt`.
- A reliably throwing rule does not crash the browser — it just orphans the object.
- Prefer `<new Type> = ...` so later lines can reuse. No `<Type>` on the RHS of
  its own creator (infinite recursion).
- Never `const`/`let` in a statement line (drawn with replacement → SyntaxError). Use `var`.
- `#` is a comment marker cut before parse — write `<hash>` inside string literals.
  Bare `#` in expression position is a SyntaxError for the whole script.
- `<hex>` is one digit; colours need six. `#` in CSS → `<hash>`.
- `min=`/`max=` only on built-in `<int>`… tags, **not** `<fuzzint>`.
- HTML angles inside JS strings → `<lt>`/`<gt>`, not `"<b>..."`.
- `p=` weights *value* rules; `p_sum > 1` zeroes undefined rules. Statement
  frequency comes from typed receivers (`interesting_lines` ~90%), not `p=`.
- Line budgets are fixed — more rules = each API less often per case.
- A throwing creator registers no variable; dependent rules become dead text the
  audit can still half-count. Verify with `check_reads.py` first.
- Dictionary keys are not member position for the audit — read the property back
  or leave a NOTE.
- `<DOMString>` lives only in `common.txt` and must stay quoted strings.
- Record refusals in `NOTES` (`tools/audit_rules.py`), as evaluated in-page.

## Never add

- `[SystemPrincipal]` / `[ChromeOnly]` / `[MozSystem]`.
- Prefs off in both `StaticPrefList.yaml` and Grizzly's `browser-fuzzing.yml`.
- `[Func]` members `probe_apis.py` has not confirmed present.
- `FuzzingFunctions.crash` / `killGPUProcess` / `signalIPCReady` /
  `memoryPressure` / `synthesizeKeyboardEvents` (the last kills the content
  process without automation prefs; GC belongs in `freememory()`).
- User prompts (`getUserMedia`, `alert`/`confirm`/`prompt`), off-harness
  network, disk writes, `window.open`.
- Navigation setters on `Location` (case never posts its report).

## Known defect shapes (do not rediscover)

- Throwing creator → null var → cascade of dead member rules.
- `document.createEvent` whitelist is tiny — prefer constructors.
- Callback constructors need `function(...){...}`, not `<EventHandler>` (often null).
- Pooled once-only / locked state → build a fresh receiver in the statement.
- Name collision across interfaces can fake audit coverage (e.g. `Notification.*`).
- `document.all` is falsy (`IsHTMLDDA`) — harness fallback replaces it; deny as creator.
- HTML vs SVG tag ambiguity — typing follows surrounding markup, not the tag alone.
- Accepted systematic throws: `RTCDataChannel.send` (never open), empty
  `TimeRanges`, unfinished `IDBRequest`, deliberate `window.reportError`.

## WGSL (naga on this build)

No `inverse`; `textureGather` component-first; comparison samplers need depth
textures; `atomicCompareExchangeWeak` → `.old_value`/`.exchanged`; `shared`/`snorm`
reserved; uniform arrays 16-byte strided; no texture/sampler binding arrays; max 4
storage textures; `read_write` storage only on accepted formats (`r32float` yes);
`modf`/`frexp` one-arg structs (`fract`/`whole`, `fract`/`exp`); derivatives
`dpdx`/`dpdy`/`fwidth`; sampling is fragment-only; vertex shaders: builtins only
(grammar randomizes buffer layouts); `override name : T = …` with defaults (no
`@override`); `<USVStringDoubleRecord> = {}` is intentional.

## Definition of done

1. One domain/interface per commit; message names the queue entry.
2. `python3 tools/check_rules.py --samples 25` exits 0.
3. `check_reads.py` exits 0 for new expressions.
4. Audit shows `reachable` (or a NOTE if only via dict/callback).
5. WGSL changes → `check_wgsl.py` exits 0.
6. `[Func]` → `probe.json` says `present:*`.
7. Nothing under `results/` committed.

Restart `./fuzz.sh` after changing `grz_domato/` or rules (grammars parse once in `setup()`).
