# Working on the Domato rules

This repo is a Grizzly adapter (`grz_domato`) around Google's Domato generator. The
fuzzable surface lives in `domato/**.txt`: context-free grammar rules that produce
HTML, CSS, JS, Canvas 2D, WebGL and WebGPU code. Growing that surface means editing
those rule files against the real Firefox WebIDL, and nothing else.

Everything below is a constraint that has already cost someone a session. Read it
before opening a rules file.

## Layout

| file | owns | note |
|---|---|---|
| `domato/rules/html.txt` | element/tag structure | includes `common`, `attributevalues`, `tagattributes`, `svg*`, `mathml*` |
| `domato/rules/js.txt` | DOM/JS statements (`!begin lines`) | includes `common`, `jshelpers`, `wasm`, `webapis`; sets the `!lineguard` |
| `domato/rules/webapis.txt` | Web API method calls, constructors, event handlers | the default destination for a new interface |
| `domato/rules/jshelpers.txt` | value-producing helpers | ends in `!begin helperlines` |
| `domato/rules/tagattributes.txt` | per-element attribute values | `*Element` interfaces route here |
| `domato/rules/css.txt` + `cssproperties.txt` | CSS grammar | `rules` is a live entry point |
| `domato/rules/svg.txt`, `mathml.txt` (+ `*attrvalues.txt`) | SVG / MathML | included by `html.txt` |
| `domato/canvas/canvas.txt` | Canvas 2D statements | own grammar, own `!lineguard`, `!varformat fuzzvar%05d` |
| `domato/webgl/webgl.txt` | WebGL 1/2 statements | same, separate grammar |
| `domato/webgpu/webgpu.txt` + `webgpuhelpers.txt` | WebGPU statements | needs `<entrypoint>`/`<BindInt>` derived from the WGSL corpus |

`grz_domato/template.html` is the harness the generated code is dropped into. It
declares `freememory`, `GetVariable`, `SetVariable`, `fuzzervars`, and one guarded
`<script>` block per API. A rule that needs a variable the template does not create
is a template change, not a rules change.

## The loop

```
py -3.14 tools/extract_idl.py            # Firefox WebIDL -> results/audit/idl_inventory.json
py -3.14 tools/audit_rules.py --show-blocked   # inventory vs reachable grammar text -> QUEUE.md
# pick ONE interface from results/audit/QUEUE.md, add rules for it
py -3.14 tools/check_rules.py --samples 25     # parse + resolve + generate; must exit 0
py -3.14 tools/probe_apis.py                   # browser answers "is this binding exposed?"; run it yourself
```

`extract_idl.py` reads `C:\mozilla-source\firefox\dom\webidl` (`--source` to move it).
It folds `interface mixin` members into the interfaces that include them, dedupes
overloads by member name, and keeps every extended attribute.

## Reading the queue, honestly

The audit matches the Firefox IDL against rule text. A member counts as emitted
only where a property can syntactically appear - `X.name`, `X["name"]`, or a direct
`name(...)` call. Bare-identifier matching would report coverage from CSS units and
ARIA roles, so the buckets are read like this:

- **reachable** - the name appears in member position in a rule the generator can
  actually select. This is coverage.
- **word only** - the word is in live rules, but never as a property of anything:
  `cm` and `Hz` are CSS units, `alert` is an ARIA role. Not coverage, and not
  necessarily work either - go look at what the IDL member means before adding it.
- **parsed but unreachable** - the name is in member position inside rules the
  generator cannot select (below a `!begin helperlines` marker, or only reachable
  from a symbol no entry point expands). Dead text.
- **missing** - a content-reachable member nothing emits. This is the work queue.
- **needs probe** - the member carries `[Func=...]`. Its gate is a C++ predicate, so
  the audit cannot evaluate it. Verify with `tools/probe_apis.py` *before* writing
  rules; a `[Func]` that is false in this build means the property does not exist and
  every generated call throws.
- Coverage is judged across all six grammars at once, so a member emitted only by the
  WebGL grammar still counts as covered for a WebGL interface. The audit does not
  prove an API is reached *often*, and it never proves the call does anything.

Numbers from one run of this pipeline are not comparable to another run with a
different grammar scope, and never to a figure quoted from a different methodology.
Quote the command that produced the number or quote nothing. Never state coverage
from the audit alone: `check_rules.py` (it generates) and `probe_apis.py` (the browser
confirms) are what produce a claim.

## Current state (last verified run)

`py -3.14 tools/audit_rules.py` on the 846-file `dom/webidl` tree, live grammar scope:
772 types considered, 651 not gated off at interface level, 48 interfaces with at least
one missing member; 1988 members reachable, 109 missing, 73 word-only, 52 awaiting a
probe, 2 parsed-but-unreachable. Missing by destination file: `webapis.txt` 75,
`webgl/webgl.txt` 31, `css.txt` 3. `py -3.14 tools/check_rules.py --samples 25` exits 0
(6 grammars, 41516 rules).

Those 109 are not 109 pieces of work. The per-destination work orders under
`results/audit/` split them by probe verdict: 9 `not-exposed` (browser says the binding
is absent - not a gap), 1 `present` (`Window.confirm`, a blocking dialog, refused by
"Never add"), and 99 `no receiver`. The last group is the honest caveat: their verdict
comes from a `probe.json` written *before* `tools/probe_apis.py` grew `getExtension()`
support and the `unprobeable` list, so the probe had no page object to read them on -
WebGL extension objects, worker-only interfaces, and a few Firefox-only services.
`no receiver` means *unknown*, not absent. The next step for them is a fresh
`py -3.14 tools/probe_apis.py` run and a re-audit with it, not rules written blind.

Re-run everything - these go stale the moment a rules file changes.

Known environment facts, verified by `tools/probe_apis.py` on this build with Grizzly's
prefs: WebGPU runs (adapter, device, shader module, command encoder all come back);
Canvas 2D runs; **WebGL2 runs and WebGL1 does not** - `getContext
('webgl2')` returns a `WebGL2RenderingContext` while `getContext('webgl')` and
`getContext('experimental-webgl')` return `null`. Ask for `webgl2` first, always: a probe
that only asks for the WebGL1 names reports the whole API as dead. WebGL extension objects
(`EXT_*`, `OES_*`, `ANGLE_*`, `WEBGL_*`) have no window global - the IDL name is the string
passed to `getExtension()` - so their members can only be probed through a context; the
probe does that since the getExtension support was added. The `results/audit/probe.json`
that ships in the working tree predates both of those fixes, so nothing in it is a
verdict about WebGL. The WebGPU grammar can only be as
varied as `domato/webgpu/wgsl/*.wgsl` allows - entry points and binding numbers come from
those shaders - so a new WGSL corpus is worth more there than new rules.


## Routing an interface

1. `GPU*` -> `webgpu/webgpu.txt`; `WebGL*`, `EXT_*`, `OES_*`, `WEBGL_*`, `ANGLE_*` ->
   `webgl/webgl.txt`; `CanvasRenderingContext2D`, `OffscreenCanvas*`, `Path2D`,
   `ImageData`, `ImageBitmap`, ... -> `canvas/canvas.txt`.
2. `SVG*` -> `svg.txt`; `MML*` -> `mathml.txt`; CSS-ish -> `css.txt`; `*Element` ->
   `tagattributes.txt`.
3. everything else -> `webapis.txt`.

Route by what the destination grammar can *say*, not by the interface name. `svg.txt` is
included by `html.txt`, whose entry point emits markup, so it has no statement slot and no
`<SVGPathElement>` variable - those are produced in `jshelpers.txt:2605` and consumed by
`js.txt`. SVG DOM methods (`getPathData`, `getPathSegmentAtLength`, ...) belong in the
`#SVGPathElement` block of `js.txt` with the rest of that receiver's calls. The audit
routes a work order by name, so its file header is advice about where the name *might*
go; check that the grammar you write into owns the receiver.

The graphics grammars are separate `Grammar` objects on purpose. Do not merge them
into `rules/`: one object would pool every `<line>` together, so 40k DOM lines would
dilute WebGPU into never being emitted, and the three `!lineguard`/`!varformat`
declarations would fight over one object.

## Rules syntax that bites

- `!begin lines` selects real statements; `!begin helperlines` selects values only.
  A rule added below a `!begin helperlines` marker will parse, will look right in the
  file, and will never be chosen as a statement.
- Directives (`!lineguard`, `!varformat`, `!max_recursion`) belong to the **root**
  file. `webapis.txt` is included by `js.txt` and deliberately declares none; a second
  `!lineguard` in an included file silently replaces the first for the whole grammar.
- `rules/js.txt` lines go inside a **synchronous** function guarded by
  `try { <line> } catch(e) { }`. `await` in a `js.txt`/`webapis.txt` line is a syntax
  error, and a syntax error kills the entire `<script>` - not one line, the whole
  case's JS. Async work belongs in `webgpu/webgpu.txt`, whose block is `async`.
- Throw only what the guard can swallow and only where a bad argument is the point.
  A rule that reliably throws does not crash the browser, it just stops that object
  being used again by later lines, so the interesting part of the API never runs.
- Produce typed variables with `<new Type> = ...` so other rules can reuse the object;
  a call that returns a value into nothing is wasted. `fuzzervars` is the cross-call
  pool for `js.txt` only - inside the canvas/webgl/webgpu blocks, reuse relies on
  Domato's own variable context.
- `!extends Child Parent` is how inherited members become reachable; the audit folds
  WebIDL inheritance for you, but the grammar needs the declaration.
- Weight rare-but-interesting *value* rules with `p=`; without it every rule for a symbol
  is picked uniformly. It does nothing for a statement: `<line>` rules are drawn with
  `random.choice(self._all_nonhelper_lines)` (grammar.py:301, filled at grammar.py:1014),
  which ignores `p=` entirely. To make an API appear more often, give it more statement
  rules.
- Never write `const` or `let` in a statement line. Lines are drawn *with replacement*
  from the pool, so one line can be emitted twice in the same function, and a repeated
  `const x` is a SyntaxError that kills the whole `<script>` - not one line. `var`
  redeclaration is legal, and hoisting turns a use-before-creation into `undefined`,
  which a nullable WebIDL argument reads as `null`. Four `const info*/ifo*` lines did
  exactly that to the WebGL block until they became `var`.
- Adding rules does not lengthen a case. Line budgets are fixed
  (`_N_MAIN_LINES`, `_N_CANVAS_LINES`, `_N_WEBGL_LINES`, `_N_WEBGPU_LINES` in
  `grz_domato/__init__.py`), so a bigger grammar means each API appears *less often*
  per case. That is the trade you are making, and it is why one domain per commit
  matters.
- Text is not a value: `<string>`, `<fuzzint>`, `<float min= max=>`, `<hex>` are
  built-in tags; inventing a tag name produces `No creators for type X` and the branch
  dies. `check_rules.py` fails on this precisely because Domato only prints it. Two traps
  in that set: `<hex>` is a *single* hex digit, so a colour is six of them and there is no
  `<hexdigit>`; and `#` is a comment marker cut from every rule line before parsing
  (`_remove_comments`, grammar.py:776), so `filter: url(#foo)` silently became the rule
  text `'filter: url('`. Write `<hash>` instead - seven rules across `common.txt`,
  `css.txt` and `mathmlattrvalues.txt` were truncated that way.
- `<hash>` belongs *inside a string literal*. In expression position it generates a bare
  `#`, which is a SyntaxError that takes the whole `<script>` with it. `check_rules.py`
  now fails on any `#` outside a string literal in a generated script body
  (`js_hazards`), because three `webapis.txt` rules did exactly that.
- HTML inside a JS string is still symbol syntax: `"<b>domato</b>"` makes Domato look for
  rules `<b>` and `<i>` and it fails with `No creators for type b`. Write
  `<lt>`/`<gt>` (`_constant_types`, grammar.py:121) for the angles.

## Never add

- `[SystemPrincipal]`, `[ChromeOnly]`, `[MozSystem]` members - not exposed to content,
  the call is always a TypeError. Examples in this tree: `Window.getInterface`,
  `Window.synthesizeMouseEvent`, `Document.createXULElement`, `Document.nodeFromPoint`.
- Members behind a `[Pref]` that is off in `StaticPrefList.yaml` *and* not turned on by
  Grizzly's `browser-fuzzing.yml`. Only one of the two being on is enough.
- Anything `[Func]`-gated that `probe_apis.py` has not confirmed present.
- `FuzzingFunctions.crash` / `FuzzingFunctions.killGPUProcess` - they end the session
  rather than fuzz it (the rest of that namespace is fair game and is queued).
- Navigator dialogs that block (`alert`/`confirm`/`prompt` wired to a callback that
  never fires), and real network calls to hosts outside `server_map` - test cases are
  served with relative URLs for a reason.
- Anything that writes to disk outside the profile or opens a window - the harness
  cannot close it and the session hangs until the runtime budget expires.

## Definition of done for a rules commit

1. One domain or interface per commit; the message says which queue entry it closes.
2. `py -3.14 tools/check_rules.py --samples 25` exits 0. Anything less than "every
   grammar parses, resolves and generates" means the rules are not in the generated
   code.
3. `py -3.14 tools/audit_rules.py` re-run shows the member in `reachable`, not in
   `missing` and not in `parsed but unreachable`.
4. If the members were `[Func]`-gated, a `probe_apis.py` record shows `present:*`.
5. Nothing under `results/` is committed (it is gitignored, and it is regenerated).

After changing `grz_domato/` (not rules), a running `fuzz.bat` session keeps the old
adapter code - restart it. Changing only `domato/**.txt` also needs a restart, because
the grammars are parsed once in `setup()`.
