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
| `domato/webgpu/webgpu.txt` + `webgpuhelpers.txt` | WebGPU statements | needs `<computeEntryPoint>`/`<vertexEntryPoint>`/`<fragmentEntryPoint>`/`<BindInt>` derived from the WGSL corpus |

`grz_domato/template.html` is the harness the generated code is dropped into. It
declares `freememory`, `GetVariable`, `SetVariable`, `fuzzervars`, and one guarded
`<script>` block per API. A rule that needs a variable the template does not create
is a template change, not a rules change.

## The loop

```
python3 tools/extract_idl.py --source /home/ruslan/firefox    # WebIDL -> results/audit/idl_inventory.json
python3 tools/audit_rules.py --show-blocked    # inventory vs reachable grammar text -> QUEUE.md
# pick ONE interface from results/audit/QUEUE.md, add rules for it
python3 tools/check_rules.py --samples 25      # parse + resolve + generate; must exit 0
python3 tools/check_wgsl.py                    # one page, one window: does the WGSL corpus compile?
python3 tools/probe_apis.py                    # browser answers "is this binding exposed?"; run it yourself
python3 tools/check_reads.py exprs.json        # browser answers "does this expression run?"; run it yourself
```

`extract_idl.py` reads `<source>/dom/webidl` (both scripts default to
`--source /home/ruslan/firefox`). It folds `interface mixin` members into the interfaces that
include them, dedupes overloads by member name, and keeps every extended attribute.
`probe_apis.py` reads that inventory too, because whether a type is a window global decides
the difference between its members being `not-exposed` and being `unprobeable`.

`audit_rules.py` reads `modules/libpref/init/StaticPrefList.yaml` out of the same `--source`,
and a pref it cannot find counts as *off* - so an unusable `--source` does not fail, it
silently deletes work by gating whole interfaces out. That is now loud: the audit refuses to
run without the file, and an earlier run against a stale Windows default had hidden 95 types
(630 ungated, not 535) and 419 reachable members behind that mistake.

`check_wgsl.py` and `probe_apis.py` both start a Firefox of their own. Use the built
binary, not the distro package: `--firefox
/home/ruslan/firefox/obj-x86_64-pc-linux-gnu/dist/bin/firefox` (that default is already in
both scripts). The Debian `/usr/lib/firefox` is a release build with `navigator.gpu`
compiled off - a WebGPU check run against it reports "navigator.gpu is undefined",
which says nothing about the corpus.

`probe_apis.py` and `check_reads.py` answer different questions, and rules need both.
The probe asks `name in obj` and never calls a getter, which is the correct way to decide
a `[Func]` gate and no evidence at all that a rule runs. `check_reads.py` takes
`{"name": "expression"}` JSON, evaluates each expression with `eval()` in the same build
with the same Grizzly prefs, and exits 1 if any threw - that is where `new
ResizeObserverSize(...)`, `MediaStreamError`, and a `MediaSource` behind `srcObject` were
refused after the probe had called them present. Write one self-contained expression per
member, in the shape the rule will actually emit, before writing the rule.

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
- **needs probe** - the member carries `[Func=...]`, or sits on an interface that does,
  or the interface is a `[Trial]` one. Its gate is a C++ predicate or a trial token, so
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

Every figure below is from the command written next to it, run on 2026-10-23 with the
rules files in this tree. Re-run everything - they go stale the moment a rules file changes.

`python3 tools/extract_idl.py --source /home/ruslan/firefox` -> 847 files, 2225 types
(1101 interfaces), 5973 members.

`python3 tools/audit_rules.py` on that inventory: 937 types considered, 785 not gated off at
interface level (152 gated), 37 interfaces with at least one missing member. Across those 785:
5601 members reachable, 89 missing (87 -> `webapis.txt`, 2 -> `css.txt`; the other five work
orders are empty), 65 word-only, 2 parsed-but-unreachable, 241 whose only gate is a `[Func]` the
audit cannot evaluate, and 423 chrome-only / 98 pref-off excluded before queuing.

All 37 queue blocks carry a NOTE, so the 89 are an adjudicated refusal rather than a to-do
list: `FuzzingFunctions` (namespace compiled out of this build), the EME chain (`MediaKeys`,
`MediaKeySystemAccess`, `MediaKeySession`, `MediaKeyError` - no CDM, so no receiver), the
negotiation-gated RTC types (`RTCIceTransport`, `RTCSctpTransport`, `RTCDTMFSender`,
`RTCCertificate`, `RTCIceCandidatePair`), the three report-body classes plus `FetchObserver`
and `CSSImportRule`, the async-only `CryptoKey` / `IDBTransaction` / `IDBIndex` / `SourceBuffer`
receivers, `AudioWorkletNode`, `PictureInPictureEvent`, `TaskPriorityChangeEvent`, `PaintRequest`,
`WebTransport` and its datagram stream, `GamepadPose` and `FileSystemEntry`, and the two dialogs
(`Window`, `Navigator`). Each NOTE states the reason *as evaluated in the page*, not as read from
the IDL.

`python3 tools/probe_apis.py` probed 740 queued members on the same build with Grizzly's prefs:
131 `present` (126 prototype, 3 instance, 2 static), 609 `not-exposed`, and 49 interfaces the
page has no receiver for at all (`unprobeable`, kept separate so a WebGL extension object or a
worker-only interface is not reported as a browser denial). Of the 131 present, 75 are emitted in
reachable rule text; the other 56 are exactly the NOTE'd refusals above.

`python3 tools/check_rules.py --samples 25` exits 0 (6 grammars, 42,047 rules - the count moves a
few dozen per run because the WebGPU grammar is rebuilt from a random 10-shader sample, so never
treat one figure as a delta against another). `python3 tools/check_wgsl.py` exits 0 (13 modules,
0 compile or pipeline failures - `domato-example.wgsl` reads `skipped (no vertex stage)` because
it is compute-only, which is the corpus being honest rather than a gap).

Two sweeps closed most of this session's work and both are worth remembering as defect shapes,
not as line counts:

- `document.createEvent("X")` accepts only a legacy whitelist. 51 of the 71 names the grammar
  asked for threw `NotSupportedError`, so those variables were never created and every statement
  reading a member off them was dead text no audit line could show. The 20 that work are: Event,
  Events, UIEvent, UIEvents, MouseEvent, MouseEvents, HTMLEvents, KeyboardEvent, MessageEvent,
  StorageEvent, TextEvent, CompositionEvent, FocusEvent, HashChangeEvent, CustomEvent, DragEvent,
  BeforeUnloadEvent, DeviceMotionEvent, DeviceOrientationEvent, SVGEvents. `KeyboardEvents` and
  `WheelEvents` are *not* in it. The constructors are now used instead; a bare
  `document.createEvent` in a rules file is a bug report, not a creator.
- A constructor's callback argument must be callable. `<EventHandler>` expands to a read of an
  `on*` property, which is `null` on a fresh object, so all 18 lines of the form
  `new IntersectionObserver(<EventHandler>)` threw and registered no variable - the observer
  surfaces looked covered and were not. Callbacks are inline `function(...){...}` now.

A third sweep was a deletion. 202 rule lines across `js.txt` and `webapis.txt` were built on
interfaces this build does not expose at all - every `XR*` name (`navigator.xr` is undefined and
`'XRSession' in window` is false), the whole `TCPSocket`/`TCPServerSocket`/`*SocketEvent` family
(`dom.tcpsocket_in_child.enabled=false`, and `ShouldTCPSocketExist` on top),
`ImageCapture`/`ImageCaptureErrorEvent`, and the CSS Color Value classes `CSSRGB`, `CSSHSL`,
`CSSHWB`, `CSSLab`, `CSSLCH`, `CSSOKLab`, `CSSOKLCH`, `CSSColorValue`, `CSSPositionValue` (all
false in `window`, while `CSS`, `CSSNumericValue`, `CSSStyleValue`, `CSSKeywordValue`,
`CSSImageValue`, `CSSVariableReferenceValue`, `CSSUnparsedValue`, `CSSMathSum`, `CSSMatrixComponent`,
`CSSPerspective`, `CSSRotate`, `CSSScale`, `CSSSkewX`, `CSSSkewY`, `CSSTranslate` are all true).
`webapis.txt` even held `<new XRSession> = undefined;`-style placeholders whose only effect was to
let a block of guaranteed throws keep parsing. Removing them drops `reachable` from 5619 to 5601 -
three of those names were being counted from a dead line that merely spelled the member, and one
(`Document.onvisibilitychange`, plus `Document.visibilityState`) went back in as a real rule - and
that lower number is the true one. If you are about to write rules for an interface,
`'Name' in window` in `check_reads.py` costs one page load.

## How much of a case each domain gets

Measured by counting guarded statements in the blocks of 25 generated cases
(`check_rules.py --samples 25 --keep`, splitting the case at
`function canvasFuzzer()` / `function webglFuzzer()` / `function webgpuFuzzer()`) - re-measure
after any large rules addition, the pools move: the DOM/JS block is ~3487 statements (82.7%) and
canvas/webgl/webgpu are pinned at their budgets of ~250
each. Dividing by each grammar's statement pool explains the rest - js 11389 rules, webgl 218,
webgpu 209, canvas 151 - so the graphics blocks draw each rule about 1.1-1.7 times per case while
the DOM block draws each rule 0.3. Distinct members actually called per case: webgl ~170,
webgpu ~45, canvas ~20. Canvas was thin because its rules used the literal `ctx`, not because the
budget was small; the typed-receiver fix above is what raised it, and it is the knob to reach for
before `_N_CANVAS_LINES`/`_N_WEBGL_LINES`/`_N_WEBGPU_LINES`.

Known environment facts, verified by `tools/probe_apis.py`'s `env:` line on this build with
Grizzly's prefs: WebGPU runs (adapter, device, shader module, command encoder all come back,
`maxBindGroups` 4); Canvas 2D runs; **both WebGL names hand out contexts** - `getContext('webgl2')`
returns a `WebGL2RenderingContext` and `getContext('webgl')` and
`getContext('experimental-webgl')` return a `WebGLRenderingContext`. An older note in this
file claimed WebGL1 returned null; that came from a `probe.json` written before the probe
recorded which context names it had asked, and the current run contradicts it. WebGL extension
objects (`EXT_*`, `OES_*`, `ANGLE_*`, `MOZ_debug`, `OVR_*`, `WEBGL_*`) have no window global -
the IDL name is the string passed to `getExtension()` - so their members can only be probed
through a context; `EXTENSION_PREFIXES` in the probe is the list of names that get that
treatment, and an extension interface missing from it is reported `unprobeable` instead of
answered.

The WebGPU grammar can only be as varied as `domato/webgpu/wgsl/*.wgsl` allows - entry
points and binding numbers come from those shaders - so a new WGSL corpus is worth more there
than new rules. `tools/check_wgsl.py` is how you know a corpus change compiled.

## WGSL facts this build enforces

naga 30.0.0 (`/home/ruslan/firefox/third_party/rust/naga`) is the WGSL compiler, and its
bound-name table (`src/front/wgsl/parse/conv.rs`) plus its reserved-word list
(`src/keywords/wgsl.rs`) are the authority. Each entry below is a module that failed to
compile here and what the fix was:

- no `inverse` - the name is not bound in the WGSL front end at all (it exists in naga's IR
  only), so a corpus that wants a reversed matrix hand-rolls it or uses `transpose`.
- `textureGather` on a colour texture takes the **component first**:
  `textureGather(0u, tex, samp, coords)`.
- a `sampler_comparison` requires a depth image - `texture_depth_cube_array` with
  `textureSampleCompare`, not `texture_cube<f32>`.
- `atomicCompareExchangeWeak` returns a struct: read `.old_value` / `.exchanged`.
- `faceForward` is three-arg; the bit queries are `firstTrailingBit` / `firstLeadingBit` and
  `countOneBits` - there is no `findLsb`/`findMsb`/`countZeroBits`/`rotateBits`, so a `rol32`
  is written as a function.
- `shared` and `snorm` are reserved words (`src/keywords/wgsl.rs`): naming a binding `shared`
  is a parse error, not a style problem.
- a `var<uniform>` array is 16-byte strided: the corpus uses `array<vec4<f32>, 2>` and
  `array<mat4x4<f32>, 4>`, and a packed element type goes in `var<storage>` instead - that
  is where `scratch : array<u32>` lives.
- a vertex stage cannot write to `storage, read_write` without the corresponding feature -
  read it, and do the writes in compute.
- there is no `array<texture_2d<f32>>` / `array<sampler>` binding array, sized or not, in any
  access mode: naga's array validator requires the base type to be `DATA`
  (`src/valid/type.rs:589`), and textures are handle-space. Use `texture_2d_array<f32>` and
  index it with the array-index argument instead.
- `maxStorageTexturesPerPipelineLayout` is 4 here - a fifth `texture_storage_*` binding in a
  module fails *pipeline* creation ("Too many bindings of type StorageTextures ... limit is 4,
  count was 5"), which compiles fine and is only visible through `check_wgsl.py`.
- `read_write` storage-texture access is rejected per format on this build: `rg32float`,
  `rgba32float` and `rgba32sint` all error, `r32float` is accepted. Spread the read_write
  bindings over the accepted formats and use `write` / `read` for the interesting ones.
- `modf` and `frexp` take exactly one argument and return a struct - and naga names the
  fields `fract`/`whole` (modf) and `fract`/`exp` (frexp), not the spec's `mantissa`/`exponent`.
  The two-argument pointer form is "too many arguments passed to `modf`", and `&v.x` is
  separately illegal ("cannot take the address of a vector component").
- `textureSampleCompareLevel` has no level argument: `(texture, sampler, coords, reference)`.
  A fifth argument is lowered in a const context and dies with "this operation is not supported
  in a const context" rather than an arity error.
- no `dpdxy` - the derivative builtins are `dpdx`, `dpdy` and `fwidth`.
- texture sampling is fragment-only: `textureSample*` and `textureGather*` in a compute entry
  point fail with "Uses operations forbidden at this stage". Keep compute to `textureLoad` /
  `textureStore` / atomics, and read sampled-or-comparison textures in the fragment stage.
- a vertex stage whose `@location` inputs are not backed by matching `vertex.buffers`
  attributes fails pipeline creation ("Location[0] Float32x4 ... is not provided by the earlier
  stage in the pipeline"). The grammar generates random buffer layouts, so a corpus vertex
  shader that required attributes would fail in almost every case: take builtins only and
  synthesize the attribute values from `vertex_index` / `instance_index`.
- `firstLeadingBit(i32)` is `i32` and `firstTrailingBit(u32)` is `u32`, and WGSL has no
  implicit sign conversion - adding them needs an explicit `u32(...)`/`i32(...)`.
- pipeline overrides are declared with the bare word `override name : u32 = 2u;` - naga 30 does
  not know the `@override` attribute ("unknown attribute: `override`"). Every override in the
  corpus needs a default, because the grammar builds pipelines with `constants: {}` and an
  unspecialized override without one fails with "Missing value for pipeline-overridable constant
  with identifier string". An override is not usable in a `const` expression ("Unexpected
  override-expression"), and an override-sized `var<storage>` array is invalid
  (`CREATION_RESOLVED` type flag) while `var<workgroup> cache : array<u32, overrideCache>;` is
  fine. Consequence for the grammar: `<USVStringDoubleRecord> = {}` is not laziness. A constant
  name that the paired module does not declare is a validation error, and the generator picks
  `<GPUShaderModule>` and the record independently, so a derived name would fail as often as the
  module that declares it is chosen.

## Routing an interface

1. `GPU*` -> `webgpu/webgpu.txt`; `WebGL*`, `EXT_*`, `OES_*`, `OVR_*`, `WEBGL_*`, `ANGLE_*`,
   `MOZ_debug` -> `webgl/webgl.txt`; `CanvasRenderingContext2D`, `OffscreenCanvas*`, `Path2D`,
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
  is picked uniformly. It does nothing for a statement: `p=` is not read when a `<line>` is
  chosen. What *does* move a statement's frequency is its receiver: 90% of lines are drawn from
  `context['interesting_lines']` - the rules that reference a typed variable of a type already in
  context (`_interesting_line_prob = 0.9`, grammar.py:297) - and only the other 10% come from
  `random.choice(self._all_nonhelper_lines)` (grammar.py:301, filled at grammar.py:1014). Measured
  on the canvas grammar (151 statement rules, 250-line budget): a rule whose receiver is the
  literal text `ctx` landed at 0.16-0.32 appearances per case, the same member written as
  `<ctx2d>.reset()` with `<new ctx2d> = ctx;` in the pool landed at 5.7. So `<new Type>`/`<Type>`
  receivers are how an API gets reached *often*, and the `!varformat` graphics grammars are no
  exception - literal `ctx` is text, not a variable.
- A `<new Type>` rule must not reference `<Type>` in its own right-hand side: creating the
  variable re-enters the rule, and the case fills with
  `Maximum recursion level reached while creating object of type X`. Split it into a creator rule
  and a use rule.
- Each statement line is drawn on its own, so a line that only *reads* a variable some
  other line declares will be emitted without that declaration often enough to matter.
  Declare and use inside one line (`var x = ...; use(x);`, the shape the audio and
  text-track rules in `webapis.txt` use), or put the whole expression in a single rule.
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
- A creator that throws is worse than no creator. `<new X> = <expr>` registers the whole line
  as the way to make an `X`, and nothing checks that `<expr>` runs: if it throws, the variable
  never appears, and every statement reading a member off it is invisible dead text that the
  audit still half-counts. Both shapes found this way in one session: `document.createEvent()`
  rejects 51 of the 71 names the grammar asked for, and 18 observer constructors were being
  handed `<EventHandler>` (a null `on*` read) as their callback. `check_reads.py` is the tool
  that says so before you write the rule.
- A dictionary key is not a member position. `{renderedBuffer: buf}` really does set the event
  field, but the audit matches `.name`, `["name"]` and `name(` only, so the row stays in
  `missing`. Read the property back too (`<OfflineAudioCompletionEvent>.renderedBuffer`) or
  leave a NOTE; never delete the dictionary write to make a number look better.
- `<DOMString>` is shared between two grammars that want opposite things. `js.txt` pulls in
  `cssproperties.txt` through `jshelpers.txt:2239`, and that file also defines
  `<DOMString> = foo|bar|baz|a` - CSS identifiers, and undeclared identifiers in JS. With 4 of
  the symbol's 9 creators in the js grammar bare, almost half of every `<DOMString>` in a
  generated statement threw ReferenceError (measured: 64 in one instrumented case). They carry
  `p=0.02` now: the js grammar draws them 8% of the time (0 in the case re-run afterwards), and
  the css grammar is untouched because those four are its *only* `<DOMString>` rules, so
  normalisation puts them back at a uniform 25% each. `wasm.txt:278-279`
  (`<wasmexportidentifier>`) is a second bare source.
- The audit routes an `*Element` name to `tagattributes.txt` by interface name, which is right
  for an attribute *value* and wrong for an attribute *read*. `el.accessKeyLabel` and
  `el.scrollLeftMax` are JS statements and belong in `webapis.txt`; check that the grammar you
  write into owns the receiver.
- A refusal is worth recording in the tool. When a member turns out unreachable, add the reason
  - as it was evaluated, not as the IDL reads it - to `NOTES` in `tools/audit_rules.py`, so the
  queue block says why. An unadjudicated `missing` row is just an invitation for the next session
  to rediscover it.

## Never add

- `[SystemPrincipal]`, `[ChromeOnly]`, `[MozSystem]` members - not exposed to content,
  the call is always a TypeError. Examples in this tree: `Window.getInterface`,
  `Window.synthesizeMouseEvent`, `Document.createXULElement`, `Document.nodeFromPoint`.
- Members behind a `[Pref]` that is off in `StaticPrefList.yaml` *and* not turned on by
  Grizzly's `browser-fuzzing.yml`. Only one of the two being on is enough.
- Anything `[Func]`-gated that `probe_apis.py` has not confirmed present.
- `FuzzingFunctions.crash` / `FuzzingFunctions.killGPUProcess` / `memoryPressure` - they end
  the session rather than fuzzing it. The rest of that namespace is normally fair game, but
  this checkout is an ASan debug build without `--enable-fuzzing`, so the *whole* namespace
  is compiled out: `grep -c FuzzingFunctions libxul.so` is 0 where the control string
  `structuredClone` is 19, and `probe_apis.py` finds no global. On a build that does
  configure fuzzing, re-probe before adding any of it back.
- A call whose only effect is to ask the user something - `Navigator.mozGetUserMedia` is
  `present` on the prototype and still must not be emitted, because a camera/microphone
  prompt is a window the harness cannot answer.
- Navigator dialogs that block (`alert`/`confirm`/`prompt` wired to a callback that
  never fires), and real network calls to hosts outside `server_map` - test cases are
  served with relative URLs for a reason.
- Anything that writes to disk outside the profile or opens a window - the harness
  cannot close it and the session hangs until the runtime budget expires.

## Definition of done for a rules commit

1. One domain or interface per commit; the message says which queue entry it closes.
2. `python3 tools/check_rules.py --samples 25` exits 0. Anything less than "every
   grammar parses, resolves and generates" means the rules are not in the generated
   code.
3. `python3 tools/check_reads.py <exprs>.json` exits 0 for the new lines' expressions -
   presence is not callability. A constructor, a `createEvent` name or a callback argument
   that throws produces no object, and the rules that depend on it stay dead text that the
   audit can still read as coverage.
4. `python3 tools/audit_rules.py` re-run shows the member in `reachable`, not in
   `missing` and not in `parsed but unreachable`. If the member only arrives through a
   dictionary or a callback argument, say so in a `NOTES` entry instead of bending the rules.
5. If the commit touched `domato/webgpu/wgsl/`, `python3 tools/check_wgsl.py` exits 0.
   Compilation is a verdict from `getCompilationInfo`; pipeline success is a verdict from
   a validation error scope - "the call did not throw" is neither, which is how a
   compute-only module used to be reported as `render=ok`.
6. If the members were `[Func]`-gated, a `probe_apis.py` record shows `present:*`.
7. Nothing under `results/` is committed (it is gitignored, and it is regenerated).

After changing `grz_domato/` (not rules), a running `./fuzz.sh` (Linux) or `fuzz.bat`
session keeps the old adapter code - restart it. Changing only `domato/**.txt` also needs a
restart, because the grammars are parsed once in `setup()`.
