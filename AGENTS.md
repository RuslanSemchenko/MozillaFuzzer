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
| `domato/rules/html.txt` | element/tag structure | includes `common`; safe markup tags and attributes |
| `domato/rules/js.txt` | DOM/JS statements (`!begin lines`) | includes `common`, `jshelpers`, `webidl_values`, `webapis`, `stateful`, `wasm`; sets `!lineguard` |
| `domato/rules/webapis.txt` | Web API calls, constructors, events | generated from Firefox dom/webidl via `gen_webidl_rules.py` |
| `domato/rules/webidl_values.txt` | WebIDL value types and dictionary generators | generated from dom/webidl |
| `domato/rules/stateful.txt` | stateful multi-step scenarios | IDB, Streams, WebCrypto, OPFS, Workers, Detached frames |
| `domato/rules/wasm.txt` | WebAssembly API & bytecodes | Wasm modules, SIMD, atomics, memory, tables, globals, exceptions |
| `domato/rules/jshelpers.txt` | value-producing helpers | ends in `!begin helperlines` |
| `domato/rules/css.txt` | CSS grammar and properties | `rules` is a live entry point |
| `domato/rules/canvas.txt` (+ `canvashelpers.txt`) | Canvas 2D statements | own grammar, own `!lineguard`, `!varformat fuzzvar%05d` |
| `domato/rules/webgl.txt` (+ `webglhelpers.txt`) | WebGL 1/2 statements | same, separate grammar |
| `domato/rules/webgpu.txt` + `webgpuhelpers.txt` | WebGPU statements | needs `<computeEntryPoint>`/`<vertexEntryPoint>`/`<fragmentEntryPoint>`/`<BindInt>` derived from the WGSL corpus |
| `domato/rules/wgsl/*.wgsl` | WGSL corpus | entry points and binding numbers the WebGPU grammar expands; parsed by `domato/wgsl_grammar.py` |

There is one rules directory. The graphics grammars are still parsed as separate
`Grammar` objects (see "How much of a case each domain gets"), but their text
lives in `domato/rules/` with everything else - an include in any of them is a
sibling file name, never `../rules/...`.

`grz_domato/template.html` is the harness the generated code is dropped into. It
declares `freememory`, `GetVariable`, `SetVariable`, `fuzzervars`, and one guarded
`<script>` block per API. A rule that needs a variable the template does not create
is a template change, not a rules change. `fuzzall()` calls `freememory()` after the
generated lines, so every case ends with `FuzzingFunctions.garbageCollect()`,
`cycleCollect()`, extra allocation pressure and a DOM/JS cycle - the GC/CC that can
surface teardown bugs happens while the report is still attributable to this case.
(`freememory()` used to be defined and never called, so those calls were dead code.)

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

`probe_apis.py --only NAME` writes the *whole* `results/audit/probe.json`, not just the
batch: a targeted run replaces the 969-record file with a handful of answers, and the
generator then silently drops every `[Func]` member and every interface only reachable
through one (Window.caches, Navigator.gpu/mediaDevices/serviceWorker, Window.navigation,
Document.createComment, Node.appendChild, ... - dozens of generated lines vanished this
way before anyone noticed the file had shrunk). After any targeted probe, re-run the full
`python3 tools/probe_apis.py` before running `gen_webidl_rules.py`.

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

Every figure below is from the command written next to it, run on 2026-10-26 with the
rules files in this tree. Re-run everything - they go stale the moment a rules file changes.

`python3 tools/extract_idl.py --source /home/ruslan/firefox` -> 847 files, 2362 types
(1101 interfaces), 10932 members.

`python3 tools/audit_rules.py` on that inventory: 937 types considered, 793 not gated off at
interface level (144 gated), 50 interfaces with at least one missing member. Across those 793:
5654 members reachable, 117 missing (115 -> `webapis.txt`, 2 -> `rules/webgl.txt`; the other
five work orders are empty), 5 word-only, 0 parsed-but-unreachable, 274 whose only gate is a
`[Func]`/trial the audit cannot evaluate, and 423 chrome-only / 78 pref-off excluded before
queuing.

All 50 queue blocks carry a NOTE, so the 117 are an adjudicated refusal rather than a to-do
list: `FuzzingFunctions` (compiled in, but `crash`/`killGPUProcess`/`signalIPCReady`/
`memoryPressure`/`synthesizeKeyboardEvents` are refused), the WebAuthn response classes
(`AuthenticatorResponse` and its two subclasses, `PublicKeyCredential` - a real credential needs
an authenticator), the deprecation/integrity report bodies (`DeprecationReportBody`,
`IntegrityViolationReportBody`) plus `FetchObserver`, the permission/UI surfaces (`Clipboard`,
`Geolocation`, `MIDIAccess`, `Serial`, `GetUserMediaRequest`, `HTMLInputElement`/`HTMLSelectElement`
`showPicker`, the `Window` and `Navigator` dialogs), the no-receiver types (`Gamepad*`,
`SpeechSynthesisVoice`, `Element` pointer capture, `History`), the legacy classes
(`MouseScrollEvent`, `ScrollAreaEvent`, `TimeEvent`, `MediaStreamError`, `MediaKeyError`,
`PaintRequest`, `IntlUtils`, `PermissionsPolicy`, `Node`, `Directory` and
`FileSystemDirectoryEntry`/`FileSystemDirectoryReader`, `CookieStoreManager`,
`LegacyMozTCPSocket`, `RTCIdentityProviderRegistrar`),
the `WebSocket` and `WebTransport` network surfaces, and the WebGL extension objects. Each
NOTE states the reason *as evaluated in the page*, not as read from the IDL.

`python3 tools/probe_apis.py` probed all 962 queued candidates on the same build with Grizzly's
prefs (the default bucket is `all` = `needs_probe` + `missing`): 191 `present` (174 prototype,
5 namespace, 4 static, 8 instance), 771 `not-exposed`, and 53 interfaces the page has
no receiver for at all (`unprobeable`, kept separate so a WebGL extension object or a worker-only
interface is not reported as a browser denial). Present is exposure, not callability *or*
obtainability: `'Geolocation' in window` is true while `navigator.geolocation` is undefined here,
so its members probe `present:prototype` and there is still no receiver. Of the 191, 17 are
emitted in reachable rule text; the rest are the refused interfaces above or members the generator
refuses by name in `DENY_MEMBERS` with the reason next to them (e.g. `GPUAdapter.requestDevice`,
because the template already consumed that adapter; the five `FuzzingFunctions` members above).

`python3 tools/check_rules.py --samples 25` exits 0 (6 grammars, 9788 rules - the count moves a
few dozen per run because the WebGPU grammar is rebuilt from a random 10-shader sample, so never
treat one figure as a delta against another). `python3 tools/check_wgsl.py` exits 0 (13 modules,
0 compile or pipeline failures - `domato-example.wgsl` reads `skipped (no vertex stage)` because
it is compute-only, which is the corpus being honest rather than a gap).

`MOZ_HEADLESS=1 python3 tools/scan_cases.py --samples 16 --case-timeout 45` reports 16/16 cases in
50 s with `30 row(s), 16 group(s); 6 systematic; creators 0 | roots 16 | cascades 0 |
async/no-line 0`. The systematic groups are the accepted classes below: several
`<RTCDataChannel>.send()` shapes (a channel from `createDataChannel` stays "connecting" until a
real peer negotiates SCTP, and send() throws InvalidStateError unless readyState is "open") and
`<TimeRanges>.start/end` IndexSizeError on an empty range. A 64-case run of the same command
reported 64/64 in 242 s with the same classes and no stalls after the navigation guard. The
other rows are validation on random
receivers or arguments (appendChild of an Attribute or an ancestor, `insertDTMF` on an
unnegotiated sender, a pooled IDBRequest read before it finishes, `SVGMatrix.inverse` on a
singular generated matrix). The `unexpected request(s)` line is mark-up fetches
(`<img src>` drawn from the URL pools, including a bare `?` that resolves to `caseN.html?`) and
is not a navigation: a case that really navigated never posts its report.
`creators 0` is the fastest check for the dead-text class described below; run it after any
creator or argument-override change. When the thrown object has no stack (a DOMException raised
through a promise), the collector records its own stack so the rule line is still named, and
`__fz_err` frames are skipped when mapping. The page hook records only `console.error` calls
that carry an argument, so the generated `console.error()` coverage line does not become a
false systematic row.

A scan is only valid if the page actually ran. Check `grep SyntaxError results/scan/firefox.log`
and the scanned report for `fuzzall is not defined`: both mean the first inline script (which
defines `fuzzall`) did not parse or execute, so every generated line on that page was dead while
the report could still say `0 systematic`.

These sweeps closed most of this session's work and are worth remembering as defect shapes,
not as line counts:

- A generated `options.length = 65535` (the alias `select.length` is the same setter) pads the
  select with that many blank `<option>` children. The next `innerText` write removes them one
  at a time, and each removal rescans the options list
  (`HTMLSelectElement::RunSelectednessSettingAlgorithm` -> `ContentList::PopulateSelf`), so the
  page spins on the main thread and never reaches its report timer. `<fuzzuint>` includes
  65535, so both length setters now have an `ATTRIBUTE_VALUE_OVERRIDES` value of 3. A gdb
  backtrace of the content process (`gdb -p <content pid> -ex "thread 1" -ex bt`) is what named
  the loop; the scan stalled at that case, and `scan_cases.py` now records the stalled case,
  kills the browser and restarts it at the next case, so one hang cannot hide every case after
  it. The stalled page is saved as `caseN.html` in the scan output and replays with `--input`.
- The audit matches member *names* anywhere in reachable text, so an interface whose members
  collide with common names (`Notification.body`, `.title`, `.tag`, `.dir`, `.lang`) looks
  covered while nothing ever creates the object. `Notification` surfaced it: the constructor
  never asks for permission, `NotificationParent::RecvShow` rejects the show with a TypeError
  when permission is "default", and no window is shown, so one `stateful.txt` line can
  construct it with `silent: true`, read the fifteen instance members, assign the handlers and
  call `close()`. That moved six members from `needs probe` to `reachable`. When the probe says
  `present` and the queue has no missing row, check whether the member name is merely shared
  with another interface before believing it is covered.
- A `ReportBody` is still reachable: `ReportingObserver` is exposed, and a script-inserted
  `<meta http-equiv="Content-Security-Policy" content="img-src 'none'; report-to fuzzgroup">`
  yields a real `csp-violation` report whose `CSPViolationReportBody` reads `blockedURL`,
  `documentURL` and the rest. Two conditions are easy to miss: Gecko creates the body only when
  the policy names a report group (`nsCSPContext::SendReportsToEndpoints` returns early on an
  empty `report-to`), and `HTMLMetaElement::BindToTree` applies the policy only when the meta is
  inside the document's `<head>`, so the line checks `document.head.isConnected` first.
  `img-src 'none'` keeps the violation off the network - the blocked image never reaches the
  server. `IntegrityViolationReportBody` is not reachable the same way: its policy needs an
  `Integrity-Policy` response header, which content cannot set.
- `Navigation.transition` and `NavigationPrecommitController.addHandler` have no receiver
  outside an intercepted navigation: `Navigation.cpp` creates `mTransition` only when the
  event's interception state is not `None`, and builds the precommit controller only when the
  event carries precommit handlers. The stateful navigation line now calls
  `e.intercept({ handler, precommitHandler })` from inside its own `onnavigate` handler and
  reads the transition from the precommit callback. A probe page confirmed canIntercept is true
  for the fragment navigation, `transition` is non-null there, `addHandler` runs, and both
  result promises resolve to the `#fuzznav` URL. `navigate()` returns a dictionary, not a
  promise - the old `.catch` on the result was dead code, and the committed/finished promises
  now carry the catches. The intercept is guarded by `e.destination.sameDocument`: a
  same-origin *cross-document* navigation is interceptable too, and the unguarded version
  swallowed the harness's own `location = "/caseN.html"`, so a 16-case scan timed out on
  exactly the case after every page that contained the line. A two-page probe confirms the
  guarded page loads the next document while the unguarded control never does, and the
  fragment navigation still reaches the precommit handler (`transition` non-null).
- Hand-written Wasm bytecodes are code, and three of the six "valid" module sources carried
  section-size typos (memory section declared 5 bytes and carried 4; type section 5 vs 6;
  a 4-character export name declared as 3). `new WebAssembly.Module` threw CompileError,
  the module variable was never created, and `new WebAssembly.Instance(<module>)` cascaded
  off it - the scan's creators section named four rows at once. Every byte array is now
  compiled once through `tools/check_reads.py`; a module source that has not been verified
  that way is a dead creator. `structuredClone` of a `WebAssembly.Table`/`.Global` throws
  DataCloneError on every draw, so those two statements are not emitted at all.
- `StaticRange` validates its init dictionary (both containers share a root, offsets are
  valid boundary points), so `new StaticRange(<StaticRangeInit>)` with a random `<Node>`
  pair threw InvalidNodeTypeError on every draw; `CONSTRUCTOR_ARG_OVERRIDES` now builds the
  range on `document.body` at offset 0. A later scan still caught the creator throwing in one
  case: a generated line had removed both the body and the documentElement, so the override's
  expression was `undefined`. The fallback is the `document` itself, which is a Node and a
  legal range container even when it has no children (verified with `check_reads.py` on a
  childless document).
- `PerformanceResourceTiming.renderBlockingStatus` was the one new audit gap after a regen;
  the existing `stateful.txt` XHR scenario reads the resource entry, so it now reads that
  member too and the queue went back to 56 blocks, all with NOTEs.
- The pooled-state sweep after that produced five more shapes. `VideoFrame.clone()` on a frame
  an earlier `close()` line closed throws "No media resource in the VideoFrame now" (close()
  itself is idempotent, clone is not), so clone builds a fresh frame. `Animation.reverse()`
  throws "Can't reverse an animation with no associated timeline" on the no-arg
  `new Animation(null, null)` creator, so the statement builds an animation on
  `document.timeline`. `NamedNodeMap.setNamedItem/NS` with a pooled `Attr` throws
  InUseAttributeError ("Attribute already in use"), so the statement creates the attribute
  and inserts it in the same line. `Selection.getRangeAt` seeding failed when the case had
  removed both `documentElement` and `body`; a `Document` is a legal Range container, so the
  fallback now selects `document` itself. `ViewTransition.skipTransition()` rejects `ready`
  and `finished` with AbortError - both need a `catch` or the scan reports an unhandled
  rejection. Same family: `MediaRecorder.start()` a second time on the pooled recorder,
  `AudioEncoder.configure()` after a pooled encoder was closed, and
  `AudioScheduledSourceNode.stop()` on a source an earlier draw already started; each now
  builds a fresh receiver. `SVGTextContentElement.getSubStringLength` needs both laid-out
  text and an in-range index and now uses the same rendered-`<text>` override as the
  char-position members with `(0, 1)`.

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
  surfaces looked covered and were not. Callbacks are inline `function(...){...}` now. One
  survivor of this class turned up later: `new PerformanceObserver(<EventHandler>)` had never
  received the override, so it threw "Argument 1 is not an object" and every `takeRecords()` read
  cascaded off the null variable. When adding a callback-taking constructor, grep for every
  other observer-shaped API in the same commit.

- A `CSSNumericValue` receiver is not necessarily convertible. `to()` and `toSum()` both build
  a Servo `SumValue` (`servo/components/style/typed_om/sum_value.rs`), and its unit parser
  (`NoCalcNumeric::parse_unit_value`) knows only length, angle, time, number and percent. A
  `CSS.Hz(1)` receiver - which `CSS.Hz` makes easy to write - throws "Failed to create a sum
  value", so a `newvar{...CSSMathSum} = <CSSNumericValue>.toSum()` creator left a null. Both
  are statements now and the constructor `new CSSMathSum(1, 2)` is the creator; `add`/`sub`/
  `mul` are safe because they never build a SumValue.

- `document.all` is an `IsHTMLDDA` object: `ToBoolean(document.all)` is `false`, so the
  harness's `if (!var) { var = GetVariable(fuzzervars, ...) }` fallback after every creator
  replaced it with `null`, and four of eight scanned cases cascaded on `var.length`. It is a
  `DENY_CREATORS` entry now and `domato/rules/stateful.txt` reads the collection in one
  statement (`var a = document.all; a.length; a.item(0); a.namedItem("fuzz")`). Any other
  creator whose result the harness might test for truthiness has the same trap; the scan's
  cascade section is how you find out.

- Typing came from the tag name alone: `<a>`, `<font>`, `<image>` and `<title>` exist in both
  the HTML and SVG tables, and the SVG entry won, so an `<a>` emitted as body markup registered
  a variable declared `SVGAElement` while the object was an `HTMLAnchorElement` - the scan's
  creators section named `svgvar00001.getBBox is not a function` and the creator never existed.
  `add_html_ids` now decides from the surrounding markup: inside an unclosed `<svg>`/`<math>`
  the foreign type wins, otherwise HTML does.

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

The 2026-10-24 sweeps were all the same shape - a creator that throws registers no variable, and
the audit still reads the member name out of the dead text that depended on it:

- `document.createElement` on an `XMLDocument` (a DOMParser or XSLT result) returns a plain
  `Element` whatever the tag name is. A creator line typed `HTMLAudioElement` then registered a
  variable with none of the HTML interface's members, and every later `captureStream()` on it
  threw "is not a function". HTML element creators now run on the global `document` (always an
  HTML document); `createElementNS` with the SVG/MathML/XHTML namespaces is fine on an XML
  document, so those suppliers are unchanged. Same family: `<Document>.evaluate("//div",
  document)` throws `WrongDocumentError` when the receiver came from DOMParser or XSLT, so that
  creator is refused and `document.evaluate` / `XPathEvaluator` supply `XPathResult` instead.
- Receiver state, not argument shape, is the other source. `RTCPeerConnection.addTrack`,
  `addTransceiver` and `createDataChannel` throw `InvalidStateError("Peer connection is closed")`
  once an earlier line closed the pooled connection; `RTCRtpSender.dtmf` is `null` on a video
  sender (`mDtmf` is created only for an audio conduit); `XSLTProcessor.transformToDocument/Fragment`
  throws `NS_ERROR_NOT_INITIALIZED` on the zero-argument constructor or after `reset()`;
  `CSSStyleSheet.cssRules` and its legacy alias `.rules` throw "still-loading style sheet" after an
  imported sheet is inserted. `HTMLCanvasElement.transferControlToOffscreen` throws
  InvalidStateError once the canvas has a rendering context, and a pooled canvas always has
  one. Those creators now build their own receiver (a fresh
  `RTCPeerConnection`, an audio transceiver, an imported stylesheet, a fresh canvas) or are
  refused as creators while the call stays in the statement pool.
- `IDBFactory.open(name, 0)` is a `TypeError` ("0 (Zero) is not a valid database version"), so
  the version overload got a fixed `"fuzzdb", 1`.
- `Location.search = ...` navigates the harness page (`GET /case0.html?fuzz`) and the case never
  posts its report; every navigation setter on `Location` is refused, only `hash` and the getters
  remain. In `stateful.txt`, `document.body.appendChild(...)` became
  `(document.body || document.documentElement)?.appendChild(...)`, because a generated line can
  remove the body and every observer scenario died with it.
- WebIDL strips one leading underscore from the exposed identifier: IDL `_any`, `_includes` and
  `_exception` are the page-visible `any`, `includes` and `exception`. The emitter strips it and
  the audit normalizes both sides; before that, `TaskSignal._any(...)` and `AbortSignal._any(...)`
  were guaranteed TypeErrors that the audit still counted.
- A `check_reads.py` batch is evaluated in one page, so two expressions that declare the same
  `var` clobber each other and a later one can read the earlier one's value - every candidate
  must run inside its own function. A WebCrypto ML-KEM keypair must request the
  `encapsulateKey`/`decapsulateKey` usages in `generateKey`, or `encapsulate`/`decapsulate`
  reject: usages restrict the key, they are not defaulted.
- **Crash found 2026-10-24:** `SpeechRecognition.start()` installs the speech model and crashed
  the content process at shutdown with `MOZ_CRASH(MozPromise::ThenValue created from 'StartImpl'
  destroyed without being either disconnected, resolved, or rejected (dispatchRv: not
  dispatched))` at `MozillaPromise.h:548`, ASan SEGV in `MOZ_CrashSequence`, stack
  `SpeechRecognitionBackend::EnsureModelsInstalled` -> `ThenValueBase::AssertIsDead` ->
  `~MozPromise` -> `LazyIdleThread::Shutdown` -> `AppShutdown`. Reproduced by a generated case;
  deleting the `start()` line removed it. The check that fired is not `MOZ_ASSERT`: `MozPromise.h`
  guards it with `#ifdef MOZ_DIAGNOSTIC_ASSERT_ENABLED`, and `moz.configure:159` turns that on for
  `moz_debug | milestone.is_nightly | moz_dev_edition`. The mozconfig has no `--enable-debug`, but
  a local mozilla-central build is Nightly (`NIGHTLY_BUILD 1`), so the diagnostic assert is live -
  the ASan SEGV is `MOZ_Crash` reporting under `MOZ_ASAN`, not memory corruption. Beta/Release
  compiles the check out and drops the undispatched promise silently. It is also a microphone surface, so
  `SpeechRecognition.start` and `install` are refused in `DENY_MEMBERS`; the constructor,
  `abort`/`stop` and the event/attribute members stay emitted.

The sweep after that crash closed the last systematic thrown-line classes. The lasting shapes:

- Domato's rule parser cuts every line at the first `#`, even inside a JS string literal
  (`grammar.py: _remove_comments`). A URL written as `"#fuzz"` became an unterminated string:
  `SyntaxError: "" string literal contains an unescaped line break` at load killed the whole
  first script, so `onload=fuzzall()` threw `ReferenceError: fuzzall is not defined` and the
  page executed none of its generated lines - 8 of 16 pages in one scan, while the report still
  printed `0 systematic`. `add_line` in the generator now raises on any `#`, and `common.txt`
  spells a literal one as `<hash>`.
- Fresh receivers are the fix for once-only attributes and pooled state. `AudioBufferSourceNode.buffer`
  can be set once per node (second line: InvalidStateError); `ImageDecoder.close()` rejects the
  eagerly-created `completed` promise and the track list's `ready` promise, so its override
  attaches a `catch` to both before closing a pooled decoder; `WritableStream.getWriter()` throws
  on a locked pooled stream; `HTMLInputElement.setRangeText` needs a text input; and
  `RTCRtpTransceiver.direction = "stopped"` is rejected while "sendrecv" is accepted.
- Some setters cannot succeed synchronously, so they are suppressed instead of fuzzed:
  `MediaSource.duration` requires readyState "open", which needs an attached media element and a
  later task. `SpeechGrammar.weight` is a stub in Gecko - both accessors throw
  NS_ERROR_NOT_IMPLEMENTED (`SpeechGrammar.cpp`) - so it is in `DENY_MEMBERS`; the name-based
  audit still calls it covered because `FontFace.weight` reads the same name.
- WebGPU: `GPUDevice.destroy()` on the pooled device turns every later buffer call into
  OperationError("Invalid buffer"), and an adapter can be consumed only once ("The adapter has
  already been consumed"), so the override requests a fresh adapter and destroys that device.
- Argument/value classes with one accepted answer: `StylePropertyMap.append` only takes
  list-valued properties ("transition-property"); `EncodedAudioChunk`/`EncodedVideoChunk.copyTo`
  needs an ArrayBuffer of exactly `byteLength` (there is no `allocationSize()`);
  `ElementInternals.setValidity` needs a message when a flag is true; `Headers` names must be
  tokens; `History.pushState`/`replaceState` reject cross-origin URLs but accept an empty one;
  `ReadableStream.from({})` throws "undefined is not a function" while `from([])` works;
  `Response.json` with a generated status is RangeError; `AudioNode.channelCountMode = "max"` is
  NotSupportedError on Panner/Convolver/DynamicsCompressor and "clamped-max" is InvalidStateError
  on Merger/Splitter, so no single value is valid for a random node; `XPathResult.iterateNext`
  is invalidated by any document mutation (a fresh iterator over the current document is not).
- Accepted systematic classes that cannot be opened from a generated synchronous line:
  `<RTCDataChannel>.send()` (never open without a peer), `RTCDTMFSender.insertDTMF`
  (`CanSendDTMF` needs a negotiated transceiver; even a valid tone throws), `TimeRanges.start/end`
  (empty ranges), `IDBRequest.result/error` (request not finished), plus the deliberate
  `window.reportError(new Error("fuzz"))` line in `stateful.txt` that exercises the window error
  hook.

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

The WebGPU grammar can only be as varied as `domato/rules/wgsl/*.wgsl` allows - entry
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

1. `GPU*` -> `rules/webgpu.txt`; `WebGL*`, `EXT_*`, `OES_*`, `OVR_*`, `WEBGL_*`, `ANGLE_*`,
   `MOZ_debug` -> `rules/webgl.txt`; `CanvasRenderingContext2D`, `OffscreenCanvas*`, `Path2D`,
   `ImageData`, `ImageBitmap`, ... -> `rules/canvas.txt`.
2. CSS-ish -> `css.txt`; `SVG*`/`MML*` markup and per-element attribute values ->
   `html.txt` (which also owns the markup-only grammars' value symbols).
3. everything else -> `webapis.txt`.

Route by what the destination grammar can *say*, not by the interface name. `html.txt`
is the markup grammar, so it has no statement slot and no `<SVGPathElement>` variable.
SVG/MathML DOM methods (`getPathData`, `getPathSegmentAtLength`, ...) and every
`*Element` attribute *read* (`el.accessKeyLabel`) are JS statements and belong in the
`webapis.txt` block for that receiver. The audit routes a work order by name, so its
file header is advice about where the name *might* go; check that the grammar you write
into owns the receiver.

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
  case's JS. Async work belongs in `rules/webgpu.txt`, whose block is `async`.
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
  text `'filter: url('`. Write `<hash>` instead - rules in `common.txt` and `css.txt`
  were truncated that way before the emitter learned to refuse a `#`.
- `min=` / `max=` are read only by the built-in integer tags (`<int>`, `<int8>` ...
  `<uint32>`; `grammar.py:165`). `<fuzzint min=0 max=5>` is a *user symbol* from
  `common.txt`, so the attributes are parsed and ignored and the value comes from the
  whole `fuzzint` pool (-2^31 .. 2^31-1, including -1). Five wasm rules carried bounds
  that never applied and threw RangeError in every case that drew them; the scan
  (`3 systematic` rows) is what surfaced it. Use `<int min=... max=...>` when a bound
  matters.
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
- `<DOMString>` is shared by every grammar, and `common.txt` is its only source now.
  Every rule there is a *quoted* string. A bare identifier added to that symbol (a CSS
  keyword, an `!important` word) would be an undeclared name in every generated JS
  statement - keep grammar-specific bare words in that grammar's own symbols.
- The audit routes an `*Element` name by interface name, which is right for an attribute
  *value* and wrong for an attribute *read*. `el.accessKeyLabel` and `el.scrollLeftMax`
  are JS statements and belong in `webapis.txt`; check that the grammar you write into
  owns the receiver.
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
- `FuzzingFunctions.crash` / `killGPUProcess` / `signalIPCReady` / `memoryPressure` /
  `synthesizeKeyboardEvents`. The namespace exists now: the build was reconfigured with
  `--enable-fuzzing` on 2026-10-24, `grep -c FuzzingFunctions libxul.so` is 119 where
  `structuredClone` is 22, and `probe_apis.py` reports 5 members `present:namespace`.
  The rest of the namespace is emitted (`garbageCollect`, `cycleCollect`,
  `garbageCollectCompacting`, `enableAccessibility`, `dump`, `procId`, `remoteType`) -
  `check_reads.py` confirms all of them run in content. Two are refused because they were
  measured, not guessed:
  - `synthesizeKeyboardEvents` is a *content-process kill* on this harness:
    `BrowserParent::RecvRequestNativeKeyBindings` opens with
    `NS_ENSURE_TRUE(xpc::IsInAutomation(), IPC_FAIL(this, "Unexpected event"))`, and
    `IsInAutomation()` requires `MOZ_DISABLE_NONLOCAL_CONNECTIONS` plus the
    `security.turn_off_all_security_so_that_viruses_can_take_over_this_computer` pref.
    Grizzly sets neither (`ffpuppet` and `prefpicker/templates/browser-fuzzing.yml`), so a
    `"Tab"` press in either headless or headful mode ends with `IPDL protocol error:
    Handler returned error code!` and `Exiting due to channel error`. `check_reads.py`
    hangs exactly here - a page that kills its own content process never posts a report.
    A fuzz-only API reachable from content should not take the process down; this one does.
  - `memoryPressure` only fires a `heap-minimize` observer notification, but the project
    rule is that GC/CC belongs to `freememory()` at the end of the case, not to a random
    statement in the middle of one; it stays out of `webapis.txt`.
  `spinEventLoopFor` is emitted with a fixed `1` ms argument - the IDL takes `unsigned
  long`, so a generated `<fuzzuint>` could spin the event loop for 49 days.
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
5. If the commit touched `domato/rules/wgsl/`, `python3 tools/check_wgsl.py` exits 0.
   Compilation is a verdict from `getCompilationInfo`; pipeline success is a verdict from
   a validation error scope - "the call did not throw" is neither, which is how a
   compute-only module used to be reported as `render=ok`.
6. If the members were `[Func]`-gated, a `probe_apis.py` record shows `present:*`.
7. Nothing under `results/` is committed (it is gitignored, and it is regenerated).

After changing `grz_domato/` (not rules), a running `./fuzz.sh` (Linux) or `fuzz.bat`
session keeps the old adapter code - restart it. Changing only `domato/**.txt` also needs a
restart, because the grammars are parsed once in `setup()`.
