"""Join the Firefox WebIDL inventory against what the Domato grammars can
actually emit, so the rules work queue is built on facts rather than on
"text appears somewhere in a .txt file".

Two different questions are answered separately and never conflated:

  mentioned  the name appears in some parsed rule, reachable or not
  reachable  the name appears in a rule that the generator can actually select,
             i.e. reachable from the grammar's live entry points

Only "reachable" means the API is being fuzzed. Gating is read from the real
sources: StaticPrefList.yaml for [Pref] defaults and Grizzly's own fuzzing
prefs template, because a pref that is off by default but on while fuzzing is
reachable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent

from grz_domato import DOMATO_DIR, _load_domato, _parse_grammar  # noqa: E402

ENTRY_POINTS = {
    "html": ("rules/html.txt", ("line", "bodyelements")),
    "css": ("rules/css.txt", ("line", "rules")),
    "js": ("rules/js.txt", ("line",)),
    "canvas": ("rules/canvas.txt", ("line",)),
    "webgl": ("rules/webgl.txt", ("line",)),
}
# IDL kind/name patterns that decide which rules file should own an interface.
# Graphics APIs each have their own grammar and template, so they must not be
# routed into the DOM rules just because they are Web APIs.
API_ROUTING = (
    (re.compile(r"^GPU"), "rules/webgpu.txt"),
    # WebGL extension namespaces (EXT_*, OES_*, WEBGL_*) are object bags reached
    # through gl.getExtension(), so their members belong to the webgl grammar.
    (re.compile(r"^(WebGL|EXT_|OES_|WEBGL_|ANGLE_|MOZ_WEBGL|WEBKIT_WEBGL)"), "rules/webgl.txt"),
    (
        re.compile(
            r"^(CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D|CanvasGradient|CanvasPattern"
            r"|Path2D|ImageData|ImageBitmap|TextMetrics|ImageTrack|ImageFrame|CanvasDrawContext)$"
        ),
        "rules/canvas.txt",
    ),
)
ROUTING = (
    (re.compile(r"^(CSS|.*CSS.*|Style.*|.*Style)$"), "css.txt"),
)
DEFAULT_TARGET = "webapis.txt"
SKIP_KINDS = ("typedef", "callback")
# Queue entries whose gap is real but whose fix is a decision, not a rule to write.
NOTES = {
    "FuzzingFunctions": (
        "enabled via --enable-fuzzing; crash(), killGPUProcess() and signalIPCReady() end "
        "the session, memoryPressure() shrinks GC/CC on demand, and synthesizeKeyboardEvents() "
        "IPC_FAILs the content process outside automation mode (IsInAutomation needs a pref "
        "Grizzly does not set), so all five are refused."
    ),
    "PermissionsPolicy": (
        "LegacyNoInterfaceObject whose only content receiver is document.featurePolicy, and that "
        "attribute is [Pref=dom.security.permissionsPolicy.webidl.enabled] - default false in "
        "StaticPrefList.yaml:5075 and not set by Grizzly's prefs"
    ),
    "IntlUtils": (
        "LegacyNoInterfaceObject whose only receiver is window.intlUtils, [Func=IsChromeOrUAWidget] "
        "in Window.webidl:933 - not exposed to content, so every call would throw"
    ),
    "GetUserMediaRequest": (
        "the object is handed to a permission-prompt handler; content has no receiver to read "
        "getAudioOutputOptions() from"
    ),
    "Element": (
        "setPointerCapture and releasePointerCapture are the only missing members: both require "
        "an active pointer with the same id as the argument (Element::SetPointerCapture checks "
        "the active-pointer list), and a synthetic PointerEvent never creates one - every "
        "generated id throws NotFoundError (evaluated), so the rules were removed rather than "
        "left as guaranteed throws"
    ),
    "Navigator": (
        "probed in the page: testTrialGatedAttribute, canShare, share, mozAddonManager and "
        "mozTCPSocket are undefined; mediaDevices, serviceWorker, requestMIDIAccess and "
        "mozGetUserMedia exist, but requestMIDIAccess and mozGetUserMedia ask the user for device "
        "permission, serviceWorker needs a registered worker script, and registerProtocolHandler "
        "asks the user to allow the handler - no silent receiver"
    ),
    "OVR_multiview2": (
        "getExtension('OVR_multiview2') returns null on both the webgl and webgl2 contexts of "
        "this build (probe_apis.py), so the extension object does not exist here - not a gap"
    ),
    "Window": (
        "alert/confirm/find/print/prompt are blocking dialogs or chrome UI that AGENTS.md refuses "
        "(confirm is present:instance); reportError is emitted by stateful.txt. All 26 [Func]-gated "
        "members - Glean, GleanPings, browserDOMWindow, getAttention, getAttentionWithCycleCount, "
        "getGroupMessageManager, getWebExposedLocales, getWorkspaceID, intlUtils, isChromeWindow, "
        "isCloaked, isFullyOccluded, maximize, messageManager, minimize, moveToWorkspace, "
        "notifyDefaultButtonLoaded, ondragexit, ontouchcancel, ontouchend, ontouchmove, "
        "ontouchstart, printPreview, promiseDocumentFlushed, setCursor, windowState - evaluate "
        "typeof undefined on this content window"
    ),
    "GamepadPose": (
        "the only content receiver is navigator.getGamepads(), which is an empty list in the "
        "harness - no device is attached and the XRInputSource path needs an XR device too, so a "
        "pose read would dereference undefined on every iteration"
    ),
    "MediaKeyError": (
        "legacy EME class: MediaKeySession.error stays null even after a rejected generateRequest "
        "(evaluated), and the constructor is illegal - no receiver"
    ),
    "PopupBlockedEvent": (
        "illegal constructor, and its receiver only exists when window.open() is blocked - "
        "AGENTS.md refuses opening windows because the harness cannot close them"
    ),
    "IntegrityViolationReportBody": (
        "IntegrityPolicyService creates the body only for a policy that names report endpoints, "
        "which needs an Integrity-Policy response header; content cannot set one, so no receiver "
        "is constructible. blockedURL/documentURL are counted from the CSPViolationReportBody "
        "observer line by name collision, not from a real integrity report; reportOnly stays "
        "missing"
    ),
    "FetchObserver": (
        "created internally per fetch; there is no content constructor to make one"
    ),
    "WebTransport": (
        "needs a live HTTP/3 connection to a host outside server_map, which AGENTS.md refuses"
    ),
    "WebTransportDatagramDuplexStream": (
        "the datagram stream only exists on a connected WebTransport"
    ),
    "PictureInPictureEvent": (
        "the constructor requires a PictureInPictureWindow, which only exists once a video is in "
        "picture-in-picture - passing a plain object throws"
    ),
    "TaskPriorityChangeEvent": (
        "the constructor needs a real TaskSignal as previousTaskSignal and rejects the string form"
    ),
    "PaintRequest": (
        "Firefox-internal paint-event object, only handed to a paint-event listener in chrome "
        "context"
    ),
    "GamepadEvent": (
        "gamepad is a required non-nullable Gamepad in GamepadInit and Gamepad has no content "
        "constructor: navigator.getGamepads() is an empty list in the harness, so "
        "new GamepadEvent(...) has nothing to put in the dictionary. The audit only counted this "
        "member while a dead <XRInputSource>.gamepad line spelled the name"
    ),
    "LegacyMozTCPSocket": (
        "not exposed on this build: navigator.mozTCPSocket is undefined and "
        "'LegacyMozTCPSocket' in window is false (check_reads.py), gated by "
        "TCPSocket::ShouldTCPSocketExist plus dom.tcpsocket_in_child.enabled=false in "
        "StaticPrefList.yaml:5791 and absent from Grizzly's browser-fuzzing.yml. The whole TCP "
        "family (TCPSocket, TCPServerSocket, TCPSocketEvent, TCPSocketErrorEvent, "
        "TCPServerSocketEvent) went out of the grammar with it"
    ),
    "MediaStreamError": (
        "LegacyNoInterfaceObject + ExceptionClass: `MediaStreamError` is not defined in content at "
        "all (evaluated - ReferenceError), so the only instance is the rejection reason the legacy "
        "navigator.mozGetUserMedia error callback receives, and that callback is refused because it "
        "raises a camera/microphone prompt"
    ),
    "Node": (
        "accessibleNode is [Func=mozilla::dom::AccessibleNode::IsAOMEnabled] and the AOM pref "
        "(accessibility.AOM.enabled) is in neither StaticPrefList.yaml defaults nor Grizzly's "
        "browser-fuzzing.yml - the property is absent on a content Node (evaluated: undefined); "
        "containingShadowRoot is [Func=IsChromeOrUAWidget], chrome/XUL only"
    ),
    "Gamepad": (
        "navigator.getGamepads() returns an empty list on this build (evaluated) - no gamepad is "
        "attached and there is no content constructor, so no receiver"
    ),
    "GamepadButton": (
        "only reachable as gamepad.buttons[i]; with no gamepad attached the array does not exist "
        "and the interface has no constructor"
    ),
    "GamepadHapticActuator": (
        "handed out as gamepad.hapticActuators[i]; no gamepad, no actuator"
    ),
    "Geolocation": (
        "navigator.geolocation is undefined on this build (evaluated): dom.geo.enabled is off in "
        "StaticPrefList.yaml and not set by Grizzly's prefs, so the Navigator.geolocation pref-off "
        "exclusion applies to the whole interface"
    ),
    "GeolocationCoordinates": (
        "only handed out through a GeolocationPosition from navigator.geolocation, which is "
        "undefined here (evaluated)"
    ),
    "GeolocationPosition": (
        "same missing receiver: navigator.geolocation is undefined, and the Position exists only "
        "as the success callback argument"
    ),
    "AuthenticatorResponse": (
        "WebAuthn: the only producer is navigator.credentials.create/get, which asks the user for "
        "a security key; getClientExtensionResults/rawId cannot be read without one"
    ),
    "AuthenticatorAttestationResponse": (
        "handed back by credentials.create() after the WebAuthn prompt - no prompt-free receiver"
    ),
    "AuthenticatorAssertionResponse": (
        "handed back by credentials.get() after the WebAuthn prompt - no prompt-free receiver"
    ),
    "PublicKeyCredential": (
        "navigator.credentials.create/get is the only producer and both ask the user for a "
        "security key (evaluated: no receiver without the prompt)"
    ),
    "Serial": (
        "navigator.serial exists and its getPorts/mock-device/autoselect members are emitted by "
        "stateful.txt; requestPort requires transient user activation and rejects SecurityError "
        "without it"
    ),
    "SerialPort": (
        "getPorts() returns only ports the user has already granted, and requestPort needs "
        "transient activation; the testing API's mock connect events notify only already-granted "
        "ports (evaluated: simulateDeviceConnection resolves, getPorts stays empty, no onconnect)"
    ),
    "SpeechRecognitionEvent": (
        "new SpeechRecognitionEvent(...) throws TypeError because the required results member is a "
        "SpeechRecognitionResultList with no constructor, and a real event only comes from a "
        "microphone-gated recognition session"
    ),
    "SpeechRecognitionResult": (
        "only exists inside SpeechRecognitionEvent.results; that event has no prompt-free producer"
    ),
    "SpeechRecognitionAlternative": (
        "only exists as results[i][j] of a SpeechRecognitionEvent - no receiver"
    ),
    "SpeechSynthesisVoice": (
        "speechSynthesis.getVoices() returns [] on this build (evaluated, also after a delay): "
        "there is no speech backend, so no voice object exists"
    ),
    "CookieStoreManager": (
        "only reachable as ServiceWorkerRegistration.cookies; the harness has no registered "
        "service worker and cannot register one from the generated document"
    ),
    "History": (
        "back/forward/go navigate away from the generated document, which AGENTS.md refuses; "
        "pushState/replaceState/state/length/scrollRestoration are emitted"
    ),
    "Location": (
        "href/protocol/host/hostname/port/pathname/search setters and assign/replace/reload "
        "navigate the harness document away, so the case's report never arrives (evaluated: "
        "setting search to a random string reloaded case04.html in scan_cases.py). hash, the "
        "readonly getters and ancestorOrigins are emitted"
    ),
    "SpeechRecognition": (
        "start() captures the default microphone and, with install-on-start enabled, starts a "
        "speech-model download whose pending MozPromise crashed the content process at shutdown "
        "(MOZ_CRASH in MozPromise::ThenValueBase::AssertIsDead from "
        "SpeechRecognitionBackend::EnsureModelsInstalled, evaluated on this build); install() "
        "starts that download directly. start/install are refused, the constructor, abort/stop "
        "and the event/attribute members are emitted"
    ),
    "MIDIAccess": (
        "navigator.requestMIDIAccess() asks the user for MIDI device permission - a prompt the "
        "harness cannot answer"
    ),
    "MIDIPort": (
        "only handed out by MIDIAccess.inputs/outputs, which needs the MIDI permission prompt"
    ),
    "MIDIInput": (
        "subclass of MIDIPort - same missing permission-gated receiver"
    ),
    "Clipboard": (
        "readText needs transient user activation and Firefox can show a paste prompt the harness "
        "cannot answer; writeText is emitted by stateful.txt and rejects NotAllowedError without "
        "activation (evaluated)"
    ),
    "RTCIdentityProviderRegistrar": (
        "only exposed to a registered IdP in chrome context; content has no registrar object"
    ),
    "WebTransportDatagramsWritable": (
        "only exists on a connected WebTransport, which needs an HTTP/3 host outside server_map"
    ),
    "WebTransportSendStream": (
        "only handed out by a connected WebTransport's createSendGroup/createSendStream"
    ),
    "WebTransportError": (
        "only delivered as a WebTransport stream/read rejection, which needs a connection"
    ),
    "WebSocket": (
        "extensions is the only missing member: a socket has no receiver without constructing "
        "one, and DENY_CREATORS refuses the constructor because its only accepted schemes are "
        "ws/wss - any generated host leaves server_map, and 'ws://' + location.host opens an "
        "upgrade request the harness never answers, so the case stalls instead of reporting. "
        "extensions also stays \"\" until the handshake completes, so even a reachable socket "
        "would read an empty string without a server that does the upgrade"
    ),
    "DeprecationReportBody": (
        "report bodies are browser-created; `new Report(...)` is undefined in content (evaluated) "
        "and no deprecation is reported in the harness"
    ),
    "Directory": (
        "legacy FileSystem API: the only content producer is a directory picker or the "
        "[ChromeOnly] constructor, and the API's entry point (window.requestFileSystem / "
        "navigator.webkitRequestFileSystem) is undefined on this build (evaluated)"
    ),
    "FileSystemDirectoryEntry": (
        "legacy FileSystem API: DataTransferItem.webkitGetAsEntry() on a synthetic File yields a "
        "FileSystemFileEntry, and its getParent() returns that same file entry on this build "
        "(evaluated) - no directory entry exists, so no reader can be obtained from one"
    ),
    "FileSystemDirectoryReader": (
        "legacy FileSystem API: DataTransferItem.webkitGetAsEntry() on a synthetic File yields a "
        "FileSystemFileEntry, and its getParent() returns that same file entry on this build "
        "(evaluated) - no directory entry exists, so no reader can be obtained from one"
    ),
    "CSSNumericValue": (
        "min() and max() are stubs that throw NS_ERROR_NOT_IMPLEMENTED for every argument "
        "(layout/style/typedom/CSSNumericValue.cpp:308-320; evaluated: min(1, 2) throws "
        "NS_ERROR_NOT_IMPLEMENTED on a CSSMathNegate receiver) - not a grammar gap"
    ),
    "HTMLInputElement": (
        "showPicker() opens a native file/date/colour picker window that the harness cannot close"
    ),
    "HTMLSelectElement": (
        "showPicker() opens a native select popup the harness cannot close"
    ),
    "IDBKeyRange": (
        "the IDL spells the page-visible method `includes` as `_includes`; the content object has "
        "`includes` (evaluated) and no `_includes`, so the IDL spelling cannot be emitted"
    ),
    "MouseScrollEvent": (
        "document.createEvent('MouseScrollEvent') throws NotSupportedError and `new` is an Illegal "
        "constructor (both evaluated) - no receiver"
    ),
    "ScrollAreaEvent": (
        "document.createEvent('ScrollAreaEvent') throws NotSupportedError and `new` is an Illegal "
        "constructor (both evaluated) - no receiver"
    ),
    "TimeEvent": (
        "document.createEvent('TimeEvent') throws NotSupportedError and `new` is an Illegal "
        "constructor (both evaluated) - no receiver"
    ),
    "WEBGL_explicit_present": (
        "getExtension('WEBGL_explicit_present') returns null on both webgl and webgl2 contexts of "
        "this build (evaluated) - the extension object does not exist here"
    ),
    "WEBGL_provoking_vertex": (
        "getExtension('WEBGL_provoking_vertex') returns null on both webgl and webgl2 contexts of "
        "this build (evaluated) - the extension object does not exist here"
    ),
}


def rule_text(rule) -> str:
    parts = []
    for part in rule["parts"]:
        parts.append(part["text"] if part["type"] == "text" else f"<{part['tagname']}>")
    return "".join(parts)


# A member counts as emitted only where a member can syntactically appear: after
# a property access, inside a bracket-string lookup, or as a direct call. Matching
# bare identifiers instead reports a keyword as coverage - `<Window>.print()` is
# commented out in js.txt, yet "print" appears in reachable text as a CSS media
# type and "cm" as a CSS unit. The call form matters because globals are fuzzed
# that way: `setTimeout(...)` in js.txt:6129 and `fetch(...)` in wasm.txt:321 are
# real Window members.
MEMBER_POSITIONS = (
    re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]"),
    re.compile(r"(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\("),
)


def reachable_text(grammar, seeds) -> str:
    """Concatenate the text of every rule the generator can reach from seeds."""
    seen_rules: set[int] = set()
    queue = list(seeds)
    seen_syms = set(queue)
    out = []
    while queue:
        symbol = queue.pop()
        for rule in grammar._creators.get(symbol, ()):
            if id(rule) not in seen_rules:
                seen_rules.add(id(rule))
                out.append(rule_text(rule))
            for part in rule["parts"]:
                if part["type"] != "text":
                    tag = part["tagname"]
                    if tag not in seen_syms:
                        seen_syms.add(tag)
                        queue.append(tag)
    return "\n".join(out)


def all_text(grammar) -> str:
    return "\n".join(rule_text(rule) for rule in grammar._all_rules)


def load_prefs(source_root: Path) -> dict[str, bool]:
    """Pref name -> enabled, from StaticPrefList.yaml defaults.

    Missing is fatal, not empty: pref_enabled reads an unknown pref as off, so a
    silent empty table would report every [Pref]-gated member of the IDL as
    unreachable and take real work out of the queue without saying so.

    Some defaults are written as @IS_NIGHTLY_BUILD@ and friends: the build
    substitutes them from mozilla-config.h at compile time. Reading those as
    false hides whole interfaces on a Nightly checkout (evaluated: `new
    QuotaExceededError().quota` is null, not a TypeError, when the pref is on).
    The objdir next to the source is the only place the substitution is
    recorded, so use it when it exists.
    """
    path = source_root / "modules" / "libpref" / "init" / "StaticPrefList.yaml"
    if not path.exists():
        raise SystemExit(
            f"no StaticPrefList.yaml under {source_root} - pass --source <firefox checkout>"
        )
    build = build_substitutions(source_root)
    prefs: dict[str, bool] = {}
    name = None
    value = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        found = re.match(r"^- name: (\S+)", line)
        if found:
            if name is not None:
                prefs[name] = bool(value)
            name, value = found.group(1), None
            continue
        found = re.match(r"^\s+value: (\S+)", line)
        if found and name is not None and value is None:
            token = found.group(1)
            if token.startswith("@") and token.endswith("@"):
                value = build.get(token[1:-1])
            else:
                value = token.lower() in ("true", "1")
    if name is not None:
        prefs[name] = bool(value)
    return prefs


def build_substitutions(source_root: Path) -> dict[str, bool]:
    """@IS_...@ tokens from the objdir's mozilla-config.h.

    Returns {} when there is no objdir, which keeps every substituted pref at
    its conservative false - the same answer as before this existed.
    """
    configs = sorted(source_root.glob("obj-*/mozilla-config.h"))
    if not configs:
        return {}
    text = configs[0].read_text(encoding="utf-8", errors="replace")
    defined = set(re.findall(r"^#define ([A-Za-z_][A-Za-z0-9_]*)", text, re.MULTILINE))
    nightly = "NIGHTLY_BUILD" in defined
    early_beta = "EARLY_BETA_OR_EARLIER" in defined
    official = "MOZILLA_OFFICIAL" in defined
    release_or_beta = "RELEASE_OR_BETA" in defined
    android = "ANDROID" in defined
    ios = "IOS" in defined
    win = "XP_WIN" in defined
    macos = "XP_MACOSX" in defined
    return {
        "IS_NIGHTLY_BUILD": nightly,
        "IS_EARLY_BETA_OR_EARLIER": early_beta,
        "IS_NIGHTLY_OR_DEV_EDITION": nightly or early_beta,
        "IS_NOT_NIGHTLY_BUILD": not nightly,
        "IS_NOT_RELEASE_OR_BETA": not release_or_beta,
        "IS_NOT_MOZILLA_OFFICIAL": not official,
        "IS_ANDROID": android,
        "IS_IOS": ios,
        "IS_NOT_ANDROID": not android,
        "IS_NOT_MOBILE": not (android or ios),
        "IS_XP_WIN": win,
        "IS_NOT_XP_WIN": not win,
        "IS_XP_MACOSX": macos,
        "IS_NOT_XP_MACOSX": not macos,
    }


def load_fuzzing_prefs() -> dict[str, bool]:
    """Prefs Grizzly itself applies, from prefpicker's template.

    Only the `default:` variant counts. A pref that is true in the `vr:` or
    `a11y:` variant is off in a normal session, and a lone `null` means "leave
    the StaticPrefList default alone", which is not an override.
    """
    try:
        from prefpicker import PrefPicker
    except ImportError:
        return {}
    path = Path(PrefPicker.lookup_template("browser-fuzzing.yml"))
    prefs: dict[str, bool] = {}
    if not path.exists():
        return prefs
    in_pref_block = False
    pref = None
    variant = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_pref_block = line.strip() == "pref:"
            continue
        if not in_pref_block:
            continue
        found = re.match(r"^  ([a-zA-Z0-9_.\-]+):\s*$", line)
        if found:
            pref, variant = found.group(1), None
            continue
        found = re.match(r"^ {6}([a-z-]+):\s*$", line)
        if found and pref is not None:
            variant = found.group(1)
            continue
        found = re.match(r"^ {6}- (.+)$", line)
        if found and pref is not None and variant == "default":
            value = found.group(1).strip()
            if value in ("true", "1"):
                prefs[pref] = True
            elif value in ("false", "0"):
                prefs.setdefault(pref, False)
    return prefs


def pref_enabled(pref: str, defaults: dict[str, bool], fuzzing: dict[str, bool]) -> bool:
    """Whether a pref is on in a Grizzly session: Grizzly's own value wins,
    otherwise the StaticPrefList default applies."""
    if pref in fuzzing:
        return fuzzing[pref]
    return defaults.get(pref, False)


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def gate_reason(entry: dict, prefs: dict[str, bool], fuzzing: dict[str, bool]) -> str | None:
    """Why a content fuzzer cannot reach this type at all, if it cannot."""
    attrs = entry["attrs"]
    if attrs.get("ChromeOnly") or attrs.get("SystemPrincipal"):
        return "chrome-only"
    exposed = attrs.get("Exposed")
    if exposed:
        # [Exposed=*] and [Exposed=(Window,Worker)] both reach a content fuzzer;
        # only a list that names no Window-ish scope is a real gate.
        values = [
            item.strip().strip("()")
            for group in _as_list(exposed)
            for item in str(group).split(",")
        ]
        if not any(item in ("*", "Window") for item in values):
            return f"not exposed to Window ({exposed})"
    for pref in (p for p in _as_list(attrs.get("Pref", "")) if p):
        if not pref_enabled(pref, prefs, fuzzing):
            return f"pref off: {pref}"
    return None


def suggest_target(name: str, entry: dict) -> str:
    for pattern, target in API_ROUTING:
        if pattern.match(name):
            return target
    if name == "CSS":
        # the CSS *object*'s members are JS statics (CSS.cm, CSS.supports) and a
        # css.txt rule emits declaration text, where such a name cannot appear
        return DEFAULT_TARGET
    for pattern, target in ROUTING:
        if pattern.match(name):
            return target
    return DEFAULT_TARGET


def member_target(base: str, kinds: list[str]) -> str:
    """Which file a member of an interface routed to `base` belongs to."""
    return base


def member_positions(text: str) -> frozenset[str]:
    """Names used where a property can be read or written, one pass over text."""
    found: set[str] = set()
    for pattern in MEMBER_POSITIONS:
        found.update(pattern.findall(text))
    return frozenset(found)


def write_work_orders(report: list[dict], probe_path: Path, out_dir: Path) -> list[Path]:
    """Join the queue with the browser's verdicts, one file per destination grammar.

    A missing member is only work if the binding exists, and only probe_apis.py can
    say that per member. An interface the page had no receiver for - a WebGL
    extension object, a worker-only interface - reports every member as not-exposed,
    which is a fact about the probe rather than the API, so those are filed apart
    instead of being mistaken for a closed gap.
    """
    if not probe_path.exists():
        return []
    probe = json.load(open(probe_path, encoding="utf-8"))
    present: dict[str, set[str]] = {}
    absent: dict[str, set[str]] = {}
    for row in probe["probed"]:
        if row["state"].startswith("present:"):
            present.setdefault(row["iface"], set()).add(row["member"])
        elif row["state"] == "not-exposed":
            absent.setdefault(row["iface"], set()).add(row["member"])
    no_receiver = set(probe.get("unprobeable", ()))
    # probe.json files written before the page reported that as data only say it in prose
    no_receiver |= {
        error.split(":", 1)[0]
        for error in probe.get("errors", ())
        if "no page object" in error or "no such global" in error
    }

    orders: dict[str, dict[str, list[str]]] = {}
    for entry in report:
        if entry["blocked"]:
            continue
        # every destination gets a file even when its queue empties, so closing a
        # target cannot leave a stale work order behind to be read as open work
        orders.setdefault(entry["target"], {})
        for target, members in entry["missing_by_target"].items():
            for member in members:
                name = entry["name"]
                if name in no_receiver:
                    verdict = "no receiver"
                elif member in present.get(name, ()):
                    verdict = "present"
                elif member in absent.get(name, ()):
                    verdict = "not-exposed"
                else:
                    verdict = "unprobed"
                orders.setdefault(target, {}).setdefault(verdict, []).append(f"{name}.{member}")

    legend = [
        "Members still missing, split by what tools/probe_apis.py answered about them.",
        "Re-derive with `python3 tools/audit_rules.py` after both it and probe_apis.py ran.",
        "",
        "- present: the browser has the binding. This is the work list.",
        "- not-exposed: the browser does not have it, so every generated call would throw",
        "  and the per-line guard would swallow it. Not a gap; do not write rules for it.",
        "- no receiver: the probe had no page object to read (WebGL extension objects are",
        "  only reachable through getExtension(), worker-only interfaces have no window).",
        "  Add a receiver to tools/probe_apis.py before treating these either way.",
        "- unprobed: probe.json has no row for the member. Probe before writing rules.",
    ]
    written = []
    for target, verdicts in sorted(orders.items(), key=lambda kv: -sum(len(v) for v in kv[1].values())):
        path = out_dir / f"work_{target.replace('/', '_')}.md"
        lines = [f"# Work order: {target}", ""] + legend + [""]
        if not verdicts:
            lines += [
                "## nothing missing",
                "",
                "No content-reachable member routed to this file is unemitted.",
                "",
            ]
        for verdict, rows in sorted(verdicts.items()):
            lines += [f"## {verdict} ({len(rows)})", ""] + [f"- {row}" for row in sorted(rows)] + [""]
        path.write_text("\n".join(lines), encoding="utf-8")
        written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="/home/ruslan/firefox", help="Firefox checkout (StaticPrefList.yaml)")
    parser.add_argument("--inventory", default="results/audit/idl_inventory.json")
    parser.add_argument("--out", default="results/audit/coverage.json")
    parser.add_argument("--queue", default="results/audit/QUEUE.md")
    parser.add_argument(
        "--probe",
        default="results/audit/probe.json",
        help="probe_apis.py output to join with the queue for the per-file work orders",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=100,
        help="interfaces to list in the queue (the header still counts them all)",
    )
    parser.add_argument("--target", default=None, help="only queue entries routed to this rules file")
    parser.add_argument("--name", default=None, help="only queue entries whose interface name contains this")
    parser.add_argument(
        "--show-blocked",
        action="store_true",
        help="list interface-level gates too, so an absent interface is not mistaken for an absent API",
    )
    args = parser.parse_args()

    source = Path(args.source)
    gen = _load_domato()
    reachable = {}
    mentioned = {}
    for label, (filename, seeds) in ENTRY_POINTS.items():
        grammar = _parse_grammar(gen, DOMATO_DIR / filename)
        reachable[label] = reachable_text(grammar, seeds)
        mentioned[label] = all_text(grammar)
    # the WebGPU grammar needs shader-derived symbols, so it is scanned via the
    # adapter's own builder rather than parsed standalone
    adapter_grammar = _parse_grammar(gen, DOMATO_DIR / "rules" / "webgpu.txt", "")
    reachable["webgpu"] = reachable_text(adapter_grammar, ("line",))
    mentioned["webgpu"] = all_text(adapter_grammar)
    # one pass per grammar beats a word-boundary regex per member over ~10MB of
    # rule text, and member position (not bare-identifier presence) decides
    # coverage - see MEMBER_POSITIONS above
    reachable_at = {label: member_positions(text) for label, text in reachable.items()}
    mentioned_at = {label: member_positions(text) for label, text in mentioned.items()}
    reachable_ids = frozenset().union(*reachable_at.values())
    mentioned_ids = frozenset().union(*mentioned_at.values())
    reachable_words = frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", "\n".join(reachable.values())))

    types = json.load(open(args.inventory, encoding="utf-8"))["types"]
    # a mixin that some interface includes has already had its members folded
    # into that interface, so listing it again would double-count the same work
    folded = {m for entry in types.values() for m in entry.get("includes", ())}
    prefs = load_prefs(source)
    fuzzing = load_fuzzing_prefs()

    report = []
    for name, entry in sorted(types.items()):
        if entry["kind"] in SKIP_KINDS or entry["kind"] == "enum" or not entry["members"]:
            continue
        if entry["kind"] == "interface mixin" and name in folded:
            continue
        blocked = gate_reason(entry, prefs, fuzzing)
        # [Func]/[Trial] on the interface gates every member, and only the browser
        # can answer it - a member of a gated interface is a probe question, never work.
        interface_needs_probe = any(
            entry["attrs"].get(key) for key in ("Func", "Trial")
        )
        # const members are numeric aliases a fuzzer reaches through the API
        # itself, so they are counted apart and never queued as work
        standard, gated, chrome_only, pref_off, consts = [], [], [], [], []
        for member, slot in entry["members"].items():
            kinds, attrs = slot["kinds"], slot["attrs"]
            if "const" in kinds or member == "constructor":
                consts.append(member)
            elif any(key in attrs for key in ("SystemPrincipal", "ChromeOnly", "MozSystem")):
                chrome_only.append(member)
            elif attrs.get("Pref") and not any(
                pref_enabled(p, prefs, fuzzing) for p in _as_list(attrs["Pref"])
            ):
                pref_off.append(member)
            elif attrs.get("Func") or interface_needs_probe:
                gated.append(member)
            else:
                standard.append(member)
        # coverage is decided first, then split by bucket: a [Func]-gated member
        # the grammar already emits is not work, and must not appear as a gap
        missing, reachable_members, mentioned_only, name_only = [], [], [], []
        covered_by, probe, missing_by_target = {}, [], {}
        base = suggest_target(name, entry)
        for member in standard + gated:
            # WebIDL strips one leading underscore from the exposed identifier:
            # `_any` is the page-visible `any`, and that is what a rule says
            exposed = member[1:] if member.startswith("_") else member
            if exposed in reachable_ids:
                reachable_members.append(member)
                covered_by[member] = sorted(
                    label for label, ids in reachable_at.items() if exposed in ids
                )
            elif exposed in mentioned_ids:
                mentioned_only.append(member)
            elif member in gated:
                # [Func] needs the browser to answer, presence in text proves nothing
                probe.append(member)
            elif exposed in reachable_words:
                # the word is in live rules, but never as a property of anything:
                # a CSS keyword, an ARIA role, an attribute name. Not this API.
                name_only.append(member)
            else:
                missing.append(member)
                missing_by_target.setdefault(
                    member_target(base, entry["members"][member]["kinds"]), []
                ).append(member)
        report.append(
            {
                "name": name,
                "kind": entry["kind"],
                "source": entry["source"],
                "parent": entry["parent"],
                "target": base,
                "blocked": blocked,
                "members": len(standard),
                "consts": len(consts),
                "chrome_only": sorted(chrome_only),
                "pref_off": sorted(pref_off),
                "needs_probe": sorted(probe),
                "reachable": sorted(reachable_members),
                "covered_by": covered_by,
                "mentioned_only": sorted(mentioned_only),
                "name_only": sorted(name_only),
                "missing": sorted(missing),
                "missing_by_target": {
                    key: sorted(value) for key, value in sorted(missing_by_target.items())
                },
            }
        )

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=1), encoding="utf-8")

    live = [r for r in report if not r["blocked"]]
    queue = [r for r in live if r["missing"]]
    spread_by_target: dict[str, int] = {}
    for entry in queue:
        for target, members in entry["missing_by_target"].items():
            spread_by_target[target] = spread_by_target.get(target, 0) + len(members)
    spread = ", ".join(
        f"{target}: {count}"
        for target, count in sorted(spread_by_target.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    if args.target:
        queue = [r for r in queue if args.target in r["missing_by_target"]]
    if args.name:
        wanted = args.name.lower()
        queue = [r for r in queue if wanted in r["name"].lower()]
    queue.sort(key=lambda r: (-len(r["missing"]), r["name"]))

    lines = [
        "# Rules work queue",
        "",
        f"Generated by `tools/audit_rules.py` from {len(types)} WebIDL types against 6 grammars.",
        "",
        "How a number here is produced, and what it is not:",
        "- covered means the member name appears in a rule reachable from the grammar's live",
        "  entry points AND in a position where a property is read or written (`X.name`,",
        "  `X[\"name\"]`). `parsed but unreachable` names are in rules the generator cannot select;",
        "  `word only` names appear in live rules as a keyword, ARIA role or attribute name and",
        "  say nothing about this API. None of them is coverage.",
        "- member names are matched, never executed: this says nothing about whether the call does",
        "  anything useful at runtime. Only tools/probe_apis.py can settle that.",
        "- excluded before queuing: const aliases (numeric enums reachable via the API itself),",
        "  [SystemPrincipal]/[ChromeOnly] members, members whose [Pref] is off in both",
        "  StaticPrefList.yaml and Grizzly's own fuzzing prefs, and mixins already folded into the",
        "  interface that includes them.",
        "- `needs probe` members carry [Func=...], i.e. a C++ reachability predicate this script",
        "  cannot evaluate; they are listed apart and must be probed before being added.",
        "",
        f"- types considered: {len(report)}, not gated off at interface level: {len(live)}",
        f"- gated off at interface level: {len(report) - len(live)}",
        f"- interfaces/objects with at least one missing content-reachable member: {len(queue)}",
        f"- missing members by destination rules file: {spread}",
        "",
    ]
    for entry in queue[: args.top]:
        owned = entry["missing_by_target"]
        routed = " or ".join(sorted(owned)) if len(owned) > 1 else entry["target"]
        lines.append(
            f"## {entry['name']} -> {routed} "
            f"(missing {len(entry['missing'])} of {entry['members']} content-reachable members) [{entry['source']}]"
        )
        if entry["name"] in NOTES:
            lines.append(f"- NOTE: {NOTES[entry['name']]}")
        if entry["parent"]:
            lines.append(f"- inherits: {entry['parent']}")
        if entry["mentioned_only"]:
            lines.append(f"- parsed but unreachable ({len(entry['mentioned_only'])}): {', '.join(entry['mentioned_only'][:12])}")
        # the full missing list is the work order, so it is never truncated; the
        # informational buckets below are
        for target, members in owned.items():
            label = "missing" if len(owned) == 1 else f"missing for {target}"
            lines.append(f"- {label} ({len(members)}): {', '.join(members)}")
        for label, key in (("needs probe", "needs_probe"), ("word only", "name_only"), ("excluded chrome-only", "chrome_only"), ("excluded pref-off", "pref_off")):
            if entry[key]:
                lines.append(f"- {label} ({len(entry[key])}): {', '.join(entry[key][:30])}")
        lines.append("")
    if args.show_blocked:
        lines.append("# Gated off at interface level (not work the rules can fix)")
        lines.append("")
        for entry in sorted((r for r in report if r["blocked"]), key=lambda r: r["name"]):
            lines.append(f"- {entry['name']} [{entry['source']}]: {entry['blocked']}")
        lines.append("")
    Path(args.queue).write_text("\n".join(lines), encoding="utf-8")

    probe_path = Path(args.probe)
    if not probe_path.is_absolute():
        probe_path = ROOT / probe_path
    orders = write_work_orders(report, probe_path, Path(args.queue).parent)

    print(f"{len(report)} types, {len(live)} ungated, {len(queue)} with missing members")
    print(f"queue -> {args.queue}  detail -> {args.out}")
    if orders:
        print("work orders -> " + ", ".join(path.name for path in orders))
    else:
        print(f"work orders -> skipped, no {probe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
