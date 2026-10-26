"""Generate Firefox Domato rules from the WebIDL inventory.

This is the Firefox-only replacement for the inherited Domato rules: nothing
here is copied from Chrome-flavoured grammars, every creator and every call
comes from dom/webidl through tools/extract_idl.py. The emitter answers four
questions per member:

  reach  is the interface exposed to a content page in this build?
  gate   is a [Pref] off, a [Func]/[Trial] unproven, or a chrome-only member?
  value  can every argument type be produced from a real object graph?
  safety is the call free of prompts, native pickers and navigation?

A member is emitted only when all four answers pass. The object graph starts at
the receivers the harness really owns (window, document, navigator, the element
variables, the canvas/WebGL/WebGPU contexts) and grows through methods and
attributes that return interfaces, so `<new Foo>` never names a type that no
generated line can create.

Usage:
  python3 tools/gen_webidl_rules.py                  # regenerate every rules file
  python3 tools/gen_webidl_rules.py --dom-only
  python3 tools/gen_webidl_rules.py --graphics-only
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "domato"))

from html_tags import _HTML_TYPES  # noqa: E402
from mathml_tags import _MATHML_TYPES  # noqa: E402
from svg_tags import _SVG_TYPES  # noqa: E402


def _load_audit():
    spec = importlib.util.spec_from_file_location("_audit_rules", ROOT / "tools" / "audit_rules.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = _load_audit()

# Members that must never be generated, with the reason. Reasons are evaluated
# facts from this build, not a reading of the IDL.
DENY_INTERFACES = {
    # native UI the harness cannot answer
    "Geolocation": "getCurrentPosition/watchPosition open the location prompt",
    "PushManager": "subscribe() opens the push permission prompt",
    "Clipboard": "read/write methods open the clipboard permission prompt",
    "PaymentResponse": "only produced by a completed PaymentRequest",
    "PaymentMethodChangeEvent": "only produced by PaymentRequest",
    "PaymentRequestUpdateEvent": "only produced by PaymentRequest",
    "CredentialsContainer": "get()/create() open the WebAuthn account chooser",
    "Credential": "only produced by CredentialsContainer",
    # PublicKeyCredential itself stays: its static capability/parsing methods
    # are reachable without a credential. The instance members need an
    # authenticator and are queued as a refusal in tools/audit_rules.py.
    "AuthenticatorAssertionResponse": "only produced by CredentialsContainer",
    "AuthenticatorAttestationResponse": "only produced by CredentialsContainer",
    "AuthenticatorResponse": "only produced by CredentialsContainer",
    "Serial": "requestPort() opens the serial-port chooser",
    "SerialPort": "only produced by the serial-port chooser",
    "DocumentPictureInPicture": "requestWindow() opens a separate always-on-top window",
    # network the harness does not control
    "WebSocket": "the constructor contacts a host named by a generated string",
    "WebSocketStream": "the constructor contacts a host named by a generated string",
    "EventSource": "the constructor contacts a host named by a generated string",
    "WebTransport": "the constructor contacts a host named by a generated string",
    "WebTransportDatagramDuplexStream": "only produced by WebTransport",
    "WebTransportBidirectionalStream": "only produced by WebTransport",
    "WebTransportError": "only produced by WebTransport",
    # media negotiation the harness cannot complete
    "MediaKeys": "requires a CDM that this build does not have",
    "MediaKeySystemAccess": "requires a CDM that this build does not have",
    "MediaKeySession": "requires a CDM that this build does not have",
    "MediaKeyError": "legacy EME class with no content receiver",
    "AudioWorkletNode": "requires an AudioWorklet module the harness never loads",
    # graphics grammars own these; the DOM block must not create extra contexts
    "OffscreenCanvas": "belongs to the canvas grammar",
    "OffscreenCanvasRenderingContext2D": "belongs to the canvas grammar",
}

# Interface prefixes refused wholesale. XR needs a device; TCP sockets are
# pref-off; WebGL extensions are created by the webgl profile. RTC is not
# refused wholesale: a connection with no ICE servers and no negotiation stays
# local, and most of its objects (data channel, transceivers, senders, DTMF)
# exist without a peer. The members that need a negotiated connection are
# adjudicated in tools/audit_rules.py NOTES instead.
DENY_PREFIXES = ("XR", "TCPSocket", "TCPServerSocket", "TCPSocketErrorEvent")

# (interface, member) pairs. Attribute and method names collide across
# interfaces (close(), open(), submit()), so this is deliberately not a set of
# bare member names.
DENY_MEMBERS = {
    ("Window", "alert"): "blocking native dialog",
    ("Window", "confirm"): "blocking native dialog",
    ("Window", "prompt"): "blocking native dialog",
    ("Window", "print"): "native print dialog",
    ("Window", "printPreview"): "opens a separate print-preview window",
    ("Window", "open"): "opens a window the harness cannot close",
    ("Window", "openDialog"): "opens a window the harness cannot close",
    ("Window", "close"): "closes the test window",
    ("Window", "find"): "opens the native find bar",
    ("Window", "showOpenFilePicker"): "opens the native file picker",
    ("Window", "showSaveFilePicker"): "opens the native file picker",
    ("Window", "showDirectoryPicker"): "opens the native directory picker",
    ("Window", "getScreenDetails"): "opens the screen-selection chooser",
    ("Window", "queryLocalFonts"): "opens the font-access prompt",
    ("Window", "getVRDisplays"): "opens the VR permission prompt",
    ("Window", "requestMIDIAccess"): "opens the MIDI permission prompt",
    # FuzzingFunctions: process abort / destructive methods excluded
    ("FuzzingFunctions", "crash"): "immediately aborts the process",
    ("FuzzingFunctions", "killGPUProcess"): "kills the GPU process",
    ("FuzzingFunctions", "signalIPCReady"): "premature IPC signaling disrupts Grizzly",
    ("FuzzingFunctions", "memoryPressure"): "shrinking GC + CC on demand is not worth a fuzz line",
    # BrowserParent::RecvRequestNativeKeyBindings starts with
    # NS_ENSURE_TRUE(xpc::IsInAutomation(), IPC_FAIL(...)) and IsInAutomation()
    # needs the security.turn_off_all_security pref plus
    # MOZ_DISABLE_NONLOCAL_CONNECTIONS; Grizzly sets neither, so a Tab key press
    # ends the content process with "Exiting due to channel error"
    ("FuzzingFunctions", "synthesizeKeyboardEvents"): "IPC_FAILs the content process outside automation mode",
    # Location and History are otherwise safe receivers: the navigation
    # methods are the only members that leave the harness document.
    ("Location", "assign"): "navigates the test page",
    ("Location", "replace"): "navigates the test page",
    ("Location", "reload"): "reloads the test page",
    # the Location setters are navigations too: setting search to a random
    # string reloaded case04.html and the report never arrived (scan_cases.py)
    ("Location", "href"): "navigates the test page",
    ("Location", "protocol"): "navigates the test page",
    ("Location", "host"): "navigates the test page",
    ("Location", "hostname"): "navigates the test page",
    ("Location", "port"): "navigates the test page",
    ("Location", "pathname"): "navigates the test page",
    ("Location", "search"): "navigates the test page",
    ("History", "back"): "leaves the current document",
    ("History", "forward"): "leaves the current document",
    ("History", "go"): "leaves the current document",
    # speechSynthesis itself is a safe receiver and its voices are readable;
    # only speaking produces audible output
    ("SpeechSynthesis", "speak"): "produces audible output the harness cannot mute",
    # both accessors are stubs that always throw NS_ERROR_NOT_IMPLEMENTED
    # (SpeechGrammar.cpp), so every rule spelling it is dead text
    ("SpeechGrammar", "weight"): "getter and setter are unimplemented",
    # start() captures the default microphone and, with install-on-start on,
    # starts a speech-model download; its pending MozPromise crashed the
    # content process at shutdown (MOZ_CRASH in MozPromise::AssertIsDead).
    # install() starts that download directly.
    ("SpeechRecognition", "start"): "captures the microphone and installs a model",
    ("SpeechRecognition", "install"): "downloads a speech model",
    ("Document", "open"): "replaces the harness document",
    ("Document", "write"): "implicitly calls document.open() and wipes the page",
    ("Document", "writeln"): "implicitly calls document.open() and wipes the page",
    ("Document", "close"): "closes the document the harness is running in",
    ("Document", "execCommand"): "can drive clipboard and editing UI",
    ("Navigator", "mozGetUserMedia"): "opens the camera/microphone prompt",
    ("Navigator", "getUserMedia"): "opens the camera/microphone prompt",
    ("Navigator", "getDisplayMedia"): "opens the screen-capture prompt",
    ("MediaDevices", "getUserMedia"): "opens the camera/microphone prompt",
    ("MediaDevices", "getDisplayMedia"): "opens the screen-capture prompt",
    ("Notification", "constructor"): "the constructor raises the notification permission doorhanger",
    ("Notification", "requestPermission"): "raises the notification permission doorhanger",
    ("PaymentRequest", "show"): "opens the payment sheet",
    ("ServiceWorkerContainer", "register"): (
        "a successful registration persists in the profile and can intercept later cases"
    ),
    # Navigation methods that leave the current document. The same-document
    # fragment call lives in stateful.txt, where it can be written by hand.
    ("Navigation", "navigate"): "a generated URL would navigate the harness away; the fragment form is hand-written",
    ("Navigation", "reload"): "reloads the harness document",
    ("Navigation", "back"): "can leave the current document",
    ("Navigation", "forward"): "can leave the current document",
    ("Navigation", "traverseTo"): "can leave the current document",
    ("Navigator", "share"): "opens the native share sheet",
    ("Navigator", "requestMIDIAccess"): "opens the MIDI permission prompt",
    ("Navigator", "registerProtocolHandler"): "opens the protocol-handler doorhanger",
    ("Navigator", "requestMediaKeySystemAccess"): "requires a CDM",
    ("Element", "requestFullscreen"): "takes over the window",
    ("Element", "mozRequestFullScreen"): "takes over the window",
    ("Element", "webkitRequestFullScreen"): "takes over the window",
    ("Element", "requestPointerLock"): "captures the cursor",
    # capture only exists after a real pointerdown with that id; a synthetic
    # event does not create one, so every generated call is NotFoundError
    ("Element", "setPointerCapture"): "no active pointer with a generated id",
    ("Element", "releasePointerCapture"): "no active pointer with a generated id",
    ("HTMLElement", "click"): "runs default actions, including anchor navigation and downloads",
    ("HTMLElement", "showPicker"): "opens a native picker",
    ("HTMLInputElement", "showPicker"): "opens a native picker",
    ("HTMLSelectElement", "showPicker"): "opens a native picker",
    ("HTMLFormElement", "submit"): "navigates and reloads the harness page",
    ("HTMLFormElement", "requestSubmit"): "navigates and reloads the harness page",
    ("XMLHttpRequest", "open"): "the async argument can be false and block the page",
    ("GPUDevice", "importExternalTexture"): "Func predicate is false in this build",
    ("GPUAdapter", "missingFeatures"): "Func predicate is chrome-only",
    # creators that cannot succeed in a well-defined page state
    ("GPUAdapter", "requestDevice"): "the template already consumed this adapter, so every call throws",
    ("Document", "createCDATASection"): "HTML documents reject CDATA sections (Operation is not supported)",
    ("Document", "startViewTransition"): "the harness document is hidden, so the transition is skipped",
    ("HTMLElement", "attachInternals"): "only a custom element can have internals; the creator in _manual_creators builds one",
    # reportError() dispatches an error event with its argument, so every call
    # is an uncaught error in the harness with no generated line to blame
    ("Window", "reportError"): "reports an uncaught error outside the line guard",
    # live SVG list attributes are read-only: every mutator throws
    # "Animated values cannot be set" on the baseVal/animVal the grammar owns
    ("SVGLengthList", "appendItem"): "live animated list; mutation always throws",
    ("SVGLengthList", "clear"): "live animated list; mutation always throws",
    ("SVGLengthList", "initialize"): "live animated list; mutation always throws",
    ("SVGLengthList", "insertItemBefore"): "live animated list; mutation always throws",
    ("SVGLengthList", "removeItem"): "live animated list; mutation always throws",
    ("SVGLengthList", "replaceItem"): "live animated list; mutation always throws",
    ("SVGNumberList", "appendItem"): "live animated list; mutation always throws",
    ("SVGNumberList", "clear"): "live animated list; mutation always throws",
    ("SVGNumberList", "initialize"): "live animated list; mutation always throws",
    ("SVGNumberList", "insertItemBefore"): "live animated list; mutation always throws",
    ("SVGNumberList", "removeItem"): "live animated list; mutation always throws",
    ("SVGNumberList", "replaceItem"): "live animated list; mutation always throws",
    ("SVGPointList", "appendItem"): "live animated list; mutation always throws",
    ("SVGPointList", "clear"): "live animated list; mutation always throws",
    ("SVGPointList", "initialize"): "live animated list; mutation always throws",
    ("SVGPointList", "insertItemBefore"): "live animated list; mutation always throws",
    ("SVGPointList", "removeItem"): "live animated list; mutation always throws",
    ("SVGPointList", "replaceItem"): "live animated list; mutation always throws",
    ("SVGStringList", "appendItem"): "live animated list; mutation always throws",
    ("SVGStringList", "clear"): "live animated list; mutation always throws",
    ("SVGStringList", "initialize"): "live animated list; mutation always throws",
    ("SVGStringList", "insertItemBefore"): "live animated list; mutation always throws",
    ("SVGStringList", "removeItem"): "live animated list; mutation always throws",
    ("SVGStringList", "replaceItem"): "live animated list; mutation always throws",
    ("SVGTransformList", "appendItem"): "live animated list; mutation always throws",
    ("SVGTransformList", "clear"): "live animated list; mutation always throws",
    ("SVGTransformList", "initialize"): "live animated list; mutation always throws",
    ("SVGTransformList", "insertItemBefore"): "live animated list; mutation always throws",
    ("SVGTransformList", "removeItem"): "live animated list; mutation always throws",
    ("SVGTransformList", "replaceItem"): "live animated list; mutation always throws",
    # a MediaSource is only usable after its element fires sourceopen; the
    # harness never attaches one, so readyState stays "closed" and every
    # member below throws InvalidStateError on every call
    ("MediaSource", "addSourceBuffer"): "readyState is closed until sourceopen",
    ("MediaSource", "endOfStream"): "readyState is closed until sourceopen",
    ("MediaSource", "clearLiveSeekableRange"): "readyState is closed until sourceopen",
    ("MediaSource", "setLiveSeekableRange"): "readyState is closed until sourceopen",
    ("HTMLMediaElement", "mozGetMetadata"): "no media data is loaded, so there is no metadata",
    # popover APIs require a popover attribute and a showing/hidden state
    ("HTMLElement", "showPopover"): "element is in the no-popover state",
    ("HTMLElement", "hidePopover"): "element is in the no-popover state",
    ("HTMLElement", "togglePopover"): "element is in the no-popover state",
    # these only accept an attribute already owned by the receiver; a generated
    # Attr is always detached, so the lookup throws NotFoundError every time
    ("Element", "removeAttributeNode"): "the Attr argument never belongs to the receiver",
    ("NamedNodeMap", "removeNamedItem"): "the name never exists in the map",
    ("NamedNodeMap", "removeNamedItemNS"): "the name never exists in the map",
    # both are stubs that throw NS_ERROR_NOT_IMPLEMENTED unconditionally
    # (layout/style/typedom/CSSNumericValue.cpp), so no argument can work
    ("CSSNumericValue", "min"): "throws NS_ERROR_NOT_IMPLEMENTED for any arguments",
    ("CSSNumericValue", "max"): "throws NS_ERROR_NOT_IMPLEMENTED for any arguments",
}

# Factory calls that stay in the statement pool but must not be used as the
# way to create a variable of their return type: they depend on receiver
# state that a generated receiver rarely has, and a failed creator leaves a
# null variable that every later rule of that type inherits.
DENY_CREATORS = {
    # only specific HTML elements are shadow hosts
    ("Element", "attachShadow"),
    # a detached text node has no layout box to measure
    ("SVGTextContentElement", "getExtentOfChar"),
    ("SVGTextContentElement", "getStartPositionOfChar"),
    ("SVGTextContentElement", "getEndPositionOfChar"),
    ("SVGTextContentElement", "getRotationOfChar"),
    # list mutation on an animated attribute throws "Animated values cannot be set"
    ("SVGLengthList", "appendItem"),
    ("SVGLengthList", "insertItemBefore"),
    ("SVGLengthList", "replaceItem"),
    ("SVGLengthList", "removeItem"),
    ("SVGLengthList", "initialize"),
    ("SVGNumberList", "appendItem"),
    ("SVGNumberList", "insertItemBefore"),
    ("SVGNumberList", "replaceItem"),
    ("SVGNumberList", "removeItem"),
    ("SVGNumberList", "initialize"),
    ("SVGPointList", "appendItem"),
    ("SVGPointList", "insertItemBefore"),
    ("SVGPointList", "replaceItem"),
    ("SVGPointList", "removeItem"),
    ("SVGPointList", "initialize"),
    ("SVGTransformList", "appendItem"),
    ("SVGTransformList", "insertItemBefore"),
    ("SVGTransformList", "replaceItem"),
    ("SVGTransformList", "removeItem"),
    ("SVGTransformList", "initialize"),
    ("SVGStringList", "appendItem"),
    ("SVGStringList", "insertItemBefore"),
    ("SVGStringList", "replaceItem"),
    ("SVGStringList", "removeItem"),
    ("SVGStringList", "initialize"),
    # measuring a detached or unrendered geometry element throws "No path
    # available for measuring", and the SVGPoint variable is then null
    ("SVGGeometryElement", "getPointAtLength"),
    # the Attr returned by these only exists when the name is already present
    ("NamedNodeMap", "removeNamedItem"),
    ("NamedNodeMap", "removeNamedItemNS"),
    # only a context configured by the manual creator can hand out a texture
    ("GPUCanvasContext", "getCurrentTexture"),
    # the pooled stream may already be locked by an earlier generated line, so
    # the writer/reader creator must build its own fresh stream instead
    ("WritableStream", "getWriter"),
    ("ReadableStream", "getReader"),
    # an imported sheet's cssRules throws while it is still loading, and a
    # random CSSNumericValue is usually not convertible to px; "rules" is the
    # legacy alias of cssRules with the same loading check
    ("CSSStyleSheet", "cssRules"),
    ("CSSStyleSheet", "rules"),
    ("CSSNumericValue", "to"),
    # toSum builds a Servo SumValue, whose unit parser knows only length,
    # angle, time, number and percent: a CSS.Hz()/CSS.dpi() receiver throws
    # "Failed to create a sum value". The constructor is the reliable creator.
    ("CSSNumericValue", "toSum"),
    # a canvas transferred to an OffscreenCanvas cannot capture a stream
    ("HTMLCanvasElement", "captureStream"),
    # an animated value refuses every setter ("Animated values cannot be set");
    # the manual creator uses the writable baseVal instead
    ("SVGAnimatedPreserveAspectRatio", "animVal"),
    # even with the seeding index the selection can come up empty once the case
    # has removed the document root; Range already has a reliable supplier,
    # <Document>.createRange()
    ("Selection", "getRangeAt"),
    # the context node is the global document, so a receiver from another
    # document (a DOMParser or XSLT result) throws WrongDocumentError; the
    # manual creator and XPathEvaluator.evaluate have no such coupling
    ("Document", "evaluate"),
    # Document.getSelection is null on a document without a browsing context
    # (createHTMLDocument, evaluated); a null variable is then reused by every
    # Selection rule. document.getSelection() is the reliable creator.
    ("Document", "getSelection"),
    # a <Document> receiver from DOMParser or XSLT is an XMLDocument, where
    # createElement("audio") returns a plain Element: the typed variable would
    # have none of the HTML interface's members. The suppliers create HTML
    # elements from the global document instead.
    ("Document", "createElement"),
    # mDtmf is created only for an audio conduit: a sender built from a video
    # track (the generated addTrack) has dtmf === null. The manual creator
    # builds an audio transceiver.
    ("RTCRtpSender", "dtmf"),
    # ensureStylesheet() throws NS_ERROR_NOT_INITIALIZED on a processor with no
    # imported sheet (the zero-argument constructor, or one that ran reset());
    # Document and DocumentFragment already have reliable suppliers, and the
    # transform calls stay as statements.
    ("XSLTProcessor", "transformToDocument"),
    ("XSLTProcessor", "transformToFragment"),
    # all three throw InvalidStateError on a closed pooled connection; the
    # manual creators above build their own connection instead
    ("RTCPeerConnection", "addTrack"),
    ("RTCPeerConnection", "addTransceiver"),
    ("RTCPeerConnection", "createDataChannel"),
    # document.all is an IsHTMLDDA object: ToBoolean(document.all) is false, so
    # the harness's "if (!var) var = GetVariable(...)" fallback replaces it with
    # null and every later member read dereferences null. The stateful scenario
    # reads the collection directly instead; <Document>.all stays a statement.
    ("Document", "all"),
}

# Nullable IDL returns whose receiver always hands back a non-null object on
# this build. Every other nullable return stays refused as a creator: a failed
# factory leaves a null variable that every later rule of the type inherits.
# Verified with tools/check_reads.py on the same binary (see AGENTS.md).
NON_NULL_PRODUCERS = {
    ("Window", "performance"),
    ("Window", "indexedDB"),
    ("Window", "matchMedia"),
    ("Window", "localStorage"),
    ("Window", "sessionStorage"),
    ("Window", "getSelection"),
    ("Document", "getSelection"),
    ("Navigator", "storage"),
    ("Navigator", "mimeTypes"),
}

# Receivers that are not constructible, not returned by any IDL member, but
# exist as window globals or as the result of a plain expression. They seed the
# object graph the same way a root does, with the same weight.
EXTRA_ROOTS = {
    ("Performance", "window.performance"),
    ("Selection", "document.getSelection()"),
    ("IDBFactory", "window.indexedDB"),
    ("MediaQueryList", 'window.matchMedia("(min-width: 0px)")'),
    ("Storage", "window.localStorage"),
    ("Location", "window.location"),
    ("MimeType", "navigator.mimeTypes[0]"),
    ("HighlightRegistry", "CSS.highlights"),
    # CSSStyleProperties (the object HTMLElement.style actually returns) is a
    # generated interface outside dom/webidl, so the inventory only knows its
    # CSSStyleDeclaration base. The runtime object has every base member.
    ("CSSStyleDeclaration", 'document.createElement("div").style'),
    # callback interfaces: the page hands these to APIs as plain objects
    ("EventListener", "({ handleEvent: function(event) { } })"),
    ("NodeFilter", "({ acceptNode: function(node) { return NodeFilter.FILTER_ACCEPT; } })"),
}

# A generated line can remove document.body and document.documentElement
# (document.open, Element.remove). Re-creating a root keeps the statement in
# the live document, where Selection ranges and text layout still work; a
# detached-document body does not (evaluated: addRange then throws).
ATTACH_ROOT = (
    "(document.body || document.documentElement"
    ' || document.appendChild(document.createElement("html")))'
)

# A node whose parent is an element, not a Document/DocumentType: Range
# boundary methods reject the generated pool's Document-rooted nodes with
# InvalidNodeTypeError.
APPENDED_NODE = (
    '(function () { var n = document.createElement("div"); '
    + ATTACH_ROOT
    + ".appendChild(n); return n; })()"
)

# Members whose generated argument list must be replaced. The default mapper
# produces type-correct values, but some members need a value that is valid in
# a second sense: a selector, a URL that does not hit the network, an async XHR.
MEMBER_ARG_OVERRIDES = {
    ("Document", "createElement"): '"div"',
    ("Document", "createElementNS"): '"http://www.w3.org/1999/xhtml", "div"',
    ("Document", "querySelector"): '"div"',
    ("Document", "querySelectorAll"): '"div"',
    ("Document", "getElementById"): '"htmlvar00001"',
    ("Document", "createEvent"): '"Event"',
    ("Element", "querySelector"): '"div"',
    ("Element", "querySelectorAll"): '"div"',
    ("Element", "closest"): '"div"',
    ("Element", "matches"): '"div"',
    ("Element", "mozMatchesSelector"): '"div"',
    ("Element", "insertAdjacentHTML"): '"beforeend", "text"',
    ("XMLHttpRequest", "open"): '"GET", "fuzz", true',
    ("URL", "constructor"): '"http://127.0.0.1/fuzz", document.baseURI',
    ("Worker", "constructor"): "<WorkerURL>",
    ("SharedWorker", "constructor"): "<WorkerURL>",
    ("CSS", "supports"): '"color", "red"',
    ("CSS", "escape"): '"fuzz"',
    ("CSS", "registerProperty"): '{ name: "--fz" + <fuzzint>, syntax: "*", inherits: false }',
    # a random descriptor pairs a layout with entries it does not declare and
    # throws; an empty layout with no entries is compatible (evaluated:
    # returns a GPUBindGroup). <GPUDevice> has exactly one creator, `device`.
    ("GPUDevice", "createBindGroup"): (
        "{ layout: device.createBindGroupLayout({ entries: [] }), entries: [] }"
    ),
    # importNode(element, true) tears down the content process on this build
    # (evaluated: same-document deep import; a cross-document import works).
    # The shallow form returns a clone and is safe, but <Node> can expand to a
    # Document, which is NotSupportedError, so name a div explicitly.
    ("Document", "importNode"): 'document.createElement("div"), false',
    # a <Node> can expand to a Document, and adopting a document is
    # NotSupportedError (evaluated); a div is adoptable everywhere
    ("Document", "adoptNode"): 'document.createElement("div")',
    # a token with whitespace is InvalidCharacterError; a single token
    # exercises the list
    ("DOMTokenList", "add"): '"fuzz"',
    ("DOMTokenList", "remove"): '"fuzz"',
    ("DOMTokenList", "toggle"): '"fuzz"',
    ("DOMTokenList", "contains"): '"fuzz"',
    ("DOMTokenList", "replace"): '"fuzz", "fuzz2"',
    # version 0 is TypeError ("0 (Zero) is not a valid database version");
    # a fresh name at version 1 opens and upgrades from scratch
    ("IDBFactory", "open"): '"fuzzdb", 1',
    # a boolean or object is not a valid IndexedDB key and every method
    # validates its arguments with DataError; strings are always valid keys
    ("IDBKeyRange", "bound"): '"a", "b"',
    ("IDBKeyRange", "lowerBound"): '"fuzz"',
    ("IDBKeyRange", "only"): '"fuzz"',
    ("IDBKeyRange", "upperBound"): '"fuzz"',
    ("IDBFactory", "cmp"): '"a", "b"',
    # a custom element name needs a hyphen and a definition may not be
    # repeated, so each line uses a fresh numbered name
    ("CustomElementRegistry", "define"): '"fuzz-el" + <fuzzint>, function() { }',
    # a generated <DOMString> mark name makes measure() look up a mark that
    # does not exist ("... is not a performance mark", evaluated); both take
    # the name-only overload, which always resolves
    ("Performance", "mark"): '"fuzzmark"',
    ("Performance", "measure"): '"fuzzmeasure"',
    # challenge and user.id are base64url strings; a generated value usually
    # does not decode (EncodingError), so pass a minimal valid dictionary
    # (evaluated; the parsed options read back)
    ("PublicKeyCredential", "parseCreationOptionsFromJSON"): (
        '{ rp: { name: "fuzz" }, user: { id: "AQ", name: "fuzz", displayName: "fuzz" },'
        ' challenge: "AQ", pubKeyCredParams: [{ type: "public-key", alg: -7 }] }'
    ),
    ("PublicKeyCredential", "parseRequestOptionsFromJSON"): (
        '{ challenge: "AQ", rpId: location.hostname, allowCredentials: [] }'
    ),
    # a fresh Selection has no ranges, so any literal index is IndexSizeError;
    # the index expression seeds the selection first. documentElement can be
    # removed by the case itself; a Document is a legal Range container, so
    # select its contents when no root is left (evaluated)
    ("Selection", "getRangeAt"): (
        "(function () { var r = document.createRange();"
        " var root = document.documentElement || document.body || document;"
        " r.selectNodeContents(root);"
        " document.getSelection().addRange(r);"
        " return 0; })()"
    ),
    # the character index must lie inside the text, and a pooled text element
    # may have none; zero is valid even on an empty one (evaluated)
    ("SVGTextContentElement", "selectSubString"): "0, 0",
    # an arbitrary <Node> is not a stylesheet (compile error), and the import
    # refuses a second sheet on one processor ("We don't support importing
    # multiple stylesheets yet", NOT_IMPLEMENTED): the statement override below
    # imports into a fresh processor instead
    # factories whose generated argument was a guaranteed throw
    ("DOMImplementation", "createHTMLDocument"): "",
    ("DOMImplementation", "createDocument"): 'null, "html"',
    ("DOMImplementation", "createDocumentType"): '"fuzz", "", ""',
    ("Document", "createAttribute"): '"fuzz"',
    ("Document", "createAttributeNS"): 'null, "fuzz"',
    ("Document", "createProcessingInstruction"): '"fuzz", "fuzz"',
    ("Document", "evaluate"): '"//div", document',
    ("DOMParser", "parseFromString"): '"<lt>div<gt>fuzz<lt>/div<gt>", "text/html"',
    ("Element", "attachShadow"): '{ mode: "open" }',
    ("Element", "animate"): '[{ opacity: 0 }, { opacity: 1 }], 100',
    ("SVGGeometryElement", "getPointAtLength"): "0",
    ("SVGTextContentElement", "getStartPositionOfChar"): "0",
    ("SVGTextContentElement", "getEndPositionOfChar"): "0",
    ("SVGTransform", "setMatrixValue"): '"matrix(1, 0, 0, 1, 0, 0)"',
    ("CanvasRenderingContext2D", "createPattern"): '<HTMLCanvasElement>, "repeat"',
    ("OffscreenCanvasRenderingContext2D", "createPattern"): '<HTMLCanvasElement>, "repeat"',
    ("BaseAudioContext", "createPeriodicWave"): "[0, 1], [0, 0]",
    ("CanvasRenderingContext2D", "createLinearGradient"): "0, 0, 1, 1",
    ("CanvasRenderingContext2D", "createRadialGradient"): "0, 0, 0, 1, 1, 1",
    ("CanvasRenderingContext2D", "createConicGradient"): "0, 0, 0",
    ("CanvasRenderingContext2D", "createImageData"): "1, 1",
    # a generated index is outside numberOfOutputs; the no-argument form
    # disconnects everything and is safe on an unconnected node (evaluated)
    ("AudioNode", "disconnect"): "",
    # a generated channel number is out of range for a small buffer
    ("AudioBuffer", "copyToChannel"): "new Float32Array(4), 0",
    # a pooled track may already be attached to another sender on the same
    # connection ("This track is already set on a sender", evaluated); a fresh
    # canvas capture track is attachable
    ("RTCPeerConnection", "addTrack"): (
        "(function () { var c = document.createElement('canvas'); c.width = 2; c.height = 2;"
        " c.getContext('2d').fillRect(0, 0, 1, 1);"
        " return c.captureStream().getVideoTracks()[0]; })()"
    ),
    # a generated <fuzzfloat> radius is often negative, which every arc call
    # rejects with IndexSizeError; positive radii draw an actual path
    ("CanvasRenderingContext2D", "arc"): "1, 1, 1, 0, 6.28",
    ("CanvasRenderingContext2D", "ellipse"): "1, 1, 1, 1, 0, 0, 6.28",
    ("CanvasRenderingContext2D", "arcTo"): "0, 0, 1, 1, 1",
    ("Path2D", "arc"): "1, 1, 1, 0, 6.28",
    ("Path2D", "ellipse"): "1, 1, 1, 1, 0, 0, 6.28",
    ("Path2D", "arcTo"): "0, 0, 1, 1, 1",
    ("OffscreenCanvasRenderingContext2D", "createLinearGradient"): "0, 0, 1, 1",
    ("OffscreenCanvasRenderingContext2D", "createRadialGradient"): "0, 0, 0, 1, 1, 1",
    ("OffscreenCanvasRenderingContext2D", "createConicGradient"): "0, 0, 0",
    ("OffscreenCanvasRenderingContext2D", "createImageData"): "1, 1",
    ("OffscreenCanvasRenderingContext2D", "arc"): "1, 1, 1, 0, 6.28",
    ("OffscreenCanvasRenderingContext2D", "ellipse"): "1, 1, 1, 1, 0, 0, 6.28",
    ("OffscreenCanvasRenderingContext2D", "arcTo"): "0, 0, 1, 1, 1",
    ("TrustedTypePolicyFactory", "createPolicy"): (
        '"fuzz", { createHTML: function(s) { return s; }, createScript: function(s) { return s; },'
        " createScriptURL: function(s) { return s; } }"
    ),
    ("XPathEvaluator", "evaluate"): '"//div", document, null, 0, null',
    ("XPathExpression", "evaluate"): "document, 0, null",
    ("HTMLTableRowElement", "insertCell"): "0",
    ("HTMLTableElement", "insertRow"): "0",
    ("HTMLTableSectionElement", "insertRow"): "0",
    ("BaseAudioContext", "createDelay"): "1",
    ("BaseAudioContext", "createChannelSplitter"): "2",
    ("BaseAudioContext", "createChannelMerger"): "2",
    ("BaseAudioContext", "createBuffer"): "1, 1, 44100",
    ("HTMLCanvasElement", "captureStream"): "",
    ("CanvasRenderingContext2D", "getImageData"): "0, 0, 1, 1",
    ("OffscreenCanvasRenderingContext2D", "getImageData"): "0, 0, 1, 1",
    # enumerated string arguments that reject the generated arbitrary text
    ("Window", "postMessage"): '"fuzz", "*"',
    ("Window", "atob"): '"fuzz"',
    ("Window", "btoa"): '"fuzz"',
    ("Worker", "postMessage"): '"fuzz"',
    ("MessagePort", "postMessage"): '"fuzz"',
    ("BroadcastChannel", "postMessage"): '"fuzz"',
    ("ServiceWorker", "postMessage"): '"fuzz"',
    ("Element", "insertAdjacentElement"): '"beforeend", document.createElement("div")',
    ("Element", "insertAdjacentText"): '"beforeend", "fuzz"',
    ("Element", "setAttribute"): '"fuzz", "fuzz"',
    ("Element", "setAttributeNS"): 'null, "fuzz", "fuzz"',
    ("Element", "getAttributeNS"): 'null, "fuzz"',
    ("Element", "hasAttributeNS"): 'null, "fuzz"',
    ("Element", "removeAttributeNS"): 'null, "fuzz"',
    ("Element", "toggleAttribute"): '"fuzz"',
    ("DocumentFragment", "querySelector"): '"div"',
    ("DocumentFragment", "querySelectorAll"): '"div"',
    ("ShadowRoot", "querySelector"): '"div"',
    ("ShadowRoot", "querySelectorAll"): '"div"',
    # offsets beyond the node length throw IndexSizeError
    ("Range", "setStart"): "<Node>, 0",
    ("Range", "setEnd"): "<Node>, 0",
    ("CharacterData", "insertData"): '0, "fuzz"',
    ("CharacterData", "deleteData"): "0, 0",
    ("CharacterData", "replaceData"): '0, 0, "fuzz"',
    ("Text", "splitText"): "0",
    ("HTMLInputElement", "setRangeText"): '"fuzz", 0, 0, "end"',
    ("HTMLTextAreaElement", "setRangeText"): '"fuzz", 0, 0, "end"',
    ("HTMLTableRowElement", "deleteCell"): "0",
    ("HTMLTableElement", "deleteRow"): "0",
    ("HTMLTableSectionElement", "deleteRow"): "0",
    ("HTMLOptionsCollection", "remove"): "0",
    ("HTMLSelectElement", "remove"): "0",
    # the expression must be legal XPath; the receiver and document are fixed
    ("XPathEvaluator", "createExpression"): '"//div", null',
    ("XPathEvaluator", "createNSResolver"): "document",
    ("Document", "createExpression"): '"//div", null',
    # filter coefficients must be finite and feedforward[0] non-zero
    ("BaseAudioContext", "createIIRFilter"): "[1, 0], [1, 0]",
    ("AudioContext", "createIIRFilter"): "[1, 0], [1, 0]",
    # bufferSize must be a power of two in [256, 16384]
    ("BaseAudioContext", "createScriptProcessor"): "256, 1, 1",
    ("AudioContext", "createScriptProcessor"): "256, 1, 1",
    # CSS parsing entry points reject the arbitrary string
    ("CSSNumericValue", "parse"): '"1"',
    ("CSSNumericValue", "to"): '"px"',
    ("CSSNumericValue", "max"): "1, 2",
    ("CSSNumericValue", "min"): "1, 2",
    ("CSSNumericValue", "sum"): "1, 2",
    ("CSSStyleValue", "parse"): '"color", "red"',
    ("CSSStyleValue", "parseAll"): '"color", "red"',
    ("Window", "structuredClone"): "new ArrayBuffer(8), { transfer: [new ArrayBuffer(8)] }",
    # bufferOffset defaults to 0 and the whole view is written when the
    # independent dataOffset/size arguments are omitted
    ("GPUQueue", "writeBuffer"): "<GPUBuffer>, 0, <ArrayBuffer>",
    ("GPUComputePassEncoder", "setBindGroup"): "0, null, new Uint32Array(4), 0, 4",
    ("GPURenderPassEncoder", "setBindGroup"): "0, null, new Uint32Array(4), 0, 4",
    ("GPURenderBundleEncoder", "setBindGroup"): "0, null, new Uint32Array(4), 0, 4",
    # observe() with an omitted options dictionary throws: every flag is false
    ("MutationObserver", "observe"): "<Node>, { childList: true }",
    # an arbitrary string is not a parseable CSS rule, and an arbitrary index
    # can exceed the sheet length: use a valid rule at the insertion point
    ("CSSStyleSheet", "insertRule"): '"div { color: red; }", 0',
    # an empty MediaStream has no audio track; the destination node provides one
    ("AudioContext", "createMediaStreamSource"): (
        "new AudioContext().createMediaStreamDestination().stream"
    ),
    ("BaseAudioContext", "createMediaStreamSource"): (
        "new AudioContext().createMediaStreamDestination().stream"
    ),
    ("BaseAudioContext", "createMediaStreamTrackSource"): (
        "new AudioContext().createMediaStreamDestination().stream.getAudioTracks()[0]"
    ),
    ("TextEncoder", "encodeInto"): "new Uint8Array(8), new Uint8Array(8)",
    # negotiation: the calls resolve or reject without contacting a server, and
    # every promise gets a handler in emit_method
    ("RTCPeerConnection", "setConfiguration"): "{ iceServers: [] }",
    ("RTCPeerConnection", "addIceCandidate"): "null",
    ("RTCPeerConnection", "setRemoteDescription"): '{ type: "offer", sdp: "v=0\\r\\n" }',
    ("RTCPeerConnection", "setLocalDescription"): '{ type: "offer", sdp: "v=0\\r\\n" }',
    ("RTCPeerConnection", "addTransceiver"): '"audio"',
    ("RTCPeerConnection", "createDataChannel"): '"fuzz"',
    ("RTCPeerConnection", "addStream"): "new MediaStream()",
    ("RTCPeerConnection", "removeTrack"): "<RTCRtpSender>",
    # a property name must parse as a CSS property
    ("StylePropertyMapReadOnly", "has"): '"color"',
    ("StylePropertyMapReadOnly", "get"): '"color"',
    ("StylePropertyMapReadOnly", "getAll"): '"color"',
    # a selector must parse before it is matched
    ("Element", "webkitMatchesSelector"): '"div"',
    # AudioParam times are checked and must not be negative; exponential ramps
    # additionally require a non-zero value, and a value curve needs at least
    # two samples
    ("AudioParam", "setValueAtTime"): "1, 0.5",
    ("AudioParam", "linearRampToValueAtTime"): "1, 0.5",
    ("AudioParam", "exponentialRampToValueAtTime"): "1, 0.5",
    ("AudioParam", "setTargetAtTime"): "1, 0, 0.5",
    ("AudioParam", "setValueCurveAtTime"): "[1, 2], 0, 0.5",
    ("AudioParam", "cancelScheduledValues"): "0.5",
    ("AudioParam", "cancelAndHoldAtTime"): "0.5",
    # the text must parse as an SVG matrix
    ("DOMMatrix", "setMatrixValue"): '"matrix(1, 0, 0, 1, 0, 0)"',
    # unit type constants are 1..5 and an unknown value throws NotSupportedError
    ("SVGAngle", "convertToSpecifiedUnits"): "1",
    ("SVGAngle", "newValueSpecifiedUnits"): "1, 90",
    # the pooled Node is often the Document or a DocumentType, which these five
    # Range methods reject; an appended div always has an element parent
    ("Range", "setStartBefore"): APPENDED_NODE,
    ("Range", "setStartAfter"): APPENDED_NODE,
    ("Range", "setEndBefore"): APPENDED_NODE,
    ("Range", "setEndAfter"): APPENDED_NODE,
    ("Range", "selectNode"): APPENDED_NODE,
    # offset 84 was out of range for every receiver; 0 is valid for any node
    ("Selection", "collapse"): "<Node>, 0",
    # the receiver's text is usually shorter than the random offset
    ("CharacterData", "substringData"): "0, 1",
    # the pooled Event was already dispatched ("no longer usable"); a new one
    # must be created per call
    ("EventTarget", "dispatchEvent"): 'new Event("fuzz")',
    # observe() without an options object is a TypeError
    ("PerformanceObserver", "observe"): '{ type: "mark" }',
    # unit type constants are 1..9 (SVG_LENGTHTYPE_NUMBER is 1)
    ("SVGLength", "convertToSpecifiedUnits"): "1",
    ("SVGLength", "newValueSpecifiedUnits"): "1, 0.5",
    # the three frequency/magnitude/phase arrays must have equal lengths
    ("BiquadFilterNode", "getFrequencyResponse"): (
        "new Float32Array(8), new Float32Array(8), new Float32Array(8)"
    ),
    # a zero vector throws InvalidAccessError
    ("SVGMatrix", "rotateFromVector"): "1, 1",
    # the color must parse; arbitrary corpus text usually does not
    ("CanvasGradient", "addColorStop"): '0.5, "red"',
    # check() parses a font shorthand, and random strings throw SyntaxError
    ("FontFaceSet", "check"): '"12px serif"',
    # the generated index can exceed the sheet's rule count
    ("CSSStyleSheet", "addRule"): '"div", "color: red", 0',
    # list-valued properties only; color is not and append rejects it
    ("StylePropertyMap", "append"): '"transition-property", "opacity"',
    ("StylePropertyMap", "set"): '"color", "red"',
    ("StylePropertyMap", "get"): '"color"',
    ("StylePropertyMap", "has"): '"color"',
    ("StylePropertyMap", "delete"): '"color"',
    # a generated name is often not a valid header token (space, comma, NUL)
    # and a generated value may contain control bytes; fixed tokens always pass
    ("Headers", "append"): '"x-fuzz", "fuzz"',
    ("Headers", "set"): '"x-fuzz", "fuzz"',
    ("Headers", "get"): '"x-fuzz"',
    ("Headers", "has"): '"x-fuzz"',
    ("Headers", "delete"): '"x-fuzz"',
    # only 301/302/303/307/308 are valid statuses
    ("Response", "redirect"): '"fuzz", 302',
    # a generated status outside 200..599 is RangeError; 200 is valid
    ("Response", "json"): "1, { status: 200 }",
    # a generated absolute URL is cross-origin and throws SecurityError; an
    # empty URL leaves the current one untouched (no '#' here: Domato strips
    # everything after '#' on a rule line, even inside a string)
    ("History", "pushState"): 'null, "", ""',
    ("History", "replaceState"): 'null, "", ""',
    # a true flag requires a message; the generated anchor element is usually
    # not a shadow-including descendant of the internals host
    ("ElementInternals", "setValidity"): '{ valueMissing: true }, "fuzz"',
    # compressed formats are not valid canvas formats; the preferred format is
    ("GPUCanvasContext", "configure"): (
        "{ device: device, format: navigator.gpu.getPreferredCanvasFormat() }"
    ),
    # the callback must be callable; the generated argument was null
    ("HTMLVideoElement", "requestVideoFrameCallback"): "function() { }",
    ("Window", "requestAnimationFrame"): "function() { }",
    ("Window", "requestIdleCallback"): "function() { }",
    ("Window", "queueMicrotask"): "function() { }",
    # unsigned long, so a generated <fuzzuint> could spin the event loop for
    # ~49 days and the case would die by timeout instead of fuzzing anything
    ("FuzzingFunctions", "spinEventLoopFor"): "1",
    ("FontFaceSet", "forEach"): "function() { }",
    # a dirty rectangle with a non-positive or out-of-image size throws; the
    # three-argument form applies the whole image
    ("CanvasRenderingContext2D", "putImageData"): "<ImageData>, 0, 0",
    ("OffscreenCanvasRenderingContext2D", "putImageData"): "<ImageData>, 0, 0",
    # a negative radius throws RangeError; positive values are valid
    ("CanvasRenderingContext2D", "roundRect"): "0, 0, 10, 10, 2",
    ("OffscreenCanvasRenderingContext2D", "roundRect"): "0, 0, 10, 10, 2",
    ("Path2D", "roundRect"): "0, 0, 10, 10, 2",
    # a generated codec string is never valid; vp8 is always supported
    ("VideoDecoder", "configure"): '{ codec: "vp8" }',
    ("VideoEncoder", "configure"): '{ codec: "vp8", width: 2, height: 2 }',
    # a generated codec string or channel count is rejected; opus/48k/mono is
    # a supported configuration
    ("AudioDecoder", "configure"): (
        '{ codec: "opus", sampleRate: 48000, numberOfChannels: 1 }'
    ),
    ("AudioEncoder", "configure"): (
        '{ codec: "opus", sampleRate: 48000, numberOfChannels: 1 }'
    ),
    # the generated dictionary pairs values that violate position <= duration
    ("MediaSession", "setPositionState"): (
        "{ duration: 10, playbackRate: 1, position: 0 }"
    ),
    # an empty preference list restores the default codecs
    ("RTCRtpTransceiver", "setCodecPreferences"): "[]",
    # the callback is required and the generated one is null
    ("HTMLCanvasElement", "toBlob"): "function() { }",
    # a generated easing string is often invalid ('null') and iterations or
    # duration may be negative; a linear 100ms timing is always accepted
    ("AnimationEffect", "updateTiming"): '{ duration: 100, easing: "linear" }',
    # a random string is not a valid ByteString argument
    ("XMLHttpRequest", "getResponseHeader"): '"content-type"',
    # setKeyframes takes a sequence of keyframe objects; a scalar is TypeError
    ("KeyframeEffect", "setKeyframes"): "[{ opacity: 0 }]",
    # from() needs an (async) iterable; a plain object throws "undefined is
    # not a function" from the iterator lookup
    ("ReadableStream", "from"): "[]",
    # data: is not an accepted beacon scheme; a relative URL posts to the
    # harness server like the generated XHR lines already do
    ("Navigator", "sendBeacon"): '"fuzz", new Uint8Array(0)',
}

# Attribute setters whose generated value is rejected or destroys harness
# state. None means the setter is not emitted at all; a string replaces the
# value expression.
ATTRIBUTE_VALUE_OVERRIDES = {
    # assigning an invalid keyword to contentEditable throws SyntaxError
    ("HTMLElement", "contentEditable"): '"true"',
    # a resolved current time cannot be set back to null (TypeError); a number
    # is valid on both idle and document-timeline animations
    ("Animation", "currentTime"): "100",
    # a parsed keyword needs a non-empty value: the setter throws TypeError on
    # "" and a generated <DOMString> is empty often enough to matter
    ("CSSKeywordValue", "value"): '"fuzz"',
    # the setter accepts milliseconds in [0, 4000] or null; a random float is
    # rejected with RangeError
    ("RTCRtpReceiver", "jitterBufferTarget"): "100",
    # the setter requires readyState "open", which needs an attached media
    # element and therefore a later task; a fresh source is always closed
    ("MediaSource", "duration"): None,
    # volume and playback rates are range-checked, and a negative rate throws
    ("HTMLMediaElement", "volume"): "<float min=0 max=1>",
    ("HTMLMediaElement", "playbackRate"): "<float min=0.5 max=2>",
    ("HTMLMediaElement", "defaultPlaybackRate"): "<float min=0.5 max=2>",
    # size==0 throws IndexSizeError; every other value is accepted
    ("HTMLInputElement", "size"): "1",
    # both length setters pad the select with blank <option> children, and the
    # next innerText/appendChild then removes them one at a time, each removal
    # rescanning the options list - a generated 65535 hung a scan case before
    # its report timer ever fired
    ("HTMLOptionsCollection", "length"): "3",
    ("HTMLSelectElement", "length"): "3",
    # only a body/frameset may be assigned; the alternative loses the body
    # that every generated markup variable was read from
    ("Document", "body"): None,
    # only the three constants are valid; anything else throws SyntaxError
    ("SVGSVGElement", "zoomAndPan"): "2",
    # same for an animated enumeration: the only supplier is
    # SVGClipPathElement.clipPathUnits, where userSpaceOnUse (1) is valid
    ("SVGAnimatedEnumeration", "baseVal"): "1",
    # these parse a CSS length/angle string; arbitrary text throws SyntaxError
    ("SVGLength", "valueAsString"): '"1px"',
    ("SVGAngle", "valueAsString"): '"1deg"',
    # a curve needs at least two entries, and "custom" is not settable
    ("WaveShaperNode", "curve"): "new Float32Array([1, 1])",
    ("OscillatorNode", "type"): '"sine"',
    # pseudoElement parses as a selector and throws SyntaxError on arbitrary text
    ("KeyframeEffect", "pseudoElement"): "null",
    # WebVTT setters validate their range and throw IndexSizeError outside it
    ("VTTRegion", "lines"): "<fuzzuint>",
    ("VTTRegion", "width"): "<float min=0 max=100>",
    ("VTTRegion", "regionAnchorX"): "<float min=0 max=100>",
    ("VTTRegion", "regionAnchorY"): "<float min=0 max=100>",
    ("VTTRegion", "viewportAnchorX"): "<float min=0 max=100>",
    ("VTTRegion", "viewportAnchorY"): "<float min=0 max=100>",
    ("VTTCue", "position"): "<float min=0 max=100>",
    ("VTTCue", "size"): "<float min=0 max=100>",
    # the PannerNode distances must be non-negative, maxDistance/refDistance
    # strictly positive, and the outer gain is a unit interval
    ("PannerNode", "maxDistance"): "<float min=1 max=100>",
    ("PannerNode", "refDistance"): "<float min=1 max=100>",
    ("PannerNode", "rolloffFactor"): "<float min=0 max=10>",
    ("PannerNode", "coneOuterGain"): "<float min=0 max=1>",
    # every FontFace descriptor except family parses a specific CSS grammar
    ("FontFace", "style"): '"normal"',
    ("FontFace", "weight"): '"normal"',
    ("FontFace", "stretch"): '"normal"',
    ("FontFace", "unicodeRange"): '"U+0-7F"',
    ("FontFace", "featureSettings"): '"normal"',
    ("FontFace", "variationSettings"): '"normal"',
    ("FontFace", "display"): '"auto"',
    ("FontFace", "ascentOverride"): '"normal"',
    ("FontFace", "descentOverride"): '"normal"',
    ("FontFace", "lineGapOverride"): '"normal"',
    ("FontFace", "sizeAdjust"): '"100%"',
    # valueAsDate throws InvalidStateError on every input whose type is not
    # date/time; the setter is skipped and stateful.txt exercises it on a
    # type=date input, while the read line above still covers the member
    ("HTMLInputElement", "valueAsDate"): None,
    # these setters take a CSSNumericValue whose unit must match the property
    # (a length for translate/perspective, an angle for rotate/skew)
    ("CSSPerspective", "length"): "CSS.px(1)",
    ("CSSRotate", "angle"): "CSS.deg(0)",
    ("CSSSkewX", "ax"): "CSS.deg(0)",
    ("CSSSkewY", "ay"): "CSS.deg(0)",
    # CSSSkew has both coordinates, and each setter demands an angle, not the
    # generic scalar the attribute type (CSSNumericValue) maps to
    ("CSSSkew", "ax"): "CSS.deg(10)",
    ("CSSSkew", "ay"): "CSS.deg(20)",
    ("CSSTranslate", "x"): "CSS.px(1)",
    ("CSSTranslate", "y"): "CSS.px(1)",
    ("CSSTranslate", "z"): "CSS.px(1)",
    # only a <thead>/<tfoot> may be assigned; a generic section element (tbody)
    # is rejected
    ("HTMLTableElement", "tHead"): 'document.createElement("thead")',
    ("HTMLTableElement", "tFoot"): 'document.createElement("tfoot")',
    # a generic <DOMString> is not a font-width descriptor ("*", "0" and URLs
    # are all refused); percentages parse
    ("FontFace", "width"): '"100%"',
    # the analyser smoothing constant is a unit interval
    ("AnalyserNode", "smoothingTimeConstant"): "<float min=0 max=1>",
    # fftSize must be a power of two in [32, 32768]; a random uint is not
    ("AnalyserNode", "fftSize"): "256",
    # channelCount is validated against the destination's maxChannelCount (2
    # on the default destination), so even 0 is out of range
    ("AudioNode", "channelCount"): "1",
    # a custom property name must start with "--"
    ("CSSVariableReferenceValue", "variable"): '"--fuzz"',
    # zoomAndPan only accepts the SVG_ZOOMANDPAN constants; 2 is MAGNIFY
    ("SVGViewElement", "zoomAndPan"): "2",
    # a random string is not a valid URL; a same-origin one re-parses cleanly
    ("URL", "href"): '"http://127.0.0.1/fuzz"',
    # the setter parses a timeline range; "normal" is the only keyword that
    # needs no scroll container
    ("Animation", "rangeStart"): '"normal"',
    ("Animation", "rangeEnd"): '"normal"',
    # unsigned short enums are range-checked; align is 1..9, meetOrSlice 1..2
    ("SVGPreserveAspectRatio", "align"): "1",
    ("SVGPreserveAspectRatio", "meetOrSlice"): "1",
    # maxDecibels must stay above minDecibels and vice versa; the defaults are
    # -100 and -30, a random float can cross the other bound
    ("AnalyserNode", "minDecibels"): "-100",
    ("AnalyserNode", "maxDecibels"): "-30",
    # artwork is a sequence of MediaImage dictionaries; the generic object
    # sequence is not one, and an empty sequence is valid
    ("MediaMetadata", "artwork"): "[]",
}

# Selection methods operate on the current selection, whose range a pooled
# receiver rarely has; build a range over a fresh text node first. Evaluated:
# collapseToEnd/removeRange/extend/setPosition all succeed with this setup.
SELECTION_WITH_RANGE = (
    'var fzsn = document.createTextNode("fuzz");'
    " " + ATTACH_ROOT + ".appendChild(fzsn);"
    " var fzsr = document.createRange(); fzsr.selectNodeContents(fzsn);"
    # Document.getSelection returns null for a createHTMLDocument document
    # (evaluated), and that null becomes a pooled Selection variable
    " var fzsel = {r} || document.getSelection();"
    " fzsel.removeAllRanges(); fzsel.addRange(fzsr);"
)

# A pooled FileReader that is already LOADING refuses every readAs* call;
# abort it first so the statement always reaches the read.
FILEREADER_FREE = 'var fzfr = {r}; if (fzfr.readyState === 1) { fzfr.abort(); }'

# The char-position/extent members need laid-out SVG text; a pooled element is
# detached, so build a rendered <text> in the same line (evaluated: no throw).
SVG_TEXT_LAYOUT = (
    'var fzns = "http://www.w3.org/2000/svg";'
    ' var fzsvg = document.createElementNS(fzns, "svg");'
    ' fzsvg.setAttribute("width", "100"); fzsvg.setAttribute("height", "100");'
    ' var fztxt = document.createElementNS(fzns, "text");'
    ' fztxt.setAttribute("x", "5"); fztxt.setAttribute("y", "20");'
    ' fztxt.textContent = "fuzz"; fzsvg.appendChild(fztxt);'
    " " + ATTACH_ROOT + ".appendChild(fzsvg);"
)

# Fresh receivers for members whose argument is an index into a per-object
# array: a pooled node/buffer is the wrong shape (evaluated).
FRESH_AUDIO_BUFFER = 'var fzbuf = new AudioBuffer({ length: 16, sampleRate: 8000, numberOfChannels: 1 });'
FRESH_AUDIO_DATA = (
    "var fzad = new AudioData({ format: \"f32\", sampleRate: 8000,"
    " numberOfFrames: 4, numberOfChannels: 1, timestamp: 0, data: new Float32Array(4) });"
)
FRESH_AUDIO_GRAPH = (
    "var fzactx = new AudioContext(); var fzga = fzactx.createGain();"
    " var fzgb = fzactx.createGain();"
)
FRESH_VIDEO_FRAME = (
    'var fzcv = document.createElement("canvas"); fzcv.width = 2; fzcv.height = 2;'
    ' fzcv.getContext("2d").fillRect(0, 0, 1, 1);'
    " var fzvf = new VideoFrame(fzcv, { timestamp: 0 });"
)
# A timed animation inside a live svg: getSimpleDuration needs the duration,
# getStartTime needs a current interval (beginElement creates one).
SVG_ANIMATION = (
    'var fzns3 = "http://www.w3.org/2000/svg";'
    ' var fzsvg3 = document.createElementNS(fzns3, "svg");'
    ' var fzanim3 = document.createElementNS(fzns3, "animate");'
    ' fzanim3.setAttribute("dur", "1s");'
    ' fzanim3.setAttribute("attributeName", "x");'
    " fzsvg3.appendChild(fzanim3);" + ATTACH_ROOT + ".appendChild(fzsvg3);"
)

# A parsed XSLT stylesheet that imports and transforms on a fresh processor.
# A processor refuses a second import, and a reset or never-seeded processor
# throws NS_ERROR_NOT_INITIALIZED/NOT_IMPLEMENTED, so these statements build
# their own. Escaping is Domato's (<lt>/<gt>) plus Python's.
XSLT_STYLESHEET_DOC = (
    "new DOMParser().parseFromString("
    '"<lt>xsl:stylesheet xmlns:xsl=\\"http://www.w3.org/1999/XSL/Transform\\"'
    ' version=\\"1.0\\"<gt><lt>xsl:template match=\\"/\\"<gt><lt>out/<gt>'
    '<lt>/xsl:template<gt><lt>/xsl:stylesheet<gt>", "application/xml")'
)

# Whole-statement replacements for members whose useful call needs more than
# a fixed argument list. {r} is the generated receiver. They also replace an
# attribute's bare read line when the member is an attribute.
STATEMENT_OVERRIDES = {
    # popErrorScope on an empty stack rejects, and the rejection escapes the
    # synchronous line guard; push a scope first so the pop resolves. Bind the
    # receiver once: two <GPUDevice> placeholders may resolve to two devices.
    ("GPUDevice", "popErrorScope"): (
        'var fuzzdev = {r}; fuzzdev.pushErrorScope("validation"); await fuzzdev.popErrorScope();'
    ),
    # getMappedRange only works on a mapped buffer; create, map and read one
    # in a single self-contained statement
    ("GPUBuffer", "getMappedRange"): (
        "var fuzzmap = device.createBuffer({ size: 16, usage: GPUBufferUsage.MAP_READ });"
        " await fuzzmap.mapAsync(GPUMapMode.READ); fuzzmap.getMappedRange();"
    ),
    # the generated <GPUBuffer> may have been destroyed by an earlier line, so
    # map a fresh buffer instead of a pooled one
    ("GPUBuffer", "mapAsync"): (
        "var fuzzmap2 = device.createBuffer({ size: 16, usage: GPUBufferUsage.MAP_READ });"
        " await fuzzmap2.mapAsync(GPUMapMode.READ);"
    ),
    # a generated buffer size need not be a multiple of 4; write a 16-byte
    # buffer that matches the data
    ("GPUQueue", "writeBuffer"): (
        "var fuzzwb = device.createBuffer({ size: 16, usage: GPUBufferUsage.COPY_DST });"
        " {r}.writeBuffer(fuzzwb, 0, new Float32Array(4));"
    ),
    # stop() before start() is InvalidStateError, and a pooled source may have
    # been started by an earlier draw of this same line (lines are drawn with
    # replacement); start and stop a fresh source in one statement
    ("AudioScheduledSourceNode", "stop"): (
        "var fzsac3 = new AudioContext(); var fzsrcs = fzsac3.createBufferSource();"
        " fzsrcs.buffer = fzsac3.createBuffer(1, 1, 8000);"
        " fzsrcs.start(0); fzsrcs.stop(); fzsac3.close();"
    ),
    # deleting at index 0 from a fresh row/table/section throws IndexSizeError;
    # insert the element in the same line so there is something to delete
    ("HTMLTableRowElement", "deleteCell"): (
        "var fuzzcell = {r}.insertCell(0); fuzzcell.parentNode.deleteCell(0);"
    ),
    ("HTMLTableElement", "deleteRow"): (
        "var fuzzrow = {r}.insertRow(0); fuzzrow.parentNode.deleteRow(0);"
    ),
    ("HTMLTableSectionElement", "deleteRow"): (
        "var fuzzrow = {r}.insertRow(0); fuzzrow.parentNode.deleteRow(0);"
    ),
    # SMIL timing only works inside an SVG time container; the grammar's
    # animation elements are either detached or live under a non-SVG parent.
    # Bind the receiver once: two placeholders may resolve to two elements.
    # ATTACH_ROOT re-creates a root when the case removed the document element,
    # so there is always a live container for the svg.
    ("SVGAnimationElement", "beginElement"): (
        'var fuzzanim = {r}; var fuzzsvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");'
        " fuzzsvg.appendChild(fuzzanim);" + ATTACH_ROOT + ".appendChild(fuzzsvg);"
        " fuzzanim.beginElement();"
    ),
    ("SVGAnimationElement", "endElement"): (
        'var fuzzanim = {r}; var fuzzsvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");'
        " fuzzsvg.appendChild(fuzzanim);" + ATTACH_ROOT + ".appendChild(fuzzsvg);"
        " fuzzanim.endElement();"
    ),
    ("SVGAnimationElement", "beginElementAt"): (
        'var fuzzanim = {r}; var fuzzsvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");'
        " fuzzsvg.appendChild(fuzzanim);" + ATTACH_ROOT + ".appendChild(fuzzsvg);"
        " fuzzanim.beginElementAt(0);"
    ),
    ("SVGAnimationElement", "endElementAt"): (
        'var fuzzanim = {r}; var fuzzsvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");'
        " fuzzsvg.appendChild(fuzzanim);" + ATTACH_ROOT + ".appendChild(fuzzsvg);"
        " fuzzanim.endElementAt(0);"
    ),
    # an earlier unconfigure() line may have left the pooled context bare
    ("GPUCanvasContext", "getCurrentTexture"): (
        "var fuzzgpu = {r}; fuzzgpu.configure({ device: device,"
        ' format: navigator.gpu.getPreferredCanvasFormat() }); fuzzgpu.getCurrentTexture();'
    ),
    # the generated source object would be a plain dictionary, not a drawable,
    # and the destination texture needs COPY_DST | RENDER_ATTACHMENT usage;
    # build both in the same line (evaluated: returns without throwing)
    ("GPUQueue", "copyExternalImageToTexture"): (
        'var fuzzqc = document.createElement("canvas"); fuzzqc.width = 2; fuzzqc.height = 2;'
        ' fuzzqc.getContext("2d");'
        ' var fuzzqtex = device.createTexture({ size: [2, 2, 1], format: "rgba8unorm",'
        " usage: GPUTextureUsage.COPY_DST | GPUTextureUsage.RENDER_ATTACHMENT });"
        " {r}.copyExternalImageToTexture({ source: fuzzqc }, { texture: fuzzqtex },"
        " { width: 2, height: 2, depthOrArrayLayers: 1 });"
    ),
    # a valid shader has no messages, so the generated info object cannot
    # carry one; compile a deliberately broken module instead
    ("GPUShaderModule", "getCompilationInfo"): (
        'var fuzzbad = device.createShaderModule({ code: "fn f( {" });'
        " var fuzzci = await fuzzbad.getCompilationInfo();"
        " var fuzzmsg = fuzzci.messages[0];"
        " if (fuzzmsg) { fuzzmsg.lineNum; fuzzmsg.linePos; fuzzmsg.offset; fuzzmsg.length;"
        " fuzzmsg.message; fuzzmsg.type; }"
    ),
    # a pooled sheet imported from markup may still be loading, and every rule
    # operation then throws "Can't access rules of still-loading style sheet";
    # a constructed sheet is always ready (evaluated)
    ("CSSStyleSheet", "insertRule"): (
        'var fuzzsheet0 = new CSSStyleSheet();'
        ' fuzzsheet0.insertRule("div { color: red; }", 0);'
    ),
    ("CSSStyleSheet", "addRule"): (
        'var fuzzsheet1 = new CSSStyleSheet();'
        ' fuzzsheet1.addRule("div", "color: red", 0);'
    ),
    ("CSSStyleSheet", "cssRules"): "new CSSStyleSheet().cssRules;",
    # a sheet from document.styleSheets can be non-modifiable, and the legacy
    # rules alias and both replace entry points then throw; a constructed
    # sheet is always modifiable (evaluated)
    ("CSSStyleSheet", "rules"): "new CSSStyleSheet().rules;",
    ("CSSStyleSheet", "replaceSync"): 'new CSSStyleSheet().replaceSync("div { color: red; }");',
    ("CSSStyleSheet", "replace"): (
        'new CSSStyleSheet().replace("div { color: red; }").catch(function (e) { });'
    ),
    # deleteRule at an index past the end throws; insert the rule in the same
    # line so the delete has a target
    ("CSSStyleSheet", "deleteRule"): (
        'var fuzzsheet = new CSSStyleSheet();'
        ' fuzzsheet.insertRule("div { color: red; }", 0); fuzzsheet.deleteRule(0);'
    ),
    ("CSSStyleSheet", "removeRule"): (
        'var fuzzsheet2 = new CSSStyleSheet();'
        ' fuzzsheet2.insertRule("div { color: red; }", 0); fuzzsheet2.removeRule(0);'
    ),
    # an adopted sheet must have been constructed by the receiver's document,
    # and a pooled Document comes from DOMParser/XSLT; adopt in the global
    # document and in a shadow root that belongs to it (evaluated)
    ("Document", "adoptedStyleSheets"): (
        "document.adoptedStyleSheets = [new CSSStyleSheet()];"
        " document.adoptedStyleSheets.length;"
    ),
    ("ShadowRoot", "adoptedStyleSheets"): (
        'var fzadhost = document.createElement("div");'
        ' var fzadroot = fzadhost.attachShadow({ mode: "open" });'
        " fzadroot.adoptedStyleSheets = [new CSSStyleSheet()];"
        " fzadroot.adoptedStyleSheets.length;"
    ),
    # attachShadow only accepts a valid shadow host; a plain div always is one
    ("Element", "attachShadow"): (
        'var fuzzhost = document.createElement("div"); fuzzhost.attachShadow({ mode: "open" });'
    ),
    # stepUp/stepDown only work on number, date and time inputs; a fresh input
    # has type "text", so set a steppable type and value first
    ("HTMLInputElement", "stepUp"): (
        'var fuzznum = {r}; fuzznum.type = "number"; fuzznum.value = "1"; fuzznum.stepUp();'
    ),
    ("HTMLInputElement", "stepDown"): (
        'var fuzznum = {r}; fuzznum.type = "number"; fuzznum.value = "1"; fuzznum.stepDown();'
    ),
    # selection* throw InvalidStateError on input types that do not support
    # text selection (number, date, ...); a fresh text input does (evaluated)
    ("HTMLInputElement", "selectionStart"): (
        'var fzs1 = document.createElement("input"); fzs1.value = "fuzz"; fzs1.selectionStart = 2;'
    ),
    ("HTMLInputElement", "selectionEnd"): (
        'var fzs2 = document.createElement("input"); fzs2.value = "fuzz"; fzs2.selectionEnd = 2;'
    ),
    ("HTMLInputElement", "selectionDirection"): (
        'var fzs3 = document.createElement("input"); fzs3.value = "fuzz";'
        ' fzs3.selectionDirection = "forward";'
    ),
    ("HTMLInputElement", "setSelectionRange"): (
        'var fzs4 = document.createElement("input"); fzs4.value = "fuzz";'
        " fzs4.setSelectionRange(0, 1);"
    ),
    # abort() rejects the writer's stored closed/ready promises with its
    # reason; a later bare read of those would then be unhandled, so attach
    # handlers to the same promise objects before aborting
    ("WritableStreamDefaultWriter", "abort"): (
        "var fuzzwriter = {r}; fuzzwriter.closed.catch(function(e) { });"
        " fuzzwriter.ready.catch(function(e) { });"
        ' fuzzwriter.abort(new Error("fuzz")).catch(function(e) { });'
    ),
    # the same rejection escapes through a stream-level abort, and the pooled
    # stream may be locked by a writer whose promises cannot be reached; use a
    # fresh stream whose writer is available
    ("WritableStream", "abort"): (
        "var fuzzstream = new WritableStream(); var fuzzstreamwriter = fuzzstream.getWriter();"
        " fuzzstreamwriter.closed.catch(function(e) { });"
        " fuzzstreamwriter.ready.catch(function(e) { });"
        ' fuzzstream.abort(new Error("fuzz")).catch(function(e) { });'
    ),
    # send() and setRequestHeader() throw unless the request is OPENED, and a
    # pooled XHR may be in any state; open it in the same line
    ("XMLHttpRequest", "send"): (
        'var fuzzxhr = {r}; fuzzxhr.open("GET", "fuzz", true); fuzzxhr.send();'
    ),
    ("XMLHttpRequest", "setRequestHeader"): (
        'var fuzzxhr2 = {r}; fuzzxhr2.open("GET", "fuzz", true);'
        ' fuzzxhr2.setRequestHeader("fuzz", "fuzz");'
    ),
    # withCredentials throws while a send is in flight; a fresh request is idle
    ("XMLHttpRequest", "withCredentials"): (
        "var fuzzxhr3 = new XMLHttpRequest(); fuzzxhr3.withCredentials = false;"
    ),
    # a second getReader on a locked stream throws; only a pooled stream can be
    # locked, so fall back to a fresh one (evaluated: no throw)
    ("ReadableStream", "getReader"): (
        "var fuzzrs = {r}; if (fuzzrs.locked) { fuzzrs = new ReadableStream(); } fuzzrs.getReader();"
    ),
    # pipeThrough needs an unlocked source; a fresh pair is unlocked (evaluated)
    ("ReadableStream", "pipeThrough"): (
        "var fuzzpp = {r}; if (fuzzpp.locked) { fuzzpp = new ReadableStream(); }"
        " fuzzpp.pipeThrough({ readable: new ReadableStream(), writable: new WritableStream() });"
    ),
    # the generated sender belongs to another connection ("This sender was not
    # created by this PeerConnection"); take one from the receiver itself
    ("RTCPeerConnection", "removeTrack"): (
        'var fuzzpc = {r}; var fuzzsender = fuzzpc.addTransceiver("audio").sender;'
        " fuzzpc.removeTrack(fuzzsender);"
    ),
    # a pooled transceiver that an earlier generated stop() line left
    # stopping/stopped refuses every direction value; a fresh transceiver
    # accepts the four current directions (evaluated)
    ("RTCRtpTransceiver", "direction"): (
        'var fzrtcdir = new RTCPeerConnection();'
        ' var fzrtctr = fzrtcdir.addTransceiver("audio");'
        ' fzrtctr.direction = "sendrecv"; fzrtctr.direction; fzrtcdir.close();'
    ),
    # a close() on a pooled connection makes every later member throw "Peer
    # connection is closed"; close a throwaway connection instead (evaluated)
    ("RTCPeerConnection", "close"): (
        "var fuzzclosepc = new RTCPeerConnection(); fuzzclosepc.close();"
    ),
    # resume() throws unless the recorder is recording; the pooled one is often
    # inactive, so build a fresh recorder on a canvas stream (evaluated)
    ("MediaRecorder", "resume"): (
        'var fuzzrec = new MediaRecorder(document.createElement("canvas").captureStream(5));'
        " fuzzrec.start(); fuzzrec.resume(); fuzzrec.pause(); fuzzrec.resume(); fuzzrec.stop();"
    ),
    # start() rejects a second call on a pooled recorder that an earlier draw
    # already started
    ("MediaRecorder", "start"): (
        'var fuzzrec4 = new MediaRecorder(document.createElement("canvas").captureStream(5));'
        " fuzzrec4.start(0); fuzzrec4.stop();"
    ),
    # pause() throws unless the recorder is recording (evaluated)
    ("MediaRecorder", "pause"): (
        'var fuzzrec2 = new MediaRecorder(document.createElement("canvas").captureStream(5));'
        " fuzzrec2.start(); fuzzrec2.pause(); fuzzrec2.stop();"
    ),
    ("MediaRecorder", "requestData"): (
        'var fuzzrec3 = new MediaRecorder(document.createElement("canvas").captureStream(5));'
        " fuzzrec3.start(); fuzzrec3.requestData(); fuzzrec3.stop();"
    ),
    # the provider must be a valid domain; a random string usually is not, and
    # the failure surfaces as NS_ERROR_UNEXPECTED (evaluated: example.com ok)
    ("RTCPeerConnection", "setIdentityProvider"): (
        'var fuzzidp = new RTCPeerConnection();'
        ' fuzzidp.setIdentityProvider("example.com", { protocol: "default" });'
        " fuzzidp.close();"
    ),
    # the pooled range's boundaries can sit on a Document, which makes
    # insertNode/surroundContents throw HierarchyRequestError every time; a
    # fresh range over a text node is valid (evaluated)
    ("Range", "insertNode"): (
        'var fuzzrn = document.createTextNode("fuzz");'
        " " + ATTACH_ROOT + ".appendChild(fuzzrn);"
        " var fuzzrr = document.createRange(); fuzzrr.selectNodeContents(fuzzrn);"
        ' fuzzrr.insertNode(document.createElement("span"));'
    ),
    ("Range", "surroundContents"): (
        'var fuzzrt = document.createTextNode("fuzz");'
        " " + ATTACH_ROOT + ".appendChild(fuzzrt);"
        " var fuzzrs2 = document.createRange(); fuzzrs2.selectNodeContents(fuzzrt);"
        ' fuzzrs2.surroundContents(document.createElement("span"));'
    ),
    # the Selection singleton keeps whatever range the last line left; these
    # members throw without one (evaluated with the setup above)
    ("Selection", "extend"): SELECTION_WITH_RANGE + " fzsel.extend(fzsn, 0);",
    ("Selection", "collapseToEnd"): SELECTION_WITH_RANGE + " fzsel.collapseToEnd();",
    ("Selection", "collapseToStart"): SELECTION_WITH_RANGE + " fzsel.collapseToStart();",
    ("Selection", "removeRange"): SELECTION_WITH_RANGE + " fzsel.removeRange(fzsr);",
    ("Selection", "setPosition"): SELECTION_WITH_RANGE + " fzsel.setPosition(fzsn, 0);",
    ("Selection", "setBaseAndExtent"): (
        SELECTION_WITH_RANGE + " fzsel.setBaseAndExtent(fzsn, 0, fzsn, 0);"
    ),
    # the context node must belong to the receiver's document; a pooled
    # Document from DOMParser is not the global one (WrongDocumentError)
    ("Document", "evaluate"): (
        "var fzdx = {r};"
        ' fzdx.evaluate("//div", fzdx.documentElement || fzdx, null, 0, null);'
    ),
    # moveBefore only moves within one tree; pooled nodes come from different
    # ones. Build the parent, the moved node and the reference in the same line.
    ("Document", "moveBefore"): (
        'var fzdm = document.createComment("fuzz");'
        " var fzdoc = {r}; fzdoc.appendChild(fzdm); fzdoc.moveBefore(fzdm, null);"
    ),
    ("DocumentFragment", "moveBefore"): (
        "var fzdf = {r};"
        ' var fzda = document.createElement("span"); var fzdb = document.createElement("b");'
        " fzdf.appendChild(fzda); fzdf.appendChild(fzdb); fzdf.moveBefore(fzda, fzdb);"
    ),
    ("Element", "moveBefore"): (
        "var fzde = {r};"
        ' var fzea = document.createElement("span"); var fzeb = document.createElement("b");'
        " fzde.appendChild(fzea); fzde.appendChild(fzeb); fzde.moveBefore(fzea, fzeb);"
    ),
    # to() converts between compatible units; a pooled sum or a number has no
    # px, so use a fresh length (evaluated)
    ("CSSNumericValue", "to"): 'CSS.px(1).to("px");',
    # toSum() fails for units outside length/angle/time/number/percent; px is
    # always in the sum parser (evaluated)
    ("CSSNumericValue", "toSum"): "CSS.px(1).toSum();",
    # a pooled signal may already be aborted, and the check then throws
    ("AbortSignal", "throwIfAborted"): (
        "new AbortController().signal.throwIfAborted();"
    ),
    # a pooled reader may have been used by an earlier readAs* line; abort it
    # first (evaluated) and each call reaches the read
    ("FileReader", "readAsArrayBuffer"): FILEREADER_FREE + " fzfr.readAsArrayBuffer(new Blob([\"fuzz\"]));",
    ("FileReader", "readAsBinaryString"): FILEREADER_FREE + " fzfr.readAsBinaryString(new Blob([\"fuzz\"]));",
    ("FileReader", "readAsDataURL"): FILEREADER_FREE + " fzfr.readAsDataURL(new Blob([\"fuzz\"]));",
    ("FileReader", "readAsText"): FILEREADER_FREE + " fzfr.readAsText(new Blob([\"fuzz\"]));",
    # responseText/responseXML only read when responseType is ""/text or
    # document; a pooled XHR may have had responseType set by an earlier line
    ("XMLHttpRequest", "responseText"): (
        "var fzxrt = new XMLHttpRequest(); fzxrt.responseText;"
    ),
    ("XMLHttpRequest", "responseXML"): (
        "var fzxrx = new XMLHttpRequest(); fzxrx.responseXML;"
    ),
    # the index arguments into a pooled object point past its channels; build a
    # buffer with a known shape in the same line (evaluated)
    ("AudioBuffer", "copyFromChannel"): (
        FRESH_AUDIO_BUFFER + " fzbuf.copyFromChannel(new Float32Array(16), 0, 0);"
    ),
    ("AudioBuffer", "getChannelData"): FRESH_AUDIO_BUFFER + " fzbuf.getChannelData(0);",
    # the pooled AudioData may have a format/plane count the options reject
    ("AudioData", "allocationSize"): FRESH_AUDIO_DATA + " fzad.allocationSize({ planeIndex: 0 });",
    ("AudioData", "copyTo"): (
        FRESH_AUDIO_DATA
        + ' fzad.copyTo(new ArrayBuffer(16), { planeIndex: 0, frameOffset: 0, frameCount: 1, format: "f32" });'
    ),
    # connect's output/input indexes must exist on the destination; a fresh
    # graph has one output and one input on each gain node, and the AudioParam
    # overload is reached through gain (evaluated)
    ("AudioNode", "connect"): (
        FRESH_AUDIO_GRAPH
        + " fzga.connect(fzgb); fzga.connect(fzgb, 0, 0); fzga.connect(fzgb.gain);"
        " fzactx.close();"
    ),
    # pooled DOM nodes come from different parents, so every one of these
    # throws NotFoundError; build a parent and its children in one line
    ("Node", "insertBefore"): (
        'var fznp = document.createElement("div"); var fzna = document.createElement("span");'
        ' var fznb = document.createElement("b"); fznp.appendChild(fznb);'
        " fznp.insertBefore(fzna, fznb);"
    ),
    ("Node", "removeChild"): (
        'var fznp2 = document.createElement("div"); var fzna2 = document.createElement("span");'
        " fznp2.appendChild(fzna2); fznp2.removeChild(fzna2);"
    ),
    ("Node", "replaceChild"): (
        'var fznp3 = document.createElement("div"); var fzna3 = document.createElement("span");'
        ' var fznb3 = document.createElement("b"); fznp3.appendChild(fzna3);'
        " fznp3.replaceChild(fznb3, fzna3);"
    ),
    # the pooled track does not contain the pooled cue
    ("TextTrack", "removeCue"): (
        'var fzvid = document.createElement("video");'
        ' var fztrack = fzvid.addTextTrack("subtitles");'
        ' var fzcue = new VTTCue(0, 1, "fuzz"); fztrack.addCue(fzcue);'
        " fztrack.removeCue(fzcue);"
    ),
    # compareBoundaryPoints requires one tree and a HOW constant in 0..3
    ("Range", "compareBoundaryPoints"): (
        "var fzrc = {r}; fzrc.compareBoundaryPoints(0, fzrc);"
    ),
    ("Range", "comparePoint"): (
        'var fzcpn = document.createTextNode("fuzz");'
        " " + ATTACH_ROOT + ".appendChild(fzcpn);"
        " var fzcrp = document.createRange(); fzcrp.selectNodeContents(fzcpn);"
        " fzcrp.comparePoint(fzcpn, 0);"
    ),
    # a pooled XPathResult need not be a node result
    ("XPathResult", "singleNodeValue"): (
        'document.evaluate("//body", document, null,'
        " XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;"
    ),
    # the pooled result is an iterator (ANY_TYPE), so every snapshot/string/
    # number/boolean accessor throws "Result is not a ..."; evaluate a small
    # expression of the matching result type instead (evaluated)
    ("XPathResult", "snapshotLength"): (
        'document.evaluate("//div", document, null,'
        " XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null).snapshotLength;"
    ),
    ("XPathResult", "snapshotItem"): (
        'document.evaluate("//div", document, null,'
        " XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null).snapshotItem(0);"
    ),
    ("XPathResult", "stringValue"): (
        'document.evaluate("string(//div)", document, null,'
        " XPathResult.STRING_TYPE, null).stringValue;"
    ),
    ("XPathResult", "numberValue"): (
        'document.evaluate("count(//div)", document, null,'
        " XPathResult.NUMBER_TYPE, null).numberValue;"
    ),
    ("XPathResult", "booleanValue"): (
        'document.evaluate("boolean(//div)", document, null,'
        " XPathResult.BOOLEAN_TYPE, null).booleanValue;"
    ),
    # the generated typed array has a random length; 2D matrix init needs 6
    ("DOMMatrix", "fromFloat32Array"): (
        "DOMMatrix.fromFloat32Array(new Float32Array([1, 0, 0, 1, 0, 0]));"
    ),
    ("DOMMatrix", "fromFloat64Array"): (
        "DOMMatrix.fromFloat64Array(new Float64Array([1, 0, 0, 1, 0, 0]));"
    ),
    ("DOMMatrixReadOnly", "fromFloat32Array"): (
        "DOMMatrixReadOnly.fromFloat32Array(new Float32Array([1, 0, 0, 1, 0, 0]));"
    ),
    ("DOMMatrixReadOnly", "fromFloat64Array"): (
        "DOMMatrixReadOnly.fromFloat64Array(new Float64Array([1, 0, 0, 1, 0, 0]));"
    ),
    # getSimpleDuration throws while the duration is indefinite; set one on an
    # animation that is inside a live svg. getStartTime also needs a current
    # interval, which beginElement creates (evaluated: returns 0).
    ("SVGAnimationElement", "getSimpleDuration"): (
        SVG_ANIMATION + " fzanim3.getSimpleDuration();"
    ),
    ("SVGAnimationElement", "getStartTime"): (
        SVG_ANIMATION + " fzanim3.beginElement(); fzanim3.getStartTime();"
    ),
    # no layout information for detached text; use freshly laid-out <text>
    ("SVGTextContentElement", "getExtentOfChar"): SVG_TEXT_LAYOUT + " fztxt.getExtentOfChar(0);",
    ("SVGTextContentElement", "getStartPositionOfChar"): SVG_TEXT_LAYOUT + " fztxt.getStartPositionOfChar(0);",
    ("SVGTextContentElement", "getEndPositionOfChar"): SVG_TEXT_LAYOUT + " fztxt.getEndPositionOfChar(0);",
    ("SVGTextContentElement", "getRotationOfChar"): SVG_TEXT_LAYOUT + " fztxt.getRotationOfChar(0);",
    ("SVGTextContentElement", "getSubStringLength"): SVG_TEXT_LAYOUT + " fztxt.getSubStringLength(0, 1);",
    # consolidate() mutates the list, and the only pooled SVGTransformList is
    # an animated value ("Animated values cannot be set"); a fresh baseVal
    # list is writable (evaluated)
    ("SVGTransformList", "consolidate"): (
        'var fzcns = "http://www.w3.org/2000/svg";'
        ' var fzcsvg = document.createElementNS(fzcns, "svg");'
        " var fzcl = fzcsvg.transform.baseVal;"
        " fzcl.appendItem(fzcsvg.createSVGTransform());"
        " fzcl.consolidate();"
    ),
    # a pooled element has no parent, and the setter needs one to replace it
    ("HTMLElement", "outerText"): (
        'var fzot = document.createElement("div");'
        " " + ATTACH_ROOT + ".appendChild(fzot); fzot.outerText = \"fuzz\";"
    ),
    # valueAsNumber throws when the input's type does not support it
    ("HTMLInputElement", "valueAsNumber"): (
        'var fzni = document.createElement("input"); fzni.type = "number";'
        " fzni.valueAsNumber = 1;"
    ),
    # a pooled canvas may already have a context, after which the mozOpaque
    # setter fails; a fresh canvas accepts it (evaluated)
    ("HTMLCanvasElement", "mozOpaque"): (
        'var fzmo = document.createElement("canvas"); fzmo.mozOpaque = false;'
    ),
    # a pooled Attr is already owned by another element
    ("Element", "setAttributeNode"): (
        'var fzse = document.createElement("div");'
        ' fzse.setAttributeNode(document.createAttribute("data-fuzz"));'
    ),
    ("Element", "setAttributeNodeNS"): (
        'var fzse2 = document.createElement("div");'
        ' fzse2.setAttributeNodeNS(document.createAttributeNS("urn:x", "p:b"));'
    ),
    # a pooled Attr is already owned, so inserting it throws InUseAttributeError;
    # build an element and an unused attribute in the same statement
    ("NamedNodeMap", "setNamedItem"): (
        'var fznnm1 = document.createElement("div");'
        ' fznnm1.attributes.setNamedItem(document.createAttribute("data-fuzz"));'
    ),
    ("NamedNodeMap", "setNamedItemNS"): (
        'var fznnm2 = document.createElement("div");'
        ' fznnm2.attributes.setNamedItemNS(document.createAttributeNS("urn:x", "p:b"));'
    ),
    # the pooled frame may have been closed by a VideoFrame.close() line
    ("VideoFrame", "allocationSize"): FRESH_VIDEO_FRAME + " fzvf.allocationSize();",
    ("VideoFrame", "clone"): FRESH_VIDEO_FRAME + " fzvf.clone(); fzvf.close();",
    ("VideoFrame", "copyTo"): (
        FRESH_VIDEO_FRAME
        + " var fzvsz = fzvf.allocationSize();"
        " fzvf.copyTo(new ArrayBuffer(fzvsz)).catch(function(e) { });"
    ),
    # start() rejects a second call on the same node and a negative time
    ("AudioScheduledSourceNode", "start"): (
        "var fzsac = new AudioContext(); var fzosc = fzsac.createOscillator();"
        " fzosc.start(0); fzsac.close();"
    ),
    ("AudioBufferSourceNode", "start"): (
        "var fzsac2 = new AudioContext(); var fzbs = fzsac2.createBufferSource();"
        " fzbs.buffer = fzsac2.createBuffer(1, 1, 8000); fzbs.start(0); fzsac2.close();"
    ),
    # decode()/encode() reject an unconfigured codec, and a pooled one may be
    # closed; build, configure, run and close in one line (evaluated)
    ("AudioDecoder", "decode"): (
        "var fzadc = new AudioDecoder({ output: function() { }, error: function() { } });"
        ' fzadc.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });'
        ' fzadc.decode(new EncodedAudioChunk({ type: "key", timestamp: 0, data: new Uint8Array([1, 2, 3, 4]) }));'
        " fzadc.flush().catch(function(e) { }); fzadc.close();"
    ),
    ("AudioEncoder", "encode"): (
        "var fzaec = new AudioEncoder({ output: function() { }, error: function() { } });"
        ' fzaec.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });'
        ' fzaec.encode(new AudioData({ format: "f32", sampleRate: 48000, numberOfFrames: 4,'
        " numberOfChannels: 1, timestamp: 0, data: new Float32Array(4) }));"
        " fzaec.flush().catch(function(e) { }); fzaec.close();"
    ),
    # a pooled encoder may have been closed by an earlier line, after which
    # configure() throws "The codec is no longer usable"
    ("AudioEncoder", "configure"): (
        "var fzaec2 = new AudioEncoder({ output: function() { }, error: function() { } });"
        ' fzaec2.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });'
        " fzaec2.close();"
    ),
    ("VideoEncoder", "encode"): (
        FRESH_VIDEO_FRAME
        + " var fzvec = new VideoEncoder({ output: function() { }, error: function() { } });"
        ' fzvec.configure({ codec: "vp8", width: 2, height: 2 });'
        " fzvec.encode(fzvf); fzvec.flush().catch(function(e) { }); fzvec.close();"
    ),
    ("VideoDecoder", "decode"): (
        'var fzvdc = new VideoDecoder({ output: function() { }, error: function() { } });'
        ' fzvdc.configure({ codec: "vp8" });'
        ' fzvdc.decode(new EncodedVideoChunk({ type: "key", timestamp: 0, data: new Uint8Array([1, 2, 3, 4]) }));'
        " fzvdc.flush().catch(function(e) { }); fzvdc.close();"
    ),
    # a pooled geometry element is detached, so it has no path to measure
    ("SVGGeometryElement", "getPointAtLength"): (
        'var fzgns = "http://www.w3.org/2000/svg";'
        ' var fzgsvg = document.createElementNS(fzgns, "svg");'
        ' var fzgpath = document.createElementNS(fzgns, "path");'
        ' fzgpath.setAttribute("d", "M0 0 L10 10"); fzgsvg.appendChild(fzgpath);'
        " " + ATTACH_ROOT + ".appendChild(fzgsvg); fzgpath.getPointAtLength(0);"
    ),
    # requiredExtensions/systemLanguage start empty, so any index throws
    # "Index out of range"; the attribute fills the reflected list (evaluated)
    ("SVGStringList", "getItem"): (
        'var fzlns = "http://www.w3.org/2000/svg";'
        ' var fzlel = document.createElementNS(fzlns, "text");'
        ' fzlel.setAttribute("systemLanguage", "en");'
        " fzlel.systemLanguage.getItem(0);"
    ),
    # showModal() throws unless the dialog is connected (evaluated)
    ("HTMLDialogElement", "showModal"): (
        'var fzdlg = document.createElement("dialog");'
        " " + ATTACH_ROOT + ".appendChild(fzdlg); fzdlg.showModal(); fzdlg.close();"
    ),
    # maxLength/minLength reject each other's already-set values (a pooled
    # input with maxLength=0 rejects minLength=256); set each on a fresh
    # element (evaluated)
    ("HTMLInputElement", "maxLength"): (
        'var fzmx = document.createElement("input"); fzmx.maxLength = 10;'
    ),
    ("HTMLInputElement", "minLength"): (
        'var fzmn = document.createElement("input"); fzmn.minLength = 2;'
    ),
    ("HTMLTextAreaElement", "maxLength"): (
        'var fztx = document.createElement("textarea"); fztx.maxLength = 10;'
    ),
    ("HTMLTextAreaElement", "minLength"): (
        'var fztn = document.createElement("textarea"); fztn.minLength = 2;'
    ),
    # the pooled node may be a ChannelSplitter/Merger with a fixed count;
    # a fresh gain node accepts the setter (evaluated)
    ("AudioNode", "channelCount"): (
        "var fzcc = new AudioContext().createGain(); fzcc.channelCount = 2;"
    ),
    # a scheduled value-curve event makes every later event/value assignment
    # throw "Can't add events during a curve event"; use a fresh param
    ("AudioParam", "value"): (
        "var fzapv = new AudioContext().createGain().gain; fzapv.value = 1;"
    ),
    ("AudioParam", "setTargetAtTime"): (
        "var fzapt = new AudioContext().createGain().gain; fzapt.setTargetAtTime(1, 0, 0.5);"
    ),
    # supports() is only defined for certain reflected attributes; classList
    # (the pooled list) always throws "does not define any supported tokens"
    ("DOMTokenList", "supports"): (
        'var fzra = document.createElement("a"); fzra.rel = "noopener";'
        ' fzra.relList.supports("noopener");'
    ),
    # a pooled MediaList usually is empty, so deletion throws NotFoundError
    ("MediaList", "deleteMedium"): (
        'var fzms = new CSSStyleSheet(); fzms.media.mediaText = "screen";'
        ' fzms.media.deleteMedium("screen");'
    ),
    # a locked stream makes tee() throw; fall back to a fresh stream
    ("ReadableStream", "tee"): (
        "var fzts = {r}; if (fzts.locked) { fzts = new ReadableStream(); } fzts.tee();"
    ),
    # a pooled writer may have errored or closed, and desiredSize then throws
    # "Missing stream"; the getter works on a fresh writer (evaluated)
    ("WritableStreamDefaultWriter", "desiredSize"): (
        "new WritableStream().getWriter().desiredSize;"
    ),
    # a pooled stream may already be locked by an earlier getWriter()
    ("WritableStream", "getWriter"): "new WritableStream().getWriter();",
    # a pooled connection may have been closed by a generated close() line
    ("RTCPeerConnection", "pendingLocalDescription"): (
        "var fzpl = new RTCPeerConnection(); fzpl.pendingLocalDescription; fzpl.close();"
    ),
    ("RTCPeerConnection", "pendingRemoteDescription"): (
        "var fzpr = new RTCPeerConnection(); fzpr.pendingRemoteDescription; fzpr.close();"
    ),
    # commitStyles throws "Target is not rendered" for a detached animation
    ("Animation", "commitStyles"): (
        'var fzce = document.createElement("div");'
        " " + ATTACH_ROOT + ".appendChild(fzce);"
        ' var fzca = fzce.animate([{ opacity: 0 }], 100); fzca.commitStyles(); fzca.cancel();'
    ),
    # reverse() throws "no associated timeline" on the no-arg constructor's
    # animation (`new Animation(null, null)`); give it document.timeline
    ("Animation", "reverse"): (
        "var fzrv = new Animation(new KeyframeEffect(null,"
        " [{ opacity: 0 }, { opacity: 1 }], 100), document.timeline);"
        " fzrv.reverse(); fzrv.cancel();"
    ),
    # offsets past the text node throw IndexSizeError; a fresh text at 0 works
    ("Range", "isPointInRange"): (
        'var fzipn = document.createTextNode("fuzz");'
        " " + ATTACH_ROOT + ".appendChild(fzipn);"
        " var fzipr = document.createRange(); fzipr.selectNodeContents(fzipn);"
        " fzipr.isPointInRange(fzipn, 0);"
    ),
    # the generated ArrayBuffer is smaller than the chunk; size it exactly
    ("EncodedAudioChunk", "copyTo"): (
        'var fzeca = new EncodedAudioChunk({ type: "key", timestamp: 0,'
        " data: new Uint8Array([1, 2, 3, 4]) });"
        " fzeca.copyTo(new ArrayBuffer(fzeca.byteLength));"
    ),
    ("EncodedVideoChunk", "copyTo"): (
        'var fzevc = new EncodedVideoChunk({ type: "key", timestamp: 0,'
        " data: new Uint8Array([1, 2, 3, 4]) });"
        " fzevc.copyTo(new ArrayBuffer(fzevc.byteLength));"
    ),
    # the pooled device is shared with every other webgpu line; destroying it
    # makes all later calls fail with OperationError. An adapter can only be
    # consumed once, so request a fresh one and destroy its device.
    ("GPUDevice", "destroy"): (
        "var fuzzdev2 = await (await navigator.gpu.requestAdapter()).requestDevice();"
        " fuzzdev2.destroy();"
    ),
    # the buffer can be set once per source node; the pooled node usually had
    # one set by an earlier line, so build a source and a buffer together
    ("AudioBufferSourceNode", "buffer"): (
        "var fzabsc = new AudioContext();"
        " var fzabuf = fzabsc.createBuffer(1, 1, 48000);"
        " var fzabsn = fzabsc.createBufferSource(); fzabsn.buffer = fzabuf;"
    ),
    # setRangeText throws InvalidStateError on a non-text input type; a fresh
    # default input/textarea is always text
    ("HTMLInputElement", "setRangeText"): (
        'var fzsrt = document.createElement("input"); fzsrt.value = "fuzz";'
        ' fzsrt.setRangeText("fuzz", 0, 0, "end");'
    ),
    ("HTMLTextAreaElement", "setRangeText"): (
        'var fzsrta = document.createElement("textarea"); fzsrta.value = "fuzz";'
        ' fzsrta.setRangeText("fuzz", 0, 0, "end");'
    ),
    # a pooled iterator result is invalidated by any document mutation; a
    # fresh iterator over the current document is not
    ("XPathResult", "iterateNext"): (
        'document.evaluate("//div", document, null,'
        " XPathResult.ORDERED_NODE_ITERATOR_TYPE, null).iterateNext();"
    ),
    # close() rejects the eagerly-created completed promise and the track
    # list's ready promise (AbortError "Closed decoder"); attach both handlers
    # before closing the pooled decoder
    ("ImageDecoder", "close"): (
        "var fzidc = {r}; fzidc.completed.catch(function (e) { });"
        " fzidc.tracks.ready.catch(function (e) { }); fzidc.close();"
    ),
    # transferControlToOffscreen throws InvalidStateError once the canvas has a
    # rendering context, and a pooled canvas always has one by then; transfer
    # a fresh canvas in the same line and render on the transferred one
    ("HTMLCanvasElement", "transferControlToOffscreen"): (
        'var fuzzocc = document.createElement("canvas");'
        ' var fuzzocs = fuzzocc.transferControlToOffscreen();'
        ' fuzzocs.getContext("2d").fillRect(0, 0, 1, 1);'
    ),
    # an arbitrary <Node> is not a stylesheet (compile error), and a processor
    # refuses a second import ("We don't support importing multiple
    # stylesheets yet", NOT_IMPLEMENTED); the creator's processor already
    # imported one, so import into a fresh processor (evaluated)
    ("XSLTProcessor", "importStylesheet"): (
        "new XSLTProcessor().importStylesheet(" + XSLT_STYLESHEET_DOC + ");"
    ),
    # reset() by an earlier line leaves the pooled processor uninitialized
    # (NS_ERROR_NOT_INITIALIZED); a fresh processor seeds and transforms in the
    # same statement (evaluated, result document/fragment read back)
    ("XSLTProcessor", "transformToDocument"): (
        "var fzxtd = new XSLTProcessor();"
        " fzxtd.importStylesheet(" + XSLT_STYLESHEET_DOC + ");"
        ' fzxtd.transformToDocument(new DOMParser().parseFromString('
        '"<lt>root/<gt>", "application/xml"));'
    ),
    ("XSLTProcessor", "transformToFragment"): (
        "var fzxtf = new XSLTProcessor();"
        " fzxtf.importStylesheet(" + XSLT_STYLESHEET_DOC + ");"
        ' fzxtf.transformToFragment(new DOMParser().parseFromString('
        '"<lt>root/<gt>", "application/xml"), document);'
    ),
    # these throw InvalidStateError on a non-HTML document; the global
    # document in the harness page is always HTML
    ("Document", "queryCommandEnabled"): 'document.queryCommandEnabled("fuzz");',
    ("Document", "queryCommandIndeterm"): 'document.queryCommandIndeterm("fuzz");',
    ("Document", "queryCommandState"): 'document.queryCommandState("fuzz");',
    ("Document", "queryCommandSupported"): 'document.queryCommandSupported("fuzz");',
    ("Document", "queryCommandValue"): 'document.queryCommandValue("fuzz");',
    # a generated <Document> may be a foreign document, where every domain
    # value throws SecurityError; the global document accepts its own host
    # (evaluated)
    ("Document", "domain"): (
        "document.domain = document.location.hostname; document.domain;"
    ),
}

# A few constructors are the only way to get commonly used objects and are
# worth forcing onto a usable value.
CONSTRUCTOR_ARG_OVERRIDES = {
    "URL": '"http://127.0.0.1/fuzz", document.baseURI',
    "Worker": "<WorkerURL>",
    "SharedWorker": "<WorkerURL>",
    # Constructors whose optional dictionary is rejected when filled with the
    # generic values (bad sample rate, unknown limit key, invalid URL/method,
    # non-callable sink). The no-argument form is a valid object.
    "AudioData": '{ format: "f32", sampleRate: 8000, numberOfFrames: 4, numberOfChannels: 1, timestamp: 0, data: new Float32Array(4) }',
    # a generated <EventHandler> is a null on* read, so the required callback
    # throws Illegal constructor; the same shape broke the observers once
    "AudioDecoder": "{ output: function() { }, error: function() { } }",
    "AudioEncoder": "{ output: function() { }, error: function() { } }",
    "VideoDecoder": "{ output: function() { }, error: function() { } }",
    "VideoEncoder": "{ output: function() { }, error: function() { } }",
    # every element overload rejects an element with no decoded frame
    # (InvalidStateError: "The image's state is broken", evaluated); a painted
    # canvas is a valid source and matches the HTMLCanvasElement overload
    "VideoFrame": (
        "(function () { var c = document.createElement('canvas'); c.width = 2; c.height = 2;"
        " c.getContext('2d').fillRect(0, 0, 1, 1); return c; })(), { timestamp: 0 }"
    ),
    "EncodedAudioChunk": '{ type: "key", timestamp: 0, duration: 1000, data: new Uint8Array([1, 2, 3]) }',
    "EncodedVideoChunk": '{ type: "key", timestamp: 0, duration: 1000, data: new Uint8Array([1, 2, 3]) }',
    # a generated BufferSource is random bytes and <DOMString> is not a MIME
    # type, which the constructor rejects; decode a real 1x1 PNG instead
    "ImageDecoder": (
        '{ data: (function () { var s = atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ'
        'AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");'
        ' var u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) { u[i] = s.charCodeAt(i); }'
        ' return u; })(), type: "image/png" }'
    ),
    # the generated amount.value is an arbitrary <DOMString>, which the
    # constructor refuses; a valid decimal is required
    "PaymentRequest": (
        '[{ supportedMethods: "https://example.com/pay" }],'
        ' { total: { label: "fuzz", amount: { currency: "USD", value: "1" } } }'
    ),
    # the generated methodName is an arbitrary DOMString, and the constructor
    # validates it as a payment method identifier ("a,b" is refused, evaluated)
    "MerchantValidationEvent": '"fuzz", { methodName: "fuzz", validationURL: "https://127.0.0.1/fuzz" }',
    "AudioContext": "{}",
    "OfflineAudioContext": "1, 1, 44100",
    "FormData": "",
    "MediaStream": "",
    # a generated stream has no tracks, so start() throws "The MediaStream is
    # inactive"; a painted canvas captureStream() is live (evaluated)
    "MediaRecorder": (
        "(function () { var c = document.createElement('canvas'); c.width = 2; c.height = 2;"
        " c.getContext('2d').fillRect(0, 0, 1, 1);"
        " return c.captureStream(); })(), { mimeType: \"video/webm\" }"
    ),
    # the options require quota >= requested; the generated pair need not hold
    "QuotaExceededError": '"fuzz", { quota: 1, requested: 2 }',
    "WritableStream": "",
    "ReadableStream": "",
    "TransformStream": "",
    "Sanitizer": "",
    "Request": '"http://127.0.0.1/fuzz"',
    "DOMMatrix": "",
    "DOMMatrixReadOnly": "",
    "IntersectionObserver": "function() { }, {}",
    "ResizeObserver": "function() { }",
    "MutationObserver": "function() { }",
    # the generated <EventHandler> is a null on* read; the constructor rejects it
    "PerformanceObserver": "function() { }",
    # StaticRange validates its init: both containers must share a root and the
    # offsets must be valid boundary points, so a random <Node> pair throws
    # InvalidNodeTypeError and the variable is never created. A generated line
    # can remove the body and documentElement, so the document itself is the
    # fallback container - it is a Node, and offset 0 is valid even childless.
    "StaticRange": (
        '{ startContainer: (document.body || document.documentElement || document), startOffset: 0,'
        ' endContainer: (document.body || document.documentElement || document), endOffset: 0 }'
    ),
    # <EventHandler> is a null on* read, which the required callback rejects
    "ReportingObserver": "function() { }",
    "MediaElementAudioSourceNode": '<AudioContext>, { mediaElement: document.createElement("audio") }',
    # the stream needs an audio track; a bare new MediaStream() has none
    "MediaStreamAudioSourceNode": (
        "(function () { var ac = new AudioContext();"
        " window.__fuzzmsstream = ac.createMediaStreamDestination().stream;"
        " return ac; })(), { mediaStream: window.__fuzzmsstream }"
    ),
    "ImageData": "1, 1",
    "AudioBuffer": "{ length: 1, sampleRate: 44100 }",
    "CSSScale": "1, 1",
    # transforms take CSSNumericValue for the coordinates, not plain numbers
    "CSSTranslate": "CSS.px(1), CSS.px(1)",
    "CSSRotate": "CSS.deg(0)",
    "CSSPerspective": "CSS.px(1)",
    "CSSSkew": "CSS.deg(10), CSS.deg(20)",
    "CSSSkewX": "CSS.deg(0)",
    "CSSSkewY": "CSS.deg(0)",
    "CSSMatrixComponent": "new DOMMatrix()",
    "CSSMathMax": "1, 2",
    "CSSMathMin": "1, 2",
    "CSSMathSum": "1, 2",
    "CSSMathProduct": "1, 2",
    "CSSMathClamp": "1, 2, 3",
    "CSSMathNegate": "1",
    "CSSMathInvert": "1",
    "CSSVariableReferenceValue": '"--fuzz"',
    "CSSUnparsedValue": "[]",
    "CSSTransformValue": "[new CSSTranslate(CSS.px(1), CSS.px(1))]",
    "CSSUnitValue": '1, "px"',
    "CSSKeywordValue": '"fuzz"',
    # the constructor requires at least one entry
    "ClipboardItem": '{ "text/plain": "fuzz" }',
    # an inset string that is not a length throws; the default has none.
    # document.body/documentElement can both be removed by the case itself,
    # and a null subject is "not an object" - a detached div always exists
    "ViewTimeline": '{ subject: document.createElement("div") }',
    # a no-argument stream is not a byte stream, so a BYOB reader refuses it
    "ReadableStreamBYOBReader": 'new ReadableStream({ type: "bytes" })',
    # a negative startTime throws; the options dictionary is not worth it
    "PerformanceMark": '"fuzz"',
    "SpeechRecognitionPhrase": '"fuzz", 0.5',
    # audio nodes reject channel counts outside [1, max] and a zero delay
    "AnalyserNode": "<AudioContext>",
    "BiquadFilterNode": "<AudioContext>",
    "ChannelMergerNode": "<AudioContext>",
    "ChannelSplitterNode": "<AudioContext>",
    "ConstantSourceNode": "<AudioContext>",
    "ConvolverNode": "<AudioContext>",
    "DelayNode": "<AudioContext>",
    "DynamicsCompressorNode": "<AudioContext>",
    "GainNode": "<AudioContext>",
    "IIRFilterNode": "<AudioContext>, { feedforward: [1, 0], feedback: [1, 0] }",
    "OscillatorNode": "<AudioContext>",
    "PannerNode": "<AudioContext>",
    "StereoPannerNode": "<AudioContext>",
    "WaveShaperNode": "<AudioContext>",
    "MediaStreamAudioDestinationNode": "<AudioContext>",
    "PeriodicWave": "<AudioContext>, { real: [0, 1], imag: [0, 0] }",
    # random descriptors (style: "utf-8") make FontFace.loaded reject with a
    # SyntaxError that surfaces as an unhandled rejection
    "FontFace": '"fuzz", \'local("fuzz")\'',
    "KeyframeEffect": "null, [{ opacity: 0 }], 100",
    "VTTCue": '0, 1, "fuzz"',
    "CompressionStream": '"gzip"',
    "DecompressionStream": '"gzip"',
    # the init dictionary's promise member must be a Promise object, not the
    # generic scalar value; a resolved promise adds no unhandled rejection
    "PromiseRejectionEvent": '"fuzz", { promise: Promise.resolve(1), reason: 1 }',
    # the pattern argument must parse as a URL pattern
    "URLPattern": '"http://127.0.0.1/fuzz"',
    # a sequence initializer must be name/value pairs
    "Headers": '[["fuzz", "fuzz"]]',
    "URLSearchParams": '[["fuzz", "fuzz"]]',
    # an empty encoding label is not a recognised encoding
    "TextDecoder": '"utf-8"',
    # a generated label ("?") is rejected; utf-8 is always supported
    "TextDecoderStream": '"utf-8"',
    # the generated init can ask for status 2 or a malformed header pair
    "Response": '"fuzz"',
    # a negative originTime is outside the timeline's supported range
    "DocumentTimeline": "",
    # the constructor locks its argument, so it must get a stream of its own
    # rather than a pooled one that another line may already have locked
    "WritableStreamDefaultWriter": "new WritableStream()",
    "ReadableStreamDefaultReader": "new ReadableStream()",
    # either sdpMid or sdpMLineIndex is mandatory on this build
    "RTCIceCandidate": '{ candidate: "", sdpMid: "0" }',
    # a data channel cannot be built without a connection, and the event
    # constructor accepts one built for the purpose
    "RTCDataChannelEvent": (
        '"fuzz", { channel: new RTCPeerConnection({ iceServers: [] }).createDataChannel("fuzz") }'
    ),
    "RTCPeerConnectionIceEvent": '"fuzz", { candidate: new RTCIceCandidate({ candidate: "", sdpMid: "0" }) }',
    "RTCDTMFToneChangeEvent": '"fuzz", { tone: "1" }',
    "RTCSessionDescription": '{ type: "offer", sdp: "v=0\\r\\n" }',
    "RTCPeerConnectionIceErrorEvent": '"fuzz", { hostCandidate: "", url: "", errorCode: 0 }',
    # this build requires the track member even though the IDL marks it optional
    "RTCTrackEvent": (
        '"fuzz", (function () { var p = new RTCPeerConnection({ iceServers: [] });'
        ' var t = p.addTransceiver("audio");'
        " return { receiver: t.receiver, transceiver: t, track: t.receiver.track, streams: [] }; })()"
    ),
}

# Variadic constructors that reject an empty argument list ("Arguments can't be
# empty"), so the generic no-argument creator must not be added for them.
NO_NOARG_CONSTRUCTORS = {
    "CSSMathMax",
    "CSSMathMin",
    "CSSMathSum",
    "CSSMathProduct",
    # the empty RTCIceCandidateInit is rejected: "Either sdpMid or sdpMLineIndex
    # must be specified" (evaluated), so only the override form creates a key
    "RTCIceCandidate",
}

# getExtension() returns null for these in the built binary (probed on
# 2026-10-24 through both context names). A creator built on that return value
# silently produces a null variable, and every rule of the interface then
# dereferences null. Re-probe after swapping the Firefox build.
ABSENT_WEBGL_EXTENSIONS = {
    "OVR_multiview2",
    "WEBGL_compressed_texture_etc1",
    "WEBGL_compressed_texture_pvrtc",
    "WEBGL_explicit_present",
    "WEBGL_provoking_vertex",
}

# Type spellings that are typedef'ed in Firefox IDL but that the generic
# mapper must know before the typedef table is consulted.
SCALARS = {
    "boolean": "<boolean>",
    "byte": "<fuzzint>",
    "octet": "<fuzzuint>",
    "short": "<fuzzint>",
    "unsigned short": "<fuzzuint>",
    "long": "<fuzzint>",
    "unsigned long": "<fuzzuint>",
    "long long": "<fuzzint>",
    "unsigned long long": "<fuzzuint>",
    "int64_t": "<fuzzint>",
    "uint64_t": "<fuzzuint>",
    "float": "<float32>",
    "unrestricted float": "<fuzzfloat>",
    "double": "<finitefloat>",
    "unrestricted double": "<fuzzfloat>",
    "bigint": "<bigint>",
    "DOMString": "<DOMString>",
    "USVString": "<DOMString>",
    "ByteString": "<DOMString>",
    "UTF8String": "<DOMString>",
    "CSSOMString": "<DOMString>",
    "any": "<anyvalue>",
    "object": "<anyvalue>",
    "ArrayBuffer": "<ArrayBuffer>",
    "SharedArrayBuffer": "<ArrayBuffer>",
    "ArrayBufferView": "<Uint8Array>",
    "BufferSource": "<ArrayBuffer>",
    "Uint8Array": "<Uint8Array>",
    "Uint8ClampedArray": "<Uint8Array>",
    "Uint16Array": "<Uint16Array>",
    "Uint32Array": "<Uint32Array>",
    "Int8Array": "<Int8Array>",
    "Int16Array": "<Int16Array>",
    "Int32Array": "<Int32Array>",
    "Float32Array": "<Float32Array>",
    "Float64Array": "<Float64Array>",
    "DataView": "<DataView>",
    "Date": "<date>",
    "RegExp": "<regexp>",
    "Error": "new Error(<DOMString>)",
    "DOMException": "new DOMException(<DOMString>)",
}


def scalar_symbol(name: str, obtainable: set[str]) -> str | None:
    if name in SCALARS:
        return SCALARS[name]
    if name == "WindowProxy":
        return "<Window>" if "Window" in obtainable else None
    if name.endswith("Callback") or name.endswith("Handler") or name.endswith("Function"):
        return "<EventHandler>"
    return None


def js_string(value: str) -> str:
    """A JS string literal that Domato will not read as a tag or a comment."""
    text = json.dumps(value, ensure_ascii=False)
    return text.replace("#", "<hash>").replace("<", "<lt>")


def exposed_member_name(member: str) -> str:
    # WebIDL removes a leading underscore from the identifier it exposes:
    # IDL `_any` and `_includes` are the page-visible `any` and `includes`
    return member[1:] if member.startswith("_") else member


def domato_text(value: str) -> str:
    """Any generated literal: never leave a bare < or # for the parser."""
    return value.replace("#", "<hash>").replace("<", "<lt>")


def split_word(text: str, word: str) -> list[str]:
    parts, depth, start, quote = [], 0, 0, None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote and text[index - 1] != "\\":
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "<([{":
            depth += 1
        elif char in ">)]}":
            depth -= 1
        elif depth == 0 and text.startswith(word, index):
            parts.append(text[start:index])
            start = index + len(word)
            index = start
            continue
        index += 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def split_top(text: str, separator: str = ",") -> list[str]:
    parts, depth, start, quote = [], 0, 0, None
    for index, char in enumerate(text):
        if quote:
            if char == quote and text[index - 1] != "\\":
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "<([{":
            depth += 1
        elif char in ">)]}":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


class Emitter:
    def __init__(self, types: dict, prefs: dict, fuzzing: dict, probe: dict | None, profile: str):
        self.types = types
        self.prefs = prefs
        self.fuzzing = fuzzing
        self.probe = probe or {}
        self.profile = profile
        self.obtainable: set[str] = set()
        self.creator_rules: dict[str, list[str]] = {}
        self.creator_seen: set[str] = set()
        self.value_rules: dict[str, list[tuple[str, float]]] = {}
        self.value_seen: set[str] = set()
        self.lines: list[str] = []
        self.line_seen: set[str] = set()
        self.enum_done: set[str] = set()
        self.dict_done: dict[str, str | None] = {}
        self.dict_active: set[str] = set()
        self.present: set[tuple[str, str]] = set()
        for row in self.probe.get("probed", ()):
            if str(row.get("state", "")).startswith("present:"):
                self.present.add((row["iface"], row["member"]))
        self.deny_members = dict(DENY_MEMBERS)
        self.suppliers = self._suppliers()
        self.func_allow = self._func_allow()
        self.roots = self._roots()
        self.manual_creators = self._manual_creators()

    # ------------------------------------------------------------------ gates

    def _func_allow(self) -> set[str]:
        if self.profile == "webgpu":
            # probe_apis.py verified navigator.gpu, requestAdapter and
            # requestDevice on this build, so this predicate is true here.
            return {"mozilla::webgpu::Instance::PrefEnabled"}
        if self.profile == "dom":
            # Each predicate below was answered by probe_apis.py on this build:
            # every member recorded in results/audit/probe.json for these
            # interfaces came back present, so the C++ gate is open under
            # Grizzly's prefs. The members that open a prompt or leave the
            # document are refused separately in DENY_MEMBERS.
            return {
                "nsRFPService::ExposeWebCodecsAPI",
                "nsRFPService::ExposeWebCodecsAPIImageDecoder",
                "mozilla::dom::CSS::IsEnabled",
                "cache::Cache::CachesEnabled",
                "cache::CacheStorage::CachesEnabled",
                "nsGlobalWindowInner::DeviceSensorsEnabled",
                "mozilla::dom::VideoFrame::PrefEnabled",
                "Navigator::HasUserMediaSupport",
                "Navigation::IsAPIEnabled",
                "mozilla::dom::PaymentRequest::PrefEnabled",
                "mozilla::dom::Notification::PrefEnabled",
                "ServiceWorkersEnabled",
            }
        return set()

    def interface_usable(self, name: str) -> bool:
        entry = self.types.get(name)
        if entry is None or entry["kind"] not in ("interface", "namespace", "callback interface"):
            return False
        if name in DENY_INTERFACES or name.startswith(DENY_PREFIXES):
            return False
        if AUDIT.gate_reason(entry, self.prefs, self.fuzzing) is not None:
            return False
        attrs = entry["attrs"]
        if attrs.get("MozSystem") or attrs.get("ChromeOnly") or attrs.get("SystemPrincipal"):
            return False
        funcs = attrs.get("Func")
        if funcs:
            values = funcs if isinstance(funcs, list) else [funcs]
            if any(value not in self.func_allow for value in values):
                return False
        if attrs.get("Trial"):
            return False
        return True

    def member_usable(self, iface: str, member: str, slot: dict) -> bool:
        if (iface, member) in self.deny_members:
            return False
        attrs = slot["attrs"]
        if any(key in attrs for key in ("SystemPrincipal", "ChromeOnly", "MozSystem")):
            return False
        if attrs.get("Pref"):
            values = attrs["Pref"] if isinstance(attrs["Pref"], list) else [attrs["Pref"]]
            if not any(AUDIT.pref_enabled(value, self.prefs, self.fuzzing) for value in values if value):
                return False
        if attrs.get("Func") or attrs.get("Trial"):
            return (iface, member) in self.present
        return True

    def in_profile(self, name: str) -> bool:
        if self.profile == "dom":
            return not self._graphics_name(name)
        if self.profile == "canvas":
            return bool(re.match(
                r"^(CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D|OffscreenCanvas|CanvasGradient"
                r"|CanvasPattern|Path2D|ImageData|ImageBitmap|TextMetrics|DOMMatrix|DOMMatrixReadOnly"
                r"|DOMPoint|DOMPointReadOnly|DOMRect|DOMRectReadOnly|DOMQuad|CanvasDrawContext)$",
                name,
            ))
        if self.profile == "webgl":
            return bool(re.match(r"^(WebGL|EXT_|OES_|WEBGL_|ANGLE_|MOZ_|OVR_)", name))
        if self.profile == "webgpu":
            return name.startswith("GPU")
        return False

    @staticmethod
    def _graphics_name(name: str) -> bool:
        return bool(re.match(
            r"^(GPU|WebGL|EXT_|OES_|WEBGL_|ANGLE_|MOZ_WEBGL|OVR_"
            r"|CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D|Path2D|ImageData"
            r"|ImageBitmap|TextMetrics|CanvasGradient|CanvasPattern|DOMMatrix|DOMMatrixReadOnly"
            r"|DOMPoint|DOMPointReadOnly|DOMRect|DOMRectReadOnly|DOMQuad)$",
            name,
        ))

    # ----------------------------------------------------------------- profile

    def _roots(self) -> list[tuple[str, str]]:
        if self.profile == "dom":
            return [
                ("Window", "window"),
                ("Document", "window.document"),
                ("Navigator", "navigator"),
            ]
        if self.profile == "canvas":
            return [
                ("CanvasRenderingContext2D", "ctx"),
                ("HTMLCanvasElement", 'document.createElement("canvas")'),
                ("OffscreenCanvas", "new OffscreenCanvas(1, 1)"),
                ("OffscreenCanvasRenderingContext2D", '<OffscreenCanvas>.getContext("2d")'),
            ]
        if self.profile == "webgl":
            return [
                ("WebGLRenderingContext", "gl1"),
                ("WebGLRenderingContext", "glw1"),
                ("WebGL2RenderingContext", "gl"),
                ("WebGL2RenderingContext", "glx"),
                ("WebGLRenderingContext", "glx"),
                ("HTMLCanvasElement", 'document.createElement("canvas")'),
                ("ImageData", "new ImageData(1, 1)"),
            ]
        if self.profile == "webgpu":
            roots = [
                ("GPU", "navigator.gpu"),
                ("GPUAdapter", "adapter"),
                ("GPUDevice", "device"),
                ("GPUQueue", "device.queue"),
                ("GPUSupportedFeatures", "device.features"),
                ("GPUSupportedLimits", "device.limits"),
                ("GPUAdapterInfo", "adapter.info"),
                (
                    "GPUCanvasContext",
                    '(function () { var c = document.createElement("canvas"); var g = c.getContext("webgpu");'
                    " g.configure({ device: device, format: navigator.gpu.getPreferredCanvasFormat() });"
                    " return g; })()",
                ),
            ]
            roots += [("GPUShaderModule", f"Shader{index}") for index in range(10)]
            return roots
        return []

    def _suppliers(self) -> list[tuple[str, str]]:
        if self.profile != "dom":
            return []
        suppliers = [
            ("DocumentFragment", "<Document>.createDocumentFragment()"),
            ("Text", "<Document>.createTextNode(<DOMString>)"),
            ("Comment", "<Document>.createComment(<DOMString>)"),
            ("Range", "<Document>.createRange()"),
            ("NodeIterator", "<Document>.createNodeIterator(<Element>)"),
            ("TreeWalker", "<Document>.createTreeWalker(<Element>)"),
            ("DOMParser", "new DOMParser()"),
            ("XMLSerializer", "new XMLSerializer()"),
            ("DOMImplementation", "<Document>.implementation"),
            # createElement on an XMLDocument (DOMParser, XSLT output) builds a
            # plain Element whatever the tag is, so a variable typed
            # HTMLAudioElement would have no HTMLMediaElement members at all;
            # the global document is always an HTML document (evaluated)
            ("Element", 'document.createElement("div")'),
            ("HTMLElement", 'document.createElement("div")'),
            ("Node", 'document.createElement("div")'),
            ("EventTarget", "<Document>"),
            ("SVGElement", '<Document>.createElementNS("http://www.w3.org/2000/svg", "svg")'),
            ("SVGSVGElement", '<Document>.createElementNS("http://www.w3.org/2000/svg", "svg")'),
            ("MathMLElement", '<Document>.createElementNS("http://www.w3.org/1998/Math/MathML", "math")'),
        ]
        seen = {name for name, _ in suppliers}
        representatives: dict[str, str] = {}
        for tag, tag_type in sorted(_HTML_TYPES.items()):
            # createElement("image") returns an HTMLUnknownElement - the
            # parser's image->img alias does not apply to createElement - so
            # the variable would be typed HTMLImageElement and have no decode()
            if tag == "image":
                continue
            representatives.setdefault(tag_type, tag)
        for tag, tag_type in sorted(_SVG_TYPES.items()):
            representatives.setdefault(tag_type, tag)
        for tag_type, tag in representatives.items():
            if tag_type in seen or tag_type not in self.types:
                continue
            if tag_type in _SVG_TYPES.values():
                ns = "http://www.w3.org/2000/svg"
            elif tag_type in _MATHML_TYPES.values():
                ns = "http://www.w3.org/1998/Math/MathML"
            else:
                ns = None
            if ns:
                suppliers.append((tag_type, f'<Document>.createElementNS("{ns}", "{tag}")'))
            else:
                # same XMLDocument trap as the generic Element supplier above
                suppliers.append((tag_type, f'document.createElement("{tag}")'))
            seen.add(tag_type)
        return suppliers

    def _manual_creators(self) -> list[tuple[str, str]]:
        if self.profile == "dom":
            creators = [
                # attachShadow only works on a shadow host; attachInternals
                # only on an upgraded custom element. Both need a receiver
                # built for the purpose, not a random element variable.
                # The harness document is the literal global: a generated
                # <Document> variable may belong to another window and then
                # customElements.define throws or createElement is missing.
                ("ShadowRoot", 'document.createElement("div").attachShadow({ mode: "open" })'),
                (
                    "ElementInternals",
                    '(customElements.get("fuzz-el") || customElements.define("fuzz-el",'
                    " class extends HTMLElement { static formAssociated = true; }),"
                    ' document.createElement("fuzz-el").attachInternals())',
                ),
                ("XPathResult", 'document.evaluate("//div", document, null, XPathResult.ANY_TYPE, null)'),
                ("Attr", 'document.createAttribute("fuzz")'),
                ("DocumentFragment", "document.createDocumentFragment()"),
                # the discovered creator is .animVal, whose setters always throw
                # "Animated values cannot be set"; baseVal is writable
                (
                    "SVGPreserveAspectRatio",
                    '<SVGSVGElement>.preserveAspectRatio.baseVal',
                ),
                # the generated Node argument is never a stylesheet, so the
                # creator imports a real one; every later transform call on
                # this processor then has a sheet to work with
                (
                    "XSLTProcessor",
                    '(function () { var p = new XSLTProcessor();'
                    ' p.importStylesheet(new DOMParser().parseFromString('
                    '"<lt>xsl:stylesheet xmlns:xsl=\\"http://www.w3.org/1999/XSL/Transform\\"'
                    ' version=\\"1.0\\"<gt><lt>xsl:template match=\\"/\\"<gt><lt>out/<gt>'
                    '<lt>/xsl:template<gt><lt>/xsl:stylesheet<gt>", "application/xml"));'
                    " return p; })()",
                ),
                # only an audio sender has a DTMF sender (a video sender's
                # .dtmf is null); an unnegotiated one cannot insertDTMF, which
                # is a caught InvalidStateError rather than a dead variable
                (
                    "RTCDTMFSender",
                    "(function () { var pc = new RTCPeerConnection();"
                    ' return pc.addTransceiver("audio").sender.dtmf; })()',
                ),
                # a pooled <RTCPeerConnection> may have been closed by an
                # earlier line ("Peer connection is closed"); these build their
                # own, and the sender/transceiver keeps the connection alive
                (
                    "RTCRtpSender",
                    '(function () { var pc = new RTCPeerConnection();'
                    ' var c = document.createElement("canvas"); c.width = 2; c.height = 2;'
                    ' c.getContext("2d").fillRect(0, 0, 1, 1);'
                    " return pc.addTrack(c.captureStream().getVideoTracks()[0]); })()",
                ),
                (
                    "RTCRtpTransceiver",
                    '(function () { var pc = new RTCPeerConnection();'
                    ' return pc.addTransceiver("audio"); })()',
                ),
                # same closed-connection trap as the sender; the channel keeps
                # its connection reachable for the lifetime of the variable
                (
                    "RTCDataChannel",
                    '(function () { var pc = new RTCPeerConnection();'
                    ' return pc.createDataChannel("fuzz"); })()',
                ),
            ]
            svg_values = {
                "SVGAngle": "createSVGAngle",
                "SVGLength": "createSVGLength",
                "SVGMatrix": "createSVGMatrix",
                "SVGNumber": "createSVGNumber",
                "SVGPoint": "createSVGPoint",
                "SVGRect": "createSVGRect",
                "SVGTransform": "createSVGTransform",
            }
            for name, factory in svg_values.items():
                if name in self.types:
                    creators.append((name, f"<SVGSVGElement>.{factory}()"))
            return creators
        if self.profile == "webgpu":
            return [
                # createTexture from the device does not depend on whether a
                # canvas context was configured first.
                ("GPUTexture", "<GPUDevice>.createTexture(<GPUTextureDescriptor>)"),
            ]
        if self.profile != "webgl":
            return []
        # Every WebGL extension interface the inventory knows about, created on
        # a context that is expected to expose it. WEBGL_lose_context gets the
        # throwaway context: losing a shared one silences the rest of the block.
        creators = []
        for name in sorted(self.types):
            entry = self.types[name]
            if entry["kind"] != "interface" or not self.in_profile(name):
                continue
            if not name.startswith(("EXT_", "OES_", "WEBGL_", "ANGLE_", "MOZ_", "OVR_")):
                continue
            if name in ABSENT_WEBGL_EXTENSIONS:
                continue
            if name == "WEBGL_lose_context":
                creators.append((name, f'glx.getExtension("{name}")'))
            else:
                # gl1 is the WebGL2 context; ANGLE_instanced_arrays,
                # OES_vertex_array_object and WEBGL_draw_buffers only exist on
                # the WebGL1 context glw1, so try that one first.
                creators.append((name, f'(glw1.getExtension("{name}") || gl1.getExtension("{name}"))'))
        creators += [
            ("WebGLShader", "vShader3"),
            ("WebGLShader", "fShader3"),
            ("WebGLProgram", "program1"),
            ("WebGLTexture", "tex1"),
            ("WebGLBuffer", "buffer1"),
        ]
        return creators

    # ----------------------------------------------------------------- values

    def peel(self, type_text: str, depth: int = 0):
        """(kind, payload, nullable) for a WebIDL type spelling."""
        text = re.sub(r"\s+", " ", type_text.strip())
        nullable = False
        if text.endswith("?"):
            nullable = True
            text = text[:-1].strip()
        if text.startswith("(") and text.endswith(")"):
            parts = split_word(text[1:-1], "or")
            if len(parts) > 1:
                return "union", parts, nullable
        for prefix in ("sequence<", "FrozenArray<", "ObservableArray<"):
            if text.startswith(prefix) and text.endswith(">"):
                return "sequence", text[len(prefix):-1].strip(), nullable
        if text.startswith("record<") and text.endswith(">"):
            parts = split_top(text[7:-1])
            if len(parts) == 2:
                return "record", (parts[0].strip(), parts[1].strip()), nullable
        if text.startswith("Promise<") and text.endswith(">"):
            return "promise", text[8:-1].strip(), nullable
        entry = self.types.get(text)
        if entry is not None and depth < 12:
            kind = entry["kind"]
            if kind == "typedef" and entry.get("typedef_type") and entry["typedef_type"] != "callback":
                inner_kind, payload, inner_nullable = self.peel(entry["typedef_type"], depth + 1)
                return inner_kind, payload, nullable or inner_nullable
            if kind == "callback":
                return "callback", text, nullable
            if kind == "callback interface":
                return "callback", text, nullable
            if kind == "enum":
                return "enum", text, nullable
            if kind == "dictionary":
                return "dictionary", text, nullable
            if kind in ("interface", "namespace"):
                return "interface", text, nullable
        return "scalar", text, nullable

    def value_for(self, type_text: str, created: str | None = None, depth: int = 0) -> str | None:
        if depth > 6:
            return None
        kind, payload, nullable = self.peel(type_text)
        if kind == "callback":
            return "<EventHandler>"
        if kind == "scalar":
            expr = scalar_symbol(payload, self.obtainable)
            return expr
        if kind == "enum":
            expr = self.enum_symbol(payload)
            return expr
        if kind == "dictionary":
            expr = self.dict_symbol(payload, depth)
            if expr is None:
                return None
            return self.optional_symbol(type_text, expr) if nullable else expr
        if kind == "interface":
            name = payload
            if name == created:
                return "null" if nullable else None
            if name not in self.obtainable or not self.interface_usable(name):
                return "null" if nullable else None
            expr = f"<{name}>"
            return self.optional_symbol(type_text, expr) if nullable else expr
        if kind == "sequence":
            element = self.value_for(payload, created, depth + 1)
            rules = [("[]", 1.0)]
            if element is not None:
                rules.append((f"[{element}]", 3.0))
            return self.synth("seq", type_text, rules)
        if kind == "record":
            key_type, value_type = payload
            value = self.value_for(value_type, created, depth + 1)
            key = self.record_key(key_type)
            if key is None or value is None:
                return "{}"
            return self.synth(
                "rec", type_text, [("{}", 1.0), ("{ " + js_string(key) + ": " + value + " }", 3.0)]
            )
        if kind == "union":
            # Prefer a scalar/enum/dictionary member over an interface one:
            # (TrustedHTML or DOMString) must produce text, not a detached
            # Trusted Types object, and DOMString is always convertible.
            ordered = sorted(
                enumerate(payload),
                key=lambda item: (self.peel(item[1])[0] == "interface", item[0]),
            )
            for _, part in ordered:
                expr = self.value_for(part, created, depth + 1)
                if expr is not None:
                    if nullable:
                        return self.optional_symbol(type_text, expr)
                    return expr
            return None
        if kind == "promise":
            return None
        return None

    def record_key(self, type_text: str) -> str | None:
        kind, payload, _ = self.peel(type_text)
        if kind == "enum":
            values = self.types.get(payload, {}).get("values", ())
            return values[0] if values else None
        if kind == "scalar" and payload in ("DOMString", "USVString", "ByteString", "UTF8String", "CSSOMString"):
            return "key"
        return None

    def enum_symbol(self, name: str) -> str | None:
        entry = self.types.get(name)
        if entry is None or not entry.get("values"):
            return None
        if name not in self.enum_done:
            self.enum_done.add(name)
            for value in entry["values"]:
                self.add_value_rule(name, js_string(value), 1.0)
        return f"<{name}>"

    def dict_symbol(self, name: str, depth: int = 0) -> str | None:
        if name in self.dict_done:
            return f"<{name}>" if self.dict_done[name] else None
        if name in self.dict_active or depth > 4:
            return None
        override = self._dict_overrides().get(name)
        if override is not None:
            self.dict_done[name] = override
            self.add_value_rule(name, override, 1.0)
            return f"<{name}>"
        entry = self.types.get(name)
        if entry is None or entry["kind"] != "dictionary":
            self.dict_done[name] = None
            return None
        self.dict_active.add(name)
        members: list[dict] = []
        parent = entry.get("parent")
        if parent and self.types.get(parent, {}).get("kind") == "dictionary":
            inherited = self._dict_members(parent, depth + 1)
            if inherited is None:
                self.dict_active.discard(name)
                self.dict_done[name] = None
                return None
            members.extend(inherited)
        members.extend(entry.get("dict_members", ()))
        parts, ok = [], True
        for member in members:
            expr = self.value_for(member["type"], None, depth + 1)
            if expr is None:
                if member["required"]:
                    ok = False
                    break
                continue
            parts.append(f"{js_string(member['name'])}: {expr}")
        self.dict_active.discard(name)
        if not ok:
            self.dict_done[name] = None
            return None
        rule = "{ " + ", ".join(parts) + " }"
        self.dict_done[name] = rule
        self.add_value_rule(name, rule, 1.0)
        return f"<{name}>"

    def _dict_members(self, name: str, depth: int) -> list[dict] | None:
        if depth > 4:
            return None
        entry = self.types.get(name)
        if entry is None or entry["kind"] != "dictionary":
            return None
        members = []
        parent = entry.get("parent")
        if parent and self.types.get(parent, {}).get("kind") == "dictionary":
            inherited = self._dict_members(parent, depth + 1)
            if inherited is None:
                return None
            members.extend(inherited)
        members.extend(entry.get("dict_members", ()))
        return members

    def _dict_overrides(self) -> dict[str, str]:
        if self.profile != "webgpu":
            # DOMMatrixInit inherits the a..f aliases of DOMMatrix2DInit; the
            # generic builder fills both groups with independent values and
            # every consumer rejects the mismatch ("m11 and a"). An empty
            # dictionary is the identity matrix in every DOM-Geometry call.
            return {
                "DOMMatrixInit": "{}",
                "DOMMatrix2DInit": "{}",
                # the generated dictionary can name invalid ICE servers, which
                # makes the connection constructor itself throw
                "RTCConfiguration": "{}",
                # observe() rejects an init where all three flags are false
                "MutationObserverInit": "{ childList: true }",
                # a generated SanitizerConfig sets elements and removeElements
                # at once, which the sanitizer rejects; the default config is
                # valid and still fuzzes the HTML string being set
                "SetHTMLUnsafeOptions": "{}",
                "SetHTMLOptions": "{}",
                # a generated pseudoElement is not a valid selector
                "GetAnimationsOptions": "{}",
            }
        return {
            # The generated values used to contain a usage flag the spec
            # forbids in combination, a zero size, a depth format as a colour
            # target format, and unknown limit keys. Each one makes the
            # factory throw or fail validation, and a failed creator leaves a
            # null GPUDevice behind for the rest of the case.
            "GPUDeviceDescriptor": "{}",
            "GPUBufferDescriptor": (
                "{ size: 16, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST"
                " | GPUBufferUsage.COPY_SRC }"
            ),
            "GPUTextureDescriptor": (
                '{ size: [16, 16], format: "rgba8unorm", usage: GPUTextureUsage.TEXTURE_BINDING'
                " | GPUTextureUsage.COPY_DST | GPUTextureUsage.RENDER_ATTACHMENT }"
            ),
            "GPUQuerySetDescriptor": '{ type: "occlusion", count: 4 }',
            "GPUSamplerDescriptor": "{}",
            "GPURenderBundleEncoderDescriptor": '{ colorFormats: ["rgba8unorm"] }',
            # Stage descriptors come from domato/wgsl_grammar.py, which
            # reads the same ten sampled modules the template declares. A
            # random <GPUShaderModule> next to <computeEntryPoint> is a
            # module/function mismatch and the pipeline never validates.
            "GPUProgrammableStage": "<computeStage>",
            "GPUVertexState": "<vertexState>",
            "GPUFragmentState": "<fragmentState>",
            "GPUComputePipelineDescriptor": "<computePipelineDesc>",
            "GPURenderPipelineDescriptor": "<renderPipelineDesc>",
            # Clear values arrive as an unbounded float or a three-element
            # sequence, and a depth attachment gets a colour view; both are
            # rejected before the pass encoder exists. A render target from
            # the configured canvas has the right usage and no depth part.
            "GPURenderPassDescriptor": (
                "{ colorAttachments: [{ view: device.createTexture(<GPUTextureDescriptor>).createView(),"
                ' clearValue: { r: 0, g: 0, b: 0, a: 0 }, loadOp: "clear", storeOp: "store" }] }'
            ),
        }

    def optional_symbol(self, type_text: str, expr: str) -> str:
        name = self.synth(
            "opt", type_text, [("null", 0.25), (expr, 1.0)]
        )
        return name

    def add_value_rule(self, name: str, expression: str, probability: float) -> None:
        symbol = f"<{name}>"
        key = f"{name}\0{expression}"
        if key in self.value_seen:
            return
        self.value_seen.add(key)
        self.value_rules.setdefault(symbol, []).append((expression, probability))

    def synth(self, kind: str, type_text: str, rules: list[tuple[str, float]]) -> str:
        digest = hashlib.sha1(type_text.encode("utf-8")).hexdigest()[:8]
        readable = re.sub(r"[^A-Za-z0-9]+", "_", type_text)[:48].strip("_")
        name = f"{kind}_{readable}_{digest}"
        for expression, probability in rules:
            self.add_value_rule(name, expression, probability)
        return f"<{name}>"

    # ----------------------------------------------------------------- graph

    def add_creator(self, iface: str, expression: str, probability: float = 1.0) -> bool:
        if not self.interface_usable(iface):
            return False
        weight = "" if probability == 1.0 else f" p={probability}"
        line = f"<new {iface}{weight}> = {expression};"
        if line in self.creator_seen:
            return False
        self.creator_seen.add(line)
        self.creator_rules.setdefault(iface, []).append(line)
        return True

    def build_args(self, args: list[dict], created: str | None, include_optional: bool) -> str | None:
        parts = []
        for arg in args:
            if arg.get("variadic"):
                continue
            if arg.get("optional") and not include_optional:
                break
            expression = self.value_for(arg["type"], created=created)
            if expression is None:
                if arg.get("optional"):
                    break
                return None
            parts.append(expression)
        return ", ".join(parts)

    def add_root_creators(self) -> None:
        # Weights bias creator selection towards the expressions that are
        # known to produce an object (a harness root, createElement, a
        # zero-argument constructor) over the factory calls whose result
        # depends on receiver state. A failed creator leaves a null variable
        # that Domato keeps reusing for the rest of the case.
        for iface, expression in self.roots:
            self.obtainable.add(iface)
            self.add_creator(iface, expression, probability=8.0)
        for iface, expression in self.suppliers:
            if self.interface_usable(iface):
                self.obtainable.add(iface)
                self.add_creator(iface, expression, probability=6.0)
        for iface, expression in self.manual_creators:
            if self.interface_usable(iface):
                self.obtainable.add(iface)
                self.add_creator(iface, expression, probability=6.0)
        for iface, expression in EXTRA_ROOTS:
            if self.interface_usable(iface):
                self.obtainable.add(iface)
                self.add_creator(iface, expression, probability=8.0)
        self.close_over_inheritance()

    def close_over_inheritance(self) -> None:
        for name in list(self.obtainable):
            parent = self.types.get(name, {}).get("parent")
            while parent and parent not in self.obtainable:
                self.obtainable.add(parent)
                parent = self.types.get(parent, {}).get("parent")

    def add_constructors(self) -> None:
        for name in sorted(self.types):
            entry = self.types[name]
            if entry["kind"] != "interface" or not self.in_profile(name):
                continue
            if not self.interface_usable(name):
                continue
            slot = entry["members"].get("constructor")
            if slot is None or not self.member_usable(name, "constructor", slot):
                continue
            attrs = slot["attrs"]
            if attrs.get("HTMLConstructor"):
                continue
            for signature in slot.get("signatures", ()):
                signature_args = signature.get("args", [])
                args = CONSTRUCTOR_ARG_OVERRIDES.get(name)
                if args is None:
                    args = self.build_args(signature_args, created=name, include_optional=True)
                    # Every event constructor takes the event type as its
                    # first argument, and an empty or control-character type
                    # makes the constructor throw. The rest of the init
                    # dictionary is still fuzzed.
                    if (
                        args is not None
                        and name.endswith("Event")
                        and signature_args
                        and signature_args[0].get("type") in ("DOMString", "USVString")
                        and not signature_args[0].get("optional")
                    ):
                        tail = self.build_args(signature_args[1:], created=name, include_optional=True)
                        if tail is not None:
                            args = '"fuzz"' + (", " + tail if tail else "")
                if args is None:
                    continue
                if self.add_creator(name, f"new {name}({args})"):
                    self.obtainable.add(name)
                required = [arg for arg in signature_args if not arg.get("optional") and not arg.get("variadic")]
                if not required and args and name not in NO_NOARG_CONSTRUCTORS:
                    self.add_creator(name, f"new {name}()", probability=5.0)
        self.close_over_inheritance()

    def discover(self) -> None:
        """Grow the object graph through factory methods and non-null-interface attributes."""
        for _ in range(30):
            changed = False
            for iface in sorted(self.obtainable):
                if not self.interface_usable(iface) or not self.in_profile(iface):
                    continue
                entry = self.types.get(iface)
                if entry is None:
                    continue
                for member, slot in entry["members"].items():
                    if member == "constructor" or not self.member_usable(iface, member, slot):
                        continue
                    for signature in slot.get("signatures", ()):
                        created = self.created_type(signature, iface)
                        if created is None or created == iface or created in self.obtainable:
                            continue
                        if not self.interface_usable(created) or not self.in_profile(created):
                            continue
                        if (iface, member) in DENY_CREATORS:
                            continue
                        if not self.can_build_creator(iface, member, signature, created):
                            continue
                        if signature["kind"] == "method":
                            args = MEMBER_ARG_OVERRIDES.get((iface, member))
                            if args is None:
                                args = self.build_args(signature.get("args", []), created=created, include_optional=True)
                            if args is None:
                                continue
                            await_prefix = ""
                            if self.profile == "webgpu" and (signature.get("return") or "").startswith("Promise<"):
                                await_prefix = "await "
                            if self.add_creator(created, f"{await_prefix}<{iface}>.{exposed_member_name(member)}({args})", probability=1.5):
                                self.obtainable.add(created)
                                changed = True
                        elif signature["kind"] == "attribute":
                            if self.add_creator(created, f"<{iface}>.{exposed_member_name(member)}", probability=2.0):
                                self.obtainable.add(created)
                                changed = True
            self.close_over_inheritance()
            if not changed:
                break

    def finalize_obtainable(self) -> None:
        """Give every reusable type a creator, or stop treating it as reusable.

        close_over_inheritance adds parents so a child's variable can be read as
        its parent. A parent with no rule of its own would still be selectable as
        a value and make Domato raise "No creators for type"; it gets an alias
        creator from a child whose creator exists directly.
        """
        direct = set(self.creator_rules)
        for _ in range(10):
            missing = [name for name in sorted(self.obtainable) if name not in self.creator_rules]
            if not missing:
                return
            for name in missing:
                for child in sorted(direct):
                    if child == name or name not in self.ancestors(child):
                        continue
                    if self.interface_usable(name) and self.interface_usable(child):
                        self.add_creator(name, f"<{child}>")
                        break
                else:
                    self.obtainable.discard(name)
        self.obtainable = {name for name in self.obtainable if name in self.creator_rules}

    def ancestors(self, name: str) -> set[str]:
        found = set()
        parent = self.types.get(name, {}).get("parent")
        while parent and parent not in found:
            found.add(parent)
            parent = self.types.get(parent, {}).get("parent")
        return found


    def created_type(self, signature: dict, receiver: str) -> str | None:
        if signature["kind"] == "method":
            return_type = signature.get("return")
            if self.profile != "webgpu" and return_type and return_type.startswith("Promise<"):
                return None
            if self.profile == "webgpu" and return_type and return_type.startswith("Promise<"):
                return_type = return_type[len("Promise<"):-1].strip()
        elif signature["kind"] == "attribute":
            return_type = signature.get("type")
        else:
            return None
        if not return_type:
            return None
        kind, payload, nullable = self.peel(return_type)
        if kind != "interface":
            return None
        if nullable and (receiver, signature.get("name")) not in NON_NULL_PRODUCERS:
            return None
        return payload

    def can_build_creator(self, iface: str, member: str, signature: dict, created: str) -> bool:
        if signature["kind"] == "attribute" and signature.get("static"):
            return False
        if signature["kind"] == "method" and signature.get("static"):
            return False
        if (iface, member) in MEMBER_ARG_OVERRIDES:
            return True
        return self.build_args(signature.get("args", []), created=created, include_optional=True) is not None

    # -------------------------------------------------------------- emit lines

    def add_line(self, line: str) -> None:
        if not line or line in self.line_seen:
            return
        # grammar.py _remove_comments cuts a rule line at the first '#', even
        # inside a string literal; a '#' here silently truncates the statement
        if "#" in line:
            raise ValueError(f"rule line contains '#': {line}")
        self.line_seen.add(line)
        self.lines.append(line)

    def receiver(self, iface: str, static: bool) -> str | None:
        if static:
            entry = self.types.get(iface, {})
            if "LegacyNoInterfaceObject" in entry.get("attrs", {}):
                return None
            return iface
        return f"<{iface}>"

    def promise_return(self, signature: dict) -> str | None:
        return_type = signature.get("return") or ""
        if return_type.startswith("Promise<"):
            return return_type[8:-1].strip()
        return None

    def emit_statements(self) -> None:
        receivers = set(self.obtainable)
        # Static members need no receiver instance: a usable interface that is
        # not obtainable still contributes its namespace-like calls (for
        # example PublicKeyCredential.getClientCapabilities and the RTP
        # getCapabilities helpers).
        for name in self.types:
            entry = self.types[name]
            if entry["kind"] not in ("interface", "namespace", "callback interface"):
                continue
            if self.interface_usable(name) and self.in_profile(name):
                receivers.add(name)
        for iface in sorted(receivers):
            if not self.interface_usable(iface) or not self.in_profile(iface):
                continue
            entry = self.types.get(iface)
            if entry is None:
                continue
            is_namespace = entry["kind"] == "namespace"
            instance = iface in self.obtainable
            for member, slot in entry["members"].items():
                if member == "constructor" or not self.member_usable(iface, member, slot):
                    continue
                for signature in slot.get("signatures", ()):
                    static = is_namespace or signature.get("static", False)
                    if not static and not instance:
                        continue
                    receiver = self.receiver(iface, static)
                    if receiver is None:
                        continue
                    if signature["kind"] == "attribute":
                        self.emit_attribute(iface, member, signature, receiver)
                    elif signature["kind"] == "method":
                        self.emit_method(iface, member, signature, receiver)

    def emit_attribute(self, iface: str, member: str, signature: dict, receiver: str) -> None:
        statement_override = STATEMENT_OVERRIDES.get((iface, member))
        if statement_override is not None:
            self.add_line(statement_override.replace("{r}", receiver))
            return
        # A bare read of a promise attribute leaves its rejection unhandled:
        # writer.ready/closed reject with whatever abort() was given, and that
        # surfaces as an unhandledrejection with no line in the case.
        name = exposed_member_name(member)
        kind, _, _ = self.peel(signature.get("type", ""))
        if kind == "promise":
            self.add_line(f"{receiver}.{name}.catch(function(e) {{ }});")
            return
        self.add_line(f"{receiver}.{name};")
        if signature.get("readonly"):
            return
        if (iface, member) in ATTRIBUTE_VALUE_OVERRIDES:
            expression = ATTRIBUTE_VALUE_OVERRIDES[(iface, member)]
            if expression is None:
                return
        else:
            expression = self.value_for(signature.get("type", ""))
        if expression is None:
            return
        self.add_line(f"{receiver}.{name} = {expression};")

    def emit_method(self, iface: str, member: str, signature: dict, receiver: str) -> None:
        name = exposed_member_name(member)
        statement_override = STATEMENT_OVERRIDES.get((iface, member))
        if statement_override is not None:
            self.add_line(statement_override.replace("{r}", receiver))
            return
        args_override = MEMBER_ARG_OVERRIDES.get((iface, member))
        if args_override is not None:
            builds: list[str | None] = [args_override]
        else:
            builds = [self.build_args(signature.get("args", []), created=None, include_optional=False)]
            if any(arg.get("optional") and not arg.get("variadic") for arg in signature.get("args", ())):
                builds.append(self.build_args(signature.get("args", []), created=None, include_optional=True))
        for args in dict.fromkeys(builds):
            if args is None:
                continue
            call = f"{receiver}.{name}({args})"
            promise = self.promise_return(signature)
            created = self.created_type(signature, iface)
            if (iface, member) in DENY_CREATORS:
                created = None
            if promise is not None:
                inner_kind, inner_payload, inner_nullable = self.peel(promise)
                if self.profile == "webgpu":
                    if inner_kind == "interface" and not inner_nullable and inner_payload in self.obtainable:
                        self.add_line(f"<new {inner_payload}> = await {call};")
                    else:
                        self.add_line(f"await {call};")
                else:
                    self.add_line(f"{call}.catch(function(e) {{ }});")
                continue
            if created is not None and created in self.obtainable and created != iface:
                self.add_line(f"<new {created}> = {call};")
            else:
                self.add_line(f"{call};")

    # ------------------------------------------------------------------ render

    def render_values(self) -> str:
        lines = [
            "# Generated by tools/gen_webidl_rules.py from dom/webidl - do not edit.",
            f"# {len(self.value_rules)} value symbols; Firefox {self.profile} profile.",
            "",
        ]
        for symbol in sorted(self.value_rules):
            for expression, probability in self.value_rules[symbol]:
                if probability == 1.0:
                    lines.append(f"{symbol} = {expression}")
                else:
                    lines.append(f"<{symbol[1:-1]} p={probability}> = {expression}")
            lines.append("")
        return "\n".join(lines)

    def render_extends(self) -> list[str]:
        lines = ["# WebIDL inheritance, so a variable of a child type is reusable as its parent."]
        for name in sorted(self.types):
            entry = self.types[name]
            if entry["kind"] != "interface" or not self.in_profile(name):
                continue
            parent = entry.get("parent")
            if parent and self.types.get(parent, {}).get("kind") == "interface":
                lines.append(f"!extends {name} {parent}")
        lines.append("")
        return lines

    def render_lines(self) -> str:
        lines = [
            "# Generated by tools/gen_webidl_rules.py from dom/webidl - do not edit.",
            f"# {len(self.line_seen)} statement lines; Firefox {self.profile} profile.",
            "# Each line is guarded by the grammar's !lineguard.",
            "",
        ]
        lines += self.render_extends()
        lines.append("!begin lines")
        lines.append("")
        for iface in sorted(self.creator_rules):
            for line in self.creator_rules[iface]:
                lines.append(line)
        lines.append("")
        lines += self.lines
        lines.append("")
        lines.append("!end lines")
        lines.append("")
        return "\n".join(lines)

    def stats(self) -> str:
        lines = sorted(self.line_seen)
        creators = sum(len(entries) for entries in self.creator_rules.values())
        attribute_lines = sum(1 for line in lines if " = " not in line and "(" not in line)
        method_lines = sum(1 for line in lines if "(" in line)
        return (
            f"{self.profile}: {len(self.obtainable)} reachable types, {creators} creators, "
            f"{len(lines)} unique lines ({attribute_lines} attribute, {method_lines} method), "
            f"{len(self.value_rules)} value symbols"
        )


PROFILES = {
    "dom": {
        "values": ROOT / "domato" / "rules" / "webidl_values.txt",
        "lines": ROOT / "domato" / "rules" / "webapis.txt",
    },
    "canvas": {
        "values": ROOT / "domato" / "rules" / "canvashelpers.txt",
        "lines": ROOT / "domato" / "rules" / "canvas.txt",
    },
    "webgl": {
        "values": ROOT / "domato" / "rules" / "webglhelpers.txt",
        "lines": ROOT / "domato" / "rules" / "webgl.txt",
    },
    "webgpu": {
        "values": ROOT / "domato" / "rules" / "webgpuhelpers.txt",
        "lines": ROOT / "domato" / "rules" / "webgpu.txt",
    },
}


def write_profile(types: dict, prefs: dict, fuzzing: dict, probe: dict | None, profile: str) -> Emitter:
    emitter = Emitter(types, prefs, fuzzing, probe, profile)
    emitter.add_root_creators()
    # Constructor arguments may name types that only become obtainable from a
    # later constructor or factory (new MediaRecorder needs MediaStream), so
    # alternate both passes until the object graph stops growing.
    for _ in range(8):
        before = sum(len(entries) for entries in emitter.creator_rules.values())
        emitter.add_constructors()
        emitter.discover()
        after = sum(len(entries) for entries in emitter.creator_rules.values())
        if after == before:
            break
    emitter.finalize_obtainable()
    emitter.emit_statements()
    paths = PROFILES[profile]
    header = (
        "# Generated by tools/gen_webidl_rules.py from /home/ruslan/firefox/dom/webidl.\n"
        "# Edit the emitter, not this file.\n\n"
    )
    values_path = Path(paths["values"])
    values_path.parent.mkdir(parents=True, exist_ok=True)
    values_path.write_text(header + emitter.render_values(), encoding="utf-8")
    lineguard = "try { <line> } catch(e) { }"
    lines_path = Path(paths["lines"])
    lines_path.parent.mkdir(parents=True, exist_ok=True)
    preamble = header
    if profile == "dom":
        # js.txt owns the line guard and includes webidl_values.txt itself.
        preamble += ""
    else:
        # The graphics pragmas are parsed on their own: nothing from rules/
        # is in scope, so the shared value symbols (DOMString, fuzzint,
        # EventHandler, ...) have to be pulled in explicitly.
        preamble += f"!lineguard {lineguard}\n\n!include {values_path.name}\n!include ../rules/common.txt\n\n"
    lines_path.write_text(preamble + emitter.render_lines(), encoding="utf-8")
    print(emitter.stats())
    return emitter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default="/home/ruslan/firefox")
    parser.add_argument("--inventory", default=str(ROOT / "results" / "audit" / "idl_inventory.json"))
    parser.add_argument("--probe", default=str(ROOT / "results" / "audit" / "probe.json"))
    parser.add_argument("--dom-only", action="store_true")
    parser.add_argument("--graphics-only", action="store_true")
    args = parser.parse_args()

    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    types = inventory["types"]
    prefs = AUDIT.load_prefs(Path(args.source))
    fuzzing = AUDIT.load_fuzzing_prefs()
    probe_path = Path(args.probe)
    probe = json.loads(probe_path.read_text(encoding="utf-8")) if probe_path.exists() else None
    if probe is None:
        print("no probe.json - [Func]-gated members will not be emitted", file=sys.stderr)

    profiles = ["dom", "canvas", "webgl", "webgpu"]
    if args.dom_only:
        profiles = ["dom"]
    elif args.graphics_only:
        profiles = ["canvas", "webgl", "webgpu"]
    for profile in profiles:
        write_profile(types, prefs, fuzzing, probe, profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
