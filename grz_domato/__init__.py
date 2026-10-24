# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""A thin Grizzly Adapter that drives Google's Domato DOM fuzzer."""
from __future__ import annotations

import importlib
import importlib.util
import random
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from grizzly.adapter import Adapter

if TYPE_CHECKING:
    from grizzly.common.storage import TestCase
    from sapphire import ServerMap

__all__ = ("DomatoAdapter",)

DOMATO_DIR = Path(__file__).resolve().parent.parent / "domato"
TEMPLATE = Path(__file__).resolve().parent / "template.html"

# Line budgets per grammar. The DOM/JS part is budgeted by Domato itself
# (_N_MAIN_LINES / _N_EVENTHANDLER_LINES in domato/generator.py); these cover
# the graphics APIs added on top of it.
_N_CANVAS_LINES = 250
_N_WEBGL_LINES = 250
_N_WEBGPU_LINES = 250
# webgpu.txt expands <GPUShaderModule> to the literals Shader0..Shader9, so the
# template has to declare exactly this many modules.
_N_SHADERS = 10


def _load_domato():
    """Load Domato's generator module so we can call it in-process."""
    domato_str = str(DOMATO_DIR)
    if domato_str not in sys.path:
        sys.path.insert(0, domato_str)
    return importlib.import_module("generator")


def _load_by_path(name: str, path: Path):
    """Load a Domato helper under a private module name.

    Importing by path keeps it from colliding with the root ``generator``
    module already in sys.modules and avoids depending on ``domato`` being a
    package.
    """
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_grammar(gen_module, path: Path, extra: str | None = None):
    grammar = gen_module.Grammar()
    if grammar.parse_from_file(str(path), extra):
        raise RuntimeError(f"failed to parse {path.name}")
    return grammar


def _embed_shader(code: str) -> str:
    """Make WGSL source safe for a JavaScript template literal."""
    return code.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")


class DomatoAdapter(Adapter):
    """Generate test cases with Domato. Supports ``--input`` to point at a
    directory of custom grammar rules (html.txt/css.txt/js.txt).

    Every case mixes the DOM/CSS/JS grammars with the Canvas 2D, WebGL and
    WebGPU grammars; each API runs in its own ``<script>`` block and its own
    guarded function, so an unsupported or broken API cannot take the rest of
    the case down with it."""

    def __init__(self, name: str = "domato") -> None:
        super().__init__(name)
        self._gen = None
        self._template = None
        self._grammars = None
        self._api_grammars = None
        self._shader_sources = ()
        self._rules_dir = DOMATO_DIR / "rules"

    def setup(self, input_path: str | None, server_map: ServerMap) -> None:
        """Parse Domato grammars once and enable the Grizzly harness so the
        browser isn't relaunched on every iteration."""
        self._gen = _load_domato()
        if input_path is not None:
            self._rules_dir = Path(input_path)
        self._template = TEMPLATE.read_text(encoding="utf-8")
        html_grammar = _parse_grammar(self._gen, self._rules_dir / "html.txt")
        css_grammar = _parse_grammar(self._gen, self._rules_dir / "css.txt")
        js_grammar = _parse_grammar(self._gen, self._rules_dir / "js.txt")
        # JS and HTML grammar need access to the CSS grammar.
        html_grammar.add_import("cssgrammar", css_grammar)
        js_grammar.add_import("cssgrammar", css_grammar)
        self._grammars = (html_grammar, css_grammar, js_grammar)
        self._setup_api_grammars()
        self.enable_harness()

    def _setup_api_grammars(self) -> None:
        """Parse the graphics grammars. They are parsed separately from the DOM
        ones: sharing one Grammar object would merge their <line> pools and
        dilute each API's code, and their !lineguard/!varformat directives would
        fight over the settings of the combined object."""
        canvas = _parse_grammar(self._gen, DOMATO_DIR / "rules" / "canvas.txt")
        webgl = _parse_grammar(self._gen, DOMATO_DIR / "rules" / "webgl.txt")
        self._webgpu_tools = _load_by_path(
            "_domato_webgpu", DOMATO_DIR / "wgsl_grammar.py"
        )
        shaders_dir = DOMATO_DIR / "rules" / "wgsl"
        self._shader_sources = tuple(
            sorted(path.read_text(encoding="utf-8", errors="replace") for path in shaders_dir.glob("*.wgsl"))
        )
        if not self._shader_sources:
            raise RuntimeError(f"no .wgsl shaders found in {shaders_dir}")
        webgpu, _ = self._build_webgpu_grammar()
        self._api_grammars = {"canvasfuzz": canvas, "glfuzz": webgl, "webgpufuzz": webgpu}

    def _build_webgpu_grammar(self):
        """Build the WebGPU grammar.

        webgpu.txt has no rules for the stage entry-point symbols (<computeEntryPoint>,
        <vertexEntryPoint>, <fragmentEntryPoint>) and leans on <BindInt> being
        extended, and both are derived from the shader sources, so the grammar
        can only be parsed once the shaders for a case are known."""
        shaders = [random.choice(self._shader_sources) for _ in range(_N_SHADERS)]
        extra = (
            self._webgpu_tools.parse_entrypoints(shaders)
            + "\n"
            + self._webgpu_tools.parse_stage_descriptors(shaders)
            + "\n"
            + self._webgpu_tools.parse_bindings(shaders)
            + "\n"
        )
        grammar = _parse_grammar(self._gen, DOMATO_DIR / "rules" / "webgpu.txt", extra)
        return grammar, shaders

    def generate(self, testcase: TestCase, server_map: ServerMap) -> None:
        """Generate a single Domato test case and add it to the testcase."""
        if self._grammars is None or self._api_grammars is None:
            raise RuntimeError("DomatoAdapter has not been set up; call setup() first")
        html_grammar, css_grammar, js_grammar = self._grammars
        html = self._gen.generate_new_sample(
            self._template, html_grammar, css_grammar, js_grammar
        )
        budgets = {
            "canvasfuzz": _N_CANVAS_LINES,
            "glfuzz": _N_WEBGL_LINES,
            "webgpufuzz": _N_WEBGPU_LINES,
        }
        for placeholder, lines in budgets.items():
            grammar = self._api_grammars[placeholder]
            if placeholder == "webgpufuzz":
                grammar, shaders = self._build_webgpu_grammar()
                for index, shader in enumerate(shaders):
                    html = html.replace(f"<shader{index}>", _embed_shader(shader), 1)
            html = html.replace(f"<{placeholder}>", grammar._generate_code(lines), 1)
        testcase.add_from_bytes(html.encode("utf-8"), testcase.entry_point, required=True)
