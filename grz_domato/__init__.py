# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""A thin Grizzly Adapter that drives Google's Domato DOM fuzzer."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from grizzly.adapter import Adapter

if TYPE_CHECKING:
    from grizzly.common.storage import TestCase
    from sapphire import ServerMap

__all__ = ("DomatoAdapter",)

DOMATO_DIR = Path(__file__).resolve().parent.parent / "domato"


def _load_domato():
    """Load Domato's generator module so we can call it in-process."""
    domato_str = str(DOMATO_DIR)
    if domato_str not in sys.path:
        sys.path.insert(0, domato_str)
    return importlib.import_module("generator")


class DomatoAdapter(Adapter):
    """Generate test cases with Domato. Supports ``--input`` to point at a
    directory of custom grammar rules (html.txt/css.txt/js.txt)."""

    def __init__(self, name: str = "domato") -> None:
        super().__init__(name)
        self._gen = None
        self._template = None
        self._grammars = None
        self._rules_dir = DOMATO_DIR / "rules"

    def setup(self, input_path: str | None, server_map: ServerMap) -> None:
        """Parse Domato grammars once and enable the Grizzly harness so the
        browser isn't relaunched on every iteration."""
        self._gen = _load_domato()
        if input_path is not None:
            self._rules_dir = Path(input_path)
        self._template = (DOMATO_DIR / "template.html").read_text(encoding="utf-8")
        html_grammar = self._gen.Grammar()
        if html_grammar.parse_from_file(str(self._rules_dir / "html.txt")):
            raise RuntimeError("failed to parse html.txt")
        css_grammar = self._gen.Grammar()
        if css_grammar.parse_from_file(str(self._rules_dir / "css.txt")):
            raise RuntimeError("failed to parse css.txt")
        js_grammar = self._gen.Grammar()
        if js_grammar.parse_from_file(str(self._rules_dir / "js.txt")):
            raise RuntimeError("failed to parse js.txt")
        # JS and HTML grammar need access to the CSS grammar.
        html_grammar.add_import("cssgrammar", css_grammar)
        js_grammar.add_import("cssgrammar", css_grammar)
        self._grammars = (html_grammar, css_grammar, js_grammar)
        self.enable_harness()

    def generate(self, testcase: TestCase, server_map: ServerMap) -> None:
        """Generate a single Domato test case and add it to the testcase."""
        if self._grammars is None or self._gen is None or self._template is None:
            raise RuntimeError("DomatoAdapter has not been set up; call setup() first")
        html_grammar, css_grammar, js_grammar = self._grammars
        html = self._gen.generate_new_sample(
            self._template, html_grammar, css_grammar, js_grammar
        )
        testcase.add_from_bytes(html.encode("utf-8"), testcase.entry_point, required=True)