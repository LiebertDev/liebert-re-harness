"""A listing cut at its cap is a result, not a failure (``liebert_re.cli._decode``).

``pe --imports`` / ``pe --exports`` end a capped listing with a visible marker
(``liebert_re.workspace._limit_marker``). The CLI classifier used to know only the older
``[limit:N]`` form, so a complete, correct, honestly truncated answer came back as
``ok:false / UNCLASSIFIED_OUTPUT`` (exit 1). Three states are kept apart here:

* complete listing        -> ok true, no ``truncation`` field
* truncated listing       -> ok true, exit 0, ``truncation`` carries limit/returned/total/omitted
* text matching no shape  -> ok false, UNCLASSIFIED_OUTPUT, exit 1 (the classifier stays narrow)

Fixtures are built in code (``build_owned_pe_sections``); no system file is read. Exports have no
fixture builder, so the export case swaps pefile's parsed object for a stand-in with many symbols.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools import binary

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def run(*argv):
    out = StringIO()
    with redirect_stdout(out):
        code = cli.main(list(argv))
    return code, json.loads(out.getvalue())


def _imports_pe(name, count):
    return build_owned_pe_sections(ROOT / name, imports={"a.dll": [f"F{i}" for i in range(count)]})


def _fake_export_pe(count):
    symbols = [SimpleNamespace(name=f"E{i}".encode(), address=0x1000 + i, ordinal=i + 1) for i in range(count)]
    return SimpleNamespace(DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=symbols))


class TruncatedListingIsAResultTests(unittest.TestCase):
    def test_truncated_imports_are_ok_exit_zero_with_visible_truncation(self):
        path = _imports_pe("many.exe", 600)   # 600 > the 500 cap of pe_imports
        code, body = run("pe", "--imports", str(path))
        self.assertEqual(code, 0)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "OK")
        self.assertNotIn("error", body)
        # imports have no cheap total: it is reported as unknown, never guessed
        self.assertEqual(body["truncation"], {"truncated": True, "limit": 500, "returned": 500,
                                              "total": None, "omitted": None})
        self.assertEqual(len([ln for ln in body["text"].splitlines() if "@IAT" in ln]), 500)

    def test_truncated_exports_carry_limit_returned_total_omitted(self):
        path = _imports_pe("exp.exe", 1)
        with mock.patch.object(binary, "_pe", return_value=_fake_export_pe(620)), \
                mock.patch.object(binary, "_parse_directories", return_value=None), \
                mock.patch.object(binary, "_directory_problem", return_value=""):
            code, body = run("pe", "--exports", str(path))
        self.assertEqual(code, 0)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "OK")
        self.assertEqual(body["truncation"], {"truncated": True, "limit": 500, "returned": 500,
                                              "total": 620, "omitted": 120})

    def test_complete_listing_has_no_truncation_field(self):
        path = _imports_pe("few.exe", 5)
        code, body = run("pe", "--imports", str(path))
        self.assertEqual(code, 0)
        self.assertNotEqual(body.get("ok"), False)
        self.assertNotIn("truncation", body)
        self.assertNotIn("error", body)


class ShapeCheckedTextSaysSoTests(unittest.TestCase):
    """Absence of ``ok`` is not a state: a complete, shape-conforming text answer is ok:true / OK."""

    def test_complete_imports_listing_is_explicitly_ok(self):
        path = _imports_pe("few2.exe", 5)
        code, body = run("pe", "--imports", str(path))
        self.assertEqual(code, 0)
        self.assertIn("ok", body)
        self.assertIs(body["ok"], True)

    def test_complete_imports_listing_carries_status_ok(self):
        path = _imports_pe("few3.exe", 5)
        _, body = run("pe", "--imports", str(path))
        self.assertEqual(body.get("status"), "OK")
        self.assertNotIn("truncation", body)
        self.assertNotIn("error", body)

    def test_unshaped_text_is_still_not_ok(self):
        body = cli._decode("the tool said something unexpected", cli._TEXT_SHAPES["imports"])
        self.assertIs(body["ok"], False)
        self.assertEqual(body["status"], "FAILED")
        self.assertEqual(body["error"], "UNCLASSIFIED_OUTPUT")


class KnownCodeTextCarriesOkTests(unittest.TestCase):
    """The two known-code text answers are not successes: ok:false, and their exit code stays 3."""

    def test_unsupported_text_carries_ok_false(self):
        body = cli._decode("Authenticode verification requires Windows", cli._TEXT_SHAPES["imports"])
        self.assertIs(body["ok"], False)
        self.assertEqual(body["status"], "UNSUPPORTED")

    def test_analysis_limited_text_carries_ok_false(self):
        body = cli._decode("IMPORT_DIRECTORY_UNREADABLE: bad", cli._TEXT_SHAPES["imports"])
        self.assertIs(body["ok"], False)
        self.assertEqual(body["status"], "ANALYSIS_LIMITED")

    def test_exit_code_is_refused_with_or_without_ok(self):
        for text in ("Authenticode verification requires Windows", "EXPORT_DIRECTORY_UNREADABLE: bad"):
            with self.subTest(text=text):
                body = cli._decode(text)
                self.assertEqual(cli._exit_code(body), cli.EXIT_REFUSED)
                self.assertEqual(cli._exit_code({k: v for k, v in body.items() if k != "ok"}), cli.EXIT_REFUSED)


class ClassifierStaysNarrowTests(unittest.TestCase):
    """Recognising the truncation marker must not turn the classifier into a catch-all."""

    def test_unrecognised_text_is_still_unclassified_through_the_cli(self):
        path = _imports_pe("odd.exe", 1)
        with mock.patch.object(binary, "pe_imports", return_value="the tool said something unexpected"):
            code, body = run("pe", "--imports", str(path))
        self.assertEqual(code, 1)
        self.assertFalse(body["ok"])
        self.assertEqual(body["status"], "FAILED")
        self.assertEqual(body["error"], "UNCLASSIFIED_OUTPUT")
        self.assertNotIn("truncation", body)

    def test_malformed_markers_are_not_recognised(self):
        shape = cli._TEXT_SHAPES["imports"]
        for text in ("[limit:500; truncated=maybe; returned=500; total=3]",
                     "[limit:500; truncated=true; returned=abc; total=3]",
                     "[limit:500; truncated=true; returned=500]",
                     "a.dll!F1 @IAT 0x10\n[limit:500; truncated=true; returned=1; total=3] and then prose"):
            with self.subTest(text=text):
                body = cli._decode(text, shape)
                self.assertFalse(body["ok"])
                self.assertEqual(body["error"], "UNCLASSIFIED_OUTPUT")

    def test_a_marker_does_not_excuse_an_unclassifiable_line(self):
        text = "garbage line\n[limit:500; truncated=true; returned=1; total=3]"
        body = cli._decode(text, cli._TEXT_SHAPES["imports"])
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "UNCLASSIFIED_OUTPUT")
        self.assertNotIn("truncation", body)

    def test_an_inconsistent_marker_is_not_a_result(self):
        # returned above limit, or total below returned: the marker contradicts itself
        for marker in ("[limit:5; truncated=true; returned=9; total=20]",
                       "[limit:500; truncated=true; returned=500; total=10]"):
            with self.subTest(marker=marker):
                body = cli._decode("a.dll!F1 @IAT 0x10\n" + marker, cli._TEXT_SHAPES["imports"])
                self.assertEqual(body["error"], "UNCLASSIFIED_OUTPUT")


if __name__ == "__main__":
    unittest.main()
