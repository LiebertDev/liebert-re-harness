"""Measured registry views over ``liebert_re.report.tool_families``.

``tool_modules`` and ``python_only_declarations`` are computed from source
text and the AST, never from a hand-kept list, so these tests compare the
functions with each other and with ``published_tools``, or feed them a
throwaway package built in ``tmp_path``.
"""

from __future__ import annotations

import textwrap
import unittest
from pathlib import Path

import pytest

from liebert_re.report import tool_families as tf


def _make_package(root: Path, modules: dict[str, str]) -> Path:
    package = root / "fixturepkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for name, source in modules.items():
        (package / f"{name}.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return package


def test_tool_modules_covers_exactly_the_published_tools():
    published: set[str] = set()
    for family in tf.FAMILIES:
        published |= tf.published_tools(family)
    modules = tf.tool_modules()
    assert set(modules) == published
    assert modules, "no published tool found; the scan itself is broken"
    assert all(module.startswith("liebert_re.") for module in modules.values())


def test_tool_modules_names_the_defining_module():
    root = Path(tf.__file__).resolve().parent.parent.parent
    for name, module in tf.tool_modules().items():
        base = root.joinpath(*module.split("."))
        source = base.with_suffix(".py")
        if not source.exists():  # a package __init__
            source = base / "__init__.py"
        assert f"def {name}(" in source.read_text(encoding="utf-8", errors="ignore")


def test_tool_modules_reports_a_name_defined_twice(tmp_path):
    package = _make_package(
        tmp_path,
        {
            "one": "def hash_file(path):\n    return 1\n",
            "two": "def hash_file(path):\n    return 2\n",
        },
    )
    with pytest.raises(ValueError) as excinfo:
        tf.tool_modules(package)
    message = str(excinfo.value)
    assert "hash_file" in message
    assert "fixturepkg.one" in message and "fixturepkg.two" in message


def test_tool_modules_ignores_unpublished_names(tmp_path):
    package = _make_package(
        tmp_path,
        {"one": "def helper_nobody_names():\n    pass\n", "two": "def helper_nobody_names():\n    pass\n"},
    )
    assert tf.tool_modules(package) == {}


def test_python_only_declarations_are_well_formed_published_and_not_dispatched_by_cli():
    declared = tf.python_only_declarations()
    assert declared, "the generic dispatcher relies on write-capable tools being declared"
    # (a) every declaration carries a reason
    assert all(reason.strip() for reason in declared.values())
    # (b) only published tools can be declared
    published = set().union(*(tf.published_tools(family) for family in tf.FAMILIES))
    assert set(declared) <= published
    # (c) cli.py dispatches by string literal; no declared tool may be among them (shared AST collector).
    from tests.cli_literals import cli_string_literals

    literals = cli_string_literals()
    assert not set(declared) & literals, f"declared python-only but dispatched by cli.py: {sorted(set(declared) & literals)}"


def test_python_only_declaration_parsing(tmp_path):
    package = _make_package(
        tmp_path,
        {
            "tools": '''
                import module_that_is_not_installed_anywhere  # must never be imported

                def hash_file(path):
                    """Hash a file.

                    CLI: python-only: needs a live Python object, not argv
                    """

                def read_file(path):
                    """Read a file.

                    CLI: python-only:
                    """

                def list_directory(path):
                    """No declaration here; mentions CLI: python-only mid-sentence."""
            ''',
        },
    )
    with pytest.raises(ValueError, match="read_file.*empty reason"):
        tf.python_only_declarations(package)

    (package / "tools.py").write_text(
        textwrap.dedent(
            '''
            import module_that_is_not_installed_anywhere  # must never be imported

            def hash_file(path):
                """Hash a file.

                CLI: python-only: needs a live Python object, not argv
                """

            def list_directory(path):
                """No declaration here; mentions CLI: python-only mid-sentence."""

            def find_files(path):
                pass
            '''
        ),
        encoding="utf-8",
    )
    assert tf.python_only_declarations(package) == {"hash_file": "needs a live Python object, not argv"}


def test_python_only_declaration_without_a_colon_is_an_empty_reason(tmp_path):
    package = _make_package(
        tmp_path, {"tools": 'def hash_file(path):\n    """Hash.\n\n    CLI: python-only\n    """\n'}
    )
    with pytest.raises(ValueError, match="empty reason"):
        tf.python_only_declarations(package)


def test_python_only_declared_twice_is_refused(tmp_path):
    package = _make_package(
        tmp_path,
        {"tools": 'def hash_file(path):\n    """Hash.\n\n    CLI: python-only: a\n    CLI: python-only: b\n    """\n'},
    )
    with pytest.raises(ValueError, match="more than once"):
        tf.python_only_declarations(package)


# -- installed flag and artifact counts are only believed when they are real values --

_WORKSPACE_TOOLS = sorted(tf.FAMILIES["workspace"])
_RELATIONSHIP_TEXT = "compare the two binaries"


def _rows(installed):
    return [{"name": name, "installed": installed} for name in _WORKSPACE_TOOLS]


def _workspace(rows):
    return next(item for item in tf.family_catalog(rows) if item["family"] == "workspace")


class InstalledFlagTests(unittest.TestCase):
    def test_text_false_is_not_installed(self):
        entry = _workspace(_rows("false"))
        self.assertEqual(entry["available_tools"], [])
        self.assertEqual(entry["unknown_tools"], _WORKSPACE_TOOLS)
        self.assertEqual(entry["status"], "UNKNOWN")

    def test_other_truthy_non_bools_are_not_installed(self):
        for value in ("true", "yes", 1, "installed", ["x"]):
            self.assertEqual(_workspace(_rows(value))["available_tools"], [], repr(value))

    def test_real_booleans_still_work(self):
        self.assertEqual(_workspace(_rows(True))["status"], "READY")
        entry = _workspace(_rows(False))
        self.assertEqual((entry["status"], entry["missing_tools"]), ("TOOL_MISSING", _WORKSPACE_TOOLS))

    def test_one_text_flag_downgrades_ready_to_partial(self):
        rows = _rows(True)
        rows[0]["installed"] = "false"
        entry = _workspace(rows)
        self.assertEqual(entry["status"], "PARTIAL")
        self.assertEqual(entry["unknown_tools"], [rows[0]["name"]])
        self.assertNotIn(rows[0]["name"], entry["available_tools"])


class ArtifactCountTests(unittest.TestCase):
    def test_missing_counts_with_relationship_text_are_unknown_and_flagged(self):
        state = {}
        self.assertEqual(tf.relationship_routing(state, _RELATIONSHIP_TEXT), "UNKNOWN")
        reasons = tf.routing_uncertainties_for_state(state, corpus_text=_RELATIONSHIP_TEXT)
        self.assertEqual(len(reasons), 1)
        self.assertTrue(reasons[0].startswith("RELATIONSHIP_ROUTING_UNKNOWN"))

    def test_invalid_counts_are_unknown_not_zero(self):
        for bad in (None, "", "many", -1, True, 2.5):
            state = {"artifacts_analyzed": bad, "artifacts_discovered": bad}
            self.assertEqual(tf.relationship_routing(state, _RELATIONSHIP_TEXT), "UNKNOWN", repr(bad))

    def test_known_counts_are_decided(self):
        known_one = {"artifacts_analyzed": 1, "artifacts_discovered": 1}
        self.assertEqual(tf.relationship_routing(known_one, _RELATIONSHIP_TEXT), "NOT_NEEDED")
        self.assertEqual(tf.relationship_routing({"artifacts_analyzed": 0, "artifacts_discovered": 3}, _RELATIONSHIP_TEXT), "NEEDED")
        self.assertEqual(tf.relationship_routing({"artifacts_analyzed": "2"}, _RELATIONSHIP_TEXT), "NEEDED")

    def test_routing_flags_count_only_as_real_bools(self):
        for key in ("relationship_needed", "conflicting_evidence", "claim_verification_needed"):
            self.assertEqual(tf.relationship_routing({key: True}), "NEEDED", key)
            self.assertEqual(tf.relationship_routing({key: False}), "NOT_NEEDED", key)
            for bad in ("false", "no", "0", 0, 1, None, [], "yes"):
                self.assertEqual(tf.relationship_routing({key: bad}), "UNKNOWN", f"{key}={bad!r}")
                reasons = tf.routing_uncertainties_for_state({key: bad})
                self.assertEqual(len(reasons), 1, f"{key}={bad!r}")
                self.assertIn(key, reasons[0])

    def test_a_real_true_flag_wins_over_a_malformed_one(self):
        state = {"relationship_needed": "false", "conflicting_evidence": True}
        self.assertEqual(tf.relationship_routing(state), "NEEDED")
        self.assertEqual(tf.routing_uncertainties_for_state(state), [])

    def test_malformed_flag_does_not_select_correlation(self):
        self.assertNotIn("correlation", tf.families_for_state({"relationship_needed": "false"}))
        self.assertIn("correlation", tf.families_for_state({"relationship_needed": True}))

    def test_no_relationship_text_needs_no_counts(self):
        self.assertEqual(tf.relationship_routing({}, "unpack the sample"), "NOT_NEEDED")
        self.assertEqual(tf.routing_uncertainties_for_state({}, corpus_text="unpack the sample"), [])

    def test_unknown_does_not_select_correlation_but_known_two_does(self):
        self.assertNotIn("correlation", tf.families_for_state({}, corpus_text="compare"))
        self.assertIn("correlation", tf.families_for_state({"artifacts_analyzed": 2}, corpus_text="compare"))
        selected = set(tf.tools_for_state({"artifacts_analyzed": 2}, corpus_text="compare"))
        self.assertTrue(set(tf.FAMILIES["correlation"]) <= selected)

