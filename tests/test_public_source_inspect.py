"""Focused public-port coverage for tools_source.py. The private tests
covering it (test_offline_capabilities.py, test_source_inspect_c.py,
test_scope_loss_visibility.py) each import an unpublished module
(coverage_engine/tool_registry/..., isolated_artifact, or similar) that is
out of scope for this port batch. This file exercises source_inspect,
project_inspect, and java_class_inspect directly: real Python-source AST
parsing (source_inspect's actual parser for .py), the regex-fallback path
for a non-Python language, and each function's documented structured
failure for a file that is not of its expected shape."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import tools_workspace
from tools_source import java_class_inspect, project_inspect, source_inspect


def _j(raw):
    import json
    return json.loads(raw)


class SourceInspectPythonAstTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_outline_finds_real_python_functions_and_classes_via_ast(self):
        p = self.root / "sample.py"
        p.write_text(
            "class Widget:\n"
            "    def draw(self):\n"
            "        pass\n"
            "\n"
            "def helper(x):\n"
            "    return x + 1\n",
            encoding="utf-8",
        )
        result = _j(source_inspect(str(p), operation="outline"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["parser"], "python_ast")
        names = {(s["name"], s["kind"]) for s in result["symbols"]}
        self.assertIn(("Widget", "class"), names)
        self.assertIn(("helper", "function"), names)

    def test_imports_operation_finds_a_python_import(self):
        p = self.root / "importer.py"
        p.write_text("import os\nfrom pathlib import Path\n", encoding="utf-8")
        result = _j(source_inspect(str(p), operation="imports"))
        values = {row["value"] for row in result["imports"]}
        self.assertIn("os", values)
        self.assertIn("pathlib", values)

    def test_call_graph_light_python_ast_path(self):
        p = self.root / "calls.py"
        p.write_text(
            "def a():\n    b()\n\ndef b():\n    pass\n",
            encoding="utf-8",
        )
        result = _j(source_inspect(str(p), operation="call_graph_light"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["parser"], "python_ast")
        edge = next(e for e in result["edges"] if e["caller"] == "a")
        self.assertEqual(edge["callee"], "b")

    def test_regex_search_operation_finds_a_literal_match(self):
        p = self.root / "text_search.py"
        p.write_text("x = 1\nfindme_marker = 2\ny = 3\n", encoding="utf-8")
        result = _j(source_inspect(str(p), operation="search", query="findme_marker"))
        self.assertTrue(any("findme_marker" in h["text"] for h in result["hits"]))

    def test_invalid_regex_is_a_structured_error_not_a_raise(self):
        p = self.root / "any.py"
        p.write_text("x = 1\n", encoding="utf-8")
        result = _j(source_inspect(str(p), operation="regex", query="("))  # unbalanced group
        self.assertFalse(result["ok"])
        self.assertTrue(result["error"].startswith("INVALID_REGEX"))

    def test_unknown_operation_is_a_structured_error(self):
        p = self.root / "any2.py"
        p.write_text("x = 1\n", encoding="utf-8")
        result = _j(source_inspect(str(p), operation="not_a_real_operation"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_OPERATION")


class SourceInspectNonPythonLanguageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_go_source_uses_the_regex_fallback_not_python_ast(self):
        p = self.root / "main.go"
        p.write_text("package main\n\nfunc helper(x int) int {\n\treturn x\n}\n", encoding="utf-8")
        result = _j(source_inspect(str(p), operation="outline"))
        self.assertEqual(result["parser"], "syntax_scan")
        self.assertEqual(result["language"], "Go")
        names = {s["name"] for s in result["symbols"]}
        self.assertIn("helper", names)


class ProjectInspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)
        (self.root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (self.root / "main.py").write_text("print('hi')\n", encoding="utf-8")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "test_thing.py").write_text("def test_x(): pass\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_summary_finds_manifest_entrypoint_and_test_files(self):
        result = _j(project_inspect(str(self.root)))
        self.assertTrue(result["ok"])
        self.assertTrue(any(m.endswith("pyproject.toml") for m in result["manifests"]))
        self.assertTrue(any(e.endswith("main.py") for e in result["entrypoints"]))
        self.assertTrue(any("test_thing.py" in t for t in result["tests"]))
        self.assertEqual(result["languages"].get("Python"), 2)

    def test_structure_operation_reports_top_level_breakdown(self):
        result = _j(project_inspect(str(self.root), operation="structure"))
        self.assertIn("top_level", result)
        # project_inspect's `structure` groups every scanned file under its
        # own top-level path component; relative() here is workspace-rooted
        # (the temp dir itself, not "tests"), so the real signal is that the
        # nested tests/test_thing.py file was actually reached by the scan.
        total_files = sum(v["files"] for v in result["top_level"].values())
        self.assertEqual(total_files, result["file_count"])
        self.assertGreaterEqual(total_files, 3)


class JavaClassInspectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_non_class_file_is_rejected_by_magic(self):
        p = self.root / "not_a_class.txt"
        p.write_bytes(b"plain text, not a JVM class file at all")
        result = _j(java_class_inspect(str(p)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "NOT_JAVA_CLASS")

    def test_truncated_class_with_valid_magic_is_a_structured_malformed_error(self):
        p = self.root / "truncated.class"
        # Real magic + major version, but the constant-pool count claims far
        # more entries than the (empty) body actually has.
        header = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + struct.pack(">H", 50)
        p.write_bytes(header)
        result = _j(java_class_inspect(str(p)))
        self.assertFalse(result["ok"])
        self.assertTrue(result["error"].startswith("MALFORMED_CLASS"))


if __name__ == "__main__":
    unittest.main()
