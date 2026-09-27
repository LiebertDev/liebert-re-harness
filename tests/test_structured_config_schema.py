"""Ported from the upstream development repo: one test method,
``test_teacher_schema_exposes_config_schema_operation``, was removed here
because it read ``teacher.py``'s source text directly off disk to assert
that a tool declaration line exists in it -- ``teacher.py`` is an upstream,
project-specific orchestration file that is not part of this package, so
the assertion has no target here. Every other test in this file exercises
``tools_formats.structured_inspect`` itself and is unaffected.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tools_formats
import tools_workspace
from tools_formats import structured_inspect


class StructuredConfigSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def parse(value):
        return json.loads(value)

    def test_sectionless_cfg_schema_supports_whitespace_and_redacts_values(self):
        path = self.root / "server.cfg"
        path.write_text(
            "GameId 123456\nRConPassword super-secret\nPort=2302\nPort:2303\n",
            encoding="utf-8",
        )
        raw = structured_inspect(str(path), "schema")
        result = self.parse(raw)
        self.assertTrue(result["ok"])
        self.assertEqual("<root>", result["sections"][0]["name"])
        self.assertEqual({"GameId", "RConPassword", "Port"}, set(result["sections"][0]["key_names"]))
        self.assertEqual(1, result["duplicate_key_count"])
        self.assertTrue(result["values_redacted"])
        self.assertEqual(0, result["value_fields_returned"])
        self.assertNotIn("123456", raw)
        self.assertNotIn("super-secret", raw)
        self.assertNotIn("2302", raw)
        self.assertNotIn("2303", raw)

    def test_ini_schema_returns_section_and_key_names_without_values(self):
        path = self.root / "launcher.ini"
        path.write_text("[Client]\nEnabled=true\nToken=hidden\n[Server]\nPort:2302\n", encoding="utf-8")
        raw = structured_inspect(str(path), "schema")
        result = self.parse(raw)
        self.assertEqual(["Client", "Server"], [row["name"] for row in result["sections"]])
        self.assertEqual(["Enabled", "Token"], result["sections"][0]["key_names"])
        self.assertEqual(["Port"], result["sections"][1]["key_names"])
        self.assertNotIn("hidden", raw)
        self.assertNotIn("2302", raw)

    def test_schema_reports_malformed_duplicates_and_key_limit(self):
        path = self.root / "bounded.cfg"
        path.write_text("A one\nA two\nmalformed\n[broken\nB=three\nC four\n", encoding="utf-8")
        result = self.parse(structured_inspect(str(path), "schema", max_results=2))
        self.assertEqual(2, result["malformed_line_count"])
        self.assertEqual(1, result["duplicate_key_count"])
        self.assertEqual(3, result["unique_key_count"])
        self.assertEqual(2, result["limits"]["max_key_names_returned"])
        self.assertTrue(result["truncated"])

    def test_schema_reports_line_scan_limit(self):
        path = self.root / "line-limit.cfg"
        path.write_text("A one\nB two\nC three\n", encoding="utf-8")
        with mock.patch.object(tools_formats, "MAX_CONFIG_SCHEMA_LINES", 2):
            result = self.parse(structured_inspect(str(path), "schema"))
        self.assertEqual(3, result["line_count"])
        self.assertEqual(2, result["lines_scanned"])
        self.assertTrue(result["truncated"])

    def test_summary_and_search_remain_compatible(self):
        path = self.root / "normal.ini"
        path.write_text("[Main]\nToken=value\n", encoding="utf-8")
        summary = self.parse(structured_inspect(str(path), "summary"))
        search = self.parse(structured_inspect(str(path), "search", "Token"))
        self.assertTrue(summary["ok"])
        self.assertTrue(search["hits"])

if __name__ == "__main__":
    unittest.main()
