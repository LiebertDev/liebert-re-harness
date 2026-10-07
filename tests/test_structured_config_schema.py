"""Ported from the upstream development repo: one test method, which checked
an upstream orchestration file's tool declaration, was removed here
because it read that file's source text directly off disk to assert
that a tool declaration line exists in it -- that file is an upstream,
project-specific orchestration file that is not part of this package, so
the assertion has no target here. Every other test in this file exercises
``tools_formats.structured_inspect`` itself and is unaffected.
"""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.tools.formats as tools_formats
import liebert_re.workspace as tools_workspace
from liebert_re.tools.formats import structured_inspect


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

    def test_toml_uses_tomllib_and_reports_parser(self):
        path = self.root / "a.toml"
        path.write_text("[tool]\nname = 'x'\n", encoding="utf-8")
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("tomllib unavailable (Python < 3.11)")
        result = self.parse(structured_inspect(str(path), "search", "name"))
        self.assertTrue(result["ok"])
        self.assertEqual("tomllib", result["toml_parser"])
        self.assertTrue(result["hits"])

    def test_toml_falls_back_to_tomli_and_says_so(self):
        path = self.root / "b.toml"
        path.write_text("[tool]\nname = 'x'\n", encoding="utf-8")
        fake = types.ModuleType("tomli")
        fake.loads = lambda text: {"tool": {"name": "x"}}
        with mock.patch.dict(sys.modules, {"tomllib": None, "tomli": fake}):
            result = self.parse(structured_inspect(str(path), "search", "name"))
        self.assertTrue(result["ok"])
        self.assertIn("fallback", result["toml_parser"])
        self.assertTrue(result["hits"])

    def test_toml_without_any_parser_is_an_error_not_a_guess(self):
        path = self.root / "c.toml"
        path.write_text("a = 1\n", encoding="utf-8")
        with mock.patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            result = self.parse(structured_inspect(str(path)))
        self.assertFalse(result["ok"])


class StructuredRowsTests(unittest.TestCase):
    def _inspect(self, name, body, **kw):
        import tempfile
        import liebert_re.workspace as tools_workspace
        with tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE) as td:
            path = Path(td) / name
            path.write_bytes(body)
            return json.loads(structured_inspect(str(path), **kw))

    def test_jsonl_with_a_bad_line_keeps_the_good_lines_and_names_the_bad_one(self):
        result = self._inspect("e.jsonl", b'{"a": 1}\nnot json\n{"a": 2}\n\n{"a": 3}\n')
        self.assertTrue(result["ok"])
        self.assertEqual(result["rows"]["rows_returned"], 3)
        self.assertEqual(result["rows"]["bad_line_count"], 1)
        self.assertEqual(result["rows"]["bad_lines"][0]["line"], 2)
        self.assertFalse(result["truncated"])

    def test_jsonl_with_no_parsable_line_fails_naming_the_line(self):
        result = self._inspect("e.jsonl", b"nope\n")
        self.assertFalse(result["ok"])
        self.assertIn("line 1", result["error"])

    def test_row_cap_is_reported_not_silent(self):
        import liebert_re.tools.formats as formats
        from unittest import mock
        with mock.patch.object(formats, "MAX_STRUCTURED_ROWS", 3):
            jsonl = self._inspect("e.jsonl", b"".join(b'{"i": %d}\n' % i for i in range(5)))
            csv_result = self._inspect("e.csv", b"i\n" + b"".join(b"%d\n" % i for i in range(5)))
        self.assertTrue(jsonl["truncated"])
        self.assertEqual((jsonl["rows"]["rows_returned"], jsonl["rows"]["row_limit"], jsonl["rows"]["unread_lines_past_limit"]), (3, 3, 2))
        self.assertTrue(csv_result["truncated"])
        self.assertEqual((csv_result["rows"]["rows_returned"], csv_result["rows"]["rows_total"]), (3, 5))


if __name__ == "__main__":
    unittest.main()
