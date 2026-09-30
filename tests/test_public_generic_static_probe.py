"""Focused public-port coverage for generic_static_probe.py.

The private test covering this module (test_universal_file_foundation.py)
imports nine unpublished orchestration modules (capability_report,
coverage_engine, deterministic_planner, file_router, memory_manager,
research_graph, research_state, tool_registry, windows_kernel) that are
out of scope for this port batch, so it cannot be ported as-is. This file
instead exercises generic_static_probe.py's own two documented outcomes
directly: a missing file's structured FAILED/FILE_NOT_FOUND result, and a
real file's normal READY/PARTIAL probe -- plus normalize_tool_result's own
status-vocabulary contract.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import tools_workspace
from generic_static_probe import generic_static_probe, normalize_tool_result


class GenericStaticProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_is_a_structured_failure_not_a_raise(self):
        result = json.loads(generic_static_probe(str(self.root / "does_not_exist.bin")))
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["details"]["error"], "FILE_NOT_FOUND")

    def test_text_file_is_probed_without_execution(self):
        p = self.root / "notes.txt"
        p.write_text("hello world\nsecond line\n", encoding="utf-8")
        result = json.loads(generic_static_probe(str(p)))
        self.assertIn(result["status"], {"READY", "PARTIAL"})
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["full_file_loaded_to_memory"])
        self.assertIn("hello world", result["printable_strings"])
        self.assertEqual(result["line_count"], 2)
        self.assertTrue(result["line_count_exact"])
        self.assertIsNotNone(result["sha256"])

    def test_binary_file_has_no_exact_line_count(self):
        p = self.root / "blob.bin"
        p.write_bytes(bytes(range(256)) * 4)
        result = json.loads(generic_static_probe(str(p)))
        self.assertFalse(result["line_count_exact"])
        self.assertIsNone(result["line_count"])
        self.assertIsNotNone(result["entropy_sample"])


class NormalizeToolResultTests(unittest.TestCase):
    def test_ok_true_without_status_maps_to_ready(self):
        out = normalize_tool_result({"ok": True}, tool="x", target="y")
        self.assertEqual(out["status"], "READY")

    def test_ok_false_without_status_maps_to_failed(self):
        out = normalize_tool_result({"ok": False, "error": "SOMETHING"}, tool="x", target="y")
        self.assertEqual(out["status"], "FAILED")
        self.assertEqual(out["summary"], "SOMETHING")

    def test_pass_and_ok_strings_normalize_to_ready(self):
        self.assertEqual(normalize_tool_result({"status": "PASS"}, tool="x", target="y")["status"], "READY")
        self.assertEqual(normalize_tool_result({"status": "OK"}, tool="x", target="y")["status"], "READY")

    def test_unrecognized_status_string_falls_back_to_failed(self):
        out = normalize_tool_result({"status": "SOMETHING_MADE_UP"}, tool="x", target="y")
        self.assertEqual(out["status"], "FAILED")

    def test_known_status_vocabulary_passes_through(self):
        for status in ("TOOL_MISSING", "NOT_TESTED", "UNSUPPORTED", "TIMEOUT", "TRUNCATED"):
            out = normalize_tool_result({"status": status}, tool="x", target="y")
            self.assertEqual(out["status"], status)

    def test_string_payload_that_is_not_json_becomes_a_summary(self):
        out = normalize_tool_result("plain text result, not json", tool="x", target="y")
        self.assertEqual(out["summary"], "plain text result, not json")
        self.assertFalse(out["truncated"])


if __name__ == "__main__":
    unittest.main()
