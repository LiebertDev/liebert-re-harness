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
from unittest import mock

import liebert_re.workspace as tools_workspace
from liebert_re.tools.generic_static_probe import generic_static_probe, normalize_tool_result


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


class ProbeEvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence_root = self.root / "evidence"
        (self.evidence_root / "generic_static_probe").mkdir(parents=True)
        self.sample = self.root / "notes.txt"
        self.sample.write_text("hello world\n", encoding="utf-8")

    def _probe(self):
        import liebert_re.evidence.index as index_module
        import liebert_re.tools.generic_static_probe as probe
        with mock.patch.object(probe, "EVIDENCE", self.evidence_root / "generic_static_probe"), \
                mock.patch.object(index_module, "EVIDENCE_ROOT_DEFAULT", self.evidence_root), \
                mock.patch.object(probe, "_evidence_index_record_write", return_value={"ok": True}) as hook:
            return json.loads(probe.generic_static_probe(str(self.sample))), hook

    def test_the_result_carries_the_evidence_identity_of_the_file_it_wrote(self):
        from liebert_re.evidence.index import _evidence_uid
        result, hook = self._probe()
        self.assertRegex(result["evidence_id"], r"^EVX-[0-9a-f]{20}$")
        written = self.evidence_root / "generic_static_probe" / result["evidence_file"]
        self.assertEqual(result["evidence_id"], _evidence_uid("generic_static_probe/" + result["evidence_file"]))
        self.assertEqual(json.loads(written.read_text(encoding="utf-8"))["evidence_id"], result["evidence_id"])
        hook.assert_called_once()

    def test_an_unwritable_ledger_leaves_the_id_empty_and_says_why(self):
        import liebert_re.tools.generic_static_probe as probe
        blocker = self.root / "blocked"
        blocker.write_text("a file where a folder is needed", encoding="utf-8")
        with mock.patch.object(probe, "EVIDENCE", blocker / "sub"), \
                mock.patch("liebert_re.evidence.index.EVIDENCE_ROOT_DEFAULT", self.root):
            result = json.loads(probe.generic_static_probe(str(self.sample)))
        self.assertIsNone(result["evidence_id"])
        self.assertTrue(result["evidence_error"].startswith("EVIDENCE_NOT_WRITTEN"))
        self.assertNotIn("evidence_file", result)

    def test_a_path_outside_the_index_root_never_gets_an_invented_id(self):
        import liebert_re.tools.generic_static_probe as probe
        with mock.patch.object(probe, "EVIDENCE", self.root / "elsewhere"), \
                mock.patch("liebert_re.evidence.index.EVIDENCE_ROOT_DEFAULT", self.evidence_root):
            result = json.loads(probe.generic_static_probe(str(self.sample)))
        self.assertIsNone(result["evidence_id"])
        self.assertTrue(result["evidence_error"].startswith("EVIDENCE_PATH_OUTSIDE_INDEX_ROOT"))


if __name__ == "__main__":
    unittest.main()
