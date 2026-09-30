"""A provenance record must say a required input is absent, not carry nulls."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import artifact_provenance as ap

_HASH_KEYS = ("system_prompt_sha256", "tool_registry_hash", "router_hash", "planner_hash", "claim_verifier_hash")


class AbsentInputsAreExplicit(unittest.TestCase):
    def test_empty_checkout_yields_explicit_absent_not_null(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(ap, "APP", Path(d)):
            rec = ap.trajectory_provenance(d, "m")
        for key in _HASH_KEYS:
            self.assertEqual(rec[key], ap.ABSENT, key)
        self.assertFalse(rec["provenance_valid"])
        self.assertEqual(len(rec["absent_inputs"]), 5)

    def test_complete_checkout_is_valid_with_real_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "prompts").mkdir()
            for rel in ("prompts/teacher_system.md", "tool_registry.json", "file_router.py",
                        "deterministic_planner.py", "claim_verifier.py"):
                (root / rel).write_text("x", encoding="utf-8")
            with mock.patch.object(ap, "APP", root):
                rec = ap.trajectory_provenance(d, "m")
        self.assertTrue(rec["provenance_valid"])
        self.assertEqual(rec["absent_inputs"], [])
        for key in _HASH_KEYS:
            self.assertEqual(len(rec[key]), 64, key)


if __name__ == "__main__":
    unittest.main()
