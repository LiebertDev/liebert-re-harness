"""The claim guard is wired into finding_report_generate as an additive field."""
from __future__ import annotations

import json
import unittest

from liebert_re.report import analysis_findings
from liebert_re.report.analysis_findings import build_security_hypothesis, finding_report_generate

EVIDENCE = "kernel32.dll!CreateFileW\n1500: mov eax, 0x401000\n"
LEGACY_TOP_KEYS = {
    "ok", "schema_version", "status", "finding_count", "findings",
    "dynamic_validation_performed", "exploit_code_generated", "coverage",
}
LEGACY_ROW_KEYS = {
    "finding_id", "artifact_id", "artifact_sha256", "function_id", "location",
    "observed_behavior", "hypothesis", "supporting_evidence", "counter_evidence",
    "missing_validation", "confidence", "status", "validation_required", "facet",
    "attacker_goal", "attacker_effort", "severity", "remediation",
    "reproduction_status", "reproduction_ref", "scope_notes", "contract_validation",
}
ABSENT = object()


def _generate(observed, evidence=ABSENT):
    row = build_security_hypothesis(
        artifact_id="artifact:one", function_id="function:one", category="input_validation",
        observed_pattern=observed, supporting_evidence=["EV-FLOW"], missing_evidence=[],
    )
    kwargs = {} if evidence is ABSENT else {"evidence": evidence}
    return json.loads(finding_report_generate(json.dumps([row]), **kwargs))


class FindingReportClaimGuardTests(unittest.TestCase):
    def test_unproven_hex_address_is_caught_and_visible(self):
        out = _generate("handler at 0xDEADBEEF writes the file", EVIDENCE)
        guard = out["claim_guard"]
        self.assertTrue(guard["checked"])
        self.assertEqual(guard["state"], "CHECKED_ISSUES")
        self.assertTrue(guard["contains_unproven_claims"])
        self.assertTrue(any("0xDEADBEEF" in i for i in guard["issues"]))

    def test_proven_address_is_not_a_false_positive(self):
        out = _generate("handler at 0x401000 writes the file", EVIDENCE)
        guard = out["claim_guard"]
        self.assertTrue(guard["checked"])
        self.assertEqual(guard["state"], "CHECKED_CLEAN")
        self.assertEqual(guard["issues"], [])
        self.assertFalse(guard["contains_unproven_claims"])

    def test_negative_claim_without_evidence_is_caught(self):
        out = _generate("the sample uses no network access at all", EVIDENCE)
        self.assertEqual(out["claim_guard"]["state"], "CHECKED_ISSUES")
        self.assertTrue(any("negative claim" in i for i in out["claim_guard"]["issues"]))

    def test_missing_evidence_is_not_checked_and_distinct_from_clean(self):
        absent = _generate("handler at 0xDEADBEEF")["claim_guard"]
        blank = _generate("handler at 0xDEADBEEF", "  ")["claim_guard"]
        clean = _generate("handler at 0x401000", EVIDENCE)["claim_guard"]
        for g in (absent, blank):
            self.assertFalse(g["checked"])
            self.assertEqual(g["state"], "NOT_CHECKED")
            self.assertIsNone(g["issues"])
            self.assertIsNone(g["contains_unproven_claims"])
            self.assertIn("not audited", g["note"])
        self.assertNotEqual(absent["state"], clean["state"])
        self.assertNotEqual(absent["issues"], clean["issues"])
        self.assertTrue(clean["checked"])

    def test_existing_output_fields_unchanged(self):
        out = _generate("handler at 0x401000", EVIDENCE)
        self.assertEqual(set(out) - {"claim_guard"}, LEGACY_TOP_KEYS)
        self.assertEqual(set(out["findings"][0]), LEGACY_ROW_KEYS)
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "PASS")

    def test_guard_findings_do_not_change_ok_or_status(self):
        out = _generate("handler at 0xDEADBEEF", EVIDENCE)
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "PASS")

    def test_false_positive_caveat_is_stated(self):
        out = _generate("handler at 0x401000", EVIDENCE)
        self.assertIn("regex", out["claim_guard"]["caveat"])
        self.assertIn("false positives", out["claim_guard"]["caveat"])
        doc = analysis_findings.finding_report_generate.__doc__
        self.assertIn("regex", doc)
        self.assertIn("false positives", doc)


if __name__ == "__main__":
    unittest.main()
