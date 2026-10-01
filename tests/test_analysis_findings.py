import unittest

from liebert_re.report.analysis_findings import (
    build_security_hypothesis, render_finding_report, validate_finding,
    verify_counter_evidence,
)


class AnalysisFindingTests(unittest.TestCase):
    def hypothesis(self):
        return build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one",
            category="input_validation", observed_pattern="input reaches privileged file operation",
            supporting_evidence=["EV-FLOW"], missing_evidence=[],
        )

    def test_supported_static_hypothesis_is_never_confirmed(self):
        row = self.hypothesis()
        self.assertEqual(row["status"], "SUPPORTED")
        self.assertFalse(row["confirmed_vulnerability"])
        self.assertTrue(validate_finding(row)["ok"])

    def test_bound_counter_evidence_refutes_and_records_scope(self):
        row = verify_counter_evidence(
            self.hypothesis(),
            [{"kind": "BOUNDS_CHECK", "summary": "caller verifies length", "evidence_ids": ["EV-GUARD"]}],
            known_evidence_ids=["EV-FLOW", "EV-GUARD"], searched_scope=["callers:depth=2"],
        )
        self.assertEqual(row["status"], "REFUTED")
        self.assertEqual(row["counter_evidence"][0]["scope"], ["callers:depth=2"])

    def test_unbound_counter_cannot_refute(self):
        row = verify_counter_evidence(
            self.hypothesis(), [{"kind": "SANITIZER", "evidence_ids": ["EV-MISSING"]}],
            known_evidence_ids=["EV-FLOW"],
        )
        self.assertEqual(row["status"], "SUPPORTED")
        self.assertEqual(row["counter_evidence"], [])

    def test_report_is_generic_and_static_only(self):
        report = render_finding_report(
            [self.hypothesis()], artifact_hashes={"artifact:one": "a" * 64}, scope_notes=["authorized static review"],
        )
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["dynamic_validation_performed"])
        self.assertEqual(report["findings"][0]["reproduction_status"], "NOT_EXECUTED")

    def test_attack_resistance_fields_default_on_minimal_hypothesis(self):
        row = self.hypothesis()
        self.assertEqual(row["facet"], "UNSPECIFIED")
        self.assertEqual(row["attacker_goal"], "")
        self.assertEqual(row["attacker_effort"], "UNKNOWN")
        self.assertEqual(row["severity"], "UNKNOWN")
        self.assertEqual(row["remediation"], "")

    def test_claim_type_fields_default_empty_additive_only(self):
        """GAP-061 step 4: a caller that never opts in gets exactly the
        same finding shape as before these fields existed -- empty/None
        defaults, never invented content."""
        row = self.hypothesis()
        self.assertEqual(row["claim_type"], "")
        self.assertEqual(row["claim_target"], "")
        self.assertIsNone(row["claim_address"])
        self.assertEqual(row["claim_address_kind"], "va")
        self.assertIsNone(row["claim_constant_value"])

    def test_claim_type_fields_round_trip_verbatim_when_supplied(self):
        """The exact field names assessment_run._constant_at_address_verdict
        reads must survive build_security_hypothesis unchanged -- this is
        the constructor-side half of GAP-061 step 4's mapping layer."""
        row = build_security_hypothesis(
            artifact_id="artifact:const", function_id="function:const",
            category="license_check", observed_pattern="constant compared at address",
            supporting_evidence=[], missing_evidence=[],
            claim_type="constant_at_address", claim_target="probe.bin",
            claim_address="0x401000", claim_address_kind="rva", claim_constant_value="0x1234",
        )
        self.assertEqual(row["claim_type"], "constant_at_address")
        self.assertEqual(row["claim_target"], "probe.bin")
        self.assertEqual(row["claim_address"], "0x401000")
        self.assertEqual(row["claim_address_kind"], "rva")
        self.assertEqual(row["claim_constant_value"], "0x1234")

    def test_attack_resistance_fields_round_trip_through_report(self):
        hypothesis = build_security_hypothesis(
            artifact_id="artifact:two", function_id="function:two",
            category="license_check", observed_pattern="license key derived from HWID",
            supporting_evidence=["EV-FLOW"], missing_evidence=[],
            facet="keygen", attacker_goal="derive a valid license key",
            attacker_effort="LOW", severity="high", remediation="bind key issuance server-side",
        )
        report = render_finding_report(
            [hypothesis], artifact_hashes={"artifact:two": "b" * 64}, scope_notes=[],
        )
        row = report["findings"][0]
        self.assertEqual(row["facet"], "KEYGEN")
        self.assertEqual(row["attacker_goal"], "derive a valid license key")
        self.assertEqual(row["attacker_effort"], "LOW")
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["remediation"], "bind key issuance server-side")
        self.assertIsNone(row["reproduction_ref"])
        self.assertIn("KEYGEN", report["coverage"])

    def test_confirmed_vulnerability_flag_stays_forbidden_with_new_fields(self):
        hypothesis = self.hypothesis()
        hypothesis["confirmed_vulnerability"] = True
        hypothesis["severity"] = "CRITICAL"
        result = validate_finding(hypothesis)
        self.assertFalse(result["ok"])
        self.assertIn("STATIC_CONFIRMATION_FORBIDDEN", result["issues"])


if __name__ == "__main__":
    unittest.main()
