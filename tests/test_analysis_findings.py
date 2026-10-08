import unittest

from liebert_re.report.exploit_validation import build_validation_plan
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
            # SUPPORTED means the cited evidence resolves in an index; without one the
            # status is UNVERIFIED (see EvidenceBindingTests).
            known_evidence_ids=["EV-FLOW"],
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


class EvidenceBindingTests(unittest.TestCase):
    def build(self, **kwargs):
        return build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one", category="input_validation",
            observed_pattern="input reaches privileged file operation",
            supporting_evidence=["made-up-id"], missing_evidence=[], **kwargs,
        )

    def test_cited_id_with_no_index_is_unverified_not_supported(self):
        row = self.build()
        self.assertEqual(row["status"], "UNVERIFIED")
        self.assertEqual(row["confidence"], "LOW")
        self.assertTrue(validate_finding(row)["ok"])
        self.assertEqual(validate_finding(row)["evidence_binding"], "UNCHECKED")

    def test_id_missing_from_the_index_is_never_supported(self):
        row = self.build(known_evidence_ids=["EV-OTHER"])
        self.assertEqual(row["status"], "NEEDS_MORE_ANALYSIS")

    def test_id_present_in_the_index_is_supported(self):
        self.assertEqual(self.build(known_evidence_ids=["made-up-id"])["status"], "SUPPORTED")

    def test_counter_evidence_pass_does_not_restore_supported_for_unknown_ids(self):
        row = verify_counter_evidence(self.build(), [], known_evidence_ids=["EV-OTHER"])
        self.assertEqual(row["status"], "NEEDS_MORE_ANALYSIS")

    def test_hand_written_supported_json_is_downgraded_in_the_report(self):
        row = self.build(known_evidence_ids=["made-up-id"])
        self.assertEqual(row["status"], "SUPPORTED")
        unchecked = render_finding_report([row])
        self.assertEqual(unchecked["findings"][0]["status"], "UNVERIFIED")
        self.assertEqual(unchecked["findings"][0]["confidence"], "LOW")
        unresolved = render_finding_report([row], known_evidence_ids=["EV-OTHER"])
        self.assertEqual(unresolved["findings"][0]["status"], "NEEDS_MORE_ANALYSIS")
        self.assertEqual(unresolved["status"], "FAIL")
        self.assertIn("SUPPORTED_WITH_UNKNOWN_EVIDENCE", unresolved["findings"][0]["contract_validation"]["issues"])
        verified = render_finding_report([row], known_evidence_ids=["made-up-id"])
        self.assertEqual(verified["findings"][0]["status"], "SUPPORTED")
        self.assertEqual(verified["status"], "PASS")


class ReproductionClaimTests(unittest.TestCase):
    SHA = "a" * 64

    def hypothesis(self, **extra):
        row = build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one", category="input_validation",
            observed_pattern="input reaches privileged file operation",
            supporting_evidence=["EV-FLOW"], known_evidence_ids=["EV-FLOW"],
        )
        row.update(extra)
        return row

    def plan_and_result(self, hypothesis):
        plan = build_validation_plan(
            hypothesis, self.SHA, backend="vm-backend",
            isolation_descriptor={"isolation_kind": "VIRTUAL_MACHINE", "not_the_analysis_host": True, "asserted_by": "test-operator"},
        )
        result = {
            "plan_id": plan["plan_id"], "test_case_id": plan["test_case_id"], "target_sha256": self.SHA,
            "backend": "vm-backend", "vm_id": "vm-1", "snapshot_id": "snap-1",
            "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
            "exit_status": "0", "watchdog_status": "PASS", "revert_status": "PASS",
            "observations": {key: True for key in plan["required_validation_links"]},
            "artifacts": ["log"], "evidence_ids": ["E-1"],
            "environment": {"isolated_vm": True, "target_hash_reverified": True, "os_build": "build-1", "architecture": "x64"},
        }
        return plan, result

    def test_bare_confirmed_claim_is_not_dynamic_validation(self):
        report = render_finding_report([self.hypothesis(reproduction_status="CONFIRMED")])
        row = report["findings"][0]
        self.assertEqual(row["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertFalse(report["dynamic_validation_performed"])
        self.assertEqual(report["coverage"]["UNSPECIFIED"], "UNKNOWN")
        claim = row["contract_validation"]["reproduction_claim"]
        self.assertEqual((claim["claimed"], claim["verified"]), ("CONFIRMED", False))

    def test_verified_plan_and_result_is_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = render_finding_report([hypothesis])
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMED")
        self.assertTrue(report["dynamic_validation_performed"])

    def test_result_the_verifier_rejects_is_not_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        result["revert_status"] = "NOT_APPLICABLE"
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = render_finding_report([hypothesis])
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertFalse(report["dynamic_validation_performed"])
        self.assertIn("AUTOMATIC_REVERT_NOT_VERIFIED", report["findings"][0]["contract_validation"]["reproduction_claim"]["issues"])

    def test_plan_for_another_hypothesis_is_not_accepted(self):
        hypothesis = self.hypothesis()
        other = dict(hypothesis, hypothesis_id="HYP-IR-other")
        plan, result = self.plan_and_result(other)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = render_finding_report([hypothesis])
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertFalse(report["dynamic_validation_performed"])


if __name__ == "__main__":
    unittest.main()
