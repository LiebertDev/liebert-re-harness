import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from liebert_re.evidence.index import EvidenceIndex
from liebert_re.report.exploit_validation import build_validation_plan
from liebert_re.report.analysis_findings import (
    build_security_hypothesis, render_finding_report, validate_finding,
    counter_evidence_verify, finding_report_generate, verify_counter_evidence,
)


class EvidenceStoreCase(unittest.TestCase):
    """A real EvidenceIndex over a temporary corpus: the only thing that may resolve a cited ID."""

    FILES = {
        "FLOW": "flow_1111111111_report_222222.json",
        "GUARD": "guard_3333333333_report_444444.json",
        "OTHER": "other_5555555555_report_666666.json",
    }

    @classmethod
    def setUpClass(cls):
        tmp = TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name) / "evidence"
        root.mkdir()
        for name in cls.FILES.values():
            (root / name).write_text(json.dumps({"ok": True}), encoding="utf-8")
        cls.root, cls.db_path = root, Path(tmp.name) / "evidence.sqlite"
        cls.store = EvidenceIndex(root, db_path=cls.db_path)
        cls.store.refresh()
        cls.ids = {key: cls.store.record(path=name)["evidence_uid"] for key, name in cls.FILES.items()}


class AnalysisFindingTests(EvidenceStoreCase):
    def hypothesis(self):
        return build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one",
            category="input_validation", observed_pattern="input reaches privileged file operation",
            supporting_evidence=[self.ids["FLOW"]], missing_evidence=[],
            # SUPPORTED means the cited evidence resolves in an evidence store; without one the
            # status is UNVERIFIED (see EvidenceBindingTests).
            evidence_store=self.store,
        )

    def test_supported_static_hypothesis_is_never_confirmed(self):
        row = self.hypothesis()
        self.assertEqual(row["status"], "SUPPORTED")
        self.assertFalse(row["confirmed_vulnerability"])
        self.assertTrue(validate_finding(row, evidence_store=self.store)["ok"])

    def test_bound_counter_evidence_refutes_and_records_scope(self):
        row = verify_counter_evidence(
            self.hypothesis(),
            [{"kind": "BOUNDS_CHECK", "summary": "caller verifies length", "evidence_ids": [self.ids["GUARD"]]}],
            evidence_store=self.store, searched_scope=["callers:depth=2"],
        )
        self.assertEqual(row["status"], "REFUTED")
        self.assertEqual(row["counter_evidence"][0]["scope"], ["callers:depth=2"])

    def test_unbound_counter_cannot_refute(self):
        row = verify_counter_evidence(
            self.hypothesis(), [{"kind": "SANITIZER", "evidence_ids": ["EVX-missing"]}],
            evidence_store=self.store,
        )
        self.assertEqual(row["status"], "SUPPORTED")
        self.assertEqual(row["counter_evidence"], [])

    def test_report_is_generic_and_static_only(self):
        report = render_finding_report(
            [self.hypothesis()], artifact_hashes={"artifact:one": "a" * 64}, scope_notes=["authorized static review"],
            evidence_store=self.store,
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
            supporting_evidence=[self.ids["FLOW"]], missing_evidence=[],
            facet="keygen", attacker_goal="derive a valid license key",
            attacker_effort="LOW", severity="high", remediation="bind key issuance server-side",
        )
        report = render_finding_report(
            [hypothesis], artifact_hashes={"artifact:two": "b" * 64}, scope_notes=[],
            evidence_store=self.store,
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
        result = validate_finding(hypothesis, evidence_store=self.store)
        self.assertFalse(result["ok"])
        self.assertIn("STATIC_CONFIRMATION_FORBIDDEN", result["issues"])


class EvidenceBindingTests(EvidenceStoreCase):
    def build(self, cited=None, **kwargs):
        return build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one", category="input_validation",
            observed_pattern="input reaches privileged file operation",
            supporting_evidence=cited or [self.ids["FLOW"]], missing_evidence=[], **kwargs,
        )

    def test_cited_id_with_no_store_is_unverified_not_supported(self):
        row = self.build()
        self.assertEqual(row["status"], "UNVERIFIED")
        self.assertEqual(row["confidence"], "LOW")
        self.assertTrue(validate_finding(row)["ok"])
        self.assertEqual(validate_finding(row)["evidence_binding"], "UNCHECKED")

    def test_caller_supplied_id_list_cannot_make_a_forged_id_supported(self):
        """The audited forgery: the list is the caller's own word and proves nothing."""
        row = build_security_hypothesis(
            artifact_id="a", category="c", observed_pattern="p",
            supporting_evidence=["fake"], known_evidence_ids=["fake"],
        )
        self.assertEqual(row["status"], "UNVERIFIED")
        report = render_finding_report([row], known_evidence_ids=["fake"])
        self.assertNotEqual(report["findings"][0]["status"], "SUPPORTED")

    def test_forged_id_is_not_supported_even_with_a_real_store_and_a_matching_list(self):
        for cited in ("fake", "EVX-fake", "7"):
            row = build_security_hypothesis(
                artifact_id="a", category="c", observed_pattern="p", supporting_evidence=[cited],
                known_evidence_ids=[cited], evidence_store=self.store,
            )
            self.assertNotEqual(row["status"], "SUPPORTED", cited)

    def test_a_store_lookup_that_raises_resolves_nothing(self):
        class Broken(EvidenceIndex):
            def record(self, *args, **kwargs):
                raise RuntimeError("index unreadable")

        broken = Broken(self.root, db_path=self.db_path)
        self.assertEqual(self.build(evidence_store=broken)["status"], "NEEDS_MORE_ANALYSIS")

    def test_an_object_that_is_not_an_evidence_index_is_no_store(self):
        class Yes:
            def record(self, record_id=None, path=None):
                return {"ok": True, "evidence_uid": record_id}

        self.assertEqual(self.build(evidence_store=Yes())["status"], "UNVERIFIED")

    def test_id_missing_from_the_store_is_never_supported(self):
        row = self.build(cited=["EVX-0000000000000000"], evidence_store=self.store)
        self.assertEqual(row["status"], "NEEDS_MORE_ANALYSIS")

    def test_id_outside_the_callers_own_list_is_not_accepted(self):
        row = self.build(known_evidence_ids=[self.ids["OTHER"]], evidence_store=self.store)
        self.assertEqual(row["status"], "NEEDS_MORE_ANALYSIS")

    def test_id_present_in_the_store_is_supported(self):
        self.assertEqual(self.build(evidence_store=self.store)["status"], "SUPPORTED")
        row = self.build(known_evidence_ids=[self.ids["FLOW"]], evidence_store=self.store)
        self.assertEqual(row["status"], "SUPPORTED")

    def test_counter_evidence_pass_does_not_restore_supported_for_unknown_ids(self):
        row = self.build(evidence_store=self.store)
        gone = dict(row, supporting_evidence=["EVX-0000000000000000"])
        result = verify_counter_evidence(gone, [], evidence_store=self.store)
        self.assertEqual(result["status"], "NEEDS_MORE_ANALYSIS")

    def test_counter_evidence_without_a_store_binds_nothing_and_cannot_refute(self):
        row = self.build(evidence_store=self.store)
        forged = [{"kind": "SANITIZER", "evidence_ids": ["fake"]}]
        for kwargs in ({}, {"known_evidence_ids": ["fake"]}):
            result = verify_counter_evidence(row, forged, **kwargs)
            self.assertEqual(result["counter_evidence"], [])
            self.assertNotEqual(result["status"], "REFUTED")
            self.assertNotEqual(result["status"], "SUPPORTED")  # nothing was verified either
        refuted = verify_counter_evidence(row, forged, known_evidence_ids=["fake"], evidence_store=self.store)
        self.assertEqual(refuted["counter_evidence"], [])

    def test_hand_written_supported_json_is_downgraded_in_the_report(self):
        row = self.build(evidence_store=self.store)
        self.assertEqual(row["status"], "SUPPORTED")
        unchecked = render_finding_report([row])
        self.assertEqual(unchecked["findings"][0]["status"], "UNVERIFIED")
        self.assertEqual(unchecked["findings"][0]["confidence"], "LOW")
        forged = dict(row, supporting_evidence=["EVX-0000000000000000"])
        unresolved = render_finding_report([forged], evidence_store=self.store)
        self.assertEqual(unresolved["findings"][0]["status"], "NEEDS_MORE_ANALYSIS")
        self.assertEqual(unresolved["status"], "FAIL")
        self.assertIn("SUPPORTED_WITH_UNKNOWN_EVIDENCE", unresolved["findings"][0]["contract_validation"]["issues"])
        verified = render_finding_report([row], evidence_store=self.store)
        self.assertEqual(verified["findings"][0]["status"], "SUPPORTED")
        self.assertEqual(verified["status"], "PASS")

    def test_supported_record_passes_validation_only_when_the_binding_is_verified(self):
        """validate_finding used to PASS a SUPPORTED record whose evidence was never checked."""
        row = self.build(evidence_store=self.store)
        self.assertEqual(row["status"], "SUPPORTED")
        unchecked = validate_finding(row)
        self.assertEqual((unchecked["status"], unchecked["evidence_binding"]), ("FAIL", "UNCHECKED"))
        self.assertIn("SUPPORTED_EVIDENCE_NOT_VERIFIED", unchecked["issues"])
        listed = validate_finding(row, known_evidence_ids=[self.ids["FLOW"]])
        self.assertEqual(listed["status"], "FAIL")  # a list alone is not verification
        self.assertEqual(validate_finding(row, evidence_store=self.store)["status"], "PASS")
        forged = dict(row, supporting_evidence=["fake"])
        self.assertEqual(validate_finding(forged, known_evidence_ids=["fake"])["status"], "FAIL")

    def test_json_tools_resolve_through_the_named_evidence_index(self):
        row = self.build(evidence_store=self.store)
        paths = {"evidence_root": str(self.root), "evidence_db_path": str(self.db_path)}
        report = json.loads(finding_report_generate(json.dumps([row]), **paths))
        self.assertEqual(report["findings"][0]["status"], "SUPPORTED")
        no_store = json.loads(finding_report_generate(json.dumps([row]), known_evidence_ids=[self.ids["FLOW"]]))
        self.assertEqual(no_store["findings"][0]["status"], "UNVERIFIED")
        counter = [{"kind": "SANITIZER", "evidence_ids": [self.ids["GUARD"]]}]
        bound = json.loads(counter_evidence_verify(json.dumps(row), json.dumps(counter), **paths))
        self.assertEqual(bound["status"], "REFUTED")
        unbound = json.loads(counter_evidence_verify(json.dumps(row), json.dumps(counter), [self.ids["GUARD"]]))
        self.assertNotEqual(unbound["status"], "REFUTED")


class ValidationRequiredFlagTests(EvidenceStoreCase):
    def row(self, **extra):
        hypothesis = build_security_hypothesis(
            artifact_id="a", category="c", observed_pattern="p",
            supporting_evidence=[self.ids["FLOW"]], evidence_store=self.store,
        )
        hypothesis.update(extra)
        return render_finding_report([hypothesis], evidence_store=self.store)["findings"][0]

    def test_only_a_real_bool_is_carried(self):
        self.assertIs(self.row()["validation_required"], True)
        self.assertIs(self.row(validation_required=False)["validation_required"], False)
        self.assertIs(self.row(validation_required=True)["validation_required"], True)

    def test_text_numbers_and_none_are_unknown_not_coerced(self):
        for bad in ("false", "true", "no", 0, 1, None, [], ""):
            self.assertEqual(self.row(validation_required=bad)["validation_required"], "UNKNOWN", repr(bad))


class ReproductionClaimTests(EvidenceStoreCase):
    SHA = "a" * 64

    def hypothesis(self, **extra):
        row = build_security_hypothesis(
            artifact_id="artifact:one", function_id="function:one", category="input_validation",
            observed_pattern="input reaches privileged file operation",
            supporting_evidence=[self.ids["FLOW"]], evidence_store=self.store,
        )
        row.update(extra)
        return row

    def plan_and_result(self, hypothesis, sha=None):
        sha = sha or self.SHA
        plan = build_validation_plan(
            hypothesis, sha, backend="vm-backend",
            isolation_descriptor={"isolation_kind": "VIRTUAL_MACHINE", "not_the_analysis_host": True, "asserted_by": "test-operator"},
        )
        result = {
            "plan_id": plan["plan_id"], "test_case_id": plan["test_case_id"], "target_sha256": sha,
            "backend": "vm-backend", "vm_id": "vm-1", "snapshot_id": "snap-1",
            "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
            "exit_status": "0", "watchdog_status": "PASS", "revert_status": "PASS",
            "observations": {key: True for key in plan["required_validation_links"]},
            "artifacts": ["log"], "evidence_ids": [self.ids["OTHER"]],
            "environment": {"isolated_vm": True, "target_hash_reverified": True, "os_build": "build-1", "architecture": "x64"},
        }
        return plan, result

    def render(self, hypothesis, sha=None):
        return render_finding_report(
            [hypothesis], artifact_hashes={"artifact:one": sha or self.SHA}, evidence_store=self.store,
        )

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
        report = self.render(hypothesis)
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMED")
        self.assertTrue(report["dynamic_validation_performed"])
        self.assertEqual(report["coverage"]["UNSPECIFIED"], "RESOLVED")

    def test_plan_validated_against_another_binary_than_the_reported_artifact_is_not_accepted(self):
        """The plan, result and hypothesis agree with each other, but on a target hash that is
        not the artifact the report names."""
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis, sha="b" * 64)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = self.render(hypothesis)  # reports artifact hash "a" * 64
        row = report["findings"][0]
        self.assertEqual(row["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertEqual(row["contract_validation"]["reproduction_claim"]["reason"], "PLAN_TARGET_NOT_REPORTED_ARTIFACT")
        self.assertFalse(report["dynamic_validation_performed"])
        self.assertEqual(report["coverage"]["UNSPECIFIED"], "UNKNOWN")

    def test_confirmation_with_no_reported_artifact_hash_is_not_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = render_finding_report([hypothesis], evidence_store=self.store)
        row = report["findings"][0]
        self.assertEqual(row["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertEqual(row["contract_validation"]["reproduction_claim"]["reason"], "ARTIFACT_HASH_UNKNOWN")

    def test_dynamic_evidence_that_the_store_does_not_know_is_not_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        result["evidence_ids"] = ["E-does-not-exist"]
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = self.render(hypothesis)
        row = report["findings"][0]
        self.assertEqual(row["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertIn("DYNAMIC_EVIDENCE_UNRESOLVED", row["contract_validation"]["reproduction_claim"]["issues"])
        self.assertEqual(report["coverage"]["UNSPECIFIED"], "UNKNOWN")

    def test_confirmation_with_no_evidence_store_is_not_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = render_finding_report([hypothesis], artifact_hashes={"artifact:one": self.SHA})
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMATION_UNVERIFIED")

    def test_result_the_verifier_rejects_is_not_accepted(self):
        hypothesis = self.hypothesis()
        plan, result = self.plan_and_result(hypothesis)
        result["revert_status"] = "NOT_APPLICABLE"
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = self.render(hypothesis)
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertFalse(report["dynamic_validation_performed"])
        self.assertIn("AUTOMATIC_REVERT_NOT_VERIFIED", report["findings"][0]["contract_validation"]["reproduction_claim"]["issues"])

    def test_plan_for_another_hypothesis_is_not_accepted(self):
        hypothesis = self.hypothesis()
        other = dict(hypothesis, hypothesis_id="HYP-IR-other")
        plan, result = self.plan_and_result(other)
        hypothesis.update(reproduction_status="CONFIRMED", validation_plan=plan, validation_result=result)
        report = self.render(hypothesis)
        self.assertEqual(report["findings"][0]["reproduction_status"], "CONFIRMATION_UNVERIFIED")
        self.assertFalse(report["dynamic_validation_performed"])


class EvidenceReadFreshnessTests(unittest.TestCase):
    """A store that cached a good record must not keep a finding SUPPORTED once the bytes on
    disk are no longer a complete, parseable record."""

    NAME = "flow_1111111111_report_222222.json"

    def supported(self, tmp):
        root = Path(tmp) / "evidence"
        root.mkdir()
        (root / self.NAME).write_text(json.dumps({"ok": True, "pad": "x" * 64}), encoding="utf-8")
        store = EvidenceIndex(root, db_path=Path(tmp) / "evidence.sqlite")
        store.refresh()
        uid = store.record(path=self.NAME)["evidence_uid"]
        row = build_security_hypothesis(
            artifact_id="a", category="c", observed_pattern="p", supporting_evidence=[uid], evidence_store=store,
        )
        self.assertEqual(row["status"], "SUPPORTED")
        return root, store, row

    def test_bytes_corrupted_after_indexing_are_not_supported(self):
        with TemporaryDirectory() as tmp:
            root, store, row = self.supported(tmp)
            (root / self.NAME).write_bytes(b'{"ok": tru\xff\xfe')
            report = render_finding_report([row], evidence_store=store)
            self.assertNotEqual(report["findings"][0]["status"], "SUPPORTED")
            self.assertEqual(report["findings"][0]["contract_validation"]["evidence_binding"], "UNRESOLVED")
            rebuilt = build_security_hypothesis(
                artifact_id="a", category="c", observed_pattern="p",
                supporting_evidence=row["supporting_evidence"], evidence_store=store,
            )
            self.assertEqual(rebuilt["status"], "NEEDS_MORE_ANALYSIS")

    def test_a_truncated_read_is_not_supported(self):
        with TemporaryDirectory() as tmp:
            _root, store, row = self.supported(tmp)
            with mock.patch("liebert_re.evidence.index.MAX_RECORD_BYTES", 16):
                self.assertEqual(store.record(record_id=row["supporting_evidence"][0])["read_error"], "TRUNCATED")
                report = render_finding_report([row], evidence_store=store)
            self.assertNotEqual(report["findings"][0]["status"], "SUPPORTED")
            self.assertEqual(report["findings"][0]["contract_validation"]["evidence_binding"], "UNRESOLVED")

    def test_intact_bytes_stay_supported(self):
        with TemporaryDirectory() as tmp:
            _root, store, row = self.supported(tmp)
            report = render_finding_report([row], evidence_store=store)
            self.assertEqual(report["findings"][0]["status"], "SUPPORTED")


if __name__ == "__main__":
    unittest.main()
