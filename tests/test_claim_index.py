"""Coverage for claim_index.py -- the claim/provenance layer on top of
evidence_index.py. Deliberately never touches dataset/evidence/ or
dataset/claims/ themselves (see evidence_index test's own isolation note):
tests/conftest.py's session guard snapshots the real evidence ledger and
fails the whole suite if it changes during a run, and it cannot distinguish
this test's writes from a concurrent agent's real evidence writes. Every
test here builds its own TemporaryDirectory-based evidence root and claim
events_root/db_path.

RealCaseValidationTests copies the REAL evidence file bytes for today's
motivating failure (four successive TBM.exe claims, each refuted) from the
real dataset/evidence/ corpus into an isolated fixture directory -- real
content, isolated location -- and proves the claim layer lands every one of
them as CONTRADICTED automatically, matching the task brief's validation
requirement.
"""
from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest
from liebert_re.evidence.claim_index import ClaimError, ClaimIndex, claim_index
from liebert_re.evidence.index import EvidenceIndex

REAL_EVIDENCE_ROOT = Path(__file__).resolve().parent.parent / "dataset" / "evidence"
REAL_CASE_FILES = [
    "tbm_loading_gate_static.md",
    "TBM_de2a5b567b_admin_gate_early_exit_2026-09-25.json",
    "tbm_patched_driver_run1.png",
    "tbm_reboot_thread_wait_measurement_2026-09-24.json",
    "tbm_task_token_elevation_verified_2026-09-25.json",
    "TBM_de2a5b567b_admin_branch_km_kill_verified_2026-09-25.json",
    "TBMKD_c360147601_reason1_killpath_classification_and_patch_diff_2026-09-25.json",
]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _make_indices(tmp: Path):
    evidence_root = tmp / "evidence"
    evidence_root.mkdir()
    evidence_index = EvidenceIndex(evidence_root, db_path=tmp / "evidence.sqlite")
    claims = ClaimIndex(
        db_path=tmp / "claims.sqlite", events_root=tmp / "claims_events", evidence_index=evidence_index,
    )
    return evidence_root, evidence_index, claims


class ClaimCreationAndTransitionTests(unittest.TestCase):
    def test_proven_requires_supporting_evidence(self):
        with TemporaryDirectory() as tmp:
            _, evidence_index, claims = _make_indices(Path(tmp))
            with self.assertRaises(ClaimError) as ctx:
                claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="PROVEN")
            self.assertEqual(ctx.exception.code, "PROVEN_REQUIRES_SUPPORTING_EVIDENCE")

    def test_contradicted_rejected_as_initial_status(self):
        with TemporaryDirectory() as tmp:
            _, evidence_index, claims = _make_indices(Path(tmp))
            with self.assertRaises(ClaimError) as ctx:
                claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="CONTRADICTED")
            self.assertEqual(ctx.exception.code, "CONTRADICTED_NOT_A_VALID_INITIAL_STATUS")

    def test_candidate_creation(self):
        with TemporaryDirectory() as tmp:
            _, evidence_index, claims = _make_indices(Path(tmp))
            result = claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="CANDIDATE")
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "CANDIDATE")

    def test_supports_evidence_does_not_promote(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "ev_1111111111_report_222222.json", {"ok": True, "tool": "manual_review"})
            evidence_index.refresh()
            uid = evidence_index.by_target("ev", strict=True)["results"][0]["evidence_uid"]
            created = claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="CANDIDATE")
            claims.add_evidence(created["claim_uid"], uid, "SUPPORTS")
            self.assertEqual(claims._current_status(created["claim_uid"]), "CANDIDATE")

    def test_refuting_evidence_flips_proven_to_contradicted(self):
        """Requirement 4, directly: adding refuting evidence to a PROVEN
        claim must not silently leave it PROVEN."""
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "sup_1111111111_report_222222.json", {"ok": True, "tool": "manual_review"})
            _write_json(root / "ref_3333333333_report_444444.json", {"ok": True, "tool": "manual_review"})
            evidence_index.refresh()
            sup_uid = evidence_index.record(path="sup_1111111111_report_222222.json")["evidence_uid"]
            ref_uid = evidence_index.record(path="ref_3333333333_report_444444.json")["evidence_uid"]
            created = claims.create_claim(
                "t", "function", "FUN_1", "root_cause", "x", status="PROVEN",
                initial_evidence=[{"evidence_uid": sup_uid, "relation": "SUPPORTS"}],
            )
            self.assertEqual(created["status"], "PROVEN")
            result = claims.add_evidence(created["claim_uid"], ref_uid, "REFUTES")
            self.assertEqual(result["status"], "CONTRADICTED")

    def test_contradicted_is_not_revived_by_later_support(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "a_1111111111_report_222222.json", {"ok": True})
            _write_json(root / "b_3333333333_report_444444.json", {"ok": True})
            _write_json(root / "c_5555555555_report_666666.json", {"ok": True})
            evidence_index.refresh()
            a = evidence_index.record(path="a_1111111111_report_222222.json")["evidence_uid"]
            b = evidence_index.record(path="b_3333333333_report_444444.json")["evidence_uid"]
            c = evidence_index.record(path="c_5555555555_report_666666.json")["evidence_uid"]
            created = claims.create_claim(
                "t", "function", "FUN_1", "root_cause", "x", status="PROVEN",
                initial_evidence=[{"evidence_uid": a, "relation": "SUPPORTS"}],
            )
            claims.add_evidence(created["claim_uid"], b, "REFUTES")
            self.assertEqual(claims._current_status(created["claim_uid"]), "CONTRADICTED")
            claims.add_evidence(created["claim_uid"], c, "SUPPORTS")
            self.assertEqual(
                claims._current_status(created["claim_uid"]), "CONTRADICTED",
                "a CONTRADICTED claim must never be silently revived by adding more SUPPORTS evidence",
            )

    def test_evidence_not_found_rejected_when_bound(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            created = claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="CANDIDATE")
            with self.assertRaises(ClaimError) as ctx:
                claims.add_evidence(created["claim_uid"], "EVX-doesnotexist0000000000", "SUPPORTS")
            self.assertEqual(ctx.exception.code, "EVIDENCE_NOT_FOUND")


class SupersedeTests(unittest.TestCase):
    def test_supersede_demotes_old_claim_and_links(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "s_1111111111_report_222222.json", {"ok": True})
            evidence_index.refresh()
            uid = evidence_index.record(path="s_1111111111_report_222222.json")["evidence_uid"]
            old = claims.create_claim(
                "t", "function", "FUN_1", "root_cause", "old-answer", status="PROVEN",
                initial_evidence=[{"evidence_uid": uid, "relation": "SUPPORTS"}],
            )
            new = claims.create_claim(
                "t", "function", "FUN_1", "root_cause", "old-answer", status="CANDIDATE",
            )
            # same subject+predicate+value as `old` -> compatible, no auto-conflict;
            # supersede is an explicit, separate action even when values happen to match.
            result = claims.supersede_claim(new["claim_uid"], old["claim_uid"], reason="re-verified with a cleaner method")
            self.assertEqual(result["old_status"], "CONTRADICTED")
            prov = claims.claim_provenance(old["claim_uid"])
            self.assertEqual(len(prov["superseded_by_edges"]), 1)
            self.assertEqual(prov["superseded_by_edges"][0]["from_claim_uid"], new["claim_uid"])
            new_prov = claims.claim_provenance(new["claim_uid"])
            self.assertEqual(new_prov["supersedes"][0]["to_claim_uid"], old["claim_uid"])


class ContradictionDetectionTests(unittest.TestCase):
    def test_same_subject_same_predicate_different_value_conflicts(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "s_1111111111_report_222222.json", {"ok": True})
            evidence_index.refresh()
            uid = evidence_index.record(path="s_1111111111_report_222222.json")["evidence_uid"]
            first = claims.create_claim(
                "TBM", "address", "14005d9d6", "token_elevation_state", "non-elevated causes exit",
                status="PROVEN", initial_evidence=[{"evidence_uid": uid, "relation": "SUPPORTS"}],
            )
            self.assertEqual(first["status"], "PROVEN")
            second = claims.create_claim(
                "TBM", "address", "0x14005d9d6", "token_elevation_state", "token is fully elevated",
                status="CANDIDATE",
            )
            self.assertIn(first["claim_uid"], second["conflicts_with"])
            self.assertEqual(claims._current_status(first["claim_uid"]), "CONTRADICTED")
            self.assertEqual(claims._current_status(second["claim_uid"]), "CANDIDATE", "the new claim's own status is untouched by the conflict it causes")

    def test_same_subject_same_predicate_same_value_is_not_a_conflict(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "s_1111111111_report_222222.json", {"ok": True})
            evidence_index.refresh()
            uid = evidence_index.record(path="s_1111111111_report_222222.json")["evidence_uid"]
            first = claims.create_claim(
                "TBM", "address", "14005d9d6", "token_elevation_state", "Non-Elevated causes exit",
                status="PROVEN", initial_evidence=[{"evidence_uid": uid, "relation": "SUPPORTS"}],
            )
            second = claims.create_claim(
                "TBM", "address", "14005d9d6", "token_elevation_state", "non-elevated   causes exit",
                status="CANDIDATE",
            )
            self.assertEqual(second["conflicts_with"], [])
            self.assertEqual(claims._current_status(first["claim_uid"]), "PROVEN", "a reinforcing duplicate claim must not disturb the original's status")

    def test_uncomparable_when_predicate_differs_for_same_subject(self):
        """Requirement 3's honesty check: a different predicate about the
        same subject must be flagged UNCOMPARABLE, never silently treated
        as compatible."""
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            first = claims.create_claim(
                "TBM", "address", "1400030ff", "process_survival_after_km_kill", "kill defeated, survives",
                status="CANDIDATE",
            )
            second = claims.create_claim(
                "TBM", "address", "0x1400030FF", "reason1_root_cause", "hypervisor/VM detection",
                status="CANDIDATE",
            )
            self.assertIn(first["claim_uid"], second["uncomparable_with"])
            self.assertEqual(second["conflicts_with"], [])
            # neither status was touched by an UNCOMPARABLE pairing
            self.assertEqual(claims._current_status(first["claim_uid"]), "CANDIDATE")
            self.assertEqual(claims._current_status(second["claim_uid"]), "CANDIDATE")
            prov = claims.claim_provenance(first["claim_uid"])
            self.assertEqual(len(prov["uncomparable_with"]), 1)

    def test_different_subject_is_never_compared(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            # The first claim has to exist for the assertions below to mean
            # anything -- it is the thing `second` could have conflicted with --
            # but nothing reads it back, so the call stays and the binding goes.
            claims.create_claim("TBM", "address", "1000", "root_cause", "A", status="CANDIDATE")
            second = claims.create_claim("TBM", "address", "2000", "root_cause", "B", status="CANDIDATE")
            self.assertEqual(second["conflicts_with"], [])
            self.assertEqual(second["uncomparable_with"], [])


class QueryTests(unittest.TestCase):
    def test_pagination_boundaries(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            for i in range(5):
                claims.create_claim("pg_target", "address", f"{i:04x}", "root_cause", f"v{i}", status="CANDIDATE")
            page1 = claims.claims_for_target("pg_target", limit=2, offset=0)
            self.assertEqual(page1["count"], 2)
            self.assertTrue(page1["truncated"])
            self.assertEqual(page1["next_offset"], 2)
            page2 = claims.claims_for_target("pg_target", limit=2, offset=page1["next_offset"])
            self.assertEqual(page2["count"], 2)
            self.assertTrue(page2["truncated"])
            page3 = claims.claims_for_target("pg_target", limit=2, offset=page2["next_offset"])
            self.assertEqual(page3["count"], 1)
            self.assertFalse(page3["truncated"])
            self.assertIsNone(page3["next_offset"])

    def test_already_claimed(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            claims.create_claim("TBM", "function", "FUN_X", "root_cause", "v1", status="CANDIDATE")
            hit = claims.already_claimed("TBM", "function", "FUN_X")
            self.assertTrue(hit["already_claimed"])
            self.assertEqual(hit["count"], 1)
            miss = claims.already_claimed("TBM", "function", "FUN_X", predicate="unrelated_predicate")
            self.assertFalse(miss["already_claimed"])
            miss2 = claims.already_claimed("TBM", "function", "FUN_NEVER_TOUCHED")
            self.assertFalse(miss2["already_claimed"])

    def test_contradicted_claims_query(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            _write_json(root / "s_1111111111_report_222222.json", {"ok": True})
            _write_json(root / "r_3333333333_report_444444.json", {"ok": True})
            evidence_index.refresh()
            s = evidence_index.record(path="s_1111111111_report_222222.json")["evidence_uid"]
            r = evidence_index.record(path="r_3333333333_report_444444.json")["evidence_uid"]
            proven = claims.create_claim(
                "TBM", "function", "FUN_X", "root_cause", "v1", status="PROVEN",
                initial_evidence=[{"evidence_uid": s, "relation": "SUPPORTS"}],
            )
            still_candidate = claims.create_claim("TBM", "function", "FUN_Y", "root_cause", "v2", status="CANDIDATE")
            claims.add_evidence(proven["claim_uid"], r, "REFUTES")
            result = claims.contradicted_claims("TBM")
            uids = {r["claim_uid"] for r in result["results"]}
            self.assertIn(proven["claim_uid"], uids)
            self.assertNotIn(still_candidate["claim_uid"], uids)
            hit = next(x for x in result["results"] if x["claim_uid"] == proven["claim_uid"])
            self.assertIn("refuting evidence", hit["contradicted_reason"])

    def test_top_level_function_returns_json_string(self):
        with TemporaryDirectory() as tmp:
            root, evidence_index, claims = _make_indices(Path(tmp))
            evidence_index.refresh()
            raw = claim_index(
                operation="create_claim", target="TBM", subject_kind="function", subject_value="FUN_X",
                predicate="root_cause", asserted_value="v1", claim_status="CANDIDATE",
                events_root=str(claims.events_root), db_path=str(claims.db_path),
            )
            payload = json.loads(raw)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["status"], "CANDIDATE")


class UnverifiedEvidenceCannotProveTests(unittest.TestCase):
    """An evidence_uid nobody resolved must never back a PROVEN claim, and a
    non-bool ``inferred`` must never be coerced into metadata."""

    FAKE = [{"evidence_uid": "EVX-made-up", "relation": "SUPPORTS"}]

    def _unbound(self, tmp):
        return ClaimIndex(db_path=tmp / "claims.sqlite", events_root=tmp / "claims_events")

    def test_proven_with_made_up_uid_is_refused_without_an_evidence_store(self):
        with TemporaryDirectory() as tmp:
            claims = self._unbound(Path(tmp))
            with self.assertRaises(ClaimError) as ctx:
                claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="PROVEN", initial_evidence=self.FAKE)
            self.assertEqual(ctx.exception.code, "PROVEN_REQUIRES_EVIDENCE_STORE")
            self.assertEqual(claims.status()["claims"], 0)

    def test_dispatcher_without_evidence_root_cannot_record_proven(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            payload = json.loads(claim_index(
                operation="create_claim", target="t", subject_kind="function", subject_value="FUN_1",
                predicate="root_cause", asserted_value="x", claim_status="PROVEN", initial_evidence=self.FAKE,
                events_root=str(tmp / "ev"), db_path=str(tmp / "c.sqlite"),
            ))
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"], "PROVEN_REQUIRES_EVIDENCE_STORE")

    def test_candidate_without_store_is_still_recorded_unverified(self):
        with TemporaryDirectory() as tmp:
            claims = self._unbound(Path(tmp))
            result = claims.create_claim("t", "function", "FUN_1", "root_cause", "x", initial_evidence=self.FAKE)
            self.assertEqual(result["status"], "CANDIDATE")

    def test_proven_with_unresolvable_uid_leaves_no_event_to_resurrect_it(self):
        with TemporaryDirectory() as tmp:
            _, _, claims = _make_indices(Path(tmp))
            with self.assertRaises(ClaimError) as ctx:
                claims.create_claim("t", "function", "FUN_1", "root_cause", "x", status="PROVEN", initial_evidence=self.FAKE)
            self.assertEqual(ctx.exception.code, "EVIDENCE_NOT_FOUND")
            self.assertEqual(list(claims.events_root.rglob("*.json")), [], "a refused claim must not leave an event file")
            claims.rebuild_from_events()
            self.assertEqual(claims.claims_for_target("t")["results"], [])

    def test_non_bool_inferred_is_rejected_not_coerced(self):
        with TemporaryDirectory() as tmp:
            claims = self._unbound(Path(tmp))
            for bad in ("false", "true", 0, 1, None, "no"):
                with self.assertRaises(ClaimError, msg=repr(bad)) as ctx:
                    claims.create_claim("t", "function", "FUN_1", "root_cause", "x", inferred=bad)
                self.assertEqual(ctx.exception.code, "INVALID_INFERRED")
            self.assertEqual(claims.create_claim("t", "function", "FUN_1", "root_cause", "x", inferred=False)["status"], "CANDIDATE")


class EvidenceUidSurvivesRebuildTests(unittest.TestCase):
    def test_claim_link_survives_full_evidence_index_rebuild(self):
        """The foundation-of-provenance property, verified directly: a
        claim references evidence by evidence_uid, so the link must survive
        a full evidence_index rebuild-from-scratch."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            evidence_root = tmp / "evidence"
            evidence_root.mkdir()
            evidence_db = tmp / "evidence.sqlite"
            _write_json(evidence_root / "x_1111111111_report_222222.json", {"ok": True, "tool": "manual_review"})
            evidence_index = EvidenceIndex(evidence_root, db_path=evidence_db)
            evidence_index.refresh()
            uid = evidence_index.record(path="x_1111111111_report_222222.json")["evidence_uid"]

            claims = ClaimIndex(db_path=tmp / "claims.sqlite", events_root=tmp / "claims_events", evidence_index=evidence_index)
            created = claims.create_claim(
                "x", "function", "FUN_1", "root_cause", "v1", status="PROVEN",
                initial_evidence=[{"evidence_uid": uid, "relation": "SUPPORTS"}],
            )

            # Full rebuild-from-scratch of the EVIDENCE index only.
            evidence_db.unlink()
            rebuilt_evidence_index = EvidenceIndex(evidence_root, db_path=evidence_db)
            rebuilt_evidence_index.refresh()
            rebuilt_uid = rebuilt_evidence_index.record(path="x_1111111111_report_222222.json")["evidence_uid"]
            self.assertEqual(uid, rebuilt_uid, "evidence_uid must be identical after a full rebuild")

            # The claim, bound to a FRESH EvidenceIndex instance over the
            # rebuilt db, must still resolve the citation.
            claims_after_rebuild = ClaimIndex(
                db_path=claims.db_path, events_root=claims.events_root, evidence_index=rebuilt_evidence_index,
            )
            prov = claims_after_rebuild.claim_provenance(created["claim_uid"])
            self.assertEqual(len(prov["supports"]), 1)
            self.assertEqual(prov["supports"][0]["evidence_uid"], uid)
            self.assertIn("evidence_summary", prov["supports"][0], "the uid must still resolve to a real record after rebuild")
            self.assertEqual(prov["supports"][0]["evidence_summary"]["path"], "x_1111111111_report_222222.json")


class ClaimEventFilesAreSourceOfTruthTests(unittest.TestCase):
    def test_rebuild_from_events_reconstructs_claims_db(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            root, evidence_index, claims = _make_indices(tmp)
            _write_json(root / "s_1111111111_report_222222.json", {"ok": True})
            _write_json(root / "r_3333333333_report_444444.json", {"ok": True})
            evidence_index.refresh()
            s = evidence_index.record(path="s_1111111111_report_222222.json")["evidence_uid"]
            r = evidence_index.record(path="r_3333333333_report_444444.json")["evidence_uid"]
            a = claims.create_claim(
                "t", "function", "FUN_1", "root_cause", "v1", status="PROVEN",
                initial_evidence=[{"evidence_uid": s, "relation": "SUPPORTS"}],
            )
            b = claims.create_claim("t", "function", "FUN_1", "root_cause", "v2", status="CANDIDATE")
            claims.add_evidence(a["claim_uid"], r, "REFUTES")
            claims.supersede_claim(b["claim_uid"], a["claim_uid"], reason="corrected")
            before = claims.status()

            claims.db_path.unlink()
            reconstructed = ClaimIndex(db_path=claims.db_path, events_root=claims.events_root, evidence_index=evidence_index)
            self.assertEqual(reconstructed.status()["claims"], 0, "a fresh db must not silently claim to already hold data")
            rebuild_result = reconstructed.rebuild_from_events()
            self.assertTrue(rebuild_result["ok"])
            after = reconstructed.status()
            self.assertEqual(after["claims"], before["claims"])
            self.assertEqual(after["evidence_links"], before["evidence_links"])
            self.assertEqual(after["edges"], before["edges"])
            self.assertEqual(reconstructed._current_status(a["claim_uid"]), "CONTRADICTED")


@unittest.skipUnless(
    REAL_EVIDENCE_ROOT.is_dir() and all((REAL_EVIDENCE_ROOT / f).exists() for f in REAL_CASE_FILES),
    "real evidence fixture files not present on this machine",
)
@pytest.mark.heavy
class RealCaseValidationTests(unittest.TestCase):
    """Encodes today's actual chain (see claim_index.py's module docstring)
    from the REAL dataset/evidence/ files on disk -- copied verbatim into an
    isolated fixture directory, never read from/written to the real corpus
    location itself."""

    def _seed_real_fixture(self, root: Path):
        for name in REAL_CASE_FILES:
            shutil.copyfile(REAL_EVIDENCE_ROOT / name, root / name)

    def test_four_real_tbm_claims_land_as_contradicted(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            evidence_root = tmp / "evidence"
            evidence_root.mkdir()
            self._seed_real_fixture(evidence_root)
            evidence_index = EvidenceIndex(evidence_root, db_path=tmp / "evidence.sqlite")
            refresh = evidence_index.refresh()
            self.assertTrue(refresh["ok"])
            self.assertEqual(refresh["errors"], 0)

            def uid(name):
                rec = evidence_index.record(path=name)
                self.assertTrue(rec["ok"] or rec.get("path"), rec)
                return rec["evidence_uid"]

            uid_static_gate = uid("tbm_loading_gate_static.md")
            uid_admin_gate_early_exit = uid("TBM_de2a5b567b_admin_gate_early_exit_2026-09-25.json")
            uid_screenshot = uid("tbm_patched_driver_run1.png")
            uid_reboot_wait = uid("tbm_reboot_thread_wait_measurement_2026-09-24.json")
            uid_token_elevation = uid("tbm_task_token_elevation_verified_2026-09-25.json")
            uid_km_kill_verified = uid("TBM_de2a5b567b_admin_branch_km_kill_verified_2026-09-25.json")
            uid_reason1_classification = uid("TBMKD_c360147601_reason1_killpath_classification_and_patch_diff_2026-09-25.json")

            claims = ClaimIndex(
                db_path=tmp / "claims.sqlite", events_root=tmp / "claims_events", evidence_index=evidence_index,
            )

            # Claim 1: "hangs, blocked on ConnectNamedPipe" (2026-09-05 static hypothesis, backfilled).
            claim1 = claims.create_claim(
                "trybypassme/TBM.exe", "function", "ConnectNamedPipe", "blocking_behavior",
                "process hangs, blocked on ConnectNamedPipe (no timeout)", status="PROVEN", inferred=True,
                source="backfilled from the 2026-09-05 static hypothesis (tbm_loading_gate_static.md); "
                       "predates this claim layer, never a structured assertion at the time",
                initial_evidence=[{"evidence_uid": uid_static_gate, "relation": "SUPPORTS"}],
            )
            self.assertEqual(claim1["status"], "PROVEN")
            r1 = claims.add_evidence(
                claim1["claim_uid"], uid_reboot_wait, "REFUTES",
                note="process lives ~326ms, exits clean, no thread in a sustained wait",
            )
            print("CLAIM 1 (ConnectNamedPipe hang) ->", json.dumps(r1, indent=2))
            self.assertEqual(r1["status"], "CONTRADICTED")

            # Claim 2: "exits early because token is not elevated".
            claim2 = claims.create_claim(
                "trybypassme/TBM.exe", "function", "FUN_14005d340", "early_exit_cause",
                "exits early because its token is not elevated", status="PROVEN", inferred=True,
                source="backfilled from the admin-gate-early-exit hypothesis "
                       "(TBM_de2a5b567b_admin_gate_early_exit_2026-09-25.json)",
                initial_evidence=[{"evidence_uid": uid_admin_gate_early_exit, "relation": "SUPPORTS"}],
            )
            self.assertEqual(claim2["status"], "PROVEN")
            r2 = claims.add_evidence(
                claim2["claim_uid"], uid_token_elevation, "REFUTES",
                note="TokenElevationTypeFull measured for the actual launch task principal",
            )
            print("CLAIM 2 (non-elevated token) ->", json.dumps(r2, indent=2))
            self.assertEqual(r2["status"], "CONTRADICTED")

            # Claim 3: "the kernel process-kill was defeated, process survives 240s+"
            # (the one that sat in PROJECT_STATE as fact for three weeks).
            claim3 = claims.create_claim(
                "trybypassme/TBM.exe", "address", "1400030ff", "process_survival_after_km_kill",
                "the kernel process-kill was defeated; the process survives 240s+", status="PROVEN",
                inferred=True,
                source="backfilled from the 2026-09-05 success screenshot (tbm_patched_driver_run1.png); "
                       "this was the claim that sat in docs/PROJECT_STATE.md as fact for three weeks",
                initial_evidence=[{"evidence_uid": uid_screenshot, "relation": "SUPPORTS"}],
            )
            self.assertEqual(claim3["status"], "PROVEN")

            # Claim 4: "reason=1 is hypervisor/VM detection" -- raised as an
            # open hypothesis inside the SAME file that verifies the kill,
            # while claim 3 is still PROVEN: same subject anchor (the kill
            # call site), a DIFFERENT predicate -> must be UNCOMPARABLE, not
            # silently treated as compatible or conflicting.
            claim4 = claims.create_claim(
                "trybypassme/TBM.exe", "address", "0x1400030FF", "reason1_root_cause",
                "reason=1 is hypervisor/VM detection", status="CANDIDATE", inferred=True,
                source="raised as an open hypothesis inside TBM_de2a5b567b_admin_branch_km_kill_verified_2026-09-25.json",
                initial_evidence=[{"evidence_uid": uid_km_kill_verified, "relation": "SUPPORTS"}],
            )
            print("CLAIM 4 create() ->", json.dumps(claim4, indent=2))
            self.assertIn(
                claim3["claim_uid"], claim4["uncomparable_with"],
                "same subject (kill call site), different predicate -- must be UNCOMPARABLE, "
                "not silently treated as no-conflict",
            )
            self.assertEqual(claim4["conflicts_with"], [])
            self.assertEqual(claims._current_status(claim3["claim_uid"]), "PROVEN", "an UNCOMPARABLE pairing must not touch either claim's status")

            r3 = claims.add_evidence(
                claim3["claim_uid"], uid_km_kill_verified, "REFUTES",
                note="KM-kill triggered (reason=1), ZwTerminateProcess on the matching PID, ring-0 kill",
            )
            print("CLAIM 3 (kill defeated) ->", json.dumps(r3, indent=2))
            self.assertEqual(r3["status"], "CONTRADICTED")

            r4 = claims.add_evidence(
                claim4["claim_uid"], uid_reason1_classification, "REFUTES",
                note="reason=1 is an ObRegisterCallbacks handle-open interceptor at VA 0x1400030FF "
                     "matching access mask 0x87A -- not VM/hypervisor detection",
            )
            print("CLAIM 4 (VM detection) ->", json.dumps(r4, indent=2))
            self.assertEqual(r4["status"], "CONTRADICTED")

            contradicted = claims.contradicted_claims("trybypassme/TBM.exe")
            print("CONTRADICTED CLAIMS FOR trybypassme/TBM.exe ->", json.dumps(contradicted, indent=2))
            contradicted_uids = {c["claim_uid"] for c in contradicted["results"]}
            for claim in (claim1, claim2, claim3, claim4):
                self.assertIn(claim["claim_uid"], contradicted_uids)
            self.assertEqual(contradicted["count"], 4)

            all_claims = claims.claims_for_target("trybypassme/TBM.exe")
            self.assertEqual(all_claims["count"], 4)

            # Same evidence file (uid_km_kill_verified) is SUPPORTS for
            # claim4 and REFUTES for claim3 -- realistic, and must not be
            # confused by relation.
            prov3 = claims.claim_provenance(claim3["claim_uid"])
            self.assertEqual(prov3["refutes"][0]["evidence_uid"], uid_km_kill_verified)
            prov4 = claims.claim_provenance(claim4["claim_uid"])
            self.assertEqual(prov4["supports"][0]["evidence_uid"], uid_km_kill_verified)


class JsonlRecordTests(unittest.TestCase):
    """A JSONL evidence file is read line by line: one bad line costs that line, not the file."""

    def _row(self, body, name="events_aaaaaa_lockevents.jsonl"):
        with TemporaryDirectory() as td:
            root = Path(td)
            path = root / name
            path.write_bytes(body)
            return EvidenceIndex(root=root, db_path=root / "x.sqlite")._build_row(path, name, path.stat())

    def test_multi_line_jsonl_is_ok_and_fields_are_extracted(self):
        body = (b'{"reason": "stale", "reclaimed_by_pid": 41, "reclaimed_at": "2026-01-01T00:00:00Z"}\n'
                b'\n'
                b'{"reason": "dead_owner", "reclaimed_by_pid": 42, "reclaimed_at": "2026-01-02T00:00:00Z"}\n')
        row = self._row(body)
        self.assertEqual(row["status"], "json_ok")
        self.assertIsNone(row["parse_error"])
        for expected in ("lines_ok=2/2", "events=stale,dead_owner", "pids=41,42", "time=2026-01-01T00:00:00Z..2026-01-02T00:00:00Z"):
            self.assertIn(expected, row["summary"])

    def test_a_bad_line_is_named_and_the_good_lines_are_kept(self):
        row = self._row(b'{"event": "a"}\nnot json\n{"event": "b"}\n{broken\n')
        self.assertEqual(row["status"], "jsonl_partial")
        self.assertIn("line 2", row["parse_error"])
        self.assertIn("2 bad line(s)", row["parse_error"])
        self.assertIn("2 of 4 read", row["parse_error"])
        self.assertIn("lines_ok=2/4", row["summary"])
        self.assertIn("bad_lines=2,4", row["summary"])
        self.assertIn("events=a,b", row["summary"])

    def test_a_file_with_no_parsable_line_is_malformed(self):
        row = self._row(b"garbage\nmore garbage\n")
        self.assertEqual(row["status"], "json_malformed")
        self.assertIn("line 1", row["parse_error"])

    def test_a_cut_read_drops_the_partial_last_line_without_calling_it_corrupt(self):
        import liebert_re.evidence.index as index_module
        line = b'{"event": "x"}\n'
        body = line * 4 + b'{"event": "cut-off-in-the-mid'
        with mock.patch.object(index_module, "MAX_CONTENT_BYTES", len(line) * 4 + 5):
            row = self._row(body)
        self.assertEqual(row["status"], "json_ok")
        self.assertIn("partial_last_line_dropped", row["summary"])
        self.assertTrue(row["parse_error"].startswith("TRUNCATED"))


class RebuildRaceAndAtomicityTests(unittest.TestCase):
    """K2: rebuild_from_events must list the event log under the same lock it
    rebuilds with, and must swap the projection inside one explicit SQLite
    transaction (executescript commits implicitly, so it cannot)."""

    @staticmethod
    def _claim_uids(claims):
        # A fresh connection each call: what an independent reader would see.
        connection = claims.connect()
        try:
            return sorted(r[0] for r in connection.execute("SELECT claim_uid FROM claims"))
        finally:
            connection.close()

    def test_claim_written_between_listing_and_rebuild_survives(self):
        import threading
        with TemporaryDirectory() as tmp:
            _, _, claims = _make_indices(Path(tmp))
            first = claims.create_claim("t", "function", "FUN_1", "root_cause", "x")["claim_uid"]
            second_uid = []
            threads = []
            real_glob = type(claims.events_root).glob
            armed = {"on": True}

            def second_writer():
                result = claims.create_claim("t", "function", "FUN_2", "root_cause", "y", status="CANDIDATE")
                second_uid.append(result["claim_uid"])

            def wrapped_glob(path, pattern, *args, **kwargs):
                listed = list(real_glob(path, pattern, *args, **kwargs))
                if armed["on"] and path == claims.events_root and pattern == "*.json":
                    armed["on"] = False
                    thread = threading.Thread(target=second_writer)
                    thread.start()
                    threads.append(thread)
                    thread.join(timeout=5)  # unlocked listing: finishes; fixed code: blocks on the lock
                return iter(listed)

            with mock.patch.object(type(claims.events_root), "glob", wrapped_glob):
                claims.rebuild_from_events()
            for thread in threads:
                thread.join(timeout=60)
            self.assertEqual(len(second_uid), 1)
            self.assertIn(second_uid[0], self._claim_uids(claims), "claim written during the rebuild vanished")
            self.assertIn(first, self._claim_uids(claims))
            # The loss was transient: a later rebuild brings the event file back.
            claims.rebuild_from_events()
            self.assertEqual(sorted([first, second_uid[0]]), self._claim_uids(claims))

    @staticmethod
    def _poison_event(claims):
        # Parses as JSON with a known event name, but cannot be applied: fails mid-replay.
        _write_json(
            claims.events_root / "9999999999999999__zz__claim_created.json",
            {"event": "claim_created", "at": "2999-01-01T00:00:00Z", "claim_uid": "zz"},
        )

    @pytest.mark.contract
    def test_a_json_event_that_is_not_an_object_is_malformed_not_a_crash(self):
        with TemporaryDirectory() as tmp:
            _, _, claims = _make_indices(Path(tmp))
            first = claims.create_claim("t", "function", "FUN_1", "root_cause", "x")["claim_uid"]
            for index, body in enumerate(("[1, 2]", '"text"', "42", "null")):
                path = claims.events_root / f"9999999999999999__nd{index}__claim_created.json"
                path.write_text(body, encoding="utf-8")
            result = claims.rebuild_from_events()  # must not raise AttributeError
            self.assertTrue(result["ok"])
            self.assertEqual(4, result["malformed"])  # counted and reported, not silently skipped
            self.assertEqual(result["events_scanned"] - 4, result["events_applied"])
            self.assertEqual([first], self._claim_uids(claims))

    def test_replay_failure_keeps_the_old_projection(self):
        with TemporaryDirectory() as tmp:
            _, _, claims = _make_indices(Path(tmp))
            first = claims.create_claim("t", "function", "FUN_1", "root_cause", "x")["claim_uid"]
            self._poison_event(claims)
            with self.assertRaises(KeyError):
                claims.rebuild_from_events()
            self.assertEqual([first], self._claim_uids(claims))

    def test_separate_connection_never_sees_a_half_rebuilt_projection(self):
        with TemporaryDirectory() as tmp:
            _, _, claims = _make_indices(Path(tmp))
            first = claims.create_claim("t", "function", "FUN_1", "root_cause", "x")["claim_uid"]
            self._poison_event(claims)
            seen = []
            real_apply = claims._apply_claim_created

            def apply_then_peek(db, ev):
                if ev["claim_uid"] == "zz":
                    # Deletes already ran; read through ANOTHER connection, then blow up.
                    seen.append(self._claim_uids(claims))
                    raise RuntimeError("replay blew up")
                return real_apply(db, ev)

            with mock.patch.object(claims, "_apply_claim_created", apply_then_peek):
                with self.assertRaises(RuntimeError):
                    claims.rebuild_from_events()
            self.assertEqual([[first]], seen, "a second connection saw a half-rebuilt projection")
            self.assertEqual([first], self._claim_uids(claims))


if __name__ == "__main__":
    unittest.main()
