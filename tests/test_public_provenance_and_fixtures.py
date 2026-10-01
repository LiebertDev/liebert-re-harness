"""Focused public-port coverage for three small, dependency-free modules:
provenance.py (engine-input-hash agreement), artifact_provenance.py
(deterministic hashing/staleness helpers), and owned_binary_fixtures.py
(synthetic PE/minidump builders used by several other tests). Written
because the private tests covering these either import unpublished
orchestration modules (test_provenance_assertion.py -> tools_ida;
test_p05_local_readiness.py, test_raw_integrity_classification.py,
test_tool_doctor_snapshot.py -> canary_suite/backup_manager/environment_manifest)
or a kernel-triage module (test_isolated_artifact.py -> isolated_artifact),
none of which are part of this port batch. The pure-function contract these
three modules expose does not need any of that machinery to verify."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.evidence.artifact_provenance as artifact_provenance
import liebert_re.recover.owned_binary_fixtures as owned_binary_fixtures
import liebert_re.evidence.provenance as provenance


class ProvenanceHelperTests(unittest.TestCase):
    """Mirrors tests/test_provenance_assertion.py's ProvenanceHelperTests --
    the part of that file that exercises provenance.py directly, with no
    tools_ida involved."""

    def test_verified_on_sha256_match(self):
        r = provenance.assess_provenance(requested_sha256="AB", engine_sha256="ab")
        self.assertEqual(r["status"], provenance.PROVENANCE_VERIFIED)
        self.assertEqual(r["algorithm"], "sha256")

    def test_mismatch_is_distinct(self):
        r = provenance.assess_provenance(requested_sha256="aa", engine_sha256="bb")
        self.assertEqual(r["status"], provenance.PROVENANCE_MISMATCH)
        self.assertEqual(r["requested_input_hash"], "aa")
        self.assertEqual(r["engine_input_hash"], "bb")

    def test_md5_fallback_when_no_sha(self):
        r = provenance.assess_provenance(requested_md5="cc", engine_md5="cc")
        self.assertEqual(r["status"], provenance.PROVENANCE_VERIFIED)
        self.assertEqual(r["algorithm"], "md5")

    def test_unverifiable_when_engine_silent(self):
        r = provenance.assess_provenance(requested_sha256="aa")
        self.assertEqual(r["status"], provenance.PROVENANCE_UNVERIFIABLE)
        self.assertEqual(r["reason"], "ENGINE_REPORTED_NO_COMPARABLE_INPUT_HASH")

    def test_one_sided_hash_is_never_agreement(self):
        r = provenance.assess_provenance(requested_sha256="aa", engine_md5="aa")
        self.assertEqual(r["status"], provenance.PROVENANCE_UNVERIFIABLE)

    def test_explicit_unverifiable_reason_short_circuits(self):
        r = provenance.assess_provenance(
            requested_sha256="aa", engine_sha256="bb",
            unverifiable_reason="EXISTING_DATABASE",
        )
        self.assertEqual(r["status"], provenance.PROVENANCE_UNVERIFIABLE)
        self.assertEqual(r["reason"], "EXISTING_DATABASE")


class ArtifactProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sha256_bytes_is_deterministic(self):
        self.assertEqual(
            artifact_provenance.sha256_bytes(b"abc"),
            artifact_provenance.sha256_bytes(b"abc"),
        )
        self.assertNotEqual(
            artifact_provenance.sha256_bytes(b"abc"),
            artifact_provenance.sha256_bytes(b"abd"),
        )

    def test_sha256_file_missing_file_returns_none_not_raise(self):
        # Structured "not applicable" result for this module: a missing file
        # yields None, never an exception.
        self.assertIsNone(artifact_provenance.sha256_file(self.root / "does_not_exist.bin"))

    def test_sha256_file_matches_sha256_bytes(self):
        p = self.root / "a.bin"
        p.write_bytes(b"hello world")
        self.assertEqual(artifact_provenance.sha256_file(p), artifact_provenance.sha256_bytes(b"hello world"))

    def test_input_hashes_skips_missing_and_keys_by_name(self):
        p = self.root / "present.bin"
        p.write_bytes(b"data")
        hashes = artifact_provenance.input_hashes([p, self.root / "absent.bin"])
        self.assertEqual(set(hashes), {"present.bin"})
        self.assertEqual(hashes["present.bin"], artifact_provenance.sha256_bytes(b"data"))

    def test_combined_hash_is_order_independent(self):
        a = artifact_provenance.combined_hash({"x": "1", "y": "2"})
        b = artifact_provenance.combined_hash({"y": "2", "x": "1"})
        self.assertEqual(a, b)

    def test_safe_model_identifier_strips_local_paths(self):
        self.assertEqual(artifact_provenance.safe_model_identifier(None), "UNKNOWN")
        self.assertEqual(artifact_provenance.safe_model_identifier("gpt-4"), "gpt-4")
        self.assertEqual(
            artifact_provenance.safe_model_identifier("C:\\models\\local\\weights.gguf"),
            "weights.gguf",
        )
        self.assertEqual(
            artifact_provenance.safe_model_identifier("/home/user/models/weights.bin"),
            "weights.bin",
        )

    def test_stale_status_missing_current_and_stale(self):
        manifest = self.root / "manifest.json"
        inputs = [self.root / "in1.bin"]
        (self.root / "in1.bin").write_bytes(b"v1")

        missing = artifact_provenance.stale_status(manifest, inputs)
        self.assertEqual(missing["status"], "MISSING")

        current_hashes = artifact_provenance.input_hashes(inputs)
        manifest.write_text(json.dumps({"input_hashes": current_hashes}), encoding="utf-8")
        current = artifact_provenance.stale_status(manifest, inputs)
        self.assertEqual(current["status"], "CURRENT")

        (self.root / "in1.bin").write_bytes(b"v2-changed")
        stale = artifact_provenance.stale_status(manifest, inputs)
        self.assertEqual(stale["status"], "STALE")

    def test_stale_status_invalid_manifest_json(self):
        manifest = self.root / "bad_manifest.json"
        manifest.write_text("{not json", encoding="utf-8")
        result = artifact_provenance.stale_status(manifest, [])
        self.assertEqual(result["status"], "INVALID")

    def test_artifact_record_shape(self):
        p = self.root / "in.bin"
        p.write_bytes(b"content")
        record = artifact_provenance.artifact_record([p], [], producer="unit_test")
        self.assertEqual(record["producer"], "unit_test")
        self.assertIn("in.bin", record["input_hashes"])
        self.assertEqual(record["output_hashes"], {})

    def test_anonymous_workspace_id_is_stable_for_same_tree(self):
        (self.root / "file_a.txt").write_bytes(b"one")
        first = artifact_provenance.anonymous_workspace_id(self.root)
        second = artifact_provenance.anonymous_workspace_id(self.root)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("WS-"))


class OwnedBinaryFixturesTests(unittest.TestCase):
    """owned_binary_fixtures.py's builders are used as PE/minidump input by
    several of this port batch's other new tests; this class is its own
    dedicated coverage: every builder must produce well-formed bytes without
    raising, and the minidump builder's own truncated-output mode must
    actually be shorter (the fixture generator's one documented failure
    shape)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_build_owned_rsds_has_rsds_magic(self):
        rsds = owned_binary_fixtures.build_owned_rsds()
        self.assertTrue(rsds.startswith(b"RSDS"))

    def test_build_owned_pe_with_rsds_is_a_valid_mz_pe(self):
        path = owned_binary_fixtures.build_owned_pe_with_rsds(self.root / "owned.sys")
        data = path.read_bytes()
        self.assertTrue(data.startswith(b"MZ"))
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        self.assertEqual(data[pe_offset:pe_offset + 4], b"PE\0\0")

    def test_build_owned_minidump_has_mdmp_magic_and_truncation_shrinks_it(self):
        full = owned_binary_fixtures.build_owned_minidump(self.root / "full.mdmp")
        full_bytes = full.read_bytes()
        self.assertTrue(full_bytes.startswith(b"MDMP"))

        truncated = owned_binary_fixtures.build_owned_minidump(self.root / "trunc.mdmp", truncate=True)
        self.assertLess(truncated.stat().st_size, full.stat().st_size)

    # ensure_owned_fixtures() is deliberately not exercised here: it writes
    # into this repo's own dataset/runtime/owned_fixtures/ tree (a fixed
    # path derived from the module's own location), not a caller-supplied
    # temp directory, so calling it from a test would leave real generated
    # files behind in whichever repo runs this suite. The three builder
    # functions above (which ensure_owned_fixtures itself just calls with
    # that fixed path) already prove the byte-level contract without that
    # side effect.


if __name__ == "__main__":
    unittest.main()
