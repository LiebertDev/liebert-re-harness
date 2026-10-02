"""tools_die.py's own contract: TOOL_MISSING when diec.exe is absent (never
raises), a nonexistent input path is rejected before any subprocess call,
a captured real DIE JSON string parses into the structured (not flattened)
result shape, and a binary DIE reports as unprotected is a real NEGATIVE
result (protected: False), not an error. Mirrors tests/test_tools_rizin.py's
guard style for a real, possibly-absent external toolchain: probe first,
skipTest cleanly when diec.exe genuinely isn't installed on this machine.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import liebert_re.tools.die as td
from liebert_re.evidence.index import EvidenceIndex, record_write as _evidence_index_record_write_real

REPO_ROOT = Path(__file__).resolve().parent.parent
TBM_EXE = REPO_ROOT / "benchmarks/real_corpora/trybypassme/TBM.exe"
UPX_KEYGENME = REPO_ROOT / "benchmarks/windows_native_ladder/corpus/tier2/keygenme_again/keygenme.exe"

# The mocked tests below never run diec.exe, but die_identify() checks that
# the input file exists before it reaches the (mocked) subprocess. They use
# these tiny stand-in files so they run with or without the unshipped corpus;
# only DieRealBinaryTests needs the real corpus binaries and skips without them.
_STUB_DIR = None
STUB_PE = Path()
STUB_UPX = Path()


def setUpModule():
    global _STUB_DIR, STUB_PE, STUB_UPX
    _STUB_DIR = TemporaryDirectory()
    STUB_PE = Path(_STUB_DIR.name) / "TBM.exe"
    STUB_UPX = Path(_STUB_DIR.name) / "keygenme.exe"
    for stub in (STUB_PE, STUB_UPX):
        stub.write_bytes(b"MZ" + bytes(64))


def tearDownModule():
    if _STUB_DIR is not None:
        _STUB_DIR.cleanup()


# A real `diec -j` capture (trimmed of nothing -- this is the verbatim
# shape DIE 3.21 emitted for the UPX-packed corpus fixture above) used to
# test JSON parsing without requiring diec.exe to be installed.
REAL_DIE_JSON_UPX = json.dumps({
    "detects": [
        {
            "filetype": "PE64",
            "info": "",
            "offset": "0",
            "parentfilepart": "Header",
            "size": "1400832",
            "values": [
                {"info": "", "name": "Microsoft Linker", "string": "Linker: Microsoft Linker(14.44.35214)", "type": "linker", "version": "14.44.35214"},
                {"info": "C", "name": "Microsoft Visual C/C++", "string": "Compiler: Microsoft Visual C/C++(19.44.35214)[C]", "type": "compiler", "version": "19.44.35214"},
                {"info": "", "name": "Microsoft Visual Studio", "string": "Tool: Microsoft Visual Studio(2022, 17.14)", "type": "tool", "version": "2022, 17.14"},
                {"info": "LZMA, brute", "name": "UPX", "string": "Packer: UPX(5.02)[LZMA, brute]", "type": "packer", "version": "5.02"},
            ],
        }
    ]
})

# A real `diec -j` capture for an unprotected, plain-compiled PE.
REAL_DIE_JSON_UNPROTECTED = json.dumps({
    "detects": [
        {
            "filetype": "PE64",
            "info": "",
            "offset": "0",
            "parentfilepart": "Header",
            "size": "463872",
            "values": [
                {"info": "", "name": "Microsoft Linker", "string": "Linker: Microsoft Linker(14.50.35224)", "type": "linker", "version": "14.50.35224"},
                {"info": "LTCG/C++", "name": "Microsoft Visual C/C++", "string": "Compiler: Microsoft Visual C/C++(19.50.35224)[LTCG/C++]", "type": "compiler", "version": "19.50.35224"},
            ],
        }
    ]
})


class DieMissingTests(unittest.TestCase):
    """The absence path must never raise and must use the repo's standard
    TOOL_MISSING shape, independent of whether diec.exe is actually
    installed on the machine running the test."""

    def test_missing_binary_returns_tool_missing_not_an_exception(self):
        with mock.patch.object(td, "_die_binary", return_value=None):
            out = td.die_identify(str(TBM_EXE))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TOOL_MISSING")
        self.assertIn("required_capability", data)

    def test_die_available_reports_false_when_binary_absent(self):
        with mock.patch.object(td, "_die_binary", return_value=None):
            self.assertFalse(td.die_available())


class DieNotFoundTests(unittest.TestCase):
    def test_nonexistent_path_returns_not_found_before_any_subprocess_call(self):
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.run_bounded_process") as mocked_run:
            out = td.die_identify(str(REPO_ROOT / "benchmarks" / "does_not_exist_at_all.exe"))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_FOUND")
        mocked_run.assert_not_called()


class DieParsingTests(unittest.TestCase):
    """A captured real DIE JSON string parses into the structured result
    shape -- protector/packer (with version and DIE's deterministic
    confidence label), compiler, linker, file type, and the raw detection
    list -- never flattened into a single string."""

    def test_upx_capture_parses_into_structured_protector_fields(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_DIE_JSON_UPX, stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_UPX), \
             mock.patch.object(td, "relative", return_value=STUB_UPX.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_UPX))
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["file_type"], "PE64")
        self.assertTrue(data["protected"])
        self.assertEqual(len(data["protectors"]), 1)
        protector = data["protectors"][0]
        self.assertEqual(protector["name"], "UPX")
        self.assertEqual(protector["version"], "5.02")
        self.assertEqual(protector["type"], "packer")
        self.assertEqual(protector["confidence"], "signature_match")
        self.assertIsNotNone(data["compiler"])
        self.assertEqual(data["compiler"]["name"], "Microsoft Visual C/C++")
        self.assertIsNotNone(data["linker"])
        self.assertEqual(data["linker"]["name"], "Microsoft Linker")
        # Raw detection list preserved (not flattened): every DIE value,
        # including the "tool" entry that isn't compiler/linker/protector.
        self.assertEqual(len(data["detections"]), 4)
        self.assertIn("internal_evidence_name", data)

    def test_unprotected_capture_is_a_real_negative_not_an_error(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_DIE_JSON_UNPROTECTED, stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE))
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertFalse(data["protected"])
        self.assertEqual(data["protectors"], [])
        self.assertIsNotNone(data["compiler"])


class DieTimeoutTests(unittest.TestCase):
    def test_timeout_result_from_run_bounded_process_becomes_timeout_status(self):
        fake_result = mock.Mock(cancelled=False, timed_out=True, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TIMEOUT")

    def test_cancellation_result_becomes_cancelled_status(self):
        fake_result = mock.Mock(cancelled=True, timed_out=False, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "CANCELLED")


class DieMalformedOutputTests(unittest.TestCase):
    def test_no_json_in_stdout_is_analysis_limited_not_a_crash(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout="no braces here", stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")

    def test_malformed_json_object_is_result_parse_failed_not_a_crash(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout="{not valid json,,,}", stderr="", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")

    def test_nonzero_exit_code_is_analysis_limited_not_a_crash(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=1,
                                 stdout="", stderr="diec: cannot open file", output_truncated=False)
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_PE), \
             mock.patch.object(td, "relative", return_value=STUB_PE.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result):
            out = td.die_identify(str(STUB_PE))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")


class DieRealBinaryTests(unittest.TestCase):
    """Exercised against the real diec.exe + real corpus binaries when DIE
    is actually installed; skips cleanly otherwise."""

    def setUp(self):
        if not td.die_available():
            raise unittest.SkipTest("Detect It Easy (diec.exe) not installed on this machine")
        if not TBM_EXE.is_file():
            raise unittest.SkipTest("corpus fixture missing: " + str(TBM_EXE))

    def test_real_unprotected_binary_is_negative_not_error(self):
        out = td.die_identify(str(TBM_EXE), timeout_seconds=30)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertFalse(data["protected"])

    def test_real_upx_packed_binary_is_detected(self):
        if not UPX_KEYGENME.is_file():
            raise unittest.SkipTest("corpus fixture missing: " + str(UPX_KEYGENME))
        out = td.die_identify(str(UPX_KEYGENME), timeout_seconds=30)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertTrue(data["protected"])
        names = [pr["name"] for pr in data["protectors"]]
        self.assertIn("UPX", names)


class EvidenceIndexWriteTimeHookTests(unittest.TestCase):
    """The freshness guarantee commits 2a203e7/cd1310b gave other writers
    must also hold for die_identify's own raw DIE JSON evidence file --
    see the _evidence_index_record_write() call right after
    raw_out.write_text(...) in tools_die.py."""

    def test_die_json_indexed_without_refresh(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_DIE_JSON_UPX, stderr="", output_truncated=False)
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "index.sqlite"

            def _redirected(path, **_kw):
                return _evidence_index_record_write_real(path, root=td.EVIDENCE, db_path=db_path)

            with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
                 mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_UPX), \
                 mock.patch.object(td, "relative", return_value=STUB_UPX.name), \
                 mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result), \
                 mock.patch.object(td, "_evidence_index_record_write", _redirected):
                out = td.die_identify(str(STUB_UPX))

            data = json.loads(out)
            self.assertTrue(data["ok"], data)
            index = EvidenceIndex(td.EVIDENCE, db_path=db_path)
            self.assertEqual(
                1, index.status()["records"],
                "the raw DIE json evidence file must be queryable without a refresh() call",
            )
            record = index.record(path=data["internal_evidence_name"])
            self.assertTrue(record.get("ok"), record)

    def test_die_write_survives_a_raising_index_hook(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_DIE_JSON_UPX, stderr="", output_truncated=False)

        def _boom(path, **_kw):
            raise RuntimeError("index unavailable")

        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.safe_path", return_value=STUB_UPX), \
             mock.patch.object(td, "relative", return_value=STUB_UPX.name), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=fake_result), \
             mock.patch.object(td, "_evidence_index_record_write", _boom):
            out = td.die_identify(str(STUB_UPX))

        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertTrue(
            (td.EVIDENCE / data["internal_evidence_name"]).exists(),
            "the evidence write itself must succeed even when the index hook raises",
        )


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool or spawns a bounded subprocess -- these can be
# slow or hang, so they are excluded from the default run and must be run explicitly
# with `pytest -m heavy`. See pytest.ini in this repo for the tools actually involved.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
