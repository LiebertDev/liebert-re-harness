"""tools_rizin.py against the repo's "a tool returns a result it did not
produce on this call, and the result looks complete" defect class.

Every test below plants a stale/partial/undecodable condition, makes the run
fail or come back incomplete, and asserts the FAILURE surfaces instead of the
plausible-looking content. Each one was also demonstrated to fail against the
pre-fix module (the exact HEAD copy of tools_rizin.py, imported side by side)
before the fix landed -- see the module's own commit message for the recorded
pre-fix statuses.

Both polarities are covered:
  * over-claimed completeness -- a truncated stdout parsed as a whole
    inventory; a partial disk write reported as OK; a sha256 computed from
    the in-memory buffer instead of the file that was written;
  * over-claimed NEGATIVE -- rizin's empty function list reported as
    "0 functions" when it never loaded the binary, and an undecodable byte
    reported as NOT_A_CONDITIONAL_BRANCH ("the answer is no") instead of
    NOT_RECOVERABLE ("the question could not be answered").

rizin itself is faked here (the real binary is exercised by
tests/test_tools_rizin.py and tests/test_tools_rizin_disasm.py); the disk
writes are real, against a throwaway copy of a PE built in code inside the
workspace.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.tools.rizin as tr
from liebert_re.recover.pe_address import normalize_address

from tests._pe_fixtures import build_pe

REPO_ROOT = Path(__file__).resolve().parents[1]

# The tests patch a PE built in code (docs/CORPUS.md, "Fixtures for tests"), not a corpus binary the
# contributor has to download. 0x20 bytes of padding, then a known `jz +10; xor eax, eax; inc eax; ret`
# at .text + 0x20 -- the bytes the tests read, expect and overwrite -- then padding again.
FIXTURE_CODE = bytes([0xCC]) * 0x20 + bytes([0x74, 0x0A, 0x31, 0xC0, 0x40, 0xC3]) + bytes([0xCC]) * 0x1A
FIXTURE_BYTES = build_pe(FIXTURE_CODE)
FIXTURE_PE = REPO_ROOT / "LoginCrackme_fixture.exe"      # replaced by setUpModule with a real temp file
_FIXTURE_DIR = None


def setUpModule():
    global FIXTURE_PE, _FIXTURE_DIR
    _FIXTURE_DIR = tempfile.TemporaryDirectory(dir=str(REPO_ROOT))
    FIXTURE_PE = Path(_FIXTURE_DIR.name) / "LoginCrackme_fixture.exe"
    FIXTURE_PE.write_bytes(FIXTURE_BYTES)


def tearDownModule():
    if _FIXTURE_DIR is not None:
        _FIXTURE_DIR.cleanup()


def _fake_cp(stdout="", stderr="", returncode=0, truncated=False):
    """A BoundedProcessResult stand-in. Every flag is set explicitly -- a bare
    mock.Mock() would hand back a truthy Mock for output_truncated and make
    these tests measure nothing."""
    return mock.Mock(stdout=stdout, stderr=stderr, returncode=returncode,
                     timed_out=False, cancelled=False, output_truncated=truncated)


def _dispatch(pdj_stdout, asm_stdout="nop\nnop\nnop\nnop\nnop"):
    """One fake for a call that spawns rizin.exe and then rz-asm.exe."""
    def _run(cmd, **_kwargs):
        if "rz-asm" in str(cmd[0]).lower():
            return _fake_cp(stdout=asm_stdout)
        return _fake_cp(stdout=pdj_stdout)
    return _run


class RizinFunctionsEmptyListPolarityTests(unittest.TestCase):
    """`aaa; aflj` printing an empty array is NOT the measurement
    "this binary has zero functions" unless rizin actually loaded the file.
    rizin exits 0 either way (measured: it exits 0 even when its whole -c
    chain fails to parse), so the exit code cannot make that distinction."""

    def _run(self, stdout, truncated=False):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("liebert_re.tools.rizin.safe_path", return_value=FIXTURE_PE), \
             mock.patch("liebert_re.tools.rizin.run_bounded_process",
                        return_value=_fake_cp(stdout=stdout, truncated=truncated)):
            return json.loads(tr.rizin_functions(str(FIXTURE_PE), timeout_seconds=10))

    def test_empty_list_without_load_probe_is_not_recoverable_not_zero_functions(self):
        data = self._run("[]\n")
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["error"], "RIZIN_EMPTY_FUNCTION_LIST_WITHOUT_LOADED_BINARY")
        self.assertNotIn("function_count", data,
                         "a count must not be published when the count is unknown")

    def test_empty_list_with_probe_saying_no_binary_loaded_is_not_recoverable(self):
        # Exactly what rizin printed on this machine for a 20-byte text file:
        # it answers iIj, but with no arch/bintype and havecode false.
        data = self._run('[]\n{"baddr":0,"binsz":20,"bits":64,"havecode":false}\n')
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["load_probe"]["status"], "NO_BINARY_LOADED")

    def test_empty_list_with_binary_confirmed_loaded_is_an_honest_zero(self):
        data = self._run('[]\n{"arch":"x86","bits":64,"bintype":"pe","havecode":true}\n')
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["function_count"], 0)
        self.assertEqual(data["analysis_completeness"], "COMPLETE_NO_FUNCTIONS_FOUND")
        self.assertEqual(data["load_probe"]["status"], "BINARY_LOADED")

    def test_truncated_stdout_is_analysis_limited_even_when_the_json_still_parses(self):
        # The dangerous case: the buffer hit the output cap but what survived
        # happens to be a complete, parseable array. Reporting that as a
        # function inventory publishes a partial result as a whole one.
        stdout = '[{"offset":4198400,"name":"fcn.00401000","size":32}]'
        data = self._run(stdout, truncated=True)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "RIZIN_OUTPUT_TRUNCATED_AT_CAP")
        self.assertTrue(data["output_truncated"])

    def test_non_empty_list_still_reports_ok_with_named_completeness(self):
        stdout = '[{"offset":4198400,"name":"fcn.00401000","size":32}]\n{"arch":"x86","bintype":"pe","havecode":true}'
        data = self._run(stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["function_count"], 1)
        self.assertEqual(data["analysis_completeness"], "COMPLETE")
        self.assertFalse(data["truncated"])


class RizinFunctionsNonEmptyFabricationPolarityTests(unittest.TestCase):
    """A NON-ZERO function count is no more self-evidently real than a zero one.

    Measured on this machine (rizin 0.9.1, 2026-09-27): on a 20-byte text file
    rizin exits 0 and answers `aaa; aflj` with a FABRICATED function
    (function_count 1, fcn.00000000) while `iIj` reports havecode:false and no
    arch/bintype. Before this fix that fabricated count left rizin_functions as
    ok:True / status:OK / function_count:1 and fed straight into
    decompiler_trust.py's cross-engine comparison -- a false CONSISTENT (if it
    landed under the divergence ratio) or a false disagreement that discredits
    a correct engine. This class pins that a non-empty list whose own probe
    says NO_BINARY_LOADED is refused as NOT_RECOVERABLE, while a non-empty list
    on a rizin build that simply does not answer the probe (PROBE_UNAVAILABLE)
    is still returned -- the load probe rejects only rizin's POSITIVE "I did
    not load this" answer, it never discards real functions for want of a
    probe. Independent of the tier1 corpus (self-contained temp file), so it
    runs everywhere.
    """

    def setUp(self):
        # Inside the workspace: rizin_functions calls tools_workspace.relative()
        # on the path, which refuses anything outside WORKSPACE.
        self._tmp = Path(tempfile.mkdtemp(prefix="rizin_fab_", dir=REPO_ROOT))
        self._file = self._tmp / "junk.txt"
        self._file.write_bytes(b"hello world 20byte!!")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, stdout):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("liebert_re.tools.rizin.safe_path", return_value=self._file), \
             mock.patch("liebert_re.tools.rizin.run_bounded_process",
                        return_value=_fake_cp(stdout=stdout)):
            return json.loads(tr.rizin_functions(str(self._file), timeout_seconds=10))

    def test_non_empty_list_with_probe_saying_no_binary_loaded_is_not_recoverable(self):
        # Exactly what rizin printed for a 20-byte text file: one fabricated
        # function, then iIj with havecode false and no arch/bintype.
        stdout = '[{"offset":0,"name":"fcn.00000000","size":0}]\n{"baddr":0,"binsz":20,"bits":64,"havecode":false}\n'
        data = self._run(stdout)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["error"], "RIZIN_FABRICATED_FUNCTIONS_WITHOUT_LOADED_BINARY")
        self.assertEqual(data["load_probe"]["status"], "NO_BINARY_LOADED")
        self.assertEqual(data["fabricated_function_count"], 1)
        self.assertNotIn("function_count", data,
                         "a fabricated count must never be published as function_count")

    def test_non_empty_list_with_probe_unavailable_is_still_a_real_inventory(self):
        # A rizin build that does not answer iIj at all (no JSON object after
        # the array) must NOT have its real function list discarded -- the
        # standing promise that a probe-less build cannot break the main path.
        stdout = '[{"offset":4198400,"name":"fcn.00401000","size":32}]\n'
        data = self._run(stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["function_count"], 1)
        self.assertEqual(data["load_probe"]["status"], "PROBE_UNAVAILABLE")


class RizinDisasmCoverageTests(unittest.TestCase):
    """A listing that contains bytes rizin could not decode must say so."""

    @classmethod
    def setUpClass(cls):
        import pefile
        pe = pefile.PE(data=FIXTURE_PE.read_bytes(), fast_load=True)
        text = next(s for s in pe.sections if s.Name.startswith(b".text"))
        cls.file_offset = hex(int(text.PointerToRawData) + 0x20)
        resolved = normalize_address(str(FIXTURE_PE), cls.file_offset, "file_offset")
        assert resolved.get("ok"), resolved
        cls.va_int = int(resolved["va"], 16)

    def _listing(self, entries, truncated=False):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("liebert_re.tools.rizin.safe_path", return_value=FIXTURE_PE), \
             mock.patch("liebert_re.tools.rizin.run_bounded_process",
                        return_value=_fake_cp(stdout=json.dumps(entries), truncated=truncated)):
            return json.loads(tr.rizin_disasm_listing(
                str(FIXTURE_PE), self.file_offset, "file_offset", count=2, timeout_seconds=10))

    def test_undecodable_instruction_is_reported_as_partial_coverage(self):
        data = self._listing([
            {"offset": self.va_int, "size": 1, "bytes": "90", "type": "nop", "opcode": "nop"},
            {"offset": self.va_int + 1, "size": 1, "bytes": "ff", "type": "invalid", "opcode": "invalid"},
        ])
        self.assertTrue(data["ok"])
        self.assertEqual(data["decode_coverage"]["status"], "PARTIALLY_DECODED")
        self.assertEqual(data["decode_coverage"]["instructions_undecodable"], 1)
        self.assertEqual(data["decode_coverage"]["instructions_decoded"], 1)
        self.assertEqual([i["decode_status"] for i in data["instructions"]],
                         ["DECODED", "UNDECODABLE"])

    def test_truncated_pdj_output_is_analysis_limited_not_a_listing(self):
        data = self._listing(
            [{"offset": self.va_int, "size": 1, "bytes": "90", "type": "nop", "opcode": "nop"}],
            truncated=True,
        )
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "RIZIN_OUTPUT_TRUNCATED_AT_CAP")


class RizinPatchPlanNegativePolarityTests(unittest.TestCase):
    """"I could not decode this" must not be rendered as "this is not a
    conditional branch" -- the same polarity of defect as a slicer answering
    "no write found" to a question that never applied."""

    @classmethod
    def setUpClass(cls):
        RizinDisasmCoverageTests.setUpClass.__func__(cls)

    def _plan(self, entries, operation, instruction_count=1):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "_rizin_asm_binary", return_value="C:/fake/rz-asm.exe"), \
             mock.patch("liebert_re.tools.rizin.safe_path", return_value=FIXTURE_PE), \
             mock.patch("liebert_re.tools.rizin.run_bounded_process",
                        side_effect=_dispatch(json.dumps(entries))):
            return json.loads(tr.rizin_patch_plan(
                str(FIXTURE_PE), self.file_offset, operation, "file_offset",
                instruction_count=instruction_count, timeout_seconds=10))

    def test_undecodable_byte_is_not_recoverable_not_a_definite_negative(self):
        data = self._plan(
            [{"offset": self.va_int, "size": 1, "bytes": "ff", "type": "invalid", "opcode": "invalid"}],
            "force_branch",
        )
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["error"], "RIZIN_INSTRUCTION_TYPE_NOT_RECOVERABLE")

    def test_unclassified_instruction_is_not_recoverable(self):
        data = self._plan(
            [{"offset": self.va_int, "size": 2, "bytes": "6690", "opcode": "nop"}],
            "force_branch",
        )
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")

    def test_nop_out_refuses_a_window_containing_an_undecodable_byte(self):
        data = self._plan(
            [
                {"offset": self.va_int, "size": 1, "bytes": "90", "type": "nop", "opcode": "nop"},
                {"offset": self.va_int + 1, "size": 1, "bytes": "ff", "type": "invalid", "opcode": "invalid"},
            ],
            "nop_out", instruction_count=2,
        )
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["error"], "UNDECODABLE_INSTRUCTION_IN_WINDOW")
        self.assertNotIn("patched_bytes", data, "no bytes may be planned over an undecoded region")

    def test_missing_size_or_bytes_is_not_recoverable_not_a_crash(self):
        data = self._plan(
            [{"offset": self.va_int, "type": "cjmp", "opcode": "je 0x401000", "jump": self.va_int + 16}],
            "force_branch",
        )
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_RECOVERABLE")
        self.assertEqual(data["error"], "RIZIN_INSTRUCTION_SIZE_OR_BYTES_MISSING")

    def test_roundtrip_that_decodes_to_invalid_fails_instead_of_returning_a_plan(self):
        # rz-asm prints "invalid" and exits 0 for bytes it cannot decode. The
        # round trip is the plan's only verification; accepting an "invalid"
        # line would make it decoration and publish disasm_after: ["invalid"]
        # under ok: true.
        entries = [{"offset": self.va_int, "size": 5, "bytes": "9090909090",
                    "type": "nop", "opcode": "nop"}]
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "_rizin_asm_binary", return_value="C:/fake/rz-asm.exe"), \
             mock.patch("liebert_re.tools.rizin.safe_path", return_value=FIXTURE_PE), \
             mock.patch("liebert_re.tools.rizin.run_bounded_process",
                        side_effect=_dispatch(json.dumps(entries), asm_stdout="invalid\ninvalid\n")):
            data = json.loads(tr.rizin_patch_plan(
                str(FIXTURE_PE), self.file_offset, "nop_out", "file_offset", timeout_seconds=10))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "DISASSEMBLY_FAILED")
        self.assertEqual(data["error"], "RZ_ASM_ROUNDTRIP_UNDECODABLE")


def _short_write(self, data):
    """A write that lands only half the bytes -- the shape of a partial/failed
    write that raises nothing."""
    with open(self, "wb") as handle:
        handle.write(bytes(data)[: len(data) // 2])
    return len(data) // 2


class PatchWritePathVerificationTests(unittest.TestCase):
    """The patch paths modify a file, so a wrong answer here is not a wrong
    report -- it is a wrong file. Nothing may be reported as written that was
    not read back from disk and compared."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=str(REPO_ROOT))
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.target = self.dir / "Fixture_copy.exe"
        shutil.copy2(FIXTURE_PE, self.target)
        self.original = self.target.read_bytes()
        self.out = self.dir / "Fixture_copy.patched.exe"

    def _first_text_offset(self):
        import pefile
        pe = pefile.PE(data=self.original, fast_load=True)
        text = next(s for s in pe.sections if s.Name.startswith(b".text"))
        return int(text.PointerToRawData) + 0x20

    # --- rizin_patch_apply -------------------------------------------------
    def test_apply_refuses_when_expected_bytes_do_not_match_and_writes_nothing(self):
        offset = self._first_text_offset()
        self.out.write_bytes(b"STALE-PREVIOUS-RESULT")
        data = json.loads(tr.rizin_patch_apply(
            str(self.target), hex(offset), "9090", str(self.out), expected_bytes="dead"))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "EXPECTED_BYTES_MISMATCH")
        self.assertEqual(self.out.read_bytes(), b"STALE-PREVIOUS-RESULT",
                         "a refused patch must not touch the output at all")

    def test_apply_verifies_expected_bytes_when_they_match_and_says_so(self):
        offset = self._first_text_offset()
        present = self.original[offset:offset + 2].hex()
        data = json.loads(tr.rizin_patch_apply(
            str(self.target), hex(offset), "9090", str(self.out), expected_bytes=present))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["expected_bytes_verification"], "VERIFIED")
        self.assertEqual(data["sha256"], hashlib.sha256(self.out.read_bytes()).hexdigest())

    def test_apply_without_expected_bytes_never_claims_it_verified_them(self):
        offset = self._first_text_offset()
        data = json.loads(tr.rizin_patch_apply(
            str(self.target), hex(offset), "9090", str(self.out)))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["expected_bytes_verification"], "NOT_REQUESTED")

    def test_apply_partial_write_is_a_failure_not_a_sha256_of_bytes_never_written(self):
        offset = self._first_text_offset()
        with mock.patch.object(Path, "write_bytes", _short_write):
            data = json.loads(tr.rizin_patch_apply(
                str(self.target), hex(offset), "9090", str(self.out)))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "WRITE_VERIFICATION_FAILED")
        self.assertNotEqual(data["sha256_intended"], data["sha256_written"])
        self.assertLess(self.out.stat().st_size, len(self.original))

    # --- binary_patch ------------------------------------------------------
    def _one_patch(self, offset):
        return [{"address": hex(offset), "address_kind": "file_offset",
                 "expected_bytes": self.original[offset:offset + 2].hex(),
                 "format": "hex", "value": "9090"}]

    def test_binary_patch_partial_write_is_not_reported_as_ok(self):
        offset = self._first_text_offset()
        with mock.patch.object(Path, "write_bytes", _short_write):
            data = json.loads(tr.binary_patch(
                str(self.target), "apply", self._one_patch(offset),
                dry_run=False, in_place=False, output_path=str(self.out)))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "WRITE_VERIFICATION_FAILED")
        self.assertNotEqual(data["sha256_after"], data["sha256_intended"])
        self.assertEqual(self.target.read_bytes(), self.original,
                         "in_place=False must never touch the input")

    def test_binary_patch_in_place_partial_write_is_reverted_from_backup(self):
        offset = self._first_text_offset()
        real_write_bytes = Path.write_bytes

        def _write(self_path, data):
            # let the backup copy through untouched, truncate only the target
            if self_path.name.endswith(".liebert_orig_backup"):
                return real_write_bytes(self_path, data)
            return _short_write(self_path, data)

        with mock.patch.object(Path, "write_bytes", _write):
            data = json.loads(tr.binary_patch(
                str(self.target), "apply", self._one_patch(offset),
                dry_run=False, in_place=True, backup=True))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "WRITE_VERIFICATION_FAILED")
        self.assertTrue(data["reverted"])
        self.assertEqual(self.target.read_bytes(), self.original,
                         "a failed in-place write must be rolled back from the verified backup")

    def test_binary_patch_refuses_to_write_when_its_own_backup_is_corrupt(self):
        offset = self._first_text_offset()

        def _bad_copy(src, dst, *_a, **_kw):
            Path(dst).write_bytes(b"NOT-THE-ORIGINAL")
            return str(dst)

        with mock.patch("liebert_re.tools.rizin.shutil.copy2", _bad_copy):
            data = json.loads(tr.binary_patch(
                str(self.target), "apply", self._one_patch(offset),
                dry_run=False, in_place=True, backup=True))
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "BACKUP_VERIFICATION_FAILED")
        self.assertEqual(self.target.read_bytes(), self.original,
                         "an unreversible in-place write must not happen at all")

    def test_binary_patch_real_in_place_write_is_verified_from_disk(self):
        offset = self._first_text_offset()
        data = json.loads(tr.binary_patch(
            str(self.target), "apply", self._one_patch(offset),
            dry_run=False, in_place=True, backup=True))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["backup_verification"], "CREATED_AND_VERIFIED")
        self.assertEqual(data["sha256_verified_from"], "READ_BACK_FROM_DISK")
        self.assertEqual(data["sha256_after"], hashlib.sha256(self.target.read_bytes()).hexdigest())
        self.assertEqual(self.target.read_bytes()[offset:offset + 2], b"\x90\x90")

    def test_binary_patch_that_leaves_an_unparseable_pe_is_reverted_from_backup(self):
        # binary_patch can only address section bytes, and pefile tolerates every single-byte change
        # to this fixture's sections (measured), so a patch cannot really make the PE unparseable.
        # The PE validator is therefore made to reject exactly the patched bytes, as it would a
        # corrupted file; everything else (write, read-back, backup, revert) is real.
        offset = self._first_text_offset()
        real_open = tr._open_pe_from_bytes

        def _reject_patched(data):
            if bytes(data) != self.original:
                raise ValueError("fixture: the patched image is not a valid PE")
            return real_open(data)

        with mock.patch.object(tr, "_open_pe_from_bytes", _reject_patched):
            data = json.loads(tr.binary_patch(
                str(self.target), "apply", self._one_patch(offset),
                dry_run=False, in_place=True, backup=True))
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "REVERTED_INVALID_PE")
        self.assertFalse(data["pe_valid_after"])
        self.assertEqual(self.target.read_bytes(), self.original,
                         "an in-place patch that leaves an unparseable PE must be rolled back")
        self.assertEqual(data["sha256_after"], hashlib.sha256(self.original).hexdigest())

    def test_binary_patch_restore_puts_the_original_back_from_the_backup(self):
        offset = self._first_text_offset()
        applied = json.loads(tr.binary_patch(
            str(self.target), "apply", self._one_patch(offset),
            dry_run=False, in_place=True, backup=True))
        self.assertTrue(applied["ok"], applied)
        self.assertNotEqual(self.target.read_bytes(), self.original)
        restored = json.loads(tr.binary_patch(str(self.target), "restore"))
        self.assertTrue(restored["ok"], restored)
        self.assertEqual(self.target.read_bytes(), self.original)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
