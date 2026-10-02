"""`liebert_re.tools.rizin` FLIRT operations: rizin_flirt_match (`Fa`, the bundled sigdb),
rizin_flirt_match_file (`Fs`, one .sig/.pat file) and rizin_flirt_inventory (`Fl`).

Fast tier: the fixtures are trimmed captures of what rizin 0.9.1 really printed for a 32-bit
PE (`iIj`, the `Fl` table, `afl~flirt`, the `Applying ...` lines and the FLIRT errors on
stderr), so the parsing contract is pinned without launching rizin. The one class that runs
the real tool is `heavy` and skips without rizin.

The cases that matter most keep a weak result from reading as a strong one: a binary no
signature set was built for is not "no match", a file rizin did not load is not an empty
binary, and an operating-system error is an environment error, not a finding.
"""
from __future__ import annotations

import json
import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

import liebert_re.tools.rizin as tr
from liebert_re.bounded_subprocess import BoundedProcessResult

INFO_PE32 = ('{"arch":"x86","baddr":4194304,"binsz":236544,"bintype":"pe","bits":32,"class":"PE32",'
             '"endian":"LE","machine":"i386","os":"windows","havecode":true}')
INFO_TEXT = '{"baddr":0,"binsz":102,"bits":64,"endian":"LE","laddr":0,"havecode":false,"static":true}'
INFO_PPC = '{"arch":"ppc","bintype":"pe","bits":32,"havecode":true}'
FL_TABLE = """\
\x1b[2Kbin arch bits name                    modules details
――――――――――――――――――――――――――――――――――――――――――――――――――――――――
elf x86    32 fedora-zlib.sig              244 Fedora ZLib build Version 1.3 (rizin.re)
pe  arm    32 winsdk.sig                 65742 Windows SDK ARM 32 (rizin.re)
pe  x86    32 VisualStudio2005.sig       17674 Microsoft Visual Studio 2005 x86 (rizin.re)
pe  x86    32 mingw32-zlib.sig             111 MinGW ZLib build Version 1.3 (rizin.re)
pe  x86    32 winsdk.sig                 14261 Windows SDK x86 (rizin.re)
pe  x86    64 winsdk.sig                 13923 Windows SDK x64 (rizin.re)
"""
PHASE1 = INFO_PE32 + "\nFLIRT_PROBE_END\n" + FL_TABLE
# `iIj; echo FLIRT_PROBE_END; aaa; afl~?; echo FLIRT_BASELINE; afl~flirt; Fa <set>; echo FLIRT_SET <set>; ...`
PHASE2 = (
    "\x1b[2K" + INFO_PE32 + "\nFLIRT_PROBE_END\n510\nFLIRT_BASELINE\n"
    "Applying pe/arm/32/VisualStudio2005.sig signature file\n"
    "Applying pe/x86/32/VisualStudio2005.sig signature file\n"
    "FLIRT_SET VisualStudio2005.sig\n"
    "0x004171a8    1 69           flirt.SEH_prolog4\n"
    "0x00417ea0    3 52           flirt.allmul\n"
    "Applying pe/x86/32/mingw32-zlib.sig signature file\n"
    "FLIRT_SET mingw32-zlib.sig\n"
    "0x004171a8    1 69           flirt.SEH_prolog4\n"
    "0x00417ea0    3 52           flirt.allmul\n"
    "Applying pe/arm/32/winsdk.sig signature file\n"
    "Applying pe/x86/32/winsdk.sig signature file\n"
    "Applying pe/x86/64/winsdk.sig signature file\n"
    "FLIRT_SET winsdk.sig\n"
    "0x00417000    4 188  -> 166  flirt.IsNonwritableInCurrentImage\n"
    "0x004171a8    1 69           flirt.SEH_prolog4\n"
    "0x00417ea0    3 52           flirt.allmul\n"
)
PHASE2_NO_MATCH = (
    INFO_PE32 + "\nFLIRT_PROBE_END\n510\nFLIRT_BASELINE\n"
    "Applying pe/x86/32/VisualStudio2005.sig signature file\nFLIRT_SET VisualStudio2005.sig\n"
    "Applying pe/x86/32/mingw32-zlib.sig signature file\nFLIRT_SET mingw32-zlib.sig\n"
    "Applying pe/arm/32/winsdk.sig signature file\nApplying pe/x86/32/winsdk.sig signature file\n"
    "Applying pe/x86/64/winsdk.sig signature file\nFLIRT_SET winsdk.sig\n"
)
ARM_STDERR = (
    "\x1b[2KERROR: FLIRT: the binary architecture did not match the .sig one.\n"
    "ERROR: FLIRT: We encountered an error while parsing the file "
    "C:\\Tools\\rizin\\share\\sigdb\\pe\\arm\\32\\winsdk.sig. Sorry.\n"
)
X86_STDERR = (
    "ERROR: FLIRT: invalid sig file (EOF in v5 header magic).\n"
    "ERROR: FLIRT: We encountered an error while parsing the file "
    "C:\\Tools\\rizin\\share\\sigdb\\pe\\x86\\32\\winsdk.sig. Sorry.\n"
)
FS_OK = (INFO_PE32 + "\nFLIRT_PROBE_END\n510\nFLIRT_BASELINE\nFound 6 FLIRT signatures via w32.sig\n"
         "FLIRT_SET FILE\n0x00417565    5 32           flirt.8error_condition\n"
         "0x00417ea0    3 52           flirt.allmul\n")
FS_NONE = INFO_PE32 + "\nFLIRT_PROBE_END\n510\nFLIRT_BASELINE\nFound 0 FLIRT signatures via z32.sig\nFLIRT_SET FILE\n"


def _ok(stdout, stderr=""):
    return BoundedProcessResult(0, stdout, stderr)


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sample = Path(self._tmp.name) / "sample.exe"
        self.sample.write_bytes(b"MZ" + b"\0" * 64)
        self.sig = Path(self._tmp.name) / "w32.sig"
        self.sig.write_bytes(b"IDASGN")
        self.commands = []

    def call(self, fn, results, *args, **kwargs):
        results = list(results) if isinstance(results, (list, tuple)) else [results]

        def fake(cmd, **_kw):
            self.commands.append(list(cmd))
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "safe_path", side_effect=Path), \
             mock.patch.object(tr, "relative", side_effect=lambda p: Path(p).name), \
             mock.patch.object(tr, "run_bounded_process", side_effect=fake):
            return json.loads(fn(*args, **kwargs))

    def match(self, results, **kwargs):
        return self.call(tr.rizin_flirt_match, results, str(self.sample), **kwargs)

    def match_file(self, results, sig=None, **kwargs):
        return self.call(tr.rizin_flirt_match_file, results, str(self.sample), str(sig or self.sig), **kwargs)


class SigdbMatchTests(_Base):
    def test_matches_are_named_addressed_and_attributed_to_a_set(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2, ARM_STDERR)])
        self.assertEqual((d["ok"], d["status"], d["tool"]), (True, "OK", "rizin_flirt_match"))
        self.assertEqual(d["target"], {"bintype": "pe", "arch": "x86", "bits": 32})
        self.assertEqual((d["functions_analyzed"], d["match_count"], d["analysis_completeness"]), (510, 3, "COMPLETE"))
        by_name = {f["name"]: f for f in d["named_functions"]}
        self.assertEqual(by_name["SEH_prolog4"]["address"], 0x4171A8)
        self.assertEqual(by_name["SEH_prolog4"]["address_hex"], "0x4171a8")
        self.assertEqual(by_name["SEH_prolog4"]["signature_set"], "VisualStudio2005.sig")
        self.assertEqual(by_name["IsNonwritableInCurrentImage"]["signature_set"], "winsdk.sig")
        self.assertEqual(by_name["IsNonwritableInCurrentImage"]["size"], 188)
        self.assertEqual(d["matches_per_signature_set"], {"VisualStudio2005.sig": 2, "winsdk.sig": 1})
        self.assertEqual(d["signature_sets_with_errors"], [])

    def test_only_compatible_sets_are_applied_one_at_a_time_with_the_sigdb_switched_off(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2)])
        self.assertEqual(d["signature_sets_considered"], [
            "pe/x86/32/VisualStudio2005.sig", "pe/x86/32/mingw32-zlib.sig", "pe/x86/32/winsdk.sig"])
        self.assertEqual(len(self.commands), 2)
        for argv in self.commands:
            self.assertIn("analysis.apply.signature=false", argv)
        phase2 = self.commands[1][self.commands[1].index("-c") + 1]
        self.assertEqual(phase2.count("Fa "), 3)
        self.assertNotIn("elf", phase2)
        self.assertNotIn("pe/arm", phase2)
        self.assertEqual(d["signature_sets_applied"], d["signature_sets_considered"])

    def test_filter_narrows_the_sets(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2)], signature_filter="winsdk")
        self.assertEqual(d["signature_sets_considered"], ["pe/x86/32/winsdk.sig"])
        self.assertEqual(self.commands[1][self.commands[1].index("-c") + 1].count("Fa "), 1)

    def test_a_real_negative_is_ok_with_zero_matches(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2_NO_MATCH)])
        self.assertEqual((d["ok"], d["status"], d["match_count"]), (True, "OK", 0))
        self.assertEqual(d["analysis_completeness"], "COMPLETE_NO_MATCH")
        self.assertEqual(d["named_functions"], [])

    def test_foreign_architecture_noise_is_not_an_error_but_a_compatible_set_failure_is(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2, ARM_STDERR)])
        self.assertEqual(d["analysis_completeness"], "COMPLETE")
        d = self.match([_ok(PHASE1), _ok(PHASE2, X86_STDERR)])
        self.assertEqual(d["analysis_completeness"], "PARTIAL_SIGNATURE_ERRORS")
        self.assertEqual(d["signature_sets_with_errors"], ["pe/x86/32/winsdk.sig"])
        self.assertNotIn("pe/x86/32/winsdk.sig", d["signature_sets_applied"])

    def test_list_is_capped_but_the_count_is_not(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2)], max_items=2)
        self.assertEqual((d["match_count"], d["returned"], d["truncated"]), (3, 2, True))
        self.assertEqual(d["analysis_completeness"], "LIST_CAPPED_AT_MAX_ITEMS")

    def test_evidence_name_is_reported(self):
        d = self.match([_ok(PHASE1), _ok(PHASE2)])
        self.assertTrue(d["internal_evidence_name"].endswith("_fa.txt"))
        self.assertIsNone(d["evidence_write_error"])

    def test_timeout_uses_the_existing_rizin_clamp(self):
        seen = []

        def fake(cmd, **kw):
            seen.append(kw["timeout_seconds"])
            return _ok(PHASE1 if len(seen) == 1 else PHASE2)

        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "safe_path", side_effect=Path), \
             mock.patch.object(tr, "relative", side_effect=lambda p: Path(p).name), \
             mock.patch.object(tr, "run_bounded_process", side_effect=fake):
            tr.rizin_flirt_match(str(self.sample), timeout_seconds=10**6)
        self.assertEqual(seen, [tr._MAX_TIMEOUT_SECONDS] * 2)


class HonestNegativeTests(_Base):
    @pytest.mark.contract
    def test_a_target_no_set_was_built_for_is_not_a_zero(self):
        ppc = INFO_PPC + "\nFLIRT_PROBE_END\n" + FL_TABLE
        d = self.match([_ok(ppc)])
        self.assertEqual((d["ok"], d["status"]), (False, "NO_COMPATIBLE_SIGNATURES"))
        self.assertNotIn("match_count", d)
        self.assertEqual(d["target"]["arch"], "ppc")
        self.assertIn("pe/x86/32", d["sigdb_targets"])
        self.assertEqual(len(self.commands), 1, "nothing may be applied when no set can match")

    @pytest.mark.contract
    def test_a_filter_that_leaves_no_compatible_set_is_the_same_status(self):
        d = self.match([_ok(PHASE1)], signature_filter="nosuchset")
        self.assertEqual(d["status"], "NO_COMPATIBLE_SIGNATURES")
        self.assertEqual(d["signature_filter"], "nosuchset")

    @pytest.mark.contract
    def test_a_file_rizin_did_not_load_is_not_an_empty_binary(self):
        d = self.match([_ok(INFO_TEXT + "\nFLIRT_PROBE_END\n" + FL_TABLE)])
        self.assertEqual((d["status"], d["error"], d["load_probe"]),
                         ("ANALYSIS_LIMITED", "RIZIN_FLIRT_NO_LOADED_BINARY", "NO_BINARY_LOADED"))
        d = self.match([_ok("garbage\nFLIRT_PROBE_END\n" + FL_TABLE)])
        self.assertEqual(d["load_probe"], "PROBE_UNAVAILABLE")

    @pytest.mark.contract
    def test_no_analysed_functions_is_not_a_zero(self):
        empty = INFO_PE32 + "\nFLIRT_PROBE_END\n0\nFLIRT_BASELINE\n"
        d = self.match([_ok(PHASE1), _ok(empty)])
        self.assertEqual((d["ok"], d["status"], d["functions_analyzed"]), (False, "NO_FUNCTIONS_TO_MATCH", 0))
        d = self.match([_ok(PHASE1), _ok(PHASE2_NO_MATCH, "ERROR: FLIRT: There are no analyzed functions.\n")])
        self.assertEqual(d["status"], "NO_FUNCTIONS_TO_MATCH")

    @pytest.mark.contract
    def test_a_changed_or_unreadable_sigdb_table_is_a_parse_failure_not_a_skip(self):
        d = self.match([_ok(INFO_PE32 + "\nFLIRT_PROBE_END\nname bin\n")])
        self.assertEqual((d["status"], d["error"]), ("RESULT_PARSE_FAILED", "RIZIN_FL_HEADER_NOT_RECOGNISED"))
        torn = FL_TABLE + "pe x86 thirty-two winsdk.sig lots\n"
        d = self.match([_ok(INFO_PE32 + "\nFLIRT_PROBE_END\n" + torn)])
        self.assertEqual((d["status"], d["error"]), ("RESULT_PARSE_FAILED", "RIZIN_FL_ROW_NOT_RECOGNISED"))


class FileMatchTests(_Base):
    def test_matches_come_from_the_named_file(self):
        d = self.match_file(_ok(FS_OK))
        self.assertEqual((d["ok"], d["status"], d["tool"]), (True, "OK", "rizin_flirt_match_file"))
        self.assertEqual((d["signature_source"], d["signature_file"], d["match_count"]), ("file", "w32.sig", 2))
        self.assertEqual(d["rizin_reported_signature_count"], 6)
        self.assertEqual({f["signature_set"] for f in d["named_functions"]}, {"w32.sig"})
        self.assertEqual(len(self.commands), 1)
        script = self.commands[0][self.commands[0].index("-c") + 1]
        self.assertIn(f'Fs "{self.sig.as_posix()}"', script)

    def test_a_zero_from_a_supplied_file_says_its_compatibility_is_unverified(self):
        d = self.match_file(_ok(FS_NONE))
        self.assertEqual((d["ok"], d["match_count"]), (True, 0))
        self.assertEqual(d["analysis_completeness"], "COMPLETE_NO_MATCH_COMPATIBILITY_UNVERIFIED")
        self.assertFalse(d["compatibility_verified"])

    @pytest.mark.contract
    def test_rejected_and_mismatched_files_are_not_zeros(self):
        bad = _ok(FS_NONE, "ERROR: FLIRT: invalid sig magic.\nERROR: FLIRT: We encountered an error while parsing "
                           "the file x.sig. Sorry.\n")
        d = self.match_file(bad)
        self.assertEqual((d["ok"], d["status"]), (False, "SIGNATURE_FILE_REJECTED"))
        self.assertNotIn("match_count", d)
        d = self.match_file(_ok(FS_NONE, ARM_STDERR))
        self.assertEqual(d["status"], "SIGNATURE_ARCH_MISMATCH")

    @pytest.mark.contract
    def test_an_unopenable_file_is_the_machine_not_the_signatures(self):
        d = self.match_file(_ok(FS_NONE, "ERROR: FLIRT: Can't open w32.sig\n"))
        self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "FLIRT_SIGNATURE_FILE_NOT_OPENED"))

    @pytest.mark.contract
    def test_extension_and_path_are_checked_before_any_subprocess(self):
        txt = Path(self._tmp.name) / "list.txt"
        txt.write_text("x")
        d = self.match_file([], sig=txt)
        self.assertEqual((d["status"], d["error"]), ("INVALID_ARGUMENT", "FLIRT_FILE_EXTENSION_NOT_SUPPORTED"))
        d = self.match_file([], sig=Path(self._tmp.name) / "absent.sig")
        self.assertEqual((d["status"], d["signature_file"].endswith("absent.sig")), ("NOT_FOUND", True))
        odd = Path(self._tmp.name) / "a;b$.sig"
        odd.write_bytes(b"x")
        d = self.match_file([], sig=odd)
        self.assertEqual((d["status"], d["error"]), ("INVALID_ARGUMENT", "FLIRT_SIGNATURE_PATH_NOT_ALLOWED"))
        self.assertEqual(self.commands, [])

    @pytest.mark.contract
    def test_the_signature_path_goes_through_the_sandbox(self):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "run_bounded_process") as run:
            def refuse(p):
                if str(p).endswith(".sig"):
                    raise PermissionError("outside the workspace")
                return Path(p)
            with mock.patch.object(tr, "safe_path", side_effect=refuse):
                d = json.loads(tr.rizin_flirt_match_file(str(self.sample), str(self.sig)))
            run.assert_not_called()
        self.assertEqual(d["status"], "PATH_REFUSED")


class InventoryTests(unittest.TestCase):
    def inv(self, result):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "run_bounded_process", return_value=result) as run:
            d = json.loads(tr.rizin_flirt_inventory())
        return d, run

    def test_files_modules_and_targets(self):
        d, run = self.inv(_ok(FL_TABLE))
        self.assertEqual((d["ok"], d["status"], d["tool"]), (True, "OK", "rizin_flirt_inventory"))
        self.assertEqual((d["file_count"], d["module_count"]), (6, 244 + 65742 + 17674 + 111 + 14261 + 13923))
        targets = {(t["bin"], t["arch"], t["bits"]): t for t in d["by_target"]}
        self.assertEqual(targets[("pe", "x86", 32)], {"bin": "pe", "arch": "x86", "bits": 32, "files": 3, "modules": 32046})
        row = [r for r in d["signature_files"] if r["name"] == "winsdk.sig" and r["arch"] == "x86" and r["bits"] == 32][0]
        self.assertEqual((row["path"], row["modules"]), ("pe/x86/32/winsdk.sig", 14261))
        self.assertIn("Windows SDK x86", row["details"])
        self.assertEqual(run.call_args[0][0][-1], "Fl")

    @pytest.mark.contract
    def test_an_empty_sigdb_is_not_a_zero_file_success(self):
        d, _ = self.inv(_ok("bin arch bits name modules details\n――――――――――――\n"))
        self.assertEqual((d["ok"], d["status"]), (False, "SIGDB_EMPTY_OR_UNAVAILABLE"))

    @pytest.mark.contract
    def test_drift_and_failures(self):
        self.assertEqual(self.inv(_ok("totally different\n"))[0]["status"], "RESULT_PARSE_FAILED")
        self.assertEqual(self.inv(BoundedProcessResult(None, "", "", timed_out=True))[0]["status"], "TIMEOUT")
        self.assertEqual(self.inv(BoundedProcessResult(None, "", "", cancelled=True))[0]["status"], "CANCELLED")
        self.assertEqual(self.inv(BoundedProcessResult(1, "", "boom"))[0]["status"], "ANALYSIS_LIMITED")
        d, _ = self.inv(BoundedProcessResult(0, FL_TABLE, "", output_truncated=True))
        self.assertEqual(d["error"], "RIZIN_FLIRT_OUTPUT_TRUNCATED_AT_CAP")

    @pytest.mark.contract
    def test_environment_error_is_labelled_and_never_raised(self):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "run_bounded_process", side_effect=PermissionError(13, "Access is denied")):
            d = json.loads(tr.rizin_flirt_inventory())
        self.assertEqual((d["status"], d["error"], d["environment_error"]["errno"]),
                         ("ANALYSIS_LIMITED", "RIZIN_FLIRT_COULD_NOT_START", 13))

    def test_rizin_status_is_unchanged(self):
        with mock.patch.object(tr, "_rizin_binary", return_value=None):
            self.assertEqual(json.loads(tr.rizin_status()), {"rizin_exe": None, "available": False})


class SharedFailureVocabularyTests(_Base):
    @pytest.mark.contract
    def test_missing_tool_is_tool_missing_for_every_operation(self):
        with mock.patch.object(tr, "_rizin_binary", return_value=None), \
             mock.patch.object(tr, "run_bounded_process") as run:
            for d in (json.loads(tr.rizin_flirt_match("x.exe")),
                      json.loads(tr.rizin_flirt_match_file("x.exe", "y.sig")),
                      json.loads(tr.rizin_flirt_inventory())):
                self.assertEqual((d["ok"], d["status"]), (False, "TOOL_MISSING"))
            run.assert_not_called()

    @pytest.mark.contract
    def test_filter_is_allow_listed_before_it_reaches_a_rizin_command(self):
        for bad in ("a;b", "x y", "$(calc)", "", "a" * 65, "..\\..", "x|y", 5):
            d = self.match([], signature_filter=bad)
            self.assertEqual((d["status"], d["error"]), ("INVALID_ARGUMENT", "FLIRT_FILTER_NOT_ALLOWED"), bad)
        self.assertEqual(self.commands, [])

    @pytest.mark.contract
    def test_path_is_checked_before_any_subprocess(self):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch.object(tr, "run_bounded_process") as run:
            with mock.patch.object(tr, "safe_path", side_effect=PermissionError("denied")):
                self.assertEqual(json.loads(tr.rizin_flirt_match("x"))["status"], "PATH_REFUSED")
            with mock.patch.object(tr, "safe_path", return_value=Path(self._tmp.name) / "absent.exe"):
                self.assertEqual(json.loads(tr.rizin_flirt_match("x"))["status"], "NOT_FOUND")
            with mock.patch.object(tr, "safe_path", return_value=Path(self._tmp.name)):
                self.assertEqual(json.loads(tr.rizin_flirt_match("x"))["status"], "NOT_FOUND")
            with mock.patch.object(tr, "safe_path", side_effect=OSError(5, "I/O error")):
                d = json.loads(tr.rizin_flirt_match("x"))
            run.assert_not_called()
        self.assertEqual((d["error"], d["environment_error"]["errno"]), ("RIZIN_FLIRT_PATH_CHECK_FAILED", 5))

    @pytest.mark.contract
    def test_nonzero_exit_empty_stdout_and_truncation_are_analysis_limited(self):
        d = self.match(BoundedProcessResult(1, "", "rizin: cannot open"))
        self.assertEqual((d["status"], d["exit_code"]), ("ANALYSIS_LIMITED", 1))
        self.assertEqual(self.match(_ok(""))["status"], "ANALYSIS_LIMITED")
        d = self.match(BoundedProcessResult(0, PHASE1, "", output_truncated=True))
        self.assertEqual(d["error"], "RIZIN_FLIRT_OUTPUT_TRUNCATED_AT_CAP")
        d = self.match([_ok(PHASE1), BoundedProcessResult(0, PHASE2, "", output_truncated=True)])
        self.assertEqual(d["error"], "RIZIN_FLIRT_OUTPUT_TRUNCATED_AT_CAP")

    @pytest.mark.contract
    def test_timeout_and_cancellation_in_either_phase(self):
        for result, status in ((BoundedProcessResult(None, "", "", timed_out=True), "TIMEOUT"),
                               (BoundedProcessResult(None, "", "", cancelled=True), "CANCELLED")):
            self.assertEqual(self.match(result)["status"], status)
            self.assertEqual(self.match([_ok(PHASE1), result])["status"], status)
            self.assertEqual(self.match_file(result)["status"], status)

    @pytest.mark.contract
    def test_environment_errors_are_labelled_as_such_and_never_raised(self):
        for exc in (PermissionError(13, "Access is denied"), FileNotFoundError(2, "no such file"), OSError(22, "bad")):
            for d in (self.match(exc), self.match([_ok(PHASE1), exc]), self.match_file(exc)):
                self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "RIZIN_FLIRT_COULD_NOT_START"))
                self.assertEqual((d["environment_error"]["type"], d["environment_error"]["errno"]),
                                 (type(exc).__name__, exc.errno))

    @pytest.mark.contract
    def test_unexpected_exception_still_returns_json(self):
        d = self.match(RuntimeError("boom"))
        self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "RIZIN_FLIRT_UNEXPECTED_ERROR"))
        self.assertNotIn("environment_error", d)

    @pytest.mark.contract
    def test_a_bad_numeric_argument_is_reported_not_raised(self):
        d = self.match([], timeout_seconds="soon")
        self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "RIZIN_FLIRT_BAD_NUMERIC_ARGUMENT"))
        d = self.match([], max_items=None)
        self.assertEqual(d["error"], "RIZIN_FLIRT_BAD_NUMERIC_ARGUMENT")

    @pytest.mark.contract
    def test_an_evidence_write_failure_never_blocks_the_result(self):
        with mock.patch.object(tr.Path, "mkdir", side_effect=PermissionError(13, "denied")):
            d = self.match([_ok(PHASE1), _ok(PHASE2)])
        self.assertTrue(d["ok"])
        self.assertIsNone(d["internal_evidence_name"])
        self.assertIn("PermissionError", d["evidence_write_error"])


@pytest.mark.heavy
class RizinFlirtRealBinaryTests(unittest.TestCase):
    """Runs the real rizin on a small PE copied from the Windows system directory (the
    original is never opened by rizin)."""

    def setUp(self):
        if tr._rizin_binary() is None:
            raise unittest.SkipTest("rizin not installed on this machine")
        source = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "cmd.exe"
        if not source.is_file():
            raise unittest.SkipTest("no system PE to copy: " + str(source))
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.pe = self.tmp / "sample.exe"
        shutil.copyfile(source, self.pe)
        for name, effect in (("safe_path", Path), ("relative", lambda p: Path(p).name)):
            patcher = mock.patch.object(tr, name, side_effect=effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_inventory_lists_the_embedded_sigdb(self):
        d = json.loads(tr.rizin_flirt_inventory())
        if d["status"] == "SIGDB_EMPTY_OR_UNAVAILABLE":
            raise unittest.SkipTest("this rizin install has no embedded sigdb")
        self.assertTrue(d["ok"], d)
        self.assertGreater(d["file_count"], 10)
        self.assertIn(("pe", "x86", 64), {(t["bin"], t["arch"], t["bits"]) for t in d["by_target"]})

    def test_sigdb_match_names_functions_in_a_real_pe(self):
        d = json.loads(tr.rizin_flirt_match(str(self.pe)))
        if d["status"] == "NO_COMPATIBLE_SIGNATURES":
            raise unittest.SkipTest("no sigdb set for this machine's system binary")
        self.assertTrue(d["ok"], d)
        self.assertGreater(d["functions_analyzed"], 0)
        self.assertGreater(d["match_count"], 0)
        first = d["named_functions"][0]
        self.assertTrue(first["name"] and first["signature_set"].endswith(".sig"))
        self.assertIsInstance(first["address"], int)
        self.assertTrue(set(d["matches_per_signature_set"]) <= {p.split("/")[-1] for p in d["signature_sets_considered"]})

    def test_a_sigdb_file_can_be_applied_explicitly(self):
        root = os.environ.get("RIZIN_HOME", "")
        found = list(Path(root).rglob("sigdb/pe/x86/64/winsdk.sig")) if root else []
        if not found:
            raise unittest.SkipTest("embedded sigdb file not found under RIZIN_HOME")
        sig = self.tmp / "winsdk.sig"
        shutil.copyfile(found[0], sig)
        d = json.loads(tr.rizin_flirt_match_file(str(self.pe), str(sig)))
        self.assertTrue(d["ok"], d)
        self.assertEqual(d["signature_source"], "file")

    def test_a_text_file_is_not_reported_as_an_unmatched_binary(self):
        text = self.tmp / "note.exe"
        text.write_text("not a binary at all\n" * 5)
        d = json.loads(tr.rizin_flirt_match(str(text)))
        self.assertFalse(d["ok"])
        self.assertEqual(d["status"], "ANALYSIS_LIMITED")
        self.assertNotIn("match_count", d)

    def test_a_garbage_signature_file_is_rejected_not_a_zero(self):
        bad = self.tmp / "bad.sig"
        bad.write_text("hello")
        d = json.loads(tr.rizin_flirt_match_file(str(self.pe), str(bad)))
        self.assertEqual(d["status"], "SIGNATURE_FILE_REJECTED", d)
