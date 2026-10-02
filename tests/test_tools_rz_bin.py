"""`liebert_re.tools.rizin` rz-bin operations: rz_bin_imports, rz_bin_sections,
rz_bin_headers, rz_bin_relocations and rz_bin_status.

Fast tier: the fixtures are trimmed captures of `rz-bin -j <flag>` from rizin
0.9.1 run on a small 64-bit PE, keeping rz-bin's own field names and value
types, so the parsing contract is pinned without launching rz-bin. The one
class that runs the real tool is `heavy` and skips without rizin.

The cases that matter most keep a weak result from reading as a strong one:
an empty list from a file rz-bin did not recognise is not a real zero, and an
operating-system error is an environment error, not a finding.
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

IMPORTS = json.dumps({"imports": [
    {"ordinal": 1, "bind": "NONE", "type": "FUNC", "name": "ShellExecuteW", "libname": "SHELL32.dll", "plt": 5368717744},
    {"ordinal": 1, "bind": "NONE", "type": "FUNC", "name": "GetCurrentThreadId", "libname": "KERNEL32.dll", "plt": 5368717640},
    {"ordinal": 2, "bind": "NONE", "type": "FUNC", "name": "GetSystemTimeAsFileTime", "libname": "KERNEL32.dll", "plt": 5368717648},
]})
SECTIONS = json.dumps({"sections": [
    {"name": ".text", "size": 3072, "vsize": 4096, "perm": "-r-x", "flags": ["CNT_CODE"], "paddr": 1024, "vaddr": 5368713216},
    {"name": ".data", "size": 512, "vsize": 4096, "perm": "-rw-", "flags": ["CNT_INITIALIZED_DATA"], "paddr": 7680, "vaddr": 5368721408},
    {"name": ".packed", "size": 512, "vsize": 4096, "perm": "-rwx", "flags": [], "paddr": 8192, "vaddr": 5368725504},
]})
_PF = [{"type": "hex", "size": 4, "offset": 144, "endian": "little", "value": 4294967295}]
HEADERS = json.dumps({"fields": [
    {"name": "RICH_ENTRY_NAME", "vaddr": 144, "paddr": 144, "comment": "Linker1400", "format": "s", "pf": []},
    {"name": "RICH_ENTRY_ID", "vaddr": 144, "paddr": 144, "comment": "0x00000102", "format": "x", "pf": _PF},
    {"name": "RICH_ENTRY_VERSION", "vaddr": 146, "paddr": 146, "comment": "0x00006b14", "format": "x", "pf": _PF},
    {"name": "RICH_ENTRY_TIMES", "vaddr": 148, "paddr": 148, "comment": "0x00000001", "format": "x", "pf": _PF},
    {"name": "RICH_ENTRY_NAME", "vaddr": 152, "paddr": 152, "comment": "Cvtres1400", "format": "s", "pf": []},
    {"name": "RICH_ENTRY_ID", "vaddr": 152, "paddr": 152, "comment": "0x000000ff", "format": "x", "pf": _PF},
    {"name": "Signature", "vaddr": 256, "paddr": 256, "comment": "0x00004550", "format": "x", "pf": _PF},
    {"name": "NumberOfSymbols ", "vaddr": 268, "paddr": 268, "comment": "0x00000000", "format": "x", "pf": _PF},
]})
RELOCS = json.dumps({"relocs": [
    {"name": "pe_00002000", "type": "IMAGE_REL_BASED_ABSOLUTE", "vaddr": 8192, "paddr": 4096, "sym_va": 0, "is_ifunc": False},
    {"name": "pe_00002000", "type": "IMAGE_REL_BASED_DIR64", "vaddr": 8192, "paddr": 4096, "sym_va": 0, "is_ifunc": False},
    {"name": "pe_00002008", "type": "IMAGE_REL_BASED_DIR64", "vaddr": 8200, "paddr": 4104, "sym_va": 0, "is_ifunc": False},
]})
INFO_PE = json.dumps({"info": {"arch": "x86", "bintype": "pe", "bits": 64, "havecode": True}})
INFO_TEXT = json.dumps({"info": {"baddr": 0, "binsz": 6, "bits": 64, "havecode": False}})


def _ok(stdout, stderr=""):
    return BoundedProcessResult(0, stdout, stderr)


class _WithSample(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sample = Path(self._tmp.name) / "sample.exe"
        self.sample.write_bytes(b"MZ" + b"\0" * 64)
        self.commands = []

    def call(self, fn, results, **kwargs):
        results = list(results) if isinstance(results, (list, tuple)) else [results]

        def fake(cmd, **_kw):
            self.commands.append(list(cmd))
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
             mock.patch.object(tr, "safe_path", return_value=self.sample), \
             mock.patch.object(tr, "relative", return_value="sample.exe"), \
             mock.patch.object(tr, "run_bounded_process", side_effect=fake):
            return json.loads(fn(str(self.sample), **kwargs))


class ImportsTests(_WithSample):
    def test_fields_and_per_library_rollup(self):
        d = self.call(tr.rz_bin_imports, _ok(IMPORTS))
        self.assertEqual((d["ok"], d["status"], d["tool"], d["count"]), (True, "OK", "rz_bin_imports", 3))
        self.assertEqual(self.commands[0][1:3], ["-j", "-i"])
        first = d["imports"][0]
        self.assertEqual((first["name"], first["library"], first["ordinal"]),
                         ("ShellExecuteW", "SHELL32.dll", 1))
        self.assertEqual(first["address"], 5368717744)
        self.assertEqual(first["address_hex"], "0x1400021b0")
        self.assertEqual(d["imports_per_library"], {"KERNEL32.dll": 2, "SHELL32.dll": 1})
        self.assertEqual(d["library_count"], 2)

    def test_cap_limits_the_listing_but_not_the_count(self):
        d = self.call(tr.rz_bin_imports, _ok(IMPORTS), max_items=1)
        self.assertEqual((d["count"], d["returned"], d["truncated"]), (3, 1, True))
        self.assertEqual(d["analysis_completeness"], "LIST_CAPPED_AT_MAX_ITEMS")
        self.assertEqual(sum(d["imports_per_library"].values()), 3)

    def test_evidence_is_the_raw_output_under_the_documented_name(self):
        d = self.call(tr.rz_bin_imports, _ok(IMPORTS))
        self.assertRegex(d["internal_evidence_name"], r"^sample_[0-9a-f]{8}_imports\.json$")
        self.assertIsNone(d["evidence_write_error"])
        saved = (tr.EVIDENCE.parent / "rz_bin" / d["internal_evidence_name"]).read_text(encoding="utf-8")
        self.assertEqual(saved, IMPORTS)

    def test_unwritable_evidence_is_reported_not_raised(self):
        with mock.patch.object(Path, "write_text", side_effect=PermissionError(13, "denied")):
            d = self.call(tr.rz_bin_imports, _ok(IMPORTS))
        self.assertTrue(d["ok"])
        self.assertIsNone(d["internal_evidence_name"])
        self.assertIn("PermissionError", d["evidence_write_error"])


class SectionsTests(_WithSample):
    def test_fields_and_writable_executable_rollup(self):
        d = self.call(tr.rz_bin_sections, _ok(SECTIONS))
        self.assertEqual(self.commands[0][1:3], ["-j", "-S"])
        text = d["sections"][0]
        self.assertEqual((text["name"], text["size"], text["virtual_size"], text["permissions"]),
                         (".text", 3072, 4096, "-r-x"))
        self.assertEqual(text["virtual_address_hex"], "0x140001000")
        self.assertEqual(text["file_offset"], 1024)
        self.assertEqual(d["writable_executable_sections"], [".packed"])

    def test_entropy_is_declared_absent_not_invented(self):
        d = self.call(tr.rz_bin_sections, _ok(SECTIONS))
        self.assertFalse(d["entropy_available"])
        self.assertNotIn("entropy", d["sections"][0])


class HeadersTests(_WithSample):
    def test_rich_entries_are_grouped_and_named_fields_are_trimmed(self):
        d = self.call(tr.rz_bin_headers, _ok(HEADERS, stderr="WARNING: pf: bare 'x' deprecated, use 'x4'\n"))
        self.assertEqual(self.commands[0][1:3], ["-j", "-H"])
        self.assertTrue(d["ok"], d)
        self.assertEqual(d["rich_entries"][0], {"name": "Linker1400", "id": "0x00000102",
                                                "version": "0x00006b14", "times": "0x00000001"})
        self.assertEqual(d["rich_entries"][1], {"name": "Cvtres1400", "id": "0x000000ff"})
        self.assertEqual(d["named"]["Signature"], "0x00004550")
        self.assertIn("NumberOfSymbols", d["named"])

    def test_the_wrong_raw_pf_decode_is_not_passed_on(self):
        d = self.call(tr.rz_bin_headers, _ok(HEADERS))
        self.assertNotIn("pf", d["fields"][1])
        self.assertEqual(d["fields"][1]["value"], "0x00000102")


class RelocationsTests(_WithSample):
    def test_fields_and_type_rollup(self):
        d = self.call(tr.rz_bin_relocations, _ok(RELOCS))
        self.assertEqual(self.commands[0][1:3], ["-j", "-R"])
        self.assertEqual(d["relocs"][0]["type"], "IMAGE_REL_BASED_ABSOLUTE")
        self.assertEqual(d["relocs"][0]["virtual_address"], 8192)
        self.assertEqual(d["by_type"], {"IMAGE_REL_BASED_ABSOLUTE": 1, "IMAGE_REL_BASED_DIR64": 2})

    def test_empty_table_on_a_recognised_binary_is_a_real_zero(self):
        d = self.call(tr.rz_bin_relocations, [_ok('{"relocs":[]}'), _ok(INFO_PE)])
        self.assertTrue(d["ok"], d)
        self.assertEqual((d["count"], d["analysis_completeness"], d["load_probe"]),
                         (0, "COMPLETE_NONE_FOUND", "BINARY_LOADED"))
        self.assertEqual(self.commands[1][1:3], ["-j", "-I"])

    def test_empty_table_on_an_unrecognised_file_is_not_a_zero(self):
        d = self.call(tr.rz_bin_relocations, [_ok('{"relocs":[]}'), _ok(INFO_TEXT)])
        self.assertFalse(d["ok"])
        self.assertEqual(d["status"], "ANALYSIS_LIMITED")
        self.assertEqual(d["error"], "RZ_BIN_EMPTY_RESULT_WITHOUT_LOADED_BINARY")
        self.assertEqual(d["load_probe"], "NO_BINARY_LOADED")
        self.assertNotIn("count", d)


class FailureVocabularyTests(_WithSample):
    def test_nonzero_exit_and_empty_stdout_are_analysis_limited(self):
        d = self.call(tr.rz_bin_imports, BoundedProcessResult(1, "", "rz_core: Cannot open file"))
        self.assertEqual((d["status"], d["exit_code"]), ("ANALYSIS_LIMITED", 1))
        d = self.call(tr.rz_bin_imports, _ok(""))
        self.assertEqual(d["status"], "ANALYSIS_LIMITED")

    def test_truncated_output_is_never_a_complete_result(self):
        d = self.call(tr.rz_bin_imports, BoundedProcessResult(0, IMPORTS, "", output_truncated=True))
        self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "RZ_BIN_OUTPUT_TRUNCATED_AT_CAP"))

    def test_bad_json_and_wrong_shape_are_parse_failures(self):
        self.assertEqual(self.call(tr.rz_bin_imports, _ok("{not json"))["status"], "RESULT_PARSE_FAILED")
        self.assertEqual(self.call(tr.rz_bin_imports, _ok('{"sections":[]}'))["status"], "RESULT_PARSE_FAILED")
        self.assertEqual(self.call(tr.rz_bin_imports, _ok('{"imports":5}'))["status"], "RESULT_PARSE_FAILED")

    def test_timeout_and_cancellation(self):
        d = self.call(tr.rz_bin_imports, BoundedProcessResult(None, "", "", timed_out=True))
        self.assertEqual(d["status"], "TIMEOUT")
        d = self.call(tr.rz_bin_imports, BoundedProcessResult(None, "", "", cancelled=True))
        self.assertEqual(d["status"], "CANCELLED")

    def test_timeout_uses_the_existing_rizin_clamp(self):
        seen = {}

        def fake(cmd, **kw):
            seen.update(kw)
            return _ok(IMPORTS)

        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
             mock.patch.object(tr, "safe_path", return_value=self.sample), \
             mock.patch.object(tr, "relative", return_value="sample.exe"), \
             mock.patch.object(tr, "run_bounded_process", side_effect=fake):
            tr.rz_bin_imports(str(self.sample), timeout_seconds=10**6)
        self.assertEqual(seen["timeout_seconds"], tr._MAX_TIMEOUT_SECONDS)

    def test_environment_errors_are_labelled_as_such_and_never_raised(self):
        for exc in (PermissionError(13, "Access is denied"), FileNotFoundError(2, "no such file"),
                    OSError(22, "bad")):
            d = self.call(tr.rz_bin_sections, exc)
            self.assertEqual(d["status"], "ANALYSIS_LIMITED")
            self.assertEqual(d["error"], "RZ_BIN_COULD_NOT_START")
            self.assertEqual(d["environment_error"]["type"], type(exc).__name__)
            self.assertEqual(d["environment_error"]["errno"], exc.errno)

    def test_unexpected_exception_still_returns_json(self):
        d = self.call(tr.rz_bin_sections, RuntimeError("boom"))
        self.assertEqual((d["status"], d["error"]), ("ANALYSIS_LIMITED", "RZ_BIN_UNEXPECTED_ERROR"))
        self.assertNotIn("environment_error", d)


class PathAndToolGateTests(unittest.TestCase):
    def test_missing_tool_is_tool_missing_for_every_operation(self):
        with mock.patch.object(tr._RzBin, "binary", return_value=None), \
             mock.patch.object(tr, "run_bounded_process") as run:
            for fn in (tr.rz_bin_imports, tr.rz_bin_sections, tr.rz_bin_headers, tr.rz_bin_relocations):
                d = json.loads(fn("x.exe"))
                self.assertEqual((d["ok"], d["status"], d["tool"]), (False, "TOOL_MISSING", fn.__name__))
            d = json.loads(tr.rz_bin_status())
            self.assertEqual(d["status"], "TOOL_MISSING")
            run.assert_not_called()

    def test_path_is_checked_before_any_subprocess(self):
        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
             mock.patch.object(tr, "run_bounded_process") as run:
            with mock.patch.object(tr, "safe_path", side_effect=PermissionError("denied")):
                self.assertEqual(json.loads(tr.rz_bin_imports("x"))["status"], "PATH_REFUSED")
            with TemporaryDirectory() as tmp:
                with mock.patch.object(tr, "safe_path", return_value=Path(tmp) / "absent.exe"):
                    self.assertEqual(json.loads(tr.rz_bin_imports("x"))["status"], "NOT_FOUND")
                with mock.patch.object(tr, "safe_path", return_value=Path(tmp)):
                    self.assertEqual(json.loads(tr.rz_bin_imports("x"))["status"], "NOT_FOUND")
            run.assert_not_called()

    def test_a_path_check_os_error_is_an_environment_error(self):
        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
             mock.patch.object(tr, "safe_path", side_effect=PermissionError(13, "denied")) as sp:
            # PermissionError from safe_path is the sandbox verdict, not an OS fault.
            self.assertEqual(json.loads(tr.rz_bin_imports("x"))["status"], "PATH_REFUSED")
            sp.side_effect = OSError(5, "I/O error")
            d = json.loads(tr.rz_bin_imports("x"))
        self.assertEqual(d["error"], "RZ_BIN_PATH_CHECK_FAILED")
        self.assertEqual(d["environment_error"]["errno"], 5)


class StatusTests(unittest.TestCase):
    def test_status_reports_version_and_operations(self):
        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
             mock.patch.object(tr, "run_bounded_process",
                               return_value=_ok("rz-bin 0.9.1 @ windows-x86-64\ncommit: abc\n")):
            d = json.loads(tr.rz_bin_status())
        self.assertEqual((d["ok"], d["status"], d["tool"]), (True, "OK", "rz_bin_status"))
        self.assertEqual(d["version"], "rz-bin 0.9.1 @ windows-x86-64")
        self.assertIn("rz_bin_headers", d["operations"])

    def test_status_environment_error_and_failure(self):
        with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"):
            with mock.patch.object(tr, "run_bounded_process", side_effect=PermissionError(13, "denied")):
                d = json.loads(tr.rz_bin_status())
            self.assertIn("environment_error", d)
            with mock.patch.object(tr, "run_bounded_process", return_value=BoundedProcessResult(1, "", "bad")):
                self.assertEqual(json.loads(tr.rz_bin_status())["status"], "ANALYSIS_LIMITED")

    def test_rizin_status_is_unchanged(self):
        with mock.patch.object(tr, "_rizin_binary", return_value=None):
            self.assertEqual(json.loads(tr.rizin_status()), {"rizin_exe": None, "available": False})


class BinaryResolutionTests(unittest.TestCase):
    def test_env_root_dir_then_bin_subdir_then_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            exe = root / "bin" / "rz-bin.exe"
            exe.write_bytes(b"")
            with mock.patch.dict("os.environ", {"RIZIN_HOME": str(root)}):
                self.assertEqual(tr._RzBin.binary(), str(exe))
            root_exe = root / "rz-bin.exe"
            root_exe.write_bytes(b"")
            with mock.patch.dict("os.environ", {"RIZIN_HOME": str(root)}):
                self.assertEqual(tr._RzBin.binary(), str(root_exe))
            with mock.patch.dict("os.environ", {"RIZIN_HOME": str(root_exe)}):
                self.assertEqual(tr._RzBin.binary(), str(root_exe))
            with mock.patch.dict("os.environ", {"RIZIN_HOME": ""}), \
                 mock.patch.object(tr.shutil, "which", side_effect=lambda n: "/usr/bin/rz-bin" if n == "rz-bin" else None):
                self.assertEqual(tr._RzBin.binary(), "/usr/bin/rz-bin")


@pytest.mark.heavy
class RzBinRealBinaryTests(unittest.TestCase):
    """Runs the real rz-bin on a small PE copied from the Windows system
    directory (the original is never opened by rz-bin)."""

    def setUp(self):
        if tr._RzBin.binary() is None:
            raise unittest.SkipTest("rz-bin not installed on this machine")
        source = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "calc.exe"
        if not source.is_file():
            raise unittest.SkipTest("no system PE to copy: " + str(source))
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pe = Path(tmp.name) / "sample.exe"
        shutil.copyfile(source, self.pe)
        for name, effect in (("safe_path", Path), ("relative", lambda p: Path(p).name)):
            patcher = mock.patch.object(tr, name, side_effect=effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_all_four_operations_return_structure_for_a_real_pe(self):
        imports = json.loads(tr.rz_bin_imports(str(self.pe)))
        self.assertTrue(imports["ok"], imports)
        self.assertGreater(imports["count"], 0)
        self.assertTrue(imports["imports"][0]["library"])
        self.assertIsInstance(imports["imports"][0]["address"], int)
        sections = json.loads(tr.rz_bin_sections(str(self.pe)))
        self.assertIn(".text", [s["name"] for s in sections["sections"]])
        headers = json.loads(tr.rz_bin_headers(str(self.pe)))
        self.assertEqual(headers["named"]["Signature"], "0x00004550")
        relocs = json.loads(tr.rz_bin_relocations(str(self.pe)))
        self.assertEqual(relocs["status"], "OK", relocs)

    def test_a_text_file_is_not_reported_as_an_empty_binary(self):
        text = self.pe.with_name("note.txt")
        text.write_text("hello")
        d = json.loads(tr.rz_bin_imports(str(text)))
        self.assertEqual((d["status"], d["load_probe"]), ("ANALYSIS_LIMITED", "NO_BINARY_LOADED"))

    def test_status_reports_the_installed_version(self):
        d = json.loads(tr.rz_bin_status())
        self.assertTrue(d["ok"], d)
        self.assertTrue(d["version"].startswith("rz-bin"))
