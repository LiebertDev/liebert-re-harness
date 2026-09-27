"""tools_rizin.py's own contract: TOOL_MISSING when rizin is absent (never
raises), a real corpus binary returns a non-empty function inventory with
plausible addresses, the timeout path is exercised, and output is bounded.
Mirrors the guard style tools_native_pdb_toolchain tests use for a real,
possibly-absent external toolchain: probe first, skipTest cleanly when the
real tool genuinely isn't installed on this machine, instead of asserting
platform state the harness doesn't control.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

import tools_rizin as tr

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGINCRACKME = REPO_ROOT / "benchmarks/windows_native_ladder/corpus/tier1/logincrackme/LoginCrackme.exe"
ELEVENPACK = REPO_ROOT / "benchmarks/windows_native_ladder/corpus/tier2/decryption_key1/elevenpack.exe"


class RizinMissingTests(unittest.TestCase):
    """The absence path must never raise and must use the repo's standard
    TOOL_MISSING shape, independent of whether rizin is actually installed
    on the machine running the test."""

    def test_missing_binary_returns_tool_missing_not_an_exception(self):
        with mock.patch.object(tr, "_rizin_binary", return_value=None):
            out = tr.rizin_functions(str(LOGINCRACKME))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TOOL_MISSING")
        self.assertIn("required_capability", data)

    def test_status_reports_unavailable_when_binary_absent(self):
        with mock.patch.object(tr, "_rizin_binary", return_value=None):
            out = tr.rizin_status()
        data = json.loads(out)
        self.assertIsNone(data["rizin_exe"])
        self.assertFalse(data["available"])


class RizinRealBinaryTests(unittest.TestCase):
    """Exercised against real rizin + a real corpus binary when rizin is
    actually installed; skips cleanly otherwise (matches the guard style
    other real-tool tests in this repo use for possibly-absent toolchains)."""

    def setUp(self):
        if tr._rizin_binary() is None:
            raise unittest.SkipTest("rizin not installed on this machine")
        if not LOGINCRACKME.is_file():
            raise unittest.SkipTest("corpus fixture missing: " + str(LOGINCRACKME))

    def test_real_corpus_binary_returns_nonempty_function_list_with_plausible_addresses(self):
        out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=60)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertGreater(data["function_count"], 0)
        self.assertTrue(data["functions"])
        for fn in data["functions"]:
            self.assertIn("address", fn)
            self.assertIn("name", fn)
            self.assertIn("size", fn)
            # LoginCrackme.exe is a real x64 PE; a plausible function
            # address lands in the typical default PE base-address range,
            # never zero/negative/absurdly large.
            self.assertIsInstance(fn["address"], int)
            self.assertGreater(fn["address"], 0)
            self.assertLess(fn["address"], 0x7FFFFFFFFFFF)
        self.assertIn("analysis_wall_clock_seconds", data)
        self.assertGreaterEqual(data["analysis_wall_clock_seconds"], 0)

    def test_packed_binary_function_count_matches_the_known_real_measurement(self):
        # Real, previously-verified figure on this exact corpus binary
        # (see tools_rizin.py's module docstring / the worker report that
        # added this module): rizin reports 7 functions on the packed
        # elevenpack.exe, versus IDA's 1 and Ghidra's fabricated 366 --
        # this is the concrete evidence the module exists to preserve.
        if not ELEVENPACK.is_file():
            raise unittest.SkipTest("corpus fixture missing: " + str(ELEVENPACK))
        out = tr.rizin_functions(str(ELEVENPACK), timeout_seconds=60)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["function_count"], 7)

    def test_output_is_bounded_by_max_functions(self):
        out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=60, max_functions=2)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertLessEqual(len(data["functions"]), 2)
        if data["function_count"] > 2:
            self.assertTrue(data["truncated"])


class RizinTimeoutTests(unittest.TestCase):
    """The timeout path is exercised without depending on a real slow
    binary or wall-clock waiting: run_bounded_process's own timed_out
    signal is what tools_rizin.py branches on, so simulate it directly."""

    def test_timeout_result_from_run_bounded_process_becomes_timeout_status(self):
        fake_result = mock.Mock(timed_out=True, cancelled=False, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("tools_rizin.safe_path", return_value=LOGINCRACKME), \
             mock.patch("tools_rizin.run_bounded_process", return_value=fake_result):
            out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TIMEOUT")

    def test_cancellation_result_becomes_cancelled_status(self):
        fake_result = mock.Mock(timed_out=False, cancelled=True, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("tools_rizin.safe_path", return_value=LOGINCRACKME), \
             mock.patch("tools_rizin.run_bounded_process", return_value=fake_result):
            out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "CANCELLED")


class RizinMalformedOutputTests(unittest.TestCase):
    """rizin producing unparseable or non-JSON stdout must degrade to a
    structured status, never an unhandled exception."""

    def test_no_json_in_stdout_is_analysis_limited_not_a_crash(self):
        fake_result = mock.Mock(timed_out=False, cancelled=False, returncode=0,
                                 stdout="no brackets here", stderr="", output_truncated=False)
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("tools_rizin.safe_path", return_value=LOGINCRACKME), \
             mock.patch("tools_rizin.run_bounded_process", return_value=fake_result):
            out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")

    def test_malformed_json_array_is_result_parse_failed_not_a_crash(self):
        fake_result = mock.Mock(timed_out=False, cancelled=False, returncode=0,
                                 stdout="[{not valid json,,,]", stderr="", output_truncated=False)
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("tools_rizin.safe_path", return_value=LOGINCRACKME), \
             mock.patch("tools_rizin.run_bounded_process", return_value=fake_result):
            out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")

    def test_nonzero_exit_code_is_analysis_limited_not_a_crash(self):
        fake_result = mock.Mock(timed_out=False, cancelled=False, returncode=1,
                                 stdout="", stderr="rizin: cannot open file", output_truncated=False)
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"), \
             mock.patch("tools_rizin.safe_path", return_value=LOGINCRACKME), \
             mock.patch("tools_rizin.run_bounded_process", return_value=fake_result):
            out = tr.rizin_functions(str(LOGINCRACKME), timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")


class RizinNotFoundTests(unittest.TestCase):
    def test_nonexistent_path_returns_not_found(self):
        with mock.patch.object(tr, "_rizin_binary", return_value="C:/fake/rizin.exe"):
            out = tr.rizin_functions(str(REPO_ROOT / "benchmarks" / "does_not_exist_at_all.exe"))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool (Ghidra analyzeHeadless, IDA idat.exe, angr, unicorn,
# frida, or a Hyper-V guest) or spawns a bounded subprocess -- these can be slow or hang,
# so they are excluded from the default run and must be run explicitly with `pytest -m heavy`.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
