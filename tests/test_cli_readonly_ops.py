"""CLI wiring for five read-only operations: kerneltriage, ghidrastatus, ghidrafacts, ghidradecompile, idaannotations.

Same contract as the existing ``ida`` commands: JSON on stdout, a ``command`` key added, refusals
visible as the module's own status/error and exit code 3 where the CLI maps them so. Nothing here
needs a real Ghidra or a real IDA: the Ghidra operations are replaced by canned module answers
(the real runs belong to tests/test_tools_ghidra.py's heavy tests), kernel_triage and
ida_annotations run for real because neither starts an engine.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools import ghidra

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
COMMANDS = ("kerneltriage", "ghidrastatus", "ghidrafacts", "ghidradecompile", "idaannotations")
_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def run(*argv):
    out = StringIO()
    with redirect_stdout(out):
        code = cli.main(list(argv))
    return code, json.loads(out.getvalue())


class RegistrationTests(unittest.TestCase):
    def test_commands_are_registered_and_in_help(self):
        parser = cli._build_parser()
        help_text = parser.format_help()
        for name in COMMANDS:
            self.assertIn(name, help_text, name)
        self.assertTrue(parser.parse_args(["kerneltriage", "x.sys"]).needs_file)
        self.assertFalse(parser.parse_args(["ghidrastatus"]).needs_file)
        self.assertEqual(parser.parse_args(["ghidrafacts", "x.exe", "--timeout", "9"]).timeout, 9)
        self.assertEqual(parser.parse_args(["idaannotations", "x.exe"]).max_results, 500)


class KernelTriageCliTests(unittest.TestCase):
    def test_success_carries_the_module_fields(self):
        path = build_owned_pe_sections(ROOT / "ok.sys", subsystem=1,
                                       imports={"ntoskrnl.exe": ["IoCreateDevice"]})
        code, body = run("kerneltriage", str(path))
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"], body["ok"]), ("kerneltriage", "kernel_triage", True))
        for key in ("pe", "indicators", "driver_likelihood", "rationale"):
            self.assertIn(key, body)
        self.assertTrue(all(i["proves_driver"] is False for i in body["indicators"]))

    def test_unknown_and_its_rationale_survive_the_cli(self):
        path = build_owned_pe_sections(ROOT / "plain.exe", subsystem=3,
                                       imports={"KERNEL32.dll": ["ExitProcess"]})
        code, body = run("kerneltriage", str(path))
        self.assertEqual(code, 0)
        self.assertEqual(body["driver_likelihood"], "UNKNOWN")
        self.assertTrue(body["rationale"])

    def test_missing_file_is_a_visible_refusal(self):
        code, body = run("kerneltriage", str(ROOT / "absent.sys"))
        self.assertEqual(code, 3)
        self.assertEqual((body["status"], body["error"]), ("PATH_REFUSED", "FILE_NOT_FOUND"))

    def test_invalid_pe_code_is_not_swallowed(self):
        path = ROOT / "notape.bin"
        path.write_bytes(b"this is plainly not a portable executable" * 8)
        code, body = run("kerneltriage", str(path))
        self.assertNotEqual(code, 0)
        self.assertEqual(body["error"], "INVALID_PE")


class GhidraStatusCliTests(unittest.TestCase):
    def test_answer_is_passed_through_with_command_key(self):
        canned = json.dumps({"ok": True, "tool": "ghidra_status", "status": "OK", "version": "0.0"})
        with mock.patch.object(ghidra, "ghidra_status", return_value=canned):
            code, body = run("ghidrastatus")
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"], body["version"]), ("ghidrastatus", "ghidra_status", "0.0"))

    def test_tool_missing_is_exit_3(self):
        canned = json.dumps({"ok": False, "tool": "ghidra_status", "status": "TOOL_MISSING"})
        with mock.patch.object(ghidra, "ghidra_status", return_value=canned):
            code, body = run("ghidrastatus")
        self.assertEqual((code, body["status"]), (3, "TOOL_MISSING"))


class GhidraFactsCliTests(unittest.TestCase):
    def test_success_and_timeout_is_passed_through(self):
        sample = ROOT / "g.exe"
        sample.write_bytes(b"MZ")
        canned = json.dumps({"ok": True, "tool": "ghidra_program_facts", "status": "OK", "source_unchanged": True})
        with mock.patch.object(ghidra, "ghidra_program_facts", return_value=canned) as fn:
            code, body = run("ghidrafacts", str(sample), "--timeout", "77")
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["source_unchanged"]), ("ghidrafacts", True))
        self.assertEqual(fn.call_args.kwargs["timeout_seconds"], 77)

    def test_missing_file_is_a_visible_refusal(self):
        code, body = run("ghidrafacts", str(ROOT / "absent.exe"))
        self.assertEqual((code, body["status"], body["error"]), (3, "PATH_REFUSED", "FILE_NOT_FOUND"))

    def test_module_refusal_status_is_not_swallowed(self):
        sample = ROOT / "h.exe"
        sample.write_bytes(b"MZ")
        for status in ("GHIDRA_LAUNCH_FAILED", "PROJECT_LOCKED"):
            canned = json.dumps({"ok": False, "tool": "ghidra_program_facts", "status": status})
            with mock.patch.object(ghidra, "ghidra_program_facts", return_value=canned):
                code, body = run("ghidrafacts", str(sample))
            self.assertEqual(body["status"], status)
            self.assertNotEqual(code, 0)


class GhidraDecompileCliTests(unittest.TestCase):
    def test_functions_and_timeouts_are_passed_through(self):
        sample = ROOT / "d.exe"
        sample.write_bytes(b"MZ")
        canned = json.dumps({"ok": True, "tool": "ghidra_decompile", "status": "OK", "source_unchanged": True,
                             "functions": []})
        with mock.patch.object(ghidra, "ghidra_decompile", return_value=canned) as fn:
            code, body = run("ghidradecompile", str(sample), "--function", "0x1000", "main",
                             "--function-timeout", "12", "--timeout", "99")
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"]), ("ghidradecompile", "ghidra_decompile"))
        self.assertEqual(fn.call_args.args[1], ["0x1000", "main"])
        self.assertEqual(fn.call_args.kwargs, {"per_function_timeout_seconds": 12, "timeout_seconds": 99})

    def test_defaults_leave_the_whole_run_bound_to_the_module(self):
        sample = ROOT / "e.exe"
        sample.write_bytes(b"MZ")
        canned = json.dumps({"ok": True, "tool": "ghidra_decompile", "status": "OK"})
        with mock.patch.object(ghidra, "ghidra_decompile", return_value=canned) as fn:
            run("ghidradecompile", str(sample), "--function", "main")
        self.assertEqual(fn.call_args.kwargs, {"per_function_timeout_seconds": 30, "timeout_seconds": None})

    def test_missing_file_is_a_visible_refusal(self):
        code, body = run("ghidradecompile", str(ROOT / "absent.exe"), "--function", "main")
        self.assertEqual((code, body["status"], body["error"]), (3, "PATH_REFUSED", "FILE_NOT_FOUND"))

    def test_a_request_the_module_refuses_is_a_usage_exit_not_a_run(self):
        sample = ROOT / "f.exe"
        sample.write_bytes(b"MZ")
        code, body = run("ghidradecompile", str(sample), "--function", *["0x1"] * 17)
        self.assertEqual((code, body["status"], body["error"]), (2, "TOOL_USAGE", "TOO_MANY_FUNCTIONS"))

    def test_partial_and_limited_answers_are_not_swallowed(self):
        sample = ROOT / "g2.exe"
        sample.write_bytes(b"MZ")
        for status, ok, expected_code in (("PARTIAL", True, 0), ("ANALYSIS_LIMITED", False, 3)):
            canned = json.dumps({"ok": ok, "tool": "ghidra_decompile", "status": status})
            with mock.patch.object(ghidra, "ghidra_decompile", return_value=canned):
                code, body = run("ghidradecompile", str(sample), "--function", "main")
            self.assertEqual((code, body["status"]), (expected_code, status))


class IdaAnnotationsCliTests(unittest.TestCase):
    def test_no_log_is_an_answer_with_no_engine_started(self):
        sample = ROOT / "a.exe"
        sample.write_bytes(b"MZ-cli-annotations-no-log")
        code, body = run("idaannotations", str(sample), "--max-results", "7")
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"], body["found"]), ("idaannotations", "ida_annotations", False))
        self.assertIs(body["engine_started"], False)
        self.assertEqual(body["invocation"]["max_results"], 7)

    def test_missing_file_is_a_visible_refusal(self):
        code, body = run("idaannotations", str(ROOT / "absent.exe"))
        self.assertEqual((code, body["status"], body["error"]), (3, "PATH_REFUSED", "FILE_NOT_FOUND"))


if __name__ == "__main__":
    unittest.main()
