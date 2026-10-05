"""CLI wiring for four measured kernel operations: kerneldispatch, kerneliat, kernelcallbacks, ioctldecode.

Same contract as ``kerneltriage``: JSON on stdout, a ``command`` key added, refusal codes visible, exit 3 for
a structured refusal. Fixtures are built in code; no real driver is used. ``ioctldecode`` takes integers, not a
file, so it is registered with ``path=False``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
COMMANDS = ("kerneldispatch", "kerneliat", "kernelcallbacks", "ioctldecode")
FILE_COMMANDS = ("kerneldispatch", "kerneliat", "kernelcallbacks")
TEXT_RAW = 0x400
LEA_RAX = bytes.fromhex("488D05F9000000")
STORE_IDX14 = bytes.fromhex("488981E0000000")
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


def make(name, code=b""):
    path = build_owned_pe_sections(ROOT / name, subsystem=1,
                                   imports={"ntoskrnl.exe": ["IoCreateDevice", "PsSetCreateProcessNotifyRoutine"]})
    if code:
        data = bytearray(path.read_bytes())
        data[TEXT_RAW:TEXT_RAW + len(code)] = code
        path.write_bytes(bytes(data))
    return path


class RegistrationTests(unittest.TestCase):
    def test_commands_are_registered_and_in_help(self):
        parser = cli._build_parser()
        help_text = parser.format_help()
        for name in COMMANDS:
            self.assertIn(name, help_text, name)
        for name in FILE_COMMANDS:
            self.assertTrue(parser.parse_args([name, "x.sys"]).needs_file, name)
        self.assertFalse(parser.parse_args(["ioctldecode", "1"]).needs_file)
        self.assertEqual(parser.parse_args(["kerneliat", "x.sys"]).max_findings, 200)
        self.assertEqual(parser.parse_args(["kerneldispatch", "x.sys"]).max_bytes, 1024)


class RefusalTests(unittest.TestCase):
    def test_missing_file_is_a_visible_refusal_for_each_file_command(self):
        for name in FILE_COMMANDS:
            code, body = run(name, str(ROOT / "absent.sys"))
            self.assertEqual(code, 3, name)
            self.assertEqual((body["status"], body["error"]), ("PATH_REFUSED", "FILE_NOT_FOUND"), name)

    def test_invalid_pe_code_is_not_swallowed_for_each_file_command(self):
        path = ROOT / "notape.bin"
        path.write_bytes(b"this is plainly not a portable executable" * 8)
        for name in FILE_COMMANDS:
            code, body = run(name, str(path))
            self.assertNotEqual(code, 0, name)
            self.assertEqual(body["error"], "INVALID_PE", name)


class DispatchTests(unittest.TestCase):
    def test_candidates_never_prove_dispatch_through_the_cli(self):
        code, body = run("kerneldispatch", str(make("d.sys", LEA_RAX + STORE_IDX14)))
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"], body["outcome"]),
                         ("kerneldispatch", "driver_major_function_scan", "FOUND"))
        self.assertTrue(body["candidates"])
        self.assertTrue(all(c["proves_dispatch"] is False for c in body["candidates"]))
        self.assertIn(body["dispatch_table"], ("CANDIDATES_ONLY", "UNKNOWN"))
        self.assertIs(body["proves_dispatch"], False)

    def test_no_pattern_is_not_found_not_a_table(self):
        code, body = run("kerneldispatch", str(make("none.sys")))
        self.assertEqual(code, 0)
        self.assertNotEqual(body["outcome"], "FOUND")
        self.assertIs(body["proves_dispatch"], False)


class IatTests(unittest.TestCase):
    def test_success_carries_the_module_fields(self):
        code, body = run("kerneliat", str(make("i.sys")))
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"], body["ok"]), ("kerneliat", "rip_relative_iat_scan", True))
        self.assertIn("outcome", body)

    def test_max_findings_is_passed_through(self):
        code, body = run("kerneliat", str(make("i2.sys")), "--max-findings", "1")
        self.assertEqual(code, 0)
        self.assertTrue(body["ok"])


class CallbackTests(unittest.TestCase):
    def test_names_checked_survives_the_cli(self):
        code, body = run("kernelcallbacks", str(make("c.sys")))
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"]), ("kernelcallbacks", "kernel_callback_registrations"))
        self.assertGreater(body["names_checked"]["count"], 0)
        self.assertIn("names", body["names_checked"])
        self.assertIn(body["outcome"], ("FOUND", "NOT_FOUND", "UNKNOWN"))


class IoctlTests(unittest.TestCase):
    def test_function_is_canonical_not_the_raw_shifted_field(self):
        code, body = run("ioctldecode", "0x222000", "0x22E004")
        self.assertEqual(code, 0)
        self.assertEqual((body["command"], body["tool"]), ("ioctldecode", "ioctl_control_code_decode"))
        self.assertEqual([r["function"] for r in body["results"]], [2048, 2049])
        self.assertTrue(all(r["status"] == "DECODED" for r in body["results"]))

    def test_invalid_codes_keep_their_own_codes(self):
        code, body = run("ioctldecode", "abc", "-1", "0x100000000", "0x00000001")
        self.assertEqual(code, 0)
        self.assertEqual([r.get("error") for r in body["results"]],
                         ["NOT_AN_INTEGER", "NEGATIVE", "OUT_OF_RANGE_U32", None])

    def test_unknown_device_type_is_decoded_not_invalid(self):
        code, body = run("ioctldecode", "0x7FFF0000")
        self.assertEqual(code, 0)
        r = body["results"][0]
        self.assertEqual(r["status"], "DECODED")
        self.assertIs(r["device_type_known"], False)

    def test_no_codes_is_a_usage_error(self):
        with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as cm:
            cli.main(["ioctldecode"])
        self.assertEqual(cm.exception.code, 2)
