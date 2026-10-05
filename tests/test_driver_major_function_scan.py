"""driver_major_function_scan (liebert_re/tools/binary.py): a byte-pattern first pass, no disassembler.

Three outcomes are kept apart and never share a code: FOUND (candidate stores, every one with
proves_dispatch false), NOT_FOUND (looked, pattern absent -- a result, not an error), NOT_LOOKED
(could not read the PE / entry point / export table -- ok false with its own error code).
Fixtures are built in code; no real driver is read.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools.binary import driver_major_function_scan

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
TEXT_RAW = 0x400   # file offset of .text in the fixture (RVA 0x1000, entry point RVA 0x1000)
ENTRY_FIELD = 88 + 16   # AddressOfEntryPoint inside the fixture's optional header
_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


# x86-64 code: lea rax,[rip+0xF9] (handler RVA 0x1100); then stores into "rcx" and other registers.
LEA_RAX = bytes.fromhex("488D05F9000000")
STORE_IDX0_DISP8 = bytes.fromhex("48894170")          # mov [rcx+0x70], rax        -> index 0  CREATE
STORE_IDX2_DISP32 = bytes.fromhex("48898180000000")   # mov [rcx+0x80], rax        -> index 2  CLOSE
STORE_IDX14_DISP32 = bytes.fromhex("488981E0000000")  # mov [rcx+0xE0], rax        -> index 14 DEVICE_CONTROL
STORE_IDX14_R8_RDX = bytes.fromhex("4C8982E0000000")  # mov [rdx+0xE0], r8         -> index 14, other registers


def make(name, code=None, **kw):
    path = build_owned_pe_sections(ROOT / name, subsystem=1, imports={"ntoskrnl.exe": ["IoCreateDevice"]}, **kw)
    if code is not None:
        data = bytearray(path.read_bytes())
        data[TEXT_RAW:TEXT_RAW + len(code)] = code
        path.write_bytes(bytes(data))
    return path


def scan(path):
    return json.loads(driver_major_function_scan(str(path)))


class DriverMajorFunctionScanTests(unittest.TestCase):
    def test_pattern_present_yields_candidates_that_never_prove_dispatch(self):
        body = scan(make("hit.sys", LEA_RAX + STORE_IDX0_DISP8 + STORE_IDX2_DISP32 + STORE_IDX14_DISP32))
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2, 14})
        for c in body["candidates"]:
            self.assertIs(c["proves_dispatch"], False)
            self.assertIn(c["confidence"], ("heuristic", "heuristic_weak"))
        self.assertTrue(body["rationale"])

    def test_varied_encodings_are_all_found(self):
        # Different registers and a disp8/disp32 mix: a pattern that demanded one exact byte sequence
        # (rcx/rax, disp32) would miss most of this. This is the narrowness guard.
        code = LEA_RAX + STORE_IDX0_DISP8 + STORE_IDX14_R8_RDX + STORE_IDX2_DISP32
        body = scan(make("varied.sys", code))
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2, 14})

    def test_no_pattern_is_not_found_and_not_an_error(self):
        body = scan(make("miss.sys"))   # a single ret
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "OK")
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["candidates"], [])
        self.assertTrue(body["rationale"])
        self.assertNotIn("error", body)

    def test_invalid_pe_is_refused_with_its_own_code(self):
        bad = ROOT / "bad.sys"
        bad.write_bytes(b"this is not a PE file at all")
        body = scan(bad)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "INVALID_PE")
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertNotEqual(body["outcome"], "NOT_FOUND")

    def test_entry_point_outside_every_section_is_not_looked(self):
        path = make("noentry.sys", LEA_RAX + STORE_IDX0_DISP8)
        data = bytearray(path.read_bytes())
        struct.pack_into("<I", data, ENTRY_FIELD, 0x7F000)
        path.write_bytes(bytes(data))
        body = scan(path)
        self.assertFalse(body["ok"])
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertEqual(body["error"], "ENTRY_POINT_NOT_IN_SECTION")
        self.assertNotEqual(body["outcome"], "NOT_FOUND")
        self.assertNotIn("candidates", body)

    def test_entry_point_bytes_missing_from_the_file_is_not_looked(self):
        path = make("cut.sys", LEA_RAX + STORE_IDX0_DISP8)
        path.write_bytes(path.read_bytes()[:TEXT_RAW])   # headers only: section data is gone
        body = scan(path)
        self.assertFalse(body["ok"])
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertEqual(body["error"], "ENTRY_POINT_UNREADABLE")

    def test_not_looked_and_not_found_never_share_a_code(self):
        found_none = scan(make("n1.sys"))
        refused = scan(ROOT / "does_not_exist.sys")
        self.assertNotEqual(found_none["outcome"], refused["outcome"])
        self.assertEqual(refused["error"], "FILE_NOT_FOUND")   # missing file: a refusal, never the NOT_FOUND outcome
        self.assertEqual(refused["outcome"], "NOT_LOOKED")

    def test_device_control_index_is_named(self):
        body = scan(make("dc.sys", LEA_RAX + STORE_IDX14_DISP32))
        (c,) = body["candidates"]
        self.assertEqual((c["index"], c["name"]), (14, "IRP_MJ_DEVICE_CONTROL"))
        self.assertEqual(c["handler_rva"], "0x1100")   # paired with the preceding lea
        self.assertEqual(c["confidence"], "heuristic")

    def test_store_without_a_lea_is_weaker_and_has_no_handler(self):
        body = scan(make("nolea.sys", STORE_IDX14_DISP32))
        (c,) = body["candidates"]
        self.assertEqual(c["confidence"], "heuristic_weak")
        self.assertIsNone(c["handler_rva"])

    def test_index_table_is_the_public_one(self):
        from liebert_re.tools.binary import _IRP_MJ_NAMES
        self.assertEqual((_IRP_MJ_NAMES[0], _IRP_MJ_NAMES[2], _IRP_MJ_NAMES[14], _IRP_MJ_NAMES[27]),
                         ("IRP_MJ_CREATE", "IRP_MJ_CLOSE", "IRP_MJ_DEVICE_CONTROL", "IRP_MJ_PNP"))
        self.assertEqual(len(_IRP_MJ_NAMES), 28)

    def test_nothing_claims_certainty_anywhere(self):
        body = scan(make("cert.sys", LEA_RAX + STORE_IDX0_DISP8 + STORE_IDX14_DISP32))
        self.assertIs(body["proves_dispatch"], False)
        self.assertNotEqual(body["dispatch_table"], "RECOVERED")
        self.assertTrue(all(i["proves_driver"] is False for i in body["indicators"]))

    def test_unsupported_machine_is_refused(self):
        body = scan(make("arm.sys", machine=0xAA64))
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "UNSUPPORTED_MACHINE")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_x86_store_uses_the_32_bit_layout(self):
        # mov [eax+0x38], ecx -> index 0 in the 32-bit DRIVER_OBJECT (MajorFunction at +0x38, stride 4)
        body = scan(make("x86.sys", bytes.fromhex("894838"), machine=0x14C))
        self.assertEqual([c["index"] for c in body["candidates"]], [0])


if __name__ == "__main__":
    unittest.main()
