"""disassemble_pe_structured (liebert_re/tools/binary.py): the numeric facts the text listing throws away.

The text listing (disassemble_pe) keeps only "0xADDR: mnemonic op_str". Capstone with detail on also knows
the instruction length, its bytes, the resolved target of a direct call/jmp, every immediate as a number
and the displacement of a RIP-relative operand. This operation returns them in the per-instruction shape
rizin_disasm_listing already defines (address form, bytes, mnemonic, operands, length, decode_status,
optional branch_target), plus two additive keys: ``immediates`` and ``rip_relative``.

Fixtures are built in code (owned_binary_fixtures); no real driver is read. Expected numbers are worked
out by hand from the encoded bytes, never taken from the function under test.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.tools.binary as binary
import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.recover.pe_address import resolve_address_form
from liebert_re.tools.binary import disassemble_pe, disassemble_pe_structured

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
TEXT_RAW = 0x400
RDATA_RVA = 0x2000
IOCTL = 0x22000004

# .text, offset: bytes                                  meaning
#  0: E8 <rel32>          call  .text+0x20             5 bytes, target = 0+5+0x1B = 0x20
#  5: B9 04 00 00 22      mov   ecx, 0x22000004        5 bytes
# 10: 81 F9 04 00 00 22   cmp   ecx, 0x22000004        6 bytes
# 16: FF 15 <disp32>      call  [rip+disp] -> .rdata   6 bytes, disp = 0x2000 - (0x1000+22) = 0xFEA
# 22: F0 90               lock-prefixed nop: F0 is undecodable (a skipdata .byte), 90 decodes
# 24: C3                  ret
CALL_REL = 0x1B
DISP = RDATA_RVA - (TEXT_RVA + 22)
CODE = (b"\xE8" + struct.pack("<i", CALL_REL) + b"\xB9" + struct.pack("<I", IOCTL)
        + b"\x81\xF9" + struct.pack("<I", IOCTL) + b"\xFF\x15" + struct.pack("<i", DISP)
        + b"\xF0\x90" + b"\xC3")

_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def make(name, code=CODE, **kw):
    path = build_owned_pe_sections(ROOT / name, subsystem=1, imports={"ntoskrnl.exe": ["IoCreateDevice"]}, **kw)
    data = bytearray(path.read_bytes())
    data[TEXT_RAW:TEXT_RAW + len(code)] = code
    path.write_bytes(bytes(data))
    return path


class StructuredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = make("s.exe")
        cls.res = disassemble_pe_structured(str(cls.path))
        cls.ins = cls.res["instructions"]

    def test_result_is_a_dict_and_ok(self):
        self.assertIsInstance(self.res, dict)
        self.assertTrue(self.res["ok"])
        self.assertEqual(self.res["status"], "ANALYSIS_LIMITED")
        # the fixture's 0x200-byte .text keeps decoding zero padding past our code, so the default
        # cap of 250 cuts it: that is the cap working, and it must say so.
        self.assertTrue(self.res["truncated"])

    def test_entries_carry_the_rizin_contract_fields(self):
        for e in self.ins:
            for key in ("address", "bytes", "mnemonic", "operands", "length", "decode_status"):
                self.assertIn(key, e)
        first = self.ins[0]
        self.assertEqual(first["mnemonic"], "call")
        self.assertEqual(first["length"], 5)
        self.assertEqual(first["bytes"], "e81b000000")
        self.assertEqual(first["decode_status"], "DECODED")
        self.assertEqual(set(first["address"]), {"file_offset", "rva", "va", "image_base", "section"})
        self.assertEqual(first["address"]["va"], hex(IMAGE_BASE + TEXT_RVA))

    def test_address_form_equals_the_shared_resolver(self):
        for e in self.ins:
            want, err = resolve_address_form(self.path, e["address"]["va"], "va")
            self.assertIsNone(err)
            self.assertEqual(e["address"], want.to_dict())

    def test_operands_text_is_the_unchanged_op_str(self):
        self.assertEqual(self.ins[1]["operands"], "ecx, 0x22000004")
        self.assertEqual(self.ins[3]["operands"], "qword ptr [rip + 0xfea]")

    def test_direct_call_target_is_numeric_and_correct(self):
        # address + size + rel32, worked by hand: 0x140001000 + 5 + 0x1B = 0x140001020
        target = self.ins[0]["branch_target"]
        self.assertEqual(target["va"], hex(IMAGE_BASE + TEXT_RVA + 5 + CALL_REL))
        self.assertEqual(target["rva"], hex(TEXT_RVA + 0x20))
        self.assertEqual(target["section"], ".text")

    def test_immediate_is_numeric_ioctl_like_value(self):
        for idx in (1, 2):
            imms = self.ins[idx]["immediates"]
            self.assertEqual([i["value"] for i in imms], [IOCTL])
            self.assertEqual(imms[0]["hex"], "0x22000004")
        self.assertEqual(self.ins[2]["mnemonic"], "cmp")

    def test_rip_relative_disp_and_target(self):
        rr = self.ins[3]["rip_relative"]
        self.assertEqual(len(rr), 1)
        self.assertEqual(rr[0]["disp"], DISP)
        # address + size + disp = 0x140001010 + 6 + 0xFEA = 0x140002000 (.rdata)
        self.assertEqual(rr[0]["target"]["va"], hex(IMAGE_BASE + RDATA_RVA))
        self.assertEqual(rr[0]["target"]["section"], ".rdata")
        self.assertNotIn("branch_target", self.ins[3])  # indirect: no direct target is claimed

    def test_undecodable_byte_is_marked_and_real_instruction_is_not(self):
        by_mn = {e["mnemonic"]: e for e in self.ins}
        self.assertEqual(by_mn[".byte"]["decode_status"], "UNDECODABLE")
        self.assertEqual(by_mn[".byte"]["length"], 1)
        self.assertEqual(by_mn["nop"]["decode_status"], "DECODED")
        self.assertEqual(by_mn["ret"]["decode_status"], "DECODED")
        # the legitimate decoded instructions must not all be flagged
        decoded = [e for e in self.ins if e["decode_status"] == "DECODED"]
        self.assertEqual(len(decoded), len(self.ins) - 1)
        self.assertEqual(self.res["decode_coverage"]["instructions_undecodable"], 1)

    def test_text_and_structured_listings_agree(self):
        text = disassemble_pe(str(self.path)).splitlines()[:-1]  # last line is the cap marker
        self.assertEqual(len(text), len(self.ins))
        for line, e in zip(text, self.ins):
            self.assertTrue(line.startswith(f"0x{int(e['address']['va'], 16):X}: {e['mnemonic']}"))


class SignedValueTests(unittest.TestCase):
    """Values whose op_str spelling is not a plain hex literal: what a text parser gets wrong."""

    def test_negative_immediate_and_negative_rip_disp(self):
        # 0: 83 F8 FF           cmp eax, -1     (imm -1, 4-byte operand -> 0xffffffff)
        # 3: 48 8D 05 F0FFFFFF  lea rax,[rip-10]  7 bytes, target = 0x140001003 + 7 - 10 = 0x140001000
        path = make("n.exe", code=b"\x83\xF8\xFF" + b"\x48\x8D\x05" + struct.pack("<i", -10) + b"\xC3")
        ins = disassemble_pe_structured(str(path), max_instructions=3)["instructions"]
        self.assertEqual(ins[0]["operands"], "eax, -1")
        self.assertEqual(ins[0]["immediates"], [{"value": -1, "hex": "0xffffffff", "size": 4}])
        rr = ins[1]["rip_relative"][0]
        self.assertEqual(rr["disp"], -10)
        self.assertEqual(rr["target"]["va"], hex(IMAGE_BASE + TEXT_RVA))


class TruncationTests(unittest.TestCase):
    def test_truncation_is_reported_as_fields(self):
        path = make("t.exe")
        res = disassemble_pe_structured(str(path), max_instructions=2)
        self.assertEqual(len(res["instructions"]), 2)
        self.assertTrue(res["truncated"])
        self.assertEqual(res["status"], "ANALYSIS_LIMITED")
        self.assertEqual(res["truncation"]["max_instructions"], 2)
        self.assertEqual(res["truncation"]["more_at"]["va"], hex(IMAGE_BASE + TEXT_RVA + 10))

    def test_cap_equal_to_listing_is_not_marked(self):
        path = make("t2.exe")
        n = len(disassemble_pe_structured(str(path), max_instructions=10000)["instructions"])
        res = disassemble_pe_structured(str(path), max_instructions=n)
        self.assertFalse(res["truncated"])
        self.assertNotIn("truncation", res)

    def test_truncation_survives_a_chunk_seam(self):
        path = make("t3.exe")
        with mock.patch.object(binary, "_DISASM_CHUNK_BYTES", 7):
            res = disassemble_pe_structured(str(path), max_instructions=3)
        self.assertTrue(res["truncated"])
        self.assertEqual(len(res["instructions"]), 3)


class TextPathUnchangedTests(unittest.TestCase):
    def test_text_listing_is_byte_for_byte(self):
        path = make("u.exe")
        want = "\n".join([
            "0x140001000: call 0x140001020",
            "0x140001005: mov ecx, 0x22000004",
            "0x14000100A: cmp ecx, 0x22000004",
            "0x140001010: call qword ptr [rip + 0xfea]",
            "0x140001016: .byte 0xf0",
            "0x140001017: nop",
            "0x140001018: ret",
        ])
        got = disassemble_pe(str(path))
        self.assertTrue(got.startswith(want), got)

    def test_text_path_never_enables_detail(self):
        path = make("u2.exe")
        seen = []
        from liebert_re.recover import code_sweep_chunking as csc
        orig = csc.disasm_chunk

        def spy(md, *a, **k):
            seen.append(md.detail)
            return orig(md, *a, **k)

        with mock.patch.object(csc, "disasm_chunk", spy):
            disassemble_pe(str(path))
            disassemble_pe_structured(str(path))
        self.assertEqual(seen, [False, True])


class RefusalTests(unittest.TestCase):
    def test_invalid_pe_keeps_its_code(self):
        bad = ROOT / "bad.exe"
        bad.write_bytes(b"not a pe")
        res = disassemble_pe_structured(str(bad))
        self.assertEqual((res["ok"], res["error"]), (False, "INVALID_PE"))

    def test_va_and_section_codes_are_kept(self):
        path = make("r.exe")
        self.assertEqual(disassemble_pe_structured(str(path), va="0x1")["error"], "VA_NOT_IN_SECTION")
        self.assertEqual(disassemble_pe_structured(str(path), va="zz")["error"], "INVALID_VA")
        self.assertEqual(disassemble_pe_structured(str(path), section=".nope")["error"], "SECTION_NOT_FOUND")

    def test_unsupported_machine_keeps_its_code(self):
        path = make("m.exe")
        data = bytearray(path.read_bytes())
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        struct.pack_into("<H", data, pe_off + 4, 0x1C0)  # ARM (32-bit), not handled by either path
        path.write_bytes(bytes(data))
        self.assertEqual(disassemble_pe_structured(str(path))["error"], "UNSUPPORTED_MACHINE")

    def test_arm64_is_refused_explicitly_not_given_an_x86_shape(self):
        path = make("a.exe")
        data = bytearray(path.read_bytes())
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        struct.pack_into("<H", data, pe_off + 4, 0xAA64)
        path.write_bytes(bytes(data))
        res = disassemble_pe_structured(str(path))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "STRUCTURED_UNSUPPORTED_MACHINE")
        self.assertEqual(res["status"], "UNSUPPORTED")
        self.assertNotIn("instructions", res)
        # the text path for ARM64 is untouched (a listing, not a refusal)
        self.assertIsInstance(disassemble_pe(str(path)), str)


class SectionAndVaTests(unittest.TestCase):
    def test_va_selects_the_start(self):
        path = make("v.exe")
        res = disassemble_pe_structured(str(path), va=hex(IMAGE_BASE + TEXT_RVA + 10))
        self.assertEqual(res["instructions"][0]["mnemonic"], "cmp")


if __name__ == "__main__":
    unittest.main()
