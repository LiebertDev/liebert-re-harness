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


# --- tail-jump following: MSVC /GS entry points (GsDriverEntry -> cookie init -> jmp real DriverEntry) ------------
TEXT2_RAW = 0x600     # file offset of the second code section (RVA 0x2000)
TWO_CODE = ((".text", 0x60000020), (".text2", 0x60000020))
PROLOGUE = bytes.fromhex("4883EC28") + bytes.fromhex("E800000000") + bytes.fromhex("4883C428")   # sub/call/add: 13 bytes
STORE_IDX3_DISP8 = bytes.fromhex("48894178")          # mov [rcx+0x78], rax -> index 3 WRITE
LEA_RAX_2000 = bytes.fromhex("488D05F9000000")        # at RVA 0x2000 -> handler 0x2100 (in .text2)


def jmp32(at_rva, to_rva):
    return b"\xE9" + struct.pack("<i", to_rva - (at_rva + 5))


def jmp8(at_rva, to_rva):
    return b"\xEB" + struct.pack("<b", to_rva - (at_rva + 2))


def make2(name, patches, **kw):
    """Two code sections (.text at RVA 0x1000, .text2 at 0x2000); ``patches`` maps file offset -> bytes."""
    path = build_owned_pe_sections(ROOT / name, subsystem=1, sections=TWO_CODE,
                                   imports={"ntoskrnl.exe": ["IoCreateDevice"]}, **kw)
    data = bytearray(path.read_bytes())
    for off, code in patches.items():
        data[off:off + len(code)] = code
    path.write_bytes(bytes(data))
    return path


REAL_DRIVER_ENTRY = LEA_RAX_2000 + STORE_IDX0_DISP8 + STORE_IDX2_DISP32


class TailJumpTests(unittest.TestCase):
    def test_rel32_tail_jump_after_a_prologue_is_followed_and_reported(self):
        # entry: sub/call/add (13 bytes) then jmp rel32 into the second section, outside the scan window.
        body = scan(make2("gs.sys", {TEXT_RAW: PROLOGUE + jmp32(0x100D, 0x2000), TEXT2_RAW: REAL_DRIVER_ENTRY}))
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2})
        self.assertEqual(body["candidates"][0]["store_rva"], hex(0x2007))
        tj = body["tail_jump"]
        self.assertEqual(tj["state"], "FOLLOWED")
        self.assertEqual(len(tj["hops"]), 1)
        hop = tj["hops"][0]
        self.assertEqual((hop["from_rva"], hop["jump_rva"], hop["to_rva"], hop["encoding"]),
                         (hex(0x1000), hex(0x100D), hex(0x2000), "jmp_rel32"))
        self.assertEqual(body["entry"]["rva"], hex(0x1000))
        self.assertEqual(body["entry"]["scanned_rva"], hex(0x2000))
        self.assertIs(body["proves_dispatch"], False)
        for c in body["candidates"]:
            self.assertIs(c["proves_dispatch"], False)

    def test_two_hops_rel8_then_rel32_are_both_listed(self):
        patches = {TEXT_RAW: jmp8(0x1000, 0x1060), TEXT_RAW + 0x60: jmp32(0x1060, 0x2000),
                   TEXT2_RAW: REAL_DRIVER_ENTRY}
        body = scan(make2("two.sys", patches))
        self.assertEqual(body["outcome"], "FOUND")
        hops = body["tail_jump"]["hops"]
        self.assertEqual([(h["from_rva"], h["to_rva"], h["encoding"]) for h in hops],
                         [(hex(0x1000), hex(0x1060), "jmp_rel8"), (hex(0x1060), hex(0x2000), "jmp_rel32")])

    def test_unresolvable_targets_carry_their_own_code_not_not_found(self):
        cases = {
            "outside": ({TEXT_RAW: jmp32(0x1000, 0x9000)}, "TARGET_OUTSIDE_IMAGE"),
            "loop": ({TEXT_RAW: jmp32(0x1000, 0x1010), TEXT_RAW + 0x10: jmp32(0x1010, 0x1000)}, "JUMP_LOOP"),
        }
        for name, (patches, reason) in cases.items():
            with self.subTest(name):
                body = scan(make2(name + ".sys", patches))
                self.assertTrue(body["ok"])
                self.assertEqual(body["outcome"], "TAIL_JUMP_UNRESOLVED")
                self.assertNotEqual(body["outcome"], "NOT_FOUND")
                self.assertEqual(body["candidates"], [])
                self.assertEqual(body["dispatch_table"], "UNKNOWN")
                self.assertEqual(body["tail_jump"]["state"], "UNRESOLVED")
                self.assertEqual(body["tail_jump"]["reason"], reason)
                self.assertIs(body["proves_dispatch"], False)
        # ...while a window with neither a jump nor a store stays a plain NOT_FOUND.
        plain = scan(make2("plain.sys", {TEXT_RAW: PROLOGUE}))
        self.assertEqual(plain["outcome"], "NOT_FOUND")
        self.assertEqual(plain["tail_jump"]["state"], "NONE")

    def test_indirect_jump_through_an_import_slot_is_named_not_guessed(self):
        import pefile
        path = make2("ind.sys", {})
        pe = pefile.PE(str(path))
        slot_va = pe.DIRECTORY_ENTRY_IMPORT[0].imports[0].address
        rva = slot_va - pe.OPTIONAL_HEADER.ImageBase
        pe.close()
        data = bytearray(path.read_bytes())
        code = b"\xFF\x25" + struct.pack("<i", rva - (0x1000 + 6))
        data[TEXT_RAW:TEXT_RAW + len(code)] = code
        path.write_bytes(bytes(data))
        body = scan(path)
        self.assertEqual(body["outcome"], "TAIL_JUMP_UNRESOLVED")
        self.assertEqual(body["tail_jump"]["reason"], "INDIRECT_TARGET_IS_IMPORT")
        self.assertEqual(body["tail_jump"]["import"], "ntoskrnl.exe!IoCreateDevice")
        self.assertEqual(body["candidates"], [])

    def test_indirect_jump_through_a_plain_data_slot_is_unresolved(self):
        # A slot in .text2 holding some value: what it holds at run time is not knowable statically.
        code = b"\xFF\x25" + struct.pack("<i", 0x2000 - (0x1000 + 6))
        body = scan(make2("slot.sys", {TEXT_RAW: code, TEXT2_RAW: struct.pack("<Q", 0x140002100)}))
        self.assertEqual(body["outcome"], "TAIL_JUMP_UNRESOLVED")
        self.assertEqual(body["tail_jump"]["reason"], "INDIRECT_TARGET_NOT_STATIC")

    def test_chain_limit_is_three_hops(self):
        def chain(n):
            patches = {TEXT2_RAW: REAL_DRIVER_ENTRY}
            stops = [0x1000 + 0x20 * k for k in range(n)] + [0x2000]
            for a, b in zip(stops, stops[1:]):
                patches[TEXT_RAW + (a - 0x1000)] = jmp32(a, b) if b == 0x2000 else jmp8(a, b)
            return patches
        ok = scan(make2("c3.sys", chain(3)))
        self.assertEqual(ok["outcome"], "FOUND")
        self.assertEqual(len(ok["tail_jump"]["hops"]), 3)
        over = scan(make2("c4.sys", chain(4)))
        self.assertEqual(over["outcome"], "TAIL_JUMP_UNRESOLVED")
        self.assertEqual(over["tail_jump"]["reason"], "CHAIN_LIMIT")
        self.assertEqual(len(over["tail_jump"]["hops"]), 3)

    def test_driver_without_a_jump_is_scanned_where_it_always_was(self):
        # Narrowness guard: stores sit directly at the entry point. Over-eager following would move the scan.
        body = scan(make2("direct.sys", {TEXT_RAW: LEA_RAX + STORE_IDX0_DISP8 + STORE_IDX2_DISP32}))
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual(body["tail_jump"]["state"], "NONE")
        self.assertEqual(body["tail_jump"]["hops"], [])
        self.assertEqual(body["entry"]["scanned_rva"], body["entry"]["rva"])
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2})

    def test_stores_at_the_entry_point_win_over_a_later_jump(self):
        # Direct stores AND a later jmp whose target holds other stores: the entry's own stores are the answer.
        patches = {TEXT_RAW: LEA_RAX + STORE_IDX0_DISP8 + jmp32(0x100B, 0x2000),
                   TEXT2_RAW: LEA_RAX_2000 + STORE_IDX3_DISP8}
        body = scan(make2("both.sys", patches))
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0})
        self.assertEqual(body["tail_jump"]["state"], "NONE")

    def test_an_e9_byte_inside_an_operand_is_not_followed_as_a_jump(self):
        # False-positive direction: a jump-looking byte that is really part of a mov immediate, with a garbage
        # target. Following it would report stores from somewhere that is not code; the scan must leave it alone.
        cases = {
            "e9": bytes.fromhex("B8E900009000"),   # mov eax, imm32 whose bytes read as jmp rel32 -> 0x901006
            "eb": bytes.fromhex("B8EB80000000"),   # ...and as jmp rel8 -0x80 -> before the image
        }
        for name, code in cases.items():
            with self.subTest(name):
                body = scan(make2("fake_" + name + ".sys", {TEXT_RAW: code, TEXT2_RAW: REAL_DRIVER_ENTRY}))
                self.assertEqual(body["outcome"], "NOT_FOUND")
                self.assertEqual(body["tail_jump"]["state"], "NONE")
                self.assertEqual(body["tail_jump"]["hops"], [])
                self.assertEqual(body["candidates"], [])
                self.assertEqual(body["entry"]["scanned_rva"], body["entry"]["rva"])

    def test_bytes_inside_a_call_operand_are_not_mistaken_for_a_jump(self):
        # E8 <E9 FA 0F 00> 00: read from the operand's first byte, that is jmp rel32 to 0x2000, a real code
        # section holding stores. The call operand must be skipped, so nothing is followed.
        code = bytes.fromhex("E8E9FA0F0000")
        body = scan(make2("callop.sys", {TEXT_RAW: code, TEXT2_RAW: REAL_DRIVER_ENTRY}))
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["tail_jump"]["state"], "NONE")
        self.assertEqual(body["candidates"], [])


def call32(at_rva, to_rva):
    return bytes.fromhex("E8") + struct.pack("<i", to_rva - (at_rva + 5))


def trampoline(at_rva, cookie_rva, body_rva):
    """The compiler's DriverEntry shape: save args, call cookie-init, call the real body, return. No jmp."""
    return (bytes.fromhex("48895C2408") + bytes.fromhex("57") + bytes.fromhex("4883EC20")
            + bytes.fromhex("488BDA") + bytes.fromhex("488BF9")
            + call32(at_rva + 16, cookie_rva)
            + bytes.fromhex("488BD3") + bytes.fromhex("488BCF")
            + call32(at_rva + 27, body_rva)
            + bytes.fromhex("488B5C2430") + bytes.fromhex("4883C420") + bytes.fromhex("5F") + bytes.fromhex("C3"))


class CallTrampolineTests(unittest.TestCase):
    def _set_entry(self, path, rva):
        data = bytearray(path.read_bytes())
        struct.pack_into("<I", data, ENTRY_FIELD, rva)
        path.write_bytes(bytes(data))

    def test_call_to_a_body_BEHIND_the_entry_is_followed(self):
        # entry at 0x2000 (.text2): cookie call (empty stub at 0x2080), then a call BACK to 0x1000 holding the stores.
        path = make2("back.sys", {TEXT2_RAW: trampoline(0x2000, 0x2080, 0x1000),
                                  TEXT_RAW: LEA_RAX + STORE_IDX0_DISP8 + STORE_IDX2_DISP32})
        self._set_entry(path, 0x2000)
        body = scan(path)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2})
        hops = body["tail_jump"]["hops"]
        self.assertEqual(body["tail_jump"]["state"], "FOLLOWED")
        self.assertEqual([(h["from_rva"], h["to_rva"], h["encoding"], h["kind"], h["direction"]) for h in hops],
                         [(hex(0x2000), hex(0x1000), "call_rel32", "call", "backward")])
        self.assertEqual(body["entry"]["scanned_rva"], hex(0x1000))

    def test_call_to_a_body_far_ahead_of_the_window_is_followed(self):
        # entry 0x1000; cookie stub 0x1040; body at 0x2000, well past the 1024-byte window.
        body = scan(make2("far.sys", {TEXT_RAW: trampoline(0x1000, 0x1040, 0x2000), TEXT2_RAW: REAL_DRIVER_ENTRY}))
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0, 2})
        hops = body["tail_jump"]["hops"]
        self.assertEqual([(h["to_rva"], h["direction"], h["calls_seen"]) for h in hops],
                         [(hex(0x2000), "forward", 2)])

    def test_the_cookie_call_is_not_listed_as_a_hop_when_the_body_call_has_the_stores(self):
        body = scan(make2("cookie.sys", {TEXT_RAW: trampoline(0x1000, 0x1040, 0x2000), TEXT2_RAW: REAL_DRIVER_ENTRY}))
        self.assertNotIn(hex(0x1040), [h["to_rva"] for h in body["tail_jump"]["hops"]])

    def test_stores_at_the_entry_point_win_over_a_call(self):
        # Narrowness guard: direct stores AND a later call into a section with other stores. Calls are not followed.
        patches = {TEXT_RAW: LEA_RAX + STORE_IDX0_DISP8 + call32(0x100B, 0x2000),
                   TEXT2_RAW: LEA_RAX_2000 + STORE_IDX3_DISP8}
        body = scan(make2("callboth.sys", patches))
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({c["index"] for c in body["candidates"]}, {0})
        self.assertEqual(body["tail_jump"]["state"], "NONE")
        self.assertEqual(body["tail_jump"]["hops"], [])

    def test_a_call_whose_target_shows_no_store_is_not_followed(self):
        # A self-call and a call into an empty stub: nothing to find, so NOT_FOUND (read, nothing matched), no hops.
        for name, code in {"self": call32(0x1000, 0x1000), "stub": call32(0x1000, 0x1040)}.items():
            with self.subTest(name):
                body = scan(make2("nostore_" + name + ".sys", {TEXT_RAW: code}))
                self.assertEqual(body["outcome"], "NOT_FOUND")
                self.assertEqual(body["tail_jump"]["hops"], [])

    def test_a_call_after_a_full_jump_chain_is_the_chain_limit_not_not_found(self):
        # Three jmp hops reach 0x10C0, which calls a body holding stores: the hop budget is spent, so UNRESOLVED.
        patches = {TEXT_RAW: jmp8(0x1000, 0x1040), TEXT_RAW + 0x40: jmp8(0x1040, 0x1080),
                   TEXT_RAW + 0x80: jmp8(0x1080, 0x10C0), TEXT_RAW + 0xC0: call32(0x10C0, 0x2000),
                   TEXT2_RAW: REAL_DRIVER_ENTRY}
        body = scan(make2("callafterchain.sys", patches))
        self.assertEqual(body["outcome"], "TAIL_JUMP_UNRESOLVED")
        self.assertEqual(body["tail_jump"]["reason"], "CHAIN_LIMIT")
        self.assertEqual(len(body["tail_jump"]["hops"]), 3)
        self.assertEqual(body["tail_jump"]["blocked_jump"]["encoding"], "call_rel32")

    def test_a_call_to_outside_the_code_sections_is_not_followed(self):
        body = scan(make2("callout.sys", {TEXT_RAW: call32(0x1000, 0x7000)}))
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["tail_jump"]["hops"], [])


if __name__ == "__main__":
    unittest.main()
