"""ioctl_candidate_scan (liebert_re/tools/binary.py): the feeder for ioctl_control_code_decode.

The decoder splits a CTL_CODE integer; nothing produced one. This operation scans a code region from a
start address, collects the immediates that are compared (cmp reg/mem, imm and sub reg, imm chains) and
hands each to ioctl_control_code_decode. It never says "the driver's IOCTLs are": it reports immediates
compared in the scanned region, the patterns that were and were not searched, and ``proves_ioctl`` false.

Fixtures are built in code (owned_binary_fixtures). Every expected number is worked out by hand from the
encoded bytes and from CTL_CODE = (device<<16)|(access<<14)|(function<<2)|method, never taken from the
function under test.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools.binary import ioctl_candidate_scan, ioctl_control_code_decode

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
TEXT_RVA = 0x1000
TEXT_RAW = 0x400

# (bytes, text). Offsets are the running sum of the lengths, worked out by the test, not by the scanner.
INSNS = [
    (b"\x48\x83\xEC\x20", "sub rsp, 0x20"),                         # noise: stack frame
    (b"\x83\x7B\x38\x01", "cmp dword ptr [rbx + 0x38], 1"),         # noise: small constant
    (b"\x83\xF9\x20", "cmp ecx, 0x20"),                             # noise: small constant
    (b"\x83\xF9\xFF", "cmp ecx, -1"),                               # noise: all-ones sentinel
    (b"\x81\xF9\x00\x20\x22\x00", "cmp ecx, 0x222000"),             # CANDIDATE cmp reg, imm
    (b"\x74\x00", "je"),
    (b"\x81\x7C\x24\x20\x04\x20\x22\x00", "cmp dword ptr [rsp + 0x20], 0x222004"),  # CANDIDATE cmp mem, imm
    (b"\x74\x00", "je"),
    (b"\x8B\x42\x18", "mov eax, dword ptr [rdx + 0x18]"),           # starts a fresh chain
    (b"\x2D\x08\x20\x22\x00", "sub eax, 0x222008"),                 # CANDIDATE sub, chain = 0x222008
    (b"\x74\x00", "je"),
    (b"\x83\xE8\x04", "sub eax, 4"),                                # CANDIDATE sub, chain = 0x222008 + 4
    (b"\x74\x00", "je"),
    (b"\x83\xF8\x10", "cmp eax, 0x10"),                             # CANDIDATE cmp after chain = 0x22200C + 0x10
    (b"\x74\x00", "je"),
    (b"\xC3", "ret"),
    (b"\x8B\x0A", "mov ecx, dword ptr [rdx]"),
    (b"\x83\xE9\x04", "sub ecx, 4"),                                # noise: small, fresh chain
]
CODE = b"".join(b for b, _ in INSNS)
OFFSETS = []
_o = 0
for _b, _t in INSNS:
    OFFSETS.append(_o)
    _o += len(_b)
OFF = {t: OFFSETS[i] for i, (_b, t) in enumerate(INSNS) if t != "je"}

V_CMP_REG = 0x222000      # device 0x22, access 0, function 0x800, method 0
V_CMP_MEM = 0x222004      # function 0x801
V_SUB_1 = 0x222008        # function 0x802
V_SUB_2 = 0x22200C        # function 0x803  (0x222008 + 4)
V_CMP_CHAIN = 0x22201C    # function 0x807  (0x22200C + 0x10)

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


def scan(path, **kw):
    kw.setdefault("start_rva", TEXT_RVA)
    kw.setdefault("max_instructions", len(INSNS))
    return json.loads(ioctl_candidate_scan(str(path), **kw))


def by_value(res):
    out = {}
    for c in res["candidates"]:
        out.setdefault(c["value"], []).append(c)
    return out


# Two "functions" in one region: a compare, a ret, then a DIFFERENT function's compare. Worked out by hand.
FN_INSNS = [
    (b"\x81\xF9\x00\x20\x22\x00", "cmp ecx, 0x222000"),   # function one: candidate, before any ret
    (b"\x74\x00", "je"),
    (b"\xC3", "ret"),                                     # first function ends here
    (b"\x83\xF9\x20", "cmp ecx, 0x20"),                   # function two: excluded (small), after the ret
    (b"\x81\xFA\x00\x40\x22\x00", "cmp edx, 0x224000"),   # function two: candidate, after the ret
    (b"\x74\x00", "je"),
    (b"\xC3", "ret"),                                     # second ret
]
FN_CODE = b"".join(b for b, _ in FN_INSNS)
FN_RET_1 = TEXT_RVA + 6 + 2          # 6-byte cmp + 2-byte je
FN_RET_2 = FN_RET_1 + 1 + 3 + 6 + 2  # ret, cmp ecx imm8, cmp edx imm32, je
FN_CAND_2 = FN_RET_1 + 1 + 3
FN_EXCL = FN_RET_1 + 1


def fn_scan(name, code, n):
    return scan(make(name, code=code), max_instructions=n)


class ReturnBoundaryTests(unittest.TestCase):
    """A linear scan walks past a ret into whatever follows; the output must say so, not stop silently."""

    @classmethod
    def setUpClass(cls):
        cls.res = fn_scan("fn.sys", FN_CODE, len(FN_INSNS))
        cls.by = {c["value"]: c for c in cls.res["candidates"]}

    def test_candidate_before_any_ret_has_rets_before_zero(self):
        c = self.by[0x222000]
        self.assertEqual(c["rets_before"], 0)
        self.assertFalse(c["may_be_in_another_function"])

    def test_candidate_after_a_ret_has_rets_before_at_least_one(self):
        c = self.by[0x224000]
        self.assertEqual(c["address"]["rva"], hex(FN_CAND_2))
        self.assertGreaterEqual(c["rets_before"], 1)
        self.assertEqual(c["rets_before"], 1)
        self.assertTrue(c["may_be_in_another_function"])
        self.assertIn("another function", c["boundary_note"])

    def test_scope_carries_the_ret_addresses_and_count(self):
        r = self.res["scope"]["rets_passed"]
        self.assertEqual(r["count"], 2)
        self.assertEqual([x["rva"] for x in r["listed"]], [hex(FN_RET_1), hex(FN_RET_2)])
        self.assertFalse(r["listed_truncated"])

    def test_excluded_records_carry_the_same_information(self):
        (x,) = self.res["excluded"]["listed"]
        self.assertEqual(x["address"]["rva"], hex(FN_EXCL))
        self.assertEqual(x["rets_before"], 1)
        self.assertEqual(x["after_ret_at"]["rva"], hex(FN_RET_1))

    def test_candidate_after_ret_names_which_ret(self):
        self.assertEqual(self.by[0x224000]["after_ret_at"]["rva"], hex(FN_RET_1))
        self.assertIsNone(self.by[0x222000]["after_ret_at"])

    def test_no_ret_gives_empty_list_and_zero(self):
        res = fn_scan("nr.sys", FN_CODE[:8], 2)
        r = res["scope"]["rets_passed"]
        self.assertEqual(r["count"], 0)
        self.assertEqual(r["listed"], [])
        self.assertEqual(res["candidates"][0]["rets_before"], 0)

    def test_ret_is_not_a_stop_and_the_candidate_set_is_unchanged(self):
        self.assertEqual(sorted(self.by), [0x222000, 0x224000])

    def test_scope_declares_int3_and_padding_not_searched_as_boundary_signals(self):
        txt = " ".join(self.res["scope"]["patterns_not_searched"])
        self.assertIn("int3", txt)

    def test_ret_list_is_capped_and_says_so(self):
        n = 60
        res = fn_scan("many.sys", b"\xC3" * n, n)
        r = res["scope"]["rets_passed"]
        self.assertEqual(r["count"], n)
        self.assertEqual(len(r["listed"]), r["limit"])
        self.assertTrue(r["listed_truncated"])


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = make("c.sys")
        cls.res = scan(cls.path, max_instructions=5000, start_note="unit test, hand-written offset")

    def test_contract_fields(self):
        r = self.res
        self.assertTrue(r["ok"])
        self.assertEqual(r["tool"], "ioctl_candidate_scan")
        self.assertIs(r["proves_ioctl"], False)
        for key in ("scope", "admission", "candidates", "excluded", "rationale", "statement", "outcome"):
            self.assertIn(key, r)

    def test_scope_declares_start_origin_count_and_patterns(self):
        s = self.res["scope"]
        self.assertEqual(s["start"]["rva"], hex(TEXT_RVA))
        self.assertEqual(s["start"]["source"], "caller_supplied")
        self.assertEqual(s["start"]["note"], "unit test, hand-written offset")
        self.assertGreaterEqual(s["instructions_scanned"], len(INSNS))
        self.assertIs(s["truncated"], False)
        self.assertEqual(s["ended_at"], "section_end")
        searched = " ".join(s["patterns_searched"])
        for needle in ("cmp reg, imm", "cmp [mem], imm", "sub reg, imm"):
            self.assertIn(needle, searched)
        not_searched = " ".join(s["patterns_not_searched"])
        for needle in ("mov reg, imm", "lea", "jump-table", "cmp reg, reg"):
            self.assertIn(needle, not_searched)

    def test_no_boolean_is_an_ioctl_field_anywhere(self):
        text = json.dumps(self.res)
        for forbidden in ('"is_ioctl"', '"looks_like_ioctl"', '"plausible"', '"is_plausible"', '"likely_ioctl"'):
            self.assertNotIn(forbidden, text)
        for c in self.res["candidates"]:
            self.assertIs(c["proves_ioctl"], False)

    def test_statement_does_not_claim_the_drivers_ioctls(self):
        st = self.res["statement"].lower()
        self.assertIn("compared", st)
        self.assertIn("not", st)
        self.assertNotIn("the driver's ioctls are", st)

    def test_entry_point_is_a_recorded_source_when_no_start_is_given(self):
        res = json.loads(ioctl_candidate_scan(str(self.path), max_instructions=10))
        self.assertEqual(res["scope"]["start"]["source"], "AddressOfEntryPoint")
        self.assertIsNone(res["scope"]["start"]["note"])


class PatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = make("p.sys")
        cls.res = scan(cls.path)
        cls.vals = by_value(cls.res)

    def test_cmp_reg_imm_is_found_with_the_right_value_and_site(self):
        (c,) = self.vals[V_CMP_REG]
        self.assertEqual(c["pattern"], "cmp_reg_imm")
        self.assertEqual(c["value_hex"], "0x00222000")
        self.assertEqual(c["address"]["rva"], hex(TEXT_RVA + OFF["cmp ecx, 0x222000"]))
        self.assertEqual(c["mnemonic"], "cmp")
        self.assertIn("0x222000", c["operands"])

    def test_cmp_mem_imm_is_found(self):
        (c,) = self.vals[V_CMP_MEM]
        self.assertEqual(c["pattern"], "cmp_mem_imm")
        self.assertEqual(c["address"]["rva"], hex(TEXT_RVA + OFF["cmp dword ptr [rsp + 0x20], 0x222004"]))

    def test_sub_chain_is_found_with_cumulative_values(self):
        (a,) = self.vals[V_SUB_1]
        (b,) = self.vals[V_SUB_2]
        self.assertEqual((a["pattern"], b["pattern"]), ("sub_reg_imm", "sub_reg_imm"))
        self.assertEqual(a["address"]["rva"], hex(TEXT_RVA + OFF["sub eax, 0x222008"]))
        self.assertEqual(b["address"]["rva"], hex(TEXT_RVA + OFF["sub eax, 4"]))
        self.assertEqual(a["compared_immediate"], "0x222008")
        self.assertEqual(b["compared_immediate"], "0x4")
        self.assertEqual(b["basis"], "sub_chain_cumulative")
        self.assertEqual([x["subtracted"] for x in b["chain"]], ["0x222008", "0x4"])

    def test_cmp_after_a_sub_chain_reports_the_reconstructed_value_not_the_raw_immediate(self):
        (c,) = self.vals[V_CMP_CHAIN]
        self.assertEqual(c["pattern"], "cmp_reg_imm")
        self.assertEqual(c["basis"], "sub_chain_cumulative")
        self.assertEqual(c["compared_immediate"], "0x10")
        self.assertNotIn(0x10, self.vals)

    def test_exactly_the_five_expected_candidates(self):
        self.assertEqual(sorted(self.vals), sorted([V_CMP_REG, V_CMP_MEM, V_SUB_1, V_SUB_2, V_CMP_CHAIN]))
        self.assertEqual(len(self.res["candidates"]), 5)


class DecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = scan(make("d.sys"))
        cls.vals = by_value(cls.res)

    def test_decoded_equals_the_existing_decoder_for_the_same_input(self):
        for value, (c,) in self.vals.items():
            direct = json.loads(ioctl_control_code_decode([value]))["results"][0]
            self.assertEqual(c["decoded"], direct)

    def test_function_is_the_canonical_twelve_bit_field(self):
        # 0x222000 = device 0x22 << 16 | function 0x800 << 2 -> function 2048, bits 2-13 (mask 0xFFF)
        self.assertEqual(self.vals[0x222000][0]["decoded"]["function"], 2048)
        self.assertEqual(self.vals[0x222004][0]["decoded"]["function"], 2049)
        self.assertEqual(self.vals[V_CMP_CHAIN][0]["decoded"]["function"], 0x807)
        self.assertEqual(self.vals[0x222000][0]["decoded"]["device_type"], 0x22)

    def test_criteria_are_named_and_not_a_verdict(self):
        c = self.vals[0x222000][0]
        names = [x["name"] for x in c["criteria"]]
        self.assertEqual(names, ["device_type_in_known_table", "reserved_bit_clear"])
        self.assertEqual((c["criteria_met"], c["criteria_total"]), (2, 2))
        self.assertTrue(all("basis" in x for x in c["criteria"]))

    def test_candidates_are_ordered_by_criteria_then_address(self):
        keys = [(-c["criteria_met"], int(c["address"]["rva"], 16)) for c in self.res["candidates"]]
        self.assertEqual(keys, sorted(keys))


class NoiseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = scan(make("n.sys"))
        cls.vals = by_value(cls.res)

    def test_small_values_stack_pointer_and_all_ones_are_not_candidates(self):
        for noise in (0x20, 0x1, 0x4, 0xFFFFFFFF):
            self.assertNotIn(noise, self.vals)

    def test_they_are_counted_and_listed_with_a_reason_not_dropped_silently(self):
        ex = self.res["excluded"]
        self.assertGreaterEqual(ex["count"], 5)
        reasons = ex["reasons"]
        self.assertGreaterEqual(reasons["below_0x10000_no_device_type"], 3)
        self.assertEqual(reasons["stack_pointer_register"], 1)
        self.assertEqual(reasons["all_ones_sentinel"], 1)
        self.assertTrue(all("reason" in e and "address" in e for e in ex["listed"]))

    def test_admission_rule_is_declared(self):
        self.assertIn("0x10000", json.dumps(self.res["admission"]))


class OutcomeTests(unittest.TestCase):
    def test_truncated_with_nothing_found_is_unknown_not_not_found(self):
        path = make("t.sys", code=INSNS[0][0] + INSNS[1][0] + INSNS[2][0] + b"\x90" * 64)
        res = scan(path, max_instructions=5)
        self.assertEqual(res["candidates"], [])
        self.assertIs(res["scope"]["truncated"], True)
        self.assertEqual(res["outcome"], "UNKNOWN")
        self.assertNotEqual(res["outcome"], "NOT_FOUND")
        self.assertIn("more_at", res["scope"])

    def test_truncated_with_candidates_says_so(self):
        res = scan(make("t2.sys"), max_instructions=6)
        self.assertEqual(res["outcome"], "FOUND")
        self.assertIs(res["scope"]["truncated"], True)
        self.assertEqual(res["status"], "ANALYSIS_LIMITED")

    def test_not_found_names_the_patterns_it_covers_and_denies_the_inference(self):
        path = make("nf.sys", code=INSNS[0][0] + INSNS[1][0] + b"\xC3\x90")
        res = scan(path, max_instructions=5000)
        self.assertEqual(res["candidates"], [])
        self.assertIs(res["scope"]["truncated"], False)
        self.assertEqual(res["outcome"], "NOT_FOUND")
        text = " ".join(res["rationale"])
        for needle in ("cmp reg, imm", "cmp [mem], imm", "sub reg, imm"):
            self.assertIn(needle, text)
        self.assertIn("does not show", text)
        self.assertIn("no IOCTL", text)

    def test_undecodable_bytes_with_nothing_found_are_unknown(self):
        res = scan(make("u.sys", code=b"\x06" + INSNS[1][0] + b"\xC3\x90"), max_instructions=5000)
        self.assertEqual(res["candidates"], [])
        self.assertIs(res["scope"]["truncated"], False)
        self.assertGreaterEqual(res["scope"]["instructions_undecodable"], 1)
        self.assertEqual(res["outcome"], "UNKNOWN")

    def test_found_has_no_not_found_text(self):
        res = scan(make("f.sys"))
        self.assertEqual(res["outcome"], "FOUND")


class RefusalTests(unittest.TestCase):
    def test_invalid_pe(self):
        bad = ROOT / "bad.sys"
        bad.write_bytes(b"not a pe")
        res = json.loads(ioctl_candidate_scan(str(bad), start_rva=0x1000))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "INVALID_PE")
        self.assertNotIn("candidates", res)

    def test_start_outside_every_section(self):
        res = json.loads(ioctl_candidate_scan(str(make("o.sys")), start_rva=0x90000))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "VA_NOT_IN_SECTION")

    def test_arm64_is_refused(self):
        path = make("a.sys")
        data = bytearray(path.read_bytes())
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        struct.pack_into("<H", data, pe_off + 4, 0xAA64)
        path.write_bytes(bytes(data))
        res = json.loads(ioctl_candidate_scan(str(path), start_rva=0x1000))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "STRUCTURED_UNSUPPORTED_MACHINE")

    def test_bad_start_value(self):
        res = json.loads(ioctl_candidate_scan(str(make("b.sys")), start_rva="zz"))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "INVALID_START_RVA")


if __name__ == "__main__":
    unittest.main()
