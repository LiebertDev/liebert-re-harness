"""pe_runtime_functions / pe_function_extent (liebert_re/tools/pe_unwind.py): the RUNTIME_FUNCTION
table read for exact function extent. Fixtures are built in code, no binary is committed.

Fixture layout (one .text section at RVA 0x1000, PE32+ amd64, exception directory = data directory 3):
  table at RVA 0x1200, four entries; unwind infos at RVA 0x1300..
    0x1000-0x1040  primary
    0x1040-0x1060  chained to 0x1000          (fragment)
    0x1080-0x10A0  chained to 0x1040          (fragment of a fragment, resolves to 0x1000)
    0x10C0-0x10E0  chained to 0x2000          (parent absent: UNKNOWN)
"""
from __future__ import annotations

import json
import struct
import tempfile
import sys
import unittest
from unittest import mock
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
from liebert_re.report import tool_families
from liebert_re.tools.pe_unwind import pe_function_extent, pe_runtime_functions
from tests._pe_fixtures import build_pe

_COFF_MACHINE = 64 + 4
_OPT = _COFF_MACHINE + 20
_EXC_DIR_ENTRY = _OPT + 112 + 3 * 8
TABLE_RVA = 0x1200
ENTRIES = [  # (begin, end, unwind rva)
    (0x1000, 0x1040, 0x1300),
    (0x1040, 0x1060, 0x1310),
    (0x1080, 0x10A0, 0x1330),
    (0x10C0, 0x10E0, 0x1350),
]
PRIMARY_INFO = bytes([0x01, 0, 0, 0])
CHAIN_FLAG = 0x01 | (0x4 << 3)


def _chained(parent_begin, parent_end):
    return bytes([CHAIN_FLAG, 0, 0, 0]) + struct.pack("<III", parent_begin, parent_end, 0x1300)


def _code(entries=ENTRIES, size=0x400):
    code = bytearray(size)
    for i, (b, e, u) in enumerate(entries):
        struct.pack_into("<III", code, TABLE_RVA - 0x1000 + 12 * i, b, e, u)
    if size != 0x400:
        return bytes(code)
    code[0x300:0x304] = PRIMARY_INFO
    code[0x310:0x320] = _chained(0x1000, 0x1040)
    code[0x330:0x340] = _chained(0x1040, 0x1060)
    code[0x350:0x360] = _chained(0x2000, 0x2040)
    return bytes(code)


def _build(dest: Path, *, dir_rva=TABLE_RVA, dir_size=12 * len(ENTRIES), machine=0x8664) -> Path:
    path = build_owned_pe_with_code(dest, _code())
    data = bytearray(path.read_bytes())
    struct.pack_into("<II", data, _EXC_DIR_ENTRY, dir_rva, dir_size)
    struct.pack_into("<H", data, _COFF_MACHINE, machine)
    path.write_bytes(bytes(data))
    return path


def _custom(dest: Path, entries, infos, *, dir_size=None, code_size=None) -> Path:
    """A PE whose table is ``entries`` and whose unwind infos are ``{rva: bytes}``."""
    code = bytearray(_code(entries, code_size or 0x400))
    for rva, blob in infos.items():
        code[rva - 0x1000:rva - 0x1000 + len(blob)] = blob
    path = build_owned_pe_with_code(dest, bytes(code))
    data = bytearray(path.read_bytes())
    struct.pack_into("<II", data, _EXC_DIR_ENTRY, TABLE_RVA, dir_size or 12 * len(entries))
    path.write_bytes(bytes(data))
    return path


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def table(self, path, **kw):
        return json.loads(pe_runtime_functions(str(path), **kw))

    def extent(self, path, address, kind="rva"):
        return json.loads(pe_function_extent(str(path), address, kind))


class TableTests(_Base):
    def test_readable_table_separates_primary_from_fragments(self):
        r = self.table(_build(self.dir / "a.exe"))
        self.assertEqual((r["ok"], r["status"], r["table_complete"]), (True, "OK", True))
        self.assertEqual(r["raw_entry_count"], 4)
        self.assertEqual(r["primary_function_count"], 1)
        self.assertEqual(r["chained_fragment_count"], 3)
        self.assertEqual(r["unresolved_fragment_count"], 1)
        kinds = [e["kind"] for e in r["entries"]]
        self.assertEqual(kinds, ["primary", "chained_fragment", "chained_fragment", "chained_fragment"])
        self.assertEqual(r["entries"][1]["primary_begin_rva"], "0x1000")
        self.assertEqual(r["entries"][2]["primary_begin_rva"], "0x1000")
        self.assertEqual(r["entries"][3]["primary_begin_rva"], "UNKNOWN")

    def test_leaf_ceiling_is_carried_in_every_answer(self):
        path = _build(self.dir / "c.exe")
        for r in (self.table(path), self.extent(path, "0x1010"), self.extent(path, "0x1100")):
            self.assertIs(r["coverage"]["complete"], False)
            self.assertIs(r["coverage"]["absence_is_evidence_of_no_function"], False)
            self.assertIn("leaf", r["coverage"]["ceiling"])

    def test_paging_reports_the_cut(self):
        r = self.table(_build(self.dir / "p.exe"), max_entries=2)
        self.assertEqual((r["entries_returned"], r["entries_truncated"], r["raw_entry_count"]), (2, True, 4))
        r = self.table(_build(self.dir / "p2.exe"), max_entries=2, offset=2)
        self.assertEqual((r["entries_returned"], r["entries_truncated"]), (2, False))

    def test_bad_paging_argument_is_refused_by_name(self):
        r = self.table(_build(self.dir / "q.exe"), max_entries="many")
        self.assertEqual((r["ok"], r["status"]), (False, "INVALID_ARGUMENT"))


class ExtentTests(_Base):
    def test_address_inside_a_primary_gets_exact_extent(self):
        r = self.extent(_build(self.dir / "e.exe"), "0x1010")
        self.assertEqual((r["ok"], r["status"], r["covered"], r["is_fragment"]), (True, "FUNCTION_FOUND", True, False))
        f = r["function"]
        self.assertEqual((f["begin_rva"], f["end_rva"], f["size"], f["offset_from_begin"]), ("0x1000", "0x1040", 0x40, 0x10))
        self.assertEqual(f["begin"]["rva"], "0x1000")  # AddressForm contract
        self.assertEqual(f["begin"]["section"], ".text")
        self.assertEqual(r["address"]["rva"], "0x1010")

    def test_end_is_exclusive(self):
        path = _build(self.dir / "x.exe")
        self.assertEqual(self.extent(path, "0x103f")["function"]["begin_rva"], "0x1000")
        self.assertEqual(self.extent(path, "0x1040")["function"]["begin_rva"], "0x1040")

    def test_va_and_file_offset_forms_agree_with_rva(self):
        path = _build(self.dir / "f.exe")
        by_va = self.extent(path, hex(0x140000000 + 0x1010), "va")
        by_off = self.extent(path, hex(0x200 + 0x10), "file_offset")
        self.assertEqual(by_va["function"]["begin_rva"], "0x1000")
        self.assertEqual(by_off["function"]["begin_rva"], "0x1000")

    def test_fragment_resolves_to_its_primary(self):
        r = self.extent(_build(self.dir / "g.exe"), "0x1090")
        self.assertEqual(r["status"], "FUNCTION_FOUND")
        self.assertTrue(r["is_fragment"])
        self.assertEqual(r["function"]["begin_rva"], "0x1080")
        self.assertEqual(r["primary"]["begin_rva"], "0x1000")
        self.assertEqual(r["primary"]["end_rva"], "0x1040")

    def test_fragment_with_absent_parent_says_unknown(self):
        r = self.extent(_build(self.dir / "h.exe"), "0x10D0")
        self.assertTrue(r["is_fragment"])
        self.assertEqual(r["primary"], "UNKNOWN")

    def test_uncovered_address_is_its_own_outcome_and_not_a_claim_about_code(self):
        r = self.extent(_build(self.dir / "u.exe"), "0x1100")
        self.assertEqual((r["ok"], r["status"], r["covered"], r["function"]), (True, "ADDRESS_NOT_COVERED", False, None))
        self.assertIn("not mean the address is not code", r["note"])

    def test_unmapped_address_is_unresolved_not_uncovered(self):
        r = self.extent(_build(self.dir / "v.exe"), "0x9000")
        self.assertEqual((r["ok"], r["status"]), (False, "ADDRESS_UNRESOLVED"))
        self.assertEqual(r["error"], "RVA_NOT_IN_ANY_SECTION")

    def test_overlapping_entries_are_ambiguous(self):
        path = build_owned_pe_with_code(self.dir / "o.exe", _code([(0x1000, 0x1040, 0x1300), (0x1020, 0x1060, 0x1300)]))
        data = bytearray(path.read_bytes())
        struct.pack_into("<II", data, _EXC_DIR_ENTRY, TABLE_RVA, 24)
        path.write_bytes(bytes(data))
        self.assertEqual(self.extent(path, "0x1030")["status"], "AMBIGUOUS_COVERAGE")


class ReviewRegressionTests(_Base):
    def test_unclassified_entry_is_unknown_not_primary(self):  # finding 1
        cases = {"ind.exe": (0x1301, {}), "ver.exe": (0x1300, {0x1300: bytes([0x03, 0, 0, 0])}),
                 "unr.exe": (0x9000, {})}
        for name, (unwind, infos) in cases.items():
            path = _custom(self.dir / name, [(0x1000, 0x1040, unwind)], infos)
            r = self.extent(path, "0x1010")
            self.assertEqual(r["status"], "FUNCTION_FOUND", name)
            self.assertIsNone(r["is_fragment"], name)
            self.assertEqual(r["classification"], "UNKNOWN", name)
            self.assertEqual(r["function"]["kind"], "unclassified", name)
            self.assertIn("UNKNOWN", r["note"], name)
            self.assertEqual((r["function"]["begin_rva"], r["function"]["end_rva"]), ("0x1000", "0x1040"), name)
            t = self.table(path)
            self.assertEqual((t["unclassified_entry_count"], t["primary_function_count"]), (1, 0), name)

    def test_known_classes_keep_a_real_boolean(self):  # finding 1
        path = _build(self.dir / "k.exe")
        a, b = self.extent(path, "0x1010"), self.extent(path, "0x1090")
        self.assertEqual((a["classification"], a["is_fragment"]), ("primary", False))
        self.assertEqual((b["classification"], b["is_fragment"]), ("chained_fragment", True))

    def test_duplicate_begin_is_told_apart_by_the_parent_end(self):  # finding 2
        # two entries begin at 0x1000; the chained record names (0x1000, 0x1040), which only one matches
        entries = [(0x1000, 0x1020, 0x1310), (0x1000, 0x1040, 0x1300), (0x1080, 0x10A0, 0x1320)]
        infos = {0x1300: PRIMARY_INFO, 0x1310: PRIMARY_INFO, 0x1320: _chained(0x1000, 0x1040)}
        r = self.extent(_custom(self.dir / "d1.exe", entries, infos), "0x1090")
        self.assertEqual(r["primary"]["end_rva"], "0x1040")
        self.assertEqual(r["function"]["primary_begin_rva"], "0x1000")

    def test_duplicate_begin_and_end_is_unknown_not_first_wins(self):  # finding 2
        entries = [(0x1000, 0x1040, 0x1300), (0x1000, 0x1040, 0x1300), (0x1080, 0x10A0, 0x1320)]
        infos = {0x1300: PRIMARY_INFO, 0x1320: _chained(0x1000, 0x1040)}
        path = _custom(self.dir / "d2.exe", entries, infos)
        r = self.extent(path, "0x1090")
        self.assertEqual(r["primary"], "UNKNOWN")
        self.assertIn("ambiguous", r["function"]["chain_note"])
        self.assertEqual(self.extent(path, "0x1010")["status"], "AMBIGUOUS_COVERAGE")

    def test_undefined_flag_bit_is_unclassified(self):  # finding 3
        for bit in (0x8, 0x10):
            info = bytes([0x01 | (bit << 3), 0, 0, 0])
            path = _custom(self.dir / f"fl{bit}.exe", [(0x1000, 0x1040, 0x1300)], {0x1300: info})
            r = self.extent(path, "0x1010")
            self.assertEqual((r["classification"], r["is_fragment"]), ("UNKNOWN", None), bit)
            self.assertIn("undefined flag", r["function"]["note"])
            self.assertEqual(r["function"]["end_rva"], "0x1040")
        for flags in (0x1, 0x2, 0x3):
            info = bytes([0x01 | (flags << 3), 0, 0, 0])
            path = _custom(self.dir / f"ok{flags}.exe", [(0x1000, 0x1040, 0x1300)], {0x1300: info})
            self.assertEqual(self.extent(path, "0x1010")["classification"], "primary", flags)

    def test_end_is_the_shared_address_shape_and_exact(self):  # finding 4
        path = _custom(self.dir / "end.exe", [(0x1000, 0x1040, 0x1300)], {0x1300: PRIMARY_INFO})
        r = self.extent(path, "0x103f")
        end = r["function"]["end_exclusive"]
        self.assertEqual(end["rva"], "0x1040")
        self.assertEqual(end["va"], hex(0x140000000 + 0x1040))
        self.assertEqual(end["file_offset"], hex(0x200 + 0x40))
        self.assertEqual(end["section"], ".text")
        self.assertIs(end["resolved"], True)
        self.assertEqual(set(end) - {"resolved"}, set(r["address"]))
        self.assertEqual(self.extent(path, "0x1040")["status"], "ADDRESS_NOT_COVERED")

    def test_unresolvable_end_keeps_the_shape_and_says_why(self):  # finding 4
        path = _custom(self.dir / "end2.exe", [(0x1000, 0x9000, 0x1300)], {0x1300: PRIMARY_INFO})
        end = self.extent(path, "0x1010")["function"]["end_exclusive"]
        self.assertEqual((end["resolved"], end["rva"]), (False, "0x9000"))
        self.assertEqual(end["error"], "RVA_NOT_IN_ANY_SECTION")

    def test_unresolved_address_carries_table_complete(self):  # finding 5
        r = self.extent(_build(self.dir / "uc.exe"), "0x9000")
        self.assertEqual((r["status"], r["table_complete"]), ("ADDRESS_UNRESOLVED", True))
        r = self.extent(_build(self.dir / "uc2.exe", dir_size=12 * 4 - 5), "0x9000")
        self.assertEqual((r["status"], r["table_complete"]), ("ADDRESS_UNRESOLVED", False))

    def test_truncated_miss_carries_table_complete_false(self):  # finding 5
        r = self.extent(_build(self.dir / "tm.exe", dir_size=12 * 4 - 5), "0x1100")
        self.assertEqual((r["status"], r["table_complete"]), ("TABLE_TRUNCATED", False))

    def test_every_failure_carries_coverage(self):  # finding 6
        path = _build(self.dir / "cv.exe")
        junk = self.dir / "junk.bin"
        junk.write_bytes(b"nope")
        results = [
            self.table(path, max_entries="bad"), self.table(path, offset="bad"),
            self.table(self.dir / "absent.exe"), self.table(junk),
            self.table(_build(self.dir / "cv2.exe", dir_rva=0, dir_size=0)),
            self.table(_build(self.dir / "cv3.exe", dir_rva=0x9000, dir_size=12)),
            self.extent(path, "0x9000"),
        ]
        for r in results:
            self.assertFalse(r["ok"], r)
            self.assertIs(r["coverage"]["absence_is_evidence_of_no_function"], False, r["status"])

    def test_invalid_offset_is_refused_by_name(self):
        r = self.table(_build(self.dir / "io.exe"), offset="x")
        self.assertEqual(r["status"], "INVALID_ARGUMENT")

    def test_chain_cycle_is_unknown(self):
        entries = [(0x1000, 0x1020, 0x1300), (0x1040, 0x1060, 0x1320)]
        infos = {0x1300: _chained(0x1040, 0x1060), 0x1320: _chained(0x1000, 0x1020)}
        r = self.extent(_custom(self.dir / "cy.exe", entries, infos), "0x1010")
        self.assertEqual(r["primary"], "UNKNOWN")
        self.assertEqual(r["function"]["chain_note"], "chain contains a cycle")

    def test_chain_depth_limit_is_reported(self):
        n = 70
        entries = [(0x2000 + 0x10 * i, 0x2008 + 0x10 * i, 0x1800 + 0x20 * i) for i in range(n)]
        infos = {}
        for i in range(n - 1):
            infos[0x1800 + 0x20 * i] = _chained(*entries[i + 1][:2])
        infos[0x1800 + 0x20 * (n - 1)] = PRIMARY_INFO
        path = _custom(self.dir / "deep.exe", entries, infos, code_size=0x2000)
        r = self.table(path)
        self.assertEqual(r["status"], "OK")
        first = r["entries"][0]
        self.assertEqual(first["primary_begin_rva"], "UNKNOWN")
        self.assertIn("deeper than", first["chain_note"])
        self.assertEqual(r["entries"][-2]["primary_begin_rva"], hex(entries[-1][0]))


class NoTableOutcomesTests(_Base):
    def test_missing_pefile_is_tool_missing(self):
        path = _build(self.dir / "tm.exe")
        with mock.patch.dict(sys.modules, {"pefile": None}):
            r = self.table(path)
        self.assertEqual((r["ok"], r["status"]), (False, "TOOL_MISSING"))

    def test_path_outside_the_workspace_is_refused(self):
        outside = Path(tempfile.gettempdir()).resolve() / "liebert_pe_unwind_outside.exe"
        r = self.table(outside)
        self.assertEqual((r["ok"], r["status"]), (False, "PATH_REFUSED"))

    def test_bad_optional_header_magic(self):
        path = _build(self.dir / "m.exe")
        data = bytearray(path.read_bytes())
        struct.pack_into("<H", data, _OPT, 0x107)
        path.write_bytes(bytes(data))
        r = self.table(path)
        self.assertEqual((r["ok"], r["status"]), (False, "UNSUPPORTED_OPTIONAL_HEADER"))

    def test_amd64_machine_with_pe32_magic_is_inconsistent(self):
        path = _build(self.dir / "inc.exe")
        data = bytearray(path.read_bytes())
        struct.pack_into("<H", data, _OPT, 0x10B)
        path.write_bytes(bytes(data))
        r = self.table(path)
        self.assertEqual((r["ok"], r["status"]), (False, "PE_HEADER_INCONSISTENT"))

    def test_no_exception_directory(self):
        path = _build(self.dir / "n.exe", dir_rva=0, dir_size=0)
        for r in (self.table(path), self.extent(path, "0x1010")):
            self.assertEqual((r["ok"], r["status"]), (False, "NO_EXCEPTION_DIRECTORY"))
            self.assertNotIn("entries", r)

    def test_x86_is_a_named_outcome_not_an_empty_success(self):
        path = self.dir / "x86.exe"
        path.write_bytes(build_pe(b"\xc3"))
        for r in (self.table(path), self.extent(path, "0x1000")):
            self.assertEqual((r["ok"], r["status"], r["machine"]), (False, "X86_NO_PDATA", "0x14c"))
            self.assertNotIn("entries", r)

    def test_other_machine_is_unsupported_not_read_as_x64(self):
        r = self.table(_build(self.dir / "arm.exe", machine=0xAA64))
        self.assertEqual((r["ok"], r["status"]), (False, "UNSUPPORTED_ARCHITECTURE"))

    def test_unreadable_table(self):
        r = self.table(_build(self.dir / "r.exe", dir_rva=0x9000, dir_size=12))
        self.assertEqual((r["ok"], r["status"]), (False, "TABLE_UNREADABLE"))

    def test_truncated_table_lists_what_it_read_but_is_not_ok(self):
        path = _build(self.dir / "t.exe", dir_size=12 * 4 - 5)
        r = self.table(path)
        self.assertEqual((r["ok"], r["status"], r["table_complete"], r["raw_entry_count"]), (False, "TABLE_TRUNCATED", False, 3))

    def test_truncated_table_cannot_prove_absence(self):
        path = _build(self.dir / "t2.exe", dir_size=12 * 4 - 5)
        self.assertEqual(self.extent(path, "0x1100")["status"], "TABLE_TRUNCATED")
        hit = self.extent(path, "0x1010")
        self.assertEqual((hit["status"], hit["table_complete"]), ("FUNCTION_FOUND", False))

    def test_table_running_past_the_section_is_truncated(self):
        r = self.table(_build(self.dir / "t3.exe", dir_rva=0x13F0, dir_size=0x100))
        self.assertEqual(r["status"], "TABLE_TRUNCATED")

    def test_non_pe(self):
        path = self.dir / "junk.bin"
        path.write_bytes(b"not a portable executable")
        for r in (self.table(path), self.extent(path, "0x1000")):
            self.assertEqual((r["ok"], r["status"]), (False, "NOT_A_PE"))

    def test_missing_file(self):
        r = self.table(self.dir / "absent.exe")
        self.assertEqual((r["ok"], r["status"]), (False, "NOT_FOUND"))

    def test_every_outcome_status_is_distinct(self):
        outcomes = {
            "OK": self.table(_build(self.dir / "1.exe"))["status"],
            "FOUND": self.extent(_build(self.dir / "2.exe"), "0x1010")["status"],
            "UNCOVERED": self.extent(_build(self.dir / "3.exe"), "0x1100")["status"],
            "NODIR": self.table(_build(self.dir / "4.exe", dir_rva=0, dir_size=0))["status"],
            "TRUNC": self.table(_build(self.dir / "5.exe", dir_size=7))["status"],
            "UNREAD": self.table(_build(self.dir / "6.exe", dir_rva=0x9000, dir_size=12))["status"],
        }
        self.assertEqual(len(set(outcomes.values())), len(outcomes), outcomes)


class RegistrationTests(unittest.TestCase):
    def test_published_in_both_families(self):
        for family in ("native", "windows-kernel"):
            published = tool_families.published_tools(family)
            self.assertIn("pe_runtime_functions", published, family)
            self.assertIn("pe_function_extent", published, family)

    def test_only_the_bare_path_operation_is_in_the_path_only_tier(self):
        self.assertIn("pe_runtime_functions", tool_families.NATIVE_PATH_ONLY_TOOLS)
        self.assertIn("pe_runtime_functions", tool_families.WINDOWS_KERNEL_PATH_ONLY_TOOLS)
        self.assertNotIn("pe_function_extent", tool_families.NATIVE_PATH_ONLY_TOOLS)
        self.assertNotIn("pe_function_extent", tool_families.WINDOWS_KERNEL_PATH_ONLY_TOOLS)
        self.assertIn("pe_function_extent", tool_families.NATIVE_COORDINATE_TOOLS)
        self.assertIn("pe_function_extent", tool_families.WINDOWS_KERNEL_COORDINATE_TOOLS)

    def test_bare_path_call_works(self):
        with tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE) as d:
            r = json.loads(pe_runtime_functions(str(_build(Path(d) / "b.exe"))))
        self.assertEqual(r["status"], "OK")


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out = StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_pdata_reaches_both_operations(self):
        with tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE) as d:
            path = str(_build(Path(d) / "c.exe"))
            code, body = self.run_cli("pdata", path)
            self.assertEqual((code, body["tool"], body["status"], body["command"]), (0, "pe_runtime_functions", "OK", "pdata"))
            code, body = self.run_cli("pdata", path, "--address", "0x1010", "--address-kind", "rva")
            self.assertEqual((code, body["tool"], body["status"]), (0, "pe_function_extent", "FUNCTION_FOUND"))
            code, body = self.run_cli("pdata", path, "--address", "0x9000", "--address-kind", "rva")
            self.assertNotEqual(code, 0)
            self.assertEqual(body["status"], "ADDRESS_UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
