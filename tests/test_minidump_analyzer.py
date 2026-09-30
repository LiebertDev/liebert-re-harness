"""Hermetic tests for minidump_analyzer: read_memory_at_va, module lookup,
crash symbolization, and the heuristic stack scan."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import tool_families
import tools_workspace
from minidump_analyzer import _module_containing_address, analyze_minidump, minidump_analyzer
from minidump_structural import read_memory_at_va
from msf_pdb import write_synthetic_pdb

# NOTE: intentionally NOT importing helpers from tests.test_codeview_rsds via
# `from tests.test_codeview_rsds import ...`. In this environment a stray
# `tests/__init__.py` shipped by the speakeasy_emulator package in
# .venv/lib/site-packages shadows this project's own `tests/` package for
# any cross-file `from tests.<module> import ...` statement (confirmed via
# `ModuleNotFoundError: No module named 'tests.test_codeview_rsds'`, which
# also breaks the pre-existing tests/test_msf_pdb_p1.py and others the same
# way). That is a pre-existing environment issue unrelated to this feature,
# so the small GUID/RSDS/PE fixture helpers this file needs are inlined here
# instead of imported, keeping this test file runnable on its own.

GUID_LE = struct.pack("<IHH", 0x8F11D2A0, 0x41B7, 0x4B0D) + bytes.fromhex("9E42112233445566")
AGE = 7


def build_rsds(guid: bytes = GUID_LE, age: int = AGE, pdb: bytes = b"fixture.pdb\0") -> bytes:
    return b"RSDS" + guid + struct.pack("<I", age) + pdb


def build_pe_with_rsds(path: Path, rsds: bytes) -> None:
    """Minimal PE32+ with one CodeView debug directory pointing at an RSDS
    blob and a `.rdata` section at VA 0x1000 (segment 1), matching the
    layout used elsewhere in this repo's test fixtures."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)

    pe_sig = b"PE\0\0"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<Q", optional, 24, 0x140000000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 1)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into("<II", optional, 160, 0x1200, 28)

    section = bytearray(40)
    section[0:6] = b".rdata"
    struct.pack_into("<IIIIIIHHI", section, 8, 0x400, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x40000040)

    headers = bytes(dos) + pe_sig + coff + bytes(optional) + bytes(section)
    file_data = bytearray(0x200 + 0x400)
    file_data[:len(headers)] = headers

    debug_file_off = 0x400
    rsds_file_off = 0x420
    struct.pack_into("<IIHHIIII", file_data, debug_file_off, 0, 0, 0, 0, 2, len(rsds), 0x1220, rsds_file_off)
    file_data[rsds_file_off:rsds_file_off + len(rsds)] = rsds
    path.write_bytes(bytes(file_data))


MODULE_BASE = 0x140000000
MODULE_IMAGE_SIZE = 0x5000
MODULE_NAME = r"C:\owned\owned_fixture.sys"
THREAD_ID = 111
STACK_START = 0x7FFE1000
PLANTED_CANDIDATE_VA = MODULE_BASE + 0x1200  # -> OwnedHelper (rva 0x1200)
EXCEPTION_ADDRESS = MODULE_BASE + 0x1000  # -> OwnedEntry (rva 0x1000)


def _utf16(value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def build_full_minidump(
    path: Path,
    *,
    rsds: bytes,
    module_base: int = MODULE_BASE,
    module_image_size: int = MODULE_IMAGE_SIZE,
    module_name: str = MODULE_NAME,
    exception_address: int = EXCEPTION_ADDRESS,
    stack_start: int = STACK_START,
    stack_qwords: list[int] | None = None,
    thread_id: int = THREAD_ID,
) -> Path:
    """Minimal synthetic minidump with SystemInfo, ModuleList, ThreadList,
    Exception, and MemoryList streams -- matching minidump_structural.py's
    exact byte layout. The thread's stack VA range is backed by real captured
    bytes in the MemoryListStream so read_memory_at_va can find them."""
    if stack_qwords is None:
        stack_qwords = [0x1111111111111111, PLANTED_CANDIDATE_VA, 0xFFFFF80000000000, 0x0]

    directory_rva = 32
    stream_count = 5
    payload_rva = directory_rva + stream_count * 12

    system = bytearray(56)
    struct.pack_into("<HHHBBIIIII", system, 0, 9, 6, 0x3A09, 4, 1, 10, 0, 22631, 2, 0)
    system_rva = payload_rva

    module = bytearray(4 + 108)
    struct.pack_into("<I", module, 0, 1)
    module_rva = system_rva + len(system)

    module_name_bytes = _utf16(module_name)
    name_rva = module_rva + len(module)
    cv_rva = name_rva + len(module_name_bytes)
    struct.pack_into("<QIIII", module, 4, module_base, module_image_size, 0, 0, name_rva)
    struct.pack_into("<II", module, 4 + 76, len(rsds), cv_rva)

    thread = bytearray(4 + 48)
    struct.pack_into("<I", thread, 0, 1)
    thread_rva = cv_rva + len(rsds)

    stack_bytes = b"".join(struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF) for v in stack_qwords)

    exception = bytearray(168)
    exception_rva = thread_rva + len(thread)

    memlist = bytearray(4 + 16)
    memlist_rva = exception_rva + len(exception)
    stack_data_rva = memlist_rva + len(memlist)

    struct.pack_into("<IIIIQ", thread, 4, thread_id, 0, 0, 0, 0)
    struct.pack_into("<QII", thread, 4 + 24, stack_start, len(stack_bytes), stack_data_rva)
    struct.pack_into("<II", thread, 4 + 40, 0, 0)

    struct.pack_into("<I", exception, 0, thread_id)
    struct.pack_into("<II", exception, 8, 0xC0000005, 0)
    struct.pack_into("<QQ", exception, 16, 0, exception_address)
    struct.pack_into("<I", exception, 32, 0)
    struct.pack_into("<II", exception, 160, 0, 0)

    struct.pack_into("<I", memlist, 0, 1)
    struct.pack_into("<QII", memlist, 4, stack_start, len(stack_bytes), stack_data_rva)

    body = (
        bytes(system) + bytes(module) + module_name_bytes + rsds
        + bytes(thread) + bytes(exception) + bytes(memlist) + stack_bytes
    )
    directory = (
        struct.pack("<III", 7, len(system), system_rva)
        + struct.pack("<III", 4, len(module), module_rva)
        + struct.pack("<III", 3, len(thread), thread_rva)
        + struct.pack("<III", 6, len(exception), exception_rva)
        + struct.pack("<III", 5, len(memlist), memlist_rva)
    )
    header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, stream_count, directory_rva, 0, 1700000000, 0)
    data = header + directory + body
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class ReadMemoryAtVaTests(unittest.TestCase):
    def test_finds_captured_memory_and_returns_bytes(self):
        rsds = build_rsds(guid=GUID_LE, age=AGE, pdb=b"owned.pdb\0")
        with tempfile.TemporaryDirectory() as temp:
            dump = build_full_minidump(Path(temp) / "owned.mdmp", rsds=rsds)
            # stack_qwords[1] (planted candidate) lives at stack offset 8,
            # i.e. captured VA STACK_START + 8.
            hit = read_memory_at_va(dump, STACK_START + 8, 8)
        self.assertTrue(hit["ok"])
        self.assertEqual(hit["status"], "CAPTURED")
        self.assertEqual(hit["source_stream"], "MemoryListStream")
        value = struct.unpack("<Q", bytes.fromhex(hit["data_hex"]))[0]
        self.assertEqual(value, PLANTED_CANDIDATE_VA)

    def test_returns_not_captured_outside_any_range(self):
        rsds = build_rsds(guid=GUID_LE, age=AGE, pdb=b"owned.pdb\0")
        with tempfile.TemporaryDirectory() as temp:
            dump = build_full_minidump(Path(temp) / "owned.mdmp", rsds=rsds)
            miss = read_memory_at_va(dump, 0x9999999999, 8)
        self.assertFalse(miss["ok"])
        self.assertEqual(miss["status"], "NOT_CAPTURED")


class ModuleContainingAddressTests(unittest.TestCase):
    modules = [{"name": r"C:\owned\owned_fixture.sys", "base_address": "0x140000000", "image_size": 0x5000}]

    def test_finds_module_for_address_inside_range(self):
        hit = _module_containing_address(self.modules, 0x140000000 + 0x1234)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["name"], r"C:\owned\owned_fixture.sys")
        self.assertEqual(hit["rva"], 0x1234)

    def test_returns_none_outside_all_modules(self):
        self.assertIsNone(_module_containing_address(self.modules, 0x1))
        self.assertIsNone(_module_containing_address(self.modules, 0x140005000))


class AnalyzeMinidumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.temp.name)
        self.rsds = build_rsds(guid=GUID_LE, age=AGE, pdb=b"owned.pdb\0")
        self.dump = build_full_minidump(self.root / "owned.mdmp", rsds=self.rsds)
        self.pe = self.root / "owned.sys"
        build_pe_with_rsds(self.pe, self.rsds)
        self.pdb = self.root / "owned.pdb"
        write_synthetic_pdb(
            self.pdb, guid_le=GUID_LE, age=AGE, include_dbi=True, include_symbols=True,
            symbols=[("OwnedEntry", 0x0, 1), ("OwnedHelper", 0x200, 1)],
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_crash_symbol_resolves_with_pdb(self):
        report = analyze_minidump(str(self.dump), pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "READY")
        crash = report["crash_symbol"]
        self.assertIsNotNone(crash)
        self.assertEqual(crash["status"], "MATCH")
        self.assertEqual(crash["symbol"], "OwnedEntry")
        self.assertEqual(crash["rva"], 0x1000)

    def test_crash_symbol_attempted_but_not_matched_without_pdb(self):
        # A module IS found for the crash address, so crash_symbol is the
        # full symbolize_rva() result (not None) -- just not a MATCH, since
        # no pdb_path was supplied.
        report = analyze_minidump(str(self.dump))
        crash = report["crash_symbol"]
        self.assertIsNotNone(crash)
        self.assertEqual(crash["status"], "PDB_NOT_FOUND")
        self.assertNotIn("crash_symbol_reason", report)

    def test_crash_symbol_none_with_reason_when_no_exception_present(self):
        rsds = build_rsds(guid=GUID_LE, age=AGE, pdb=b"owned.pdb\0")
        no_exception_dump = self.root / "no_exception.mdmp"
        # exception_address=0 -> outside any module range -> module lookup misses.
        build_full_minidump(no_exception_dump, rsds=rsds, exception_address=0)
        report = analyze_minidump(str(no_exception_dump))
        self.assertIsNone(report["crash_symbol"])
        self.assertIn("crash_symbol_reason", report)
        self.assertEqual(report["crash_symbol_reason"], "CRASH_ADDRESS_NOT_INSIDE_ANY_KNOWN_MODULE")

    def test_stack_scan_finds_planted_candidate_and_no_false_positives(self):
        report = analyze_minidump(str(self.dump), pe_path=str(self.pe), pdb_path=str(self.pdb))
        threads = report["threads"]["items"]
        self.assertEqual(len(threads), 1)
        candidates = threads[0]["stack_scan_candidates"]
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["candidate_address"], hex(PLANTED_CANDIDATE_VA))
        self.assertEqual(candidate["stack_offset"], 8)
        self.assertEqual(candidate["rva"], 0x1200)
        self.assertEqual(candidate.get("symbol"), "OwnedHelper")
        self.assertEqual(threads[0]["stack_scan_status"], "SCANNED")

    def test_claims_ceiling_marks_stack_scan_heuristic_not_unwind(self):
        report = analyze_minidump(str(self.dump), pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertEqual(report["claims_ceiling"]["stack_scan_candidates"], "HEURISTIC_NOT_PROVEN_UNWIND")
        self.assertEqual(report["claims_ceiling"]["crash_symbol"], "PROVEN_WHEN_PDB_MATCHED")
        self.assertTrue(any("NOT a proven call stack" in item for item in report["limitations"]))

    def test_wrapper_returns_valid_json_ok_true(self):
        raw = minidump_analyzer(str(self.dump), pe_path=str(self.pe), pdb_path=str(self.pdb))
        report = json.loads(raw)
        self.assertTrue(report["ok"])
        self.assertEqual(report["tool"], "minidump_analyzer")

    def test_wrapper_reports_clean_structured_failure_on_corrupt_path(self):
        bad = self.root / "does_not_exist.mdmp"
        raw = minidump_analyzer(str(bad))
        report = json.loads(raw)
        self.assertFalse(report["ok"])

        corrupt = self.root / "corrupt.mdmp"
        corrupt.write_bytes(b"not a minidump")
        raw2 = minidump_analyzer(str(corrupt))
        report2 = json.loads(raw2)
        self.assertFalse(report2["ok"])


class FamiliesRegistrationTests(unittest.TestCase):
    def test_minidump_analyzer_registered_in_debug_family(self):
        self.assertIn("minidump_analyzer", tool_families.FAMILIES["debug"])


if __name__ == "__main__":
    unittest.main()
