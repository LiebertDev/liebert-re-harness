"""api_hash_recover.py has no coverage anywhere in this repo (per the port
audit) -- this is new, written for the public port batch.

Per the task's own instruction: computes a known export name's hash with
the SAME algorithm the module implements (not by calling the module twice)
and asserts crack_api_hash recovers that exact export name from a real
system DLL's export table -- kernel32.dll, present on every Windows host,
used here instead of the module's own ntoskrnl.exe default so the test
also runs for a non-administrator user. Skipped (not failed) on a non-
Windows host or if that DLL is absent, the same pattern this repo already
uses elsewhere for a real-system-file dependency
(tests/test_binary_patch.py's kernel32.dll skipUnless)."""
from __future__ import annotations

import pytest
import unittest
import zlib
from pathlib import Path

from liebert_re.recover.api_hash_recover import ALGORITHMS, crack_api_hash

KERNEL32 = Path(r"C:\Windows\System32\kernel32.dll")


def _ror(value, bits, width=32):
    mask = (1 << width) - 1
    value &= mask
    bits %= width
    return ((value >> bits) | (value << (width - bits))) & mask


def _fnv1a_32(name: bytes) -> int:
    h = 0x811C9DC5
    for b in name:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class CrackApiHashStructuredFailureTests(unittest.TestCase):
    """The documented failure path: a DLL that does not exist must return a
    structured, non-raising result, never an exception."""

    @pytest.mark.contract
    def test_missing_dll_is_a_structured_error_not_a_raise(self):
        result = crack_api_hash(0x12345678, dll_path=r"C:\definitely\not\a\real\path.dll")
        self.assertFalse(result["ok"])
        self.assertIn("DLL_NOT_FOUND", result["error"])

    @pytest.mark.contract
    def test_unknown_algorithm_name_is_rejected(self):
        result = crack_api_hash(0x1, dll_path=str(KERNEL32), algorithms=["not_a_real_algorithm"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_ALGORITHM")
        self.assertIn("not_a_real_algorithm", result["unknown"])

    @pytest.mark.contract
    def test_zero_matches_still_reports_the_full_search_space(self):
        # A hash value that (near-certainly) matches nothing must still come
        # back ok:true with matches:[] and the exact space searched -- never
        # a silent/ambiguous empty return.
        if not KERNEL32.exists():
            self.skipTest("kernel32.dll not present (non-Windows host)")
        result = crack_api_hash(0xDEADBEEF, dll_path=str(KERNEL32), algorithms=["crc32"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["match_count"], len(result["matches"]))
        self.assertGreater(result["export_count_searched"], 0)


@unittest.skipUnless(KERNEL32.exists(), "kernel32.dll not present (non-Windows host)")
class CrackApiHashKnownExportRoundTripTests(unittest.TestCase):
    """Computes a known export's hash independently (this test's own
    algorithm implementations, not the module's), then asks the module to
    recover the export name from the raw integer alone."""

    def test_ror13_add_recovers_a_known_export(self):
        # Metasploit-style block_api hash, computed here independently of
        # api_hash_recover.py's own _hash_ror13_add.
        name = b"CreateFileW\x00"
        h = 0
        for b in name:
            h = (_ror(h, 13) + b) & 0xFFFFFFFF
        result = crack_api_hash(h, dll_path=str(KERNEL32), algorithms=["ror13_add"])
        self.assertTrue(result["ok"])
        hit = next((m for m in result["matches"] if m["export_name"] == "CreateFileW"), None)
        self.assertIsNotNone(hit, result["matches"])
        self.assertEqual(hit["algorithm"], "ror13_add")
        self.assertTrue(hit["null_terminator_included"])

    def test_fnv1a_recovers_a_known_export_case_insensitively(self):
        name = b"createfilew"  # lowercase, no null terminator
        h = _fnv1a_32(name)
        result = crack_api_hash(h, dll_path=str(KERNEL32), algorithms=["fnv1a_32"])
        hit = next((m for m in result["matches"] if m["export_name"].lower() == "createfilew"), None)
        self.assertIsNotNone(hit, result["matches"])
        self.assertEqual(hit["case_variant"], "lower")
        self.assertFalse(hit["null_terminator_included"])

    def test_crc32_recovers_a_known_export(self):
        name = b"ExitProcess"
        h = zlib.crc32(name) & 0xFFFFFFFF
        result = crack_api_hash(h, dll_path=str(KERNEL32), algorithms=["crc32"])
        hit = next((m for m in result["matches"] if m["export_name"] == "ExitProcess"), None)
        self.assertIsNotNone(hit, result["matches"])

    def test_every_algorithm_is_internally_self_consistent(self):
        # Every registered algorithm must round-trip against ITS OWN output
        # for at least one real export -- proves ALGORITHMS is wired
        # correctly end to end, independent of which one this test suite
        # spot-checks above.
        for algo_name, fn in ALGORITHMS.items():
            h = fn(b"ExitProcess")
            result = crack_api_hash(h, dll_path=str(KERNEL32), algorithms=[algo_name],
                                     case_variants=("as_is",), append_null=(False,))
            found = any(m["export_name"] == "ExitProcess" for m in result["matches"])
            self.assertTrue(found, f"{algo_name} failed to round-trip")


class DeclaredNameIsDefinedTests(unittest.TestCase):
    """FAMILIES["crypto"] declares ``api_hash_recover``; the inventory only
    counts a name that some ``def <name>(`` line defines. The implementation
    lives under ``crack_api_hash``/``api_hash_recover_tool``, so the declared
    name must exist as a thin surface over them."""

    def test_declared_name_is_in_the_inventory(self):
        from liebert_re.report import tool_families
        self.assertIn("api_hash_recover", tool_families.FAMILIES["crypto"])
        self.assertIn("api_hash_recover", tool_families._locally_defined_tool_names())
        self.assertIn("api_hash_recover", tool_families.published_tools("crypto"))

    @unittest.skipUnless(KERNEL32.exists(), "kernel32.dll not present (non-Windows host)")
    def test_surface_returns_what_the_implementation_returns(self):
        import json
        from liebert_re.recover.api_hash_recover import api_hash_recover, api_hash_recover_tool
        h = 0
        for b in b"CreateFileW\x00":
            h = (_ror(h, 13) + b) & 0xFFFFFFFF
        kwargs = dict(dll_path=str(KERNEL32), algorithms=["ror13_add"])
        out = api_hash_recover(h, **kwargs)
        self.assertEqual(out, api_hash_recover_tool(h, **kwargs))
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(any(m["export_name"] == "CreateFileW" for m in data["matches"]))
        self.assertEqual(data, json.loads(json.dumps(crack_api_hash(h, **kwargs))))

    def test_refusals_surface_unchanged(self):
        import json
        from liebert_re.recover.api_hash_recover import api_hash_recover
        missing = json.loads(api_hash_recover(0x1, dll_path=r"C:\definitely\not\a\real\path.dll"))
        self.assertFalse(missing["ok"])
        self.assertTrue(missing["error"])
        bad = json.loads(api_hash_recover(0x1, algorithms=["not_a_real_algorithm"]))
        self.assertEqual(bad["error"], "UNKNOWN_ALGORITHM")
        self.assertEqual(bad["unknown"], ["not_a_real_algorithm"])
        self.assertIn("crc32", bad["available"])


if __name__ == "__main__":
    unittest.main()


def _pe_without_exports(directory: Path) -> Path:
    from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
    return build_owned_pe_sections(directory / "no_exports.exe")


def _pe_with_empty_export_directory(directory: Path) -> Path:
    """The owned PE with its export data directory pointed at an all-zero
    IMAGE_EXPORT_DIRECTORY (NumberOfNames 0): the directory exists, holds nothing."""
    import struct
    data = bytearray(_pe_without_exports(directory).read_bytes())
    struct.pack_into("<II", data, 200, 0x1000, 40)   # optional header data directory 0
    out = directory / "empty_exports.dll"
    out.write_bytes(bytes(data))
    return out


def _write_dll_with_exports(path: Path, names: list) -> Path:
    """Owned PE whose export directory (inside .text, RVA 0x1010) names ``names``."""
    import struct
    data = bytearray(_pe_without_exports(path.parent).read_bytes())
    base, n = 0x1000 + 0x10, len(names)
    funcs_at, names_at, ords_at = 40, 40 + 4 * n, 40 + 8 * n
    blob = bytearray(ords_at + 2 * n)
    strings = bytearray()
    for i, name in enumerate(names):
        struct.pack_into("<I", blob, funcs_at + 4 * i, 0x1000)
        struct.pack_into("<I", blob, names_at + 4 * i, base + len(blob) + len(strings))
        struct.pack_into("<H", blob, ords_at + 2 * i, i)
        strings += name.encode("ascii") + b"\x00"
    blob += strings
    struct.pack_into("<I", blob, 16, 1)             # Base
    struct.pack_into("<I", blob, 20, n)             # NumberOfFunctions
    struct.pack_into("<I", blob, 24, n)             # NumberOfNames
    struct.pack_into("<I", blob, 28, base + funcs_at)
    struct.pack_into("<I", blob, 32, base + names_at)
    struct.pack_into("<I", blob, 36, base + ords_at)
    data[0x400 + 0x10:0x400 + 0x10 + len(blob)] = blob
    struct.pack_into("<II", data, 200, base, len(blob))
    path.write_bytes(bytes(data))
    return path


class ZeroExportsIsNotAMeasurementOfAbsenceTests(unittest.TestCase):
    """Searching zero export names answers nothing: the domain of the question
    ("which export does this hash correspond to?") is empty. It must say it did
    not look, not report an empty search as ok:true / match_count:0. Fixtures
    are built in code (owned PE), no system file is involved."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    @pytest.mark.contract
    def test_pe_with_no_export_directory_is_not_looked(self):
        result = crack_api_hash(0x12345678, dll_path=str(_pe_without_exports(self.dir)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "NO_EXPORT_DIRECTORY")
        self.assertIs(result["export_directory_present"], False)
        self.assertNotIn("matches", result)

    @pytest.mark.contract
    def test_present_but_empty_export_directory_is_the_same_answer(self):
        # Measured: pefile parses it (DIRECTORY_ENTRY_EXPORT exists) with zero
        # symbols, and the old code returned the same ok:true/0/[] as for no
        # directory. The analyst's situation is identical (nothing to hash
        # against), so the code is the same; the detail field tells them apart.
        result = crack_api_hash(0x12345678, dll_path=str(_pe_with_empty_export_directory(self.dir)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "NO_EXPORT_DIRECTORY")
        self.assertIs(result["export_directory_present"], True)

    @pytest.mark.contract
    def test_status_categories_are_distinct_and_error_strings_unchanged(self):
        no_dir = crack_api_hash(1, dll_path=str(_pe_without_exports(self.dir)))
        missing = crack_api_hash(1, dll_path=str(self.dir / "absent.dll"))
        bad = self.dir / "bad.dll"
        bad.write_bytes(b"not a pe at all")
        malformed = crack_api_hash(1, dll_path=str(bad))
        usage = crack_api_hash(1, dll_path=str(bad), algorithms=["nope"])
        for refusal in (no_dir, missing, malformed):
            self.assertFalse(refusal["ok"])
            self.assertEqual(refusal["status"], "ANALYSIS_LIMITED")
        self.assertTrue(missing["error"].startswith("DLL_NOT_FOUND:"))
        self.assertTrue(malformed["error"].startswith("PEFormatError:"))
        self.assertFalse(usage["ok"])
        self.assertEqual(usage["status"], "INVALID_INPUT")   # a usage error, not "could not look"
        self.assertEqual(usage["error"], "UNKNOWN_ALGORITHM")

    @pytest.mark.contract
    def test_tool_layer_carries_the_same_status(self):
        import json
        from liebert_re.recover.api_hash_recover import api_hash_recover
        out = json.loads(api_hash_recover("0x1", dll_path=str(_pe_without_exports(self.dir))))
        self.assertEqual((out["ok"], out["error"], out["status"]), (False, "NO_EXPORT_DIRECTORY", "ANALYSIS_LIMITED"))
        bad_value = json.loads(api_hash_recover("zz", dll_path=str(_pe_without_exports(self.dir))))
        self.assertFalse(bad_value["ok"])
        self.assertEqual(bad_value["status"], "INVALID_INPUT")
        self.assertEqual(bad_value["error"], "ValueError")

    @pytest.mark.contract
    def test_a_real_search_that_finds_nothing_is_still_ok(self):
        # The narrow side: a PE that HAS exports, searched fully, matching
        # nothing, is a real answer. Built in code, so no system file.
        pe = self.dir / "named.dll"
        _write_dll_with_exports(pe, ["AlphaExport", "BetaExport"])
        result = crack_api_hash(0xDEADBEEF, dll_path=str(pe), algorithms=["crc32"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["export_count_searched"], 2)
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["matches"], [])
