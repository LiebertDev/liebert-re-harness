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

import unittest
import zlib
from pathlib import Path

from api_hash_recover import ALGORITHMS, crack_api_hash

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

    def test_missing_dll_is_a_structured_error_not_a_raise(self):
        result = crack_api_hash(0x12345678, dll_path=r"C:\definitely\not\a\real\path.dll")
        self.assertFalse(result["ok"])
        self.assertIn("DLL_NOT_FOUND", result["error"])

    def test_unknown_algorithm_name_is_rejected(self):
        result = crack_api_hash(0x1, dll_path=str(KERNEL32), algorithms=["not_a_real_algorithm"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_ALGORITHM")
        self.assertIn("not_a_real_algorithm", result["unknown"])

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


if __name__ == "__main__":
    unittest.main()
