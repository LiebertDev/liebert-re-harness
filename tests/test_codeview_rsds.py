"""Independent tests for ``codeview_rsds.py``.

New file, not ported from the upstream development repo: the
upstream test for this module imported ``tests/fixtures_pe_builder.py`` and
``kernel_debug.py``, neither of which is part of this package, so it could
not be carried over as-is. This file exercises the same module (which has
no third-party dependency at all -- pure ``struct``/``pathlib``) against
small, fully self-contained fixtures built programmatically below; nothing
is downloaded and nothing is executed.

At least one positive and one negative case is covered for each of the
module's public entry points: ``parse_rsds``, ``correlate_rsds``,
``extract_pe_rsds`` and ``extract_pe_section_map``.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from liebert_re.recover.codeview_rsds import (
    correlate_rsds,
    extract_pe_rsds,
    extract_pe_section_map,
    format_guid,
    parse_rsds,
)

GUID_LE = struct.pack("<IHH", 0x8F11D2A0, 0x41B7, 0x4B0D) + bytes.fromhex("9E42112233445566")
AGE = 7
PDB_NAME = b"fixture.pdb\0"
GUID_TEXT = "8F11D2A0-41B7-4B0D-9E42-112233445566"


def _build_rsds(guid: bytes = GUID_LE, age: int = AGE, pdb: bytes = PDB_NAME) -> bytes:
    return b"RSDS" + guid + struct.pack("<I", age) + pdb


def _build_pe32_with_rsds(rsds: bytes) -> bytes:
    """Minimal, real, valid 32-bit PE with exactly one section and one
    CodeView (type 2) debug-directory entry pointing at ``rsds``. Built by
    hand with ``struct`` to match exactly what ``extract_pe_rsds`` parses
    (see its own source): PE32 magic 0x10B, data-directory slot 6 (debug) at
    optional-header offset 96, one section covering both the debug-directory
    record and the RSDS blob it points to.
    """
    image_base = 0x00400000
    section_rva = 0x1000
    header_size = 0x200
    # Layout inside the one section: debug directory record (28 bytes),
    # immediately followed by the RSDS blob itself.
    debug_rva = section_rva
    rsds_rva = debug_rva + 28
    section_size = max((rsds_rva - section_rva + len(rsds) + 0xF) & ~0xF, 0x200)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)          # PE32 magic
    struct.pack_into("<I", optional, 16, section_size)  # SizeOfCode
    struct.pack_into("<I", optional, 28, section_rva)   # AddressOfEntryPoint
    struct.pack_into("<I", optional, 28 + 4, image_base)
    struct.pack_into("<I", optional, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", optional, 36, 0x200)         # FileAlignment
    struct.pack_into("<I", optional, 56, section_rva + section_size)  # SizeOfImage
    struct.pack_into("<I", optional, 60, header_size)   # SizeOfHeaders
    struct.pack_into("<H", optional, 68, 3)             # Subsystem
    struct.pack_into("<I", optional, 92, 16)            # NumberOfRvaAndSizes
    # DataDirectory[6] (debug) starts at optional-header offset 96 for PE32.
    struct.pack_into("<II", optional, 96 + 6 * 8, debug_rva, 28)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        section_size, section_rva,
        section_size, header_size,
        0, 0, 0, 0,
        0x40000040,
    )

    headers = bytearray(header_size)
    at = 0
    headers[at:at + len(dos)] = dos
    at += len(dos)
    headers[at:at + 4] = b"PE\x00\x00"
    at += 4
    headers[at:at + len(file_header)] = file_header
    at += len(file_header)
    headers[at:at + len(optional)] = optional
    at += len(optional)
    headers[at:at + len(section_header)] = section_header

    section = bytearray(section_size)
    # IMAGE_DEBUG_DIRECTORY: characteristics, timestamp, major, minor, type,
    # size_of_data, addr_of_raw_data, pointer_to_raw_data.
    struct.pack_into(
        "<IIHHIIII", section, 0,
        0, 0, 0, 0, 2, len(rsds), rsds_rva, header_size + (rsds_rva - section_rva),
    )
    section[rsds_rva - section_rva:rsds_rva - section_rva + len(rsds)] = rsds

    return bytes(headers) + bytes(section)


class CodeViewRsdsHermeticTests(unittest.TestCase):
    def test_parse_rsds_positive(self):
        parsed = parse_rsds(_build_rsds())
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["guid"], GUID_TEXT)
        self.assertEqual(parsed["age"], AGE)
        self.assertEqual(parsed["pdb_path"], "fixture.pdb")
        self.assertEqual(parsed["identity_key"], f"{GUID_TEXT}:{AGE}")

    def test_parse_rsds_negative_bad_signature_and_unterminated_path(self):
        self.assertEqual(parse_rsds(b"NB10" + b"\0" * 20)["error"], "UNSUPPORTED_CV_TYPE")
        self.assertEqual(parse_rsds(b"XXXX" + b"\0" * 20)["error"], "INVALID_CV_SIGNATURE")
        unterminated = b"RSDS" + GUID_LE + struct.pack("<I", 1) + b"no-null-terminator"
        self.assertEqual(parse_rsds(unterminated)["error"], "PDB_PATH_NOT_TERMINATED")
        self.assertEqual(parse_rsds(b"short")["error"], "RSDS_TRUNCATED")

    def test_format_guid_rejects_wrong_size(self):
        with self.assertRaises(Exception):
            format_guid(b"\x00" * 8)

    def test_correlate_rsds_positive_match(self):
        left = parse_rsds(_build_rsds())
        right = parse_rsds(_build_rsds())
        matched = correlate_rsds(left, right)
        self.assertEqual(matched["status"], "MATCH")
        self.assertEqual(matched["identity_match"], "PROVEN")
        self.assertIn("guid", matched["match_basis"])

    def test_correlate_rsds_negative_age_and_guid_mismatch(self):
        left = parse_rsds(_build_rsds())
        age_mismatch = correlate_rsds(left, parse_rsds(_build_rsds(age=AGE + 1)))
        self.assertEqual(age_mismatch["status"], "MISMATCH")
        self.assertEqual(age_mismatch["reason"], "AGE_MISMATCH")

        different_guid = struct.pack("<IHH", 0x11111111, 0x2222, 0x3333) + bytes.fromhex("4444555566667777")
        guid_mismatch = correlate_rsds(left, parse_rsds(_build_rsds(guid=different_guid)))
        self.assertEqual(guid_mismatch["status"], "MISMATCH")
        self.assertEqual(guid_mismatch["reason"], "GUID_MISMATCH")

        unknown = correlate_rsds(None, left)
        self.assertEqual(unknown["status"], "UNKNOWN")

    def test_extract_pe_rsds_positive(self):
        rsds = _build_rsds()
        pe_bytes = _build_pe32_with_rsds(rsds)
        with tempfile.TemporaryDirectory(prefix="codeview-rsds-") as tmp:
            path = Path(tmp) / "fixture.sys"
            path.write_bytes(pe_bytes)
            result = extract_pe_rsds(path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["rsds"]["identity_key"], f"{GUID_TEXT}:{AGE}")
        self.assertEqual(result["source"], "PE_DEBUG_DIRECTORY")

    def test_extract_pe_rsds_negative_no_debug_directory(self):
        # Same builder, but zero out the debug directory's RVA/size so no
        # debug directory is advertised at all -- must be a decisive
        # ANALYSIS_LIMITED / DEBUG_DIRECTORY_EMPTY, not a crash. DataDirectory[6]
        # (debug) sits at optional-header-relative offset 96 + 6*8; the
        # optional header itself starts right after DOS header (0x40) + the
        # "PE\0\0" signature (4 bytes) + FILE_HEADER (20 bytes).
        debug_directory_slot_offset = 0x40 + 4 + 20 + (96 + 6 * 8)
        pe_bytes = bytearray(_build_pe32_with_rsds(_build_rsds()))
        struct.pack_into("<II", pe_bytes, debug_directory_slot_offset, 0, 0)
        with tempfile.TemporaryDirectory(prefix="codeview-rsds-") as tmp:
            path = Path(tmp) / "no_debug.sys"
            path.write_bytes(bytes(pe_bytes))
            result = extract_pe_rsds(path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "DEBUG_DIRECTORY_EMPTY")

    def test_extract_pe_rsds_negative_not_a_pe(self):
        with tempfile.TemporaryDirectory(prefix="codeview-rsds-") as tmp:
            path = Path(tmp) / "not_a_pe.bin"
            path.write_bytes(b"this is not a PE file at all, just plain bytes")
            result = extract_pe_rsds(path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "NOT_PE")

    def test_extract_pe_section_map_positive_and_negative(self):
        pe_bytes = _build_pe32_with_rsds(_build_rsds())
        with tempfile.TemporaryDirectory(prefix="codeview-rsds-") as tmp:
            good = Path(tmp) / "fixture.sys"
            good.write_bytes(pe_bytes)
            result = extract_pe_section_map(good)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["section_count"], 1)
            self.assertEqual(result["sections"][0]["name"], ".rdata")

            bad = Path(tmp) / "empty.bin"
            bad.write_bytes(b"")
            bad_result = extract_pe_section_map(bad)
            self.assertFalse(bad_result["ok"])
            self.assertEqual(bad_result["error"], "EMPTY_FILE")


if __name__ == "__main__":
    unittest.main()
