"""Hermetic MSF 7.00 P0 container parser tests."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from msf_pdb import MSF_MAGIC, build_synthetic_msf, detect_pdb_container, parse_msf, write_synthetic_msf


class MsfPdbP0Tests(unittest.TestCase):
    def test_detect_bsjb_vs_msf(self):
        self.assertEqual(detect_pdb_container(b"BSJB" + b"\0" * 28), "PORTABLE_PDB_BSJB")
        self.assertEqual(detect_pdb_container(MSF_MAGIC), "MSF7")

    def test_parses_minimum_valid_and_multi_stream(self):
        data = build_synthetic_msf(streams=[b"", b"ALPHA", b"BETA-123"])
        report = parse_msf(data=data)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["valid"])
        self.assertEqual(report["format"], "msf")
        self.assertEqual(report["block_size"], 4096)
        self.assertEqual(report["stream_count"], 3)
        self.assertEqual(report["streams"][0]["size"], 0)
        self.assertEqual(report["streams"][1]["size"], 5)
        self.assertEqual(report["streams"][2]["size"], 8)
        self.assertEqual(report["pdb_symbol_records"], "NOT_IMPLEMENTED_P0")
        self.assertEqual(report["claims_ceiling"]["symbols"], "UNKNOWN")

    def test_rejects_portable_pdb(self):
        report = parse_msf(data=b"BSJB\x01\x00\x01\x00" + b"\0" * 64)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "PORTABLE_PDB_NOT_MSF")

    def test_rejects_invalid_magic_and_truncated_superblock(self):
        self.assertEqual(parse_msf(data=b"NOT_MSF" + b"\0" * 64)["error"], "INVALID_MSF_SIGNATURE")
        self.assertEqual(parse_msf(data=MSF_MAGIC[:20])["error"], "SUPERBLOCK_TRUNCATED")

    def test_rejects_invalid_block_size(self):
        raw = bytearray(build_synthetic_msf())
        struct.pack_into("<I", raw, 32, 1234)
        self.assertEqual(parse_msf(data=bytes(raw))["error"], "INVALID_BLOCK_SIZE")

    def test_rejects_directory_and_stream_block_oob(self):
        raw = bytearray(build_synthetic_msf(streams=[b"X" * 8]))
        # Corrupt directory block map entry to an impossible block index.
        struct.pack_into("<I", raw, 2 * 4096, 999999)
        self.assertEqual(parse_msf(data=bytes(raw))["error"], "DIRECTORY_BLOCK_OUT_OF_BOUNDS")

        raw = bytearray(build_synthetic_msf(streams=[b"X" * 8]))
        # Truncate file after claiming many blocks.
        struct.pack_into("<I", raw, 40, 100)  # NumBlocks
        self.assertEqual(parse_msf(data=bytes(raw[: 8 * 4096]))["error"], "FILE_SMALLER_THAN_NUM_BLOCKS")

    def test_rejects_truncated_directory_payload(self):
        raw = bytearray(build_synthetic_msf(streams=[b"ABCDEFGH"]))
        # Directory claims only 4 bytes but encodes stream_count=2 (needs size table).
        struct.pack_into("<I", raw, 44, 4)
        start = 3 * 4096
        struct.pack_into("<I", raw, start, 2)
        self.assertEqual(parse_msf(data=bytes(raw))["error"], "DIRECTORY_TRUNCATED")

    def test_write_fixture_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "owned.msf.pdb"
            write_synthetic_msf(path, streams=[b"", b"P0"])
            report = parse_msf(path)
        self.assertTrue(report["ok"])
        self.assertTrue(report["msf_container_parsed"])


if __name__ == "__main__":
    unittest.main()
