"""crash_symbolize.py has no coverage anywhere in this repo (per the port
audit) -- this is new, written for the public port batch. Uses
owned_binary_fixtures.py's synthetic PE/RSDS builder and msf_pdb's synthetic
PDB writer (both already-published/newly-published modules) rather than a
real captured sample, matching this module's own "generic, not one binary"
scope."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import owned_binary_fixtures
import tools_workspace
from crash_symbolize import crash_symbolize, symbolize_rva
from msf_pdb import write_synthetic_pdb


class SymbolizeRvaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)
        self.rsds = owned_binary_fixtures.build_owned_rsds()
        self.pe = self.root / "owned.sys"
        owned_binary_fixtures.build_owned_pe_with_rsds(self.pe, rsds=self.rsds)
        self.pdb = self.root / "owned.pdb"
        write_synthetic_pdb(
            self.pdb,
            guid_le=owned_binary_fixtures.GUID_LE,
            age=owned_binary_fixtures.AGE,
            include_dbi=True,
            include_symbols=True,
            symbols=[("OwnedEntry", 0x0, 1), ("OwnedHelper", 0x200, 1)],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_pe_and_no_minidump_is_no_rsds(self):
        result = symbolize_rva(module="owned.sys", rva=0x1000)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "NO_RSDS")
        self.assertFalse(result["execution_performed"])

    def test_pe_without_pdb_path_is_pdb_not_found(self):
        result = symbolize_rva(module="owned.sys", rva=0x1000, pe_path=str(self.pe))
        self.assertEqual(result["status"], "PDB_NOT_FOUND")
        self.assertEqual(result["identity"]["status"], "PDB_NOT_FOUND")

    def test_matching_pe_and_pdb_resolves_the_symbol(self):
        result = symbolize_rva(module="owned.sys", rva=0x1000, pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertEqual(result["status"], "MATCH")
        self.assertEqual(result["symbol"], "OwnedEntry")
        self.assertEqual(result["confidence"], "HIGH")

    def test_offset_from_a_known_symbol_is_reported(self):
        result = symbolize_rva(module="owned.sys", rva=0x1204, pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertEqual(result["status"], "MATCH")
        self.assertEqual(result["symbol"], "OwnedHelper")
        self.assertEqual(result["offset_from_symbol"], 4)


class CrashSymbolizeToolWrapperTests(unittest.TestCase):
    def test_invalid_rva_is_a_structured_failure_not_a_raise(self):
        raw = crash_symbolize(module="owned.sys", rva="not-a-number")
        report = json.loads(raw)
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "INVALID_ADDRESS")

    def test_wrapper_returns_valid_json_for_a_bare_module_with_no_pe(self):
        raw = crash_symbolize(module="owned.sys", rva="0x10")
        report = json.loads(raw)
        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "NO_RSDS")
        self.assertEqual(report["rva"], 16)


if __name__ == "__main__":
    unittest.main()
