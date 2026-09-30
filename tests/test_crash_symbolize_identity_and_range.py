"""symbolize_rva: an RVA outside the module image is refused by name, and two
same-basename modules in a dump are never silently conflated."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import crash_symbolize
import owned_binary_fixtures
import tools_workspace
from crash_symbolize import symbolize_rva
from msf_pdb import write_synthetic_pdb


class RvaRange(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.pe = root / "owned.sys"
        owned_binary_fixtures.build_owned_pe_with_rsds(self.pe)  # SizeOfImage 0x2000
        self.pdb = root / "owned.pdb"
        write_synthetic_pdb(self.pdb, guid_le=owned_binary_fixtures.GUID_LE, age=owned_binary_fixtures.AGE,
                            include_dbi=True, include_symbols=True, symbols=[("OwnedEntry", 0x0, 1)])

    def test_rva_beyond_size_of_image_is_refused_not_symbolised(self):
        r = symbolize_rva(module="owned.sys", rva=0x50000, pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "RVA_OUT_OF_MODULE_RANGE")
        self.assertIsNone(r["symbol"])

    def test_last_valid_rva_is_still_symbolised(self):
        r = symbolize_rva(module="owned.sys", rva=0x1FFF, pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertEqual(r["status"], "MATCH")

    def test_negative_rva_refused(self):
        r = symbolize_rva(module="owned.sys", rva=-1, pe_path=str(self.pe), pdb_path=str(self.pdb))
        self.assertEqual(r["status"], "RVA_OUT_OF_MODULE_RANGE")

    def test_minidump_image_size_bounds_the_rva(self):
        dump = {"ok": True, "modules": {"items": [
            {"name": r"C:\a\owned.sys", "image_size": 0x800, "codeview": None}]}}
        with mock.patch.object(crash_symbolize, "parse_minidump", return_value=dump):
            r = symbolize_rva(module="owned.sys", rva=0x900, minidump_path="x.mdmp")
        self.assertEqual(r["status"], "RVA_OUT_OF_MODULE_RANGE")


class SameBasenameModules(unittest.TestCase):
    DUMP = {"ok": True, "modules": {"items": [
        {"name": r"C:\one\foo.dll", "image_size": 0x10000, "codeview": None},
        {"name": r"C:\two\foo.dll", "image_size": 0x10000, "codeview": None}]}}

    def _run(self, module):
        with mock.patch.object(crash_symbolize, "parse_minidump", return_value=self.DUMP):
            return symbolize_rva(module=module, rva=0x10, minidump_path="x.mdmp")

    def test_bare_basename_with_two_candidates_is_ambiguous(self):
        r = self._run("foo.dll")
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "AMBIGUOUS_MODULE")
        self.assertEqual(len(r["candidates"]), 2)

    def test_full_path_disambiguates(self):
        r = self._run(r"C:\two\FOO.DLL")
        self.assertNotEqual(r["status"], "AMBIGUOUS_MODULE")
        self.assertTrue(r["ok"])


if __name__ == "__main__":
    unittest.main()
