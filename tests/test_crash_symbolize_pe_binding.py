"""symbolize_rva: a symbol address is only computed from a PE that is the one
the dump was talking about.

The PDB is tied to the dump module by the dump's RSDS; the address comes from
the PE's section map. Nothing used to tie the PE to the dump module, so a PE of
a different build with another section layout produced a confident wrong RVA.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.recover.crash_symbolize as crash_symbolize
import liebert_re.recover.owned_binary_fixtures as fx
import liebert_re.workspace as tools_workspace
from liebert_re.recover.codeview_rsds import parse_rsds
from liebert_re.recover.crash_symbolize import symbolize_rva
from liebert_re.recover.msf_pdb import write_synthetic_pdb

COFF_TIMESTAMP_AT = 64 + 4 + 4        # e_lfanew + "PE\0\0" + Machine/NumberOfSections
SECTION_TABLE_AT = 64 + 4 + 20 + 240
OTHER_GUID_LE = struct.pack("<IHH", 0x11111111, 0x2222, 0x3333) + bytes.fromhex("4455667788990011")
OTHER_RSDS = b"RSDS" + OTHER_GUID_LE + struct.pack("<I", fx.AGE) + fx.PDB_NAME
SECTIONS = ((".text", 0x60000020), (".data", 0xC0000040))   # seg 2 (.data) at RVA 0x2000
SYMBOL_OFFSET = 0x10
TRUE_RVA = 0x2000 + SYMBOL_OFFSET
SHIFTED_RVA = 0x2800 + SYMBOL_OFFSET


def _patch(path: Path, offset: int, fmt: str, value: int) -> None:
    data = bytearray(path.read_bytes())
    struct.pack_into(fmt, data, offset, value)
    path.write_bytes(bytes(data))


class PeBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pdb = self.root / "owned.pdb"
        write_synthetic_pdb(self.pdb, guid_le=fx.GUID_LE, age=fx.AGE, include_dbi=True,
                            include_symbols=True, symbols=[("Sym", SYMBOL_OFFSET, 2)])
        self.good = fx.build_owned_pe_sections(self.root / "good.sys", sections=SECTIONS, rsds=fx.build_owned_rsds())
        self.size = int.from_bytes(self.good.read_bytes()[64 + 4 + 20 + 56:][:4], "little")

    def _module(self, **over):
        item = {"name": r"C:\owned\owned.sys", "image_size": self.size, "timestamp": 0, "checksum": 0xDEAD,
                "codeview": {"rsds": parse_rsds(fx.build_owned_rsds())}}
        item.update(over)
        return item

    def _run(self, pe, rva, module=None):
        dump = {"ok": True, "modules": {"items": [module or self._module()]}}
        with mock.patch.object(crash_symbolize, "parse_minidump", return_value=dump):
            return symbolize_rva(module="owned.sys", rva=rva, pe_path=str(pe), pdb_path=str(self.pdb),
                                 minidump_path="x.mdmp")

    def _other_build(self, name="other.sys", rsds=OTHER_RSDS):
        """Another build: other section layout (.data moved), carrying its own RSDS."""
        path = fx.build_owned_pe_sections(self.root / name, sections=SECTIONS, rsds=rsds)
        _patch(path, SECTION_TABLE_AT + 40 + 12, "<I", 0x2800)
        return path

    def assertNoAddress(self, r):
        self.assertIsNone(r["symbol"])
        self.assertIsNone(r["symbol_rva"])
        self.assertIsNone(r["offset_from_symbol"])
        self.assertNotEqual(r["status"], "MATCH")
        self.assertNotIn(r["confidence"], {"HIGH", "MEDIUM"})

    def test_pe_of_another_build_does_not_yield_an_address(self):
        r = self._run(self._other_build(), SHIFTED_RVA)
        self.assertNoAddress(r)

    def test_unbound_pe_is_analysis_limited_and_says_why(self):
        r = self._run(self._other_build(), SHIFTED_RVA)
        self.assertEqual(r["status"], "ANALYSIS_LIMITED")
        self.assertEqual(r["pe_binding"]["status"], "MISMATCH")
        self.assertEqual(r["pe_binding"]["checks"]["rsds"]["status"], "MISMATCH")
        self.assertIs(r["pe_bound_to_dump_module"], False)
        self.assertIn("rsds", r["pe_binding"]["reason"])

    def test_measured_facts_survive_when_unbound(self):
        r = self._run(self._other_build(), SHIFTED_RVA)
        self.assertTrue(r["identity"]["identity_match"])      # the PDB does belong to the dump module
        self.assertEqual(r["module"], "owned.sys")

    def test_same_rsds_but_other_size_of_image_is_a_mismatch(self):
        pe = self._other_build("size.sys", rsds=fx.build_owned_rsds())
        _patch(pe, 64 + 4 + 20 + 56, "<I", self.size + 0x1000)
        r = self._run(pe, SHIFTED_RVA)
        self.assertNoAddress(r)
        self.assertEqual(r["pe_binding"]["status"], "MISMATCH")
        self.assertEqual(r["pe_binding"]["checks"]["size_of_image"]["status"], "MISMATCH")
        self.assertEqual(r["pe_binding"]["checks"]["rsds"]["status"], "MATCH")

    def test_same_rsds_but_other_timestamp_is_a_mismatch(self):
        pe = self._other_build("ts.sys", rsds=fx.build_owned_rsds())
        _patch(pe, COFF_TIMESTAMP_AT, "<I", 0x5F5E100)
        r = self._run(pe, SHIFTED_RVA)
        self.assertNoAddress(r)
        self.assertEqual(r["pe_binding"]["checks"]["timestamp"]["status"], "MISMATCH")

    def test_pe_without_a_debug_record_is_unverifiable_not_mismatched(self):
        pe = fx.build_owned_pe_sections(self.root / "nodbg.sys", sections=SECTIONS)
        size = int.from_bytes(pe.read_bytes()[64 + 4 + 20 + 56:][:4], "little")
        r = self._run(pe, TRUE_RVA, module=self._module(image_size=size))   # nothing measured contradicts it
        self.assertNoAddress(r)
        self.assertEqual(r["status"], "ANALYSIS_LIMITED")
        self.assertEqual(r["pe_binding"]["status"], "UNVERIFIABLE")
        self.assertEqual(r["pe_binding"]["checks"]["rsds"]["status"], "PE_RSDS_UNREADABLE")
        self.assertIs(r["pe_bound_to_dump_module"], None)

    def test_dump_module_without_codeview_is_unverifiable_not_mismatched(self):
        r = self._run(self.good, TRUE_RVA, module=self._module(codeview=None))
        self.assertNoAddress(r)
        self.assertEqual(r["pe_binding"]["status"], "UNVERIFIABLE")
        self.assertEqual(r["pe_binding"]["checks"]["rsds"]["status"], "DUMP_RSDS_UNAVAILABLE")

    def test_matching_pe_still_symbolises(self):
        r = self._run(self.good, TRUE_RVA)
        self.assertEqual(r["status"], "MATCH")
        self.assertEqual(r["confidence"], "HIGH")
        self.assertEqual(r["symbol"], "Sym")
        self.assertEqual(r["symbol_rva"], TRUE_RVA)
        self.assertEqual(r["pe_binding"]["status"], "BOUND")
        self.assertIs(r["pe_bound_to_dump_module"], True)

    def test_binding_is_narrow_checksum_and_file_hash_are_not_required(self):
        # The dump records a loader checksum the PE file does not carry, and the
        # PE bytes differ in unrelated ways: same RSDS, SizeOfImage and
        # TimeDateStamp is the identity, and it must be enough.
        pe = fx.build_owned_pe_sections(self.root / "same.sys", sections=SECTIONS, rsds=fx.build_owned_rsds())
        _patch(pe, 64 + 4 + 20 + 64, "<I", 0x1234)          # PE file checksum differs from the dump's
        r = self._run(pe, TRUE_RVA, module=self._module(checksum=0xBEEF))
        self.assertEqual(r["status"], "MATCH")
        self.assertEqual(r["pe_binding"]["status"], "BOUND")

    def test_pe_without_a_dump_has_nothing_to_bind_to_and_is_unchanged(self):
        r = symbolize_rva(module="owned.sys", rva=TRUE_RVA, pe_path=str(self.good), pdb_path=str(self.pdb))
        self.assertEqual(r["status"], "MATCH")
        self.assertEqual(r["pe_binding"]["status"], "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
