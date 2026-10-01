"""Focused public-port coverage for five PE-native inspection modules whose
private test files each import at least one unpublished orchestration
module (file_router, teacher, tool_registry, or `tests` itself as a
package) and, for tools_image_map, a real corpus fixture kept out of scope
for this port batch:

  tools_delphi.py     <- tests/test_delphi_inspect.py
  tools_vb6.py         <- tests/test_vb6_inspect.py
  tools_tls_directory.py (no gate-clean private test at all)
  tools_image_map.py  <- tests/test_tools_image_map.py
  tools_cpp_rtti.py   <- tests/test_cpp_rtti.py

All five modules share one shape: static PE parsing that never raises on a
plain, unrelated PE, instead returning a named "structure absent" status.
owned_binary_fixtures.build_owned_pe_with_rsds() builds exactly that kind of
plain PE (no Delphi VMT, no VB6 header, no TLS directory, no MSVC RTTI, and
small enough that image_address_map's RVA query lands cleanly inside its one
.rdata section) -- so it doubles as the negative-control fixture for every
module here."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import liebert_re.recover.owned_binary_fixtures as owned_binary_fixtures
import liebert_re.workspace as tools_workspace
from liebert_re.tools.cpp_rtti import cpp_rtti_inspect
from liebert_re.tools.delphi import delphi_inspect
from liebert_re.tools.image_map import image_address_map
from liebert_re.tools.tls_directory import analyze_tls_directory
from liebert_re.tools.vb6 import vb6_inspect


def _j(raw):
    import json
    return json.loads(raw)


class PeNativeToolsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)
        self.plain_pe = self.root / "owned_plain.sys"
        owned_binary_fixtures.build_owned_pe_with_rsds(self.plain_pe)
        self.garbage = self.root / "garbage.bin"
        self.garbage.write_bytes(b"not a PE at all, just filler bytes\x00\x01\x02" * 4)

    def tearDown(self):
        self.tmp.cleanup()


class DelphiInspectTests(PeNativeToolsTestCase):
    def test_non_pe_is_not_a_pe(self):
        result = _j(delphi_inspect(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_A_PE")

    def test_plain_pe_with_no_vmt_reports_absence_not_a_crash(self):
        result = _j(delphi_inspect(str(self.plain_pe)))
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["class_count"], 0)
        self.assertEqual(result["classes"], [])
        self.assertIn("THAT_THIS_BINARY_IS_NOT_DELPHI", result["not_established"])

    def test_unknown_operation_is_rejected(self):
        result = _j(delphi_inspect(str(self.plain_pe), operation="not_a_real_operation"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_OPERATION")


class Vb6InspectTests(PeNativeToolsTestCase):
    def test_non_pe_is_not_a_pe(self):
        result = _j(vb6_inspect(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_A_PE")

    def test_plain_pe_with_no_vb_header_is_not_visual_basic(self):
        result = _j(vb6_inspect(str(self.plain_pe)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_VISUAL_BASIC")

    def test_unknown_operation_is_rejected(self):
        result = _j(vb6_inspect(str(self.plain_pe), operation="not_a_real_operation"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_OPERATION")


class TlsDirectoryTests(PeNativeToolsTestCase):
    def test_non_pe_is_not_a_pe(self):
        result = _j(analyze_tls_directory(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_A_PE")

    def test_missing_file_is_not_found(self):
        result = _j(analyze_tls_directory(str(self.root / "does_not_exist.sys")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_FOUND")

    def test_plain_pe_with_no_tls_directory_is_reported_explicitly(self):
        result = _j(analyze_tls_directory(str(self.plain_pe)))
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "NO_TLS_DIRECTORY")
        self.assertFalse(result["has_tls_directory"])


class CppRttiInspectTests(PeNativeToolsTestCase):
    def test_non_pe_is_not_a_pe(self):
        result = _j(cpp_rtti_inspect(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_A_PE")

    def test_plain_pe_with_no_rtti_is_reported_absent_not_a_crash(self):
        result = _j(cpp_rtti_inspect(str(self.plain_pe)))
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ABSENT")
        self.assertEqual(result["classes"], [])
        self.assertEqual(result["hierarchy_edges"], [])

    def test_unknown_operation_is_rejected(self):
        result = _j(cpp_rtti_inspect(str(self.plain_pe), operation="not_a_real_operation"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNKNOWN_OPERATION")


class ImageAddressMapTests(PeNativeToolsTestCase):
    def test_missing_dump_path_is_not_found(self):
        result = _j(image_address_map(str(self.root / "does_not_exist.exe"), rva="0x1000"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_FOUND")

    def test_non_pe_is_not_a_pe(self):
        result = _j(image_address_map(str(self.garbage), rva="0x1000"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "NOT_A_PE")

    def test_zero_query_selectors_is_invalid_arguments(self):
        result = _j(image_address_map(str(self.plain_pe)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "INVALID_ARGUMENTS")

    def test_two_query_selectors_is_invalid_arguments(self):
        result = _j(image_address_map(str(self.plain_pe), rva="0x1000", file_offset="0x400"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "INVALID_ARGUMENTS")

    def test_live_va_without_base_is_invalid_arguments_never_invents_one(self):
        result = _j(image_address_map(str(self.plain_pe), live_va="0x140001200"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "INVALID_ARGUMENTS")

    def test_rva_inside_the_owned_fixtures_section_resolves(self):
        # owned_binary_fixtures builds a single .rdata section at
        # VirtualAddress 0x1000; RVA 0x1010 lands inside it.
        result = _j(image_address_map(str(self.plain_pe), rva="0x1010"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "OK")

    def test_rva_past_the_end_of_the_image_is_unmapped(self):
        result = _j(image_address_map(str(self.plain_pe), rva="0x99999999"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "UNMAPPED_RVA")

    def test_rva_to_live_va_round_trips_back_to_the_same_rva(self):
        first = _j(image_address_map(str(self.plain_pe), rva="0x1010", live_module_base="0x140000000"))
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["live_virtual_address"], "0x140001010")
        second = _j(image_address_map(
            str(self.plain_pe), live_va=first["live_virtual_address"], live_module_base="0x140000000",
        ))
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["status"], "OK")
        self.assertEqual(second["rva"], "0x1010")


if __name__ == "__main__":
    unittest.main()
