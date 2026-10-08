"""liebert_re.tools.formats.file_identity: a header field that was not read is None with a reason, never 0 or a guess.

Fixtures are built in code: cut ELF and Mach-O headers, a bare ``MZ`` blob, a PE built by tests/_pe_fixtures.py.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.tools.formats as formats
import liebert_re.workspace as tools_workspace
from liebert_re.tools.formats import file_identity
from tests._pe_fixtures import build_pe


class FileIdentityTruncationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _identify(self, data: bytes, name: str = "blob") -> dict:
        p = self.root / name
        p.write_bytes(data)
        return json.loads(file_identity(str(p)))

    def test_elf_magic_alone_does_not_raise_and_leaves_fields_unknown(self):
        info = self._identify(b"\x7fELF")
        self.assertEqual(info["type"], "ELF")
        self.assertIsNone(info["architecture"])
        self.assertIsNone(info["subtype"])
        self.assertTrue(any("EI_DATA" in text for text in info["limitations"]))
        self.assertLess(info["confidence"], 0.95)

    def test_elf_cut_before_e_machine_has_no_architecture_not_machine_0(self):
        info = self._identify(b"\x7fELF\x02\x01\x01\x00" + bytes(8) + struct.pack("<H", 3))
        self.assertEqual(info["subtype"], "shared_library")
        self.assertIsNone(info["architecture"])
        self.assertNotIn("machine_0", json.dumps(info))
        self.assertTrue(any("e_machine" in text for text in info["limitations"]))
        self.assertLess(info["confidence"], 0.95)

    def test_elf_with_invalid_byte_order_has_unknown_type_and_machine(self):
        info = self._identify(b"\x7fELF\x02\x07\x01\x00" + bytes(8) + struct.pack("<HH", 3, 62))
        self.assertIsNone(info["architecture"])
        self.assertIsNone(info["subtype"])
        self.assertEqual(info["endianness"], "unknown")

    def test_complete_elf_header_is_still_fully_identified(self):
        info = self._identify(b"\x7fELF\x02\x01\x01\x00" + bytes(8) + struct.pack("<HH", 3, 62))
        self.assertEqual((info["architecture"], info["subtype"], info["confidence"]), ("x86_64", "shared_library", 0.99))
        self.assertEqual(info["limitations"], [])

    def test_macho_cut_before_cputype_does_not_raise_struct_error(self):
        info = self._identify(b"\xcf\xfa\xed\xfe")
        self.assertEqual(info["type"], "MACHO")
        self.assertIsNone(info["architecture"])
        self.assertTrue(any("cputype" in text for text in info["limitations"]))
        self.assertLess(info["confidence"], 0.95)

    def test_complete_macho_header_is_still_identified(self):
        info = self._identify(b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x0100000c))
        self.assertEqual((info["architecture"], info["limitations"]), ("ARM64", []))

    def test_bare_mz_is_a_signature_claim_not_a_confident_pe(self):
        info = self._identify(b"MZ", "bare.exe")
        self.assertLess(info["confidence"], 0.95)
        self.assertTrue(any("PE parse failed" in text and "unverified" in text for text in info["limitations"]))
        self.assertIsNone(info["architecture"])

    def test_parsed_pe_keeps_its_high_confidence(self):
        info = self._identify(build_pe(), "real.exe")
        self.assertFalse(info["limitations"], info["limitations"])
        self.assertEqual(info["confidence"], 0.98)
        self.assertIsNotNone(info["architecture"])

    def test_skipped_hash_says_why(self):
        with mock.patch.object(formats, "MAX_IDENTITY_HASH_BYTES", 4):
            info = self._identify(b"plain text, longer than four bytes\n", "t.txt")
        self.assertIsNone(info["sha256"])
        self.assertTrue(any("sha256 not computed" in text for text in info["limitations"]))

    def test_hash_present_has_no_skip_limitation(self):
        info = self._identify(b"short\n", "t.txt")
        self.assertIsNotNone(info["sha256"])
        self.assertFalse(any("sha256" in text for text in info["limitations"]))


if __name__ == "__main__":
    unittest.main()
