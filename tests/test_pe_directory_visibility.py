"""pe_imports / pe_exports must tell "no directory" from "directory I could not read".

pefile does not normally raise on a corrupt import/export directory: it records a
warning and leaves DIRECTORY_ENTRY_* unset, which used to look identical to a PE
that genuinely has none. These tests build real synthetic PEs (no shipped binary)
and prove the two cases now differ.
"""
import struct
import unittest
from pathlib import Path

import tools_workspace
from owned_binary_fixtures import build_owned_pe_with_rsds
from tools_binary import pe_exports, pe_imports

# Data directories start at optional-header offset 112; the optional header starts
# at file offset 88 (64-byte DOS stub + "PE\0\0" + 20-byte COFF header).
_DD = 88 + 112
_EXPORT, _IMPORT = _DD, _DD + 8


def _build(path: Path, *, import_dir=None, export_dir=None, truncate_to=None) -> Path:
    build_owned_pe_with_rsds(path)
    data = bytearray(path.read_bytes())
    if import_dir:
        struct.pack_into("<II", data, _IMPORT, *import_dir)
    if export_dir:
        struct.pack_into("<II", data, _EXPORT, *export_dir)
    if truncate_to:
        data = data[:truncate_to]
    path.write_bytes(bytes(data))
    return path


class PeDirectoryVisibilityTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)

    def test_genuinely_absent_directories_keep_the_plain_message(self):
        p = _build(self.dir / "none.exe")
        self.assertEqual(pe_imports(str(p)), "Import tablosu yok.")
        self.assertEqual(pe_exports(str(p)), "Export tablosu yok.")

    def test_corrupt_import_directory_is_not_reported_as_absent(self):
        p = _build(self.dir / "bad.exe", import_dir=(0x90000000, 40))
        out = pe_imports(str(p))
        self.assertNotEqual(out, "Import tablosu yok.")
        self.assertTrue(out.startswith("IMPORT_DIRECTORY_UNREADABLE"), out)
        self.assertIn("declared", out)

    def test_truncated_import_descriptor_is_not_reported_as_absent(self):
        # Descriptor slot starts 20 bytes before end of file -> short read.
        p = _build(self.dir / "trunc.exe", import_dir=(0x13F0, 40), truncate_to=0x5F8)
        out = pe_imports(str(p))
        self.assertTrue(out.startswith("IMPORT_DIRECTORY_UNREADABLE"), out)

    def test_corrupt_export_directory_is_not_reported_as_absent(self):
        p = _build(self.dir / "badx.exe", export_dir=(0x90000000, 40))
        out = pe_exports(str(p))
        self.assertNotEqual(out, "Export tablosu yok.")
        self.assertTrue(out.startswith("EXPORT_DIRECTORY_UNREADABLE"), out)

    def test_the_two_cases_are_distinguishable_for_both_functions(self):
        good = _build(self.dir / "a.exe")
        bad = _build(self.dir / "b.exe", import_dir=(0x90000000, 40),
                     export_dir=(0x90000000, 40))
        self.assertNotEqual(pe_imports(str(good)), pe_imports(str(bad)))
        self.assertNotEqual(pe_exports(str(good)), pe_exports(str(bad)))


if __name__ == "__main__":
    unittest.main()
