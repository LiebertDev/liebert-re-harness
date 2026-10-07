"""pe_imports / pe_exports must tell "no directory" from "directory I could not read".

pefile does not normally raise on a corrupt import/export directory: it records a
warning and leaves DIRECTORY_ENTRY_* unset, which used to look identical to a PE
that genuinely has none. These tests build real synthetic PEs (no shipped binary)
and prove the two cases now differ.
"""
import struct
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_rsds
from liebert_re.tools.binary import pe_exports, pe_imports

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
        self.assertEqual(pe_imports(str(p)), "EMPTY_RESULT: No import table.")
        self.assertEqual(pe_exports(str(p)), "EMPTY_RESULT: No export table.")

    def test_corrupt_import_directory_is_not_reported_as_absent(self):
        p = _build(self.dir / "bad.exe", import_dir=(0x90000000, 40))
        out = pe_imports(str(p))
        self.assertNotEqual(out, "EMPTY_RESULT: No import table.")
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
        self.assertNotEqual(out, "EMPTY_RESULT: No export table.")
        self.assertTrue(out.startswith("EXPORT_DIRECTORY_UNREADABLE"), out)

    def test_the_two_cases_are_distinguishable_for_both_functions(self):
        good = _build(self.dir / "a.exe")
        bad = _build(self.dir / "b.exe", import_dir=(0x90000000, 40),
                     export_dir=(0x90000000, 40))
        self.assertNotEqual(pe_imports(str(good)), pe_imports(str(bad)))
        self.assertNotEqual(pe_exports(str(good)), pe_exports(str(bad)))


class TruncationMarkerTests(unittest.TestCase):
    """A list cut at its cap says so: that it was cut, what came back, the cap and the total."""

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)

    def test_strings_over_the_cap_carry_a_marker_with_the_true_total(self):
        from liebert_re.tools.binary import binary_strings
        p = self.dir / "s.bin"
        p.write_bytes(b"\x00".join(b"string_number_%03d" % i for i in range(12)))
        cut = binary_strings(str(p), max_results=5)
        self.assertIn("[limit:5; truncated=true; returned=5; total=12]", cut)
        self.assertEqual(len([ln for ln in cut.splitlines() if ln.startswith("0x")]), 5)
        whole = binary_strings(str(p), max_results=12)
        self.assertNotIn("truncated", whole)

    def test_binary_and_byte_searches_mark_a_cut_and_only_a_cut(self):
        from liebert_re.tools.binary import find_binaries, search_binary_bytes
        for i in range(4):
            (self.dir / f"b{i}.exe").write_bytes(b"MZ" * 4)
        cut = find_binaries(str(self.dir), max_results=3)
        self.assertIn("[limit:3; truncated=true; returned=3; total=unknown (more exist)]", cut)
        self.assertNotIn("truncated", find_binaries(str(self.dir), max_results=4))
        p = self.dir / "b0.exe"
        self.assertIn("truncated=true; returned=2", search_binary_bytes(str(p), "4D 5A", max_results=2))
        self.assertNotIn("truncated", search_binary_bytes(str(p), "4D 5A", max_results=4))

    def test_exports_over_the_cap_carry_a_marker_with_the_total(self):
        import liebert_re.tools.binary as binary

        class Symbol:
            def __init__(self, i):
                self.name, self.address, self.ordinal = b"fn%d" % i, 0x1000 + i, i

        class Export:
            symbols = [Symbol(i) for i in range(7)]

        class FakePe:
            DIRECTORY_ENTRY_EXPORT = Export()

        with mock.patch.object(binary, "_pe", return_value=FakePe()), \
                mock.patch.object(binary, "_parse_directories", return_value=None), \
                mock.patch.object(binary, "_directory_problem", return_value=None):
            cut = binary.pe_exports(str(self.dir), max_results=3)
            whole = binary.pe_exports(str(self.dir), max_results=7)
        self.assertIn("[limit:3; truncated=true; returned=3; total=7]", cut)
        self.assertEqual(len(whole.splitlines()), 7)
        self.assertNotIn("truncated", whole)

    def test_workspace_listings_mark_a_cut(self):
        for i in range(12):
            (self.dir / f"f{i}.txt").write_text("x", encoding="utf-8")
        with mock.patch.object(tools_workspace, "MAX_FIND_RESULTS", 5):
            cut = tools_workspace.find_files("*.txt", str(self.dir))
        self.assertIn("[limit:5; truncated=true; returned=5; total=unknown (more exist)]", cut)
        paths = [str(self.dir / f"f{i}.txt") for i in range(12)]
        text = tools_workspace.read_files(paths)
        self.assertIn("[limit:10; truncated=true; returned=10; total=12]", text)
        self.assertNotIn("truncated", tools_workspace.read_files(paths[:10]))

    def test_msf_unresolved_symbols_report_their_true_count(self):
        from liebert_re.recover.msf_pdb import resolve_public_symbol_rvas
        symbols = [{"name": f"s{i}", "segment": 9, "offset": i} for i in range(70)]
        result = resolve_public_symbol_rvas(symbols, [])
        self.assertEqual((len(result["unresolved"]), result["unresolved_count"], result["unresolved_truncated"]), (64, 70, True))


if __name__ == "__main__":
    unittest.main()
