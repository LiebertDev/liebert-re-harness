"""_executable_ranges: VirtualSize is the code extent (not rounded up to
SectionAlignment), and VirtualSize == 0 falls back to SizeOfRawData instead of
producing an empty range that silently truncates every vtable."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from liebert_re.tools.cpp_rtti import IMAGE_SCN_MEM_EXECUTE, _executable_ranges, _in_executable_range


def _image(*sections):
    return SimpleNamespace(base=0x400000, pe=SimpleNamespace(sections=list(sections)))


def _sec(va, vsize, raw, flags=IMAGE_SCN_MEM_EXECUTE):
    return SimpleNamespace(VirtualAddress=va, Misc_VirtualSize=vsize, SizeOfRawData=raw, Characteristics=flags)


class ExecutableRanges(unittest.TestCase):
    def test_range_is_virtual_size_not_alignment_padding(self):
        ranges = _executable_ranges(_image(_sec(0x1000, 0x180, 0x200)))
        self.assertEqual(ranges, [(0x401000, 0x401180)])
        self.assertTrue(_in_executable_range(0x40117F, ranges))
        self.assertFalse(_in_executable_range(0x401180, ranges))

    def test_zero_virtual_size_falls_back_to_raw_size(self):
        ranges = _executable_ranges(_image(_sec(0x1000, 0, 0x200)))
        self.assertEqual(ranges, [(0x401000, 0x401200)])

    def test_non_executable_section_excluded(self):
        self.assertEqual(_executable_ranges(_image(_sec(0x1000, 0x100, 0x200, flags=0))), [])


if __name__ == "__main__":
    unittest.main()
