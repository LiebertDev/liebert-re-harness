"""Regression test for the same silent-under-reporting defect class fixed
2026-09-27 in ``tools_import_xrefs.py`` (root cause: ``Cs.disasm()`` -- one
native ``cs_disasm()`` call -- STOPS at the first byte it cannot decode
instead of skipping and resynchronising), found here in
``tools_binary.disassemble_pe``: a plain-text linear disassembly listing
used by ``ioctl_recovery.py`` and ``tools_native.py``. Without ``skipdata``,
one undecodable byte early in a section silently truncates the listing to
far fewer lines than ``max_instructions`` requested, with no error and no
indication real code continues past the gap.

Self-contained PE builder (does not touch ``tests/fixtures_pe_builder.py``),
following the same pattern as ``tests/test_import_xrefs_sweep_budget.py``.
"""
import shutil
import struct
import unittest
from pathlib import Path

from liebert_re.tools.binary import disassemble_pe

# tools_binary.disassemble_pe -> safe_path enforces WORKSPACE (repo root)
# containment, so the fixture must live under the repo, not the OS temp dir.
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_DIR = REPO_ROOT / "dataset" / "runtime" / "_test_disassemble_pe_skipdata_scratch"

IMAGE_BASE = 0x00400000
SECTION_RVA = 0x1000
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADER_SIZE = 0x200


def _build_minimal_exec_pe(code: bytes) -> bytes:
    """A minimal 32-bit PE with exactly one executable section holding
    ``code`` verbatim (padded to file alignment). See
    ``tests/test_import_xrefs_sweep_budget.py``'s identical builder for the
    full field-by-field rationale; duplicated here to stay self-contained."""
    section_size = (len(code) + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)
    section_size = max(section_size, FILE_ALIGNMENT)
    section = bytearray(section_size)
    section[:len(code)] = code

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)

    file_header = struct.pack("<HHIIIHH",
                              0x014C,   # i386
                              1,        # one section
                              0, 0, 0,
                              0xE0,     # size of optional header
                              0x0102)   # executable, 32-bit

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B, 0, 0,          # PE32
        len(code), 0, 0,
        SECTION_RVA,            # entry point (unused -- code is never run)
        SECTION_RVA, 0,
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        4, 0, 0, 0, 4, 0,      # versions
        0,                     # win32 version
        SECTION_RVA + section_size,   # size of image
        HEADER_SIZE,           # size of headers
        0,                     # checksum
        3, 0,                  # subsystem CONSOLE, dll characteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16)                 # loader flags, number of data directories

    directories = bytearray(16 * 8)  # all zero: no import/export/etc directories

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        section_size, SECTION_RVA,
        section_size, HEADER_SIZE,
        0, 0, 0, 0,
        0x60000020)  # code, executable, readable

    headers = bytearray(HEADER_SIZE)
    headers[0:0x40] = dos
    at = 0x40
    headers[at:at + 4] = b"PE\x00\x00"
    at += 4
    headers[at:at + len(file_header)] = file_header
    at += len(file_header)
    headers[at:at + len(optional)] = optional
    at += len(optional)
    headers[at:at + len(directories)] = directories
    at += len(directories)
    headers[at:at + len(section_header)] = section_header

    return bytes(headers) + bytes(section)


class DisassemblePeSkipdataTests(unittest.TestCase):
    def _code(self):
        # 0xF0 (LOCK) immediately followed by NOP is undecodable by this
        # repo's pinned capstone/CS_MODE_32 combination (empirically
        # verified in tests/test_import_xrefs_sweep_budget.py) and desyncs
        # a plain disasm() call. A real ``inc eax`` follows it.
        return b"\x90" * 2 + b"\xf0\x90" + b"\x40" + b"\x90" * 2

    def test_sanity_without_skipdata_the_instruction_is_never_reached(self):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True  # skipdata deliberately left at its default (False)
        insns = list(md.disasm(self._code(), IMAGE_BASE + SECTION_RVA))
        self.assertTrue(all(insn.mnemonic != "inc" for insn in insns),
                         "sanity check: without skipdata this fixture's real instruction is not reached")

    def test_real_instruction_after_undecodable_byte_is_not_silently_dropped(self):
        SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        path = SCRATCH_DIR / "fixture.exe"
        try:
            path.write_bytes(_build_minimal_exec_pe(self._code()))
            out = disassemble_pe(str(path), max_instructions=10)
        finally:
            shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
        self.assertIn("inc eax", out,
                       "the real instruction after the undecodable byte must still be found "
                       "-- this is exactly the line the pre-fix listing would have silently dropped")
        self.assertIn(".byte", out,
                      "the undecodable byte must show up honestly as a .byte pseudo-line, "
                      "never silently absorbed into the listing as if it were real code")


if __name__ == "__main__":
    unittest.main()
