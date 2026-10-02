"""Regression test for the same silent-under-reporting defect class fixed
2026-09-27 in ``tools_import_xrefs.py`` (root cause: ``Cs.disasm()`` -- one
native ``cs_disasm()`` call -- STOPS at the first byte it cannot decode
instead of skipping and resynchronising), found here in
``tools_binary.disassemble_pe``: a plain-text linear disassembly listing
used by ``ioctl_recovery.py`` and ``tools_native.py``. Without ``skipdata``,
one undecodable byte early in a section silently truncates the listing to
far fewer lines than ``max_instructions`` requested, with no error and no
indication real code continues past the gap.

The PE comes from the shared builder in ``tests/_pe_fixtures.py``.
"""
import shutil
import unittest
from pathlib import Path

from liebert_re.tools.binary import disassemble_pe
from tests import _pe_fixtures
from tests._pe_fixtures import build_pe

# tools_binary.disassemble_pe -> safe_path enforces WORKSPACE (repo root)
# containment, so the fixture must live under the repo, not the OS temp dir.
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_DIR = REPO_ROOT / "dataset" / "runtime" / "_test_disassemble_pe_skipdata_scratch"

# The builder lives in tests/_pe_fixtures.py (shared with test_pe_resources.py); this name is kept
# so the call sites below read as before.
_build_minimal_exec_pe = build_pe

IMAGE_BASE = _pe_fixtures.IMAGE_BASE
SECTION_RVA = _pe_fixtures.SECTION_RVA


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
