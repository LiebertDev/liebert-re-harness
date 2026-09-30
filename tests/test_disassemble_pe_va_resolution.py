"""tools_binary.disassemble_pe `va` parameter (Tier2 remediation roadmap
Priority 3, Problem B: automate the manual raw-disassembly-fallback
technique).

Previously a caller with only a function's virtual address (e.g. from
ghidra_query's list_functions/decompile_function) had to manually compute
the containing section + in-section start_offset via native_inspect's
per-section RVA/raw-offset table before calling disassemble_pe (a real,
repeatedly hand-done step -- see WNL-T2-040/WNL-T2-073's manual
raw-disassembly fallbacks). `va` now resolves this internally.

Reuses the existing owned PE32 fixture built for the Phase 5 item 1
cfg_deobfuscate x86-32 regression (benchmarks/dynamic_fixtures/
owned_cfg_deobfuscate_x86_32_loop/) rather than building a new one --
its known instruction layout (mov ecx,5 / nop / loop / ret) is exactly
what's needed to prove va-based lookup lands on the right byte.
"""
from __future__ import annotations

import json
import unittest
import zipfile
from pathlib import Path

from tools_binary import disassemble_pe

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "dynamic_fixtures" / "owned_cfg_deobfuscate_x86_32_loop"
FIXTURE_EXE = FIXTURE_DIR / "loop32_fixture.exe"
FIXTURE_ADDRESSES = FIXTURE_DIR / "loop32_fixture_addresses.json"

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH_DIR = REPO_ROOT / "dataset" / "runtime" / "_test_disassemble_pe_scratch"


@unittest.skipUnless(FIXTURE_EXE.exists() and FIXTURE_ADDRESSES.exists(), "owned loop32 fixture not present")
class DisassemblePeVaResolutionTests(unittest.TestCase):
    def setUp(self):
        self.addrs = json.loads(FIXTURE_ADDRESSES.read_text(encoding="utf-8"))

    def test_va_at_function_entry_matches_default_entry_point_disassembly(self):
        by_entry = disassemble_pe(str(FIXTURE_EXE), max_instructions=4)
        by_va = disassemble_pe(str(FIXTURE_EXE), va=self.addrs["entry_mov_ecx_5"], max_instructions=4)
        self.assertEqual(by_entry, by_va)
        self.assertIn("mov ecx, 5", by_va)

    def test_va_mid_function_lands_on_the_correct_instruction(self):
        out = disassemble_pe(str(FIXTURE_EXE), va=self.addrs["loop_top_nop"], max_instructions=3)
        lines = out.splitlines()
        self.assertEqual(lines[0], "0x401005: nop")
        self.assertEqual(lines[1], "0x401006: loop 0x401005")
        self.assertEqual(lines[2], "0x401008: ret")

    def test_va_accepts_decimal_string_and_int_not_just_0x_hex(self):
        va_int = int(self.addrs["loop_instruction"], 16)
        out_hex = disassemble_pe(str(FIXTURE_EXE), va=self.addrs["loop_instruction"], max_instructions=1)
        out_int = disassemble_pe(str(FIXTURE_EXE), va=va_int, max_instructions=1)
        out_dec_str = disassemble_pe(str(FIXTURE_EXE), va=str(va_int), max_instructions=1)
        self.assertEqual(out_hex, out_int)
        self.assertEqual(out_hex, out_dec_str)
        self.assertIn("loop 0x401005", out_hex)

    def test_va_outside_any_section_fails_gracefully_not_an_exception(self):
        result = disassemble_pe(str(FIXTURE_EXE), va="0xdeadbeef", max_instructions=5)
        self.assertIn("bulunamadi", result)

    def test_va_takes_precedence_over_stale_section_start_offset_args(self):
        # A caller passing both va and a leftover section/start_offset from
        # a previous manual call should get the va-resolved location, not
        # the stale manual one silently mixed in.
        out = disassemble_pe(str(FIXTURE_EXE), section="bogus_section", start_offset=999, va=self.addrs["done_ret"], max_instructions=1)
        self.assertEqual(out.strip(), "0x401008: ret")


# --------------------------------------------------------------------------
# DEFECT 3 fix: a non-PE input (e.g. a zip -- the exact case observed
# against a real ConfuserEx target's companion archive) must fail the same
# way disassemble_pe's OTHER failure paths already do -- a plain,
# human-readable error string, never an uncaught pefile.PEFormatError. See
# ioctl_recovery.py's own _parse_disassembly_lines docstring, which already
# documents and relies on "disassemble_pe returns a plain human-readable
# error string ... never raises" as this function's established contract;
# dotnet_inspect (tools_dotnet.py) handles the identical bad-input case via
# its own distinct JSON error vocabulary, so this stays plain text rather
# than switching shapes mid-function.
# --------------------------------------------------------------------------

class DisassemblePeNonPeInputTests(unittest.TestCase):
    def setUp(self):
        SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self.zip_path = SCRATCH_DIR / "__not_a_pe__.zip"
        with zipfile.ZipFile(self.zip_path, "w") as zf:
            zf.writestr("readme.txt", "this is a zip, not a PE")

    def tearDown(self):
        self.zip_path.unlink(missing_ok=True)

    def test_zip_input_never_raises_and_returns_a_plain_error_string(self):
        # Must not raise pefile.PEFormatError -- previously uncaught.
        result = disassemble_pe(str(self.zip_path))
        self.assertIsInstance(result, str)
        self.assertNotIn("Traceback", result)

    def test_zip_input_error_text_names_the_real_cause(self):
        result = disassemble_pe(str(self.zip_path))
        self.assertIn("PE", result)

    def test_truncated_pe_header_also_fails_gracefully(self):
        truncated = SCRATCH_DIR / "__truncated__.exe"
        truncated.write_bytes(b"MZ" + b"\x00" * 10)
        try:
            result = disassemble_pe(str(truncated))
            self.assertIsInstance(result, str)
            self.assertNotIn("Traceback", result)
        finally:
            truncated.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool or spawns a bounded subprocess -- these can be
# slow or hang, so they are excluded from the default run and must be run explicitly
# with `pytest -m heavy`. See pytest.ini in this repo for the tools actually involved.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
