"""Regression for GAP 2 found solving a real external ConfuserEx crackme
(benchmarks/real_corpora/cm1_confuserex_userpass/extracted/CrackMeV1.exe;
solve evidence: dataset/evidence/confuserex_dotnet_userpass_solved_20260925.json).

DEFECT (dotnet_il.py): the hand-transcribed single-byte/0xFE-prefixed
two-byte IL opcode table only covered a subset of ECMA-335 (22 of 54
opcodes seen in one real method, e.g. Main, came back UNSUPPORTED_OPCODE:
0xd0 ldtoken, 0x74 castclass, 0x8e ldlen, 0x91 ldelem.i4, 0x60 or, 0x62 shl,
0xa2 stelem.ref, 0xa5 ldelem, 0xfe06 ldftn, ...). Because IL instructions
are variable-length, the first UNSUPPORTED opcode desynchronised every byte
offset after it -- the old code then `continue`d decoding at the wrong
offset anyway, producing a complete-looking but silently wrong
disassembly (this project's worst failure mode) rather than stopping.

Fixed by:
  1. Deriving the complete opcode table from `dncil` (the FLARE team's
     Apache-2.0 ECMA-335 CIL opcode/reader library, used by capa) instead of
     hand-transcribing ECMA-335 -- covers all 227 real one-/two-byte
     mnemonics, including the previously-entirely-missing InlineSwitch
     variable-length operand.
  2. Making an unrecognised opcode STOP the walk (explicit
     UNSUPPORTED_OPCODE error, loop breaks) instead of continuing at a
     guessed offset -- kept even with the complete table, since a
     genuinely malformed/obfuscated stream can still desync.

These tests fail against the pre-fix `dotnet_il.py` (proven live this
session via `git stash push -- dotnet_il.py`: Decrypt (0x06000001) in
CrackMeV1.exe returns unsupported_opcodes=100 out of the 54-method sample's
348 total UNSUPPORTED_OPCODE events across 55 distinct opcodes) and pass
against the fix (0 UNSUPPORTED_OPCODE events across the same 54 methods).
"""
import json
import unittest
from pathlib import Path

import tools_workspace
from dotnet_il import parse_dotnet_il, parse_il_body

TARGET = Path(tools_workspace.WORKSPACE) / "benchmarks" / "real_corpora" / "cm1_confuserex_userpass" / "extracted" / "CrackMeV1.exe"
# Decrypt() in CrackMeV1.exe -- real, measured evidence: 100 of its own
# UNSUPPORTED_OPCODE events out of the 348 total across the 54-method sample
# came from this one method under the pre-fix incomplete table.
DESYNCED_METHOD_TOKEN = "0x06000001"


@unittest.skipUnless(TARGET.exists(), "real corpus target CrackMeV1.exe missing (Defender has transiently quarantined it this session)")
class DotnetIlOpcodeCoverageTests(unittest.TestCase):
    def test_previously_desynced_method_now_decodes_cleanly(self):
        report = parse_dotnet_il(str(TARGET), method_name="Decrypt", max_methods=5)
        self.assertTrue(report.get("ok"), report)
        matches = [m for m in report["il_methods"] if m.get("token") == DESYNCED_METHOD_TOKEN]
        self.assertEqual(len(matches), 1, report["il_methods"])
        method = matches[0]
        self.assertEqual(method["unsupported_opcodes"], 0, method)
        self.assertTrue(method["ok"], method)
        self.assertGreater(len(method["instructions"]), 300)

    def test_full_method_sample_has_zero_unsupported_opcodes(self):
        report = parse_dotnet_il(str(TARGET), max_methods=60)
        self.assertTrue(report.get("ok"), report)
        self.assertEqual(len(report["il_methods"]), 54)
        total_unsupported = sum(m.get("unsupported_opcodes", 0) for m in report["il_methods"])
        self.assertEqual(total_unsupported, 0, report["il_methods"])

    def test_unrecognised_opcode_stops_the_walk_instead_of_guessing(self):
        # Tiny-header method body: nop (0x00), a genuinely reserved/unused
        # one-byte opcode (0x24 -- confirmed via dncil.cil.opcode.OpCodes to
        # be an UNKNOWN1 filler slot, never a real mnemonic), then ret
        # (0x2A). code_size=3 -> tiny header byte = (3 << 2) | 0x02.
        data = bytes([0x0E, 0x00, 0x24, 0x2A])
        result = parse_il_body(data, 0)
        self.assertEqual(len(result["instructions"]), 2)
        self.assertEqual(result["instructions"][0]["mnemonic"], "nop")
        self.assertEqual(result["instructions"][1]["mnemonic"], "UNSUPPORTED_OPCODE")
        self.assertEqual(result["instructions"][1]["opcode"], "0x24")
        # The walk must have STOPPED at the unknown opcode -- the trailing
        # `ret` byte must never have been reached/decoded as if nothing
        # were wrong.
        self.assertEqual(result["unsupported_opcodes"], 1)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["error"], "UNSUPPORTED_OPCODE")


if __name__ == "__main__":
    unittest.main()
