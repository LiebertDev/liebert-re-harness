"""rip_relative_iat_scan (liebert_re/tools/binary.py): which imports a binary calls through its address table.

A byte-pattern first pass, no disassembler. Three outcomes never share a code: FOUND (findings, each
proves_call false), NOT_FOUND (looked, nothing resolved to an import -- a result, not an error) and
NOT_LOOKED (could not read the PE / import directory / code -- ok false with its own error code).
The target must land on an import-table slot; a reference elsewhere is never a finding.
Fixtures are built in code; no real driver is read.
"""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools.binary import rip_relative_iat_scan

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
TEXT_RAW = 0x400    # file offset of .text (RVA 0x1000)
TEXT_RVA = 0x1000
IMPORTS = {"ntoskrnl.exe": ["IoCreateDevice", "IoDeleteDevice"]}
_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def slots(path):
    import pefile
    pe = pefile.PE(str(path))
    base = pe.OPTIONAL_HEADER.ImageBase
    out = [int(m.address) - base for d in pe.DIRECTORY_ENTRY_IMPORT for m in d.imports]
    pe.close()
    return out


def rip(opcode, at, target_rva):
    """FF 15 / FF 25 placed at .text offset ``at`` that reaches ``target_rva`` through RIP."""
    return at, bytes([0xFF, opcode]) + struct.pack("<i", target_rva - (TEXT_RVA + at + 6))


def make(name, patches=(), imports=IMPORTS, **kw):
    path = build_owned_pe_sections(ROOT / name, subsystem=1, imports=imports, **kw)
    data = bytearray(path.read_bytes())
    for at, code in patches:
        data[TEXT_RAW + at:TEXT_RAW + at + len(code)] = code
    path.write_bytes(bytes(data))
    return path


def scan(path, **kw):
    return json.loads(rip_relative_iat_scan(str(path), **kw))


class RipRelativeIatScanTests(unittest.TestCase):
    def setUp(self):
        self.slot0, self.slot1 = slots(make("probe.sys"))

    def test_call_through_a_slot_names_the_import(self):
        body = scan(make("call.sys", [rip(0x15, 0x10, self.slot0)]))
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "FOUND")
        (f,) = body["findings"]
        self.assertEqual(f["call_rva"], hex(TEXT_RVA + 0x10))
        self.assertEqual(f["encoding"], "FF15")
        self.assertEqual(f["slot_rva"], hex(self.slot0))
        self.assertEqual(f["import"], "ntoskrnl.exe!IoCreateDevice")
        self.assertIs(f["proves_call"], False)
        self.assertIs(body["proves_call"], False)

    def test_jump_through_a_slot_is_found(self):
        body = scan(make("jmp.sys", [rip(0x25, 0x20, self.slot1)]))
        self.assertEqual(body["outcome"], "FOUND")
        (f,) = body["findings"]
        self.assertEqual(f["encoding"], "FF25")
        self.assertEqual(f["import"], "ntoskrnl.exe!IoDeleteDevice")

    def test_reference_outside_the_address_table_is_not_a_finding(self):
        # Same bytes, but the target is code (.text) and, separately, the import descriptor area of
        # .rdata (inside the section, not a slot). Neither is an import call.
        patches = [rip(0x15, 0x10, TEXT_RVA + 0x100), rip(0x25, 0x20, 0x2000)]
        body = scan(make("outside.sys", patches))
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["findings"], [])

    def test_in_range_reference_is_found_beside_the_outside_one(self):
        patches = [rip(0x15, 0x10, TEXT_RVA + 0x100), rip(0x15, 0x30, self.slot1)]
        body = scan(make("mixed.sys", patches))
        self.assertEqual([f["import"] for f in body["findings"]], ["ntoskrnl.exe!IoDeleteDevice"])

    def test_no_import_directory_is_not_found_and_not_an_error(self):
        body = scan(make("noimp.sys", [(0x10, b"\xFF\x15\x00\x10\x00\x00")], imports=None))
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["reason"], "NO_IMPORT_DIRECTORY")
        self.assertEqual(body["findings"], [])
        self.assertNotIn("error", body)

    def test_unreadable_import_directory_is_not_looked(self):
        body = scan(make("badimp.sys", imports=None, bad_import_rva=True))
        self.assertFalse(body["ok"])
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertEqual(body["error"], "IMPORT_DIRECTORY_UNREADABLE")

    def test_not_looked_and_not_found_never_share_a_code(self):
        miss = scan(make("miss.sys"))
        bad = scan(make("badimp2.sys", imports=None, bad_import_rva=True))
        self.assertEqual(miss["outcome"], "NOT_FOUND")
        self.assertEqual(bad["outcome"], "NOT_LOOKED")
        self.assertNotEqual(miss["outcome"], bad["outcome"])
        self.assertTrue(miss["ok"])
        self.assertFalse(bad["ok"])

    def test_no_executable_section_is_not_looked(self):
        body = scan(make("nocode.sys", sections=((".data", 0xC0000040),)))
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertEqual(body["error"], "CODE_SECTION_UNREADABLE")

    def test_invalid_pe_is_refused_with_its_own_code(self):
        p = ROOT / "junk.sys"
        p.write_bytes(b"not a pe at all")
        body = scan(p)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "INVALID_PE")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_missing_file_is_refused(self):
        body = scan(ROOT / "nonexistent.sys")
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "FILE_NOT_FOUND")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_unsupported_machine_is_refused(self):
        body = scan(make("arm.sys", machine=0xAA64))
        self.assertEqual(body["error"], "UNSUPPORTED_MACHINE")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_truncation_is_reported_when_the_limit_fills(self):
        patches = [rip(0x15, 6 * i, self.slot0) for i in range(8)]
        body = scan(make("many.sys", patches), max_findings=3)
        self.assertEqual(len(body["findings"]), 3)
        t = body["truncation"]
        self.assertIs(t["truncated"], True)
        self.assertEqual(t["limit"], 3)
        self.assertEqual(t["limit_name"], "max_findings")
        self.assertEqual(t["found_total"], 8)
        self.assertEqual(t["returned"], 3)
        self.assertEqual(t["omitted"], 5)
        self.assertTrue(any("omitted" in r for r in body["rationale"]))

    def test_no_truncation_below_the_limit(self):
        body = scan(make("few.sys", [rip(0x15, 0, self.slot0)]), max_findings=3)
        self.assertIs(body["truncation"]["truncated"], False)
        self.assertEqual(body["truncation"]["omitted"], 0)

    def test_x86_ff15_is_an_absolute_address_not_rip_relative(self):
        # x86 FF 15 is call [abs32]. The scan maps disp32 - ImageBase to a slot; it never adds the
        # instruction end. The fixture is patched to a 32-bit-sized image base and machine.
        base = 0x10000000
        slot = self.slot0

        def x86(name, disp):
            path = make(name, [(0x10, b"\xFF\x15" + struct.pack("<I", disp))], machine=0x14C)
            data = bytearray(path.read_bytes())
            struct.pack_into("<Q", data, 64 + 4 + 20 + 24, base)
            path.write_bytes(bytes(data))
            return scan(path)

        body = x86("x86abs.sys", base + slot)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual(body["entry"]["architecture"], "x86")
        (f,) = body["findings"]
        self.assertEqual(f["import"], "ntoskrnl.exe!IoCreateDevice")
        self.assertEqual(f["target_basis"], "absolute_disp32")
        # The bytes an x64 RIP-relative reading would resolve to this slot are NOT a hit on x86.
        rel = (slot - (TEXT_RVA + 0x10 + 6)) & 0xFFFFFFFF
        self.assertEqual(x86("x86rip.sys", rel)["outcome"], "NOT_FOUND")

    def test_x64_findings_say_rip_relative(self):
        body = scan(make("basis.sys", [rip(0x15, 0, self.slot0)]))
        self.assertEqual(body["findings"][0]["target_basis"], "rip_relative")

    def test_nothing_claims_certainty_anywhere(self):
        body = scan(make("cert.sys", [rip(0x15, 0, self.slot0)]))
        self.assertNotIn('"proves_call": true', json.dumps(body).lower())
        self.assertTrue(body["caveats"])
        self.assertIn("heuristic", body["findings"][0]["confidence"])


if __name__ == "__main__":
    unittest.main()
