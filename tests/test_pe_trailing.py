"""pe_trailing_data (liebert_re/tools/pe_trailing.py): what lies past the end of the last section.

Fixtures are built in code from ``tests._pe_fixtures.build_pe`` (a 32-bit PE whose one ``.text``
section ends at file offset 0x400), with trailing bytes appended and header fields patched. No
binary is committed. One test reads a real signed system binary in place, read-only, and skips
when the machine has none.
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.report import tool_families
from liebert_re.tools.pe_trailing import pe_trailing_data
from tests._pe_fixtures import build_pe, pseudo_random_bytes

PTR_SYMTAB = 0x44 + 8
NUM_SYMS = 0x44 + 12
NUM_SECTIONS = 0x44 + 2
SECURITY_DIR = 0x58 + 96 + 4 * 8
END_OF_SECTIONS = 0x400


def _coff(count: int, strtab_length: int | None = None, extra_names: bytes = b"") -> bytes:
    """``count`` 18-byte symbol records, then the string table (4-byte length prefix + names)."""
    names = extra_names or b"\0" * 6
    length = 4 + len(names) if strtab_length is None else strtab_length
    return b"\x2e" * (count * 18) + struct.pack("<I", length) + names


def _cert(total: int) -> bytes:
    """One WIN_CERTIFICATE (dwLength, revision 2.0, PKCS#7) of ``total`` bytes, a multiple of 8."""
    return struct.pack("<IHH", total, 0x0200, 0x0002) + b"\xa5" * (total - 8)


def _patch(pe: bytes, **fields) -> bytes:
    data = bytearray(pe)
    for key, value in fields.items():
        offset = {"symtab": PTR_SYMTAB, "nsyms": NUM_SYMS, "nsections": NUM_SECTIONS}.get(key)
        if offset is not None:
            struct.pack_into("<H" if key == "nsections" else "<I", data, offset, value)
    if "security" in fields:
        struct.pack_into("<II", data, SECURITY_DIR, *fields["security"])
    return bytes(data)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def run_on(self, content: bytes, name: str = "t.exe") -> dict:
        path = self.dir / name
        path.write_bytes(content)
        return json.loads(pe_trailing_data(str(path)))


class OutcomeTests(_Base):
    def test_no_trailing_data(self):
        r = self.run_on(build_pe())
        self.assertEqual((r["ok"], r["status"]), (True, "NO_TRAILING_DATA"))
        self.assertEqual(r["trailing"], {"exists": False, "offset": END_OF_SECTIONS, "size": 0, "fraction_of_file": 0.0})
        self.assertEqual((r["attributed"], r["unattributed"]), ([], []))

    def test_unknown_trailing_data_reports_numbers_and_no_verdict(self):
        tail = pseudo_random_bytes(1024)
        r = self.run_on(build_pe() + tail)
        self.assertEqual((r["ok"], r["status"]), (True, "TRAILING_UNKNOWN"))
        self.assertEqual(r["trailing"]["offset"], END_OF_SECTIONS)
        self.assertEqual(r["trailing"]["size"], 1024)
        self.assertAlmostEqual(r["trailing"]["fraction_of_file"], 1024 / (END_OF_SECTIONS + 1024), places=4)
        (unknown,) = r["unattributed"]
        self.assertEqual(unknown["purpose"], "UNKNOWN")
        self.assertIsInstance(unknown["entropy_bits_per_byte"], float)
        self.assertGreater(unknown["entropy_bits_per_byte"], 7.0)
        self.assertEqual(r["attributed"], [])
        verdictless = {k: v for k, v in r.items() if k != "statement"}  # the statement itself negates the verdict words
        self.assertNotRegex(json.dumps(verdictless).lower(), r"malicious|benign|payload|packed|encrypted|debug data")

    def test_low_entropy_tail_is_equally_unknown(self):
        r = self.run_on(build_pe() + b"\0" * 512)
        self.assertEqual(r["status"], "TRAILING_UNKNOWN")
        self.assertEqual(r["unattributed"][0]["entropy_bits_per_byte"], 0.0)
        self.assertIs(r["unattributed"][0]["all_zero"], True)
        self.assertEqual(r["unattributed"][0]["purpose"], "UNKNOWN")

    def test_coff_symbol_table_that_fits_is_fully_attributed_as_consistent_with(self):
        table = _coff(5, extra_names=b"_main\0_start\0")
        r = self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=5) + table)
        self.assertEqual((r["ok"], r["status"]), (True, "TRAILING_FULLY_ATTRIBUTED"))
        coff = r["coff_symbol_table"]
        self.assertEqual(coff["state"], "CONSISTENT")
        self.assertEqual(coff["expected_size"], len(table))
        self.assertIn("consistent with", coff["note"])
        self.assertNotIn(" is a COFF", coff["note"])
        self.assertEqual(r["attributed"][0]["kind"], "COFF_SYMBOL_AND_STRING_TABLE")
        self.assertEqual((r["attributed"][0]["offset"], r["attributed"][0]["size"]), (END_OF_SECTIONS, len(table)))
        self.assertEqual(r["unattributed"], [])

    def test_coff_arithmetic_that_does_not_fit_is_said_and_attributes_nothing(self):
        table = _coff(2)
        r = self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=1000) + table)
        self.assertEqual(r["coff_symbol_table"]["state"], "DOES_NOT_FIT")
        self.assertIn("need 18004 bytes", r["coff_symbol_table"]["detail"])
        self.assertEqual(r["status"], "TRAILING_UNKNOWN")
        self.assertEqual(r["attributed"], [])

    def test_coff_string_table_length_that_overruns_the_file_does_not_fit(self):
        table = _coff(2, strtab_length=5000)
        r = self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=2) + table)
        self.assertEqual(r["coff_symbol_table"]["state"], "DOES_NOT_FIT")
        self.assertEqual(r["coff_symbol_table"]["declared_string_table_length"], 5000)
        self.assertEqual(r["status"], "TRAILING_UNKNOWN")

    def test_coff_pointer_inside_section_data_attributes_nothing(self):
        r = self.run_on(_patch(build_pe(), symtab=0x200, nsyms=3) + pseudo_random_bytes(64))
        self.assertEqual(r["coff_symbol_table"]["state"], "OUTSIDE_TRAILING_REGION")
        self.assertEqual(r["status"], "TRAILING_UNKNOWN")

    def test_coff_with_extra_bytes_after_is_partly_attributed(self):
        table = _coff(3)
        tail = pseudo_random_bytes(100)
        r = self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=3) + table + tail)
        self.assertEqual(r["status"], "TRAILING_PARTLY_ATTRIBUTED")
        (unknown,) = r["unattributed"]
        self.assertEqual((unknown["offset"], unknown["size"], unknown["purpose"]),
                         (END_OF_SECTIONS + len(table), 100, "UNKNOWN"))

    def test_signed_file_is_not_reported_as_unknown_trailing_data(self):
        cert = _cert(0x200)
        r = self.run_on(_patch(build_pe(), security=(END_OF_SECTIONS, len(cert))) + cert)
        self.assertEqual((r["ok"], r["status"]), (True, "TRAILING_FULLY_ATTRIBUTED"))
        self.assertEqual(r["unattributed"], [])
        sec = r["security_directory"]
        self.assertEqual((sec["state"], sec["within_trailing_region"], sec["header_walk_consistent"]), ("DECLARED", True, True))
        self.assertEqual(sec["certificate_entry_count"], 1)
        self.assertEqual(r["attributed"][0]["kind"], "AUTHENTICODE_CERTIFICATE_TABLE")

    def test_signature_plus_coff_plus_remainder_leaves_only_the_remainder(self):
        table = _coff(2)
        cert = _cert(0x40)
        tail = b"\x07" * 33
        body = table + cert + tail
        pe = _patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=2, security=(END_OF_SECTIONS + len(table), len(cert)))
        r = self.run_on(pe + body)
        self.assertEqual(r["status"], "TRAILING_PARTLY_ATTRIBUTED")
        self.assertEqual([a["kind"] for a in r["attributed"]],
                         ["COFF_SYMBOL_AND_STRING_TABLE", "AUTHENTICODE_CERTIFICATE_TABLE"])
        (unknown,) = r["unattributed"]
        self.assertEqual((unknown["offset"], unknown["size"]), (END_OF_SECTIONS + len(table) + len(cert), 33))

    def test_security_directory_pointing_into_section_data_attributes_nothing(self):
        r = self.run_on(_patch(build_pe(), security=(0x200, 0x40)) + pseudo_random_bytes(64))
        self.assertEqual(r["security_directory"]["state"], "OUTSIDE_TRAILING_REGION")
        self.assertIs(r["security_directory"]["within_trailing_region"], False)
        self.assertEqual(r["status"], "TRAILING_UNKNOWN")

    def test_security_directory_with_no_trailing_bytes_is_reported_not_attributed(self):
        r = self.run_on(_patch(build_pe(), security=(END_OF_SECTIONS, 0x40)))
        self.assertEqual(r["status"], "NO_TRAILING_DATA")
        self.assertEqual(r["security_directory"]["state"], "OUTSIDE_TRAILING_REGION")

    def test_cut_file_makes_the_question_unanswerable(self):
        full = build_pe(resources=[(10, 1, 0x409, b"x" * 300)])
        cut = build_pe(resources=[(10, 1, 0x409, b"x" * 300)], truncate_in_resource_data=True)
        self.assertLess(len(cut), len(full))
        r = self.run_on(cut)
        self.assertEqual((r["ok"], r["status"]), (False, "SECTION_TABLE_UNUSABLE"))
        self.assertIn(".rsrc", r["error"])
        self.assertNotIn("trailing", r)

    def test_zero_declared_sections_makes_the_question_unanswerable(self):
        r = self.run_on(_patch(build_pe(), nsections=0) + b"tail")
        self.assertEqual((r["ok"], r["status"]), (False, "SECTION_TABLE_UNUSABLE"))

    def test_not_a_pe_and_missing_file(self):
        self.assertEqual(self.run_on(b"not a pe at all" * 10)["status"], "NOT_A_PE")
        self.assertEqual(json.loads(pe_trailing_data(str(self.dir / "absent.exe")))["status"], "NOT_FOUND")

    def test_the_five_outcomes_have_five_distinct_codes(self):
        table = _coff(1)
        outcomes = [
            self.run_on(build_pe()),
            self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=1) + table),
            self.run_on(_patch(build_pe(), symtab=END_OF_SECTIONS, nsyms=1) + table + b"\x01\x02\x03"),
            self.run_on(build_pe() + b"\x01\x02\x03"),
            self.run_on(_patch(build_pe(), nsections=0)),
        ]
        self.assertEqual(len({o["status"] for o in outcomes}), 5)


class RealSignedBinaryTests(unittest.TestCase):
    CANDIDATES = (r"C:\Windows\System32\ApplicationFrameHost.exe", r"C:\Windows\System32\appverif.exe",
                  r"C:\Windows\System32\AppVClient.exe")

    def test_embedded_signature_of_a_real_binary_is_attributed_in_place(self):
        import pefile

        for candidate in self.CANDIDATES:
            if not os.path.isfile(candidate):
                continue
            pe = pefile.PE(candidate, fast_load=True)
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            declared = (int(entry.VirtualAddress), int(entry.Size))
            pe.close()
            if declared[0]:
                break
        else:
            self.skipTest("no system binary with an embedded Authenticode table on this machine")
        out = StringIO()
        with redirect_stdout(out):
            code = cli.main(["trailing", candidate])
        r = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(r["status"], "TRAILING_FULLY_ATTRIBUTED")
        self.assertEqual(r["unattributed"], [])
        self.assertEqual(r["attributed"][0]["kind"], "AUTHENTICODE_CERTIFICATE_TABLE")
        self.assertEqual((r["attributed"][0]["offset"], r["attributed"][0]["size"]), declared)


class RegistrationAndCliTests(_Base):
    def test_registered_in_native_and_routable_by_path_alone(self):
        self.assertIn("pe_trailing_data", tool_families.FAMILIES["native"])
        self.assertIn("pe_trailing_data", tool_families.published_tools("native"))
        self.assertIn("pe_trailing_data", tool_families.NATIVE_PATH_ONLY_TOOLS)
        self.assertNotIn("pe_trailing_data", tool_families.NATIVE_COORDINATE_TOOLS)

    def run_cli(self, *argv):
        out = StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_cli_reaches_the_tool_and_maps_exit_codes(self):
        good = self.dir / "g.exe"
        good.write_bytes(build_pe() + b"\x09" * 16)
        code, body = self.run_cli("trailing", str(good))
        self.assertEqual((code, body["tool"], body["status"], body["command"]), (0, "pe_trailing_data", "TRAILING_UNKNOWN", "trailing"))
        bad = self.dir / "b.exe"
        bad.write_bytes(_patch(build_pe(), nsections=0))
        code, body = self.run_cli("trailing", str(bad))
        self.assertNotEqual(code, 0)
        self.assertEqual(body["status"], "SECTION_TABLE_UNUSABLE")


if __name__ == "__main__":
    unittest.main()
