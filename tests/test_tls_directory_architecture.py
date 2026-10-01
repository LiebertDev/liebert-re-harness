"""analyze_tls_directory must derive pointer width from the optional-header
magic and refuse machine types it has not been shown to handle, instead of
defaulting every non-amd64 PE to 4-byte pointers under ``status: OK``."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
from liebert_re.tools.tls_directory import analyze_tls_directory

_COFF_MACHINE = 64 + 4  # e_lfanew + "PE\0\0"
_OPT = _COFF_MACHINE + 20
_TLS_DIR_ENTRY = _OPT + 112 + 9 * 8


def _build(dest: Path, *, machine: int = 0x8664) -> Path:
    code = bytearray(0x400)
    # TLS directory (PE32+, 40 bytes) at RVA 0x1000; callback array at 0x1100.
    struct.pack_into("<QQQQII", code, 0, 0x140002000, 0x140002010, 0x140002020, 0x140001100, 0, 0)
    struct.pack_into("<QQ", code, 0x100, 0x140001200, 0)
    path = build_owned_pe_with_code(dest, bytes(code))
    data = bytearray(path.read_bytes())
    struct.pack_into("<II", data, _TLS_DIR_ENTRY, 0x1000, 40)
    struct.pack_into("<H", data, _COFF_MACHINE, machine)
    path.write_bytes(bytes(data))
    return path


class TlsArchitectureGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def _run(self, name, **kw):
        return json.loads(analyze_tls_directory(str(_build(self.dir / name, **kw))))

    def test_amd64_pe32plus_reads_eight_byte_callbacks(self):
        r = self._run("a.exe")
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["pointer_size"], 8)
        self.assertEqual(r["callback_count"], 1)

    def test_arm64_is_refused_by_name_not_read_with_four_byte_pointers(self):
        r = self._run("arm64.exe", machine=0xAA64)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "UNSUPPORTED_ARCHITECTURE")

    def test_ia64_and_arm32_are_refused_by_name(self):
        for machine in (0x200, 0x1C4):
            with self.subTest(machine=hex(machine)):
                r = self._run(f"m{machine:x}.exe", machine=machine)
                self.assertEqual(r["status"], "UNSUPPORTED_ARCHITECTURE")

    def test_machine_and_magic_disagreement_is_refused(self):
        r = self._run("i386_with_pe32plus.exe", machine=0x14C)
        self.assertEqual(r["status"], "PE_HEADER_INCONSISTENT")

    def test_unknown_optional_header_magic_is_refused(self):
        path = _build(self.dir / "rom.exe")
        data = bytearray(path.read_bytes())
        struct.pack_into("<H", data, _OPT, 0x107)
        path.write_bytes(bytes(data))
        r = json.loads(analyze_tls_directory(str(path)))
        self.assertEqual(r["status"], "UNSUPPORTED_OPTIONAL_HEADER")


if __name__ == "__main__":
    unittest.main()
