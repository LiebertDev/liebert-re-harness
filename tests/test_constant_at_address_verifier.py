"""Independent tests for ``constant_at_address_verifier.py``.

New file, not ported from the upstream development repo: the
upstream test for this module imported a shared PE-builder fixture that is
not part of this package, so it could not be carried over as-is (see
``docs/CORPUS.md``/the package's porting notes). This file exercises the
same module with its own small, self-contained 32-bit PE builder -- nothing
is downloaded, and the built bytes are never executed, only disassembled.

At least one positive (``VERIFIED``) and one negative (``REFUTED``) case are
covered, plus one ``UNTESTABLE`` case for an address that does not resolve.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from liebert_re.evidence.constant_at_address_verifier import verify_constant_at_address

try:
    import pefile  # noqa: F401
    import capstone  # noqa: F401
    _HAVE_DEPS = True
except ImportError:
    _HAVE_DEPS = False


_IMAGE_BASE = 0x00400000
_SECTION_RVA = 0x1000
_SECTION_ALIGNMENT = 0x1000
_FILE_ALIGNMENT = 0x200
_HEADER_SIZE = 0x200


def _build_minimal_pe32(code: bytes) -> tuple[bytes, int]:
    """Build the smallest real, valid 32-bit PE ``pefile`` can parse: one
    executable section holding exactly ``code``, with the entry point at its
    start. Returns ``(pe_bytes, entry_va)``. No import table, no resources --
    none of that is needed to disassemble one instruction at a known VA.
    Never executed on this host, only ever fed to Capstone/pefile.
    """
    section_size = max((len(code) + 0xF) & ~0xF, 0x10)
    if len(code) > section_size:
        raise ValueError("code does not fit its own reserved section")
    padded_code = code + b"\x00" * (section_size - len(code))

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x40)

    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # i386
        1,       # one section
        0, 0, 0,
        0xE0,    # size of optional header
        0x0102,  # characteristics: executable image, 32-bit machine
    )

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B, 0, 0,                       # PE32 magic
        len(padded_code), 0, 0,
        _SECTION_RVA,                       # address of entry point
        _SECTION_RVA, 0,
        _IMAGE_BASE,
        _SECTION_ALIGNMENT, _FILE_ALIGNMENT,
        4, 0, 0, 0, 4, 0,                   # OS/image/subsystem versions
        0,                                   # win32 version
        _SECTION_RVA + section_size,         # size of image
        _HEADER_SIZE,                        # size of headers
        0,                                   # checksum
        3, 0,                                # subsystem CONSOLE, dll chars
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap reserve/commit
        0, 16,                               # loader flags, number of RVAs
    )
    directories = bytearray(16 * 8)  # all zero: no imports/exports/etc

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        section_size, _SECTION_RVA,
        section_size, _HEADER_SIZE,
        0, 0, 0, 0,
        0x60000020,  # code, executable, readable
    )

    headers = bytearray(_HEADER_SIZE)
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

    pe_bytes = bytes(headers) + padded_code
    entry_va = _IMAGE_BASE + _SECTION_RVA
    return pe_bytes, entry_va


@unittest.skipUnless(_HAVE_DEPS, "pefile/capstone not installed")
class ConstantAtAddressVerifierSyntheticTests(unittest.TestCase):
    """Fixture built programmatically in ``setUpClass``, never downloaded."""

    @classmethod
    def setUpClass(cls):
        code = b"\x3D\x34\x12\x00\x00"    # cmp eax, 0x1234        (+0, 5 bytes)
        code += b"\x83\xF8\xFF"            # cmp eax, -1 (imm8 0xff) (+5, 3 bytes)
        code += b"\x31\xC0"                # xor eax, eax            (+8, 2 bytes)
        code += b"\x89\xC3"                # mov ebx, eax  (not comparison-family, +10)
        pe_bytes, entry_va = _build_minimal_pe32(code)
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="const-addr-verifier-")
        cls.pe_path = str(Path(cls._tmpdir.name) / "probe.exe")
        with open(cls.pe_path, "wb") as fh:
            fh.write(pe_bytes)
        cls.entry_va = entry_va

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()

    def test_ordinary_cmp_immediate_is_verified(self):
        """Positive control: a real cmp-immediate at a known VA is VERIFIED
        with the exact immediate value the bytes encode."""
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va), "0x1234", "va")
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(result["reason"], "IMMEDIATE_MATCHES_CLAIM")
        self.assertEqual(result["immediate"], "0x1234")

    def test_wrong_constant_at_the_same_address_is_refuted(self):
        """Negative control: the same real instruction, a wrong claimed
        constant -- a decisive REFUTED, not a shrug."""
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va), "0x9999", "va")
        self.assertEqual(result["verdict"], "REFUTED")
        self.assertEqual(result["reason"], "IMMEDIATE_VALUE_MISMATCH")
        self.assertEqual(result["immediate"], "0x1234")

    def test_sign_extended_byte_immediate_matches_unsigned_hex_claim(self):
        # `cmp eax, -1` is encoded with a one-byte sign-extended immediate;
        # Capstone reports it as the signed int -1. The claim, expressed as
        # the unsigned hex literal a human/model would actually write, must
        # still verify after width/sign masking.
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va + 5), "0xffffffff", "va")
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(result["reason"], "IMMEDIATE_MATCHES_CLAIM")

    def test_xor_reg_reg_zero_idiom_verifies_a_zero_claim(self):
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va + 8), "0x0", "va")
        self.assertEqual(result["verdict"], "VERIFIED")
        self.assertEqual(result["reason"], "ZERO_PRODUCING_XOR_IDIOM")

    def test_reg_reg_mov_has_no_immediate_and_is_refuted(self):
        """Negative control: a real, non-comparison instruction is a
        decisive REFUTED, never UNTESTABLE."""
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va + 10), "0x0", "va")
        self.assertEqual(result["verdict"], "REFUTED")
        self.assertEqual(result["reason"], "NOT_A_COMPARISON_INSTRUCTION")

    def test_unresolvable_address_is_untestable_not_failed(self):
        result = verify_constant_at_address(self.pe_path, "0xdeadbeef", "0x1234", "va")
        self.assertEqual(result["verdict"], "UNTESTABLE")
        self.assertEqual(result["reason"], "ADDRESS_NOT_RESOLVED")

    def test_non_numeric_claimed_value_is_untestable_not_failed(self):
        result = verify_constant_at_address(self.pe_path, hex(self.entry_va), "not-a-number", "va")
        self.assertEqual(result["verdict"], "UNTESTABLE")
        self.assertEqual(result["reason"], "CLAIMED_VALUE_NOT_A_NUMBER")


if __name__ == "__main__":
    unittest.main()
