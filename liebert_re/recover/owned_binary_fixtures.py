"""Synthetic owned-binary fixture builders (PE/RSDS, minidump).

Extracted from the former ``qwen8b_safe_test_specialist.py`` module during the
local-model/training-era cleanup: these builders are generic PE and minidump
fixture generators used by several live kernel/native/Ghidra tests and carry
no dependency on any model-candidate benchmarking code.
"""
from __future__ import annotations

import struct
from pathlib import Path

from liebert_re.workspace import PROJECT_ROOT as APP
FIXTURE_DIR = APP / "dataset" / "runtime" / "qwen8b_safe_fixtures"

GUID_LE = struct.pack("<IHH", 0x8F11D2A0, 0x41B7, 0x4B0D) + bytes.fromhex("9E42112233445566")
AGE = 7
PDB_NAME = b"owned_fixture.pdb\0"
GUID_TEXT = "8F11D2A0-41B7-4B0D-9E42-112233445566"


def build_owned_rsds() -> bytes:
    return b"RSDS" + GUID_LE + struct.pack("<I", AGE) + PDB_NAME


def build_owned_minidump(path: Path, *, rsds: bytes | None = None, truncate: bool = False) -> Path:
    rsds = rsds or build_owned_rsds()
    directory_rva = 32
    stream_count = 3
    payload_rva = directory_rva + stream_count * 12

    system = bytearray(56)
    struct.pack_into("<HHHBBIIIII", system, 0, 9, 6, 0x3A09, 4, 1, 10, 0, 22631, 2, 0)

    module_name_str = r"C:\owned\owned_fixture.sys"
    encoded = module_name_str.encode("utf-16-le")
    module_name = struct.pack("<I", len(encoded)) + encoded
    module = bytearray(4 + 108)
    struct.pack_into("<I", module, 0, 1)
    name_rva = payload_rva + len(system) + len(module)
    cv_rva = name_rva + len(module_name)
    struct.pack_into("<QIIII", module, 4, 0x140000000, 0x5000, 7, 123456, name_rva)
    struct.pack_into("<II", module, 4 + 76, len(rsds), cv_rva)

    mem_blob = b"SAFEONLY"
    mem = bytearray(4 + 16)
    mem_rva = cv_rva + len(rsds)
    mem_data_rva = mem_rva + len(mem)
    struct.pack_into("<I", mem, 0, 1)
    struct.pack_into("<QII", mem, 4, 0x7FFE0000, len(mem_blob), mem_data_rva)

    body = bytes(system) + bytes(module) + module_name + rsds + bytes(mem) + mem_blob
    directory = (
        struct.pack("<III", 7, len(system), payload_rva)
        + struct.pack("<III", 4, len(module), payload_rva + len(system))
        + struct.pack("<III", 5, len(mem), mem_rva)
    )
    header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, stream_count, directory_rva, 0, 1700000000, 0)
    data = header + directory + body
    if truncate:
        data = data[:40]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def build_owned_pe_with_rsds(path: Path, rsds: bytes | None = None) -> Path:
    rsds = rsds or build_owned_rsds()
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe_sig = b"PE\0\0"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<Q", optional, 24, 0x140000000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 1)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into("<II", optional, 160, 0x1200, 28)
    section = bytearray(40)
    section[0:6] = b".rdata"
    struct.pack_into("<IIIIIIHHI", section, 8, 0x400, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x40000040)
    headers = bytes(dos) + pe_sig + coff + bytes(optional) + bytes(section)
    file_data = bytearray(0x200 + 0x400)
    file_data[:len(headers)] = headers
    debug_off, rsds_off = 0x400, 0x420
    struct.pack_into("<IIHHIIII", file_data, debug_off, 0, 0, 0, 0, 2, len(rsds), 0x1220, rsds_off)
    file_data[rsds_off:rsds_off + len(rsds)] = rsds
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(file_data))
    return path


def build_owned_pe_with_code(path: Path, code: bytes) -> Path:
    """Minimal PE32+ (x86-64) with one executable ``.text`` section holding
    ``code`` verbatim at RVA 0x1000 (entry point there), raw data at file
    offset 0x200. Built from scratch here; no third-party binary involved."""
    raw_size = max(0x200, (len(code) + 0x1FF) & ~0x1FF)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    optional = bytearray(240)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 4, len(code))            # SizeOfCode
    struct.pack_into("<I", optional, 16, 0x1000)              # entry point
    struct.pack_into("<I", optional, 20, 0x1000)              # BaseOfCode
    struct.pack_into("<Q", optional, 24, 0x140000000)         # ImageBase
    struct.pack_into("<I", optional, 32, 0x1000)              # SectionAlignment
    struct.pack_into("<I", optional, 36, 0x200)               # FileAlignment
    struct.pack_into("<I", optional, 56, 0x1000 + ((raw_size + 0xFFF) & ~0xFFF))  # SizeOfImage
    struct.pack_into("<I", optional, 60, 0x200)               # SizeOfHeaders
    struct.pack_into("<H", optional, 68, 3)                   # subsystem
    struct.pack_into("<I", optional, 108, 16)                 # NumberOfRvaAndSizes
    section = bytearray(40)
    section[0:5] = b".text"
    struct.pack_into("<IIIIIIHHI", section, 8, len(code), 0x1000, raw_size, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + bytes(section)
    file_data = bytearray(0x200 + raw_size)
    file_data[:len(headers)] = headers
    file_data[0x200:0x200 + len(code)] = code
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(file_data))
    return path


def ensure_owned_fixtures() -> dict[str, Path]:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    paths = {
        "owned_minidump": build_owned_minidump(FIXTURE_DIR / "owned_valid.mdmp"),
        "owned_minidump_truncated": build_owned_minidump(FIXTURE_DIR / "owned_truncated.mdmp", truncate=True),
        "owned_pe": build_owned_pe_with_rsds(FIXTURE_DIR / "owned_fixture.sys"),
    }
    # Malformed RSDS age mismatch companion dump
    bad = build_owned_rsds()
    # mutate age bytes
    bad = bad[:20] + struct.pack("<I", 99) + bad[24:]
    paths["owned_minidump_age_mismatch"] = build_owned_minidump(FIXTURE_DIR / "owned_age_mismatch.mdmp", rsds=bad)
    return paths
