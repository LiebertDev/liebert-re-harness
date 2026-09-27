"""Dependency-free CodeView RSDS (CV_INFO_PDB70) identity helpers.

Parses GUID+age+PDB path from CodeView blobs and correlates PE debug identity
with Minidump module CodeView records. Never loads symbols, maps source, or
executes targets.
"""
from __future__ import annotations

import struct
from pathlib import Path

RSDS_SIGNATURE = b"RSDS"
NB10_SIGNATURE = b"NB10"
IMAGE_DEBUG_TYPE_CODEVIEW = 2
MAX_PDB_PATH_BYTES = 1024
MAX_PE_DEBUG_ENTRIES = 64
MAX_PE_READ = 64 * 1024 * 1024


class CodeViewFormatError(ValueError):
    def __init__(self, code: str, **detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


def extract_pe_section_map(path: str | Path) -> dict:
    """Return the bounded PE COFF section-index to RVA mapping.

    CodeView ``S_PUB32`` records store a one-based section/segment index plus
    an offset inside that section.  The offset is not an RVA by itself.
    """
    target = Path(path)
    try:
        size = target.stat().st_size
        if size <= 0 or size > MAX_PE_READ:
            return {
                "ok": False,
                "status": "ANALYSIS_LIMITED",
                "error": "PE_SIZE_LIMIT" if size > MAX_PE_READ else "EMPTY_FILE",
                "detail": {"file_size": size, "maximum": MAX_PE_READ},
            }
        data = target.read_bytes()
    except OSError as exc:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": type(exc).__name__, "detail": {}}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "NOT_PE", "detail": {}}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "INVALID_PE_SIGNATURE", "detail": {}}
    coff = e_lfanew + 4
    _machine, section_count, _, _, _, optional_size = struct.unpack_from("<HHIIIH", data, coff)
    if section_count < 1 or section_count > 96:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "SECTION_COUNT_LIMIT",
            "detail": {"section_count": section_count, "maximum": 96},
        }
    section_table = coff + 20 + optional_size
    if section_table + section_count * 40 > len(data):
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "SECTION_TABLE_TRUNCATED", "detail": {}}
    sections = []
    for index in range(section_count):
        off = section_table + index * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
        sections.append({
            "segment": index + 1,
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
        })
    return {
        "ok": True,
        "status": "PROVEN",
        "sections": sections,
        "section_count": len(sections),
        "execution_performed": False,
    }


def format_guid(guid_bytes: bytes) -> str:
    if len(guid_bytes) != 16:
        raise CodeViewFormatError("GUID_SIZE", observed=len(guid_bytes))
    data1, data2, data3 = struct.unpack_from("<IHH", guid_bytes, 0)
    data4 = guid_bytes[8:16]
    return (
        f"{data1:08X}-{data2:04X}-{data3:04X}-"
        f"{data4[0]:02X}{data4[1]:02X}-{data4[2:].hex().upper()}"
    )


def parse_rsds(blob: bytes | bytearray | memoryview) -> dict:
    """Parse a CV_INFO_PDB70 record. Returns structured identity or fail-closed error."""
    data = bytes(blob)
    if len(data) < 24:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "RSDS_TRUNCATED",
            "detail": {"size": len(data)},
        }
    signature = data[:4]
    if signature == NB10_SIGNATURE:
        return {
            "ok": False,
            "status": "UNSUPPORTED",
            "error": "UNSUPPORTED_CV_TYPE",
            "detail": {"signature": "NB10", "reason": "Only RSDS/CV_INFO_PDB70 is implemented"},
        }
    if signature != RSDS_SIGNATURE:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "INVALID_CV_SIGNATURE",
            "detail": {"observed": signature.hex()},
        }
    guid = format_guid(data[4:20])
    age = struct.unpack_from("<I", data, 20)[0]
    path_region = data[24:]
    nul = path_region.find(b"\0")
    if nul < 0:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "PDB_PATH_NOT_TERMINATED",
            "detail": {"available": len(path_region)},
        }
    if nul > MAX_PDB_PATH_BYTES:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "PDB_PATH_TOO_LONG",
            "detail": {"length": nul, "maximum": MAX_PDB_PATH_BYTES},
        }
    pdb_path = path_region[:nul].decode("utf-8", errors="replace")
    identity_key = f"{guid}:{age}"
    return {
        "ok": True,
        "status": "PROVEN",
        "signature": "RSDS",
        "guid": guid,
        "age": age,
        "identity_key": identity_key,
        "guid_age": identity_key,
        "pdb_path": pdb_path,
        "claims_ceiling": {
            "debug_identity": "PROVEN",
            "symbols": "UNKNOWN",
            "types": "UNKNOWN",
            "source_mapping": "UNKNOWN",
        },
        "limitations": [
            "RSDS proves debug-record identity only",
            "No symbols, types, or source mapping without a PDB parser",
        ],
    }


def correlate_rsds(left: dict | None, right: dict | None) -> dict:
    """Correlate two RSDS identities. Never escalates to symbol claims."""
    left_ok = bool(left and left.get("ok") and left.get("guid") is not None)
    right_ok = bool(right and right.get("ok") and right.get("guid") is not None)
    if not left_ok or not right_ok:
        return {
            "status": "UNKNOWN",
            "identity_match": "UNKNOWN",
            "match_basis": [],
            "reason": "MISSING_OR_INVALID_RSDS",
            "claims_ceiling": {"debug_identity": "UNKNOWN", "symbols": "UNKNOWN"},
        }
    guid_match = left["guid"] == right["guid"]
    age_match = int(left["age"]) == int(right["age"])
    path_left = Path(str(left.get("pdb_path") or "")).name.casefold()
    path_right = Path(str(right.get("pdb_path") or "")).name.casefold()
    path_match = bool(path_left and path_right and path_left == path_right)
    if guid_match and age_match:
        basis = ["guid", "age"]
        if path_match:
            basis.append("pdb_basename")
        return {
            "status": "MATCH",
            "identity_match": "PROVEN",
            "match_basis": basis,
            "identity_key": left["identity_key"],
            "left": {"guid": left["guid"], "age": left["age"], "pdb_path": left.get("pdb_path")},
            "right": {"guid": right["guid"], "age": right["age"], "pdb_path": right.get("pdb_path")},
            "claims_ceiling": {
                "debug_identity": "PROVEN",
                "symbols": "UNKNOWN",
                "types": "UNKNOWN",
                "source_mapping": "UNKNOWN",
            },
            "limitations": [
                "Matching RSDS GUID+age binds debug identity only",
                "Does not prove PDB contents, symbols, or source lines",
            ],
        }
    if guid_match and not age_match:
        return {
            "status": "MISMATCH",
            "identity_match": "REJECTED",
            "match_basis": ["guid"],
            "reason": "AGE_MISMATCH",
            "left": {"guid": left["guid"], "age": left["age"]},
            "right": {"guid": right["guid"], "age": right["age"]},
            "claims_ceiling": {"debug_identity": "REJECTED", "symbols": "UNKNOWN"},
        }
    return {
        "status": "MISMATCH",
        "identity_match": "REJECTED",
        "match_basis": [],
        "reason": "GUID_MISMATCH",
        "left": {"guid": left["guid"], "age": left["age"]},
        "right": {"guid": right["guid"], "age": right["age"]},
        "claims_ceiling": {"debug_identity": "REJECTED", "symbols": "UNKNOWN"},
    }


def extract_pe_rsds(path: str | Path, *, max_entries: int = MAX_PE_DEBUG_ENTRIES) -> dict:
    """Extract the first RSDS CodeView record from a PE debug directory."""
    target = Path(path)
    try:
        size = target.stat().st_size
        if size <= 0 or size > MAX_PE_READ:
            return {
                "ok": False,
                "status": "ANALYSIS_LIMITED",
                "error": "PE_SIZE_LIMIT" if size > MAX_PE_READ else "EMPTY_FILE",
                "detail": {"file_size": size, "maximum": MAX_PE_READ},
            }
        data = target.read_bytes()
    except OSError as exc:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": type(exc).__name__,
            "detail": {},
        }
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "NOT_PE", "detail": {}}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "INVALID_PE_SIGNATURE", "detail": {}}
    coff = e_lfanew + 4
    machine, section_count, _, _, _, optional_size = struct.unpack_from("<HHIIIH", data, coff)
    optional = coff + 20
    if optional + optional_size > len(data) or optional_size < 96:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "OPTIONAL_HEADER_TRUNCATED", "detail": {}}
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        num_rva_off, dd_start = 108, 112
    elif magic == 0x10B:
        num_rva_off, dd_start = 92, 96
    else:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "UNSUPPORTED_OPTIONAL_MAGIC",
            "detail": {"magic": hex(magic)},
        }
    if optional + num_rva_off + 4 > optional + optional_size:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "NO_DEBUG_DIRECTORY", "detail": {}}
    num_rva = struct.unpack_from("<I", data, optional + num_rva_off)[0]
    if num_rva < 7:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "NO_DEBUG_DIRECTORY", "detail": {"number_of_rva_and_sizes": num_rva}}
    debug_off = optional + dd_start + 6 * 8
    if debug_off + 8 > optional + optional_size:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "NO_DEBUG_DIRECTORY", "detail": {}}
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_off)
    if not debug_rva or not debug_size:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "DEBUG_DIRECTORY_EMPTY", "detail": {}}

    sections = []
    section_table = optional + optional_size
    for index in range(min(section_count, 96)):
        off = section_table + index * 40
        if off + 40 > len(data):
            break
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((virt_addr, max(virt_size, raw_size), raw_ptr, raw_size))

    def rva_to_offset(rva: int) -> int | None:
        for virt_addr, mapped, raw_ptr, raw_size in sections:
            if virt_addr <= rva < virt_addr + mapped and raw_ptr and rva - virt_addr < raw_size:
                return raw_ptr + (rva - virt_addr)
        return None

    directory_offset = rva_to_offset(debug_rva)
    if directory_offset is None:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": "DEBUG_DIRECTORY_UNMAPPED",
            "detail": {"rva": debug_rva},
        }
    entry_count = min(debug_size // 28, max(1, int(max_entries)))
    records = []
    for index in range(entry_count):
        entry = directory_offset + index * 28
        if entry + 28 > len(data):
            break
        _characteristics, timestamp, _major, _minor, dtype, size_of_data, _addr_of_raw, ptr_to_raw = struct.unpack_from(
            "<IIHHIIII", data, entry
        )
        if dtype != IMAGE_DEBUG_TYPE_CODEVIEW or not size_of_data:
            continue
        raw_offset = ptr_to_raw
        if raw_offset <= 0 or raw_offset + size_of_data > len(data):
            records.append({"ok": False, "error": "CODEVIEW_RAW_OUT_OF_BOUNDS", "index": index})
            continue
        if size_of_data > MAX_PDB_PATH_BYTES + 64:
            records.append({"ok": False, "error": "CODEVIEW_BLOB_TOO_LARGE", "index": index, "size": size_of_data})
            continue
        parsed = parse_rsds(data[raw_offset:raw_offset + size_of_data])
        parsed["debug_entry_index"] = index
        parsed["timestamp"] = timestamp
        parsed["raw_offset"] = raw_offset
        parsed["data_size"] = size_of_data
        records.append(parsed)
        if parsed.get("ok"):
            return {
                "ok": True,
                "status": "PROVEN",
                "source": "PE_DEBUG_DIRECTORY",
                "architecture_hint": hex(machine),
                "rsds": parsed,
                "records_examined": index + 1,
                "claims_ceiling": parsed.get("claims_ceiling"),
                "limitations": parsed.get("limitations", []),
            }
    if records:
        return {
            "ok": False,
            "status": "ANALYSIS_LIMITED",
            "error": records[0].get("error", "NO_RSDS_RECORD"),
            "detail": {"records": records[:8]},
        }
    return {
        "ok": False,
        "status": "ANALYSIS_LIMITED",
        "error": "NO_CODEVIEW_DEBUG_ENTRY",
        "detail": {"entries": entry_count},
    }


def module_basename_match(module_name: str, binary_name: str) -> bool:
    left = Path(str(module_name or "")).name.casefold()
    right = Path(str(binary_name or "")).name.casefold()
    return bool(left and right and left == right)
