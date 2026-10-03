"""Dependency-free MSF 7.00 container P0 parser (native PDB envelope).

Parses superblock + stream directory only. Does not decode DBI/TPI/IPI symbol
or type records. Portable PDB (BSJB) is rejected as a different format.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

from liebert_re.recover.codeview_rsds import format_guid

# Exact 32-byte MSF 7.00 file magic (LLVM/Microsoft layout).
MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
PORTABLE_PDB_MAGIC = b"BSJB"
ALLOWED_BLOCK_SIZES = frozenset({512, 1024, 2048, 4096})
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_STREAMS = 4096
MAX_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_BLOCKS = 1_048_576
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_SYMBOL_RECORDS = 4096
PDB_INFO_STREAM = 1
PDB_DBI_STREAM = 3
PDB_VC70 = 20000404
DBI_HEADER_SIZE = 64
S_PUB32 = 0x110E


class MsfFormatError(ValueError):
    def __init__(self, code: str, **detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


def detect_pdb_container(data: bytes | bytearray | memoryview) -> str:
    raw = bytes(data[:32])
    if raw.startswith(PORTABLE_PDB_MAGIC):
        return "PORTABLE_PDB_BSJB"
    if raw.startswith(b"Microsoft C/C++ MSF 7.00"):
        return "MSF7"
    if raw.startswith(b"Microsoft C/C++ MSF 2.00"):
        return "MSF2_UNSUPPORTED"
    return "UNKNOWN"


def _fail(code: str, **detail) -> dict:
    return {
        "ok": False,
        "valid": False,
        "format": "msf",
        "status": "ANALYSIS_LIMITED",
        "error": code,
        "detail": detail,
        "pdb_symbol_records": "NOT_IMPLEMENTED_P0",
        "claims_ceiling": {
            "msf_container": "REJECTED",
            "symbols": "UNKNOWN",
            "types": "UNKNOWN",
            "source_mapping": "UNKNOWN",
        },
        "execution_performed": False,
    }


def _mul(a: int, b: int, *, code: str) -> int:
    if a < 0 or b < 0:
        raise MsfFormatError(code, a=a, b=b)
    try:
        return a * b
    except OverflowError as exc:
        raise MsfFormatError(code, a=a, b=b) from exc


def parse_msf(path: str | Path | None = None, *, data: bytes | None = None) -> dict:
    """Parse MSF 7.00 container metadata. Fail-closed structured errors."""
    try:
        if data is None:
            if path is None:
                return _fail("NO_INPUT")
            target = Path(path)
            size = target.stat().st_size
            if size <= 0:
                return _fail("EMPTY_FILE")
            if size > MAX_FILE_BYTES:
                return _fail("FILE_TOO_LARGE", size=size, maximum=MAX_FILE_BYTES)
            data = target.read_bytes()
        else:
            data = bytes(data)
            size = len(data)
            if size > MAX_FILE_BYTES:
                return _fail("FILE_TOO_LARGE", size=size, maximum=MAX_FILE_BYTES)

        kind = detect_pdb_container(data)
        if kind == "PORTABLE_PDB_BSJB":
            return {
                "ok": False,
                "valid": False,
                "format": "portable_pdb",
                "status": "UNSUPPORTED",
                "error": "PORTABLE_PDB_NOT_MSF",
                "detail": {"magic": "BSJB"},
                "pdb_symbol_records": "NOT_IMPLEMENTED_P0",
                "claims_ceiling": {"msf_container": "REJECTED", "symbols": "UNKNOWN"},
                "execution_performed": False,
            }
        if kind == "MSF2_UNSUPPORTED":
            return _fail("UNSUPPORTED_MSF_VERSION", version="2.00")
        if data.startswith(b"Microsoft C/C++ MSF") and len(data) < 56:
            return _fail("SUPERBLOCK_TRUNCATED", size=len(data))
        if kind != "MSF7":
            return _fail("INVALID_MSF_SIGNATURE", observed=data[:16].hex())

        if data[:32] != MSF_MAGIC:
            return _fail("INVALID_MSF_MAGIC", observed=data[:32].hex())

        block_size, free_map, num_blocks, num_dir_bytes, _unknown, block_map_addr = struct.unpack_from(
            "<IIIIII", data, 32
        )
        if block_size not in ALLOWED_BLOCK_SIZES:
            return _fail("INVALID_BLOCK_SIZE", block_size=block_size, allowed=sorted(ALLOWED_BLOCK_SIZES))
        if num_blocks < 1 or num_blocks > MAX_BLOCKS:
            return _fail("INVALID_NUM_BLOCKS", num_blocks=num_blocks)
        expected_min = _mul(num_blocks, block_size, code="SIZE_OVERFLOW")
        if len(data) < expected_min:
            return _fail(
                "FILE_SMALLER_THAN_NUM_BLOCKS",
                file_size=len(data),
                expected_min=expected_min,
                num_blocks=num_blocks,
                block_size=block_size,
            )
        if num_dir_bytes > MAX_DIRECTORY_BYTES:
            return _fail("DIRECTORY_TOO_LARGE", num_directory_bytes=num_dir_bytes)
        if free_map not in {1, 2}:
            return _fail("INVALID_FREE_BLOCK_MAP", free_block_map_block=free_map)
        if block_map_addr >= num_blocks:
            return _fail("BLOCK_MAP_OUT_OF_BOUNDS", block_map_addr=block_map_addr, num_blocks=num_blocks)

        def read_block(index: int) -> bytes:
            if index < 0 or index >= num_blocks:
                raise MsfFormatError("BLOCK_INDEX_OUT_OF_BOUNDS", index=index, num_blocks=num_blocks)
            start = _mul(index, block_size, code="OFFSET_OVERFLOW")
            end = start + block_size
            if end > len(data):
                raise MsfFormatError("BLOCK_READ_TRUNCATED", index=index, start=start, end=end)
            return data[start:end]

        # Directory block map: enough uint32 indices to cover NumDirectoryBytes.
        dir_block_count = (num_dir_bytes + block_size - 1) // block_size if num_dir_bytes else 0
        map_bytes_needed = dir_block_count * 4
        if map_bytes_needed > block_size:
            # P0: single block map only (common for tiny fixtures). Multi-level maps = later.
            return _fail(
                "DIRECTORY_BLOCK_MAP_SPANS_MULTIPLE_BLOCKS",
                directory_block_count=dir_block_count,
                block_size=block_size,
            )
        map_block = read_block(block_map_addr)
        dir_block_indices = []
        for i in range(dir_block_count):
            idx = struct.unpack_from("<I", map_block, i * 4)[0]
            if idx >= num_blocks:
                return _fail("DIRECTORY_BLOCK_OUT_OF_BOUNDS", index=idx, num_blocks=num_blocks)
            dir_block_indices.append(idx)

        directory = bytearray()
        for idx in dir_block_indices:
            directory.extend(read_block(idx))
        directory = directory[:num_dir_bytes]
        if num_dir_bytes and len(directory) < num_dir_bytes:
            return _fail("DIRECTORY_TRUNCATED", expected=num_dir_bytes, observed=len(directory))
        if num_dir_bytes == 0:
            streams = []
            stream_count = 0
        else:
            if len(directory) < 4:
                return _fail("DIRECTORY_TRUNCATED", expected=4, observed=len(directory))
            stream_count = struct.unpack_from("<I", directory, 0)[0]
            if stream_count > MAX_STREAMS:
                return _fail("STREAM_COUNT_LIMIT", stream_count=stream_count, maximum=MAX_STREAMS)
            header_need = 4 + stream_count * 4
            if len(directory) < header_need:
                return _fail("DIRECTORY_TRUNCATED", expected=header_need, observed=len(directory))
            sizes = list(struct.unpack_from(f"<{stream_count}I", directory, 4))
            offset = header_need
            streams = []
            for index, stream_size in enumerate(sizes):
                # 0xFFFFFFFF marks unused stream slots in some PDBs; treat as empty.
                if stream_size == 0xFFFFFFFF:
                    streams.append({"index": index, "size": 0, "blocks": [], "unused": True})
                    continue
                if stream_size > MAX_DIRECTORY_BYTES:
                    return _fail("STREAM_SIZE_LIMIT", index=index, size=stream_size)
                nblocks = (stream_size + block_size - 1) // block_size if stream_size else 0
                need = offset + nblocks * 4
                if need > len(directory):
                    return _fail(
                        "STREAM_BLOCK_LIST_TRUNCATED",
                        index=index,
                        expected=need,
                        observed=len(directory),
                    )
                blocks = list(struct.unpack_from(f"<{nblocks}I", directory, offset)) if nblocks else []
                offset = need
                for block in blocks:
                    if block >= num_blocks:
                        return _fail(
                            "STREAM_BLOCK_OUT_OF_BOUNDS",
                            stream=index,
                            block=block,
                            num_blocks=num_blocks,
                        )
                streams.append({"index": index, "size": stream_size, "blocks": blocks, "unused": False})

        return {
            "ok": True,
            "valid": True,
            "format": "msf",
            "status": "PARTIAL",
            "analysis_class": "MSF_PDB_CONTAINER_P0",
            "magic": "MSF_7_00",
            "block_size": block_size,
            "free_block_map_block": free_map,
            "num_blocks": num_blocks,
            "num_directory_bytes": num_dir_bytes,
            "block_map_addr": block_map_addr,
            "directory_block_indices": dir_block_indices,
            "stream_count": stream_count,
            "streams": streams,
            "msf_container_parsed": True,
            "pdb_symbol_records": "NOT_IMPLEMENTED_P0",
            "claims_ceiling": {
                "msf_container": "PROVEN",
                "symbols": "UNKNOWN",
                "types": "UNKNOWN",
                "source_mapping": "UNKNOWN",
            },
            "limitations": [
                "MSF P0 parses container/stream directory only",
                "No DBI/TPI/IPI/symbol/type/source decoding",
                "Single-block directory maps only",
            ],
            "execution_performed": False,
        }
    except MsfFormatError as exc:
        return _fail(exc.code, **exc.detail)
    except OSError as exc:
        return _fail(type(exc).__name__)


def build_synthetic_msf(
    *,
    block_size: int = 4096,
    streams: list[bytes] | None = None,
) -> bytes:
    """Deterministic minimal MSF 7.00 with the given stream payloads."""
    if block_size not in ALLOWED_BLOCK_SIZES:
        raise ValueError("unsupported block size")
    payloads = list(streams if streams is not None else [b"", b"P0META\0\0"])
    if len(payloads) > MAX_STREAMS:
        raise ValueError("too many streams")

    # Layout blocks:
    # 0: superblock
    # 1: free block map (zeros)
    # 2: directory block map
    # 3: stream directory
    # 4+: stream data blocks
    stream_blocks: list[list[int]] = []
    data_blocks: list[bytes] = []
    next_block = 4
    for payload in payloads:
        if not payload:
            stream_blocks.append([])
            continue
        chunks = [payload[i:i + block_size] for i in range(0, len(payload), block_size)]
        indices = []
        for chunk in chunks:
            padded = chunk + b"\0" * (block_size - len(chunk))
            data_blocks.append(padded)
            indices.append(next_block)
            next_block += 1
        stream_blocks.append(indices)

    directory = bytearray()
    directory += struct.pack("<I", len(payloads))
    for payload in payloads:
        directory += struct.pack("<I", len(payload))
    for indices in stream_blocks:
        for idx in indices:
            directory += struct.pack("<I", idx)
    num_dir_bytes = len(directory)
    if num_dir_bytes > block_size:
        raise ValueError("directory exceeds single block (P0 builder limit)")
    dir_padded = bytes(directory) + b"\0" * (block_size - num_dir_bytes)

    num_blocks = next_block
    file_data = bytearray(_mul(num_blocks, block_size, code="BUILD_OVERFLOW"))

    # Superblock in block 0
    file_data[0:32] = MSF_MAGIC
    struct.pack_into("<IIIIII", file_data, 32, block_size, 1, num_blocks, num_dir_bytes, 0, 2)

    # Free block map block 1 already zero
    # Directory block map at block 2: one entry -> block 3
    struct.pack_into("<I", file_data, 2 * block_size, 3)
    # Directory at block 3
    file_data[3 * block_size:3 * block_size + block_size] = dir_padded
    # Stream payloads
    for offset, block in enumerate(data_blocks):
        start = (4 + offset) * block_size
        file_data[start:start + block_size] = block
    return bytes(file_data)


def write_synthetic_msf(path: str | Path, **kwargs) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(build_synthetic_msf(**kwargs))
    return target


def read_stream_bytes(msf: dict, data: bytes, index: int) -> tuple[bytes | None, dict | None]:
    """Reassemble one MSF stream. Returns (payload, error_detail)."""
    streams = msf.get("streams") or []
    if index < 0 or index >= len(streams):
        return None, {"error": "STREAM_INDEX_OUT_OF_BOUNDS", "index": index, "stream_count": len(streams)}
    row = streams[index]
    if row.get("unused"):
        return b"", None
    size = int(row.get("size") or 0)
    if size > MAX_STREAM_BYTES:
        return None, {"error": "STREAM_SIZE_LIMIT", "index": index, "size": size}
    block_size = int(msf["block_size"])
    num_blocks = int(msf["num_blocks"])
    out = bytearray()
    for block in row.get("blocks") or []:
        if block < 0 or block >= num_blocks:
            return None, {"error": "STREAM_BLOCK_OUT_OF_BOUNDS", "index": index, "block": block}
        start = block * block_size
        end = start + block_size
        if end > len(data):
            return None, {"error": "STREAM_BLOCK_READ_TRUNCATED", "index": index, "block": block}
        out.extend(data[start:end])
    return bytes(out[:size]), None


def parse_pdb_info_stream(blob: bytes | None) -> dict:
    if blob is None:
        return {"ok": False, "present": False, "error": "INFOSTREAM_MISSING"}
    if len(blob) == 0:
        return {"ok": False, "present": False, "error": "INFOSTREAM_MISSING"}
    if len(blob) < 28:
        return {"ok": False, "present": True, "error": "INFOSTREAM_TRUNCATED", "detail": {"size": len(blob)}}
    version, signature, age = struct.unpack_from("<III", blob, 0)
    try:
        guid = format_guid(blob[12:28])
    except Exception:
        return {"ok": False, "present": True, "error": "INFOSTREAM_INVALID_GUID", "detail": {"size": len(blob)}}
    return {
        "ok": True,
        "present": True,
        "version": version,
        "signature": signature,
        "age": age,
        "guid": guid,
        "identity_key": f"{guid}:{age}",
        "claims_ceiling": {"debug_identity": "PROVEN", "symbols": "UNKNOWN"},
    }


def build_info_stream(*, version: int = PDB_VC70, signature: int = 1, age: int = 7, guid_le: bytes) -> bytes:
    if len(guid_le) != 16:
        raise ValueError("guid must be 16 bytes")
    return struct.pack("<III", version, signature, age) + guid_le


def parse_dbi_header(blob: bytes | None) -> dict:
    if blob is None or len(blob) == 0:
        return {"ok": False, "present": False, "error": "DBI_MISSING"}
    if len(blob) < DBI_HEADER_SIZE:
        return {"ok": False, "present": True, "error": "DBI_TRUNCATED", "detail": {"size": len(blob), "minimum": DBI_HEADER_SIZE}}
    (
        version_signature, version_header, age, global_stream, build_number,
        public_stream, pdb_dll_version, sym_record_stream, pdb_dll_rbld,
        modi_size, sec_contr_size, section_map_size, src_info_size, type_server_size,
        mfc_type_server, optional_dbg_hdr_size, ec_substream_size, flags, machine, _pad,
    ) = struct.unpack_from("<iiiHHHHHHiiiiiIiiHHI", blob, 0)
    substreams = {
        "modi_size": modi_size,
        "section_contribution_size": sec_contr_size,
        "section_map_size": section_map_size,
        "source_info_size": src_info_size,
        "type_server_size": type_server_size,
        "optional_dbg_hdr_size": optional_dbg_hdr_size,
        "ec_substream_size": ec_substream_size,
    }
    if any(v < 0 or v > MAX_STREAM_BYTES for v in substreams.values()):
        return {
            "ok": False,
            "present": True,
            "error": "DBI_INVALID_SUBSTREAM_SIZE",
            "detail": substreams,
        }
    header_plus = DBI_HEADER_SIZE + sum(substreams.values())
    if header_plus > len(blob):
        return {
            "ok": False,
            "present": True,
            "error": "DBI_SUBSTREAM_OUT_OF_BOUNDS",
            "detail": {"needed": header_plus, "available": len(blob), **substreams},
        }
    return {
        "ok": True,
        "present": True,
        "version_signature": version_signature,
        "version_header": version_header,
        "age": age,
        "global_stream_index": global_stream,
        "public_stream_index": public_stream,
        "sym_record_stream": sym_record_stream,
        "build_number": build_number,
        "machine": machine,
        "flags": flags,
        "substream_sizes": substreams,
        "header_size": DBI_HEADER_SIZE,
        "status": "DISCOVERY_ONLY",
    }


def build_dbi_header(
    *,
    age: int = 7,
    public_stream: int = 0xFFFF,
    sym_record_stream: int = 0xFFFF,
    global_stream: int = 0xFFFF,
    machine: int = 0x8664,
) -> bytes:
    buf = bytearray(DBI_HEADER_SIZE)
    struct.pack_into(
        "<iiiHHHHHHiiiiiIiiHHI",
        buf,
        0,
        -1,
        19990903,
        age,
        global_stream,
        0,
        public_stream,
        0,
        sym_record_stream,
        0,
        0, 0, 0, 0, 0,
        0,
        0,
        0,
        0,
        machine,
        0,
    )
    return bytes(buf)


def parse_pub32_symbols(blob: bytes | None) -> dict:
    if blob is None:
        return {
            "ok": False,
            "public_symbol_stream_present": False,
            "records_parsed": 0,
            "status": "MISSING",
            "error": "SYMBOL_STREAM_MISSING",
            "symbols": [],
        }
    if len(blob) == 0:
        return {
            "ok": True,
            "public_symbol_stream_present": True,
            "records_parsed": 0,
            "status": "DISCOVERY_ONLY",
            "symbols": [],
            "unsupported_records": 0,
        }
    offset = 0
    symbols = []
    unsupported = 0
    errors = []
    while offset + 4 <= len(blob) and len(symbols) < MAX_SYMBOL_RECORDS:
        reclen, rectyp = struct.unpack_from("<HH", blob, offset)
        if reclen < 2:
            errors.append({"error": "INVALID_RECORD_LENGTH", "offset": offset, "reclen": reclen})
            break
        rec_end = offset + 2 + reclen
        if rec_end > len(blob):
            errors.append({"error": "TRUNCATED_RECORD", "offset": offset, "reclen": reclen, "available": len(blob) - offset})
            break
        body = blob[offset + 4:rec_end]
        if rectyp == S_PUB32:
            if len(body) < 10:
                errors.append({"error": "TRUNCATED_S_PUB32", "offset": offset})
                break
            flags, off, seg = struct.unpack_from("<IIH", body, 0)
            name = body[10:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            symbols.append({"name": name, "offset": off, "segment": seg, "flags": flags, "kind": "S_PUB32"})
        else:
            unsupported += 1
            errors.append({"error": "UNSUPPORTED_RECORD_TYPE", "offset": offset, "rectyp": hex(rectyp)})
        offset = rec_end
        # CodeView records are often 4-byte aligned
        if offset % 4:
            offset += 4 - (offset % 4)
    status = "PARSED" if symbols else ("DISCOVERY_ONLY" if not errors else "ANALYSIS_LIMITED")
    return {
        "ok": not any(e.get("error") in {"TRUNCATED_RECORD", "INVALID_RECORD_LENGTH", "TRUNCATED_S_PUB32"} for e in errors),
        "public_symbol_stream_present": True,
        "records_parsed": len(symbols),
        "unsupported_records": unsupported,
        "status": status if not errors or symbols else "ANALYSIS_LIMITED",
        "symbols": symbols,
        "errors": errors[:32],
        "error_count": len(errors),
        "errors_truncated": len(errors) > 32,
    }


def build_pub32_stream(symbols: list[tuple[str, int, int]] | None = None) -> bytes:
    """Build a minimal SymRecord stream of S_PUB32 records. symbols: (name, offset, seg)."""
    out = bytearray()
    for name, off, seg in symbols or [("OwnedEntry", 0x1000, 1)]:
        raw_name = name.encode("utf-8") + b"\0"
        body = struct.pack("<IIH", 0, off, seg) + raw_name
        reclen = 2 + len(body)  # rectyp + body
        rec = struct.pack("<HH", reclen, S_PUB32) + body
        if len(rec) % 4:
            rec += b"\0" * (4 - (len(rec) % 4))
        out.extend(rec)
    return bytes(out)


def resolve_public_symbol_rvas(symbols: list[dict], sections: list[dict] | None) -> dict:
    """Resolve S_PUB32 section-relative offsets to PE RVAs without guessing."""
    section_by_segment = {
        int(row.get("segment") or 0): row
        for row in (sections or [])
        if int(row.get("segment") or 0) > 0
    }
    resolved = []
    unresolved = []
    for original in symbols or []:
        row = dict(original)
        segment = int(row.get("segment") or 0)
        section = section_by_segment.get(segment)
        if section is None:
            unresolved.append({"name": row.get("name"), "segment": segment, "error": "SECTION_NOT_MAPPED"})
            continue
        offset = int(row.get("offset") or 0)
        section_rva = int(section.get("virtual_address") or 0)
        row.update({
            "rva": section_rva + offset,
            "section_name": section.get("name"),
            "section_rva": section_rva,
            "address_basis": "PE_SECTION_RVA_PLUS_S_PUB32_OFFSET",
        })
        resolved.append(row)
    return {
        "ok": bool(resolved) and not unresolved,
        "status": "RESOLVED" if resolved and not unresolved else "PARTIAL" if resolved else "SECTION_MAP_REQUIRED",
        "symbols": resolved,
        "unresolved": unresolved[:64],
        "unresolved_count": len(unresolved),
        "unresolved_truncated": len(unresolved) > 64,
    }


def lookup_symbol_by_rva(symbols: list[dict], rva: int, *, sections: list[dict] | None = None) -> dict:
    if not symbols:
        return {"ok": True, "status": "NO_SYMBOLS", "match": None, "kind": "none"}
    if sections is not None:
        resolution = resolve_public_symbol_rvas(symbols, sections)
        candidates = resolution.get("symbols") or []
    elif all("rva" in row for row in symbols):
        resolution = {"ok": True, "status": "PRE_RESOLVED", "symbols": list(symbols), "unresolved": []}
        candidates = list(symbols)
    else:
        return {
            "ok": False,
            "status": "SECTION_MAP_REQUIRED",
            "match": None,
            "kind": "none",
            "reason": "S_PUB32_OFFSET_IS_SECTION_RELATIVE_NOT_RVA",
        }
    if not candidates:
        return {
            "ok": False,
            "status": resolution.get("status") or "SECTION_MAP_REQUIRED",
            "match": None,
            "kind": "none",
            "unresolved": resolution.get("unresolved") or [],
        }
    exact = [s for s in candidates if int(s.get("rva") or 0) == int(rva)]
    if exact:
        return {"ok": True, "status": "EXACT", "match": exact[0], "ambiguous": len(exact) > 1, "kind": "exact"}
    before = [s for s in candidates if int(s.get("rva") or 0) <= int(rva)]
    if not before:
        return {"ok": True, "status": "BEFORE_FIRST", "match": None, "kind": "none"}
    nearest = max(before, key=lambda s: int(s.get("rva") or 0))
    after_last = all(int(s.get("rva") or 0) < int(rva) for s in candidates) and nearest == max(candidates, key=lambda s: int(s.get("rva") or 0))
    return {
        "ok": True,
        "status": "AFTER_LAST" if after_last and int(nearest.get("rva") or 0) != int(rva) and int(rva) > max(int(s.get("rva") or 0) for s in candidates) else "NEAREST_PREVIOUS",
        "match": nearest,
        "kind": "nearest_previous",
    }


def correlate_minidump_to_pdb(
    minidump_report: dict | None,
    pdb_report: dict | None,
    *,
    module_name: str | None = None,
) -> dict:
    """Offline module → RSDS → PDB InfoStream → public-symbol availability chain."""
    from liebert_re.recover.codeview_rsds import module_basename_match

    modules = ((minidump_report or {}).get("modules") or {}).get("items") or []
    matched = None
    if module_name:
        for item in modules:
            if module_basename_match(item.get("name", ""), module_name):
                matched = item
                break
    elif modules:
        matched = modules[0]
    rsds = None
    if matched and isinstance(matched.get("codeview"), dict):
        rsds = matched["codeview"].get("rsds")
    info = (pdb_report or {}).get("info_stream") or {}
    identity = correlate_pe_pdb_identity(rsds, info)
    publics = (pdb_report or {}).get("public_symbols") or {}
    symbols_available = bool(publics.get("ok") and publics.get("records_parsed"))
    if identity.get("identity_match"):
        provider = "AVAILABLE_PUBLIC_SYMBOLS" if symbols_available else "IDENTITY_ONLY"
    elif identity.get("status") == "MISMATCH":
        provider = "REJECTED_WRONG_PDB"
    else:
        provider = "UNAVAILABLE"
    return {
        "ok": True,
        "module": None if matched is None else {
            "name": matched.get("name"),
            "base_address": matched.get("base_address"),
        },
        "identity": identity,
        "public_symbols": {
            "available": symbols_available,
            "records_parsed": publics.get("records_parsed") or 0,
            "status": publics.get("status"),
        },
        "symbol_provider": provider,
        "stack_unwind": "UNKNOWN",
        "claims_ceiling": {
            "debug_identity": (
                "PROVEN" if identity.get("identity_match")
                else "REJECTED" if identity.get("status") == "MISMATCH"
                else "UNKNOWN"
            ),
            "symbols": "PARTIAL" if symbols_available and identity.get("identity_match") else "UNKNOWN",
            "stack_unwind": "UNKNOWN",
            "types": "UNKNOWN",
            "source_mapping": "UNKNOWN",
        },
    }


def find_owned_native_msf_pdbs(root: str | Path, *, max_files: int = 8000) -> dict:
    """Read-only scan for real owned native MSF PDBs. Skips synthetic fixtures."""
    base = Path(root)
    skip_parts = {
        "owned_fixtures",
        "__pycache__",
        ".git",
        ".venv",
        "node_modules",
    }
    skip_names = {"owned_valid.msf.pdb"}
    search_roots = [
        base / "smoke-tests",
        base / "benchmarks",
        base / "crash-dumps",
        base / "dataset",
    ]
    scanned = 0
    candidates = []
    skipped_synthetic = []
    skipped_non_msf = []
    parse_failures = []
    for search in search_roots:
        if not search.is_dir():
            continue
        for path in search.rglob("*"):
            if scanned >= max_files:
                break
            if not path.is_file():
                continue
            if any(part in skip_parts for part in path.parts):
                if path.suffix.casefold() == ".pdb":
                    skipped_synthetic.append(str(path))
                continue
            name = path.name.casefold()
            if path.suffix.casefold() not in {".pdb", ".msf"} and "pdb" not in name:
                continue
            if path.name in skip_names:
                skipped_synthetic.append(str(path))
                continue
            scanned += 1
            try:
                head = path.read_bytes()[:64]
            except OSError as exc:
                parse_failures.append({"path": str(path), "error": type(exc).__name__})
                continue
            kind = detect_pdb_container(head)
            if kind != "MSF7":
                skipped_non_msf.append({"path": str(path), "kind": kind})
                continue
            parsed = parse_pdb(path)
            info = parsed.get("info_stream") or {}
            if not parsed.get("ok") or not info.get("ok"):
                parse_failures.append({
                    "path": str(path),
                    "error": parsed.get("error") or info.get("error") or "INFOSTREAM_MISSING",
                    "size": path.stat().st_size,
                })
                continue
            candidates.append({
                "path": str(path),
                "size": path.stat().st_size,
                "guid": info.get("guid"),
                "age": info.get("age"),
                "version": info.get("version"),
                "dbi_ok": bool((parsed.get("dbi") or {}).get("ok")),
                "public_symbols": int((parsed.get("public_symbols") or {}).get("records_parsed") or 0),
            })
    return {
        "ok": True,
        "scanned_files": scanned,
        "found": candidates,
        "count": len(candidates),
        "skipped_synthetic": skipped_synthetic[:50],
        "skipped_synthetic_count": len(skipped_synthetic),
        "skipped_non_msf": skipped_non_msf[:50],
        "skipped_non_msf_count": len(skipped_non_msf),
        "parse_failures": parse_failures[:50],
        "parse_failure_count": len(parse_failures),
        "lists_truncated": max(len(skipped_synthetic), len(skipped_non_msf), len(parse_failures)) > 50,
        "status": "FOUND" if candidates else "NOT_EXECUTED_NO_REAL_OWNED_NATIVE_PDB",
    }


def correlate_pe_pdb_identity(pe_rsds: dict | None, pdb_info: dict | None) -> dict:
    pe_ok = bool(pe_rsds and pe_rsds.get("ok") and pe_rsds.get("guid") is not None)
    info_ok = bool(pdb_info and pdb_info.get("ok") and pdb_info.get("guid") is not None)
    if not pe_ok and not info_ok:
        return {
            "identity_match": False, "guid_match": False, "age_match": False,
            "status": "MISSING_RSDS_AND_INFOSTREAM", "reason": "MISSING_BOTH",
        }
    if not pe_ok:
        return {
            "identity_match": False, "guid_match": False, "age_match": False,
            "status": "MISSING_RSDS", "reason": pe_rsds.get("error") if isinstance(pe_rsds, dict) else "MISSING_RSDS",
        }
    if not info_ok:
        return {
            "identity_match": False, "guid_match": False, "age_match": False,
            "status": "MISSING_PDB_INFOSTREAM", "reason": pdb_info.get("error") if isinstance(pdb_info, dict) else "MISSING_INFOSTREAM",
        }
    guid_match = pe_rsds["guid"] == pdb_info["guid"]
    age_match = int(pe_rsds["age"]) == int(pdb_info["age"])
    matched = guid_match and age_match
    if matched:
        reason = "MATCH"
    elif guid_match:
        reason = "AGE_MISMATCH"
    elif age_match:
        reason = "GUID_MISMATCH"
    else:
        reason = "GUID_AND_AGE_MISMATCH"
    return {
        "identity_match": matched,
        "guid_match": guid_match,
        "age_match": age_match,
        "status": "MATCH" if matched else "MISMATCH",
        "reason": reason,
        "pe": {"guid": pe_rsds.get("guid"), "age": pe_rsds.get("age")},
        "pdb": {"guid": pdb_info.get("guid"), "age": pdb_info.get("age")},
    }


def parse_pdb(path: str | Path | None = None, *, data: bytes | None = None) -> dict:
    """MSF container + InfoStream + optional DBI/public symbol discovery."""
    if data is None:
        if path is None:
            return _fail("NO_INPUT")
        target = Path(path)
        try:
            size = target.stat().st_size
            if size <= 0:
                return _fail("EMPTY_FILE")
            if size > MAX_FILE_BYTES:
                return _fail("FILE_TOO_LARGE", size=size, maximum=MAX_FILE_BYTES)
            data = target.read_bytes()
        except OSError as exc:
            return _fail(type(exc).__name__)
    else:
        data = bytes(data)
        target = Path(path) if path else None
        if len(data) > MAX_FILE_BYTES:
            return _fail("FILE_TOO_LARGE", size=len(data), maximum=MAX_FILE_BYTES)
    msf = parse_msf(data=data)
    if not msf.get("ok"):
        return msf
    info = {"ok": False, "present": False, "error": "INFOSTREAM_MISSING"}
    if msf.get("stream_count", 0) > PDB_INFO_STREAM:
        payload, err = read_stream_bytes(msf, data, PDB_INFO_STREAM)
        if err:
            info = {"ok": False, "present": True, "error": err["error"], "detail": err}
        else:
            info = parse_pdb_info_stream(payload)
    dbi = {"ok": False, "present": False, "error": "DBI_MISSING"}
    if msf.get("stream_count", 0) > PDB_DBI_STREAM:
        payload, err = read_stream_bytes(msf, data, PDB_DBI_STREAM)
        if err:
            dbi = {"ok": False, "present": True, "error": err["error"], "detail": err}
        else:
            dbi = parse_dbi_header(payload)
    publics = {
        "ok": False,
        "public_symbol_stream_present": False,
        "stream_index": None,
        "size": 0,
        "records_parsed": 0,
        "status": "NOT_REQUESTED",
        "symbols": [],
    }
    if dbi.get("ok"):
        sym_index = int(dbi.get("sym_record_stream") or 0xFFFF)
        if sym_index == 0xFFFF:
            publics = {
                "ok": True,
                "public_symbol_stream_present": False,
                "stream_index": None,
                "size": 0,
                "records_parsed": 0,
                "status": "DISCOVERY_ONLY",
                "symbols": [],
            }
        elif sym_index >= int(msf.get("stream_count") or 0):
            publics = {
                "ok": False,
                "public_symbol_stream_present": False,
                "stream_index": sym_index,
                "size": 0,
                "records_parsed": 0,
                "status": "INVALID_STREAM_INDEX",
                "error": "DBI_SYMBOL_STREAM_OUT_OF_BOUNDS",
                "symbols": [],
            }
        else:
            payload, err = read_stream_bytes(msf, data, sym_index)
            size = (msf["streams"][sym_index].get("size") or 0) if not err else 0
            if err:
                publics = {
                    "ok": False,
                    "public_symbol_stream_present": False,
                    "stream_index": sym_index,
                    "size": size,
                    "records_parsed": 0,
                    "status": "ANALYSIS_LIMITED",
                    "error": err["error"],
                    "symbols": [],
                }
            else:
                parsed = parse_pub32_symbols(payload)
                parsed["stream_index"] = sym_index
                parsed["size"] = len(payload or b"")
                publics = parsed
    symbols_ok = bool(publics.get("ok") and publics.get("records_parsed"))
    report = {
        **msf,
        "analysis_class": "MSF_PDB_P1" if dbi.get("ok") or info.get("ok") else "MSF_PDB_CONTAINER_P0",
        "info_stream": info,
        "dbi": dbi,
        "public_symbols": publics,
        "pdb_symbol_records": "PARSED" if symbols_ok else ("DISCOVERY_ONLY" if publics.get("public_symbol_stream_present") else "NOT_IMPLEMENTED_P0" if not dbi.get("ok") else "NONE"),
        "claims_ceiling": {
            "msf_container": "PROVEN",
            "debug_identity": "PROVEN" if info.get("ok") else "UNKNOWN",
            "dbi": "PROVEN" if dbi.get("ok") else "UNKNOWN",
            "symbols": "PARTIAL" if symbols_ok else "UNKNOWN",
            "types": "UNKNOWN",
            "source_mapping": "UNKNOWN",
        },
        "limitations": [
            "MSF container + InfoStream GUID/age + optional DBI/S_PUB32 only",
            "No TPI/IPI/type/source/line/unwind decoding",
        ],
        "execution_performed": False,
    }
    if target is not None:
        report["path"] = str(target)
    return report


def build_synthetic_pdb(
    *,
    guid_le: bytes,
    age: int = 7,
    version: int = PDB_VC70,
    signature: int = 1,
    symbols: list[tuple[str, int, int]] | None = None,
    include_dbi: bool = True,
    include_symbols: bool = False,
    info_stream: bytes | None = None,
) -> bytes:
    info = info_stream if info_stream is not None else build_info_stream(version=version, signature=signature, age=age, guid_le=guid_le)
    streams: list[bytes] = [b"", info, b""]
    if include_dbi or include_symbols:
        sym_index = 0xFFFF
        public_index = 0xFFFF
        extra: list[bytes] = []
        if include_symbols:
            extra.append(b"")  # placeholder public GSI (index 4)
            extra.append(build_pub32_stream(symbols))  # index 5
            public_index = 4
            sym_index = 5
        dbi = build_dbi_header(age=age, public_stream=public_index, sym_record_stream=sym_index)
        streams.append(dbi)
        streams.extend(extra)
    return build_synthetic_msf(streams=streams)


def write_synthetic_pdb(path: str | Path, **kwargs) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(build_synthetic_pdb(**kwargs))
    return target


def msf_pdb_inspect(path: str) -> str:
    """ToolBus-facing workspace-contained MSF/PDB inspector."""
    from liebert_re.workspace import relative, safe_path

    target = safe_path(path)
    report = parse_pdb(target)
    report["tool"] = "msf_pdb_inspect"
    report["path"] = relative(target)
    return json.dumps(report, ensure_ascii=False, indent=2)


def pdb_symbols(path: str, operation: str = "summary", address: str = "", pe_path: str = "") -> str:
    """PARTIAL native MSF PDB specialist: identity + optional public symbols/RVA lookup."""
    from liebert_re.workspace import relative, safe_path

    target = safe_path(path)
    report = parse_pdb(target)
    report["tool"] = "pdb_symbols"
    report["path"] = relative(target)
    report["operation"] = operation
    report["capabilities"] = {
        "status": "PARTIAL",
        "identity": bool((report.get("info_stream") or {}).get("ok")),
        "public_symbols": bool((report.get("public_symbols") or {}).get("records_parsed")),
        "types": False,
        "source": False,
    }
    if operation == "lookup":
        try:
            rva = int(str(address), 0)
        except (TypeError, ValueError):
            report["lookup"] = {"ok": False, "error": "INVALID_ADDRESS", "address": address}
        else:
            symbols = (report.get("public_symbols") or {}).get("symbols") or []
            sections = None
            if pe_path:
                from liebert_re.recover.codeview_rsds import extract_pe_section_map
                pe_target = safe_path(pe_path)
                section_report = extract_pe_section_map(pe_target)
                report["pe_section_map"] = section_report
                report["pe_path"] = relative(pe_target)
                sections = section_report.get("sections") if section_report.get("ok") else []
            report["lookup"] = lookup_symbol_by_rva(symbols, rva, sections=sections)
            report["lookup"]["address"] = rva
    return json.dumps(report, ensure_ascii=False, indent=2)
