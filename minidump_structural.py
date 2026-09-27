"""Dependency-free, bounded structural parser for Windows minidumps.

This module reads metadata only. It never executes the target, unwinds stacks,
loads symbols, or infers a crash cause.
"""
from __future__ import annotations

import struct
import json
from pathlib import Path

from codeview_rsds import parse_rsds


HEADER_SIZE = 32
DIRECTORY_SIZE = 12
MAX_STREAMS = 256
MAX_ITEMS = 10_000
MAX_STRING_BYTES = 64 * 1024
MAX_MEMORY_READ_BYTES = 64 * 1024

STREAM_NAMES = {
    0: "UnusedStream", 3: "ThreadListStream", 4: "ModuleListStream",
    5: "MemoryListStream", 6: "ExceptionStream", 7: "SystemInfoStream",
    8: "ThreadExListStream", 9: "Memory64ListStream", 10: "CommentStreamA",
    11: "CommentStreamW", 12: "HandleDataStream", 13: "FunctionTableStream",
    14: "UnloadedModuleListStream", 15: "MiscInfoStream", 16: "MemoryInfoListStream",
    17: "ThreadInfoListStream", 18: "HandleOperationListStream", 19: "TokenStream",
    20: "JavaScriptDataStream", 21: "SystemMemoryInfoStream",
    22: "ProcessVmCountersStream", 23: "IptTraceStream", 24: "ThreadNamesStream",
}
ARCHITECTURES = {0: "x86", 5: "arm", 6: "ia64", 9: "x86_64", 12: "arm64", 0xFFFF: "unknown"}
PLATFORMS = {0: "win32s", 1: "windows_9x", 2: "windows_nt", 3: "windows_ce"}


class MinidumpFormatError(ValueError):
    def __init__(self, code: str, **detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _Reader:
    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size
        self.handle = path.open("rb")

    def close(self):
        self.handle.close()

    def read(self, rva: int, size: int, *, code: str = "RVA_OUT_OF_BOUNDS") -> bytes:
        self.ensure(rva, size, code=code)
        self.handle.seek(rva)
        data = self.handle.read(size)
        if len(data) != size:
            raise MinidumpFormatError("TRUNCATED_READ", rva=rva, requested=size, observed=len(data))
        return data

    def ensure(self, rva: int, size: int, *, code: str = "RVA_OUT_OF_BOUNDS") -> None:
        if rva < 0 or size < 0 or rva > self.size or size > self.size - rva:
            raise MinidumpFormatError(code, rva=rva, requested=size, file_size=self.size)

    def string(self, rva: int) -> str:
        length = struct.unpack("<I", self.read(rva, 4, code="STRING_RVA_OUT_OF_BOUNDS"))[0]
        if length > MAX_STRING_BYTES or length % 2:
            raise MinidumpFormatError("INVALID_STRING_LENGTH", rva=rva, length=length)
        return self.read(rva + 4, length, code="STRING_OUT_OF_BOUNDS").decode("utf-16-le", errors="replace")


def _bounded_count(count: int, max_items: int, item_size: int, available: int, kind: str) -> tuple[int, bool]:
    if count > MAX_ITEMS:
        raise MinidumpFormatError("ITEM_COUNT_LIMIT", kind=kind, count=count, maximum=MAX_ITEMS)
    if 4 + count * item_size > available:
        raise MinidumpFormatError("STREAM_RECORDS_TRUNCATED", kind=kind, count=count, item_size=item_size, available=available)
    selected = min(count, max_items)
    return selected, selected < count


def _system_info(reader: _Reader, rva: int, size: int) -> dict:
    if size < 32:
        raise MinidumpFormatError("SYSTEM_INFO_TRUNCATED", size=size)
    data = reader.read(rva, min(size, 56))
    arch, level, revision, processors, product = struct.unpack_from("<HHHBB", data, 0)
    major, minor, build, platform, csd_rva = struct.unpack_from("<IIIII", data, 8)
    csd = None
    if csd_rva:
        csd = reader.string(csd_rva)
    return {
        "architecture": ARCHITECTURES.get(arch, f"unknown_{arch}"), "architecture_code": arch,
        "processor_level": level, "processor_revision": revision, "processor_count": processors,
        "product_type": product, "os_version": f"{major}.{minor}.{build}",
        "platform": PLATFORMS.get(platform, f"unknown_{platform}"), "service_pack": csd,
    }


def _modules(reader: _Reader, rva: int, size: int, max_items: int) -> dict:
    if size < 4:
        raise MinidumpFormatError("MODULE_LIST_TRUNCATED", size=size)
    count = struct.unpack("<I", reader.read(rva, 4))[0]
    selected, truncated = _bounded_count(count, max_items, 108, size, "modules")
    items = []
    for index in range(selected):
        data = reader.read(rva + 4 + index * 108, 108)
        base, image_size, checksum, timestamp, name_rva = struct.unpack_from("<QIIII", data, 0)
        cv_size, cv_rva = struct.unpack_from("<II", data, 76)
        codeview = None
        if cv_size:
            reader.ensure(cv_rva, cv_size, code="CODEVIEW_OUT_OF_BOUNDS")
            if cv_size > MAX_STRING_BYTES:
                raise MinidumpFormatError("CODEVIEW_BLOB_TOO_LARGE", size=cv_size, maximum=MAX_STRING_BYTES)
            codeview = {
                "data_size": cv_size,
                "rva": cv_rva,
                "rsds": parse_rsds(reader.read(cv_rva, cv_size, code="CODEVIEW_OUT_OF_BOUNDS")),
            }
        items.append({
            "base_address": f"0x{base:X}", "image_size": image_size,
            "checksum": checksum, "timestamp": timestamp,
            "name": reader.string(name_rva),
            "codeview": codeview,
        })
    return {"count": count, "items": items, "truncated": truncated}


def _threads(reader: _Reader, rva: int, size: int, max_items: int) -> dict:
    if size < 4:
        raise MinidumpFormatError("THREAD_LIST_TRUNCATED", size=size)
    count = struct.unpack("<I", reader.read(rva, 4))[0]
    selected, truncated = _bounded_count(count, max_items, 48, size, "threads")
    items = []
    for index in range(selected):
        data = reader.read(rva + 4 + index * 48, 48)
        thread_id, suspend, priority_class, priority, teb = struct.unpack_from("<IIIIQ", data, 0)
        stack_start, stack_size, stack_rva = struct.unpack_from("<QII", data, 24)
        context_size, context_rva = struct.unpack_from("<II", data, 40)
        if stack_size:
            reader.ensure(stack_rva, stack_size, code="THREAD_STACK_OUT_OF_BOUNDS")
        if context_size:
            reader.ensure(context_rva, context_size, code="THREAD_CONTEXT_OUT_OF_BOUNDS")
        items.append({
            "thread_id": thread_id, "suspend_count": suspend,
            "priority_class": priority_class, "priority": priority,
            "teb": f"0x{teb:X}",
            "stack": {"start": f"0x{stack_start:X}", "data_size": stack_size, "rva": stack_rva},
            "context": {"data_size": context_size, "rva": context_rva},
        })
    return {"count": count, "items": items, "truncated": truncated, "stacks_unwound": False}


def _exception(reader: _Reader, rva: int, size: int) -> dict:
    if size < 168:
        raise MinidumpFormatError("EXCEPTION_STREAM_TRUNCATED", size=size)
    data = reader.read(rva, 168)
    thread_id = struct.unpack_from("<I", data, 0)[0]
    code, flags = struct.unpack_from("<II", data, 8)
    record, address = struct.unpack_from("<QQ", data, 16)
    parameter_count = struct.unpack_from("<I", data, 32)[0]
    if parameter_count > 15:
        raise MinidumpFormatError("EXCEPTION_PARAMETER_LIMIT", count=parameter_count)
    parameters = list(struct.unpack_from(f"<{parameter_count}Q", data, 40)) if parameter_count else []
    context_size, context_rva = struct.unpack_from("<II", data, 160)
    if context_size:
        reader.ensure(context_rva, context_size, code="EXCEPTION_CONTEXT_OUT_OF_BOUNDS")
    return {
        "thread_id": thread_id, "code": f"0x{code:08X}", "flags": flags,
        "record": f"0x{record:X}", "address": f"0x{address:X}",
        "parameters": [f"0x{x:X}" for x in parameters],
        "context": {"data_size": context_size, "rva": context_rva},
        "crash_cause": "UNKNOWN",
    }


def _memory_list(reader: _Reader, rva: int, size: int, max_items: int) -> dict:
    """Inventory MemoryListStream descriptors only; never emit memory bytes."""
    if size < 4:
        raise MinidumpFormatError("MEMORY_LIST_TRUNCATED", size=size)
    count = struct.unpack("<I", reader.read(rva, 4))[0]
    selected, truncated = _bounded_count(count, max_items, 16, size, "memory_list")
    items = []
    for index in range(selected):
        data = reader.read(rva + 4 + index * 16, 16)
        start, data_size, data_rva = struct.unpack_from("<QII", data, 0)
        if data_size:
            reader.ensure(data_rva, data_size, code="MEMORY_RANGE_OUT_OF_BOUNDS")
        items.append({
            "start": f"0x{start:X}",
            "data_size": data_size,
            "rva": data_rva,
            "contents_dumped": False,
        })
    return {
        "stream": "MemoryListStream",
        "count": count,
        "items": items,
        "truncated": truncated,
        "contents_dumped": False,
        "stacks_unwound": False,
    }


def _memory64_list(reader: _Reader, rva: int, size: int, max_items: int) -> dict:
    """Inventory Memory64ListStream descriptors; validate contiguous payload span."""
    if size < 16:
        raise MinidumpFormatError("MEMORY64_LIST_TRUNCATED", size=size)
    count, base_rva = struct.unpack("<QQ", reader.read(rva, 16))
    if count > MAX_ITEMS:
        raise MinidumpFormatError("ITEM_COUNT_LIMIT", kind="memory64_list", count=count, maximum=MAX_ITEMS)
    if 16 + count * 16 > size:
        raise MinidumpFormatError(
            "STREAM_RECORDS_TRUNCATED", kind="memory64_list", count=count, item_size=16, available=size,
        )
    selected = min(int(count), max_items)
    truncated = selected < count
    items = []
    offset = int(base_rva)
    for index in range(selected):
        data = reader.read(rva + 16 + index * 16, 16)
        start, data_size = struct.unpack_from("<QQ", data, 0)
        data_size_i = int(data_size)
        if data_size_i:
            reader.ensure(offset, data_size_i, code="MEMORY64_RANGE_OUT_OF_BOUNDS")
        items.append({
            "start": f"0x{start:X}",
            "data_size": data_size_i,
            "rva": offset,
            "contents_dumped": False,
        })
        offset += data_size_i
    return {
        "stream": "Memory64ListStream",
        "count": int(count),
        "base_rva": int(base_rva),
        "items": items,
        "truncated": truncated,
        "contents_dumped": False,
        "stacks_unwound": False,
    }


def _thread_names(reader: _Reader, rva: int, size: int, max_items: int) -> dict:
    """Inventory ThreadNamesStream names without interpreting stack state."""
    if size < 4:
        raise MinidumpFormatError("THREAD_NAMES_TRUNCATED", size=size)
    count = struct.unpack("<I", reader.read(rva, 4))[0]
    selected, truncated = _bounded_count(count, max_items, 16, size, "thread_names")
    items = []
    for index in range(selected):
        data = reader.read(rva + 4 + index * 16, 16)
        thread_id, name_rva = struct.unpack_from("<I4xQ", data, 0)
        name = reader.string(int(name_rva)) if name_rva else ""
        items.append({"thread_id": thread_id, "name": name})
    return {"count": count, "items": items, "truncated": truncated}


def parse_minidump(path: str | Path, *, max_items: int = 1000) -> dict:
    """Return bounded structural facts or a structured fail-closed error."""
    target = Path(path)
    max_items = max(1, min(int(max_items), MAX_ITEMS))
    reader = None
    try:
        reader = _Reader(target)
        if reader.size < HEADER_SIZE:
            raise MinidumpFormatError("HEADER_TRUNCATED", file_size=reader.size)
        header = reader.read(0, HEADER_SIZE)
        signature, version, stream_count, directory_rva, checksum, timestamp, flags = struct.unpack("<4sIIIIIQ", header)
        if signature != b"MDMP":
            raise MinidumpFormatError("INVALID_SIGNATURE", observed=signature.hex())
        if stream_count > MAX_STREAMS:
            raise MinidumpFormatError("STREAM_COUNT_LIMIT", count=stream_count, maximum=MAX_STREAMS)
        directory = reader.read(directory_rva, stream_count * DIRECTORY_SIZE, code="DIRECTORY_OUT_OF_BOUNDS")
        streams = []
        parsed = {}
        seen = set()
        duplicate_streams = []
        for index in range(stream_count):
            stream_type, data_size, rva = struct.unpack_from("<III", directory, index * DIRECTORY_SIZE)
            reader.ensure(rva, data_size, code="STREAM_OUT_OF_BOUNDS")
            name = STREAM_NAMES.get(stream_type, f"UnknownStream_{stream_type}")
            streams.append({"index": index, "type": stream_type, "name": name, "data_size": data_size, "rva": rva})
            if stream_type in seen:
                duplicate_streams.append({"index": index, "type": stream_type, "name": name, "rva": rva})
                continue
            seen.add(stream_type)
            if stream_type == 7:
                parsed["system_info"] = _system_info(reader, rva, data_size)
            elif stream_type == 4:
                parsed["modules"] = _modules(reader, rva, data_size, max_items)
            elif stream_type == 3:
                parsed["threads"] = _threads(reader, rva, data_size, max_items)
            elif stream_type == 6:
                parsed["exception"] = _exception(reader, rva, data_size)
            elif stream_type == 5:
                parsed["memory_list"] = _memory_list(reader, rva, data_size, max_items)
            elif stream_type == 9:
                parsed["memory64_list"] = _memory64_list(reader, rva, data_size, max_items)
            elif stream_type == 24:
                parsed["thread_names"] = _thread_names(reader, rva, data_size, max_items)
        return {
            "ok": True, "status": "PARTIAL", "analysis_class": "MINIDUMP_STRUCTURAL_V1",
            "file_size": reader.size,
            "header": {"status": "PROVEN", "version": version, "stream_count": stream_count,
                       "directory_rva": directory_rva, "checksum": checksum, "timestamp": timestamp, "flags": flags},
            "streams": streams, "duplicate_streams": duplicate_streams, **parsed,
            "claims_ceiling": {
                "structure": "PROVEN",
                "codeview_identity": "PROVEN_WHEN_RSDS_PARSED",
                "memory_range_inventory": "PROVEN_WHEN_PRESENT",
                "memory_contents": "NOT_DUMPED",
                "stack_unwind": "UNKNOWN",
                "crash_cause": "UNKNOWN",
                "symbols": "UNKNOWN",
            },
            "limitations": [
                "No stack unwinding",
                "No symbol loading",
                "No crash-cause inference",
                "RSDS proves debug identity only",
                "MemoryList/Memory64 inventory does not dump memory contents",
                "ThreadNames inventory does not imply stack or crash semantics",
                "Unknown streams are inventoried but not interpreted",
            ],
            "execution_performed": False, "debugger_attached": False,
        }
    except (OSError, MinidumpFormatError) as exc:
        return {
            "ok": False, "status": "ANALYSIS_LIMITED", "analysis_class": "MINIDUMP_STRUCTURAL_V1",
            "error": exc.code if isinstance(exc, MinidumpFormatError) else type(exc).__name__,
            "detail": exc.detail if isinstance(exc, MinidumpFormatError) else {},
            "execution_performed": False, "debugger_attached": False,
        }
    finally:
        if reader is not None:
            reader.close()


def read_memory_at_va(path: str | Path, va: int, size: int, *, max_items: int = 1000) -> dict:
    """Read `size` bytes starting at virtual address `va` from a minidump's
    captured memory (MemoryListStream or Memory64ListStream), if present.

    Reuses the header/directory validation of ``parse_minidump`` and the
    existing ``_memory_list``/``_memory64_list`` descriptor parsers rather
    than duplicating that logic. Never claims bytes that were not actually
    captured in the dump.
    """
    target = Path(path)
    max_items = max(1, min(int(max_items), MAX_ITEMS))
    reader = None
    try:
        va = int(va)
        size = int(size)
        if size < 0 or size > MAX_MEMORY_READ_BYTES:
            raise MinidumpFormatError("MEMORY_READ_SIZE_LIMIT", requested=size, maximum=MAX_MEMORY_READ_BYTES)
        reader = _Reader(target)
        if reader.size < HEADER_SIZE:
            raise MinidumpFormatError("HEADER_TRUNCATED", file_size=reader.size)
        header = reader.read(0, HEADER_SIZE)
        signature, version, stream_count, directory_rva, checksum, timestamp, flags = struct.unpack("<4sIIIIIQ", header)
        if signature != b"MDMP":
            raise MinidumpFormatError("INVALID_SIGNATURE", observed=signature.hex())
        if stream_count > MAX_STREAMS:
            raise MinidumpFormatError("STREAM_COUNT_LIMIT", count=stream_count, maximum=MAX_STREAMS)
        directory = reader.read(directory_rva, stream_count * DIRECTORY_SIZE, code="DIRECTORY_OUT_OF_BOUNDS")
        memory_streams = []
        seen = set()
        for index in range(stream_count):
            stream_type, data_size, rva = struct.unpack_from("<III", directory, index * DIRECTORY_SIZE)
            reader.ensure(rva, data_size, code="STREAM_OUT_OF_BOUNDS")
            if stream_type not in (5, 9) or stream_type in seen:
                continue
            seen.add(stream_type)
            if stream_type == 5:
                memory_streams.append(("MemoryListStream", _memory_list(reader, rva, data_size, max_items)))
            else:
                memory_streams.append(("Memory64ListStream", _memory64_list(reader, rva, data_size, max_items)))
        for source_name, stream in memory_streams:
            for item in stream.get("items", []):
                start = int(item["start"], 16)
                data_size_item = int(item["data_size"])
                if not data_size_item or not (start <= va < start + data_size_item):
                    continue
                inner_offset = va - start
                if size > data_size_item - inner_offset:
                    continue
                read_rva = int(item["rva"]) + inner_offset
                data = reader.read(read_rva, size, code="MEMORY_READ_OUT_OF_BOUNDS")
                return {
                    "ok": True, "status": "CAPTURED",
                    "va": hex(va), "size": size,
                    "data_hex": data.hex(),
                    "source_stream": source_name,
                }
        return {"ok": False, "status": "NOT_CAPTURED", "va": hex(va), "size": size}
    except (OSError, MinidumpFormatError) as exc:
        return {
            "ok": False, "status": "ANALYSIS_LIMITED",
            "error": exc.code if isinstance(exc, MinidumpFormatError) else type(exc).__name__,
            "detail": exc.detail if isinstance(exc, MinidumpFormatError) else {},
            "va": hex(va) if isinstance(va, int) else va, "size": size,
        }
    finally:
        if reader is not None:
            reader.close()


def minidump_structural_analyze(path: str, max_items: int = 1000) -> str:
    """ToolBus-facing workspace-contained structural analyzer."""
    from tools_workspace import relative, safe_path
    target = safe_path(path)
    report = parse_minidump(target, max_items=max_items)
    report["tool"] = "minidump_structural_analyze"
    report["path"] = relative(target)
    return json.dumps(report, ensure_ascii=False, indent=2)
