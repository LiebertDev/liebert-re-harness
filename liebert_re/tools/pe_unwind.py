"""Read a 64-bit PE's RUNTIME_FUNCTION table (exception directory / ``.pdata``).

What it is for: **function extent**, not function discovery. Each entry carries
an exact begin RVA and end RVA, so "where does the function containing this
address begin and end" is answered from the file alone, with no disassembler
and no external tool. The file is read in place (never copied).

Two operations:

  ``pe_runtime_functions(path)``           the whole table, summarised, with
                                           a bounded page of entries.
  ``pe_function_extent(path, address)``    the entry containing one address,
                                           in the ``pe_address`` address-form
                                           contract (``va`` / ``rva`` /
                                           ``file_offset``).

Honesty ceilings, carried in every result under ``coverage``:

  * Leaf functions (no stack allocation, no non-volatile register use, no
    handler) get NO entry. The table is never a complete function list, and
    "not in the table" is not "not code". ``coverage.complete`` is always
    false and ``coverage.absence_is_evidence_of_no_function`` is always false.
  * Entries with ``UNW_FLAG_CHAININFO`` continue another function. They are
    fragments, counted apart from primary functions
    (``primary_function_count`` vs ``raw_entry_count``); a fragment resolves
    to the primary it belongs to, or says ``UNKNOWN``.
  * ``end_rva`` is exclusive (one past the last byte), as stored.
  * An entry's extent is its own contiguous range; the fragments of the same
    function are separate entries and are not included in a primary's extent.

Status vocabulary (each one a distinct answer):

  ``OK``                    table read in full (``pe_runtime_functions``).
  ``FUNCTION_FOUND``        the address lies inside exactly one entry.
                            ``classification`` is ``primary``, ``chained_fragment``
                            or ``UNKNOWN``; ``is_fragment`` is true, false or
                            null (null exactly when classification is UNKNOWN).
  ``ADDRESS_NOT_COVERED``   table read in full; no entry contains the address.
                            Says nothing about whether the address is code.
  ``AMBIGUOUS_COVERAGE``    more than one entry contains the address
                            (overlapping entries; the file is malformed).
  ``ADDRESS_UNRESOLVED``    the address does not resolve to a mapped location
                            (``error`` is ``pe_address``'s own reason).
  ``NO_EXCEPTION_DIRECTORY`` 64-bit PE whose exception directory is empty.
  ``X86_NO_PDATA``          machine 0x14c: 32-bit x86 has no ``.pdata``; its
                            exception handling is stack based. Not an empty
                            table -- there is no table to read.
  ``UNSUPPORTED_ARCHITECTURE`` / ``UNSUPPORTED_OPTIONAL_HEADER`` /
  ``PE_HEADER_INCONSISTENT``  a machine or header this module does not read
                            (ARM and ARM64 use a different ``.pdata`` format).
  ``TABLE_UNREADABLE``      the directory points at no mapped data.
  ``TABLE_TRUNCATED``       the table is cut short or its size is not a
                            multiple of 12. For a lookup this is returned
                            instead of ``ADDRESS_NOT_COVERED`` (a partial table
                            cannot prove absence); a hit inside the readable
                            part is still ``FUNCTION_FOUND`` with
                            ``table_complete: false``.
  ``TOOL_MISSING`` / ``NOT_A_PE`` / ``NOT_FOUND`` / ``PATH_REFUSED`` /
  ``INVALID_ARGUMENT``      as the other tools in this package.

``ok`` is true only for ``OK``, ``FUNCTION_FOUND`` and ``ADDRESS_NOT_COVERED``.
"""
from __future__ import annotations

import json
import struct

from liebert_re.recover.pe_address import resolve_address_form
from liebert_re.workspace import relative, safe_path

_ENTRY_SIZE = 12
_DIRECTORY_EXCEPTION = 3
_MAGIC_PE32, _MAGIC_PE32PLUS = 0x10B, 0x20B
_MACHINE_I386, _MACHINE_AMD64 = 0x14C, 0x8664
_UNW_FLAG_CHAININFO = 0x4
_KNOWN_FLAGS = 0x1 | 0x2 | _UNW_FLAG_CHAININFO  # EHANDLER, UHANDLER, CHAININFO
_MAX_CHAIN_DEPTH = 64
_DEFAULT_PAGE = 1000
_MAX_PAGE = 100000

_COVERAGE = {
    "complete": False,
    "absence_is_evidence_of_no_function": False,
    "ceiling": (
        "leaf functions get no RUNTIME_FUNCTION entry, so this table is never a complete function list; "
        "an address that is not in it may still be code"
    ),
    "extent": (
        "an entry's extent is its own contiguous range; fragments of the same function are separate entries"
    ),
}


def _j(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _fail(tool: str, status: str, **extra) -> str:
    return _j({"ok": False, "tool": tool, "status": status, "coverage": _COVERAGE, **extra})


def _read(pe, rva: int, size: int) -> bytes:
    try:
        return pe.get_data(rva, size) or b""
    except Exception:  # noqa: BLE001
        return b""


def _classify(pe, unwind_rva: int):
    """``(kind, parent, note)``; kind is PRIMARY, FRAGMENT or UNCLASSIFIED.
    ``parent`` is the chained ``(begin, end)`` pair, or None."""
    if unwind_rva & 1:
        return "UNCLASSIFIED", None, "indirect unwind data (low bit set) is not followed"
    head = _read(pe, unwind_rva, 4)
    if len(head) < 4:
        return "UNCLASSIFIED", None, "unwind info is not readable"
    version, flags = head[0] & 7, head[0] >> 3
    if version not in (1, 2):
        return "UNCLASSIFIED", None, f"unwind info version {version} is not 1 or 2"
    if flags & ~_KNOWN_FLAGS:
        return "UNCLASSIFIED", None, f"unwind info has undefined flag bits (0x{flags & ~_KNOWN_FLAGS:x}); not classified"
    if not flags & _UNW_FLAG_CHAININFO:
        return "PRIMARY", None, None
    chain_at = unwind_rva + 4 + ((head[2] + 1) & ~1) * 2
    raw = _read(pe, chain_at, _ENTRY_SIZE)
    if len(raw) < _ENTRY_SIZE:
        return "FRAGMENT", None, "chained parent entry is not readable"
    return "FRAGMENT", struct.unpack("<III", raw)[:2], None


def _parse_table(pe, data: bytes) -> list:
    entries = []
    for i in range(len(data) // _ENTRY_SIZE):
        begin, end, unwind = struct.unpack_from("<III", data, i * _ENTRY_SIZE)
        if end <= begin:
            entries.append({"index": i, "begin_rva": begin, "end_rva": end, "kind": "MALFORMED",
                            "parent_begin": None, "note": "end RVA is not greater than begin RVA"})
            continue
        kind, parent, note = _classify(pe, unwind)
        entries.append({"index": i, "begin_rva": begin, "end_rva": end, "kind": kind,
                        "parent_begin": parent, "note": note})
    # The chained record names its parent by (begin, end); index by that pair and
    # treat a pair held by more than one entry as unresolvable, never first-wins.
    by_key = {}
    for e in entries:
        if e["kind"] != "MALFORMED":
            by_key.setdefault((e["begin_rva"], e["end_rva"]), []).append(e)
    for e in entries:
        e["primary_begin"] = None
        e["primary_index"] = None
        e["chain_note"] = None
        if e["kind"] == "PRIMARY":
            e["primary_begin"], e["primary_index"] = e["begin_rva"], e["index"]
        elif e["kind"] == "FRAGMENT":
            cur, seen = e["parent_begin"], set()
            for _ in range(_MAX_CHAIN_DEPTH):
                if cur is None:
                    break
                if cur in seen:
                    e["chain_note"] = "chain contains a cycle"
                    break
                seen.add(cur)
                found = by_key.get(cur, [])
                if not found:
                    break
                if len(found) > 1:
                    e["chain_note"] = "more than one entry has the chained parent's begin and end; parent is ambiguous"
                    break
                target = found[0]
                if target["kind"] == "PRIMARY":
                    e["primary_begin"], e["primary_index"] = target["begin_rva"], target["index"]
                    break
                if target["kind"] != "FRAGMENT":
                    break
                cur = target["parent_begin"]
            else:
                e["chain_note"] = f"chain deeper than {_MAX_CHAIN_DEPTH}; not followed"
    return entries


def _public(e: dict, image_base: int) -> dict:
    out = {
        "begin_rva": hex(e["begin_rva"]), "end_rva": hex(e["end_rva"]),
        "begin_va": hex(image_base + e["begin_rva"]),
        "size": e["end_rva"] - e["begin_rva"] if e["end_rva"] > e["begin_rva"] else None,
        "kind": {"PRIMARY": "primary", "FRAGMENT": "chained_fragment"}.get(e["kind"], e["kind"].lower()),
    }
    if e["kind"] == "FRAGMENT":
        out["primary_begin_rva"] = hex(e["primary_begin"]) if e["primary_begin"] is not None else "UNKNOWN"
        if e.get("chain_note"):
            out["chain_note"] = e["chain_note"]
    if e["note"]:
        out["note"] = e["note"]
    return out


def _load(tool: str, path):
    """``(pe, info)`` on success, or ``(None, error_json)``."""
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return None, _fail(tool, "PATH_REFUSED", error=str(exc))
    if not p.is_file():
        return None, _fail(tool, "NOT_FOUND", path=str(path))
    try:
        import pefile
    except ImportError:
        return None, _fail(tool, "TOOL_MISSING", required_capability="pefile (pip install pefile)")
    try:
        pe = pefile.PE(data=p.read_bytes(), fast_load=True)
    except Exception as exc:  # noqa: BLE001
        return None, _fail(tool, "NOT_A_PE", error=f"{type(exc).__name__}: {exc}")

    machine, magic = int(pe.FILE_HEADER.Machine), int(pe.OPTIONAL_HEADER.Magic)
    base = {"path": relative(p), "machine": hex(machine), "coverage": _COVERAGE}
    dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", None) or []
    dd = dirs[_DIRECTORY_EXCEPTION] if len(dirs) > _DIRECTORY_EXCEPTION else None
    problem = None
    if magic not in (_MAGIC_PE32, _MAGIC_PE32PLUS):
        problem = _fail(tool, "UNSUPPORTED_OPTIONAL_HEADER", optional_header_magic=hex(magic), **base,
                        error="optional-header magic is neither PE32 (0x10b) nor PE32+ (0x20b)")
    elif machine == _MACHINE_I386:
        problem = _fail(tool, "X86_NO_PDATA", **base,
                        exception_directory_size=int(dd.Size) if dd is not None else None,
                        error="32-bit x86 has no .pdata/RUNTIME_FUNCTION table; its exception handling is stack based")
    elif machine != _MACHINE_AMD64:
        problem = _fail(tool, "UNSUPPORTED_ARCHITECTURE", **base,
                        error="only the x64 RUNTIME_FUNCTION layout is read (ARM and ARM64 use a different format)")
    elif magic != _MAGIC_PE32PLUS:
        problem = _fail(tool, "PE_HEADER_INCONSISTENT", optional_header_magic=hex(magic), **base,
                        error="machine type amd64 and optional-header magic disagree about pointer width")
    elif dd is None or not dd.VirtualAddress or not dd.Size:
        problem = _fail(tool, "NO_EXCEPTION_DIRECTORY", **base,
                        error="the exception directory is empty; there is no table to read")
    if problem:
        pe.close()
        return None, problem

    data = _read(pe, int(dd.VirtualAddress), int(dd.Size))
    if not data:
        pe.close()
        return None, _fail(tool, "TABLE_UNREADABLE", **base,
                           exception_directory_rva=hex(int(dd.VirtualAddress)), exception_directory_size=int(dd.Size),
                           error="the exception directory points at no mapped data")
    info = {
        "base": base, "dir_rva": int(dd.VirtualAddress), "dir_size": int(dd.Size),
        "complete": len(data) == int(dd.Size) and len(data) % _ENTRY_SIZE == 0,
        "entries": _parse_table(pe, data), "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
    }
    return pe, info


def _clamp(value, default: int, lo: int, hi: int):
    if value is None:
        return default
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return None


def pe_runtime_functions(path, max_entries=_DEFAULT_PAGE, offset=0):
    """Read a 64-bit PE's RUNTIME_FUNCTION table: counts (raw entries vs primary
    functions vs chained fragments) plus a bounded page of entries
    (``max_entries`` from ``offset``; a cut is reported, never hidden). Not a
    complete function list: see ``coverage`` in the result."""
    tool = "pe_runtime_functions"
    limit, start = _clamp(max_entries, _DEFAULT_PAGE, 1, _MAX_PAGE), _clamp(offset, 0, 0, 1 << 31)
    if limit is None or start is None:
        return _fail(tool, "INVALID_ARGUMENT", error="max_entries and offset must be integers")
    pe, info = _load(tool, path)
    if pe is None:
        return info
    try:
        entries = info["entries"]
        fragments = [e for e in entries if e["kind"] == "FRAGMENT"]
        page = entries[start:start + limit]
        ok = info["complete"]
        payload = {
            "ok": ok, "tool": tool, "status": "OK" if ok else "TABLE_TRUNCATED", **info["base"],
            "image_base": hex(info["image_base"]),
            "exception_directory_rva": hex(info["dir_rva"]), "exception_directory_size": info["dir_size"],
            "table_complete": ok,
            "raw_entry_count": len(entries),
            "primary_function_count": sum(1 for e in entries if e["kind"] == "PRIMARY"),
            "chained_fragment_count": len(fragments),
            "unresolved_fragment_count": sum(1 for e in fragments if e["primary_begin"] is None),
            "unclassified_entry_count": sum(1 for e in entries if e["kind"] == "UNCLASSIFIED"),
            "malformed_entry_count": sum(1 for e in entries if e["kind"] == "MALFORMED"),
            "sorted_by_begin": all(a["begin_rva"] <= b["begin_rva"] for a, b in zip(entries, entries[1:])),
            "offset": start, "entries_returned": len(page),
            "entries_truncated": start + len(page) < len(entries),
            "entries": [_public(e, info["image_base"]) for e in page],
        }
        if not ok:
            payload["error"] = "the table is cut short or its size is not a multiple of 12; only whole entries were read"
        return _j(payload)
    finally:
        pe.close()


def _begin_form(path, rva: int, image_base: int) -> dict:
    form, err = resolve_address_form(path, hex(rva), "rva")
    if form is None:
        return {"rva": hex(rva), "va": hex(image_base + rva), "resolved": False,
                "error": err.get("error") if err else "UNKNOWN"}
    return {**form.to_dict(), "resolved": True}


def pe_function_extent(path, address, address_kind="va"):
    """Where the function containing ``address`` begins and ends, from the
    RUNTIME_FUNCTION table alone. ``address_kind`` is ``va`` (default), ``rva``
    or ``file_offset`` as in ``pe_address.normalize_address``. A chained
    fragment also reports the primary function it belongs to (or ``UNKNOWN``).
    ``ADDRESS_NOT_COVERED`` does not mean the address is not code: see
    ``coverage``."""
    tool = "pe_function_extent"
    pe, info = _load(tool, path)
    if pe is None:
        return info
    try:
        form, err = resolve_address_form(path, address, address_kind)
        if form is None:
            return _fail(tool, "ADDRESS_UNRESOLVED", **info["base"], table_complete=info["complete"],
                         raw_entry_count=len(info["entries"]), address=address, address_kind=address_kind,
                         error=err.get("error") if err else "UNKNOWN", detail=err)
        rva = int(form.rva, 0)
        entries, image_base = info["entries"], info["image_base"]
        hits = [e for e in entries if e["kind"] != "MALFORMED" and e["begin_rva"] <= rva < e["end_rva"]]
        common = {**info["base"], "address": form.to_dict(), "table_complete": info["complete"],
                  "raw_entry_count": len(entries)}
        if len(hits) > 1:
            return _fail(tool, "AMBIGUOUS_COVERAGE", **common, candidates=[_public(e, image_base) for e in hits[:8]],
                         error="more than one entry contains the address; the table is malformed")
        if not hits:
            if not info["complete"]:
                return _fail(tool, "TABLE_TRUNCATED", **common,
                             error="the table is cut short, so absence of an entry proves nothing")
            return _j({"ok": True, "tool": tool, "status": "ADDRESS_NOT_COVERED", **common, "covered": False,
                       "function": None,
                       "note": "no RUNTIME_FUNCTION entry contains this address; leaf functions have none, "
                               "so this does not mean the address is not code"})
        e = hits[0]
        out = _public(e, image_base)
        out["begin"] = _begin_form(path, e["begin_rva"], image_base)
        # The end is one past the last byte and may sit outside every section; then
        # the same shape comes back with resolved: false and the reason.
        out["end_exclusive"] = _begin_form(path, e["end_rva"], image_base)
        out["offset_from_begin"] = rva - e["begin_rva"]
        payload = {"ok": True, "tool": tool, "status": "FUNCTION_FOUND", **common, "covered": True,
                   "classification": out["kind"],
                   "is_fragment": {"PRIMARY": False, "FRAGMENT": True}.get(e["kind"]), "function": out}
        if e["kind"] == "FRAGMENT":
            pi = e["primary_index"]
            payload["primary"] = _public(entries[pi], image_base) if pi is not None else "UNKNOWN"
        elif e["kind"] == "UNCLASSIFIED":
            payload["classification"] = "UNKNOWN"
            payload["note"] = "extent is exact, but whether this entry is a primary function or a fragment is UNKNOWN"
        return _j(payload)
    finally:
        pe.close()
