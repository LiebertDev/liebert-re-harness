"""What lives past the end of a PE's last section (the "overlay"), read in place and attributed
only as far as the file itself proves it.

One operation: ``pe_trailing_data(path)``. It is a sibling of ``pe_runtime_functions`` rather
than a mode of ``pe_sections``: the structural readers in ``binary.py`` answer one directory each
as text, while this one combines three header fields into a JSON verdict with its own status
vocabulary, the way ``pe_unwind.py`` does.

The trailing region is ``[end of the last raw section, end of file)``. The end of the last raw
section is the largest ``PointerToRawData + SizeOfRawData`` over sections that have raw data.

Attribution, in order, each independent of the others:

  * **Authenticode.** The security data directory (index 4) holds a *file offset*, not an RVA.
    A certificate table normally sits in the trailing region and is labelled as such, so a
    signed file never produces an "unknown trailing data" answer for its signature. Only the
    part of the declared range that lies inside the trailing region is attributed; a directory
    pointing elsewhere is reported under ``security_directory`` and attributes nothing.
    ``certificate_entries`` is a walk of the WIN_CERTIFICATE headers; the signature is NOT
    verified here (use ``authenticode_signature``).
  * **COFF symbols.** If ``PointerToSymbolTable`` is non-zero and inside the trailing region,
    the minimum size is ``NumberOfSymbols * 18 + 4`` and, when the 4-byte string-table length
    is readable, the full size is ``NumberOfSymbols * 18`` plus that length. Whether that fits
    the file is ``coff_symbol_table.state``: ``CONSISTENT`` means *consistent with* a symbol
    table and string table (the arithmetic fits; the records are not decoded), ``DOES_NOT_FIT``
    says the arithmetic does not.
  * **Everything left** is trailing data of ``purpose: "UNKNOWN"``, with its size and a Shannon
    entropy in bits per byte as a plain number. The entropy is not a verdict: a high and a low
    value are both just unexplained. ``all_zero`` is a measurement, not a reading of intent.

Status vocabulary (each one a distinct answer; ``ok`` is false only for the last group):

  ``NO_TRAILING_DATA``             the file ends at the last section's raw data.
  ``TRAILING_FULLY_ATTRIBUTED``    every trailing byte is inside an attributed range.
  ``TRAILING_PARTLY_ATTRIBUTED``   some is, and ``unattributed`` lists the rest as UNKNOWN.
  ``TRAILING_UNKNOWN``             trailing data exists and none of it is attributed.
  ``SECTION_TABLE_UNUSABLE``       the end of the last section cannot be computed (no sections,
                                   fewer sections parsed than declared, or raw data declared
                                   past the end of the file). The question is not answered.
  ``TOOL_MISSING`` / ``NOT_A_PE`` / ``NOT_FOUND`` / ``PATH_REFUSED``  as the other tools here.
"""
from __future__ import annotations

import json
import math
import struct
from collections import Counter

from liebert_re.workspace import relative, safe_path

_TOOL = "pe_trailing_data"
_SYMBOL_SIZE = 18
_DIRECTORY_SECURITY = 4
_STATEMENT = ("Trailing data is described by its offset, size and what the headers say about it. "
              "'Consistent with' is an arithmetic fit, not a decode; UNKNOWN is not a finding of "
              "benign or malicious, and an Authenticode range is located, not verified.")


def _j(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _fail(status: str, **extra) -> str:
    return _j({"ok": False, "tool": _TOOL, "status": status, "statement": _STATEMENT, **extra})


def _entropy(data: bytes):
    if not data:
        return None
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()), 4)


def _security_directory(pe, data: bytes, region_start: int, size: int) -> dict:
    dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", None) or []
    if len(dirs) <= _DIRECTORY_SECURITY:
        return {"state": "ABSENT", "detail": "the optional header has no security directory entry"}
    off, length = int(dirs[_DIRECTORY_SECURITY].VirtualAddress), int(dirs[_DIRECTORY_SECURITY].Size)
    if not off and not length:
        return {"state": "ABSENT"}
    out = {"file_offset": off, "size": length, "note": "the security directory's address is a file offset, not an RVA"}
    if not length or off < region_start or off >= size:
        out["state"] = "OUTSIDE_TRAILING_REGION"
        out["within_trailing_region"] = False
        return out
    end = min(off + length, size)
    out["within_trailing_region"] = True
    out["state"] = "DECLARED" if off + length <= size else "DECLARED_PAST_END_OF_FILE"
    out["attributed_range"] = {"offset": off, "size": end - off}
    entries, at, walk_ok = [], off, True
    while at < end:
        if end - at < 8:
            walk_ok = False
            break
        dw_length, revision, cert_type = struct.unpack_from("<IHH", data, at)
        if dw_length < 8 or at + dw_length > off + length:
            walk_ok = False
            break
        entries.append({"offset": at, "length": dw_length, "revision": hex(revision), "type": hex(cert_type)})
        at += (dw_length + 7) & ~7
    out["certificate_entries"] = entries[:16]
    out["certificate_entry_count"] = len(entries)
    out["header_walk_consistent"] = walk_ok and bool(entries)
    return out


def _coff(data: bytes, pe, region_start: int, size: int, cert) -> dict:
    ptr, count = int(pe.FILE_HEADER.PointerToSymbolTable), int(pe.FILE_HEADER.NumberOfSymbols)
    if not ptr:
        return {"state": "ABSENT", "number_of_symbols": count}
    out = {"file_offset": ptr, "number_of_symbols": count}
    if ptr < region_start or ptr >= size:
        out["state"] = "OUTSIDE_TRAILING_REGION"
        out["detail"] = ("the pointer is past the end of the file" if ptr >= size
                         else "the pointer lies inside the section data, not in the trailing region")
        return out
    out["minimum_size"] = count * _SYMBOL_SIZE + 4
    if count == 0:
        out["state"] = "DECLARED_EMPTY"
        out["detail"] = "a symbol table pointer is set but zero symbols are declared; nothing is attributed"
        return out
    out["available_bytes"] = size - ptr
    if ptr + out["minimum_size"] > size:
        out["state"] = "DOES_NOT_FIT"
        out["detail"] = (f"{count} symbols of {_SYMBOL_SIZE} bytes plus the 4-byte string-table length "
                         f"need {out['minimum_size']} bytes; {size - ptr} remain in the file")
        return out
    strtab = struct.unpack_from("<I", data, ptr + count * _SYMBOL_SIZE)[0]
    out["declared_string_table_length"] = strtab
    if strtab < 4:
        out["state"] = "DOES_NOT_FIT"
        out["detail"] = "the string-table length prefix is below 4, the size of the prefix itself"
        return out
    total = count * _SYMBOL_SIZE + strtab
    out["expected_size"] = total
    if ptr + total > size:
        out["state"] = "DOES_NOT_FIT"
        out["detail"] = f"symbols plus the declared string table need {total} bytes; {size - ptr} remain in the file"
        return out
    if cert and ptr < cert["offset"] + cert["size"] and cert["offset"] < ptr + total:
        out["state"] = "OVERLAPS_SECURITY_DIRECTORY"
        out["detail"] = "the range the symbol table would occupy overlaps the declared certificate table; nothing is attributed"
        return out
    out["state"] = "CONSISTENT"
    out["attributed_range"] = {"offset": ptr, "size": total}
    out["note"] = "consistent with a COFF symbol table and string table; the records were not decoded"
    return out


def pe_trailing_data(path):
    """Report the bytes past the end of the last section: whether they exist, where, how big, what
    fraction of the file, and which part is explained by the security directory or a COFF symbol
    table. The remainder is reported as UNKNOWN purpose. Read-only; the file is read in place."""
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _fail("PATH_REFUSED", error=str(exc))
    if not p.is_file():
        return _fail("NOT_FOUND", path=str(path))
    try:
        import pefile
    except ImportError:
        return _fail("TOOL_MISSING", required_capability="pefile (pip install pefile)")
    try:
        data = p.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:  # noqa: BLE001
        return _fail("NOT_A_PE", error=f"{type(exc).__name__}: {exc}")
    try:
        size = len(data)
        base = {"path": relative(p), "file_size": size}
        declared = int(pe.FILE_HEADER.NumberOfSections)
        if declared == 0 or len(pe.sections) < declared:
            return _fail("SECTION_TABLE_UNUSABLE", **base, declared_sections=declared, parsed_sections=len(pe.sections),
                         error=("the file declares no sections" if declared == 0
                                else "fewer section headers could be read than the file declares"))
        cut = [s.Name.rstrip(b"\x00").decode(errors="replace") for s in pe.sections
               if s.SizeOfRawData and s.PointerToRawData + s.SizeOfRawData > size]
        if cut:
            return _fail("SECTION_TABLE_UNUSABLE", **base,
                         error="raw data declared by section(s) extends past the end of the file: " + ", ".join(cut))
        ends = [int(s.PointerToRawData) + int(s.SizeOfRawData) for s in pe.sections if s.SizeOfRawData]
        if not ends:
            return _fail("SECTION_TABLE_UNUSABLE", **base, error="no section has raw data, so no end of section data exists")
        start = max(ends)
        trailing = size - start
        sec = _security_directory(pe, data, start, size)
        cert = sec.get("attributed_range")
        coff = _coff(data, pe, start, size, cert)
        result = {
            "ok": True, "tool": _TOOL, **base, "last_section_raw_end": start,
            "trailing": {"exists": trailing > 0, "offset": start, "size": trailing,
                         "fraction_of_file": round(trailing / size, 4) if size else None},
            "security_directory": sec, "coff_symbol_table": coff, "statement": _STATEMENT,
        }
        if trailing <= 0:
            result.update(status="NO_TRAILING_DATA", attributed=[], unattributed=[])
            return _j(result)
        spans = sorted((r["offset"], r["offset"] + r["size"], kind) for kind, r in
                       (("AUTHENTICODE_CERTIFICATE_TABLE", cert), ("COFF_SYMBOL_AND_STRING_TABLE", coff.get("attributed_range")))
                       if r)
        result["attributed"] = [
            {"kind": k, "offset": a, "size": b - a,
             "basis": ("security data directory (a file offset)" if k.startswith("AUTH")
                       else "PointerToSymbolTable and NumberOfSymbols; consistent with, not decoded")} for a, b, k in spans]
        rest, at = [], start
        for a, b, _ in spans:
            if a > at:
                rest.append((at, a))
            at = max(at, b)
        if at < size:
            rest.append((at, size))
        result["unattributed"] = [
            {"offset": a, "size": b - a, "purpose": "UNKNOWN", "entropy_bits_per_byte": _entropy(data[a:b]),
             "all_zero": not any(data[a:b])} for a, b in rest]
        result["status"] = ("TRAILING_FULLY_ATTRIBUTED" if not rest else
                            "TRAILING_PARTLY_ATTRIBUTED" if spans else "TRAILING_UNKNOWN")
        return _j(result)
    finally:
        pe.close()
