"""Offline crash symbolization P1: module + RVA → nearest public symbol. No unwind."""
from __future__ import annotations

import json
from pathlib import Path

from codeview_rsds import extract_pe_rsds, extract_pe_section_map, module_basename_match
from minidump_structural import parse_minidump
from msf_pdb import correlate_pe_pdb_identity, lookup_symbol_by_rva, parse_pdb


def symbolize_rva(
    *,
    module: str,
    rva: int,
    pe_path: str | Path | None = None,
    pdb_path: str | Path | None = None,
    minidump_path: str | Path | None = None,
) -> dict:
    result = {
        "ok": True,
        "tool": "offline_crash_symbolization_p1",
        "module": module,
        "rva": int(rva),
        "symbol": None,
        "symbol_rva": None,
        "offset_from_symbol": None,
        "confidence": "UNKNOWN",
        "status": "NO_PDB",
        "identity": None,
        "stack_unwind": "UNKNOWN",
        "source_line": None,
        "execution_performed": False,
    }
    pe_rsds = None
    pe_sections = None
    # Upper bounds (exclusive) for a valid RVA, from whichever sources exist.
    range_bounds: dict[str, int] = {}
    if int(rva) < 0:
        return _refuse_rva(result, range_bounds, "RVA is negative")
    if pe_path:
        pe_report = extract_pe_rsds(pe_path)
        pe_rsds = pe_report.get("rsds") if pe_report.get("ok") else None
        section_report = extract_pe_section_map(pe_path)
        pe_sections = section_report.get("sections") if section_report.get("ok") else []
        result["pe_section_map_status"] = section_report.get("status")
        if section_report.get("ok") and section_report.get("size_of_image"):
            range_bounds["pe_size_of_image"] = int(section_report["size_of_image"])
        if pe_rsds is None and not pe_report.get("ok"):
            result["pe_rsds_error"] = pe_report.get("error")
    if minidump_path:
        dump = parse_minidump(minidump_path)
        result["minidump_ok"] = dump.get("ok")
        candidates = [
            item for item in ((dump.get("modules") or {}).get("items") or [])
            if module_basename_match(item.get("name", ""), module)
        ]
        # Basename equality is a candidate filter, not an identity: two loaded
        # modules can share a file name from different directories. The PDB
        # GUID/age check below is what proves a PDB belongs to the module, but
        # it cannot tell which same-named module the caller MEANT, so narrow by
        # full path when the caller gave one and refuse when still ambiguous.
        if len(candidates) > 1 and _has_directory(module):
            wanted = _norm_path(module)
            narrowed = [c for c in candidates if _norm_path(c.get("name", "")) == wanted]
            if narrowed:
                candidates = narrowed
        if len(candidates) > 1:
            result["ok"] = False
            result["status"] = "AMBIGUOUS_MODULE"
            result["confidence"] = "LOW"
            result["candidates"] = [c.get("name", "") for c in candidates]
            return _confidence_describes_the_symbol(result)
        if candidates:
            item = candidates[0]
            cv = (item.get("codeview") or {}).get("rsds")
            if cv and cv.get("ok"):
                pe_rsds = cv
            if item.get("image_size"):
                range_bounds["minidump_image_size"] = int(item["image_size"])
    over = {k: v for k, v in range_bounds.items() if int(rva) >= v}
    if over:
        return _refuse_rva(result, range_bounds, "RVA is outside the module's image")
    if pe_rsds is None:
        result["status"] = "NO_RSDS"
        result["confidence"] = "LOW"
        return _confidence_describes_the_symbol(result)
    if not pdb_path:
        result["status"] = "PDB_NOT_FOUND"
        result["identity"] = {"status": "PDB_NOT_FOUND"}
        result["confidence"] = "LOW"
        return _confidence_describes_the_symbol(result)
    parsed = parse_pdb(pdb_path)
    info = parsed.get("info_stream") or {}
    identity = correlate_pe_pdb_identity(pe_rsds, info)
    result["identity"] = identity
    if not parsed.get("ok") or not info.get("ok"):
        result["status"] = "UNSUPPORTED"
        result["confidence"] = "LOW"
        return _confidence_describes_the_symbol(result)
    if not identity.get("identity_match"):
        result["status"] = "MISMATCH" if identity.get("status") == "MISMATCH" else identity.get("status") or "WRONG_PDB"
        result["confidence"] = "HIGH"
        return _confidence_describes_the_symbol(result)
    symbols = (parsed.get("public_symbols") or {}).get("symbols") or []
    if not symbols:
        result["status"] = "NO_PUBLIC_SYMBOLS"
        result["confidence"] = "MEDIUM"
        return _confidence_describes_the_symbol(result)
    lookup = lookup_symbol_by_rva(symbols, int(rva), sections=pe_sections)
    match = lookup.get("match")
    result["lookup_status"] = lookup.get("status")
    if lookup.get("status") == "SECTION_MAP_REQUIRED":
        result["status"] = "SECTION_MAP_REQUIRED"
        result["confidence"] = "HIGH"
        return _confidence_describes_the_symbol(result)
    if lookup.get("status") == "BEFORE_FIRST" or match is None:
        result["status"] = "BEFORE_FIRST"
        result["confidence"] = "MEDIUM"
        return _confidence_describes_the_symbol(result)
    symbol_rva = int(match.get("rva") or 0)
    result["symbol"] = match.get("name")
    result["symbol_rva"] = symbol_rva
    result["offset_from_symbol"] = int(rva) - symbol_rva
    result["status"] = "MATCH"
    result["confidence"] = "HIGH" if lookup.get("status") == "EXACT" else "MEDIUM"
    return _confidence_describes_the_symbol(result)


def _has_directory(name: str) -> bool:
    return "/" in str(name) or "\\" in str(name)


def _norm_path(name: str) -> str:
    return str(name).replace("\\", "/").casefold()


def _refuse_rva(result: dict, bounds: dict, reason: str) -> dict:
    """A caller error, refused by name -- never symbolised against the nearest symbol."""
    result["ok"] = False
    result["status"] = "RVA_OUT_OF_MODULE_RANGE"
    result["confidence"] = "LOW"
    result["error"] = reason
    result["module_rva_upper_bounds"] = dict(bounds)
    return _confidence_describes_the_symbol(result)


def _confidence_describes_the_symbol(result: dict) -> dict:
    """`confidence` rates the returned symbol, so it cannot outrank having one.

    The field is initialised to UNKNOWN beside `symbol: None`, and the match
    branch is the only place that earns HIGH (an EXACT lookup). Three earlier
    branches contradicted that by hand: a PDB whose identity does not match the
    crashing module returned `confidence: "HIGH"` with `symbol: None`, and so did
    SECTION_MAP_REQUIRED, while NO_PUBLIC_SYMBOLS and BEFORE_FIRST returned
    MEDIUM with no symbol either. A caller ranking results by confidence would
    have put a wrong-PDB answer above a real, merely non-exact one -- and the
    wrong-PDB case is exactly the one the documentation warns about.

    HIGH on a mismatch was not meaningless, it was the wrong field: the verdict
    "this PDB definitely does not belong to this module" is indeed certain. That
    certainty lives in `status` and `identity`, which say so precisely. This
    function keeps `confidence` answering one question only, and a no-symbol
    result is never allowed to claim more than LOW.
    """
    if result.get("symbol") is None and result.get("confidence") in {"HIGH", "MEDIUM"}:
        result["confidence"] = "LOW"
    return result

def crash_symbolize(
    module: str,
    rva: str = "0",
    pe_path: str = "",
    pdb_path: str = "",
    minidump_path: str = "",
) -> str:
    """ToolBus-facing workspace-contained wrapper around symbolize_rva."""
    from tools_workspace import safe_path
    try:
        address = int(str(rva), 0)
    except (TypeError, ValueError):
        return json.dumps({"ok": False, "error": "INVALID_ADDRESS", "rva": rva}, ensure_ascii=False, indent=2)
    try:
        safe_pe = safe_path(pe_path) if pe_path else None
        safe_pdb = safe_path(pdb_path) if pdb_path else None
        safe_minidump = safe_path(minidump_path) if minidump_path else None
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": "PATH_OUTSIDE_WORKSPACE", "detail": str(exc)}, ensure_ascii=False, indent=2)
    report = symbolize_rva(
        module=module,
        rva=address,
        pe_path=safe_pe,
        pdb_path=safe_pdb,
        minidump_path=safe_minidump,
    )
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)
