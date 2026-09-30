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
    if pe_path:
        pe_report = extract_pe_rsds(pe_path)
        pe_rsds = pe_report.get("rsds") if pe_report.get("ok") else None
        section_report = extract_pe_section_map(pe_path)
        pe_sections = section_report.get("sections") if section_report.get("ok") else []
        result["pe_section_map_status"] = section_report.get("status")
        if pe_rsds is None and not pe_report.get("ok"):
            result["pe_rsds_error"] = pe_report.get("error")
    if minidump_path:
        dump = parse_minidump(minidump_path)
        result["minidump_ok"] = dump.get("ok")
        for item in ((dump.get("modules") or {}).get("items") or []):
            if module_basename_match(item.get("name", ""), module):
                cv = (item.get("codeview") or {}).get("rsds")
                if cv and cv.get("ok"):
                    pe_rsds = cv
                break
    if pe_rsds is None:
        result["status"] = "NO_RSDS"
        result["confidence"] = "LOW"
        return result
    if not pdb_path:
        result["status"] = "PDB_NOT_FOUND"
        result["identity"] = {"status": "PDB_NOT_FOUND"}
        result["confidence"] = "LOW"
        return result
    parsed = parse_pdb(pdb_path)
    info = parsed.get("info_stream") or {}
    identity = correlate_pe_pdb_identity(pe_rsds, info)
    result["identity"] = identity
    if not parsed.get("ok") or not info.get("ok"):
        result["status"] = "UNSUPPORTED"
        result["confidence"] = "LOW"
        return result
    if not identity.get("identity_match"):
        result["status"] = "MISMATCH" if identity.get("status") == "MISMATCH" else identity.get("status") or "WRONG_PDB"
        result["confidence"] = "HIGH"
        return result
    symbols = (parsed.get("public_symbols") or {}).get("symbols") or []
    if not symbols:
        result["status"] = "NO_PUBLIC_SYMBOLS"
        result["confidence"] = "MEDIUM"
        return result
    lookup = lookup_symbol_by_rva(symbols, int(rva), sections=pe_sections)
    match = lookup.get("match")
    result["lookup_status"] = lookup.get("status")
    if lookup.get("status") == "SECTION_MAP_REQUIRED":
        result["status"] = "SECTION_MAP_REQUIRED"
        result["confidence"] = "HIGH"
        return result
    if lookup.get("status") == "BEFORE_FIRST" or match is None:
        result["status"] = "BEFORE_FIRST"
        result["confidence"] = "MEDIUM"
        return result
    symbol_rva = int(match.get("rva") or 0)
    result["symbol"] = match.get("name")
    result["symbol_rva"] = symbol_rva
    result["offset_from_symbol"] = int(rva) - symbol_rva
    result["status"] = "MATCH"
    result["confidence"] = "HIGH" if lookup.get("status") == "EXACT" else "MEDIUM"
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
