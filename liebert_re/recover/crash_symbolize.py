"""Offline crash symbolization P1: module + RVA → nearest public symbol. No unwind."""
from __future__ import annotations

import json
from pathlib import Path

from liebert_re.recover.codeview_rsds import extract_pe_rsds, extract_pe_section_map, module_basename_match
from liebert_re.recover.minidump_structural import parse_minidump
from liebert_re.recover.msf_pdb import correlate_pe_pdb_identity, lookup_symbol_by_rva, parse_pdb


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
    pe_own_rsds = None
    pe_facts: dict = {}
    dump_module = None
    # Upper bounds (exclusive) for a valid RVA, from whichever sources exist.
    range_bounds: dict[str, int] = {}
    if int(rva) < 0:
        return _refuse_rva(result, range_bounds, "RVA is negative")
    if pe_path:
        pe_report = extract_pe_rsds(pe_path)
        pe_rsds = pe_report.get("rsds") if pe_report.get("ok") else None
        pe_own_rsds = pe_rsds
        pe_facts["rsds_error"] = None if pe_report.get("ok") else pe_report.get("error")
        section_report = extract_pe_section_map(pe_path)
        pe_sections = section_report.get("sections") if section_report.get("ok") else []
        result["pe_section_map_status"] = section_report.get("status")
        if section_report.get("ok"):
            pe_facts["size_of_image"] = section_report.get("size_of_image") or None
            pe_facts["time_date_stamp"] = section_report.get("time_date_stamp")
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
            dump_module = item
            cv = (item.get("codeview") or {}).get("rsds")
            if cv and cv.get("ok"):
                pe_rsds = cv
            if item.get("image_size"):
                range_bounds["minidump_image_size"] = int(item["image_size"])
    # The PDB is tied to the dump by RSDS, but the section map -- and so every
    # symbol address -- comes from the caller's PE. Without proof that this PE is
    # the module the dump loaded, that map can be another build's.
    if pe_path:
        binding = _bind_pe_to_dump_module(pe_own_rsds, pe_facts, dump_module)
        result["pe_binding"] = binding
        result["pe_bound_to_dump_module"] = {"BOUND": True, "MISMATCH": False}.get(binding["status"])
        # Its SizeOfImage is only a valid bound if the file is the dump's module.
        if binding["status"] in {"BOUND", "NOT_APPLICABLE"} and pe_facts.get("size_of_image"):
            range_bounds["pe_size_of_image"] = int(pe_facts["size_of_image"])
    else:
        binding = None
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
    if binding is not None and binding["status"] not in {"BOUND", "NOT_APPLICABLE"}:
        # Never derive an address from a section map that may belong to another
        # build. The identity facts gathered above stay in the result.
        result["status"] = "ANALYSIS_LIMITED"
        result["confidence"] = "LOW"
        result["limitation"] = "PE_NOT_BOUND_TO_DUMP_MODULE: " + binding["reason"]
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


def _bind_pe_to_dump_module(pe_rsds: dict | None, pe_facts: dict, dump_module: dict | None) -> dict:
    """Is the caller's PE the file the dump's module was loaded from?

    BOUND: the PE's own debug-directory CodeView record equals the dump
    module's (GUID and age) and no supporting field contradicts it.
    MISMATCH: the two were measured and differ.
    UNVERIFIABLE: a side could not be read, so equality was never measured.
    NOT_APPLICABLE: no dump module to bind to (PE queried on its own).
    Supporting fields (SizeOfImage, COFF TimeDateStamp) can only veto: they are
    the dump's image_size / timestamp, and an unreadable one is UNCHECKED, not a
    failure. File checksum and whole-file hash are deliberately not required.
    """
    if dump_module is None:
        return {"status": "NOT_APPLICABLE", "checks": {},
                "reason": "no dump module matched; the PE is the only source of the section map"}
    checks: dict[str, dict] = {}
    dump_rsds = (dump_module.get("codeview") or {}).get("rsds")
    if not (dump_rsds and dump_rsds.get("ok")):
        checks["rsds"] = {"status": "DUMP_RSDS_UNAVAILABLE"}
    elif not (pe_rsds and pe_rsds.get("ok")):
        checks["rsds"] = {"status": "PE_RSDS_UNREADABLE", "error": pe_facts.get("rsds_error")}
    else:
        same = (str(pe_rsds.get("guid")).upper() == str(dump_rsds.get("guid")).upper()
                and pe_rsds.get("age") == dump_rsds.get("age"))
        checks["rsds"] = {"status": "MATCH" if same else "MISMATCH",
                          "pe": pe_rsds.get("identity_key"), "dump": dump_rsds.get("identity_key")}
    for name, pe_key, dump_key in (("size_of_image", "size_of_image", "image_size"),
                                   ("timestamp", "time_date_stamp", "timestamp")):
        pe_value, dump_value = pe_facts.get(pe_key), dump_module.get(dump_key)
        if pe_value is None or dump_value is None:
            checks[name] = {"status": "UNCHECKED", "pe": pe_value, "dump": dump_value}
        else:
            checks[name] = {"status": "MATCH" if int(pe_value) == int(dump_value) else "MISMATCH",
                            "pe": int(pe_value), "dump": int(dump_value)}
    mismatched = [k for k, v in checks.items() if v["status"] == "MISMATCH"]
    if mismatched:
        status, reason = "MISMATCH", "does not match the dump module: " + ", ".join(mismatched)
    elif checks["rsds"]["status"] != "MATCH":
        status, reason = "UNVERIFIABLE", "rsds could not be compared: " + checks["rsds"]["status"]
    else:
        status, reason = "BOUND", "rsds, and every readable supporting field, match the dump module"
    return {"status": status, "checks": checks, "reason": reason}


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
    from liebert_re.workspace import safe_path
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
