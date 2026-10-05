"""Minidump analyzer: structural parse + best-effort crash symbolization +
heuristic stack scan.

This module never claims more than what is proven:
  - Structural facts (streams, modules, threads, exception, memory inventory)
    come straight from ``minidump_structural.parse_minidump`` and are proven.
  - Crash-address symbolization is only as strong as the RSDS identity match
    performed by ``crash_symbolize.symbolize_rva``; it is UNKNOWN unless a
    supplied PDB's identity matches the crashing module.
  - The "stack scan" is a heuristic 8-byte-aligned pointer scan over captured
    stack bytes, not a proven call stack. It is explicitly NOT unwind: no
    frame-pointer or unwind-info validation is performed, so it will include
    false positives from stale stack data, spilled registers, and unrelated
    values that merely happen to fall inside a module's address range.
"""
from __future__ import annotations

import json

from liebert_re.recover.crash_symbolize import symbolize_rva
from liebert_re.recover.minidump_structural import MAX_MEMORY_READ_BYTES, parse_minidump, read_memory_at_va

MAX_STACK_SCAN_BYTES = MAX_MEMORY_READ_BYTES


def _module_containing_address(modules: list[dict], va: int) -> dict | None:
    """Find the module whose [base, base+image_size) range contains va.

    ``modules`` is ``structural['modules']['items']`` from ``parse_minidump``;
    ``base_address`` is a hex string like ``'0x7FF6...'``.
    """
    for module in modules or []:
        try:
            base = int(str(module.get("base_address")), 16)
            image_size = int(module.get("image_size") or 0)
        except (TypeError, ValueError):
            continue
        if image_size <= 0:
            continue
        if base <= va < base + image_size:
            return {"name": module.get("name"), "base_address": module.get("base_address"), "rva": va - base}
    return None


def analyze_minidump(path: str, *, pe_path: str = "", pdb_path: str = "", max_stack_candidates: int = 20) -> dict:
    """Structural parse + best-effort crash symbolization + heuristic stack scan."""
    structural = parse_minidump(path)
    if not structural.get("ok"):
        result = dict(structural)
        result["analysis_class"] = "MINIDUMP_ANALYZER_V1"
        result["tool"] = "minidump_analyzer"
        return result

    result = dict(structural)
    modules_items = ((structural.get("modules") or {}).get("items")) or []

    # 1. Crash symbolization.
    crash_symbol = None
    crash_symbol_reason = None
    exception = structural.get("exception")
    if not exception or not exception.get("address"):
        crash_symbol_reason = "NO_EXCEPTION_STREAM_PRESENT"
    else:
        try:
            address_int = int(str(exception["address"]), 16)
        except (TypeError, ValueError):
            address_int = None
        if address_int is None:
            crash_symbol_reason = "INVALID_EXCEPTION_ADDRESS"
        else:
            module_hit = _module_containing_address(modules_items, address_int)
            if module_hit is None:
                crash_symbol_reason = "CRASH_ADDRESS_NOT_INSIDE_ANY_KNOWN_MODULE"
            else:
                crash_symbol = symbolize_rva(
                    module=module_hit["name"],
                    rva=module_hit["rva"],
                    pe_path=pe_path or None,
                    pdb_path=pdb_path or None,
                    minidump_path=str(path),
                )
    result["crash_symbol"] = crash_symbol
    if crash_symbol is None:
        result["crash_symbol_reason"] = crash_symbol_reason

    # 2. Heuristic stack scan (NOT proven unwind).
    architecture = (structural.get("system_info") or {}).get("architecture")
    threads_items = ((structural.get("threads") or {}).get("items")) or []
    any_captured_stack = False
    max_stack_candidates = max(0, int(max_stack_candidates))
    for thread in threads_items:
        stack = thread.get("stack") or {}
        data_size = int(stack.get("data_size") or 0)
        candidates: list[dict] = []
        thread["stack_scan_candidates"] = candidates
        if data_size <= 0:
            thread["stack_scan_status"] = "NO_CAPTURED_STACK"
            continue
        if architecture != "x86_64":
            thread["stack_scan_status"] = f"SKIPPED_UNSUPPORTED_ARCHITECTURE:{architecture}"
            continue
        try:
            start_va = int(str(stack.get("start")), 16)
        except (TypeError, ValueError):
            thread["stack_scan_status"] = "INVALID_STACK_START"
            continue
        read_size = min(data_size, MAX_STACK_SCAN_BYTES)
        mem = read_memory_at_va(path, start_va, read_size)
        if not mem.get("ok"):
            thread["stack_scan_status"] = mem.get("status") or "NOT_CAPTURED"
            continue
        any_captured_stack = True
        raw = bytes.fromhex(mem["data_hex"])
        truncated = read_size < data_size
        limits_reached = ["max_stack_scan_bytes"] if truncated else []
        omitted = 0
        for offset in range(0, len(raw) - 7, 8):
            value = int.from_bytes(raw[offset:offset + 8], "little")
            hit = _module_containing_address(modules_items, value)
            if hit is None:
                continue
            if len(candidates) >= max_stack_candidates:
                # Keep counting (without symbolizing) so the omission is stated.
                omitted += 1
                continue
            candidate = {
                "stack_offset": offset,
                "candidate_address": hex(value),
                "module": hit["name"],
                "rva": hit["rva"],
            }
            if pdb_path:
                try:
                    sym = symbolize_rva(
                        module=hit["name"],
                        rva=hit["rva"],
                        pe_path=pe_path or None,
                        pdb_path=pdb_path or None,
                        minidump_path=str(path),
                    )
                    if sym.get("status") == "MATCH":
                        candidate["symbol"] = sym.get("symbol")
                        candidate["symbol_offset"] = sym.get("offset_from_symbol")
                except Exception:
                    pass
            candidates.append(candidate)
        if omitted:
            limits_reached.append("max_stack_candidates")
        thread["stack_scan_limits_reached"] = limits_reached
        thread["stack_scan_truncated"] = bool(limits_reached)
        # Candidates omitted by the candidate limit; the bytes beyond the byte
        # limit were never read, so no count exists for them.
        thread["stack_scan_candidates_omitted"] = omitted
        thread["stack_scan_status"] = "SCANNED_TRUNCATED" if limits_reached else "SCANNED"

    # 3. Claims ceiling + limitations.
    ceiling = dict(structural.get("claims_ceiling") or {})
    ceiling["crash_symbol"] = "PROVEN_WHEN_PDB_MATCHED" if (crash_symbol and crash_symbol.get("status") == "MATCH") else "UNKNOWN"
    ceiling["stack_scan_candidates"] = "HEURISTIC_NOT_PROVEN_UNWIND" if any_captured_stack else "NOT_CAPTURED"
    result["claims_ceiling"] = ceiling

    limitations = list(structural.get("limitations") or [])
    limitations.append(
        "Stack-scan candidates are NOT a proven call stack: no frame-pointer or "
        "unwind-info validation is performed. Any 8-byte-aligned value that "
        "happens to point into a module's address range is included, which "
        "will include false positives from stale stack data, spilled "
        "registers, and other coincidental matches."
    )
    result["limitations"] = limitations

    result["ok"] = True
    result["status"] = "READY"
    result["tool"] = "minidump_analyzer"
    result["analysis_class"] = "MINIDUMP_ANALYZER_V1"
    return result


def minidump_analyzer(path: str, pe_path: str = "", pdb_path: str = "", max_stack_candidates: int = 20) -> str:
    """ToolBus-facing workspace-contained minidump analyzer."""
    from liebert_re.workspace import relative, safe_path

    target = safe_path(path)
    pe_target = safe_path(pe_path) if pe_path else None
    pdb_target = safe_path(pdb_path) if pdb_path else None
    report = analyze_minidump(
        str(target),
        pe_path=str(pe_target) if pe_target is not None else "",
        pdb_path=str(pdb_target) if pdb_target is not None else "",
        max_stack_candidates=max_stack_candidates,
    )
    report["tool"] = "minidump_analyzer"
    report["path"] = relative(target)
    if pe_target is not None:
        report["pe_path"] = relative(pe_target)
    if pdb_target is not None:
        report["pdb_path"] = relative(pdb_target)
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)
