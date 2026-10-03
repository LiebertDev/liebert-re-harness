"""Owned .NET metadata P0 + structural IL P1 (no full decompiler)."""
from __future__ import annotations

import json
import struct
from pathlib import Path

MAX_IL_BYTES = 64 * 1024
MAX_INSTRUCTIONS = 512
MAX_DOTNET_FILE_BYTES = 64 * 1024 * 1024

# Sentinel operand "size" for InlineSwitch (ECMA-335 II.23.2): a 4-byte
# branch count N followed by N 4-byte branch offsets -- the only opcode
# operand whose length is data-dependent rather than fixed by the opcode
# itself. Handled specially in the decode loop below, never treated as a
# fixed byte count.
_SWITCH_OPERAND = -1

# Fixed operand byte length for every ECMA-335 OperandType (II.23.1.16).
# InlineSwitch is data-dependent (see _SWITCH_OPERAND above); InlinePhi is
# reserved/unused by any real opcode and treated as no operand.
_OPERAND_SIZE = {
    "InlineNone": 0, "InlinePhi": 0,
    "ShortInlineBrTarget": 1, "ShortInlineI": 1, "ShortInlineVar": 1,
    "InlineVar": 2,
    "InlineBrTarget": 4, "InlineField": 4, "InlineI": 4, "InlineMethod": 4,
    "InlineSig": 4, "InlineString": 4, "InlineTok": 4, "InlineType": 4,
    "ShortInlineR": 4,
    "InlineI8": 8, "InlineR": 8,
    "InlineSwitch": _SWITCH_OPERAND,
}


def _load_opcode_tables():
    """Build the complete one-byte and 0xFE-prefixed two-byte CIL opcode
    tables from the FLARE team's `dncil` library (Apache-2.0, ECMA-335 CIL
    disassembler used by capa) rather than hand-transcribing ECMA-335
    ourselves -- GAP 2 fix: the previous hand-written table only covered
    32/54 opcodes seen in one real method, and because IL instructions are
    variable-length, the first UNSUPPORTED_OPCODE silently desynchronised
    every following byte offset. Returns (one_byte, two_byte, error) where
    error is None on success; on any failure both tables are None so the
    caller fails closed (TOOL_MISSING) instead of silently falling back to
    an incomplete table."""
    try:
        from dncil.cil.opcode import OpCodes as _DncilOpCodes
    except ImportError as exc:
        return None, None, f"{type(exc).__name__}: {exc}"
    try:
        codes = _DncilOpCodes()
        one_byte: dict[int, tuple[str, int]] = {}
        two_byte: dict[int, tuple[str, int]] = {}
        for i in range(256):
            entry = codes.one_byte_op_codes[i]
            if entry.name not in ("UNKNOWN1", "UNKNOWN2"):
                one_byte[i] = (entry.name, _OPERAND_SIZE[entry.operand_type.name])
            entry2 = codes.two_byte_op_codes[i]
            if entry2.name not in ("UNKNOWN1", "UNKNOWN2"):
                two_byte[i] = (entry2.name, _OPERAND_SIZE[entry2.operand_type.name])
        return one_byte, two_byte, None
    except Exception as exc:  # pragma: no cover - dncil API shape change
        return None, None, f"{type(exc).__name__}: {exc}"


# opcode -> (mnemonic, extra_operand_bytes) ; 0xFE-prefixed two-byte opcodes
# keyed separately. None tables + OPCODE_TABLE_ERROR set means dncil was not
# importable/usable -- parse_il_body then refuses (TOOL_MISSING) rather than
# silently decoding against an incomplete table.
OPCODES, FE_OPCODES, OPCODE_TABLE_ERROR = _load_opcode_tables()


def _j(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


def _rva_to_offset(pe, rva: int) -> int | None:
    for section in pe.sections:
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < start + size:
            return section.PointerToRawData + (rva - start)
    return None


def parse_dotnet_metadata(path: str | Path) -> dict:
    target = Path(path)
    try:
        import dnfile
        import pefile
    except ImportError as exc:
        return {"ok": False, "status": "TOOL_MISSING", "error": type(exc).__name__, "execution_performed": False}
    try:
        size = target.stat().st_size
        if size <= 0 or size > MAX_DOTNET_FILE_BYTES:
            return {
                "ok": False, "status": "ANALYSIS_LIMITED",
                "error": "DOTNET_FILE_SIZE_LIMIT", "size": size,
                "maximum": MAX_DOTNET_FILE_BYTES, "execution_performed": False,
            }
        data = target.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": f"NOT_PE:{type(exc).__name__}", "execution_performed": False}
    clr = None
    try:
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14:
            clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    except Exception:
        clr = None
    if not clr or not clr.VirtualAddress:
        return {
            "ok": False,
            "status": "NOT_DOTNET",
            "error": "NOT_DOTNET",
            "path": str(target),
            "execution_performed": False,
        }
    try:
        dn = dnfile.dnPE(data=data)
    except Exception as exc:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": f"MALFORMED_METADATA:{type(exc).__name__}", "execution_performed": False}
    if not getattr(dn, "net", None):
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "METADATA_ROOT_MISSING", "execution_performed": False}
    streams = []
    try:
        for stream in getattr(dn.net, "streams", []) or []:
            streams.append({
                "name": getattr(stream, "name", None) or getattr(stream, "Name", None),
                "offset": getattr(stream, "offset", None) or getattr(stream, "Offset", None),
                "size": getattr(stream, "size", None) or getattr(stream, "Size", None),
            })
    except Exception:
        streams = []
    assembly = {}
    try:
        row = dn.net.mdtables.Assembly.rows[0]
        assembly = {
            "name": str(row.Name),
            "version": f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}",
        }
    except Exception:
        assembly = {}
    types = []
    methods = []
    try:
        for typedef in dn.net.mdtables.TypeDef.rows:
            full = ".".join(x for x in (str(typedef.TypeNamespace or ""), str(typedef.TypeName or "")) if x)
            types.append(full)
            for method in typedef.MethodList:
                methods.append({
                    "type": full,
                    "name": str(method.row.Name),
                    "rva": int(method.row.Rva or 0),
                    "rva_hex": hex(int(method.row.Rva or 0)),
                    "token": f"0x060{method.row_index:05X}",
                })
    except Exception as exc:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "error": f"TYPE_TABLE:{type(exc).__name__}", "execution_performed": False}
    refs = []
    try:
        for row in dn.net.mdtables.AssemblyRef.rows:
            refs.append({"name": str(row.Name), "version": f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"})
    except Exception:
        refs = []
    return {
        "ok": True,
        "status": "PARTIAL",
        "tool": "dotnet_metadata_p0",
        "path": str(target),
        "clr_rva": hex(clr.VirtualAddress),
        "clr_size": int(clr.Size),
        "streams": streams,
        "assembly": assembly,
        "types": types[:200],
        "type_count": len(types),
        "types_truncated": len(types) > 200,
        "methods": methods[:400],
        "method_count": len(methods),
        "methods_truncated": len(methods) > 400,
        "references": refs[:100],
        "reference_count": len(refs),
        "references_truncated": len(refs) > 100,
        "claims_ceiling": {"metadata": "PROVEN", "il": "UNKNOWN", "decompile": "UNKNOWN"},
        "execution_performed": False,
    }


def parse_il_body(data: bytes, file_offset: int) -> dict:
    if OPCODES is None or FE_OPCODES is None:
        return {
            "ok": False, "status": "TOOL_MISSING", "error": "DNCIL_OPCODE_TABLE_UNAVAILABLE",
            "detail": OPCODE_TABLE_ERROR, "execution_performed": False,
        }
    if file_offset < 0 or file_offset >= len(data):
        return {"ok": False, "error": "INVALID_RVA", "file_offset": file_offset}
    available = len(data) - file_offset
    if available < 1:
        return {"ok": False, "error": "TRUNCATED_BODY"}
    header0 = data[file_offset]
    kind = header0 & 0x03
    if kind == 0x02:
        code_size = header0 >> 2
        header_size = 1
        max_stack = 8
        local_var_sig = 0
        more_sects = False
        init_locals = False
        header_kind = "tiny"
    elif kind == 0x03:
        if available < 12:
            return {"ok": False, "error": "MALFORMED_FAT_HEADER", "available": available}
        flags, max_stack, code_size, local_var_sig = struct.unpack_from("<HHII", data, file_offset)
        header_size = ((flags >> 12) & 0x0F) * 4
        if header_size < 12 or file_offset + header_size > len(data):
            return {"ok": False, "error": "MALFORMED_FAT_HEADER", "header_size": header_size}
        more_sects = bool(flags & 0x08)
        init_locals = bool(flags & 0x10)
        header_kind = "fat"
    else:
        return {"ok": False, "error": "MALFORMED_FAT_HEADER", "flags": hex(header0)}
    code_start = file_offset + header_size
    if code_size < 0 or code_size > MAX_IL_BYTES or code_start + code_size > len(data):
        return {"ok": False, "error": "TRUNCATED_BODY", "code_size": code_size}
    code = data[code_start:code_start + code_size]
    instructions = []
    errors = []
    offset = 0
    while offset < len(code) and len(instructions) < MAX_INSTRUCTIONS:
        start = offset  # offset of this instruction's opcode byte(s)
        op = code[offset]
        offset += 1
        if op == 0xFE:
            if offset >= len(code):
                errors.append({"error": "INVALID_INSTRUCTION_OPERAND", "offset": start})
                break
            sub = code[offset]
            offset += 1
            info = FE_OPCODES.get(sub)
            opcode_hex = hex(0xFE00 | sub)
        else:
            info = OPCODES.get(op)
            opcode_hex = hex(op)
        if not info:
            # GAP 2 fix: an unrecognised opcode STOPS the walk here rather
            # than continuing at a guessed offset. IL instructions are
            # variable-length, so once one opcode is misread every later
            # offset in this method is untrustworthy -- a truncated-but-
            # correct disassembly is useful, a complete-looking wrong one is
            # the worst failure mode this project tracks. This guard stays
            # even though the table below is now the complete ECMA-335 set
            # (derived from dncil, not hand-transcribed), because a
            # genuinely malformed/obfuscated stream can still desync.
            errors.append({"error": "UNSUPPORTED_OPCODE", "opcode": opcode_hex, "offset": start})
            instructions.append({"offset": start, "mnemonic": "UNSUPPORTED_OPCODE", "opcode": opcode_hex})
            break
        name, extra = info
        if extra == _SWITCH_OPERAND:
            # InlineSwitch (ECMA-335 II.23.2): a 4-byte branch count N
            # followed by N 4-byte branch-target offsets -- the operand
            # length is data-dependent, computed here rather than looked up.
            if offset + 4 > len(code):
                errors.append({"error": "INVALID_INSTRUCTION_OPERAND", "mnemonic": name, "offset": start})
                break
            (branch_count,) = struct.unpack_from("<I", code, offset)
            extra = 4 + branch_count * 4
        if extra and offset + extra > len(code):
            errors.append({"error": "INVALID_INSTRUCTION_OPERAND", "mnemonic": name, "offset": start})
            break
        operand = code[offset:offset + extra].hex() if extra else None
        offset += extra
        instructions.append({"offset": start, "mnemonic": name, "operand": operand})
    return {
        "ok": not any(e.get("error") in {"INVALID_INSTRUCTION_OPERAND", "TRUNCATED_BODY", "MALFORMED_FAT_HEADER"} for e in errors),
        "header_kind": header_kind,
        "header_size": header_size,
        "code_size": code_size,
        "max_stack": max_stack,
        "local_var_sig": local_var_sig,
        "exception_section_present": more_sects,
        "init_locals": init_locals,
        "instructions": instructions,
        "errors": errors[:32],
        "error_count": len(errors),
        "errors_truncated": len(errors) > 32,
        "unsupported_opcodes": sum(1 for e in errors if e.get("error") == "UNSUPPORTED_OPCODE"),
    }


def parse_dotnet_il(path: str | Path, *, method_name: str | None = None, max_methods: int = 12) -> dict:
    meta = parse_dotnet_metadata(path)
    if not meta.get("ok"):
        return meta
    target = Path(path)
    size = target.stat().st_size
    if size <= 0 or size > MAX_DOTNET_FILE_BYTES:
        return {
            "ok": False, "status": "ANALYSIS_LIMITED", "error": "DOTNET_FILE_SIZE_LIMIT",
            "size": size, "maximum": MAX_DOTNET_FILE_BYTES, "execution_performed": False,
        }
    data = target.read_bytes()
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    selected = meta.get("methods") or []
    if method_name:
        selected = [row for row in selected if method_name.lower() in str(row.get("name") or "").lower()]
    bodies = []
    for row in selected[: max(1, int(max_methods))]:
        rva = int(row.get("rva") or 0)
        if rva <= 0:
            bodies.append({**row, "ok": False, "error": "INVALID_RVA"})
            continue
        off = _rva_to_offset(pe, rva)
        if off is None:
            bodies.append({**row, "ok": False, "error": "INVALID_RVA", "rva": rva})
            continue
        parsed = parse_il_body(data, off)
        bodies.append({**row, **parsed})
    ok = any(row.get("ok") for row in bodies)
    return {
        **{k: v for k, v in meta.items() if k not in {"claims_ceiling"}},
        "tool": "dotnet_il_structural_p1",
        "ok": ok,
        "status": "PARTIAL" if ok else "ANALYSIS_LIMITED",
        "il_methods": bodies,
        "claims_ceiling": {"metadata": "PROVEN", "il": "PARTIAL" if ok else "UNKNOWN", "decompile": "UNKNOWN"},
        "limitations": ["Structural IL only; no semantic decompile or type reconstruction"],
        "execution_performed": False,
    }


def dotnet_metadata_inspect(path: str) -> str:
    from liebert_re.workspace import relative, safe_path
    report = parse_dotnet_metadata(safe_path(path))
    report["path"] = relative(safe_path(path))
    return _j(report)


def dotnet_il_inspect(path: str, method_name: str = "", max_methods: int = 12) -> str:
    from liebert_re.workspace import relative, safe_path
    report = parse_dotnet_il(safe_path(path), method_name=method_name or None, max_methods=max_methods)
    report["path"] = relative(safe_path(path))
    return _j(report)
