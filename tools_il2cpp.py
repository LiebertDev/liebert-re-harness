"""Unity IL2CPP metadata/native-method mapping. Shells out to the real,
MIT-licensed Il2CppDumper (Perfare/Il2CppDumper) against a real
GameAssembly.dll + global-metadata.dat pair, then serves bounded queries
over its own script.json output: managed type/method name -> il2cpp
virtual address (the same address value its own IDA/Ghidra companion
scripts consume directly), plus string-literal address recovery. This
module does not itself parse il2cpp metadata/CodeRegistration -- Il2CppDumper
is the real engine; this is a thin, bounded, JSON-normalizing wrapper."""
from __future__ import annotations
import json, os, shutil, tempfile
from pathlib import Path
from bounded_subprocess import run_bounded_process
from tools_workspace import safe_path, relative


def _j(x):
    return json.dumps(x, ensure_ascii=False, indent=2, default=str)


def _il2cppdumper():
    explicit = os.getenv("IL2CPPDUMPER_EXE", "")
    if explicit:
        found = shutil.which(explicit) or (explicit if Path(explicit).exists() else None)
        if found:
            return found
    bundled = Path.home() / "teacher-tools" / "il2cppdumper" / "Il2CppDumper.exe"
    return str(bundled) if bundled.exists() else None


_ADDRESS_NOTE = (
    "Address is the il2cpp virtual address as emitted by Il2CppDumper itself "
    "(the same value its own IDA/Ghidra companion scripts apply directly to "
    "a loaded image) -- not independently re-derived or re-verified by this "
    "adapter."
)


def il2cpp_mapper(binary_path, metadata_path, operation="summary", query="", max_results=100, cancellation_token=None):
    bp = safe_path(binary_path)
    mp = safe_path(metadata_path)
    max_results = max(1, min(int(max_results), 2000))
    exe = _il2cppdumper()
    if not exe:
        return _j({"ok": False, "tool": "il2cpp_mapper", "error": "IL2CPPDUMPER_TOOL_MISSING"})
    with tempfile.TemporaryDirectory(prefix="teacher_il2cpp_") as td:
        cp = run_bounded_process(
            [exe, str(bp), str(mp), td],
            timeout_seconds=180,
            cancellation_token=cancellation_token,
            max_output_chars=200_000,
        )
        if cp.cancelled:
            return _j({"ok": False, "tool": "il2cpp_mapper", "error": "IL2CPPDUMPER_CANCELLED_PROCESS_TREE_TERMINATED"})
        if cp.timed_out:
            return _j({"ok": False, "tool": "il2cpp_mapper", "error": "IL2CPPDUMPER_TIMEOUT_PROCESS_TREE_TERMINATED"})
        script_path = Path(td) / "script.json"
        if not script_path.exists():
            return _j({
                "ok": False, "tool": "il2cpp_mapper", "error": "IL2CPPDUMPER_NO_OUTPUT",
                "stdout_tail": (cp.stdout or "")[-2000:], "stderr_tail": (cp.stderr or "")[-2000:],
            })
        script = json.loads(script_path.read_text(encoding="utf-8"))
        methods = script.get("ScriptMethod", []) or []
        strings = script.get("ScriptString", []) or []
        metadata_defs = script.get("ScriptMetadata", []) or []
        base = {
            "ok": True, "tool": "il2cpp_mapper", "binary_path": relative(bp), "metadata_path": relative(mp),
            "operation": operation, "method_count": len(methods), "string_literal_count": len(strings),
            "metadata_definition_count": len(metadata_defs),
        }
        if operation == "summary":
            return _j(base)
        if operation == "search_methods":
            if not query:
                return _j({**base, "ok": False, "error": "QUERY_REQUIRED"})
            q = query.lower()
            hits = [m for m in methods if q in (m.get("Name") or "").lower()]
            return _j({
                **base, "query": query, "matches": hits[:max_results], "match_count": len(hits),
                "truncated": len(hits) > max_results, "address_note": _ADDRESS_NOTE,
            })
        if operation == "search_strings":
            if not query:
                return _j({**base, "ok": False, "error": "QUERY_REQUIRED"})
            q = query.lower()
            hits = [s for s in strings if q in (s.get("Value") or "").lower()]
            return _j({
                **base, "query": query, "matches": hits[:max_results], "match_count": len(hits),
                "truncated": len(hits) > max_results,
            })
        return _j({**base, "ok": False, "error": "UNSUPPORTED_IL2CPP_OPERATION"})
