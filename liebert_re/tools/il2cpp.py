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
from liebert_re.bounded_subprocess import launch_failure, run_bounded_process
from liebert_re.workspace import safe_path, relative


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
        if cp.launch_failed is True:
            return _j(launch_failure(cp, "il2cpp_mapper", "IL2CPPDUMPER_LAUNCH_FAILED"))
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


def il2cpp_status():
    """Whether Il2CppDumper is reachable, where from, whether it actually runs, and
    its version -- the capability probe to run before reporting IL2CPP mapping as
    unavailable.

    Runs `Il2CppDumper --help` once (prints its usage line and exits; no binary or
    metadata file is opened). The tool has no version switch, so `version` is read
    from the exe's own version resource (Windows API, runs nothing) and
    `version_source` says so; it is null when the resource is unreadable. Statuses:
    `OK`, `TOOL_MISSING`, `TIMEOUT`, `ANALYSIS_LIMITED`. `resolved_by` is
    IL2CPPDUMPER_EXE (a file path, or a name on PATH) or bundled_fallback.
    """
    tool = "il2cpp_status"
    try:
        exe = _il2cppdumper()
        if not exe:
            return _j({
                "ok": False, "tool": tool, "status": "TOOL_MISSING", "resolved": False,
                "required_capability": "Il2CppDumper console build (Il2CppDumper.exe)",
                "detail": (
                    "Il2CppDumper.exe was not found. Set IL2CPPDUMPER_EXE to its full path, or "
                    "install it at "
                    f"{Path.home() / 'teacher-tools' / 'il2cppdumper' / 'Il2CppDumper.exe'}. "
                    "il2cpp_mapper cannot run until then."
                ),
                "env_set": {"IL2CPPDUMPER_EXE": bool(os.getenv("IL2CPPDUMPER_EXE", "").strip())},
            })

        def _same(a, b):
            return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))

        explicit = os.getenv("IL2CPPDUMPER_EXE", "").strip()
        resolved_by = "bundled_fallback"
        if explicit and any(_same(exe, c) for c in (explicit, shutil.which(explicit) or explicit)):
            resolved_by = "IL2CPPDUMPER_EXE"
        cp = run_bounded_process([exe, "--help"], timeout_seconds=15, max_output_chars=4096)
        if cp.launch_failed is True:
            return _j({**launch_failure(cp, tool, "IL2CPPDUMPER_LAUNCH_FAILED"), "binary": exe, "resolved_by": resolved_by, "runnable": False})
        if cp.timed_out or cp.cancelled:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "IL2CPPDUMPER_HELP_TIMEOUT"})
        text = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        if cp.returncode not in (0, None) or "il2cppdumper" not in text.lower():
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "IL2CPPDUMPER_HELP_UNREADABLE",
                       "exit_code": cp.returncode, "output_tail": text[-500:],
                       "detail": "The file resolved but did not print its usage line when run, so it is not known to work."})
        version = None
        if os.name == "nt":  # the exe's own version resource, via the OS API: reads it, runs nothing
            try:
                import ctypes
                from ctypes import wintypes
                api = ctypes.WinDLL("version", use_last_error=True)
                api.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
                api.GetFileVersionInfoSizeW.restype = wintypes.DWORD
                api.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
                api.GetFileVersionInfoW.restype = wintypes.BOOL
                api.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
                api.VerQueryValueW.restype = wintypes.BOOL
                size = api.GetFileVersionInfoSizeW(exe, None)
                if size:
                    buf = ctypes.create_string_buffer(size)
                    if api.GetFileVersionInfoW(exe, 0, size, buf):
                        ptr, length = ctypes.c_void_p(), wintypes.UINT()
                        if api.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(length)) and length.value >= 4:
                            lang, page = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort * 2)).contents
                            if api.VerQueryValueW(buf, rf"\StringFileInfo\{lang:04x}{page:04x}\ProductVersion",
                                                  ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                                version = ctypes.wstring_at(ptr.value, length.value).rstrip(chr(0)).strip() or None
            except Exception:  # noqa: BLE001 - a missing version is reported as null, never an error
                version = None
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": resolved_by, "runnable": True,
            "version": version, "version_source": "exe_version_resource" if version else "unavailable",
            "usage": text.splitlines()[0].strip() if text else None,
            "operations": ["il2cpp_mapper", "il2cpp_status"],
            "note": (
                "OK means Il2CppDumper started and printed its usage line; it was not run on any file. "
                "il2cpp_mapper needs a GameAssembly/executable plus its global-metadata.dat and can take "
                "minutes on a real pair."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IL2CPPDUMPER_STATUS_UNEXPECTED_ERROR",
                   "detail": f"{type(exc).__name__}: {exc}"})
