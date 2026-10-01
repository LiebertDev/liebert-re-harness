"""Detect (never install) an already-present native compiler that can emit MSF PDBs."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from tools_workspace import PROJECT_ROOT as APP
SOURCE = APP / "dataset" / "runtime" / "qwen8b_safe_fixtures" / "owned_native" / "owned_native.c"
OUT_DIR = APP / "dataset" / "runtime" / "qwen8b_safe_fixtures" / "owned_native"
VSWHERE = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"


def _which(name: str) -> str | None:
    found = shutil.which(name)
    return found


# The component id an installation must declare to actually carry cl.exe.
VC_TOOLSET_COMPONENT = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"


def _vswhere_query(arguments: list) -> str | None:
    if not VSWHERE.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(VSWHERE)] + arguments,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    return lines[0] if lines else None


def _vswhere_find(pattern: str) -> str | None:
    """Ask every installation, not just the newest one.

    Measured on a real host: `-latest` selects the newest *installation*, which
    was Visual Studio 2022 Community without the C++ workload, while the
    toolchain lived in a separate 2022 Build Tools installation. The query
    returned nothing and the harness reported the compiler as absent when it was
    present -- a detection defect reported as an environment gap, which is the
    kind of wrong answer that quietly turns into a permanent "known failure".

    So the newest installation is a preference, not a filter: ask the ones that
    declare the C++ toolset first, then fall back to any installation at all.
    """
    for arguments in (
        ["-latest", "-products", "*", "-requires", VC_TOOLSET_COMPONENT, "-find", pattern],
        ["-products", "*", "-requires", VC_TOOLSET_COMPONENT, "-find", pattern],
        ["-products", "*", "-find", pattern],
    ):
        hit = _vswhere_query(arguments)
        if hit:
            return hit
    return None


def detect_native_pdb_toolchain() -> dict:
    cl = _which("cl") or _vswhere_find(r"**\Hostx64\x64\cl.exe")
    # Do not resolve `link` via a bare shutil.which("link") PATH lookup: Git for
    # Windows ships its own unrelated `link.exe` (a Unix-like tool) in usr/bin,
    # which sits earlier on PATH than MSVC's linker on hosts where vcvars64.bat
    # hasn't been sourced. Always resolve link.exe next to the detected cl.exe
    # instead, so the two are guaranteed to come from the same VC toolchain.
    link = None
    if cl:
        candidate = Path(cl).resolve().parent / "link.exe"
        if candidate.is_file():
            link = str(candidate)
    if not link:
        link = _vswhere_find(r"**\Hostx64\x64\link.exe")
    vcvars = None
    if cl:
        candidate = Path(cl).resolve()
        for parent in candidate.parents:
            hit = parent / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
            if hit.is_file():
                vcvars = str(hit)
                break
    status = "READY" if cl and link else "NOT_EXECUTED_NO_NATIVE_PDB_TOOLCHAIN"
    return {
        "ok": bool(cl and link),
        "status": status,
        "cl": cl,
        "link": link,
        "vcvars64": vcvars,
        "dotnet": _which("dotnet"),
        "installation_performed": False,
    }


def owned_native_artifacts() -> dict:
    exe = OUT_DIR / "owned_native.exe"
    pdb = OUT_DIR / "owned_native.pdb"
    present = exe.is_file() and pdb.is_file()
    return {
        "ok": present,
        "exe": str(exe) if exe.is_file() else None,
        "pdb": str(pdb) if pdb.is_file() else None,
        "source": str(SOURCE) if SOURCE.is_file() else None,
        "status": "PRESENT" if present else "MISSING",
    }


def build_owned_native_pdb(*, timeout_seconds: int = 90) -> dict:
    """Compile the owned C fixture with an already-installed MSVC toolchain. Never installs."""
    tool = detect_native_pdb_toolchain()
    if not tool.get("ok"):
        return {
            "ok": False,
            "status": "NOT_EXECUTED_NO_NATIVE_PDB_TOOLCHAIN",
            "toolchain": tool,
            "installation_performed": False,
        }
    if not SOURCE.is_file():
        return {"ok": False, "status": "NOT_EXECUTED", "error": "SOURCE_MISSING", "toolchain": tool}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    obj = OUT_DIR / "owned_native.obj"
    exe = OUT_DIR / "owned_native.exe"
    pdb = OUT_DIR / "owned_native.pdb"
    script = OUT_DIR / "_build_owned_native.bat"
    lines = ["@echo off"]
    if tool.get("vcvars64"):
        lines.append(f'call "{tool["vcvars64"]}"')
    lines.append(f'"{tool["cl"]}" /nologo /c /Zi /Od /W3 /DWIN32 /Fo"{obj.name}" "{SOURCE.name}"')
    lines.append('if errorlevel 1 exit /b 1')
    lines.append(f'"{tool["link"]}" /nologo /DEBUG /INCREMENTAL:NO /OUT:"{exe.name}" /PDB:"{pdb.name}" "{obj.name}"')
    script.write_text("\r\n".join(lines) + "\r\n", encoding="ascii")
    try:
        completed = subprocess.run(
            ["cmd.exe", "/c", str(script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            cwd=str(OUT_DIR),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "status": "NOT_EXECUTED", "error": "COMPILE_TIMEOUT", "detail": str(exc)[:300], "toolchain": tool}
    artifacts = owned_native_artifacts()
    ok = artifacts["ok"] and completed.returncode == 0
    return {
        "ok": ok,
        "status": "BUILT" if ok else "BUILD_FAILED",
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[-2000:],
        "stderr": (completed.stderr or "")[-2000:],
        "artifacts": artifacts,
        "toolchain": {"cl": tool["cl"], "link": tool["link"], "vcvars64": tool.get("vcvars64")},
        "installation_performed": False,
        "execution_performed": False,
    }


def validate_owned_native_pdb(exe_path: str | Path | None = None, pdb_path: str | Path | None = None) -> dict:
    """Read-only validation of a real owned native EXE+PDB pair."""
    from codeview_rsds import extract_pe_rsds
    from msf_pdb import correlate_pe_pdb_identity, detect_pdb_container, lookup_symbol_by_rva, parse_pdb

    artifacts = owned_native_artifacts()
    exe = Path(exe_path) if exe_path else Path(artifacts["exe"] or "")
    pdb = Path(pdb_path) if pdb_path else Path(artifacts["pdb"] or "")
    if not exe.is_file() or not pdb.is_file():
        return {
            "ok": False,
            "status": "NOT_EXECUTED_NO_REAL_OWNED_NATIVE_PDB",
            "error": "ARTIFACTS_MISSING",
            "artifacts": artifacts,
        }
    head = pdb.read_bytes()[:64]
    kind = detect_pdb_container(head)
    parsed = parse_pdb(pdb)
    pe = extract_pe_rsds(exe)
    info = parsed.get("info_stream") or {}
    identity = correlate_pe_pdb_identity(pe.get("rsds") if pe.get("ok") else None, info)
    publics = parsed.get("public_symbols") or {}
    symbols = publics.get("symbols") or []
    names = [row.get("name") for row in symbols]
    wanted = ("OwnedEntry", "OwnedHelper", "OwnedCompute")
    found_wanted = [name for name in wanted if any(name in str(n) for n in names)]
    lookups = {}
    for row in symbols[:8]:
        off = int(row.get("offset") or 0)
        lookups[str(row.get("name"))] = lookup_symbol_by_rva(symbols, off)
    unsupported = []
    if kind != "MSF7":
        unsupported.append("NOT_MSF")
    if not info.get("ok"):
        unsupported.append("INFOSTREAM")
    if not (parsed.get("dbi") or {}).get("ok"):
        unsupported.append("DBI")
    if not publics.get("public_symbol_stream_present"):
        unsupported.append("PUBLIC_SYMBOL_STREAM")
    if publics.get("unsupported_records"):
        unsupported.append("UNSUPPORTED_SYMBOL_RECORDS")
    if not found_wanted:
        unsupported.append("OWNED_SYMBOL_NAMES")
    status = "PASS"
    if not parsed.get("ok") or kind != "MSF7" or not info.get("ok"):
        status = "FAIL"
    elif unsupported or not identity.get("identity_match") or not found_wanted:
        status = "PARTIAL_REAL_PDB_SUPPORT"
    return {
        "ok": status in {"PASS", "PARTIAL_REAL_PDB_SUPPORT"},
        "status": status,
        "format": kind,
        "msf_ok": bool(parsed.get("ok")),
        "info_stream": {"ok": info.get("ok"), "guid": info.get("guid"), "age": info.get("age")},
        "pe_rsds": pe.get("rsds") if pe.get("ok") else pe,
        "identity": identity,
        "dbi": {"ok": bool((parsed.get("dbi") or {}).get("ok")), "status": (parsed.get("dbi") or {}).get("status")},
        "public_symbols": {
            "present": publics.get("public_symbol_stream_present"),
            "records_parsed": publics.get("records_parsed"),
            "status": publics.get("status"),
            "names": names[:40],
            "wanted_found": found_wanted,
            "unsupported_records": publics.get("unsupported_records") or 0,
        },
        "lookups": lookups,
        "unsupported": unsupported,
        "pdb_symbol_records": parsed.get("pdb_symbol_records"),
        "claims_ceiling": parsed.get("claims_ceiling"),
        "execution_performed": False,
    }


if __name__ == "__main__":
    print(json.dumps({"detect": detect_native_pdb_toolchain(), "build": build_owned_native_pdb()}, indent=2))
