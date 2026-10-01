"""Static UPX unpacking -- a real, generic capability gap this benchmark
program's Tier-2 blind runs surfaced: a UPX-compressed section cannot be
meaningfully decompiled (the real program logic is compressed bytes, not
instructions, until reversed). UPX's own official CLI (MIT-licensed,
github.com/upx/upx) reverses UPX's own public, documented, deterministic
compression format -- this is a static, algorithmic byte transform, not
execution of the target's own program logic, and follows the same
untrusted-artifact discipline as every other parser in this harness: the
operator's own trusted `upx.exe` processes untrusted DATA, never runs the
crackme's code.

Deliberately narrow: this wraps `upx -d` (decompress) only, always against
a COPY of the input written to a bounded evidence-cache location, never
mutating the original. It does not attempt to unpack any protector other
than UPX (VMProtect/Themida/etc. are out of scope and would need their own,
separately-verified capabilities if a real gap for them is found).
"""
from __future__ import annotations
import hashlib
import json
import os
import shutil
from pathlib import Path
from bounded_subprocess import run_bounded_process
from tools_workspace import PROJECT_ROOT, safe_path, relative

EVIDENCE = PROJECT_ROOT / "dataset" / "evidence" / "upx_unpacked"
EVIDENCE.mkdir(parents=True, exist_ok=True)


def _upx_binary():
    explicit = os.getenv("UPX_HOME", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        candidate = p / "upx.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("upx")
    if found:
        return found
    tools = Path.home() / "teacher-tools" / "upx" / "upx.exe"
    if tools.exists():
        return str(tools)
    return None


def _j(x):
    return json.dumps(x, ensure_ascii=False, indent=2, default=str)


def upx_unpack(path, timeout_seconds=60, cancellation_token=None):
    """Statically decompress a UPX-packed PE via the real upx.exe -d, on a
    disposable copy. Returns the unpacked copy's path/sha256/size alongside
    the original's, or a real TOOL_MISSING/UPX_UNPACK_FAILED status.
    """
    exe = _upx_binary()
    if not exe:
        return _j({
            "ok": False, "tool": "upx_unpack", "status": "TOOL_MISSING",
            "required_capability": "UPX CLI (upx.exe)",
        })
    try:
        p = safe_path(path)
        original_bytes = p.read_bytes()
        original_sha256 = hashlib.sha256(original_bytes).hexdigest()
        original_size = len(original_bytes)

        work_copy = EVIDENCE / f"{original_sha256}_input{p.suffix or '.exe'}"
        work_copy.write_bytes(original_bytes)
        output_path = EVIDENCE / f"{original_sha256}_unpacked{p.suffix or '.exe'}"
        if output_path.exists():
            output_path.unlink()

        cp = run_bounded_process(
            [exe, "-d", "-o", str(output_path), str(work_copy)],
            timeout_seconds=timeout_seconds,
            cancellation_token=cancellation_token,
        )
        if cp.timed_out or cp.cancelled:
            return _j({
                "ok": False, "tool": "upx_unpack",
                "status": "CANCELLED" if cp.cancelled else "TIMEOUT",
                "stdout": cp.stdout, "stderr": cp.stderr,
            })
        if cp.returncode != 0 or not output_path.exists():
            return _j({
                "ok": False, "tool": "upx_unpack", "status": "UPX_UNPACK_FAILED",
                "exit_code": cp.returncode, "stdout": cp.stdout, "stderr": cp.stderr,
                "note": "Non-zero exit or missing output usually means the input is not actually UPX-packed, or uses a UPX variant/version this upx.exe cannot reverse.",
            })

        unpacked_bytes = output_path.read_bytes()
        unpacked_sha256 = hashlib.sha256(unpacked_bytes).hexdigest()
        return _j({
            "ok": True, "tool": "upx_unpack", "status": "UNPACKED",
            "input_path": relative(p),
            "input_sha256": original_sha256, "input_size_bytes": original_size,
            "output_path": str(output_path),
            "output_sha256": unpacked_sha256, "output_size_bytes": len(unpacked_bytes),
            "note": "output_path is a disposable evidence-cache copy outside the workspace's original artifact; the original input file was never modified.",
        })
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "tool": "upx_unpack", "status": "UPX_UNPACK_FAILED", "error": str(exc)})
