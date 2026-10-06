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
import tempfile
from pathlib import Path
from liebert_re.bounded_subprocess import launch_failure, run_bounded_process
from liebert_re.workspace import PROJECT_ROOT, safe_path, relative

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

        suffix = p.suffix or ".exe"
        # The published path stays content-addressed (same input bytes, same name), but nothing is ever
        # written to it directly and a published output is never deleted to make room: each call works
        # in its own scratch directory and promotes with os.replace only on success. A failed or
        # timed-out call therefore cannot remove or alter what an earlier call published.
        output_path = EVIDENCE / f"{original_sha256}_unpacked{suffix}"
        scratch = Path(tempfile.mkdtemp(prefix="scratch-", dir=EVIDENCE))
        try:
            work_copy = scratch / f"input{suffix}"
            work_copy.write_bytes(original_bytes)
            scratch_output = scratch / f"unpacked{suffix}"

            cp = run_bounded_process(
                [exe, "-d", "-o", str(scratch_output), str(work_copy)],
                timeout_seconds=timeout_seconds,
                cancellation_token=cancellation_token,
            )
            if cp.launch_failed is True:
                return _j(launch_failure(cp, "upx_unpack", "UPX_LAUNCH_FAILED"))
            if cp.timed_out or cp.cancelled:
                return _j({
                    "ok": False, "tool": "upx_unpack",
                    "status": "CANCELLED" if cp.cancelled else "TIMEOUT",
                    "stdout": cp.stdout, "stderr": cp.stderr,
                })
            if cp.returncode != 0 or not scratch_output.exists():
                return _j({
                    "ok": False, "tool": "upx_unpack", "status": "UPX_UNPACK_FAILED",
                    "exit_code": cp.returncode, "stdout": cp.stdout, "stderr": cp.stderr,
                    "note": "Non-zero exit or missing output usually means the input is not actually UPX-packed, or uses a UPX variant/version this upx.exe cannot reverse.",
                })

            unpacked_bytes = scratch_output.read_bytes()
            unpacked_sha256 = hashlib.sha256(unpacked_bytes).hexdigest()
            os.replace(scratch_output, output_path)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
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


def upx_status():
    """Whether upx.exe is reachable, where from, whether it actually runs, and its
    version -- the capability probe to run before reporting UPX as unavailable.

    Runs `upx --version` once (touches no file). Statuses: `OK`, `TOOL_MISSING`
    (`detail` names UPX_HOME and the other places it looked), `TIMEOUT`, and
    `ANALYSIS_LIMITED` (resolved but did not run or printed no version).
    `resolved_by` is UPX_HOME, PATH or bundled_fallback (the per-user tools folder).
    Only decompression (`upx_unpack`) is wrapped; this adds no compression.
    """
    tool = "upx_status"
    try:
        exe = _upx_binary()
        if not exe:
            return _j({
                "ok": False, "tool": tool, "status": "TOOL_MISSING", "resolved": False,
                "required_capability": "UPX CLI (upx.exe)",
                "detail": (
                    "upx.exe was not found. Set UPX_HOME to its full path (or its folder), or put "
                    "it on PATH; the last place this module looks is "
                    f"{Path.home() / 'teacher-tools' / 'upx' / 'upx.exe'}. upx_unpack cannot run until then."
                ),
                "env_set": {"UPX_HOME": bool(os.getenv("UPX_HOME", "").strip())},
            })

        def _same(a, b):
            return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))

        explicit = os.getenv("UPX_HOME", "").strip()
        resolved_by = "bundled_fallback"
        if explicit and any(_same(exe, c) for c in (explicit, Path(explicit) / "upx.exe")):
            resolved_by = "UPX_HOME"
        else:
            on_path = shutil.which("upx")
            if on_path and _same(exe, on_path):
                resolved_by = "PATH"
        cp = run_bounded_process([exe, "--version"], timeout_seconds=10, max_output_chars=4096)
        if cp.launch_failed is True:
            return _j({**launch_failure(cp, tool, "UPX_LAUNCH_FAILED"), "binary": exe, "resolved_by": resolved_by, "runnable": False})
        if cp.timed_out or cp.cancelled:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "UPX_VERSION_TIMEOUT"})
        lines = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip().splitlines()
        if cp.returncode not in (0, None) or not lines or not lines[0].strip():
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "UPX_VERSION_UNREADABLE",
                       "exit_code": cp.returncode, "output_tail": ((cp.stdout or "") + (cp.stderr or ""))[-500:],
                       "detail": "The file resolved but did not print a version when run, so it is not known to work."})
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": resolved_by, "runnable": True,
            "version": lines[0].strip(),
            "operations": ["upx_unpack", "upx_status"],
            "note": (
                "OK means upx.exe started and printed its version. Only `upx -d` on a disposable copy "
                "is wrapped (upx_unpack); compression is not offered."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "UPX_STATUS_UNEXPECTED_ERROR",
                   "detail": f"{type(exc).__name__}: {exc}"})
