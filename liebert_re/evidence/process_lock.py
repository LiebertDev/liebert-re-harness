"""Cross-process durable lock with liveness-aware stale reclaim.

A bare ``os.O_CREAT | os.O_EXCL`` lock file only tells you *someone* holds
it, never whether that someone is still alive. Reclaiming purely by file
age is unsafe: a live-but-slow holder past an age threshold would have its
lock silently stolen out from under it. A lock here is only ever reclaimed
once it is BOTH older than ``stale_seconds`` (a bounded grace period -- err
toward waiting) AND its recorded owner PID is confirmed no longer running.
Every reclaim is recorded, visibly, in a sibling ``<lock>.recovery.jsonl``
file so a customer or a later debugging session can see that it happened
and what it cost, instead of a dead process silently blocking live work
forever (the previous, unrecoverable behavior this module replaces).
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from liebert_re import strict_json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


_IS_WINDOWS = os.name == "nt"

# Win32 constants. Only ERROR_INVALID_PARAMETER from OpenProcess means "no such
# process" for a valid, non-zero DWORD pid and constant valid arguments; access
# denied means the process EXISTS but is not ours to inspect.
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_INVALID_PARAMETER = 87
STILL_ACTIVE = 259
_MAX_DWORD = 0xFFFFFFFF


class _WinApi:
    """The three kernel32 calls used, plus ``get_last_error``, behind one seam.

    Bound with ``use_last_error=True`` and explicit argtypes/restype. HANDLE is
    pointer-width (``c_void_p``): truncating it to a C int would silently
    corrupt 64-bit handles.
    """

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        k32.GetExitCodeProcess.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = wintypes.BOOL
        self._k32 = k32
        self._ctypes = ctypes
        self._wintypes = wintypes

    def open_process(self, pid: int):
        return self._k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)

    def get_exit_code(self, handle):
        """Return the exit code, or None if the call itself failed."""
        code = self._wintypes.DWORD()
        if not self._k32.GetExitCodeProcess(handle, self._ctypes.byref(code)):
            return None
        return code.value

    def close(self, handle) -> None:
        self._k32.CloseHandle(handle)

    def get_last_error(self) -> int:
        return self._ctypes.get_last_error()


def _windows_api() -> _WinApi:
    return _WinApi()


def _windows_pid_alive(pid: int, api: Any) -> bool | None:
    handle = api.open_process(pid)
    if not handle:
        err = api.get_last_error()  # immediately, nothing in between
        if err == ERROR_INVALID_PARAMETER:
            return False
        return None  # access denied, 0 and every other error: unknown
    try:
        code = api.get_exit_code(handle)
        if code is None:
            return None
        return code == STILL_ACTIVE
    finally:
        api.close(handle)


def pid_alive(pid: Any) -> bool | None:
    """Three-valued liveness check for a PID recorded by a lock holder.

    ``True``: running. ``False``: confirmed not running. ``None``: cannot be
    determined (unreadable pid, access denied, any unclassified failure).
    Callers must act on death only for ``is False``; ``None`` means keep the
    lock.
    """
    if isinstance(pid, bool):
        return None
    try:
        pid = int(pid)
    except (TypeError, ValueError, OverflowError):
        return None
    if pid <= 0 or pid > _MAX_DWORD:
        return None
    if _IS_WINDOWS:
        try:
            api = _windows_api()
        except Exception:
            return None
        return _windows_pid_alive(pid, api)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def record_reclaim(lock_path: str | Path, holder: dict | None, reason: str) -> dict:
    """Append a visible, durable record that a stale lock was reclaimed."""
    event = {
        "reclaimed_at": utc_now(),
        "reclaimed_by_pid": os.getpid(),
        "previous_holder": holder,
        "reason": reason,
        "lock_path": str(lock_path),
    }
    log_path = Path(str(lock_path) + ".recovery.jsonl")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return event


_DELETE_PENDING_GRACE_SECONDS = 2.0


class LockTimeout(RuntimeError):
    pass


class DurableLock:
    """Blocking, liveness-aware, cross-process lock file.

    ``stale_seconds``: minimum age before a held lock is even considered
    for reclaim -- the bounded grace period that protects a merely slow,
    live holder. Past that age, the recorded owner PID's liveness is
    checked; a live holder is still waited on (never reclaimed), a
    confirmed-dead holder's lock is reclaimed immediately and the reclaim
    is recorded via :func:`record_reclaim`. ``timeout_seconds`` bounds the
    total wait: a live holder that never releases eventually raises
    :class:`LockTimeout` rather than blocking forever.
    """

    def __init__(
        self, path: str | Path, *, stale_seconds: float = 30, timeout_seconds: float = 120,
        poll_seconds: float = 0.05,
    ):
        self.path = Path(path)
        self.stale_seconds = max(0.1, float(stale_seconds))
        self.timeout_seconds = max(self.stale_seconds, float(timeout_seconds))
        self.poll_seconds = max(0.01, float(poll_seconds))
        self.acquired = False
        self.reclaimed: dict | None = None

    def _read_holder(self) -> dict | None:
        try:
            return strict_json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _try_reclaim_if_dead(self) -> bool:
        try:
            age = time.time() - self.path.stat().st_mtime
        except OSError:
            return False
        if age <= self.stale_seconds:
            return False
        holder = self._read_holder()
        pid = (holder or {}).get("pid")
        # Age is not evidence of death: reclaim only on a confirmed False.
        # None (owner unknown) keeps the lock; the wait ends by timeout and
        # the next attempt re-measures. A lock that stays held when death
        # cannot be established is the accepted availability cost.
        if pid is None or pid_alive(pid) is not False:
            return False
        try:
            self.path.unlink()
        except FileNotFoundError:
            return False
        self.reclaimed = record_reclaim(self.path, holder, "HOLDER_PROCESS_NOT_ALIVE")
        return True

    def __enter__(self) -> "DurableLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.reclaimed = None
        deadline = time.monotonic() + self.timeout_seconds
        denied_until = None
        while True:
            try:
                descriptor = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except PermissionError:
                # Windows answers an exclusive create on a file that was unlinked but is still held open by
                # another handle (delete pending) with access denied, not "exists". That state ends in
                # milliseconds, so it is waited out for a short grace; access denied that lasts is a real
                # permission problem and is raised as itself, never relabelled as contention.
                if not _IS_WINDOWS:
                    raise
                now = time.monotonic()
                if denied_until is None:
                    denied_until = now + _DELETE_PENDING_GRACE_SECONDS
                if now >= denied_until or now >= deadline:
                    raise
                time.sleep(self.poll_seconds)
                continue
            except FileExistsError:
                self._try_reclaim_if_dead()  # no-op unless the holder is confirmed dead
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"LOCK_CONTENDED_LIVE_HOLDER:{self.path}")
                time.sleep(self.poll_seconds)
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"pid": os.getpid(), "created_at": utc_now()}, stream)
            self.acquired = True
            return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)
            self.acquired = False
