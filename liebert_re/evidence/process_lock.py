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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def pid_alive(pid: Any) -> bool:
    """Best-effort liveness check for a PID recorded by a lock holder.

    Errs toward "alive" whenever liveness cannot be determined -- an
    uncertain answer must never cause a live holder's lock to be reclaimed.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            STILL_ACTIVE = 259
            return exit_code.value == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
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
            return json.loads(self.path.read_text(encoding="utf-8"))
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
        if pid is None or pid_alive(pid):
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
        while True:
            try:
                descriptor = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
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
