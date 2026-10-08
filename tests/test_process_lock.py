"""Contract tests for liebert_re.evidence.process_lock (WinAPI mocked).

An aged lock is reclaimed only on a confirmed-dead owner. Unknown liveness
keeps the lock: age is never turned into evidence of death.
"""
from __future__ import annotations

import json
import os
import time

import pytest

import liebert_re.evidence.process_lock as pl

pytestmark = pytest.mark.contract


class FakeApi:
    def __init__(self, handle=0, last_error=0, exit_code=pl.STILL_ACTIVE):
        self.handle = handle
        self.last_error = last_error
        self.exit_code = exit_code
        self.opened = []
        self.closed = []

    def open_process(self, pid):
        self.opened.append(pid)
        return self.handle

    def get_last_error(self):
        return self.last_error

    def get_exit_code(self, handle):
        return self.exit_code

    def close(self, handle):
        self.closed.append(handle)


@pytest.fixture
def windows(monkeypatch):
    def install(api):
        monkeypatch.setattr(pl, "_IS_WINDOWS", True)
        monkeypatch.setattr(pl, "_windows_api", lambda: api)
        return api
    return install


def _aged_lock(tmp_path, pid):
    path = tmp_path / "x.lock"
    path.write_text(json.dumps({"pid": pid}), encoding="utf-8")
    old = time.time() - 3600
    os.utime(path, (old, old))
    return path


def _contend(path):
    with pytest.raises(pl.LockTimeout):
        with pl.DurableLock(path, stale_seconds=0.1, timeout_seconds=0.3, poll_seconds=0.01):
            pass  # pragma: no cover


def test_aged_lock_with_access_denied_owner_is_kept(tmp_path, windows):
    windows(FakeApi(handle=0, last_error=5))
    path = _aged_lock(tmp_path, 4242)
    _contend(path)
    assert path.exists()
    assert not (tmp_path / "x.lock.recovery.jsonl").exists()


def test_invalid_parameter_means_dead_and_aged_lock_is_reclaimed(tmp_path, windows):
    windows(FakeApi(handle=0, last_error=pl.ERROR_INVALID_PARAMETER))
    assert pl.pid_alive(4242) is False
    path = _aged_lock(tmp_path, 4242)
    with pl.DurableLock(path, stale_seconds=0.1, timeout_seconds=2, poll_seconds=0.01) as lock:
        assert lock.reclaimed is not None
    assert (tmp_path / "x.lock.recovery.jsonl").exists()


@pytest.mark.parametrize("err", [0, 5, 6, 1, 1450])
def test_every_other_open_error_is_unknown(windows, err):
    windows(FakeApi(handle=0, last_error=err))
    assert pl.pid_alive(4242) is None


def test_get_exit_code_failure_is_unknown_and_lock_kept(tmp_path, windows):
    api = windows(FakeApi(handle=0x10, exit_code=None))
    assert pl.pid_alive(4242) is None
    assert api.closed == [0x10]
    path = _aged_lock(tmp_path, 4242)
    _contend(path)
    assert path.exists()


def test_exit_code_distinguishes_running_and_exited(windows):
    windows(FakeApi(handle=0x10, exit_code=pl.STILL_ACTIVE))
    assert pl.pid_alive(7) is True
    windows(FakeApi(handle=0x10, exit_code=0))
    assert pl.pid_alive(7) is False


@pytest.mark.parametrize("bad", ["abc", None, [], {}, 0, -5, True, 2**40, float("inf")])
def test_unreadable_pid_is_unknown_and_never_asks_the_os(windows, bad):
    api = windows(FakeApi(handle=0, last_error=pl.ERROR_INVALID_PARAMETER))
    assert pl.pid_alive(bad) is None
    assert api.opened == []


def test_corrupt_pid_in_aged_lock_is_kept(tmp_path, windows):
    windows(FakeApi(handle=0, last_error=pl.ERROR_INVALID_PARAMETER))
    path = _aged_lock(tmp_path, "garbage")
    _contend(path)
    assert path.exists()


def test_handle_is_pointer_width_not_truncated(windows):
    big = 0x7FFF_FFFF_1234_5678
    api = windows(FakeApi(handle=big, exit_code=pl.STILL_ACTIVE))
    assert pl.pid_alive(7) is True
    assert api.closed == [big]


@pytest.mark.skipif(os.name != "nt", reason="binds the real kernel32")
def test_real_binding_is_pointer_width_and_own_pid_is_alive():
    import ctypes

    k32 = pl._WinApi()._k32
    assert k32.OpenProcess.restype is ctypes.c_void_p
    assert k32.OpenProcess.argtypes is not None
    assert k32.CloseHandle.argtypes == [ctypes.c_void_p]
    assert pl.pid_alive(os.getpid()) is True


def test_non_windows_dead_pid_still_false(monkeypatch):
    monkeypatch.setattr(pl, "_IS_WINDOWS", False)

    def kill(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", kill)
    assert pl.pid_alive(4242) is False


def test_access_denied_on_a_delete_pending_lock_file_is_waited_out_on_windows(tmp_path, monkeypatch):
    """The other process just released the lock; Windows still answers the exclusive create with access denied."""
    real_open, calls = os.open, []

    def flaky_open(path, flags, *args):
        calls.append(path)
        if len(calls) <= 2:
            raise PermissionError(13, "Permission denied")
        return real_open(path, flags, *args)

    monkeypatch.setattr(pl, "_IS_WINDOWS", True)
    monkeypatch.setattr(pl.os, "open", flaky_open)
    with pl.DurableLock(tmp_path / "x.lock", poll_seconds=0.01) as lock:
        assert lock.acquired and len(calls) == 3


def test_lasting_access_denied_is_raised_as_itself_not_as_contention(tmp_path, monkeypatch):
    def denied(path, flags, *args):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(pl, "_IS_WINDOWS", True)
    monkeypatch.setattr(pl.os, "open", denied)
    monkeypatch.setattr(pl, "_DELETE_PENDING_GRACE_SECONDS", 0.05)
    with pytest.raises(PermissionError):
        pl.DurableLock(tmp_path / "x.lock", poll_seconds=0.01).__enter__()


def test_access_denied_is_not_waited_out_off_windows(tmp_path, monkeypatch):
    calls = []

    def denied(path, flags, *args):
        calls.append(path)
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(pl, "_IS_WINDOWS", False)
    monkeypatch.setattr(pl.os, "open", denied)
    with pytest.raises(PermissionError):
        pl.DurableLock(tmp_path / "x.lock", poll_seconds=0.01).__enter__()
    assert len(calls) == 1
