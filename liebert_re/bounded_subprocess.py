"""Exact, bounded subprocess execution for Teacher tool limbs."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

# Cross-thread emergency cleanup registry. An outer caller (e.g. an attempt-
# level timeout wrapping this whole thread) cannot force-kill a Python
# thread, so a tool subprocess started here could otherwise be abandoned and
# orphaned if the hosting thread is a daemon thread and the process exits
# before this module's own timeout loop ever reaches its cleanup code. Every
# owned Popen is registered here for the lifetime of the call and reaped
# automatically wherever it would already be terminated; `reap_thread` lets
# an outer timeout handler terminate anything still tracked for a thread it
# is giving up on.
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_BY_THREAD: dict[int, "set[subprocess.Popen]"] = {}


def _register_active(process: subprocess.Popen) -> None:
    ident = threading.get_ident()
    with _ACTIVE_LOCK:
        _ACTIVE_BY_THREAD.setdefault(ident, set()).add(process)


def _unregister_active(process: subprocess.Popen) -> None:
    ident = threading.get_ident()
    with _ACTIVE_LOCK:
        bucket = _ACTIVE_BY_THREAD.get(ident)
        if bucket is None:
            return
        bucket.discard(process)
        if not bucket:
            _ACTIVE_BY_THREAD.pop(ident, None)


def reap_thread(ident: int, *, grace_seconds: float = 2.0) -> int:
    """Best-effort cross-thread cleanup for a thread an outer caller is
    abandoning (e.g. after its own timeout already fired). Terminates every
    process tree this module is still tracking for that thread identity and
    returns how many were actually torn down. Safe to call even if the
    thread already cleaned up normally (nothing left to reap)."""
    with _ACTIVE_LOCK:
        processes = list(_ACTIVE_BY_THREAD.pop(ident, ()))
    return sum(1 for process in processes if terminate_process_tree(process, grace_seconds=grace_seconds))


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    process_tree_terminated: bool = False
    memory_exceeded: bool = False
    resource_limit_unavailable: bool = False
    output_truncated: bool = False
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None


def _process_tree_rss_bytes(pid: int) -> int | None:
    """Resident bytes of ``pid`` and its descendants, or None when the ROOT's
    memory cannot be measured at all (psutil missing, or access denied on a
    non-elevated host).

    None means "could not measure" and NEVER "over the limit"; callers must
    keep those two outcomes on separate branches (``resource_limit_unavailable``
    vs ``memory_exceeded``). A descendant that vanishes or denies access is
    skipped rather than failing the whole read: the sum then undercounts that
    one process, which is the honest limit of what an unprivileged host can
    observe, and is preferable to killing a healthy tree over one opaque child.
    """
    try:
        import psutil
    except ImportError:
        return None
    try:
        root = psutil.Process(pid)
        total = root.memory_info().rss
        children = root.children(recursive=True)
    except psutil.NoSuchProcess:
        return 0
    except (psutil.Error, OSError):
        return None
    for proc in children:
        try:
            total += proc.memory_info().rss
        except (psutil.Error, OSError):
            continue
    return total


def _memory_monitor_usable() -> bool:
    """Preflight, before any child is spawned: can this host measure process
    memory at all? Probed on our own pid; if it is unreadable a child's will
    be too. Lets a memory-bounded call be REFUSED up front with the named
    ``resource_limit_unavailable`` status instead of launching a child only to
    kill it, and instead of running it with a bound that is not enforced
    (this module is the base for untrusted-tool execution, so an unenforceable
    bound fails closed)."""
    return _process_tree_rss_bytes(os.getpid()) is not None


def _limit_text(value: str, maximum: int | None) -> tuple[str, bool, str]:
    """Bound a captured stream, keeping BOTH ends.

    Head-only truncation destroys exactly the part that matters for a
    streamed event log: a CLI worker's final answer is the last event, so
    when a chatty tool loop pushes the stream past the cap, dropping the
    tail silently deletes the model's whole result and leaves only its
    opening narration. That was observed live: an OpenCode call whose
    stream reached 1,013,043 chars came back with 127 chars of "I'll start
    by reading the ground-truth files" and no answer at all, because every
    later event -- including the answer -- was past the cut.

    So the middle is dropped instead, and the marker records where. The
    tail gets the larger share because finality lives there; the head is
    kept because it carries the invocation's own preamble.
    """
    value = value or ""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    if maximum is None or len(value) <= maximum:
        return value, False, digest
    maximum = max(0, int(maximum))
    marker_template = "\n[OUTPUT_TRUNCATED original_chars={n} omitted_chars={omitted} kept_head={head} kept_tail={tail} sha256={sha}]\n"
    # Two passes: the marker's own length depends on the numbers inside it.
    head = tail = 0
    for _ in range(2):
        marker = marker_template.format(n=len(value), omitted=len(value) - head - tail, head=head, tail=tail, sha=digest)
        budget = max(0, maximum - len(marker))
        head = budget * 2 // 5
        tail = budget - head
    marker = marker_template.format(n=len(value), omitted=len(value) - head - tail, head=head, tail=tail, sha=digest)
    if head + tail <= 0:
        return marker[:maximum], True, digest
    return value[:head] + marker + (value[len(value) - tail:] if tail else ""), True, digest


def _child_pids_by_ppid_scan(parent_pid: int) -> list[int]:
    """Every currently-running process whose recorded parent pid is
    ``parent_pid`` -- found by a direct process-table scan, NOT via
    ``psutil.Process(parent_pid).children()``.

    Root cause this exists to close (measured live, not hypothesized): a
    ``.bat``/``cmd.exe`` wrapper (e.g. ``analyzeHeadless.bat``) can exit on
    its own well before the real grandchild it spawned (``java.exe``) does.
    ``psutil.Process(parent_pid).children()`` first asserts the PARENT
    itself is still alive and raises ``NoSuchProcess`` if not -- so once the
    wrapper has already exited, that helper can no longer find the orphaned
    grandchild at all, even though it is still running and still holding
    the inherited stdout/stderr pipe *write* handles open (Windows only
    signals EOF on a pipe once EVERY write handle across every process is
    closed, so one surviving orphan blocks the reader thread forever).
    Windows never clears/reparents a child's recorded ppid when its parent
    dies, so a raw table scan for ``ppid == parent_pid`` still finds it
    (best-effort: a since-reused ``parent_pid`` is the same small,
    accepted race already relied on elsewhere in this module).

    Walks the WHOLE descendant subtree (BFS over the live ppid graph), not
    just direct children -- measured live: some interpreters/launchers on
    this machine (e.g. a venv's ``python.exe``) are themselves a relay stub
    that spawns the REAL interpreter as an extra hidden child layer, so a
    real grandchild's recorded ppid can be an intermediate pid several
    layers below ``parent_pid``, never ``parent_pid`` itself. A one-level
    ``ppid == parent_pid`` check silently missed exactly this case.
    """
    try:
        import psutil
    except ImportError:
        return []
    ppid_by_pid: dict[int, int | None] = {}
    for proc in psutil.process_iter(["pid", "ppid"]):
        try:
            ppid_by_pid[proc.info["pid"]] = proc.info.get("ppid")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    found: list[int] = []
    frontier = {parent_pid}
    seen = {parent_pid}
    while frontier:
        next_frontier = set()
        for pid, ppid in ppid_by_pid.items():
            if ppid in frontier and pid not in seen:
                found.append(pid)
                seen.add(pid)
                next_frontier.add(pid)
        frontier = next_frontier
    return found


def _kill_pid_tree_by_pid(pid: int) -> bool:
    """Best-effort hard-kill of ``pid`` and everything under it, addressed
    purely by pid (never assumes the pid's own parent is still alive)."""
    try:
        import psutil
    except ImportError:
        return False
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False
    try:
        descendants = proc.children(recursive=True)
    except psutil.NoSuchProcess:
        descendants = []
    killed_any = False
    for target in [proc, *descendants]:
        try:
            target.kill()
            killed_any = True
        except psutil.NoSuchProcess:
            pass
    return killed_any


def _snapshot_descendant_pids(pid: int) -> set[int]:
    """Best-effort full descendant snapshot while ``pid`` is still alive.

    This is the ONLY point in this module that can reliably see a
    multi-hop descendant chain (e.g. a venv's ``python.exe`` relay-launcher
    stub spawning the real interpreter, which spawns a further stub for a
    grandchild -- measured live on this machine; the same shape as a
    ``.bat`` wrapper spawning ``java.exe``). Once an INTERMEDIATE hop in
    that chain has already exited, it drops out of the live process table
    entirely, permanently breaking a from-scratch ppid-graph walk done
    later at kill time -- there is no way to reconnect through a process
    that no longer exists. Calling this repeatedly WHILE everything is
    still alive (see its caller's polling loop) is what makes the later
    kill able to reach descendants whose direct parent may have since
    died.
    """
    try:
        import psutil
    except ImportError:
        return set()
    try:
        root = psutil.Process(pid)
        return {child.pid for child in root.children(recursive=True)}
    except psutil.NoSuchProcess:
        return set()
    except (psutil.Error, OSError):
        return set()


def _terminate_process_group_posix(pgid: int, *, grace_seconds: float) -> bool:
    """POSIX-only group kill: SIGTERM the whole process group first, then
    escalate to SIGKILL only if it is still around after ``grace_seconds``
    -- never straight to SIGKILL, and never an unbounded wait either.

    This is the mechanism that actually closes the Linux-only defect
    ``_child_pids_by_ppid_scan`` cannot: that scan (and the Windows
    ``taskkill /T`` path below) both identify descendants by walking
    ``ppid`` links, which is reliable on Windows (a dead parent's recorded
    ppid is never rewritten there -- see that function's own docstring)
    but NOT on POSIX/Linux, where the kernel reparents an orphaned
    descendant to the nearest subreaper/init the moment its immediate
    parent exits -- exactly the shape of this module's own regression (a
    direct child that exits before the grandchild it spawned does; see
    ``tests/test_bounded_subprocess_orphan_timeout.py``). Reparenting only
    ever rewrites ``ppid``; it never moves a process out of its process
    GROUP. ``run_bounded_process`` spawns every POSIX child with
    ``start_new_session=True`` (``setsid()``), which makes that child's own
    pid its process group id by construction -- so ``pgid`` here is always
    just ``process.pid``, valid to use directly with no ``os.getpgid()``
    lookup (which would itself require the original process to still be
    alive/unreaped to succeed). ``killpg`` reaches every member of that
    group regardless of which process now shows as its parent.

    Must be called even when the group leader itself has already exited:
    a process group persists as long as any member is still alive, and
    ``killpg`` only needs a valid ``pgid``, never a live leader.
    """
    delivered = False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
            delivered = True
        except ProcessLookupError:
            break  # group has no live member left -- nothing further to escalate to
        except OSError:
            break
        if sig is signal.SIGKILL:
            break
        # Bounded grace period between SIGTERM and the SIGKILL escalation,
        # polled via a signal-0 liveness probe (no extra dependency, no
        # unbounded wait): stop early the moment the group is confirmed
        # gone instead of always sleeping the full grace_seconds.
        deadline = time.monotonic() + max(0.1, grace_seconds)
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return delivered
            except OSError:
                return delivered
            time.sleep(0.05)
    return delivered


def terminate_process_tree(
    process: subprocess.Popen[str], *, grace_seconds: float = 2.0,
    known_descendant_pids: "set[int] | None" = None,
) -> bool:
    """Terminate the process group/tree rooted at an owned Popen handle.

    Kills orphaned descendants (see ``_child_pids_by_ppid_scan``) FIRST and
    unconditionally -- even when ``process.poll()`` already shows the
    direct child has exited -- because that is exactly the case
    ``taskkill /T`` (which only walks a still-live parent chain) and the
    old early-return here (added before this fix) both miss. Skipping this
    left a live grandchild holding the pipe open forever, which then
    deadlocked ANY later attempt to close/drain that pipe (a background
    reader thread blocked inside a blocking read holds the stream's
    internal buffer lock for the duration of that read; ``stream.close()``
    needs the same lock, so it hangs right alongside it -- see
    ``_bounded_drain``). This was measured live: a `.bat` wrapper exiting
    immediately while its spawned grandchild kept running reproduced a
    real, indefinite hang in ``_bounded_drain`` (not bounded by
    ``grace_seconds`` at all), which is now the fixed regression covered by
    ``tests/test_bounded_subprocess_orphan_timeout.py``.

    On POSIX, the ppid-walk orphan scan above is Windows-reliable only
    (see ``_terminate_process_group_posix``'s docstring): Linux reparents
    an orphan the instant its direct parent exits, which is precisely the
    scenario that regression test exercises, so the ppid walk alone is not
    trustworthy there. ``_terminate_process_group_posix`` is therefore run
    UNCONDITIONALLY on POSIX (also before the ``process.poll()`` check
    below, for the same "direct child may already be gone" reason), as a
    second, independent mechanism that does not depend on ppid at all.
    """
    _unregister_active(process)
    orphan_pids = set(_child_pids_by_ppid_scan(process.pid))
    orphan_pids |= set(known_descendant_pids or ())
    orphans_killed = False
    for pid in orphan_pids:
        if _kill_pid_tree_by_pid(pid):
            orphans_killed = True
    if os.name != "nt":
        if _terminate_process_group_posix(process.pid, grace_seconds=grace_seconds):
            orphans_killed = True
    if process.poll() is not None:
        return orphans_killed
    tree_signal_succeeded = True
    if os.name == "nt":
        try:
            killed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=max(1.0, grace_seconds),
            )
            tree_signal_succeeded = killed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            tree_signal_succeeded = False
    # POSIX: no separate branch needed here -- _terminate_process_group_posix
    # above already delivered SIGTERM/SIGKILL to the whole group
    # unconditionally, regardless of whether the direct child was still
    # alive at that point.
    try:
        process.wait(timeout=max(0.1, grace_seconds))
    except subprocess.TimeoutExpired:
        tree_signal_succeeded = False
        try:
            process.kill()
            process.wait(timeout=max(0.1, grace_seconds))
        except subprocess.TimeoutExpired:
            # Still not reaped -- do not let this specific call hang the
            # caller indefinitely; the caller's own outer bound (and this
            # function's orphan sweep above) already did everything
            # reasonably possible to make the process go away.
            pass
    return tree_signal_succeeded or orphans_killed


def _bounded_close(stream, *, join_seconds: float = 1.0) -> None:
    """Close a stdout/stderr pipe object without ever blocking the caller
    indefinitely.

    Root cause this defends against (measured live): CPython's
    ``_readerthread`` (the background thread ``Popen.communicate`` uses on
    Windows) holds the SAME stream object's internal buffer lock for the
    entire duration of its blocking ``fh.read()`` call. If that thread is
    still stuck reading (e.g. a just-killed process's pipe has not yet
    actually signalled EOF), calling ``stream.close()`` on the main thread
    needs that identical lock and hangs right alongside it -- forever, in
    the exact case that matters most (this is the deadlock this whole
    module exists to prevent). Running the close on a daemon thread and
    bounding how long we wait for it means a residual race here can only
    ever leak one already-being-killed process's handle, never hang the
    caller.
    """
    if stream is None:
        return
    closer = threading.Thread(target=stream.close, daemon=True)
    closer.start()
    closer.join(timeout=max(0.1, join_seconds))


def _bounded_drain(process: subprocess.Popen[str], grace_seconds: float = 2.0) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=max(0.1, grace_seconds))
        return stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        for stream in (process.stdout, process.stderr):
            _bounded_close(stream)
        return "", ""


def run_bounded_process(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cancellation_token: Any = None,
    cwd: str | Path | None = None,
    environment: Mapping[str, str] | None = None,
    poll_seconds: float = 0.1,
    max_memory_bytes: int | None = None,
    max_output_chars: int | None = 131_072,
) -> BoundedProcessResult:
    """Run an owned process group and stop its exact tree on timeout/cancellation."""
    if bool(getattr(cancellation_token, "cancelled", False)):
        return BoundedProcessResult(None, "", "", cancelled=True)
    if max_memory_bytes is not None and not _memory_monitor_usable():
        return BoundedProcessResult(None, "", "", resource_limit_unavailable=True)
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=dict(environment) if environment is not None else None,
        stdin=subprocess.DEVNULL,  # never inherit the caller's stdin: a non-interactive
        # CLI tool that unexpectedly probes for piped input (e.g. Codex CLI's
        # exec subcommand) must see immediate EOF, not block waiting on a
        # parent stdin that may never close.
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    _register_active(process)
    # Continuously-refreshed descendant snapshot -- see
    # `_snapshot_descendant_pids`'s docstring for why this must be captured
    # WHILE the process tree is alive rather than reconstructed from
    # scratch at kill time. Taken immediately AND every poll tick below
    # (the same cadence the caller already accepted for responsiveness): a
    # lightweight wrapper (e.g. a thin `.bat` around a real payload) can
    # spawn its child and exit again within a fraction of a second, well
    # under any coarser cadence -- a throttled snapshot measurably missed
    # exactly this case while building this fix.
    known_descendant_pids: set[int] = _snapshot_descendant_pids(process.pid)
    if max_memory_bytes is not None and _process_tree_rss_bytes(process.pid) is None:
        terminated = terminate_process_tree(process, known_descendant_pids=known_descendant_pids)
        stdout, stderr = _bounded_drain(process)
        stdout, out_truncated, out_hash = _limit_text(stdout, max_output_chars)
        stderr, err_truncated, err_hash = _limit_text(stderr, max_output_chars)
        return BoundedProcessResult(
            process.returncode, stdout, stderr, process_tree_terminated=terminated,
            resource_limit_unavailable=True, output_truncated=out_truncated or err_truncated,
            stdout_sha256=out_hash, stderr_sha256=err_hash,
        )
    deadline = time.monotonic() + max(0.001, float(timeout_seconds))
    while True:
        # Every poll tick (the same cadence the caller already accepted for
        # responsiveness -- never a SEPARATE, coarser cadence): see
        # `_snapshot_descendant_pids`'s docstring for why a throttled/coarser
        # cadence measurably misses a wrapper that spawns a real payload and
        # exits again in well under that window (measured live on this
        # machine with a venv relay-launcher stub).
        known_descendant_pids |= _snapshot_descendant_pids(process.pid)
        cancelled = bool(getattr(cancellation_token, "cancelled", False))
        remaining = deadline - time.monotonic()
        if cancelled or remaining <= 0:
            terminated = terminate_process_tree(process, known_descendant_pids=known_descendant_pids)
            stdout, stderr = _bounded_drain(process)
            stdout, out_truncated, out_hash = _limit_text(stdout, max_output_chars)
            stderr, err_truncated, err_hash = _limit_text(stderr, max_output_chars)
            return BoundedProcessResult(
                process.returncode, stdout or "", stderr or "",
                timed_out=not cancelled, cancelled=cancelled,
                process_tree_terminated=terminated,
                output_truncated=out_truncated or err_truncated,
                stdout_sha256=out_hash, stderr_sha256=err_hash,
            )
        if max_memory_bytes is not None:
            rss = _process_tree_rss_bytes(process.pid)
            if rss is None:
                terminated = terminate_process_tree(process, known_descendant_pids=known_descendant_pids)
                stdout, stderr = _bounded_drain(process)
                stdout, out_truncated, out_hash = _limit_text(stdout, max_output_chars)
                stderr, err_truncated, err_hash = _limit_text(stderr, max_output_chars)
                return BoundedProcessResult(
                    process.returncode, stdout, stderr, process_tree_terminated=terminated,
                    resource_limit_unavailable=True, output_truncated=out_truncated or err_truncated,
                    stdout_sha256=out_hash, stderr_sha256=err_hash,
                )
            if rss > max_memory_bytes:
                terminated = terminate_process_tree(process, known_descendant_pids=known_descendant_pids)
                stdout, stderr = _bounded_drain(process)
                stdout, out_truncated, out_hash = _limit_text(stdout, max_output_chars)
                stderr, err_truncated, err_hash = _limit_text(stderr, max_output_chars)
                return BoundedProcessResult(
                    process.returncode, stdout, stderr, process_tree_terminated=terminated,
                    memory_exceeded=True, output_truncated=out_truncated or err_truncated,
                    stdout_sha256=out_hash, stderr_sha256=err_hash,
                )
        try:
            stdout, stderr = process.communicate(timeout=min(max(0.01, poll_seconds), remaining))
            _unregister_active(process)
            stdout, out_truncated, out_hash = _limit_text(stdout or "", max_output_chars)
            stderr, err_truncated, err_hash = _limit_text(stderr or "", max_output_chars)
            return BoundedProcessResult(
                process.returncode, stdout, stderr,
                output_truncated=out_truncated or err_truncated,
                stdout_sha256=out_hash, stderr_sha256=err_hash,
            )
        except subprocess.TimeoutExpired:
            continue
