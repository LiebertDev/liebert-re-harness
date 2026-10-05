"""Thin, generic frida instrumentation client -- runs ONLY inside the
isolated Hyper-V guest, packaged by build_exe.py into a single standalone
exe and placed at C:\\Tools\\frida_trace_client.exe there. This is the ONLY
place in this repository that is allowed to ``import frida`` / call
``frida.attach``/``frida.spawn``/``frida.get_local_device`` -- every host-side
harness module talks to this client only by generating a command line for it
and parsing its JSON-lines stdout (see
tests/test_frida_client_stays_in_guest.py, which asserts that fact against
the rest of the repository).

What this file deliberately does NOT contain: any target-specific offset,
process name, module name, export name, or version constant. Those all
arrive from the OUTSIDE as data:
  - ``--agent`` is a path to a caller-supplied Frida JS agent (the actual
    instrumentation logic -- which exports to hook, what to log -- lives
    entirely in that external .js file, not in this launcher).
  - ``--agent-params`` is an optional path to a JSON file (or an inline JSON
    string) posted to the loaded agent once via ``script.post({"type":
    "init", "params": <parsed JSON>})`` immediately after load, so the same
    generic agent script can be parameterized per target (e.g. an export
    list, addresses, a module name) without this launcher ever needing to
    know what "params" means.

Surface (all via argparse, run ``--help`` for the authoritative list):
  one of --attach-name NAME | --attach-pid PID | --spawn PATH  (what to
    instrument)
  --agent PATH                  (required: JS agent to load)
  --agent-params PATH_OR_JSON   (optional: forwarded to the agent verbatim)
  --duration-seconds N          (required budget; clamped to
                                  [MIN_DURATION_SECONDS, MAX_DURATION_SECONDS]
                                  -- this process always exits on its own,
                                  never runs unbounded)
  --no-resume                   (when spawning, do not resume the process
                                  after the agent loads -- lets an agent set
                                  up hooks before the target's own entry
                                  point runs; ignored for --attach-*)
  --stdin-data PATH              (spawn-only: path to a file of raw bytes
                                  written to the spawned target's real stdin
                                  via frida's own ``Device.input()`` once the
                                  agent is loaded, BEFORE resume -- lets a
                                  console target's std::cin/scanf/gets read
                                  loop be fed a fixed, reproducible test
                                  input with hooks already installed and the
                                  target still suspended. MEASURED root
                                  cause (2026-09-16): plain OS-level stdin
                                  redirection of THIS process (even with
                                  ``stdio="inherit"`` on the frida spawn
                                  call) does not reach a frida-spawned
                                  target on Windows, because frida's Windows
                                  backend performs the actual CreateProcess
                                  for the target through its own native
                                  spawn path (see ``src/windows/windows-
                                  host-session.vala`` -- ``_spawn`` is a
                                  native ``extern`` call, and the ``pipes``
                                  it returns are only non-null for
                                  ``stdio="pipe"``); an OS pipe handle this
                                  launcher inherited from ITS OWN parent
                                  does not automatically re-inherit through
                                  that native spawn path. ``Device.input()``
                                  is frida's own documented, cross-platform
                                  mechanism for exactly this ("Input data on
                                  stdin of a spawned process" --
                                  ``frida.core.Device.input``) -- using it
                                  sidesteps the whole host-OS handle-
                                  inheritance question entirely, forces
                                  ``stdio="pipe"`` for this spawn (required
                                  for ``pipes`` to be non-null), and this
                                  launcher then mirrors the target's own
                                  stdout/stderr, which pipe mode routes
                                  through frida's ``output`` device signal
                                  instead of OS-level redirection, as
                                  ``output`` JSON-lines events (base64
                                  payload) so no visibility is lost.
  --device-id ID                (optional; defaults to the local device via
                                  frida.get_local_device())
  --output PATH                 (optional; defaults to stdout)

Output contract: exactly one JSON object per line (JSON Lines), flushed
immediately after each write so a caller streaming this process's stdout
sees events as they happen rather than only at exit. Every line has an
``event`` key. Lifecycle events: ``ready`` (args accepted, about to
attach/spawn), ``attached``/``spawned`` (pid now known), ``agent_loaded``,
``stdin_sent`` (``--stdin-data`` bytes handed to ``Device.input()``, with
``bytes_len``), ``resumed``, ``message`` (one JS->Python message from the
agent, with ``type``/``payload``/``data_len`` mirrored from frida's own
``script.on('message', ...)`` callback), ``output`` (one stdout/stderr
chunk from a ``stdio="pipe"`` spawn -- i.e. whenever ``--stdin-data`` was
given -- with ``pid``, ``fd`` (1=stdout, 2=stderr), ``data_b64``, and
``data_len``; NOT emitted for ``stdio="inherit"`` spawns or ``--attach-*``,
since frida never wires its ``output`` device signal for those),
``agent_params_sent`` (``--agent-params`` was delivered; ``method`` is
``"rpc_sync"`` when the loaded agent defines ``rpc.exports.init`` -- a real
blocking call/response, completed before this launcher ever resumes a
spawned target -- or ``"post_async"`` when it does not, the older fire-
and-forget ``script.post({"type": "init", ...})``, kept for every agent
that only defines ``recv('init', ...)``), ``budget_exceeded``,
``detach_timed_out`` (``session.detach()`` did not return within
``DETACH_TIMEOUT_SECONDS`` -- abandoned on its own daemon thread, never
blocks this process's own exit), ``target_killed``/``target_kill_failed``
(spawn mode only: this launcher's own best-effort ``device.kill()`` of a
target it spawned itself, run regardless of ``detach``'s outcome so a
target left blocked in a syscall can never linger as an orphaned guest
process), ``target_terminated`` (spawn mode only, emitted from frida's own
``session.on('detached', ...)`` callback whenever a target THIS launcher
spawned goes away, for any reason -- a clean exit, a crash, an anti-
analysis self-kill, or this launcher's own kill/detach: ``pid``,
``killed_by_us`` (bool -- True only once this launcher has itself started
tearing the session down via the existing bounded detach/kill path below,
never conflated with the target dying on its own), ``frida_reason`` (str
-- frida's own detach reason, e.g. ``"process-terminated"``, passed
through verbatim, never paraphrased), ``exit_code``/``exit_code_hex``
(best-effort, read via ``GetExitCodeProcess`` from a Windows process
handle this launcher opened and RETAINED at spawn time -- the one moment
the PID is known and the process is definitely alive -- rather than
opened fresh by PID after termination, which loses the race once nothing
holds the process object open and risks a recycled PID's unrelated exit
code entirely; ``None`` when Windows cannot supply one even from that
retained handle, e.g. access was denied at open time), ``exit_code_meaning`` (decoded from a small
fixed table of well-known NTSTATUS-shaped codes such as
``0xC0000005``/ACCESS_VIOLATION -- ``None``, never a guess, for any code
not in that table), and ``runtime_seconds`` (spawn to termination)),
``detached``, ``error`` (with ``detail``; always followed by a
non-zero process exit).

``--follow-children`` (OFF by default -- see ``--max-children``) also
gates and instruments every child process the target spawns while this
run is active, via frida's SESSION-level child gating -- ``Session.
enable_child_gating()`` on the main target's OWN session, subscribed via
``Device.on('child-added', ...)`` on the DEVICE, and released one at a
time via ``Device.resume(pid)``. CORRECTED (2026-09-16, primary-source
investigation of frida's own source and maintainers, after three live
sessions were lost to the bug this replaces): child gating on Windows IS
implemented -- frida's payload hooks ``CreateProcessInternalW`` inside the
instrumented parent itself and adds the suspended flag, then reports the
child (pid, parent, path, arguments) already suspended. The prior
``'child-added' raised on Session.on()`` failure this launcher previously
worked around was an API-misuse bug in THIS file, not a missing frida
feature: ``child-added`` is a DEVICE signal, never a session one --
subscribing on the session is exactly what produces "a session only
supports the 'detached' signal". The commit that switched this launcher to
``Device.enable_spawn_gating()``/``'spawn-added'`` instead was a wrong
turn and has been removed outright, not kept as a fallback: device-level
SPAWN gating genuinely has never been implemented on Windows (open
upstream since 2022, maintainer waiting on a volunteer; the Windows host
session source raises "Not yet supported on this OS" for all three
spawn-gating entry points), so it could never have worked as a fallback
either. ``session.enable_child_gating()`` is called BEFORE the main target
is ever resumed further down, so a fast-spawning child can never race
ahead of gating. A gated child's frida ``Child`` object exposes ``pid``,
``parent_pid``, ``path``, ``argv``, ``envp``, ``identifier``, and
``origin``; this launcher reports whatever fields it actually has via
``getattr`` with a ``None`` default, never inventing one a build does not
supply. Loads the SAME ``--agent``/``--agent-params`` into every gated
child before letting it run, via the same bounded
``_init_agent_params_blocking`` path the main target uses. Adds these
events, all attributable by ``pid``: ``child_added`` (a child was gated --
``pid``, ``parent_pid``, ``identifier``, ``path``, ``argv`` if the build's
``Child`` object supplied them; emitted even for a child this run will not
instrument, e.g. past the cap), ``child_instrumented`` (``pid``, ``path``
-- attach+load+params succeeded), ``child_agent_params_sent`` (``pid``,
``method`` -- same ``"rpc_sync"``/``"post_async"`` vocabulary as
``agent_params_sent``), ``child_instrumentation_failed`` (``pid``,
``path``, ``detail`` -- attach/load/params failed; the child is still
resumed, never left gated), ``child_resumed``/``child_resume_failed``
(``pid`` -- every gated child, instrumented or not, is resumed exactly
once, via ``Device.resume(pid)`` -- the same call this launcher already
used for its own spawned target; note this is the DEVICE's resume, not
``Session.resume()``, which is an unrelated network-reconnect call), and
``child_skipped_cap_reached``/``child_cap_reached`` as before. With
``--follow-children`` on, every ``message`` event (from the main target's
own script AND every instrumented gated child's) also carries
``source_pid`` so a hit from a gated child is never mistaken for one from
the parent; with it OFF (the default), ``message`` events carry no such
key and every event this launcher emits is byte-for-byte what it always
produced -- no existing caller's behavior changes. Breakpoints/hooks
resolved by module+RVA (or any module-relative form) are resolved
independently PER PROCESS -- a gated child may load different modules, at
different base addresses, than its parent; this launcher does not attempt
to reconcile that, it only guarantees the same agent+params were loaded
into each process.

GRANDCHILDREN: each gated child's own freshly-attached session also has
``enable_child_gating()`` called on it (before that child is resumed),
via the SAME ``on_child_added`` callback used for the main target -- since
``child-added`` is a device-level signal shared by every session on that
device with gating enabled, a grandchild spawned by a gated child is
delivered to this same handler with no separate wiring needed. This falls
out naturally from instrumenting each child the same way; it is not a
separate code path.

Two hard constraints from frida's own child-gating design, given here so a
caller does not expect more than this mechanism can deliver: (1) it only
ever catches children of a process this launcher is ALREADY INSIDE --
the process must have been spawned and attached BY THIS LAUNCHER
(``--spawn``), never attached to late (``--attach-name``/``--attach-pid``)
after it may have already spawned the children of interest, since gating
only takes effect once ``enable_child_gating()`` has run inside that
process's own session; and (2) a process created by a BROKER OR SERVICE
rather than directly by the gated parent (e.g. a spawned worker actually
launched via an OS service, a COM/RPC broker, or a third-party launcher
process) is not that parent's own child in frida's sense and will NOT be
caught by this mechanism at all -- there is no workaround for this within
child gating itself. A known upstream frida issue also reports attach
hangs on Windows specifically when gating SANDBOXED children; if hit here,
it surfaces as a specific gated child never reaching ``child_instrumented``
or ``child_resumed`` while ``on_child_added`` is blocked inside
``device.attach()`` on frida's own internal (non-Python, not
``threading``-tracked) callback thread -- this is a known failure mode of
the underlying frida build, not a new bug in this launcher. It is
contained, not fixed: that internal thread is invisible to Python's own
thread bookkeeping, so it can delay/strand only the ONE stuck child, never
this launcher's own process exit -- the main wait loop, the bounded
``session.detach()`` (``DETACH_TIMEOUT_SECONDS``), and the bounded
``device.kill()`` (``KILL_TIMEOUT_SECONDS``) all run independently on this
launcher's own threads and still return within this file's normal bounds
regardless. The practical consequence a caller should expect: a child hit
by this bug may remain suspended in the guest when this launcher exits
rather than receiving its own ``child_resumed`` -- the guest-side
checkpoint revert around every run (see ``tools_frida.py``) is what
actually clears it, not this launcher.

Child gating is disabled again (``session.disable_child_gating()``,
best-effort) in this launcher's own teardown, on the main target's own
session, whenever it was actually enabled, so a run never leaves that
session's own gating turned on after it ends. (Child sessions established
for already-gated children are not separately torn down here -- their own
lifetime already ends when that child process itself exits, unchanged from
before.)

A process NAME given via ``--attach-name`` that matches more than one
currently-running process (checked via ``Device.enumerate_processes()``
before ever calling ``Device.attach()``) is refused as ``ambiguous_attach_
name`` -- exit code 7 -- with every candidate ``pid``/``name`` listed in
the error event's ``candidates`` field, rather than silently attaching to
whichever one frida's own name resolution happens to pick (MEASURED live,
2026-09-16: a decoy process name collided with a genuine unrelated system
process sharing that name, and the prior code silently picked one).
``--attach-pid`` remains exact and is never subject to this check.

Exit code 0 only on a clean, intentional stop (budget exceeded, or the
target process itself exited/detached on its own); non-zero on any setup or
runtime failure -- never a silent partial success. Exit code 6 is specific
to ``--follow-children``: ``session.enable_child_gating()`` itself raised
on the main target's own session (e.g. this frida build supports neither
session child gating on this OS) -- refused as a clean, reported status
rather than a crash, and (when the main target was this launcher's own
spawn) the target is still best-effort resumed and killed here rather than
left suspended forever, since this refusal can only be reached after the
target was already spawned. Exit code 7 is specific to an ambiguous
``--attach-name`` (see above)."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

# Well-known Windows process exit codes this launcher can decode WITHOUT
# guessing -- NTSTATUS-shaped values (the 0xC0000000+ STATUS_SEVERITY_ERROR
# range) a crashed, killed, or anti-analysis-self-terminated process's exit
# code commonly carries on Windows. Deliberately small and non-exhaustive:
# any exit code not in this table is still reported verbatim (raw decimal +
# hex in the emitted event), just without an invented "meaning" attached.
# General by construction -- keyed only by the numeric code itself, never by
# any particular target's name/path/module.
KNOWN_EXIT_CODES: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000096: "STATUS_PRIVILEGED_INSTRUCTION",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC000013A: "STATUS_CONTROL_C_EXIT",
    0x40000015: "STATUS_FATAL_APP_EXIT",
}

MIN_DURATION_SECONDS = 1.0
MAX_DURATION_SECONDS = 3600.0
DEFAULT_DURATION_SECONDS = 60.0
# Bounded wait for session.detach() at shutdown -- see its own call site
# below for the MEASURED reason this exists at all: a plain, un-timed
# detach() is not actually guaranteed to return promptly.
DETACH_TIMEOUT_SECONDS = 5.0
# Bounded wait for the synchronous script.exports_sync.init(...) RPC call --
# see its own call site below. Nothing here can guarantee a caller-supplied
# agent's rpc.exports.init body itself returns promptly (it is external,
# untrusted code, same as any other agent), so the same idiom as
# DETACH_TIMEOUT_SECONDS applies: run it on a daemon thread and never let it
# block this launcher past a fixed bound.
INIT_TIMEOUT_SECONDS = 5.0
# Bounded wait for a --follow-children CHILD's own script.exports_sync.
# init(...) RPC call specifically -- see on_child_added's own call site
# below. MEASURED FALSE FAILURE (2026-09-16, three live runs, see
# dataset/evidence/project_mayhem_bypass_20260916.json session_7): every
# run reported a gated child's own init() as having "not returned within
# INIT_TIMEOUT_SECONDS", yet that SAME child's own breakpoints went on to
# attach and fire later in the run -- proving the RPC call genuinely
# succeeded, just not within INIT_TIMEOUT_SECONDS, and the report was
# simply wrong. Root cause: unlike the main target's own session (already
# attached, well before this launcher's own duration budget even starts),
# a freshly-gated child must ADDITIONALLY complete device.attach() +
# Session.enable_child_gating() + Session.create_script() + Script.load()
# -- all synchronous, unbounded-by-anything-here work on frida's own
# device callback thread -- immediately before its own init() RPC call can
# even begin, on a process still held suspended at its very first
# instruction. That is real extra latency the main target's own timing
# window never has to absorb, so the SAME bound the main target uses is
# simply too tight for a child. Derived from that same bound, not a
# second unrelated magic number: a child gets double the main target's
# own budget, since it is paying for the same RPC call PLUS this one
# extra round of synchronous session setup the main target already did
# before its own timer ever started.
CHILD_INIT_TIMEOUT_SECONDS = INIT_TIMEOUT_SECONDS * 2.0
# Bounded wait for device.kill() of a target this launcher spawned itself.
# Never measured to hang, but bounded on the same idiom for consistency --
# every blocking guest call in this file gets a daemon-thread timeout so
# none of them can violate this module's own "never runs unbounded" claim.
KILL_TIMEOUT_SECONDS = 5.0

# --follow-children (OFF by default -- see build_arg_parser) caps how many
# child processes ONE run will instrument, so a target that fork-bombs or
# spawns many workers can never turn this launcher into an unbounded number
# of guest sessions. A child seen after the cap is still resumed immediately
# (never left gated), just not instrumented -- see on_child_added below.
DEFAULT_MAX_CHILDREN = 16
MIN_MAX_CHILDREN = 1
MAX_MAX_CHILDREN = 64


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# PID-based OpenProcess()/GetExitCodeProcess() calls made from inside the
# detach callback (i.e. AFTER termination) MEASURABLY lose the exit code on
# most real runs: Windows only keeps a process's exit code retrievable via
# GetExitCodeProcess while at least one handle to that process OBJECT is
# still held open, and by the time frida's async detach signal reaches this
# launcher and it tries to OpenProcess() by PID, nothing here has been
# holding one -- the object is very often already fully destroyed, and a
# recycled PID would silently return an unrelated process's exit code
# instead (a live handle identifies the process object, never the number).
# The fix used below is to acquire and RETAIN a handle at the one moment
# the PID is known and the process is definitely alive -- immediately after
# spawn -- and read the exit code from that SAME retained handle later, no
# matter how much time has passed or whether the PID has since been reused.
def _open_process_handle(pid: int) -> Optional[int]:
    """Best-effort, general (by PID alone, no target-specific knowledge):
    opens and returns a Windows process handle for ``pid``, to be retained
    for the life of this run and closed exactly once in this launcher's own
    teardown (see ``_close_process_handle``). Returns ``None`` whenever
    Windows/ctypes cannot supply one at all -- not running on Windows, the
    PID is already gone by the time this launcher gets to call this (spawn
    itself failed or raced), access denied -- callers must treat ``None``
    exactly like any other "unavailable" case and keep running unaffected;
    this must never raise into, or abort, the caller's own run."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        return handle if handle else None
    except Exception:  # noqa: BLE001 -- best-effort only, never fatal to this launcher
        return None


def _read_exit_code_from_handle(handle: Optional[int]) -> Optional[int]:
    """Reads ``GetExitCodeProcess`` from a handle THIS launcher already
    retained (see ``_open_process_handle``) -- never opens a fresh handle
    by PID itself, which is exactly the race this whole mechanism exists to
    avoid. Returns ``None`` for a ``None`` handle, a failed call, or a
    still-running process (``STILL_ACTIVE``, which after a real
    ``detached`` signal means this simply hasn't observed the exit yet, not
    that the process is alive) -- callers must treat ``None`` as "unknown",
    never invent a code for it."""
    if handle is None or sys.platform != "win32":
        return None
    try:
        import ctypes

        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        exit_code = ctypes.c_ulong(0)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return None
        if exit_code.value == STILL_ACTIVE:
            return None
        return exit_code.value
    except Exception:  # noqa: BLE001 -- best-effort only, never fatal to this launcher
        return None


def _close_process_handle(handle: Optional[int]) -> None:
    """Closes a handle THIS launcher opened via ``_open_process_handle``,
    exactly once, in this launcher's own existing teardown. A no-op for
    ``None`` (never opened, e.g. attach mode or the open itself failed) --
    best-effort, never raises into the caller's own teardown."""
    if handle is None or sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 -- best-effort only, never fatal to this launcher
        pass


def _decode_exit_code(exit_code: Optional[int]) -> Optional[str]:
    """Looks ``exit_code`` up in ``KNOWN_EXIT_CODES`` only -- ``None`` for
    both "no exit code available" and "a real exit code Windows gave us,
    just not one of the well-known ones this launcher recognizes"; the
    caller still has the raw ``exit_code``/``exit_code_hex`` for that case,
    this function only ever adds a meaning it is actually sure of."""
    if exit_code is None:
        return None
    return KNOWN_EXIT_CODES.get(exit_code & 0xFFFFFFFF)


class _JsonLineWriter:
    """Writes one JSON object per line to a file-like handle, flushing
    every write, and serializing writes from multiple frida callback
    threads (frida delivers ``on('message', ...)`` callbacks on its own
    internal thread, never the main thread) behind a single lock so lines
    from concurrent messages can never interleave mid-write."""

    def __init__(self, handle) -> None:
        self._handle = handle
        self._lock = threading.Lock()

    def write(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False, default=str)
        with self._lock:
            self._handle.write(line + "\n")
            self._handle.flush()


def _parse_agent_params(raw: Optional[str]) -> Any:
    """``raw`` is either a filesystem path to a JSON file or an inline JSON
    string -- tried as a path first (an inline JSON object/array can never
    also be an existing file path in practice), falling back to parsing
    ``raw`` itself as JSON text. Returns ``None`` if ``raw`` is ``None``.
    Raises ``ValueError`` with a clear message on anything that is neither
    a readable JSON file nor parseable JSON text -- this launcher never
    silently drops a caller-supplied params value it could not understand."""
    if raw is None:
        return None
    from pathlib import Path

    candidate = Path(raw)
    if candidate.is_file():
        text = candidate.read_text(encoding="utf-8")
    else:
        text = raw
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--agent-params value is neither an existing JSON file nor parseable JSON text: {exc}") from exc


# UNVERIFIED (DOGRULANMADI): these substrings are an assumption about how a
# real frida reports a call to an export the agent does not define; the real
# exception types/messages were not measured. Anything not matching is
# reported as "init_failed" (the export may exist and have thrown) -- the
# fallback still happens either way, but the real error stays visible.
_MISSING_EXPORT_MARKERS = ("unable to find method", "not a function", "no attribute", "has no")


def _classify_rpc_init_error(exc: BaseException) -> str:
    """"export_missing" for an AttributeError or a message that looks like a
    missing RPC export; otherwise "init_failed". A heuristic, not a measured
    contract (see _MISSING_EXPORT_MARKERS)."""
    if isinstance(exc, AttributeError):
        return "export_missing"
    text = str(exc).lower()
    if any(marker in text for marker in _MISSING_EXPORT_MARKERS):
        return "export_missing"
    return "init_failed"


def _init_agent_params_blocking(script, agent_params: Any, timeout_seconds: float) -> dict:
    """Delivers ``agent_params`` to an already-``script.load()``-ed agent
    script, synchronously, with a hard bound -- the SAME mechanism for the
    main target's own script AND for any ``--follow-children`` child's own
    script (extracted from what was previously duplicated inline here, so
    both call sites share one bounded, tested path rather than a
    parallel/divergent copy for children).

    Prefers ``script.exports_sync.init(agent_params)`` (frida's own
    synchronous RPC round trip -- see https://frida.re/docs/javascript-api/
    #rpc): a real call/response that only returns once the agent's own
    ``rpc.exports.init`` body has actually finished running (e.g. attaching
    every already-resolvable hook), closing the resume-before-hooks-attach
    race documented at this function's original call site below. An agent
    that does NOT define ``rpc.exports.init`` raises a clean, catchable
    error here -- caught and treated as "this agent uses the older
    ``recv('init', ...)`` convention instead", the same
    ``script.post({"type": "init", ...})`` fire-and-forget call this
    launcher always made for such agents.

    Run on a daemon thread with a hard join timeout (same idiom as
    ``DETACH_TIMEOUT_SECONDS``/``KILL_TIMEOUT_SECONDS`` elsewhere in this
    file): nothing here can guarantee a caller-supplied agent's own
    ``init()`` body returns promptly, so a hung agent must never be able to
    hang this launcher past ``timeout_seconds``.

    Returns ``{"timed_out": bool, "method": "rpc_sync"|"post_async"|None}``
    -- ``method`` is ``None`` only when ``timed_out`` is ``True`` (the RPC
    call is abandoned mid-flight, its eventual outcome unknown, so nothing
    here claims a method). Never falls back to ``post()`` after a timeout:
    the loaded agent DID define ``rpc.exports.init`` (an agent without it
    raises immediately, well inside the bound), so a fallback would risk
    firing that same init logic a second time on whatever eventually
    unblocks the abandoned call. Callers decide what a timeout means for
    them (the main target aborts the whole run; a ``--follow-children``
    child is instead reported via its own ``child_instrumentation_failed``
    and still resumed -- see ``run()`` below for both)."""
    outcome: dict[str, Any] = {"method": None}

    def _worker() -> None:
        try:
            script.exports_sync.init(agent_params)
            outcome["method"] = "rpc_sync"
        except Exception as exc:  # noqa: BLE001 -- classified below, never swallowed
            outcome["method"] = "rpc_unsupported"
            outcome["error_type"] = type(exc).__name__
            outcome["error_detail"] = str(exc)
            outcome["reason"] = _classify_rpc_init_error(exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        return {"timed_out": True, "method": None}
    if outcome["method"] == "rpc_sync":
        return {"timed_out": False, "method": "rpc_sync"}
    script.post({"type": "init", "params": agent_params})
    return {
        "timed_out": False, "method": "post_async",
        "fallback_reason": outcome.get("reason"),
        "rpc_error_type": outcome.get("error_type"),
        "rpc_error_detail": outcome.get("error_detail"),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frida_trace_client",
        description=(
            "Generic, guest-only frida instrumentation client: attach/spawn a "
            "process, load an externally-supplied JS agent, stream its "
            "messages to stdout as JSON Lines for a bounded duration, then "
            "exit cleanly."
        ),
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--attach-name", metavar="PROCESS_NAME", help="attach to a running process by name")
    target.add_argument("--attach-pid", metavar="PID", type=int, help="attach to a running process by PID")
    target.add_argument("--spawn", metavar="EXE_PATH", help="spawn a new process from this path and instrument it")

    parser.add_argument("--agent", required=True, metavar="JS_PATH", help="path to the Frida JS agent script to load")
    parser.add_argument(
        "--agent-params", metavar="PATH_OR_JSON", default=None,
        help="optional JSON file path or inline JSON text posted to the agent once after load",
    )
    parser.add_argument(
        "--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS,
        help=f"how long to keep tracing before detaching and exiting cleanly (clamped to [{MIN_DURATION_SECONDS}, {MAX_DURATION_SECONDS}])",
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="when --spawn is used, do not resume the spawned process after the agent loads (ignored for --attach-*)",
    )
    parser.add_argument(
        "--stdin-data", metavar="PATH", default=None,
        help=(
            "spawn-only: path to a file of raw bytes written to the spawned target's real stdin via "
            "Device.input() once the agent is loaded, before resume (forces stdio=\"pipe\" for this spawn; "
            "see this module's own docstring for why stdio=\"inherit\" does not deliver stdin to a frida-"
            "spawned target on Windows)"
        ),
    )
    parser.add_argument("--device-id", default=None, metavar="ID", help="optional frida device id; defaults to the local device")
    parser.add_argument("--output", default=None, metavar="PATH", help="write JSON-lines output here instead of stdout")
    parser.add_argument(
        "--follow-children", action="store_true",
        help=(
            "also instrument child processes the target spawns (frida session-level child gating): each "
            "child is held suspended the instant it appears, the SAME --agent (and --agent-params, if given) "
            "is loaded into it before it is ever allowed to run, and it is then resumed -- OFF by default, so "
            "no existing caller's behavior changes. Only catches children of a process THIS launcher itself "
            "spawned and attached (--spawn), never children of a process attached to late via --attach-name/"
            "--attach-pid, and never a process created by a broker/service rather than the parent itself. "
            "Every message/hit this produces is tagged with \"source_pid\" so a child's own records are "
            "never mistaken for the main target's."
        ),
    )
    parser.add_argument(
        "--max-children", type=int, default=DEFAULT_MAX_CHILDREN, metavar="N",
        help=(
            f"only meaningful with --follow-children: caps how many children ONE run will instrument "
            f"(clamped to [{MIN_MAX_CHILDREN}, {MAX_MAX_CHILDREN}]); a child seen after the cap is still "
            f"reported (child_added) and resumed immediately (never left gated/hanging), just not "
            f"instrumented -- reported via its own child_skipped_cap_reached event, plus one "
            f"child_cap_reached marker the first time the cap is hit in a run"
        ),
    )
    return parser


def _clamp_duration(requested: float) -> float:
    return max(MIN_DURATION_SECONDS, min(MAX_DURATION_SECONDS, requested))


def _clamp_max_children(requested: int) -> int:
    return max(MIN_MAX_CHILDREN, min(MAX_MAX_CHILDREN, requested))


def _abandon_spawned_target_best_effort(
    device, spawned_pid: Optional[int], *, resume_first: bool = True,
) -> None:
    """Best-effort resume-then-kill of a target THIS launcher itself
    spawned, used only from a setup-failure path that is reached AFTER
    ``device.spawn()`` but BEFORE the normal resume/teardown flow further
    down in ``run()`` would ever get to it -- e.g. ``--follow-children``
    was requested but ``session.enable_child_gating()`` itself raised on
    the main target's own session. MEASURED live (2026-09-16, see this
    module's own docstring): returning straight from that kind of failure
    without this call leaves the spawned target still suspended
    (``CREATE_SUSPENDED``), never resumed and never killed -- "the feature
    is not merely useless, it breaks the run." A no-op for ``spawned_pid is
    None`` (attach modes own nothing here). Both calls are independently
    best-effort (a resume can succeed while a kill races the target's own
    natural exit, or vice versa) -- neither is allowed to raise into the
    caller's own refusal path."""
    if spawned_pid is None:
        return
    # resume_first=False: used where the agent's hook state is UNKNOWN (init
    # timed out / agent start raised) -- resuming would run the target
    # un-instrumented, so it is killed while still suspended. Default True
    # keeps the original behaviour for the child-gating caller unchanged.
    if resume_first:
        try:
            device.resume(spawned_pid)
        except Exception:  # noqa: BLE001 -- best-effort only
            pass
    try:
        device.kill(spawned_pid)
    except Exception:  # noqa: BLE001 -- best-effort only, e.g. already exited
        pass


# --- guest-only entry guard -------------------------------------------------
# This client is designed to run ONLY inside the isolated guest, but nothing
# used to enforce that: the module is directly runnable and never called the
# dynamic-lab gate. It is NOT wired to lab_gate.LabGate on purpose: that gate
# answers ISOLATION_REQUIRED / ISOLATED_GUEST_NOT_VERIFIABLE for every
# executing operation, so binding spawn/attach to it would kill guest use
# permanently. Instead the guest is identified by an explicit, operator-set
# marker. It is a self-asserted marker, not an attestation of isolation.
GUEST_MARKER_ENV = "LIEBERT_RE_FRIDA_GUEST"
GUEST_MARKER_VALUE = "isolated-guest"


def _read_guest_marker() -> Optional[str]:
    """The marker value, or None if absent. May raise if unreadable."""
    return os.environ.get(GUEST_MARKER_ENV)


def _guest_marker_refusal() -> Optional[dict]:
    """None only when a valid marker is present; otherwise a structured
    refusal. Absent, unreadable and malformed all refuse: failing to check
    never means proceed."""
    try:
        value = _read_guest_marker()
    except Exception as exc:  # noqa: BLE001 -- any failure to read is a refusal
        return {"code": "GUEST_MARKER_UNREADABLE",
                "detail": f"could not read the guest marker {GUEST_MARKER_ENV}: {type(exc).__name__}; refusing"}
    if value is None:
        return {"code": "GUEST_MARKER_ABSENT",
                "detail": f"{GUEST_MARKER_ENV} is not set: this client runs only inside the isolated guest; "
                          "refusing to spawn or attach on this machine"}
    if value != GUEST_MARKER_VALUE:
        return {"code": "GUEST_MARKER_UNREADABLE",
                "detail": f"{GUEST_MARKER_ENV} is set but is not a valid guest marker; refusing"}
    return None


def run(
    args: argparse.Namespace,
    *,
    frida_module=None,
    open_process_handle=None,
    read_exit_code=None,
    close_process_handle=None,
) -> int:
    """Does the real work; ``frida_module`` is an injectable seam purely for
    testing this file's argument/event/exit-code plumbing WITHOUT a real
    frida runtime or a real target process -- every non-test invocation
    (including every invocation from the packaged exe) uses the real
    ``frida`` package, imported lazily below so importing this module for
    ``--help``/arg-parsing tests never requires frida/a running target.
    ``open_process_handle``/``read_exit_code``/``close_process_handle`` are
    the same kind of seam for ``_open_process_handle``/
    ``_read_exit_code_from_handle``/``_close_process_handle`` -- a real
    retained Windows handle under a real kernel32 in every non-test
    invocation, fakes in tests."""
    if frida_module is None:
        # The real frida path: refuse before importing frida or opening anything.
        # The marker check covers this real-frida path only; passing frida_module
        # explicitly is the offline test seam and is not a supported bypass.
        refusal = _guest_marker_refusal()
        if refusal is not None:
            sys.stdout.write(json.dumps({"event": "error", "timestamp": _now_iso(), **refusal}) + "\n")
            sys.stdout.flush()
            return 2
        import frida as frida_module  # noqa: PLC0415 -- intentionally local, see docstring
    if open_process_handle is None:
        open_process_handle = _open_process_handle
    if read_exit_code is None:
        read_exit_code = _read_exit_code_from_handle
    if close_process_handle is None:
        close_process_handle = _close_process_handle

    out_handle = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    writer = _JsonLineWriter(out_handle)
    process_handle: Optional[int] = None
    follow_children = bool(getattr(args, "follow_children", False))
    max_children = _clamp_max_children(getattr(args, "max_children", DEFAULT_MAX_CHILDREN))
    # Set True only once session.enable_child_gating() has actually
    # succeeded below, on the main target's OWN session -- read from this
    # launcher's own outer teardown (the finally: block at the bottom of
    # this function) to decide whether session.disable_child_gating() is
    # meaningful to call at all; `session` itself is only ever referenced
    # there when this is True, so an early failure before the session is
    # even established never touches it.
    child_gating_enabled = False
    device = None

    def _make_on_message(source_pid: Optional[int]):
        # ``source_pid`` is only non-None when --follow-children is in play
        # (see the two call sites below) -- with the option OFF, this is
        # called with None for the (only) target, and the emitted "message"
        # event is byte-for-byte what this launcher always produced, no new
        # key at all. With it ON, every "message" event -- from the main
        # target's own script AND from every instrumented child's own
        # script -- carries "source_pid" so a hit/record can never be
        # mistaken for a different process's once a caller is looking at
        # more than one process's records in the same JSON-lines stream.
        def _on_message(message: dict, data) -> None:
            record = {
                "event": "message",
                "timestamp": _now_iso(),
                "type": message.get("type"),
                "payload": message.get("payload"),
                "stack": message.get("stack"),
                "description": message.get("description"),
                "data_len": len(data) if data else 0,
            }
            if source_pid is not None:
                record["source_pid"] = source_pid
            writer.write(record)
        return _on_message

    try:
        duration = _clamp_duration(args.duration_seconds)
        writer.write({"event": "ready", "timestamp": _now_iso(), "duration_seconds": duration})

        try:
            agent_params = _parse_agent_params(args.agent_params)
        except ValueError as exc:
            writer.write({"event": "error", "timestamp": _now_iso(), "detail": str(exc)})
            return 2

        try:
            with open(args.agent, "r", encoding="utf-8") as fh:
                agent_source = fh.read()
        except OSError as exc:
            writer.write({"event": "error", "timestamp": _now_iso(), "detail": f"could not read --agent {args.agent!r}: {exc}"})
            return 2

        stdin_data: Optional[bytes] = None
        if args.stdin_data is not None:
            if args.spawn is None:
                writer.write({
                    "event": "error", "timestamp": _now_iso(),
                    "detail": "--stdin-data requires --spawn (Device.input() only targets a process this launcher itself spawned)",
                })
                return 2
            try:
                with open(args.stdin_data, "rb") as fh:
                    stdin_data = fh.read()
            except OSError as exc:
                writer.write({"event": "error", "timestamp": _now_iso(), "detail": f"could not read --stdin-data {args.stdin_data!r}: {exc}"})
                return 2

        def on_output(pid_out: int, fd: int, data: Optional[bytes]) -> None:
            # Only ever fires for a stdio="pipe" spawn (this launcher's own
            # ChildProcess.pipes -- see frida-core's windows-host-session.
            # vala: `if (pipes != null) { process_next_output_from... }`);
            # never for stdio="inherit" spawns or --attach-*, where frida
            # never wires this device-level signal at all -- so this is
            # always a no-op for every invocation that did not pass
            # --stdin-data. base64 keeps arbitrary binary output JSON-safe.
            writer.write({
                "event": "output", "timestamp": _now_iso(), "pid": pid_out, "fd": fd,
                "data_b64": base64.b64encode(data).decode("ascii") if data else "",
                "data_len": len(data) if data else 0,
            })

        try:
            device = frida_module.get_device(args.device_id) if args.device_id else frida_module.get_local_device()
            device.on("output", on_output)
        except Exception as exc:  # noqa: BLE001 -- reported as a JSON error line, never a bare traceback
            writer.write({"event": "error", "timestamp": _now_iso(), "detail": f"could not resolve frida device: {exc}"})
            return 3

        spawned_pid: Optional[int] = None
        spawn_monotonic: Optional[float] = None
        try:
            if args.spawn is not None:
                # stdio: "pipe" when --stdin-data was given, "inherit"
                # otherwise. MEASURED root cause (2026-09-16, see this
                # module's own docstring above --stdin-data): stdio=
                # "inherit" does NOT deliver a caller-redirected stdin of
                # THIS process to a frida-spawned target on Windows, because
                # frida's Windows backend performs the actual CreateProcess
                # through its own native spawn path, not by re-inheriting an
                # OS handle this launcher happened to receive from ITS OWN
                # parent. stdio="pipe" makes frida create its own real OS
                # pipe wired directly into the target's stdin at the exact
                # CreateProcess call that creates it (single-hop, no cross-
                # process handle-inheritance question at all), and exposes
                # writing to it via the documented, cross-platform
                # Device.input() API used below. "inherit" is kept as the
                # default (unchanged behavior) when no stdin data is being
                # fed, since it needs no extra IPC round trip for stdout/
                # stderr in that case.
                stdio = "pipe" if stdin_data is not None else "inherit"
                spawned_pid = device.spawn([args.spawn], stdio=stdio)
                spawn_monotonic = time.monotonic()
                # Acquire and RETAIN a process handle right here -- the PID
                # is known and the process is definitely alive at this exact
                # point (frida-core's Windows spawn always creates it
                # suspended, it cannot have exited yet) -- see
                # _open_process_handle's own docstring for why this must
                # happen now rather than later, from inside the detach
                # callback, by PID.
                process_handle = open_process_handle(spawned_pid)
                pid = spawned_pid
                writer.write({"event": "spawned", "timestamp": _now_iso(), "pid": pid, "path": args.spawn})
                session = device.attach(pid)
            elif args.attach_pid is not None:
                pid = args.attach_pid
                session = device.attach(pid)
                writer.write({"event": "attached", "timestamp": _now_iso(), "pid": pid})
            else:
                # A bare NAME can collide with an unrelated running process
                # that happens to share it (MEASURED live, 2026-09-16: a
                # decoy's name matched a genuine system process, and the
                # prior code just let frida's own device.attach(name) pick
                # one silently). Checked via Device.enumerate_processes()
                # BEFORE ever calling device.attach() -- best-effort: a
                # build/backend that cannot enumerate at all (caught below)
                # falls back to the old direct-attach-by-name behavior
                # rather than inventing ambiguity it cannot actually detect.
                try:
                    candidates = [
                        {"pid": proc.pid, "name": getattr(proc, "name", None)}
                        for proc in device.enumerate_processes()
                        if getattr(proc, "name", None) == args.attach_name
                    ]
                except Exception:  # noqa: BLE001 -- enumeration unsupported; fall back below
                    candidates = None
                if candidates is not None and len(candidates) > 1:
                    writer.write({
                        "event": "error", "timestamp": _now_iso(),
                        "detail": (
                            f"--attach-name {args.attach_name!r} matched {len(candidates)} running "
                            f"processes; refusing to guess which one -- use --attach-pid instead."
                        ),
                        "candidates": candidates,
                    })
                    return 7
                if candidates:
                    pid = candidates[0]["pid"]
                    session = device.attach(pid)
                else:
                    session = device.attach(args.attach_name)
                    pid = getattr(session, "pid", None)
                writer.write({"event": "attached", "timestamp": _now_iso(), "pid": pid, "process_name": args.attach_name})
        except Exception as exc:  # noqa: BLE001
            writer.write({"event": "error", "timestamp": _now_iso(), "detail": f"could not attach/spawn target: {exc}"})
            return 4

        # --follow-children (OFF by default -- see build_arg_parser): gate
        # children via frida's SESSION-level child gating (Session.
        # enable_child_gating(), called on the main target's OWN session)
        # combined with the DEVICE-level 'child-added' signal, so a child
        # process spawned while this run is active is held suspended the
        # instant it appears, then instrumented with the SAME agent (and
        # agent_params, if any) before ever letting it run. This is the
        # whole point of the option: a launcher/worker target whose real
        # logic lives in a spawned CHILD process is otherwise invisible
        # after the first process (MEASURED 2026-09-16 against a real
        # protected target: every hook attached, nothing detected the
        # instrumentation, and console read/write hooks still never fired,
        # because the real work happened in a child under an innocuous
        # name). CORRECTED (2026-09-16, primary-source investigation, see
        # this module's own docstring): the previous 'child-added' raised
        # on Session.on() failure that had led to a device-spawn-gating
        # detour was this launcher's own API misuse -- 'child-added' is a
        # DEVICE signal, never a session one; subscribing on the session is
        # exactly what produced that error. session.enable_child_gating()
        # is called here, BEFORE the main target is ever resumed further
        # down, so a fast-spawning child can never race ahead of gating.
        children_lock = threading.Lock()
        children_state = {"count": 0, "cap_reported": False}

        def _resume_child_best_effort(child_pid: int) -> None:
            # ALWAYS called, on every path out of on_child_added below (see
            # its own try/finally) -- a child this launcher gates and then
            # never resumes is a hang it itself caused, indistinguishable
            # from the target simply never continuing. Device.resume(pid)
            # is frida's own resume call for a GATED child (distinct from
            # Session.resume(), which is an unrelated network-reconnect
            # call and does not apply here) -- the same call this launcher
            # already uses for its own spawned main target. Best-effort/
            # reported, never raises into frida's own callback thread.
            try:
                device.resume(child_pid)
                writer.write({"event": "child_resumed", "timestamp": _now_iso(), "pid": child_pid})
            except Exception as exc:  # noqa: BLE001
                writer.write({
                    "event": "child_resume_failed", "timestamp": _now_iso(),
                    "pid": child_pid, "detail": str(exc),
                })

        def on_child_added(child) -> None:
            # Runs on frida's own callback thread, same as on_message/
            # on_detached elsewhere in this file -- writer is already
            # lock-protected (_JsonLineWriter), and children_state is
            # guarded by children_lock below for the same reason (several
            # processes could spawn in quick succession while gating is
            # active). ``child`` is frida's own Child object, which exposes
            # ``pid``/``parent_pid``/``path``/``argv``/``envp``/
            # ``identifier``/``origin`` on this build (CONFIRMED by
            # introspecting the installed frida package's own type stubs,
            # 2026-09-16) -- every field is still read via getattr with a
            # None default so this never raises on a build that supplies
            # fewer/more fields, and a caller only ever sees a field this
            # run's actual build proved it has, never an invented one.
            child_pid = getattr(child, "pid", None)
            child_parent_pid = getattr(child, "parent_pid", None)
            child_identifier = getattr(child, "identifier", None)
            child_path = getattr(child, "path", None)
            child_argv = list(getattr(child, "argv", None) or []) or None
            # Reported BEFORE the cap decision below -- a caller must learn
            # a child existed even when it is not going to be instrumented.
            writer.write({
                "event": "child_added", "timestamp": _now_iso(), "pid": child_pid,
                "parent_pid": child_parent_pid, "identifier": child_identifier,
                "path": child_path, "argv": child_argv,
            })

            with children_lock:
                over_cap = children_state["count"] >= max_children
                if not over_cap:
                    children_state["count"] += 1
                elif not children_state["cap_reported"]:
                    children_state["cap_reported"] = True
                    writer.write({
                        "event": "child_cap_reached", "timestamp": _now_iso(),
                        "max_children": max_children,
                    })

            if over_cap:
                writer.write({"event": "child_skipped_cap_reached", "timestamp": _now_iso(), "pid": child_pid})
                _resume_child_best_effort(child_pid)
                return

            try:
                child_session = device.attach(child_pid)
                # GRANDCHILDREN: enable child gating on THIS child's own
                # session too, before it is ever resumed -- 'child-added'
                # is a device-level signal shared by every session on this
                # device with gating enabled, so a grandchild spawned by
                # this now-gated child is delivered to this SAME
                # on_child_added callback with no separate wiring. Falls
                # out naturally from instrumenting every gated child the
                # same way; best-effort (a build/backend that cannot gate a
                # child's own session at all is still instrumented and
                # resumed normally -- it simply will not see further
                # descendants, which is honestly no worse than not
                # attempting this at all).
                try:
                    child_session.enable_child_gating()
                except Exception:  # noqa: BLE001 -- best-effort; see comment above
                    pass
                child_script = child_session.create_script(agent_source)
                child_script.on("message", _make_on_message(child_pid))
                child_script.load()
                if agent_params is not None:
                    # CHILD_INIT_TIMEOUT_SECONDS, not INIT_TIMEOUT_SECONDS --
                    # see that constant's own docstring above for the
                    # MEASURED false-failure this bound exists to close (a
                    # freshly-gated child's own init() genuinely takes
                    # longer than the main target's, not because it fails).
                    init_result = _init_agent_params_blocking(child_script, agent_params, CHILD_INIT_TIMEOUT_SECONDS)
                    if init_result["timed_out"]:
                        raise TimeoutError(
                            f"script.exports_sync.init() did not return within {CHILD_INIT_TIMEOUT_SECONDS}s "
                            f"for child pid {child_pid}"
                        )
                    child_sent = {
                        "event": "child_agent_params_sent", "timestamp": _now_iso(),
                        "pid": child_pid, "method": init_result["method"],
                    }
                    if init_result.get("fallback_reason") is not None:
                        child_sent["fallback_reason"] = init_result["fallback_reason"]
                        child_sent["rpc_error_type"] = init_result.get("rpc_error_type")
                        child_sent["rpc_error_detail"] = init_result.get("rpc_error_detail")
                    writer.write(child_sent)
                writer.write({"event": "child_instrumented", "timestamp": _now_iso(), "pid": child_pid, "path": child_path})
            except Exception as exc:  # noqa: BLE001 -- a child we cannot instrument is REPORTED, never left gated
                writer.write({
                    "event": "child_instrumentation_failed", "timestamp": _now_iso(),
                    "pid": child_pid, "path": child_path, "detail": str(exc),
                })
            finally:
                # Resumed regardless of whether instrumentation above
                # succeeded -- see _resume_child_best_effort's own docstring.
                # NOTE (known upstream Windows hang, see this module's own
                # docstring): if device.attach() above itself hangs on this
                # callback thread, this finally: block -- and therefore this
                # ONE child's own resume -- never runs either; that stays
                # scoped to this one gated child and does not block this
                # launcher's own bounded exit (main wait loop + bounded
                # detach/kill run on this launcher's own separate threads).
                _resume_child_best_effort(child_pid)

        if follow_children:
            try:
                session.enable_child_gating()
                device.on("child-added", on_child_added)
                child_gating_enabled = True
            except Exception as exc:  # noqa: BLE001
                writer.write({
                    "event": "error", "timestamp": _now_iso(),
                    "detail": (
                        f"could not enable --follow-children (session.enable_child_gating()): {exc} "
                        f"-- this frida build appears not to support session child gating on this OS; "
                        f"refusing --follow-children rather than racing children"
                    ),
                })
                # The main target may already be a spawned-suspended process
                # of this launcher's own (device.spawn() above, if --spawn
                # was used) -- never leave it hanging just because gating
                # itself could not be enabled; see this helper's own
                # docstring for the MEASURED bug this closes.
                _abandon_spawned_target_best_effort(device, spawned_pid)
                return 6

        stop_reason = {"value": None}
        # Set True only once THIS launcher has itself started tearing the
        # session down (the existing bounded detach/kill path further
        # below) -- read inside on_detached at the moment frida actually
        # delivers the detach signal, so "we killed it" vs "it died on its
        # own" is decided by ordering, never guessed at or inferred from
        # the reason string alone (frida reports "process-terminated" for
        # both a genuine self-kill AND the aftermath of our own kill()).
        we_initiated_stop = {"value": False}

        # source_pid only when --follow-children is in play -- see
        # _make_on_message's own docstring for why this keeps the OFF-by-
        # default case byte-for-byte identical to this launcher's prior
        # output.
        on_message = _make_on_message(pid if follow_children else None)

        def on_detached(reason, crash) -> None:
            stop_reason["value"] = str(reason)
            # Spawn-only, general for any spawned target (see this
            # function's own docstring for the field meanings): a target
            # this launcher only ATTACHED to was never ours to time/kill,
            # so it gets no target_terminated event, same spawn-only
            # scoping target_killed/target_kill_failed already use below.
            if spawned_pid is not None:
                runtime_seconds = (
                    time.monotonic() - spawn_monotonic if spawn_monotonic is not None else None
                )
                # Read from the handle retained at spawn time, never a
                # fresh by-PID open here -- see _open_process_handle's own
                # docstring for why a by-PID open at THIS point, after
                # termination, is the unreliable/hazardous path this
                # mechanism exists to avoid.
                exit_code = read_exit_code(process_handle)
                writer.write({
                    "event": "target_terminated",
                    "timestamp": _now_iso(),
                    "pid": spawned_pid,
                    "killed_by_us": we_initiated_stop["value"],
                    "frida_reason": str(reason),
                    "exit_code": exit_code,
                    "exit_code_hex": f"0x{exit_code & 0xFFFFFFFF:08X}" if exit_code is not None else None,
                    "exit_code_meaning": _decode_exit_code(exit_code),
                    "runtime_seconds": runtime_seconds,
                })

        try:
            script = session.create_script(agent_source)
            script.on("message", on_message)
            session.on("detached", on_detached)
            script.load()
            writer.write({"event": "agent_loaded", "timestamp": _now_iso()})

            if agent_params is not None:
                # Prefer a SYNCHRONOUS RPC call (frida's own documented
                # request/response mechanism, script.exports_sync -- see
                # https://frida.re/docs/javascript-api/#rpc) over the older
                # fire-and-forget script.post({"type": "init", ...}): a
                # plain post() only ENQUEUES the message; nothing here ever
                # waited for the agent's own recv('init', ...) handler to
                # actually finish running before falling through to resume()
                # below. MEASURED live (2026-09-16, against a real spawned
                # crackme with a bare few dozen instructions between its
                # entry point and the first hooked address, fed
                # pre-supplied stdin so no interactive wait masked the
                # race): the target ran to completion and produced its real
                # output before the agent's async 'init' handler had even
                # attached the requested hooks, so every hook that should
                # have fired on that single pass never did -- not a hook-
                # placement bug, a synchronization bug in THIS launcher.
                # rpc.exports.init(...), if the loaded agent defines it, is
                # a real call/response round trip: this blocks until the
                # agent has finished whatever synchronous work its own
                # init() does (e.g. attaching every already-resolvable
                # hook) before this call returns, closing the race for any
                # agent that opts in. An agent that does NOT define
                # rpc.exports.init (every other agent this launcher already
                # supports, none of which were changed) raises a clean,
                # catchable RPC error here -- caught and treated as "this
                # agent uses the plain recv('init', ...) convention
                # instead", the exact same post() call this launcher always
                # made, so nothing already working regresses.
                #
                # This call is itself run on a daemon thread with a hard
                # join timeout (INIT_TIMEOUT_SECONDS), same idiom as
                # session.detach() below: nothing in this launcher can
                # guarantee a caller-supplied agent's own init() body
                # returns promptly -- it is external code, and this file's
                # own contract ("always exits on its own, never runs
                # unbounded") would otherwise be violated BEFORE the
                # duration budget timer below even starts. If the call has
                # not returned within the bound, this is treated as a
                # genuine setup failure (an "error" event + non-zero exit,
                # same family as "could not load/start agent" just below),
                # not a silent fall-back to post(): the loaded agent DID
                # define rpc.exports.init (an agent without it raises
                # immediately, well inside the bound), so falling back to
                # post() here would fire that same init logic a second time
                # on whatever eventually unblocks the abandoned RPC call,
                # and resuming the target now would reopen the exact
                # unsynchronized-hook race rpc_sync exists to close.
                #
                # Extracted into _init_agent_params_blocking (see its own
                # docstring, above in this file) so the SAME bounded
                # delivery path is reused, unchanged, for every
                # --follow-children child's own script too -- see
                # on_child_added above.
                init_result = _init_agent_params_blocking(script, agent_params, INIT_TIMEOUT_SECONDS)
                if init_result["timed_out"]:
                    writer.write({
                        "event": "error", "timestamp": _now_iso(),
                        "detail": (
                            f"script.exports_sync.init() did not return within "
                            f"{INIT_TIMEOUT_SECONDS}s; agent params not confirmed "
                            f"delivered, aborting before resume."
                        ),
                    })
                    _abandon_spawned_target_best_effort(device, spawned_pid, resume_first=False)
                    return 5
                sent_event = {"event": "agent_params_sent", "timestamp": _now_iso(), "method": init_result["method"]}
                if init_result.get("fallback_reason") is not None:
                    sent_event["fallback_reason"] = init_result["fallback_reason"]
                    sent_event["rpc_error_type"] = init_result.get("rpc_error_type")
                    sent_event["rpc_error_detail"] = init_result.get("rpc_error_detail")
                writer.write(sent_event)

            if spawned_pid is not None and stdin_data is not None:
                # Sent BEFORE resume, deliberately: the target is still
                # CREATE_SUSPENDED at this point (frida-core's Windows spawn
                # always creates it suspended -- see this module's own
                # --stdin-data docstring), so this data just sits in
                # frida's own pipe buffer until the target's own C runtime
                # calls read()/ReadFile() on its stdin, no race with the
                # target's own startup code -- and the agent's hooks (set
                # up by script.load() above) are already active before a
                # single instruction of the target's own entry point runs,
                # so this loses nothing an attach-after-launch approach
                # would (early anti-debug/init checks are still covered).
                device.input(spawned_pid, stdin_data)
                writer.write({"event": "stdin_sent", "timestamp": _now_iso(), "pid": spawned_pid, "bytes_len": len(stdin_data)})

            if spawned_pid is not None and not args.no_resume:
                device.resume(spawned_pid)
                writer.write({"event": "resumed", "timestamp": _now_iso(), "pid": spawned_pid})
        except Exception as exc:  # noqa: BLE001
            writer.write({"event": "error", "timestamp": _now_iso(), "detail": f"could not load/start agent: {exc}"})
            _abandon_spawned_target_best_effort(device, spawned_pid, resume_first=False)
            return 5

        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            if stop_reason["value"] is not None:
                writer.write({"event": "detached", "timestamp": _now_iso(), "reason": stop_reason["value"]})
                return 0
            time.sleep(0.1)

        writer.write({"event": "budget_exceeded", "timestamp": _now_iso(), "duration_seconds": duration})
        # From this point on, THIS launcher is the one tearing the session
        # down (detach below, then kill further down) -- any target_terminated
        # event on_detached emits from here onward must report killed_by_us
        # =True, never conflated with a genuine self-termination, which
        # would already have short-circuited the wait loop above and never
        # reached this line at all.
        we_initiated_stop["value"] = True
        # session.detach() is a COOPERATIVE, protocol-level round trip with
        # frida-core's own session teardown machinery. MEASURED live
        # (2026-09-16, against a real target whose only thread was parked
        # in a blocking synchronous Win32 console read at the moment the
        # duration budget ran out, with one or more Interceptor hooks still
        # attached): this call did not return within any bounded time this
        # launcher was willing to wait, silently violating this module's
        # own documented contract ("this process always exits on its own,
        # never runs unbounded") and leaving an orphaned frida_trace_client.
        # exe + target process pair behind in the guest for the NEXT run to
        # trip over. Run on a daemon thread with a hard join timeout so a
        # slow/hung detach can never again keep this process alive past its
        # own duration budget -- "daemon" specifically so an abandoned
        # detach call cannot block process exit either.
        def _detach_best_effort() -> None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001 -- best-effort only
                pass

        detach_thread = threading.Thread(target=_detach_best_effort, daemon=True)
        detach_thread.start()
        detach_thread.join(timeout=DETACH_TIMEOUT_SECONDS)
        if detach_thread.is_alive():
            writer.write({
                "event": "detach_timed_out", "timestamp": _now_iso(),
                "detail": f"session.detach() did not return within {DETACH_TIMEOUT_SECONDS}s; abandoned.",
            })

        # For a target THIS launcher spawned (never for --attach-name/
        # --attach-pid, which this launcher does not own and must never
        # kill), also hard-kill it directly -- independent of whatever
        # session.detach() above did or did not manage to do -- so a target
        # left blocked in a syscall can never linger as an orphaned guest
        # process across runs regardless of detach's own outcome.
        # Never measured to hang, but bounded on the same daemon-thread
        # idiom as session.detach() above for hygiene: every blocking guest
        # call in this file shares one bounded-wait mechanism, so none of
        # them can silently become the one unbounded step.
        if spawned_pid is not None:
            kill_outcome: dict[str, Any] = {"error": None}

            def _kill_best_effort() -> None:
                try:
                    device.kill(spawned_pid)
                except Exception as exc:  # noqa: BLE001 -- best-effort only, e.g. already exited on its own
                    kill_outcome["error"] = exc

            kill_thread = threading.Thread(target=_kill_best_effort, daemon=True)
            kill_thread.start()
            kill_thread.join(timeout=KILL_TIMEOUT_SECONDS)

            if kill_thread.is_alive():
                writer.write({
                    "event": "target_kill_failed", "timestamp": _now_iso(), "pid": spawned_pid,
                    "detail": f"device.kill() did not return within {KILL_TIMEOUT_SECONDS}s; abandoned.",
                })
            elif kill_outcome["error"] is None:
                writer.write({"event": "target_killed", "timestamp": _now_iso(), "pid": spawned_pid})
            else:
                writer.write({
                    "event": "target_kill_failed", "timestamp": _now_iso(), "pid": spawned_pid,
                    "detail": str(kill_outcome["error"]),
                })

        writer.write({"event": "detached", "timestamp": _now_iso(), "reason": "budget_exceeded"})
        return 0
    finally:
        # Runs on every exit path out of the try above (clean return, early
        # return on self-termination, any error return) -- exactly one
        # close for whatever _open_process_handle returned (a no-op if it
        # returned None, e.g. attach mode or the open itself failed), so the
        # handle this launcher retained never leaks regardless of how this
        # run ends.
        close_process_handle(process_handle)
        # Only ever True once session.enable_child_gating() actually
        # succeeded above, on the main target's OWN session -- disabled
        # again here, on EVERY exit path (clean return, early error return,
        # self-termination), so a run that enabled child gating never
        # leaves that session in that state afterward. (Gated children's
        # own sessions are not separately torn down here -- see this
        # module's own docstring.) Best-effort/never raises into this
        # launcher's own teardown.
        if child_gating_enabled:
            try:
                session.disable_child_gating()
            except Exception:  # noqa: BLE001 -- best-effort only
                pass
        if args.output:
            out_handle.close()


def main(argv: Optional[list] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
