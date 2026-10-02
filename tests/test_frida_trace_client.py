"""Offline coverage for guest_agents/frida_client/frida_trace_client.py's
argument parsing, JSON-lines event plumbing, and exit-code contract -- run
entirely on the HOST, with no real frida runtime, no frida-server, no
Hyper-V guest, and no real target process. This exercises the file's own
``run(args, frida_module=...)`` injectable seam (see that function's
docstring) with a small fake object standing in for the real ``frida``
module's ``get_local_device()``/``Device``/``Session``/``Script`` surface,
so this test proves the launcher's own logic (arg handling, event
sequencing, clean bounded exit, error-to-nonzero-exit mapping) independent
of whether a real frida-server is reachable.

This is deliberately NOT a claim that the packaged exe has been proven
against a live guest frida-server -- that is a separate, live, guest-side
verification step outside what a host-side unit test can honestly claim."""
from __future__ import annotations

import io
import json
import sys
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLIENT_DIR = REPO_ROOT / "guest_agents" / "frida_client"
sys.path.insert(0, str(CLIENT_DIR))

import liebert_re.dynamic.frida_trace_client as client  # noqa: E402


class _FakeScript:
    def __init__(self, source: str) -> None:
        self.source = source
        self._on_message = None
        self.loaded = False
        self.posted = []

    def on(self, event_name, callback) -> None:
        if event_name == "message":
            self._on_message = callback

    def load(self) -> None:
        self.loaded = True

    def post(self, message) -> None:
        self.posted.append(message)
        if self._on_message is not None:
            # Simulate the agent immediately echoing back whatever init
            # params it received, exactly the shape a real send() call
            # from JS would produce on script.on('message', ...).
            self._on_message({"type": "send", "payload": {"echo": message}}, None)


class _FakeExportsSync:
    """Stands in for frida's real ``Script.exports_sync`` -- a proxy whose
    attribute access returns a callable RPC stub. Records every call so a
    test can assert the launcher preferred this SYNCHRONOUS path over the
    older ``post()`` fire-and-forget one, and never returns None (mirrors
    frida's own contract of returning whatever the agent's rpc.exports
    function returned)."""

    def __init__(self, script: "_FakeScriptWithExports") -> None:
        self._script = script

    def __getattr__(self, name):
        def _call(*args, **kwargs):
            self._script.rpc_calls.append((name, args, kwargs))
            return {"ok": True}
        return _call


class _FakeScriptWithExports(_FakeScript):
    """A ``_FakeScript`` whose ``exports_sync`` actually works (unlike
    plain ``_FakeScript``, which has no such attribute at all and so makes
    the launcher's own ``try: script.exports_sync...`` raise ``AttributeError``
    and fall back to ``post()`` -- the SAME fallback a real agent that only
    defines ``recv('init', ...)`` and no ``rpc.exports`` would trigger)."""

    def __init__(self, source: str) -> None:
        super().__init__(source)
        self.rpc_calls = []
        self.exports_sync = _FakeExportsSync(self)


class _FakeBlockingExportsSync:
    """Stands in for a real agent's ``rpc.exports.init`` whose own
    synchronous body hangs -- every attribute access returns a callable
    that blocks on an ``Event`` nothing ever sets, i.e. never returns on
    its own. Used to prove the launcher's own INIT_TIMEOUT_SECONDS bound
    (not the fake) is what stops the launcher from hanging."""

    def __getattr__(self, name):
        def _call(*args, **kwargs):
            threading.Event().wait()
        return _call


class _FakeScriptWithBlockingExports(_FakeScript):
    """A ``_FakeScript`` whose ``exports_sync`` exists (so the launcher
    takes the rpc_sync path, not the AttributeError/post() fallback path)
    but never returns from the RPC call -- simulates a caller-supplied
    agent that defines ``rpc.exports.init`` yet whose own body hangs."""

    def __init__(self, source: str) -> None:
        super().__init__(source)
        self.exports_sync = _FakeBlockingExportsSync()


def _make_first_fast_rest_slow_script_cls(sleep_seconds):
    """Factory (fresh state per call, so tests never share a counter) for a
    ``_FakeScript`` subclass where ``create_script()`` call #1 (the MAIN
    target's own session, always created and initialized before any
    ``--follow-children`` child ever appears -- see run()'s own ordering)
    gets an ``exports_sync`` that returns immediately, and every call after
    that (each gated child's own session) gets one that sleeps
    ``sleep_seconds`` before returning successfully -- simulating a
    freshly-gated child's own ``rpc.exports.init`` RPC genuinely taking
    longer than the main target's, the MEASURED false-failure this file's
    own ``CHILD_INIT_TIMEOUT_SECONDS`` (see that constant's own docstring)
    exists to close: proves a bound derived specifically for a child, not
    the shared main-target bound, is what actually gets consulted."""
    import itertools
    import time as _time

    counter = itertools.count()

    class _SlowExportsSync:
        def __init__(self, script) -> None:
            self._script = script

        def __getattr__(self, name):
            def _call(*args, **kwargs):
                self._script.rpc_calls.append((name, args, kwargs))
                _time.sleep(sleep_seconds)
                return {"ok": True}
            return _call

    class _Script(_FakeScript):
        def __init__(self, source: str) -> None:
            super().__init__(source)
            self.rpc_calls = []
            if next(counter) == 0:
                self.exports_sync = _FakeExportsSync(self)
            else:
                self.exports_sync = _SlowExportsSync(self)

    return _Script


def _make_first_fast_rest_hang_script_cls():
    """Same shape as ``_make_first_fast_rest_slow_script_cls`` above, but
    every call after the first (i.e. every gated child's own session)
    NEVER returns at all -- a genuine, not merely slow, child init
    failure, for the companion regression guard that a real failure must
    still be reported as one."""
    import itertools

    counter = itertools.count()

    class _Script(_FakeScript):
        def __init__(self, source: str) -> None:
            super().__init__(source)
            self.rpc_calls = []
            if next(counter) == 0:
                self.exports_sync = _FakeExportsSync(self)
            else:
                self.exports_sync = _FakeBlockingExportsSync()

    return _Script


class _FakeSession:
    def __init__(self, pid, script_cls=_FakeScript) -> None:
        self.pid = pid
        self._detached_cb = None
        self.detach_called = False
        self._script_cls = script_cls
        self.script = None
        # session-level child gating (frida's real Session.
        # enable_child_gating()/disable_child_gating()) -- every _FakeSession
        # (main target's own AND every gated child's own, since
        # frida_trace_client.py now calls this on BOTH, for grandchild
        # support) can independently track/refuse it.
        self.child_gating_enabled = False
        self.child_gating_enable_calls = 0
        self.child_gating_disable_calls = 0
        # Configurable by a test (or a _FakeDevice subclass's own attach())
        # to prove the launcher's own fail-closed handling of a build that
        # does not support session child gating on this OS.
        self._enable_child_gating_should_fail = False

    def create_script(self, source: str) -> _FakeScript:
        self.script = self._script_cls(source)
        return self.script

    def on(self, event_name, callback) -> None:
        if event_name == "detached":
            self._detached_cb = callback

    def detach(self) -> None:
        self.detach_called = True

    def enable_child_gating(self) -> None:
        if self._enable_child_gating_should_fail:
            raise RuntimeError("session child gating unsupported by this frida build on this OS")
        self.child_gating_enabled = True
        self.child_gating_enable_calls += 1

    def disable_child_gating(self) -> None:
        self.child_gating_enabled = False
        self.child_gating_disable_calls += 1


class _FakeChild:
    """Stands in for frida's real ``Child`` object delivered to a
    ``'child-added'`` callback under SESSION-level child gating (subscribed
    on the DEVICE -- see this module's own corrected understanding, 2026-
    09-16). CONFIRMED by direct introspection of the installed frida
    package's own type stubs (17.10.1): a real ``Child`` exposes ``pid``,
    ``parent_pid``, ``path``, ``argv``, ``envp``, ``identifier``, and
    ``origin``. ``frida_trace_client.py`` itself only ever reads these via
    ``getattr`` with a ``None`` default, so a test can still exercise a
    build that supplies fewer fields by leaving them at their ``None``
    default here."""

    def __init__(self, pid, parent_pid=None, identifier=None, path=None, argv=None) -> None:
        self.pid = pid
        self.parent_pid = parent_pid
        self.identifier = identifier
        self.path = path
        self.argv = argv


class _FakeProcess:
    """Stands in for frida's real ``Process`` object returned by
    ``Device.enumerate_processes()`` -- only ``pid``/``name``, the two
    fields this launcher's own ambiguous-``--attach-name`` check reads."""

    def __init__(self, pid, name) -> None:
        self.pid = pid
        self.name = name


class _FakeDevice:
    def __init__(self, script_cls=_FakeScript) -> None:
        self.resumed = []
        self.spawned_path = None
        self.spawned_stdio = None
        self.input_calls = []
        self._output_cb = None
        self._child_added_cb = None
        self._script_cls = script_cls
        self.last_session = None
        self.sessions_by_pid = {}
        self.killed = []
        self.attach_calls = []
        # pids for which attach() should raise -- exercises a child that
        # cannot be instrumented (see _FakeDeviceChildrenAppearOnResume
        # users below).
        self.attach_should_fail_for = set()
        # Configurable by a test via `fake.device.processes = [...]` --
        # backs enumerate_processes() for the ambiguous-attach-name checks.
        self.processes = []

    def spawn(self, argv, stdio=None) -> int:
        self.spawned_path = argv[0]
        self.spawned_stdio = stdio
        return 4242

    def attach(self, target):
        pid = target if isinstance(target, int) else 4242
        self.attach_calls.append(pid)
        if pid in self.attach_should_fail_for:
            raise RuntimeError(f"fake attach() failure for pid {pid}")
        session = _FakeSession(pid, script_cls=self._script_cls)
        self.last_session = session
        self.sessions_by_pid[pid] = session
        return session

    def resume(self, pid) -> None:
        self.resumed.append(pid)

    def kill(self, pid) -> None:
        self.killed.append(pid)

    def on(self, event_name, callback) -> None:
        if event_name == "output":
            self._output_cb = callback
        elif event_name == "child-added":
            self._child_added_cb = callback

    def input(self, pid, data) -> None:
        self.input_calls.append((pid, data))
        # Simulate frida's own "output" device signal firing once real
        # bytes are written -- exercises this launcher's on_output ->
        # JSON-lines "output" event plumbing without a real pipe/target.
        if self._output_cb is not None:
            self._output_cb(pid, 1, b"echoed:" + data)

    def enumerate_processes(self, pids=None, scope=None):
        return list(self.processes)


class _FakeDeviceChildrenAppearOnResume(_FakeDevice):
    """A target whose own resume() is the moment ONE OR MORE gated children
    appear -- mirrors the real timing --follow-children exists for: a
    launcher process spawns its real-work child shortly after it starts
    running. Fires the DEVICE's own 'child-added' callback (session-level
    child gating delivers its signal on the DEVICE, not the session -- see
    this file's own module docstring, and frida_trace_client.py's own
    module docstring, for the corrected understanding of this, 2026-09-16)
    exactly once per configured child, synchronously, the first time
    resume() is called for the PARENT pid -- never again on a later
    resume() call for one of the gated children themselves (which this
    launcher's own on_child_added also triggers, via
    _resume_child_best_effort), so this fake can never recurse into firing
    children twice."""

    def __init__(self, children, script_cls=_FakeScript) -> None:
        super().__init__(script_cls=script_cls)
        self._children = list(children)
        self._fired = False

    def resume(self, pid) -> None:
        super().resume(pid)
        if self._fired:
            return
        self._fired = True
        if self._child_added_cb is None:
            return
        for child in self._children:
            self._child_added_cb(child)


class _FakeDeviceGrandchildAppearsWhenChildResumed(_FakeDevice):
    """Proves grandchild gating: ``child`` is reported/gated the same way
    as ``_FakeDeviceChildrenAppearOnResume`` (on the PARENT's own resume()),
    but ``grandchild`` is only reported once ``child``'s own pid is itself
    resumed -- which only happens after frida_trace_client.py's own
    on_child_added has called ``child_session.enable_child_gating()`` and
    instrumented it, exactly mirroring the real multi-level timing this
    launcher relies on (a grandchild spawned by an already-gated child is
    delivered to the SAME device-level 'child-added' handler, with no
    separate wiring)."""

    def __init__(self, child, grandchild, script_cls=_FakeScript) -> None:
        super().__init__(script_cls=script_cls)
        self._child = child
        self._grandchild = grandchild
        self._child_fired = False
        self._grandchild_fired = False

    def resume(self, pid) -> None:
        super().resume(pid)
        if not self._child_fired and pid != self._child.pid:
            self._child_fired = True
            if self._child_added_cb is not None:
                self._child_added_cb(self._child)
        elif not self._grandchild_fired and pid == self._child.pid:
            self._grandchild_fired = True
            if self._child_added_cb is not None:
                self._child_added_cb(self._grandchild)


class _FakeDeviceChildGatingUnsupported(_FakeDevice):
    """A device whose attach()-returned sessions all refuse
    ``enable_child_gating()`` -- simulates a frida build that does not
    support session child gating on this OS, exercising this launcher's
    own fail-closed reporting (exit code 6) for that setup failure, rather
    than a bare crash, AND that a target this launcher itself spawned is
    still resumed/killed rather than left suspended forever (the MEASURED
    bug this closes -- see
    frida_trace_client._abandon_spawned_target_best_effort)."""

    def attach(self, target):
        session = super().attach(target)
        session._enable_child_gating_should_fail = True
        return session


class _FakeDeviceSelfTerminating(_FakeDevice):
    """A spawned target that dies fully on its own moments after resume --
    mirrors a real anti-VM crackme self-terminating in ~547ms. Fires the
    same ``session.on('detached', ...)`` callback a real frida Session
    would, with a caller-supplied ``(reason, crash)`` pair, WITHOUT
    anything in this launcher itself calling detach()/kill() first (this
    fake's own resume() is the only thing that triggers it -- the fastest-
    possible real-world case, before the launcher's wait loop even starts
    polling)."""

    def __init__(self, reason, crash=None, script_cls=_FakeScript) -> None:
        super().__init__(script_cls=script_cls)
        self._detach_reason = reason
        self._detach_crash = crash

    def resume(self, pid) -> None:
        super().resume(pid)
        if self.last_session is not None and self.last_session._detached_cb is not None:
            self.last_session._detached_cb(self._detach_reason, self._detach_crash)


class _FakeDeviceKillTriggersDetach(_FakeDevice):
    """A target that stays alive through the whole duration budget, so it
    only goes away once THIS launcher's own bounded kill() path (run after
    budget_exceeded) reaches it -- exercises frida delivering the SAME
    'process-terminated' detach reason a genuine self-kill would, but as
    the direct result of this launcher's own kill(), which the launcher
    itself must still report as killed_by_us, never as a self-termination."""

    def kill(self, pid) -> None:
        super().kill(pid)
        if self.last_session is not None and self.last_session._detached_cb is not None:
            self.last_session._detached_cb("process-terminated", None)


class _FakeFridaModule:
    def __init__(self, script_cls=_FakeScript, device=None) -> None:
        self.device = device if device is not None else _FakeDevice(script_cls=script_cls)

    def get_local_device(self):
        return self.device

    def get_device(self, device_id):
        return self.device


def _write_temp_agent(tmp_path: Path) -> Path:
    agent = tmp_path / "agent.js"
    agent.write_text("// no-op test agent\n", encoding="utf-8")
    return agent


class FridaTraceClientTest(unittest.TestCase):
    def _run(
        self, argv, frida_module=None,
        open_process_handle=None, read_exit_code=None, close_process_handle=None,
    ):
        parser = client.build_arg_parser()
        args = parser.parse_args(argv)
        buf = io.StringIO()
        args.output = None
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            code = client.run(
                args,
                frida_module=frida_module or _FakeFridaModule(),
                open_process_handle=open_process_handle,
                read_exit_code=read_exit_code,
                close_process_handle=close_process_handle,
            )
        finally:
            sys.stdout = old_stdout
        lines = [json.loads(line) for line in buf.getvalue().splitlines() if line.strip()]
        return code, lines

    def test_attach_by_pid_runs_clean_bounded_exit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            code, lines = self._run([
                "--attach-pid", "999", "--agent", str(agent), "--duration-seconds", "0.2",
            ])
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events, ["ready", "attached", "agent_loaded", "budget_exceeded", "detached"],
        )
        attached = next(line for line in lines if line["event"] == "attached")
        self.assertEqual(attached["pid"], 999)

    def test_spawn_resumes_and_forwards_agent_params(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--agent-params", '{"exports": ["Foo", "Bar"]}',
                "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        # No exports_sync on plain _FakeScript (matches a real agent that
        # only defines recv('init', ...), not rpc.exports.init) -- the
        # launcher's own try/except falls back to the old post() path,
        # recorded as its own agent_params_sent(method=post_async) event.
        self.assertEqual(
            events,
            ["ready", "spawned", "agent_loaded", "message", "agent_params_sent", "resumed", "budget_exceeded", "target_killed", "detached"],
        )
        self.assertEqual(fake.device.resumed, [4242])
        # A target this launcher spawned itself is hard-killed at shutdown
        # -- independent of detach() -- so it can never linger as an
        # orphaned guest process (MEASURED live, 2026-09-16: a real target
        # blocked in a syscall at budget_exceeded left session.detach()
        # never returning at all).
        self.assertEqual(fake.device.killed, [4242])
        message_line = next(line for line in lines if line["event"] == "message")
        self.assertEqual(message_line["payload"]["echo"]["params"], {"exports": ["Foo", "Bar"]})
        sent_line = next(line for line in lines if line["event"] == "agent_params_sent")
        self.assertEqual(sent_line["method"], "post_async")
        # MEASURED live (2026-09-16): frida's default spawn gives the new
        # process its own independent stdio, not this launcher's own --
        # stdio="inherit" is required for a caller-redirected stdin (e.g. a
        # console crackme's std::cin/scanf test input) to actually reach
        # the spawned target. Regression guard for that real fix.
        self.assertEqual(fake.device.spawned_stdio, "inherit")

    def test_agent_params_prefer_synchronous_rpc_over_post_when_agent_supports_it(self):
        # ROOT CAUSE regression guard (MEASURED live, 2026-09-16): a plain
        # script.post({"type": "init", ...}) only enqueues the message --
        # nothing waited for the agent's own handler to actually finish
        # attaching anything before this launcher's very next step, resuming
        # a spawned-suspended target, ran. A target reaching a hooked
        # address within microseconds of resume (no blocking wait, e.g.
        # because its stdin was already pre-supplied) could run straight
        # through before an async recv('init', ...) handler ever attached.
        # When the loaded agent exposes rpc.exports.init (script.exports_sync
        # here), the launcher must call THAT instead -- a real blocking
        # call/response -- and must NEVER also fall back to post() in that
        # case (that would mean parameters get delivered/processed twice).
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule(script_cls=_FakeScriptWithExports)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--agent-params", '{"breakpoints": [{"id": "bp1", "address": "0x1234"}]}',
                "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events,
            ["ready", "spawned", "agent_loaded", "agent_params_sent", "resumed", "budget_exceeded", "target_killed", "detached"],
        )
        self.assertEqual(fake.device.killed, [4242])
        sent_line = next(line for line in lines if line["event"] == "agent_params_sent")
        self.assertEqual(sent_line["method"], "rpc_sync")
        # agent_params_sent (the synchronous RPC call) must precede resumed
        # -- the entire point of preferring it.
        self.assertLess(events.index("agent_params_sent"), events.index("resumed"))
        # The real RPC call landed on the agent's own exports_sync.init --
        # exactly once, with the parsed params -- and post() was never used.
        script = fake.device.last_session.script
        self.assertEqual(script.rpc_calls, [("init", ({"breakpoints": [{"id": "bp1", "address": "0x1234"}]},), {})])
        self.assertEqual(script.posted, [])

    def test_agent_params_sync_init_hang_is_bounded_not_an_unbounded_wait(self):
        # DEFECT FIX regression guard: script.exports_sync.init(...) is a
        # blocking RPC round trip into caller-supplied agent code this
        # launcher does not control. Nothing here enforces that a future
        # agent's rpc.exports.init body returns promptly -- an agent that
        # hangs inside it must not be able to hang this launcher BEFORE the
        # duration budget timer even starts. Same daemon-thread + join(
        # timeout=...) idiom as DETACH_TIMEOUT_SECONDS below, bounded here
        # via INIT_TIMEOUT_SECONDS -- patched small so this test itself
        # stays fast without weakening what it proves (the bound, not its
        # exact value, is what's under test).
        old_timeout = client.INIT_TIMEOUT_SECONDS
        client.INIT_TIMEOUT_SECONDS = 0.05
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                agent = _write_temp_agent(Path(tmp))
                fake = _FakeFridaModule(script_cls=_FakeScriptWithBlockingExports)
                code, lines = self._run([
                    "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                    "--agent-params", '{"breakpoints": [{"id": "bp1", "address": "0x1234"}]}',
                    "--duration-seconds", "0.2",
                ], frida_module=fake)
        finally:
            client.INIT_TIMEOUT_SECONDS = old_timeout
        # Aborted as a genuine setup failure, not silently treated as
        # delivered and not silently degraded to post() (which would risk
        # firing the agent's own init logic a second time once the
        # abandoned RPC call eventually unblocks, if it ever does).
        self.assertEqual(code, 5)
        events = [line["event"] for line in lines]
        self.assertEqual(events, ["ready", "spawned", "agent_loaded", "error"])
        self.assertNotIn("resumed", events)
        self.assertNotIn("agent_params_sent", events)
        error_line = next(line for line in lines if line["event"] == "error")
        self.assertIn("exports_sync.init", error_line["detail"])
        # The target was never resumed while its own init confirmation was
        # unbounded/unknown -- resuming here would silently reopen the
        # unsynchronized-hook race rpc_sync exists to close.
        self.assertEqual(fake.device.resumed, [])

    def test_stdin_data_forces_pipe_stdio_and_delivers_via_device_input(self):
        # ROOT CAUSE regression guard (MEASURED live, 2026-09-16): stdio=
        # "inherit" does not deliver a caller-redirected stdin to a
        # frida-spawned target on Windows (frida's Windows backend performs
        # the target's own CreateProcess through its native spawn path, not
        # by re-inheriting this launcher's inherited handle) -- --stdin-data
        # instead forces stdio="pipe" (required for Device.input() to have
        # a real pipe to write into) and delivers the bytes via that
        # documented, cross-platform API, BEFORE resume (still suspended).
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            stdin_file = Path(tmp) / "stdin.bin"
            stdin_file.write_bytes(b"CANDIDATE-SERIAL-123\n")
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--stdin-data", str(stdin_file), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.device.spawned_stdio, "pipe")
        self.assertEqual(fake.device.input_calls, [(4242, b"CANDIDATE-SERIAL-123\n")])
        events = [line["event"] for line in lines]
        self.assertIn("stdin_sent", events)
        stdin_sent = next(line for line in lines if line["event"] == "stdin_sent")
        self.assertEqual(stdin_sent["bytes_len"], len(b"CANDIDATE-SERIAL-123\n"))
        # stdin_sent (still suspended) must precede resumed.
        self.assertLess(events.index("stdin_sent"), events.index("resumed"))
        # The fake device's own input() call simulated frida's "output"
        # signal firing -- proves on_output -> JSON-lines "output" wiring.
        output_line = next(line for line in lines if line["event"] == "output")
        self.assertEqual(output_line["pid"], 4242)
        self.assertEqual(output_line["fd"], 1)
        import base64 as _b64
        self.assertEqual(_b64.b64decode(output_line["data_b64"]), b"echoed:CANDIDATE-SERIAL-123\n")

    def test_stdin_data_without_spawn_is_a_reported_error_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            stdin_file = Path(tmp) / "stdin.bin"
            stdin_file.write_bytes(b"x")
            code, lines = self._run([
                "--attach-pid", "1", "--agent", str(agent),
                "--stdin-data", str(stdin_file), "--duration-seconds", "0.2",
            ])
        self.assertEqual(code, 2)
        self.assertEqual(lines[-1]["event"], "error")
        self.assertIn("requires --spawn", lines[-1]["detail"])

    def test_missing_stdin_data_file_is_a_reported_error_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--stdin-data", r"C:\does\not\exist.bin", "--duration-seconds", "0.2",
            ])
        self.assertEqual(code, 2)
        self.assertEqual(lines[-1]["event"], "error")
        self.assertIn("could not read --stdin-data", lines[-1]["detail"])

    def test_no_stdin_data_still_uses_inherit_and_never_sends_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.device.spawned_stdio, "inherit")
        self.assertEqual(fake.device.input_calls, [])
        self.assertNotIn("stdin_sent", [line["event"] for line in lines])

    def test_no_resume_flag_skips_resume(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--no-resume", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.device.resumed, [])
        self.assertNotIn("resumed", [line["event"] for line in lines])

    def _handle_tracker(self, exit_code=None, handle="FAKE_PROCESS_HANDLE"):
        """A small fake standing in for a real retained Windows process
        handle's whole lifecycle -- records exactly what THIS launcher did
        with it (opened once by PID, read from later, closed once at
        teardown) so a test can assert on the calls, same fake-object style
        as the rest of this file's frida stand-ins."""
        tracker = {"open": [], "read": [], "close": []}

        def open_process_handle(pid):
            tracker["open"].append(pid)
            return handle

        def read_exit_code(h):
            tracker["read"].append(h)
            return exit_code

        def close_process_handle(h):
            tracker["close"].append(h)

        return tracker, open_process_handle, read_exit_code, close_process_handle

    def test_self_terminated_target_reports_decoded_exit_code_and_is_not_killed_by_us(self):
        # Live-ladder blind spot this event exists to close: a target that
        # self-terminates (e.g. an anti-VM check) in well under the
        # duration budget must be reported with WHY, not just the bare
        # "process-terminated" string -- here, a decoded well-known
        # NTSTATUS-shaped exit code, and explicitly NOT attributed to this
        # launcher's own kill path.
        import tempfile
        tracker, open_h, read_h, close_h = self._handle_tracker(exit_code=0xC0000005)
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule(device=_FakeDeviceSelfTerminating(reason="process-terminated"))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake, open_process_handle=open_h, read_exit_code=read_h, close_process_handle=close_h)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events, ["ready", "spawned", "agent_loaded", "target_terminated", "resumed", "detached"],
        )
        # This launcher never reached its own kill path (the target was
        # already gone) -- target_killed/target_kill_failed must not appear.
        self.assertNotIn("target_killed", events)
        self.assertNotIn("target_kill_failed", events)
        term = next(line for line in lines if line["event"] == "target_terminated")
        self.assertEqual(term["pid"], 4242)
        self.assertFalse(term["killed_by_us"])
        self.assertEqual(term["frida_reason"], "process-terminated")
        self.assertEqual(term["exit_code"], 0xC0000005)
        self.assertEqual(term["exit_code_hex"], "0xC0000005")
        self.assertEqual(term["exit_code_meaning"], "STATUS_ACCESS_VIOLATION")
        self.assertIsInstance(term["runtime_seconds"], float)
        self.assertGreaterEqual(term["runtime_seconds"], 0.0)
        self.assertEqual(tracker["close"], ["FAKE_PROCESS_HANDLE"])

    def test_killed_by_us_target_is_not_reported_as_self_termination(self):
        # The distinguishing case this event exists to make impossible to
        # conflate: frida reports the SAME "process-terminated" reason for
        # a target this launcher kills itself (via the existing bounded
        # device.kill() path, after the duration budget) as it does for a
        # genuine self-kill -- killed_by_us must still tell them apart.
        import tempfile
        tracker, open_h, read_h, close_h = self._handle_tracker(exit_code=None)
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule(device=_FakeDeviceKillTriggersDetach())
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake, open_process_handle=open_h, read_exit_code=read_h, close_process_handle=close_h)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events,
            ["ready", "spawned", "agent_loaded", "resumed", "budget_exceeded", "target_terminated", "target_killed", "detached"],
        )
        term = next(line for line in lines if line["event"] == "target_terminated")
        self.assertEqual(term["pid"], 4242)
        self.assertTrue(term["killed_by_us"])
        self.assertEqual(term["frida_reason"], "process-terminated")
        self.assertIsNone(term["exit_code"])
        self.assertIsNone(term["exit_code_meaning"])
        self.assertEqual(tracker["close"], ["FAKE_PROCESS_HANDLE"])

    def test_clean_exit_reports_exit_code_zero(self):
        import tempfile
        tracker, open_h, read_h, close_h = self._handle_tracker(exit_code=0)
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule(device=_FakeDeviceSelfTerminating(reason="process-terminated"))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake, open_process_handle=open_h, read_exit_code=read_h, close_process_handle=close_h)
        self.assertEqual(code, 0)
        term = next(line for line in lines if line["event"] == "target_terminated")
        self.assertEqual(term["exit_code"], 0)
        self.assertEqual(term["exit_code_hex"], "0x00000000")
        self.assertFalse(term["killed_by_us"])

    def test_exit_code_is_read_from_the_handle_retained_at_spawn_not_a_fresh_by_pid_open(self):
        # ROOT CAUSE regression guard: OpenProcess()/GetExitCodeProcess() by
        # PID from INSIDE the detach callback (i.e. after termination) loses
        # the exit code on most real runs -- Windows only keeps it
        # retrievable while a handle to the process OBJECT stays open, and a
        # recycled PID would silently return an unrelated process's exit
        # code. The fix: acquire a handle once, right after spawn (this
        # launcher's own retained-handle path, proven here by a fake
        # open_process_handle that only ever sees the PID once, at spawn
        # time), and read the exit code later from THAT SAME handle object,
        # never a fresh by-PID open at detach time.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            RETAINED_HANDLE = object()
            open_calls = []
            read_calls = []
            close_calls = []

            def fake_open(pid):
                open_calls.append(pid)
                return RETAINED_HANDLE

            def fake_read(handle):
                read_calls.append(handle)
                # Only the retained handle object yields a real exit code
                # -- anything else (e.g. a bare PID, which would prove this
                # launcher fell back to a fresh by-PID open instead of using
                # the retained handle) gets nothing, exactly like a real
                # GetExitCodeProcess call on a wrong/foreign handle would.
                return 0xC0000005 if handle is RETAINED_HANDLE else None

            def fake_close(handle):
                close_calls.append(handle)

            fake = _FakeFridaModule(device=_FakeDeviceSelfTerminating(reason="process-terminated"))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake, open_process_handle=fake_open, read_exit_code=fake_read, close_process_handle=fake_close)
        self.assertEqual(code, 0)
        # Opened exactly once, by PID, right at spawn.
        self.assertEqual(open_calls, [4242])
        # Read exactly once, from the SAME retained handle object -- not a
        # fresh open, not the bare PID.
        self.assertEqual(read_calls, [RETAINED_HANDLE])
        term = next(line for line in lines if line["event"] == "target_terminated")
        self.assertEqual(term["exit_code"], 0xC0000005)
        self.assertEqual(term["exit_code_meaning"], "STATUS_ACCESS_VIOLATION")
        # Closed exactly once, in this launcher's own teardown, same handle.
        self.assertEqual(close_calls, [RETAINED_HANDLE])

    def test_process_handle_open_failure_still_completes_the_run_with_exit_code_none(self):
        # Best-effort, non-fatal (permissions, non-Windows, PID already
        # gone by the time this launcher gets to open it): if the handle
        # cannot be acquired at spawn, the run must proceed exactly as it
        # does today -- exit_code simply stays None, nothing here aborts or
        # raises into the rest of this launcher.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule(device=_FakeDeviceSelfTerminating(reason="process-terminated"))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake,
                open_process_handle=lambda pid: None,
                read_exit_code=lambda handle: 0xDEADBEEF if handle is not None else None,
                close_process_handle=lambda handle: None,
            )
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events, ["ready", "spawned", "agent_loaded", "target_terminated", "resumed", "detached"],
        )
        term = next(line for line in lines if line["event"] == "target_terminated")
        self.assertIsNone(term["exit_code"])
        self.assertIsNone(term["exit_code_meaning"])
        self.assertFalse(term["killed_by_us"])

    def test_duration_is_clamped_not_rejected(self):
        self.assertEqual(client._clamp_duration(0.0), client.MIN_DURATION_SECONDS)
        self.assertEqual(client._clamp_duration(999999.0), client.MAX_DURATION_SECONDS)
        self.assertEqual(client._clamp_duration(10.0), 10.0)

    def test_missing_agent_file_is_a_reported_error_not_a_crash(self):
        code, lines = self._run([
            "--attach-pid", "1", "--agent", r"C:\does\not\exist.js", "--duration-seconds", "0.2",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(lines[-1]["event"], "error")
        self.assertIn("could not read --agent", lines[-1]["detail"])

    def test_bad_agent_params_is_a_reported_error_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            code, lines = self._run([
                "--attach-pid", "1", "--agent", str(agent),
                "--agent-params", "{not valid json", "--duration-seconds", "0.2",
            ])
        self.assertEqual(code, 2)
        self.assertEqual(lines[-1]["event"], "error")

    def test_mutually_exclusive_target_args_enforced_by_argparse(self):
        parser = client.build_arg_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--attach-pid", "1", "--attach-name", "x", "--agent", "a.js"])

    def test_at_least_one_target_arg_required(self):
        parser = client.build_arg_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--agent", "a.js"])

    # ------------------------------------------------------------------
    # --follow-children
    # ------------------------------------------------------------------

    def test_follow_children_off_by_default_leaves_behavior_unchanged(self):
        # A child WOULD appear (the fake fires it on the parent's own
        # resume()) even though --follow-children is never passed -- proves
        # this launcher never even looks for gated children unless asked,
        # and the emitted event stream is exactly what it always was.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, identifier="worker", path=r"C:\fake\worker.exe", argv=[r"C:\fake\worker.exe"])
            fake = _FakeFridaModule(device=_FakeDeviceChildrenAppearOnResume([child]))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(
            events, ["ready", "spawned", "agent_loaded", "resumed", "budget_exceeded", "target_killed", "detached"],
        )
        self.assertFalse(any(ev.startswith("child_") for ev in events))
        self.assertEqual(fake.device.attach_calls, [4242])
        main_session = fake.device.sessions_by_pid[4242]
        self.assertFalse(main_session.child_gating_enabled)
        self.assertEqual(main_session.child_gating_enable_calls, 0)
        # No "message" event carries source_pid when the option is off.
        self.assertTrue(all("source_pid" not in line for line in lines))

    def test_follow_children_enables_child_gating_before_parent_resumes(self):
        # The core ordering guarantee this whole mechanism exists for: a
        # child cannot slip past ungated. Proven here directly against the
        # fake main session's own enable_child_gating() call count/flag,
        # and against the moment the parent is actually resumed.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, identifier="worker")
            device = _FakeDeviceChildrenAppearOnResume([child])
            fake = _FakeFridaModule(device=device)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        # Enabled exactly once, on the MAIN TARGET'S OWN session (and,
        # since this run reached a clean teardown, disabled again there too
        # -- see the dedicated teardown test below; the flag itself is back
        # to False by the time this run has fully returned, so the call
        # COUNT is what proves gating was actually turned on during the
        # run).
        main_session = device.sessions_by_pid[4242]
        self.assertEqual(main_session.child_gating_enable_calls, 1)
        events = [line["event"] for line in lines]
        # resumed (the parent's own resume) only ever happens after gating
        # was enabled -- the fake's own child firing on that SAME resume()
        # call proves nothing could have appeared while ungated.
        self.assertIn("resumed", events)
        self.assertIn(4242, device.resumed)

    def test_follow_children_pending_child_is_reported_instrumented_and_resumed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, parent_pid=4242, identifier="worker.exe")
            fake = _FakeFridaModule(device=_FakeDeviceChildrenAppearOnResume([child]))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertIn("child_added", events)
        self.assertIn("child_instrumented", events)
        self.assertIn("child_resumed", events)
        self.assertNotIn("child_instrumentation_failed", events)
        self.assertNotIn("child_skipped_cap_reached", events)
        self.assertNotIn("child_cap_reached", events)
        # Reported, then instrumented, then resumed -- in that order, and
        # the child is NEVER left gated (it is resumed regardless).
        self.assertLess(events.index("child_added"), events.index("child_instrumented"))
        self.assertLess(events.index("child_instrumented"), events.index("child_resumed"))

        added = next(line for line in lines if line["event"] == "child_added")
        self.assertEqual(added["pid"], 5555)
        self.assertEqual(added["parent_pid"], 4242)
        self.assertEqual(added["identifier"], "worker.exe")

        resumed_child = next(line for line in lines if line["event"] == "child_resumed")
        self.assertEqual(resumed_child["pid"], 5555)

        # Child gating was enabled on the MAIN TARGET'S OWN session (and
        # disabled again at this run's own clean teardown -- see the
        # dedicated teardown test); a SEPARATE session (device.attach()
        # called again, this time for the pending child's own pid) was
        # established for it, with its OWN child gating also enabled (for
        # grandchild support -- see the dedicated grandchild test) and its
        # own script loaded, and it was resumed via device.resume(pid) --
        # the same call used for the main target.
        main_session = fake.device.sessions_by_pid[4242]
        self.assertEqual(main_session.child_gating_enable_calls, 1)
        self.assertEqual(fake.device.attach_calls, [4242, 5555])
        child_session = fake.device.sessions_by_pid[5555]
        self.assertTrue(child_session.script.loaded)
        self.assertEqual(child_session.child_gating_enable_calls, 1)
        self.assertIsNot(child_session, main_session)
        self.assertIn(5555, fake.device.resumed)
        self.assertIn(4242, fake.device.resumed)

    def test_follow_children_grandchild_is_gated_via_its_own_session(self):
        # Proves --follow-children's grandchild support falls out of
        # instrumenting every gated child the same way (each child's own
        # session also gets enable_child_gating() called on it, before it
        # is resumed) -- a grandchild spawned by an already-gated child is
        # delivered to the SAME device-level 'child-added' handler, with no
        # separate code path.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, parent_pid=4242, identifier="worker")
            grandchild = _FakeChild(pid=9999, parent_pid=5555, identifier="worker-helper")
            device = _FakeDeviceGrandchildAppearsWhenChildResumed(child, grandchild)
            fake = _FakeFridaModule(device=device)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(sum(1 for e in events if e == "child_added"), 2)
        self.assertEqual(sum(1 for e in events if e == "child_instrumented"), 2)
        added_pids = {line["pid"] for line in lines if line["event"] == "child_added"}
        self.assertEqual(added_pids, {5555, 9999})
        instrumented_pids = {line["pid"] for line in lines if line["event"] == "child_instrumented"}
        self.assertEqual(instrumented_pids, {5555, 9999})
        # Every level -- main target, child, grandchild -- got its own
        # session gated and resumed.
        for pid in (4242, 5555, 9999):
            self.assertEqual(fake.device.sessions_by_pid[pid].child_gating_enable_calls, 1)
            self.assertIn(pid, fake.device.resumed)
        self.assertEqual(fake.device.attach_calls, [4242, 5555, 9999])

    def test_follow_children_message_records_are_attributed_by_source_pid(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, identifier="worker")
            fake = _FakeFridaModule(device=_FakeDeviceChildrenAppearOnResume([child]))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--agent-params", '{"exports": ["Foo"]}',
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        message_lines = [line for line in lines if line["event"] == "message"]
        source_pids = {line["source_pid"] for line in message_lines}
        # One "message" (the params echo, see _FakeScript.post) from the
        # main target's own script AND one from the gated child's own
        # script -- never conflated, each tagged with the process it
        # actually came from.
        self.assertEqual(source_pids, {4242, 5555})

    def test_follow_children_cap_is_enforced_with_an_explicit_marker(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            children = [
                _FakeChild(pid=6001, identifier="w1"),
                _FakeChild(pid=6002, identifier="w2"),
                _FakeChild(pid=6003, identifier="w3"),
            ]
            fake = _FakeFridaModule(device=_FakeDeviceChildrenAppearOnResume(children))
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--max-children", "1", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        # Every pending child is reported as having appeared, regardless of
        # the cap.
        self.assertEqual(sum(1 for e in events if e == "child_added"), 3)
        # Only the first is actually instrumented.
        self.assertEqual(sum(1 for e in events if e == "child_instrumented"), 1)
        # The cap marker fires exactly once, not once per skipped child.
        cap_events = [line for line in lines if line["event"] == "child_cap_reached"]
        self.assertEqual(len(cap_events), 1)
        self.assertEqual(cap_events[0]["max_children"], 1)
        # The two skipped children are each still individually named.
        skipped = [line["pid"] for line in lines if line["event"] == "child_skipped_cap_reached"]
        self.assertEqual(sorted(skipped), [6002, 6003])
        # No gated child is ever left hanging -- all three are resumed.
        self.assertEqual(sorted(pid for pid in fake.device.resumed if pid != 4242), [6001, 6002, 6003])
        # Only the instrumented one was ever attach()-ed.
        self.assertEqual(fake.device.attach_calls, [4242, 6001])

    def test_follow_children_instrumentation_failure_is_reported_and_child_still_resumed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=7777, identifier="broken")
            device = _FakeDeviceChildrenAppearOnResume([child])
            device.attach_should_fail_for.add(7777)
            fake = _FakeFridaModule(device=device)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertIn("child_added", events)
        self.assertIn("child_instrumentation_failed", events)
        self.assertNotIn("child_instrumented", events)
        # Never left gated -- resumed despite the instrumentation failure.
        self.assertIn("child_resumed", events)
        failed = next(line for line in lines if line["event"] == "child_instrumentation_failed")
        self.assertEqual(failed["pid"], 7777)
        self.assertIn("fake attach() failure", failed["detail"])
        self.assertIn(7777, fake.device.resumed)

    def test_follow_children_slow_but_successful_init_is_reported_instrumented_not_failed(self):
        # FALSE-FAILURE FIX (2026-09-16, three live runs, see dataset/
        # evidence/project_mayhem_bypass_20260916.json session_7): every
        # run reported a gated child's own init() as having failed to
        # return within the bound, yet that SAME child's breakpoints went
        # on to attach and fire afterward. The bound (INIT_TIMEOUT_SECONDS)
        # was simply too tight for a freshly-gated child -- CHILD_INIT_
        # TIMEOUT_SECONDS (derived from it, see its own docstring) fixes
        # this: a child whose init() takes longer than INIT_TIMEOUT_SECONDS
        # but still finishes within CHILD_INIT_TIMEOUT_SECONDS must be
        # reported as instrumented, never as failed.
        old_init = client.INIT_TIMEOUT_SECONDS
        old_child_init = client.CHILD_INIT_TIMEOUT_SECONDS
        client.INIT_TIMEOUT_SECONDS = 0.05
        client.CHILD_INIT_TIMEOUT_SECONDS = 0.3
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                agent = _write_temp_agent(Path(tmp))
                child = _FakeChild(pid=8888, identifier="slow-worker")
                # Sleeps 0.15s -- longer than the main target's own (now
                # patched-small) INIT_TIMEOUT_SECONDS, but well inside
                # CHILD_INIT_TIMEOUT_SECONDS.
                script_cls = _make_first_fast_rest_slow_script_cls(0.15)
                device = _FakeDeviceChildrenAppearOnResume([child], script_cls=script_cls)
                fake = _FakeFridaModule(device=device)
                code, lines = self._run([
                    "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                    "--agent-params", '{"x": 1}',
                    "--follow-children", "--duration-seconds", "1.0",
                ], frida_module=fake)
        finally:
            client.INIT_TIMEOUT_SECONDS = old_init
            client.CHILD_INIT_TIMEOUT_SECONDS = old_child_init
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertIn("child_instrumented", events)
        self.assertIn("child_agent_params_sent", events)
        self.assertNotIn("child_instrumentation_failed", events)
        instrumented = next(line for line in lines if line["event"] == "child_instrumented")
        self.assertEqual(instrumented["pid"], 8888)
        self.assertIn(8888, fake.device.resumed)

    def test_follow_children_genuinely_hung_init_is_still_reported_failed(self):
        # Companion regression guard: raising CHILD_INIT_TIMEOUT_SECONDS
        # must never turn a REAL failure into a silent success -- a child
        # whose init() never returns at all is still reported failed (and
        # still resumed, never left gated), once CHILD_INIT_TIMEOUT_SECONDS
        # itself has genuinely elapsed.
        old_init = client.INIT_TIMEOUT_SECONDS
        old_child_init = client.CHILD_INIT_TIMEOUT_SECONDS
        client.INIT_TIMEOUT_SECONDS = 0.05
        client.CHILD_INIT_TIMEOUT_SECONDS = 0.1
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                agent = _write_temp_agent(Path(tmp))
                child = _FakeChild(pid=9090, identifier="hung-worker")
                script_cls = _make_first_fast_rest_hang_script_cls()
                device = _FakeDeviceChildrenAppearOnResume([child], script_cls=script_cls)
                fake = _FakeFridaModule(device=device)
                code, lines = self._run([
                    "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                    "--agent-params", '{"x": 1}',
                    "--follow-children", "--duration-seconds", "1.0",
                ], frida_module=fake)
        finally:
            client.INIT_TIMEOUT_SECONDS = old_init
            client.CHILD_INIT_TIMEOUT_SECONDS = old_child_init
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertIn("child_instrumentation_failed", events)
        self.assertNotIn("child_instrumented", events)
        self.assertIn("child_resumed", events)
        failed = next(line for line in lines if line["event"] == "child_instrumentation_failed")
        self.assertEqual(failed["pid"], 9090)
        self.assertIn("did not return within", failed["detail"])
        self.assertIn(9090, fake.device.resumed)

    def test_follow_children_hung_init_message_reports_bound_actually_used_not_main_target_bound(self):
        # Regression guard for a fixed message that contradicted the code
        # (2026-09-16, live-measured): a gated child's own init() timeout
        # message must report CHILD_INIT_TIMEOUT_SECONDS -- the bound that
        # actually governed the join() call just above it -- never
        # INIT_TIMEOUT_SECONDS (the main target's own, unrelated bound).
        # Patches the two constants to visibly DIFFERENT values (0.05s vs.
        # 0.4s, an 8x gap no rounding/formatting quirk could paper over) so
        # this test would fail loudly if the message ever again quoted the
        # wrong one.
        old_init = client.INIT_TIMEOUT_SECONDS
        old_child_init = client.CHILD_INIT_TIMEOUT_SECONDS
        client.INIT_TIMEOUT_SECONDS = 0.05
        client.CHILD_INIT_TIMEOUT_SECONDS = 0.4
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                agent = _write_temp_agent(Path(tmp))
                child = _FakeChild(pid=9191, identifier="hung-worker-2")
                script_cls = _make_first_fast_rest_hang_script_cls()
                device = _FakeDeviceChildrenAppearOnResume([child], script_cls=script_cls)
                fake = _FakeFridaModule(device=device)
                code, lines = self._run([
                    "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                    "--agent-params", '{"x": 1}',
                    "--follow-children", "--duration-seconds", "1.0",
                ], frida_module=fake)
        finally:
            client.INIT_TIMEOUT_SECONDS = old_init
            client.CHILD_INIT_TIMEOUT_SECONDS = old_child_init
        self.assertEqual(code, 0)
        failed = next(line for line in lines if line["event"] == "child_instrumentation_failed")
        self.assertEqual(failed["pid"], 9191)
        # Reports the CHILD bound that actually applied (0.4s) ...
        self.assertIn("within 0.4s", failed["detail"])
        # ... and never the main target's own, different bound (0.05s) --
        # the exact shape of the fixed-message-contradicts-the-code defect.
        self.assertNotIn("within 0.05s", failed["detail"])

    def test_follow_children_enable_child_gating_failure_is_reported_exit_code_6(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            device = _FakeDeviceChildGatingUnsupported()
            fake = _FakeFridaModule(device=device)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 6)
        self.assertEqual(lines[-1]["event"], "error")
        self.assertIn("enable_child_gating", lines[-1]["detail"])
        # MEASURED bug this closes: a build that does not support session
        # child gating on this OS must never leave the already-spawned-
        # suspended main target hanging -- it is resumed and killed here,
        # best-effort, rather than exiting in a way that breaks the run.
        self.assertIn(4242, device.resumed)
        self.assertIn(4242, device.killed)

    def test_follow_children_disables_child_gating_on_clean_teardown(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            child = _FakeChild(pid=5555, identifier="worker")
            device = _FakeDeviceChildrenAppearOnResume([child])
            fake = _FakeFridaModule(device=device)
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent),
                "--follow-children", "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        # Enabled once, disabled once, and left disabled -- the guest must
        # never be left with the main target's own session gating turned on
        # after a run ends.
        main_session = device.sessions_by_pid[4242]
        self.assertEqual(main_session.child_gating_enable_calls, 1)
        self.assertEqual(main_session.child_gating_disable_calls, 1)
        self.assertFalse(main_session.child_gating_enabled)

    def test_child_gating_not_disabled_when_never_enabled(self):
        # --follow-children OFF -- child gating is never touched at all,
        # not even disable_child_gating() as a harmless no-op call.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--spawn", r"C:\fake\target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        main_session = fake.device.sessions_by_pid[4242]
        self.assertEqual(main_session.child_gating_enable_calls, 0)
        self.assertEqual(main_session.child_gating_disable_calls, 0)

    def test_max_children_is_clamped_not_rejected(self):
        self.assertEqual(client._clamp_max_children(0), client.MIN_MAX_CHILDREN)
        self.assertEqual(client._clamp_max_children(999999), client.MAX_MAX_CHILDREN)
        self.assertEqual(client._clamp_max_children(4), 4)

    # ------------------------------------------------------------------
    # --attach-name ambiguity
    # ------------------------------------------------------------------

    def test_attach_name_unique_match_attaches_by_resolved_pid(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            fake.device.processes = [_FakeProcess(pid=321, name="target.exe")]
            code, lines = self._run([
                "--attach-name", "target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        events = [line["event"] for line in lines]
        self.assertEqual(events, ["ready", "attached", "agent_loaded", "budget_exceeded", "detached"])
        attached = next(line for line in lines if line["event"] == "attached")
        self.assertEqual(attached["pid"], 321)
        self.assertEqual(fake.device.attach_calls, [321])

    def test_attach_name_with_no_enumerated_match_falls_back_to_direct_attach(self):
        # enumerate_processes() found nothing matching (e.g. a build whose
        # naming differs slightly from this launcher's own comparison) --
        # falls back to the same device.attach(name) call this launcher
        # always made, rather than refusing something it cannot actually
        # prove is ambiguous.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            code, lines = self._run([
                "--attach-name", "target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        attached = next(line for line in lines if line["event"] == "attached")
        self.assertEqual(attached["pid"], 4242)  # _FakeDevice.attach() default pid for a non-int target
        self.assertEqual(fake.device.attach_calls, [4242])

    def test_attach_name_ambiguous_match_is_refused_with_candidates_never_guessed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            fake.device.processes = [
                _FakeProcess(pid=321, name="target.exe"),
                _FakeProcess(pid=999, name="target.exe"),
            ]
            code, lines = self._run([
                "--attach-name", "target.exe", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 7)
        self.assertEqual(lines[-1]["event"], "error")
        self.assertIn("matched 2 running processes", lines[-1]["detail"])
        candidates = lines[-1]["candidates"]
        self.assertEqual(sorted(c["pid"] for c in candidates), [321, 999])
        # Never resolved silently -- device.attach() must never have been
        # called at all for this ambiguous name.
        self.assertEqual(fake.device.attach_calls, [])

    def test_attach_pid_is_never_subject_to_ambiguity_resolution(self):
        # --attach-pid stays exact even when enumerate_processes() would
        # report multiple processes sharing some name -- the ambiguity
        # check only ever applies to --attach-name.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            agent = _write_temp_agent(Path(tmp))
            fake = _FakeFridaModule()
            fake.device.processes = [
                _FakeProcess(pid=321, name="target.exe"),
                _FakeProcess(pid=999, name="target.exe"),
            ]
            code, lines = self._run([
                "--attach-pid", "321", "--agent", str(agent), "--duration-seconds", "0.2",
            ], frida_module=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.device.attach_calls, [321])


if __name__ == "__main__":
    unittest.main()
