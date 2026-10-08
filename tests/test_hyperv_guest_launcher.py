"""`liebert_re.dynamic.hyperv_guest_launcher`: the real GuestLauncher over PowerShell Direct, with a fake runner.

No VM, no Hyper-V, no PowerShell Direct: the transport's process runner is injected (the same
``FakePS`` the transport tests use), and a ``FakeGuest`` answers as a faithful guest agent would, so
every ordering, bound, mismatch and cleanup rule is driven without a guest. What the tests can and
cannot show:

* They pin the host-side rules (what is sent in which order, what is refused before any guest call,
  how a reply is validated, how ``debugger_run`` maps the outcome) against a SIMULATED agent.
* They pin the text of the two constant scripts: the flags that matter are set, ``ResumeThread`` sits
  behind the job verification, the cmdlet lists are short, nothing from the host leaks into them.
* On a Windows host with ``powershell.exe`` they parse both scripts and compile the C# class, and
  compare the P/Invoke struct sizes with the documented x64 sizes. That compiles code and starts
  nothing: no target, no job object, no process is created.
* They do NOT show that the agent works in a real guest. The one live test is marked ``heavy`` and
  skips unless ``LIEBERT_LIVE_GUEST_RUN=1``, a guest is named in the environment and the lab gate says
  VERIFIED. Nothing here has been run against a real guest.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from liebert_re.bounded_subprocess import BoundedProcessResult
from liebert_re.dynamic import hyperv_guest_launcher as hvl
from liebert_re.dynamic import hyperv_transport as hvt_module
from liebert_re.dynamic.debugger_run import DebuggerRun
from liebert_re.dynamic.hyperv_guest_launcher import HypervGuestLauncher
from liebert_re.dynamic.hyperv_transport import HypervTransport
from tests import test_debugger_run as tdr
from tests import test_hyperv_transport as hvt

contract = pytest.mark.contract

VM = "Test VM"
GUEST_PATH = tdr.GUEST_PATH
STEP_PHASES = ["decode", "credential", "vm", "session", "session_open", "agent_call"]
CREATE_PHASES = ["decode", "credential", "vm", "session", "session_open", "agent_start", "agent_call"]


# --------------------------------------------------------------------------------- the fake guest


class LauncherPS(hvt.FakePS):
    """``FakePS`` that also keeps the other files the runner put next to the script."""

    def __init__(self, handler):
        super().__init__(handler)
        self.siblings: list[dict[str, str]] = []

    def __call__(self, argv, timeout):
        folder = Path(argv[argv.index("-File") + 1]).parent
        self.siblings.append({p.name: p.read_text(encoding="ascii") for p in folder.iterdir()})
        return super().__call__(argv, timeout)


def result_line(op, ok, phase, data=None, failure=None, schema=None):
    return "LIEBERT_RESULT " + json.dumps({
        "schema": schema or hvl._RESULT_SCHEMA, "op": op, "ok": ok, "phase": phase,
        "failure": failure, "data": {} if data is None else data,
    })


def step_proc(script_op, reply_text, **flags):
    phases = ["LIEBERT_PHASE " + p for p in (CREATE_PHASES if script_op == "agent_create" else STEP_PHASES)]
    data = {"vm_state": "Running", "reply": reply_text}
    return hvt.proc(phases + [result_line(script_op, True, "agent_call", data)], **flags)


class Raw:
    """A reply override that is sent as the exact agent text."""

    def __init__(self, text):
        self.text = text


class FakeGuest:
    """A faithful guest agent, as a FakePS handler. ``faults[op]`` is a function from the good reply to
    a bad one, a ``Raw`` text, or a ``BoundedProcessResult`` that replaces the whole PowerShell run."""

    def __init__(self, **faults):
        self.faults = faults
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.pid = 4242
        self.in_job = True
        self.limits_applied = True
        self.exited = True
        self.exit_code = 0
        self.stdout = b"hello\n"
        self.stderr = b""
        self.total_extra = 0
        self.terminated = True
        self.on_wait = None

    def good(self, areq):
        op, run_id = areq["op"], areq["run_id"]
        base = {"schema": hvl._AGENT_SCHEMA, "op": op, "ok": True, "run_id": run_id, "pid": self.pid}
        if op == "create":
            return {**base, "suspended": True}
        if op == "assign":
            return {**base, "assigned": True}
        if op == "verify":
            return {**base, "in_job": self.in_job, "limits_applied": self.limits_applied}
        if op == "resume":
            return {**base, "resumed": True, "previous_suspend_count": 1}
        if op == "wait":
            if self.on_wait is not None:
                self.on_wait()
            return {**base, "exited": self.exited, "exit_code": self.exit_code if self.exited else None}
        if op == "terminate":
            return {**base, "terminated": self.terminated}
        data = (self.stdout + self.stderr)[: areq["max_bytes"]]
        return {**base, "total_bytes": len(self.stdout) + len(self.stderr) + self.total_extra,
                "kept_bytes": len(data), "stdout_total": len(self.stdout) + self.total_extra,
                "stderr_total": len(self.stderr), "data_b64": base64.b64encode(data).decode("ascii")}

    def __call__(self, req, argv):
        areq = json.loads(req["agent_request_json"])
        self.requests.append((req["op"], areq))
        reply = self.good(areq)
        fault = self.faults.get(areq["op"])
        if isinstance(fault, BoundedProcessResult):
            return fault
        if isinstance(fault, Raw):
            return step_proc(req["op"], fault.text)
        if callable(fault):
            reply = fault(reply)
        return step_proc(req["op"], json.dumps(reply) + "\n")

    def ops(self):
        return [a["op"] for _, a in self.requests]


@pytest.fixture
def cred(tmp_path):
    return str(tmp_path / "guest.cred")


def build(cred, guest=None, **kw):
    guest = guest or FakeGuest()
    fake = LauncherPS(guest)
    transport = HypervTransport(cred, runner=fake, powershell="powershell.exe")
    return HypervGuestLauncher(transport, **kw), guest, fake


def started(cred, guest=None, **kw):
    launcher, guest, fake = build(cred, guest, **kw)
    created = launcher.create_suspended(VM, GUEST_PATH)
    assert created["ok"] is True, created
    return launcher, guest, fake, created["run_id"]


def advance(launcher, run_id, upto):
    """Drive a created run through the steps up to and including ``upto``."""
    steps = [
        ("assign", lambda: launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})),
        ("verify", lambda: launcher.verify_job_assignment(VM, run_id)),
        ("resume", lambda: launcher.resume(VM, run_id)),
        ("wait", lambda: launcher.wait(VM, run_id, 5.0)),
        ("terminate", lambda: launcher.terminate_job(VM, run_id)),
    ]
    out = None
    for name, call in steps:
        out = call()
        assert out["ok"] is True, (name, out)
        if name == upto:
            return out
    raise AssertionError(upto)


# --------------------------------------------------------------------------------- the PowerShell Direct plumbing


def test_launcher_uses_transport_psdirect_configuration(cred):
    launcher, guest, fake, run_id = started(cred, step_timeout_s=33.0)
    first = fake.calls[0]
    argv = first["argv"]
    assert argv[0] == "powershell.exe"                        # the transport's executable
    assert argv[1:6] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
    assert Path(first["script_path"]).name == "launcher.ps1"
    assert first["script_text"] == hvl._HOST_SCRIPT           # the script is the constant
    assert first["request"]["credential_path"] == cred        # the transport's credential file
    assert first["request"]["vm"] == VM and first["request"]["op"] == "agent_create"
    assert first["timeout"] == 66.0                           # create gets twice the step bound
    assert fake.siblings[0]["agent.ps1"] == hvl._AGENT_SCRIPT
    wire = hvl._wire_bytes(hvl._AGENT_SCRIPT)
    assert first["request"]["agent_sha256"] == hashlib.sha256(wire).hexdigest() == hvl._agent_sha256()
    launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
    second = fake.calls[1]
    assert second["request"]["op"] == "agent_step" and second["timeout"] == 33.0
    assert "agent.ps1" not in fake.siblings[1]                # only the first call carries the agent
    assert "target_path" not in second["request"]
    # the credential path is never echoed, and the object does not print it
    assert cred not in repr(launcher) and "REDACTED" in repr(launcher)
    assert cred not in json.dumps(launcher.verify_job_assignment(VM, run_id))
    # the default step bound follows the transport's probe timeout, with a floor
    default, _, _ = build(cred)
    assert default._step_timeout_s == max(HypervTransport(cred)._probe_timeout_s, 120.0)


def test_launcher_requires_a_real_transport_and_sane_options(cred):
    with pytest.raises(TypeError):
        HypervGuestLauncher(object())  # type: ignore[arg-type]
    transport = HypervTransport(cred)
    for bad in (0, -1, float("nan"), float("inf"), True, "5", 3601):
        with pytest.raises(ValueError):
            HypervGuestLauncher(transport, step_timeout_s=bad)  # type: ignore[arg-type]
    for bad in (9, 3601, True, 30.0):
        with pytest.raises(ValueError):
            HypervGuestLauncher(transport, idle_seconds=bad)  # type: ignore[arg-type]


def test_values_travel_as_data_and_never_change_the_script_or_the_command_line(cred):
    launcher, guest, fake = build(cred)
    for hostile in hvt.HOSTILE:
        launcher.create_suspended(hostile, GUEST_PATH)
        launcher.create_suspended(VM, "C:\\Lab\\in\\" + hostile.replace("\\", "_").replace("/", "_") + ".exe")
    assert fake.calls                                          # at least the printable hostile names went through
    for call in fake.calls:
        assert call["script_text"] == hvl._HOST_SCRIPT
        assert call["argv"][-2] == "-RequestB64" and re.fullmatch(r"[A-Za-z0-9+/=]+", call["blob"])
        assert len(call["argv"]) == 9


def test_the_default_runner_is_given_room_for_the_largest_reply(cred, monkeypatch):
    seen = []

    def stub(argv, seconds, max_chars=0):
        seen.append(max_chars)
        return BoundedProcessResult(1, "", "")

    monkeypatch.setattr(hvt_module, "_default_runner", stub)
    transport = HypervTransport(cred, powershell="powershell.exe")
    launcher = HypervGuestLauncher(transport)
    run = hvl._Run(VM)
    run.pid, run.state = 7, "terminated"
    launcher._runs["abc"] = run
    assert launcher.collect_output(VM, "abc", hvl.MAX_OUTPUT_CAP)["ok"] is False
    big = seen[-1]
    assert big >= 4 * (hvl.MAX_OUTPUT_CAP // 3) + 4096         # base64 of the whole cap fits
    run.state = "created"
    launcher.assign_to_job(VM, "abc", {"memory_bytes": 1 << 20})
    assert seen[-1] == hvl._NORMAL_REPLY_CHARS + hvl._RESULT_OVERHEAD_CHARS < big
    assert big < 4_000_000                                       # and the room is bounded


# --------------------------------------------------------------------------------- malformed and mismatched replies


def _swap(**changes):
    return lambda reply: {**reply, **changes}


def _drop(key):
    return lambda reply: {k: v for k, v in reply.items() if k != key}


BAD_REPLIES = {
    "wrong_run_id": _swap(run_id="other-run"),
    "wrong_pid": _swap(pid=1),
    "pid_as_text": _swap(pid="4242"),
    "pid_as_bool": _swap(pid=True),
    "pid_as_float": _swap(pid=4242.0),
    "zero_pid": _swap(pid=0),
    "wrong_op": _swap(op="resume"),
    "wrong_schema": _swap(schema="liebert-re.guest-agent/2"),
    "extra_key": _swap(surprise=1),
    "missing_ok": _drop("ok"),
    "ok_as_text": _swap(ok="true"),
    "missing_run_id": _drop("run_id"),
    "failure_without_code": _swap(ok=False),
    "failure_with_bad_code": _swap(ok=False, code="not a code", win32_error=None),
    "raw_empty": Raw(""),
    "raw_not_json": Raw("not json\n"),
    "raw_list": Raw("[1, 2]\n"),
    "raw_nan": Raw('{"pid": NaN}\n'),
    "raw_infinity": Raw('{"pid": -Infinity}\n'),
    "raw_overflowing_number": Raw('{"pid": 1e999}\n'),
    "raw_deep_nesting": Raw("[" * 2000 + "]" * 2000 + "\n"),
    "raw_duplicate_key": Raw('{"schema":"liebert-re.guest-agent/1","schema":"x"}\n'),
    "raw_two_lines": Raw('{"a":1}\n{"b":2}\n'),
    "raw_non_ascii": Raw('{"a":"\u00e9"}\n'),
    "raw_huge": Raw(" " * 9000 + "{}\n"),
}


@pytest.mark.parametrize("name", sorted(BAD_REPLIES))
def test_launcher_rejects_malformed_or_mismatched_reply(cred, name):
    fault = BAD_REPLIES[name]
    for op, call in (("create", lambda l, r: l.create_suspended(VM, GUEST_PATH)),
                     ("assign", lambda l, r: l.assign_to_job(VM, r, {"memory_bytes": 1 << 28})),
                     ("verify", lambda l, r: l.verify_job_assignment(VM, r))):
        if op == "create" and name == "wrong_pid":
            continue                  # the first reply is where the pid is learned: another valid pid is just the pid
        launcher, guest, fake = build(cred, FakeGuest(**{op: fault}))
        run_id = None
        if op != "create":
            run_id = launcher.create_suspended(VM, GUEST_PATH)["run_id"]
            if op == "verify":
                launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
        reply = call(launcher, run_id)
        assert reply["ok"] is False, (op, name, reply)
        assert re.fullmatch(r"[A-Z][A-Z0-9_]+", reply["reason"]), reply
        json.dumps(reply)


@pytest.mark.parametrize("text,reason", [
    ('{"schema":"liebert-re.guest-agent/1","schema":"x"}', "AGENT_REPLY_DUPLICATE_KEY"),
    ('{"a":{"b":1,"b":2}}', "AGENT_REPLY_DUPLICATE_KEY"),
    ('{"pid": NaN}', "AGENT_REPLY_NOT_JSON"),
    ('{"pid": Infinity}', "AGENT_REPLY_NOT_JSON"),
    ('{"pid": 1e999}', "AGENT_REPLY_NOT_JSON"),
    ("[" * 2000 + "]" * 2000, "AGENT_REPLY_NOT_JSON"),
    ("{not json", "AGENT_REPLY_NOT_JSON"),
])
def test_agent_replies_are_read_through_strict_json_with_the_reason_it_gives(text, reason):
    assert hvl._parse_agent_reply(text, "create", "run", None, 4096) == (None, reason)


def test_the_launcher_imports_only_names_the_transport_still_has_and_reads_json_strictly():
    import ast

    source = Path(hvl.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = [alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
              and node.module == "liebert_re.dynamic.hyperv_transport" for alias in node.names]
    assert wanted and all(hasattr(hvt_module, name) for name in wanted), wanted
    assert "json.loads(" not in source.replace("strict_json.loads(", "")      # no lenient reader
    assert "strict_json.loads(" in source
    for gone in ("_DuplicateKey", "_no_duplicates", "_refuse_constant"):
        assert gone not in source and not hasattr(hvt_module, gone), gone     # the helpers moved to strict_json


def test_a_valid_failure_reply_is_a_refusal_with_the_agents_code(cred):
    launcher, guest, fake, run_id = started(cred, FakeGuest(assign=lambda r: {
        k: r[k] for k in ("schema", "op", "run_id")} | {"ok": False, "code": "ASSIGN_FAILED", "win32_error": 5}))
    reply = launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
    assert reply["ok"] is False and reply["reason"] == "AGENT_ASSIGN_FAILED" and reply["win32_error"] == 5


@pytest.mark.parametrize("problem", [
    "no_result", "two_results", "bad_schema", "wrong_op", "exit_contradicts", "timed_out", "truncated",
    "launch_failed", "extra_data_key", "vm_not_running", "not_a_string",
])
def test_script_level_problems_are_refusals_never_a_pass(cred, problem):
    launcher, guest, fake, run_id = started(cred)

    def broken(req, argv):
        good = step_proc("agent_step", json.dumps(guest.good(json.loads(req["agent_request_json"]))) + "\n")
        lines = good.stdout.splitlines()
        result = json.loads(lines[-1][len("LIEBERT_RESULT "):])
        if problem == "no_result":
            return hvt.proc(lines[:-1])
        if problem == "two_results":
            return hvt.proc(lines + [lines[-1]])
        if problem == "bad_schema":
            result["schema"] = "liebert-re.hyperv-transport-result/1"
        if problem == "wrong_op":
            result["op"] = "agent_create"
        if problem == "extra_data_key":
            result["data"]["extra"] = 1
        if problem == "vm_not_running":
            result["data"]["vm_state"] = "Off"
        if problem == "not_a_string":
            result["data"]["reply"] = {"pid": 4242}
        out = lines[:-1] + ["LIEBERT_RESULT " + json.dumps(result)]
        flags = {"timed_out": {"timed_out": True}, "truncated": {"output_truncated": True},
                 "launch_failed": {"launch_failed": True}}.get(problem, {})
        return hvt.proc(out, returncode=1 if problem == "exit_contradicts" else 0, **flags)

    fake.handler = broken
    reply = launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
    assert reply["ok"] is False and re.fullmatch(r"[A-Z][A-Z0-9_]+", reply["reason"]), reply


def test_a_guest_script_failure_keeps_a_fixed_code_and_no_free_text(cred):
    launcher, guest, fake = build(cred)
    fail = {"code": "TARGET_MISSING", "category": "InvalidOperation", "error_id": None,
            "exception_type": "InvalidOperationException", "auth_hint": False, "timeout_hint": False}
    fake.handler = lambda req, argv: hvt.proc(
        ["LIEBERT_PHASE " + p for p in CREATE_PHASES[:6]]
        + [result_line("agent_create", False, "agent_start", failure=fail)], returncode=1)
    reply = launcher.create_suspended(VM, GUEST_PATH)
    reply = launcher.create_suspended(VM, GUEST_PATH)
    assert reply["ok"] is False and reply["reason"] == "TARGET_MISSING"
    assert "run_id" not in reply and launcher._runs == {}      # failed before the request was sent: nothing exists
    fail["code"] = "not a fixed code with D:\\hostmark in it"
    reply = launcher.create_suspended(VM, GUEST_PATH)
    assert reply["ok"] is False and "hostmark" not in json.dumps(reply)


@pytest.mark.parametrize("name,makes_run_id", [
    ("never_launched", False), ("failed_before_the_request", False), ("agent_not_reachable", False),
    ("agent_said_create_failed", False), ("timeout_after_the_request", True), ("garbled_reply", True),
    ("no_result_after_session_opened", True), ("reply_timeout", True),
])
def test_a_create_failure_names_the_run_only_when_a_process_may_exist(cred, name, makes_run_id):
    launcher, guest, fake = build(cred)
    open_phases = ["LIEBERT_PHASE " + p for p in CREATE_PHASES]

    def fail_in(phase, code=None, upto=None):
        fail = {"code": code, "category": None, "error_id": None, "exception_type": None,
                "auth_hint": False, "timeout_hint": False}
        shown = CREATE_PHASES[: CREATE_PHASES.index(upto or phase) + 1]
        return hvt.proc(["LIEBERT_PHASE " + p for p in shown]
                        + [result_line("agent_create", False, phase, failure=fail)], returncode=1)

    handlers = {
        "never_launched": lambda req, argv: BoundedProcessResult(-1, "", "", launch_failed=True),
        "failed_before_the_request": lambda req, argv: fail_in("session", "VM_NOT_RUNNING"),
        "agent_not_reachable": lambda req, argv: fail_in("agent_call", "AGENT_NOT_REACHABLE"),
        "agent_said_create_failed": lambda req, argv: step_proc("agent_create", json.dumps({
            "schema": hvl._AGENT_SCHEMA, "op": "create", "ok": False, "run_id": json.loads(req["agent_request_json"])["run_id"],
            "code": "CREATE_PROCESS_FAILED", "win32_error": 193}) + "\n"),
        "timeout_after_the_request": lambda req, argv: hvt.proc(open_phases, returncode=1, timed_out=True),
        "garbled_reply": lambda req, argv: step_proc("agent_create", "garbled\n"),
        "no_result_after_session_opened": lambda req, argv: hvt.proc(open_phases, returncode=1),
        "reply_timeout": lambda req, argv: fail_in("agent_call", "AGENT_REPLY_TIMEOUT"),
    }
    fake.handler = handlers[name]
    reply = launcher.create_suspended(VM, GUEST_PATH)
    assert reply["ok"] is False
    assert ("run_id" in reply) is makes_run_id, reply
    assert (len(launcher._runs) == 1) is makes_run_id


# --------------------------------------------------------------------------------- order


def test_launcher_orders_suspend_assign_verify_resume(cred):
    launcher, guest, fake, run_id = started(cred)
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id)
    advance(launcher, run_id, "terminate")
    collected = launcher.collect_output(VM, run_id, 64)
    assert collected["ok"] is True and collected["data"] == b"hello\n" and collected["total_bytes"] == 6
    assert guest.ops() == ["create", "assign", "verify", "resume", "wait", "terminate", "collect"]
    assert [op for op, _ in guest.requests] == ["agent_create"] + ["agent_step"] * 6
    # every request names this run; nothing else travels
    assert all(a["run_id"] == run_id for _, a in guest.requests)
    assert guest.requests[1][1] == {"op": "assign", "run_id": run_id, "memory_bytes": 1 << 28}
    # a finished run is forgotten
    assert launcher.terminate_job(VM, run_id) == {"ok": False, "reason": "RUN_UNKNOWN"}


def test_steps_out_of_order_are_refused_before_any_guest_call(cred):
    launcher, guest, fake = build(cred)
    unknown = [
        launcher.assign_to_job(VM, "abc", {"memory_bytes": 1}), launcher.verify_job_assignment(VM, "abc"),
        launcher.resume(VM, "abc"), launcher.wait(VM, "abc", 1.0), launcher.terminate_job(VM, "abc"),
        launcher.collect_output(VM, "abc", 1),
    ]
    assert all(r == {"ok": False, "reason": "RUN_UNKNOWN"} for r in unknown) and fake.calls == []
    run_id = launcher.create_suspended(VM, GUEST_PATH)["run_id"]
    sent = len(fake.calls)
    for call in (lambda: launcher.verify_job_assignment(VM, run_id), lambda: launcher.resume(VM, run_id),
                 lambda: launcher.wait(VM, run_id, 1.0), lambda: launcher.collect_output(VM, run_id, 8)):
        assert call()["reason"] == "STEP_OUT_OF_ORDER"
    assert len(fake.calls) == sent and guest.ops() == ["create"]           # nothing out of order reached the guest
    launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
    sent = len(fake.calls)
    assert launcher.resume(VM, run_id)["reason"] == "STEP_OUT_OF_ORDER"       # assigned but not verified
    assert launcher.assign_to_job(VM, run_id, {"memory_bytes": 1})["reason"] == "STEP_OUT_OF_ORDER"
    assert launcher.collect_output(VM, run_id, 8)["reason"] == "STEP_OUT_OF_ORDER"
    assert len(fake.calls) == sent
    assert launcher.assign_to_job("Other VM", run_id, {"memory_bytes": 1})["reason"] == "VM_MISMATCH"
    for bad in ("", "a b", "../x", "x" * 65, None, 5):
        assert launcher.terminate_job(VM, bad)["reason"] == "RUN_UNKNOWN"          # type: ignore[arg-type]
    assert len(fake.calls) == sent


def test_resume_is_never_sent_unless_the_last_verify_said_in_job_and_limits_applied(cred):
    for field in ("in_job", "limits_applied"):
        guest = FakeGuest()
        setattr(guest, field, False)
        launcher, guest, fake, run_id = started(cred, guest)
        launcher.assign_to_job(VM, run_id, {"memory_bytes": 1 << 28})
        verified = launcher.verify_job_assignment(VM, run_id)
        assert verified["ok"] is True and verified[field] is False             # reported as is
        assert launcher.resume(VM, run_id)["reason"] == "STEP_OUT_OF_ORDER"
        assert "resume" not in guest.ops()
        setattr(guest, field, True)                                            # a later verify may succeed
        assert launcher.verify_job_assignment(VM, run_id)["ok"] is True
        assert launcher.resume(VM, run_id)["ok"] is True


def test_assign_checks_its_limits_before_the_guest_is_asked(cred):
    launcher, guest, fake, run_id = started(cred)
    sent = len(fake.calls)
    for bad in (None, {}, {"memory_bytes": 0}, {"memory_bytes": -1}, {"memory_bytes": True},
                {"memory_bytes": 1.5}, {"memory_bytes": "1"}, {"memory_bytes": hvl.MAX_MEMORY_BYTES + 1}, [], "x"):
        assert launcher.assign_to_job(VM, run_id, bad)["reason"] == "MEMORY_LIMIT_OUT_OF_RANGE"   # type: ignore[arg-type]
    assert len(fake.calls) == sent


def test_create_checks_its_arguments_before_the_guest_is_asked(cred):
    launcher, guest, fake = build(cred)
    for vm, path in (("", GUEST_PATH), (None, GUEST_PATH), (VM, ""), (VM, None), (VM, "relative\\x.exe"),
                     (VM, "C:\\Lab\\..\\x.exe"), (VM, "C:\\Lab\\a:b.exe"), (VM, "C:\\Lab\\\"q\".exe"),
                     (VM, "\\\\host\\share\\x.exe"), (VM, "C:\\Lab\\" + "a" * 300)):
        reply = launcher.create_suspended(vm, path)       # type: ignore[arg-type]
        assert reply["ok"] is False and re.fullmatch(r"[A-Z][A-Z0-9_]+", reply["reason"]) and "run_id" not in reply
    assert fake.calls == [] and launcher._runs == {}


def test_a_create_whose_reply_is_lost_still_carries_the_run_id_so_it_can_be_terminated(cred):
    guest = FakeGuest(create=Raw("garbage\n"))
    launcher, guest, fake = build(cred, guest)
    reply = launcher.create_suspended(VM, GUEST_PATH)
    assert reply["ok"] is False and re.fullmatch(r"[0-9a-f]{16}", reply["run_id"])
    guest.faults.clear()
    done = launcher.terminate_job(VM, reply["run_id"])
    assert done["ok"] is True and done["terminated"] is True and guest.ops() == ["create", "terminate"]


def test_in_flight_runs_are_bounded(cred):
    launcher, guest, fake = build(cred)
    for _ in range(hvl.MAX_TRACKED_RUNS):
        assert launcher.create_suspended(VM, GUEST_PATH)["ok"] is True
    sent = len(fake.calls)
    assert launcher.create_suspended(VM, GUEST_PATH)["reason"] == "TOO_MANY_RUNS_IN_FLIGHT"
    assert len(fake.calls) == sent
    oldest = next(iter(launcher._runs))
    assert launcher.terminate_job(VM, oldest)["ok"] is True
    assert launcher.create_suspended(VM, GUEST_PATH)["ok"] is True       # a terminated run's slot is reusable


# --------------------------------------------------------------------------------- wait and output bounds


def test_launcher_bounds_wait_and_output(cred):
    launcher, guest, fake, run_id = started(cred, step_timeout_s=40.0)
    advance(launcher, run_id, "resume")
    sent = len(fake.calls)
    for bad in (0, -1, float("nan"), float("inf"), hvl.MAX_TIMEOUT_S + 1, True, "5", None):
        assert launcher.wait(VM, run_id, bad)["reason"] == "TIMEOUT_OUT_OF_RANGE"        # type: ignore[arg-type]
    assert len(fake.calls) == sent
    waited = launcher.wait(VM, run_id, 12.5)
    assert waited == {"ok": True, "run_id": run_id, "pid": 4242, "exited": True, "exit_code": 0}
    request = fake.calls[-1]["request"]
    assert json.loads(request["agent_request_json"])["timeout_ms"] == 12500
    assert request["reply_timeout_ms"] == int((12.5 + 15) * 1000)
    assert fake.calls[-1]["timeout"] == 40.0 + 12.5 + 15          # the host call outlives the guest wait
    assert launcher.terminate_job(VM, run_id)["ok"] is True
    sent = len(fake.calls)
    for bad in (0, -1, hvl.MAX_OUTPUT_CAP + 1, True, 1.5, "8", None):
        assert launcher.collect_output(VM, run_id, bad)["reason"] == "OUTPUT_CAP_OUT_OF_RANGE"   # type: ignore[arg-type]
    assert len(fake.calls) == sent
    out = launcher.collect_output(VM, run_id, 3)
    assert out["data"] == b"hel" and out["total_bytes"] == 6 and out["stdout_total"] == 6
    asked = json.loads(fake.calls[-1]["request"]["agent_request_json"])
    assert asked["max_bytes"] == 3 and fake.calls[-1]["request"]["max_reply_chars"] == 4 * 1 + 4096


def test_the_deadline_wait_that_did_not_exit_has_no_exit_code(cred):
    guest = FakeGuest()
    guest.exited = False
    launcher, guest, fake, run_id = started(cred, guest)
    advance(launcher, run_id, "resume")
    waited = launcher.wait(VM, run_id, 1.0)
    assert waited["ok"] is True and waited["exited"] is False and waited["exit_code"] is None


@pytest.mark.parametrize("name,fault", [
    ("more_than_asked", lambda r: {**r, "data_b64": base64.b64encode(b"x" * 100).decode(), "kept_bytes": 100}),
    ("kept_count_wrong", lambda r: {**r, "kept_bytes": 5}),
    ("total_below_kept", lambda r: {**r, "total_bytes": 1, "stdout_total": 1}),
    ("total_not_sum", lambda r: {**r, "total_bytes": 99}),
    ("not_base64", lambda r: {**r, "data_b64": "***"}),
    ("negative_count", lambda r: {**r, "stdout_total": -1}),
    ("count_as_float", lambda r: {**r, "stderr_total": 0.0}),
    ("too_large", lambda r: {**r, "data_b64": "A" * 20000}),
])
def test_output_replies_that_do_not_add_up_are_refused(cred, name, fault):
    launcher, guest, fake, run_id = started(cred, FakeGuest(collect=fault))
    advance(launcher, run_id, "terminate")
    reply = launcher.collect_output(VM, run_id, 8)
    assert reply["ok"] is False and "data" not in reply, (name, reply)


def test_output_beyond_the_cap_is_reported_as_total_not_as_data(cred):
    guest = FakeGuest()
    guest.stdout, guest.stderr, guest.total_extra = b"a" * 20, b"b" * 20, 1000
    launcher, guest, fake, run_id = started(cred, guest)
    advance(launcher, run_id, "terminate")
    out = launcher.collect_output(VM, run_id, 16)
    assert out["ok"] is True and len(out["data"]) == 16 and out["total_bytes"] == 1040


# --------------------------------------------------------------------------------- termination


def test_launcher_terminates_and_confirms_job(cred):
    launcher, guest, fake, run_id = started(cred)
    advance(launcher, run_id, "resume")
    done = launcher.terminate_job(VM, run_id)
    assert done == {"ok": True, "run_id": run_id, "pid": 4242, "terminated": True}
    again = launcher.terminate_job(VM, run_id)                    # idempotent, still confirmed by the guest
    assert again["ok"] is True and again["terminated"] is True


def test_a_termination_the_agent_does_not_confirm_is_not_ok_and_is_not_retried(cred):
    guest = FakeGuest()
    guest.terminated = False
    launcher, guest, fake, run_id = started(cred, guest)
    advance(launcher, run_id, "resume")
    sent = len(fake.calls)
    reply = launcher.terminate_job(VM, run_id)
    assert reply["ok"] is False and reply["terminated"] is False and reply["reason"] == "AGENT_TERMINATION_NOT_CONFIRMED"
    assert len(fake.calls) == sent + 1
    assert launcher.collect_output(VM, run_id, 8)["reason"] == "STEP_OUT_OF_ORDER"   # output is not final


def test_a_failed_terminate_call_is_tried_twice(cred):
    calls = {"n": 0}
    launcher, guest, fake, run_id = started(cred)
    advance(launcher, run_id, "resume")
    good = fake.handler

    def handler(req, argv):
        areq = json.loads(req["agent_request_json"])
        if areq["op"] == "terminate":
            calls["n"] += 1
            if calls["n"] == 1:
                return hvt.proc([], returncode=1)                  # no result at all
        return good(req, argv)

    fake.handler = handler
    reply = launcher.terminate_job(VM, run_id)
    assert reply["ok"] is True and calls["n"] == 2
    fresh, g2, f2, rid2 = started(cred)
    advance(fresh, rid2, "resume")
    f2.handler = lambda req, argv: hvt.proc([], returncode=1)
    before = len(f2.calls)
    failed = fresh.terminate_job(VM, rid2)
    assert failed["ok"] is False and "terminated" not in failed and len(f2.calls) == before + 2


def test_a_termination_reply_about_another_process_is_not_a_confirmation(cred):
    launcher, guest, fake, run_id = started(cred, FakeGuest(terminate=_swap(pid=1)))
    advance(launcher, run_id, "resume")
    assert launcher.terminate_job(VM, run_id)["ok"] is False


# --------------------------------------------------------------------------------- through debugger_run


def run_debugger(cred, guest, **over):
    calls = tdr.Calls()
    launcher, guest, fake = build(cred, guest)
    clock = over.pop("clock", None)
    extra = {} if clock is None else {"clock": clock}
    runner = DebuggerRun(tdr.FakeTransport(calls), launcher, gate=lambda op, **kw: tdr.good_decision(), **extra)
    result = runner.run(VM, "host-sample.bin", tdr.SHA, tdr.GUEST_DIR, timeout_s=over.pop("timeout_s", 5.0),
                        output_cap_bytes=over.pop("cap", 64), **over)
    return result, guest, fake


def test_a_clean_run_is_completed_and_the_order_is_the_orchestrators(cred):
    result, guest, fake = run_debugger(cred, FakeGuest())
    assert result["status"] == "COMPLETED" and result["exit_code"] == 0, result
    assert guest.ops() == ["create", "assign", "verify", "resume", "wait", "terminate", "collect"]
    assert result["job"] == {"assignment_confirmed": True, "terminated": True}
    assert base64.b64decode(result["output"]["data_b64"]) == b"hello\n"
    text = json.dumps(result)
    assert cred not in text and "powershell" not in text.lower()


@pytest.mark.parametrize("field", ["in_job", "limits_applied"])
def test_unverified_assignment_is_job_assignment_unconfirmed_and_never_resumed(cred, field):
    guest = FakeGuest()
    setattr(guest, field, False)
    result, guest, fake = run_debugger(cred, guest)
    assert result["status"] == "JOB_ASSIGNMENT_UNCONFIRMED"
    assert "resume" not in guest.ops() and guest.ops()[-1] == "terminate"


def test_a_failed_assignment_is_job_assignment_unconfirmed(cred):
    failure = lambda r: {k: r[k] for k in ("schema", "op", "run_id")} | {"ok": False, "code": "ASSIGN_FAILED", "win32_error": 5}  # noqa: E731
    result, guest, fake = run_debugger(cred, FakeGuest(assign=failure))
    assert result["status"] == "JOB_ASSIGNMENT_UNCONFIRMED" and "resume" not in guest.ops()


def _guest_that_spends(clock, seconds, **state):
    """A guest whose ``wait`` takes ``seconds`` of the orchestrator's clock."""
    guest = FakeGuest()
    for key, value in state.items():
        setattr(guest, key, value)
    guest.on_wait = lambda: setattr(clock, "now", clock.now + seconds)
    return guest


def test_a_deadline_that_passes_is_timed_out(cred):
    clock = tdr.FakeClock()
    guest = _guest_that_spends(clock, 6.0, exited=False)          # the run was given 5 s
    result, guest, fake = run_debugger(cred, guest, clock=clock, timeout_s=5.0)
    assert clock.now == 1006.0                                    # the deadline really passed on the clock
    assert result["status"] == "TIMED_OUT" and result["reason"] == "DEADLINE_REACHED_BEFORE_EXIT"
    assert guest.ops()[-2:] == ["terminate", "collect"]


def test_a_success_reply_that_comes_after_the_deadline_is_not_a_completion(cred):
    clock = tdr.FakeClock()
    guest = _guest_that_spends(clock, 6.0)                        # exited, code 0, but only after 6 s of a 5 s run
    result, guest, fake = run_debugger(cred, guest, clock=clock, timeout_s=5.0)
    assert result["status"] == "TIMED_OUT" and result["reason"] == "EXIT_NOT_PROVEN_WITHIN_DEADLINE"
    assert guest.ops()[-2:] == ["terminate", "collect"]


def test_the_same_reply_inside_the_deadline_is_a_completion(cred):
    clock = tdr.FakeClock()
    guest = _guest_that_spends(clock, 4.0)                        # control: only the time differs
    result, guest, fake = run_debugger(cred, guest, clock=clock, timeout_s=5.0)
    assert result["status"] == "COMPLETED" and result["exit_code"] == 0


def test_output_beyond_the_cap_is_output_truncated(cred):
    guest = FakeGuest()
    guest.stdout = b"x" * 200
    result, guest, fake = run_debugger(cred, guest, cap=64)
    assert result["status"] == "OUTPUT_TRUNCATED" and result["output"]["bytes_kept"] == 64
    assert result["output"]["total_bytes"] == 200


def test_cleanup_outranks_every_other_status(cred):
    guest = FakeGuest()
    guest.terminated = False
    result, guest, fake = run_debugger(cred, guest)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "JOB_TERMINATION_NOT_CONFIRMED"
    # the run itself finished; the unfinal output (refused while the job is not confirmed gone) is the cause kept
    assert result["primary_status"] == "TRANSPORT_ERROR" and result["primary_reason"] == "OUTPUT_REPLY_INVALID"
    assert result["job"]["terminated"] is False


def test_invalid_replies_and_failed_steps_are_transport_errors(cred):
    for faults, reason in (({"wait": _swap(pid=9)}, "WAIT_REPLY_INVALID"),
                           ({"resume": Raw("nope\n")}, "RESUME_NOT_CONFIRMED"),
                           ({"collect": _swap(total_bytes=-1)}, "OUTPUT_REPLY_INVALID")):
        result, guest, fake = run_debugger(cred, FakeGuest(**faults))
        assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == reason, (faults, result["reason"])
        assert guest.ops()[-1] in ("terminate", "collect") and "terminate" in guest.ops()


def test_a_lost_create_reply_is_still_followed_by_a_terminate(cred):
    result, guest, fake = run_debugger(cred, FakeGuest(create=Raw("garbage\n")))
    assert result["status"] == "TRANSPORT_ERROR"
    assert guest.ops() == ["create", "terminate"]


# --------------------------------------------------------------------------------- the constant scripts


def _code(text):
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _csharp():
    src = hvl._AGENT_SCRIPT
    start = src.index("$source = @'\n") + len("$source = @'\n")
    return src[start: src.index("\n'@\n", start)]


def _method(text, signature):
    """The body of the C# method whose declaration contains ``signature`` (brace matching)."""
    at = text.index(signature)
    open_at = text.index("{", at)
    depth = 0
    for i in range(open_at, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[open_at: i + 1]
    raise AssertionError(signature)


HOST_ALLOWED = frozenset({
    "Import-Clixml", "Get-VM", "Where-Object", "New-PSSession", "Remove-PSSession", "Invoke-Command",
    "New-Object", "ConvertTo-Json", "ConvertFrom-Json", "Join-Path", "Invoke-CimMethod",
})
AGENT_ALLOWED = frozenset({"Add-Type", "New-Object", "Join-Path", "ConvertTo-Json", "ConvertFrom-Json"})
FORBIDDEN = (
    "Restore-VMSnapshot", "Checkpoint-VM", "Stop-VM", "Start-VM", "Restart-VM", "Suspend-VM", "Save-VM", "Set-VM",
    "Remove-VM", "Remove-VMSnapshot", "Import-VM", "Export-VM", "Connect-VMNetworkAdapter",
    "Disconnect-VMNetworkAdapter", "Start-Process", "Invoke-Expression", "Enter-PSSession", "Invoke-WebRequest",
    "Invoke-RestMethod", "Set-NetFirewallRule", "New-NetFirewallRule", "Set-MpPreference", "Disable-",
)


@contract
def test_both_scripts_are_ascii_constants_with_stable_hashes():
    for text in (hvl._HOST_SCRIPT, hvl._AGENT_SCRIPT):
        assert text.isascii() and "\r" not in text
    assert hvl._host_script_sha256() == hashlib.sha256(hvl._HOST_SCRIPT.encode("ascii")).hexdigest()
    assert hvl._wire_bytes("a\nb\r\nc") == b"a\r\nb\r\nc"
    assert hvl._agent_sha256() == hashlib.sha256(hvl._AGENT_SCRIPT.replace("\n", "\r\n").encode("ascii")).hexdigest()


@contract
def test_the_host_script_uses_a_short_cmdlet_list_and_nothing_that_touches_vm_state():
    used = set(re.findall(r"\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b", _code(hvl._HOST_SCRIPT)))
    assert used <= HOST_ALLOWED, sorted(used - HOST_ALLOWED)
    for name in FORBIDDEN:
        assert name.lower() not in _code(hvl._HOST_SCRIPT).lower(), name
    assert not re.search(r"snapshot|checkpoint|\biex\b|-EncodedCommand|\.Invoke\(|\[scriptblock\]::Create",
                         _code(hvl._HOST_SCRIPT), re.IGNORECASE)
    assert "Add-Type" not in hvl._HOST_SCRIPT                     # nothing is compiled by the host script
    assert "Start-Process" not in hvl._HOST_SCRIPT


@contract
def test_the_agent_script_uses_a_short_cmdlet_list_and_has_no_network_or_vm_state_calls():
    body = _code(hvl._AGENT_SCRIPT)
    ps_only = body[: body.index("$source = @'")] + body[body.index("\n'@\n") :]
    used = set(re.findall(r"\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b", ps_only))
    assert used <= AGENT_ALLOWED, sorted(used - AGENT_ALLOWED)
    for name in FORBIDDEN:
        assert name.lower() not in body.lower(), name
    assert not re.search(r"System\.Net|Sockets|WebClient|DownloadString|HttpClient|\biex\b|Invoke-Command",
                         body, re.IGNORECASE)
    assert not re.search(r"snapshot|checkpoint|HVCI|Memory Integrity|Core Isolation", body, re.IGNORECASE)


@contract
def test_here_strings_cannot_be_ended_early():
    agent_lines = hvl._AGENT_SCRIPT.split("\n")
    assert [ln for ln in agent_lines if ln.startswith("'@")] == ["'@"]
    assert sum(1 for ln in agent_lines if ln.rstrip().endswith("@'")) == 1
    assert "@'" not in hvl._HOST_SCRIPT and "'@" not in hvl._HOST_SCRIPT


@contract
def test_the_process_is_created_suspended_and_the_job_kills_on_close():
    cs = _csharp()
    assert re.search(r"CREATE_SUSPENDED\s*=\s*0x00000004;", cs)
    create = _method(cs, "public static LrRun Create(")
    call = create[create.index("CreateProcessW("): create.index(";", create.index("CreateProcessW("))]
    assert "CREATE_SUSPENDED" in call and ", true," in call.replace("IntPtr.Zero, IntPtr.Zero", "")  # inherits the pipes
    assert re.search(r"JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE\s*=\s*0x00002000;", cs)
    wanted = re.search(r"WantedFlags\s*=([^;]+);", cs).group(1)
    for flag in ("KILL_ON_JOB_CLOSE", "ACTIVE_PROCESS", "PROCESS_MEMORY", "JOB_MEMORY", "JOB_TIME"):
        assert f"JOB_OBJECT_LIMIT_{flag}" in wanted, flag
    assert "BREAKAWAY" not in wanted
    forbidden = re.search(r"ForbiddenFlags\s*=([^;]+);", cs).group(1)
    assert "BREAKAWAY_OK" in forbidden and "SILENT_BREAKAWAY_OK" in forbidden
    assign = _method(cs, "public void AssignToJob(")
    assert "info.BasicLimitInformation.LimitFlags = WantedFlags;" in assign
    assert assign.index("SetInformationJobObject(_job, 9") < assign.index("AssignProcessToJobObject(")
    for const, value in (("ACTIVE_PROCESS", "0x00000008"), ("PROCESS_MEMORY", "0x00000100"),
                         ("JOB_MEMORY", "0x00000200"), ("JOB_TIME", "0x00000004")):
        assert re.search(rf"JOB_OBJECT_LIMIT_{const}\s*=\s*{value};", cs), const


@contract
def test_resume_thread_comes_only_after_the_job_assignment_is_verified_again():
    cs = _csharp()
    assert len(re.findall(r"\bResumeThread\(", cs)) == 2          # the import and the single call
    resume = _method(cs, "public int Resume(")
    assert resume.index("Verify();") < resume.index("InJob && LimitsApplied") < resume.index("ResumeThread(")
    assert "NOT_VERIFIED_AT_RESUME" in resume
    verify = _method(cs, "public void Verify(")
    assert verify.index("IsProcessInJob(") < verify.index("QueryInformationJobObject(_job, 3") \
        < verify.index("QueryInformationJobObject(_job, 9")
    assert "InJob = member && listed;" in verify
    for needle in ("ActiveProcessLimit", "PerJobUserTimeLimit", "ProcessMemoryLimit", "JobMemoryLimit", "ForbiddenFlags"):
        assert needle in verify, needle
    agent = hvl._AGENT_SCRIPT
    handler = agent[agent.index("if ($op -ceq 'resume')"): agent.index("if ($op -ceq 'wait')")]
    assert "-cne 'verified'" in handler and handler.index("Fail 'BAD_STATE'") < handler.index(".Resume()")


@contract
def test_termination_kills_the_job_and_the_process_and_confirms_both():
    terminate = _method(_csharp(), "public bool Terminate(")
    order = [terminate.index(n) for n in ("TerminateJobObject(", "TerminateProcess(", "WaitForSingleObject(",
                                           "ActiveProcesses()")]
    assert order == sorted(order)
    assert "return false" in terminate and "return true" in terminate
    wait = _method(_csharp(), "public bool WaitExit(")
    assert "GetExitCodeProcess" in wait and "0x102" in wait


@contract
def test_output_is_pumped_into_capped_files_and_counted():
    cs = _csharp()
    loop = _method(cs, "private void Loop(")
    assert "room = _cap - " in loop and "_total" in loop and "_kept" in loop
    assert "FileMode.CreateNew" in cs                              # an existing output file is never reused
    agent = hvl._AGENT_SCRIPT
    assert "OUTPUT_NOT_FINAL" in agent and "OUTPUT_PUMP_FAILED" in agent
    assert agent.index("NOT_TERMINATED") < agent.index(".FinishPumps(")


@contract
def test_the_struct_layout_is_checked_by_the_agent_itself_before_it_starts_anything():
    cs = _csharp()
    ok = _method(cs, "public static bool LayoutOk(")
    for size in ("== 104", "== 24", "== 64", "== 144", "== 48"):
        assert size in ok, size
    assert "IntPtr.Size == 8" in ok
    assert hvl._AGENT_SCRIPT.index("LayoutOk()") < hvl._AGENT_SCRIPT.index("[LrRun]::Create(")


@contract
def test_the_agent_serves_one_user_and_idles_out():
    agent = hvl._AGENT_SCRIPT
    assert "PipeAccessRule" in agent and "WindowsIdentity]::GetCurrent().User" in agent
    assert "NamedPipeServerStream" in agent and ", 1, [System.IO.Pipes.PipeTransmissionMode]" in agent
    assert "WaitOne($script:IdleMs)" in agent and "$script:Run.Terminate()" in agent
    assert re.search(r"\$script:State -cne 'new'.*?\n.*?LayoutOk", agent, re.DOTALL)
    assert "-cnotin @('create', 'assign', 'verify', 'resume', 'wait', 'terminate', 'collect')" in agent


@contract
def test_no_host_identity_or_path_is_in_the_scripts_or_the_module():
    source = Path(hvl.__file__).read_text(encoding="utf-8")
    for text in (hvl._HOST_SCRIPT, hvl._AGENT_SCRIPT):
        assert not re.search(r"[A-Za-z]:\\+Users\\|/home/|\\\\Users\\", text)
    assert not re.search(r"os\.environ|getenv|putenv", source)    # no environment, no default location
    assert "run_bounded_process" not in source                    # the runner is the transport's
    assert "subprocess" not in source


@contract
def test_the_module_adds_no_public_top_level_function_and_the_transport_contract_stands():
    public = [n for n in hvl.__all__]
    assert public == ["SCHEMA", "HypervGuestLauncher"]
    transport_source = Path(hvt_module.__file__).read_text(encoding="utf-8")
    assert "never starts a target" in transport_source
    assert "CreateProcess" not in hvt_module._SCRIPT and "Add-Type" not in hvt_module._SCRIPT
    for name in ("create_suspended", "assign_to_job", "verify_job_assignment", "resume", "wait", "terminate_job",
                 "collect_output"):
        assert callable(getattr(HypervGuestLauncher, name))
        assert not hasattr(HypervTransport, name)


# --------------------------------------------------------------------------------- local parse and compile only


def _powershell():
    return shutil.which("powershell.exe") if sys.platform == "win32" else None


_PARSE = (
    "param([string]$Dir); "
    "foreach ($n in 'agent.ps1','launcher.ps1') { "
    "$e = $null; $t = $null; "
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $Dir $n), [ref]$t, [ref]$e); "
    "'FILE:' + $n + ':ERRORS:' + $e.Count; "
    "foreach ($x in $e) { 'ERROR:' + $n + ':' + $x.Extent.StartLineNumber + ':' + $x.Message }; "
    "$cmds = $ast.FindAll({ param($q) $q -is [System.Management.Automation.Language.CommandAst] }, $true); "
    "foreach ($c in $cmds) { $name = $c.GetCommandName(); if ($null -eq $name) { 'CMD:' + $n + ':<DYNAMIC>' } else { 'CMD:' + $n + ':' + $name } } }"
)


def _write_scripts(folder: Path) -> None:
    (folder / "agent.ps1").write_text(hvl._AGENT_SCRIPT, encoding="ascii", newline="\r\n")
    (folder / "launcher.ps1").write_text(hvl._HOST_SCRIPT, encoding="ascii", newline="\r\n")


def test_both_scripts_parse_and_call_only_the_listed_commands(tmp_path):
    shell = _powershell()
    if shell is None:
        pytest.skip("powershell.exe is not available: the parse check cannot run here")
    folder = tmp_path / "scripts"
    folder.mkdir()
    _write_scripts(folder)
    driver = tmp_path / "parse.ps1"
    driver.write_text(_PARSE, encoding="ascii")
    done = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver),
                           "-Dir", str(folder)], capture_output=True, text=True, timeout=180, check=False)
    assert done.returncode == 0, done.stderr[:300]
    lines = [ln.strip() for ln in done.stdout.splitlines() if ln.strip()]
    assert "FILE:agent.ps1:ERRORS:0" in lines and "FILE:launcher.ps1:ERRORS:0" in lines, lines[:10]
    for script, allowed, own in (
        ("launcher.ps1", HOST_ALLOWED, {"Say", "Mark", "Fail", "AsciiJson", "ErrInfo", "Emit"}),
        ("agent.ps1", AGENT_ALLOWED, {"ToJson", "Fail", "CodeOf", "OkReply", "RunOp", "Dispatch", "ReadRequest"}),
    ):
        names = {ln.split(":", 2)[2] for ln in lines if ln.startswith(f"CMD:{script}:")}
        assert "<DYNAMIC>" not in names, "a command with no static name"
        assert names <= allowed | own | {"New-Object"}, sorted(names - allowed - own)
        assert len(names) > 5


_COMPILE = (
    "param([string]$Source); "
    "$text = [System.IO.File]::ReadAllText($Source); "
    "Add-Type -TypeDefinition $text -Language CSharp; "
    "'LAYOUT:' + [LrRun]::LayoutReport(); 'LAYOUTOK:' + [LrRun]::LayoutOk()"
)


def test_the_csharp_compiles_and_its_struct_sizes_match_the_documented_x64_layout(tmp_path):
    shell = _powershell()
    if shell is None:
        pytest.skip("powershell.exe is not available: the compile check cannot run here")
    if not sys.maxsize > 2 ** 32:
        pytest.skip("a 64-bit host is needed: the agent itself refuses anything else")
    source = tmp_path / "native.cs"
    source.write_text(_csharp(), encoding="ascii")
    driver = tmp_path / "compile.ps1"
    driver.write_text(_COMPILE, encoding="ascii")
    done = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver),
                           "-Source", str(source)], capture_output=True, text=True, timeout=300, check=False)
    lines = [ln.strip() for ln in done.stdout.splitlines() if ln.strip()]
    assert done.returncode == 0 and any(ln.startswith("LAYOUT:") for ln in lines), (done.stdout[-600:], done.stderr[-600:])
    report = dict(item.split("=") for item in next(ln for ln in lines if ln.startswith("LAYOUT:"))[len("LAYOUT:"):].split(";"))
    assert report == {"STARTUPINFO": "104", "PROCESS_INFORMATION": "24", "JOBOBJECT_BASIC_LIMIT_INFORMATION": "64",
                      "JOBOBJECT_EXTENDED_LIMIT_INFORMATION": "144", "JOBOBJECT_BASIC_ACCOUNTING_INFORMATION": "48",
                      "SECURITY_ATTRIBUTES": "24", "IntPtr": "8"}
    assert "LAYOUTOK:True" in lines


# --------------------------------------------------------------------------------- real Hyper-V (skipped by default)


@pytest.mark.heavy
def test_real_guest_run_of_a_benign_host_binary(tmp_path):
    """Needs `LIEBERT_LIVE_GUEST_RUN=1`, a running lab guest (LIEBERT_HV_VM, LIEBERT_HV_CRED,
    LIEBERT_HV_GUEST_DIR), a JSON object of lab-gate arguments in LIEBERT_LIVE_GUEST_RUN_GATE_ARGS, and a
    gate that says VERIFIED. Pushes a copy of a small Windows system binary and runs it under the job.
    Nothing in this repository has ever run this test."""
    if os.environ.get("LIEBERT_LIVE_GUEST_RUN") != "1":
        pytest.skip("LIEBERT_LIVE_GUEST_RUN=1 is required")
    vm, credential, guest_dir = (os.environ.get(k) for k in ("LIEBERT_HV_VM", "LIEBERT_HV_CRED", "LIEBERT_HV_GUEST_DIR"))
    if not (vm and credential and guest_dir) or shutil.which("powershell.exe") is None:
        pytest.skip("LIEBERT_HV_VM, LIEBERT_HV_CRED, LIEBERT_HV_GUEST_DIR and powershell.exe are required")
    from liebert_re.dynamic.lab_gate import LabGate

    try:
        gate_args = json.loads(os.environ.get("LIEBERT_LIVE_GUEST_RUN_GATE_ARGS", "{}"))
    except ValueError:
        pytest.skip("LIEBERT_LIVE_GUEST_RUN_GATE_ARGS is not a JSON object")
    sample = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "whoami.exe"
    if not sample.is_file() or not isinstance(gate_args, dict):
        pytest.skip("the benign sample or the gate arguments are missing")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    decision = LabGate.check("debugger_run", **{**gate_args, "sample_sha256": digest})
    if not DebuggerRun.admitted(decision):
        pytest.skip("the lab gate does not say VERIFIED for debugger_run: no guest run is attempted")
    transport = HypervTransport(credential)
    result = DebuggerRun(transport, HypervGuestLauncher(transport)).run(
        vm, str(sample), digest, guest_dir, gate_args={**gate_args, "sample_sha256": digest}, timeout_s=60.0)
    assert result["status"] == "COMPLETED", result
