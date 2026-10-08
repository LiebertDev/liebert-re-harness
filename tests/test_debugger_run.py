"""`liebert_re.dynamic.debugger_run`: gate-first, bounded guest run, orchestration only.

No VM, no Hyper-V, no PowerShell: the launcher is a fake that records every call in order, the
transport is either a fake or the real `HypervTransport` over the hyperv test suite's fake runner,
and the gate is a function returning a canned decision (plus one test of the real gate refusing
with no measurement). There is no live test: the guest-side launcher does not exist yet, so there
is nothing real to run, and this file does not pretend otherwise.

What is pinned: nothing touches the guest before a gate decision that proves a VERIFIED isolated
guest; the process is never resumed before the job assignment is verified; every missing or
malformed confirmation is a non-COMPLETED status; output over the cap is OUTPUT_TRUNCATED with the
kept bytes marked; no host path or user name is in a result.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from liebert_re.dynamic import debugger_run as dr
from liebert_re.dynamic import lab_gate as lg
from liebert_re.dynamic.debugger_run import STATUSES, DebuggerRun
from liebert_re.dynamic.hyperv_transport import ERROR_CLASSES, HypervTransport
from tests import test_hyperv_transport as hvt

VM = "Test VM"
SAMPLE = b"MZ liebert debugger_run sample\n"
SHA = hashlib.sha256(SAMPLE).hexdigest()
GUEST_DIR = "C:\\Lab\\in"
GUEST_PATH = GUEST_DIR + "\\sample.bin"


IDENT = {"run_id": "run-1", "pid": 4321}


def good_decision() -> dict[str, Any]:
    return {"ok": True, "decision": "ALLOW", "status": "GATE_PASSED", "operation": dr.OPERATION,
            "isolation_verified": True, "error": None,
            "isolation": {"verified": True, "attestation": {"verdict": "VERIFIED", "reasons": []}},
            "environment": {"user": "hostmark_user", "home": "D:\\hostmark"},
            "target": {"image": "D:\\hostmark\\x.exe"}}


class Calls:
    """One ordered log shared by the fake gate, transport and launcher."""

    def __init__(self) -> None:
        self.log: list[str] = []

    def names(self, prefix: str = "") -> list[str]:
        return [c for c in self.log if c.startswith(prefix)]


class FakeTransport:
    def __init__(self, calls: Calls, reply=None, raises: bool = False) -> None:
        self.calls, self.raises = calls, raises
        self.reply = reply if reply is not None else {
            "ok": True, "status": "OK", "error_class": None, "reason": None,
            "measured": {"host_sha256": SHA, "guest_sha256": SHA, "guest_path": GUEST_PATH, "hashes_equal": True}}

    def push_file(self, vm, host_path, guest_dir):
        self.calls.log.append("push_file")
        if self.raises:
            raise RuntimeError("D:\\hostmark\\secret")
        return self.reply


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeLauncher:
    def __init__(self, calls: Calls, **over: Any) -> None:
        self.calls, self.over, self.seen_limits = calls, over, None
        self.output = over.pop("output", (b"hello\n", 6))
        self.clock, self.advance_in_wait = over.pop("clock", None), over.pop("advance_in_wait", 0.0)

    def _do(self, name: str, default: Any) -> Any:
        self.calls.log.append(name)
        reply = self.over.get(name, default)
        if isinstance(reply, Exception):
            raise reply
        return reply

    def create_suspended(self, vm, guest_path):
        return self._do("create_suspended", {"ok": True, **IDENT, "suspended": True})

    def assign_to_job(self, vm, run_id, limits):
        self.seen_limits = dict(limits)
        return self._do("assign_to_job", {"ok": True, **IDENT})

    def verify_job_assignment(self, vm, run_id):
        return self._do("verify_job_assignment", {"ok": True, **IDENT, "in_job": True, "limits_applied": True})

    def resume(self, vm, run_id):
        return self._do("resume", {"ok": True, **IDENT, "resumed": True})

    def wait(self, vm, run_id, timeout_s):
        self.waited_for = timeout_s
        if self.clock is not None:
            self.clock.now += self.advance_in_wait
        return self._do("wait", {"ok": True, **IDENT, "exited": True, "exit_code": 0})

    def terminate_job(self, vm, run_id):
        return self._do("terminate_job", {"ok": True, **IDENT, "terminated": True})

    def collect_output(self, vm, run_id, max_bytes):
        self.cap_seen = max_bytes
        data, total = self.output
        return self._do("collect_output", {"ok": True, **IDENT, "data": data, "total_bytes": total})


_UNSET = object()


def build(decision=_UNSET, *, transport_reply=None, transport_raises=False, gate_raises=False, **launcher_over):
    calls = Calls()

    def gate(operation, **kwargs):
        calls.log.append("gate")
        calls.gate_args = (operation, kwargs)
        if gate_raises:
            raise RuntimeError("gate blew up at D:\\hostmark")
        return good_decision() if decision is _UNSET else decision

    transport = FakeTransport(calls, transport_reply, transport_raises)
    clock = launcher_over.get("clock")
    extra = {"clock": clock} if clock is not None else {}
    return DebuggerRun(transport, FakeLauncher(calls, **launcher_over), gate=gate, **extra), calls


def go(runner, **kw):
    return runner.run(VM, "D:\\hostmark\\work\\sample.bin", SHA, GUEST_DIR, **kw)


# ------------------------------------------------------------------ the operation is registered


def test_debugger_run_is_in_the_gate_needs_isolation_set():
    assert "debugger_run" in lg.NEEDS_ISOLATION
    assert dr.OPERATION == "debugger_run" and "debugger_run" not in lg.OBSERVE_OWNED


def test_the_real_gate_refuses_debugger_run_without_a_measurement():
    decision = lg.LabGate.check(dr.OPERATION)
    assert decision["ok"] is False and decision["status"] == "ISOLATION_REQUIRED"
    calls = Calls()
    runner = DebuggerRun(FakeTransport(calls), FakeLauncher(calls))  # default gate: LabGate.check
    result = go(runner)
    assert result["status"] == "REFUSED" and result["gate"]["status"] == "ISOLATION_REQUIRED"
    assert calls.log == []


# ------------------------------------------------------------------ refusal before any guest call


def _decision(**changes):
    d = good_decision()
    for key, value in changes.items():
        d[key] = value
    return d


def _no_verdict():
    d = good_decision()
    d["isolation"]["attestation"] = {"reasons": []}
    return d


def _verdict(value):
    d = good_decision()
    d["isolation"]["attestation"]["verdict"] = value
    return d


@pytest.mark.parametrize("decision", [
    _verdict("UNKNOWN"), _verdict("FAILED"), _verdict("verified"), _verdict(["VERIFIED"]), _verdict(True),
    _no_verdict(),
    _decision(isolation={"verified": True, "attestation": None}),
    _decision(isolation={"verified": True}),
    _decision(isolation=None),
    _decision(ok=1), _decision(ok="yes"), _decision(ok=False),
    _decision(isolation_verified=1), _decision(isolation_verified="true"), _decision(isolation_verified=False),
    _decision(isolation={"verified": 1, "attestation": {"verdict": "VERIFIED"}}),
    _decision(isolation={"verified": "VERIFIED", "attestation": {"verdict": "VERIFIED"}}),
    _decision(status="ISOLATION_REQUIRED"), _decision(status=None), _decision(decision="REFUSE"),
    _decision(operation="pe_sieve_scan"), _decision(operation=None),
    {}, None, [], "ok", 1, True,
])
def test_refuses_before_transport_unless_isolation_verified(decision):
    runner, calls = build(decision)
    result = go(runner)
    assert result["status"] == "REFUSED" and result["ok"] is False
    assert calls.log == ["gate"]  # the gate was asked, nothing else was touched
    assert result["steps"] == ["gate"]


def test_a_gate_that_raises_is_a_refusal_with_no_guest_contact():
    runner, calls = build(gate_raises=True)
    result = go(runner)
    assert result["status"] == "REFUSED" and result["reason"] == "GATE_RAISED"
    assert calls.log == ["gate"]
    assert "hostmark" not in json.dumps(result)


def test_bad_arguments_are_refused_with_no_gate_and_no_guest_call():
    runner, calls = build()
    bad = [
        dict(timeout_s=0), dict(timeout_s=float("nan")), dict(timeout_s=float("inf")), dict(timeout_s=True),
        dict(timeout_s=dr.MAX_TIMEOUT_S + 1), dict(output_cap_bytes=0), dict(output_cap_bytes=True),
        dict(output_cap_bytes=dr.MAX_OUTPUT_CAP + 1), dict(memory_bytes=0), dict(memory_bytes=dr.MAX_MEMORY_BYTES + 1),
        dict(gate_args={"operation": "pe_sieve_scan"}),
    ]
    for kw in bad:
        assert go(runner, **kw)["status"] == "REFUSED", kw
    for sha in ("", "xyz", "0" * 63, None, 5):
        assert runner.run(VM, "C:\\x", sha, GUEST_DIR)["status"] == "REFUSED"
    for vm, path, gdir in (("", "C:\\x", "C:\\g"), (VM, "", "C:\\g"), (VM, "C:\\x", ""), (None, "C:\\x", "C:\\g")):
        assert runner.run(vm, path, SHA, gdir)["status"] == "REFUSED"
    assert calls.log == []


def test_the_gate_is_asked_for_this_operation_with_the_deadline_and_the_callers_args():
    runner, calls = build()
    go(runner, timeout_s=7, gate_args={"pid": 4242, "authorization": {"authorized_by": "ops"}})
    operation, kwargs = calls.gate_args
    assert operation == "debugger_run"
    assert kwargs["timeout_seconds"] == 7 and kwargs["pid"] == 4242


# ------------------------------------------------------------------ order of the run


def test_completed_run_follows_the_exact_order_and_records_bounded_output():
    runner, calls = build()
    result = go(runner, output_cap_bytes=64, memory_bytes=1 << 20)
    assert result["status"] == "COMPLETED" and result["ok"] is True and result["reason"] is None
    assert calls.log == ["gate", "push_file", "create_suspended", "assign_to_job", "verify_job_assignment",
                         "resume", "wait", "terminate_job", "collect_output"]
    assert result["steps"] == calls.log
    out = result["output"]
    assert base64.b64decode(out["data_b64"]) == b"hello\n"
    assert (out["bytes_kept"], out["total_bytes"], out["cap_bytes"], out["truncated"]) == (6, 6, 64, False)
    assert out["sha256_of_kept"] == hashlib.sha256(b"hello\n").hexdigest() and out["untrusted"] is True
    assert result["exit_code"] == 0 and result["job"] == {"assignment_confirmed": True, "terminated": True}
    assert runner._launcher.seen_limits == {"memory_bytes": 1 << 20} and runner._launcher.cap_seen == 64


def test_a_non_zero_exit_code_is_reported_not_judged():
    runner, _ = build(wait={"ok": True, **IDENT, "exited": True, "exit_code": 3})
    result = go(runner)
    assert result["status"] == "COMPLETED" and result["exit_code"] == 3


def test_resume_occurs_only_after_job_assignment():
    runner, calls = build()
    go(runner)
    log = calls.log
    assert log.index("assign_to_job") < log.index("verify_job_assignment") < log.index("resume")
    assert log.index("create_suspended") < log.index("assign_to_job")
    assert log.count("resume") == 1


@pytest.mark.parametrize("over", [
    {"assign_to_job": {"ok": False}},
    {"assign_to_job": {}},
    {"assign_to_job": None},
    {"assign_to_job": RuntimeError("boom")},
    {"verify_job_assignment": {"ok": True, "in_job": False, "limits_applied": True}},
    {"verify_job_assignment": {"ok": True, "in_job": True, "limits_applied": False}},
    {"verify_job_assignment": {"ok": True, "in_job": True}},
    {"verify_job_assignment": {"ok": True, "in_job": 1, "limits_applied": 1}},
    {"verify_job_assignment": {"ok": True, "in_job": "yes", "limits_applied": True}},
    {"verify_job_assignment": {"ok": False, "in_job": True, "limits_applied": True}},
    {"verify_job_assignment": "in job"},
    {"verify_job_assignment": RuntimeError("boom")},
])
def test_unconfirmed_job_assignment_never_resumes(over):
    runner, calls = build(**over)
    result = go(runner)
    assert result["status"] == "JOB_ASSIGNMENT_UNCONFIRMED" and result["ok"] is False
    assert "resume" not in calls.log and "wait" not in calls.log and "collect_output" not in calls.log
    assert calls.log[-1] == "terminate_job"  # the suspended process is not left behind
    assert result["job"]["assignment_confirmed"] is False and result["job"]["terminated"] is True


def test_unconfirmed_assignment_with_a_failed_cleanup_says_the_cleanup_is_unconfirmed():
    runner, _ = build(assign_to_job={"ok": False}, terminate_job={"ok": True, **IDENT})
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "JOB_TERMINATION_NOT_CONFIRMED"
    assert result["primary_status"] == "JOB_ASSIGNMENT_UNCONFIRMED" and result["job"]["terminated"] is False


@pytest.mark.parametrize("over", [
    {"create_suspended": {"ok": True, "run_id": "run-1", "suspended": False}},
    {"create_suspended": {"ok": True, "run_id": "run-1"}},
    {"create_suspended": {"ok": True, "run_id": "run-1", "suspended": 1}},
    {"create_suspended": {"ok": True, "run_id": "bad id; calc", "suspended": True}},
    {"create_suspended": {"ok": True, "suspended": True}},
    {"create_suspended": {"ok": False}},
    {"create_suspended": None},
    {"create_suspended": RuntimeError("boom")},
])
def test_a_process_not_confirmed_suspended_is_never_assigned_or_resumed(over):
    runner, calls = build(**over)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "CREATE_SUSPENDED_NOT_CONFIRMED"
    assert not {"assign_to_job", "verify_job_assignment", "resume", "wait"} & set(calls.log)


def test_an_unresumable_process_is_terminated_and_not_completed():
    runner, calls = build(resume={"ok": True, "resumed": False})
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "RESUME_NOT_CONFIRMED"
    assert calls.log[-1] == "terminate_job" and "wait" not in calls.log


# ------------------------------------------------------------------ deadline and output cap


def test_deadline_returns_timed_out():
    runner, calls = build(wait={"ok": True, **IDENT, "exited": False, "exit_code": None})
    result = go(runner, timeout_s=2.5)
    assert result["status"] == "TIMED_OUT" and result["ok"] is False and result["exit_code"] is None
    assert runner._launcher.waited_for == 2.5
    assert calls.log.index("terminate_job") < calls.log.index("collect_output")  # killed, then partial output read
    assert result["job"]["terminated"] is True and result["output"]["bytes_kept"] == 6


def test_output_cap_returns_truncated():
    runner, _ = build(output=(b"x" * 16, 5000))
    result = go(runner, output_cap_bytes=16)
    assert result["status"] == "OUTPUT_TRUNCATED" and result["ok"] is False
    out = result["output"]
    assert out["truncated"] is True and out["bytes_kept"] == 16 and out["total_bytes"] == 5000
    assert base64.b64decode(out["data_b64"]) == b"x" * 16  # the partial bytes are kept, and marked
    assert result["exit_code"] == 0


def test_a_launcher_that_returns_more_than_the_cap_is_clipped_and_truncated():
    runner, _ = build(output=(b"y" * 100, 100))
    result = go(runner, output_cap_bytes=10)
    assert result["status"] == "OUTPUT_TRUNCATED" and result["output"]["bytes_kept"] == 10
    assert result["output"]["truncated_reason"] == "LAUNCHER_RETURNED_MORE_THAN_THE_CAP"


@pytest.mark.parametrize("over", [
    {"collect_output": {"ok": True, "data": b"a", "total_bytes": None}},
    {"collect_output": {"ok": True, "data": "text", "total_bytes": 4}},
    {"collect_output": {"ok": True, "data": b"abc", "total_bytes": 1}},
    {"collect_output": {"ok": False}},
    {"collect_output": None},
    {"collect_output": RuntimeError("boom")},
])
def test_an_output_reply_that_cannot_be_trusted_is_never_completed(over):
    runner, _ = build(**over)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "OUTPUT_REPLY_INVALID"
    assert result["output"] is None


@pytest.mark.parametrize("over", [
    {"wait": {"ok": True, **IDENT, "exited": True}},
    {"wait": {"ok": True, **IDENT, "exited": True, "exit_code": True}},
    {"wait": {"ok": True, **IDENT, "exited": 1, "exit_code": 0}},
    {"wait": {"ok": True, **IDENT, "exit_code": 0}},
    {"wait": {"ok": False}},
    {"wait": None},
    {"wait": RuntimeError("boom")},
])
def test_a_wait_reply_that_cannot_be_trusted_is_never_completed(over):
    runner, calls = build(**over)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "WAIT_REPLY_INVALID"
    assert "terminate_job" in calls.log  # the target is not left running


@pytest.mark.parametrize("term", [{"ok": True}, {"ok": True, "terminated": False}, {"ok": False}, None, RuntimeError("x")])
def test_unconfirmed_job_termination_is_not_completed(term):
    runner, _ = build(terminate_job=term)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "JOB_TERMINATION_NOT_CONFIRMED"
    assert result["job"]["terminated"] is False and result["output"]["bytes_kept"] == 6


# ------------------------------------------------------------------ transport


@pytest.mark.parametrize("error_class", ERROR_CLASSES)
def test_transport_failures_are_classified(error_class):
    reply = {"ok": False, "status": "FAILED", "error_class": error_class, "reason": "SOME_REASON", "measured": {}}
    runner, calls = build(transport_reply=reply)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["ok"] is False
    assert result["transport"] == {"error_class": error_class, "reason": "SOME_REASON"}
    assert calls.log == ["gate", "push_file"]


def test_unrecognised_or_missing_transport_answers_are_unknown_never_a_pass():
    for reply in (None, [], "ok", {}, {"ok": True}, {"ok": True, "status": "OK", "error_class": None, "measured": {}},
                  {"ok": False, "error_class": "SOMETHING_NEW", "reason": "x"}):
        runner, calls = build(transport_reply=reply if reply is not None else 5)
        result = go(runner)
        assert result["status"] == "TRANSPORT_ERROR", reply
        assert result["transport"]["error_class"] in ERROR_CLASSES
        assert calls.log == ["gate", "push_file"]


def test_a_transport_that_raises_is_a_transport_error_without_its_text():
    runner, calls = build(transport_raises=True)
    result = go(runner)
    assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "TRANSPORT_RAISED"
    assert "hostmark" not in json.dumps(result) and calls.log == ["gate", "push_file"]


def test_a_push_that_is_ok_but_not_the_declared_sample_never_launches():
    for host, guest in (("0" * 64, SHA), (SHA, "0" * 64), (SHA, None)):
        reply = {"ok": True, "status": "OK", "error_class": None, "reason": None,
                 "measured": {"host_sha256": host, "guest_sha256": guest, "guest_path": GUEST_PATH, "hashes_equal": True}}
        runner, calls = build(transport_reply=reply)
        result = go(runner)
        assert result["status"] == "TRANSPORT_ERROR" and result["transport"]["error_class"] == "HASH_MISMATCH"
        assert "create_suspended" not in calls.log


def test_push_hash_mismatch_never_launches(tmp_path):
    """The real HypervTransport, a fake PowerShell runner whose guest reports a different hash."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    transport, fake = hvt.make(str(tmp_path / "guest.cred"), hvt._push_handler(SAMPLE, guest_sha="0" * 64))
    calls = Calls()
    runner = DebuggerRun(transport, FakeLauncher(calls), gate=lambda *a, **k: good_decision())
    result = runner.run(VM, str(sample), SHA, GUEST_DIR)
    assert result["status"] == "TRANSPORT_ERROR"
    assert result["transport"]["error_class"] == "HASH_MISMATCH"
    assert calls.log == []  # not one launcher call
    assert len(fake.calls) == 1
    assert str(tmp_path) not in json.dumps(result)


def test_the_real_transport_with_a_matching_hash_reaches_the_launcher(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(SAMPLE)
    transport, _ = hvt.make(str(tmp_path / "guest.cred"), hvt._push_handler(SAMPLE))
    assert isinstance(transport, HypervTransport)
    calls = Calls()
    runner = DebuggerRun(transport, FakeLauncher(calls), gate=lambda *a, **k: good_decision())
    result = runner.run(VM, str(sample), SHA, GUEST_DIR)
    assert result["status"] == "COMPLETED"
    assert calls.log[0] == "create_suspended"


# ------------------------------------------------------------------ result hygiene


def test_result_carries_no_host_path():
    host_path = "D:\\hostmark\\work\\sample.bin"
    for kw in ({}, {"wait": {"ok": True, **IDENT, "exited": False, "exit_code": None}}, {"assign_to_job": {"ok": False}},
               {"output": (b"z" * 8, 99)}):
        runner, _ = build(**kw)
        result = runner.run(VM, host_path, SHA, GUEST_DIR)
        text = json.dumps(result)
        for forbidden in (host_path, "hostmark", "environment"):
            assert forbidden not in text, (kw, forbidden)
    refused, _ = build(_decision(ok=False))
    text = json.dumps(go(refused))
    assert "hostmark" not in text and "environment" not in text


def test_every_status_is_a_member_of_the_enum_and_only_completed_is_ok():
    seen = set()
    scenarios = [
        {}, {"wait": {"ok": True, **IDENT, "exited": False, "exit_code": None}}, {"output": (b"x", 2)},
        {"assign_to_job": {"ok": False}}, {"resume": {"ok": False}},
    ]
    for kw in scenarios:
        result = go(build(**kw)[0])
        seen.add(result["status"])
        assert result["status"] in STATUSES and result["ok"] is (result["status"] == "COMPLETED")
    seen.add(go(build(_decision(ok=False))[0])["status"])
    assert seen == set(STATUSES)
    assert result["schema"] == dr.SCHEMA


def test_the_result_says_what_is_not_verified():
    result = go(build()[0])
    assert any("no real guest launcher" in line for line in result["not_verified"])


# ------------------------------------------------------------------ adversarial review fixes


@pytest.mark.parametrize("over, primary", [
    ({"assign_to_job": {"ok": False}}, "JOB_ASSIGNMENT_UNCONFIRMED"),
    ({"wait": {"ok": True, **IDENT, "exited": False, "exit_code": None}}, "TIMED_OUT"),
    ({"output": (b"x" * 4, 99)}, "OUTPUT_TRUNCATED"),
    ({"resume": {"ok": False}}, "TRANSPORT_ERROR"),
    ({"create_suspended": {"ok": True, **IDENT, "suspended": False}}, "TRANSPORT_ERROR"),
])
def test_an_unconfirmed_termination_outranks_every_other_status(over, primary):
    for term in ({"ok": True, **IDENT, "terminated": False}, None, {"ok": True, **IDENT}):
        runner, _ = build(terminate_job=term, **over)
        result = go(runner)
        assert result["status"] == "TRANSPORT_ERROR" and result["reason"] == "JOB_TERMINATION_NOT_CONFIRMED", over
        assert result["primary_status"] == primary and result["primary_reason"]
        assert result["job"]["terminated"] is False and result["ok"] is False


def test_a_confirmed_cleanup_leaves_the_primary_fields_empty():
    result = go(build(wait={"ok": True, **IDENT, "exited": False, "exit_code": None})[0])
    assert result["status"] == "TIMED_OUT" and result["primary_status"] is None and result["primary_reason"] is None


def test_an_exit_reported_after_the_deadline_is_timed_out_even_if_the_process_exited():
    clock = FakeClock()
    runner, _ = build(clock=clock, advance_in_wait=2.0)
    result = go(runner, timeout_s=1)
    assert result["status"] == "TIMED_OUT" and result["reason"] == "EXIT_NOT_PROVEN_WITHIN_DEADLINE"
    assert result["ok"] is False and result["elapsed_s"] == 2.0


def test_an_exit_reported_inside_the_deadline_still_completes():
    clock = FakeClock()
    runner, _ = build(clock=clock, advance_in_wait=0.9)
    assert go(runner, timeout_s=1)["status"] == "COMPLETED"


WRONG = [{"run_id": "other", "pid": 4321}, {"run_id": "run-1", "pid": 999}, {"pid": 4321}, {"run_id": "run-1"},
         {}, {"run_id": "run-1", "pid": True}, {"run_id": "run-1", "pid": "4321"}, {"run_id": 1, "pid": 4321}]


@pytest.mark.parametrize("ident", WRONG)
@pytest.mark.parametrize("step", ["assign_to_job", "verify_job_assignment", "resume", "wait", "terminate_job",
                                  "collect_output"])
def test_a_confirmation_about_another_process_is_never_completed(step, ident):
    good = {
        "assign_to_job": {"ok": True}, "resume": {"ok": True, "resumed": True},
        "verify_job_assignment": {"ok": True, "in_job": True, "limits_applied": True},
        "wait": {"ok": True, "exited": True, "exit_code": 0}, "terminate_job": {"ok": True, "terminated": True},
        "collect_output": {"ok": True, "data": b"hi", "total_bytes": 2},
    }[step]
    reply = dict(good)
    reply.update(ident)
    runner, calls = build(**{step: reply})
    result = go(runner)
    assert result["status"] != "COMPLETED" and result["ok"] is False, (step, ident)
    if step in ("assign_to_job", "verify_job_assignment"):
        assert result["status"] == "JOB_ASSIGNMENT_UNCONFIRMED" and "resume" not in calls.log


def test_create_suspended_must_name_a_process_id():
    for created in ({"ok": True, "run_id": "run-1", "suspended": True},
                    {"ok": True, "run_id": "run-1", "pid": 0, "suspended": True},
                    {"ok": True, "run_id": "run-1", "pid": True, "suspended": True}):
        runner, calls = build(create_suspended=created)
        assert go(runner)["status"] == "TRANSPORT_ERROR"
        assert "assign_to_job" not in calls.log
