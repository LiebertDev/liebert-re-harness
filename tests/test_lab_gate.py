"""`liebert_re.dynamic.lab_gate`: the gate every live-process operation must pass.

The gate is exercised for real here: a harmless console process is started by the test (no
window), the gate reads its genuine identity and image hash, and the process is always killed
and confirmed dead. Only the scanner (`run_bounded_process`) is mocked, because the gate's job
ends where the scanner starts.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import time
from contextlib import redirect_stdout
from unittest import mock

import pytest

import liebert_re.cli as cli
import liebert_re.tools.pe_sieve as ps
from liebert_re.bounded_subprocess import BoundedProcessResult
import liebert_re.dynamic.lab_gate as lg

pytestmark = pytest.mark.contract

OPEN = {lg.ENABLE_ENV: lg.ENABLE_VALUE}


def _auth(pid, operation="pe_sieve_scan"):
    return {"authorized_by": "test", "purpose": "gate test", "operations": [operation], "pids": [pid]}


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _gate(pid, **kw):
    kw.setdefault("operation", "pe_sieve_scan")
    kw.setdefault("authorization", _auth(pid, kw["operation"]))
    return json.loads(lg.dynamic_lab_gate(pid=pid, **kw))


def _command():
    if os.name == "nt":
        return ["ping", "-n", "120", "127.0.0.1"]
    return ["sleep", "120"]


def _confirmed_dead(pid):
    """True when `pid` is gone (or only a reaped zombie). A pid that vanishes between the existence
    probe and the status query is the very state wanted, so psutil.NoSuchProcess counts as proof of
    death. AccessDenied and every other error are not proof of anything and propagate."""
    import psutil
    if not psutil.pid_exists(pid):
        return True
    try:
        return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


@pytest.fixture()
def child():
    """A process THIS test started: console, no window, always killed and confirmed dead."""
    proc = subprocess.Popen(_command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.time() + 10
        while time.time() < deadline and lg.LabGate.target(proc.pid)[0] is None:
            time.sleep(0.05)
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=10)
        assert proc.poll() is not None
        assert _confirmed_dead(proc.pid)


@pytest.fixture()
def image_sha(child):
    return _sha(lg.LabGate.target(child.pid)[0]["image"])


@pytest.fixture()
def lab_open():
    with mock.patch.dict(os.environ, OPEN):
        yield


class TestConfirmedDead:
    """The teardown's death proof must treat a vanished pid as dead and nothing else as a pass."""

    def test_pid_vanishing_between_probe_and_query_is_death(self):
        import psutil
        with mock.patch.object(psutil, "pid_exists", return_value=True),                 mock.patch.object(psutil, "Process", side_effect=psutil.NoSuchProcess(4242)):
            assert _confirmed_dead(4242) is True

    def test_a_live_process_is_not_dead(self, child):
        assert _confirmed_dead(child.pid) is False

    def test_access_denied_is_not_proof_of_death(self):
        import psutil
        with mock.patch.object(psutil, "pid_exists", return_value=True),                 mock.patch.object(psutil, "Process", side_effect=psutil.AccessDenied(4242)):
            with pytest.raises(psutil.AccessDenied):
                _confirmed_dead(4242)


class TestRefusals:
    def test_closed_by_default_without_the_operator_switch(self, child, image_sha):
        with mock.patch.dict(os.environ):
            os.environ.pop(lg.ENABLE_ENV, None)
            data = _gate(child.pid, sample_sha256=image_sha)
        assert data["ok"] is False and data["status"] == "AUTHORIZATION_REQUIRED" and data["error"] == "LAB_SWITCH_OFF"
        assert data["isolation_verified"] is False

    @pytest.mark.parametrize("bad", [None, "", "not json", [], {}, {"authorized_by": "x"},
                                     {"authorized_by": " ", "purpose": "p", "operations": ["pe_sieve_scan"], "pids": [1]}])
    def test_authorization_missing_or_malformed_is_refused(self, child, image_sha, lab_open, bad):
        data = _gate(child.pid, authorization=bad, sample_sha256=image_sha)
        assert data["status"] == "AUTHORIZATION_REQUIRED" and data["decision"] == "REFUSE"

    def test_authorization_for_another_operation_or_another_pid_does_not_cover_this_run(self, child, image_sha, lab_open):
        other_op = _gate(child.pid, authorization=_auth(child.pid, "something_else"), sample_sha256=image_sha)
        other_pid = _gate(child.pid, authorization=_auth(child.pid + 1), sample_sha256=image_sha)
        bool_pid = _gate(child.pid, authorization={**_auth(child.pid), "pids": [True]}, sample_sha256=image_sha)
        for data in (other_op, other_pid, bool_pid):
            assert data["status"] == "AUTHORIZATION_REQUIRED" and data["error"] == "AUTHORIZATION_MISSING_OR_OUT_OF_SCOPE"

    def test_authorization_may_be_given_as_json_text(self, child, image_sha, lab_open):
        data = _gate(child.pid, authorization=json.dumps(_auth(child.pid)), sample_sha256=image_sha)
        assert data["status"] == "GATE_PASSED"

    @pytest.mark.parametrize("declared", [None, "", "abc", "z" * 64, "a" * 63, 123])
    def test_hash_must_be_declared(self, child, lab_open, declared):
        data = _gate(child.pid, sample_sha256=declared)
        assert data["status"] == "SAMPLE_HASH_REQUIRED"

    def test_wrong_hash_is_refused_and_both_hashes_are_shown(self, child, image_sha, lab_open):
        wrong = ("0" if image_sha[0] != "0" else "1") + image_sha[1:]
        data = _gate(child.pid, sample_sha256=wrong)
        assert data["status"] == "SAMPLE_HASH_MISMATCH" and data["decision"] == "REFUSE"
        assert data["target"]["image_sha256_declared"] == wrong and data["target"]["image_sha256_actual"] == image_sha

    def test_a_process_the_harness_did_not_start_is_refused(self, image_sha, lab_open):
        # This very process is not a child of itself, and nobody registered it.
        data = _gate(os.getpid(), sample_sha256=_sha(sys.executable))
        assert data["status"] == "PROCESS_NOT_OWNED" and data["error"] == "NO_OWNERSHIP_PROOF"

    def test_a_grandchild_is_not_owned(self, lab_open):
        # A direct child that starts its own child: only the direct child is the harness's.
        code = ("import subprocess,sys,time;"
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                "print(p.pid,flush=True);time.sleep(60)")
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), text=True)
        grandchild = None
        try:
            grandchild = int(proc.stdout.readline())
            image = lg.LabGate.target(grandchild)[0]["image"]
            data = _gate(grandchild, sample_sha256=_sha(image))
            assert data["status"] == "PROCESS_NOT_OWNED"
        finally:
            import psutil
            victims = [proc.pid] + ([grandchild] if grandchild else [])
            for pid in victims:
                try:
                    psutil.Process(pid).kill()
                except psutil.Error:
                    pass
            proc.wait(timeout=10)
            deadline = time.time() + 10
            while time.time() < deadline and any(psutil.pid_exists(p) for p in victims):
                time.sleep(0.1)
            assert all(_confirmed_dead(p) for p in victims)

    def test_a_missing_or_nonexistent_process_is_refused(self, lab_open):
        assert _gate(None, authorization=_auth(1), sample_sha256="0" * 64)["status"] == "PID_REQUIRED"
        data = _gate(2 ** 31 - 3, sample_sha256="0" * 64)
        assert data["status"] == "PROCESS_NOT_OWNED"

    def test_unknown_operation_is_refused(self, child, image_sha, lab_open):
        data = _gate(child.pid, operation="whole_system_scan", sample_sha256=image_sha)
        assert data["status"] == "UNKNOWN_OPERATION"
        assert json.loads(lg.dynamic_lab_gate())["status"] == "UNKNOWN_OPERATION"

    @pytest.mark.parametrize("operation", sorted(lg.NEEDS_ISOLATION))
    def test_operations_that_execute_or_instrument_need_isolation_whatever_is_supplied(self, child, image_sha, lab_open, operation):
        data = _gate(child.pid, operation=operation, sample_sha256=image_sha)
        assert data["ok"] is False and data["status"] == "ISOLATION_REQUIRED"
        assert data["isolation"]["required_for_operation"] is True and data["isolation_verified"] is False
        assert {p["prerequisite"] for p in data["isolation"]["unmet_prerequisites"]} == {
            "isolated_guest", "snapshot_and_rollback", "network_control"}

    def test_bounds_are_required_and_the_memory_monitor_must_work(self, child, image_sha, lab_open):
        assert _gate(child.pid, sample_sha256=image_sha, timeout_seconds=0)["status"] == "BOUNDS_REQUIRED"
        assert _gate(child.pid, sample_sha256=image_sha, max_memory_bytes=None)["status"] == "BOUNDS_REQUIRED"
        with mock.patch("liebert_re.bounded_subprocess._memory_monitor_usable", return_value=False):
            data = _gate(child.pid, sample_sha256=image_sha)
        assert data["status"] == "RESOURCE_LIMIT_UNAVAILABLE"

    def test_a_gate_that_cannot_write_evidence_refuses_with_an_environment_error(self, child, image_sha, lab_open, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        with mock.patch.object(lg, "EVIDENCE", blocker / "sub"):
            data = _gate(child.pid, sample_sha256=image_sha)
        assert data["ok"] is False and data["status"] == "ANALYSIS_LIMITED" and data["error"] == "GATE_EVIDENCE_UNWRITABLE"
        assert data["environment_error"]["type"] and "target" in data["detail"]

    def test_hostile_arguments_never_raise(self):
        for value in (object(), 1.5, float("nan"), [], {}, b"x", "\x00", 10 ** 30, True):
            for out in (lg.dynamic_lab_gate(value, value, value, value, value, value),
                        lg.dynamic_lab_register_owned_process(value)):
                assert isinstance(json.loads(out), dict)

    def test_every_refusal_lists_each_check_as_passed_failed_or_not_evaluated(self, child, lab_open):
        data = _gate(child.pid, sample_sha256=None)
        results = {c["check"]: c["result"] for c in data["checks"]}
        assert list(results) == ["operation_known", "isolation_requirement", "operator_switch", "pid",
                                 "authorization", "ownership", "sample_hash", "bounds", "evidence_writable"]
        assert results["ownership"] == "passed" and results["sample_hash"] == "failed"
        assert results["bounds"] == results["evidence_writable"] == "not_evaluated"


class TestPassAndEvidence:
    def test_a_process_the_harness_started_passes_and_says_what_it_did_not_verify(self, child, image_sha, lab_open):
        data = _gate(child.pid, sample_sha256=image_sha)
        assert data["ok"] is True and data["status"] == "GATE_PASSED" and data["decision"] == "ALLOW"
        assert data["isolation_verified"] is False and data["isolation"]["required_for_operation"] is False
        assert "read-only observation" in data["isolation"]["reason_not_required"]
        assert len(data["isolation"]["unmet_prerequisites"]) == 3
        assert data["ownership"]["basis"] == "direct_child_of_calling_process"
        assert data["enforced"] == ["operation_known", "isolation_requirement", "operator_switch", "pid",
                                    "authorization", "ownership", "sample_hash", "bounds", "evidence_writable"]

    def test_evidence_records_environment_privilege_target_and_decision(self, child, image_sha, lab_open):
        data = _gate(child.pid, sample_sha256=image_sha)
        record = json.loads((lg.EVIDENCE / data["evidence_name"]).read_text(encoding="utf-8"))
        assert record["environment"]["platform"] and record["environment"]["python"]
        assert "elevated" in record["environment"]["privilege"] and record["environment"]["user"]
        assert record["target"]["pid"] == child.pid and record["authorization"]["authorized_by"] == "test"

    def test_an_elevated_context_is_recorded_as_a_different_observation(self, child, image_sha, lab_open):
        with mock.patch.object(lg.LabGate, "elevated", return_value=True):
            data = _gate(child.pid, sample_sha256=image_sha)
        assert data["environment"]["privilege"]["elevated"] is True
        assert "ELEVATED" in data["environment"]["privilege"]["note"]
        with mock.patch.object(lg.LabGate, "elevated", return_value=None):
            assert _gate(child.pid, sample_sha256=image_sha)["environment"]["privilege"]["elevated"] is None

    def test_a_refusal_is_also_written_to_evidence(self, child, lab_open):
        data = _gate(child.pid, sample_sha256="0" * 64)
        assert (lg.EVIDENCE / data["evidence_name"]).is_file() and data["evidence_write_error"] is None


class TestRegistry:
    def test_a_registered_child_is_owned_from_another_process_and_a_reused_pid_is_not(self, child, image_sha, lab_open):
        reg = json.loads(lg.dynamic_lab_register_owned_process(child.pid))
        assert reg["ok"] is True and reg["registered"]["pid"] == child.pid
        # From a different process the child is no longer a direct child; the registry is the proof.
        with mock.patch.object(lg.LabGate, "is_direct_child", return_value=False):
            data = _gate(child.pid, sample_sha256=image_sha)
            assert data["status"] == "GATE_PASSED" and data["ownership"]["basis"] == "harness_registry"
            entry = lg.LabGate.registry_dir() / reg["entry"]
            tampered = json.loads(entry.read_text())
            tampered["create_time"] += 5
            entry.write_text(json.dumps(tampered))
            again = _gate(child.pid, sample_sha256=image_sha)
            assert again["status"] == "PROCESS_NOT_OWNED"

    def test_only_a_direct_child_can_be_registered(self):
        data = json.loads(lg.dynamic_lab_register_owned_process(os.getpid()))
        assert data["ok"] is False and data["status"] == "PROCESS_NOT_OWNED" and data["error"] == "NOT_A_DIRECT_CHILD"
        assert json.loads(lg.dynamic_lab_register_owned_process(None))["status"] == "PID_REQUIRED"
        assert json.loads(lg.dynamic_lab_register_owned_process(2 ** 31 - 3))["ok"] is False

    def test_an_unwritable_registry_is_an_environment_error(self, child, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        with mock.patch.object(lg, "EVIDENCE", blocker / "sub"):
            data = json.loads(lg.dynamic_lab_register_owned_process(child.pid))
        assert data["status"] == "ANALYSIS_LIMITED" and data["environment_error"]["type"]


class TestPeSieveBehindTheGate:
    """pe_sieve_scan with the REAL gate and a faked scanner."""

    @pytest.fixture()
    def scan(self, tmp_path):
        with mock.patch.object(ps, "EVIDENCE", tmp_path), \
             mock.patch.object(ps._PeSieve, "candidates", return_value=[(r"C:\fake\pe-sieve64.exe", "PATH")]), \
             mock.patch.object(ps, "run_bounded_process") as run:
            run.return_value = BoundedProcessResult(1, "", "no json here")
            yield run

    def test_refused_without_authorization_and_nothing_is_started(self, scan, child, image_sha):
        with mock.patch.dict(os.environ):
            os.environ.pop(lg.ENABLE_ENV, None)
            data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256=image_sha))
        assert data["status"] == "AUTHORIZATION_REQUIRED" and data["ok"] is False and not scan.called
        with mock.patch.dict(os.environ, OPEN):
            data = json.loads(ps.pe_sieve_scan(child.pid, sample_sha256=image_sha))
        assert data["status"] == "AUTHORIZATION_REQUIRED" and not scan.called

    def test_refused_with_a_wrong_hash(self, scan, child, lab_open):
        data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256="1" * 64))
        assert data["status"] == "SAMPLE_HASH_MISMATCH" and not scan.called
        assert data["lab_gate"]["isolation_verified"] is False

    def test_refused_for_a_process_the_harness_did_not_start(self, scan, lab_open):
        data = json.loads(ps.pe_sieve_scan(os.getpid(), authorization=_auth(os.getpid()),
                                           sample_sha256=_sha(sys.executable)))
        assert data["status"] == "PROCESS_NOT_OWNED" and not scan.called

    def test_passes_for_an_owned_process_with_bounds_and_complete_evidence(self, scan, child, image_sha, lab_open):
        data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256=image_sha,
                                           timeout_seconds=30))
        assert scan.called and data["status"] == "ANALYSIS_LIMITED" and data["error"] == "PE_SIEVE_NO_JSON_OUTPUT"
        kwargs = scan.call_args.kwargs
        assert kwargs["max_memory_bytes"] == ps._MAX_SCANNER_MEMORY_BYTES and kwargs["timeout_seconds"] == 30
        gate = data["lab_gate"]
        assert gate["ok"] is True and gate["isolation_verified"] is False and gate["evidence_finalize_error"] is None
        record = json.loads((lg.EVIDENCE / gate["evidence_name"]).read_text(encoding="utf-8"))
        assert record["invoked_argv"] == scan.call_args[0][0] == data["invoked_argv"]
        assert record["result"]["error"] == "PE_SIEVE_NO_JSON_OUTPUT"
        assert record["target_identity_unchanged_after_run"] is True

    def test_memory_limit_outcomes_are_not_findings(self, scan, child, image_sha, lab_open):
        kw = {"authorization": _auth(child.pid), "sample_sha256": image_sha}
        scan.return_value = BoundedProcessResult(None, "", "", resource_limit_unavailable=True)
        assert json.loads(ps.pe_sieve_scan(child.pid, **kw))["error"] == "PE_SIEVE_RESOURCE_LIMIT_UNAVAILABLE"
        scan.return_value = BoundedProcessResult(None, "", "", memory_exceeded=True)
        data = json.loads(ps.pe_sieve_scan(child.pid, **kw))
        assert data["ok"] is False and data["status"] == "ANALYSIS_LIMITED" and "anomalies_found" not in data

    def test_an_exception_after_the_gate_keeps_the_gate_block_and_json(self, scan, child, image_sha, lab_open):
        scan.side_effect = RuntimeError("boom")
        data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256=image_sha))
        assert data["error"] == "PE_SIEVE_UNEXPECTED_ERROR" and data["lab_gate"]["ok"] is True

    def test_gate_failures_for_an_unwritable_ledger_carry_the_environment_error(self, scan, child, image_sha, lab_open, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        with mock.patch.object(lg, "EVIDENCE", blocker / "sub"):
            data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256=image_sha))
        assert data["status"] == "ANALYSIS_LIMITED" and data["environment_error"]["type"] and not scan.called


class TestCli:
    def _run(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, json.loads(buf.getvalue())

    def test_labgate_refusal_exit_codes(self, child, image_sha, lab_open):
        code, body = self._run("labgate", "--operation", "frida_trace", "--pid", str(child.pid),
                               "--authorization", json.dumps(_auth(child.pid, "frida_trace")), "--sample-sha256", image_sha)
        assert code == 3 and body["status"] == "ISOLATION_REQUIRED" and body["isolation_verified"] is False
        code, body = self._run("labgate", "--operation", "pe_sieve_scan", "--pid", str(child.pid))
        assert code == 3 and body["status"] == "AUTHORIZATION_REQUIRED"

    def test_sieve_without_the_gate_arguments_is_refused_with_exit_3(self, child, lab_open):
        code, body = self._run("sieve", "--pid", str(child.pid))
        assert code == 3 and body["status"] == "AUTHORIZATION_REQUIRED" and body["command"] == "sieve"

    def test_labgate_passes_for_an_owned_process(self, child, image_sha, lab_open):
        code, body = self._run("labgate", "--operation", "pe_sieve_scan", "--pid", str(child.pid),
                               "--authorization", json.dumps(_auth(child.pid)), "--sample-sha256", image_sha)
        assert code == 0 and body["status"] == "GATE_PASSED"
