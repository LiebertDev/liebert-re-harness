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
from tests.test_guest_attestation import VM_ID as _GA_VM_ID
from tests.test_guest_attestation import _admissible as _ga_admissible
from tests.test_guest_attestation import _with as _ga_with
from tests.test_guest_attestation import _without as _ga_without

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


def _birth(pid):
    """The creation time of the process `pid` names right now, or None when it is not readable. Taken while a
    test's own process is known to be the one holding the pid, so a later reuse of the number can be told apart."""
    import psutil
    try:
        return psutil.Process(pid).create_time()
    except psutil.Error:
        return None


def _confirmed_dead(pid, birth=None):
    """True when `pid` is gone (or only a reaped zombie). A pid that vanishes between the existence
    probe and the status query is the very state wanted, so psutil.NoSuchProcess counts as proof of
    death. AccessDenied and every other error are not proof of anything and propagate.
    `birth` is the creation time `_birth` recorded for the process under test: once the pid is free the OS may
    hand it to an unrelated new process (Windows does so quickly), and a live process with a different creation
    time is proof that the one under test is gone, not a reason to fail. Without `birth` the pid alone is judged."""
    import psutil
    if not psutil.pid_exists(pid):
        return True
    try:
        process = psutil.Process(pid)
        if birth is not None and process.create_time() != birth:
            return True
        return process.status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


@pytest.fixture()
def child():
    """A process THIS test started: console, no window, always killed and confirmed dead."""
    proc = subprocess.Popen(_command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    birth = _birth(proc.pid)
    try:
        deadline = time.time() + 10
        while time.time() < deadline and lg.LabGate.target(proc.pid)[0] is None:
            time.sleep(0.05)
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=10)
        assert proc.poll() is not None
        assert _confirmed_dead(proc.pid, birth)


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
        assert _confirmed_dead(child.pid, _birth(child.pid)) is False

    def test_a_reused_pid_is_not_the_process_under_test(self, child):
        """The number is held by a live process, but not the one that was recorded: the recorded one is gone."""
        recorded = _birth(child.pid)
        assert recorded is not None
        assert _confirmed_dead(child.pid, recorded - 1000.0) is True

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
        grandchild, births = None, {proc.pid: _birth(proc.pid)}
        try:
            grandchild = int(proc.stdout.readline())
            births[grandchild] = _birth(grandchild)
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
            assert all(_confirmed_dead(p, births.get(p)) for p in victims)

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
        for bad in (float("inf"), float("-inf"), float("nan"), True, "30", None):
            assert _gate(child.pid, sample_sha256=image_sha, timeout_seconds=bad)["status"] == "BOUNDS_REQUIRED", bad
        with mock.patch("liebert_re.bounded_subprocess._memory_monitor_usable", return_value=False):
            data = _gate(child.pid, sample_sha256=image_sha)
        assert data["status"] == "RESOURCE_LIMIT_UNAVAILABLE"

    def test_an_int_too_large_for_a_float_is_a_structured_refusal(self, child, image_sha, lab_open):
        for huge in (10**10000, -(10**10000)):
            data = _gate(child.pid, sample_sha256=image_sha, timeout_seconds=huge)
            assert data["ok"] is False and data["status"] == "BOUNDS_REQUIRED", huge

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

    def test_the_gate_record_holds_the_full_result_but_the_response_gate_keeps_the_short_outcome(self, scan, child, image_sha, lab_open):
        data = json.loads(ps.pe_sieve_scan(child.pid, authorization=_auth(child.pid), sample_sha256=image_sha,
                                           timeout_seconds=30))
        gate = data["lab_gate"]
        record = json.loads((lg.EVIDENCE / gate["evidence_name"]).read_text(encoding="utf-8"))
        full = record["result"]["full_result"]
        assert full["error"] == "PE_SIEVE_NO_JSON_OUTPUT" and full["tool"] == data["tool"]
        assert full["invoked_argv"] == data["invoked_argv"]
        assert "lab_gate" not in full, "the record keeps the scan result, not a copy of the gate inside itself"
        # the response is unchanged: its gate carries the short outcome, never the full result
        assert set(gate["result"]) == {"status", "ok", "error"}
        assert "full_result" not in gate["result"]

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


class TestAuditFixes:
    """The three defects the adversarial audit found. No real process: the gate's decision and the
    target lookup are faked, only the code under test is real."""

    IDENTITY = {"pid": 4242, "create_time": 1000.5, "image": r"C:ake	arget.exe", "parent_pid": 1, "state": "running"}

    @pytest.fixture()
    def passed_gate(self, tmp_path):
        def fake_check(*_a, **_k):
            return {"ok": True, "decision": "ALLOW", "status": "GATE_PASSED", "isolation_verified": False,
                    "target": dict(self.IDENTITY), "checks": [{"check": "evidence_writable", "result": "passed"}],
                    "enforced": ["evidence_writable"], "evidence_name": "pe_sieve_scan_pid4242_fake_gate.json"}
        with mock.patch.object(lg, "EVIDENCE", tmp_path),              mock.patch.object(lg.LabGate, "check", side_effect=fake_check),              mock.patch.object(ps, "EVIDENCE", tmp_path / "ps"),              mock.patch.object(ps._PeSieve, "candidates", return_value=[(r"C:ake\pe-sieve64.exe", "PATH")]),              mock.patch.object(ps, "run_bounded_process") as run:
            run.return_value = BoundedProcessResult(1, "", "no json here")
            yield run

    def _scan(self):
        return json.loads(ps.pe_sieve_scan(4242, authorization=_auth(4242), sample_sha256="0" * 64))

    def test_a_path_escaping_operation_name_cannot_leave_the_evidence_folder(self, tmp_path):
        evidence = tmp_path / "evidence"
        hostile = ("..", "..\\", "../../outside", "a/../../b", r"x\..\..\y", r"C:\abs", "\x00bad", "")
        with mock.patch.object(lg, "EVIDENCE", evidence):
            for operation in hostile:
                data = json.loads(lg.dynamic_lab_gate(operation=operation, pid=1))
                assert data["status"] == "UNKNOWN_OPERATION" and data["evidence_write_error"] is None
                written = (evidence / data["evidence_name"]).resolve()
                assert written.parent == evidence.resolve() and written.is_file()
                assert data["evidence_name"].isascii() and not any(c in data["evidence_name"] for c in "/\\:")
                record = json.loads(written.read_text(encoding="utf-8"))
                assert record["operation"] == operation  # the raw text stays in the record
        assert [p for p in tmp_path.rglob("*.json") if evidence.resolve() not in p.resolve().parents] == []

    def test_write_refuses_a_name_that_resolves_outside_the_evidence_folder(self, tmp_path):
        evidence = tmp_path / "evidence"
        with mock.patch.object(lg, "EVIDENCE", evidence):
            error = lg.LabGate.write("../escaped.json", {"x": 1})
        assert error and error["type"] == "EvidencePathEscape" and not (tmp_path / "escaped.json").exists()

    def test_a_final_record_that_cannot_be_written_withholds_the_result(self, passed_gate):
        with mock.patch.object(lg.LabGate, "target", return_value=(dict(self.IDENTITY), None)),              mock.patch.object(lg.LabGate, "write", return_value={"type": "OSError", "errno": 28, "strerror": "disk full"}):
            data = self._scan()
        assert passed_gate.called  # the scanner did run: it cannot be undone
        assert data["ok"] is False and data["status"] == "EVIDENCE_FINALIZE_FAILED"
        assert data["operation_ran"] is True and data["result_withheld"] is True
        assert data["evidence_finalize_error"]["strerror"] == "disk full"
        assert data["lab_gate"]["evidence_finalize_error"]["errno"] == 28
        assert "anomalies_found" not in data and "PE_SIEVE_NO_JSON_OUTPUT" not in json.dumps(data)

    def test_an_exception_path_also_withholds_when_the_record_cannot_be_written(self, passed_gate):
        passed_gate.side_effect = RuntimeError("boom")
        with mock.patch.object(lg.LabGate, "target", return_value=(dict(self.IDENTITY), None)),              mock.patch.object(lg.LabGate, "write", return_value={"type": "OSError", "errno": 5, "strerror": "io"}):
            data = self._scan()
        assert data["status"] == "EVIDENCE_FINALIZE_FAILED" and data["operation_ran"] is None

    def test_a_target_that_drifted_before_the_start_is_not_scanned(self, passed_gate):
        for drifted in ({**self.IDENTITY, "create_time": 2000.0}, {**self.IDENTITY, "image": r"C:\other.exe"}):
            with mock.patch.object(lg.LabGate, "target", return_value=(drifted, None)):
                data = self._scan()
            assert not passed_gate.called
            assert data["ok"] is False and data["status"] == "TARGET_IDENTITY_DRIFTED"
            assert "Nothing was started" in data["detail"]
            assert data["lab_gate"]["checks"][-1] == {**data["lab_gate"]["checks"][-1], "check": "identity_recheck", "result": "failed"}
        with mock.patch.object(lg.LabGate, "target", return_value=(None, ("PROCESS_NOT_OWNED", "gone"))):
            assert self._scan()["status"] == "TARGET_IDENTITY_DRIFTED" and not passed_gate.called

    def test_without_drift_the_normal_flow_is_unchanged(self, passed_gate):
        with mock.patch.object(lg.LabGate, "target", return_value=(dict(self.IDENTITY), None)):
            data = self._scan()
        assert passed_gate.called and data["status"] == "ANALYSIS_LIMITED" and data["error"] == "PE_SIEVE_NO_JSON_OUTPUT"
        assert data["target_identity_unchanged_after_run"] is True and "identity_drift_after_run" not in data
        assert data["lab_gate"]["evidence_finalize_error"] is None
        assert [c["result"] for c in data["lab_gate"]["checks"] if c["check"] == "identity_recheck"] == ["passed"]

    def test_drift_after_the_run_is_still_detected_and_carried_in_the_result(self, passed_gate):
        drifted = {**self.IDENTITY, "create_time": 2000.0}
        with mock.patch.object(lg.LabGate, "target", side_effect=[(dict(self.IDENTITY), None), (drifted, None)]):
            data = self._scan()
        assert passed_gate.called and data["target_identity_unchanged_after_run"] is False
        assert "identity_drift_after_run" in data and data["lab_gate"]["target_identity_unchanged_after_run"] is False


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


# ---------------------------------------------------------------------------------------------
# NEEDS_ISOLATION operations open only for a VERIFIED guest attestation, read from a named file.
# ---------------------------------------------------------------------------------------------

def _fresh(measurement, age_s=60):
    """The measurement stamped `age_s` seconds before the real clock (the gate reads the real clock)."""
    from datetime import datetime, timedelta, timezone
    moment = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    earlier = moment - timedelta(days=1)
    return _ga_with(_ga_with(measurement, "measured_at_utc", moment.strftime("%Y-%m-%dT%H:%M:%SZ")),
                    "checkpoints.items.0.created_utc", earlier.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _measurement_file(tmp_path, measurement, name="measurement.json"):
    path = tmp_path / name
    path.write_text(json.dumps(measurement), encoding="utf-8")
    return str(path)


def _isolated_gate(pid, path, operation="frida_trace", **kw):
    kw.setdefault("local_vm_id", _GA_VM_ID)
    return _gate(pid, operation=operation, guest_measurement_path=path, **kw)


class TestIsolationFromAttestation:
    @pytest.mark.parametrize("operation", sorted(lg.NEEDS_ISOLATION))
    def test_a_verified_attestation_opens_only_the_isolation_check(self, child, image_sha, lab_open, tmp_path, operation):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible()))
        data = _isolated_gate(child.pid, path, operation=operation, sample_sha256=image_sha)
        assert data["ok"] is True, (data["status"], data.get("detail"))
        assert data["status"] == "GATE_PASSED" and data["decision"] == "ALLOW"
        assert data["isolation_verified"] is True and data["isolation"]["verified"] is True
        assert data["isolation"]["unmet_prerequisites"] == [] and data["isolation"]["required_for_operation"] is True
        att = data["isolation"]["attestation"]
        assert att["verdict"] == "VERIFIED" and att["spoofable"] is True and att["not_covered"]
        assert data["invoked_argv"] is None and data["result"] is None  # the gate starts nothing
        results = {c["check"]: c["result"] for c in data["checks"]}
        assert results["isolation_requirement"] == "passed" and set(results.values()) == {"passed"}

    def test_the_other_checks_still_apply_after_a_verified_attestation(self, child, image_sha, tmp_path):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible()))
        with mock.patch.dict(os.environ):
            os.environ.pop(lg.ENABLE_ENV, None)
            data = _isolated_gate(child.pid, path, sample_sha256=image_sha)
        assert data["status"] == "AUTHORIZATION_REQUIRED" and data["error"] == "LAB_SWITCH_OFF"
        with mock.patch.dict(os.environ, OPEN):
            data = _isolated_gate(child.pid, path, sample_sha256="0" * 64)
            assert data["status"] == "SAMPLE_HASH_MISMATCH"
            data = _isolated_gate(child.pid, path, sample_sha256=image_sha, authorization=_auth(child.pid, "other"))
            assert data["status"] == "AUTHORIZATION_REQUIRED"
            data = _isolated_gate(child.pid, path, sample_sha256=image_sha, timeout_seconds=0)
            assert data["status"] == "BOUNDS_REQUIRED"

    def test_no_measurement_path_is_refused_as_before(self, child, image_sha, lab_open):
        data = _gate(child.pid, operation="frida_trace", sample_sha256=image_sha)
        assert data["status"] == "ISOLATION_REQUIRED" and data["error"] == "ISOLATED_GUEST_NOT_VERIFIABLE"
        assert data["isolation_verified"] is False and data["isolation"]["attestation"]["verdict"] == "UNKNOWN"
        assert data["isolation"]["attestation"]["reasons"] == ["GUEST_MEASUREMENT_NOT_SUPPLIED"]
        assert len(data["isolation"]["unmet_prerequisites"]) == 3

    def test_no_environment_variable_or_default_location_supplies_a_measurement(self, child, image_sha, lab_open,
                                                                               tmp_path, monkeypatch):
        _measurement_file(tmp_path, _fresh(_ga_admissible()), name="measure-guest.json")
        monkeypatch.chdir(tmp_path)
        for name in ("LIEBERT_RE_GUEST_MEASUREMENT", "LIEBERT_RE_MEASUREMENT", "GUEST_MEASUREMENT"):
            monkeypatch.setenv(name, str(tmp_path / "measure-guest.json"))
        data = _gate(child.pid, operation="frida_trace", sample_sha256=image_sha, local_vm_id=_GA_VM_ID)
        assert data["status"] == "ISOLATION_REQUIRED" and data["isolation_verified"] is False

    @pytest.mark.parametrize("label,mutate,verdict,error", [
        ("stale", lambda m: _fresh(m, age_s=100000), "UNKNOWN", "ISOLATED_GUEST_NOT_VERIFIABLE"),
        ("hvci_off", lambda m: _ga_with(m, "guest.security_services_running", []), "FAILED",
         "ISOLATED_GUEST_ATTESTATION_FAILED"),
        ("no_standard_checkpoint", lambda m: _ga_with(m, "checkpoints.items.0.type", "Production"), "FAILED",
         "ISOLATED_GUEST_ATTESTATION_FAILED"),
        ("public_switch", lambda m: _ga_with(m, "switches.items.0.switch_type", "External"), "FAILED",
         "ISOLATED_GUEST_ATTESTATION_FAILED"),
        ("guest_missing", lambda m: _ga_without(m, "guest"), "UNKNOWN", "ISOLATED_GUEST_NOT_VERIFIABLE"),
        ("field_missing", lambda m: _ga_without(m, "vm.state"), "UNKNOWN", "ISOLATED_GUEST_NOT_VERIFIABLE"),
        ("old_schema", lambda m: _ga_with(m, "schema_version", "liebert-re.guest-measurement/1"), "UNKNOWN",
         "ISOLATED_GUEST_NOT_VERIFIABLE"),
    ])
    def test_anything_but_verified_is_refused_with_its_reasons(self, child, image_sha, lab_open, tmp_path,
                                                               label, mutate, verdict, error):
        path = _measurement_file(tmp_path, mutate(_fresh(_ga_admissible())))
        data = _isolated_gate(child.pid, path, sample_sha256=image_sha)
        assert data["ok"] is False and data["status"] == "ISOLATION_REQUIRED" and data["error"] == error
        assert data["isolation_verified"] is False and data["isolation"]["verified"] is False
        att = data["isolation"]["attestation"]
        assert att["verdict"] == verdict and att["reasons"]
        assert all(reason in data["detail"] for reason in att["reasons"])
        assert len(data["isolation"]["unmet_prerequisites"]) == 3

    @pytest.mark.parametrize("label,payload,reason", [
        ("not_json", b"{not json", "GUEST_MEASUREMENT_NOT_JSON"),
        ("empty", b"", "GUEST_MEASUREMENT_NOT_JSON"),
        ("not_utf8", b"\xff\xfe\x00bad", "GUEST_MEASUREMENT_NOT_JSON"),
        ("nan_constant", b'{"schema_version": NaN}', "GUEST_MEASUREMENT_NOT_JSON"),
        ("array", b"[]", "MEASUREMENT_NOT_AN_OBJECT"),
        ("scalar", b"7", "MEASUREMENT_NOT_AN_OBJECT"),
        # Deep enough to exceed the json parser's recursion guard on every supported Python (3.14 parses 5000
        # levels fine and would answer NOT_AN_OBJECT; 50000 already raises there), under the 1 MiB size cap.
        pytest.param("deeply_nested", b"[" * 200_000 + b"]" * 200_000, "GUEST_MEASUREMENT_NOT_JSON",
                     id="deeply_nested"),     # an explicit id: the payload must not become the test id
    ])
    def test_a_broken_file_is_unknown(self, child, image_sha, lab_open, tmp_path, label, payload, reason):
        path = tmp_path / "broken.json"
        path.write_bytes(payload)
        data = _isolated_gate(child.pid, str(path), sample_sha256=image_sha)
        assert data["status"] == "ISOLATION_REQUIRED" and data["isolation_verified"] is False
        assert data["isolation"]["attestation"]["verdict"] == "UNKNOWN"
        assert reason in data["isolation"]["attestation"]["reasons"]

    @pytest.mark.parametrize("payload", [
        b'{"guest": {"ok": false}, "guest": {"ok": true}}',
        b'{"guest": {"ok": false, "ok": true}}',
        b'{"a": [{"x": 1, "x": 1}]}',
    ])
    def test_a_duplicate_key_at_any_level_is_unknown(self, child, image_sha, lab_open, tmp_path, payload):
        path = tmp_path / "dup.json"
        path.write_bytes(payload)
        data = _isolated_gate(child.pid, str(path), sample_sha256=image_sha)
        assert data["status"] == "ISOLATION_REQUIRED" and data["isolation_verified"] is False
        assert data["isolation"]["attestation"]["verdict"] == "UNKNOWN"
        assert "GUEST_MEASUREMENT_DUPLICATE_KEY" in data["isolation"]["attestation"]["reasons"]

    def test_a_verified_document_with_a_duplicated_key_added_is_unknown(self, child, image_sha, lab_open, tmp_path):
        text = json.dumps(_fresh(_ga_admissible()))
        path = tmp_path / "dup2.json"
        path.write_text(text[:-1] + ', "guest": {"ok": true}}', encoding="utf-8")
        data = _isolated_gate(child.pid, str(path), sample_sha256=image_sha)
        assert data["isolation_verified"] is False
        assert "GUEST_MEASUREMENT_DUPLICATE_KEY" in data["isolation"]["attestation"]["reasons"]

    def test_a_missing_directory_or_oversized_file_is_unknown(self, child, image_sha, lab_open, tmp_path):
        data = _isolated_gate(child.pid, str(tmp_path / "nowhere.json"), sample_sha256=image_sha)
        assert data["isolation"]["attestation"]["reasons"] == ["GUEST_MEASUREMENT_UNREADABLE:FileNotFoundError"]
        data = _isolated_gate(child.pid, str(tmp_path), sample_sha256=image_sha)
        assert data["isolation"]["attestation"]["verdict"] == "UNKNOWN"
        big = tmp_path / "big.json"
        big.write_bytes(b" " * (lg._MAX_MEASUREMENT_BYTES + 1))
        data = _isolated_gate(child.pid, str(big), sample_sha256=image_sha)
        assert data["isolation"]["attestation"]["reasons"] == ["GUEST_MEASUREMENT_TOO_LARGE"]
        for value in ("", "  ", 7, [], {}, None):
            data = _isolated_gate(child.pid, value, sample_sha256=image_sha)
            assert data["isolation"]["attestation"]["reasons"] == ["GUEST_MEASUREMENT_NOT_SUPPLIED"]

    def test_the_measurement_must_be_about_the_machine_the_gate_runs_on(self, child, image_sha, lab_open, tmp_path):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible()))
        for vm_id in (None, "not-a-guid", "99999999-9999-4999-8999-999999999999"):
            data = _isolated_gate(child.pid, path, sample_sha256=image_sha, local_vm_id=vm_id)
            assert data["status"] == "ISOLATION_REQUIRED" and data["isolation"]["attestation"]["verdict"] == "UNKNOWN"

    def test_the_age_limit_is_a_parameter(self, child, image_sha, lab_open, tmp_path):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible(), age_s=600))
        assert _isolated_gate(child.pid, path, sample_sha256=image_sha, max_age_s=900)["status"] == "GATE_PASSED"
        data = _isolated_gate(child.pid, path, sample_sha256=image_sha, max_age_s=300)
        assert data["status"] == "ISOLATION_REQUIRED" and "STALE_MEASUREMENT" in data["isolation"]["attestation"]["reasons"]
        for bad in (0, -1, None, "900", True):
            data = _isolated_gate(child.pid, path, sample_sha256=image_sha, max_age_s=bad)
            assert data["status"] == "ISOLATION_REQUIRED"

    def test_observation_does_not_read_the_measurement(self, child, image_sha, lab_open, tmp_path):
        data = _isolated_gate(child.pid, str(tmp_path / "nowhere.json"), operation="pe_sieve_scan",
                              sample_sha256=image_sha)
        assert data["status"] == "GATE_PASSED" and data["isolation_verified"] is False
        assert data["isolation"]["attestation"] is None and len(data["isolation"]["unmet_prerequisites"]) == 3

    def test_the_record_keeps_the_file_hash_and_no_path_or_identity(self, child, image_sha, lab_open, tmp_path):
        measurement = _fresh(_ga_admissible())
        path = _measurement_file(tmp_path, measurement, name="needle_dir_name.json")
        data = _isolated_gate(child.pid, path, sample_sha256=image_sha)
        att = data["isolation"]["attestation"]
        assert att["measurement_sha256"] == _sha(path) and att["measurement_bytes"] == os.path.getsize(path)
        text = (lg.EVIDENCE / data["evidence_name"]).read_text(encoding="utf-8")
        for secret in (str(tmp_path), "needle_dir_name", _GA_VM_ID, "lab-vm", "lab-private"):
            assert secret not in text
        assert json.loads(text)["isolation"]["attestation"]["verdict"] == "VERIFIED"

    def test_a_bom_prefixed_file_as_written_by_windows_powershell_is_read(self, child, image_sha, lab_open, tmp_path):
        path = tmp_path / "bom.json"
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps(_fresh(_ga_admissible())).encode("utf-8"))
        assert _isolated_gate(child.pid, str(path), sample_sha256=image_sha)["status"] == "GATE_PASSED"

    def test_hostile_attestation_arguments_never_raise(self):
        for value in (object(), 1.5, float("nan"), [], {}, b"x", "\x00", 10 ** 30, True):
            out = lg.dynamic_lab_gate("frida_trace", 1, None, None, 1, 1, value, value, value)
            assert isinstance(json.loads(out), dict)


class TestIsolationCli:
    def _run(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, json.loads(buf.getvalue())

    def _args(self, child, image_sha, path, *more):
        return ("labgate", "--operation", "frida_trace", "--pid", str(child.pid),
                "--authorization", json.dumps(_auth(child.pid, "frida_trace")), "--sample-sha256", image_sha,
                "--guest-measurement", path, *more)

    def test_a_verified_measurement_passes_the_gate_from_the_command_line(self, child, image_sha, lab_open, tmp_path):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible()))
        code, body = self._run(*self._args(child, image_sha, path, "--local-vm-id", _GA_VM_ID))
        assert code == 0 and body["status"] == "GATE_PASSED" and body["isolation_verified"] is True

    def test_the_command_line_refuses_without_the_vm_id_and_when_stale(self, child, image_sha, lab_open, tmp_path):
        path = _measurement_file(tmp_path, _fresh(_ga_admissible()))
        code, body = self._run(*self._args(child, image_sha, path))
        assert code == 3 and body["status"] == "ISOLATION_REQUIRED"
        assert "MISSING:local_vm_id" in body["isolation"]["attestation"]["reasons"]
        code, body = self._run(*self._args(child, image_sha, path, "--local-vm-id", _GA_VM_ID, "--max-age-s", "5"))
        assert code == 3 and "STALE_MEASUREMENT" in body["isolation"]["attestation"]["reasons"]

    def test_the_command_line_has_no_default_for_the_measurement(self, child, image_sha, lab_open):
        code, body = self._run("labgate", "--operation", "frida_trace", "--pid", str(child.pid),
                               "--authorization", json.dumps(_auth(child.pid, "frida_trace")),
                               "--sample-sha256", image_sha, "--local-vm-id", _GA_VM_ID)
        assert code == 3 and body["isolation"]["attestation"]["reasons"] == ["GUEST_MEASUREMENT_NOT_SUPPLIED"]
