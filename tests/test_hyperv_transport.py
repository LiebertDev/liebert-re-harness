"""`liebert_re.dynamic.hyperv_transport`: PowerShell Direct probe, push and pull, with a fake runner.

No PowerShell and no Hyper-V is needed: the process runner is injected, so every scenario (order,
timeout, hash mismatch, disconnect, hostile input, a script that lies) is driven by a fake that
returns what a real script run would print. The one real-VM test is marked ``heavy`` and is skipped
unless the operator names a VM, a credential file and a guest directory in the environment.

What is pinned: the script is a constant and only a short cmdlet list (no checkpoint, restore, VM
start or stop, no process start); user values travel only inside one base64 argument; the module
re-verifies every claim the script makes and answers ``UNKNOWN`` for anything it cannot confirm;
nothing identifies the credential in a result.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from liebert_re.bounded_subprocess import BoundedProcessResult
from liebert_re.dynamic import hyperv_transport as hvt
from liebert_re.dynamic.hyperv_transport import ERROR_CLASSES, HypervTransport

contract = pytest.mark.contract

VM = "Test VM"
SESSION_PHASES = ["decode", "credential", "vm", "session", "session_open"]
HOSTILE = [
    'x"; calc; $(calc) `Get-Process` \'--',
    "a;b",
    "$(whoami)",
    "`n`r",
    "'; Remove-Item C:\\ -Recurse #",
    "%COMSPEC% & calc",
    "-VMName",
]


# --------------------------------------------------------------------------------- the fake runner


class FakePS:
    """Records every call and answers from ``handler(request, argv)``."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv, timeout):
        blob = argv[argv.index("-RequestB64") + 1]
        script_path = Path(argv[argv.index("-File") + 1])
        call = {
            "argv": list(argv), "timeout": timeout, "blob": blob,
            "request": json.loads(base64.b64decode(blob)),
            "script_path": script_path, "script_text": script_path.read_text(encoding="ascii"),
            "script_existed": script_path.is_file(),
        }
        self.calls.append(call)
        return self.handler(call["request"], argv)


def result_line(op, ok, phase, data=None, failure=None):
    return "LIEBERT_RESULT " + json.dumps({
        "schema": "liebert-re.hyperv-transport-result/1", "op": op, "ok": ok, "phase": phase,
        "failure": failure, "data": data or {},
    })


def proc(lines, returncode=0, **flags):
    return BoundedProcessResult(returncode, "\n".join(lines) + "\n", "", **flags)


def phases_to(last):
    return ["LIEBERT_PHASE " + p for p in hvt._PHASES[: hvt._PHASES.index(last) + 1]]


def failure(code=None, category=None, exception_type=None, auth=False, timeout=False):
    return {"code": code, "category": category, "error_id": None, "exception_type": exception_type,
            "auth_hint": auth, "timeout_hint": timeout}


def fail_proc(op, phase, **kw):
    return proc(phases_to(phase) + [result_line(op, False, phase, failure=failure(**kw))], returncode=1)


def probe_ok(req, argv=None):
    return proc(phases_to("probe") + [result_line("probe", True, "probe", {
        "vm_state": "Running", "guest_computer_name": "GUEST01", "guest_user": "GUEST01\\Op",
        "guest_ps_version": "5.1.22621.3880"})])


@pytest.fixture
def cred(tmp_path):
    return str(tmp_path / "guest.cred")


def make(cred, handler, **kw):
    fake = FakePS(handler)
    return HypervTransport(cred, runner=fake, powershell="powershell.exe", **kw), fake


def assert_never_ok(result):
    assert result["ok"] is False and result["status"] != "OK"
    assert result["error_class"] in ERROR_CLASSES


# --------------------------------------------------------------------------------- the script


def _code(text):
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


ALLOWED = frozenset({
    "Import-Clixml", "Get-VM", "Where-Object", "ForEach-Object", "New-PSSession", "Remove-PSSession",
    "Invoke-Command", "Get-FileHash", "Copy-Item", "Move-Item", "Remove-Item", "New-Object",
    "ConvertTo-Json", "ConvertFrom-Json",
})
FORBIDDEN = (
    "Restore-VMSnapshot", "Checkpoint-VM", "Stop-VM", "Start-VM", "Restart-VM", "Suspend-VM", "Save-VM",
    "Set-VM", "Remove-VM", "Remove-VMSnapshot", "Import-VM", "Export-VM", "Connect-VMNetworkAdapter",
    "Disconnect-VMNetworkAdapter", "Start-Process", "Invoke-Expression", "Add-Type", "Enter-PSSession",
)


@contract
def test_script_is_ascii_and_hash_is_stable():
    assert hvt._SCRIPT.isascii()
    assert hvt._script_sha256() == hashlib.sha256(hvt._SCRIPT.encode("ascii")).hexdigest()


@contract
def test_script_uses_only_the_allowed_cmdlets_and_none_that_touch_the_vm_state():
    used = set(re.findall(r"\b[A-Z][A-Za-z]+-[A-Z][A-Za-z]+\b", _code(hvt._SCRIPT)))
    assert used <= ALLOWED, sorted(used - ALLOWED)
    for name in FORBIDDEN:
        assert name.lower() not in hvt._SCRIPT.lower(), name
    # no checkpoint, restore, shutdown or start wording anywhere in the executable text
    assert not re.search(r"snapshot|checkpoint|stop-vm|start-vm|\biex\b|-EncodedCommand|\.Invoke\(|\[scriptblock\]::Create",
                         _code(hvt._SCRIPT), re.IGNORECASE)


@contract
def test_script_remote_work_runs_only_in_the_one_session_and_deletes_only_its_own_partial():
    code = _code(hvt._SCRIPT)
    assert code.count("Invoke-Command") == code.count("Invoke-Command -Session $session")
    for match in re.finditer(r"Remove-Item[^\n]*", code):
        assert "-LiteralPath $partial" in match.group(0)
    for match in re.finditer(r"(?:Copy|Move)-Item[^\n]*", code):
        assert "-LiteralPath" in match.group(0)
    # no value is interpolated into a command: no string is ever executed
    assert "Invoke-Expression" not in code and "& $" not in code and "&(" not in code


@contract
def test_module_reads_no_environment_and_never_opens_the_credential():
    source = Path(hvt.__file__).read_text(encoding="utf-8")
    assert not re.search(r"os\.environ|getenv|putenv", source)
    assert not re.search(r"open\([^)]*cred", source, re.IGNORECASE)
    assert not re.search(r"[A-Za-z]:\\\\Users|\.liebert-guest", source)


def _powershell():
    return shutil.which("powershell") or shutil.which("pwsh")


@pytest.mark.skipif(_powershell() is None, reason="no PowerShell on this machine")
def test_script_parses_as_powershell(tmp_path):
    script = tmp_path / "transport.ps1"
    script.write_text(hvt._SCRIPT, encoding="ascii")
    probe = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
             "$env:LR_PARSE_TARGET,[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
    done = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", probe],
                          capture_output=True, text=True, timeout=60,
                          env={**os.environ, "LR_PARSE_TARGET": str(script)})
    assert done.returncode == 0, done.stdout[:400]


# --------------------------------------------------------------------------------- construction


@contract
def test_constructor_rejects_bad_arguments(tmp_path, cred):
    for bad in ("", "relative.cred", "guest.cred"):
        with pytest.raises(ValueError):
            HypervTransport(bad)
    for kw in ({"probe_timeout_s": 0}, {"transfer_timeout_s": float("nan")}, {"probe_timeout_s": True},
               {"transfer_timeout_s": float("inf")}, {"max_push_bytes": 0}, {"max_pull_files": 0},
               {"max_pull_files": 33}, {"max_pull_file_bytes": -1}, {"max_pull_total_bytes": 1.5}):
        with pytest.raises(ValueError):
            HypervTransport(cred, **kw)


@contract
def test_repr_hides_the_credential_path(cred):
    assert cred not in repr(HypervTransport(cred))


# --------------------------------------------------------------------------------- probe


@contract
def test_probe_ok_reports_measured_values_only(cred):
    transport, fake = make(cred, probe_ok)
    result = transport.probe(VM)
    assert result["ok"] is True and result["status"] == "OK" and result["error_class"] is None
    assert result["measured"] == {"ready": True, "guest_computer_name": "GUEST01", "guest_user": "GUEST01\\Op",
                                  "guest_powershell_version": "5.1.22621.3880", "vm_state": "Running"}
    assert len(fake.calls) == 1 and fake.calls[0]["request"]["op"] == "probe"
    assert result["script_sha256"] == hvt._script_sha256()


@contract
@pytest.mark.parametrize("data", [
    {}, {"vm_state": "Off", "guest_computer_name": "G", "guest_user": "U", "guest_ps_version": "5.1"},
    {"vm_state": "Running", "guest_computer_name": "", "guest_user": "U", "guest_ps_version": "5.1"},
    {"vm_state": "Running", "guest_computer_name": "G", "guest_user": "U", "guest_ps_version": "x; calc"},
    {"vm_state": "Running", "guest_computer_name": "G\x00", "guest_user": "U", "guest_ps_version": "5.1"},
    {"vm_state": "Running", "guest_computer_name": 5, "guest_user": "U", "guest_ps_version": "5.1"},
])
def test_probe_with_invalid_data_is_unknown_not_ready(cred, data):
    transport, _ = make(cred, lambda r, a: proc(phases_to("probe") + [result_line("probe", True, "probe", data)]))
    result = transport.probe(VM)
    assert_never_ok(result)
    assert result["error_class"] == "UNKNOWN" and result["measured"]["ready"] is False


@contract
@pytest.mark.parametrize("phase, kw, expected", [
    ("credential", {"exception_type": "FileNotFoundException"}, ("AUTH_FAILED", "CREDENTIAL_UNUSABLE")),
    ("credential", {"code": "CREDENTIAL_INVALID"}, ("AUTH_FAILED", "CREDENTIAL_INVALID")),
    ("session", {"auth": True}, ("AUTH_FAILED", "SESSION_AUTH_REJECTED")),
    ("session", {"category": "AuthenticationError"}, ("AUTH_FAILED", "SESSION_AUTH_REJECTED")),
    ("session", {"timeout": True}, ("PSDIRECT_TIMEOUT", "SESSION_OPEN_TIMEOUT")),
    ("session", {"category": "OpenError"}, ("UNKNOWN", "SESSION_OPEN_FAILED")),
    ("vm", {"code": "VM_NOT_RUNNING"}, ("UNKNOWN", "VM_NOT_RUNNING")),
    ("vm", {"code": "VM_NOT_FOUND"}, ("UNKNOWN", "VM_NOT_FOUND")),
    ("vm", {"code": "VM_NOT_UNIQUE"}, ("UNKNOWN", "VM_NOT_UNIQUE")),
    ("vm", {"category": "PermissionDenied"}, ("UNKNOWN", "UNMAPPED_FAILURE")),
    ("probe", {"exception_type": "PSRemotingTransportException"}, ("UNKNOWN", "SESSION_LOST")),
    ("probe", {}, ("UNKNOWN", "UNMAPPED_FAILURE")),
])
def test_probe_failure_phases_map_to_classes(cred, phase, kw, expected):
    transport, _ = make(cred, lambda r, a: fail_proc("probe", phase, **kw))
    result = transport.probe(VM)
    assert (result["error_class"], result["reason"]) == expected
    assert result["status"] == ("UNKNOWN" if expected[0] == "UNKNOWN" else "FAILED")
    assert result["measured"]["ready"] is False


@contract
def test_probe_process_timeout_is_psdirect_timeout_at_any_phase(cred):
    transport, fake = make(cred, lambda r, a: proc(phases_to("session_open"), None, timed_out=True), probe_timeout_s=7)
    result = transport.probe(VM)
    assert result["error_class"] == "PSDIRECT_TIMEOUT" and result["status"] == "FAILED"
    assert fake.calls[0]["timeout"] == 7.0
    assert result["last_phase"] == "session_open"


@contract
def test_per_call_timeout_overrides_and_is_validated(cred):
    transport, fake = make(cred, probe_ok)
    transport.probe(VM, timeout_s=3)
    assert fake.calls[0]["timeout"] == 3
    for bad in (0, -1, float("nan"), "5", True):
        assert transport.probe(VM, timeout_s=bad)["error_class"] == "UNKNOWN"
    assert len(fake.calls) == 1


@contract
def test_unusable_runner_outcomes_are_unknown(cred, monkeypatch):
    def boom(argv, timeout):
        raise OSError("disk fell off")
    result = HypervTransport(cred, runner=boom, powershell="powershell.exe").probe(VM)
    assert_never_ok(result)
    assert result["reason"].startswith("RUNNER_FAULT")
    launch = HypervTransport(cred, runner=lambda a, t: BoundedProcessResult(None, "", "", launch_failed=True,
                                                                           launch_error="x"), powershell="p")
    assert launch.probe(VM)["reason"] == "POWERSHELL_LAUNCH_FAILED"
    monkeypatch.setattr(hvt.shutil, "which", lambda name: None)
    missing = HypervTransport(cred).probe(VM)
    assert missing["reason"] == "POWERSHELL_UNAVAILABLE" and missing["status"] == "UNKNOWN"


@contract
@pytest.mark.parametrize("name", ["", "   ", "x" * 101, "a\x00b", "a\nb", 5, None, "a\u202eb"])
def test_malformed_vm_name_is_rejected_before_any_process(cred, name):
    transport, fake = make(cred, probe_ok)
    result = transport.probe(name)
    assert result["error_class"] == "PATH_REJECTED" and result["reason"] == "VM_NAME_REJECTED"
    assert fake.calls == []


# --------------------------------------------------------------------------------- strict output reading


GOOD_RESULT = result_line("probe", True, "probe", {
    "vm_state": "Running", "guest_computer_name": "G", "guest_user": "U", "guest_ps_version": "5.1"})
DUP = ('LIEBERT_RESULT {"schema": "liebert-re.hyperv-transport-result/1", "op": "probe", "ok": true, '
       '"ok": false, "phase": "probe", "failure": null, "data": {}}')


@contract
@pytest.mark.parametrize("label, build", [
    ("no result", lambda: proc(phases_to("probe"))),
    ("empty output", lambda: proc([])),
    ("two results", lambda: proc([GOOD_RESULT, GOOD_RESULT])),
    ("duplicate key", lambda: proc([DUP])),
    ("not json", lambda: proc(["LIEBERT_RESULT {nope"])),
    ("nan", lambda: proc(['LIEBERT_RESULT {"schema": NaN}'])),
    ("wrong schema", lambda: proc([GOOD_RESULT.replace("transport-result/1", "transport-result/2")])),
    ("ok not bool", lambda: proc([GOOD_RESULT.replace('"ok": true', '"ok": "true"')])),
    ("wrong operation", lambda: proc([GOOD_RESULT.replace('"op": "probe"', '"op": "push"')])),
    ("ok with exit 1", lambda: proc([GOOD_RESULT], returncode=1)),
    ("failure with exit 0", lambda: proc([result_line("probe", False, "vm", failure=failure(code="X"))], 0)),
    ("truncated output", lambda: proc([GOOD_RESULT], output_truncated=True)),
    ("died without result", lambda: proc(phases_to("session_open"), returncode=-1)),
    ("failure not described", lambda: proc([result_line("probe", False, "vm")], 1)),
    ("hostile free-text failure", lambda: proc([result_line("probe", False, "vm", failure={
        "code": "x; calc", "category": "Cat egory", "exception_type": "A B"})], 1)),
])
def test_anything_the_module_cannot_confirm_is_unknown_never_ok(cred, label, build):
    transport, _ = make(cred, lambda r, a: build())
    result = transport.probe(VM)
    assert_never_ok(result)
    assert result["error_class"] == "UNKNOWN", label
    assert result["status"] == "UNKNOWN"
    assert "calc" not in json.dumps(result)


@contract
def test_a_result_line_hidden_in_ordinary_output_is_still_counted(cred):
    junk = "noise LIEBERT_RESULT {}"  # not at line start: ignored, so only the real line counts
    transport, _ = make(cred, lambda r, a: proc([junk, "LIEBERT_PHASE not-a-phase", GOOD_RESULT]))
    assert transport.probe(VM)["ok"] is True


# --------------------------------------------------------------------------------- injection


@contract
def test_hostile_vm_names_travel_as_data_and_never_change_script_or_argv_shape(cred):
    transport, fake = make(cred, probe_ok)
    for value in HOSTILE:
        assert transport.probe(value)["ok"] is True
    assert len(fake.calls) == len(HOSTILE)
    baseline = fake.calls[0]
    for value, call in zip(HOSTILE, fake.calls):
        assert call["request"]["vm"] == value
        assert call["script_text"].replace("\r\n", "\n") == hvt._SCRIPT
        assert call["script_text"] == baseline["script_text"]
        assert re.fullmatch(r"[A-Za-z0-9+/=]+", call["blob"])
        assert [a for a in call["argv"] if a != call["blob"] and a != str(call["script_path"])] == [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            "-RequestB64"]
        assert all(value not in part for part in call["argv"])


@contract
def test_hostile_paths_travel_as_data_in_push_and_pull(cred, tmp_path):
    hostile_name = "a;b$(calc)`x'y.txt"
    src = tmp_path / hostile_name
    src.write_bytes(b"payload")
    sha = hashlib.sha256(b"payload").hexdigest()
    guest_dir = "C:\\Lab;$(calc)`\\in'x"

    def push(req, argv):
        return proc(phases_to("guest_verify") + [result_line("push", True, "guest_verify", {
            "guest_path": req["guest_dir"] + "\\" + req["guest_name"], "guest_sha256": sha, "guest_size": 7})])

    transport, fake = make(cred, push)
    result = transport.push_file(VM, src, guest_dir)
    assert result["ok"] is True, result
    request = fake.calls[0]["request"]
    assert request["guest_name"] == hostile_name and request["guest_dir"] == guest_dir
    assert request["host_path"] == str(src)
    for part in fake.calls[0]["argv"]:
        assert "calc" not in part and ";" not in part.replace(str(fake.calls[0]["script_path"]), "")
    assert fake.calls[0]["script_text"].replace("\r\n", "\n") == hvt._SCRIPT


@contract
def test_credential_path_travels_as_data_and_never_appears_in_any_result(tmp_path):
    hostile_cred = str(tmp_path / "c;$(calc)`.xml")
    seen = []

    def handler(req, argv):
        seen.append(req)
        return fail_proc("probe", "credential", exception_type="FileNotFoundException")

    transport = HypervTransport(hostile_cred, runner=FakePS(handler), powershell="powershell.exe")
    for result in (transport.probe(VM), transport.push_file(VM, tmp_path / "missing", "C:\\Lab")):
        text = json.dumps(result)
        assert hostile_cred not in text and "calc" not in text and "password" not in text.lower()
    assert seen[0]["credential_path"] == hostile_cred
    assert set(seen[0]) == {"op", "vm", "credential_path", "run_id"}  # no secret-looking field exists


# --------------------------------------------------------------------------------- push


def _push_handler(src_bytes, *, guest_sha=None, guest_size=None, guest_path=None, after=None):
    def handler(req, argv):
        if after:
            after()
        return proc(phases_to("guest_verify") + [result_line("push", True, "guest_verify", {
            "host_sha256": req["host_sha256"],
            "guest_path": guest_path or (req["guest_dir"] + "\\" + req["guest_name"]),
            "guest_sha256": guest_sha or hashlib.sha256(src_bytes).hexdigest(),
            "guest_size": len(src_bytes) if guest_size is None else guest_size})])
    return handler


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"liebert transport sample\n")
    return path


@contract
def test_push_hashes_the_host_first_then_checks_the_guest_value(cred, sample):
    data = sample.read_bytes()
    order = []

    def handler(req, argv):
        order.append(("runner", req["host_sha256"]))
        return _push_handler(data)(req, argv)

    transport, fake = make(cred, handler)
    result = transport.push_file(VM, sample, "C:\\Lab\\in\\")
    assert result["ok"] is True and result["status"] == "OK"
    assert order == [("runner", hashlib.sha256(data).hexdigest())]  # the host digest was already in the request
    assert result["measured"] == {
        "host_sha256": hashlib.sha256(data).hexdigest(), "host_size": len(data),
        "guest_sha256": hashlib.sha256(data).hexdigest(), "guest_size": len(data),
        "guest_path": "C:\\Lab\\in\\sample.txt", "hashes_equal": True}
    request = fake.calls[0]["request"]
    assert request["guest_dir"] == "C:\\Lab\\in" and request["overwrite"] is False
    assert not fake.calls[0]["script_path"].exists()  # the temporary script is removed afterwards
    assert fake.calls[0]["script_existed"] is True


@contract
def test_push_guest_hash_that_differs_is_hash_mismatch_even_if_the_script_said_ok(cred, sample):
    transport, _ = make(cred, _push_handler(sample.read_bytes(), guest_sha="0" * 64))
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert result["error_class"] == "HASH_MISMATCH" and result["status"] == "FAILED"
    transport, _ = make(cred, _push_handler(sample.read_bytes(), guest_size=3))
    assert transport.push_file(VM, sample, "C:\\Lab")["error_class"] == "HASH_MISMATCH"


@contract
def test_push_script_reported_mismatch_keeps_both_digests_and_the_cleanup_fact(cred, sample):
    def handler(req, argv):
        return proc(phases_to("guest_verify") + [result_line("push", False, "guest_verify", {
            "guest_sha256": "a" * 64, "guest_size": 9, "partial_removed": True}, failure(code="GUEST_HASH_MISMATCH"))], 1)
    transport, _ = make(cred, handler)
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("HASH_MISMATCH", "GUEST_HASH_MISMATCH")
    assert result["measured"]["guest_sha256"] == "a" * 64 and result["measured"]["partial_removed"] is True
    assert result["measured"]["host_sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()


@contract
def test_push_host_file_changed_during_the_copy_is_not_reported_as_transferred(cred, sample):
    data = sample.read_bytes()
    transport, _ = make(cred, _push_handler(data, after=lambda: sample.write_bytes(b"changed underneath")))
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("HASH_MISMATCH", "HOST_FILE_CHANGED")


@contract
@pytest.mark.parametrize("kw, expected", [
    ({"code": "GUEST_DIR_MISSING"}, ("TRANSFER_FAILED", "GUEST_DIR_MISSING")),
    ({"code": "GUEST_FILE_EXISTS"}, ("TRANSFER_FAILED", "GUEST_FILE_EXISTS")),
    ({"code": "GUEST_PATH_REPARSE"}, ("PATH_REJECTED", "GUEST_PATH_REPARSE")),
    ({"code": "HOST_FILE_CHANGED"}, ("HASH_MISMATCH", "HOST_FILE_CHANGED")),
    ({"exception_type": "PSRemotingTransportException"}, ("TRANSFER_FAILED", "SESSION_LOST")),
    ({"category": "ConnectionError"}, ("TRANSFER_FAILED", "SESSION_LOST")),
    ({"exception_type": "IOException"}, ("TRANSFER_FAILED", "COPY_FAILED")),
])
def test_push_disconnect_and_failures_during_the_copy(cred, sample, kw, expected):
    transport, _ = make(cred, lambda r, a: fail_proc("push", "copy", **kw))
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == expected
    assert result["ok"] is False


@contract
def test_push_timeouts_before_and_after_the_session_opened(cred, sample):
    before = make(cred, lambda r, a: proc(phases_to("session"), None, timed_out=True))[0]
    assert before.push_file(VM, sample, "C:\\Lab")["error_class"] == "PSDIRECT_TIMEOUT"
    after, _ = make(cred, lambda r, a: proc(phases_to("copy"), None, timed_out=True))
    result = after.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("TRANSFER_FAILED", "TIMEOUT_AFTER_SESSION_OPEN")
    assert result["measured"]["guest_state"] == "UNKNOWN"


@contract
def test_push_process_that_dies_mid_copy_is_unknown(cred, sample):
    transport, _ = make(cred, lambda r, a: proc(phases_to("copy"), returncode=-1073741510))
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["status"], result["last_phase"]) == ("UNKNOWN", "UNKNOWN", "copy")


@contract
def test_push_reported_guest_path_that_is_not_the_expected_one_is_unknown(cred, sample):
    transport, _ = make(cred, _push_handler(sample.read_bytes(), guest_path="C:\\Windows\\sample.txt"))
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("UNKNOWN", "GUEST_PATH_MISMATCH")


@contract
def test_push_over_quota_never_starts_powershell(cred, sample):
    transport, fake = make(cred, probe_ok, max_push_bytes=5)
    result = transport.push_file(VM, sample, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("QUOTA_EXCEEDED", "HOST_FILE_OVER_QUOTA")
    assert fake.calls == []


@contract
@pytest.mark.parametrize("guest_dir", [
    "Lab", "\\Lab", "C:Lab", "C:\\", "C:\\..\\Windows", "C:\\Lab\\..\\..", "C:\\Lab\\.", "C:\\Lab\\a:b",
    "C:\\Lab\\a:b:$DATA", "\\\\server\\share\\x", "\\\\?\\C:\\Lab", "C:/Lab", "C:\\Lab\\*", "C:\\La?b",
    "C:\\Lab\\CON", "C:\\Lab\\nul.txt", "C:\\Lab\\x ", "C:\\Lab\\x.", "C:\\Lab\\\\x", "C:\\Lab\\a\x00b",
    "C:\\Lab\\a|b", "C:\\" + "d\\" * 140, "", None, 7, "C:\\Lab\\<x>",
])
def test_push_rejects_bad_guest_directories_before_any_process(cred, sample, guest_dir):
    transport, fake = make(cred, probe_ok)
    result = transport.push_file(VM, sample, guest_dir)
    assert result["error_class"] == "PATH_REJECTED", result
    assert fake.calls == []


@contract
def test_push_rejects_bad_host_files_before_any_process(cred, tmp_path):
    transport, fake = make(cred, probe_ok)
    folder = tmp_path / "dir"
    folder.mkdir()
    cases = [tmp_path / "missing.txt", folder, "relative.txt", "", None, 3.5, str(tmp_path / "a.txt:stream"),
             str(tmp_path / "x") + "\x00"]
    for case in cases:
        assert transport.push_file(VM, case, "C:\\Lab")["error_class"] == "PATH_REJECTED", case
    assert fake.calls == []
    for name in ("CON.txt", "trail.", "x" * 129):
        path = tmp_path / name
        try:
            path.write_bytes(b"x")
        except OSError:
            continue
        assert transport.push_file(VM, path, "C:\\Lab")["error_class"] == "PATH_REJECTED"
    assert fake.calls == []


@contract
def test_push_rejects_a_symlinked_host_file(cred, sample, tmp_path):
    link = tmp_path / "link.txt"
    try:
        os.symlink(sample, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available to this user")
    transport, fake = make(cred, probe_ok)
    result = transport.push_file(VM, link, "C:\\Lab")
    assert (result["error_class"], result["reason"]) == ("PATH_REJECTED", "HOST_FILE_REPARSE_POINT")
    assert fake.calls == []


@contract
def test_push_flags_must_be_booleans(cred, sample):
    transport, fake = make(cred, probe_ok)
    assert transport.push_file(VM, sample, "C:\\Lab", overwrite="yes")["error_class"] == "PATH_REJECTED"
    assert fake.calls == []


# --------------------------------------------------------------------------------- pull


def _pull_handler(contents, *, claim=None, status="COPIED", ok=True, failure_=None, phase="copy", rows_only=None):
    """Fake that writes each ``contents[i]`` to the host partial name and reports it."""
    def handler(req, argv):
        rows = []
        for index, data in enumerate(contents):
            claimed = (claim or {}).get(index, data if data is not None else b"?")
            rows.append({"index": index, "status": status, "code": None, "size": len(claimed),
                         "sha256": hashlib.sha256(claimed).hexdigest()})
            if data is not None and status == "COPIED":
                Path(req["host_dir"], req["partial_names"][index]).write_bytes(data)
        if rows_only is not None:
            rows = rows[:rows_only]
        line = result_line("pull", ok, phase, {"files": rows}, failure_)
        return proc(phases_to(phase) + [line], 0 if ok else 1)
    return handler


@pytest.fixture
def outdir(tmp_path):
    path = tmp_path / "out"
    path.mkdir()
    return path


@contract
def test_pull_names_are_generated_on_the_host_and_every_file_is_verified(cred, outdir):
    contents = [b"alpha", b"", b"gamma" * 100]
    guest = ["C:\\Lab\\out\\evil;$(calc).log", "C:\\Lab\\out\\empty.json", "C:\\Lab\\out\\..hidden"]
    guest[2] = "C:\\Lab\\out\\a.dmp"
    transport, fake = make(cred, _pull_handler(contents))
    result = transport.pull_files(VM, guest, outdir)
    assert result["ok"] is True and result["status"] == "OK", result
    files = result["measured"]["files"]
    assert [f["status"] for f in files] == ["VERIFIED"] * 3 and result["measured"]["verified"] == 3
    names = sorted(p.name for p in outdir.iterdir())
    assert names == sorted(Path(f["host_path"]).name for f in files)
    assert all(re.fullmatch(r"[0-9a-f]{12}-\d{3}\.guestfile", n) for n in names)
    assert not any(".partial" in n or "calc" in n or "evil" in n for n in names)
    for entry, data in zip(files, contents):
        assert Path(entry["host_path"]).read_bytes() == data
        assert entry["sha256"] == hashlib.sha256(data).hexdigest() and entry["size"] == len(data)
    assert result["measured"]["verified_bytes"] == sum(len(c) for c in contents)
    request = fake.calls[0]["request"]
    assert request["guest_paths"] == guest and request["indexes"] == [0, 1, 2]
    assert request["max_file_bytes"] == 32 * 1024 * 1024


@contract
def test_pull_hash_mismatch_leaves_nothing_behind_and_keeps_earlier_good_files(cred, outdir):
    contents = [b"good", b"tampered"]
    transport, _ = make(cred, _pull_handler(contents, claim={1: b"claimed!"}))
    result = transport.pull_files(VM, ["C:\\Lab\\a.log", "C:\\Lab\\b.log"], outdir)
    assert (result["error_class"], result["reason"]) == ("HASH_MISMATCH", "SHA256_MISMATCH")
    statuses = [f["status"] for f in result["measured"]["files"]]
    assert statuses == ["VERIFIED", "REJECTED"] and result["measured"]["verified"] == 1
    left = sorted(p.name for p in outdir.iterdir())
    assert len(left) == 1 and left[0].endswith("-000.guestfile")


@contract
def test_pull_size_mismatch_and_host_size_over_quota(cred, outdir):
    transport, _ = make(cred, _pull_handler([b"12345"], claim={0: b"123456"}))
    assert transport.pull_files(VM, ["C:\\Lab\\a"], outdir)["reason"] == "SIZE_MISMATCH"
    # the guest claims 3 bytes but 40 arrive: the host measures, and the quota is judged on the host value
    transport, _ = make(cred, _pull_handler([b"x" * 40], claim={0: b"abc"}), max_pull_file_bytes=10)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("QUOTA_EXCEEDED", "HOST_SIZE_OVER_QUOTA")
    assert list(outdir.iterdir()) == []


@contract
def test_pull_total_quota_is_enforced_on_measured_host_bytes(cred, outdir):
    transport, _ = make(cred, _pull_handler([b"x" * 6, b"y" * 6]), max_pull_total_bytes=10)
    result = transport.pull_files(VM, ["C:\\Lab\\a", "C:\\Lab\\b"], outdir)
    assert result["error_class"] == "QUOTA_EXCEEDED"
    assert [f["status"] for f in result["measured"]["files"]] == ["VERIFIED", "REJECTED"]


@contract
def test_pull_script_quota_and_path_codes_map_to_classes_per_file(cred, outdir):
    def handler(req, argv):
        rows = [{"index": 0, "status": "STATED", "code": None, "size": 3},
                {"index": 1, "status": "REJECTED", "code": "GUEST_PATH_REPARSE", "size": None},
                {"index": 2, "status": "REJECTED", "code": "FILE_TOO_LARGE", "size": 999999999}]
        return proc(phases_to("guest_stat") + [result_line("pull", False, "guest_stat", {"files": rows},
                                                            failure(code="GUEST_PATH_REPARSE"))], 1)
    transport, _ = make(cred, handler)
    result = transport.pull_files(VM, ["C:\\a", "C:\\b", "C:\\c"], outdir)
    assert (result["error_class"], result["reason"]) == ("PATH_REJECTED", "GUEST_PATH_REPARSE")
    classes = [f["error_class"] for f in result["measured"]["files"]]
    assert classes == [None, "PATH_REJECTED", "QUOTA_EXCEEDED"]
    assert result["measured"]["verified"] == 0 and list(outdir.iterdir()) == []


@contract
@pytest.mark.parametrize("code, expected", [
    ("GUEST_FILE_MISSING", "TRANSFER_FAILED"), ("GUEST_NOT_A_FILE", "PATH_REJECTED"),
    ("TOTAL_TOO_LARGE", "QUOTA_EXCEEDED"), ("GUEST_FILE_CHANGED", "HASH_MISMATCH"),
    ("COPY_FAILED", "TRANSFER_FAILED"), ("SOMETHING_NEW", "UNKNOWN"),
])
def test_pull_script_failure_codes(cred, outdir, code, expected):
    transport, _ = make(cred, lambda r, a: proc(phases_to("copy") + [result_line("pull", False, "copy", {"files": []},
                                                                                 failure(code=code))], 1))
    assert transport.pull_files(VM, ["C:\\Lab\\a"], outdir)["error_class"] == expected


@contract
def test_pull_disconnect_removes_partial_files_and_reports_transfer_failed(cred, outdir):
    def handler(req, argv):
        Path(req["host_dir"], req["partial_names"][0]).write_bytes(b"half")  # a file the session never finished
        return fail_proc("pull", "copy", exception_type="PSRemotingTransportException")
    transport, _ = make(cred, handler)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("TRANSFER_FAILED", "SESSION_LOST")
    assert list(outdir.iterdir()) == []


@contract
def test_pull_timeout_after_session_open_is_transfer_failed_with_unknown_guest_state(cred, outdir):
    def handler(req, argv):
        Path(req["host_dir"], req["partial_names"][0]).write_bytes(b"half")
        return proc(phases_to("copy"), None, timed_out=True)
    transport, _ = make(cred, handler)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert result["error_class"] == "TRANSFER_FAILED" and result["measured"]["guest_state_unknown"] is True
    assert list(outdir.iterdir()) == []
    early = make(cred, lambda r, a: proc(phases_to("vm"), None, timed_out=True))[0]
    assert early.pull_files(VM, ["C:\\Lab\\a"], outdir)["error_class"] == "PSDIRECT_TIMEOUT"


@contract
@pytest.mark.parametrize("label, kwargs", [
    ("claims ok with a missing row", {"rows_only": 1}),
    ("claims ok but not copied", {"status": "HASHED"}),
])
def test_pull_ok_claims_the_host_cannot_confirm_are_unknown(cred, outdir, label, kwargs):
    transport, _ = make(cred, _pull_handler([b"a", b"b"], **kwargs))
    result = transport.pull_files(VM, ["C:\\Lab\\a", "C:\\Lab\\b"], outdir)
    assert_never_ok(result)
    assert result["error_class"] == "UNKNOWN", label


@contract
def test_pull_claimed_file_that_never_arrived_is_not_ok(cred, outdir):
    transport, _ = make(cred, _pull_handler([None]))
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("TRANSFER_FAILED", "HOST_FILE_MISSING")


@contract
@pytest.mark.parametrize("guest_path", [
    "C:\\Lab\\..\\Windows\\x", "C:\\Lab\\..", "C:\\Lab\\a:ads", "C:\\Lab\\a.txt:$DATA", "C:\\Lab\\*.log",
    "C:\\Lab\\a?.log", "\\\\host\\share\\a", "\\\\?\\C:\\a", "\\\\.\\PhysicalDrive0",
    "C:\\Lab\\NUL", "C:\\Lab\\com1.txt", "C:\\Lab\\a.txt ", "C:\\Lab\\a.", "relative\\a", "a.txt", "C:/Lab/a",
    "C:\\Lab\\\\a", "C:\\Lab\\a\x00", "C:\\Lab\\a\n", "C:\\Lab\\", "C:\\", "", None, 5,
    "C:\\" + "x\\" * 200,
])
def test_pull_rejects_bad_guest_paths_before_any_process(cred, outdir, guest_path):
    transport, fake = make(cred, probe_ok)
    result = transport.pull_files(VM, ["C:\\Lab\\fine.log", guest_path], outdir)
    assert result["error_class"] == "PATH_REJECTED", result
    assert fake.calls == [] and list(outdir.iterdir()) == []


@contract
def test_pull_rejects_bad_lists_and_directories(cred, outdir, tmp_path):
    transport, fake = make(cred, probe_ok)
    assert transport.pull_files(VM, "C:\\Lab\\a.log", outdir)["error_class"] == "PATH_REJECTED"  # a bare string
    assert transport.pull_files(VM, [], outdir)["error_class"] == "PATH_REJECTED"
    assert transport.pull_files(VM, None, outdir)["error_class"] == "PATH_REJECTED"
    assert transport.pull_files(VM, ["C:\\a", "c:\\A"], outdir)["reason"] == "DUPLICATE_GUEST_PATH"
    too_many = [f"C:\\Lab\\f{i}" for i in range(17)]
    assert transport.pull_files(VM, too_many, outdir)["error_class"] == "QUOTA_EXCEEDED"
    for bad_dir in (tmp_path / "nope", tmp_path / "sample.txt", "relative", "", None, str(outdir) + "\x00",
                    str(outdir / "x:y")):
        assert transport.pull_files(VM, ["C:\\Lab\\a"], bad_dir)["error_class"] == "PATH_REJECTED", bad_dir
    assert fake.calls == []


@contract
def test_pull_rejects_a_symlinked_host_directory(cred, outdir, tmp_path):
    link = tmp_path / "linkdir"
    try:
        os.symlink(outdir, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available to this user")
    transport, fake = make(cred, probe_ok)
    assert transport.pull_files(VM, ["C:\\Lab\\a"], link)["error_class"] == "PATH_REJECTED"
    assert fake.calls == []


def _make_dir_link(link, target):
    """A symlink, or on Windows a junction (needs no privilege); skips the test when neither works."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if done.returncode == 0:
            return
    pytest.skip("neither symlinks nor junctions are available to this user")


@contract
def test_pull_rejects_a_host_dir_whose_parent_is_a_link_not_only_the_last_component(cred, outdir, tmp_path):
    real = outdir / "real"
    (real / "inner").mkdir(parents=True)
    link = tmp_path / "linkparent"
    _make_dir_link(link, real)
    transport, fake = make(cred, probe_ok)
    # the last component (inner) is an ordinary directory; its parent is the link
    for target in (link / "inner", link):
        result = transport.pull_files(VM, ["C:\\Lab\\a"], target)
        assert (result["error_class"], result["reason"]) == ("PATH_REJECTED", "HOST_DIR_MISSING_OR_REPARSE")
    assert fake.calls == []
    assert hvt._chain_problem(str(link / "inner")) == "REPARSE"
    assert hvt._chain_problem(str(real / "inner")) is None
    assert hvt._chain_problem(str(real / "missing")) == "UNREADABLE"
    assert hvt._chain_problem(str(real / "inner" / ".." / "inner")) == "DOTDOT"


@contract
def test_pull_rejects_a_dotdot_host_dir_even_when_it_would_fold_to_a_plain_directory(cred, outdir):
    transport, fake = make(cred, probe_ok)
    (outdir / "sub").mkdir()
    sneaky = str(outdir / "sub" / "..")
    assert transport.pull_files(VM, ["C:\\Lab\\a"], sneaky)["error_class"] == "PATH_REJECTED"
    assert fake.calls == []


# ---- what "verified" means: transfer integrity, and a source check only when the caller brings a hash


@contract
def test_pull_result_says_transfer_integrity_and_does_not_claim_a_source_check(cred, outdir):
    transport, _ = make(cred, _pull_handler([b"alpha", b"beta"]))
    result = transport.pull_files(VM, ["C:\\Lab\\a", "C:\\Lab\\b"], outdir)
    assert result["ok"] is True and result["measured"]["source_verified"] is False
    for entry in result["measured"]["files"]:
        assert entry["status"] == "VERIFIED"  # kept for compatibility; it means transfer integrity only
        assert entry["transfer_integrity"] is True and entry["source_verified"] is False
        assert entry["integrity_basis"] == "HOST_MATCHES_GUEST_REPORT"


@contract
def test_pull_a_guest_that_lies_consistently_passes_transfer_integrity_but_fails_a_caller_hash(cred, outdir):
    # the guest serves b"planted" and reports the hash of b"planted": host and guest agree, content is wrong
    real_digest = hashlib.sha256(b"expected content").hexdigest()
    transport, _ = make(cred, _pull_handler([b"planted"]))
    plain = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert plain["ok"] is True and plain["measured"]["files"][0]["source_verified"] is False
    for leftover in outdir.iterdir():
        leftover.unlink()
    transport, _ = make(cred, _pull_handler([b"planted"]))
    checked = transport.pull_files(VM, ["C:\\Lab\\a"], outdir, expected_sha256=[real_digest])
    assert (checked["error_class"], checked["reason"]) == ("HASH_MISMATCH", "EXPECTED_SHA256_MISMATCH")
    entry = checked["measured"]["files"][0]
    assert entry["status"] == "REJECTED" and entry["transfer_integrity"] is False and entry["host_path"] is None
    assert checked["measured"]["verified"] == 0 and list(outdir.iterdir()) == []


@contract
def test_pull_expected_sha256_match_marks_the_file_source_verified(cred, outdir):
    digest = hashlib.sha256(b"known").hexdigest()
    transport, _ = make(cred, _pull_handler([b"known", b"other"]))
    result = transport.pull_files(VM, ["C:\\Lab\\a", "C:\\Lab\\b"], outdir, expected_sha256=[digest.upper(), None])
    assert result["ok"] is True
    first, second = result["measured"]["files"]
    assert first["source_verified"] is True and first["integrity_basis"].endswith("CALLER_EXPECTED_SHA256")
    assert second["source_verified"] is False and second["transfer_integrity"] is True
    assert result["measured"]["source_verified"] is False  # not every file had an expected hash


@contract
@pytest.mark.parametrize("bad", [
    ["x" * 64], ["a" * 63], ["a" * 65], [5], "a" * 64, [], ["a" * 64, "a" * 64], {"0": "a" * 64}, [b"a" * 64],
])
def test_pull_malformed_expected_sha256_is_rejected_before_any_process(cred, outdir, bad):
    transport, fake = make(cred, probe_ok)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir, expected_sha256=bad)
    assert (result["error_class"], result["reason"]) == ("PATH_REJECTED", "EXPECTED_SHA256_INVALID")
    assert fake.calls == []


# ---- the copy is bounded while it runs, not measured afterwards


@contract
def test_pull_copy_is_a_bounded_chunked_read_not_an_unbounded_copy_item():
    code = _code(hvt._SCRIPT)
    pull = code[code.index("elseif ($script:Op -eq 'pull')"):code.index("else { Fail 'UNKNOWN_OPERATION' }")]
    assert "-FromSession" not in pull and "Copy-Item" not in pull
    copy_section = pull[pull.index("Mark 'copy'"):]
    assert "[System.IO.FileMode]::CreateNew" in copy_section        # never opens an existing host file
    assert "$limit = [int64] $files[$i]['size']" in copy_section    # bound = the measured size
    assert "Fail 'COPY_OVER_QUOTA'" in copy_section                  # the quotas are enforced before writing
    assert "$limit - $written" in copy_section                       # no read request goes past the bound
    assert "-ne $want" in copy_section                               # a long or short answer stops the copy
    assert "Fail 'GUEST_FILE_CHANGED'" in copy_section              # growth beyond the measurement stops it
    assert "Remove-Item -LiteralPath $partial" in copy_section       # and its own partial is deleted
    assert "if ($created)" in copy_section                           # only a file this run created


@contract
def test_pull_script_reported_copy_over_quota_is_a_quota_class_with_nothing_left(cred, outdir):
    def handler(req, argv):
        Path(req["host_dir"], req["partial_names"][0]).write_bytes(b"x" * 5)  # what a stopped copy might leave
        rows = [{"index": 0, "status": "COPY_FAILED", "code": "COPY_OVER_QUOTA", "size": 5}]
        return proc(phases_to("copy") + [result_line("pull", False, "copy", {"files": rows},
                                                     failure(code="COPY_OVER_QUOTA"))], 1)
    transport, _ = make(cred, handler)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("QUOTA_EXCEEDED", "COPY_OVER_QUOTA")
    assert result["measured"]["files"][0]["error_class"] == "QUOTA_EXCEEDED"
    assert list(outdir.iterdir()) == []


@contract
def test_pull_a_file_that_grew_after_the_script_measured_it_never_survives_on_the_host(cred, outdir):
    # the script would have stopped; even if it wrongly reports success the host size check still decides
    transport, _ = make(cred, _pull_handler([b"x" * 400], claim={0: b"x" * 4}), max_pull_file_bytes=64)
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("QUOTA_EXCEEDED", "HOST_SIZE_OVER_QUOTA")
    assert list(outdir.iterdir()) == []


# ---- the final name is created exclusively; an existing file is never replaced


def _plant_final(handler, existing: bytes):
    def wrapped(req, argv):
        done = handler(req, argv)
        final = req["partial_names"][0][: -len(".partial")]
        Path(req["host_dir"], final).write_bytes(existing)
        return done
    return wrapped


@contract
def test_pull_never_replaces_an_existing_file_at_the_final_name(cred, outdir):
    transport, _ = make(cred, _plant_final(_pull_handler([b"new content", b"second"]), b"precious"))
    result = transport.pull_files(VM, ["C:\\Lab\\a", "C:\\Lab\\b"], outdir)
    assert (result["error_class"], result["reason"]) == ("TRANSFER_FAILED", "HOST_FINAL_NAME_EXISTS")
    first, second = result["measured"]["files"]
    assert first["status"] == "REJECTED" and first["host_path"] is None and first["transfer_integrity"] is False
    assert second["status"] == "VERIFIED" and result["measured"]["verified"] == 1
    names = sorted(p.name for p in outdir.iterdir())
    assert len(names) == 2 and not any(n.endswith(".partial") for n in names)
    planted = next(p for p in outdir.iterdir() if p.name.endswith("-000.guestfile"))
    assert planted.read_bytes() == b"precious"


@contract
def test_pull_publishes_by_hard_link_and_reports_the_method(cred, outdir):
    transport, _ = make(cred, _pull_handler([b"abc"]))
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert result["ok"] is True
    assert result["measured"]["files"][0]["publish_method"] in ("HARDLINK", "EXCLUSIVE_COPY")


@contract
def test_pull_fallback_without_hard_links_is_exclusive_copy_and_says_so(cred, outdir, monkeypatch):
    def no_links(src, dst, **kw):
        raise OSError("hard links are not supported on this volume")
    monkeypatch.setattr(os, "link", no_links)
    transport, _ = make(cred, _pull_handler([b"abc" * 50]))
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert result["ok"] is True
    entry = result["measured"]["files"][0]
    assert entry["publish_method"] == "EXCLUSIVE_COPY"
    assert Path(entry["host_path"]).read_bytes() == b"abc" * 50
    assert [p.name for p in outdir.iterdir()] == [Path(entry["host_path"]).name]


@contract
def test_pull_fallback_also_refuses_an_existing_final_name(cred, outdir, monkeypatch):
    def no_links(src, dst, **kw):
        raise OSError("hard links are not supported on this volume")
    monkeypatch.setattr(os, "link", no_links)
    transport, _ = make(cred, _plant_final(_pull_handler([b"new"]), b"precious"))
    result = transport.pull_files(VM, ["C:\\Lab\\a"], outdir)
    assert (result["error_class"], result["reason"]) == ("TRANSFER_FAILED", "HOST_FINAL_NAME_EXISTS")
    only = list(outdir.iterdir())
    assert len(only) == 1 and only[0].read_bytes() == b"precious"


@contract
def test_a_request_too_large_for_the_command_line_is_quota_exceeded(cred, outdir, monkeypatch):
    monkeypatch.setattr(hvt, "_MAX_REQUEST_B64", 200)
    transport, fake = make(cred, probe_ok)
    result = transport.pull_files(VM, [f"C:\\Lab\\{'f' * 100}{i}" for i in range(4)], outdir)
    assert result["error_class"] == "QUOTA_EXCEEDED" and result["reason"] == "REQUEST_TOO_LARGE"
    assert fake.calls == []


# --------------------------------------------------------------------------------- surface


@contract
def test_error_classes_are_exactly_the_documented_set():
    assert ERROR_CLASSES == ("AUTH_FAILED", "PSDIRECT_TIMEOUT", "TRANSFER_FAILED", "HASH_MISMATCH",
                             "QUOTA_EXCEEDED", "PATH_REJECTED", "UNKNOWN")
    assert set(hvt._CODE_CLASS.values()) <= set(ERROR_CLASSES)


@contract
def test_every_result_has_the_same_envelope(cred, sample, outdir):
    transport, _ = make(cred, lambda r, a: proc([]))
    for result in (transport.probe(VM), transport.push_file(VM, sample, "C:\\Lab"),
                   transport.pull_files(VM, ["C:\\Lab\\a"], outdir), transport.probe("")):
        assert {"schema", "operation", "ok", "status", "error_class", "reason", "last_phase", "elapsed_s",
                "script_sha256", "measured"} <= set(result)
        assert result["schema"] == hvt.SCHEMA
        json.dumps(result)  # serialisable
        assert_never_ok(result)


# --------------------------------------------------------------------------------- real Hyper-V


@pytest.mark.heavy
def test_real_guest_probe_push_pull_roundtrip(tmp_path):
    """Needs a running guest. Set LIEBERT_HV_VM, LIEBERT_HV_CRED (an Export-Clixml file) and
    LIEBERT_HV_GUEST_DIR (an existing guest directory). Moves one small text file in and out."""
    vm, credential, guest_dir = (os.environ.get(k) for k in ("LIEBERT_HV_VM", "LIEBERT_HV_CRED", "LIEBERT_HV_GUEST_DIR"))
    if not (vm and credential and guest_dir) or shutil.which("powershell.exe") is None:
        pytest.skip("LIEBERT_HV_VM, LIEBERT_HV_CRED, LIEBERT_HV_GUEST_DIR and powershell.exe are required")
    transport = HypervTransport(credential)
    assert transport.probe(vm)["ok"] is True
    src = tmp_path / f"hvt-{os.getpid()}.txt"
    src.write_text("transport round trip\n", encoding="utf-8")
    pushed = transport.push_file(vm, src, guest_dir)
    assert pushed["ok"] is True, pushed
    out = tmp_path / "out"
    out.mkdir()
    pulled = transport.pull_files(vm, [pushed["measured"]["guest_path"]], out)
    assert pulled["ok"] is True, pulled
    assert Path(pulled["measured"]["files"][0]["host_path"]).read_bytes() == src.read_bytes()
