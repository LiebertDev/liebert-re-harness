"""`liebert_re.tools.pe_sieve`: one-process, scan-only pe-sieve wrapper.

Fast tier on purpose: `run_bounded_process` is mocked and the fixtures are captures of what
pe-sieve 0.4.1.1 printed on a Windows 10 machine, so the contract is pinned without the
scanner installed. The only real scans are in `TestLiveScanOfOwnProcess` (heavy), and they
scan a console process that the test itself starts and kills.

What was captured and what was not:

* REAL: a report with `patched` and `implanted_pe` detections (a process that patched one
  byte of a ntdll function and copied a PE into private RWX memory), a clean-module report
  (truncated to its first three of 123 entries), the 32-bit-scanner-on-64-bit-target output
  (a report-shaped, all-zero JSON plus a "Scanner mismatch" line, exit -1), and the
  "Could not open the process" output for a PID with no process.
* NOT CAPTURED: an access-denied refusal and a report whose `errors` is non-zero. Those
  fixtures are constructed from the documented shape, and the tests that use them say so.
  Reproducing them needs an elevated or protected target, which a scan here never touches.
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

# Since the lab gate, pe_sieve_scan runs only with the operator switch, an authorization naming this
# operation and PID, the declared image hash and a process the harness started. The scan tests below
# fake the TARGET PROCESS (as they already fake the scanner) so the gate passes; the gate itself is
# tested for real in tests/test_lab_gate.py and in the heavy class here.
GATE_IMAGE = sys.executable
GATE_IMAGE_SHA256 = hashlib.sha256(open(GATE_IMAGE, "rb").read()).hexdigest()


def _gate_kwargs(pid=4242):
    return {"authorization": {"authorized_by": "test", "purpose": "unit test of the scan wrapper",
                              "operations": ["pe_sieve_scan"], "pids": [pid]},
            "sample_sha256": GATE_IMAGE_SHA256}


@pytest.fixture()
def gate_open():
    identity = {"pid": 4242, "create_time": 1.0, "image": GATE_IMAGE, "parent_pid": os.getpid(),
                "state": "running", "user": "test"}
    with mock.patch.dict(os.environ, {lg.ENABLE_ENV: lg.ENABLE_VALUE}), \
         mock.patch.object(lg.LabGate, "target", return_value=(identity, None)), \
         mock.patch.object(lg.LabGate, "is_direct_child", return_value=True):
        yield


FAKE_EXE = r"C:\fake\pe-sieve64.exe"


def _report(**overrides):
    base = {
        "pid": 4242, "is_64_bit": 1, "is_managed": 0,
        "main_image_path": r"C:\Windows\System32\notepad.exe", "used_reflection": 0,
        "scanner_version": "0.4.1.1",
        "scanned": {
            "total": 41, "skipped": 0,
            "modified": {"total": 0, "patched": 0, "iat_hooked": 0, "replaced": 0, "hdr_modified": 0,
                         "implanted_pe": 0, "implanted_shc": 0, "unreachable_file": 0, "other": 0},
            "errors": 0,
        },
        "scans": [],
    }
    base.update(overrides)
    return {"scan_report": base}


# REAL (truncated): `pe-sieve64 /pid <notepad> /json /jlvl 2 /report 7`; first 3 of 123 entries.
CLEAN_JSON = json.dumps(_report(scans=[
    {"mapping_scan": {"module": "7ff73a5a0000", "module_file": r"C:\Windows\System32\notepad.exe",
                      "mapped_file": r"C:\Windows\System32\notepad.exe", "status": 0}},
    {"headers_scan": {"status": 0, "module": "7ff73a5a0000", "module_size": "38000",
                      "module_file": r"C:\Windows\System32\notepad.exe", "is_connected_to_peb": 1,
                      "is_pe_replaced": 0, "dos_hdr_modified": 0, "file_hdr_modified": 0,
                      "nt_hdr_modified": 0, "ep_modified": 0, "sec_hdr_modified": 0}},
    {"code_scan": {"status": 0, "module": "7ff73a5a0000", "module_size": "38000",
                   "module_file": r"C:\Windows\System32\notepad.exe", "scanned_sections": 1}},
]))

# REAL: a process that patched one byte of a ntdll export and implanted a PE in private memory.
PATCHED_JSON = json.dumps({"scan_report": {
    "pid": 4242, "is_64_bit": 1, "is_managed": 0, "main_image_path": r"C:\Python\python.exe",
    "used_reflection": 0, "scanner_version": "0.4.1.1",
    "scanned": {
        "total": 27, "skipped": 0,
        "modified": {"total": 2, "patched": 1, "iat_hooked": 0, "replaced": 0, "hdr_modified": 0,
                     "implanted_pe": 1, "implanted_shc": 0, "unreachable_file": 0, "other": 0},
        "errors": 0,
    },
    "scans": [
        {"code_scan": {"status": 1, "module": "7ffe18f30000", "module_size": "1f8000",
                       "module_file": r"C:\Windows\System32\ntdll.dll", "scanned_sections": 2, "patches": 1,
                       "patches_list": [{"rva": "a10d0", "size": 1, "is_hook": 0, "func_name": "DbgBreakPoint"}]}},
        {"workingset_scan": {"status": 1, "module": "188957b0000", "module_size": "7000", "has_pe": 1,
                             "has_shellcode": 0, "is_listed_module": 0, "protection": "40",
                             "mapping_type": "MEM_PRIVATE",
                             "pe_artefacts": {"pe_base_offset": "0", "nt_file_hdr": "ec", "sections_hdrs": "1f0",
                                              "sections_count": 6, "is_dll": 0, "is_64_bit": 1}}},
    ],
}})

# REAL: 32-bit scanner against a 64-bit target. A clean-looking JSON, zero modules scanned.
MISMATCH_STDOUT = (
    "PID: 4242\nOutput filter: don't dump any files\nDump mode: autodetect (default)\n[*] Using raw process!\n"
    "Scanning workingset: 4 memory regions.\n[*] Workingset scanned in 0 ms.\n"
    + json.dumps(_report(scanned={"total": 0, "skipped": 0, "modified": {
        "total": 0, "patched": 0, "iat_hooked": 0, "replaced": 0, "hdr_modified": 0, "implanted_pe": 0,
        "implanted_shc": 0, "unreachable_file": 0, "other": 0}, "errors": 0}), indent=1)
)
MISMATCH_STDERR = "[!] Scanner mismatch! Try to use the 64bit version of the scanner!\n"

# REAL: a PID with no process.
NOT_OPENED_STDOUT = "PID: 4242\nOutput filter: don't dump any files\nDump mode: autodetect (default)\n"
NOT_OPENED_STDERR = "-> Is this process still running?\n[ERROR] Could not open the process: Invalid Parameter\n"
# CONSTRUCTED: Windows' own wording for error 5; never captured here.
DENIED_STDERR = "[ERROR] Could not open the process: Access is denied.\n"


def _done(stdout="", stderr="", code=1, **kw):
    return BoundedProcessResult(code, stdout, stderr, **kw)


@pytest.fixture()
def scanner(tmp_path, gate_open):
    """A resolved fake scanner, evidence redirected into tmp, and the process runner mocked."""
    with mock.patch.object(ps, "EVIDENCE", tmp_path), \
         mock.patch.object(ps._PeSieve, "candidates", return_value=[(FAKE_EXE, "PATH")]), \
         mock.patch.object(ps, "run_bounded_process") as run:
        run.return_value = _done(CLEAN_JSON)
        yield run


def _scan(**kw):
    kw.setdefault("pid", 4242)
    for key, value in _gate_kwargs(kw["pid"] if isinstance(kw["pid"], int) else 4242).items():
        kw.setdefault(key, value)
    out = ps.pe_sieve_scan(**kw)
    assert isinstance(out, str)
    return json.loads(out)


class TestOperations:
    def test_clean_scan_is_ok_with_the_scanners_own_category_names(self, scanner):
        data = _scan()
        assert data["ok"] is True and data["status"] == "OK"
        assert data["verdict"] == "NO_ANOMALIES_IN_SCANNED_MODULES" and data["anomalies_found"] is False
        assert list(data["categories"]) == ["patched", "iat_hooked", "replaced", "hdr_modified",
                                            "implanted_pe", "implanted_shc", "unreachable_file", "other"]
        assert data["categories_nonzero"] == {}
        assert data["coverage"]["scanned_modules"] == 41 and data["coverage"]["errors"] == 0
        assert data["target"]["is_64_bit"] == 1 and data["scanner_version"] == "0.4.1.1"
        assert "not a statement that the process is benign" in data["note"]

    def test_real_detections_are_listed_not_summarised_away(self, scanner):
        scanner.return_value = _done(PATCHED_JSON, code=2)
        data = _scan()
        assert data["ok"] is True and data["status"] == "OK" and data["verdict"] == "ANOMALIES_FOUND"
        assert data["categories_nonzero"] == {"patched": 1, "implanted_pe": 1}
        kinds = {f["scan_kind"]: f for f in data["findings"]}
        assert set(kinds) == {"code_scan", "workingset_scan"}
        assert kinds["code_scan"]["patches_list"][0]["func_name"] == "DbgBreakPoint"
        assert kinds["workingset_scan"]["has_pe"] == 1
        assert data["coverage"]["scan_kinds"] == {"code_scan": 1, "workingset_scan": 1}

    def test_raw_report_goes_to_evidence_unmodified(self, scanner, tmp_path):
        scanner.return_value = _done(PATCHED_JSON, code=2)
        data = _scan()
        saved = json.loads((tmp_path / data["internal_evidence_name"]).read_text(encoding="utf-8"))
        assert saved == json.loads(PATCHED_JSON)

    def test_evidence_write_failure_does_not_fail_the_scan(self, scanner, tmp_path):
        with mock.patch.object(ps, "EVIDENCE", tmp_path / "missing" / "dir"):
            data = _scan()
        assert data["status"] == "OK" and data["internal_evidence_name"] is None
        assert data["evidence_write_error"]

    def test_json_is_found_inside_surrounding_log_text(self, scanner):
        scanner.return_value = _done("[*] Scanning: x.dll\n" + PATCHED_JSON + "\ntrailing\n", code=2)
        assert _scan()["verdict"] == "ANOMALIES_FOUND"

    def test_status_reports_binary_bitness_and_version(self):
        with mock.patch.object(ps._PeSieve, "candidates", return_value=[(FAKE_EXE, "PATH")]), \
             mock.patch.object(ps, "run_bounded_process", return_value=_done("0.4.1.1\n", code=0)) as run:
            data = json.loads(ps.pe_sieve_status())
        assert data["status"] == "OK" and data["version"] == "0.4.1.1"
        assert data["scanner_bitness"] == 64 and data["resolved_by"] == "PATH"
        assert data["invoked_argv"] == [FAKE_EXE, "/version"] == run.call_args[0][0]
        assert data["policy"]["scan_only"] is True


class TestArgumentVector:
    """The invocation is the part a Windows tool never complains about: a bent flag runs defaults."""

    def test_exact_default_argv_is_passed_and_echoed(self, scanner):
        data = _scan(pid=4242)
        expected = [FAKE_EXE, "/pid", "4242", "/json", "/jlvl", "2", "/ofilter", "2", "/report", "5", "/quiet",
                    "/iat", "1", "/shellc", "3", "/obfusc", "0", "/data", "0", "/dnet", "0"]
        assert scanner.call_args[0][0] == expected
        assert data["invoked_argv"] == expected
        assert data["scan_flags"] == {"iat": 1, "shellcode": 3, "obfuscation": 0, "data": 0,
                                      "dotnet_policy": 0, "threads": False}

    def test_options_map_to_their_switches(self, scanner):
        _scan(iat=3, shellcode=0, obfuscation=3, data=5, dotnet_policy=4, threads=True)
        argv = scanner.call_args[0][0]
        for switch, value in (("/iat", "3"), ("/shellc", "0"), ("/obfusc", "3"), ("/data", "5"), ("/dnet", "4")):
            assert argv[argv.index(switch) + 1] == value
        assert argv[-1] == "/threads"

    def test_no_dump_or_whole_system_switch_can_ever_be_passed(self, scanner):
        _scan(iat=3, shellcode=4, obfuscation=3, data=5, dotnet_policy=4, threads=True)
        argv = scanner.call_args[0][0]
        assert argv[argv.index("/ofilter") + 1] == "2"
        for forbidden in ("/dmode", "/imp", "/minidmp", "/rebase", "/refl", "/dir", "/loop", "/suspend", "/shellc_dump"):
            assert forbidden not in argv
        assert argv.count("/pid") == 1 and argv[argv.index("/pid") + 1] == "4242"

    def test_pid_is_a_decimal_string_in_argv_for_int_and_digit_string(self, scanner):
        for pid in (4242, "4242", " 4242 "):
            _scan(pid=pid)
            assert scanner.call_args[0][0][1:3] == ["/pid", "4242"]

    def test_msys_conversion_is_disabled_in_the_child_environment(self, scanner):
        _scan()
        env = scanner.call_args.kwargs["environment"]
        assert env["MSYS_NO_PATHCONV"] == "1" and env["MSYS2_ARG_CONV_EXCL"] == "*"

    def test_timeout_is_clamped_by_this_module(self, scanner):
        for given, used in ((1, 10), (999999, 600), (45, 45), ("x", 120), (True, 120)):
            _scan(timeout_seconds=given)
            assert scanner.call_args.kwargs["timeout_seconds"] == used

    def test_pid_in_report_that_differs_from_the_request_is_not_accepted(self, scanner):
        scanner.return_value = _done(json.dumps(_report(pid=999)))
        data = _scan()
        assert data["ok"] is False and data["error"] == "PE_SIEVE_PID_MISMATCH" and data["reported_pid"] == 999


class TestResolution:
    def _names(self, tmp_path, *names):
        for n in names:
            (tmp_path / n).write_bytes(b"MZ")

    def test_env_directory_wins_over_path_and_known_install(self, tmp_path, monkeypatch):
        self._names(tmp_path, "pe-sieve64.exe", "pe-sieve32.exe")
        monkeypatch.setenv("PE_SIEVE_HOME", str(tmp_path))
        exe, how, found = ps._PeSieve.pick()
        assert exe == str(tmp_path / "pe-sieve64.exe") and how == "PE_SIEVE_HOME"
        assert [ps._PeSieve.bitness(p) for p, _ in found][:2] == [64, 32]

    def test_explicit_env_file_is_honoured_even_if_32_bit(self, tmp_path, monkeypatch):
        self._names(tmp_path, "pe-sieve32.exe", "pe-sieve64.exe")
        monkeypatch.setenv("PE_SIEVE_HOME", str(tmp_path / "pe-sieve32.exe"))
        exe, how, _ = ps._PeSieve.pick()
        assert exe == str(tmp_path / "pe-sieve32.exe") and how == "PE_SIEVE_HOME"

    def test_path_is_searched_after_env_and_prefers_64(self, tmp_path, monkeypatch):
        self._names(tmp_path, "pe-sieve64.exe", "pe-sieve32.exe")
        monkeypatch.delenv("PE_SIEVE_HOME", raising=False)
        lookup = {"pe-sieve64": str(tmp_path / "pe-sieve64.exe"), "pe-sieve32": str(tmp_path / "pe-sieve32.exe")}
        with mock.patch.object(ps.shutil, "which", side_effect=lambda n: lookup.get(n)), \
             mock.patch.object(ps, "_KNOWN_INSTALL_DIR", str(tmp_path / "nowhere")):
            exe, how, _ = ps._PeSieve.pick()
        assert exe == str(tmp_path / "pe-sieve64.exe") and how == "PATH"

    def test_known_install_directory_is_the_last_resort(self, tmp_path, monkeypatch):
        self._names(tmp_path, "pe-sieve64.exe")
        monkeypatch.delenv("PE_SIEVE_HOME", raising=False)
        with mock.patch.object(ps.shutil, "which", return_value=None), \
             mock.patch.object(ps, "_KNOWN_INSTALL_DIR", str(tmp_path)):
            exe, how, _ = ps._PeSieve.pick()
        assert exe == str(tmp_path / "pe-sieve64.exe") and how == "known_install_path"

    def test_only_a_32_bit_scanner_is_used_when_it_is_all_there_is(self, tmp_path, monkeypatch):
        self._names(tmp_path, "pe-sieve32.exe")
        monkeypatch.delenv("PE_SIEVE_HOME", raising=False)
        with mock.patch.object(ps.shutil, "which", return_value=None), \
             mock.patch.object(ps, "_KNOWN_INSTALL_DIR", str(tmp_path)):
            exe, _, _ = ps._PeSieve.pick()
        assert ps._PeSieve.bitness(exe) == 32


@pytest.mark.contract
class TestPidIsRequired:
    @pytest.mark.parametrize("value", [
        None, "", "   ", "all", "ALL", "*", "-1", "any", "everything", "system", 0, -1, -4242, True, False,
        "abc", "0x10", "12.5", 12.5, 2 ** 40, "99999999999", [], {}, (4242,), b"4242",
    ])
    def test_missing_invalid_or_all_process_requests_are_refused_before_anything_starts(self, value):
        with mock.patch.object(ps, "run_bounded_process") as run, \
             mock.patch.object(ps._PeSieve, "candidates", side_effect=AssertionError("resolved a binary")):
            data = json.loads(ps.pe_sieve_scan(value))
        assert data["ok"] is False and data["status"] == "PID_REQUIRED"
        assert data["error"] in {"PID_MISSING", "PID_INVALID", "ALL_PROCESSES_REFUSED"}
        assert not run.called

    def test_no_argument_at_all_is_pid_missing(self):
        data = json.loads(ps.pe_sieve_scan())
        assert data["status"] == "PID_REQUIRED" and data["error"] == "PID_MISSING"

    def test_all_spellings_get_the_all_process_reason(self):
        for spelling in ("all", "*", "-1", "EVERYTHING"):
            assert json.loads(ps.pe_sieve_scan(spelling))["error"] == "ALL_PROCESSES_REFUSED"

    def test_cli_without_pid_is_a_structured_refusal_with_exit_3(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["sieve"])
        body = json.loads(buf.getvalue())
        assert code == 3 and body["status"] == "PID_REQUIRED" and body["command"] == "sieve"

    def test_cli_all_is_refused_too(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["sieve", "--pid", "all"])
        assert code == 3 and json.loads(buf.getvalue())["error"] == "ALL_PROCESSES_REFUSED"

    def test_the_module_offers_no_all_process_operation(self):
        assert [n for n in vars(ps) if n.startswith("pe_sieve_")] == ["pe_sieve_status", "pe_sieve_scan"]
        import inspect
        assert list(inspect.signature(ps.pe_sieve_scan).parameters)[0] == "pid"


@pytest.mark.contract
class TestNeverAGuessedNegative:
    """No path here may read as "scanned and clean"."""

    def test_32_bit_scanner_on_a_64_bit_target_is_a_mismatch_not_a_clean_report(self, scanner):
        scanner.return_value = _done(MISMATCH_STDOUT, MISMATCH_STDERR, code=0xFFFFFFFF)
        data = _scan()
        assert data["ok"] is False and data["status"] == "SCANNER_MISMATCH"
        assert "verdict" not in data and "anomalies_found" not in data
        assert data["text_derived"] is True and "Scanner mismatch" in data["scanner_message"]

    def test_a_zero_module_report_is_nothing_scanned_even_without_the_mismatch_text(self, scanner):
        scanner.return_value = _done(MISMATCH_STDOUT, "", code=1)
        data = _scan()
        assert data["ok"] is False and data["status"] == "NOTHING_SCANNED" and data["verdict"] == "INCONCLUSIVE"
        assert data["coverage"]["scanned_modules"] == 0

    def test_process_that_could_not_be_opened_is_not_a_negative(self, scanner):
        scanner.return_value = _done(NOT_OPENED_STDOUT, NOT_OPENED_STDERR, code=0xFFFFFFFF)
        data = _scan()
        assert data["ok"] is False and data["status"] == "PROCESS_NOT_OPENED" and "anomalies_found" not in data
        assert "Invalid Parameter" in data["scanner_message"] and "NOT a finding" in data["detail"]

    def test_access_denied_is_its_own_status_from_constructed_text(self, scanner):
        # DENIED_STDERR is constructed (Windows' wording for error 5), not captured.
        scanner.return_value = _done(NOT_OPENED_STDOUT, DENIED_STDERR, code=0xFFFFFFFF)
        data = _scan()
        assert data["ok"] is False and data["status"] == "ACCESS_DENIED" and "anomalies_found" not in data

    def test_unreadable_modules_make_a_partial_scan_that_keeps_what_was_found(self, scanner):
        # CONSTRUCTED from the documented shape: errors > 0 and a status -1 entry next to a real finding.
        report = json.loads(PATCHED_JSON)
        report["scan_report"]["scanned"]["errors"] = 1
        report["scan_report"]["scans"].append({"code_scan": {"status": -1, "module": "7ff000000000",
                                                             "module_file": r"C:\x\locked.dll"}})
        scanner.return_value = _done(json.dumps(report), code=2)
        data = _scan()
        assert data["ok"] is False and data["status"] == "SCAN_PARTIAL"
        assert data["verdict"] == "ANOMALIES_FOUND_IN_PART" and data["anomalies_found"] is True
        assert len(data["findings"]) == 2 and len(data["error_entries"]) == 1
        assert data["coverage"]["errors"] == 1

    def test_partial_scan_without_findings_is_inconclusive_never_clean(self, scanner):
        report = json.loads(CLEAN_JSON)
        report["scan_report"]["scanned"]["errors"] = 3
        scanner.return_value = _done(json.dumps(report))
        data = _scan()
        assert data["ok"] is False and data["status"] == "SCAN_PARTIAL" and data["verdict"] == "INCONCLUSIVE"
        assert data["anomalies_found"] is False and "NOT established" in data["detail"]

    def test_skipped_modules_are_partial_coverage(self, scanner):
        report = json.loads(CLEAN_JSON)
        report["scan_report"]["scanned"]["skipped"] = 2
        scanner.return_value = _done(json.dumps(report))
        assert _scan()["status"] == "SCAN_PARTIAL"

    def test_an_entry_status_this_module_does_not_know_is_not_called_clean(self, scanner):
        report = json.loads(CLEAN_JSON)
        report["scan_report"]["scans"].append({"code_scan": {"status": 7}})
        scanner.return_value = _done(json.dumps(report))
        data = _scan()
        assert data["status"] == "SCAN_PARTIAL" and data["unrecognised_entries"]

    def test_a_failure_exit_with_a_report_is_not_trusted(self, scanner):
        scanner.return_value = _done(CLEAN_JSON, code=0xFFFFFFFF)
        data = _scan()
        assert data["ok"] is False and data["error"] == "PE_SIEVE_REPORTED_FAILURE_EXIT"
        assert data["anomalies_found"] is False and "status" in data and data["status"] == "ANALYSIS_LIMITED"

    def test_a_detection_count_without_entries_still_counts_as_anomalies(self, scanner):
        report = json.loads(CLEAN_JSON)
        report["scan_report"]["scanned"]["modified"].update(total=1, hdr_modified=1)
        scanner.return_value = _done(json.dumps(report), code=2)
        data = _scan()
        assert data["anomalies_found"] is True and data["verdict"] == "ANOMALIES_FOUND"
        assert data["categories_nonzero"] == {"hdr_modified": 1}


@pytest.mark.contract
class TestFailureBranches:
    def test_tool_missing(self, gate_open):
        with mock.patch.object(ps._PeSieve, "candidates", return_value=[]):
            for out in (ps.pe_sieve_scan(4242, **_gate_kwargs()), ps.pe_sieve_status()):
                data = json.loads(out)
                assert data["ok"] is False and data["status"] == "TOOL_MISSING" and "PE_SIEVE_HOME" in data["detail"]

    def test_timeout_and_cancellation_are_not_findings(self, scanner):
        scanner.return_value = _done("", "", code=None, timed_out=True)
        data = _scan()
        assert data["status"] == "TIMEOUT" and data["ok"] is False and "anomalies_found" not in data
        scanner.return_value = _done("", "", code=None, cancelled=True)
        assert _scan()["status"] == "CANCELLED"

    def test_no_json_output_is_analysis_limited_with_the_message(self, scanner):
        scanner.return_value = _done("something unexpected\n", "", code=7)
        data = _scan()
        assert data["status"] == "ANALYSIS_LIMITED" and data["error"] == "PE_SIEVE_NO_JSON_OUTPUT"
        assert data["exit_code"] == 7 and "unexpected" in data["scanner_message"]

    def test_json_without_a_scan_report_is_a_parse_failure(self, scanner):
        scanner.return_value = _done('{"other": 1}')
        assert _scan()["status"] == "RESULT_PARSE_FAILED"
        scanner.return_value = _done('{"scan_report": [1]}')
        assert _scan()["status"] == "RESULT_PARSE_FAILED"

    def test_broken_json_is_no_json_not_a_crash(self, scanner):
        scanner.return_value = _done('{"scan_report": {"pid": ')
        assert _scan()["error"] == "PE_SIEVE_NO_JSON_OUTPUT"

    def test_os_error_is_an_environment_error_not_a_data_error(self, scanner):
        for exc in (FileNotFoundError(2, "The system cannot find the file"), PermissionError(13, "Access is denied")):
            scanner.side_effect = exc
            data = _scan()
            assert data["status"] == "ANALYSIS_LIMITED" and data["error"] == "PE_SIEVE_COULD_NOT_RUN"
            assert data["environment_error"]["type"] == type(exc).__name__
            assert data["environment_error"]["errno"] == exc.errno
            assert "not the target process" in data["detail"]

    def test_status_os_error_is_an_environment_error(self):
        with mock.patch.object(ps._PeSieve, "candidates", return_value=[(FAKE_EXE, "PATH")]), \
             mock.patch.object(ps, "run_bounded_process", side_effect=OSError(5, "Access is denied")):
            data = json.loads(ps.pe_sieve_status())
        assert data["status"] == "ANALYSIS_LIMITED" and data["environment_error"]["errno"] == 5

    def test_unexpected_exception_still_returns_json(self, scanner):
        scanner.side_effect = RuntimeError("boom")
        data = _scan()
        assert data["status"] == "ANALYSIS_LIMITED" and data["error"] == "PE_SIEVE_UNEXPECTED_ERROR"
        assert "environment_error" not in data

    def test_status_unreadable_version_and_timeout(self):
        with mock.patch.object(ps._PeSieve, "candidates", return_value=[(FAKE_EXE, "PATH")]):
            with mock.patch.object(ps, "run_bounded_process", return_value=_done("garbage", code=0)):
                assert json.loads(ps.pe_sieve_status())["error"] == "PE_SIEVE_VERSION_UNREADABLE"
            with mock.patch.object(ps, "run_bounded_process", return_value=_done("", code=None, timed_out=True)):
                assert json.loads(ps.pe_sieve_status())["status"] == "TIMEOUT"
            with mock.patch.object(ps, "run_bounded_process", side_effect=RuntimeError("x")):
                assert json.loads(ps.pe_sieve_status())["error"] == "PE_SIEVE_UNEXPECTED_ERROR"

    @pytest.mark.parametrize("kwargs", [
        {"iat": 4}, {"iat": -1}, {"shellcode": 5}, {"obfuscation": 4}, {"data": 6}, {"dotnet_policy": 5},
        {"iat": "1"}, {"iat": True}, {"iat": 1.0}, {"threads": 1}, {"threads": "yes"},
    ])
    def test_invalid_options_are_refused_before_a_process_starts(self, scanner, kwargs):
        data = _scan(**kwargs)
        assert data["status"] == "ANALYSIS_LIMITED" and data["error"] == "INVALID_OPTION"
        assert not scanner.called

    def test_hostile_inputs_never_raise_and_always_return_a_json_object(self, scanner):
        weird = [object(), 4242.0, float("nan"), "4242\n/dmode 0", "4242 /dmode", "../../x", 10 ** 30, ["4242"]]
        for value in weird:
            out = ps.pe_sieve_scan(value)
            assert isinstance(out, str) and isinstance(json.loads(out), dict)
        # A PID with trailing text is refused, so no extra switch can ride along on it.
        assert json.loads(ps.pe_sieve_scan("4242 /dmode 0"))["status"] == "PID_REQUIRED"
        scanner.return_value = _done(CLEAN_JSON)
        for junk in ("", "{}", "null", "[]", "}{", "\x00\xff", '{"scan_report": null}'):
            scanner.return_value = _done(junk)
            assert isinstance(json.loads(ps.pe_sieve_scan(4242, **_gate_kwargs())), dict)

    def test_cli_exit_codes_for_the_new_refusals(self):
        for status in ("PID_REQUIRED", "ACCESS_DENIED", "PROCESS_NOT_OPENED", "SCANNER_MISMATCH",
                       "NOTHING_SCANNED", "SCAN_PARTIAL"):
            assert cli._exit_code({"ok": False, "status": status}) == cli.EXIT_REFUSED

    def test_cli_status_without_the_tool_is_exit_3(self):
        buf = io.StringIO()
        with mock.patch.object(ps._PeSieve, "candidates", return_value=[]), redirect_stdout(buf):
            code = cli.main(["sievestatus"])
        assert code == 3 and json.loads(buf.getvalue())["status"] == "TOOL_MISSING"


@pytest.mark.heavy
class TestLiveScanOfOwnProcess:
    """Real pe-sieve, against a console process THIS test starts (no window) and always kills.
    Nothing else on the machine is ever scanned."""

    @pytest.fixture()
    def own_process(self):
        if os.name != "nt" or not ps._PeSieve.pick()[0]:
            pytest.skip("pe-sieve is not installed on this machine")
        proc = subprocess.Popen(
            ["ping", "-n", "120", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            time.sleep(1.0)
            yield proc
        finally:
            proc.kill()
            proc.wait(timeout=10)
            assert proc.poll() is not None

    def test_status_is_real(self):
        if os.name != "nt" or not ps._PeSieve.pick()[0]:
            pytest.skip("pe-sieve is not installed on this machine")
        data = json.loads(ps.pe_sieve_status())
        assert data["status"] == "OK" and data["version"]

    def test_scan_of_a_process_this_test_started(self, own_process, tmp_path):
        with mock.patch.object(ps, "EVIDENCE", tmp_path):
            with mock.patch.dict(os.environ, {lg.ENABLE_ENV: lg.ENABLE_VALUE}),                  mock.patch.object(lg, "EVIDENCE", tmp_path / "gate"):
                image = lg.LabGate.target(own_process.pid)[0]["image"]
                digest = lg.LabGate.sha256_of_file(image)[0]
                data = json.loads(ps.pe_sieve_scan(own_process.pid, **{
                    "authorization": _gate_kwargs(own_process.pid)["authorization"], "sample_sha256": digest}))
        assert data["lab_gate"]["ok"] is True and data["lab_gate"]["isolation_verified"] is False
        assert data["lab_gate"]["ownership"]["basis"] == "direct_child_of_calling_process"
        assert data["pid"] == own_process.pid
        assert data["invoked_argv"][1:3] == ["/pid", str(own_process.pid)]
        # Whatever the outcome, it is one of the honest ones, and a clean claim has coverage behind it.
        assert data["status"] in {"OK", "SCAN_PARTIAL", "NOTHING_SCANNED", "ACCESS_DENIED", "SCANNER_MISMATCH"}
        if data["status"] == "OK":
            assert data["coverage"]["scanned_modules"] > 0 and data["coverage"]["errors"] == 0
            assert set(data["categories"]) >= {"patched", "implanted_pe", "implanted_shc"}
        assert not any(p.suffix in {".dll", ".exe", ".bin", ".dmp"} for p in tmp_path.iterdir())

    def test_a_pid_nobody_asked_for_is_never_scanned(self):
        # No PID, "all": refused with nothing started, whatever is installed.
        assert json.loads(ps.pe_sieve_scan(None))["status"] == "PID_REQUIRED"
        assert json.loads(ps.pe_sieve_scan("all"))["status"] == "PID_REQUIRED"
