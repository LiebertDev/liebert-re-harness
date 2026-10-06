"""``run_bounded_process`` on an executable that exists but cannot be started.

A quarantined binary (Windows ``WinError 225``), a permission denial and a
corrupt image all make ``subprocess.Popen`` raise ``OSError``. That is an
environment fault: it must come back as the named ``launch_failed`` status with
the OS cause, not escape as a raw exception, and it must never be reported as
"tool missing" (the file is there) or as a parse/analysis failure of the input.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from unittest import mock

import pytest

import liebert_re.bounded_subprocess as bs
import liebert_re.tools.capa as tc
import liebert_re.tools.upx as tu

# Fictional paths on purpose: the repo scanner rejects any drive-Users-name or home-name shape,
# so those shapes must not appear as literals here. The redactor is shape-based (drive,
# UNC, POSIX), not name-based, so these exercise the same branches.
_OPERATOR_PATH = r"C:\opzone\someoperator\capa\capa.exe"
_POSIX_PATH = "/srv/someoperator/bin/tool"


def _winerror_225(path=_OPERATOR_PATH):
    exc = OSError(
        22, "Operation did not complete successfully because the file contains a virus or "
            "potentially unwanted software", path, 225,
    )
    # On non-Windows hosts OSError ignores the 4th arg, so set it explicitly.
    exc.winerror = 225
    return exc


def _popen_raising(exc):
    return mock.patch.object(bs.subprocess, "Popen", side_effect=exc)


def test_runner_turns_winerror_225_into_a_named_status_without_raising():
    with _popen_raising(_winerror_225()):
        result = bs.run_bounded_process(["capa.exe", "--version"], timeout_seconds=5)
    assert result.launch_failed is True
    assert result.returncode is None
    assert not result.timed_out and not result.cancelled
    assert "WinError 225" in result.launch_error
    assert "unwanted software" in result.launch_error


def test_runner_reports_posix_errno_for_a_permission_denial():
    exc = PermissionError(13, "Permission denied", _POSIX_PATH)
    with _popen_raising(exc):
        result = bs.run_bounded_process(["tool"], timeout_seconds=5)
    assert result.launch_failed is True
    assert "PermissionError errno 13" in result.launch_error
    assert "Permission denied" in result.launch_error
    assert "someoperator" not in result.launch_error


def test_launch_error_carries_no_absolute_path_even_when_the_os_text_does():
    exc = OSError(22, rf"cannot run {_OPERATOR_PATH} here", _OPERATOR_PATH, 225)
    exc.winerror = 225
    exc.strerror = (
        rf"cannot run {_OPERATOR_PATH} or \fileserver\share\x.exe or /srv/someoperator/x here"
    )
    text = bs.describe_launch_failure(exc)
    assert "someoperator" not in text
    assert "fileserver" not in text
    assert "C:\\" not in text
    assert "<PATH>" in text
    assert "WinError 225" in text


def test_missing_and_unlaunchable_are_distinct_codes():
    missing = json.loads(_call_with_exe(None))
    unlaunchable = json.loads(_call_with_exe("C:/fake/capa.exe"))
    assert missing["status"] == "TOOL_MISSING"
    assert unlaunchable["status"] == "TOOL_UNLAUNCHABLE"
    assert missing["status"] != unlaunchable["status"]
    assert missing.get("error") != unlaunchable.get("error")


def _call_with_exe(exe):
    with mock.patch.object(tc, "_capa_binary", return_value=exe), _popen_raising(_winerror_225()):
        return tc.capa_status()


def test_capa_analyze_end_to_end_reports_unlaunchable_not_a_parse_or_analysis_failure(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
         mock.patch.object(tc, "safe_path", return_value=sample), \
         mock.patch.object(tc, "relative", return_value="sample.exe"), \
         _popen_raising(_winerror_225()):
        data = json.loads(tc.capa_analyze(str(sample)))
    assert data["ok"] is False
    assert data["status"] == "TOOL_UNLAUNCHABLE"
    assert data["error"] == "CAPA_LAUNCH_FAILED"
    assert "WinError 225" in data["launch_error"]
    assert "someoperator" not in json.dumps(data)
    assert data["status"] not in ("RESULT_PARSE_FAILED", "ANALYSIS_LIMITED", "TOOL_MISSING")


def test_another_wrapper_passes_the_status_through():
    with mock.patch.object(tu, "_upx_binary", return_value="C:/fake/upx.exe"),          _popen_raising(_winerror_225()):
        data = json.loads(tu.upx_status())
    assert data["ok"] is False
    assert data["status"] == "TOOL_UNLAUNCHABLE"
    assert data["error"] == "UPX_LAUNCH_FAILED"
    assert data["runnable"] is False
    assert "WinError 225" in data["launch_error"]


_CALLERS = ("tools/capa", "tools/die", "tools/dex", "tools/jvm", "tools/il2cpp", "tools/upx",
            "tools/yara_x", "tools/pe_sieve", "tools/binary", "tools/rizin", "tools/ghidra",
            "tools/ida", "dynamic/lab_gate")


@pytest.mark.parametrize("name", _CALLERS)
def test_every_runner_caller_reads_launch_failed(name):
    source = (Path(bs.__file__).parent / f"{name}.py").read_text(encoding="utf-8")
    assert "launch_failed" in source, f"{name} calls run_bounded_process but never reads launch_failed"
    assert re.search(r"run_bounded_process\(", source)
