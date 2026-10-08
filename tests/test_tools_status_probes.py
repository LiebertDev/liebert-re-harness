"""The status probes for the tools that had none: yara_x_status, upx_status, il2cpp_status,
dex_status, jvm_status (all four JADX/UPX/YARA-X/Il2CppDumper resolvers) and frida_status.

Same contract as die_status/capa_status/pe_sieve_status: a JSON string, `ok`/`tool`/`status`
always present, never an exception, and "the file exists" is kept apart from "it runs".

Two tiers. The `contract` classes need no tool installed: they pin the statuses a machine
WITHOUT the tool must produce (TOOL_MISSING with a teaching `detail`), the found-but-broken
branches (TIMEOUT, ANALYSIS_LIMITED), where the tool was resolved from, and frida's refusal to
call a host install "ready". The `heavy` classes call the real tool when this machine has it
and skip when it does not.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

import liebert_re.dynamic.lab_gate as lg
import liebert_re.tools.dex as dex
import liebert_re.tools.il2cpp as il2cpp
import liebert_re.tools.jvm as jvm
import liebert_re.tools.upx as upx
import liebert_re.tools.yara_x as yara_x
from liebert_re.bounded_subprocess import BoundedProcessResult

# (module, status function, resolver name, env var that overrides the resolver, expected tool name)
PROBES = {
    "yara_x": (yara_x, "yara_x_status", "_yara_x_binary", "YARA_X_EXE", "yara_x_status"),
    "upx": (upx, "upx_status", "_upx_binary", "UPX_HOME", "upx_status"),
    "il2cpp": (il2cpp, "il2cpp_status", "_il2cppdumper", "IL2CPPDUMPER_EXE", "il2cpp_status"),
    "dex": (dex, "dex_status", "_jadx", "JADX_EXE", "dex_status"),
    "jvm": (jvm, "jvm_status", "_jadx", "JADX_EXE", "jvm_status"),
}
# What a successful probe run prints, per tool, so the version/usable parsing is pinned.
GOOD_OUTPUT = {
    "yara_x": ("yara-x-cli 1.20.0\n", "yara-x-cli 1.20.0"),
    "upx": ("upx 4.2.4\nUCL data compression library 1.03\n", "upx 4.2.4"),
    "il2cpp": ("usage: Il2CppDumper <executable-file> <global-metadata> <output-directory>\n", None),
    "dex": ("1.5.6\n", "1.5.6"),
    "jvm": ("1.5.6\n", "1.5.6"),
}


def _call(name):
    module, fn, *_ = PROBES[name]
    out = getattr(module, fn)()
    assert isinstance(out, str), "a status probe returns a JSON string"
    return json.loads(out)


def _result(stdout="", stderr="", returncode=0, timed_out=False):
    return BoundedProcessResult(returncode, stdout, stderr, timed_out=timed_out)


@pytest.mark.contract
class TestStatusProbeContract:
    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_unresolvable_tool_is_tool_missing_and_says_what_to_do(self, name):
        module, _fn, resolver, env, tool = PROBES[name]
        with mock.patch.object(module, resolver, return_value=None):
            data = _call(name)
        assert (data["ok"], data["tool"], data["status"]) == (False, tool, "TOOL_MISSING")
        assert data["resolved"] is False
        assert env in data["detail"], "the reply must name the variable that fixes it"
        assert data["required_capability"]
        assert "binary" not in data and "version" not in data

    @pytest.mark.parametrize("name", ["dex", "jvm"])
    def test_missing_jadx_still_lists_what_works_without_it(self, name):
        module, *_ = PROBES[name]
        with mock.patch.object(module, "_jadx", return_value=None):
            data = _call(name)
        assert "classes" in data["operations_without_the_tool"]
        assert "decompile_class" not in data["operations_without_the_tool"]
        assert "Java" in data["detail"]

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_running_tool_reports_version_runnable_and_source(self, name, tmp_path):
        module, _fn, resolver, env, tool = PROBES[name]
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        stdout, version = GOOD_OUTPUT[name]
        with mock.patch.object(module, resolver, return_value=str(exe)), \
             mock.patch.object(module, "run_bounded_process", return_value=_result(stdout)) as run:
            data = _call(name)
        assert (data["ok"], data["status"], data["runnable"]) == (True, "OK", True)
        assert data["binary"] == str(exe)
        assert data["resolved_by"]
        assert run.call_args.kwargs["timeout_seconds"] <= 30, "a status probe is short"
        if version is not None:
            assert data["version"] == version
        # The tool is run with a version/help switch only, never on an input file.
        assert len(run.call_args.args[0]) == 2

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_env_variable_is_reported_as_the_source_when_it_resolved_the_tool(self, name, tmp_path):
        module, _fn, resolver, env, _tool = PROBES[name]
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        stdout, _ = GOOD_OUTPUT[name]
        with mock.patch.dict(os.environ, {env: str(exe)}), \
             mock.patch.object(module, resolver, return_value=str(exe)), \
             mock.patch.object(module, "run_bounded_process", return_value=_result(stdout)):
            data = _call(name)
        assert data["status"] == "OK" and data["resolved_by"] == env

    @pytest.mark.parametrize("name", ["dex", "jvm"])
    def test_env_source_is_kept_when_which_would_refuse_the_file(self, name, tmp_path):
        # shutil.which rejects a file with no executable bit/extension (3.12+ on Windows, every
        # Python on Linux), so the attribution must not depend on which() accepting JADX_EXE.
        # which() is forced to refuse here so the case is the same on every interpreter and OS.
        module, _fn, resolver, env, _tool = PROBES[name]
        exe = tmp_path / "jadx-launcher"
        exe.write_bytes(b"")
        with mock.patch.dict(os.environ, {env: str(exe)}),              mock.patch.object(module, resolver, return_value=str(exe)),              mock.patch.object(module.shutil, "which", return_value=None),              mock.patch.object(module, "run_bounded_process", return_value=_result(GOOD_OUTPUT[name][0])):
            data = _call(name)
        assert data["status"] == "OK" and data["resolved_by"] == env

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_file_that_does_not_run_is_analysis_limited_not_ok(self, name, tmp_path):
        module, _fn, resolver, *_ = PROBES[name]
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        with mock.patch.object(module, resolver, return_value=str(exe)), \
             mock.patch.object(module, "run_bounded_process", return_value=_result("", "boom", 1)):
            data = _call(name)
        assert (data["ok"], data["status"], data["runnable"]) == (False, "ANALYSIS_LIMITED", False)
        assert data["binary"] == str(exe)

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_hung_tool_is_timeout(self, name, tmp_path):
        module, _fn, resolver, *_ = PROBES[name]
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        with mock.patch.object(module, resolver, return_value=str(exe)), \
             mock.patch.object(module, "run_bounded_process",
                               return_value=_result(returncode=1, timed_out=True)):
            data = _call(name)
        assert (data["ok"], data["status"]) == (False, "TIMEOUT")

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_an_unexpected_failure_is_a_json_status_not_an_exception(self, name, tmp_path):
        module, _fn, resolver, *_ = PROBES[name]
        exe = tmp_path / "fake-tool.exe"
        exe.write_bytes(b"")
        with mock.patch.object(module, resolver, return_value=str(exe)), \
             mock.patch.object(module, "run_bounded_process", side_effect=PermissionError(13, "denied")):
            data = _call(name)
        assert data["ok"] is False and data["status"] == "ANALYSIS_LIMITED"

    def test_il2cpp_without_a_readable_version_resource_is_still_ok_with_a_null_version(self, tmp_path):
        exe = tmp_path / "Il2CppDumper.exe"
        exe.write_bytes(b"not a PE: there is no version resource to read")
        stdout, _ = GOOD_OUTPUT["il2cpp"]
        with mock.patch.object(il2cpp, "_il2cppdumper", return_value=str(exe)),              mock.patch.object(il2cpp, "run_bounded_process", return_value=_result(stdout)):
            data = _call("il2cpp")
        assert data["status"] == "OK" and data["version"] is None
        assert data["version_source"] == "unavailable", "a missing version is said to be missing, never guessed"

    def test_il2cpp_help_without_its_usage_line_is_not_a_working_tool(self, tmp_path):
        exe = tmp_path / "Il2CppDumper.exe"
        exe.write_bytes(b"")
        with mock.patch.object(il2cpp, "_il2cppdumper", return_value=str(exe)), \
             mock.patch.object(il2cpp, "run_bounded_process", return_value=_result("something else\n")):
            data = _call("il2cpp")
        assert data["status"] == "ANALYSIS_LIMITED"

    def test_yara_x_status_lists_rulesets_with_install_state(self, tmp_path):
        exe = tmp_path / "yr.exe"
        exe.write_bytes(b"")
        with mock.patch.object(yara_x, "_yara_x_binary", return_value=str(exe)), \
             mock.patch.object(yara_x, "run_bounded_process", return_value=_result(GOOD_OUTPUT["yara_x"][0])):
            data = _call("yara_x")
        assert set(data["rulesets"]) == set(yara_x._RULESETS)
        assert all("installed" in v for v in data["rulesets"].values())


@pytest.mark.contract
class TestFridaStatusContract:
    def _call(self, spec=None, which=None, run=None, version="17.0.0"):
        patches = [
            mock.patch("importlib.util.find_spec", return_value=spec),
            mock.patch("shutil.which", return_value=which),
            mock.patch("importlib.metadata.version", return_value=version),
        ]
        if run is not None:
            patches.append(mock.patch("liebert_re.bounded_subprocess.run_bounded_process", return_value=run))
        for p in patches:
            p.start()
        try:
            out = lg.frida_status()
        finally:
            for p in reversed(patches):
                p.stop()
        assert isinstance(out, str)
        return json.loads(out)

    def test_no_host_frida_is_tool_missing_and_says_the_harness_is_not_blocked(self):
        data = self._call()
        assert (data["ok"], data["tool"], data["status"]) == (False, "frida_status", "TOOL_MISSING")
        assert "does NOT block" in data["detail"] and "guest" in data["detail"]
        assert data["host_frida_used_by_harness"] is False

    def test_a_host_install_is_never_reported_as_ready_for_the_harness(self):
        spec = mock.Mock(origin="C:/site-packages/frida/__init__.py")
        data = self._call(spec=spec, which="C:/bin/frida.exe", run=_result("17.0.0\n"))
        assert (data["ok"], data["status"]) == (True, "OK")
        assert data["host_frida"]["python_library"]["found"] is True
        assert data["host_frida"]["python_library"]["version"] == "17.0.0"
        assert data["host_frida"]["cli"]["runnable"] is True
        assert data["host_frida_used_by_harness"] is False
        assert data["harness_client"]["uses_host_frida"] is False
        assert "guest" in data["harness_client"]["runs_where"]
        assert data["harness_client"]["guest_probed"] is False
        assert "does NOT mean the harness can" in data["note"]

    def test_cli_that_resolves_but_does_not_run_is_analysis_limited(self):
        data = self._call(which="C:/bin/frida.exe", run=_result("", "no", 1))
        assert (data["ok"], data["status"]) == (False, "ANALYSIS_LIMITED")
        assert data["host_frida"]["cli"]["found"] is True and data["host_frida"]["cli"]["runnable"] is False

    def test_hung_cli_without_a_library_is_timeout(self):
        data = self._call(which="C:/bin/frida.exe", run=_result(returncode=1, timed_out=True))
        assert data["status"] == "TIMEOUT"

    def test_it_reports_which_interpreter_answered(self):
        assert self._call()["interpreter"]["executable"] == sys.executable

    def test_never_raises(self):
        with mock.patch("importlib.util.find_spec", side_effect=RuntimeError("x")):
            data = json.loads(lg.frida_status())
        assert data["status"] == "ANALYSIS_LIMITED" and data["ok"] is False

    def test_probing_frida_never_imports_it(self):
        code = ("import sys, json; from liebert_re.dynamic import lab_gate; lab_gate.frida_status(); "
                "assert 'frida' not in sys.modules, 'frida was imported'")
        import subprocess
        root = Path(__file__).resolve().parent.parent
        done = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True)
        assert done.returncode == 0, done.stderr


def _real(name):
    module, _fn, resolver, *_ = PROBES[name]
    if getattr(module, resolver)() is None:
        pytest.skip(f"{name}: tool not installed on this machine")


@pytest.mark.heavy
class TestRealStatusProbes:
    """Calls the real tool for each probe; skips on a machine without it."""

    @pytest.mark.parametrize("name", sorted(PROBES))
    def test_real_tool_resolves_runs_and_reports_where_from(self, name):
        _real(name)
        data = _call(name)
        assert (data["ok"], data["status"], data["runnable"]) == (True, "OK", True)
        assert data["binary"] and Path(data["binary"]).is_file()
        assert data["resolved_by"] in {"YARA_X_EXE", "YARA_X_HOME", "UPX_HOME", "IL2CPPDUMPER_EXE", "JADX_EXE",
                                       "PATH", "known_install", "bundled_fallback"}
        if name != "il2cpp" or os.name == "nt":
            assert data["version"]

    def test_real_frida_host_install_is_not_called_ready_for_the_harness(self):
        data = json.loads(lg.frida_status())
        if data["status"] == "TOOL_MISSING":
            pytest.skip("no host frida for this interpreter or on PATH")
        assert data["status"] == "OK"
        assert data["host_frida_used_by_harness"] is False
        assert data["harness_client"]["uses_host_frida"] is False
