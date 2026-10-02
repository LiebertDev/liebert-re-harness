"""The ``liebert-re`` entrypoint: JSON-only output, honest exit codes, lazy imports."""
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import liebert_re.cli as cli

ROOT = Path(__file__).resolve().parent.parent


def _run(*args):
    """Run the CLI in a real subprocess from the repo root (the workspace root is the cwd)."""
    return subprocess.run([sys.executable, "-m", "liebert_re", *args], cwd=ROOT, capture_output=True, text=True)


def test_help_and_version_work():
    helped = _run("--help")
    assert helped.returncode == 0 and "identify" in helped.stdout
    version = _run("--version")
    assert version.returncode == 0 and version.stdout.startswith("liebert-re ")


def test_dunder_main_module_is_importable_without_running():
    # Importing must not execute main(); only `python -m` does (covered above).
    mod = importlib.import_module("liebert_re.__main__")
    assert mod.main is cli.main


def test_identify_a_repo_file_is_json_exit_0():
    r = _run("identify", "pyproject.toml")
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout)
    assert body["command"] == "identify" and body["ok"] is True


@pytest.mark.contract
def test_missing_path_is_a_structured_refusal_not_a_traceback():
    r = _run("identify", "no_such_file_anywhere.bin")
    assert r.returncode == 3
    body = json.loads(r.stdout)
    assert body["status"] in cli.REFUSAL_STATUSES and body["error"] == "FILE_NOT_FOUND"
    assert "Traceback" not in r.stdout + r.stderr


@pytest.mark.contract
def test_packer_without_die_is_exit_3_tool_missing(monkeypatch, capsys):
    # Forced absence via monkeypatch, so the result does not depend on the runner.
    from liebert_re.tools import die
    monkeypatch.setattr(die, "_die_binary", lambda: None)
    code = cli.main(["packer", str(ROOT / "pyproject.toml")])
    body = json.loads(capsys.readouterr().out)
    assert code == 3 and body["status"] == "TOOL_MISSING" and body["status"] in cli.REFUSAL_STATUSES


def test_pe_with_two_modes_is_a_usage_error():
    r = _run("pe", "pyproject.toml", "--sections", "--imports")
    assert r.returncode == 2 and r.stdout == ""


def test_pe_with_no_mode_is_a_usage_error():
    assert _run("pe", "pyproject.toml").returncode == 2


def test_envelope_only_adds_command_key():
    payload = {"status": "PARTIAL", "ok": True, "limitations": ["x"], "nested": {"status": "READY"}}
    out = cli._envelope("probe", payload)
    assert out["command"] == "probe"
    assert {k: v for k, v in out.items() if k != "command"} == payload
    refused = {"ok": False, "status": "TOOL_MISSING", "required_capability": "diec"}
    out = cli._envelope("packer", refused)
    assert {k: v for k, v in out.items() if k != "command"} == refused
    assert cli._envelope("pe", [1, 2]) == {"command": "pe", "result": [1, 2]}


@pytest.mark.parametrize("status,code", [("PARTIAL", 0), ("READY", 0), ("TOOL_MISSING", 3), ("ANALYSIS_LIMITED", 3), ("TIMEOUT", 3)])
@pytest.mark.contract
def test_cli_cannot_upgrade_a_module_status(monkeypatch, capsys, status, code):
    from liebert_re.tools import formats
    monkeypatch.setattr(formats, "file_identity", lambda path: json.dumps({"ok": status in ("PARTIAL", "READY"), "status": status}))
    assert cli.main(["identify", str(ROOT / "pyproject.toml")]) == code
    assert json.loads(capsys.readouterr().out)["status"] == status


@pytest.mark.contract
def test_unexpected_exception_is_json_failed_exit_1(monkeypatch, capsys):
    from liebert_re.tools import formats

    def boom(path):
        raise ZeroDivisionError("kaboom")
    monkeypatch.setattr(formats, "file_identity", boom)
    assert cli.main(["identify", str(ROOT / "pyproject.toml")]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "FAILED" and body["error_type"] == "ZeroDivisionError" and "kaboom" in body["error"]


@pytest.mark.contract
def test_missing_optional_dependency_is_tool_missing_exit_3(monkeypatch, capsys):
    from liebert_re.tools import formats

    def no_dep(path):
        raise ModuleNotFoundError("No module named 'pefile'")
    monkeypatch.setattr(formats, "file_identity", no_dep)
    assert cli.main(["identify", str(ROOT / "pyproject.toml")]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "TOOL_MISSING"


def test_refusal_vocabulary_comes_from_the_shared_status_set():
    from liebert_re.tools.generic_static_probe import ALLOWED_STATUSES
    # PATH_REFUSED is the one name the wrappers emit that the probe set lacks.
    assert cli.REFUSAL_STATUSES - {"PATH_REFUSED"} <= ALLOWED_STATUSES


def test_importing_the_package_loads_no_heavy_dependency():
    code = "import sys, liebert_re; bad=[m for m in ('pefile','capstone','frida') if m in sys.modules]; assert not bad, bad"
    assert subprocess.run([sys.executable, "-c", code], cwd=ROOT).returncode == 0


def test_identify_does_not_import_heavy_modules_or_frida_client():
    code = (
        "import sys; from liebert_re import cli; "
        "cli.main(['identify','pyproject.toml']); "
        "bad=[m for m in ('capstone','frida','liebert_re.dynamic.frida_trace_client') if m in sys.modules]; "
        "assert not bad, bad"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_cli_source_never_imports_the_frida_client():
    import re
    text = (ROOT / "liebert_re" / "cli.py").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\s*(import|from)\s+\S*frida", text)
    code = text.split('"""', 2)[2]  # everything after the module docstring
    assert "frida" not in code


def test_capabilities_reports_a_nonempty_family_set():
    r = _run("capabilities")
    assert r.returncode == 0, r.stderr
    result = json.loads(r.stdout)["families"]
    assert result and sum(published for _named, published in result.values()) > 0


# --- unclassifiable text, structured failures, and the workspace choice ---

@pytest.mark.contract
def test_unrecognised_failure_text_does_not_exit_zero(monkeypatch, capsys):
    from liebert_re.tools import binary
    monkeypatch.setattr(binary, "pe_imports", lambda path: "Something went badly wrong in some new way.")
    code = cli.main(["pe", str(ROOT / "pyproject.toml"), "--imports"])
    body = json.loads(capsys.readouterr().out)
    assert code == 1 and body["status"] == "FAILED" and body["error"] == "UNCLASSIFIED_OUTPUT"


def test_known_text_answers_still_exit_zero(monkeypatch, capsys):
    from liebert_re.tools import binary
    monkeypatch.setattr(binary, "pe_imports", lambda path: "No import table.")
    assert cli.main(["pe", str(ROOT / "pyproject.toml"), "--imports"]) == 0
    capsys.readouterr()


def test_structured_disasm_failure_is_a_refusal_with_english_message(tmp_path):
    f = tmp_path / "notpe.bin"
    f.write_bytes(b"this is not a PE file at all")
    r = subprocess.run([sys.executable, "-m", "liebert_re", "disasm", str(f), "--va", "0x1000"],
                       cwd=tmp_path, capture_output=True, text=True, env=_env())
    body = json.loads(r.stdout)
    assert r.returncode == 3
    assert body["ok"] is False and body["error"] == "INVALID_PE" and body["status"] == "ANALYSIS_LIMITED"
    assert body["message"].startswith("Invalid or corrupt PE file")


def _env():
    import os
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TEACHER")}
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _run_in(cwd, *args):
    return subprocess.run([sys.executable, "-m", "liebert_re", *args], cwd=cwd, capture_output=True, text=True, env=_env())


def test_file_outside_cwd_is_analysed_and_workspace_is_reported(tmp_path):
    here, there = tmp_path / "here", tmp_path / "there"
    here.mkdir()
    there.mkdir()
    f = there / "sample.txt"
    f.write_text("hello")
    r = _run_in(here, "identify", str(f))
    body = json.loads(r.stdout)
    assert r.returncode == 0, r.stdout
    assert body["workspace"] == {"root": str(there.resolve()), "source": "target_parent"}


def test_file_inside_cwd_keeps_cwd_as_workspace(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    r = _run_in(tmp_path, "identify", "a.txt")
    assert r.returncode == 0, r.stdout
    assert json.loads(r.stdout)["workspace"] == {"root": str(tmp_path.resolve()), "source": "default"}


def test_explicit_workspace_is_honoured(tmp_path):
    ws, other = tmp_path / "ws", tmp_path / "other"
    ws.mkdir()
    other.mkdir()
    (ws / "in.txt").write_text("x")
    r = _run_in(other, "--workspace", str(ws), "identify", str(ws / "in.txt"))
    assert r.returncode == 0, r.stdout
    assert json.loads(r.stdout)["workspace"] == {"root": str(ws.resolve()), "source": "--workspace"}


def test_traversal_out_of_explicit_workspace_is_still_refused(tmp_path):
    ws, other = tmp_path / "ws", tmp_path / "other"
    ws.mkdir()
    other.mkdir()
    (other / "secret.txt").write_text("x")
    escape = str(ws / ".." / "other" / "secret.txt")
    r = _run_in(tmp_path, "--workspace", str(ws), "identify", escape)
    body = json.loads(r.stdout)
    assert r.returncode == 3 and body["status"] == "PATH_REFUSED"
    assert body["workspace"]["source"] == "--workspace"


def test_dotdot_relative_path_is_refused_inside_workspace_sandbox(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "secret.txt").write_text("x")
    r = _run_in(ws, "--workspace", str(ws), "identify", "../secret.txt")
    assert r.returncode == 3 and json.loads(r.stdout)["status"] == "PATH_REFUSED"
