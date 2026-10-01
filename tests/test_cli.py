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


def test_missing_path_is_a_structured_refusal_not_a_traceback():
    r = _run("identify", "no_such_file_anywhere.bin")
    assert r.returncode == 3
    body = json.loads(r.stdout)
    assert body["status"] in cli.REFUSAL_STATUSES and body["error"] == "FILE_NOT_FOUND"
    assert "Traceback" not in r.stdout + r.stderr


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
def test_cli_cannot_upgrade_a_module_status(monkeypatch, capsys, status, code):
    from liebert_re.tools import formats
    monkeypatch.setattr(formats, "file_identity", lambda path: json.dumps({"ok": status in ("PARTIAL", "READY"), "status": status}))
    assert cli.main(["identify", str(ROOT / "pyproject.toml")]) == code
    assert json.loads(capsys.readouterr().out)["status"] == status


def test_unexpected_exception_is_json_failed_exit_1(monkeypatch, capsys):
    from liebert_re.tools import formats

    def boom(path):
        raise ZeroDivisionError("kaboom")
    monkeypatch.setattr(formats, "file_identity", boom)
    assert cli.main(["identify", str(ROOT / "pyproject.toml")]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["status"] == "FAILED" and body["error_type"] == "ZeroDivisionError" and "kaboom" in body["error"]


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
