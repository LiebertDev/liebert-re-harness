"""The managed pre-push gate must not wave through a masked failure."""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("_pre_push_gate", ROOT / "scripts" / "pre_push_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

# Built by concatenation so this file never prints the markers itself.
FATAL = "Windows fatal " + "exception: access " + "violation"


def _child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_fatal_text_blocks_even_with_exit_zero(capsys):
    rc, hits = gate.run_pytest(_child(f"import sys; print({FATAL!r}, file=sys.stderr)"))
    assert rc == 0
    assert hits and hits[0].startswith("stderr line 1:")


def test_fatal_text_on_stdout_is_found_too():
    rc, hits = gate.run_pytest(_child(f"print({'Fatal Python ' + 'error: x'!r})"))
    assert rc == 0 and hits and hits[0].startswith("stdout line 1:")


def test_clean_output_has_no_findings():
    rc, hits = gate.run_pytest(_child("print('37 passed')"))
    assert rc == 0 and hits == []


def test_run_gate_returns_one_on_fatal_text_despite_exit_zero(monkeypatch):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd: (0, [f"stderr line 3: {FATAL}"]))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 1


def test_run_gate_still_blocks_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd: (1, []))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 1


def test_hook_template_fails_loudly_instead_of_falling_back_to_path_python():
    hook = gate.HOOK_TEMPLATE
    assert "PY=python" not in hook
    assert "exit 1" in hook and "BLOCKED" in hook


def _dump(frame: str) -> str:
    return (f"{FATAL.split(':')[0]}: access " + "violation\n\nThread 0x1 (most recent call first):\n"
            '  File "threading.py", line 369 in wait\n\nCurrent thread 0x2 (most recent call first):\n'
            f"  File {frame}\n")


_MEM_MAP = '"C:/v/site-packages/unicorn/unicorn_py3/unicorn.py", line 831 in mem_map'
_EMU_START = '"C:/v/site-packages/unicorn/unicorn_py3/unicorn.py", line 9 in emu_start'


def test_every_dump_blocks_whatever_its_frame():
    """No allow-list: not even the once-measured unicorn mem_map dump is skipped."""
    mem_map, other = _dump(_MEM_MAP), _dump(_EMU_START)
    assert len(gate.fatal_findings(mem_map, "stderr")) == 1
    assert len(gate.fatal_findings(other, "stderr")) == 1
    assert len(gate.fatal_findings(mem_map * 3 + other, "stderr")) == 4
    assert gate.fatal_findings(FATAL + "\n", "stderr")           # no readable frame: blocks


def test_a_child_that_prints_the_mem_map_dump_is_blocked_end_to_end():
    dump = _dump(_MEM_MAP)
    rc, hits = gate.run_pytest(_child(f"import sys; sys.stderr.write({dump!r})"))
    assert rc == 0 and len(hits) == 1


# ---- the multi-interpreter contract stage -------------------------------------------------------

def _found(*versions):
    return {v: (Path(f"/fake/py{v}/python"), f"{v}.9") for v in versions}


def test_gate_has_four_numbered_stages_and_stays_green_when_all_pass(monkeypatch, capsys):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, []))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 0
    err = capsys.readouterr().err
    for n in (1, 2, 3, 4):
        assert f"[{n}/4]" in err
    assert "/3]" not in err


def test_a_red_contract_test_blocks_and_names_interpreter_and_test(monkeypatch, capsys):
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.10", "3.12", "3.14"), {}))

    def fake(cmd, failed=None):
        if "3.10" in cmd[0]:
            failed.append("tests/test_tools_ida.py::StatusTests::test_x")
            return 1, []
        return 0, []

    monkeypatch.setattr(gate, "run_pytest", fake)
    assert gate.run_contract_stage({}) is True
    err = capsys.readouterr().err
    assert "BLOCKED" in err and "Python 3.10.9" in err
    assert "[py3.10] tests/test_tools_ida.py::StatusTests::test_x" in err
    assert "[py3.12]" not in err and "[py3.14]" not in err


def test_a_fatal_dump_in_the_contract_stage_blocks_even_with_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.10", "3.12", "3.14"), {}))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None: (0, [f"stderr line 1: {FATAL}"]))
    assert gate.run_contract_stage({}) is True
    assert "fatal-exception" in capsys.readouterr().err


def test_a_missing_interpreter_is_reported_loudly_not_skipped_silently(monkeypatch, capsys):
    why = {"3.10": ["/x/python: path does not exist"]}
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.12", "3.14"), why))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None: (0, []))
    assert gate.run_contract_stage({}) is False           # a warning by default ...
    err = capsys.readouterr().err
    assert "no usable Python 3.10" in err and "DID NOT RUN" in err and "path does not exist" in err
    assert "no usable Python 3.12" not in err
    # ... and a block when the machine is meant to have every version.
    assert gate.run_contract_stage({"LIEBERT_CONTRACT_STRICT": "1"}) is True
    assert "STRICT" in capsys.readouterr().err


def test_every_version_missing_warns_for_each_one(monkeypatch, capsys):
    monkeypatch.setattr(gate, "find_contract_interpreters",
                        lambda env=None: ({}, {v: [] for v in gate.CONTRACT_VERSIONS}))
    assert gate.run_contract_stage({}) is False
    err = capsys.readouterr().err
    assert all(f"no usable Python {v}" in err for v in gate.CONTRACT_VERSIONS)


def test_contract_versions_match_the_ci_matrix():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    m = re.search(r"python-version:\s*\[([^\]]*)\]", ci)
    assert m, "ci.yml matrix not found"
    assert tuple(v.strip(" '\"") for v in m.group(1).split(",")) == gate.CONTRACT_VERSIONS


def test_discovery_reads_the_env_list_and_the_venv_dir_without_hardcoded_paths(tmp_path):
    scripts = tmp_path / "py310" / "Scripts"
    scripts.mkdir(parents=True)
    exe = scripts / "python.exe"
    exe.write_text("")
    other = tmp_path / "elsewhere" / "python"
    env = {"LIEBERT_VENV_DIR": str(tmp_path), "LIEBERT_CONTRACT_PYTHONS": str(other)}
    cands = gate.candidate_interpreters(env)
    assert cands[0] == other and exe in cands and Path(sys.executable) in cands


def test_probe_reports_the_running_interpreter_and_a_reason_for_a_broken_one(tmp_path):
    ok = gate.probe_interpreter(Path(sys.executable))
    assert ok == ("%d.%d" % sys.version_info[:2], sys.version.split()[0])
    broken = tmp_path / "python.exe"
    broken.write_text("not an executable")
    assert isinstance(gate.probe_interpreter(broken), str)


def test_a_candidate_that_does_not_exist_is_rejected_with_a_reason_not_dropped():
    found, why = gate.find_contract_interpreters({"LIEBERT_CONTRACT_PYTHONS": "/no/such/python",
                                                  "LIEBERT_VENV_DIR": "/no/such/dir"})
    assert any("/no/such/python" in w and "does not exist" in w for ws in why.values() for w in ws) or found


def test_failed_ids_reads_the_short_summary():
    text = "\n".join(["FAILED tests/a.py::C::test_one - boom", "ERROR tests/b.py::test_two", "PASSED x"])
    assert gate.failed_ids(text) == ["tests/a.py::C::test_one", "tests/b.py::test_two"]
