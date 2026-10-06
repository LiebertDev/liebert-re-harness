"""The managed pre-push gate must not wave through a masked failure."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("_pre_push_gate", ROOT / "scripts" / "pre_push_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

@pytest.fixture(autouse=True)
def _no_real_registry(monkeypatch, tmp_path_factory):
    """Every test in this file sees a registry path that does not exist, so none of them can read the
    operator's real private target registry. Tests that need another state set the variable again."""
    monkeypatch.setenv("LIEBERT_RE_TARGETS", str(tmp_path_factory.mktemp("noreg") / "absent-targets.txt"))


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
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, [f"stderr line 3: {FATAL}"]))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 1


def test_run_gate_still_blocks_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (1, []))
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

    def fake(cmd, failed=None, **kw):
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
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None, **kw: (0, [f"stderr line 1: {FATAL}"]))
    assert gate.run_contract_stage({}) is True
    assert "fatal-exception" in capsys.readouterr().err


def test_each_contract_interpreter_gets_its_own_basetemp(monkeypatch):
    """The three interpreters run one after another; none may share a pytest temp root with another or
    with the suite stage, or what one leaves behind is state the next one sees."""
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.10", "3.12", "3.14"), {}))
    seen = []

    def fake(cmd, failed=None, **kw):
        assert cmd.count("--basetemp") == 1
        seen.append(cmd[cmd.index("--basetemp") + 1])
        return 0, []

    monkeypatch.setattr(gate, "run_pytest", fake)
    assert gate.run_contract_stage({}) is False
    assert len(seen) == 3 and len(set(seen)) == 3
    assert all(Path(p).parent.name == f"liebert-gate-{os.getpid()}" for p in seen)
    assert all(Path(p).parent.is_dir() for p in seen), "pytest creates the basetemp but not its parent"
    shutil.rmtree(Path(seen[0]).parent, ignore_errors=True)
    assert gate.isolated_basetemp("suite") != gate.isolated_basetemp("discipline")


def test_a_missing_interpreter_is_reported_loudly_not_skipped_silently(monkeypatch, capsys):
    why = {"3.10": ["/x/python: path does not exist"]}
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.12", "3.14"), why))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None, **kw: (0, []))
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


# ---- failure evidence: a BLOCKed stage keeps its full output ------------------------------------------
def _use_evidence_dir(monkeypatch, tmp_path):
    d = tmp_path / "gate_failures"
    monkeypatch.setattr(gate, "EVIDENCE_DIR", d)
    return d


def test_a_blocked_stage_saves_its_full_unfiltered_output_and_names_the_file(monkeypatch, tmp_path, capsys):
    d = _use_evidence_dir(monkeypatch, tmp_path)
    cmd = _child("import sys; print('FAILED tests/x.py::Cls::test_the_one_that_fell - boom'); "
                 "print('traceback detail', file=sys.stderr); sys.exit(1)")
    rc, _ = gate.run_pytest(cmd)
    assert rc == 1
    path = gate.save_evidence(cmd, "contract", "py3.10.11")
    assert list(d.glob("*.log")) == [path]
    assert path.name.endswith("Z_contract_py3.10.11.log") and path.name[:8].isdigit()
    body = path.read_text(encoding="utf-8")
    assert "test_the_one_that_fell" in body and "traceback detail" in body
    assert str(path) in capsys.readouterr().err


def test_a_passing_gate_writes_no_evidence(monkeypatch, tmp_path):
    d = _use_evidence_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, []))
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 0
    assert not d.exists()


def test_evidence_is_not_saved_for_a_run_whose_output_is_not_on_hand(monkeypatch, tmp_path):
    d = _use_evidence_dir(monkeypatch, tmp_path)
    gate.run_pytest(_child("print('x')"))
    assert gate.save_evidence(["some", "other", "cmd"], "suite", "py3.14") is None
    assert not d.exists()


def test_only_the_newest_ten_evidence_files_are_kept(monkeypatch, tmp_path):
    d = _use_evidence_dir(monkeypatch, tmp_path)
    cmd = _child("import sys; sys.exit(1)")
    paths = []
    for _ in range(14):
        gate.run_pytest(cmd)
        paths.append(gate.save_evidence(cmd, "suite", "py3.14"))
    kept = sorted(f.name for f in d.glob("*.log"))
    assert len(kept) == gate.EVIDENCE_KEEP == 10
    assert kept == sorted(p.name for p in paths[-10:])


def test_the_evidence_directory_is_gitignored():
    import subprocess
    r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index",
                        str(gate.EVIDENCE_DIR / "x.log")])
    assert r.returncode == 0


# --- a stage that cannot be judged BLOCKs with an honest status; the gate never hangs ---------------

def _big_unicode_child(tmp_path) -> list[str]:
    """A child that writes UTF-8 CJK and emoji, then far more than a pipe buffer holds. If the relay
    thread dies on the first line, the child blocks on the full pipe and the run never ends."""
    script = tmp_path / "child.py"
    script.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(('ok \\u4e2d\\u6587 \\U0001F600 end\\n' + 'filler line\\n' * 300000)"
        ".encode('utf-8'))\n", encoding="utf-8")
    return [sys.executable, str(script)]


def test_output_the_console_encoding_cannot_show_neither_kills_the_relay_nor_hangs(monkeypatch, tmp_path, capsys):
    import io
    sink = io.TextIOWrapper(io.BytesIO(), encoding="cp1254", errors="strict")
    monkeypatch.setattr(sys, "stdout", sink)
    rc, hits = gate.run_pytest(_big_unicode_child(tmp_path), timeout=120)
    sink.flush()
    shown = sink.buffer.getvalue().decode("cp1254")
    assert rc == 0 and hits == []
    bs = chr(92)
    assert bs + "u4e2d" + bs + "u6587" in shown and bs + "U0001f600" in shown   # the loss is visible, as escapes
    assert shown.count("filler line") == 300000                         # and nothing after it was dropped
    assert "中文" in gate._LAST_RUN[2]                          # the evidence copy keeps the real text
    assert "cannot show" in capsys.readouterr().err


def test_a_dead_relay_thread_blocks_with_a_status_instead_of_waiting(monkeypatch, tmp_path):
    class Dying:
        encoding = "utf-8"

        def write(self, s):
            raise RuntimeError("relay thread killed on purpose")

        def flush(self):
            pass

    monkeypatch.setattr(sys, "stdout", Dying())
    with pytest.raises(gate.GateStageError) as ei:
        gate.run_pytest(_big_unicode_child(tmp_path), timeout=120)
    assert ei.value.status == "GATE_RELAY_FAILURE" and "killed on purpose" in ei.value.detail


def test_a_stage_past_its_ceiling_is_killed_and_reported_not_waited_for():
    import time
    t0 = time.monotonic()
    with pytest.raises(gate.GateStageError) as ei:
        gate.run_pytest(_child("import time; time.sleep(120)"), timeout=2)
    assert ei.value.status == "GATE_STAGE_TIMEOUT"
    assert time.monotonic() - t0 < 30


def test_every_stage_has_a_finite_ceiling_above_its_typical_run():
    assert gate.stage_timeout("suite", {}) >= 300          # suite runs 86-92 s
    assert gate.stage_timeout("contract", {}) >= 60        # one interpreter runs about 8 s
    assert gate.stage_timeout("nonexistent", {}) > 0
    assert gate.stage_timeout("suite", {"LIEBERT_GATE_STAGE_TIMEOUT": "7"}) == 7
    assert gate.stage_timeout("suite", {"LIEBERT_GATE_STAGE_TIMEOUT": "junk"}) == gate.STAGE_TIMEOUTS["suite"]


@pytest.mark.parametrize("stage_hit", ["discipline", "suite"])
def test_run_gate_blocks_when_a_stage_cannot_be_judged(monkeypatch, capsys, stage_hit):
    def fake(cmd, **kw):
        if kw.get("stage") == stage_hit:
            raise gate.GateStageError("GATE_STAGE_TIMEOUT", "boom")
        return 0, []
    monkeypatch.setattr(gate, "run_pytest", fake)
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 1
    assert "GATE_STAGE_TIMEOUT" in capsys.readouterr().err


def test_a_contract_stage_that_cannot_be_judged_blocks_and_still_runs_the_other_interpreters(monkeypatch, capsys):
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.10", "3.12", "3.14"), {}))
    calls = []

    def fake(cmd, failed=None, **kw):
        calls.append(cmd)
        if len(calls) == 1:
            raise gate.GateStageError("GATE_RELAY_FAILURE", "x")
        return 0, []
    monkeypatch.setattr(gate, "run_pytest", fake)
    assert gate.run_contract_stage() is True
    assert len(calls) == 3 and "GATE_RELAY_FAILURE" in capsys.readouterr().err


# ---- first-chance REPORT MODE ----------------------------------------------------------------------
NOTE = "behaviour monitor noise, measured in a bare interpreter"


@pytest.fixture(autouse=True)
def _no_report_mode_unless_a_test_sets_it(monkeypatch):
    for name in (gate.FIRSTCHANCE_ENV, gate.FIRSTCHANCE_NOTE_ENV, "CI", "GITHUB_ACTIONS"):
        monkeypatch.delenv(name, raising=False)


def _gate_with(monkeypatch, tmp_path, run):
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "run_pytest", run)
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)


def _report(monkeypatch, note=NOTE):
    monkeypatch.setenv(gate.FIRSTCHANCE_ENV, "report")
    if note is not None:
        monkeypatch.setenv(gate.FIRSTCHANCE_NOTE_ENV, note)


def test_a_trace_blocks_without_the_flag(monkeypatch, tmp_path):
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (0, [f"stderr line 1: {FATAL}"]))
    assert gate.run_gate([["HEAD"]]) == 1
    assert not (tmp_path / "dataset").exists()


def test_a_trace_is_reported_not_blocked_with_flag_and_reason_and_is_recorded(monkeypatch, tmp_path, capsys):
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (0, [f"stderr line 1: {FATAL}", f"stderr line 9: {FATAL}"]))
    _report(monkeypatch)
    assert gate.run_gate([["HEAD"]]) == 0
    err = capsys.readouterr().err
    assert "REPORT MODE" in err and NOTE in err and "2 first-chance trace line(s)" in err
    record = json.loads(next((tmp_path / "dataset" / "evidence" / "pre_push_gate").glob("*.json")).read_text())
    assert record["mode"] == "report" and record["note"] == NOTE and record["gate_exit"] == 0
    assert record["traces_total"] == 4 and len(record["stages"]) == 2


@pytest.mark.parametrize("note", [None, "", "   "])
def test_flag_without_a_reason_is_ignored_and_still_blocks(monkeypatch, tmp_path, capsys, note):
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (0, [f"stderr line 1: {FATAL}"]))
    _report(monkeypatch, note)
    assert gate.run_gate([["HEAD"]]) == 1
    assert "is ignored" in capsys.readouterr().err


def test_report_mode_is_never_active_in_ci(monkeypatch, tmp_path):
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (0, [f"stderr line 1: {FATAL}"]))
    _report(monkeypatch)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert gate.run_gate([["HEAD"]]) == 1


def test_a_real_failure_still_blocks_in_report_mode(monkeypatch, tmp_path):
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (1, [f"stderr line 1: {FATAL}"]))
    _report(monkeypatch)
    assert gate.run_gate([["HEAD"]]) == 1
    _gate_with(monkeypatch, tmp_path, lambda cmd, **kw: (1, []))
    assert gate.run_gate([["HEAD"]]) == 1


def test_timeouts_and_relay_failures_still_block_in_report_mode(monkeypatch, tmp_path):
    def boom(cmd, **kw):
        raise gate.GateStageError("GATE_RELAY_FAILURE", "x")
    _gate_with(monkeypatch, tmp_path, boom)
    _report(monkeypatch)
    assert gate.run_gate([["HEAD"]]) == 1


def test_the_contract_stage_honours_report_mode_only_for_traces(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "find_contract_interpreters", lambda env=None: (_found("3.10", "3.12", "3.14"), {}))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None, **kw: (0, [f"stderr line 1: {FATAL}"]))
    _report(monkeypatch)
    assert gate.run_contract_stage({}) is False
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, failed=None, **kw: (1, [f"stderr line 1: {FATAL}"]))
    assert gate.run_contract_stage({}) is True


def test_the_flag_is_written_into_no_file():
    for text in (gate.HOOK_TEMPLATE, (gate.ROOT / "pytest.ini").read_text(), (gate.ROOT / ".github" / "workflows" / "ci.yml").read_text()):
        assert gate.FIRSTCHANCE_ENV not in text


# ---- the product-name rule must never be silently inactive --------------------------------------
# The registry holds real names, so tests only ever write placeholder names to a temp file.
_PLACEHOLDER = "TARGET-01 | Examplecorp Widget; Widgetpro | test category\n"


def _gate_with_registry(monkeypatch, capsys, path, content=None):
    if content is not None:
        path.write_text(content, encoding="utf-8")
    monkeypatch.setenv("LIEBERT_RE_TARGETS", str(path))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, []))
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    rc = gate.run_gate([["HEAD"]])
    lines = [x for x in capsys.readouterr().err.splitlines() if x.strip()]
    return rc, lines


def test_absent_registry_does_not_block_but_the_last_line_names_the_inactive_rule(monkeypatch, capsys, tmp_path):
    path = tmp_path / "targets.txt"
    rc, lines = _gate_with_registry(monkeypatch, capsys, path)
    assert rc == 0
    assert lines[-1] != "pre-push gate: ok."
    assert lines[-1].startswith("pre-push gate: ok,")
    assert "product-name rule INACTIVE" in lines[-1] and "no private target registry" in lines[-1]
    assert str(path) in lines[-1]
    assert any(x.startswith("pre-push gate: rules:") and "INACTIVE" in x for x in lines)


def test_empty_registry_is_told_apart_from_an_absent_one(monkeypatch, capsys, tmp_path):
    path = tmp_path / "targets.txt"
    rc, lines = _gate_with_registry(monkeypatch, capsys, path, "# only a comment\n\n")
    assert rc == 0
    assert "INACTIVE" in lines[-1] and "NO entries" in lines[-1]
    assert "no private target registry" not in lines[-1]
    state_empty = gate.product_rule_state()[0]
    path.unlink()
    assert (state_empty, gate.product_rule_state()[0]) == ("empty", "absent")


def test_malformed_registry_still_blocks_through_the_real_message_scan(monkeypatch, tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("this is not a registry line\n", encoding="utf-8")
    monkeypatch.setenv("LIEBERT_RE_TARGETS", str(path))
    assert gate.product_rule_state()[0] == "malformed"
    with pytest.raises(ValueError):                 # run_gate turns this into a BLOCK (hits)
        gate.message_findings([["HEAD"]])


def test_malformed_registry_blocks_the_gate_and_never_prints_the_line(monkeypatch, capsys, tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("SECRETLINE-not-a-registry-line\n", encoding="utf-8")
    monkeypatch.setenv("LIEBERT_RE_TARGETS", str(path))
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, []))
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    assert gate.run_gate([["HEAD"]]) == 1
    err = capsys.readouterr().err
    assert "BLOCKED" in err and "could not run the message scan" in err
    assert "SECRETLINE" not in err


def test_populated_registry_is_reported_active_with_probes(monkeypatch, capsys, tmp_path):
    path = tmp_path / "targets.txt"
    rc, lines = _gate_with_registry(monkeypatch, capsys, path, _PLACEHOLDER)
    assert rc == 0
    assert lines[-1].startswith("pre-push gate: ok.") and "product-name rule active" in lines[-1]
    assert "INACTIVE" not in "\n".join(lines)
    state, text = gate.product_rule_state()
    assert state == "active" and "1 target(s)" in text and "2 name probe(s)" in text
    assert "Examplecorp" not in "\n".join(lines)
    assert len(gate._discipline()._denylist_probes()) == 2


def test_inactive_rule_is_also_the_last_line_when_the_gate_blocks(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (1, []))
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    assert gate.run_gate([["HEAD"]]) == 1
    last = [x for x in capsys.readouterr().err.splitlines() if x.strip()][-1]
    assert "BLOCKED" in last and "product-name rule INACTIVE" in last


def test_the_gates_own_pytest_runs_print_skip_reasons(monkeypatch):
    seen = []
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (seen.append(cmd), (0, []))[1])
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    monkeypatch.setattr(gate, "message_findings", lambda ranges: [])
    gate.run_gate([["HEAD"]])
    assert len(seen) == 2 and all("-rs" in c for c in seen)
