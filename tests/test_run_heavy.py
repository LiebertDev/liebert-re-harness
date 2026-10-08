"""`scripts/run_heavy.py`: the local one-command run of the heavy tier and its out/heavy summary.

Fast tier: the pytest child is replaced by a tiny Python program that writes a JUnit report and exits, so
nothing here needs IDA or runs the real heavy tier.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("_run_heavy", ROOT / "scripts" / "run_heavy.py")
rh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rh)

# A stand-in for `pytest -m heavy --junitxml=...`: writes the report named by the switch, prints, exits.
FAKE = r"""
import sys
path = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml="))
body = sys.argv[1]
open(path, "w", encoding="utf-8").write(body)
print("fake pytest output")
sys.exit(int(sys.argv[2]))
"""

REPORT = (
    '<?xml version="1.0"?><testsuites><testsuite name="pytest" errors="1" failures="2" skipped="3" tests="10">'
    '<testcase classname="tests.test_a.A" name="test_ok"/>'
    '<testcase classname="tests.test_a.A" name="test_bad"><failure message="x"/></testcase>'
    '<testcase classname="tests.test_b" name="test_boom"><error message="y"/></testcase>'
    '<testcase classname="tests.test_b" name="test_skip"><skipped message="s"/></testcase>'
    '<testcase classname="tests.test_a.A" name="test_bad"><failure message="x again"/></testcase>'
    "</testsuite></testsuites>"
)


def _fake(report: str, code: int) -> list[str]:
    # the script appends --junitxml=...; the fake reads its report body and exit code from argv[1:3]
    return [sys.executable, "-c", FAKE, report, str(code)]


def _run(tmp_path, report=REPORT, code=1, **kw):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    out = tmp_path / "out" / "heavy"
    rc, path = rh.run_heavy(out, command=_fake(report, code), repo_root=repo, **kw)
    return rc, path, json.loads(path.read_text(encoding="utf-8")), repo, out


def test_the_summary_counts_and_failed_names_come_from_the_report(tmp_path):
    rc, path, data, _repo, out = _run(tmp_path)
    assert rc == 1
    assert (data["status"], data["exit_code"]) == ("FAILED", 1)
    assert (data["failed"], data["errors"], data["skipped"], data["passed"]) == (2, 1, 3, 4)
    assert data["failed_tests"] == ["tests.test_a.A::test_bad", "tests.test_b::test_boom"]
    assert data["schema"] == 1 and data["duration_seconds"] >= 0
    assert path.parent == out and re.fullmatch(r"\d{8}T\d{6}Z\.json", path.name)
    assert (out / path.name.replace(".json", ".log")).read_text(encoding="utf-8").startswith("fake pytest output")


def test_started_utc_is_an_iso_utc_timestamp(tmp_path):
    data = _run(tmp_path)[2]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", data["started_utc"])


def test_a_green_run_is_passed_with_exit_zero(tmp_path):
    green = ('<testsuites><testsuite tests="2" failures="0" errors="0" skipped="1">'
             '<testcase classname="t" name="a"/><testcase classname="t" name="b"><skipped/></testcase>'
             "</testsuite></testsuites>")
    rc, _path, data, _repo, _out = _run(tmp_path, green, 0)
    assert rc == 0 and data["status"] == "PASSED"
    assert (data["passed"], data["failed"], data["skipped"], data["failed_tests"]) == (1, 0, 1, [])


def test_a_missing_or_broken_report_is_no_report_not_zero_counts(tmp_path):
    rc, _path, data, _repo, _out = _run(tmp_path, "<not xml", 3)
    assert rc == 3 and data["status"] == "NO_REPORT"
    assert data["passed"] is None and data["failed"] is None and data["failed_tests"] is None


def test_a_missing_report_with_exit_zero_is_still_no_report(tmp_path):
    data = _run(tmp_path, "", 0)[2]
    assert data["status"] == "NO_REPORT" and data["exit_code"] == 0


def test_a_command_that_cannot_start_is_exit_2_with_the_reason(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    rc, path = rh.run_heavy(tmp_path / "o", command=[str(tmp_path / "no-such-interpreter")], repo_root=repo)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert rc == 2 and data["status"] == "NO_REPORT" and data["launch_error"]


def test_files_written_beside_the_real_samples_are_reported(tmp_path):
    repo = tmp_path / "repo"
    (repo / "samples").mkdir(parents=True)
    (repo / "samples" / "keep.exe").write_bytes(b"MZ")
    writer = ("import sys, pathlib\n"
              "p = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--junitxml='))\n"
              "open(p, 'w').write('<testsuite tests=\"0\" failures=\"0\" errors=\"0\" skipped=\"0\"/>')\n"
              "pathlib.Path('samples/keep.exe.i64').write_bytes(b'x')\n")
    _rc, path = rh.run_heavy(tmp_path / "o", command=[sys.executable, "-c", writer], repo_root=repo)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["samples_changed"] == {"added": ["keep.exe.i64"], "removed": []}


def test_a_clean_run_leaves_samples_unchanged_and_no_samples_dir_is_null(tmp_path):
    repo = tmp_path / "repo"
    (repo / "samples").mkdir(parents=True)
    empty_repo = tmp_path / "repo2"
    empty_repo.mkdir()
    _rc, path = rh.run_heavy(tmp_path / "o2", command=_fake(REPORT, 1), repo_root=empty_repo)
    assert json.loads(path.read_text(encoding="utf-8"))["samples_changed"] is None
    _rc, path = rh.run_heavy(tmp_path / "o3", command=_fake(REPORT, 1), repo_root=repo)
    assert json.loads(path.read_text(encoding="utf-8"))["samples_changed"] == {"added": [], "removed": []}


def test_extra_arguments_reach_the_child(tmp_path):
    echo = ("import sys\n"
            "p = next(a.split('=', 1)[1] for a in sys.argv if a.startswith('--junitxml='))\n"
            "open(p, 'w').write('<testsuite tests=\"0\" failures=\"0\" errors=\"0\" skipped=\"0\"/>')\n"
            "print('ARGS', sys.argv[1:])\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "o"
    _rc, path = rh.run_heavy(out, ["-k", "ida"], command=[sys.executable, "-c", echo], repo_root=repo)
    log = (out / path.name.replace(".json", ".log")).read_text(encoding="utf-8")
    assert "'-k', 'ida'" in log


def test_main_prints_a_one_line_summary_and_returns_the_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rh, "REPO_ROOT", tmp_path)
    real = rh.run_heavy
    monkeypatch.setattr(rh, "run_heavy", lambda out, extra=None: real(out, extra, command=_fake(REPORT, 1),
                                                                      repo_root=tmp_path))
    assert rh.main(["--out-dir", str(tmp_path / "o")]) == 1
    printed = capsys.readouterr().out
    assert "status=FAILED" in printed and "FAILED tests.test_b::test_boom" in printed


def test_the_default_output_directory_is_gitignored():
    assert rh.DEFAULT_OUT_DIR == ROOT / "out" / "heavy"
    lines = [ln.strip() for ln in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()]
    assert "out/" in lines


def test_the_real_command_selects_the_heavy_marker():
    src = (ROOT / "scripts" / "run_heavy.py").read_text(encoding="utf-8")
    assert '"-m", "heavy"' in src


@pytest.mark.parametrize("name", ["run_heavy.py"])
def test_the_script_has_no_third_party_import(name):
    text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
    imports = set(re.findall(r"^(?:from|import) (\w+)", text, re.M))
    assert imports <= set(sys.stdlib_module_names) | {"__future__"}
