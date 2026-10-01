"""Tests for scripts/case_purge.py (the case-artifact quarantine tool).

Everything runs against throwaway fixtures under pytest's tmp_path; the quarantine
location is redirected there too. Nothing touches a real case or this repository.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "case_purge.py"
_spec = importlib.util.spec_from_file_location("case_purge", SCRIPT)
cp = importlib.util.module_from_spec(_spec)
sys.modules["case_purge"] = cp
_spec.loader.exec_module(cp)

MARK = '{"liebert_case": 1, "name": "%s", "status": "open"}\n'
GITIGNORE = ("cases/**\n!cases/*/\n!cases/*/REPORT.md\n!cases/*/knowledge/\n"
             "!cases/*/knowledge/**\n!cases/*/.liebert-case\n")


def _w(p: Path, data=b"x" * 64):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())


def _snap(root: Path) -> dict:
    out = {}
    for r, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            p = Path(r) / f
            out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def _link(link: Path, target: Path):
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("cannot create symlink")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if r.returncode != 0:
            pytest.skip("cannot create junction")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """repo (git-initialised, committed) + redirected quarantine root."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    monkeypatch.setattr(cp.tempfile, "tempdir", str(tmpdir))
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "fixture")
    _w(repo / ".gitignore", GITIGNORE)
    _w(repo / "liebert_re" / "__init__.py", "# src\n")
    _w(repo / "docs" / "sample_notes.i64", "outside cases; must never be touched\n")
    c = repo / "cases" / "alpha"
    _w(c / ".liebert-case", MARK % "alpha")
    _w(c / "REPORT.md", "# report\n")
    _w(c / "knowledge" / "technique.md", "# generalised\n")
    _w(c / "knowledge" / "ida" / "type.til", b"t" * 40)
    _w(c / "ida" / "lessons.writeup.md", "# kept writeup\n")
    _w(c / "ida" / "target.i64", b"i" * 5000)
    _w(c / "ida" / "target.id0", b"0" * 300)
    _w(c / "samples" / "alpha.exe", b"MZ" * 100)
    _w(c / "dumps" / "proc.dmp", b"d" * 900)
    _w(c / "ida" / "scratch-ideas.md", "# my valuable ideas\n")
    _w(c / "scratch" / "scratch-ideas.md", "# more ideas\n")
    _w(c / "scratch" / "notes.md", "# notes\n")
    _w(c / "decomp" / "main.decomp.md", "tool dump\n")
    _w(c / "decomp" / "main.decomp.c", "int main(){}\n")
    _w(c / "my_keygen.py", "print(1)\n")
    b = repo / "cases" / "beta"
    _w(b / ".liebert-case", MARK % "beta")
    _w(b / "ida" / "b.i64", b"b" * 100)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "baseline")
    return repo, tmpdir


# ---------------------------------------------------------------- scope fence
BAD = ["", ".", "..", "../x", "..\\x", "a/b", "a\\b", "C:\\Windows", "/etc", "x:stream",
       "foo\n", "foo ", " foo", "-lead", ".hidden", "a..b", "CON", "nul", "lpt1",
       ".git", "liebert_re", "tests", "docs", "scripts", "x" * 65, "\u0430bc", None, 0]


@pytest.mark.parametrize("name", BAD)
def test_bad_names_refused(env, name):
    repo, _ = env
    with pytest.raises(cp.ScopeError):
        cp.validate_name(name)
    with pytest.raises(cp.ScopeError):
        cp.resolve_case_target(repo, name)


def test_good_names():
    for n in ["a", "crackme-alpha", "CTF_2026-x1", "x" * 64]:
        assert cp.validate_name(n) == n


def test_repo_without_dotgit_and_wrong_root_refused(env, tmp_path):
    repo, _ = env
    outside = tmp_path / "outside"
    _w(outside / "evil_target" / ".liebert-case", MARK % "evil_target")
    for bad_repo in (outside, repo / "cases", repo / "liebert_re"):
        with pytest.raises(cp.ScopeError):
            cp.resolve_case_target(bad_repo, "evil_target" if bad_repo == outside else "alpha")


def test_no_marker_and_liar_marker_refused(env):
    repo, _ = env
    _w(repo / "cases" / "nomarker" / "x.i64")
    _w(repo / "cases" / "liar" / ".liebert-case", MARK % "other")
    _w(repo / "cases" / "liar" / "x.i64")
    for n in ("nomarker", "liar"):
        with pytest.raises(cp.ScopeError):
            cp.resolve_case_target(repo, n)
        assert cp.main(["--repo", str(repo), "purge", n, "--execute", "--yes"]) == 3
    assert (repo / "cases" / "liar" / "x.i64").exists()


def test_missing_case_is_not_found(env):
    repo, _ = env
    with pytest.raises(cp.CaseNotFound):
        cp.resolve_case_target(repo, "ghost")


def test_junction_as_case_dir_and_inside_tree_refused(env, tmp_path):
    repo, _ = env
    victim = tmp_path / "victim"
    _w(victim / ".liebert-case", MARK % "evil")
    _w(victim / "keep.i64")
    _link(repo / "cases" / "evil", victim)
    assert cp.main(["--repo", str(repo), "purge", "evil", "--execute", "--yes"]) == 3
    assert (victim / "keep.i64").exists()
    inner = tmp_path / "inner_victim"
    _w(inner / "v.dmp")
    _link(repo / "cases" / "alpha" / "artifacts_link", inner)
    before = _snap(repo)
    assert cp.main(["--repo", str(repo), "purge", "alpha", "--execute", "--yes"]) == 3
    assert _snap(repo) == before and (inner / "v.dmp").exists()


# ------------------------------------------------------------ classification
def test_keep_beats_every_purge_glob():
    samples = [g.replace("*", "x").replace("[0-9]", "1") for g in cp.PURGE_FILE_GLOBS]
    for s in samples:
        for keepdir in ("knowledge", "keep"):
            assert cp.classify(f"{keepdir}/{s}") == "keep"
            assert cp.classify(f"{keepdir}/ida/ghidra/{s}") == "keep"


def test_keep_wins_even_if_a_careless_pattern_is_added(monkeypatch):
    monkeypatch.setattr(cp, "PURGE_FILE_GLOBS", cp.PURGE_FILE_GLOBS + ("*", "*.*"))
    for rel in ("REPORT.md", ".liebert-case", "knowledge/a.md", "knowledge/x.i64",
                "ida/lessons.writeup.md", "keep/anything.exe"):
        assert cp.classify(rel) == "keep"


def test_artifact_classes():
    for rel in ["ida/a.i64", "x.idb", "a.id0", "t.asm", "p.rep/db.gbf", "m.dmp", "core.123",
                "t.exe", "samples/anything", "run.log", "frida-x.js", "scratch/tmp.txt"]:
        assert cp.classify(rel) == "purge", rel
    for rel in ["my_keygen.py", "idea.txt", "README.md", "corefile.md"]:
        assert cp.classify(rel) == "unclassified", rel


def test_markdown_survives_unless_explicit_dump_in_scratch_dir():
    keep_ish = ["scratch/scratch-ideas.md", "ida/scratch-ideas.md", "scratch-ideas.md",
                "scratch.md", "ida/notes.md", "samples/README.md", "dumps/analysis.markdown",
                "ida/NOTES.MD", "decomp/dump.md", "main.decomp.md", "x.dump.md"]
    for rel in keep_ish:
        assert cp.classify(rel) != "purge", rel
    for rel in ["decomp/main.decomp.md", "dumps/proc.dump.md", "ida/f.disasm.md",
                "traces/run.TRACE.md", "scratch/a.log.md"]:
        assert cp.classify(rel) == "purge", rel
    # a dump suffix never beats the keep-list
    assert cp.classify("knowledge/main.decomp.md") == "keep"
    assert cp.classify("ida/x.writeup.md") == "keep"


# ------------------------------------------------------------- commit parsing
def test_commit_marker_parsing():
    p = cp.parse_close_markers
    assert p("msg\n\ncase: solved foo\n")[0] == [("solved", "foo")]
    assert p("CASE: Solved foo\r\n")[0] == [("solved", "foo")]
    assert p("case: solved\n")[0] == [("solved", None)]
    for quoted in ("> case: solved foo", "  case: solved foo", "we have case: solved foo",
                   "case: solved foo bar"):
        f, ign = p(quoted)
        assert f == [] and len(ign) == 1, quoted


# ------------------------------------------------------- dry run / quarantine
def _run(repo, *args):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = cp.main(["--repo", str(repo), *args])
    return rc, buf.getvalue(), err.getvalue()


def test_dry_run_changes_nothing(env):
    repo, tmpdir = env
    before = _snap(repo)
    rc, out, _ = _run(repo, "purge", "alpha")
    assert rc == 0 and "DRY RUN" in out
    assert _snap(repo) == before
    assert not (tmpdir / cp.QUARANTINE_DIRNAME).exists()


def test_purge_quarantines_restores_and_keeps_tree_clean(env):
    repo, tmpdir = env
    case = repo / "cases" / "alpha"
    before_case = _snap(case)
    other_before = _snap(repo / "cases" / "beta")
    status_before = _git(repo, "status", "--porcelain")
    rc, out, _ = _run(repo, "purge", "alpha", "--execute", "--yes")
    assert rc == 0, out
    after = _snap(case)
    gone = set(before_case) - set(after)
    assert {"ida/target.i64", "ida/target.id0", "samples/alpha.exe", "dumps/proc.dmp",
            "decomp/main.decomp.c", "decomp/main.decomp.md"} <= gone
    survivors = {"REPORT.md", ".liebert-case", "knowledge/technique.md", "knowledge/ida/type.til",
                 "ida/lessons.writeup.md", "ida/scratch-ideas.md", "scratch/scratch-ideas.md",
                 "scratch/notes.md", "my_keygen.py"}
    assert survivors <= set(after)
    assert _snap(repo / "cases" / "beta") == other_before
    assert (repo / "docs" / "sample_notes.i64").exists()
    # tree exactly as clean as before; quarantine is outside the repo and invisible to git
    assert _git(repo, "status", "--porcelain") == status_before == ""
    qroot = tmpdir / cp.QUARANTINE_DIRNAME
    assert qroot.is_dir() and not str(qroot.resolve()).startswith(str(repo.resolve()))
    # restore brings every file back byte-identical
    rc, out, _ = _run(repo, "restore", "alpha")
    assert rc == 0, out
    assert _snap(case) == before_case
    assert _git(repo, "status", "--porcelain") == ""
    # restoring again never overwrites
    rc, out, _ = _run(repo, "restore", "alpha")
    assert rc == 0 and "0 files" in out


def test_restore_never_overwrites_and_uses_fence(env):
    repo, _ = env
    case = repo / "cases" / "alpha"
    _run(repo, "purge", "alpha", "--execute", "--yes")
    _w(case / "ida" / "target.i64", b"new work")
    rc, out, _ = _run(repo, "restore", "alpha")
    assert (case / "ida" / "target.i64").read_bytes() == b"new work"
    assert "exists, left alone: ida/target.i64" in out
    assert _run(repo, "restore", "../x")[0] == 3
    assert _run(repo, "restore", "alpha", "--stamp", "..")[0] == 3
    assert _run(repo, "restore", "beta")[0] == 1          # nothing quarantined for beta


def test_quarantine_list_and_tampered_manifest(env, tmp_path):
    repo, tmpdir = env
    _run(repo, "purge", "alpha", "--execute", "--yes")
    rc, out, _ = _run(repo, "quarantine")
    assert rc == 0 and "alpha" in out and "expires in 6d" in out or "expires in 7d" in out
    # a manifest trying to restore onto a kept path or outside the case is skipped
    qroot = tmpdir / cp.QUARANTINE_DIRNAME
    entry = next(iter((qroot / "alpha").iterdir()))
    m = cp.json.loads((entry / "manifest.json").read_text())
    m["files"] = [{"rel": "../../escape.txt", "size": 1, "sha256": "0"},
                  {"rel": "REPORT.md", "size": 1, "sha256": "0"}]
    (entry / "manifest.json").write_text(cp.json.dumps(m))
    rc, _, err = _run(repo, "restore", "alpha")
    assert rc == 4 and err.count("SKIP") == 2
    assert not (tmp_path / "escape.txt").exists()


def test_expiry_sweep_removes_only_old_entries(env):
    repo, tmpdir = env
    t0 = 1_700_000_000
    case = repo / "cases" / "alpha"
    plan = cp.build_plan(case)
    cp.execute_plan(plan, repo, "alpha", "manual", now=t0)                       # old
    _w(case / "dumps" / "later.dmp")
    cp.execute_plan(cp.build_plan(case), repo, "alpha", "manual", now=t0 + 6 * 86400)  # recent
    qroot = cp.quarantine_root()
    assert len(list(cp.iter_quarantine(qroot))) == 2
    assert cp.sweep_quarantine(now=t0 + 7 * 86400 - 1) == []                     # not yet
    removed = cp.sweep_quarantine(now=t0 + 7 * 86400 + 60)
    assert len(removed) == 1
    left = list(cp.iter_quarantine(qroot))
    assert len(left) == 1 and left[0][3]["purged_epoch"] == t0 + 6 * 86400
    # a stray directory in the quarantine root is not a stamp dir and is never swept
    stray = qroot / "alpha" / "not-a-stamp"
    _w(stray / "keep.txt")
    cp.sweep_quarantine(now=t0 + 400 * 86400)
    assert (stray / "keep.txt").exists()
    assert _git(repo, "status", "--porcelain") == ""


def test_quarantine_inside_repo_is_refused(env, monkeypatch):
    repo, _ = env
    monkeypatch.setattr(cp.tempfile, "tempdir", str(repo / "inside"))
    (repo / "inside").mkdir()
    before = _snap(repo)
    rc, _, err = _run(repo, "purge", "alpha", "--execute", "--yes")
    assert rc == 3 and "inside the repo" in err
    assert _snap(repo) == before


def test_changed_file_is_not_deleted_if_copy_fails_verification(env, monkeypatch):
    repo, _ = env
    case = repo / "cases" / "alpha"
    monkeypatch.setattr(cp.shutil, "copy2", lambda s, d: Path(d).write_bytes(b"corrupt"))
    rc, _, err = _run(repo, "purge", "alpha", "--execute", "--yes")
    assert rc == 4 and "FAILED" in err
    assert (case / "ida" / "target.i64").read_bytes() == b"i" * 5000


# ----------------------------------------------------------------------- doctor
def test_doctor_reports_unmarked_dirs_and_modifies_nothing(env, tmp_path):
    repo, tmpdir = env
    _w(repo / "cases" / "stray" / "ida" / "x.i64", b"s" * 2048)
    _w(repo / "cases" / "stray" / "y.dmp")
    _w(repo / "cases" / "badmark" / ".liebert-case", "not json")
    _run(repo, "purge", "alpha", "--execute", "--yes")
    before_repo, before_q = _snap(repo), _snap(tmpdir)
    rc, out, _ = _run(repo, "doctor")
    assert rc == 0
    assert "stray" in out and "badmark" in out and "alpha " not in out.split("[quarantine]")[0]
    assert "no .liebert-case marker" in out and "[quarantine]" in out and "1 entries" in out
    assert _snap(repo) == before_repo and _snap(tmpdir) == before_q


def test_doctor_does_not_sweep_expired_entries(env, monkeypatch):
    repo, tmpdir = env
    cp.execute_plan(cp.build_plan(repo / "cases" / "alpha"), repo, "alpha", "manual", now=1_000_000)
    before = _snap(tmpdir)
    rc, out, _ = _run(repo, "doctor")
    assert rc == 0 and "already expired, awaiting the next sweep: alpha/" in out
    assert _snap(tmpdir) == before
    # any other command does sweep it
    _run(repo, "quarantine")
    assert _snap(tmpdir) != before


def test_doctor_flags_entries_expiring_soon(env):
    repo, _ = env
    now = cp._now()
    cp.execute_plan(cp.build_plan(repo / "cases" / "alpha"), repo, "alpha", "manual",
                    now=now - 6 * 86400)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cp.do_doctor(repo, now=now)
    assert "expiring within 2 days: alpha/" in out.getvalue()


# ------------------------------------------------- added patterns (item 1)
NEW_PATTERN_FILES = [
    "a.pdb", "a.hdmp", "a.cdmp", "a.dump", "a.wer", "a.hprof", "a.etl", "a.pml", "a.pmc",
    "a.pcap", "a.pcapng", "a.gdt", "a.idc", "a.bak", "a.old", "a.orig", "a.swp", "a.swo",
    "a.tmp", "main.c~", "x~", "UPPER.PDB", "deep/er/a.bak",
]
# Extensions that would delete source, config or notes in a Python repo. Never purgeable.
NEVER_PURGE = ["a.py", "a.c", "a.cpp", "a.h", "a.json", "a.xml", "a.txt", "notes.txt",
               "setup.cfg", "a.md", "a.cab", "docs/a.cab", "sub/config.json"]


@pytest.mark.parametrize("rel", NEW_PATTERN_FILES)
def test_new_patterns_are_purgeable_and_keep_still_wins(rel):
    assert cp.classify(rel) == "purge"
    for keepdir in ("knowledge", "keep"):
        assert cp.classify(f"{keepdir}/{rel}") == "keep"
    assert cp.classify(f"ida/lessons.writeup.md") == "keep"


def test_forbidden_extensions_are_not_in_the_new_pattern_set():
    for rel in ["a.py", "a.c", "a.cpp", "a.h", "a.json", "a.xml", "a.txt", "notes.txt",
                "setup.cfg", "a.cab", "docs/a.cab", "sub/config.json"]:
        assert cp.classify(rel) == "unclassified", rel
    # markdown rules still win over every new pattern
    assert cp.classify("scratch/notes.md") != "purge"
    assert cp.classify("scratch/a.bak.md") != "purge"
    assert cp.classify("scratch/a.bak.markdown") != "purge"


def test_real_purge_removes_new_patterns_and_spares_source_config_notes(env):
    repo, _ = env
    case = repo / "cases" / "alpha"
    for rel in NEW_PATTERN_FILES:
        _w(case / "work" / rel)
    for rel in ("a.py", "a.c", "a.h", "a.json", "a.xml", "a.txt", "notes.txt", "setup.cfg"):
        _w(case / "work" / "src" / rel, b"precious")
    _w(case / "lonely" / "lonely.cab")                   # .cab with no .wer beside it
    _w(case / "work" / "wer" / "Report.wer")
    _w(case / "work" / "wer" / "Report.cab")             # companion: purged
    _w(case / "knowledge" / "dump.pdb", b"keepme")       # keep-list beats the new pattern
    _w(case / "keep" / "x.bak", b"keepme")
    rc, _, _ = _run(repo, "purge", "alpha", "--execute", "--yes")
    assert rc == 0
    for rel in NEW_PATTERN_FILES:
        assert not (case / "work" / rel).exists(), rel
    assert not (case / "work" / "wer" / "Report.wer").exists()
    assert not (case / "work" / "wer" / "Report.cab").exists()
    for rel in ("a.py", "a.c", "a.h", "a.json", "a.xml", "a.txt", "notes.txt", "setup.cfg"):
        assert (case / "work" / "src" / rel).read_bytes() == b"precious", rel
    assert (case / "lonely" / "lonely.cab").exists()
    assert (case / "knowledge" / "dump.pdb").read_bytes() == b"keepme"
    assert (case / "keep" / "x.bak").read_bytes() == b"keepme"
    assert (case / "my_keygen.py").exists()


def test_cab_companion_only_beside_wer_and_restores(env):
    repo, _ = env
    case = repo / "cases" / "alpha"
    _w(case / "w" / "a.wer")
    _w(case / "w" / "a.cab", b"c" * 10)
    _w(case / "other" / "b.cab", b"c" * 10)
    plan = cp.build_plan(case)
    assert "w/a.cab" in dict(plan.purge) and "other/b.cab" not in dict(plan.purge)
    _run(repo, "purge", "alpha", "--execute", "--yes")
    assert not (case / "w" / "a.cab").exists() and (case / "other" / "b.cab").exists()
    rc, _, _ = _run(repo, "restore", "alpha")
    assert rc == 0 and (case / "w" / "a.cab").read_bytes() == b"c" * 10


def test_scope_fence_still_refuses_every_malicious_input(env):
    repo, _ = env
    before = _snap(repo)
    for name in BAD:
        with pytest.raises(cp.ScopeError):
            cp.resolve_case_target(repo, name)
        if isinstance(name, str):
            rc, _, _ = _run(repo, "purge", "--execute", "--yes", "--", name)
            assert rc == 3, repr(name)
    assert _snap(repo) == before


# ------------------------------------------------------ doctor, new section
def test_doctor_reports_out_of_scope_dirs_and_modifies_nothing(env):
    repo, tmpdir = env
    _w(repo / "samples" / "t" / "a.bin", b"s" * 2048)
    _w(repo / "samples" / "b.bin", b"s" * 1024)
    _w(repo / "out" / "r.log", b"o" * 100)
    before_repo, before_q = _snap(repo), _snap(tmpdir)
    rc, out, _ = _run(repo, "doctor")
    assert rc == 0 and "[outside purge scope]" in out
    assert "samples/" in out and "2 files, 3.0 KiB" in out
    assert "out/" in out and "1 files, 100 B" in out
    assert "runs/" in out and "(absent)" in out and "newest file" in out
    assert _snap(repo) == before_repo and _snap(tmpdir) == before_q


# --------------------------------------------- solved-without-knowledge guard
def _new_case(repo, name):
    c = repo / "cases" / name
    _w(c / ".liebert-case", MARK % name)
    (c / "knowledge").mkdir(exist_ok=True)
    _w(c / "ida" / "x.i64", b"i" * 100)
    return c


def test_solved_refused_without_report_or_knowledge_then_proceeds(env):
    repo, tmpdir = env
    c = _new_case(repo, "gamma")
    before = _snap(repo)
    rc, out, err = _run(repo, "purge", "gamma", "--execute", "--yes", "--reason", "solved")
    assert rc == 3 and "neither a REPORT.md nor a non-empty knowledge/" in err
    assert _snap(repo) == before
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "close\n\ncase: solved gamma")
    rc, out, err = _run(repo, "from-commit", "--execute")
    assert rc == 3 and "REFUSED" in err and (c / "ida" / "x.i64").exists()
    _w(c / "REPORT.md", "# done\n")
    rc, _, _ = _run(repo, "purge", "gamma", "--execute", "--yes", "--reason", "solved")
    assert rc == 0 and not (c / "ida" / "x.i64").exists() and (c / "REPORT.md").exists()


def test_solved_accepts_non_empty_knowledge_but_not_empty_report(env):
    repo, _ = env
    c = _new_case(repo, "delta")
    _w(c / "REPORT.md", b"")
    rc, _, err = _run(repo, "purge", "delta", "--execute", "--yes", "--reason", "solved")
    assert rc == 3 and (c / "ida" / "x.i64").exists()
    _w(c / "knowledge" / "technique.md", "# t\n")
    rc, _, _ = _run(repo, "purge", "delta", "--execute", "--yes", "--reason", "solved")
    assert rc == 0 and not (c / "ida" / "x.i64").exists()


def test_abandoned_and_manual_purge_do_not_need_a_report(env):
    repo, _ = env
    for name, reason in (("eps", "abandoned"), ("zeta", "manual")):
        c = _new_case(repo, name)
        rc, _, _ = _run(repo, "purge", name, "--execute", "--yes", "--reason", reason)
        assert rc == 0 and not (c / "ida" / "x.i64").exists(), reason
