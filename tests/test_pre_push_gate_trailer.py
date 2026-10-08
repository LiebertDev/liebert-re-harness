"""AGENTS.md rule 14: the push gate refuses a Co-Authored-By trailer in a pushed commit message."""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("_pre_push_gate_trailer", ROOT / "scripts" / "pre_push_gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

# Built by concatenation so this file never carries a trailer line itself.
_TRAILER = "Co-" + "Authored-" + "By: Someone <someone@example.invalid>"


class _NoProbes:
    """Stand-in for the discipline module: no identity probes, so only the trailer rule can fire."""

    @staticmethod
    def _machine_identity():
        return []

    @staticmethod
    def _denylist_probes():
        return []

    @staticmethod
    def _identity_findings(line, ident, deny):
        return []

    @staticmethod
    def _mask(text):
        return text


@pytest.mark.parametrize("message, lines", [
    ("subject\n\nbody\n\n" + _TRAILER + "\n", [5]),
    ("subject\n\n" + _TRAILER.lower() + "\n", [3]),
    ("subject\n\n" + _TRAILER.upper() + "\n", [3]),
    ("subject\n\n  " + _TRAILER.replace("By:", "By :") + "\n", [3]),
    ("subject\n\nno trailer here\nmentions co-authored-by in prose\n", []),
    ("Co-Authored by hand\n", []),
    ("", []),
])
def test_coauthor_trailer_lines(message, lines):
    assert gate.coauthor_trailer_lines(message) == lines


def _repo(tmp_path):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

    def run(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
                              text=True, env=env).stdout.strip()
    run("init", "-q")
    return run


def test_message_findings_blocks_a_trailer_in_the_pushed_range_and_names_the_commit(monkeypatch, tmp_path):
    run = _repo(tmp_path)
    (tmp_path / "f").write_text("1", encoding="utf-8")
    run("add", "f")
    run("commit", "-q", "-m", "old\n\n" + _TRAILER)            # history before the pushed range: not judged
    base = run("rev-parse", "HEAD")
    (tmp_path / "f").write_text("2", encoding="utf-8")
    run("commit", "-q", "-am", "clean change")
    (tmp_path / "f").write_text("3", encoding="utf-8")
    run("commit", "-q", "-am", "feature\n\nbody\n\n" + _TRAILER.lower())
    bad = run("rev-parse", "HEAD")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    hits = gate.message_findings([[f"{base}..HEAD"]], mod=_NoProbes)
    assert len(hits) == 1
    assert hits[0].startswith(f"commit {bad[:10]} message, line 5: [co-authored-by-trailer]")
    assert "someone" not in hits[0].lower()                     # the trailer value is never echoed
    assert gate.message_findings([[f"{base}..{base}"]], mod=_NoProbes) == []
    assert gate.message_findings([["HEAD~1..HEAD~1"]], mod=_NoProbes) == []


def test_clean_pushed_range_has_no_trailer_finding(monkeypatch, tmp_path):
    run = _repo(tmp_path)
    (tmp_path / "f").write_text("1", encoding="utf-8")
    run("add", "f")
    run("commit", "-q", "-m", "plain message")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    assert gate.message_findings([["HEAD"]], mod=_NoProbes) == []


def test_a_trailer_blocks_the_whole_gate(monkeypatch, capsys):
    monkeypatch.setattr(gate, "run_pytest", lambda cmd, **kw: (0, []))
    monkeypatch.setattr(gate, "run_contract_stage", lambda: False)
    monkeypatch.setattr(gate, "message_findings",
                        lambda ranges: ["commit abcdef0123 message, line 3: [co-authored-by-trailer] x"])
    assert gate.run_gate([["HEAD"]]) == 1
    err = capsys.readouterr().err
    assert "BLOCKED" in err and "abcdef0123" in err and "Co-Authored-By" in err
