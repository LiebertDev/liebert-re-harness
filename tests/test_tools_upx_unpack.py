"""upx_unpack: a failed call must not delete or alter an output another call published, while an
honest re-run of the same input still publishes. The UPX runner is faked; no real upx binary is used."""
import json
import types
from pathlib import Path

import pytest

import liebert_re.tools.upx as upx

PAYLOAD = b"MZ-packed-input-bytes"


def _result(returncode=0, timed_out=False):
    return types.SimpleNamespace(returncode=returncode, timed_out=timed_out, cancelled=False,
                                 stdout="", stderr="")


@pytest.fixture
def env(tmp_path, monkeypatch):
    evidence = upx.EVIDENCE  # already redirected per test by conftest's isolation guard
    evidence.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(PAYLOAD)
    monkeypatch.setattr(upx, "_upx_binary", lambda: "fake-upx")
    monkeypatch.setattr(upx, "safe_path", lambda p: Path(p))
    monkeypatch.setattr(upx, "relative", lambda p: str(p))
    return evidence, sample


def _runner(monkeypatch, *, content=None, returncode=0, leave_partial=None):
    def fake(command, **kwargs):
        out = Path(command[command.index("-o") + 1])
        if content is not None:
            out.write_bytes(content)
        if leave_partial is not None:
            out.write_bytes(leave_partial)
        return _result(returncode)
    monkeypatch.setattr(upx, "run_bounded_process", fake)


def _published(evidence):
    return [p for p in evidence.rglob("*_unpacked*") if p.is_file()]


@pytest.mark.parametrize("partial", [None, b"half-written"], ids=["fails-cleanly", "fails-leaving-partial"])
def test_failed_second_call_leaves_the_first_calls_output_intact(env, monkeypatch, partial):
    evidence, sample = env
    _runner(monkeypatch, content=b"UNPACKED-A")
    first = json.loads(upx.upx_unpack(str(sample)))
    assert first["status"] == "UNPACKED"
    published = Path(first["output_path"])
    assert published.read_bytes() == b"UNPACKED-A"

    _runner(monkeypatch, returncode=1, leave_partial=partial)
    second = json.loads(upx.upx_unpack(str(sample)))
    assert second["status"] == "UPX_UNPACK_FAILED"

    assert published.exists(), "a failed call deleted the output another call published"
    assert published.read_bytes() == b"UNPACKED-A", "a failed call altered a published output"


def test_failed_call_without_prior_output_publishes_nothing(env, monkeypatch):
    evidence, sample = env
    _runner(monkeypatch, returncode=1, leave_partial=b"half-written")
    body = json.loads(upx.upx_unpack(str(sample)))
    assert body["status"] == "UPX_UNPACK_FAILED"
    assert _published(evidence) == []


def test_rerun_with_same_input_still_publishes_a_fresh_result(env, monkeypatch):
    """The guard must be narrow: a second SUCCESSFUL call is legitimate and replaces the output."""
    evidence, sample = env
    _runner(monkeypatch, content=b"UNPACKED-A")
    first = json.loads(upx.upx_unpack(str(sample)))
    _runner(monkeypatch, content=b"UNPACKED-B")
    second = json.loads(upx.upx_unpack(str(sample)))
    assert second["status"] == "UNPACKED"
    assert second["output_path"] == first["output_path"]
    assert Path(second["output_path"]).read_bytes() == b"UNPACKED-B"
    assert second["output_sha256"] != first["output_sha256"]


def test_second_call_does_not_write_into_the_published_path_while_running(env, monkeypatch):
    evidence, sample = env
    _runner(monkeypatch, content=b"UNPACKED-A")
    published = Path(json.loads(upx.upx_unpack(str(sample)))["output_path"])
    seen = {}

    def fake(command, **kwargs):
        out = Path(command[command.index("-o") + 1])
        seen["target"] = out
        seen["published_during_run"] = published.read_bytes() if published.exists() else None
        out.write_bytes(b"UNPACKED-B")
        return _result(0)
    monkeypatch.setattr(upx, "run_bounded_process", fake)
    upx.upx_unpack(str(sample))
    assert seen["target"] != published
    assert seen["published_during_run"] == b"UNPACKED-A"


def test_scratch_is_removed_after_success_and_failure(env, monkeypatch):
    evidence, sample = env
    _runner(monkeypatch, content=b"UNPACKED-A")
    upx.upx_unpack(str(sample))
    _runner(monkeypatch, returncode=1, leave_partial=b"x")
    upx.upx_unpack(str(sample))
    assert [p.name for p in evidence.iterdir() if p.name.startswith(("scratch", "."))] == []
