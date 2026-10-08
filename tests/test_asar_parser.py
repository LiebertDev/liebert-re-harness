"""liebert_re.tools.asar_parser: a header field that is missing is unknown, never a valid 0."""
import json

from liebert_re.tools import asar_parser
from liebert_re.tools.asar_parser import build_synthetic_asar, parse_asar


def _asar(tree: dict, payload: bytes = b"") -> bytes:
    raw = json.dumps(tree, separators=(",", ":")).encode()
    pad = (-len(raw)) % 4
    return (4 + len(raw) + pad).to_bytes(4, "little") + len(raw).to_bytes(4, "little") + raw + b"\0" * pad + payload


def _errors(report):
    return [e["error"] for e in report["errors"]]


def test_synthetic_archive_round_trips_as_a_proven_inventory():
    report = parse_asar(data=build_synthetic_asar({"a.txt": b"abc", "d/b.bin": b"xy"}, unpacked={"u.dll"}))
    assert report["ok"] is True and report["file_count"] == 2
    assert [e["offset"] for e in report["entries"] if e["kind"] == "file"] == [0, 3]


def test_file_without_size_is_an_error_not_a_zero_size_file():
    report = parse_asar(data=_asar({"files": {"a.txt": {"offset": "0"}}}))
    assert report["ok"] is False and report["status"] == "ANALYSIS_LIMITED"
    assert "MISSING_OFFSET_OR_SIZE" in _errors(report)
    assert report["entries"] == []
    assert report["claims_ceiling"]["inventory"] == "REJECTED"


def test_packed_file_without_offset_is_an_error_not_offset_zero():
    report = parse_asar(data=_asar({"files": {"a.txt": {"size": 3}}}, b"abc"))
    assert report["ok"] is False
    err = next(e for e in report["errors"] if e["error"] == "MISSING_OFFSET_OR_SIZE")
    assert err["missing"] == ["offset"]


def test_unpacked_file_needs_a_size_but_no_offset():
    ok = parse_asar(data=_asar({"files": {"a.dll": {"size": 3, "unpacked": True}}}))
    assert ok["ok"] is True and ok["entries"][0]["offset"] is None
    bad = parse_asar(data=_asar({"files": {"a.dll": {"unpacked": True}}}))
    assert bad["ok"] is False and "MISSING_OFFSET_OR_SIZE" in _errors(bad)


def test_module_is_the_one_under_test():
    assert asar_parser.MAX_ENTRIES > 0
