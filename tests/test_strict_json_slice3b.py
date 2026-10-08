"""strict_json slice 3b: structured_inspect (.json/.jsonl), har_inspect, asar header, il2cpp script.json,
the emulator job file and image_map's JSON-shaped live_module_base are read strictly."""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import liebert_re.workspace as tools_workspace
from liebert_re import strict_json
from liebert_re.recover import emulate
from liebert_re.tools import asar_parser, il2cpp, image_map
from liebert_re.tools.formats import har_inspect, structured_inspect

DUP = '{"a": 1, "a": 2}'
NAN = '{"a": NaN}'


@pytest.fixture
def ws():
    with tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE, ignore_cleanup_errors=True) as td:
        yield Path(td)


@pytest.mark.parametrize("text,reason", [(DUP, "DUPLICATE_KEY"), (NAN, "NON_FINITE")])
def test_structured_json_file_is_refused_with_the_strict_reason(ws, text, reason):
    p = ws / "x.json"
    p.write_text(text, encoding="utf-8")
    out = json.loads(structured_inspect(str(p)))
    assert out["ok"] is False and reason in out["error"]


def test_structured_json_valid_and_malformed_unchanged(ws):
    p = ws / "x.json"
    p.write_text('{"a": [1, 2]}', encoding="utf-8")
    assert json.loads(structured_inspect(str(p)))["ok"] is True
    p.write_text("{", encoding="utf-8")
    assert json.loads(structured_inspect(str(p)))["ok"] is False


@pytest.mark.parametrize("bad", [DUP, NAN])
def test_jsonl_rejected_line_is_a_bad_line_and_good_lines_are_kept(ws, bad):
    p = ws / "x.jsonl"
    p.write_text('{"ok": 1}\n' + bad + '\n{"ok": 2}\n', encoding="utf-8")
    out = json.loads(structured_inspect(str(p)))
    assert out["ok"] is True and out["rows"]["bad_line_count"] == 1
    assert out["rows"]["bad_lines"][0]["line"] == 2 and out["rows"]["rows_returned"] == 2


@pytest.mark.parametrize("bad", [DUP, NAN])
def test_jsonl_with_every_line_rejected_is_never_ok_with_an_empty_list(ws, bad):
    p = ws / "x.jsonl"
    p.write_text(bad + "\n" + bad + "\n", encoding="utf-8")
    out = json.loads(structured_inspect(str(p)))
    assert out["ok"] is False and "JSONL_NO_LINE_PARSED" in out["error"]


def test_jsonl_big_integer_is_kept_not_rejected(ws):
    p = ws / "x.jsonl"
    p.write_text('{"n": %d}\n' % (2 ** 200), encoding="utf-8")
    out = json.loads(structured_inspect(str(p)))
    assert out["ok"] is True and out["rows"]["rows_returned"] == 1 and out["rows"]["bad_line_count"] == 0


@pytest.mark.parametrize("text,reason", [('{"log": {"entries": [], "entries": []}}', "DUPLICATE_KEY"),
                                         ('{"log": {"entries": [], "time": NaN}}', "NON_FINITE")])
def test_har_with_a_repeated_key_or_nan_is_malformed_har_with_the_reason(ws, text, reason):
    p = ws / "x.har"
    p.write_text(text, encoding="utf-8")
    out = json.loads(har_inspect(str(p)))
    assert out["ok"] is False and out["error"].startswith("MALFORMED_HAR") and reason in out["error"]


def test_har_valid_still_works(ws):
    p = ws / "x.har"
    p.write_text('{"log": {"entries": [], "pages": []}}', encoding="utf-8")
    assert json.loads(har_inspect(str(p)))["ok"] is True


def _asar(header: bytes) -> bytes:
    pad = (-len(header)) % 4
    return (4 + len(header) + pad).to_bytes(4, "little") + len(header).to_bytes(4, "little") + header + b"\0" * pad


@pytest.mark.parametrize("header", [b'{"files": {}, "files": {}}', b'{"files": {"a": {"size": NaN, "offset": "0"}}}'])
def test_asar_header_with_a_repeated_key_or_nan_makes_no_inventory(header):
    report = asar_parser.parse_asar(data=_asar(header))
    assert report["ok"] is False and report["error"] == "MALFORMED_HEADER_JSON"
    assert report["detail"]["detail"].startswith(("DUPLICATE_KEY", "NON_FINITE")) and "entries" not in report


def test_asar_tree_depth_limit_is_still_reached_below_the_strict_depth_bound():
    assert asar_parser.MAX_DEPTH * 2 < strict_json.DEFAULT_MAX_DEPTH
    tree: dict = {"files": {}}
    node = tree
    for _ in range(asar_parser.MAX_DEPTH + 5):
        node["files"]["d"] = {"files": {}}
        node = node["files"]["d"]
    report = asar_parser.parse_asar(data=_asar(json.dumps(tree).encode()))
    assert any(e["error"] == "TREE_TOO_DEEP" for e in report["errors"])


def _dumper(script_text):
    def run(argv, **_kw):
        (Path(argv[-1]) / "script.json").write_text(script_text, encoding="utf-8")
        return SimpleNamespace(launch_failed=False, cancelled=False, timed_out=False, stdout="", stderr="")
    return run


def _il2cpp(ws, script_text):
    binary = ws / "GameAssembly.dll"
    binary.write_bytes(b"MZ")
    meta = ws / "global-metadata.dat"
    meta.write_bytes(b"\0" * 8)
    with mock.patch.object(il2cpp, "_il2cppdumper", return_value="x"), \
            mock.patch.object(il2cpp, "run_bounded_process", _dumper(script_text)):
        return json.loads(il2cpp.il2cpp_mapper(str(binary), str(meta)))


def test_il2cpp_valid_script_json_counts(ws):
    out = _il2cpp(ws, '{"ScriptMethod": [{"Name": "a"}], "ScriptString": []}')
    assert out["ok"] is True and out["method_count"] == 1


@pytest.mark.parametrize("text,reason", [('{"ScriptMethod": [], "ScriptMethod": [1]}', "DUPLICATE_KEY"),
                                         ('{"ScriptMethod": NaN}', "NON_FINITE")])
def test_il2cpp_script_json_not_strict_is_a_failure_never_a_count(ws, text, reason):
    out = _il2cpp(ws, text)
    assert out["ok"] is False and out["error"] == "IL2CPPDUMPER_SCRIPT_JSON_NOT_STRICT" and out["reason"] == reason
    assert "method_count" not in out


def test_il2cpp_malformed_or_non_object_script_json_is_structured(ws):
    out = _il2cpp(ws, "{")
    assert out["ok"] is False and out["error"] == "IL2CPPDUMPER_SCRIPT_JSON_MALFORMED"
    out = _il2cpp(ws, "[1]")
    assert out["ok"] is False and out["error"] == "IL2CPPDUMPER_SCRIPT_JSON_NOT_OBJECT"


@pytest.mark.parametrize("text,reason", [(DUP, "DUPLICATE_KEY"), (NAN, "NON_FINITE")])
def test_emulator_job_file_not_strict_is_a_named_process_error(ws, text, reason, capsys):
    p = ws / "job.json"
    p.write_text(text, encoding="utf-8")
    assert emulate._child_main(str(p)) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["ok"] is False and result["error"] == "EMULATOR_PROCESS_ERROR"
    assert reason in result["detail"] and "StrictJSONError" in result["detail"]


@pytest.mark.parametrize("raw", ['{"base": 16, "base": 32}', '{"base": NaN}',
                                 '[{"address": 1, "address": 2}]', '{"base": 1'])
def test_json_shaped_live_module_base_that_is_not_strict_is_refused_never_guessed(raw):
    with pytest.raises(ValueError) as caught:
        image_map._resolve_live_base(raw)
    assert "JSON" in str(caught.value) and "hex" not in str(caught.value)


def test_live_module_base_plain_forms_unchanged():
    assert image_map._resolve_live_base("0x1000")[0] == 0x1000
    assert image_map._resolve_live_base("4096")[0] == 4096
    assert image_map._resolve_live_base('{"base": "0x2000"}')[0] == 0x2000
    assert image_map._resolve_live_base('{"address": 4112, "rva": 16}')[0] == 4096
    with pytest.raises(ValueError):
        image_map._resolve_live_base("zzz")
