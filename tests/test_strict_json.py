"""liebert_re.strict_json: the one dependency-free strict JSON reader."""

import ast
import json
from pathlib import Path

import pytest

from liebert_re import strict_json
from liebert_re.strict_json import StrictJSONError, loads


def _reason(text, **kwargs):
    with pytest.raises(StrictJSONError) as caught:
        loads(text, **kwargs)
    return caught.value.reason


def test_valid_json_round_trips():
    document = {"a": [1, 2.5, None, True, "x"], "b": {"c": {"d": []}}, "e": "é"}
    assert loads(json.dumps(document)) == document
    assert loads("[]") == [] and loads("0") == 0 and loads('"s"') == "s"


def test_duplicate_key_at_every_nesting_level():
    assert _reason('{"a": 1, "a": 2}') == strict_json.DUPLICATE_KEY
    assert _reason('{"x": {"a": 1, "a": 2}}') == strict_json.DUPLICATE_KEY
    assert _reason('{"x": [{"y": {"k": 1, "k": 1}}]}') == strict_json.DUPLICATE_KEY
    # The same key in different objects is not a duplicate.
    assert loads('{"a": {"a": 1}, "b": {"a": 2}}') == {"a": {"a": 1}, "b": {"a": 2}}


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_constants_are_refused_anywhere(constant):
    assert _reason(constant) == strict_json.NON_FINITE
    assert _reason(f'{{"a": [{constant}]}}') == strict_json.NON_FINITE


def test_there_is_no_switch_to_allow_non_finite():
    with pytest.raises(TypeError):
        loads("[NaN]", allow_non_finite=True)


def test_size_limit_exact_accepted_and_one_over_refused():
    text = '{"k": "' + "a" * 20 + '"}'
    size = len(text.encode("utf-8"))
    assert loads(text, max_bytes=size) == {"k": "a" * 20}
    assert loads(text.encode("utf-8"), max_bytes=size) == {"k": "a" * 20}
    assert _reason(text, max_bytes=size - 1) == strict_json.TOO_LARGE
    assert _reason(text.encode("utf-8"), max_bytes=size - 1) == strict_json.TOO_LARGE


def test_size_limit_counts_utf8_bytes_not_characters():
    text = '"éé"'  # 4 characters, 6 bytes
    assert loads(text, max_bytes=6) == "éé"
    assert _reason(text, max_bytes=5) == strict_json.TOO_LARGE


def test_size_limit_is_checked_before_parsing():
    # Malformed AND too large: the size is the answer, nothing was parsed.
    assert _reason("{" * 50, max_bytes=10) == strict_json.TOO_LARGE


def test_zero_limit_refuses_everything_and_none_means_unbounded():
    assert _reason("1", max_bytes=0) == strict_json.TOO_LARGE
    assert loads("1" * 100) == int("1" * 100)


def test_deep_nesting_is_too_deep_not_a_recursion_error():
    assert _reason("[" * 100000 + "]" * 100000) == strict_json.TOO_DEEP
    assert _reason('{"a":' * 100000 + "1" + "}" * 100000) == strict_json.TOO_DEEP


@pytest.mark.parametrize("text", ["", "{", "[1,", "nope", '{"a":}', "'a'", "1 2", "﻿{}"])
def test_malformed_input(text):
    assert _reason(text) == strict_json.MALFORMED


def test_over_long_integer_literal_is_malformed():
    assert _reason("1" * 100000) == strict_json.MALFORMED


def test_error_type_reason_and_message():
    with pytest.raises(ValueError) as caught:
        loads('{"a": 1, "a": 2}')
    error = caught.value
    assert isinstance(error, StrictJSONError)
    assert error.reason == "DUPLICATE_KEY" and "'a'" in str(error)
    assert set(strict_json.REASONS) == {"DUPLICATE_KEY", "NON_FINITE", "TOO_LARGE", "TOO_DEEP", "MALFORMED"}
    assert StrictJSONError("MALFORMED").reason == "MALFORMED"


def test_bytes_utf8_with_and_without_one_bom():
    assert loads(b'{"a": 1}') == {"a": 1}
    assert loads(b"\xef\xbb\xbf" + b'{"a": 1}') == {"a": 1}
    assert loads(bytearray(b'["\xc3\xa9"]')) == ["é"]
    assert _reason(b"\xef\xbb\xbf\xef\xbb\xbf{}") == strict_json.MALFORMED


def test_invalid_utf8_bytes_are_malformed_never_replaced():
    assert _reason(b'["\xff"]') == strict_json.MALFORMED
    assert _reason(b'["\xc3"]') == strict_json.MALFORMED


def test_bytes_still_get_the_strict_rules():
    assert _reason(b'{"a": 1, "a": 2}') == strict_json.DUPLICATE_KEY
    assert _reason(b"[NaN]") == strict_json.NON_FINITE


def test_wrong_argument_type_is_a_type_error():
    with pytest.raises(TypeError):
        loads(None)
    with pytest.raises(TypeError):
        loads(12)


def test_module_imports_nothing_from_the_package():
    source = Path(strict_json.__file__).read_text(encoding="utf-8")
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert "liebert_re" not in imported


def test_evidence_layer_reads_through_this_module():
    from liebert_re.evidence import index

    deep = "[" * 100000 + "]" * 100000
    with pytest.raises(StrictJSONError) as caught:
        index._strict_json_loads(deep)
    assert caught.value.reason == strict_json.TOO_DEEP
    record = {"ok": True, "evidence_uid": "x", "read_error": None, "content": deep, "path": "a.json"}
    assert index._record_resolves(record, "x") is False
    assert index._record_target_hash(record) is None


# -- slice 2: the other readers of untrusted JSON go through strict_json ------------------------------------------
# Each reader keeps the outward code it always reported; a repeated key or a NaN/Infinity constant is now refused
# there, where json.loads accepted it (last key won; NaN compared unlike any number).

_DUP = '{"k": 1, "k": 2}'
_NAN = '{"k": NaN}'
_INF = '{"k": -Infinity}'


def test_artifact_provenance_manifest_with_a_repeated_key_or_nan_is_invalid(tmp_path):
    from liebert_re.evidence import artifact_provenance

    source = tmp_path / "in.bin"
    source.write_bytes(b"v1")
    current = artifact_provenance.input_hashes([source])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"input_hashes": current}), encoding="utf-8")
    assert artifact_provenance.stale_status(manifest, [source])["status"] == "CURRENT"
    # The last repeated key matches the current hashes, so json.loads called this CURRENT.
    body = json.dumps(current)
    manifest.write_text('{"input_hashes": {"x": "0"}, "input_hashes": %s}' % body, encoding="utf-8")
    assert artifact_provenance.stale_status(manifest, [source]) == {"status": "INVALID", "manifest": "manifest.json"}
    manifest.write_text('{"input_hashes": %s, "n": NaN}' % body, encoding="utf-8")
    assert artifact_provenance.stale_status(manifest, [source])["status"] == "INVALID"


def test_evidence_index_jsonl_names_a_line_with_a_repeated_key_or_nan_as_bad():
    from liebert_re.evidence import index

    parsed = index._parse_jsonl('{"a": 1, "a": 2}\n{"b": NaN}\n{"c": 1}\n', False)
    assert parsed["records"] == [{"c": 1}] and parsed["non_blank"] == 3
    assert [number for number, _ in parsed["bad"]] == [1, 2]


def test_evidence_index_marks_a_json_file_with_a_repeated_key_or_nan_malformed(tmp_path):
    from liebert_re.evidence.index import EvidenceIndex

    root = tmp_path / "ev"
    root.mkdir()
    (root / "good.json").write_text('{"tool": "t"}', encoding="utf-8")
    (root / "dup.json").write_text('{"tool": "a", "tool": "b"}', encoding="utf-8")
    (root / "nan.json").write_text('{"tool": "a", "x": NaN}', encoding="utf-8")
    idx = EvidenceIndex(root, db_path=tmp_path / "idx.sqlite")
    idx.refresh()
    with idx._session() as db:
        status = {r["path"]: r["status"] for r in db.execute("SELECT path, status FROM records")}
    assert status == {"good.json": "json_ok", "dup.json": "json_malformed", "nan.json": "json_malformed"}


def test_durable_lock_holder_file_with_a_repeated_key_or_nan_names_no_holder(tmp_path):
    from liebert_re.evidence import process_lock as pl

    path = tmp_path / "x.lock"
    lock = pl.DurableLock(path)
    path.write_text('{"pid": 4242}', encoding="utf-8")
    assert lock._read_holder() == {"pid": 4242}
    for text in ('{"pid": 4242, "pid": 1}', '{"pid": NaN}', '{"pid": 4242, "n": Infinity}'):
        path.write_text(text, encoding="utf-8")
        assert lock._read_holder() is None, text


def test_lab_gate_registry_entry_with_a_repeated_key_or_nan_does_not_register(tmp_path, monkeypatch):
    from liebert_re.dynamic import lab_gate as lg

    monkeypatch.setattr(lg.LabGate, "registry_dir", staticmethod(lambda: tmp_path))
    identity = {"pid": 77, "create_time": 5.0, "image": "c:/x/a.exe"}
    good = '{"pid": 77, "create_time": 5.0, "image": "c:/x/a.exe", "launcher_pid": 9}'
    entry = tmp_path / "pid77_a.json"
    entry.write_text(good, encoding="utf-8")
    assert lg.LabGate.registered(identity) == {"entry": "pid77_a.json", "registered_by_pid": 9}
    # A repeated key whose LAST value is the right one registered the process before.
    entry.write_text('{"pid": 1, "pid": 77, "create_time": 5.0, "image": "c:/x/a.exe"}', encoding="utf-8")
    assert lg.LabGate.registered(identity) is None
    entry.write_text('{"pid": 77, "create_time": 5.0, "image": "c:/x/a.exe", "n": NaN}', encoding="utf-8")
    assert lg.LabGate.registered(identity) is None


def test_frida_agent_params_with_a_repeated_key_or_nan_are_refused():
    from liebert_re.dynamic import frida_trace_client as ftc

    assert ftc._parse_agent_params('{"k": 1}') == {"k": 1}
    for text in (_DUP, _NAN, _INF, "NaN"):
        with pytest.raises(ValueError, match="--agent-params"):
            ftc._parse_agent_params(text)


def test_emulator_result_line_with_a_repeated_key_or_nan_is_not_a_result():
    from liebert_re.recover import emulate

    def outcome(stdout):
        class Outcome:
            launch_failed = False
            resource_limit_unavailable = False
            timed_out = False
            memory_exceeded = False
            process_tree_terminated = True
            returncode = 0
            stderr = ""
        Outcome.stdout = stdout
        return Outcome

    ok = emulate._Runner.interpret(outcome('{"ok": true, "status": "OK"}\n'), Path("."))
    assert ok == {"ok": True, "status": "OK"}
    for line in ('{"ok": true, "ok": false}', '{"ok": true, "n": NaN}', '{"ok": true, "n": Infinity}'):
        body = emulate._Runner.interpret(outcome(line + "\n"), Path("."))
        assert body["ok"] is False and body["error"] == "ENGINE_CRASH", line


def test_emulator_authorization_text_with_a_repeated_key_or_nan_is_refused():
    from liebert_re.recover import emulate

    base = '"authorized_by": "x", "purpose": "p", "sample_sha256": "%s"' % ("a" * 64)
    clean, why = emulate.EmulationGate._authorization("{%s}" % base)
    assert why is None and clean["purpose"] == "p"
    for text in ('{%s, "purpose": "q"}' % base, '{%s, "n": NaN}' % base):
        clean, why = emulate.EmulationGate._authorization(text)
        assert clean is None and why[0] == "AUTHORIZATION_REQUIRED", text


def test_cli_tool_args_with_a_repeated_key_or_nan_are_bad_args_json():
    from liebert_re import cli

    class Args:
        tool_command = "run"
        name = "get_file_info"

    for text in (_DUP, _NAN):
        args = Args()
        args.args = text
        refused = cli._tool_prepare(args)
        assert refused is not None and refused["error"] == "BAD_ARGS_JSON", text


def test_cli_json_result_with_a_repeated_key_or_nan_is_a_failure_never_an_answer():
    from liebert_re import cli

    assert cli._decode('{"ok": true, "k": 1}') == {"ok": True, "k": 1}
    for text in (_DUP, _NAN, _INF, '[{"a": 1, "a": 2}]'):
        body = cli._decode(text)
        assert body["ok"] is False and body["status"] == "FAILED" and body["error"] == "NON_STRICT_JSON_RESULT", text
        assert body["text"] == text and body["reason"] in (strict_json.DUPLICATE_KEY, strict_json.NON_FINITE)
        assert cli._exit_code(body) != 0
    tooled = cli._decode(_NAN, None, "get_file_info")
    assert tooled["tool"] == "get_file_info" and tooled["error"] == "NON_STRICT_JSON_RESULT"
    # Prose that is merely not JSON still takes the text path it always took.
    assert cli._decode("not json at all")["error"] == "UNCLASSIFIED_OUTPUT"
