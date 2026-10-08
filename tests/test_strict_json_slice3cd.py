"""strict_json slice 3c/3d: IDA wrapper inputs and worker files, recover/ and report/ JSON arguments, the generic probe.

Every reader here used to take ``json.loads``: a repeated key (the last one wins) or ``NaN`` / ``Infinity`` was
accepted. Each test feeds one of them and checks the reader's own outward refusal, with a valid control.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import liebert_re.tools.ida as ti
from liebert_re import strict_json

DUP = '{"k": 1, "k": 2}'
NAN = '{"k": NaN}'


# -- 3c: ida.py ---------------------------------------------------------------------------------------------------

def test_read_bytes_request_with_a_repeated_key_or_nan_is_invalid():
    assert ti._read_bytes_request_problem('{"address": "0x1000", "size": 4}') is None
    for text in ('{"address": "0x1000", "address": "0x2000", "size": 4}', '{"address": 4096, "size": NaN}'):
        assert ti._read_bytes_request_problem(text) == "INVALID_READ_BYTES_REQUEST", text


def test_json_fields_refuses_a_repeated_key_or_nan():
    assert ti._json_fields('{"start": 1}', ("start", "end")) == {"start": 1}
    for text in ('{"start": 1, "start": 2}', '{"start": NaN}'):
        assert ti._json_fields(text, ("start", "end")) is None, text


def test_annotations_apply_plan_text_with_a_repeated_key_or_nan_is_plan_not_json():
    for text, reason in (('{"items": [], "items": [1]}', strict_json.DUPLICATE_KEY),
                         ('{"items": [], "n": NaN}', strict_json.NON_FINITE)):
        body = json.loads(ti.ida_annotations_apply("unused", plan=text))
        assert (body["status"], body["error"], body["json_reason"]) == ("INVALID_PLAN", "PLAN_NOT_JSON", reason)


def test_manifest_with_a_repeated_key_or_nan_is_malformed_never_absent(tmp_path):
    good = {"version": 1, "db_sha256": "a", "write_id": "w", "sha256": "s", "label": "l"}
    (tmp_path / "manifest.json").write_text(json.dumps(good), encoding="utf-8")
    assert ti._manifest_read(tmp_path) == (good, None)
    base = json.dumps(good)[:-1]
    for text in (base + ', "version": 2}', base + ', "n": NaN}'):
        (tmp_path / "manifest.json").write_text(text, encoding="utf-8")
        assert ti._manifest_read(tmp_path) == (None, "MANIFEST_MALFORMED"), text


def test_slot_metadata_with_a_repeated_key_or_nan_starts_a_fresh_record(tmp_path):
    meta = tmp_path / "meta.json"
    for text in ('{"created": 5, "created": 6}', '{"created": NaN}'):
        meta.write_text(text, encoding="utf-8")
        ti._touch_meta(tmp_path, "abc")
        record = json.loads(meta.read_text(encoding="utf-8"))
        assert record["created"] > 1_000_000, text      # the unreadable record's "created" was not carried over
    meta.write_text('{"created": 5}', encoding="utf-8")
    ti._touch_meta(tmp_path, "abc")
    assert json.loads(meta.read_text(encoding="utf-8"))["created"] == 5


def _journal(tmp_path, monkeypatch, *lines):
    monkeypatch.setattr(ti, "ANNOTATED_ROOT", tmp_path)
    (tmp_path / ("a" * 64 + ti._ANNOTATION_LOG_SUFFIX)).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_annotation_journal_lines_with_a_repeated_key_or_nan_are_unreadable(tmp_path, monkeypatch):
    _journal(tmp_path, monkeypatch, '{"event": "x"}', '{"event": "a", "event": "b"}', '{"event": NaN}')
    records, unreadable, error = ti._journal_records("a" * 64)
    assert records == [{"event": "x"}] and unreadable == 2 and error is None


def test_ida_annotations_reader_counts_a_line_with_a_repeated_key_or_nan_as_unreadable(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")
    monkeypatch.setattr(ti, "_checked_path", lambda path, tool, echo_path=True: (sample, None))
    monkeypatch.setattr(ti, "_sha256_md5", lambda p: ("a" * 64, "m"))
    _journal(tmp_path, monkeypatch, '{"event": "x"}', '{"event": "a", "event": "b"}', '{"event": NaN}')
    body = json.loads(ti.ida_annotations(str(sample)))
    assert (body["total_entries"], body["unreadable_lines"]) == (1, 2)


def _cp(code=0):
    return SimpleNamespace(returncode=code, stdout="", stderr="")


_DONE = '{"script_completed": %s, "operation": "summary", "results": [{"operation": "summary"}]}'


def test_idat_result_file_with_a_repeated_key_or_nan_is_not_a_completed_result(tmp_path):
    result = tmp_path / ti._RESULT_NAME
    result.write_text(_DONE % "true", encoding="utf-8")
    _data, _error, signals = ti._verdict(_cp(), tmp_path, tmp_path / ti._DB_NAME, expect_database=False,
                                         expect_operation="summary")
    assert signals["result_script_completed"] is True
    for text in ('{"script_completed": false, "script_completed": true, "operation": "summary"}',
                 '{"script_completed": true, "operation": "summary", "n": NaN}'):
        result.write_text(text, encoding="utf-8")
        data, _error, signals = ti._verdict(_cp(), tmp_path, tmp_path / ti._DB_NAME, expect_database=False,
                                            expect_operation="summary")
        assert data is None and signals["result_script_completed"] is False, text


def test_idalib_result_file_with_a_repeated_key_or_nan_is_not_a_completed_result(tmp_path):
    result = tmp_path / ti._IDALIB_RESULT_NAME
    ops = [{"operation": "summary"}]
    result.write_text(_DONE % "true", encoding="utf-8")
    *_rest, signals = ti._verdict_idalib(_cp(), tmp_path, creating=False, operations=ops)
    assert signals["result_script_completed"] is True and signals["result_operation_matches"] is True
    for text in ('{"script_completed": false, "script_completed": true, "results": [{"operation": "summary"}]}',
                 '{"script_completed": true, "results": [{"operation": "summary"}], "n": NaN}'):
        result.write_text(text, encoding="utf-8")
        envelope, _first, _error, signals = ti._verdict_idalib(_cp(), tmp_path, creating=False, operations=ops)
        assert envelope is None and signals["result_script_completed"] is False, text
        assert signals["result_operation_matches"] is False, text


def test_idalib_probe_result_with_a_repeated_key_or_nan_is_a_failed_probe(tmp_path, monkeypatch):
    interpreter = tmp_path / "python.exe"
    interpreter.write_bytes(b"x")
    monkeypatch.setenv(ti.IDALIB_PYTHON_ENV, str(interpreter))

    def run_with(text):
        def fake(command, **kwargs):
            Path(command[-1]).write_text(text, encoding="utf-8")
            return SimpleNamespace(launch_failed=False, launch_error=None, timed_out=False, returncode=0,
                                   stdout="", stderr="")
        monkeypatch.setattr(ti, "run_bounded_process", fake)
        return ti._idalib_probe(use_cache=False)[0]["status"]

    assert run_with('{"import_ok": false, "error": "x"}') == "IDAPRO_IMPORT_FAILED"
    for text in ('{"import_ok": false, "import_ok": true}', '{"import_ok": true, "n": NaN}'):
        assert run_with(text) == "PROBE_FAILED", text


# -- 3d: recover/ and report/ ------------------------------------------------------------------------------------

def _refusal(body_text):
    body = json.loads(body_text)
    return body["status"], body.get("reason")


def test_binary_version_diff_refuses_a_repeated_key_or_nan_with_its_reason():
    from liebert_re.recover.binary_version_diff import binary_version_diff

    assert json.loads(binary_version_diff("{}", "{}")).get("status") != "INVALID_JSON"
    assert _refusal(binary_version_diff(DUP, "{}")) == ("INVALID_JSON", strict_json.DUPLICATE_KEY)
    assert _refusal(binary_version_diff("{}", NAN)) == ("INVALID_JSON", strict_json.NON_FINITE)


def test_dotnet_relationship_analyze_refuses_a_repeated_key_or_nan_with_its_reason():
    from liebert_re.recover.dotnet_relationships import dotnet_relationship_analyze

    assert json.loads(dotnet_relationship_analyze("{}")).get("status") != "INVALID_JSON"
    assert _refusal(dotnet_relationship_analyze(DUP)) == ("INVALID_JSON", strict_json.DUPLICATE_KEY)
    assert _refusal(dotnet_relationship_analyze(NAN)) == ("INVALID_JSON", strict_json.NON_FINITE)


def test_cross_binary_relationship_analyze_refuses_a_repeated_key_or_nan_with_its_reason():
    from liebert_re.recover.cross_binary_relationships import cross_binary_relationship_analyze

    assert _refusal(cross_binary_relationship_analyze("[]"))[0] != "INVALID_INPUT"
    assert _refusal(cross_binary_relationship_analyze("[]", DUP)) == ("INVALID_INPUT", strict_json.DUPLICATE_KEY)
    assert _refusal(cross_binary_relationship_analyze(NAN)) == ("INVALID_INPUT", strict_json.NON_FINITE)


def test_native_xref_analyze_refuses_a_repeated_key_or_nan_with_its_reason():
    from liebert_re.recover.native_xref import native_xref_analyze

    from liebert_re.recover.analysis_ir import AnalysisIR

    ir = json.dumps(AnalysisIR().to_dict())
    assert _refusal(native_xref_analyze(ir, "[]"))[0] != "INVALID_INPUT"
    assert _refusal(native_xref_analyze(DUP, "[]")) == ("INVALID_INPUT", strict_json.DUPLICATE_KEY)
    assert _refusal(native_xref_analyze(ir, "[NaN]")) == ("INVALID_INPUT", strict_json.NON_FINITE)
    assert _refusal(native_xref_analyze(ir, '[{"a": 1, "a": 2}]')) == ("INVALID_INPUT", strict_json.DUPLICATE_KEY)


def test_counter_evidence_and_finding_report_refuse_a_repeated_key_or_nan_with_their_reason():
    from liebert_re.report.analysis_findings import counter_evidence_verify, finding_report_generate

    assert _refusal(counter_evidence_verify(DUP, "[]")) == ("INVALID_JSON", strict_json.DUPLICATE_KEY)
    assert _refusal(counter_evidence_verify("{}", "[NaN]")) == ("INVALID_JSON", strict_json.NON_FINITE)
    assert _refusal(finding_report_generate("[]", DUP)) == ("INVALID_JSON", strict_json.DUPLICATE_KEY)
    assert _refusal(finding_report_generate(NAN)) == ("INVALID_JSON", strict_json.NON_FINITE)


def test_tool_families_classification_text_that_is_not_strict_is_unknown():
    from liebert_re.report.tool_families import _classification_dict

    assert _classification_dict('{"tool_family": "native"}') == {"tool_family": "native"}
    for text in ('{"tool_family": "native", "tool_family": "dotnet"}', '{"tool_family": NaN}'):
        assert _classification_dict(text) is None, text


_HASH = "a" * 64
_DESCRIPTOR = {"vm_id": "vm1", "snapshot_id": "s1", "os_build": "10.0", "architecture": "x64",
               "isolated_vm": True}


def test_exploit_validation_plan_with_a_bad_json_argument_is_blocked_and_says_why():
    from liebert_re.report.exploit_validation import exploit_validation_plan

    good = json.loads(exploit_validation_plan('{"hypothesis_id": "H1"}', _HASH, "vm-backend", 60))
    assert not any("not_strict_json" in r for r in good["blocking_reasons"])
    for text, reason in ((DUP, strict_json.DUPLICATE_KEY), (NAN, strict_json.NON_FINITE)):
        plan = json.loads(exploit_validation_plan(text, _HASH, "vm-backend", 60))
        assert plan["status"] == "BLOCKED"
        assert f"hypothesis_json_not_strict_json:{reason}" in plan["blocking_reasons"]
        plan = json.loads(exploit_validation_plan('{"hypothesis_id": "H1"}', _HASH, "vm-backend", 60, text))
        assert plan["status"] == "BLOCKED"
        assert f"isolation_descriptor_json_not_strict_json:{reason}" in plan["blocking_reasons"]


def test_exploit_validation_result_verify_with_a_bad_json_argument_rejects_and_names_the_input():
    from liebert_re.report.exploit_validation import exploit_validation_result_verify

    clean = json.loads(exploit_validation_result_verify("{}", "{}"))
    assert not any(i["code"] == "INPUT_NOT_STRICT_JSON" for i in clean["issues"])
    for text, reason in ((DUP, strict_json.DUPLICATE_KEY), (NAN, strict_json.NON_FINITE)):
        verdict = json.loads(exploit_validation_result_verify(text, "{}"))
        assert verdict["status"] == "INCONCLUSIVE" and verdict["eligible_for_confirmed"] is False
        assert verdict["issues"][0] == {"code": "INPUT_NOT_STRICT_JSON", "severity": "REJECT",
                                        "field": "plan_json", "reason": reason}
        verdict = json.loads(exploit_validation_result_verify("{}", text))
        assert {"code": "INPUT_NOT_STRICT_JSON", "severity": "REJECT", "field": "result_json",
                "reason": reason} in verdict["issues"]


def test_exploit_validation_result_verify_a_bad_result_does_not_empty_the_other_input():
    """Only the unreadable argument is replaced by an empty one; the readable plan is still checked as given."""
    from liebert_re.report.exploit_validation import exploit_validation_result_verify

    plan = json.dumps({"status": "BLOCKED"})
    verdict = json.loads(exploit_validation_result_verify(plan, DUP))
    codes = [i["code"] for i in verdict["issues"]]
    assert "PLAN_BLOCKED" in codes and "PLAN_NOT_READY" not in codes


# -- 3d: the generic probe ----------------------------------------------------------------------------------------

def test_normalize_tool_result_text_with_a_repeated_key_or_nan_is_never_ready():
    from liebert_re.tools.generic_static_probe import normalize_tool_result

    ok = normalize_tool_result('{"ok": true}', tool="t", target="x")
    assert ok["status"] == "READY"
    for text in ('{"ok": false, "ok": true}', '{"ok": true, "n": NaN}'):
        got = normalize_tool_result(text, tool="t", target="x")
        assert got["status"] == "UNKNOWN", text
        assert any("not strict JSON" in item for item in got["limitations"]), text
    plain = normalize_tool_result("plain words", tool="t", target="x")
    assert "tool output was not JSON; its status could not be determined" in plain["limitations"]


@pytest.mark.parametrize("identity_text", ["not json", DUP, NAN, "[1, 2]"])
def test_generic_static_probe_with_an_unreadable_file_identity_is_a_failed_result(tmp_path, monkeypatch,
                                                                                  identity_text):
    from liebert_re.tools import generic_static_probe as gsp

    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + b"\0" * 64)
    monkeypatch.setattr(gsp, "safe_path", lambda p: target)
    monkeypatch.setattr(gsp, "relative", lambda p: p.name)
    monkeypatch.setattr(gsp, "file_identity", lambda p: identity_text)
    body = json.loads(gsp.generic_static_probe(str(target)))
    assert body["status"] == "FAILED"
    assert body["details"]["error"] == "FILE_IDENTITY_UNREADABLE" and body["details"]["reason"]
    # A readable identity still probes as before.
    monkeypatch.setattr(gsp, "file_identity", lambda p: json.dumps({"type": "UNKNOWN", "text": False}))
    assert json.loads(gsp.generic_static_probe(str(target)))["status"] == "PARTIAL"

