"""strict_json slice 3a: external tool stdout that is JSON but not strict JSON (a repeated key,
NaN/Infinity, a number that overflows a double, nesting past the bound) is a named failure in the
tool's result with the strict_json ``reason``, never an empty result or a success. Covers capa, die,
yara_x, ghidra, binary (authenticode), rizin (aflj, pdj, rz-bin, the iIj probe) and the strict
``raw_decode`` helper they share. pe_sieve's cases live in ``test_tools_pe_sieve.py`` (its fixtures).
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from liebert_re import strict_json
from liebert_re.bounded_subprocess import BoundedProcessResult

DEEP = "[" * 300 + "]" * 300
# (label, text for a top-level object, expected strict_json reason)
OBJECT_CASES = [
    ("dup", '{"rules": {}, "meta": {}, "rules": {"x": 1}}', "DUPLICATE_KEY"),
    ("nan", '{"rules": {}, "matches": [], "n": NaN}', "NON_FINITE"),
    ("inf", '{"rules": {}, "matches": [], "n": -Infinity}', "NON_FINITE"),
    ("overflow", '{"rules": {}, "matches": [], "n": 1e999}', "NON_FINITE"),
    ("deep", '{"rules": {}, "matches": [], "n": ' + DEEP + "}", "TOO_DEEP"),
]


@pytest.fixture()
def sample(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"\0" * 64)
    return path


def _ok(stdout):
    return BoundedProcessResult(0, stdout, "")


def _run(module_name, binary_attr, binary_value, fn_name, sample, result, *args, **kwargs):
    import importlib
    mod = importlib.import_module("liebert_re.tools." + module_name)
    with mock.patch.object(mod, binary_attr, return_value=binary_value), \
         mock.patch.object(mod, "safe_path", return_value=sample), \
         mock.patch.object(mod, "relative", return_value=sample.name), \
         mock.patch.object(mod, "run_bounded_process", return_value=result):
        return json.loads(getattr(mod, fn_name)(str(sample), *args, **kwargs))


@pytest.mark.parametrize("label,text,reason", OBJECT_CASES)
def test_capa_non_strict_stdout_is_a_parse_failure_with_the_reason(sample, label, text, reason):
    data = _run("capa", "_capa_binary", "C:/fake/capa.exe", "capa_analyze", sample, _ok(text))
    assert data["ok"] is False and data["status"] == "RESULT_PARSE_FAILED", label
    assert data["reason"] == reason, label


@pytest.mark.parametrize("label,text,reason", OBJECT_CASES)
def test_die_non_strict_stdout_is_a_parse_failure_with_the_reason(sample, label, text, reason):
    data = _run("die", "_die_binary", "C:/fake/diec.exe", "die_identify", sample, _ok(text))
    assert data["ok"] is False and data["status"] == "RESULT_PARSE_FAILED", label
    assert data["reason"] == reason, label


@pytest.mark.parametrize("label,text,reason", OBJECT_CASES)
def test_yara_x_non_strict_stdout_is_a_parse_failure_with_the_reason(sample, label, text, reason):
    data = _run("yara_x", "_yara_x_binary", "C:/fake/yr.exe", "yara_x_scan", sample, _ok(text),
                rules_text="rule r{condition:true}")
    assert data["ok"] is False and data["status"] == "RESULT_PARSE_FAILED", label
    assert data["reason"] == reason, label


def test_strict_stdout_is_still_accepted_by_capa_die_and_yara_x(sample):
    capa = _run("capa", "_capa_binary", "C:/fake/capa.exe", "capa_analyze", sample,
                _ok(json.dumps({"meta": {}, "rules": {}})))
    assert capa["ok"] is True
    yara = _run("yara_x", "_yara_x_binary", "C:/fake/yr.exe", "yara_x_scan", sample,
                _ok(json.dumps({"matches": []})), rules_text="rule r{condition:true}")
    assert yara["ok"] is True and yara["matched"] is False


@pytest.mark.parametrize("label,text,reason", OBJECT_CASES)
def test_ghidra_result_file_that_is_not_strict_json_is_a_named_refusal(tmp_path, label, text, reason):
    from liebert_re.tools import ghidra
    result = tmp_path / "result.json"
    result.write_text(text, encoding="utf-8")
    data, error = ghidra._read_result(result)
    assert data is None and error == "GHIDRA_RESULT_NOT_STRICT_JSON_" + reason, label
    result.write_text("{not json", encoding="utf-8")
    assert ghidra._read_result(result) == (None, "GHIDRA_RESULT_NOT_JSON")


@pytest.mark.parametrize("label,text,reason", OBJECT_CASES)
def test_authenticode_stdout_that_is_not_strict_json_is_not_a_signature_answer(label, text, reason):
    from liebert_re.tools import binary
    out = binary._authenticode_fields(text.replace('"rules"', '"Status"'))
    assert out["ok"] is False and out["status"] == "ANALYSIS_LIMITED", label
    assert out["error"] == "NON_STRICT_JSON_RESULT" and out["reason"] == reason, label
    assert binary._authenticode_fields("Status : Valid")["error"] == "AUTHENTICODE_OUTPUT_UNPARSEABLE"


ARRAY_CASES = [
    ('[{"offset": 1, "offset": 2}]', "DUPLICATE_KEY"),
    ('[{"offset": NaN}]', "NON_FINITE"),
    ('[{"offset": 1e999}]', "NON_FINITE"),
    (DEEP, "TOO_DEEP"),
]


@pytest.mark.parametrize("text,reason", ARRAY_CASES)
def test_rizin_extract_json_array_refuses_non_strict_and_does_not_scan_on(text, reason):
    from liebert_re.tools import rizin
    assert rizin._extract_json_array(text) == (None, None, "NOT_STRICT_" + reason)
    # a banner "[INFO]" before the array is still skipped; a non-strict array after it is not rescued
    assert rizin._extract_json_array("[INFO] x " + text)[2] == "NOT_STRICT_" + reason
    # no fragment of the untrusted array is returned as a list
    assert rizin._extract_json_array('[{"a": 1, "a": [1]}]')[0] is None


def test_rizin_extract_json_array_keeps_its_old_behaviour_on_strict_input():
    from liebert_re.tools import rizin
    assert rizin._extract_json_array('[INFO] noise [1, 2] {"x": 1}') == ([1, 2], 19, "OK")
    assert rizin._extract_json_array("no brackets")[2] == "ABSENT"
    assert rizin._extract_json_array("[{not json,,,]")[2] == "MALFORMED"


@pytest.mark.parametrize("text,reason", [
    ('{"havecode": true, "havecode": false}', "DUPLICATE_KEY"), ('{"bits": NaN}', "NON_FINITE")])
def test_rizin_load_probe_with_non_strict_info_is_unavailable_with_the_reason(text, reason):
    from liebert_re.tools import rizin
    probe = rizin._rizin_load_probe(text)
    assert probe["status"] == "PROBE_UNAVAILABLE" and reason in probe["reason"]
    assert rizin._rizin_load_probe('{"havecode": true}')["status"] == "BINARY_LOADED"


@pytest.mark.parametrize("text,reason", ARRAY_CASES)
def test_rizin_functions_non_strict_array_is_a_parse_failure_with_the_reason(sample, text, reason):
    data = _run("rizin", "_rizin_binary", "C:/fake/rizin.exe", "rizin_functions", sample, _ok(text),
                timeout_seconds=10)
    assert data["ok"] is False and data["status"] == "RESULT_PARSE_FAILED"
    assert data["error"] == "NON_STRICT_JSON_RESULT" and data["reason"] == reason


@pytest.mark.parametrize("label,text,reason", [
    ("dup", '{"imports": [], "imports": [1]}', "DUPLICATE_KEY"),
    ("nan", '{"imports": [{"ordinal": NaN}]}', "NON_FINITE")])
def test_rz_bin_non_strict_stdout_is_a_parse_failure_with_the_reason(sample, label, text, reason):
    from liebert_re.tools import rizin as tr
    with mock.patch.object(tr._RzBin, "binary", return_value="C:/fake/rz-bin.exe"), \
         mock.patch.object(tr, "safe_path", return_value=sample), \
         mock.patch.object(tr, "relative", return_value=sample.name), \
         mock.patch.object(tr, "run_bounded_process", return_value=_ok(text)):
        data = json.loads(tr.rz_bin_imports(str(sample)))
    assert data["ok"] is False and data["status"] == "RESULT_PARSE_FAILED", label
    assert data["reason"] == reason, label


def test_rizin_pdj_non_strict_array_is_a_parse_failure_with_the_reason():
    from liebert_re.tools import rizin as tr
    resolved = {"va": "0x1000", "rizin_arch": "x86", "bits": 64}
    with mock.patch.object(tr, "run_bounded_process", return_value=_ok('[{"offset": 1, "offset": 2}]')):
        items, fail = tr._pdj("C:/fake/rizin.exe", "x.exe", resolved, 1, 10, None)
    assert items is None and fail["ok"] is False and fail["status"] == "RESULT_PARSE_FAILED"
    assert fail["error"] == "NON_STRICT_JSON_RESULT" and fail["reason"] == "DUPLICATE_KEY"


# ---- strict_json.raw_decode itself ---------------------------------------------------------------

def test_raw_decode_reports_the_end_and_ignores_what_follows():
    assert strict_json.raw_decode('xx[1, 2] trailing "[" junk', 2) == ([1, 2], 8)
    assert strict_json.raw_decode('{"a": 1} NaN {"b": 1, "b": 2}') == ({"a": 1}, 8)


@pytest.mark.parametrize("text,reason", [
    ('{"a": 1, "a": 2}', "DUPLICATE_KEY"), ('[NaN]', "NON_FINITE"), ('[Infinity]', "NON_FINITE"),
    ('[1e999]', "NON_FINITE"), (DEEP, "TOO_DEEP"), ('{"a":' * 300 + "1" + "}" * 300, "TOO_DEEP"),
    ("[1, 2", "MALFORMED"), ("nope", "MALFORMED")])
def test_raw_decode_refuses_what_loads_refuses(text, reason):
    with pytest.raises(strict_json.StrictJSONError) as caught:
        strict_json.raw_decode(text)
    assert caught.value.reason == reason
    with pytest.raises(TypeError):
        strict_json.raw_decode(b"[1]")


def test_raw_decode_depth_counts_only_the_consumed_span():
    assert strict_json.raw_decode("[1] " + DEEP) == ([1], 3)
    assert strict_json.raw_decode('["[[[[", 1]')[0] == ["[[[[", 1]
