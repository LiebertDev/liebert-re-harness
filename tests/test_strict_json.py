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
