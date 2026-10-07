"""``liebert-re tool list | describe | run``: the registry-driven generic dispatcher in ``cli.py``.

Names and modules come from ``liebert_re.report.tool_families`` (a source scan), signatures from the AST,
so nothing here hard-codes how many tools exist: ``list`` is compared with ``published_tools``. The
exit-code contract is the CLI's own (module docstring of ``liebert_re/cli.py``): 0 answered, 2 bad
invocation, 3 structured refusal.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from liebert_re import cli
from liebert_re.report.tool_families import FAMILIES, published_tools, python_only_declarations

REPO_ROOT = Path(__file__).resolve().parent.parent


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    return root


def _published():
    return set().union(*(published_tools(family) for family in FAMILIES))


def test_list_covers_every_published_tool_and_shows_declarations(capsys):
    code, out = run(capsys, "tool", "list")
    assert code == 0 and out["ok"] is True and out["command"] == "tool"
    names = [row["name"] for row in out["tools"]]
    assert set(names) == _published() and len(names) == len(set(names)) == out["count"]
    assert {row["name"]: row["python_only"] for row in out["tools"] if row["python_only"]} == python_only_declarations()
    assert all(row["module"].startswith("liebert_re.") for row in out["tools"])


def test_describe_reads_the_signature_from_source(capsys):
    code, out = run(capsys, "tool", "describe", "binary_strings")
    assert code == 0 and out["tool"] == "binary_strings" and out["module"] == "liebert_re.tools.binary"
    params = {p["name"]: p for p in out["parameters"]}
    assert list(params) == ["path", "min_length", "contains", "max_results"]
    assert params["path"]["required"] is True and "default" not in params["path"]
    assert params["min_length"]["default"] == 4 and params["min_length"]["default_source"] == "4"
    assert params["contains"]["default"] is None and params["contains"]["required"] is False


def test_describe_gives_the_first_docstring_paragraph_and_works_for_a_declared_tool(capsys):
    code, out = run(capsys, "tool", "describe", "binary_patch")
    assert code == 0 and out["python_only"] == python_only_declarations()["binary_patch"]
    assert out["summary"].startswith("General-purpose, reusable disk-patch capability")
    assert "\n" not in out["summary"] and "CLI: python-only" not in out["summary"]
    assert out["async"] is False and out["parameters"][0]["name"] == "path"


def test_describe_does_not_import_the_tool_module():
    # In a fresh interpreter: another test may already have imported the module in this process.
    code = (
        "import io, json, sys, contextlib\n"
        "from liebert_re import cli\n"
        "buf = io.StringIO()\n"
        "with contextlib.redirect_stdout(buf):\n"
        "    rc = cli.main(['tool', 'describe', 'hash_file'])\n"
        "    rc2 = cli.main(['tool', 'list'])\n"
        "loaded = [m for m in ('liebert_re.tools.binary', 'liebert_re.workspace', 'liebert_re.tools.ida',"
        " 'liebert_re.tools.rizin', 'liebert_re.tools.formats') if m in sys.modules]\n"
        "print(json.dumps({'rc': [rc, rc2], 'loaded': loaded}))\n"
    )
    done = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
                          env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.splitlines()[-1]) == {"rc": [0, 0], "loaded": []}


@pytest.mark.parametrize("argv, error", [
    (("tool", "run", "no_such_tool"), "UNKNOWN_TOOL"),
    (("tool", "describe", "no_such_tool"), "UNKNOWN_TOOL"),
    (("tool", "run", "hash_file", "--args", "{not json"), "BAD_ARGS_JSON"),
    (("tool", "run", "hash_file", "--args", "[1, 2]"), "ARGS_NOT_OBJECT"),
    (("tool", "run", "hash_file", "--args", '{"path": "x", "extra": 1}'), "UNKNOWN_ARGUMENT"),
    (("tool", "run", "hash_file", "--args", "{}"), "MISSING_ARGUMENT"),
    (("tool", "run", "hash_file", "--args", '{"path": 5}'), "BAD_ARGUMENT_TYPE"),
    # a write destination is never accepted, even though archive_inspect itself declares it
    (("tool", "run", "archive_inspect", "--args", '{"path": "x.zip", "operation": "extract", "dest_path": "out"}'),
     "ARGUMENT_NOT_ACCEPTED"),
    (("tool", "run", "pe_sections", "--args", '{"path": "x", "cancellation_token": "t"}'), "UNKNOWN_ARGUMENT"),
    (("tool", "run", "authenticode_signature", "--args", '{"path": "x", "cancellation_token": "t"}'),
     "ARGUMENT_NOT_ACCEPTED"),
])
def test_bad_invocations_are_usage_errors(capsys, argv, error):
    code, out = run(capsys, *argv)
    assert code == 2 and out["status"] == "TOOL_USAGE" and out["error"] == error and out["ok"] is False


def test_declared_tool_is_unsupported_with_its_reason(capsys):
    declared = python_only_declarations()
    assert declared, "the write-capable tools must be declared"
    for name, reason in declared.items():
        code, out = run(capsys, "tool", "run", name, "--args", "{}")
        assert code == 3 and out["status"] == "UNSUPPORTED" and out["error"] == "PYTHON_ONLY"
        assert out["reason"] == reason and out["tool"] == name


def test_no_archive_inspect_or_rar_7z_extraction_destination(capsys):
    # rar_7z has no destination parameter at all; archive_inspect's is refused by the dispatcher.
    code, out = run(capsys, "tool", "describe", "rar_7z")
    assert code == 0 and "dest_path" not in {p["name"] for p in out["parameters"]}
    code, out = run(capsys, "tool", "describe", "archive_inspect")
    assert code == 0 and "dest_path" in {p["name"] for p in out["parameters"]}
    assert "archive_inspect" not in python_only_declarations()


def test_run_hash_file_on_a_temp_file(capsys, workspace):
    target = workspace / "sample.bin"
    target.write_bytes(b"liebert dispatch fixture")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "hash_file",
                    "--args", json.dumps({"path": str(target)}))
    assert code == 0 and out["command"] == "tool"
    assert out["sha256"] == hashlib.sha256(b"liebert dispatch fixture").hexdigest()
    assert out["md5"] == hashlib.md5(b"liebert dispatch fixture").hexdigest()
    assert out["workspace"]["source"] == "--workspace"


def test_run_binary_strings_on_a_small_byte_string_file(capsys, workspace):
    (workspace / "blob.bin").write_bytes(b"\x00\x01needle-string-here\x00\xff\xfe" + "wide!".encode("utf-16le"))
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "binary_strings",
                    "--args", json.dumps({"path": str(workspace / "blob.bin"), "contains": "needle", "min_length": 4}))
    assert code == 0 and out["tool"] == "binary_strings" and out["ok"] is True and out["classified"] is False
    assert "needle-string-here" in out["text"]


def test_path_outside_the_workspace_is_refused_before_the_tool_runs(capsys, workspace, tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x" * 8)
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "hash_file",
                    "--args", json.dumps({"path": str(outside)}))
    assert code == 3 and out["status"] == "PATH_REFUSED"


def test_secondary_path_parameter_is_checked_too(capsys, workspace, tmp_path):
    inside = workspace / "a.bin"
    inside.write_bytes(b"y" * 8)
    outside = tmp_path / "b.bin"
    outside.write_bytes(b"z" * 8)
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "minidump_analyzer",
                    "--args", json.dumps({"path": str(inside), "pe_path": str(outside)}))
    assert code == 3 and out["status"] == "PATH_REFUSED"


def test_missing_target_file_is_the_usual_file_not_found_refusal(capsys, workspace):
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "hash_file",
                    "--args", json.dumps({"path": "absent.bin"}))
    assert code == 3 and out["status"] == "PATH_REFUSED" and out["error"] == "FILE_NOT_FOUND"


def test_text_answer_is_wrapped_in_the_generic_envelope_and_says_it_is_unclassified(capsys, workspace):
    # read_file answers in prose; the generic path carries it as {"tool", "text"} and does not pretend
    # to have classified it (a prose "File not found" from another tool looks the same).
    (workspace / "t.txt").write_text("hello\n", encoding="utf-8")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "read_file",
                    "--args", json.dumps({"path": str(workspace / "t.txt")}))
    assert code == 0 and out["command"] == "tool" and out["tool"] == "read_file"
    assert out["result_format"] == "text" and "hello" in out["text"]
    assert out["ok"] is True and out["status"] == "OK" and out["classified"] is False


def _str_annotated_tools():
    """Published tools declared ``-> str``, read from the AST (never imported), minus the python-only ones."""
    import ast
    modules, declared = cli._tool_registry()
    out = []
    for name, module in sorted(modules.items()):
        node = cli._tool_node(module, name)
        if node is not None and node.returns is not None and ast.unparse(node.returns) == "str" and name not in declared:
            out.append(name)
    return out


def test_str_annotated_analysis_tool_runs_through_the_generic_path(capsys, workspace):
    # Every `-> str` analysis tool in this package returns a JSON document as text; the generic path
    # must hand back the parsed document (not a {"text": ...} wrapper) and exit 0.
    tools = _str_annotated_tools()
    assert "generic_static_probe" in tools, "the str-annotated selection is broken"
    (workspace / "s.bin").write_bytes(b"MZ\x90\x00 liebert fixture \x00")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "generic_static_probe",
                    "--args", json.dumps({"path": str(workspace / "s.bin")}))
    assert code == 0 and out["command"] == "tool" and out["tool"] == "generic_static_probe"
    assert "text" not in out and "classified" not in out and out["status"] == "READY"


def test_plain_text_from_a_str_tool_is_enveloped_and_bytes_are_decoded_or_refused(capsys, workspace, monkeypatch):
    (workspace / "s.bin").write_bytes(b"x" * 8)
    answers = {}
    real_load = cli._load
    monkeypatch.setattr(cli, "_load", lambda m, n: (lambda **kw: answers["v"])
                        if (m, n) == ("liebert_re.tools.binary", "hash_file") else real_load(m, n))
    argv = ("--workspace", str(workspace), "tool", "run", "hash_file", "--args", json.dumps({"path": str(workspace / "s.bin")}))
    answers["v"] = "plain prose answer\n[limit:5; truncated=true; returned=5; total=9]"
    code, out = run(capsys, *argv)
    assert code == 0 and out["tool"] == "hash_file" and out["text"] == answers["v"]
    assert out["truncation"]["omitted"] == 4 and out["classified"] is False
    answers["v"] = "plain\n[limit:5; truncated=true; returned=9; total=9]"
    code, out = run(capsys, *argv)
    assert code == 1 and out["error"] == "UNCLASSIFIED_OUTPUT"
    answers["v"] = "Authenticode verification requires Windows."
    code, out = run(capsys, *argv)
    assert code == 3 and out["status"] == "UNSUPPORTED" and out["tool"] == "hash_file"
    answers["v"] = "bytes answer".encode()
    code, out = run(capsys, *argv)
    assert code == 0 and out["text"] == "bytes answer" and out["tool"] == "hash_file"
    answers["v"] = b"\xff\xfe\x00"
    code, out = run(capsys, *argv)
    assert code == 1 and out["error"] == "BINARY_OUTPUT"


def test_no_per_tool_text_shape_remains_for_tool_run():
    assert cli._shape(cli._build_parser().parse_args(["tool", "run", "binary_strings"])) is None
    assert "binary_strings" not in cli._TEXT_SHAPES
