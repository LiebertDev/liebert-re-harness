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


# ---- text tools: failure lines carry a recognised status prefix; empty results are distinguishable ----

def _corrupt_import_pe(path):
    import struct

    from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_rsds
    build_owned_pe_with_rsds(path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<II", data, 88 + 112 + 8, 0x90000000, 40)  # import data directory -> outside the image
    path.write_bytes(bytes(data))


def test_text_tool_failure_through_the_envelope_is_ok_false_with_a_status(capsys, workspace):
    _corrupt_import_pe(workspace / "bad.exe")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "pe_imports",
                    "--args", json.dumps({"path": str(workspace / "bad.exe")}))
    assert out["tool"] == "pe_imports" and out["ok"] is False and out["status"] == "ANALYSIS_LIMITED"
    assert out["text"].startswith("IMPORT_DIRECTORY_UNREADABLE") and "empty" not in out
    assert code == 3


def test_empty_text_result_through_the_envelope_is_ok_true_and_marked_empty(capsys, workspace):
    (workspace / "blob.bin").write_bytes(b"\x00\x01needle-string-here\x00")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "binary_strings",
                    "--args", json.dumps({"path": str(workspace / "blob.bin"), "contains": "absent-needle"}))
    assert code == 0 and out["ok"] is True and out["status"] == "OK" and out["empty"] is True
    assert out["text"] == "EMPTY_RESULT: No strings found." and out["classified"] is False
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "binary_strings",
                    "--args", json.dumps({"path": str(workspace / "blob.bin"), "contains": "needle"}))
    assert code == 0 and out["ok"] is True and "empty" not in out  # a real listing is not marked empty


def test_empty_prefix_and_failure_codes_are_pinned_between_cli_and_tools():
    from liebert_re.tools import binary
    assert cli._TEXT_EMPTY_PREFIX == binary.EMPTY_RESULT_PREFIX
    assert binary.DOTNET_METADATA_UNREADABLE in cli._TEXT_LIMITED_PREFIXES
    assert binary.DISASSEMBLY_FAILED in cli._TEXT_LIMITED_PREFIXES
    assert binary.IMPORT_DIRECTORY_UNREADABLE in cli._TEXT_LIMITED_PREFIXES
    assert binary.EXPORT_DIRECTORY_UNREADABLE in cli._TEXT_LIMITED_PREFIXES


def test_every_empty_sentence_of_the_text_tools_carries_the_prefix(workspace, monkeypatch):
    import sys
    import types

    from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_rsds
    from liebert_re.tools import binary
    root = workspace
    monkeypatch.setattr(binary, "safe_path", lambda p: Path(p))
    monkeypatch.setattr(binary, "relative", lambda p: str(p))
    (root / "plain.bin").write_bytes(b"\x00" * 16)
    assert binary.binary_strings(str(root / "plain.bin")) == "EMPTY_RESULT: No strings found."
    assert binary.find_binaries(str(root)) == "EMPTY_RESULT: No binary found."
    assert binary.search_binary_bytes(str(root / "plain.bin"), "AA BB") == "EMPTY_RESULT: No matches."
    build_owned_pe_with_rsds(root / "x.exe")
    assert binary.pe_imports(str(root / "x.exe")) == "EMPTY_RESULT: No import table."
    assert binary.pe_exports(str(root / "x.exe")) == "EMPTY_RESULT: No export table."
    assert binary.dotnet_metadata(str(root / "x.exe")) == "EMPTY_RESULT: No CLR/.NET header present."
    # a CLR header whose TypeDef table is empty, and one whose metadata cannot be read (fake dnfile, no real assembly)
    monkeypatch.setattr(binary, "_pe", lambda p: types.SimpleNamespace(OPTIONAL_HEADER=types.SimpleNamespace(
        DATA_DIRECTORY=[types.SimpleNamespace(VirtualAddress=1)] * 15)))
    fake = types.ModuleType("dnfile")
    fake.dnPE = lambda p: types.SimpleNamespace(net=types.SimpleNamespace(
        mdtables=types.SimpleNamespace(TypeDef=types.SimpleNamespace(rows=[]))))
    monkeypatch.setitem(sys.modules, "dnfile", fake)
    assert binary.dotnet_metadata(str(root / "x.exe")) == "EMPTY_RESULT: .NET assembly parsed, but TypeDef table is empty."
    fake.dnPE = lambda p: types.SimpleNamespace(net=types.SimpleNamespace(mdtables=None))
    out = binary.dotnet_metadata(str(root / "x.exe"))
    assert out.startswith("DOTNET_METADATA_UNREADABLE: .NET metadata incomplete or failed: ")
    assert cli._decode(out, None, "dotnet_metadata")["status"] == "ANALYSIS_LIMITED"


def test_disassembly_with_nothing_decoded_is_a_limited_failure_not_an_empty_answer(monkeypatch):
    from liebert_re.tools import binary
    monkeypatch.setattr(binary, "_dpe_open", lambda *a, **k: (
        {"md": None, "data": b"", "start_offset": 0, "base": 0}, None))
    out = binary.disassemble_pe("x")
    assert out == "DISASSEMBLY_FAILED: No instruction could be decoded."
    body = cli._decode(out, cli._TEXT_SHAPES["disasm"])
    assert body["ok"] is False and body["status"] == "ANALYSIS_LIMITED" and "empty" not in body


def test_direct_commands_mark_an_empty_listing_too():
    body = cli._decode("EMPTY_RESULT: No import table.", cli._TEXT_SHAPES["imports"])
    assert body["ok"] is True and body["empty"] is True and body["status"] == "OK"
    assert cli._decode("EMPTY_RESULT: No export table.", cli._TEXT_SHAPES["exports"])["empty"] is True
    assert cli._decode("No import table.", cli._TEXT_SHAPES["imports"])["error"] == "UNCLASSIFIED_OUTPUT"


# ---- authenticode_signature: JSON on success and on failure, parsed from the PowerShell stdout ----

_PS_OK = json.dumps({"Status": "Valid", "StatusMessage": "Signature verified.", "SignerSubject": "CN=Example Signer",
                     "Issuer": "CN=Example CA", "Thumbprint": "AB" * 20, "TimestamperSubject": None})


def _fake_powershell(monkeypatch, *, stdout="", stderr="", returncode=0):
    import sys
    import types

    from liebert_re.tools import binary
    monkeypatch.setattr(sys, "platform", "win32")  # the gate reads sys.platform
    monkeypatch.setattr(binary, "run_bounded_process", lambda *a, **k: types.SimpleNamespace(
        launch_failed=False, cancelled=False, timed_out=False, stdout=stdout, stderr=stderr, returncode=returncode))


def _signature(capsys, workspace, monkeypatch, **fake):
    (workspace / "s.exe").write_bytes(b"MZ")
    _fake_powershell(monkeypatch, **fake)
    return run(capsys, "--workspace", str(workspace), "tool", "run", "authenticode_signature",
               "--args", json.dumps({"path": str(workspace / "s.exe")}))


def test_authenticode_success_is_json_with_unknown_fields_as_none(capsys, workspace, monkeypatch):
    code, out = _signature(capsys, workspace, monkeypatch, stdout=_PS_OK + "\n")
    assert code == 0 and out["ok"] is True and out["status"] == "OK" and out["signature_status"] == "Valid"
    assert out["signer"] == "CN=Example Signer" and out["issuer"] == "CN=Example CA"
    assert out["timestamper"] is None and out["raw"] == _PS_OK and "text" not in out
    partial = json.dumps({"Status": "NotSigned", "StatusMessage": "The file is not digitally signed."})
    code, out = _signature(capsys, workspace, monkeypatch, stdout=partial)
    assert code == 0 and out["signature_status"] == "NotSigned"
    assert out["signer"] is None and out["issuer"] is None and out["thumbprint"] is None and out["timestamper"] is None


def test_authenticode_unparseable_output_and_command_failure_are_json_failures(capsys, workspace, monkeypatch):
    code, out = _signature(capsys, workspace, monkeypatch, stdout="Status : Valid")
    assert code == 3 and out["ok"] is False and out["status"] == "ANALYSIS_LIMITED"
    assert out["error"] == "AUTHENTICODE_OUTPUT_UNPARSEABLE" and out["raw"] == "Status : Valid"
    code, out = _signature(capsys, workspace, monkeypatch, stderr="boom\n", returncode=1)
    assert code == 3 and out["ok"] is False and out["error"] == "AUTHENTICODE_COMMAND_FAILED" and out["stderr"] == "boom"


def test_authenticode_direct_command_returns_the_same_json(capsys, workspace, monkeypatch):
    (workspace / "s.exe").write_bytes(b"MZ")
    _fake_powershell(monkeypatch, stdout=_PS_OK)
    code, out = run(capsys, "--workspace", str(workspace), "pe", str(workspace / "s.exe"), "--signature")
    assert code == 0 and out["command"] == "pe" and out["signature_status"] == "Valid" and out["ok"] is True


def test_authenticode_off_windows_is_a_structured_unsupported_failure(capsys, workspace, monkeypatch):
    import sys
    (workspace / "s.exe").write_bytes(b"MZ")
    monkeypatch.setattr(sys, "platform", "linux")
    code, out = run(capsys, "--workspace", str(workspace), "tool", "run", "authenticode_signature",
                    "--args", json.dumps({"path": str(workspace / "s.exe")}))
    assert code == 3 and out["ok"] is False and out["status"] == "UNSUPPORTED"
    assert out["error"] == "AUTHENTICODE_REQUIRES_WINDOWS" and "Windows" in out["message"] and "text" not in out
