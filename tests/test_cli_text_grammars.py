"""``tool run`` plain-text answers: ``cli_text_grammars.TEXT_GRAMMARS`` and the gate that keeps it complete.

A text answer is a success only if its tool declares a grammar and the text fits it; every other text is UNKNOWN
(exit 1). Each grammar below is exercised against the tool's real output on a fixture built in code (no binaries
are committed), plus the failure forms the tool's code actually produces.
"""
from __future__ import annotations

import ast
import importlib
import json
import sys
import types
from types import SimpleNamespace

import pytest

import liebert_re.cli_text_grammars as grammars
from liebert_re import cli
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections, build_owned_pe_with_code

# The most tools UNDECLARED_TEXT_TOOLS may hold. It only goes down: when a tool gets a grammar (or stops being
# text-capable), lower this number with it. A new text-capable tool must join TEXT_GRAMMARS or the list, which
# is a decision the developer has to make; raising this ceiling to avoid that decision defeats the gate.
UNDECLARED_CEILING = 27


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    return root


def tool_run(capsys, ws, name, **kwargs):
    return run(capsys, "--workspace", str(ws), "tool", "run", name, "--args", json.dumps(kwargs))


def real_text(ws, module, name, **kwargs):
    """Call the real tool function inside ``ws`` (for answers the CLI's own pre-checks would stop first)."""
    undo = cli._apply_workspace(ws)
    try:
        return getattr(importlib.import_module(module), name)(**kwargs)
    finally:
        undo()


def assert_success(code, out, *, empty=False, truncated=None):
    assert code == 0, json.dumps(out)[:700]
    assert out["ok"] is True and out["status"] == "OK" and out["outcome"] == "OK" and out["classified"] is True
    assert out.get("empty", False) is empty
    assert out["truncated"] is truncated


def assert_unknown(code, out):
    assert code == 1 and out["ok"] is False and out["status"] == "UNKNOWN" and out["outcome"] == "UNKNOWN"
    assert out["classified"] is False and out["error"] == "UNCLASSIFIED_OUTPUT" and "text" in out


# ---- the gate: every text-capable published tool is declared or knowingly undeclared ------------------------

def _top_level_returns(fn):
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            yield node.value
        stack.extend(c for c in ast.iter_child_nodes(node) if isinstance(c, ast.stmt))


def _is_text_expression(v):
    if isinstance(v, (ast.JoinedStr, ast.BinOp, ast.IfExp, ast.BoolOp)):
        return True
    if isinstance(v, ast.Constant) and isinstance(v.value, str):
        return True
    return isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "join"


def _text_capable_tools():
    """Published, CLI-runnable tools that are annotated ``-> str`` or that return a text expression (f-string,
    join, concatenation, conditional, string literal) from the function body. Read from the AST, never imported."""
    modules, declared = cli._tool_registry()
    found = set()
    for name, module in modules.items():
        node = cli._tool_node(module, name)
        if name in declared or node is None or isinstance(node, ast.AsyncFunctionDef):
            continue
        annotated = node.returns is not None and ast.unparse(node.returns) == "str"
        if annotated or any(_is_text_expression(v) for v in _top_level_returns(node)):
            found.add(name)
    return found


def test_every_text_capable_tool_is_declared_or_knowingly_undeclared():
    found = _text_capable_tools()
    assert {"binary_strings", "read_file", "generic_static_probe"} <= found, "the detector is broken"
    declared, undeclared = set(grammars.TEXT_GRAMMARS), set(grammars.UNDECLARED_TEXT_TOOLS)
    assert not declared & undeclared, "a tool is both declared and undeclared"
    missing = found - declared - undeclared
    assert not missing, f"text-capable tool(s) with no decision: {sorted(missing)}; add a TEXT_GRAMMARS rule or list it in UNDECLARED_TEXT_TOOLS"


def test_the_lists_name_only_published_runnable_tools_and_undeclared_only_shrinks():
    modules, python_only = cli._tool_registry()
    published = set(modules) - set(python_only)
    assert set(grammars.TEXT_GRAMMARS) <= published and set(grammars.UNDECLARED_TEXT_TOOLS) <= published
    assert len(grammars.UNDECLARED_TEXT_TOOLS) <= UNDECLARED_CEILING
    assert set(grammars.UNDECLARED_TEXT_TOOLS) <= _text_capable_tools(), "a listed tool is not text-capable any more: remove it"


def test_every_grammar_has_the_two_parts_and_failure_statuses_are_known():
    for name, grammar in grammars.TEXT_GRAMMARS.items():
        assert set(grammar) == {"success", "failures"}, name
        assert grammar["success"] is None or callable(grammar["success"]), name
        for prefix, status in grammar["failures"]:
            assert prefix and status in cli.REFUSAL_STATUSES | cli._MODULE_REFUSALS, (name, status)


def test_a_tool_without_a_grammar_is_unknown_for_any_text(capsys, ws, monkeypatch):
    (ws / "s.bin").write_bytes(b"x")
    real_load = cli._load
    monkeypatch.setattr(cli, "_load", lambda m, n: (lambda **kw: "0x10 [ascii] looks like a listing")
                        if (m, n) == ("liebert_re.tools.binary", "hash_file") else real_load(m, n))
    assert "hash_file" not in grammars.TEXT_GRAMMARS
    assert_unknown(*tool_run(capsys, ws, "hash_file", path=str(ws / "s.bin")))


def test_failure_prose_from_a_declared_tool_does_not_fit_and_is_unknown(capsys, ws, monkeypatch):
    (ws / "s.bin").write_bytes(b"x")
    real_load = cli._load
    monkeypatch.setattr(cli, "_load", lambda m, n: (lambda **kw: "Error: could not read the file.")
                        if (m, n) == ("liebert_re.tools.binary", "binary_strings") else real_load(m, n))
    assert_unknown(*tool_run(capsys, ws, "binary_strings", path=str(ws / "s.bin")))


# ---- binary_strings ------------------------------------------------------------------------------------------

def test_binary_strings_listing_empty_and_cut(capsys, ws):
    blob = ws / "s.bin"
    blob.write_bytes(b"\x00".join(b"string_number_%03d" % i for i in range(12)) + "wide text".encode("utf-16le"))
    assert_success(*tool_run(capsys, ws, "binary_strings", path=str(blob), max_results=50))
    code, out = tool_run(capsys, ws, "binary_strings", path=str(blob), max_results=5)
    assert_success(code, out, truncated=True)
    assert out["truncation"]["returned"] == 5 and out["truncation"]["limit"] == 5
    assert "[utf16]" in tool_run(capsys, ws, "binary_strings", path=str(blob), contains="wide")[1]["text"]
    code, out = tool_run(capsys, ws, "binary_strings", path=str(blob), contains="absent-needle")
    assert_success(code, out, empty=True)
    assert out["text"] == "EMPTY_RESULT: No strings found."


# ---- find_binaries, search_binary_bytes -----------------------------------------------------------------------

def test_find_binaries_and_search_binary_bytes(capsys, ws):
    for i in range(4):
        (ws / f"b{i}.exe").write_bytes(b"MZ" * 4)
    assert_success(*tool_run(capsys, ws, "find_binaries", path=str(ws), max_results=10))
    code, out = tool_run(capsys, ws, "find_binaries", path=str(ws), max_results=3)
    assert_success(code, out, truncated=True)
    empty = ws / "empty_dir"
    empty.mkdir()
    assert_success(*tool_run(capsys, ws, "find_binaries", path=str(empty)), empty=True)
    target = str(ws / "b0.exe")
    assert_success(*tool_run(capsys, ws, "search_binary_bytes", path=target, pattern="4D 5A", max_results=10))
    assert_success(*tool_run(capsys, ws, "search_binary_bytes", path=target, pattern="4D 5A", max_results=2), truncated=True)
    assert_success(*tool_run(capsys, ws, "search_binary_bytes", path=target, pattern="AA BB"), empty=True)


# ---- pe_imports, pe_exports, disassemble_pe, dotnet_metadata ---------------------------------------------------

def test_pe_imports_listing_cut_and_empty(capsys, ws):
    many = build_owned_pe_sections(ws / "many.exe", imports={"a.dll": [f"F{i}" for i in range(7)]})
    code, out = tool_run(capsys, ws, "pe_imports", path=str(many))
    assert_success(code, out)
    assert out["text"].count("@IAT") == 7
    assert_success(*tool_run(capsys, ws, "pe_imports", path=str(many), max_results=3), truncated=True)
    assert_success(*tool_run(capsys, ws, "pe_imports", path=str(many), filter_text="nothing-like-this"), empty=True)
    bare = build_owned_pe_sections(ws / "bare.exe")
    code, out = tool_run(capsys, ws, "pe_imports", path=str(bare))
    assert_success(code, out, empty=True)
    assert out["text"] == "EMPTY_RESULT: No import table."


def test_pe_imports_unreadable_directory_is_a_refusal_not_unknown(capsys, ws):
    bad = build_owned_pe_sections(ws / "bad.exe", bad_import_rva=True)
    code, out = tool_run(capsys, ws, "pe_imports", path=str(bad))
    assert code == 3 and out["status"] == "ANALYSIS_LIMITED" and out["classified"] is True and out["outcome"] == "REFUSED"


def test_a_partial_directory_marker_is_not_a_clean_success():
    listing = "a.dll!F0 @IAT 0x1000\n[IMPORT_DIRECTORY_PARTIAL: descriptor 3 truncated]"
    body = cli._decode(listing, None, "pe_imports")
    assert body["status"] == "UNKNOWN" and body["ok"] is False


def test_pe_exports_listing_cut_empty_and_partial(capsys, ws, monkeypatch):
    from liebert_re.tools import binary
    target = ws / "e.exe"
    target.write_bytes(b"MZ")
    symbols = [SimpleNamespace(name=f"E{i}".encode(), address=0x1000 + i, ordinal=i + 1) for i in range(7)]
    fake = SimpleNamespace(DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=symbols))
    monkeypatch.setattr(binary, "_pe", lambda p: fake)
    monkeypatch.setattr(binary, "_parse_directories", lambda pe: None)
    monkeypatch.setattr(binary, "_directory_problem", lambda *a: "")
    code, out = tool_run(capsys, ws, "pe_exports", path=str(target))
    assert_success(code, out)
    assert out["text"].count("RVA=") == 7
    code, out = tool_run(capsys, ws, "pe_exports", path=str(target), max_results=3)
    assert_success(code, out, truncated=True)
    assert out["truncation"] == {"truncated": True, "limit": 3, "returned": 3, "total": 7, "omitted": 4}
    monkeypatch.setattr(binary, "_directory_problem", lambda *a: "ordinal table cut short")
    assert_unknown(*tool_run(capsys, ws, "pe_exports", path=str(target)))  # [EXPORT_DIRECTORY_PARTIAL: ...] is not clean


def test_pe_exports_empty_table(capsys, ws):
    bare = build_owned_pe_sections(ws / "bare.exe")
    assert_success(*tool_run(capsys, ws, "pe_exports", path=str(bare)), empty=True)


def test_disassemble_pe_listing_cut_and_structured_failure(capsys, ws):
    exe = build_owned_pe_with_code(ws / "c.exe", b"\x90" * 5 + b"\xc3")
    code, out = tool_run(capsys, ws, "disassemble_pe", path=str(exe), max_instructions=1000)
    assert_success(code, out)  # the section's zero padding decodes too, so the listing is longer than the code
    assert out["text"].splitlines()[0].endswith(": nop") and any(ln.endswith(": ret") for ln in out["text"].splitlines())
    assert_success(*tool_run(capsys, ws, "disassemble_pe", path=str(exe)), truncated=True)  # default cap 250
    code, out = tool_run(capsys, ws, "disassemble_pe", path=str(exe), max_instructions=3)
    assert_success(code, out, truncated=True)
    assert out["truncation"]["limit"] == 3 and out["truncation"]["returned"] == 3
    junk = ws / "junk.bin"
    junk.write_bytes(b"not a pe at all")
    code, out = tool_run(capsys, ws, "disassemble_pe", path=str(junk))  # a structured dict, not text
    assert code == 3 and out["status"] == "ANALYSIS_LIMITED" and out["error"] == "INVALID_PE" and out["outcome"] == "REFUSED"


def test_dotnet_metadata_listing_empty_and_unreadable(capsys, ws, monkeypatch):
    from liebert_re.tools import binary
    exe = build_owned_pe_sections(ws / "plain.exe")
    code, out = tool_run(capsys, ws, "dotnet_metadata", path=str(exe))
    assert_success(code, out, empty=True)
    assert out["text"] == "EMPTY_RESULT: No CLR/.NET header present."
    monkeypatch.setattr(binary, "_pe", lambda p: SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=1)] * 15)))
    rows = [SimpleNamespace(TypeNamespace="Ns", TypeName=f"T{i}") for i in range(5)] + [SimpleNamespace(TypeNamespace="", TypeName="<Module>")]
    fake = types.ModuleType("dnfile")
    fake.dnPE = lambda p: SimpleNamespace(net=SimpleNamespace(mdtables=SimpleNamespace(TypeDef=SimpleNamespace(rows=rows))))
    monkeypatch.setitem(sys.modules, "dnfile", fake)
    code, out = tool_run(capsys, ws, "dotnet_metadata", path=str(exe))
    assert_success(code, out)
    assert out["text"].splitlines() == ["Ns.T0", "Ns.T1", "Ns.T2", "Ns.T3", "Ns.T4", "<Module>"]
    assert_success(*tool_run(capsys, ws, "dotnet_metadata", path=str(exe), max_types=2), truncated=True)
    fake.dnPE = lambda p: SimpleNamespace(net=SimpleNamespace(mdtables=None))
    code, out = tool_run(capsys, ws, "dotnet_metadata", path=str(exe))
    assert code == 3 and out["status"] == "ANALYSIS_LIMITED" and out["outcome"] == "REFUSED"
    rows[:] = [SimpleNamespace(TypeNamespace="", TypeName="has a space")]
    fake.dnPE = lambda p: SimpleNamespace(net=SimpleNamespace(mdtables=SimpleNamespace(TypeDef=SimpleNamespace(rows=rows))))
    assert_unknown(*tool_run(capsys, ws, "dotnet_metadata", path=str(exe)))  # a name with whitespace: conservative


# ---- workspace tools ---------------------------------------------------------------------------------------------

def test_list_directory_listing_empty_cut_and_missing(capsys, ws):
    (ws / "sub").mkdir()
    (ws / "a.txt").write_text("a", encoding="utf-8")
    code, out = tool_run(capsys, ws, "list_directory", path=str(ws))
    assert_success(code, out)
    assert "DIR: " in out["text"] and "FILE: " in out["text"]
    empty = ws / "nothing"
    empty.mkdir()
    code, out = tool_run(capsys, ws, "list_directory", path=str(empty))
    assert_success(code, out, empty=True)
    assert out["text"] == "Directory is empty."
    deep = ws / "deep"
    deep.mkdir()
    for i in range(520):
        (deep / f"f{i}.txt").write_text("x", encoding="utf-8")
    code, out = tool_run(capsys, ws, "list_directory", path=str(deep), recursive=True)
    assert_success(code, out, truncated=True)
    assert out["truncation"]["limit"] == 500 and out["truncation"]["returned"] == 500
    code, out = tool_run(capsys, ws, "list_directory", path=str(ws / "a.txt"))  # a file is not a directory
    assert code == 3 and out["status"] == "NOT_FOUND" and out["classified"] is True and out["outcome"] == "REFUSED"


def test_find_files_listing_empty_cut_and_missing(capsys, ws, monkeypatch):
    from liebert_re import workspace as wsmod
    for i in range(6):
        (ws / f"f{i}.txt").write_text("x", encoding="utf-8")
    code, out = tool_run(capsys, ws, "find_files", pattern="*.txt", path=str(ws))
    assert_success(code, out)
    assert len(out["text"].splitlines()) == 6
    assert out["text"].splitlines()[0].endswith(".txt")
    code, out = tool_run(capsys, ws, "find_files", pattern="*.nothing", path=str(ws))
    assert_success(code, out, empty=True)
    assert out["text"] == "File not found."
    monkeypatch.setattr(wsmod, "MAX_FIND_RESULTS", 4)
    assert_success(*tool_run(capsys, ws, "find_files", pattern="*.txt", path=str(ws)), truncated=True)
    code, out = tool_run(capsys, ws, "find_files", pattern="*", path=str(ws / "f0.txt"))
    assert code == 3 and out["status"] == "NOT_FOUND" and out["classified"] is True


def test_search_text_listing_empty_cut_and_missing(capsys, ws, monkeypatch):
    from liebert_re import workspace as wsmod
    (ws / "a.txt").write_text("alpha needle\nbeta\nneedle again\n", encoding="utf-8")
    code, out = tool_run(capsys, ws, "search_text", query="needle", path=str(ws))
    assert_success(code, out)
    assert out["text"].count(":") >= 4 and len(out["text"].splitlines()) == 2
    code, out = tool_run(capsys, ws, "search_text", query="absent-needle", path=str(ws))
    assert_success(code, out, empty=True)
    assert out["text"] == "No results found."
    monkeypatch.setattr(wsmod, "MAX_SEARCH_RESULTS", 1)
    code, out = tool_run(capsys, ws, "search_text", query="needle", path=str(ws))
    assert_success(code, out, truncated=True)
    assert out["truncation"]["limit"] == 1 and out["truncation"]["returned"] == 1
    code, out = tool_run(capsys, ws, "search_text", query="x", path=str(ws / "a.txt"))
    assert code == 3 and out["status"] == "NOT_FOUND"


def test_get_file_info_json_success_and_the_not_found_text(capsys, ws):
    (ws / "a.txt").write_text("a", encoding="utf-8")
    code, out = tool_run(capsys, ws, "get_file_info", path=str(ws / "a.txt"))
    assert code == 0 and out["outcome"] == "OK" and out["type"] == "file" and "text" not in out
    raw = real_text(ws, "liebert_re.workspace", "get_file_info", path="nothing-here.txt")
    body = cli._decode(raw, None, "get_file_info")
    assert body["status"] == "NOT_FOUND" and body["ok"] is False and body["classified"] is True
    assert cli._exit_code(body) == cli.EXIT_REFUSED
    other = cli._decode("some other text", None, "get_file_info")
    assert other["status"] == "UNKNOWN"


def test_read_file_listing_failures_and_the_unclassifiable_range_answer(capsys, ws):
    lines = [f"line {i}" for i in range(1, 8)]
    (ws / "t.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    code, out = tool_run(capsys, ws, "read_file", path=str(ws / "t.txt"))
    assert_success(code, out)
    assert out["text"].splitlines()[0].endswith("| lines 1-7/7]") and out["text"].splitlines()[-1] == "7: line 7"
    code, out = tool_run(capsys, ws, "read_file", path=str(ws / "t.txt"), start_line=3, end_line=4)
    assert_success(code, out, truncated=True)  # lines 5-7 were not returned: the tool says "more follows"
    assert out["text"].splitlines()[1:3] == ["3: line 3", "4: line 4"]
    assert out["truncation"] == {"truncated": True, "limit": None, "returned": 2, "total": 7, "omitted": 3}
    (ws / "empty.txt").write_text("", encoding="utf-8")
    assert_success(*tool_run(capsys, ws, "read_file", path=str(ws / "empty.txt")))
    from liebert_re import workspace as wsmod
    (ws / "long.txt").write_text("\n".join(str(i) for i in range(wsmod.MAX_READ_LINES + 10)), encoding="utf-8")
    code, out = tool_run(capsys, ws, "read_file", path=str(ws / "long.txt"))
    assert_success(code, out, truncated=True)
    assert out["truncation"]["returned"] == wsmod.MAX_READ_LINES
    # start line past the end: "7 line(s) total." fits no success rule and no failure rule: UNKNOWN, never OK
    assert_unknown(*tool_run(capsys, ws, "read_file", path=str(ws / "t.txt"), start_line=50))
    (ws / "bin.dat").write_bytes(b"\x00\x01\x02binary")
    code, out = tool_run(capsys, ws, "read_file", path=str(ws / "bin.dat"))
    assert code == 3 and out["status"] == "UNSUPPORTED" and out["classified"] is True
    big = ws / "big.txt"
    big.write_text("x" * 10, encoding="utf-8")
    from unittest import mock
    with mock.patch.object(wsmod, "MAX_FILE_BYTES", 5):
        code, out = tool_run(capsys, ws, "read_file", path=str(big))
    assert code == 3 and out["status"] == "ANALYSIS_LIMITED" and out["text"].startswith("File too large (")
    raw = real_text(ws, "liebert_re.workspace", "read_file", path="gone.txt")
    body = cli._decode(raw, None, "read_file")
    assert body["status"] == "NOT_FOUND" and cli._exit_code(body) == cli.EXIT_REFUSED


def test_read_file_row_count_must_match_the_header():
    good = "[a.txt | lines 1-2/2]\n1: x\n2: y"
    assert cli._decode(good, None, "read_file")["status"] == "OK"
    assert cli._decode("[a.txt | lines 1-3/3]\n1: x\n2: y", None, "read_file")["status"] == "UNKNOWN"
    assert cli._decode("[a.txt | lines 1-1/1]\nx", None, "read_file")["status"] == "UNKNOWN"
    assert cli._decode("File not found", None, "read_file")["status"] == "UNKNOWN"  # near-miss spelling is not a code


def test_read_files_all_ok_cut_and_mixed(capsys, ws):
    paths = []
    for i in range(12):
        p = ws / f"r{i}.txt"
        p.write_text(f"content {i}\n", encoding="utf-8")
        paths.append(str(p))
    code, out = tool_run(capsys, ws, "read_files", paths=paths[:3])
    assert_success(code, out)
    assert out["text"].count("| lines 1-1/1]") == 3
    code, out = tool_run(capsys, ws, "read_files", paths=paths)
    assert_success(code, out, truncated=True)
    assert out["truncation"] == {"truncated": True, "limit": 10, "returned": 10, "total": 12, "omitted": 2}
    # one unreadable path among good ones: not reported as a clean success
    assert_unknown(*tool_run(capsys, ws, "read_files", paths=[paths[0], str(ws / "missing.txt")]))


def test_non_recursive_list_directory_says_when_it_stopped_at_the_cap(capsys, ws):
    # 500 entries is the cap. Exactly 500 is complete; a 501st entry must show up as a visible cut, never as a
    # complete-looking list of 500.
    full = ws / "full"
    full.mkdir()
    for i in range(500):
        (full / f"f{i:03}.txt").write_text("x", encoding="utf-8")
    assert_success(*tool_run(capsys, ws, "list_directory", path=str(full)))
    over = ws / "over"
    over.mkdir()
    for i in range(501):
        (over / f"f{i:03}.txt").write_text("x", encoding="utf-8")
    code, out = tool_run(capsys, ws, "list_directory", path=str(over))
    assert_success(code, out, truncated=True)
    assert out["truncation"]["limit"] == 500 and out["truncation"]["returned"] == 500
    assert len([ln for ln in out["text"].splitlines() if ln.startswith("FILE: ")]) == 500
