"""Every published tool is reachable from the command line, measured rather than counted by hand.

A published tool is reached in exactly one of three ways: ``cli.py`` names it by string literal (a
dedicated subcommand or a name table), its docstring declares ``CLI: python-only: <reason>``
(``python_only_declarations()``), or the generic ``tool run`` dispatches it (published minus declared).
Nothing here types a number. The AST collector is shared (``tests/cli_literals.py``); the ``tool list``
name set is compared with ``published_tools`` in ``tests/test_cli_tool_dispatch.py``, not repeated here.

This replaces ``tests/test_cli_name_coverage.py``, whose pinned ``PUBLISHED_TOTAL`` / ``NOT_NAMED_IN_CLI``
measured "name occurs in cli.py", a signal that stopped meaning anything once ``tool run`` reached every
undeclared tool.
"""
from __future__ import annotations

import ast
import json
import sys

import pytest

from liebert_re import cli
from liebert_re.report.tool_families import python_only_declarations, tool_modules
from tests.cli_literals import directly_dispatched, published_set

PUBLISHED = sorted(published_set())


@pytest.mark.parametrize("name", PUBLISHED)
def test_describe_answers_without_importing_the_tool_module(name, capsys):
    module = tool_modules()[name]
    # The module may already be loaded by an earlier test; take it out so a re-import by `describe` shows.
    stashed = sys.modules.pop(module, None)
    before = set(sys.modules)
    try:
        code = cli.main(["tool", "describe", name])
        out = json.loads(capsys.readouterr().out)
        assert code == 0 and out["ok"] is True and out["tool"] == name and out["module"] == module
        assert module not in sys.modules, f"`tool describe {name}` imported {module}"
        assert not {m for m in set(sys.modules) - before if m.startswith("liebert_re.")}
    finally:
        if stashed is not None:
            sys.modules[module] = stashed


def test_tool_list_marks_exactly_the_declared_tools_as_python_only(capsys):
    # The generic route is "published minus declared"; `tool list` is what a user sees, so it must agree:
    # a python_only reason on every declared tool and on no other, and every published tool listed.
    assert published_set(), "no published tool found; the scan itself is broken"
    assert cli.main(["tool", "list"]) == 0
    rows = {row["name"]: row["python_only"] for row in json.loads(capsys.readouterr().out)["tools"]}
    assert set(rows) == published_set()
    declared = python_only_declarations()
    assert {n for n, reason in rows.items() if reason} == set(declared)
    assert all(rows[n] is None for n in set(rows) - set(declared))


def test_every_generic_route_tool_really_runs_through_tool_run():
    # "published - declared" is only a claim of reachability if the dispatcher can actually take the tool:
    # its signature must be readable from source, synchronous, and all required parameters passable by keyword.
    modules = tool_modules()
    unrunnable = []
    for name in sorted(set(modules) - set(python_only_declarations())):
        node = cli._tool_node(modules[name], name)
        if node is None or isinstance(node, ast.AsyncFunctionDef):
            unrunnable.append(name)
            continue
        if any(p["required"] and p["kind"] not in cli._TOOL_KINDS for p in cli._tool_params(node)):
            unrunnable.append(name)
    assert not unrunnable, f"undeclared tools `tool run` cannot take (declare them python-only or fix them): {unrunnable}"


def test_direct_and_declared_routes_do_not_overlap():
    # A declared tool is, by definition, one cli.py does not dispatch (the registry test checks the same
    # on the raw literals; this checks it on the published set the docs count).
    assert not directly_dispatched() & set(python_only_declarations())


def test_published_is_a_strict_subset_of_the_raw_manifest():
    # The one assertion of the retired name-coverage test worth keeping, in measured form: FAMILIES is
    # upstream routing and names tools this package does not ship, so reachability is measured over
    # published_tools(), never over the raw manifest.
    from liebert_re.report.tool_families import FAMILIES

    raw = set().union(*(set(names) for names in FAMILIES.values()))
    assert published_set() < raw
