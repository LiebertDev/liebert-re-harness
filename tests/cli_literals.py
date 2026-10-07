"""Shared, measured view of how ``liebert_re/cli.py`` names tools: by string literal in its AST.

``cli.py`` dispatches lazily (``_load("module", "function")``, or a literal in a name table), so the
only honest measurement of "a command names this tool" is a string constant equal to the tool name.
A mention in a comment or a docstring sentence does not count, and neither does a substring.
Used by the registry test, the reachability test and the docs count gate; one definition, no copies.
"""
from __future__ import annotations

import ast
from pathlib import Path

from liebert_re.report.tool_families import FAMILIES, published_tools

CLI_SOURCE = Path(__file__).resolve().parent.parent / "liebert_re" / "cli.py"


def cli_string_literals() -> set[str]:
    tree = ast.parse(CLI_SOURCE.read_text(encoding="utf-8"))
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def published_set() -> set[str]:
    return set().union(*(published_tools(family) for family in FAMILIES))


def directly_dispatched() -> set[str]:
    """Published tools that cli.py names by string literal (a dedicated subcommand or name table)."""
    return published_set() & cli_string_literals()
