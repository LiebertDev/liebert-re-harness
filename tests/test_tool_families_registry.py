"""Measured registry views over ``liebert_re.report.tool_families``.

``tool_modules`` and ``python_only_declarations`` are computed from source
text and the AST, never from a hand-kept list, so these tests compare the
functions with each other and with ``published_tools``, or feed them a
throwaway package built in ``tmp_path``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from liebert_re.report import tool_families as tf


def _make_package(root: Path, modules: dict[str, str]) -> Path:
    package = root / "fixturepkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    for name, source in modules.items():
        (package / f"{name}.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return package


def test_tool_modules_covers_exactly_the_published_tools():
    published: set[str] = set()
    for family in tf.FAMILIES:
        published |= tf.published_tools(family)
    modules = tf.tool_modules()
    assert set(modules) == published
    assert modules, "no published tool found; the scan itself is broken"
    assert all(module.startswith("liebert_re.") for module in modules.values())


def test_tool_modules_names_the_defining_module():
    root = Path(tf.__file__).resolve().parent.parent.parent
    for name, module in tf.tool_modules().items():
        base = root.joinpath(*module.split("."))
        source = base.with_suffix(".py")
        if not source.exists():  # a package __init__
            source = base / "__init__.py"
        assert f"def {name}(" in source.read_text(encoding="utf-8", errors="ignore")


def test_tool_modules_reports_a_name_defined_twice(tmp_path):
    package = _make_package(
        tmp_path,
        {
            "one": "def hash_file(path):\n    return 1\n",
            "two": "def hash_file(path):\n    return 2\n",
        },
    )
    with pytest.raises(ValueError) as excinfo:
        tf.tool_modules(package)
    message = str(excinfo.value)
    assert "hash_file" in message
    assert "fixturepkg.one" in message and "fixturepkg.two" in message


def test_tool_modules_ignores_unpublished_names(tmp_path):
    package = _make_package(
        tmp_path,
        {"one": "def helper_nobody_names():\n    pass\n", "two": "def helper_nobody_names():\n    pass\n"},
    )
    assert tf.tool_modules(package) == {}


def test_python_only_declarations_are_well_formed_published_and_not_dispatched_by_cli():
    import ast

    declared = tf.python_only_declarations()
    assert declared, "the generic dispatcher relies on write-capable tools being declared"
    # (a) every declaration carries a reason
    assert all(reason.strip() for reason in declared.values())
    # (b) only published tools can be declared
    published = set().union(*(tf.published_tools(family) for family in tf.FAMILIES))
    assert set(declared) <= published
    # (c) cli.py dispatches by string literal (`_load("module", "function")`, or a literal in a name table);
    # collect every string literal in it and require that no declared tool is among them.
    cli_source = (Path(__file__).resolve().parent.parent / "liebert_re" / "cli.py").read_text(encoding="utf-8")
    literals = {n.value for n in ast.walk(ast.parse(cli_source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not set(declared) & literals, f"declared python-only but dispatched by cli.py: {sorted(set(declared) & literals)}"


def test_python_only_declaration_parsing(tmp_path):
    package = _make_package(
        tmp_path,
        {
            "tools": '''
                import module_that_is_not_installed_anywhere  # must never be imported

                def hash_file(path):
                    """Hash a file.

                    CLI: python-only: needs a live Python object, not argv
                    """

                def read_file(path):
                    """Read a file.

                    CLI: python-only:
                    """

                def list_directory(path):
                    """No declaration here; mentions CLI: python-only mid-sentence."""
            ''',
        },
    )
    with pytest.raises(ValueError, match="read_file.*empty reason"):
        tf.python_only_declarations(package)

    (package / "tools.py").write_text(
        textwrap.dedent(
            '''
            import module_that_is_not_installed_anywhere  # must never be imported

            def hash_file(path):
                """Hash a file.

                CLI: python-only: needs a live Python object, not argv
                """

            def list_directory(path):
                """No declaration here; mentions CLI: python-only mid-sentence."""

            def find_files(path):
                pass
            '''
        ),
        encoding="utf-8",
    )
    assert tf.python_only_declarations(package) == {"hash_file": "needs a live Python object, not argv"}


def test_python_only_declaration_without_a_colon_is_an_empty_reason(tmp_path):
    package = _make_package(
        tmp_path, {"tools": 'def hash_file(path):\n    """Hash.\n\n    CLI: python-only\n    """\n'}
    )
    with pytest.raises(ValueError, match="empty reason"):
        tf.python_only_declarations(package)


def test_python_only_declared_twice_is_refused(tmp_path):
    package = _make_package(
        tmp_path,
        {"tools": 'def hash_file(path):\n    """Hash.\n\n    CLI: python-only: a\n    CLI: python-only: b\n    """\n'},
    )
    with pytest.raises(ValueError, match="more than once"):
        tf.python_only_declarations(package)
