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


def test_python_only_declarations_are_the_write_capable_tools_and_the_sentinel():
    # Names, not a count: each of these writes or deletes state, or is the tool_missing sentinel. Adding to
    # this set is a decision to keep a tool off the generic `tool run` path.
    declared = tf.python_only_declarations()
    assert set(declared) == {
        "asar_inspect", "binary_patch", "claim_index", "evidence_index", "ida_annotations_apply",
        "ida_annotations_purge", "rizin_patch_apply", "tool_missing", "workspace_index",
    }
    assert all(reason.strip() for reason in declared.values())


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
