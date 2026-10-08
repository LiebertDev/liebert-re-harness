"""Launch-failure contract across the tool wrappers.

An executable that exists but cannot be started must never read as success.
Wrappers meet that in one of two ways, and both lists are pinned here so the
split is read from one place:

* the shared path: import ``launch_failure`` from ``liebert_re.bounded_subprocess``
  and surface ``TOOL_UNLAUNCHABLE``;
* a deliberate own-code path: ``ida`` and ``ghidra`` check ``cp.launch_failed``
  themselves and report ``IDA_LAUNCH_FAILED`` / ``JAVA_LAUNCH_FAILED`` /
  ``GHIDRA_LAUNCH_FAILED`` instead of ``TOOL_UNLAUNCHABLE``.
"""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import liebert_re
from liebert_re.tools import ghidra

PKG = Path(liebert_re.__file__).parent

SHARED = {
    "tools/binary.py", "tools/capa.py", "tools/dex.py", "tools/die.py", "tools/il2cpp.py",
    "tools/jvm.py", "tools/pe_sieve.py", "tools/rizin.py", "tools/upx.py", "tools/yara_x.py",
    "recover/emulate.py",
}
OWN_CODE = {
    "tools/ida.py": ["IDA_LAUNCH_FAILED"],
    "tools/ghidra.py": ["JAVA_LAUNCH_FAILED", "GHIDRA_LAUNCH_FAILED"],
}
# lab_gate builds its own TOOL_UNLAUNCHABLE record without the helper.
LAB_GATE = "dynamic/lab_gate.py"


def _calls_runner(tree):
    return any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "run_bounded_process"
               for n in ast.walk(tree))


def _imports_name(tree, name):
    return any(isinstance(n, ast.ImportFrom) and any(a.name == name for a in n.names)
               for n in ast.walk(tree))


def _scan():
    callers, importers = set(), set()
    for p in PKG.rglob("*.py"):
        rel = p.relative_to(PKG).as_posix()
        if rel == "bounded_subprocess.py":
            continue
        tree = ast.parse(p.read_text(encoding="utf-8-sig"))
        if _calls_runner(tree):
            callers.add(rel)
        if _imports_name(tree, "run_bounded_process"):
            importers.add(rel)
    return callers, importers


def test_fourteen_modules_call_run_bounded_process():
    callers, _ = _scan()
    assert len(callers) == 14, sorted(callers)
    assert callers == SHARED | set(OWN_CODE) | {LAB_GATE}


def test_no_module_imports_the_runner_without_calling_it():
    callers, importers = _scan()
    assert importers == callers, sorted(importers ^ callers)


def test_shared_wrappers_import_launch_failure_and_own_code_ones_do_not():
    for rel in SHARED:
        tree = ast.parse((PKG / rel).read_text(encoding="utf-8-sig"))
        assert _imports_name(tree, "launch_failure"), rel
    for rel, codes in OWN_CODE.items():
        text = (PKG / rel).read_text(encoding="utf-8-sig")
        assert not _imports_name(ast.parse(text), "launch_failure"), rel
        assert "launch_failed is True" in text, rel
        for code in codes:
            assert code in text, (rel, code)
        assert "TOOL_UNLAUNCHABLE" not in text, rel


def test_ghidra_java_probe_reports_launch_failure_not_success():
    cp = SimpleNamespace(launch_failed=True, launch_error="PermissionError", timed_out=False,
                         stdout="", stderr="")
    with mock.patch.object(ghidra, "_java_executable", return_value=("java", "PATH")), \
            mock.patch.object(ghidra, "run_bounded_process", return_value=cp):
        info = ghidra._probe_java()
    assert info["major"] is None
    assert info["error"].startswith("JAVA_LAUNCH_FAILED")
