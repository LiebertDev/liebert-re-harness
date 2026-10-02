"""The `Uc.mem_map` faulthandler silence in test_vex_layer.py must never outlive that module.

A leaked patch, or a faulthandler left off, would hide real native crashes in every later
test, which is the failure the pre-push gate exists to catch. The `zz` name sorts this file
after test_vex_layer.py, so in a full run these assertions execute after that module's teardown.
"""
from __future__ import annotations

import faulthandler
import importlib.util
from pathlib import Path

import pytest

unicorn = pytest.importorskip("unicorn")

_spec = importlib.util.spec_from_file_location(
    "_vex_layer_for_leak_check", Path(__file__).resolve().parent / "test_vex_layer.py")
vex_tests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vex_tests)


def _faulthandler_expected(request) -> bool:
    return request.config.pluginmanager.has_plugin("faulthandler")


def _is_original():
    fn = unicorn.Uc.mem_map
    return not hasattr(fn, "__wrapped__") and fn.__qualname__ == "Uc.mem_map"


def test_mem_map_is_the_original_and_faulthandler_is_on_after_the_module(request):
    assert _is_original()
    if _faulthandler_expected(request):
        assert faulthandler.is_enabled()


def test_the_silence_is_undone_when_the_body_raises(request):
    with pytest.raises(RuntimeError, match="boom"):
        with vex_tests.mem_map_silenced():
            assert not _is_original()
            raise RuntimeError("boom")
    assert _is_original()
    if _faulthandler_expected(request):
        assert faulthandler.is_enabled()


def test_faulthandler_is_back_on_after_a_mem_map_call_and_after_one_that_fails(request):
    if not _faulthandler_expected(request):
        pytest.skip("pytest faulthandler plugin is not active")
    with vex_tests.mem_map_silenced():
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        uc.mem_map(0x1000, 0x1000)
        assert faulthandler.is_enabled()
        with pytest.raises(unicorn.UcError):
            uc.mem_map(0x1000, 0x1000)          # overlapping map: the engine rejects it
        assert faulthandler.is_enabled()
