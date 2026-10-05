"""dex_decompiler / jvm_decompiler `decompile_class`: the class returned is the class asked for.

JADX is faked (no install needed): the fake writes a chosen layout into the output directory the
wrapper hands it. Two defects are pinned: the file-name-only fallback used to return another
package's class under the requested label, and a class name that is really an absolute path used
to read a file outside the workspace.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import pytest

import liebert_re.tools.dex as dex
import liebert_re.tools.jvm as jvm
from liebert_re import workspace
from liebert_re.bounded_subprocess import BoundedProcessResult


def _fake_jadx(layout):
    """A run_bounded_process stand-in: writes {relative path: text} under the -d directory."""
    def run(args, **_kw):
        out = Path(args[args.index("-d") + 1])
        for rel, text in layout.items():
            f = out / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        return BoundedProcessResult(0, "", "")
    return run


@pytest.fixture
def sample():
    with tempfile.TemporaryDirectory(dir=workspace.WORKSPACE) as d:
        d = Path(d)
        dex_p = d / "t.dex"
        dex_p.write_bytes(b"dex\n035\x00" + b"\x00" * 104)
        jvm_p = d / "Foo.class"
        jvm_p.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 16)
        yield {"dex": dex_p, "jvm": jvm_p}


@pytest.fixture
def outside():
    """A real .java file outside the workspace; yields its path without the .java suffix."""
    d = Path(tempfile.mkdtemp(prefix="outside_"))
    try:
        (d / "Secret.java").write_text("class Secret { /* LEAKMARK-7 */ }", encoding="utf-8")
        stem = (d / "Secret").as_posix()
        assert "." not in stem, "the JVM form turns dots into separators; keep the stem dot-free"
        yield stem
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _call(kind, sample, name, layout):
    mod, fn = (dex, "dex_decompiler") if kind == "dex" else (jvm, "jvm_decompiler")
    with mock.patch.object(mod, "_jadx", return_value="jadx"), \
         mock.patch.object(mod, "run_bounded_process", _fake_jadx(layout)):
        return json.loads(getattr(mod, fn)(str(sample[kind]), "decompile_class", name))


def _wire(kind, name):
    """The same class named in each tool's own notation."""
    return f"L{name.replace('.', '/')};" if kind == "dex" else name


@pytest.mark.parametrize("kind", ["dex", "jvm"])
class TestWrongClassIsNotReturned:
    def test_same_simple_name_in_another_package_is_refused(self, kind, sample):
        out = _call(kind, sample, _wire(kind, "a.Foo"), {"sources/b/Foo.java": "package b; class Foo { /* B */ }"})
        assert out["ok"] is False
        assert out["error"] == "CLASS_PATH_MISMATCH"
        assert "content" not in out and "class" not in out
        assert out["requested_package"] == "a" and out["found_packages"] == ["b"]
        assert "B */" not in json.dumps(out)

    def test_the_mismatch_reply_does_not_leak_an_absolute_path(self, kind, sample):
        out = _call(kind, sample, _wire(kind, "a.Foo"), {"sources/b/Foo.java": "x"})
        text = json.dumps(out)
        assert tempfile.gettempdir().replace("\\", "/") not in text.replace("\\\\", "/")
        assert "jadx_out_" not in text and "jadx_jvm_out_" not in text

    def test_nothing_with_that_name_stays_class_not_found(self, kind, sample):
        out = _call(kind, sample, _wire(kind, "a.Foo"), {"sources/b/Bar.java": "x"})
        assert out["error"] == "CLASS_NOT_FOUND_IN_DECOMPILED_OUTPUT"


@pytest.mark.parametrize("kind", ["dex", "jvm"])
class TestClassNameCannotLeaveTheRoot:
    def test_absolute_name_does_not_read_a_file_outside(self, kind, sample, outside):
        out = _call(kind, sample, _wire(kind, outside), {"sources/a/Other.java": "x"})
        assert out["ok"] is False
        assert out["error"] == "CLASS_NAME_OUTSIDE_ROOT"
        assert "LEAKMARK-7" not in json.dumps(out)


def test_dex_parent_traversal_in_a_descriptor_is_refused(sample):
    out = _call("dex", sample, "L../../a/Foo;", {"sources/a/Foo.java": "x"})
    assert out["ok"] is False and out["error"] == "CLASS_NAME_OUTSIDE_ROOT"


@pytest.mark.parametrize("kind", ["dex", "jvm"])
class TestLegitimateNamesStillWork:
    @pytest.mark.parametrize("name,rel", [
        ("a.Foo", "a/Foo.java"),
        ("a.Foo$Bar", "a/Foo$Bar.java"),
        ("com.example.deep.er.pkg.Foo", "com/example/deep/er/pkg/Foo.java"),
        ("p1.p_2.Cls_9", "p1/p_2/Cls_9.java"),
    ])
    def test_exact_package_path_is_returned(self, kind, sample, name, rel):
        out = _call(kind, sample, _wire(kind, name), {f"sources/{rel}": "BODY"})
        assert out["ok"] is True and out["class"] == _wire(kind, name) and out["content"] == "BODY"

    def test_layout_without_a_sources_directory_still_resolves(self, kind, sample):
        out = _call(kind, sample, _wire(kind, "a.Foo"), {"a/Foo.java": "BODY"})
        assert out["ok"] is True and out["content"] == "BODY"
