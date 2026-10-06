"""A missing optional Python package is an environment fault, never a data fault.

unity.py, android.py, pcap.py and archive2.py import a third-party package that is
only an optional extra. When that import fails they must answer with the package's
own TOOL_MISSING shape (status, missing_dependency, required_capability, detail),
not fold the ImportError into a parse error as though the input were malformed.

The missing import is simulated by putting None into sys.modules, so the test does
not depend on whether the package happens to be installed.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.workspace as workspace
from liebert_re.tools.android import android_resource_analyzer
from liebert_re.tools.archive2 import rar_7z
from liebert_re.tools.pcap import pcap_analyzer
from liebert_re.tools.unity import unity_asset_analyzer

PARSE_ERRORS = ("NOT_UNITY_ASSET_OR_LOAD_ERROR", "ANDROID_MANIFEST_PARSE_ERROR", "PCAP_PARSE_ERROR", "ModuleNotFoundError")


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=workspace.WORKSPACE, ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _file(self, name, data):
        p = self.root / name
        p.write_bytes(data)
        return str(p)

    def _blocked(self, *modules):
        return mock.patch.dict(sys.modules, {m: None for m in modules})

    def assertMissing(self, raw, package, tool):
        r = json.loads(raw)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "TOOL_MISSING")
        self.assertEqual(r["tool"], tool)
        self.assertEqual(r["missing_dependency"], package)
        self.assertIn(package, r["required_capability"])
        self.assertIn("pip install", r["required_capability"])
        self.assertIn("not examined", r["detail"])
        for bad in PARSE_ERRORS:
            self.assertNotIn(bad, r["error"])
        return r


class UnityMissing(_Base):
    def test_missing_unitypy_is_tool_missing_not_a_load_error(self):
        f = self._file("a.assets", b"\x00" * 64)
        with self._blocked("UnityPy"):
            self.assertMissing(unity_asset_analyzer(f), "UnityPy", "unity_asset_analyzer")


class AndroidMissing(_Base):
    def test_missing_androguard_is_tool_missing_for_apk_and_axml(self):
        for name, data in (("a.apk", b"PK\x03\x04" + b"\x00" * 32), ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)):
            with self.subTest(name=name), self._blocked("androguard", "androguard.core", "androguard.core.apk", "androguard.core.axml"):
                self.assertMissing(android_resource_analyzer(self._file(name, data)), "androguard", "android_resource_analyzer")


class PcapMissing(_Base):
    def test_missing_dpkt_is_tool_missing_not_a_parse_error(self):
        f = self._file("a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        with self._blocked("dpkt", "dpkt.pcapng"):
            r = self.assertMissing(pcap_analyzer(f), "dpkt", "pcap_analyzer")
        self.assertEqual(r["format"], "PCAP")


class ArchiveMissing(_Base):
    CASES = (
        ("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32, "py7zr", ("py7zr", "py7zr.io")),
        ("a.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 32, "rarfile", ("rarfile",)),
        # compression.zstd is tried first on 3.14+, so blocking only the backport
        # would leave a working zstd path and no TOOL_MISSING to assert.
        ("a.zst", b"\x28\xb5\x2f\xfd" + b"\x00" * 32, "backports.zstd", ("compression.zstd", "backports", "backports.zstd")),
    )

    def test_each_missing_package_is_named_and_is_tool_missing(self):
        for name, data, package, blocked in self.CASES:
            with self.subTest(package=package), self._blocked(*blocked):
                self.assertMissing(rar_7z(self._file(name, data)), package, "rar_7z")

    def test_stdlib_codecs_do_not_need_any_optional_package(self):
        import gzip
        f = self._file("a.gz", gzip.compress(b"hello"))
        with self._blocked("py7zr", "rarfile", "compression.zstd", "backports", "backports.zstd"):
            r = json.loads(rar_7z(f, "summary"))
        self.assertTrue(r["ok"])
        self.assertNotIn("status", r)


if __name__ == "__main__":
    unittest.main()
