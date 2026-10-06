"""zstd in liebert_re.tools.archive2: standard library first, backport second,
TOOL_MISSING only when neither imports. Fixtures are built in code."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.workspace as workspace
from liebert_re.tools import archive2
from liebert_re.tools.archive2 import rar_7z

STDLIB = sys.version_info >= (3, 14)


def _zstd_module():
    try:
        from compression import zstd
        return zstd
    except ImportError:
        try:
            from backports import zstd
            return zstd
        except ImportError:
            return None


class ZstdBackends(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=workspace.WORKSPACE, ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _file(self, name, data):
        p = self.root / name
        p.write_bytes(data)
        return str(p)

    @unittest.skipUnless(STDLIB, "compression.zstd needs Python 3.14+")
    def test_stdlib_is_used_without_the_backport(self):
        import compression.zstd as z
        payload = b"liebert zstd stdlib " * 50
        f = self._file("a.zst", z.compress(payload))
        with mock.patch.dict(sys.modules, {"backports": None, "backports.zstd": None}):
            r = json.loads(rar_7z(f, "summary"))
        self.assertTrue(r["ok"], r)
        self.assertNotIn("status", r)
        self.assertEqual(r["format"], "ZSTD")
        self.assertIs(archive2._zstd_module(), z)

    def test_real_zstd_fixture_is_decompressed_on_this_interpreter(self):
        z = _zstd_module()
        if z is None:
            self.skipTest("no zstd backend on this interpreter")
        payload = b"hello zstd\n" * 100
        f = self._file("b.zst", z.compress(payload))
        r = json.loads(rar_7z(f, "read", max_chars=5000))
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["format"], "ZSTD")
        self.assertEqual(r["byte_size"], len(payload))
        self.assertTrue(r["content"].startswith("hello zstd"))

    def test_neither_backend_is_tool_missing_naming_the_backport(self):
        f = self._file("c.zst", b"\x28\xb5\x2f\xfd" + b"\x00" * 32)
        with mock.patch.dict(sys.modules, {"compression.zstd": None, "backports": None, "backports.zstd": None}):
            r = json.loads(rar_7z(f))
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], "TOOL_MISSING")
        self.assertEqual(r["missing_dependency"], "backports.zstd")
        self.assertIn('.[zstd]', r["required_capability"])
        self.assertIn("not examined", r["detail"])
        self.assertNotIn("no installable zstd backend", r["detail"])


if __name__ == "__main__":
    unittest.main()
