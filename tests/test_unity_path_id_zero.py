"""path_id 0 is a legal Unity object id; only an omitted path_id means 'not specified'."""
from __future__ import annotations

import json
import sys
import types
import unittest
from unittest import mock


class _Obj:
    def __init__(self, path_id):
        self.path_id = path_id
        self.class_id = 1
        self.type = types.SimpleNamespace(name="GameObject")
        self.assets_file = types.SimpleNamespace(name="level0")

    def read(self):
        return types.SimpleNamespace(m_Name="zero")


class PathIdZero(unittest.TestCase):
    def _call(self, **kw):
        fake = types.ModuleType("UnityPy")
        fake.load = lambda _p: types.SimpleNamespace(objects=[_Obj(0), _Obj(6)])
        with mock.patch.dict(sys.modules, {"UnityPy": fake}):
            from tools_unity import unity_asset_analyzer
            return json.loads(unity_asset_analyzer("nothing.assets", "read", **kw))

    def test_omitted_path_id_is_required(self):
        self.assertEqual(self._call()["error"], "PATH_ID_REQUIRED")

    def test_path_id_zero_reads_object_zero(self):
        r = self._call(path_id=0)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["path_id"], 0)

    def test_zero_as_string_behaves_like_zero_int(self):
        self.assertEqual(self._call(path_id="0")["path_id"], 0)


if __name__ == "__main__":
    unittest.main()
