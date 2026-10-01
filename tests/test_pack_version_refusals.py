"""Godot .pck / Unreal .pak: pack versions outside the closed allowlist are refused by a
named error, never parsed with a guessed layout."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.tools.godot import godot_asset_analyzer
from liebert_re.tools.unreal import unreal_asset_analyzer


class PackVersionRefusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_godot_versions_outside_2_3_4_are_named_refusals(self):
        for version in (0, 1, 5):
            with self.subTest(version=version):
                f = self.dir / f"v{version}.pck"
                f.write_bytes(b"GDPC" + struct.pack("<IIIII", version, 3, 5, 0, 0) + b"\0" * 200)
                r = json.loads(godot_asset_analyzer(str(f)))
                self.assertFalse(r["ok"])
                self.assertEqual(r["error"], f"UNSUPPORTED_PCK_VERSION_{version}")

    def test_unreal_versions_outside_allowlist_are_named_refusals(self):
        for version in (0, 5, 6, 8):
            with self.subTest(version=version):
                f = self.dir / f"v{version}.pak"
                f.write_bytes(b"\0" * 64 + struct.pack("<IIQQ20s", 0x5A6F12E1, version, 0, 0, b"\0" * 20))
                r = json.loads(unreal_asset_analyzer(str(f)))
                self.assertFalse(r["ok"])
                self.assertEqual(r["error"], f"UNSUPPORTED_PAK_VERSION_{version}")


if __name__ == "__main__":
    unittest.main()
