"""Landmark set and text-decoder order must not depend on the author's machine.

SIMULATION: the POSIX case is produced by patching the host check and clearing
the Windows environment variables, so it runs on any OS; it does not prove
behaviour on a real POSIX host.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.workspace as tw

_WIN_ENV = ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "WINDIR", "SystemRoot")


class PosixLandmarks(unittest.TestCase):
    def _landmarks(self, posix: bool):
        env = {k: v for k, v in os.environ.items() if k not in _WIN_ENV}
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(tw, "_host_is_posix", return_value=posix):
            return tw._broad_scope_landmarks()

    def test_simulated_posix_refuses_system_directories(self):
        marks = self._landmarks(True)
        for name in ("/etc", "/usr", "/home", "/root", "/var"):
            self.assertIn(Path(name).resolve(), marks, name)
        self.assertGreater(len(marks), 5)  # not collapsed to just Path.home()

    def test_posix_landmark_refuses_only_the_directory_not_its_children(self):
        marks = self._landmarks(True)
        self.assertNotIn((Path("/home") / "someone" / "target").resolve(), marks)

    def test_windows_set_is_not_widened(self):
        self.assertNotIn(Path("/etc").resolve(), self._landmarks(False))


class TextDecoderOrder(unittest.TestCase):
    def _decode(self, data: bytes, **env):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            p.write_bytes(data)
            with mock.patch.dict(os.environ, env):
                if not env:
                    os.environ.pop(tw.TEXT_LOCAL_CODEPAGE_ENV, None)
                return tw.text_of(p)

    def test_general_cp1252_wins_by_default(self):
        self.assertEqual(self._decode(b"\xf0"), "ð")  # eth, not Turkish g-breve

    def test_local_codepage_is_opt_in(self):
        self.assertEqual(self._decode(b"\xf0", **{tw.TEXT_LOCAL_CODEPAGE_ENV: "cp1254"}), "ğ")

    def test_bogus_codepage_name_falls_through(self):
        self.assertEqual(self._decode(b"\xf0", **{tw.TEXT_LOCAL_CODEPAGE_ENV: "no-such-codec"}), "ð")


if __name__ == "__main__":
    unittest.main()
