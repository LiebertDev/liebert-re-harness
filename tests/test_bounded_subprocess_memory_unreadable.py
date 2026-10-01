"""'Could not measure memory' must never be treated as 'over the limit'.

SIMULATION: psutil is patched to raise AccessDenied, the failure a
non-elevated host produces; these tests do not need an unprivileged machine.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock

import psutil

import liebert_re.bounded_subprocess as bounded_subprocess
from liebert_re.bounded_subprocess import run_bounded_process

_SLEEP = [sys.executable, "-c", "import time; time.sleep(0.5); print('done')"]
_BIG = 10 * 1024 ** 3


class UnreadableMemoryIsNotOverLimit(unittest.TestCase):
    def test_unreadable_root_is_refused_before_spawn_and_not_over_limit(self):
        with mock.patch.object(psutil.Process, "memory_info", side_effect=psutil.AccessDenied(1)), \
                mock.patch.object(bounded_subprocess.subprocess, "Popen") as popen:
            result = run_bounded_process(_SLEEP, timeout_seconds=5, max_memory_bytes=_BIG)
        popen.assert_not_called()
        self.assertTrue(result.resource_limit_unavailable)
        self.assertFalse(result.memory_exceeded)

    def test_unreadable_descendant_does_not_kill_a_healthy_tree(self):
        real = psutil.Process.memory_info
        me = psutil.Process().pid

        def flaky(self):
            if self.pid != me and self.ppid() == me:
                return real(self)  # the spawned root: readable
            if self.pid != me:
                raise psutil.AccessDenied(self.pid)  # any deeper descendant: denied
            return real(self)

        for attr in ("cache_activate", "cache_deactivate"):  # psutil bookkeeping hooks
            if hasattr(real, attr):
                setattr(flaky, attr, getattr(real, attr))
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(0.4)']); time.sleep(0.5); print('ok')"
        with mock.patch.object(psutil.Process, "memory_info", flaky):
            result = run_bounded_process([sys.executable, "-c", code], timeout_seconds=20, max_memory_bytes=_BIG)
        self.assertFalse(result.resource_limit_unavailable)
        self.assertFalse(result.memory_exceeded)
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)

    def test_real_over_limit_is_still_reported_as_memory_exceeded(self):
        code = "b=bytearray(200*1024*1024); import time; time.sleep(5)"
        result = run_bounded_process([sys.executable, "-c", code], timeout_seconds=20, max_memory_bytes=50 * 1024 ** 2)
        self.assertTrue(result.memory_exceeded)
        self.assertFalse(result.resource_limit_unavailable)


if __name__ == "__main__":
    unittest.main()
