"""Regression: run_bounded_process must never hang past a bounded ceiling
when the DIRECT child exits before a real grandchild it spawned does.

Measured live (py-spy stack dump, this session): analyzeHeadless.bat's
java.exe grandchild can still be running -- holding the inherited
stdout/stderr pipe *write* handles open -- after the .bat wrapper itself
has already exited. `terminate_process_tree` used to short-circuit ALL
cleanup once `process.poll()` showed the direct child already gone, and a
later `stream.close()` on a pipe whose background reader thread is still
blocked inside a blocking read deadlocks forever (the reader thread holds
the stream's internal buffer lock for the whole blocking read). This test
is intentionally fast (a 2s inner timeout, generous outer ceiling) so it
stays in the default/non-heavy suite -- unlike the module-marked-heavy
tests, this is exactly the fast-suite regression that must
catch a reintroduced silent-hang defect.
"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

from bounded_subprocess import run_bounded_process


def _process_exists(pid: int) -> bool:
    # os.kill(pid, 0) is not a safe liveness probe on Windows (it
    # unconditionally calls TerminateProcess) -- see the identical note in
    # tests/test_bounded_subprocess.py. psutil.pid_exists is used here for
    # the same reason.
    import psutil

    return psutil.pid_exists(pid)


def _wait_gone(pid: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return True
        time.sleep(0.05)
    return not _process_exists(pid)


class OrphanedGrandchildTimeoutTests(unittest.TestCase):
    def _orphaning_wrapper_command(self, pid_path: Path) -> list[str]:
        """A direct child that spawns a real grandchild inheriting its OWN
        stdout/stderr pipe handles (``close_fds=False``), then exits almost
        immediately -- orphaning the grandchild while it still holds the
        pipe's write end open. Same shape as a ``.bat`` wrapper that
        returns before the real ``java.exe`` it launched has exited.

        Uses ``sys._base_executable`` (never plain ``sys.executable``) to
        spawn both the direct child and the grandchild: on this repo's own
        venv, ``sys.executable`` is itself a relay-launcher stub that
        re-spawns the REAL interpreter as a further hidden hop, which
        (measured live while building this regression) silently shifts
        which pid actually ends up holding the pipe open, one layer deeper
        than expected. ``_base_executable`` is CPython's own documented
        way to name the real interpreter binary underneath any such
        relay/venv-launcher indirection, so the test's synthetic tree has
        exactly the two hops (direct child, orphaned grandchild) it
        claims to have.
        """
        real_python = getattr(sys, "_base_executable", None) or sys.executable
        parent = (
            "import pathlib,subprocess,sys;"
            f"g=subprocess.Popen([{real_python!r},'-c','import time;time.sleep(30)'],close_fds=False);"
            "pathlib.Path(sys.argv[1]).write_text(str(g.pid));"
            "sys.exit(0)"
        )
        return [real_python, "-c", parent, str(pid_path)]

    def test_timeout_returns_bounded_even_when_direct_child_exits_before_its_orphaned_grandchild(self):
        with tempfile.TemporaryDirectory() as temp:
            pid_path = Path(temp) / "grandchild.pid"
            t0 = time.monotonic()
            result = run_bounded_process(
                self._orphaning_wrapper_command(pid_path), timeout_seconds=2.0, poll_seconds=0.05,
            )
            elapsed = time.monotonic() - t0
            # (a) the function returns near the requested bound, never
            # anywhere near the orphaned grandchild's full 30s lifetime.
            self.assertTrue(result.timed_out)
            self.assertLess(
                elapsed, 12.0,
                "must not hang anywhere near the orphaned grandchild's full 30s lifetime",
            )
            # (c) the timeout is reported explicitly, never a silent empty
            # success -- this was the GhidraSession-class defect this
            # session's own investigation flagged as unacceptable.
            self.assertFalse(result.cancelled)
            self.assertEqual(result.stdout, "")
            self.assertTrue(pid_path.exists())
            grandchild_pid = int(pid_path.read_text())
            # (b) the orphan actually holding the pipe open must be found
            # and killed, not merely bounded-around/leaked.
            self.assertTrue(
                _wait_gone(grandchild_pid),
                "the orphaned grandchild holding the pipe open must actually be killed, not just leaked",
            )


if __name__ == "__main__":
    unittest.main()
