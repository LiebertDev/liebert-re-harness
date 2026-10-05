"""liebert_re.dynamic.frida_trace_client is a guest-only entry point: without
an explicit guest marker, main()/run() on the real-frida path must refuse
before any spawn/attach/resume. Frida is replaced by a recording fake
installed as sys.modules['frida']; no process is started, nothing is attached,
real frida is never called. Complements test_frida_client_stays_in_guest.py."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import liebert_re.dynamic.frida_trace_client as client
from tests.test_frida_trace_client import _FakeFridaModule


MARKER_ENV = "LIEBERT_RE_FRIDA_GUEST"
MARKER_VALUE = "isolated-guest"


def _argv(tmp: str, mode: str) -> list:
    agent = Path(tmp) / "agent.js"
    agent.write_text("// no-op\n", encoding="utf-8")
    base = ["--agent", str(agent), "--duration-seconds", "0.2"]
    return (["--spawn", r"C:\fake\target.exe"] if mode == "spawn" else ["--attach-pid", "999"]) + base


class GuestMarkerTest(unittest.TestCase):
    def _main(self, mode, env):
        fake = _FakeFridaModule()
        buf = io.StringIO()
        clean = {k: v for k, v in os.environ.items() if k != MARKER_ENV}
        clean.update(env)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, clean, clear=True), \
                mock.patch.dict(sys.modules, {"frida": fake}), \
                redirect_stdout(buf):
            code = client.main(_argv(tmp, mode))
        lines = [json.loads(x) for x in buf.getvalue().splitlines() if x.strip()]
        return code, lines, fake.device

    def _assert_untouched(self, device):
        self.assertIsNone(device.spawned_path)
        self.assertEqual(device.attach_calls, [])
        self.assertEqual(device.resumed, [])

    def test_absent_marker_refuses_before_spawn_or_attach(self):
        for mode in ("spawn", "attach"):
            code, lines, device = self._main(mode, {})
            self._assert_untouched(device)
            self.assertNotEqual(code, 0)
            self.assertEqual(lines[-1]["code"], "GUEST_MARKER_ABSENT")

    def test_unreadable_marker_refuses(self):
        fake = _FakeFridaModule()
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(client, "_read_guest_marker", side_effect=OSError("boom"), create=True), \
                mock.patch.dict(sys.modules, {"frida": fake}), redirect_stdout(buf):
            code = client.main(_argv(tmp, "spawn"))
        self._assert_untouched(fake.device)
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue().splitlines()[-1])["code"], "GUEST_MARKER_UNREADABLE")

    def test_malformed_marker_refuses(self):
        code, lines, device = self._main("spawn", {MARKER_ENV: "1"})
        self._assert_untouched(device)
        self.assertNotEqual(code, 0)
        self.assertEqual(lines[-1]["code"], "GUEST_MARKER_UNREADABLE")

    def test_injected_frida_module_is_a_test_seam_not_a_supported_bypass(self):
        # Deliberate: the marker check covers the real-frida path (frida_module
        # is None), which is the accidental host vector. Passing a module
        # explicitly is the offline test seam; it is not a supported bypass and
        # is intentionally not gated (gating it would break every offline test).
        fake = _FakeFridaModule()
        buf = io.StringIO()
        clean = {k: v for k, v in os.environ.items() if k != MARKER_ENV}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, clean, clear=True), redirect_stdout(buf):
            args = client.build_arg_parser().parse_args(_argv(tmp, "attach"))
            args.output = None
            code = client.run(args, frida_module=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.device.attach_calls, [999])

    def test_valid_marker_still_runs_inside_the_guest(self):
        env = {MARKER_ENV: MARKER_VALUE}
        code, lines, device = self._main("spawn", env)
        self.assertEqual(code, 0)
        self.assertEqual(device.spawned_path, r"C:\fake\target.exe")
        self.assertEqual(device.resumed, [4242])
        code, lines, device = self._main("attach", env)
        self.assertEqual(code, 0)
        self.assertEqual(device.attach_calls, [999])


if __name__ == "__main__":
    unittest.main()
