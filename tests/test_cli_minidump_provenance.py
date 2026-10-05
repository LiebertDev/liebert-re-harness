"""CLI ``minidump``: say where the symbol files actually came from.

The command used to hand the raw ``--pe``/``--pdb`` strings to the analyzer and report nothing about
them. Now every path (the dump, the PE, the PDB) is resolved (``..`` and links followed) and the
response says where it landed: INSIDE_WORKSPACE, OUTSIDE_WORKSPACE or UNRESOLVABLE. None of the
three refuses: a dump in one directory and its PE in another is the normal case, so
OUTSIDE_WORKSPACE is information, not an error. The narrowness test below pins that.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import liebert_re.workspace as tools_workspace
from liebert_re import cli
from liebert_re.recover.msf_pdb import write_synthetic_pdb


def _load_fixtures():
    spec = importlib.util.spec_from_file_location(
        "_minidump_fixtures", Path(__file__).with_name("test_minidump_analyzer.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fx = _load_fixtures()


def run(*argv):
    out = StringIO()
    with redirect_stdout(out):
        code = cli.main(list(argv))
    return code, json.loads(out.getvalue())


class MinidumpProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.inside_tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.outside_tmp = tempfile.TemporaryDirectory()
        self.inside = Path(self.inside_tmp.name)
        self.outside = Path(self.outside_tmp.name)
        rsds = fx.build_rsds(guid=fx.GUID_LE, age=fx.AGE, pdb=b"owned.pdb\0")
        self.dump = fx.build_full_minidump(self.inside / "owned.mdmp", rsds=rsds)
        self.pe_in = self.inside / "owned.sys"
        fx.build_pe_with_rsds(self.pe_in, rsds)
        self.pe_out = self.outside / "owned.sys"
        fx.build_pe_with_rsds(self.pe_out, rsds)
        self.pdb_out = self.outside / "owned.pdb"
        write_synthetic_pdb(
            self.pdb_out, guid_le=fx.GUID_LE, age=fx.AGE, include_dbi=True, include_symbols=True,
            symbols=[("OwnedEntry", 0x0, 1), ("OwnedHelper", 0x200, 1)],
        )

    def tearDown(self):
        self.inside_tmp.cleanup()
        self.outside_tmp.cleanup()

    def test_pe_outside_the_workspace_is_reported_and_analysis_still_runs(self):
        code, body = run("minidump", str(self.dump), "--pe", str(self.pe_out), "--pdb", str(self.pdb_out))
        self.assertEqual(code, 0, body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["crash_symbol"]["status"], "MATCH")
        self.assertEqual(body["crash_symbol"]["symbol"], "OwnedEntry")
        res = body["path_resolution"]
        self.assertEqual(res["path"]["scope"], "INSIDE_WORKSPACE")
        self.assertEqual(res["pe"]["scope"], "OUTSIDE_WORKSPACE")
        self.assertEqual(res["pdb"]["scope"], "OUTSIDE_WORKSPACE")

    def test_inside_pe_is_reported_inside(self):
        code, body = run("minidump", str(self.dump), "--pe", str(self.pe_in))
        self.assertEqual(code, 0, body)
        self.assertEqual(body["path_resolution"]["pe"]["scope"], "INSIDE_WORKSPACE")
        self.assertNotIn("pdb", body["path_resolution"])

    def test_dotdot_is_resolved_in_every_reported_path(self):
        (self.inside / "sub").mkdir()
        (self.outside / "sub").mkdir()
        dump = f"{self.inside}{os.sep}sub{os.sep}..{os.sep}owned.mdmp"
        pe = f"{self.outside}{os.sep}sub{os.sep}..{os.sep}owned.sys"
        code, body = run("minidump", dump, "--pe", pe)
        self.assertEqual(code, 0, body)
        res = body["path_resolution"]
        for key in ("path", "pe"):
            self.assertNotIn("..", res[key]["resolved"], key)
        self.assertTrue(res["path"]["resolved"].endswith("owned.mdmp"))
        self.assertTrue(res["pe"]["resolved"].endswith("owned.sys"))
        self.assertEqual(res["pe"]["scope"], "OUTSIDE_WORKSPACE")

    def test_symlink_is_followed(self):
        link = self.inside / "link.sys"
        try:
            os.symlink(self.pe_out, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks not permitted here: {exc}")
        code, body = run("minidump", str(self.dump), "--pe", str(link))
        self.assertEqual(code, 0, body)
        pe = body["path_resolution"]["pe"]
        self.assertEqual(pe["scope"], "OUTSIDE_WORKSPACE")
        self.assertNotIn("link.sys", pe["resolved"])

    def test_unresolvable_does_not_stop_the_analysis(self):
        real = Path.resolve

        def picky(self_, *a, **k):
            if self_.name == "broken.sys":
                raise OSError("cannot resolve")
            return real(self_, *a, **k)

        with mock.patch.object(Path, "resolve", autospec=True, side_effect=picky):
            code, body = run("minidump", str(self.dump), "--pe", str(self.inside / "broken.sys"))
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["path_resolution"]["pe"]["scope"], "UNRESOLVABLE")
        self.assertIsNone(body["path_resolution"]["pe"]["resolved"])

    def test_reported_paths_do_not_expose_the_machine(self):
        _, body = run("minidump", str(self.dump), "--pe", str(self.pe_out))
        text = json.dumps(body["path_resolution"])
        self.assertNotIn(os.path.expanduser("~"), text)
        self.assertIsNone(re.search(r"[A-Za-z]:[\/]", text.replace("\\\\", "/")), text)


if __name__ == "__main__":
    unittest.main()
