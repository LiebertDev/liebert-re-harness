r"""A crash dump's module paths are Windows paths whatever host analyses them.

On Linux, pathlib splits only on "/", so r"C:\one\foo.dll" was one long
"basename" that matched nothing: an ambiguous module resolved silently and an
out-of-range RVA was never bounded. These tests drive the parsing helpers with
the host's path flavour forced to POSIX, so they fail on any OS if the code
inherits host semantics.
"""
from __future__ import annotations

import os
import unittest
from pathlib import PurePosixPath
from unittest import mock

import liebert_re.recover.codeview_rsds as codeview_rsds
from liebert_re.recover.codeview_rsds import module_basename_match


class _PosixOnly:
    """Make Path behave as on Linux, to reproduce the CI host on any machine."""

    def __enter__(self):
        self._patches = [
            mock.patch.object(codeview_rsds, "Path", PurePosixPath),
            mock.patch.object(os, "sep", "/"),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()


class BasenameMatch(unittest.TestCase):
    def test_splits_on_both_separators_and_folds_case(self):
        for left, right in ((r"C:\one\FOO.DLL", "foo.dll"), ("/usr/lib/Foo.dll", "foo.dll"),
                            (r"C:/mixed\Foo.dll", "FOO.DLL")):
            self.assertTrue(module_basename_match(left, right), (left, right))
        self.assertFalse(module_basename_match(None, "foo.dll"))
        self.assertFalse(module_basename_match("", ""))

    def test_independent_of_host_path_flavour(self):
        with _PosixOnly():
            self.assertTrue(module_basename_match(r"C:\one\foo.dll", "FOO.dll"))
            self.assertTrue(module_basename_match(r"C:\one\foo.dll", r"D:\x\Foo.DLL"))
            self.assertFalse(module_basename_match(r"C:\one\foo.dll", "bar.dll"))

    def test_pdb_basename_compares_across_separators(self):
        rsds = {"ok": True, "guid": "g", "age": 1, "identity_key": "k"}
        with _PosixOnly():
            res = codeview_rsds.correlate_rsds(
                dict(rsds, pdb_path=r"C:\build\Foo.pdb"), dict(rsds, pdb_path="/x/foo.pdb"))
        self.assertIn("pdb_basename", res["match_basis"])


class SymbolizeUnderPosixSemantics(unittest.TestCase):
    DUMP = {"ok": True, "modules": {"items": [
        {"name": r"C:\one\foo.dll", "image_size": 0x800, "codeview": None},
        {"name": r"C:\two\foo.dll", "image_size": 0x800, "codeview": None}]}}

    def _run(self, module, rva):
        from liebert_re.recover import crash_symbolize
        with _PosixOnly(), mock.patch.object(crash_symbolize, "parse_minidump", return_value=self.DUMP):
            return crash_symbolize.symbolize_rva(module=module, rva=rva, minidump_path="x.mdmp")

    def test_ambiguous_bare_name_is_refused(self):
        self.assertEqual(self._run("foo.dll", 0x10)["status"], "AMBIGUOUS_MODULE")

    def test_full_path_resolves_and_range_is_enforced(self):
        self.assertEqual(self._run(r"C:\two\FOO.DLL", 0x900)["status"], "RVA_OUT_OF_MODULE_RANGE")


if __name__ == "__main__":
    unittest.main()
