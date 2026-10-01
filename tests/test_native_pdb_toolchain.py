"""Regression test for the link.exe PATH-collision bug in native_pdb_toolchain.py.

On hosts where Git for Windows appears earlier on PATH than MSVC's linker
(the normal case unless vcvars64.bat has been sourced), a bare
`shutil.which("link")` resolves to Git's own unrelated `usr/bin/link.EXE`
(a Unix-like tool) instead of MSVC's linker. detect_native_pdb_toolchain()
must resolve `link` from the same VC toolchain directory as the detected
`cl`, never from an ambiguous PATH lookup.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from liebert_re.recover.native_pdb_toolchain import detect_native_pdb_toolchain


class NativePdbToolchainTests(unittest.TestCase):
    def test_link_is_in_same_vc_toolchain_dir_as_cl(self):
        tool = detect_native_pdb_toolchain()
        if not tool.get("ok"):
            raise unittest.SkipTest(tool.get("status") or "native MSVC toolchain not available")
        cl = Path(tool["cl"]).resolve()
        link = Path(tool["link"]).resolve()
        self.assertEqual(
            link.parent, cl.parent,
            f"link.exe ({link}) is not in the same directory as cl.exe ({cl}); "
            "likely resolved an unrelated `link` from PATH (e.g. Git for Windows' usr/bin/link.EXE)",
        )
        self.assertTrue("VC" in link.parts and "MSVC" in link.parts, link)


class VswhereQueryTests(unittest.TestCase):
    """The newest installation is a preference, not a filter.

    Measured on a real host: `vswhere -latest` selected Visual Studio 2022
    Community, which had no C++ workload, while the toolchain lived in a
    separate 2022 Build Tools installation. The detector reported the compiler
    absent when cl.exe was present -- a detection defect that had been recorded
    as an environment gap and was on its way to becoming a permanent "known
    failure". This pins the fallback rather than the host.
    """

    def test_it_falls_back_past_the_newest_installation(self):
        import liebert_re.recover.native_pdb_toolchain as toolchain
        seen = []

        def fake_query(arguments):
            seen.append(list(arguments))
            # The newest installation has no C++ toolset; a later one does.
            if "-latest" in arguments:
                return None
            return r"C:\BuildTools\VC\Tools\MSVC.44in\Hostx64d\cl.exe"

        original = toolchain._vswhere_query
        toolchain._vswhere_query = fake_query
        try:
            found = toolchain._vswhere_find(r"**\Hostx64d\cl.exe")
        finally:
            toolchain._vswhere_query = original
        self.assertTrue(found and found.endswith("cl.exe"))
        self.assertGreaterEqual(len(seen), 2,
                                "a single -latest query is what hid a real toolchain")
        self.assertIn("-latest", seen[0])
        self.assertNotIn("-latest", seen[1])

    def test_the_first_answer_wins(self):
        import liebert_re.recover.native_pdb_toolchain as toolchain
        calls = []

        def fake_query(arguments):
            calls.append(list(arguments))
            return r"C:\First\cl.exe"

        original = toolchain._vswhere_query
        toolchain._vswhere_query = fake_query
        try:
            self.assertEqual(toolchain._vswhere_find("pattern"), r"C:\First\cl.exe")
        finally:
            toolchain._vswhere_query = original
        self.assertEqual(len(calls), 1, "it must not keep querying after a hit")


if __name__ == "__main__":
    unittest.main()
