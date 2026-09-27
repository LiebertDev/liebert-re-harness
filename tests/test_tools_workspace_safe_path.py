"""Platform-independent proof for the POSIX guard in tools_workspace.safe_path.

Regression context: tests/test_tools_archive_extract.py::TestExtractOutcomes::
test_dest_path_outside_workspace_is_path_refused passed on Windows but failed
on Linux CI. Root cause (measured, not guessed): backslash is not a path
separator on POSIX, so pathlib.Path("C:\\Windows\\evil.txt") is neither
absolute nor a traversal there -- the whole string parses as ONE ordinary,
oddly-named RELATIVE path component, which then gets silently joined
*inside* the workspace instead of being refused.

``_looks_like_windows_absolute_path`` is pure string logic with no
``os.name`` branch and no filesystem access, so its correctness can be
proven directly on this (Windows) host, without waiting on a Linux CI run,
by calling it directly and separately confirming Python's own pathlib
absolute-path semantics differ by platform for the same input (the actual
mechanism of the bug).
"""
from __future__ import annotations

import pathlib
import unittest

from tools_workspace import _looks_like_windows_absolute_path


class WindowsAbsoluteSyntaxDetectionTests(unittest.TestCase):
    def test_drive_letter_backslash_form_detected(self):
        self.assertTrue(_looks_like_windows_absolute_path("C:\\Windows\\evil.txt"))

    def test_drive_letter_forward_slash_form_detected(self):
        self.assertTrue(_looks_like_windows_absolute_path("C:/Windows/evil.txt"))

    def test_lowercase_drive_letter_detected(self):
        self.assertTrue(_looks_like_windows_absolute_path("d:\\payload.bin"))

    def test_unc_path_detected(self):
        self.assertTrue(_looks_like_windows_absolute_path("\\\\server\\share\\evil.txt"))

    def test_bare_rooted_backslash_path_detected(self):
        self.assertTrue(_looks_like_windows_absolute_path("\\Windows\\evil.txt"))

    def test_ordinary_relative_path_not_detected(self):
        self.assertFalse(_looks_like_windows_absolute_path("hello.txt"))
        self.assertFalse(_looks_like_windows_absolute_path("sub/dir/hello.txt"))

    def test_posix_absolute_path_not_matched_by_this_guard(self):
        # Real POSIX-absolute input ("/etc/passwd") is already handled by
        # the pre-existing Path.is_absolute() + resolve() + relative_to()
        # check further down in safe_path -- this guard only needs to
        # cover the syntax that check misses (Windows-style absolute
        # syntax that POSIX itself does not recognize as absolute).
        self.assertFalse(_looks_like_windows_absolute_path("/etc/passwd"))

    def test_single_letter_without_colon_not_detected(self):
        # "c" alone, or "c" followed by something other than ':', must
        # never be treated as a drive letter -- would over-refuse
        # ordinary filenames.
        self.assertFalse(_looks_like_windows_absolute_path("c"))
        self.assertFalse(_looks_like_windows_absolute_path("cd/hello.txt"))

    def test_empty_string_not_detected(self):
        self.assertFalse(_looks_like_windows_absolute_path(""))

    def test_mechanism_pathlib_itself_disagrees_by_platform(self):
        # This is the actual mechanism of the CI-only failure: the SAME
        # literal is absolute per pathlib.PureWindowsPath (native Windows
        # semantics) but NOT absolute per pathlib.PurePosixPath (native
        # Linux semantics, used by plain pathlib.Path on a Linux host).
        raw = "C:\\Windows\\evil.txt"
        self.assertTrue(pathlib.PureWindowsPath(raw).is_absolute())
        self.assertFalse(pathlib.PurePosixPath(raw).is_absolute())


if __name__ == "__main__":
    unittest.main()
