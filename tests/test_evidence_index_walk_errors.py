"""EvidenceIndex.refresh(): a directory that cannot be read is not a directory
that is empty. A coverage error (walk error, or a candidate whose stat fails)
makes the scan incomplete, so NO deletions happen on that run; accessible
records are still updated. A later complete, error-free scan must still be able
to remove genuinely deleted records (the guard is narrow, not a permanent
freeze). Filesystem permissions are never touched; failures are simulated."""

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from liebert_re.evidence.index import EvidenceIndex

REAL_WALK = os.walk
REAL_STAT = pathlib.Path.stat


def _walk_failing(bad_name):
    def walk(top, onerror=None, **kw):
        for dirpath, dirnames, filenames in REAL_WALK(top, **kw):
            if bad_name in dirnames:
                dirnames.remove(bad_name)
                if onerror is not None:
                    onerror(PermissionError(13, "simulated denied", os.path.join(dirpath, bad_name)))
            yield dirpath, dirnames, filenames
    return walk


class WalkErrorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = pathlib.Path(self._tmp.name)
        self.root = tmp / "ev"
        (self.root / "sub").mkdir(parents=True)
        (self.root / "top.json").write_text("{}", encoding="utf-8")
        (self.root / "sub" / "deep.json").write_text("{}", encoding="utf-8")
        self.index = EvidenceIndex(self.root, db_path=tmp / "idx.sqlite")

    def _paths(self):
        with self.index._session() as db:
            return {r["path"] for r in db.execute("SELECT path FROM records")}

    def test_unreadable_subdir_does_not_delete_its_records(self):
        self.index.refresh()
        self.assertEqual(self._paths(), {"top.json", "sub/deep.json"})
        with mock.patch("liebert_re.evidence.index.os.walk", _walk_failing("sub")):
            result = self.index.refresh()
        self.assertIn("sub/deep.json", self._paths())
        self.assertEqual(result["removed"], 0)
        self.assertGreaterEqual(result["errors"], 1)
        self.assertTrue(result["truncated"])

    def test_accessible_records_still_update_when_coverage_incomplete(self):
        self.index.refresh()
        (self.root / "new.json").write_text("{}", encoding="utf-8")
        with mock.patch("liebert_re.evidence.index.os.walk", _walk_failing("sub")):
            result = self.index.refresh()
        self.assertIn("new.json", self._paths())
        self.assertTrue(result["truncated"])

    def test_stat_error_blocks_deletion_once_then_clean_scan_removes(self):
        self.index.refresh()
        (self.root / "top.json").unlink()  # genuinely deleted

        def stat(path, *a, **kw):
            if path.name == "deep.json":
                raise PermissionError(13, "simulated stat failure")
            return REAL_STAT(path, *a, **kw)

        with mock.patch.object(pathlib.Path, "stat", stat):
            first = self.index.refresh()
        self.assertEqual(first["removed"], 0)
        self.assertTrue(first["truncated"])
        self.assertIn("top.json", self._paths())
        # Narrow guard: a complete, error-free scan removes the deleted record.
        second = self.index.refresh()
        self.assertFalse(second["truncated"])
        self.assertEqual(second["errors"], 0)
        self.assertEqual(second["removed"], 1)
        self.assertEqual(self._paths(), {"sub/deep.json"})


if __name__ == "__main__":
    unittest.main()
