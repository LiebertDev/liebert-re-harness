"""Regression coverage for a real, reproduced bug: WorkspaceIndex.refresh()'s
first-N os.walk() cutoff let a large vendor/generated tree silently starve
out small canonical directories (confirmed against the real repository --
external/ alone was ~76% of every file the old walk saw, leaving tests/,
prompts/, ghidra_scripts/, ida_scripts/, runpod/, smoke-tests/, and
offline_training/ at zero indexed files even though max_files was never
close to the repo's true canonical-content size).
"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from workspace_index import WorkspaceIndex


def _touch_many(directory: Path, count: int, prefix: str, ext: str = ".txt") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (directory / f"{prefix}{i}{ext}").write_text(f"content {i}\n", encoding="utf-8")


class WorkspaceIndexPriorityTests(unittest.TestCase):
    def test_large_vendor_tree_does_not_starve_small_canonical_directory(self):
        # Reproduces the exact real-repo failure shape at small scale: a
        # `external`-style vendor tree with far more files than a tight
        # max_files budget, alongside a tiny canonical `tests` directory.
        # Under the old single first-N os.walk() cutoff, whichever directory
        # the filesystem happened to walk first could fully consume the
        # budget before the walk ever reached the other -- exactly what was
        # observed against the real repository (dataset/ visited before
        # tests/). The fix must guarantee canonical content survives
        # regardless of raw walk order.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _touch_many(root / "external" / "vendor_lib", 500, "hdr")
            _touch_many(root / "tests", 20, "test_case_")
            index = WorkspaceIndex(root, db_path=root / "index.sqlite")
            result = index.refresh(max_files=50)
            self.assertTrue(result["ok"])

            status = index.status()
            # external/ is a hard exclusion, not deferred -- it contributes
            # zero eligible candidates, so only the real tests/ files (20)
            # are ever seen, well under the 50-file budget.
            self.assertEqual(status["files"], 20)

            import sqlite3
            conn = sqlite3.connect(root / "index.sqlite")
            tests_indexed = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE 'tests/%'").fetchone()[0]
            external_indexed = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE 'external/%'").fetchone()[0]
            conn.close()
            # external is a hard exclusion (matches this project's own
            # gitignored vendor-toolchain directory of the same name) --
            # zero of it should ever be indexed.
            self.assertEqual(external_indexed, 0)
            # All 20 real tests/ files must survive a 50-file budget.
            self.assertEqual(tests_indexed, 20)

    def test_nested_git_worktree_is_pruned_generically(self):
        # A directory that owns its own `.git` entry is a separate
        # repository root (most commonly a `git worktree` checkout nested
        # inside the tree, as this project's own `.claude/worktrees/*`
        # actually is) -- a full duplicate of project content, not unique
        # canonical material. Detected generically via `.git` presence, not
        # a hardcoded path, so this also covers any future nested-repo case.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _touch_many(root / "src", 5, "module_")
            worktree = root / ".claude" / "worktrees" / "some-branch"
            _touch_many(worktree, 30, "duplicate_")
            (worktree / ".git").write_text("gitdir: /elsewhere\n", encoding="utf-8")
            index = WorkspaceIndex(root, db_path=root / "index.sqlite")
            result = index.refresh(max_files=100)
            self.assertEqual(result["worktrees_pruned"], 1)
            self.assertFalse(result["truncated"])

            import sqlite3
            conn = sqlite3.connect(root / "index.sqlite")
            worktree_indexed = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE '.claude/worktrees/%'").fetchone()[0]
            src_indexed = conn.execute("SELECT COUNT(*) FROM files WHERE path LIKE 'src/%'").fetchone()[0]
            conn.close()
            self.assertEqual(worktree_indexed, 0)
            self.assertEqual(src_indexed, 5)

    def test_deferred_prefix_is_lower_priority_but_still_indexed_when_room_allows(self):
        # dataset/evidence and dataset/runtime are real, harness-generated
        # content -- worth finding if budget allows, unlike external/ or a
        # stale worktree, which are never useful. A tight budget must
        # prioritize non-deferred content first; a generous budget must
        # still include deferred content rather than silently dropping it
        # forever.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _touch_many(root / "tests", 5, "test_")
            _touch_many(root / "dataset" / "evidence", 20, "ev_")

            tight_index = WorkspaceIndex(root, db_path=root / "tight.sqlite")
            tight_result = tight_index.refresh(max_files=5)
            self.assertEqual(tight_result["primary_available"], 5)
            self.assertEqual(tight_result["deferred_included"], 0)

            roomy_index = WorkspaceIndex(root, db_path=root / "roomy.sqlite")
            roomy_result = roomy_index.refresh(max_files=100)
            self.assertEqual(roomy_result["deferred_included"], 20)
            self.assertFalse(roomy_result["truncated"])


if __name__ == "__main__":
    unittest.main()
