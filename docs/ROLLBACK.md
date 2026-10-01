# Rollback

Git is the safety net. Nothing here needs a tool beyond git.

## Porting rule

- One capability family per commit. Never squash.
- A commit touches only the files it introduces, plus the registry and
  `py-modules` lines it needs. Nothing else rides along.
- `tests/test_repo_discipline.py` enforces part of this in CI: every module is
  in `py-modules`, every module has a test reference, no artifacts or
  user-specific paths are tracked.

## Tags

- `port-baseline` marks the state before any porting began. It is a local tag
  (not on the remote), so its commit is also recorded here:
  `bfd748c80558aa3918f9fbaf0d2ddbde8c2137b3`. If the tag is missing, recreate it
  with `git tag -a port-baseline -m "before porting" bfd748c80558aa3918f9fbaf0d2ddbde8c2137b3`.
- Before each family lands, tag `port-<family>-pre`:
  `git tag -a port-<family>-pre -m "before <family>"`
- List them: `git tag -n1`

## Find what a step added

    git show --stat <sha>
    git diff --stat port-baseline..HEAD

## Roll back an UNPUSHED step

    git reset --hard <tag-or-sha>

Safe only when the working tree is clean (`git status --short` prints nothing)
and nothing else is in flight. It discards every commit after the target and
any uncommitted edits. Never use it on commits that have been pushed.

## Roll back a PUSHED step

    git revert <sha>
    git revert -m 1 <sha>      # when <sha> is a merge commit

This adds a new commit that undoes the step. Force-push is forbidden: history
that others may have fetched is never rewritten.

## Rehearsed

Both procedures were run for real in a throwaway clone (not this working tree).
Unpushed: dummy commit, `git reset --hard port-baseline` gave a clean status and
HEAD `bfd748c8...`. Pushed: dummy commit, `git revert --no-edit <sha>` gave a clean
status and a tree identical to `port-baseline` (`git diff --quiet port-baseline HEAD`).

## What rollback does NOT undo

Rollback only moves tracked files. It does not remove:

- installed packages (compare `python -m pip list` against `pyproject.toml`);
- files written into ignored paths such as `dataset/`, `.pytest_evidence_scratch/`,
  `__pycache__/`, `liebert_re_harness.egg-info/`.

Check what is sitting in ignored paths:

    git status --short --ignored

Delete stale ignored files by hand after reading that list. Do not run
`git clean -x` blindly; it also removes local config you may want.
