<!--
Thanks for contributing. The checklist is short on purpose; every line on it has
caught a real problem before.
-->

## What this changes, and why

<!-- One or two sentences. Link the issue if there is one: Fixes #123 -->

## How you know it is correct

<!--
The part reviewers care about most. What did you actually measure or observe --
before and after? If you fixed a wrong answer, state the wrong value and the
right one.
-->

## Checklist

- [ ] There is a test that **fails before this change and passes after**, and I
      have said above how I confirmed that.
- [ ] Anything the code cannot determine is returned as an explicit `None` /
      `"UNKNOWN"` / error — never a default, a zero, or a guess.
- [ ] Any fallback path announces itself in the result rather than silently
      substituting for the primary path.
- [ ] Docstrings state the contract, including what is returned on failure and
      which parts of the format are **not** handled.
- [ ] The diff contains only my own changes — no drive-by reformatting, import
      re-sorting, or unrelated tidying.
- [ ] `pytest -q`, `ruff check .` and `black --check .` all pass locally.
- [ ] No new required dependency (or it was discussed in an issue first).
- [ ] No third-party binary, sample, credential, or absolute local path is
      committed. Samples are referenced by name and SHA-256 per
      `docs/CORPUS.md`.
- [ ] This contribution is outside the *Out of scope* list in `DISCLAIMER.md`,
      and I have the right to submit it under the Apache License 2.0.

## Anything a reviewer should know

<!--
Known limitations, deliberate omissions, follow-up work you chose not to do.
Stating a limitation is a feature here, not an admission.
-->
