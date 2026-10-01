# Contributing

Thanks for considering it. This document is mostly about one idea, and the rest
follows from it.

## The one rule: never return a confidently wrong answer

An analysis tool that says "I don't know" is useful. An analysis tool that
returns a plausible number it did not actually measure is worse than no tool at
all, because someone will build on it. Every silently-wrong answer this project
has shipped was eventually found by someone who trusted it.

So, concretely:

- **If you could not determine something, say so in the return value.** Use an
  explicit `None`, `"UNKNOWN"`, or an error — never a default, a zero, a guess, or
  the value that happens to be lying around in a nearby variable.
- **Distinguish "measured" from "derived" from "assumed"** in both output and
  docstrings. If a function reads a field from the file, say so. If it infers the
  field from something else because the real one was missing, say *that*, and say
  which fallback it used.
- **A fallback path must announce itself.** If the fast path fails and you fall
  back, the result must carry a field saying which path produced it.
- **Prefer a narrow correct answer to a broad approximate one.** Handling one file
  format properly beats handling four of them almost.

If you take nothing else from this file, take that.

## Before you write code

- **Open an issue first for anything non-trivial**, especially a new analysis
  capability, a new external tool dependency, or anything that touches the
  responsible-use boundary in [DISCLAIMER.md](DISCLAIMER.md). A short "here is
  what I want to do and why" saves both of us a rejected pull request.
- **Small, typo-level, and documentation fixes need no issue.** Send them
  directly.
- **Read [DISCLAIMER.md](DISCLAIMER.md)'s "Out of scope" section.** Some
  contributions will be declined for reasons that have nothing to do with code
  quality, and it is better to know that before you start.

## Development setup

```bash
git clone https://github.com/LiebertDev/liebert-re-harness.git
cd liebert-re-harness
python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate
pip install -e ".[dev,lattice]"
pytest -q
```

Python 3.10 or newer. The `lattice` extra brings `mpmath`; without it the two
lattice test modules skip instead of running. The test suite must pass on a clean checkout with no
external analysis tools installed — anything that needs an external engine must
skip cleanly when it is absent, with a message naming what is missing.

## What a good pull request looks like

1. **A test that fails before your change and passes after.** For a bug fix, the
   test should encode the wrong behaviour you observed, not just the code path.
   For a parser, include the smallest input that exercises it — build the fixture
   programmatically where you can, so the repository does not accumulate opaque
   binaries.
2. **Only your own files.** Do not reformat, re-sort imports, or "tidy" code you
   are not otherwise changing; it buries the actual diff. Separate mechanical
   changes into their own pull request.
3. **A commit message that says what changed and why.** One line of subject, a
   blank line, then the reasoning — particularly what you measured and how. A
   reviewer should not have to reverse-engineer your intent from the diff.
4. **Docstrings that state the contract**, including what the function returns
   when it cannot determine an answer, and which parts of a format it does *not*
   handle. Known limitations written down are a feature.
5. **No new required dependency without discussing it.** Each one is a supply-chain
   surface and a platform-support problem. The standard library is usually enough.

## Style

- Follow the surrounding code. Match its naming, its comment density, and its
  idioms rather than importing conventions from elsewhere.
- Type hints on public functions.
- `ruff check .` must pass. It is scoped in `pyproject.toml` to **bug-finding rules
  only** (`E9`, `F` — syntax errors, undefined names, unused imports, redefinitions),
  not style: ruff's wider default set reports 481 findings here and 469 of them are
  the dense one-line `if not x: return y` style this codebase is written in
  throughout. The style is not the problem; rewriting every file would bury every real
  diff.
- **There is no formatter gate.** `black --check` is deliberately not run, for the
  same reason. Match the surrounding code instead. Adopting a formatter is welcome as
  its own pull request — the formatting commit first, no behaviour change mixed in.
- Comments should explain *why*, not restate the code. A comment naming the
  specification section a magic number comes from is worth ten that describe
  syntax.
- No `print` in library code. Return data and let the caller decide what to
  display (no module under `liebert_re/` uses `logging`; the CLI in
  `liebert_re/cli.py` is the one place that writes to stdout).

## Working with samples

- **Do not commit third-party binaries.** Reference them by name and SHA-256 and
  let the reader fetch them, as described in [docs/CORPUS.md](docs/CORPUS.md). This
  keeps the repository small and keeps other people's distribution terms
  applicable only to their own files.
- Crackme and CTF challenge write-ups are welcome and are the intended home for
  "how I solved this" work. Credit the challenge author, link the original, and
  respect any rule the author set — if a crackme says "no patching", a patching
  solution is not a solution to it.
- Never commit a sample's output uncritically; analysis artefacts routinely embed
  absolute paths and machine names.

## Review

Expect questions about evidence. "How do you know?" is not scepticism about you,
it is the project's normal review question, and the answer belongs in the code or
the commit message where the next reader will find it. Reviews aim to be prompt,
but this is volunteer work and sometimes it is not — a polite ping after a week is
welcome rather than annoying.

## Licensing your contribution

This project is licensed under the [Apache License 2.0](LICENSE). By opening a
pull request you agree that your contribution is licensed under the same terms,
and you confirm that you have the right to submit it — that it is your own work
or that you are permitted to contribute it, and that it contains no proprietary
code, credential, or third-party material you cannot license this way. There is
no separate CLA to sign.
