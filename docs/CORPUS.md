# Working with samples

This repository contains **no third-party binaries**, and pull requests that add
them will be declined. This page explains why, and how a write-up refers to a
sample instead.

## Why no binaries

Three reasons, in order of how often they bite:

1. **We have no right to redistribute most of them.** A crackme is someone's
   work, released on their terms and often from their own page; a commercial
   binary is nobody's to re-host. Referencing a file by hash leaves the author's
   distribution terms as the only ones that apply to it.
2. **A repository that accumulates binaries becomes unusable.** Clones get large,
   history gets permanent, and a file committed once is committed forever.
3. **Scanners.** A repository full of packed executables and driver samples gets
   flagged, quarantined, and sometimes taken down — on your machine, in CI, and on
   the hosting side. Contributors then cannot clone it.

## How a write-up identifies its sample

Every analysis document starts with a provenance block, so a reader can verify
they are looking at exactly the file the author looked at:

```yaml
sample:
  name:        example-crackme-3.exe
  sha256:      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  size:        463872
  source:      https://example.org/crackmes/example-3   # where the author published it
  author:      Original Author Name
  license:     as stated by the author on that page
  retrieved:   2026-09-27
```

If the hash of your copy does not match, **stop and say so** rather than assuming
the write-up applies. Different builds of the same challenge are common, and
almost every address in an analysis is build-specific. A mismatch is a finding,
not an inconvenience — several of this project's own dead ends were exactly that.

## Where to put samples locally

Put them in `samples/` or `corpus/`. Both are in `.gitignore`, along with the
usual executable extensions, specifically so that a file fetched for local work
cannot be committed by accident. Do not "fix" that by force-adding.

## Fixtures for tests

Tests must not depend on a file the contributor has to download. Build fixtures
programmatically instead — emit the smallest PE, ELF, or archive that exercises
the code path, from a helper in the test suite. This keeps the suite runnable on
a clean checkout, makes the fixture's intent readable in the diff, and lets a
reviewer see precisely which malformed field a parser test is about.

When a real sample is genuinely irreplaceable for a regression test, commit a
**minimised, redacted excerpt** — the specific structure under test, not the
whole file — and document in the test what was cut and why.

## Challenge authors' rules

Crackmes usually come with rules: no patching, keygen only, a required proof of
solution. **Those rules define what counts as solving it.** A patched binary is
not a solution to a keygen-only challenge, and presenting it as one is not a
contribution we will merge. Credit the author, link the original page, and if the
author asks that solutions not be published, respect that — link your write-up
somewhere else, or write about the technique without handing over the answer.
