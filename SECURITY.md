# Security policy

## Reporting a vulnerability in this toolkit

Use GitHub's private reporting: go to the **Security** tab of this repository and
choose **Report a vulnerability**. That opens a draft advisory visible only to
you and the maintainers.

If private reporting is unavailable to you, open a public issue containing
**nothing but** a request for a private channel — no details, no reproducer, no
affected version. A maintainer will open a private advisory and invite you.

Please include, once you are in a private channel:

- what an attacker gains, in one sentence;
- the smallest input or command that reproduces it;
- the affected version or commit, and your Python and OS versions;
- whether you are willing to be credited, and under what name.

**What to expect.** This is a small project, not a vendor with a response team.
We aim to acknowledge a report within 7 days and to agree a fix and disclosure
timeline with you from there. If a report needs more than 90 days we will say so
and explain why, rather than letting it go quiet. We will credit you unless you
ask us not to. We do not run a bug bounty and cannot pay for reports.

## What counts as a vulnerability here

This project parses hostile input for a living, so the interesting bugs are the
ones where *analysing* a file does something worse than producing a wrong answer:

- **In scope:** code execution, file write, or command injection triggered by
  parsing a crafted sample; path traversal when extracting or naming output;
  unsafe deserialisation; a sandbox or isolation control that does not actually
  contain what it claims to; a bug that causes the toolkit to run a sample it was
  only supposed to read; leaking credentials, tokens, or absolute local paths into
  committed output; a dependency pinned to a version with a known exploitable
  flaw.
- **Not a vulnerability, but still worth an issue:** a crash, hang, unhandled
  exception, or memory blow-up on a malformed file, and a wrong or incomplete
  analysis result. These are ordinary bugs — real ones, worth reporting — but they
  are the expected failure mode of binary analysis rather than a security
  boundary being crossed. Please file them publicly so others can find them.
- **Out of scope:** vulnerabilities in third-party analysis engines, disassemblers,
  or other external tools this project can invoke. Report those to their
  maintainers; tell us too, so we can pin or gate around them.

## Using this project safely

The toolkit is designed so that reading a file never runs it, and any step that
actually executes code is explicit and gated. That design is not a containment
guarantee and is not a substitute for isolation.

- Analyse untrusted samples in a **disposable virtual machine**, on a snapshot you
  can revert. Do not analyse hostile files on a machine you or anyone else depends
  on.
- Keep samples out of paths that are synced, backed up, or shared, and out of any
  directory a scanner or indexer watches.
- Treat every path, name, and string inside a sample as attacker-controlled, and
  never pass one to a shell.
- Review what you are about to commit. Analysis output can carry absolute paths,
  machine names, and sample contents; this repository's `.gitignore` excludes the
  usual output directories, but the final check is yours.

## Responsible use

This is dual-use tooling and it comes with conditions. See
[DISCLAIMER.md](DISCLAIMER.md) for the responsible-use policy, the categories of
contribution we decline, and the limitation of liability. Reports of misuse of
this project belong in a private advisory, not a public issue.
