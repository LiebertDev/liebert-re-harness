# Architecture notes

This document is for someone picking up the codebase, not for someone evaluating
whether to use it. It answers "why is this written this way" for the decisions
that are not obvious from the diff, and it is deliberately narrower than the
README: no pitch, no results, just the reasoning behind the structure.

## 1. The one rule, and what it costs

[CONTRIBUTING.md](../CONTRIBUTING.md) states the rule this codebase is organised
around: never return a confidently wrong answer. In code, that rule shows up as
a small number of concrete, repeated patterns rather than as a comment anyone
has to remember to apply:

- **Explicit absence over a default.** `tools_formats.file_identity()` returns
  `architecture: null` and `endianness: null` for a text file — not `"unknown"`
  as a string, not `"x86"` because that happens to be the common case, `null`.
  The same function returns a structured `{"ok": false, "error":
  "FILE_NOT_ACCESSIBLE", ...}` for a directory or an unreadable path instead of
  letting the underlying `OSError` propagate as a traceback, because a caller
  asking "can this path be identified as a file" has the same honest answer —
  no — for every flavour of unreadable path, and a raw exception is not that
  answer in a form a model can act on.
- **Fallbacks announce themselves.** Where a function has a fast, precise path
  and a slower or heuristic one, the result carries a field naming which path
  actually produced it. A caller — model or human — should never have to guess
  whether a number was measured or approximated by reading the value alone.
- **`UNKNOWN` is a real return value, not an absence of one.** `analysis_ir.py`
  defines `UNKNOWN` as one of exactly four confidence levels
  (`SYMBOL_PROVEN`, `METADATA_PROVEN`, `HEURISTIC`, `UNKNOWN`), so "we don't
  know" is representable in the schema on the same footing as "we measured it
  from a symbol", not a `None` a downstream consumer has to special-case.

**The cost is real and is paid on purpose.** Return shapes are more verbose
than they would be if a missing field could simply be omitted. Every parser
that could fail in more than one way ends up with a small taxonomy of error
codes instead of one `except: return None`. Docstrings get longer because they
have to state what a function returns when it cannot determine an answer, not
just what it returns on the happy path (`CONTRIBUTING.md` asks for this
explicitly). None of that is accidental sprawl — it is the direct, accepted
price of making a wrong answer distinguishable from an unknown one, which is
the property the rest of the evidence layer below depends on.

## 2. Evidence before conclusions

A tool's output and a claim about a target are kept as two different kinds of
object on purpose, because a sentence a model writes and a byte a parser read
are not the same thing, and treating them as interchangeable is exactly how a
plausible-sounding wrong answer survives to become a "finding".

- **`evidence_index.py`** is the read side over the evidence corpus a session
  accumulates: tool-output records, indexed by content, joined by a stable
  `evidence_uid` derived from the file's own hash so it survives a full
  rebuild-from-scratch. The module treats the corpus as append-only and
  immutable — it never writes, renames, or mutates an evidence file; the
  index itself is disposable and reconstructible.
- **`evidence_security.py`** computes an integrity checksum
  (`sha256(canonical_json(record))`) over an evidence record and is explicit,
  in its own module docstring, about what that does and does not prove: it
  catches accidental corruption (truncation, a stale copy, a bit flip), and it
  is *not* a cryptographic attestation that the record came from a trusted
  tool dispatcher rather than a hand-built forgery — the algorithm and inputs
  are public, so a forger can compute a matching checksum too. The property
  that actually resists deliberate forgery is binding a record to a
  `result_id` that a live tool dispatcher produced during the process's own
  run, which lives upstream (see §6), not in this checksum.
- **`claim_index.py`** turns evidence into structured, comparable assertions —
  `(target_identity, subject_kind, subject_value, predicate) -> asserted_value`
  — specifically so that "do these two claims answer the same question with a
  different answer" is a mechanical string comparison, not a judgment call.
  It exists because of a real failure it names in its own docstring: four
  successive claims about one target were each refuted by later evidence, and
  none was ever marked superseded automatically — one sat in the project's
  state document as fact for three weeks after evidence had already
  contradicted it. `create_claim` now flips a claim to `CONTRADICTED`
  unconditionally the moment a `REFUTES` evidence link is added to it, PROVEN
  claims included, and that flip can never be undone by adding more supporting
  evidence — only a new claim that explicitly supersedes it can move the story
  forward. That is deliberate: the failure this module answers was a missing
  mechanical check, not a missing human reviewer, so the fix is mechanical
  too.
- **`claim_guard.py`** is the last, cheapest check before a piece of model
  output is accepted as evidence-backed: every `0x...`-shaped hex reference
  and every `line N` reference in an answer must appear literally in the
  evidence text it is supposedly grounded in, or it is flagged. It also
  flags a claimed-absent import (`"does not import X"`) that in fact
  appears in the evidence, and flags a hedge-free negative claim about a
  risk-relevant domain (network, encryption, anti-cheat, ...) that is not
  phrased with the evidence-based caution the project expects. This is
  intentionally shallow pattern matching, not semantic verification — it
  catches a model citing an address that was never measured, not a model
  that is subtly wrong in a way that still cites real numbers.

The reason this is this strict: a large language model's output is fluent by
construction, and fluency is exactly orthogonal to correctness. A number a
model writes and a number `pefile` read out of a section table look identical
on the page. The only way to keep them distinguishable downstream is to never
let the first one pass as the second without a literal, checkable link back to
a measurement — hence content-hashed identities, hence a guard that rejects an
address it cannot find verbatim in the cited evidence.

## 3. The workspace sandbox is a guardrail, not a boundary

`tools_workspace.py` confines every file-access call — `safe_path()` and
everything built on it (`read_file`, `list_directory`, `search_text`, ...) —
to a single root: `TEACHER_WORKSPACE` if set, otherwise the current directory.
An absolute path outside that root, including an absolute path to a system
file, is refused with a `PermissionError` before anything is opened.

**What it does:** stops an ordinary, non-adversarial call from wandering
outside the directory it was meant to analyse — the default failure mode of a
model given a `read_file(path)` tool and a typo, or a relative-path
computation that walks up one directory too many.

**What it does not do:** it is not a security boundary against a file that is
itself hostile input. `docs/INSTALL.md` says this plainly: the standing advice
is to analyse untrusted binaries in a disposable VM regardless of what this
sandbox enforces, and that was true before any of the fixes below, not a
downgrade introduced by them.

**The lesson from the POSIX bug.** `safe_path()` used to decide containment
with `pathlib.Path.is_absolute()`. On Windows that correctly rejects
`C:\Windows\evil.txt`. On POSIX, a backslash is not a path separator, so that
exact string parses as one ordinary, oddly-named *relative* filename — it gets
joined inside the workspace root and passes containment without raising.
Containment itself was never actually broken (the write still landed inside
the workspace), but a plainly foreign path was silently accepted instead of
refused, which broke the sandbox's own contract of failing closed on anything
that looks foreign. The fix is a pure, platform-independent syntax check
(`_looks_like_windows_absolute_path`) that runs unconditionally before any
`Path` parsing, gated only by `os.name != "nt"` so it is a deliberate no-op on
Windows, where the existing logic already handles the same syntax correctly.

The generalisable lesson is not about backslashes specifically: **a scoping or
containment check whose correctness depends on a path library's
platform-specific interpretation of syntax will silently do the wrong thing on
whichever platform that interpretation doesn't match the check's assumption.**
This project's own containment logic was one CI run on a second platform away
from shipping exactly that bug, and the fix was extracted into a pure,
platform-independent function precisely so it could be unit-tested on any
host rather than trusted by inspection.

## 4. Bounded execution

`bounded_subprocess.py` is the single place every external engine call in this
project goes through (`rizin`, `diec`, `yara-x`, and anything else that shells
out). Every call is wrapped with a time bound and an output-size bound, and
every process it starts is one this module can find and kill by its own
tracked identity later, not by trusting the tool's own well-behavedness.

**Why the process tree has to be killed, not just the direct child.** A
launcher — a `.bat` wrapper, a venv's relay `python.exe` stub — routinely
exits before the real payload process it spawned does, and can do so in well
under a second. A naive "kill the pid I started" leaves the grandchild running
and, on Windows, still holding a write handle on the same stdout/stderr pipe
this module is trying to read — Windows only signals EOF on a pipe once every
write handle across every process is closed, so one surviving orphan can block
the reader thread forever. The module therefore snapshots the whole descendant
tree *while everything is still alive* (an already-exited intermediate hop
permanently breaks a from-scratch parent-id walk done later, because that
process has already dropped out of the live process table), and kills by pid
directly rather than assuming a process's own recorded parent is still around
to vouch for it.

**Why partial output is kept, not discarded.** If a bound is hit, whatever
stdout/stderr had already been captured is returned, truncation-marked and
content-hashed, rather than replaced with an empty result. Half of a
measurement — the disassembly of the first 40% of a section before a hung
engine had to be killed — is strictly more useful to a caller than silence,
provided the caller can tell that it is partial. `output_truncated` and the
`stdout_sha256`/`stderr_sha256` fields make that distinction explicit rather
than leaving a caller to guess whether short output means "that's everything"
or "that's what survived".

**Why POSIX and Windows share one contract despite using different
mechanisms.** Windows can reliably walk a dead process's recorded parent-id
chain, because Windows never rewrites a child's ppid when its parent exits —
so a `taskkill /T /F` plus a parent-id-graph scan is sufficient there. POSIX
reparents an orphan to the nearest subreaper the instant its direct parent
exits, which breaks a parent-id walk done after the fact; the module's
independent, unconditional fix there is a POSIX process-group kill
(`setsid()` at spawn time makes the spawned process its own group leader, so
`killpg` reaches every group member regardless of who the OS now claims their
parent is), escalating from `SIGTERM` to `SIGKILL` after a bounded grace
period rather than either an instant hard kill or an unbounded wait. Both
mechanisms are platform-specific; the `BoundedProcessResult` they both feed is
not — a caller never needs to know which teardown path actually fired.

## 5. Why flat modules and no framework

The repository root is one flat directory of Python modules — `tools_binary.py`,
`tools_workspace.py`, `evidence_index.py`, `pe_address.py`, and so on — not a
package tree, and there is no dependency-injection container, no plugin
registry, and no framework the modules register themselves into. This is a
choice, not an oversight, and it is made for reasons specific to this project
rather than as a general recommendation:

- **A small team maintains this.** A framework earns its cost when enough
  people need a stable extension point that nobody remembers by hand; a flat
  module layout costs nothing to reason about for a team small enough to just
  know where things are.
- **A single module should be importable and runnable on its own.** `python -c
  "import pe_address"` or a single test file exercising `tools_workspace.py`
  in isolation has no framework to bootstrap first. That property is worth
  more here than the convenience a plugin system would add, because
  isolating exactly which module produced a wrong answer is a recurring
  need, not a rare one.
- **`CONTRIBUTING.md`'s style section says the same thing from the other
  direction**: match the surrounding code rather than importing conventions
  from elsewhere, and a formatter or restructuring pass is its own pull
  request with no behaviour change mixed in, specifically so it never buries
  a real diff.

If a contribution wants to introduce a package structure, a DI layer, or a
plugin system, that is a proposal-issue conversation first (per
`CONTRIBUTING.md`), not a pull request — not because the idea is necessarily
wrong, but because it is a structural change to how every module in the
repository is found, imported, and tested, and that is exactly the kind of
change this document exists to make people stop and discuss before writing.

## 6. What the upstream tree adds, and the one lesson from it

This repository is a curated subset of a larger private working tree. What the
upstream tree adds and does not publish here: an agent brain/model-dispatch
loop, a tool bus that routes and records calls to the operations this
repository implements, a deterministic planner, a provider abstraction over
which model backend is actually driving a session, and orchestration state
(worker dispatch, task queues, session bookkeeping) specific to how that tree
is operated day to day. None of those modules — referred to here only by the
role they play, e.g. "the tool dispatcher", "the planner" — are in this
repository, and any reference to them elsewhere in this document is a
reference to that upstream tree, not to code published here.

The one lesson from that tree worth carrying into any codebase, stated without
naming the specific modules or lines involved (they are not published here):
**verify that a mechanism is actually wired into the live path by finding the
call or the import that reaches it — not by finding its definition and
inferring that a well-named, well-tested function must be in use.** In that
upstream tree, a function existed to compute a dependency ordering for a
planning graph and was never called from anywhere the planner's real code path
reached; separately, a completion guard had been written and had its own
passing tests, and was never wired into the live pipeline it was built to
guard. Both were discovered only by tracing actual call sites and imports
forward from the entry point a real run goes through, not by reading the
function in isolation and assuming its existence implied its use. A
well-named, tested, and merged function is evidence that someone intended to
wire it up — it is not evidence that they did.

## 7. If you are picking this up

1. **Run the tests first.** `pytest -q` on a clean checkout, no external
   engine installed, is expected to be green with the skip count
   `docs/INSTALL.md` states — if it isn't, that is a bug worth reporting
   before you build on top of it.
2. **Read one script in `crackme_solutions/`** before reading the analysis
   modules it uses. They are written to be self-contained and are the
   fastest way to see how the toolkit's typed operations actually compose
   into an attack, rather than reading a module's docstring in isolation.
3. **Pick a "start here" item from `docs/ROADMAP.md`.** It is maintained
   separately from this document and is the current, prioritised list of
   what is worth working on next; do not assume this document's gap
   descriptions are still current by the time you read them.
4. **Send a small pull request first.** Per `CONTRIBUTING.md`: a test that
   fails before your change and passes after, touching only the files your
   change actually needs.
5. **Open an issue when you are unsure**, especially before a new analysis
   capability, a new external dependency, or anything touching the
   responsible-use boundary in `DISCLAIMER.md`. A short "here is what I want
   to do and why" is cheaper for everyone than a rejected pull request.
