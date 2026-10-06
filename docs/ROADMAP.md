# Roadmap and known gaps

This project is not under active development right now. This document exists so
that someone who wants to pick it back up knows where to start, what is genuinely
missing, and what has already been tried and abandoned as too hard for a casual
contribution. It is a map, not a promise — nobody is committed to working through
it on a schedule.

Contributions against anything below are welcome. The one rule that governs all
of them lives in [CONTRIBUTING.md](../CONTRIBUTING.md): never return a
confidently wrong answer. Read that file before opening a pull request; almost
everything else follows from it.

## Start here

Small, self-contained, and each closable without touching more than one or two
files.

1. **The mutated-crackme-5 serial solver is not runnable from this tree.** Its
   script is not distributed in this public package (see
   [SOLVED_INDEX.md](../SOLVED_INDEX.md)); its emulation step depended on a
   bounded-emulation module from the upstream tree that was never published here
   (see the README's "deliberately not in this repository" list). The write-up
   and the recovered algorithm are correct and worth keeping. A useful
   contribution is a minimal emulation path built from what is already in this
   repository (Capstone for decode, Unicorn is already a dependency — see
   `pyproject.toml`), or a documented manual trace of that step.
2. ~~`liebert_re/tools/vb6_pcode.py`'s `program_strings` operation raises `ImportError`.~~
   **No longer true — verified closed.** `liebert_re/tools/vb6_pcode.py` is fully published
   in this package; `program_strings` only imports `pefile` and `capstone`
   (both shipped dependencies), and calling it returns a normal structured
   result (e.g. `FILE_NOT_FOUND` for a missing path), not an `ImportError`.
   `from liebert_re.tools.vb6 import vb6_inspect` also resolves cleanly. This item is kept,
   struck through, so a reader who remembers the old defect can see it was
   checked rather than silently dropped.
3. **Lint coverage is narrow on purpose, and widening it is real, bounded work.**
   `ruff` is currently scoped to `E9,F` (syntax errors, undefined names, unused
   imports, redefinitions) because the wider default rule set reports hundreds
   of findings that are just this codebase's dense `if not x: return y` style,
   and fixing that in bulk would bury every real diff. Picking one additional
   rule family (`B` for bug-prone patterns, or `SIM` for simplifiable code) and
   fixing it file-by-file, with the formatting change in its own PR separate
   from any behaviour change, is exactly the shape of contribution this project
   wants. Do not turn on the whole default set in one pass.
4. **Test fixtures should be generated, not fetched.** [CORPUS.md](CORPUS.md)
   already states the rule: build the smallest PE/ELF/archive that exercises a
   code path programmatically, inside the test suite, instead of depending on a
   sample the contributor has to download. Several tests already do this; a good
   contribution is finding a test that still skips or depends on an external
   sample and converting it to a generated fixture.
5. **Docstrings should state the "cannot determine" contract, and many do not
   yet.** The project's central rule — never return a confidently wrong answer —
   only works if a caller can read a function's docstring and learn what it
   returns when it fails, not just what it returns when it succeeds. Measured on
   `liebert_re/tools/binary.py` as of this writing: of its 12 public (non-underscore)
   top-level functions, **11 have no docstring at all**. Auditing a module,
   writing docstrings that state the failure contract explicitly (what comes
   back on missing data, on a malformed field, on a missing external tool), and
   sending that as its own PR is welcome and does not require touching any
   function body.

## Bigger pieces

Capabilities that exist in the private working tree this repository was cut from
but were deliberately left out of the public package — not because they are
secret, but because they are specific to the upstream tree's own plumbing or
large enough to need their own design discussion. Each is a real gap here, not a
hidden feature.

- **Bounded emulation** (Unicorn-based range emulation, execution traces, a
  backward slicer, per-instruction snapshots and register capture). **Still
  open.** `liebert_re/recover/vex.py` ships, but it only corrects how AVX (VEX-encoded)
  instructions execute inside an emulation session; it is not range emulation,
  tracing or slicing. This is the
  single most useful missing piece, because several things in this repository
  currently degrade to "documentation only" without it — see item 1 above. Start
  by defining the narrowest useful surface: emulate a bounded instruction range
  starting from a known register state and return a trace, before attempting
  anything like slicing.
- **IDA and Ghidra wrappers** (headless decompilation, cross-references,
  callers/callees, answers normalised across engines so a caller does not need to
  know which one ran). **Partly done.** The read-only half of an IDA wrapper
  ships (`liebert_re/tools/ida.py`: `ida_query`, `ida_status`; summary, function list,
  segments, function-at-address, Hex-Rays pseudocode, cross-references, imports/exports,
  strings; database cache keyed by input hash and size-capped; PDB downloads off). It
  needs a licensed IDA Pro 9.x, so CI cannot exercise it: the default tier tests the
  wrapper against a stand-in `idat`, and one `heavy` class runs the real thing locally.
  Also shipped: `ida_type_member_offset`, `ida_patch_plan` (a plan, checked by hashing the
  cached database before and after), `ida_annotations` (a read of the annotation log) and the
  persistent rename pair `ida_rename_plan` / `ida_annotations_apply` (own annotated root, audit
  journal, read-back in a separate engine process).
  **Round 2, comment write: landed.** `ida_set_comments_plan` plans and `ida_annotations_apply` writes
  `regular` and `repeatable` comments. **What is left of round 2 is the CLI binding.**
  `case_purge` integration is not done: the annotated purge does not read case state today, so a case
  becoming `solved` or `abandoned` does not trigger it.
  **Still open:** `ida_disasm_listing` (read-only, next
  round), Ghidra decompilation and cross-references (slice 1, `ghidra_status` and
  `ghidra_program_facts`, has landed), and normalising answers across engines.
- **Function-boundary recovery from exception-directory unwind data.** **Partly closed.**
  `liebert_re/tools/pe_unwind.py` reads the x64 exception directory (`.pdata`): published tools
  `pe_runtime_functions` (the table, summarised, with a bounded page of entries) and
  `pe_function_extent` (the entry containing one address), CLI `pdata`. It needs no
  disassembler session and gives exact begin and end of each function that has an entry.
  (~~no `.pdata` parser ships~~ was the earlier statement; it is out of date.) **Still open:**
  it is not function discovery. Leaf functions get no entry, and its own `coverage.ceiling`
  says so: on one real x64 crackme it reported 48 primary entries where IDA had 88 functions,
  a gap consistent with that. It does not help with an import's callers. Prologue scanning and
  cross-checking against what a disassembly engine found are not built, and x86 has no such
  table (`X86_NO_PDATA`).
- **A cross-reference query answers an unresolved question as an empty one.** `ida --operation
  xrefs_to` on an import name, an IAT slot or a jump thunk returns `status OK` with `items: []`.
  That reads as "this import has no callers" when it means "the query was not resolved through the
  import thunk and indirect uses were not searched": a negative that looks measured and is not.
  The honest shape separates "no callers found" from "resolved to a thunk, callers not followed".
  `kerneliat` comes closest, but it is explicitly heuristic (`proves_call: false`) and gives the
  thunk, not the callers. **Open**, found on a second crackme.
- **No caller search for an import's indirect uses, and no data-reference tool.** Settling "is
  this import ever called" and "who reads this data blob" both needed a hand-written byte scan of
  `.text` for rel32 and RIP-relative targets. Whole-program dataflow is already recorded under
  "Interprocedural taint analysis / whole-program dataflow" below; the new part is narrower: no
  shipped operation resolves an import's callers or a static data pointer's readers. **Open.**
- **Crash symbolisation.** ~~Minidump *parsing* is already here
  (`liebert_re/recover/minidump_structural.py`); turning a raw address recovered from a dump into a
  symbol is not.~~ **Closed for its stated scope.** `liebert_re/recover/minidump_analyzer.py` maps
  an address recovered from a dump to its module, and `liebert_re/recover/crash_symbolize.py`
  turns module plus RVA into the nearest public symbol, built on the PDB/CodeView
  work (`liebert_re/recover/msf_pdb.py`, `liebert_re/recover/codeview_rsds.py`). What remains open: it needs a PDB whose
  identity matches the crashing module (otherwise the answer is `UNKNOWN`), it
  resolves public symbols only (no source lines), and there is no stack
  unwinding — the stack scan in `liebert_re/recover/minidump_analyzer.py` is a heuristic pointer
  scan, explicitly not a proven call stack.
- **Delay-import, TLS, relocation, and rich-header parsing.** The PE support here
  covers headers, sections, imports, exports and resources; ~~these four
  directories are not implemented~~. **Partly closed.** TLS is closed:
  `liebert_re/tools/tls_directory.py` (`analyze_tls_directory`) parses the TLS directory and
  its callback array. **Still open:** delay-import, base-relocation and
  rich-header parsing. (`liebert_re/tools/cpp_rtti.py` reads the base-relocation directory
  internally as a validity check for vtable scanning, but that is a private
  helper, not a relocation parser.) Each remaining one is a bounded,
  well-specified parsing task with public documentation, and any one of the
  three is a reasonable self-contained PR.
- **Data past the end of the last section (the "overlay").** This gap was unrecorded: nothing in the
  package computed the end of the last raw section against the file size, so a PE whose last
  section ends at the file's last byte and one with most of the file past it looked the same.
  **Partly closed.** `pe_trailing_data` (`liebert_re/tools/pe_trailing.py`, CLI `trailing`) reports
  whether trailing data exists, its offset, size and fraction of the file, then labels the part the
  headers explain: an Authenticode certificate table (the security directory holds a file offset,
  so a signed file does not read as unexplained) and a range whose size is consistent with a COFF
  symbol table plus string table (an arithmetic fit from `PointerToSymbolTable` and
  `NumberOfSymbols`, not a decode; a table that does not fit is reported as not fitting). Whatever
  is left is `UNKNOWN` purpose with a size and an entropy number, and the tool does not call it
  benign, malicious, packed or debug data. **Still open:** the symbol and string records are not
  decoded, so "consistent with" is as far as it goes; the certificate is located, not verified
  (see `authenticode_signature`); no other appended-data format (installer or archive
  payloads, CodeView or other debug data, appended resources) is recognised, so those stay
  `UNKNOWN`; and the result does not yet feed `die_*`, `binary_summary` or any report. What it
  explains is worth keeping in mind for a whole class of targets: an unstripped symbol table
  past the last section is a reason a disassembler may hand back named functions.
- **Page-based sliding-window entropy.** What exists today is whole-file and
  per-section entropy, which is enough for coarse triage but not for locating a
  small encrypted or packed region inside an otherwise-normal section. Worth
  doing once someone needs to find where inside a section, not just whether one
  is suspicious.

## Hard problems, honestly hard

- **Kernel static analysis is a staged roadmap and is NOT implemented.** The `windows-kernel` family in
  `liebert_re/report/tool_families.py` names 15 tools, of which two are defined in this package: the generic
  `tool_missing` sentinel and `kernel_triage`, the first slice. `kernel_triage` is a first look only (static
  indicators and a `driver_likelihood` that is never a proof); it does not read dispatch tables, IOCTL codes or
  callback registrations. The other 13 names in the `windows-kernel` family are roadmap: treat them as planned
  routing, not as capability.

These are real and known gaps, named so nobody rediscovers them by surprise. They
are explicitly **not** good first contributions — each is a research problem on
its own, not a bounded task, and starting here is the most common way for a
contribution to stall.

A note on the figures below: the measurements quoted in this section came from
real targets in the upstream tree's private corpus. That corpus is not shipped
here and the targets are not named, so those numbers describe what was observed
upstream; they cannot be reproduced from this repository.

- **Virtualised / VM-based protections.** When a packer replaces native code with
  its own bytecode interpreter, static disassembly of that region produces
  nothing usable, and there is no devirtualiser in this project. On the hardest
  real target this tooling has been measured against (a private-corpus file, not
  included in this repository), roughly 87% of the file
  sat behind such a region and stayed opaque. This is the largest single gap in
  the whole project.
- **Control-flow flattening.** There is no unflattening pass. A flattened
  function is recovered today as a dispatch loop — technically an accurate
  description, practically useless to a reader.
- **Interprocedural taint analysis / whole-program dataflow.** Nothing in this
  project answers "does attacker-controlled input reach this sink" across
  function boundaries. A backward slicer that works inside a single emulation
  trace across a bounded number of hops exists in the upstream tree, is not
  published here, and is not whole-program taint analysis either — it answers a
  much narrower question.
- **Symbolic or concolic execution.** There is no such engine anywhere in this
  project. A constant that is computed at runtime rather than written as an
  immediate typically comes back `UNKNOWN`, which is an honest answer and not a
  useful one.
- **Mobile targets (APK/DEX, Android-specific obfuscators).** ~~No support exists,
  and there is no near-term plan to add it.~~ **Partly closed.** Structural
  support now ships: `liebert_re/tools/dex.py` (DEX header, class and string-pool parse),
  `liebert_re/tools/android.py` (manifest, permission and component inspection of an APK or
  raw AXML, via the optional `androguard` extra (`android`) — see `docs/INSTALL.md`)
  and `liebert_re/tools/jvm.py` (JVM `.class` / `.jar`). Decompiling one named class needs
  the optional JADX tool. **Still open:** none of these disassembles Dalvik
  method bytecode itself, `liebert_re/tools/android.py` does not implement resource-table
  (`resources.arsc`) resolution or signature verification depth (presence and
  identity only), and there is nothing for Android-specific obfuscators. That
  last part remains a hard problem and only makes sense after the
  native/desktop gaps above are addressed.
- **Encrypted-at-rest sections.** Where a section is encrypted on disk and only
  decrypted in memory at runtime, there is no static path to its contents. This
  is a real closed door encountered on a real target (again a private-corpus
  file not shipped here), not a theoretical gap.

## Lessons from the unpublished core

Four things this project actually got wrong while building the parts that are
not in this repository, written generally because the lesson generalises well
beyond this codebase. No line references are given below — the code involved is
in the upstream tree, not here.

**A dependency graph that was built but never consumed.** A planning component
computed a full dependency ordering for a set of steps — a real, correct DAG —
but the function that would have walked that ordering to decide execution
sequence was never called from anywhere. Everything downstream assumed the plan
was driving execution, when in fact a much simpler, unordered path was. The
general lesson: verifying that a plan is followed means finding and reading the
call site that consumes it, not reading the code that produces it. A DAG sitting
in a variable that nothing iterates over is indistinguishable, from the producing
code alone, from one that governs everything.

**A silent `except: pass` around the code that records state.** An error raised
while writing a result to durable storage was being swallowed rather than
surfaced. The practical effect was not a crash — it was quiet, undetected
divergence between what the system believed had happened and what had actually
been persisted, discovered only much later when the two disagreed. The general
lesson: the path that records what happened is the one place in a system where a
swallowed exception is least affordable, because there is no downstream
consumer positioned to notice the gap.

**One logical operation persisted through three separate atomic writes.** Each
individual write was safe on its own, but a crash between the first and the
third left the overall operation in a state that was neither "not started" nor
"complete" — a state nothing else in the system had been designed to reconcile.
Giving each record a content-derived identity prevented a duplicate record from
being created on retry, but a content-addressed identity solves duplicate
*records*, not duplicate or partial *executions*; those are different problems
and require different guarantees.

**A guard that existed, was tested, and was never wired into the path it was
meant to protect.** The check itself was correct in isolation and had its own
passing unit test — but nothing on the live execution path ever imported or
called it, so it protected nothing in practice. This is a specifically dangerous
shape of bug, worse than a guard that was never written at all, because
everyone reviewing the code who sees the guard's definition and its passing test
reasonably assumes it is active. The general lesson: confirm a guard is load-
bearing by finding where it is imported and invoked on the real path, not by
finding where it is defined and tested.

## How to contribute

Open an issue describing what you want to do before writing anything
non-trivial — see [CONTRIBUTING.md](../CONTRIBUTING.md) for what "non-trivial"
means here and what a good pull request looks like. Small, typo-level and
documentation fixes can go straight to a pull request without an issue first.

[DISCLAIMER.md](../DISCLAIMER.md)'s "Out of scope" list still applies in full:
no ready-to-use circumvention of licensing, activation, DRM, or anti-cheat
protection in real, currently distributed products; no undisclosed findings
about a specific third party's protection mechanism; no working exploits or
weaponised payloads; no malware; no third-party binaries or credentials. A
contribution that sits close to one of those lines should start as an issue
describing intent, not as finished code.
