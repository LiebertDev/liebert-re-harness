# Liebert Reverse Engineering Harness

**Reverse-engineering tooling built so that an AI model can actually drive it.**

A language model on its own cannot reverse-engineer a binary. It can talk about
disassembly convincingly, which is worse than being unable to, because the output
looks like analysis and is not grounded in the file. It cannot open IDA, it cannot
run Ghidra headless, it cannot emulate a code range, and when it guesses a section
offset it does not know that it guessed.

This project is the layer that fixes that. It exposes real analysis engines — IDA,
Ghidra, rizin/radare2, Capstone, Unicorn, and the rest of the usual toolbox — as a
set of narrow, typed operations a model can call, each of which either returns a
measured answer or says explicitly that it could not determine one. The model
decides *what* to ask. The harness makes sure the answer comes from the file.

> **Read [DISCLAIMER.md](DISCLAIMER.md) before you use this.** It is dual-use
> tooling: analyse only software you are authorised to analyse. There is no
> warranty, and we accept no liability for misuse — see
> [LICENSE](LICENSE) §§7–8.

---

## The idea in one page

Three things make binary analysis hard to automate, and each has a matching piece
here.

**1. The tools are not callable.** IDA is a GUI with a scripting console; Ghidra
is a Java application with a headless mode and its own project model; rizin is a
shell. None of them accept "tell me every function that references this import"
as a function call with a typed result. The harness wraps each engine so that it
does, normalises their disagreements, and reports which engine produced an answer.
When an engine is not installed, the operation says so by name instead of quietly
degrading.

**2. Wrong answers are indistinguishable from right ones.** This is the real
problem. A parser that returns `0` for a field it failed to read, or falls back to
a heuristic without saying so, produces output that a model will happily build ten
conclusions on. The single rule this codebase is organised around:

> **Never return a confidently wrong answer.** If something could not be
> determined, that is the return value — an explicit `None`, `"UNKNOWN"`, or an
> error. Never a default, never a zero, never the value that happened to be
> nearby. Every fallback path announces itself in the result.

Most of the bugs found in this project have been violations of that rule rather
than crashes, and each one was found because someone downstream trusted a number
that had never been measured. See [CONTRIBUTING.md](CONTRIBUTING.md).

**3. Claims drift from their evidence.** An analysis session produces hundreds of
intermediate results, and by the time they reach a report nobody remembers which
were measured, which were derived, and which were assumed. The harness keeps an
evidence record: results are stored with the input hash and the command that
produced them, and a claim can be traced back to the measurement behind it. A
finding without a traceable measurement is treated as a hypothesis, and labelled
as one.

---

## What is in this repository, and what is not

Honest scoping, because it matters for anyone deciding whether to contribute:

**This repository is the open core** — the general-purpose analysis machinery that
is useful to anyone working on any binary, plus solved-challenge material. It is
a curated subset of a larger private working tree, assembled file by file rather
than exported wholesale, and every file in it has been scanned to ensure it
carries no target-specific analysis of any third party's software.

**Not published here:** analysis of specific commercial products, including
anything identifying a vendor's protection mechanism. That work exists, some of
it is discussed in anonymised form under [Results](#results-so-far), and it stays
out of this repository on purpose — see the out-of-scope list in
[DISCLAIMER.md](DISCLAIMER.md). Harness-internal orchestration (worker dispatch,
task queues, session state) is also omitted; it is specific to how the private
tree is operated and would only be noise here.

What that means practically: **the pieces here run and are tested, but this is not
the complete system.** If you want a capability that is missing, that is the point
of the repository being public.

---

## What it can do today

This table describes **what is in this repository**, module by module — not the
wider tree it came from. What is *not* here is listed immediately after it.

| Area | What works | Module |
|---|---|---|
| **PE / COFF** | Headers, sections with per-section entropy, imports, exports, resource enumeration and extraction, Authenticode signature inspection (Windows), raw byte search, string extraction, hashing | `tools_binary.py` |
| **Disassembly** | Capstone-based disassembly of a PE range | `tools_binary.py` |
| **Symbols and debug data** | CodeView / RSDS record parsing and correlation to a module; MSF/PDB container parsing; detection, build and validation of a PDB toolchain for binaries you own | `codeview_rsds.py`, `msf_pdb.py`, `native_pdb_toolchain.py` |
| **Addressing** | RVA / VA / file-offset normalisation and form resolution — the conversion people get wrong by hand | `pe_address.py` |
| **.NET** | Metadata and IL method-body parsing, inline constants, and relationship extraction across managed assemblies | `dotnet_il.py`, `dotnet_relationships.py` |
| **Crash and memory artefacts** | Minidump parsing and reading memory at a virtual address out of a dump | `minidump_structural.py` |
| **Crypto identification and attacks** | Constant identification for 21 algorithms in both endiannesses, re-derived from the algorithms rather than copied from a signature list; exact LLL lattice reduction and short-vector enumeration; lattice helpers used by the subset-sum attack | `tools_crypto_id.py`, `lll_exact.py`, `tools_lattice.py` |
| **Legacy and niche formats** | VB6 P-Code decoding; an LZMA1 range decoder; ASAR archive parsing; archive, HAR, log, SQLite and general file-identity inspection | `tools_vb6_pcode.py`, `lzma1_range_decoder.py`, `asar_parser.py`, `tools_formats.py` |
| **Instruction-level correctness** | A measured study of VEX/AVX decoding, including the case where a VEX instruction is silently executed as its legacy SSE equivalent and the answer is simply wrong | `vex.py` |
| **Comparison and verification** | Version diffing between two builds; cross-binary relationship building; verifying that a named constant really is at a claimed address | `binary_version_diff.py`, `cross_binary_relationships.py`, `constant_at_address_verifier.py` |
| **Findings and IR** | A stable analysis IR with stable ids, security-hypothesis construction, counter-evidence verification, finding validation and rendering, and validation planning | `analysis_ir.py`, `analysis_findings.py`, `exploit_validation.py` |
| **Evidence layer** | Content-hash-keyed result storage, claim indexing, a guard against claims unsupported by evidence, provenance records, and workspace indexing | `evidence_index.py`, `evidence_security.py`, `claim_index.py`, `claim_guard.py`, `workspace_index.py` |
| **Engine wrappers that ship here** | rizin (disassembly listings, patch planning and application, closed-form CRC-32 correction), Detect It Easy, YARA-X, API Monitor catalogue | `tools_rizin.py`, `tools_die.py`, `tools_yara_x.py`, `tools_apimonitor.py` |
| **Execution plumbing** | Bounded subprocess execution with process-tree teardown, cross-process locking, and the workspace sandbox that confines file access | `bounded_subprocess.py`, `process_lock.py`, `tools_workspace.py` |

### In the wider tree, deliberately **not** in this repository

Named explicitly, because a capability list that quietly includes things you cannot
import is the exact failure this project is organised against:

- **Bounded emulation** (Unicorn-based range emulation, execution traces, the
  backward slicer, per-instruction byte snapshots, register capture). Not here. This
  is why `crackme_solutions/scripts_mutated_crackme5_serial.py` is
  documentation-only.
- **IDA and Ghidra wrappers** (headless decompilation, cross-references,
  callers/callees, normalised across engines). Not here — `docs/INSTALL.md` is the
  authority on which engines this package can actually drive, and it lists rizin,
  Detect It Easy, YARA-X and API Monitor.
- **Function-boundary recovery from exception-directory unwind data**, prologue
  scanning, and engine cross-check. Not here.
- **Crash symbolisation.** Minidump *parsing* is here; turning an address into a
  symbol is not.
- **Delay imports, TLS, relocation and rich-header parsing.** The PE work here
  covers headers, sections, imports, exports and resources; those four directories
  are not implemented.
- **Sliding-window entropy** per page. What ships is whole-file and per-section
  entropy, which is enough for triage and is not the same thing.

Several of these are good contributions, and the first two are large enough to be
somebody's main one.

## What it cannot do — read this before proposing work

Stated plainly, because a capability list without this section is marketing:

- **Virtualised / VM-based protections.** When a packer replaces native code with
  its own bytecode interpreter, static disassembly of that region produces
  nothing, and this project has no devirtualiser. On the hardest target attempted
  so far, roughly **87% of the file** sat in such a region and stayed opaque. This
  is the single biggest gap.
- **Control-flow flattening.** No unflattening pass. Flattened functions are
  recovered as a dispatch loop, which is technically correct and practically
  useless.
- **Interprocedural taint / full dataflow.** There is no whole-program taint
  analysis anywhere in the project, so "does attacker input reach this sink" is
  answered by hand today. (The wider tree has a backward slicer that works inside
  an emulation trace across a bounded set of hops; it is not in this repository, and
  it is not whole-program taint either.)
- **Symbolic execution.** No symbolic or concolic engine. Constants that are
  computed rather than written as immediates frequently come back `UNKNOWN`, which
  is honest but is not an answer.
- **Obfuscated import resolution.** A binary that resolves its imports at runtime
  through its own mechanism, leaving nothing in the import table, defeats static
  import recovery here. It has been *observed* that this happens; the mechanism
  has not been recovered.
- **Mobile targets.** No APK/DEX support, and none planned soon.
- **Decryption of packed sections at rest.** Where a section is encrypted on disk
  and only decrypted in memory, there is no static path to its contents.
- **Automated exploitation of anything.** The project measures and explains; it
  does not build payloads. See [DISCLAIMER.md](DISCLAIMER.md).

If you want to close one of these, open a proposal issue — several are large
enough to be somebody's main contribution.

---

## Results so far

Full detail, with every challenge named and linked to its author's page:
**[docs/BENCHMARKS.md](docs/BENCHMARKS.md)**. Summary below.

### The crackme ladder

Correctness is measured against a graded corpus of real, externally authored
challenge binaries rather than synthetic tests, because a unit test only proves a
parser handles the input its author thought of. **101 challenges: 85
`VERIFIED_SOLVE`, 12 `PARTIAL_SOLVE`, 2 `UNSAFE_TO_EXECUTE`, 1 `ANALYZED`, 1
`BLOCKED`.**

The bar is deliberately awkward:

> `VERIFIED_SOLVE` requires independently **re-deriving or reimplementing** the
> answer, with negative controls — not merely detecting it.

Noticing that a binary compares against `S3cr3t` is detection. Reimplementing the
key schedule, producing a serial the program accepts, and showing a wrong input is
rejected, is a solve. Several entries sit at `PARTIAL_SOLVE` precisely because that
line was enforced against our own work — one binary was successfully unpacked from
entropy 7.476 to 5.754 with 99.1% bytecode coverage, and is *still* not counted as
solved because the intended serial was never derived.

The hardest one solved so far is **TryBypassMe Kernel Edition** by *DeadEye*
([crackmes.one](https://crackmes.one/crackme/69db34d6b38f9259eec7eb32),
author-rated 6.0/6), which ships a game, a watchdog process and a **kernel
driver**, and whose author explicitly ruled out the easy path: a solve that
disables or unloads the kernel watchdog does not count. It was solved with the
watchdog untouched and still running, confirmed by live play. The score axis of the
author's stated bar was not separately confirmed, and that is recorded as an open
gap rather than rounded up.

`crackme_solutions/` holds the standalone attack scripts from this work — a SipHash
key-recovery attack, a Lagarias–Odlyzko lattice attack, a meet-in-the-middle
search, a VB6 P-Code interpreter. They read on their own and are the best
introduction to how the toolkit is actually used.

Per [docs/CORPUS.md](docs/CORPUS.md), the binaries themselves are **not**
redistributed. Each write-up names its challenge, its author, where it was
published, and the SHA-256 of the exact file analysed, so you can fetch the same
one and check the work. Where an author set rules — keygen only, no patching — the
solution is judged against the author's rule, not ours.

### A hard target, described without naming it

The harness's limits were established against a commercial **kernel-mode
anti-cheat driver and its privileged user-mode service** on Windows. The vendor is
deliberately not named, no addresses or identifiers are published, and none of
that analysis is in this repository — what follows is only what it taught us about
the *tooling*, which is the part worth sharing.

**What the harness could do:**

- Recover the full function inventory — over **125,000 function boundaries** —
  from a binary whose section table advertised a decoy exception directory, by
  finding the real one elsewhere and validating that the recovered ranges
  disassembled as valid code.
- Separate encrypted regions from merely compressed ones by per-window entropy,
  and prove that a specific call site was **absent** from every section it could
  have been in — a clean negative, which is a result rather than a failure.
- Measure a live privileged service's object security at kernel level rather than
  inferring it from API return values, and catch a case where the Win32 layer
  reported success while the kernel had silently removed part of the requested
  access.
- Establish scale before calling a finding severe: a machine-wide survey showed a
  permission pattern that looked alarming in isolation was shared by **31%** of
  comparable objects on the same system. That measurement downgraded our own
  headline claim, which is exactly what it was for.

**What it could not do, and why that matters more:**

- The majority of the target's code was virtualised. No devirtualiser, no
  progress — the single hardest blocker, listed above.
- One binary's code section was encrypted at rest, and the runtime image was
  unreadable because the driver stripped the access rights needed to read it. Both
  routes closed, proven closed rather than abandoned — but closed.
- A published third-party analysis of a *different build* of the same product was
  tested against ours claim by claim: **five of seven claims did not hold**, and
  did not hold either after correcting for a measured address delta. Useful
  lesson, and a reminder that in this field a document without a file hash is a
  hypothesis.

Three of our own conclusions were withdrawn during that work after further
measurement contradicted them. That is recorded here deliberately: a harness whose
findings never get retracted is a harness nobody is checking.

### Scale, and bugs found in our own tooling

For context on what the open subset is a subset *of*: the private working tree has
**196** callable analysis operations across **205** registered tool entries (128
`READY`, 70 `PARTIAL`, 6 with the external tool missing), and **2,933** tests in the
default tier plus 2,423 more marked `heavy` because they invoke a real engine or a
VM. The last completed full run was **2,909 passed / 6 failed / 18 skipped** —
stated with the failures included, because the previous entry in this file said "0
failed, projected" and the projection turned out to be wrong.

[docs/BENCHMARKS.md](docs/BENCHMARKS.md) also lists defects found in *our own*
tools, which is the part most inventories omit. The one worth repeating here:

> Capstone's linear sweep silently under-decoded by more than **600×** where
> `skipdata` was unset — **769** instructions versus **466,085** on the identical
> section — and the affected tools reported no coverage ratio, so nothing announced
> the shortfall.

That is the exact failure mode this project is organised against: not a crash, a
confidently wrong answer. If you are looking for a first contribution, auditing a
tool for that shape of bug is more valuable than adding a feature.

---

## Getting started

```bash
git clone https://github.com/LiebertDev/liebert-re-harness.git
cd liebert-re-harness
python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Python 3.10 or newer. On a clean checkout with **no external analysis tool
installed**, the measured result is `190 passed, 35 skipped`, zero failures, in
about 11 seconds — across 35 test files. The skips are guards for tests needing a
sample binary this package does not ship.

That measurement is **on Windows** (3.10 and 3.12), which is where this code was
developed and where the analysis focus points.

**Linux does not fully pass yet, and the first CI run is how we found out.** Two
tests fail on `ubuntu-latest`, and both are real bugs in this package rather than CI
noise — so they are named here instead of being softened:

1. **The workspace sandbox does not hold on POSIX paths.** A destination outside the
   workspace root is supposed to be refused and is not
   (`tests/test_tools_archive_extract.py::test_dest_path_outside_workspace_is_path_refused`).
   This is the containment control described below and in `docs/INSTALL.md`, so on
   Linux you should treat it as absent until this is fixed.
2. **`bounded_subprocess` does not tear down a process tree on Linux.** An orphaned
   grandchild holding a pipe open survives the timeout instead of being killed
   (`tests/test_bounded_subprocess_orphan_timeout.py`), so the module's bounded-
   execution contract is not met there.

Both are tracked as issues and are good first contributions. The Linux CI leg is
marked non-blocking so its result stays visible while they are open — not hidden, and
not left to redden the whole build indefinitely. Everything else passes on Linux:
181 passed, 42 skipped.

Every external engine is **optional**; nothing here ships or requires a licensed
tool, and the IDA and Ghidra wrappers are not part of this package at all. **[docs/INSTALL.md](docs/INSTALL.md)** lists exactly
what each one unlocks, the environment variable that locates it, what is *not* in
this repository and why, and the workspace sandbox you will meet on your first call.

### It looks like this

Plain Python functions. Each returns a result that says what it measured, and says
so explicitly when it could not.

```python
>>> import tools_formats
>>> print(tools_formats.file_identity("README.md"))
{
  "ok": true,
  "path": "README.md",
  "extension": ".md",
  "size_bytes": 15839,
  "sha256": "3abf0baf4497fe8fda68aaf7e79a6d21b735685fe73d1e0d054d776935bbb766",
  "text": true,
  "container": null,
  "type": "TEXT",
  "subtype": null,
  "architecture": null,
  "endianness": null,
  ...
}
```

Note the shape: `architecture` and `endianness` are `null` because this is a text
file and there is nothing to measure — not `"unknown"`, not `"x86"` as a default.
That is the whole design in one output.

Some operations are pure computation with no engine behind them at all — this is
the lattice reduction the knapsack attack in `crackme_solutions/` is built on:

```python
>>> import lll_exact
>>> lll_exact.lll_reduce([[1, 0, 0, 12345],
...                       [0, 1, 0, 23456],
...                       [0, 0, 1, 34567]])
[[1, -2, 1, 0], [-12, -4, 7, 5], [-326, -79, 170, -1104]]
```

The first vector is short and its last coordinate is `0` — which, for a subset-sum
key check, is the answer falling out of the lattice rather than out of a search.

**One thing to know before your first call on a real file:** file access is confined
to a workspace root (`TEACHER_WORKSPACE`, defaulting to the repository directory),
and paths outside it are refused. That is deliberate for code that reads hostile
input; [docs/INSTALL.md](docs/INSTALL.md) explains how to point it at your samples.

Samples are not included and never will be. See
[docs/CORPUS.md](docs/CORPUS.md) for how write-ups identify the file they analysed
and how to build test fixtures in code instead of committing binaries.

## Contributing

Genuinely wanted — that is why this repository exists. Start with
[CONTRIBUTING.md](CONTRIBUTING.md), which is mostly about the one rule above, and
with the gap list, which is where the interesting work is. Open a proposal issue
before writing anything substantial; small fixes can come straight in.

By contributing you agree your work is licensed under Apache-2.0. There is no CLA.

## Licence and legal

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

**[DISCLAIMER.md](DISCLAIMER.md) is not boilerplate; it is the condition of use.**
No warranty, no liability, authorised targets only, and an explicit list of
contributions that will be declined regardless of quality. Security issues in the
toolkit itself go through [SECURITY.md](SECURITY.md) — privately, not in an issue.
