# Benchmarks and solved challenges

This page is the evidence behind the README's claims. Numbers here were counted
from the project's own manifests, not estimated, and where a figure is a
projection rather than a measurement it says so.

## Why a challenge corpus instead of synthetic tests

Unit tests prove a parser handles the input the author thought of. They do not
prove a toolkit can answer a question about a binary somebody else wrote to be
difficult. So correctness is measured against a graded corpus of real, externally
authored challenge binaries, worked from easiest to hardest, and the bar for
"solved" is deliberately awkward:

> **`VERIFIED_SOLVE` requires independently re-deriving or reimplementing the
> answer, with negative controls — not merely detecting it.**

Recognising that a binary compares against the string `S3cr3t` is detection.
Reimplementing the key schedule, producing a valid serial the original program
accepts, and showing that a deliberately wrong input is rejected, is a solve.
Several entries below sit at `PARTIAL_SOLVE` precisely because that distinction
was enforced against our own work.

## Windows Native Ladder — current state

Live count of `benchmarks/windows_native_ladder/manifests/` in the working tree:

| State | Count |
|---|---|
| `VERIFIED_SOLVE` | **85** |
| `PARTIAL_SOLVE` | 12 |
| `UNSAFE_TO_EXECUTE` | 2 |
| `ANALYZED` | 1 |
| `BLOCKED` | 1 |
| **Total manifests** | **101** |

`UNSAFE_TO_EXECUTE` means exactly what it says: the binary was analysed
statically and never run, because running it was judged unsafe. No untrusted
binary is executed to produce a static solve.

### Notable entries, with what made each one hard

- **`WNL-T2-079` — "son_crackme_cubed"** by *SoN* — `VERIFIED_SOLVE`. The serial
  is not present in any string table or literal pool; it is assembled at runtime
  from immediates inside VB6 P-Code. A decoy MD5-shaped string *is* in the literal
  table and was shown to be unreachable. Solving it required decoding P-Code, not
  searching strings.
- **`WNL-T2-091` — "son_crackme_3"** by *son* — `PARTIAL_SOLVE`, and the honest
  label matters. The binary is Upack-packed; emulation-assisted unpacking
  recovered a readable P-Code program (section entropy **7.476 → 5.754**, 99.1%
  bytecode coverage). The intended serial was still not independently derived, so
  it is not a solve. Unpacking succeeded; the challenge did not fall.
- **`WNL-T2-002` — "mutated crackme 5/10"** by *0xbabe* — `VERIFIED_SOLVE`.
- **`WNL-T2-023` — "niko's crack me"** by *niko122* — `ANALYZED` only, kept as a
  deliberately *unpacked* negative control for entropy triage. A corpus with no
  negative controls measures nothing.
- **`WNL-T2-089` — "son_crackme_q"** by *son* — `BLOCKED`.

## Standalone challenges

Each of these was fetched from its author's own page. **The binaries are not
redistributed here** — see [CORPUS.md](CORPUS.md). `crackme_solutions/` holds the
standalone attack scripts.

| Challenge | Author | Source | Status |
|---|---|---|---|
| TryBypassMe Kernel Edition | DeadEye (`DeadEye707`) | [crackmes.one/crackme/69db34d6b38f9259eec7eb32](https://crackmes.one/crackme/69db34d6b38f9259eec7eb32) | **Solved** (see below) |
| Ring0 KeygenMe | rasm | [crackmes.one/crackme/5ab77f5333c5d40ad448c10d](https://crackmes.one/crackme/5ab77f5333c5d40ad448c10d) | Solved |
| ConfuserEx user/pass | bobby77 | [crackmes.one/crackme/613cdf8c33c5d4649c52b9d7](https://crackmes.one/crackme/613cdf8c33c5d4649c52b9d7) | Solved (.NET / ConfuserEx) |
| MCM6 "Project Mayhem" | CrackNotMe | [crackmes.one/crackme/69a95101fbfe0ef21de94652](https://crackmes.one/crackme/69a95101fbfe0ef21de94652) | **Not solved** — commercial-grade packer; automated unpack returned `UNPACKING_FAILED` / `OEP_TIMEOUT` across three attempts |
| Level 1 | Lacks | [crackmes.one/crackme/6a512980234391ae74f63ae8](https://crackmes.one/crackme/6a512980234391ae74f63ae8) | Used as a live dynamic-breakpoint target; solve state not re-confirmed |

Further acquired targets whose solve state has not been re-verified recently, kept
here so the list is not cherry-picked: challenges by *git*, *benladan*, *4epuxa*,
*DosX* (two), *ray33ee*, *hex0rc1st*, *LeSynd1c*, *kaganisildak*, *Piggy63*,
*coderess*, *Fatmike* (two), and *pranav*. Acquisition is not achievement, and
listing them as solved would be exactly the kind of claim this project exists to
avoid.

### TryBypassMe Kernel Edition — the hardest thing solved so far

Author-stated difficulty **6.0/6**, quality 6.0/6. Windows x64, and it ships three
cooperating components: the game, a watchdog process, and a **kernel driver**.

The author's success criterion is specific, and it excludes the easy route:

> Produce a live running trainer with infinite health, ammo, and score, **without**
> triggering the kill switch and **without** crashing — and a solve that strips,
> disables, or unloads the kernel watchdog instead of bypassing it live **does not
> count**.

Result: solved, and confirmed by live play rather than by our own instrumentation.
The patched build (SHA-256 `0A514FA4…F692A`, CRC-32 `0x688ffe38`) runs with ammo
and health not decreasing, the anti-cheat not triggering, and **the kernel watchdog
untouched and still running** — which is the part the author's rule was written to
force. Honest remaining gap: the *score* axis of the author's bar was not
separately confirmed.

Three techniques generalised out of it, and this is the real product of the
exercise:

1. **Patch on disk, do not inject.** The watchdog's detection surface assumed a
   live intruder.
2. **Repairing a whole-file CRC-32 is a closed-form problem over GF(2)**, not a
   search. It is now a reusable `crc_fix` operation rather than a one-off script.
3. **Freeze every consumer of a value, not just the check you are defeating.** The
   generalisable failure mode is patching the comparison a value feeds and missing
   a second reader that then disagrees with the first.

## Harness scale

Live-counted in the private working tree, for context on what the open subset is a
subset *of*:

- **196** callable analysis operations.
- **205** registered tool entries: 128 `READY`, 70 `PARTIAL`, 6 `TOOL_MISSING`,
  1 deferred legacy.
- **2,933** tests collected in the default tier (a further 2,423 deselected as
  `heavy` — meaning they invoke a real external engine or a VM). Last completed
  full run: **2,672 passed, 6 failed, 9 skipped**, 636 subtests, in 4,960 s. The
  six failures were traced to one shared-fixture defect (a module-level tool-budget
  singleton shared across the pytest process) and fixed; **a clean zero-failure
  result is a projection until a full run confirms it**, and saying otherwise would
  be the exact sin this project is organised against.

## External engines: which are really wired

**Scope warning, so this table is not misread.** It describes the **wider private
working tree**, not this package. This repository ships wrappers for **rizin,
Detect It Easy, YARA-X and API Monitor only** — the IDA, Ghidra, capa, FLOSS,
pe-sieve and Frida integrations listed below are *not* in it.
[INSTALL.md](INSTALL.md) is the authority on what this package can actually drive,
and the README lists what is deliberately excluded.

The table is kept because it answers a different and still-useful question: which
integrations are real work and which are a name in a planning document. That
distinction is usually where tool inventories lie.

| Engine | Integration |
|---|---|
| IDA (Professional) | **Real** — `idat.exe -A -S` batch, content-hash-keyed database cache |
| Ghidra | **Real** — `analyzeHeadless`, session-scoped project |
| rizin / radare2 | **Real** — bounded subprocess wrapper |
| Capstone, Unicorn, angr | **Real** — in-process imports |
| capa | **Real** — bundled binary, plus an IDA backend path |
| FLOSS | **Real** — bundled binary; upstream's own 16 MB cap is surfaced rather than hidden |
| Detect It Easy | **Real** — `diec.exe -j` |
| pe-sieve, hollows_hunter, Frida | Real, **but isolated-VM only** by policy — never invoked on the host |
| API Monitor | **Partial** — catalogue works, live trace is an unwired stub |
| Scylla, System Informer, Process Monitor, ExtremeDumper, DriverView, PE-bear, Cutter | **Not implemented** — named in planning docs, no code |

## Measured capability results

Individual numbers worth quoting because each came from a real file, not a fixture:

- **VB6 P-Code decoding: 99.8% / 99.6% / 89.5%** opcode coverage on three real
  challenge binaries. The opcode table was derived from a real `MSVBVM60.DLL` on
  the analysing machine rather than transcribed from a blog post.
- **Emulation-assisted unpacking:** an Upack-class VB6 sample went from unreadable
  to **99.1%** bytecode coverage.
- **Cryptographic constant identification: 21 algorithms**, both endiannesses,
  re-derived from the algorithms themselves rather than copied from a signature
  list.
- **Native Delphi:** 48 classes and 47 parent links recovered from one real binary.
  VMT method-table parsing is still absent — so this is `PARTIAL`, and labelled so.

## Bugs found in our own tooling

Kept public on purpose: a project that only publishes its wins is not measuring
anything.

- **Capstone linear sweep under-decoded by more than 600×** where `skipdata` was
  not set — **769** instructions decoded versus **466,085** on the identical
  section — and the affected tools reported no coverage ratio, so the shortfall
  was silent. This is the failure mode this project cares most about: not a crash,
  a confidently wrong answer.
- A tool returned **non-deterministic results on identical input** across two
  consecutive calls (`FileNotFoundError`, then success).
- A bounded emulation **timeout reported no partial progress** — no instruction
  count, no last address — leaving "stuck" and "slow" indistinguishable.
- A machine-wide survey's first run reported **0%** in a plausible category. The
  zero was the tell: a write-permission test mask had been built from constants
  whose low bits overlap read permissions, so read-only entries matched. **A 0% or
  100% bucket in a plausible category is a bug signal, not a finding.**
