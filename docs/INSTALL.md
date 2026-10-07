# Installing and configuring

## What is in this repository

Only what you need to run and develop the analysis code. Concretely:

- **73<!-- count:modules --> Python modules** in the `liebert_re/` package — the analysis code itself.
- **111<!-- count:test_files --> test files** in `tests/` (`tests/test_*.py`), plus `conftest.py` and an empty `__init__.py`
  (the latter is required so the flat top-level modules resolve on `sys.path`).
- No challenge-solution scripts: they are not distributed in this public package (see [SOLVED_INDEX.md](../SOLVED_INDEX.md) for the record of what was solved).
- Documentation, licence, CI configuration, and issue templates.

**Deliberately not here**, so you are not cloning several gigabytes of someone
else's working state:

- No evidence store, no analysis output, no run logs, no session or task state.
- No sample or challenge binaries of any kind — see [CORPUS.md](CORPUS.md) for how
  a write-up identifies the file it analysed instead.
- No decompiler project databases or caches (IDA `.i64`, Ghidra projects). These
  are large, machine-specific, and frequently contain decompiled third-party code.
  The IDA wrapper builds its own cache locally under `dataset/ida_cache/` (git-ignored,
  and CI rejects a committed `.i64` / `.idb`).
- No orchestration internals from the upstream development tree — worker dispatch,
  queues, session bookkeeping. They are specific to how that tree is operated and
  would only be noise here.

Two mechanical guards keep it that way rather than relying on review attention:
`.gitignore` excludes sample and output directories and the usual executable
extensions, and **CI fails the build if a binary sample is ever committed**.

## Install

```bash
git clone https://github.com/LiebertDev/liebert-re-harness.git
cd liebert-re-harness
python -m venv .venv
# Windows:        .venv\Scripts\activate
# Linux / macOS:  source .venv/bin/activate
pip install -e ".[dev,lattice]"
pytest -q
```

Python **3.10 or newer**.

Expected result: `pytest -q` exits 0. Some tests skip unless optional dependencies
(such as the `lattice` extra) or sample binaries are present; `pytest -rs` lists each
skip and its reason. No pass/skip tally is promised. The default run also excludes
tests marked `heavy` (`pytest.ini` sets `addopts = -m "not heavy"`; the marker is
applied per test, per class or, in one file, to the whole module). Run everything with `pytest -m ""`. If `pytest -q` fails on a
fresh clone after the install step, that is a bug worth reporting.

### Pre-push gate (contributors)

`.git/hooks/` is not part of the repository, so every clone installs the gate itself, with the
venv's interpreter: `.venv/Scripts/python.exe scripts/pre_push_gate.py install` (Windows) or
`.venv/bin/python scripts/pre_push_gate.py install` (Linux / macOS). The hook records that
interpreter's path and blocks the push with an explicit error if it later goes missing (recreate
the venv, then re-run `install --force`). The gate also blocks when pytest prints a fatal-exception
report ("Windows fatal exception", "Fatal Python error") even though its exit code is 0.
`python scripts/pre_push_gate.py --check` says whether the hook is installed.

The gate has four stages: discipline test, default suite, contract tests, commit-message identity
probes. The contract stage runs `pytest -m contract` (error-path tests: a wrapper never raises and
returns an honest status) on every CI-matrix Python it finds (3.10, 3.12, 3.14), because stdlib
exception behaviour differs between versions. It looks in `LIEBERT_CONTRACT_PYTHONS` (interpreter paths
separated by `os.pathsep`), then the venvs under `~/.liebert-venvs` (`LIEBERT_VENV_DIR` overrides the
directory; each needs `pip install -e ".[dev,lattice]"`), then the repo's `.venv*`, then the running
interpreter. A version that is not found prints "DID NOT RUN" and the push is NOT blocked, so a fresh
clone does not need three venvs; CI runs the contract tests on all legs. `LIEBERT_CONTRACT_STRICT=1`
turns a missing version into a block. A red test on a found interpreter always blocks and names it.

### Python dependencies

Installed automatically: `pefile`, `capstone`, `unicorn`, `keystone-engine`,
`numpy`, `dnfile`, `dncil`, `ijson`, `psutil`, `PyYAML`.

Optional extras: `pip install -e ".[lattice]"` adds `mpmath` (needed by
`liebert_re/tools/lattice.py` / `liebert_re/recover/lll_exact.py`; without it `liebert_re.tools.lattice` returns a structured
`TOOL_MISSING` result and its tests skip). `pip install -e ".[frida]"` — needed only by
`liebert_re/dynamic/frida_trace_client.py`, which is a client for an isolated-VM tracing setup and is
not on the core analysis path.

Format wrappers that need a third-party Python package declare it as an optional extra, never as
a core dependency. Without the extra, the call returns `ok: false` with `status: "TOOL_MISSING"`,
`missing_dependency` naming the package, `required_capability` with the install command and a
`detail` saying the input was not examined. It is never reported as a parse error, because the
file was never read:

| Extra | Package | Module |
| --- | --- | --- |
| `unity` | `UnityPy` (held to `>=1.25.4,<1.26`: its README warns of breaking changes between releases) | `liebert_re/tools/unity.py` |
| `android` | `androguard`, `loguru` | `liebert_re/tools/android.py` |
| `pcap` | `dpkt` | `liebert_re/tools/pcap.py` |
| `7z`, `rar`, `zstd` (or `archive` for all three) | `py7zr`, `rarfile`, `backports.zstd` | `liebert_re/tools/archive2.py` |

`loguru` is only used to silence androguard's logger; androguard already depends on it, and
`android.py` ignores a failed `loguru` import. zstd uses the standard library's `compression.zstd` on Python 3.14 or newer, where the `zstd` extra
installs nothing and is not needed; `backports.zstd` (published for Python below 3.14 only) is the
fallback on older interpreters, and the zstd path of `rar_7z` returns `TOOL_MISSING` only when neither is importable. gzip, bzip2 and xz use the standard library and need none of these.

## External applications — all optional

**None of these are required.** The core analysis (PE parsing,
entropy, .NET IL, the crypto attacks) runs on the
Python dependencies alone. Function inventory (`rizin_functions`) needs rizin, and no
range emulation ships — Unicorn is imported only by the VEX self-check in
`liebert_re/recover/vex.py`. Each external tool unlocks additional operations, and
when one is absent the relevant call returns an explicit "tool missing" result
naming it — it does not silently degrade or guess.

| Application | What it unlocks here | How it is found |
|---|---|---|
| **rizin** (or radare2) | Disassembly listings, patch planning and application, CRC-32 correction, `rz-bin` imports, sections, header fields and relocations, and FLIRT signature matching (the bundled sigdb needs no extra files) (`rz-bin.exe` sits next to `rizin.exe`, in the install root or its `bin` folder) | `RIZIN_HOME` environment variable, else `rizin` / `rz-bin` on `PATH` |
| **Detect It Easy** | Packer and compiler identification (`diec.exe -j`) | `DIE_HOME`, else `diec` on `PATH` |
| **pe-sieve** (0.4.1.1 measured) | Scan of ONE running process, by PID, for in-memory differences from disk (`pe_sieve_scan`, `liebert-re sieve --pid N`); scan only, nothing is dumped, no all-processes mode. Runs only behind the dynamic-lab gate (`LIEBERT_RE_DYNAMIC_LAB=authorized`, `--authorization`, `--sample-sha256`, a process this harness started; see `docs/CAPABILITIES_AND_LIMITS.md`). Needs a process you started; an elevated or protected one may be refused as `ACCESS_DENIED`. Do not call it from Git Bash without `MSYS_NO_PATHCONV=1` (the wrapper itself spawns it directly and echoes the argument vector) | `PE_SIEVE_HOME` (directory or file), else `pe-sieve64` on `PATH`, else `C:\Tools\pe-sieve`; the 64-bit scanner is used whenever present |
| **YARA-X** | Rule-based scanning | `YARA_X_EXE` or `YARA_X_HOME`; rule sets via `YARA_RULESETS_HOME` |
| **API Monitor** | API catalogue lookups (live tracing and trace parsing are both **not** wired up and return `NOT_SUPPORTED` — see the gap list in the README) | `APIMONITOR_HOME` |
| **JADX** | Decompiling one named class from a DEX, APK-derived DEX or JVM `.class` / `.jar` (`liebert_re/tools/dex.py`, `liebert_re/tools/jvm.py`); structural listing works without it and the decompile operation returns `JADX_TOOL_MISSING` | `JADX_EXE`, else `jadx` on `PATH`, else a `teacher-tools/jadx/bin/jadx.bat` under the user's home directory |
| **Il2CppDumper** | Unity IL2CPP type and method name to address mapping (`liebert_re/tools/il2cpp.py`); every operation returns `IL2CPPDUMPER_TOOL_MISSING` without it | `IL2CPPDUMPER_EXE`, else a `teacher-tools/il2cppdumper/Il2CppDumper.exe` under the user's home directory |
| **UPX** | Static UPX unpacking with `upx -d` on a copy of the input (`liebert_re/tools/upx.py`); returns `TOOL_MISSING` without it | `UPX_HOME`, else `upx` on `PATH`, else a `teacher-tools/upx/upx.exe` under the user's home directory |
| **IDA Pro 9.x** (licensed, with the Hex-Rays decompiler for `decompile_function`) | Headless queries through `idat -A` (reads, plus a plan-then-apply annotation write path): summary, function list, segments, function-at-address, pseudocode, cross-references, imports/exports, strings, and one function's microcode as a graph (`ida_microcode_cfg`; raw by default, with an opt-in d810 pass that needs the third-party d810 package in IDA's Python and says so in the answer) (`liebert_re/tools/ida.py`); returns `TOOL_MISSING` without it. also `ida_type_member_offset`, a patch *plan* (`ida_patch_plan`) and a read of the annotation log (`ida_annotations`, which needs no IDA). Persistent renames and comments: `ida_rename_plan` or `ida_set_comments_plan` then `ida_annotations_apply` (annotated data in its own root, byte ceiling `LIEBERT_IDA_ANNOTATED_BYTES`, default 2 GiB). Not wrapped: a disassembly listing, decompiler comments | `IDAT_EXE` (file or folder), else `IDA_HOME`, else `idat` on `PATH`, else the installer's default `IDA Professional 9*` / `IDA Pro 9*` folder under Program Files. Cache size cap: `LIEBERT_IDA_CACHE_BYTES` (default 5 GiB) |
| **Ghidra** | Decompilation, cross-references, callers and callees | Slice 1 ships (`liebert_re/tools/ghidra.py`): `ghidra_status` and `ghidra_program_facts` (loader, language, processor, endianness, address width, compiler spec, image base, entry points, memory blocks, function count). No decompilation or cross-references yet. `analyzeHeadless` exits 0 even when its post-script fails, so success is judged from the log and the result file. Java script only (Jython does not run on a stock install). Not wired to the CLI. Located by `GHIDRA_INSTALL_DIR`, else `GHIDRA_HOME`, else `PATH`, else known install folders |

Set an environment variable to the tool's install directory, for example:

```bash
# Windows (PowerShell)
$env:RIZIN_HOME = "C:\tools\rizin"
$env:DIE_HOME   = "C:\tools\die"
$env:IDA_HOME   = "C:\Program Files\IDA Professional 9.4"

# Linux / macOS
export RIZIN_HOME=/opt/rizin
export DIE_HOME=/opt/die
export IDA_HOME=/opt/ida   # not verified on Linux: only a Windows install was run
```

For rizin, Detect It Easy, YARA-X and API Monitor there are no hardcoded fallback
paths. IDA checks only the installer's default folder under Program Files, never a home
directory. JADX, Il2CppDumper and UPX are the exception: after their variable and
`PATH`, they also look in one fixed `teacher-tools` folder under your home
directory, and use it if it exists. For the tools without a fixed fallback, if a
variable is unset and the tool is not on `PATH`, the operation reports the tool as
missing rather than trying a guessed location — a guessed path that happens to exist on somebody else's machine is
exactly the class of silent wrong answer this project refuses.

## The workspace sandbox — read this before your first call

`liebert_re.workspace.safe_path()` confines file access to a single workspace root.
Anything outside it is refused with a `PermissionError`, including absolute paths
to system files. This is deliberate: analysis code is pointed at hostile input for
a living, and the default should not be "can open anything on the machine".

The root is the value of **`TEACHER_WORKSPACE`** if set, otherwise the current working
directory (`Path.cwd()`). (The variable name is a legacy of the upstream project's earlier name
and is kept for compatibility.) So:

```bash
export TEACHER_WORKSPACE=/path/to/your/samples   # then analyse files under it
```

If a call fails with a permission error on a path that plainly exists, this is
almost always why. It is also worth knowing when writing tests: a fixture in a
system temp directory is outside the workspace unless you repoint the root, and
one test file in the upstream tree failed for exactly that reason until it was
fixed.

Several modules write their own output *outside* this workspace root on purpose
(the measured count and the full list are in the README, under the capability table);
for example `liebert_re/tools/binary.py` (`pe_resources`), `liebert_re/tools/die.py`, `liebert_re/tools/capa.py`, `liebert_re/tools/ida.py`, `liebert_re/tools/pe_sieve.py`, `liebert_re/tools/yara_x.py`,
`liebert_re/tools/rizin.py` (`binary_patch`, the `rz-bin` reads and the FLIRT runs) and `liebert_re/tools/upx.py` each persist their raw
engine output under a module-level `dataset/evidence/<tool_name>/` directory
inside the repository itself, which is git-ignored. The *input* file you pass
in is still confined by `safe_path()` exactly as above; only each tool's own
result is deposited there, under a sanitised, content-hash- or UUID-derived
filename you do not control. See the README's capability table for the same
note next to each tool. `liebert_re/tools/ida.py` also keeps its analysis-database cache there,
under `dataset/ida_cache/<sha256-of-input>.<profile>/`: it is capped (`LIEBERT_IDA_CACHE_BYTES`,
default 5 GiB, least-recently-used whole-slot eviction), keyed by the input file's content,
and safe to delete.

## What the IDA wrapper does on your machine

`ida_query` runs `idat -A` (headless, no dialogs) in a bounded subprocess; it needs a licensed IDA Pro
9.x and returns `TOOL_MISSING` without one. `ida_status` launches idat once on an empty database
(about a second) so "available" means "started headless and exited cleanly", and reports the version and
whether the decompiler initialises.

- **First call on a file** analyses it (two idat sessions: analyse-and-save, then your question) and
  stores the database under `dataset/ida_cache/`. Later calls reopen it. The timeout is one budget,
  clamped to 5-600 s (default 180): the first analysis may use all of it, the session that answers
  your question never runs longer than 300 s. A timed-out analysis is thrown away rather than
  half-cached, and is reported as a timeout, not as an empty result.
- **Symbol-server lookups are off.** Left on, IDA downloads PDBs from a public symbol server during
  analysis and writes them under your temp directory, which makes results depend on the network and
  tells a third party which file you analysed. Every launch passes `-Opdb:off`. The consequence: symbols
  from a PDB are not loaded, even a local one.
- **Your files are not modified.** The input is only read; the cache holds IDA's own database.
- **What is returned is scrubbed.** Anything from IDA's log that reaches a result (failure tails) has the
  licence line, home-directory paths, and the input and scratch paths replaced.
- Not shipped: a disassembly listing and decompiler comments. Only IDA 9.x is supported (IDA 9 has a
  single `idat`; there is no `idat64`).

## The heavy test tier

`pytest.ini` excludes tests marked `heavy` by default. In this package those are
the rizin, Detect It Easy, YARA-X, API Monitor and IDA wrapper tests (real-tool cases
skip when the tool is absent), Unicorn/Capstone emulation tests, tests that need
corpus files this repository does not ship (they skip when absent), the
`frida_trace_client` tests, and one long pure-Python unpacking test. Some take
minutes rather than seconds. The IDA real-install class needs a licensed IDA Pro 9.x; it analyses
a tiny synthetic PE that the test builds itself. No Ghidra, angr or virtual-machine test ships
here. Once you have the tools configured:

```bash
pytest -m heavy
```

An explicit `-m` on the command line replaces the ini's marker filter rather than
combining with it.

## Platform notes

Development and measurement have been on **Windows x64** (Python 3.10 and 3.12,
both run in CI, on Linux and Windows), and the analysis focus — PE/COFF, VB6, .NET on
Windows — reflects that.

The first Linux CI run found two real defects, both now fixed
([#1](https://github.com/LiebertDev/liebert-re-harness/issues/1),
[#2](https://github.com/LiebertDev/liebert-re-harness/issues/2)). The one that
concerns the sandbox above is worth stating precisely, because an earlier version of
this page overstated it:

- **What was broken:** `safe_path()` tested containment with
  `pathlib.Path.is_absolute()`. On POSIX a backslash is not a separator, so
  `C:\Windows\evil.txt` parses as one ordinary *filename*, is joined inside the
  workspace root, and passes the containment check without raising.
- **What was NOT broken:** containment itself. The write still landed inside the
  workspace. The bug was failing to *refuse* an obviously foreign path — wrong and
  worth fixing, but not an escape. The earlier "do not rely on the containment"
  wording was too strong and is withdrawn.
- **Symlinks** were checked at the same time and were already correct: `resolve()`
  follows the link before containment is tested, so a link inside the workspace
  pointing outside it was already refused. It now has a regression test.

None of that changes the standing advice: analyse untrusted input in a disposable VM.
The sandbox is a guardrail against mistakes, not a containment boundary for hostile
code, and that was true before these fixes too.

A Linux contributor should expect Windows-shaped test data in places, and should say
so in a pull request when something is genuinely platform-broken rather than merely
untested.
