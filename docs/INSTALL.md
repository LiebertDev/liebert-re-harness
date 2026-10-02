# Installing and configuring

## What is in this repository

Only what you need to run and develop the analysis code. Concretely:

- **67 Python modules** in the `liebert_re/` package — the analysis code itself.
- **67 test files** in `tests/`, plus `conftest.py` and an empty `__init__.py`
  (the latter is required so the flat top-level modules resolve on `sys.path`).
- No challenge-solution scripts: they were moved to the `archive/crackme-solutions` branch (see [SOLVED_INDEX.md](../SOLVED_INDEX.md)).
- Documentation, licence, CI configuration, and issue templates.

**Deliberately not here**, so you are not cloning several gigabytes of someone
else's working state:

- No evidence store, no analysis output, no run logs, no session or task state.
- No sample or challenge binaries of any kind — see [CORPUS.md](CORPUS.md) for how
  a write-up identifies the file it analysed instead.
- No decompiler project databases or caches (IDA `.i64`, Ghidra projects). These
  are large, machine-specific, and frequently contain decompiled third-party code.
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
tests marked `heavy` (`pytest.ini` sets `addopts = -m "not heavy"`; 9 test files are
module-marked `heavy`). Run everything with `pytest -m ""`. If `pytest -q` fails on a
fresh clone after the install step, that is a bug worth reporting.

### Python dependencies

Installed automatically: `pefile`, `capstone`, `unicorn`, `keystone-engine`,
`numpy`, `dnfile`, `dncil`, `ijson`, `psutil`, `PyYAML`.

Optional extras: `pip install -e ".[lattice]"` adds `mpmath` (needed by
`liebert_re/tools/lattice.py` / `liebert_re/recover/lll_exact.py`; without it `liebert_re.tools.lattice` returns a structured
`TOOL_MISSING` result and its tests skip). `pip install -e ".[frida]"` — needed only by
`liebert_re/dynamic/frida_trace_client.py`, which is a client for an isolated-VM tracing setup and is
not on the core analysis path.

Some modules import a Python package the repository does **not** declare, neither as
a dependency nor as an extra. Install one yourself if you want the operation it
backs; without it the call returns an error containing the import failure rather
than doing anything: `androguard` (`liebert_re/tools/android.py`), `UnityPy` (`liebert_re/tools/unity.py`),
`dpkt` (`liebert_re/tools/pcap.py`), `py7zr`, `rarfile` and `backports.zstd`
(`liebert_re/tools/archive2.py`).

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
| **rizin** (or radare2) | Disassembly listings, patch planning and application, CRC-32 correction | `RIZIN_HOME` environment variable, else `rizin` on `PATH` |
| **Detect It Easy** | Packer and compiler identification (`diec.exe -j`) | `DIE_HOME`, else `diec` on `PATH` |
| **YARA-X** | Rule-based scanning | `YARA_X_EXE` or `YARA_X_HOME`; rule sets via `YARA_RULESETS_HOME` |
| **API Monitor** | API catalogue lookups (live tracing and trace parsing are both **not** wired up and return `NOT_SUPPORTED` — see the gap list in the README) | `APIMONITOR_HOME` |
| **JADX** | Decompiling one named class from a DEX, APK-derived DEX or JVM `.class` / `.jar` (`liebert_re/tools/dex.py`, `liebert_re/tools/jvm.py`); structural listing works without it and the decompile operation returns `JADX_TOOL_MISSING` | `JADX_EXE`, else `jadx` on `PATH`, else a `teacher-tools/jadx/bin/jadx.bat` under the user's home directory |
| **Il2CppDumper** | Unity IL2CPP type and method name to address mapping (`liebert_re/tools/il2cpp.py`); every operation returns `IL2CPPDUMPER_TOOL_MISSING` without it | `IL2CPPDUMPER_EXE`, else a `teacher-tools/il2cppdumper/Il2CppDumper.exe` under the user's home directory |
| **UPX** | Static UPX unpacking with `upx -d` on a copy of the input (`liebert_re/tools/upx.py`); returns `TOOL_MISSING` without it | `UPX_HOME`, else `upx` on `PATH`, else a `teacher-tools/upx/upx.exe` under the user's home directory |
| **IDA / Ghidra** | Decompilation, cross-references, callers and callees | Wrappers for these live in the upstream tree; this package does not ship them |

Set an environment variable to the tool's install directory, for example:

```bash
# Windows (PowerShell)
$env:RIZIN_HOME = "C:\tools\rizin"
$env:DIE_HOME   = "C:\tools\die"

# Linux / macOS
export RIZIN_HOME=/opt/rizin
export DIE_HOME=/opt/die
```

For rizin, Detect It Easy, YARA-X and API Monitor there are no hardcoded fallback
paths. JADX, Il2CppDumper and UPX are the exception: after their variable and
`PATH`, they also look in one fixed `teacher-tools` folder under your home
directory, and use it if it exists. For the four tools without that fallback, if a
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

Six modules write their own output *outside* this workspace root on purpose:
`liebert_re/tools/binary.py` (`pe_resources`), `liebert_re/tools/die.py`, `liebert_re/tools/capa.py`, `liebert_re/tools/yara_x.py`,
`liebert_re/tools/rizin.py` (`binary_patch`) and `liebert_re/tools/upx.py` each persist their raw
engine output under a module-level `dataset/evidence/<tool_name>/` directory
inside the repository itself, which is git-ignored. The *input* file you pass
in is still confined by `safe_path()` exactly as above; only each tool's own
result is deposited there, under a sanitised, content-hash- or UUID-derived
filename you do not control. See the README's capability table for the same
note next to each tool.

## The heavy test tier

`pytest.ini` excludes tests marked `heavy` by default. In this package those are
the rizin, Detect It Easy, YARA-X and API Monitor wrapper tests (real-tool cases
skip when the tool is absent), Unicorn/Capstone emulation tests, tests that need
corpus files this repository does not ship (they skip when absent), the
`frida_trace_client` tests, and one long pure-Python unpacking test. Some take
minutes rather than seconds. No IDA, Ghidra, angr or virtual-machine test ships
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
