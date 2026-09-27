# Installing and configuring

## What is in this repository

Only what you need to run and develop the analysis code. Concretely:

- **35 Python modules** at the repository root — the analysis code itself.
- **35 test files** in `tests/`, plus `conftest.py` and an empty `__init__.py`
  (the latter is required so the flat top-level modules resolve on `sys.path`).
- **11 standalone challenge-solution scripts** in `crackme_solutions/`.
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
pip install -e ".[dev]"
pytest -q
```

Python **3.10 or newer**.

Expected result on a clean checkout with **no external analysis tool installed**:

```
190 passed, 35 skipped
```

The 35 skips are `skipUnless` guards for tests that need a sample binary this
package correctly does not ship. **Zero failures is the expected state** — if you
see a failure on a fresh clone, that is a bug worth reporting.

### Python dependencies

Installed automatically: `pefile`, `capstone`, `unicorn`, `keystone-engine`,
`numpy`, `mpmath`, `dnfile`, `dncil`, `ijson`, `psutil`, `PyYAML`.

One optional extra: `pip install -e ".[frida]"` — needed only by
`frida_trace_client.py`, which is a client for an isolated-VM tracing setup and is
not on the core analysis path.

## External applications — all optional

**None of these are required.** The core analysis (PE parsing, function inventory,
entropy, .NET IL, emulation, the crypto attacks, the crackme scripts) runs on the
Python dependencies alone. Each external tool unlocks additional operations, and
when one is absent the relevant call returns an explicit "tool missing" result
naming it — it does not silently degrade or guess.

| Application | What it unlocks here | How it is found |
|---|---|---|
| **rizin** (or radare2) | Disassembly listings, patch planning and application, CRC-32 correction | `RIZIN_HOME` environment variable, else `rizin` on `PATH` |
| **Detect It Easy** | Packer and compiler identification (`diec.exe -j`) | `DIE_HOME`, else `diec` on `PATH` |
| **YARA-X** | Rule-based scanning | `YARA_X_EXE` or `YARA_X_HOME`; rule sets via `YARA_RULESETS_HOME` |
| **API Monitor** | API catalogue lookups (live tracing is **not** wired up — see the gap list in the README) | `APIMONITOR_HOME` |
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

There are no hardcoded fallback paths. If a variable is unset and the tool is not
on `PATH`, the operation reports the tool as missing rather than trying a guessed
location — a guessed path that happens to exist on somebody else's machine is
exactly the class of silent wrong answer this project refuses.

## The workspace sandbox — read this before your first call

`tools_workspace.safe_path()` confines file access to a single workspace root.
Anything outside it is refused with a `PermissionError`, including absolute paths
to system files. This is deliberate: analysis code is pointed at hostile input for
a living, and the default should not be "can open anything on the machine".

The root is the value of **`TEACHER_WORKSPACE`** if set, otherwise the repository
directory. (The variable name is a legacy of the upstream project's earlier name
and is kept for compatibility.) So:

```bash
export TEACHER_WORKSPACE=/path/to/your/samples   # then analyse files under it
```

If a call fails with a permission error on a path that plainly exists, this is
almost always why. It is also worth knowing when writing tests: a fixture in a
system temp directory is outside the workspace unless you repoint the root, and
one test file in the upstream tree failed for exactly that reason until it was
fixed.

## The heavy test tier

`pytest.ini` excludes tests marked `heavy` by default. Those invoke a real
external engine or a virtual machine, take minutes rather than seconds, and can
hang if the tool itself misbehaves. Once you have engines configured:

```bash
pytest -m heavy
```

An explicit `-m` on the command line replaces the ini's marker filter rather than
combining with it.

## Platform notes

Development and measurement have been on **Windows x64** (Python 3.10 and 3.12,
both green: 190 passed, 35 skipped), and the analysis focus — PE/COFF, VB6, .NET on
Windows — reflects that.

**On Linux, two tests fail, and both are genuine defects in this package.** CI runs
the suite on `ubuntu-latest` and found them on the first run; they are named rather
than glossed:

1. **The workspace sandbox above does not hold on POSIX paths.** An out-of-tree
   destination is not refused. So on Linux, **do not rely on the containment
   described in the previous section** — analyse untrusted input in a disposable VM,
   which you should be doing regardless.
2. **`bounded_subprocess` does not kill a process tree on Linux.** An orphaned
   grandchild survives a timeout, so "bounded" is not currently true there.

Everything else passes on Linux (181 passed, 42 skipped). Both defects are tracked
as issues ([#1](https://github.com/LiebertDev/liebert-re-harness/issues/1),
[#2](https://github.com/LiebertDev/liebert-re-harness/issues/2)) and are good first
contributions; the Linux CI leg is marked non-blocking
while they are open so its result stays visible without reddening the whole build.

A Linux contributor should also expect Windows-shaped test data in places, and should
say so in a pull request when something is genuinely platform-broken rather than
merely untested.
