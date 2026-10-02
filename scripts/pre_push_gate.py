#!/usr/bin/env python3
"""Managed pre-push gate: the privacy check, run before the irreversible step.

    python scripts/pre_push_gate.py install [--force]   write .git/hooks/pre-push
    python scripts/pre_push_gate.py --check             is the managed hook installed? (exit 1 if not)
    python scripts/pre_push_gate.py run [--range A..B]  run the gate by hand (default: origin/main..HEAD)

As a hook (git feeds "<local ref> <local sha> <remote ref> <remote sha>" lines on stdin) it runs
  1. pytest -q tests/test_repo_discipline.py        (the discipline + privacy gate on the tree)
  2. pytest -q, the default (not heavy) suite minus the discipline file already run in 1, so a
     discipline failure stays its own named stage and no test runs twice. Never `-m heavy`.
  3. `pytest -m contract` (the wrapper-contract tests: a call never raises, it returns an honest
     status) on EVERY supported interpreter it can find (3.10, 3.12 and 3.14, the CI matrix). Stdlib
     exception behaviour differs between versions (Path.is_dir() re-raised PermissionError before 3.13),
     so one interpreter cannot vouch for the contract. A version with no usable interpreter is reported
     loudly as "did not run"; it is never skipped silently. Discovery: LIEBERT_CONTRACT_PYTHONS (paths
     separated by os.pathsep), the venvs under ~/.liebert-venvs (override: LIEBERT_VENV_DIR), the repo
     .venv*, the running interpreter. LIEBERT_CONTRACT_STRICT=1 turns a missing version into a BLOCK.
  4. the SAME identity probes that gate uses, over every commit's author, e-mail and message in
     the pushed range (the file scan cannot see commit messages or history).
A red or leaking tree cannot be pushed without `git push --no-verify`. Commits and all local work
stay unrestricted: this runs on push only. It never pushes anything itself.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZERO = "0" * 40
HOOK_TAG = "# liebert-pre-push-gate (managed by scripts/pre_push_gate.py install)"
HOOK_TEMPLATE = """#!/bin/sh
{tag}
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
script="$root/scripts/pre_push_gate.py"
[ -f "$script" ] || exit 0
PY='{py}'
if [ ! -x "$PY" ]; then
  echo "pre-push gate: BLOCKED, the interpreter this hook was installed with is missing: $PY" >&2
  echo "  fix: recreate the venv, then run: python scripts/pre_push_gate.py install --force" >&2
  exit 1
fi
exec "$PY" "$script" hook "$@"
"""


# This repo's rule is never to mask a failure. A pytest run that prints a native crash report
# ("Windows fatal exception: access violation", "Fatal Python error") and still exits 0 has hidden
# a failure behind a green exit code, so the gate treats that text as a block on its own.
# No test or fixture contains these phrases, so the patterns are not narrowed, and there is no
# allow-list: every dump blocks, whatever its frames. The unicorn mem_map dumps that used to
# appear on every run are silenced at their source, only around the `Uc.mem_map` call, in
# tests/test_vex_layer.py.
FATAL_PATTERNS = (re.compile(r"Windows fatal exception", re.I), re.compile(r"Fatal Python error", re.I),
                  re.compile(r"access violation", re.I))


# A stage that BLOCKs leaves its complete, unfiltered stdout+stderr here, so a failure seen once can
# still be diagnosed after the terminal scrollback is gone (a 3.10 contract BLOCK that never recurred
# was lost exactly because only a filtered summary survived). The directory is gitignored, and the
# repo-discipline gate bans it from the tree: the output carries machine paths and environment
# details and must never be committed. Only failures write a file; the newest EVIDENCE_KEEP stay.
EVIDENCE_DIR = ROOT / ".pytest_evidence_scratch" / "gate_failures"
EVIDENCE_KEEP = 10
_LAST_RUN: tuple | None = None     # (cmd, rc, stdout, stderr) of the most recent run_pytest call


def prune_evidence(directory: Path | None = None, keep: int | None = None) -> None:
    """Delete all but the newest `keep` evidence files (names start with a sortable UTC stamp)."""
    directory = EVIDENCE_DIR if directory is None else directory
    keep = EVIDENCE_KEEP if keep is None else keep
    files = sorted(directory.glob("*.log"), key=lambda f: f.name, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def save_evidence(cmd: list[str], stage: str, interpreter: str, directory: Path | None = None) -> Path | None:
    """Write the full captured output of the run_pytest(cmd) that just BLOCKed and say where it went.
    Returns the path, or None if that run's output is not on hand or the file cannot be written
    (evidence is best effort and never changes the gate's verdict)."""
    directory = EVIDENCE_DIR if directory is None else directory
    if _LAST_RUN is None or _LAST_RUN[0] is not cmd:
        return None
    _, rc, out, err = _LAST_RUN
    now = datetime.now(timezone.utc)
    tag = re.sub(r"[^A-Za-z0-9.]+", "-", interpreter)
    name = f"{now:%Y%m%dT%H%M%S}{now.microsecond:06d}Z_{stage}_{tag}.log"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text(f"# stage: {stage}\n# interpreter: {interpreter}\n# command: {' '.join(cmd)}\n"
                        f"# pytest exit code: {rc}\n\n===== STDOUT =====\n{out}\n===== STDERR =====\n{err}",
                        encoding="utf-8", errors="replace")
        prune_evidence(directory)
    except OSError as e:
        print(f"pre-push gate: could not save the failing output ({e.__class__.__name__}).", file=sys.stderr)
        return None
    print(f"pre-push gate: full output of the failing stage saved to {path}", file=sys.stderr)
    return path


def isolated_basetemp(label: str) -> list[str]:
    """``--basetemp`` for one pytest run, so no two runs of the gate (the three interpreters of the
    contract stage included) share a temp root. A shared root is a variable: a leftover or a
    still-open file from one run is state the next run can trip over. The directory is per process and
    per label, outside the repo; ``run_gate`` removes the process's root when it finishes."""
    root = Path(tempfile.gettempdir()) / f"liebert-gate-{os.getpid()}"
    root.mkdir(parents=True, exist_ok=True)              # pytest creates the basetemp, not its parent
    return ["--basetemp", str(root / label)]


def fatal_findings(text: str, stream: str) -> list[str]:
    """Lines of captured pytest output that carry a fatal-exception marker, as 'stream line n: text'."""
    return [f"{stream} line {n}: {line.strip()[:160]}" for n, line in enumerate(text.splitlines(), 1)
            if any(p.search(line) for p in FATAL_PATTERNS)]


def run_pytest(cmd: list[str], failed: list[str] | None = None) -> tuple[int, list[str]]:
    """Run pytest, relaying its output live, and return (exit code, fatal-exception findings).
    If `failed` is given it receives the FAILED/ERROR test ids from pytest's -rfE summary."""
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    bufs: dict[str, list[str]] = {"stdout": [], "stderr": []}

    def pump(src, name, dst):
        for raw in iter(src.readline, b""):
            line = raw.decode("utf-8", errors="replace")
            bufs[name].append(line)
            dst.write(line)
            dst.flush()

    threads = [threading.Thread(target=pump, args=(proc.stdout, "stdout", sys.stdout)),
               threading.Thread(target=pump, args=(proc.stderr, "stderr", sys.stderr))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rc = proc.wait()
    global _LAST_RUN
    _LAST_RUN = (cmd, rc, "".join(bufs["stdout"]), "".join(bufs["stderr"]))
    hits = [h for name, lines in bufs.items() for h in fatal_findings("".join(lines), name)]
    if failed is not None:
        failed.extend(failed_ids("".join(bufs["stdout"])))
    return rc, hits


def failed_ids(text: str) -> list[str]:
    """Test ids from pytest's short summary lines ('FAILED tests/x.py::Cls::test - message')."""
    return [m.group(1) for m in re.finditer(r"^(?:FAILED|ERROR) (\S+)", text, re.M)]


# ---- contract stage: interpreter discovery -------------------------------------------------------
# Mirrors the CI matrix on purpose; tests/test_pre_push_gate.py checks the two lists agree.
CONTRACT_VERSIONS = ("3.10", "3.12", "3.14")
_PROBE = ("import sys; print('%d.%d' % sys.version_info[:2]); print(sys.version.split()[0]); "
          "import pytest, liebert_re, mpmath")


def _venv_python(d: Path) -> Path | None:
    for rel in ("Scripts/python.exe", "bin/python"):
        if (d / rel).is_file():
            return d / rel
    return None


def candidate_interpreters(env=None) -> list[Path]:
    """Where to look, in priority order. Nothing is hard-coded to one machine: an explicit list from
    LIEBERT_CONTRACT_PYTHONS, then the per-user venv directory (default ~/.liebert-venvs, where one
    venv per version is the natural layout and carries pytest and the dev extras), then the repo's
    own .venv*, then the interpreter running the gate."""
    env = os.environ if env is None else env
    out: list[Path] = [Path(x) for x in env.get("LIEBERT_CONTRACT_PYTHONS", "").split(os.pathsep) if x.strip()]
    vdir = Path(env.get("LIEBERT_VENV_DIR") or Path.home() / ".liebert-venvs")
    roots = [*(sorted(vdir.iterdir()) if vdir.is_dir() else []), *sorted(ROOT.glob(".venv*"))]
    out += [p for r in roots if r.is_dir() and (p := _venv_python(r))]
    out.append(Path(sys.executable))
    return out


def probe_interpreter(py: Path):
    """(major.minor, full version) if `py` can run the contract tests, else a reason string."""
    try:
        r = subprocess.run([str(py), "-c", _PROBE], capture_output=True, text=True, timeout=60, cwd=ROOT)
    except (OSError, subprocess.SubprocessError) as e:
        return f"cannot start: {e.__class__.__name__}"
    if r.returncode != 0:
        tail = (r.stderr.strip().splitlines() or ["?"])[-1][:120]
        return f"pytest or the package dependencies are not importable ({tail})"
    lines = r.stdout.split()
    return lines[0], lines[1]


def find_contract_interpreters(env=None):
    """({'3.10': (path, '3.10.11'), ...} for the versions found usable,
    {'3.10': [rejected candidates and why]} for the versions not found)."""
    found: dict[str, tuple[Path, str]] = {}
    rejected: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for py in candidate_interpreters(env):
        key = os.path.normcase(str(py.resolve())) if py.exists() else str(py)
        if key in seen:
            continue
        seen.add(key)
        res = probe_interpreter(py) if py.exists() else "path does not exist"
        if isinstance(res, str):
            rejected.append((py, res))
        elif res[0] in CONTRACT_VERSIONS and res[0] not in found:
            found[res[0]] = (py, res[1])
    why = {v: [f"{p}: {r}" for p, r in rejected] for v in CONTRACT_VERSIONS if v not in found}
    return found, why


def run_contract_stage(env=None) -> bool:
    """Run `-m contract` on every supported interpreter. True means the stage failed (block)."""
    found, why = find_contract_interpreters(env)
    blocked = False
    strict = (os.environ if env is None else env).get("LIEBERT_CONTRACT_STRICT") == "1"
    for ver in CONTRACT_VERSIONS:
        if ver not in found:
            print(f"pre-push gate: WARNING, no usable Python {ver} found: the contract tests DID NOT RUN on "
                  f"{ver}. Python-version-dependent stdlib behaviour is unverified here "
                  "(set LIEBERT_CONTRACT_PYTHONS, or create a venv under ~/.liebert-venvs with "
                  "`pip install -e .[dev,lattice]`).", file=sys.stderr)
            for w in why.get(ver, [])[:5]:
                print("  rejected candidate " + w, file=sys.stderr)
            if strict:
                print(f"pre-push gate: BLOCKED, LIEBERT_CONTRACT_STRICT=1 and Python {ver} is missing.",
                      file=sys.stderr)
                blocked = True
            continue
        py, full = found[ver]
        print(f"pre-push gate:   contract tests on Python {full} ({py}) ...", file=sys.stderr, flush=True)
        failed: list[str] = []
        cmd = [str(py), "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rfE", "-m", "contract",
               *isolated_basetemp(f"contract-py{ver}")]
        rc, fatal = run_pytest(cmd, failed=failed)
        if fatal:
            _report_fatal(f"the contract tests on Python {full}", rc, fatal)
            save_evidence(cmd, "contract", f"py{full}")
            blocked = True
        elif rc != 0:
            print(f"pre-push gate: BLOCKED, contract tests are red on Python {full} ({py}), pytest exit {rc}:",
                  file=sys.stderr)
            for t in failed[:30] or ["(no FAILED line captured; see the output above)"]:
                print(f"  [py{ver}] {t}", file=sys.stderr)
            save_evidence(cmd, "contract", f"py{full}")
            blocked = True
        else:
            print(f"pre-push gate:   Python {full}: contract tests ok.", file=sys.stderr)
    return blocked


def _git(*args: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.stdout if r.returncode == 0 else ""


def _discipline():
    spec = importlib.util.spec_from_file_location("_discipline_gate", ROOT / "tests" / "test_repo_discipline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def message_findings(rev_ranges: list[list[str]], mod=None) -> list[str]:
    """Run the discipline gate's identity probes + product denylist over author, e-mail and full
    message of every commit in each rev-list argument set."""
    mod = mod or _discipline()
    ident = [p for p in mod._machine_identity() if p[0] != "operator-home"]
    deny = mod._denylist_probes()
    seen, out = set(), []
    for revs in rev_ranges:
        for sha in _git("rev-list", *revs).split():
            if sha in seen:
                continue
            seen.add(sha)
            for label, fmt in (("author name", "%an"), ("author e-mail", "%ae"), ("committer", "%cn%n%ce"),
                               ("message", "%B")):
                text = _git("show", "-s", f"--format={fmt}", sha)
                for n, line in enumerate(text.split("\n"), 1):
                    for rule, shown in mod._identity_findings(line, ident, deny):
                        masked = shown if rule == "denylisted-product" else mod._mask(shown)
                        out.append(f"commit {sha[:10]} {label}, line {n}: [{rule}] {masked}")
    return out


def pushed_ranges(stdin_text: str) -> list[list[str]]:
    ranges = []
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == ZERO:      # blank or a branch deletion
            continue
        _, local, _, remote = parts
        ranges.append([local, "--not", "--remotes"] if remote == ZERO else [f"{remote}..{local}"])
    return ranges


def _report_fatal(what: str, rc: int, hits: list[str]) -> None:
    print(f"pre-push gate: BLOCKED, {what} printed a fatal-exception report (pytest exit {rc}); "
          "a crash report is a failure even when the exit code is 0:", file=sys.stderr)
    for h in hits[:10]:
        print("  " + h, file=sys.stderr)


def run_gate(ranges: list[list[str]]) -> int:
    try:
        return _run_gate(ranges)
    finally:
        shutil.rmtree(Path(tempfile.gettempdir()) / f"liebert-gate-{os.getpid()}", ignore_errors=True)


def _run_gate(ranges: list[list[str]]) -> int:
    print("pre-push gate: discipline test + test suite + contract tests on every Python + identity probes "
          "(bypass only with: git push --no-verify)", file=sys.stderr)
    pytest = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    failed = False
    print("pre-push gate: [1/4] discipline test ...", file=sys.stderr, flush=True)
    cmd = [*pytest, *isolated_basetemp("discipline"), "tests/test_repo_discipline.py"]
    rc, fatal = run_pytest(cmd)
    py_tag = "py" + sys.version.split()[0]
    if fatal:
        _report_fatal("tests/test_repo_discipline.py", rc, fatal)
        save_evidence(cmd, "discipline", py_tag)
        failed = True
    elif rc != 0:
        print("pre-push gate: BLOCKED, tests/test_repo_discipline.py is not green.", file=sys.stderr)
        save_evidence(cmd, "discipline", py_tag)
        failed = True
    else:
        print("pre-push gate: [1/4] discipline test: ok.", file=sys.stderr)
    # Default mode of pytest.ini (-m "not heavy" from addopts); the discipline file ran above.
    print("pre-push gate: [2/4] test suite (not heavy) ...", file=sys.stderr, flush=True)
    cmd = [*pytest, "-rfE", *isolated_basetemp("suite"), "--ignore=tests/test_repo_discipline.py"]
    rc, fatal = run_pytest(cmd)
    if fatal:
        _report_fatal("the test suite", rc, fatal)
        save_evidence(cmd, "suite", py_tag)
        failed = True
    elif rc != 0:
        print(f"pre-push gate: BLOCKED, the test suite is not green (pytest exit {rc}; "
              "failed tests are listed above as FAILED/ERROR).", file=sys.stderr)
        save_evidence(cmd, "suite", py_tag)
        failed = True
    else:
        print("pre-push gate: [2/4] test suite: ok.", file=sys.stderr)
    print("pre-push gate: [3/4] contract tests on every supported Python ...", file=sys.stderr, flush=True)
    if run_contract_stage():
        failed = True
    else:
        print("pre-push gate: [3/4] contract tests: done.", file=sys.stderr)
    print("pre-push gate: [4/4] commit-message identity probes ...", file=sys.stderr, flush=True)
    try:
        hits = message_findings(ranges)
    except Exception as e:                           # cannot scan messages => do not wave it through
        hits = [f"could not run the message scan: {e!r}"]
    if hits:
        print("pre-push gate: BLOCKED, commit metadata matches the identity probes "
              "(values masked):", file=sys.stderr)
        for h in hits:
            print("  " + h, file=sys.stderr)
        print("  fix: reword/rewrite those commits locally, or --no-verify if you accept the leak.",
              file=sys.stderr)
        failed = True
    if not failed:
        print("pre-push gate: ok.", file=sys.stderr)
    return 1 if failed else 0


def hook_path() -> Path:
    p = Path(_git("rev-parse", "--git-path", "hooks").strip() or ".git/hooks")
    return (p if p.is_absolute() else ROOT / p) / "pre-push"


def installed() -> bool:
    hp = hook_path()
    return hp.is_file() and HOOK_TAG in hp.read_text(encoding="utf-8", errors="replace")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", nargs="?", default="run", choices=["install", "run", "hook"])
    ap.add_argument("rest", nargs="*", help="(hook) remote name and url, passed by git")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--range", default="origin/main..HEAD")
    a = ap.parse_args(argv)
    if a.check:
        print(f"pre-push hook {'INSTALLED' if installed() else 'NOT installed'}: {hook_path()}")
        return 0 if installed() else 1
    if a.cmd == "install":
        hp = hook_path()
        if hp.exists() and not installed() and not a.force:
            print(f"refusing: {hp} exists and is not ours (use --force)", file=sys.stderr)
            return 3
        py = Path(sys.executable).as_posix()
        if "'" in py:
            print("interpreter path contains a single quote", file=sys.stderr)
            return 3
        hp.parent.mkdir(parents=True, exist_ok=True)
        with open(hp, "w", encoding="utf-8", newline="\n") as f:
            f.write(HOOK_TEMPLATE.format(tag=HOOK_TAG, py=py))
        try:
            os.chmod(hp, 0o755)
        except OSError:
            pass
        print(f"installed {hp} (python: {py})")
        return 0
    if a.cmd == "hook":
        ranges = pushed_ranges(sys.stdin.read())
        if not ranges:
            return 0                                 # nothing but deletions: nothing to leak
        return run_gate(ranges)
    return run_gate([[a.range]])


if __name__ == "__main__":
    sys.exit(main())
