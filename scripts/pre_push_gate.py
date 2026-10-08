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
     The final line names any version whose contract tests did not run; "ok" alone is never printed then.
  4. the SAME identity probes that gate uses, over every commit's author, e-mail and message in
     the pushed range (the file scan cannot see commit messages or history), plus a refusal of any
     case-insensitive `Co-Authored-By:` line in a pushed commit message (AGENTS.md rule 14). Only the
     pushed range is looked at; history already on the remote is never rewritten or re-judged.
The installed hook never skips silently: if git cannot resolve the repository root, or this checkout has no
scripts/pre_push_gate.py (an old branch), it prints why no checks ran and BLOCKS. Only the operator typing
LIEBERT_GATE_ALLOW_MISSING=1 on that push turns this into a loud, deliberate skip (like
LIEBERT_CONTRACT_STRICT=1, a named variable, never written to a file or hook).
`--check` tells no hook, a current hook and a STALE hook (older template) apart; only current exits 0.
A red or leaking tree cannot be pushed without `git push --no-verify`. Commits and all local work
stay unrestricted: this runs on push only. It never pushes anything itself.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
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
# liebert-hook-template: {ver}
skip_or_block() {{
  echo "pre-push gate: NO CHECKS RAN: $1" >&2
  if [ "$LIEBERT_GATE_ALLOW_MISSING" = "1" ]; then
    echo "pre-push gate: SKIPPED ON PURPOSE (LIEBERT_GATE_ALLOW_MISSING=1): this push is UNCHECKED." >&2
    exit 0
  fi
  echo "pre-push gate: BLOCKED, a gate that cannot run is not a pass." >&2
  echo "  to push unchecked, on purpose: LIEBERT_GATE_ALLOW_MISSING=1 git push ..." >&2
  exit 1
}}
root=$(git rev-parse --show-toplevel 2>/dev/null) || root=""
[ -n "$root" ] || skip_or_block "git could not resolve the repository root from $(pwd)"
script="$root/scripts/pre_push_gate.py"
[ -f "$script" ] || skip_or_block "$script does not exist (a checkout that predates the gate?)"
PY='{py}'
if [ ! -x "$PY" ]; then
  echo "pre-push gate: BLOCKED, the interpreter this hook was installed with is missing: $PY" >&2
  echo "  fix: recreate the venv, then run: python scripts/pre_push_gate.py install --force" >&2
  exit 1
fi
exec "$PY" "$script" hook "$@"
"""
# The template's own fingerprint, embedded in every installed hook. It changes whenever the template text
# changes, with nothing to remember to bump, and `--check` compares it: an installed hook from an older
# template is STALE, not "installed". Whitespace elsewhere in the hook file is irrelevant to the comparison.
HOOK_VERSION = hashlib.sha256(HOOK_TEMPLATE.encode("utf-8")).hexdigest()[:12]


def render_hook(py: str) -> str:
    return HOOK_TEMPLATE.format(tag=HOOK_TAG, py=py, ver=HOOK_VERSION)


# This repo's rule is never to mask a failure. A pytest run that prints a native crash report
# ("Windows fatal exception: access violation", "Fatal Python error") and still exits 0 has hidden
# a failure behind a green exit code, so the gate treats that text as a block on its own.
# No test or fixture contains these phrases, so the patterns are not narrowed, and there is no
# allow-list: every dump blocks, whatever its frames. The unicorn mem_map dumps that used to
# appear on every run are silenced at their source, only around the `Uc.mem_map` call, in
# tests/test_vex_layer.py.
FATAL_PATTERNS = (re.compile(r"Windows fatal exception", re.I), re.compile(r"Fatal Python error", re.I),
                  re.compile(r"access violation", re.I))


# REPORT MODE for first-chance traces only. On a machine where a security product's behaviour monitor
# makes every Python process print a handled access violation (measured: a bare interpreter spinning in a
# loop, and the baseline commit, both do), the scan above would block every run. Two variables, BOTH
# required, make the scan count, print and record those traces without blocking on them:
#   LIEBERT_GATE_FIRSTCHANCE=report  and  LIEBERT_GATE_FIRSTCHANCE_NOTE="<non-empty reason>"
# No reason, no bypass: the flag alone is ignored and the gate blocks as usual. It is never active when
# CI or GITHUB_ACTIONS is set, and it is never written to a hook, pytest.ini or any file: it lives only in
# the environment of one run. It touches the trace scan and nothing else: a failing test, a nonzero exit,
# a stage timeout and GATE_RELAY_FAILURE block in every mode. Mode, reason and counts go to the output
# and to dataset/evidence/pre_push_gate/ so a forgotten flag stays visible afterwards.
FIRSTCHANCE_ENV = "LIEBERT_GATE_FIRSTCHANCE"
FIRSTCHANCE_NOTE_ENV = "LIEBERT_GATE_FIRSTCHANCE_NOTE"
_FIRSTCHANCE_SEEN: list[dict] = []


def firstchance_report_note(env=None) -> str | None:
    """The reason text when report mode is validly requested, else None."""
    env = os.environ if env is None else env
    if env.get(FIRSTCHANCE_ENV, "").strip() != "report":
        return None
    if env.get("CI") or env.get("GITHUB_ACTIONS"):
        print(f"pre-push gate: NOTE, {FIRSTCHANCE_ENV} is ignored in CI; first-chance traces block.", file=sys.stderr)
        return None
    note = env.get(FIRSTCHANCE_NOTE_ENV, "").strip()
    if not note:
        print(f"pre-push gate: NOTE, {FIRSTCHANCE_ENV}=report is ignored because {FIRSTCHANCE_NOTE_ENV} is empty; "
              "first-chance traces block.", file=sys.stderr)
        return None
    return note


def fatal_blocks(what: str, rc: int, hits: list[str], env=None) -> bool:
    """True when `hits` (a non-empty list of trace lines) must block. In a valid report mode they are
    counted, printed with the reason, and do not block; everything else is unchanged."""
    note = firstchance_report_note(env)
    if note is None:
        _report_fatal(what, rc, hits)
        return True
    _FIRSTCHANCE_SEEN.append({"stage": what, "traces": len(hits), "pytest_exit": rc, "sample": hits[:3]})
    print(f"pre-push gate: REPORT MODE, {len(hits)} first-chance trace line(s) in {what} were counted and "
          f"NOT blocked on (pytest exit {rc}). Reason given: {note}", file=sys.stderr)
    return False


def write_firstchance_record(verdict: int, env=None) -> Path | None:
    """Evidence of report mode for this run (written whenever the mode is active, hits or not)."""
    note = firstchance_report_note(env)
    if note is None:
        return None
    directory = ROOT / "dataset" / "evidence" / "pre_push_gate"
    now = datetime.now(timezone.utc)
    record = {"mode": "report", "note": note, "gate_exit": verdict, "stages": list(_FIRSTCHANCE_SEEN),
              "traces_total": sum(x["traces"] for x in _FIRSTCHANCE_SEEN),
              "scope": "first-chance trace scan only; failures, nonzero exits, timeouts and relay failures still block",
              "at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{now:%Y%m%dT%H%M%S}{now.microsecond:06d}Z_firstchance_report.json"
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"pre-push gate: could not write the report-mode record ({e.__class__.__name__}).", file=sys.stderr)
        return None
    print(f"pre-push gate: REPORT MODE was active: {record['traces_total']} trace line(s) in total; record at {path}",
          file=sys.stderr)
    return path


# A stage that BLOCKs leaves its complete, unfiltered stdout+stderr here, so a failure seen once can
# still be diagnosed after the terminal scrollback is gone (a 3.10 contract BLOCK that never recurred
# was lost exactly because only a filtered summary survived). The directory is gitignored, and the
# repo-discipline gate bans it from the tree: the output carries machine paths and environment
# details and must never be committed. Only failures write a file; the newest EVIDENCE_KEEP stay.
EVIDENCE_DIR = ROOT / ".pytest_evidence_scratch" / "gate_failures"
EVIDENCE_KEEP = 10
_CONTRACT_MISSING: list[str] = []   # supported versions whose contract tests did not run, this gate run
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


class GateStageError(Exception):
    """A stage could not be judged: it outran its wall-clock ceiling or its output relay failed.
    The gate treats this as a BLOCK with an honest status. A hung or silent gate is worse than a red
    one, because it leaves nothing to read and invites `--no-verify`."""

    def __init__(self, status: str, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


# Wall-clock ceilings per stage, in seconds. Typical runs: discipline a few seconds, suite 86-92,
# one contract interpreter ~8 (about 24 for three). Each ceiling is several times the typical run,
# so a slow machine passes and only a genuine hang trips it. LIEBERT_GATE_STAGE_TIMEOUT overrides all.
STAGE_TIMEOUTS = {"discipline": 300, "suite": 600, "contract": 300}
RELAY_JOIN_GRACE = 15      # seconds the relay threads get to finish once the child is gone


def stage_timeout(stage: str, env=None) -> float:
    raw = (os.environ if env is None else env).get("LIEBERT_GATE_STAGE_TIMEOUT", "")
    try:
        if raw and float(raw) > 0:
            return float(raw)
    except ValueError:
        pass
    return float(STAGE_TIMEOUTS.get(stage, 600))


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30)
        else:
            os.killpg(proc.pid, 9)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _relay(dst, line: str) -> bool:
    """Write `line` to `dst`; a character the stream's encoding cannot hold is shown as a backslash
    escape instead of raising. True if that happened (so the loss is visible, never silent)."""
    try:
        dst.write(line)
        dst.flush()
        return False
    except UnicodeEncodeError:
        enc = getattr(dst, "encoding", None) or "ascii"
        dst.write(line.encode(enc, errors="backslashreplace").decode(enc, errors="replace"))
        dst.flush()
        return True


def run_pytest(cmd: list[str], failed: list[str] | None = None, stage: str = "suite",
               timeout: float | None = None) -> tuple[int, list[str]]:
    """Run pytest, relaying its output live, and return (exit code, fatal-exception findings).
    If `failed` is given it receives the FAILED/ERROR test ids from pytest's -rfE summary.
    Raises GateStageError (GATE_STAGE_TIMEOUT, GATE_RELAY_FAILURE) when the run cannot be judged."""
    timeout = stage_timeout(stage) if timeout is None else timeout
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=(os.name != "nt"))
    bufs: dict[str, list[str]] = {"stdout": [], "stderr": []}
    problems: list[str] = []
    lossy = [0]

    def pump(src, name, dst):
        try:
            for raw in iter(src.readline, b""):
                line = raw.decode("utf-8", errors="replace")
                bufs[name].append(line)
                try:
                    if _relay(dst, line):
                        lossy[0] += 1
                except Exception as e:           # a relay failure must not stop the draining below
                    problems.append(f"{name} relay: {e.__class__.__name__}: {e}")
                    for _ in iter(src.readline, b""):   # keep the pipe empty so the child cannot block
                        pass
                    return
        except BaseException as e:
            problems.append(f"{name} reader died: {e.__class__.__name__}: {e}")

    threads = [threading.Thread(target=pump, args=(proc.stdout, "stdout", sys.stdout), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "stderr", sys.stderr), daemon=True)]
    for t in threads:
        t.start()
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        rc = proc.wait()
    for t in threads:
        t.join(timeout=RELAY_JOIN_GRACE)
        if t.is_alive():
            problems.append("an output relay thread did not finish after the child exited")
    global _LAST_RUN
    _LAST_RUN = (cmd, rc, "".join(bufs["stdout"]), "".join(bufs["stderr"]))
    if lossy[0]:
        print(f"pre-push gate: NOTE, {lossy[0]} output line(s) held characters this console encoding cannot "
              "show; they are printed as backslash escapes here. The saved evidence keeps the full text.",
              file=sys.stderr)
    if timed_out:
        raise GateStageError("GATE_STAGE_TIMEOUT", f"{stage} exceeded {timeout:g}s and its process tree was killed")
    if problems:
        raise GateStageError("GATE_RELAY_FAILURE", "; ".join(problems))
    hits = [h for name, lines in bufs.items() for h in fatal_findings("".join(lines), name)]
    if failed is not None:
        failed.extend(failed_ids("".join(bufs["stdout"])))
    return rc, hits


def _report_stage_error(what: str, e: GateStageError) -> None:
    try:
        print(f"pre-push gate: BLOCKED, {what}: {e.status}: {e.detail}. The stage was not judged; "
              "this is a block, not a pass.", file=sys.stderr)
    except Exception:
        pass


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
    _CONTRACT_MISSING.clear()
    strict = (os.environ if env is None else env).get("LIEBERT_CONTRACT_STRICT") == "1"
    for ver in CONTRACT_VERSIONS:
        if ver not in found:
            _CONTRACT_MISSING.append(ver)
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
        try:
            rc, fatal = run_pytest(cmd, failed=failed, stage="contract")
        except GateStageError as e:
            _report_stage_error(f"the contract tests on Python {full}", e)
            save_evidence(cmd, "contract", f"py{full}")
            blocked = True
            continue
        if fatal and fatal_blocks(f"the contract tests on Python {full}", rc, fatal):
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


class GitOutputError(RuntimeError):
    """git ran but its output cannot be trusted (non-zero exit, or no stdout captured at all)."""


def _git(*args: str) -> str:
    """stdout of a git command. Empty stdout with exit 0 is a real answer (for instance "no commits");
    an unreadable stdout (None, as when the reader thread died) or a non-zero exit raises
    GitOutputError instead of being turned into "" and read as "nothing found"."""
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.stdout is None or r.returncode != 0:
        raise GitOutputError(f"{' '.join(args)}, rc={r.returncode}")
    return r.stdout


def _discipline():
    spec = importlib.util.spec_from_file_location("_discipline_gate", ROOT / "tests" / "test_repo_discipline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_COAUTHOR_TRAILER = re.compile(r"^\s*co-authored-by\s*:", re.IGNORECASE)


def coauthor_trailer_lines(message: str) -> list[int]:
    """1-based line numbers of `Co-Authored-By:` lines in a commit message, case-insensitive
    (AGENTS.md rule 14). A line only counts when it starts with the trailer key."""
    return [n for n, line in enumerate(message.splitlines(), 1) if _COAUTHOR_TRAILER.match(line)]


def message_findings(rev_ranges: list[list[str]], mod=None) -> list[str]:
    """Run the discipline gate's identity probes + product denylist over author, e-mail and full
    message of every commit in each rev-list argument set, and refuse a `Co-Authored-By:` trailer
    (AGENTS.md rule 14) in any of those messages."""
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
                if label == "message":
                    out.extend(f"commit {sha[:10]} message, line {n}: [co-authored-by-trailer] "
                               "Co-Authored-By trailers are not allowed (AGENTS.md rule 14)"
                               for n in coauthor_trailer_lines(text))
                for n, line in enumerate(text.split("\n"), 1):
                    for rule, shown in mod._identity_findings(line, ident, deny):
                        masked = shown if rule == "denylisted-product" else mod._mask(shown)
                        out.append(f"commit {sha[:10]} {label}, line {n}: [{rule}] {masked}")
    return out


def product_rule_state(mod=None) -> tuple[str, str]:
    """(state, text) for the product-name rule on THIS machine, without raising and without ever
    printing a registry line (only its path, a count, or a line number).

    States: "active" (entries present), "absent" (no file), "empty" (file present, no entries),
    "unreadable" (file present, cannot be read), "malformed" (a bad line; message_findings blocks on
    that), "unknown" (the discipline module could not be loaded). Everything but "active" means no
    product name was checked in this run; the gate says so, it does not refuse (the registry is
    operator-private, so a fresh clone could never satisfy a refusal)."""
    try:
        mod = mod or _discipline()
        path = mod._registry_path()
    except Exception as e:
        return "unknown", f"product-name rule INACTIVE (could not load the discipline module: {e.__class__.__name__})"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "absent", (f"product-name rule INACTIVE: no private target registry at {path} "
                          f"(set {mod.TARGETS_ENV} or create it); no commercial product name was checked")
    except OSError as e:
        return "unreadable", (f"product-name rule INACTIVE: private target registry at {path} could not be read "
                              f"({e.__class__.__name__}); no commercial product name was checked")
    try:
        entries = mod._parse_registry(text)
    except ValueError as e:
        return "malformed", f"product-name rule BROKEN: private target registry at {path} is malformed ({e})"
    if not entries:
        return "empty", (f"product-name rule INACTIVE: private target registry at {path} exists but has NO entries "
                         "(an emptied registry is not the same as none; if it should list targets, restore it); "
                         "no commercial product name was checked")
    probes = mod._denylist_probes([(c, n) for c, n, _ in entries])
    return "active", f"product-name rule active: {len(entries)} target(s), {len(probes)} name probe(s)"


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
    _FIRSTCHANCE_SEEN.clear()
    try:
        verdict = _run_gate(ranges)
        write_firstchance_record(verdict)
        return verdict
    finally:
        shutil.rmtree(Path(tempfile.gettempdir()) / f"liebert-gate-{os.getpid()}", ignore_errors=True)


def _run_gate(ranges: list[list[str]]) -> int:
    print("pre-push gate: discipline test + test suite + contract tests on every Python + identity probes "
          "(bypass only with: git push --no-verify)", file=sys.stderr)
    # -rs: a skip reason is printed, not just counted. A rule that skips itself must be readable.
    pytest = [sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider"]
    failed = False
    print("pre-push gate: [1/4] discipline test ...", file=sys.stderr, flush=True)
    cmd = [*pytest, *isolated_basetemp("discipline"), "tests/test_repo_discipline.py"]
    py_tag = "py" + sys.version.split()[0]
    try:
        rc, fatal = run_pytest(cmd, stage="discipline")
    except GateStageError as e:
        _report_stage_error("tests/test_repo_discipline.py", e)
        save_evidence(cmd, "discipline", py_tag)
        rc, fatal, failed = 1, [], True
    if failed:
        pass
    elif fatal and fatal_blocks("tests/test_repo_discipline.py", rc, fatal):
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
    suite_failed = False
    try:
        rc, fatal = run_pytest(cmd, stage="suite")
    except GateStageError as e:
        _report_stage_error("the test suite", e)
        save_evidence(cmd, "suite", py_tag)
        rc, fatal, failed, suite_failed = 1, [], True, True
    if suite_failed:
        pass
    elif fatal and fatal_blocks("the test suite", rc, fatal):
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
    _CONTRACT_MISSING.clear()
    if run_contract_stage():
        failed = True
    else:
        print("pre-push gate: [3/4] contract tests: done.", file=sys.stderr)
    print("pre-push gate: [4/4] commit-message identity probes ...", file=sys.stderr, flush=True)
    rule_state, rule_text = product_rule_state()
    print(f"pre-push gate: rules: {rule_text}", file=sys.stderr)
    scan_error = None
    try:
        hits = message_findings(ranges)
    except GitOutputError as e:                      # empty/unreadable git output is not "no commits"
        hits, scan_error = [], f"could not run the message scan: git output unreadable ({e})"
    except Exception as e:                           # cannot scan messages => do not wave it through
        hits, scan_error = [], f"could not run the message scan: {e!r}"
    if scan_error:
        print(f"pre-push gate: BLOCKED, {scan_error}", file=sys.stderr)
        failed = True
    if hits:
        print("pre-push gate: BLOCKED, commit metadata matches the identity probes or carries a "
              "Co-Authored-By trailer (values masked):", file=sys.stderr)
        for h in hits:
            print("  " + h, file=sys.stderr)
        print("  fix: reword/rewrite those commits locally, or --no-verify if you accept the leak.",
              file=sys.stderr)
        failed = True
    # The LAST line the operator sees names every check that did not run; "ok." is never the whole line then.
    notes = []
    if _CONTRACT_MISSING:
        notes.append("contract tests DID NOT RUN on Python " + ", ".join(_CONTRACT_MISSING))
    if rule_state != "active":
        notes.append(rule_text)
    if failed:
        if notes:
            print("pre-push gate: BLOCKED, and note: " + "; AND ".join(notes), file=sys.stderr)
    elif notes:
        tail = f" ({rule_text})" if rule_state == "active" else ""
        print("pre-push gate: ok, BUT " + "; AND ".join(notes) + tail, file=sys.stderr)
    else:
        print(f"pre-push gate: ok. ({rule_text})", file=sys.stderr)
    return 1 if failed else 0


def hook_path() -> Path:
    try:
        out = _git("rev-parse", "--git-path", "hooks").strip()
    except GitOutputError:
        out = ""                                     # no usable git answer: fall back to the default path
    p = Path(out or ".git/hooks")
    return (p if p.is_absolute() else ROOT / p) / "pre-push"


def hook_state() -> str:
    """"none" (no managed hook), "current" (managed, from this template) or "stale" (managed, older template)."""
    hp = hook_path()
    if not hp.is_file():
        return "none"
    text = hp.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    if HOOK_TAG not in text:
        return "none"
    return "current" if f"# liebert-hook-template: {HOOK_VERSION}\n" in text else "stale"


def installed() -> bool:
    return hook_state() != "none"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", nargs="?", default="run", choices=["install", "run", "hook"])
    ap.add_argument("rest", nargs="*", help="(hook) remote name and url, passed by git")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--range", default="origin/main..HEAD")
    a = ap.parse_args(argv)
    if a.check:
        state = hook_state()
        if state == "current":
            print(f"pre-push hook INSTALLED: {hook_path()}")
            return 0
        if state == "stale":
            print(f"pre-push hook STALE: {hook_path()} was installed from an older template than this script; "
                  "it is not the hook this version would install. Fix: python scripts/pre_push_gate.py install")
            return 1
        print(f"pre-push hook NOT installed: {hook_path()}")
        return 1
    if a.cmd == "install":
        hp = hook_path()
        if hp.exists() and not installed() and not a.force:
            print(f"refusing: {hp} exists and is not ours (use --force). A stale managed hook needs no --force: "
                  "plain `install` replaces it.", file=sys.stderr)
            return 3
        py = Path(sys.executable).as_posix()
        if "'" in py:
            print("interpreter path contains a single quote", file=sys.stderr)
            return 3
        hp.parent.mkdir(parents=True, exist_ok=True)
        with open(hp, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_hook(py))
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
