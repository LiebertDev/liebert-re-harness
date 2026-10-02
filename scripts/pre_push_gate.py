#!/usr/bin/env python3
"""Managed pre-push gate: the privacy check, run before the irreversible step.

    python scripts/pre_push_gate.py install [--force]   write .git/hooks/pre-push
    python scripts/pre_push_gate.py --check             is the managed hook installed? (exit 1 if not)
    python scripts/pre_push_gate.py run [--range A..B]  run the gate by hand (default: origin/main..HEAD)

As a hook (git feeds "<local ref> <local sha> <remote ref> <remote sha>" lines on stdin) it runs
  1. pytest -q tests/test_repo_discipline.py        (the discipline + privacy gate on the tree)
  2. pytest -q, the default (not heavy) suite minus the discipline file already run in 1, so a
     discipline failure stays its own named stage and no test runs twice. Never `-m heavy`.
  3. the SAME identity probes that gate uses, over every commit's author, e-mail and message in
     the pushed range (the file scan cannot see commit messages or history).
A red or leaking tree cannot be pushed without `git push --no-verify`. Commits and all local work
stay unrestricted: this runs on push only. It never pushes anything itself.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
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
[ -x "$PY" ] || PY=python
exec "$PY" "$script" hook "$@"
"""


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


def run_gate(ranges: list[list[str]]) -> int:
    print("pre-push gate: discipline test + test suite + commit-message identity probes "
          "(bypass only with: git push --no-verify)", file=sys.stderr)
    pytest = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    failed = False
    print("pre-push gate: [1/3] discipline test ...", file=sys.stderr, flush=True)
    r = subprocess.run([*pytest, "tests/test_repo_discipline.py"], cwd=ROOT)
    if r.returncode != 0:
        print("pre-push gate: BLOCKED, tests/test_repo_discipline.py is not green.", file=sys.stderr)
        failed = True
    else:
        print("pre-push gate: [1/3] discipline test: ok.", file=sys.stderr)
    # Default mode of pytest.ini (-m "not heavy" from addopts); the discipline file ran above.
    print("pre-push gate: [2/3] test suite (not heavy) ...", file=sys.stderr, flush=True)
    r = subprocess.run([*pytest, "-rfE", "--ignore=tests/test_repo_discipline.py"], cwd=ROOT)
    if r.returncode != 0:
        print(f"pre-push gate: BLOCKED, the test suite is not green (pytest exit {r.returncode}; "
              "failed tests are listed above as FAILED/ERROR).", file=sys.stderr)
        failed = True
    else:
        print("pre-push gate: [2/3] test suite: ok.", file=sys.stderr)
    print("pre-push gate: [3/3] commit-message identity probes ...", file=sys.stderr, flush=True)
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
