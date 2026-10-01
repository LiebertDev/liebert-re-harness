#!/usr/bin/env python3
"""SessionStart health check. SILENT when healthy; prints only what needs attention.

Wired from .claude/settings.json. It reads the purge tool's `doctor` and
`install-hook --check` (both report-only) and adds two checks doctor has no verdict for.
Anything that goes wrong inside this script is swallowed: a hook must never wedge a session.

Reports (each one only when true):
  - the post-commit purge hook is not installed (fresh clone / new machine)
  - cases/ directories the purge cannot see (unmarked) or quarantine entries past expiry
  - open cases untouched for STALE_DAYS (probably abandoned: close or abandon them)
  - samples/ corpus/ out/ output/ artifacts/ runs/ growing past a size or file-count budget
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

STALE_DAYS = 14
SCOPE_DIRS = ("samples", "corpus", "out", "output", "artifacts", "runs")
SCOPE_MAX_BYTES = 100 * 1024 * 1024
SCOPE_MAX_FILES = 2000
SCAN_CAP = 20000


def _run(repo: Path, *args: str) -> tuple[int, str]:
    tool = repo / "scripts" / "case_purge.py"
    r = subprocess.run([sys.executable, str(tool), "--repo", str(repo), *args],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _walk_stats(p: Path) -> tuple[int, int, float]:
    files = total = 0
    newest = 0.0
    stack = [p]
    while stack and files < SCAN_CAP:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        stack.append(Path(e.path))
                    elif e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        files += 1
                        total += st.st_size
                        newest = max(newest, st.st_mtime)
        except OSError:
            continue
    return files, total, newest


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def findings(repo: Path, now: float | None = None) -> list[str]:
    now = time.time() if now is None else now
    out: list[str] = []
    rc, text = _run(repo, "install-hook", "--check")
    if rc != 0:
        out.append("post-commit purge hook is NOT installed, so 'case: solved/abandoned' commits will not "
                   "purge anything. Fix: python scripts/case_purge.py install-hook")
    rc, doc = _run(repo, "doctor")
    m = re.search(r"(\d+) unmarked/invalid", doc)
    if m:
        out.append(f"{m.group(1)} directories under cases/ have no valid .liebert-case marker; their "
                   "artifacts are never purged (python scripts/case_purge.py doctor)")
    m = re.search(r"already expired, awaiting the next sweep: (.+)", doc)
    if m and m.group(1).strip().lower() != "none":
        out.append(f"quarantine entries past expiry (swept by the next purge command): {m.group(1).strip()}")
    cases = repo / "cases"
    if cases.is_dir() and not cases.is_symlink():
        for d in sorted(cases.iterdir()):
            marker = d / ".liebert-case"
            if not (d.is_dir() and not d.is_symlink() and marker.is_file()):
                continue
            try:
                status = json.loads(marker.read_text(encoding="utf-8")).get("status", "open")
            except (OSError, ValueError):
                status = "open"
            if status != "open":
                continue
            files, _, newest = _walk_stats(d)
            newest = max(newest, marker.stat().st_mtime)
            age_days = (now - newest) / 86400
            if age_days >= STALE_DAYS:
                out.append(f"case '{d.name}' is open but untouched for {age_days:.0f} days; close it with "
                           f"'case: solved {d.name}' / 'case: abandoned {d.name}' in a commit message")
    for name in SCOPE_DIRS:
        d = repo / name
        if d.is_dir() and not d.is_symlink():
            files, total, _ = _walk_stats(d)
            if total > SCOPE_MAX_BYTES or files >= SCOPE_MAX_FILES:
                out.append(f"{name}/ holds {files} files, {_human(total)} and is outside the purge's scope "
                           "(nothing here is ever purged); move case work to cases/<name> or clean it by hand")
    return out


def main() -> int:
    try:
        repo = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent)
        if not (repo / "scripts" / "case_purge.py").is_file():
            return 0
        found = findings(repo)
        if found:
            print("liebert-re health check (SessionStart):")
            for f in found:
                print(f"  - {f}")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
