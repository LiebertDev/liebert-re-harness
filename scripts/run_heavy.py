#!/usr/bin/env python3
"""run_heavy - run the `heavy` pytest tier locally and keep a one-file summary of the result.

Stdlib only. Repo location: scripts/run_heavy.py (NOT in the wheel).

The heavy tier needs real external tools (IDA, rizin, ...) that CI does not have, so it cannot run there and
used to run only when someone remembered. This is the one command:

    python scripts/run_heavy.py [--out-dir DIR] [-- extra pytest args]

It runs `python -m pytest -m heavy -q` and writes, under `out/heavy/` (gitignored):

    <UTC stamp>.json   the summary: counts, failed test names, duration, exit code
    <UTC stamp>.log    the raw pytest output, kept so a failure can be read afterwards

Summary fields are measured from pytest's own JUnit report, never inferred from the exit code. If the report
is missing or unreadable the counts are null and `status` is "NO_REPORT"; nothing is guessed. `samples_changed`
lists files that appeared in or vanished from `samples/` during the run (a heavy test must not write beside the
real samples); it is null when `samples/` does not exist.

Exit code: pytest's own (0 only when the heavy tier passed), or 2 if pytest could not be started.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "out" / "heavy"
SCHEMA = 1


def _utc_stamp(moment: datetime) -> str:
    return moment.strftime("%Y%m%dT%H%M%SZ")


def parse_junit(path: Path) -> dict | None:
    """Counts and failed test names from a JUnit XML file, or None when it is absent or not parseable."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        return None
    total = failed = errors = skipped = 0
    names: list[str] = []
    for suite in suites:
        total += int(suite.get("tests", 0))
        failed += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
        for case in suite.iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                cls, name = case.get("classname", ""), case.get("name", "")
                names.append(f"{cls}::{name}" if cls else name)
    return {"passed": total - failed - errors - skipped, "failed": failed, "errors": errors,
            "skipped": skipped, "failed_tests": sorted(set(names))}


def _snapshot(directory: Path) -> set[str] | None:
    if not directory.is_dir():
        return None
    return {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}


def run_heavy(out_dir: Path = DEFAULT_OUT_DIR, extra_args: list[str] | None = None, *,
              command: list[str] | None = None, repo_root: Path = REPO_ROOT) -> tuple[int, Path]:
    """Run the tier, write the summary, return (exit code, summary path). `command` replaces the pytest
    invocation (without the junit switch, which is appended) so the script can be tested without IDA."""
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _utc_stamp(started)
    base = command if command is not None else [sys.executable, "-m", "pytest", "-m", "heavy", "-q",
                                                 "-p", "no:cacheprovider", "-rfE"]
    samples_before = _snapshot(repo_root / "samples")
    with tempfile.TemporaryDirectory(prefix="liebert-heavy-") as tmp:
        junit = Path(tmp) / "report.xml"
        argv = [*base, f"--junitxml={junit}", *(extra_args or [])]
        launch_error = None
        try:
            cp = subprocess.run(argv, cwd=repo_root, capture_output=True, text=True, encoding="utf-8",
                                errors="replace")
            rc, output = cp.returncode, (cp.stdout or "") + (cp.stderr or "")
        except OSError as exc:
            rc, output, launch_error = 2, "", f"{type(exc).__name__}: {exc}"
        parsed = parse_junit(junit)
    duration = round(time.monotonic() - t0, 1)
    samples_after = _snapshot(repo_root / "samples")
    if samples_before is None or samples_after is None:
        samples_changed = None
    else:
        samples_changed = {"added": sorted(samples_after - samples_before),
                           "removed": sorted(samples_before - samples_after)}
    summary = {
        "schema": SCHEMA,
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_seconds": duration,
        "exit_code": rc,
        "status": "NO_REPORT" if parsed is None else ("PASSED" if rc == 0 else "FAILED"),
        "passed": parsed["passed"] if parsed else None,
        "failed": parsed["failed"] if parsed else None,
        "errors": parsed["errors"] if parsed else None,
        "skipped": parsed["skipped"] if parsed else None,
        "failed_tests": parsed["failed_tests"] if parsed else None,
        "samples_changed": samples_changed,
        # Measured, not interpreted: the real-IDA tests were seen failing deterministically when the checkout sat
        # under a very long path (idat could not locate its worker script). The length is recorded so a run can
        # be read against that.
        "repo_root_chars": len(str(repo_root)),
        "python": ".".join(map(str, sys.version_info[:3])),
        "launch_error": launch_error,
    }
    summary_path = out_dir / f"{stamp}.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out_dir / f"{stamp}.log").write_text(output, encoding="utf-8")
    return rc, summary_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the heavy pytest tier and write out/heavy/<UTC>.json.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("extra", nargs="*", help="extra pytest arguments (put them after --)")
    args = parser.parse_args(argv)
    rc, path = run_heavy(args.out_dir, args.extra)
    data = json.loads(path.read_text(encoding="utf-8"))
    print(f"heavy: status={data['status']} exit={rc} passed={data['passed']} failed={data['failed']} "
          f"errors={data['errors']} skipped={data['skipped']} in {data['duration_seconds']}s")
    for name in data["failed_tests"] or []:
        print(f"  FAILED {name}")
    print(f"summary: {path.name} (under {args.out_dir.name}/)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
