#!/usr/bin/env python3
"""case_purge - quarantine the artifacts of a finished/abandoned reverse-engineering case.

Stdlib only. Intended repo location: scripts/case_purge.py (NOT in the wheel).

Layout it understands (and ONLY this layout):

    <repo>/cases/<name>/.liebert-case     marker file (JSON), required
    <repo>/cases/<name>/REPORT.md         kept
    <repo>/cases/<name>/knowledge/...     kept
    <repo>/cases/<name>/<everything else> purged only if it matches PURGE rules

A purge MOVES files to a quarantine directory under the OS temp dir (never inside
the repo): <tmp>/liebert-re-quarantine/<case>/<UTC stamp>/. Entries expire after
7 days and are swept on every invocation (except `doctor`, which only reports).
`.md` files are kept unless their name carries an explicit dump suffix AND they
sit in a scratch directory.

Subcommands:
    init NAME                  create cases/NAME with marker
    list                       show cases and purgeable size
    purge NAME [--execute]     escape hatch; dry-run unless --execute (moves to quarantine)
    quarantine                 list quarantine entries and when they expire
    restore NAME [--stamp S]   put a quarantined purge back (never overwrites)
    doctor                     report-only: unmarked cases/ dirs, samples/ out/ runs/ dataset/
                               size and age (outside purge scope), quarantine size/expiry
    from-commit [--rev R] [--execute]
                               parse a commit message for `case: solved NAME` /
                               `case: abandoned NAME` lines
    claude-hook                PostToolUse adapter (reads hook JSON on stdin)
    install-hook [--force|--check]
                               install the git post-commit hook

Exit codes: 0 ok / nothing to do, 3 scope-fence refusal, 4 partial delete failure.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CASES_DIRNAME = "cases"
MARKER = ".liebert-case"
MARKER_VERSION = 1

# ---------------------------------------------------------------------------
# SCOPE FENCE
# ---------------------------------------------------------------------------
# Case names are an ALLOW-LIST: ASCII letter/digit first, then letters, digits,
# '_' or '-'. No dots, no separators, no colons (NTFS streams / drive letters),
# no spaces. Matched with fullmatch() (NOT match()/`$`, which would accept a
# trailing newline).
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {
    f"LPT{i}" for i in range(1, 10)}
# Defense in depth: even though target is structurally cases/<name>, refuse if
# the name collides with anything that looks like repo infrastructure.
DENY_NAMES = {".git", "liebert_re", "tests", "docs", "scripts", ".claude", ".github",
              ".venv", "src", "cases"}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class ScopeError(Exception):
    """The requested purge is outside the fence. Nothing was touched."""


class CaseNotFound(ScopeError):
    """No such case directory (idempotent no-op for commit-triggered runs)."""


def validate_name(name) -> str:
    if not isinstance(name, str) or name == "":
        raise ScopeError("empty case name")
    if not NAME_RE.fullmatch(name):
        why = []
        if any(c in name for c in "/\\"):
            why.append("contains a path separator")
        if ":" in name:
            why.append("contains ':' (drive letter / NTFS stream)")
        if ".." in name or name in (".", ".."):
            why.append("contains '..' or '.'")
        if not why:
            why.append("must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}")
        raise ScopeError(f"illegal case name {name!r}: " + "; ".join(why))
    if name.upper() in WIN_RESERVED:
        raise ScopeError(f"illegal case name {name!r}: reserved Windows device name")
    if name.lower() in DENY_NAMES:
        raise ScopeError(f"illegal case name {name!r}: collides with a protected directory")
    return name


def is_reparse(p) -> bool:
    """True for symlinks AND Windows junctions/mount points (never follows)."""
    st = os.lstat(p)
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _norm(p) -> str:
    return os.path.normcase(os.path.abspath(str(p)))


def _require_real_dir(p: Path, what: str) -> None:
    try:
        if is_reparse(p):
            raise ScopeError(f"{what} is a symlink/junction: {p}")
    except FileNotFoundError:
        raise CaseNotFound(f"{what} does not exist: {p}") from None
    if not p.is_dir():
        raise ScopeError(f"{what} is not a directory: {p}")
    if _norm(os.path.realpath(p)) != _norm(p):
        raise ScopeError(f"{what} resolves through a link: {p} -> {os.path.realpath(p)}")


def resolve_case_target(repo_arg, name) -> tuple[Path, Path]:
    """Return (repo, target) or raise ScopeError. The ONLY way to obtain a purge root.

    target is constructed as repo/'cases'/<validated name>, never from a
    caller-supplied path, so the name cannot widen the scope.
    """
    name = validate_name(name)
    repo = Path(os.path.realpath(str(repo_arg)))
    if not (repo / ".git").exists():
        raise ScopeError(f"not a git repo root (no .git): {repo}")
    cases_root = repo / CASES_DIRNAME
    _require_real_dir(cases_root, "cases root")
    target = cases_root / name
    _require_real_dir(target, "case dir")

    # Structural re-check: independent of how we built it.
    try:
        rel = target.relative_to(repo)
    except ValueError:
        raise ScopeError(f"target outside repo: {target}") from None
    if len(rel.parts) != 2 or rel.parts[0] != CASES_DIRNAME or rel.parts[1] != name:
        raise ScopeError(f"target is not exactly cases/<name>: {rel}")
    if _norm(target) == _norm(repo):
        raise ScopeError("target is the repo root")
    if any(part.lower() in DENY_NAMES - {"cases"} for part in rel.parts):
        raise ScopeError(f"target touches a protected directory: {rel}")

    # Marker: only directories the harness itself created can be purged.
    marker = target / MARKER
    try:
        if is_reparse(marker) or not marker.is_file():
            raise ScopeError(f"missing or non-regular {MARKER} in case dir")
        meta = json.loads(marker.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScopeError(f"{target} has no {MARKER} marker; refusing (not a harness case)") from None
    except (OSError, ValueError) as e:
        raise ScopeError(f"unreadable {MARKER}: {e}") from None
    if not isinstance(meta, dict) or meta.get("liebert_case") != MARKER_VERSION or meta.get("name") != name:
        raise ScopeError(f"{MARKER} does not describe case {name!r}")
    return repo, target


# ---------------------------------------------------------------------------
# CLASSIFICATION  (keep-list is evaluated FIRST and always wins)
# ---------------------------------------------------------------------------
# KEEP: matched against the lower-cased posix path relative to the case dir.
KEEP_EXACT = {"report.md", MARKER}                  # case root only
KEEP_DIR_PREFIXES = ("knowledge/", "keep/")         # anything below these
KEEP_BASENAME_GLOBS = ("*.writeup.md", "writeup.md", "writeup-*.md", "*.knowledge.md")

# PURGE: only consulted for paths NOT kept.
PURGE_DIR_GLOBS = (                                   # any ancestor dir with this name
    "artifacts", "samples", "sample", "targets", "scratch", "traces", "dumps", "logs",
    "ida", "ghidra", "ghidra_project*", "*.rep", "frida", "decomp", "disasm",
    "decompiled", "x64dbg", "windbg", "ttd",
)
PURGE_FILE_GLOBS = (
    # IDA databases + components + exports
    "*.idb", "*.i64", "*.til", "*.nam", "*.id0", "*.id1", "*.id2", "*.id3", "*.id4",
    "*.asm", "*.lst", "*.map",
    # Ghidra
    "*.gpr", "*.lock", "*.lock~", "*.gbf", "*.prp",
    # other disassembler/decompiler databases and dumps
    "*.bndb", "*.rzdb", "*.decomp.c", "*.decomp.txt", "*.decompiled.*", "*.pseudo.c",
    "*.hexrays.*", "*.disasm", "*.disasm.*", "*.objdump", "*.objdump.*",
    # debug symbols, Ghidra data types, IDA scripts/exports
    "*.pdb", "*.gdt", "*.idc",
    # memory dumps / cores
    "*.dmp", "*.mdmp", "*.hdmp", "*.cdmp", "*.core", "core", "core.[0-9]*", "*.dump",
    "*.wer", "*.hprof",
    # debugger logs and traces
    "*.log", "*.trace", "*.trc", "*.tti", "*.etl", "*.run", "*.dd32", "*.dd64", "*.pcap", "*.pcapng",
    "*.pml", "*.pmc",                                  # Process Monitor log / config
    # frida / script scratch output
    "frida-*.js", "frida-*.json", "*.frida.*",
    # target binaries / samples themselves
    "*.exe", "*.dll", "*.sys", "*.so", "*.so.*", "*.dylib", "*.elf", "*.bin", "*.apk",
    "*.msi", "*.ocx", "*.scr", "*.out", "*.crackme", "*.sample", "*.7z", "*.zip",
    # per-target scratch notes (plain text only; markdown is governed by MD_DUMP_GLOBS)
    "scratch*.txt", "*.scratch.txt", "notes.tmp*",
    # editor/backup leftovers. DELIBERATELY absent (would destroy source, config, notes):
    # .py .c .cpp .h .json .xml .txt (txt only via the scratch globs above) -- do not add.
    "*.bak", "*.old", "*.orig", "*.swp", "*.swo", "*~", "*.tmp",
)
# A Windows Error Reporting bundle: a .cab is purgeable ONLY when a .wer sits in the
# same directory. Decided at plan time (Plan.companions) because it depends on siblings.
COMPANION_CAB_SUFFIX = ".cab"
COMPANION_WER_SUFFIX = ".wer"
# Markdown is human writing until proven otherwise. A .md file is purgeable ONLY
# when (a) it sits under a PURGE_DIR_GLOBS directory AND (b) its basename ends in
# one of these explicit tool-dump suffixes. Everything else (scratch-ideas.md,
# notes.md, scratch.md, README.md, ...) is left alone. When in doubt: KEEP.
MD_EXTENSIONS = (".md", ".markdown")
MD_DUMP_GLOBS = (
    "*.dump.md", "*.decomp.md", "*.decompiled.md", "*.disasm.md", "*.pseudo.md",
    "*.hexrays.md", "*.objdump.md", "*.trace.md", "*.log.md",
)


def _rel_posix(rel: str) -> str:
    return rel.replace("\\", "/").lower()


def is_kept(rel: str) -> bool:
    r = _rel_posix(rel)
    if r in KEEP_EXACT:
        return True
    if any(r.startswith(p) for p in KEEP_DIR_PREFIXES):
        return True
    base = r.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(base, g) for g in KEEP_BASENAME_GLOBS)


def is_purgeable(rel: str) -> bool:
    """Pattern match only. Callers MUST check is_kept first (classify() does)."""
    parts = _rel_posix(rel).split("/")
    in_purge_dir = any(fnmatch.fnmatchcase(d, g) for d in parts[:-1] for g in PURGE_DIR_GLOBS)
    if parts[-1].endswith(MD_EXTENSIONS):
        return in_purge_dir and any(fnmatch.fnmatchcase(parts[-1], g) for g in MD_DUMP_GLOBS)
    if in_purge_dir:
        return True
    return any(fnmatch.fnmatchcase(parts[-1], g) for g in PURGE_FILE_GLOBS)


def classify(rel: str, companion: bool = False) -> str:
    """`companion` is True only for a .cab the plan found beside a .wer."""
    if is_kept(rel):
        return "keep"
    if companion and _rel_posix(rel).endswith(COMPANION_CAB_SUFFIX):
        return "purge"
    return "purge" if is_purgeable(rel) else "unclassified"


# ---------------------------------------------------------------------------
# PLAN / EXECUTE
# ---------------------------------------------------------------------------
class Plan:
    def __init__(self, target: Path):
        self.target = target
        self.purge: list[tuple[str, int]] = []       # (rel, size)
        self.keep: list[tuple[str, int]] = []
        self.unclassified: list[tuple[str, int]] = []
        self.companions: set[str] = set()            # .cab files purged only because of a sibling .wer

    @property
    def purge_bytes(self) -> int:
        return sum(s for _, s in self.purge)


def build_plan(target: Path) -> Plan:
    """Walk target WITHOUT following links. Any link anywhere => refuse everything."""
    plan = Plan(target)
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        here = target / rel_dir if rel_dir else target
        with os.scandir(here) as it:
            entries = list(it)
        has_wer = any(x.name.lower().endswith(COMPANION_WER_SUFFIX)
                      and x.is_file(follow_symlinks=False) for x in entries)
        for e in entries:
            rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
            if is_reparse(e.path):
                raise ScopeError(f"symlink/junction inside case tree, refusing whole purge: {rel}")
            if e.is_dir(follow_symlinks=False):
                stack.append(rel)
            elif e.is_file(follow_symlinks=False):
                size = e.stat(follow_symlinks=False).st_size
                comp = has_wer and e.name.lower().endswith(COMPANION_CAB_SUFFIX)
                kind = classify(rel, companion=comp)
                if comp and kind == "purge" and not is_purgeable(rel):
                    plan.companions.add(rel)
                {"keep": plan.keep, "purge": plan.purge,
                 "unclassified": plan.unclassified}[kind].append((rel, size))
            else:
                plan.unclassified.append((rel, 0))   # sockets/devices: never touched
    for L in (plan.purge, plan.keep, plan.unclassified):
        L.sort()
    # invariant: nothing kept is ever planned for deletion
    assert not any(is_kept(r) for r, _ in plan.purge), "keep-list violated"
    return plan


def human(n: int) -> str:
    x = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if x < 1024 or u == "TiB":
            return f"{int(x)} {u}" if u == "B" else f"{x:.1f} {u}"
        x /= 1024


def print_plan(plan: Plan, name: str, limit: int = 200, out=None) -> None:
    out = out or sys.stdout

    def w(s=""):
        print(s, file=out)
    w(f"case:   {name}")
    w(f"target: {CASES_DIRNAME}/{name}")
    w(f"WILL MOVE TO QUARANTINE ({len(plan.purge)} files, {human(plan.purge_bytes)}):")
    for rel, size in plan.purge[:limit]:
        w(f"  {human(size):>10}  {rel}")
    if len(plan.purge) > limit:
        rest = plan.purge[limit:]
        w(f"  ... and {len(rest)} more files, {human(sum(s for _, s in rest))}")
    w(f"KEEPING ({len(plan.keep)} files):")
    for rel, size in plan.keep[:limit]:
        w(f"  {human(size):>10}  {rel}")
    if plan.unclassified:
        w(f"LEFT ALONE, not matched by any rule ({len(plan.unclassified)} files):")
        for rel, size in plan.unclassified[:limit]:
            w(f"  {human(size):>10}  {rel}")


# ---------------------------------------------------------------------------
# QUARANTINE  (purge = MOVE out of the repo; entries expire after 7 days)
# ---------------------------------------------------------------------------
QUARANTINE_DIRNAME = "liebert-re-quarantine"
QUARANTINE_SCHEMA = 1
QUARANTINE_TTL_SECONDS = 7 * 24 * 3600
EXPIRING_SOON_SECONDS = 2 * 24 * 3600
STAMP_RE = re.compile(r"\d{8}T\d{6}Z(?:-\d{1,3})?")


def _now() -> float:
    return time.time()


def quarantine_root() -> Path:
    """<OS temp>/liebert-re-quarantine. Always outside the repo (checked per use)."""
    return Path(os.path.realpath(tempfile.gettempdir())) / QUARANTINE_DIRNAME


def _disp(p) -> str:
    """Display a path without leaking the user's home: the temp dir becomes <tmp>."""
    tmp = os.path.realpath(tempfile.gettempdir())
    s = str(p)
    return ("<tmp>" + s[len(tmp):]) if _norm(s).startswith(_norm(tmp)) else s


def repo_id(repo) -> str:
    return hashlib.sha256(_norm(os.path.realpath(str(repo))).encode("utf-8")).hexdigest()[:16]


def _require_outside_repo(repo, qroot: Path) -> None:
    q, r = _norm(os.path.realpath(qroot)), _norm(os.path.realpath(str(repo)))
    if q == r or q.startswith(r + os.sep):
        raise ScopeError("quarantine directory would be inside the repo; refusing")


def _sha256(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _rmtree(p: Path) -> None:
    def onexc(fn, path, exc):
        os.chmod(path, stat.S_IWRITE)
        fn(path)
    shutil.rmtree(p, onexc=onexc)


def _dir_bytes(p: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(p, followlinks=False):
        dirs[:] = [d for d in dirs if not is_reparse(os.path.join(root, d))]
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def _load_manifest(entry: Path, case: str):
    try:
        m = json.loads((entry / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (isinstance(m, dict) and m.get("case_purge_quarantine") == QUARANTINE_SCHEMA
            and m.get("case") == case and isinstance(m.get("purged_epoch"), int)
            and isinstance(m.get("files"), list)):
        return m
    return None


def iter_quarantine(qroot: Path):
    """Yield (case, stamp, entry_path, manifest_or_None). Never follows links."""
    if not qroot.is_dir() or is_reparse(qroot):
        return
    for cd in sorted(os.scandir(qroot), key=lambda e: e.name):
        if not cd.is_dir(follow_symlinks=False) or is_reparse(cd.path) or not NAME_RE.fullmatch(cd.name):
            continue
        for ed in sorted(os.scandir(cd.path), key=lambda e: e.name):
            if (ed.is_dir(follow_symlinks=False) and not is_reparse(ed.path)
                    and STAMP_RE.fullmatch(ed.name)):
                yield cd.name, ed.name, Path(ed.path), _load_manifest(Path(ed.path), cd.name)


def sweep_quarantine(now=None, qroot=None) -> list[str]:
    """Delete quarantine entries older than the TTL. Touches ONLY <qroot>/<case>/<stamp>."""
    now = _now() if now is None else now
    qroot = qroot or quarantine_root()
    removed = []
    for case, stamp, entry, m in list(iter_quarantine(qroot)):
        if _norm(os.path.realpath(entry)) != _norm(entry) or not _norm(entry).startswith(_norm(qroot) + os.sep):
            continue
        if m is not None:
            age = now - m["purged_epoch"]
        else:                                    # no valid manifest (crash): fall back to mtime
            age = now - entry.stat().st_mtime
        if age > QUARANTINE_TTL_SECONDS:
            _rmtree(entry)
            removed.append(f"{case}/{stamp}")
    if qroot.is_dir() and not is_reparse(qroot):
        for cd in os.scandir(qroot):             # drop case dirs emptied by the sweep
            if cd.is_dir(follow_symlinks=False) and not is_reparse(cd.path):
                try:
                    os.rmdir(cd.path)            # fails (harmlessly) if not empty
                except OSError:
                    pass
    return removed


def _auto_sweep() -> None:
    try:
        gone = sweep_quarantine()
        if gone:
            print(f"case_purge: expired quarantine entries removed: {', '.join(gone)}")
    except OSError as e:
        print(f"case_purge: quarantine sweep failed: {e}", file=sys.stderr)


def _new_entry_dir(qroot: Path, case: str, now: float) -> tuple[Path, str]:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    n, cand = 0, stamp
    while (qroot / case / cand).exists():
        n += 1
        cand = f"{stamp}-{n}"
    d = qroot / case / cand
    d.mkdir(parents=True, exist_ok=False)
    return d, cand


# ---------------------------------------------------------------------------
# EXECUTE (move to quarantine) / RESTORE
# ---------------------------------------------------------------------------
def _quarantine_one(target: Path, rel: str, dest_files: Path, want_sha: str,
                    companion: bool = False) -> int:
    """Move one planned regular file into quarantine after re-verifying every safety
    property. The original is unlinked ONLY after the copy is hash-verified."""
    if is_kept(rel):
        raise ScopeError(f"keep-list violated at purge time: {rel}")
    if classify(rel, companion=companion) != "purge":
        raise ScopeError(f"not classified purge at purge time: {rel}")
    p = target / rel
    if not _norm(p).startswith(_norm(target) + os.sep):
        raise ScopeError(f"path escaped target: {p}")
    if _norm(os.path.realpath(p)) != _norm(p):
        raise ScopeError(f"path resolves through a link at purge time: {p}")
    st = os.lstat(p)
    if is_reparse(p) or not stat.S_ISREG(st.st_mode):
        raise ScopeError(f"not a regular file at purge time: {p}")
    dest = dest_files / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, dest)
    if _sha256(dest) != want_sha:
        dest.unlink()
        raise OSError("quarantine copy failed hash verification (file changed?); original kept")
    if not st.st_mode & stat.S_IWRITE:
        os.chmod(p, st.st_mode | stat.S_IWRITE)
    os.unlink(p)
    return st.st_size


def execute_plan(plan: Plan, repo, name: str, reason: str, now=None):
    """-> (moved, bytes, errors, entry_dir|None, stamp|None)"""
    now = _now() if now is None else now
    qroot = quarantine_root()
    _require_outside_repo(repo, qroot)
    entry, stamp = _new_entry_dir(qroot, name, now)
    files, errors = [], []
    for rel, size in plan.purge:
        try:
            files.append({"rel": rel, "size": size, "sha256": _sha256(plan.target / rel)})
        except OSError as e:
            errors.append(f"{rel}: {e}")
    manifest = {"case_purge_quarantine": QUARANTINE_SCHEMA, "case": name, "repo_id": repo_id(repo),
                "reason": reason, "purged_epoch": int(now), "purged_at": _utc_iso(now),
                "expires_at": _utc_iso(now + QUARANTINE_TTL_SECONDS), "files": files}
    tmp = entry / "manifest.json.tmp"
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, entry / "manifest.json")     # manifest exists BEFORE anything is moved
    moved = freed = 0
    touched_dirs: set[str] = set()
    for f in files:
        rel = f["rel"]
        try:
            freed += _quarantine_one(plan.target, rel, entry / "files", f["sha256"],
                                   companion=rel in plan.companions)
            moved += 1
            d = rel.rsplit("/", 1)[0] if "/" in rel else ""
            while d:
                touched_dirs.add(d)
                d = d.rsplit("/", 1)[0] if "/" in d else ""
        except ScopeError:
            raise
        except OSError as e:
            errors.append(f"{rel}: {e}")
    # Remove only directories that became empty because of us. os.rmdir fails on
    # non-empty dirs, so this can never delete content. Deepest first.
    for d in sorted(touched_dirs, key=lambda s: s.count("/"), reverse=True):
        if is_kept(d + "/x"):
            continue
        p = plan.target / d
        try:
            if not is_reparse(p) and not any(os.scandir(p)):
                os.rmdir(p)
        except OSError:
            pass
    if moved == 0:
        _rmtree(entry)
        return 0, 0, errors, None, None
    return moved, freed, errors, entry, stamp


def knowledge_recorded(target: Path) -> bool:
    """True if the case kept a record: a non-empty REPORT.md, or a knowledge/ holding
    at least one regular file. Never follows links."""
    rp = target / "REPORT.md"
    try:
        if not is_reparse(rp) and rp.is_file() and rp.stat().st_size > 0:
            return True
    except OSError:
        pass
    kd = target / "knowledge"
    try:
        if is_reparse(kd) or not kd.is_dir():
            return False
    except OSError:
        return False
    for _root, dirs, files in os.walk(kd, followlinks=False):
        dirs[:] = [d for d in dirs if not is_reparse(os.path.join(_root, d))]
        if any(not is_reparse(os.path.join(_root, f)) for f in files):
            return True
    return False


def do_purge(repo, name, execute: bool, reason: str, confirm: bool = False) -> int:
    repo, target = resolve_case_target(repo, name)       # may raise ScopeError
    if reason == "solved" and not knowledge_recorded(target):
        # 'solved' means the lesson was kept. With no REPORT.md and no knowledge/ the
        # artifacts would be the only record and vanish after the quarantine expires.
        raise ScopeError(
            f"case {name!r} is marked solved but has neither a REPORT.md nor a non-empty "
            f"knowledge/. Nothing was purged, so the artifacts stay. Write cases/{name}/REPORT.md "
            f"(or add files under knowledge/) and close it again; use 'case: abandoned {name}' "
            f"if there is nothing to record.")
    plan = build_plan(target)                            # may raise ScopeError
    print_plan(plan, name)
    if not plan.purge:
        print("nothing to purge.")
        return 0
    if not execute:
        print(f"\nDRY RUN: nothing was moved. Re-run with --execute to quarantine the "
              f"{len(plan.purge)} files listed under WILL MOVE TO QUARANTINE.")
        return 0
    if confirm:
        ans = input(f"\nType the case name ({name}) to confirm: ").strip()
        if ans != name:
            print("confirmation mismatch; nothing moved.")
            return 0
    moved, freed, errors, entry, stamp = execute_plan(plan, repo, name, reason)
    if entry is not None:
        print(f"\nQUARANTINED {moved} files, {human(freed)}, into {_disp(entry)}")
        print(f"Expires in 7 days. Undo with: scripts/case_purge.py restore {name} --stamp {stamp}")
    for e in errors:
        print(f"FAILED  {e}", file=sys.stderr)
    return 4 if errors else 0


def _safe_rel(rel) -> bool:
    if not isinstance(rel, str) or rel == "" or "\\" in rel or ":" in rel or rel.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in rel.split("/"))


def _restore_one(target: Path, entry: Path, f) -> str:
    """-> 'restored' | 'exists' | 'absent' | error text starting with '!'"""
    rel = f.get("rel") if isinstance(f, dict) else None
    if not _safe_rel(rel) or is_kept(rel):
        return f"!unsafe path in manifest: {rel!r}"
    src, dest = entry / "files" / rel, target / rel
    if not src.is_file() or is_reparse(src):
        return "absent"                                  # never reached quarantine; original stayed
    if _sha256(src) != f.get("sha256"):
        return f"!{rel}: quarantined copy fails its hash"
    if os.path.lexists(dest):
        return "exists"
    chk = target
    for part in Path(rel).parent.parts:                  # never restore through a link
        chk = chk / part
        if os.path.lexists(chk) and is_reparse(chk):
            return f"!{rel}: parent is a link"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    if _sha256(dest) != f["sha256"]:
        dest.unlink()
        return f"!{rel}: restored copy failed verification"
    return "restored"


def do_restore(repo_arg, name, stamp=None) -> int:
    repo, target = resolve_case_target(repo_arg, name)   # same fence as purge
    qroot = quarantine_root()
    _require_outside_repo(repo, qroot)
    mine = [(s, e, m) for c, s, e, m in iter_quarantine(qroot)
            if c == name and m is not None and m.get("repo_id") == repo_id(repo)]
    if stamp is not None:
        if not STAMP_RE.fullmatch(stamp):
            raise ScopeError(f"illegal stamp {stamp!r}")
        mine = [x for x in mine if x[0] == stamp]
    if not mine:
        print(f"no quarantine entry for case {name}" + (f" with stamp {stamp}" if stamp else "") + ".")
        return 1
    st, entry, m = mine[-1]                              # newest (stamps sort chronologically)
    counts = {"restored": 0, "exists": 0, "absent": 0}
    rc = 0
    for f in m["files"]:
        r = _restore_one(target, entry, f)
        if r.startswith("!"):
            print(f"SKIP {r[1:]}", file=sys.stderr)
            rc = 4
        else:
            counts[r] += 1
            if r == "exists":
                print(f"exists, left alone: {f['rel']}")
    print(f"RESTORED {counts['restored']} files into {CASES_DIRNAME}/{name} from {name}/{st} "
          f"({counts['exists']} already present). The quarantine copy is kept until it expires.")
    return rc


# ---------------------------------------------------------------------------
# QUARANTINE LISTING / DOCTOR (read-only)
# ---------------------------------------------------------------------------
def _fmt_remaining(sec: float) -> str:
    if sec <= 0:
        return "expired (pending sweep)"
    d, rem = divmod(int(sec), 86400)
    return f"{d}d {rem // 3600}h"


def do_quarantine_list(now=None) -> int:
    now = _now() if now is None else now
    n = 0
    for case, stamp, entry, m in iter_quarantine(quarantine_root()):
        n += 1
        if m is None:
            print(f"{case:30} {stamp:20} (no valid manifest)")
            continue
        left = m["purged_epoch"] + QUARANTINE_TTL_SECONDS - now
        print(f"{case:30} {stamp:20} {len(m['files']):5} files {human(_dir_bytes(entry)):>10}  "
              f"expires in {_fmt_remaining(left)}")
    if not n:
        print("quarantine is empty.")
    return 0


def _scan_size(p: Path, cap: int = 200_000) -> tuple[int, int]:
    files = total = 0
    stack = [p]
    while stack and files < cap:
        with os.scandir(stack.pop()) as it:
            for e in it:
                if is_reparse(e.path):
                    continue
                if e.is_dir(follow_symlinks=False):
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    files += 1
                    total += e.stat(follow_symlinks=False).st_size
    return files, total


def _scan_stats(p: Path, cap: int = 200_000) -> tuple[int, int, float | None, bool]:
    """-> (files, bytes, newest_mtime|None, truncated). Read-only, never follows links."""
    files = total = 0
    newest = None
    stack = [p]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    if is_reparse(e.path):
                        continue
                    if e.is_dir(follow_symlinks=False):
                        stack.append(Path(e.path))
                    elif e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        files += 1
                        total += st.st_size
                        newest = st.st_mtime if newest is None else max(newest, st.st_mtime)
                        if files >= cap:
                            return files, total, newest, True
        except OSError:
            continue
    return files, total, newest, False


# Where the rules send samples and tool output. The purge never walks these (it only
# walks marked cases/<name>), so doctor reports them to keep accumulation visible.
OUT_OF_SCOPE_DIRS = ("samples", "out", "runs", "dataset")


def _fmt_age(sec: float) -> str:
    sec = max(0, int(sec))
    d, rem = divmod(sec, 86400)
    return f"{d}d {rem // 3600}h" if d else f"{rem // 3600}h {rem % 3600 // 60}m"


ADOPT_HINT = ('  To adopt one, create cases/<name>/' + MARKER + ' containing\n'
              '  {"liebert_case": 1, "name": "<name>", "status": "open"}'
              '  (this tool will not do it for you)')


def do_doctor(repo_arg, now=None) -> int:
    """REPORT ONLY. Never creates, moves, deletes or rewrites anything."""
    now = _now() if now is None else now
    repo = Path(os.path.realpath(str(find_repo(repo_arg))))
    print("doctor: report only, nothing is modified.")
    root = repo / CASES_DIRNAME
    unmarked = 0
    print(f"\n[cases] directories under {CASES_DIRNAME}/ that the purge cannot see:")
    if not root.is_dir() or is_reparse(root):
        print("  (no cases/ directory)")
    else:
        for e in sorted(os.scandir(root), key=lambda x: x.name):
            if not (e.is_dir(follow_symlinks=False) or is_reparse(e.path)):
                continue
            try:
                resolve_case_target(repo, e.name)
                continue                                  # valid, marked case
            except ScopeError as err:
                reason = str(err).replace(str(repo), "<repo>")
            unmarked += 1
            if is_reparse(e.path):
                print(f"  {e.name:30} {reason}")
            else:
                n, b = _scan_size(Path(e.path))
                print(f"  {e.name:30} {n} files, {human(b)}  -- {reason}")
        if unmarked:
            print(f"  {unmarked} unmarked/invalid. Their artifacts are NOT purged and will accumulate.")
            print(ADOPT_HINT)
        else:
            print("  none.")
    print("\n[outside purge scope] the purge never looks here; report only, nothing is touched:")
    for dn in OUT_OF_SCOPE_DIRS:
        d = repo / dn
        if not os.path.lexists(d):
            print(f"  {dn + '/':10} (absent)")
        elif is_reparse(d) or not d.is_dir():
            print(f"  {dn + '/':10} skipped: symlink/junction or not a directory")
        else:
            n, b, newest, trunc = _scan_stats(d)
            age = "empty" if newest is None else f"newest file {_fmt_age(now - newest)} old"
            print(f"  {dn + '/':10} {n}{'+' if trunc else ''} files, {human(b)}, {age}")
    qroot = quarantine_root()
    entries = list(iter_quarantine(qroot))
    total = sum(_dir_bytes(e) for _, _, e, _ in entries)
    print(f"\n[quarantine] {_disp(qroot)}: {len(entries)} entries, {human(total)}")
    soon, expired = [], []
    for case, stamp, entry, m in entries:
        left = (m["purged_epoch"] if m else int(entry.stat().st_mtime)) + QUARANTINE_TTL_SECONDS - now
        if left <= 0:
            expired.append(f"{case}/{stamp}")
        elif left <= EXPIRING_SOON_SECONDS:
            soon.append(f"{case}/{stamp} (in {_fmt_remaining(left)})")
    print(f"  expiring within {EXPIRING_SOON_SECONDS // 86400} days: " + (", ".join(soon) or "none"))
    print("  already expired, awaiting the next sweep: " + (", ".join(expired) or "none"))
    return 0


# ---------------------------------------------------------------------------
# COMMIT MARKER PARSING
# ---------------------------------------------------------------------------
# The line must START with the marker (so quoted/indented text and prose do not
# fire) and may have at most one trailing token: the case name.
MARKER_LINE = re.compile(r"(?i)case:[ \t]*(solved|abandoned)(?:[ \t]+(\S+))?[ \t]*")
LOOSE_MARKER = re.compile(r"(?i)case:[ \t]*(solved|abandoned)")


def parse_close_markers(msg: str):
    """-> (list[(reason, name|None)], list[str] ignored_lines)"""
    found, ignored = [], []
    for line in msg.splitlines():
        m = MARKER_LINE.fullmatch(line.rstrip("\r"))
        if m:
            found.append((m.group(1).lower(), m.group(2)))
        elif LOOSE_MARKER.search(line):
            ignored.append(line.strip())
    return found, ignored


def git_commit_message(repo, rev: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%B", rev],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"git log failed: {r.stderr.strip()}")
    return r.stdout


def do_from_commit(repo, rev: str, execute: bool) -> int:
    msg = git_commit_message(repo, rev)
    found, ignored = parse_close_markers(msg)
    for line in ignored:
        print(f"case_purge: ignoring marker-like line (not exactly 'case: solved|abandoned NAME'): {line!r}")
    if not found:
        return 0
    rc, seen = 0, set()
    for reason, name in found:
        if name is None:
            print(f"case_purge: commit has 'case: {reason}' but names no case; NOTHING purged. "
                  f"Use 'case: {reason} <name>' or run: scripts/case_purge.py purge <name>")
            continue
        if name in seen:
            continue
        seen.add(name)
        try:
            rc = max(rc, do_purge(repo, name, execute, reason))
        except CaseNotFound as e:
            print(f"case_purge: {e}; nothing to do.")
        except ScopeError as e:
            print(f"case_purge: REFUSED ({name!r}): {e}", file=sys.stderr)
            rc = max(rc, 3)
    return rc


# ---------------------------------------------------------------------------
# REPO DISCOVERY, HOOK GLUE
# ---------------------------------------------------------------------------
def find_repo(arg, fallback=None) -> Path:
    """--repo, then $CLAUDE_PROJECT_DIR, then `fallback` (hook JSON cwd), then git toplevel."""
    if arg:
        return Path(arg)
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env)
    if fallback:
        return Path(fallback)
    r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if r.returncode != 0:
        raise ScopeError("cannot locate repo (pass --repo)")
    return Path(r.stdout.strip())


def do_claude_hook(repo_arg) -> int:
    """PostToolUse adapter. Never blocks, never exits 2."""
    try:
        data = json.loads(sys.stdin.read() or "{}")
        cmd = ((data.get("tool_input") or {}).get("command")) or ""
        if not re.search(r"\bgit\b[^\n]*\bcommit\b", cmd):
            return 0
        repo = find_repo(repo_arg, data.get("cwd"))
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            do_from_commit(repo, "HEAD", True)
        text = buf.getvalue().strip()
        if text:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": text[-4000:]}}))
    except Exception as e:  # a hook must never wedge the session
        print(f"case_purge claude-hook: {e}", file=sys.stderr)
    return 0


HOOK_TAG = "# liebert-case-purge (managed by scripts/case_purge.py install-hook)"
HOOK_TEMPLATE = """#!/bin/sh
{tag}
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
script="$root/scripts/case_purge.py"
[ -f "$script" ] || exit 0
PY='{py}'
[ -x "$PY" ] || PY=python
"$PY" "$script" --repo "$root" from-commit --execute || true
exit 0
"""


def hook_path(repo: Path) -> Path:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-path", "hooks"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise ScopeError("git rev-parse --git-path failed")
    p = Path(r.stdout.strip())
    return (p if p.is_absolute() else repo / p) / "post-commit"


def do_install_hook(repo_arg, force: bool, check: bool) -> int:
    repo = Path(os.path.realpath(str(find_repo(repo_arg))))
    hp = hook_path(repo)
    ours = hp.exists() and HOOK_TAG in hp.read_text(encoding="utf-8", errors="replace")
    if check:
        print(f"post-commit hook {'INSTALLED' if ours else 'NOT installed'}: {hp}")
        return 0 if ours else 1
    py = Path(sys.executable).as_posix()
    if "'" in py:
        raise ScopeError("interpreter path contains a single quote")
    if hp.exists() and not ours and not force:
        print(f"refusing: {hp} exists and is not ours (use --force to overwrite)", file=sys.stderr)
        return 3
    if not (repo / "scripts" / "case_purge.py").is_file():
        print("warning: scripts/case_purge.py not found in repo; hook will no-op until it is.")
    hp.parent.mkdir(parents=True, exist_ok=True)
    with open(hp, "w", encoding="utf-8", newline="\n") as f:
        f.write(HOOK_TEMPLATE.format(tag=HOOK_TAG, py=py))
    try:
        os.chmod(hp, 0o755)
    except OSError:
        pass
    print(f"installed {hp} (python: {py})")
    return 0


# ---------------------------------------------------------------------------
def do_init(repo_arg, name) -> int:
    name = validate_name(name)
    repo = Path(os.path.realpath(str(find_repo(repo_arg))))
    if not (repo / ".git").exists():
        raise ScopeError(f"not a git repo root: {repo}")
    t = repo / CASES_DIRNAME / name
    t.mkdir(parents=True, exist_ok=False)
    (t / MARKER).write_text(json.dumps({"liebert_case": MARKER_VERSION, "name": name,
                                        "status": "open",
                                        "created": time.strftime("%Y-%m-%dT%H:%M:%S")},
                                       indent=2) + "\n", encoding="utf-8")
    (t / "knowledge").mkdir()
    print(f"created {CASES_DIRNAME}/{name}")
    return 0


def do_list(repo_arg) -> int:
    repo = Path(os.path.realpath(str(find_repo(repo_arg))))
    root = repo / CASES_DIRNAME
    if not root.is_dir():
        print("no cases/ directory")
        return 0
    for p in sorted(root.iterdir()):
        try:
            _, target = resolve_case_target(repo, p.name)
            plan = build_plan(target)
            meta = json.loads((target / MARKER).read_text(encoding="utf-8"))
            print(f"{p.name:30} {meta.get('status', '?'):8} purgeable: "
                  f"{len(plan.purge)} files, {human(plan.purge_bytes)}")
        except ScopeError as e:
            print(f"{p.name:30} SKIPPED ({e})")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="case_purge", description=__doc__.split("\n")[0])
    ap.add_argument("--repo", help="repo root (default: $CLAUDE_PROJECT_DIR, then git toplevel)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init")
    s.add_argument("name")
    sub.add_parser("list")
    s = sub.add_parser("purge")
    s.add_argument("name")
    s.add_argument("--execute", action="store_true", help="actually delete (default is dry-run)")
    s.add_argument("--yes", action="store_true", help="skip the typed confirmation on a TTY")
    s.add_argument("--reason", default="manual", choices=["manual", "solved", "abandoned"])
    s = sub.add_parser("from-commit")
    s.add_argument("--rev", default="HEAD")
    s.add_argument("--execute", action="store_true", help="actually delete (default is dry-run)")
    sub.add_parser("claude-hook")
    sub.add_parser("quarantine", help="list quarantine entries")
    s = sub.add_parser("restore", help="restore a quarantined purge of NAME (newest unless --stamp)")
    s.add_argument("name")
    s.add_argument("--stamp")
    sub.add_parser("doctor", help="report-only health check")
    s = sub.add_parser("install-hook")
    s.add_argument("--force", action="store_true")
    s.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.cmd != "doctor":                    # doctor must not modify anything, not even expiry
            _auto_sweep()
        if a.cmd == "claude-hook":
            return do_claude_hook(a.repo)
        if a.cmd == "init":
            return do_init(a.repo, a.name)
        if a.cmd == "install-hook":
            return do_install_hook(a.repo, a.force, a.check)
        if a.cmd == "quarantine":
            return do_quarantine_list()
        if a.cmd == "doctor":
            return do_doctor(a.repo)
        if a.cmd == "restore":
            return do_restore(find_repo(a.repo), a.name, a.stamp)
        repo = find_repo(a.repo)
        if a.cmd == "list":
            return do_list(repo)
        if a.cmd == "purge":
            return do_purge(repo, a.name, a.execute, a.reason,
                            confirm=a.execute and not a.yes and sys.stdin.isatty())
        if a.cmd == "from-commit":
            return do_from_commit(repo, a.rev, a.execute)
    except ScopeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
