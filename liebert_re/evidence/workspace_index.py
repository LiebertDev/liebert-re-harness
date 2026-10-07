"""Incremental, bounded workspace index backed by SQLite FTS5.

The index is metadata only: workspace files are never modified.  It provides
deterministic perception for the planner and retrieval layers without an
embedding model dependency.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from liebert_re.evidence.process_lock import DurableLock

from liebert_re.workspace import PROJECT_ROOT as APP
INDEX_ROOT = APP / "dataset" / "metadata" / "workspace_indexes"
# Basename-level, unconditional exclusions: dependency/tool/vendor install
# trees that are never useful for self-analysis retrieval, regardless of
# budget. `external` (this project's own vendored-toolchain directory, e.g.
# a bundled Zig cross-compiler with its own libc headers) belongs in the
# same category as `node_modules`/`models`/`checkpoints` -- fully gitignored,
# zero tracked files, third-party content, not project source. Measured
# directly against this repo: `external/` alone was ~76% of every file
# os.walk() would otherwise see (20,628 of 27,286), starving out `tests/`,
# `prompts/`, `ghidra_scripts/`, `ida_scripts/`, `runpod/`, `smoke-tests/`,
# and `offline_training/` entirely under the old single-cutoff walk.
EXCLUDED = {".git", ".venv", "__pycache__", "node_modules", ".vs", "cache", "ghidra_projects", "checkpoints", "models", "external",
    # Self-referential output tree: WorkspaceIndex writes its own sqlite
    # db(s) under INDEX_ROOT (dataset/metadata/workspace_indexes[...]).
    # Measured live on this repo (2026-09-26): this directory held 469
    # sqlite files totalling ~1.14GB (one per workspace ever indexed on
    # this machine, never pruned) plus a sibling `workspace_indexes_session`
    # directory with a single actively-growing ~549MB db from a
    # concurrently-running process. Before this exclusion, refresh()'s own
    # os.walk() entered that directory like any other, paying resolve()+
    # stat() (and, if selected as a PRIMARY candidate -- see
    # DEFERRED_PREFIXES below -- a full sha256 hash up to MAX_HASH_BYTES)
    # against files that are (a) not source/docs, (b) can be actively
    # mutated mid-read by another live indexing process, and (c) grow
    # without bound over the life of the machine. This is the leading
    # candidate for the observed 3+ hour DurableLock hold: hashing/reading
    # a several-hundred-MB file while a *different* process is still
    # appending to it (WAL growth) is exactly the kind of contention this
    # exclusion removes entirely rather than trying to detect at read time.
    "workspace_indexes", "workspace_indexes_session"}
# Path *prefixes* (relative to the indexed workspace root, POSIX-separated)
# of real, harness-generated or historical content: worth finding if the
# max_files budget allows, but must never crowd out canonical source/tests
# just because os.walk() happens to reach them before smaller canonical
# directories -- confirmed on this repo's own filesystem ordering, where
# `dataset/` (dominated by `dataset/evidence/` and `dataset/runtime/`, both
# gitignored generated state) is visited by os.walk() before `tests/`.
# Indexed in a deterministic second pass, after all non-deferred content,
# only with whatever budget remains -- see `refresh()`.
# Measured live on this repo (2026-09-26): `dataset/` as a whole is 118,609
# of 125,687 total post-EXCLUDED candidate files (94.4%) -- not just
# `dataset/evidence`/`dataset/runtime`. `dataset/metadata` alone (reports,
# claim/evidence index sidecars, and -- pre-exclusion above -- the index's
# own sqlite output) was 26,444 files / ~2.8GB; `dataset/claims` and
# `dataset/tmp` are further real-but-generated event-sourced/scratch trees.
# Deferring only two of dataset/'s subdirectories left the rest (metadata,
# claims, tmp, cleaned, ...) competing as PRIMARY against real source --
# unbounded, and ahead of `tests/`/`prompts/`/etc. in the priority bucket
# purely by walk-order accident, the exact starvation class this file's
# other comments already document. A single "dataset" prefix covers every
# subdirectory (prefix-matched below), preserving the existing, tested
# behavior that dataset content is still discoverable when budget allows
# (see tests/test_workspace_index_priority.py) while no longer treating any
# part of it as higher-priority than canonical source.
DEFERRED_PREFIXES = ("dataset", "docs/archive")
# Hard ceiling on raw walk enumeration (stat() calls only, before any
# hashing/text-reading), independent of `max_files` -- bounds worst-case
# walk cost against a pathological workspace without limiting the two-bucket
# prioritization logic below, which needs to see the *whole* eligible set
# (up to this ceiling) to prioritize correctly rather than stopping at the
# first max_files files encountered in raw walk order.
MAX_WALK_CANDIDATES = 200_000
MAX_TEXT_BYTES = 4_000_000
MAX_HASH_BYTES = 512_000_000
MAX_CHUNKS_PER_FILE = 250
CHUNK_CHARS = 2400
MAX_FILES_FLOOR = 1
MAX_FILES_CEILING = 100_000
MAX_FILES_DEFAULT = 12_000
SCHEMA_VERSION = "2"


def _clamp_max_files_with_report(value):
    """Same honest-clamp shape as ``tools_memory_scan._clamp_with_report``
    (parameter/requested/applied/min/max/clamped/reason) -- ``max_files`` was
    silently coerced into ``[1, 100000]`` with no way for a caller to see
    whether their request was honoured, the same DEFECT-1 class that module
    fixed for its own bounded numeric parameters."""
    requested = value
    try:
        parsed = int(value)
        unparsable = False
    except (TypeError, ValueError):
        parsed = MAX_FILES_DEFAULT
        unparsable = True
    if unparsable:
        applied = MAX_FILES_DEFAULT
        reason = "UNPARSEABLE_USED_DEFAULT"
    elif parsed < MAX_FILES_FLOOR:
        applied = MAX_FILES_FLOOR
        reason = "BELOW_MINIMUM_RAISED_TO_FLOOR"
    elif parsed > MAX_FILES_CEILING:
        applied = MAX_FILES_CEILING
        reason = "ABOVE_MAXIMUM_LOWERED_TO_CEILING"
    else:
        applied = parsed
        reason = "WITHIN_BOUNDS"
    return applied, {
        "parameter": "max_files", "requested": requested, "applied": applied,
        "min": MAX_FILES_FLOOR, "max": MAX_FILES_CEILING,
        "clamped": reason != "WITHIN_BOUNDS", "reason": reason,
    }
TEXT_EXTENSIONS = {
    ".py", ".cs", ".c", ".h", ".cpp", ".hpp", ".java", ".js", ".jsx", ".ts", ".tsx",
    ".go", ".rs", ".lua", ".ps1", ".sh", ".rb", ".php", ".gd", ".json", ".jsonl", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv", ".log", ".md", ".txt", ".sql",
    ".sln", ".csproj", ".fsproj", ".vcxproj", ".gradle", ".properties", ".proto", ".graphql",
}
LANGUAGE = {
    ".py": "Python", ".cs": "C#", ".c": "C", ".h": "C/C++", ".cpp": "C++", ".hpp": "C++",
    ".java": "Java", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".rs": "Rust", ".lua": "Lua", ".ps1": "PowerShell", ".sh": "Shell", ".rb": "Ruby",
    ".php": "PHP", ".gd": "GDScript", ".sql": "SQL",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path):
    if path.stat().st_size > MAX_HASH_BYTES:
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _workspace_key(path: Path):
    return hashlib.sha256(str(path).casefold().encode("utf-8")).hexdigest()[:20]


def _simple_identity(path: Path):
    head = b""
    try:
        with path.open("rb") as stream:
            head = stream.read(64)
    except OSError:
        pass
    ext = path.suffix.lower()
    typ = "TEXT" if ext in TEXT_EXTENSIONS else "UNKNOWN"
    runtime = None
    if head.startswith(b"MZ"):
        typ = "PE"
    elif head.startswith(b"\x7fELF"):
        typ = "ELF"
    elif head[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        typ = "MACHO"
    elif head.startswith(b"\x00asm"):
        typ = "WASM"
    elif head.startswith(b"PK\x03\x04"):
        typ = {".apk": "APK", ".jar": "JAR", ".ipa": "IPA", ".whl": "PYTHON_WHEEL", ".nupkg": "NUGET"}.get(ext, "ZIP")
    elif head.startswith(b"SQLite format 3\x00"):
        typ = "SQLITE"
    elif head[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        typ = "PCAP"
    elif head.startswith(b"\x0a\x0d\x0d\x0a"):
        typ = "PCAPNG"
    elif head.startswith(b"MDMP"):
        typ = "MINIDUMP"
    elif head.startswith(b"dex\n"):
        typ = "DEX"
    elif head.startswith(b"\xca\xfe\xba\xbe"):
        typ = "JAVA_CLASS"
    elif ext == ".har":
        typ = "HAR"
    elif ext == ".dex" or head.startswith(b"dex\n"):
        typ = "DEX"
    elif ext in LANGUAGE:
        typ = "SOURCE"
    category = "SOURCE" if typ == "SOURCE" else "TEXT" if typ == "TEXT" else "UNKNOWN_BINARY" if typ == "UNKNOWN" else typ
    return {"type": typ, "category": category, "runtime": runtime, "language": LANGUAGE.get(ext), "extension": ext}


def _symbols_and_imports(text: str, ext: str):
    symbols, imports = [], []
    if ext == ".py":
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    symbols.append({"name": node.name, "kind": "class" if isinstance(node, ast.ClassDef) else "function", "line": node.lineno, "signature": node.name})
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [x.name for x in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    imports.extend({"name": name, "line": getattr(node, "lineno", None), "kind": "module"} for name in names if name)
            return symbols[:2000], imports[:2000]
        except Exception:
            pass
    rules = [
        (r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", "function"),
        (r"^\s*(?:public|private|protected|internal|static|async|virtual|override|export|pub|final|abstract|\s)*(?:class|interface|record|struct|enum|trait)\s+([A-Za-z_]\w*)", "type"),
        (r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$]\w*)", "function"),
        (r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)", "function"),
        (r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", "function"),
        # C/C++/WDM-style declarations: NTSTATUS DriverEntry(...) {
        (r"^\s*(?:[\w:<>\*]+\s+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:CONST)?\s*(?:\{|$)", "function"),
    ]
    import_rules = [
        r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., /:-]+))",
        r"^\s*(?:using|use|package)\s+([\w./:]+)",
        r"^\s*#include\s*[<\"]([^>\"]+)",
        r"(?:require\(|from\s+)[\"']([^\"']+)",
    ]
    for line_no, line in enumerate(text.splitlines(), 1):
        for pattern, kind in rules:
            match = re.search(pattern, line)
            if match:
                symbols.append({"name": match.group(1), "kind": kind, "line": line_no, "signature": line.strip()[:400]})
                break
        for pattern in import_rules:
            match = re.search(pattern, line)
            if match:
                value = next((x for x in match.groups() if x), "").strip()
                if value:
                    imports.append({"name": value, "line": line_no, "kind": "module"})
                break
    return symbols[:2000], imports[:2000]


def _chunks(text: str):
    result, buffer, start = [], [], 1
    size = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        buffer.append(line)
        size += len(line) + 1
        if size >= CHUNK_CHARS:
            result.append((start, line_no, "\n".join(buffer)))
            buffer, start, size = [], line_no + 1, 0
            if len(result) >= MAX_CHUNKS_PER_FILE:
                break
    if buffer and len(result) < MAX_CHUNKS_PER_FILE:
        result.append((start, start + len(buffer) - 1, "\n".join(buffer)))
    return result


class WorkspaceIndex:
    def __init__(self, workspace, db_path=None):
        self.workspace = Path(workspace).expanduser().resolve()
        if not self.workspace.is_dir():
            raise ValueError(f"workspace is not a directory: {self.workspace}")
        self.db_path = Path(db_path) if db_path else INDEX_ROOT / f"{_workspace_key(self.workspace)}.sqlite"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @contextlib.contextmanager
    def connect(self):
        # `with sqlite3.connect(...) as db` commits (or rolls back) but does NOT
        # close the connection -- a long-standing Python gotcha. Every caller here
        # used that form, so every call leaked an open handle plus its WAL
        # sidecars. Harmless-looking until it is not: on Windows an open handle
        # makes the file undeletable, which is how this surfaced (three tests
        # failing on 3.12 with WinError 32 while a TemporaryDirectory tried to
        # clean up index.sqlite).
        #
        # This wrapper keeps the exact transaction semantics callers already rely
        # on -- `with connection` commits on success and rolls back on an
        # exception -- and adds the close that was missing.
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _write_guard(self):
        # sqlite's own `timeout=30` busy-wait (see connect()) cannot tell a
        # live writer from a dead/orphaned one: reproduced live -- a
        # connection holding an open write transaction (simulating a
        # hung/orphaned worker) makes a second process's refresh() block for
        # the full 30s and then raise sqlite3.OperationalError: database is
        # locked, with no recovery and no way to tell it was an orphaned
        # holder rather than a live one. This lock file wraps the write
        # transaction with a liveness-aware, cross-process lock instead: a
        # dead holder's lock is reclaimed (visibly recorded) after a bounded
        # grace period, a live holder is waited on.
        # Dash separator, not dot: matches the existing sqlite-sidecar
        # exclusion below (`path.name.startswith(self.db_path.name + "-")`)
        # so this lock file (and its own ".recovery.jsonl" companion) is
        # never walked back in as an indexable candidate of the very
        # workspace refresh() it is guarding -- a dot-suffixed name isn't
        # covered by that check and was reproduced live inflating file
        # counts by exactly one entry while the lock was held.
        # timeout_seconds is generous (not the primary safety mechanism):
        # reproduced live -- serializing refresh()'s full os.walk()+hash+
        # insert body (previously allowed to overlap via sqlite's own WAL
        # concurrency) behind one exclusive lock means a queued-but-live
        # refresh() over a large real workspace can legitimately take
        # several minutes. A live holder is NEVER reclaimed regardless of
        # this bound (see _try_reclaim_if_dead(): only a confirmed-dead PID
        # is ever reclaimed, after the much shorter stale_seconds grace) --
        # this ceiling only protects against the case where liveness can
        # never be confirmed either way, so it favors "wait" over "fail".
        return DurableLock(
            self.db_path.parent / (self.db_path.name + "-writelock"), stale_seconds=30, timeout_seconds=600,
        )

    def _schema_already_current(self) -> bool:
        # Fast path, deliberately NOT protected by _write_guard(): reproduced
        # live (py-spy, 2026-09-26) that __init__ -> _ensure_schema() took
        # the heavy, liveness-aware DurableLock *unconditionally* on every
        # WorkspaceIndex construction, even when this db's schema was
        # already fully created -- so a process that only wanted to read
        # status()/search() (or another process's own unrelated refresh() on
        # the same shared workspace, e.g. every test that leaves
        # the workspace environment variable unset and defaults to the repo root) blocked for
        # up to the lock's own 600s ceiling behind a live, unrelated,
        # multi-minute refresh() -- purely to run idempotent
        # "CREATE TABLE IF NOT EXISTS" statements that would have been a
        # no-op anyway. A plain read of `meta.schema_version` is safe to do
        # without the write lock: `connect()` always sets
        # `PRAGMA journal_mode=WAL`, and WAL's whole point is that readers
        # never block on -- and are never blocked by -- a concurrent writer.
        # Only a genuinely new or outdated db (schema missing/mismatched)
        # falls through to the slow, lock-protected create/upgrade path.
        if not self.db_path.exists():
            return False
        try:
            # closing() for the same reason as connect() above: the `with`
            # statement on a connection does not close it.
            with contextlib.closing(sqlite3.connect(self.db_path, timeout=5)) as probe:
                row = probe.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()
        except sqlite3.Error:
            return False
        return row is not None and row[0] == SCHEMA_VERSION

    def _ensure_schema(self):
        if self._schema_already_current():
            return
        with self._write_guard(), self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS files(
                    id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                    sha256 TEXT, type TEXT, runtime TEXT, language TEXT, extension TEXT, metadata_json TEXT,
                    indexed_text INTEGER NOT NULL DEFAULT 0, index_error TEXT, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chunks(
                    id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    chunk_no INTEGER NOT NULL, line_start INTEGER, line_end INTEGER, content TEXT NOT NULL,
                    UNIQUE(file_id, chunk_no)
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(content, content='chunks', content_rowid='id', tokenize='unicode61');
                CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
                    INSERT INTO chunks_fts(rowid,content) VALUES(new.id,new.content);
                END;
                CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
                    INSERT INTO chunks_fts(chunks_fts,rowid,content) VALUES('delete',old.id,old.content);
                END;
                CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
                    INSERT INTO chunks_fts(chunks_fts,rowid,content) VALUES('delete',old.id,old.content);
                    INSERT INTO chunks_fts(rowid,content) VALUES(new.id,new.content);
                END;
                CREATE TABLE IF NOT EXISTS symbols(
                    id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    name TEXT NOT NULL, kind TEXT, line INTEGER, signature TEXT
                );
                CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(name COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS imports(
                    id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    name TEXT NOT NULL, kind TEXT, line INTEGER
                );
                CREATE INDEX IF NOT EXISTS imports_name_idx ON imports(name COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS index_runs(
                    id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT, scanned INTEGER DEFAULT 0,
                    changed INTEGER DEFAULT 0, unchanged INTEGER DEFAULT 0, removed INTEGER DEFAULT 0,
                    errors INTEGER DEFAULT 0, truncated INTEGER DEFAULT 0
                );
            """)
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('workspace',?)", (str(self.workspace),))
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))

    def refresh(self, max_files=MAX_FILES_DEFAULT):
        max_files, _max_files_clamp = _clamp_max_files_with_report(max_files)
        started = _now()
        # Enumeration (os.walk + per-file resolve()/stat()) intentionally
        # runs BEFORE and OUTSIDE `_write_guard()`/`connect()`: it reads only
        # the filesystem, never the database, so serializing it behind the
        # cross-process DurableLock only grew every *other* process's wait
        # time with zero correctness benefit -- reproduced live (2026-09-26)
        # as a 3+ hour lock hold whose time was almost entirely spent in this
        # walk, not in any sqlite write. Only the diff-against-`existing`/
        # insert/update phase below touches shared db state and needs the
        # lock.
        try:
            db_path_resolved = self.db_path.resolve()
            db_path_parent_resolved = self.db_path.parent.resolve()
        except OSError:
            db_path_resolved = self.db_path
            db_path_parent_resolved = self.db_path.parent
        # Two priority buckets, not a single first-N cutoff: `primary` is
        # canonical project content; `deferred` matches DEFERRED_PREFIXES
        # (real but generated/historical trees -- worth finding if budget
        # allows, but must never starve out source/tests just because
        # os.walk()'s filesystem-dependent order happens to reach them
        # first). Both buckets are collected from a full walk (bounded by
        # MAX_WALK_CANDIDATES, not max_files) so prioritization is
        # deterministic rather than an accident of walk order -- measured
        # directly against this repo: os.walk() visits `dataset/` before
        # `tests/`, which a naive single-cutoff would silently starve.
        primary, deferred = [], []
        worktree_roots = set()
        errors = 0
        for root, dirs, names in os.walk(self.workspace):
            pruned = []
            for name in dirs:
                lowered = name.lower()
                # Prefix match (not just the exact ".venv" entry in
                # EXCLUDED): this repo alone also has `.venv-graphify` and
                # `.venv-emulation` as separate, equally heavy interpreter
                # trees (measured live: 2,981 and 1,496 files respectively)
                # that an exact-name check silently let through the walk.
                if lowered in EXCLUDED or lowered.startswith(".venv"):
                    continue
                child = Path(root) / name
                # A directory that itself owns a `.git` entry (file or
                # dir) is a separate repository root -- most commonly a
                # `git worktree` checkout nested inside this tree (e.g.
                # `.claude/worktrees/<name>`), which is a full duplicate
                # of project content on a different branch, not unique
                # canonical material. Detected generically (any nested
                # `.git`), not as a hardcoded `.claude/worktrees` path,
                # so it also covers any future nested-repo case.
                if (child / ".git").exists():
                    worktree_roots.add(str(child))
                    continue
                pruned.append(name)
            dirs[:] = pruned
            try:
                root_rel = Path(root).relative_to(self.workspace).as_posix()
            except ValueError:
                root_rel = ""
            is_deferred_dir = any(
                root_rel == prefix or root_rel.startswith(prefix + "/") for prefix in DEFERRED_PREFIXES
            )
            for name in names:
                path = Path(root) / name
                if name.casefold() in {".env", ".env.local", ".env.production", ".env.development"} or name.casefold().endswith(".bak"):
                    continue
                try:
                    resolved_path = path.resolve()
                except OSError:
                    continue
                if resolved_path != self.workspace and self.workspace not in resolved_path.parents:
                    continue
                # Single resolve() per file, reused for both the
                # workspace-containment check above and this db-sidecar
                # exclusion below -- previously two separate path.resolve()
                # calls per file, PLUS self.db_path.resolve() and
                # self.db_path.parent.resolve() each recomputed fresh on
                # every single file instead of once per refresh() call.
                # Measured live: resolve() costs ~4x stat()'s syscalls on
                # this filesystem (0.176ms vs 0.047ms/file average over a
                # 20k-file sample), so halving the per-file resolve() count
                # and hoisting the two workspace-invariant ones out of the
                # loop directly cuts the walk's dominant cost.
                if resolved_path == db_path_resolved or (resolved_path.parent == db_path_parent_resolved and path.name.startswith(self.db_path.name + "-")):
                    continue
                try:
                    rel = path.relative_to(self.workspace).as_posix()
                    stat = path.stat()
                except OSError:
                    errors += 1
                    continue
                (deferred if is_deferred_dir else primary).append((rel, path, stat))
            if len(primary) + len(deferred) >= MAX_WALK_CANDIDATES:
                break
        walk_truncated = (len(primary) + len(deferred)) >= MAX_WALK_CANDIDATES
        total_eligible = len(primary) + len(deferred)
        candidates = primary[:max_files]
        if len(candidates) < max_files:
            candidates += deferred[: max_files - len(candidates)]
        deferred_included = max(0, len(candidates) - min(len(primary), max_files))

        with self._write_guard(), self.connect() as db:
            run_id = db.execute("INSERT INTO index_runs(started_at) VALUES(?)", (started,)).lastrowid
            existing = {row["path"]: row for row in db.execute("SELECT id,path,size,mtime_ns FROM files")}
            seen, changed, unchanged = set(), 0, 0
            for rel, path, stat in candidates:
                seen.add(rel)
                old = existing.get(rel)
                if old and old["size"] == stat.st_size and old["mtime_ns"] == stat.st_mtime_ns:
                    unchanged += 1
                    continue
                if old:
                    db.execute("DELETE FROM files WHERE id=?", (old["id"],))
                try:
                    identity = _simple_identity(path)
                    digest = _sha256(path)
                    if digest is None:
                        identity["hash_skipped"] = f"size>{MAX_HASH_BYTES}"
                    text = None
                    if path.suffix.lower() in TEXT_EXTENSIONS and stat.st_size <= MAX_TEXT_BYTES:
                        text = path.read_text(encoding="utf-8", errors="replace")
                    cursor = db.execute(
                        "INSERT INTO files(path,size,mtime_ns,sha256,type,runtime,language,extension,metadata_json,indexed_text,index_error,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rel, stat.st_size, stat.st_mtime_ns, digest, identity.get("type"), identity.get("runtime"), identity.get("language"), path.suffix.lower(), json.dumps(identity, ensure_ascii=False), int(text is not None), None if text is not None or path.suffix.lower() not in TEXT_EXTENSIONS else "TEXT_TOO_LARGE", _now()),
                    )
                    file_id = cursor.lastrowid
                    if text is not None:
                        for chunk_no, (line_start, line_end, content) in enumerate(_chunks(text)):
                            db.execute("INSERT INTO chunks(file_id,chunk_no,line_start,line_end,content) VALUES(?,?,?,?,?)", (file_id, chunk_no, line_start, line_end, content))
                        symbols, imports = _symbols_and_imports(text, path.suffix.lower())
                        db.executemany("INSERT INTO symbols(file_id,name,kind,line,signature) VALUES(?,?,?,?,?)", [(file_id, x["name"], x.get("kind"), x.get("line"), x.get("signature")) for x in symbols])
                        db.executemany("INSERT INTO imports(file_id,name,kind,line) VALUES(?,?,?,?)", [(file_id, x["name"], x.get("kind"), x.get("line")) for x in imports])
                    changed += 1
                except Exception as exc:
                    errors += 1
                    db.execute(
                        "INSERT OR REPLACE INTO files(path,size,mtime_ns,sha256,type,runtime,language,extension,metadata_json,indexed_text,index_error,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rel, stat.st_size, stat.st_mtime_ns, None, "UNKNOWN", None, LANGUAGE.get(path.suffix.lower()), path.suffix.lower(), "{}", 0, f"{type(exc).__name__}: {exc}"[:1000], _now()),
                    )
            # Only prune stale DB rows when the walk genuinely enumerated
            # every eligible candidate -- if either bound cut it short, a
            # file missing from `seen` might just be unreached, not deleted.
            saw_everything = not walk_truncated and total_eligible <= max_files
            removed_paths = sorted(set(existing) - seen) if saw_everything else []
            for rel in removed_paths:
                db.execute("DELETE FROM files WHERE path=?", (rel,))
            truncated = int(not saw_everything)
            db.execute(
                "UPDATE index_runs SET completed_at=?,scanned=?,changed=?,unchanged=?,removed=?,errors=?,truncated=? WHERE id=?",
                (_now(), len(candidates), changed, unchanged, len(removed_paths), errors, truncated, run_id),
            )
        return {
            "ok": True, "tool": "workspace_index", "workspace": str(self.workspace), "database": str(self.db_path),
            "scanned": len(candidates), "changed": changed, "unchanged": unchanged, "removed": len(removed_paths),
            "errors": errors, "truncated": bool(truncated), "run_id": run_id,
            "primary_available": len(primary), "deferred_available": len(deferred),
            "deferred_included": deferred_included, "worktrees_pruned": len(worktree_roots),
            "parameter_clamps": [_max_files_clamp],
        }

    def status(self):
        with self.connect() as db:
            counts = {
                "files": db.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                "text_files": db.execute("SELECT COUNT(*) FROM files WHERE indexed_text=1").fetchone()[0],
                "chunks": db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "symbols": db.execute("SELECT COUNT(*) FROM symbols").fetchone()[0],
                "imports": db.execute("SELECT COUNT(*) FROM imports").fetchone()[0],
                "errors": db.execute("SELECT COUNT(*) FROM files WHERE index_error IS NOT NULL AND index_error!='TEXT_TOO_LARGE'").fetchone()[0],
                "limited_text_files": db.execute("SELECT COUNT(*) FROM files WHERE index_error='TEXT_TOO_LARGE'").fetchone()[0],
            }
            last = db.execute("SELECT * FROM index_runs ORDER BY id DESC LIMIT 1").fetchone()
            types = {row[0] or "UNKNOWN": row[1] for row in db.execute("SELECT type,COUNT(*) FROM files GROUP BY type")}
        return {"ok": True, "tool": "workspace_index", "workspace": str(self.workspace), "database": str(self.db_path), **counts, "types": types, "last_run": dict(last) if last else None}

    def file(self, path):
        rel = Path(path).as_posix().lstrip("./")
        with self.connect() as db:
            row = db.execute("SELECT * FROM files WHERE path=?", (rel,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result["symbols"] = [dict(x) for x in db.execute("SELECT name,kind,line,signature FROM symbols WHERE file_id=? ORDER BY line LIMIT 500", (row["id"],))]
            result["imports"] = [dict(x) for x in db.execute("SELECT name,kind,line FROM imports WHERE file_id=? ORDER BY line LIMIT 500", (row["id"],))]
            return result

    def lexical_search(self, query, limit=50):
        tokens = re.findall(r"[\w.$:/-]{2,}", str(query), re.UNICODE)[:12]
        if not tokens:
            return []
        match = " OR ".join('"' + token.replace('"', '') + '"' for token in tokens)
        with self.connect() as db:
            rows = db.execute(
                "SELECT c.id,c.file_id,f.path,c.line_start,c.line_end,snippet(chunks_fts,0,'[',']',' … ',24) AS snippet,bm25(chunks_fts) AS rank FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid JOIN files f ON f.id=c.file_id WHERE chunks_fts MATCH ? ORDER BY rank,f.path,c.line_start,c.line_end,c.id LIMIT ?",
                (match, max(1, min(int(limit), 500))),
            ).fetchall()
        return [dict(row) for row in rows]


def workspace_index(operation="status", path=".", query="", max_files=MAX_FILES_DEFAULT, max_results=50):
    """Top-level workspace-index dispatcher; returns JSON text.

    CLI: python-only: 'build' and 'refresh' write the workspace index database; the generic path never writes state
    """
    index = WorkspaceIndex(path)
    if operation in {"build", "refresh"}:
        result = index.refresh(max_files=max_files)
    elif operation == "status":
        result = index.status()
    elif operation == "search":
        result = {"ok": True, "tool": "workspace_index", "operation": "search", "query": query, "results": index.lexical_search(query, max_results)}
    elif operation == "file":
        value = index.file(query)
        result = {"ok": value is not None, "tool": "workspace_index", "operation": "file", "file": value, "error": None if value else "NOT_INDEXED"}
    else:
        result = {"ok": False, "tool": "workspace_index", "error": "UNKNOWN_OPERATION"}
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)
