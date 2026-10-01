"""Incremental, offline index over ``dataset/evidence/`` -- the ~80k-file
tool-output ledger this product accumulates per session, per target, per
tool call.  Nothing could query it before this module: every agent that
needed "what do we already know about X" re-ran the same tool calls and
re-derived findings that had already been paid for, because the only access
path was an unbounded grep across tens of thousands of files.

Mirrors ``workspace_index.py``'s already-proven shape deliberately (same
project, same problem class, same answer) rather than inventing a second
indexing convention: SQLite + FTS5, mtime/size-based incremental refresh
(never re-hashes/re-reads unchanged files), a cross-process ``DurableLock``
around every write transaction so several agents writing evidence while one
queries never corrupts the database, and a stable ``dataset/metadata/
<name>_indexes/`` location that is gitignored the same way ``workspace_
indexes/`` already is.

Corpus shape (measured directly against the real corpus, see
``docs/PROJECT_STATE.md`` (upstream-only; not part of the published package) evidence-index entry for the numbers):
  - The large majority of files are flat, tool-written JSON envelopes
    directly under ``dataset/evidence/`` named
    ``{target}_{idhash}_{operation}_{suffix}.json`` (idhash/suffix are
    short hex tokens; target may itself contain spaces or underscores, so
    the split is best-effort, never assumed exact).  Common envelope shapes
    seen: a ``ghidra_query``-style ``{ok,tool,program,operation,items,...}``
    dict, an ``emulate_range``/``emulate_entry`` engine-report dict with no
    ``tool``/``target`` field at all, and an isolated-dynamic-validate
    ``{controller_outcome,target_sha256,evidence_ids,...}`` dict.  None of
    the sampled envelopes carry a timestamp field -- the filesystem mtime is
    the only reliable one and is what this index uses.
  - A `dataset/evidence/ledger/<session_id>/EV-*.txt` subtree (one raw
    content body per registered evidence_id, no metadata of its own --
    the real metadata for these lives in the *separate*
    ``dataset/metadata/research_state/<session_id>.json`` ``evidence[]``
    array, joined by content_ref/evidence_id, and is intentionally OUT of
    this module's scope: that is a different corpus with its own
    already-working lookup path (``research_state.evidence_ledger_v2``,
    ``ResearchState`` -- both in ``research_state.py``, upstream-only; not part of the published package), not an
    unindexed one).  This index still records
    these files (path/size/mtime, bounded content excerpt) so a raw-token
    search does not silently miss them, but does not attempt to parse
    target/tool out of their filename (``EV-<hash>.txt`` carries none).
  - A handful of tool-named subdirectories (``x64dbg/``, ``windbg/``,
    ``frida/``, ``apimonitor/``, ``unpack/``, ``die_identify/``, ...) hold
    files in the same flat-envelope style; the subdirectory name is
    recorded as a ``dir_hint`` and used as a tool fallback when no ``tool``
    field is present in the JSON body.

No existing on-disk index or catalogue over this corpus was found (checked
for an evidence-ID index/manifest/ledger convention before adding this;
``research_state.py``'s ``evidence_ledger_v2`` and the ``EV-``/``TR-``
schemes it and ``tool_result_store.py`` use (upstream-only; not part of the published package) are SESSION-scoped citation
registries over an in-memory/active store, not a persistent index over the
physical corpus files on disk -- this module is additive, not a competing
second index).

General by construction: no target name, tool name, or path is hardcoded
anywhere below. Every target/tool/operation this module ever returns is
discovered from the corpus at index time.

Architecture note (files are the source of truth): the corpus itself is
treated as append-only and immutable here -- this module NEVER writes,
renames, or mutates a file under ``dataset/evidence/``. The SQLite database
is purely derived, disposable, and rebuildable from scratch at any time
(``refresh()`` from an empty/missing db reproduces it byte-for-byte
equivalent, modulo timestamps); provenance and integrity come from the
files existing on disk, not from index bookkeeping. A schema version bump
(``SCHEMA_VERSION`` below) wipes and rebuilds the derived tables
automatically on the next ``refresh()`` -- there is deliberately no
in-place migration path, because none is needed for a disposable index.

Forward-compatible for a claim/provenance layer (claims with
PROVEN/CANDIDATE/CONTRADICTED/INSUFFICIENT status and evidence-SUPPORTS/
REFUTES/SUPERSEDES-claim edges, planned on top of this, NOT built here):
every record carries a stable ``evidence_uid`` (deterministic from its
path's sha256 -- unchanged across a full rebuild-from-scratch as long as
the file itself is not renamed, so a future claim table can hold a foreign
key into this index that survives reindexing), a ``target``/``target_hash``
pair (name always available, a real sha256 content hash only when the
record's own JSON happens to carry one), ``tool``, a filesystem-mtime-based
``record_time``, an optional ``session_id``, and a normalized ``anchors``
table (kind in address/function/api/session, one row per distinct subject
token a record actually mentions) that is the join key a claim layer would
use to ask "which evidence touches this exact function/address/API".
Real corpus anchor-presence inventory (measured, see this module's
CLAUDE-facing report for the sampling methodology) is intentionally NOT
100% for any anchor kind -- see ``by_anchor``/``already_answered`` below for
exactly where the canonical (target+anchor) lookup is precise versus where
it degrades to fuzzy full-text search.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from process_lock import DurableLock

from tools_workspace import PROJECT_ROOT as APP
EVIDENCE_ROOT_DEFAULT = APP / "dataset" / "evidence"
INDEX_ROOT = APP / "dataset" / "metadata" / "evidence_indexes"

# Bumping this wipes and rebuilds the (purely derived, disposable) database
# on the next refresh() -- see the module docstring's "files are the source
# of truth" note. No in-place column migration is implemented on purpose.
SCHEMA_VERSION = "2"

MAX_WALK_CANDIDATES = 300_000
MAX_CONTENT_BYTES = 262_144  # covers the measured p99 file size (~192KB) with headroom
MAX_RECORD_BYTES = 2_000_000  # bound for a single record() body fetch
MAX_ANCHORS_PER_RECORD = 60  # bounds index growth against a pathological api_calls/items list
JSON_EXTENSIONS = {".json", ".jsonl"}

# Subject-anchor patterns -- deliberately generic (no target/tool name is
# ever hardcoded): a hex address token (with or without an 0x prefix -- the
# corpus's own ghidra_query-style records store addresses as bare hex
# strings, e.g. "140001000", not "0x140001000"), and a Ghidra-style
# auto-named function symbol (FUN_<hex>). Both are scanned over the same
# bounded body_excerpt already read for FTS indexing -- no extra file I/O.
_HEX_ADDR_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{6,16}\b")
_FUN_NAME_RE = re.compile(r"\bFUN_[0-9a-fA-F]{4,16}\b")
# A bare hex token with no letters at all (e.g. "140001000") is
# indistinguishable from a large decimal number by pattern alone; only
# tokens that are plausibly addresses (contain at least one a-f letter, OR
# came from a structured "address"/"entry_point"/"from"/"to" JSON field --
# see _extract_anchors) are trusted as an 'address' anchor from free text.
_HEX_ADDR_HAS_LETTER_RE = re.compile(r"[a-fA-F]")


def _normalize_anchor_value(kind, value):
    value = str(value or "").strip()
    if kind == "address":
        value = value.lower()
        if value.startswith("0x"):
            value = value[2:]
        return value.lstrip("0") or "0"
    return value.strip().lower() if kind in ("api",) else value.strip()


def _deterministic_record_id(rel_path: str) -> int:
    # Derived from the relative path only (never file content) so the same
    # file always maps to the same id across a full rebuild-from-scratch --
    # the stable "evidence identity" a future claim/provenance layer can
    # hold a foreign key against without it shifting on reindex. Masked to
    # 62 bits to stay a valid positive SQLite INTEGER (signed 64-bit).
    digest = hashlib.sha256(rel_path.encode("utf-8", "replace")).digest()
    return int.from_bytes(digest[:8], "big") & 0x3FFFFFFFFFFFFFFF


def _evidence_uid(rel_path: str) -> str:
    return "EVX-" + hashlib.sha256(rel_path.encode("utf-8", "replace")).hexdigest()[:20]


def _extract_target_hash(payload):
    """A real content hash for the target binary, when the record's own
    JSON happens to carry one -- measured present in only a minority of the
    real corpus (see this module's report); most records only carry a
    target NAME, not a hash. Never computed here (no file is opened beyond
    what refresh() already reads) -- only ever read out of the record."""
    if not isinstance(payload, dict):
        return None
    for key in ("target_sha256", "sha256", "program_sha256", "binary_sha256"):
        value = payload.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value or ""):
            return value.lower()
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        value = provenance.get("target_sha256")
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value or ""):
            return value.lower()
    return None


def _extract_session_id(payload):
    if not isinstance(payload, dict):
        return None
    for key in ("session_id", "plan_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _extract_anchors(payload, body_text):
    """Best-effort, generic subject-anchor extraction. Structured JSON
    fields are trusted first (an 'items[].address'/'name' or an
    'api_calls' entry IS the subject, not a guess); a bounded regex scan of
    the body text is the fallback for envelope shapes with no structured
    field at all (e.g. decompiled C source embedded as a 'content' string).
    Returns a de-duplicated ``[(kind, value), ...]`` list, capped at
    ``MAX_ANCHORS_PER_RECORD``."""
    found = []
    seen = set()

    def add(kind, value):
        if len(found) >= MAX_ANCHORS_PER_RECORD:
            return
        norm = _normalize_anchor_value(kind, value)
        if not norm:
            return
        key = (kind, norm)
        if key in seen:
            return
        seen.add(key)
        found.append(key)

    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            for entry in items[:200]:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if isinstance(name, str) and name:
                    add("function", name)
                for addr_key in ("address", "from", "to", "entry_point"):
                    addr = entry.get(addr_key)
                    if isinstance(addr, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{4,16}", addr):
                        add("address", addr)
        entry_point = payload.get("entry_point")
        if isinstance(entry_point, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{4,16}", entry_point):
            add("address", entry_point)
        api_calls = payload.get("api_calls")
        if isinstance(api_calls, list):
            for entry in api_calls[:200]:
                if isinstance(entry, str) and entry:
                    add("api", entry)
                elif isinstance(entry, dict):
                    name = entry.get("name") or entry.get("api")
                    if isinstance(name, str) and name:
                        add("api", name)
        api_counts = payload.get("api_call_counts")
        if isinstance(api_counts, dict):
            for name in list(api_counts.keys())[:200]:
                if isinstance(name, str) and name:
                    add("api", name)

    if len(found) < MAX_ANCHORS_PER_RECORD and body_text:
        for match in _FUN_NAME_RE.finditer(body_text):
            add("function", match.group(0))
            if len(found) >= MAX_ANCHORS_PER_RECORD:
                break
        if len(found) < MAX_ANCHORS_PER_RECORD:
            for match in _HEX_ADDR_RE.finditer(body_text):
                token = match.group(0)
                if token.lower().startswith("0x") or _HEX_ADDR_HAS_LETTER_RE.search(token):
                    add("address", token)
                if len(found) >= MAX_ANCHORS_PER_RECORD:
                    break

    return found

# Best-effort split of a tool-written filename stem into
# target/idhash/operation/suffix.  Deliberately loose: idhash/suffix are
# short lowercase-hex tokens (the corpus's own convention, e.g.
# "998b462e5a" or "3a174c"); target is "everything before that", including
# spaces -- filenames like "2nd CrackMe Advanced_998b462e5a_..." are real.
# Hand-written filenames that don't follow the convention at all (no hex
# token) fail this regex and fall back to using the whole stem as target,
# which still supports substring/FTS lookup even without a clean split.
_FILENAME_RE = re.compile(
    r"^(?P<target>.+?)_(?P<idhash>[0-9a-f]{6,16})_(?P<operation>[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*)"
    r"(?:_(?P<suffix>[0-9a-f]{6,16}))?$"
)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _mtime_iso(mtime_ns):
    try:
        return datetime.fromtimestamp(mtime_ns / 1e9, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _index_key(root: Path):
    import hashlib

    return hashlib.sha256(str(root.resolve()).encode("utf-8", "replace")).hexdigest()[:16]


def _read_bounded(path: Path, limit: int):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    truncated = len(raw) > limit
    if truncated:
        raw = raw[:limit]
    return raw.decode("utf-8", errors="replace"), None if not truncated else "TRUNCATED"


def _parse_filename(stem: str):
    match = _FILENAME_RE.match(stem)
    if match:
        return match.group("target").strip(), match.group("operation"), match.group("idhash"), match.group("suffix")
    return stem.strip(), None, None, None


def _summarize_json(payload, max_chars=280):
    """One-line, bounded summary -- never the record body.  Built from a
    handful of common envelope fields observed across the real corpus
    (``ok``/``tool``/``operation``/``program``/``count`` for ghidra_query-
    style records, ``controller_outcome``/``exit_status`` for isolated-
    dynamic records, generic ``status``/``error`` fallbacks for anything
    else) so a caller can triage a hit list without opening any file."""
    if not isinstance(payload, dict):
        return f"<{type(payload).__name__} json, {len(payload) if hasattr(payload, '__len__') else '?'} items>"
    bits = []
    for key in ("tool", "operation", "program"):
        value = payload.get(key)
        if isinstance(value, (str, int, float)) and str(value):
            bits.append(f"{key}={value}")
    if "ok" in payload:
        bits.append(f"ok={payload.get('ok')}")
    if "count" in payload and isinstance(payload.get("count"), (int, float)):
        bits.append(f"count={payload.get('count')}")
    for key in ("controller_outcome", "exit_status", "status", "backend"):
        value = payload.get(key)
        if isinstance(value, (str, int, float)) and str(value):
            bits.append(f"{key}={value}")
    if payload.get("error"):
        bits.append(f"error={str(payload.get('error'))[:80]}")
    if not bits:
        bits.append("keys=" + ",".join(sorted(str(k) for k in payload.keys())[:6]))
    summary = " ".join(bits)
    return summary[:max_chars]


class EvidenceIndex:
    """Query surface over ``dataset/evidence/``. Never mutates the corpus
    itself -- read-only over the evidence tree, all writes go to this
    module's own SQLite database under ``dataset/metadata/evidence_indexes/``."""

    def __init__(self, root=None, db_path=None):
        self.root = Path(root).expanduser().resolve() if root else EVIDENCE_ROOT_DEFAULT.resolve()
        self.db_path = Path(db_path) if db_path else INDEX_ROOT / f"{_index_key(self.root)}.sqlite"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextlib.contextmanager
    def _session(self):
        # sqlite3.Connection's own context-manager protocol only manages
        # the transaction (commit on a clean exit, rollback on an
        # exception) -- it does NOT close the connection. Left open, a
        # short-lived connection is only actually closed whenever CPython's
        # refcounting/GC happens to finalize it, which is not prompt enough
        # on Windows: a caller (e.g. a test's TemporaryDirectory cleanup)
        # touching the same db file immediately after this method returns
        # can still find it locked. Always close explicitly here.
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _write_guard(self):
        # Same liveness-aware cross-process lock workspace_index.py already
        # uses for exactly the same reason: several agents write into
        # dataset/evidence/ while a refresh() runs, and sqlite's own
        # timeout=30 busy-wait cannot distinguish a live writer from a dead
        # one. Suffix excludes the lock/recovery sidecar files from ever
        # being walked back in as index candidates.
        return DurableLock(
            self.db_path.parent / (self.db_path.name + "-writelock"), stale_seconds=30, timeout_seconds=600,
        )

    def _ensure_schema(self):
        with self._write_guard(), self._session() as db:
            existing_version = None
            try:
                row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                existing_version = row[0] if row else None
            except sqlite3.OperationalError:
                pass  # no meta table yet -- first-ever build
            if existing_version is not None and existing_version != SCHEMA_VERSION:
                # The index is purely derived/disposable (see module
                # docstring): a schema bump wipes and lets the next
                # refresh() rebuild from the real files on disk, rather
                # than attempting an in-place column migration.
                db.executescript(
                    "DROP TABLE IF EXISTS records_fts; DROP TABLE IF EXISTS anchors; "
                    "DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS index_runs;"
                )
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS records(
                    id INTEGER PRIMARY KEY, evidence_uid TEXT NOT NULL UNIQUE,
                    path TEXT NOT NULL UNIQUE, size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL, ext TEXT, dir_hint TEXT,
                    target TEXT, target_hash TEXT, operation TEXT, tool TEXT, id_hash TEXT,
                    session_id TEXT, status TEXT NOT NULL, summary TEXT, parse_error TEXT,
                    record_time TEXT, indexed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS records_target_idx ON records(target COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS records_target_hash_idx ON records(target_hash);
                CREATE INDEX IF NOT EXISTS records_tool_idx ON records(tool COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS records_operation_idx ON records(operation COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS records_mtime_idx ON records(mtime_ns);
                CREATE INDEX IF NOT EXISTS records_session_idx ON records(session_id);
                CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
                    path, target, tool, operation, summary, body, content='records', content_rowid='id',
                    tokenize='unicode61'
                );
                CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
                    INSERT INTO records_fts(rowid,path,target,tool,operation,summary,body)
                    VALUES(new.id,new.path,new.target,new.tool,new.operation,new.summary,'');
                END;
                CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
                    INSERT INTO records_fts(records_fts,rowid,path,target,tool,operation,summary,body)
                    VALUES('delete',old.id,old.path,old.target,old.tool,old.operation,old.summary,'');
                END;
                -- Canonical subject-anchor join table -- the exact-match
                -- (target + anchor) lookup by_anchor()/already_answered()
                -- use, distinct from the fuzzy records_fts full-text index.
                CREATE TABLE IF NOT EXISTS anchors(
                    id INTEGER PRIMARY KEY,
                    record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL, value TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS anchors_unique_idx ON anchors(record_id, kind, value);
                CREATE INDEX IF NOT EXISTS anchors_lookup_idx ON anchors(kind, value COLLATE NOCASE);
                CREATE TABLE IF NOT EXISTS index_runs(
                    id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
                    scanned INTEGER DEFAULT 0, changed INTEGER DEFAULT 0, unchanged INTEGER DEFAULT 0,
                    removed INTEGER DEFAULT 0, malformed INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
                    truncated INTEGER DEFAULT 0, elapsed_seconds REAL
                );
                """
            )
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('root',?)", (str(self.root),))
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))

    # -- build -----------------------------------------------------------
    def _upsert_record(self, db, full: Path, rel: str, stat, old_row):
        """Insert-or-update ONE record row (records + records_fts + anchors)
        from a real stat() already taken -- the single-file body shared by
        both the full ``refresh()`` walk and ``index_one()`` (the write-time
        hook), so the two paths can never silently drift apart. Returns
        ``("unchanged"|"changed", malformed: bool)``; never raises on a
        malformed/unreadable file -- ``_build_row`` already degrades that to
        a ``json_malformed``/``read_error`` status row, same as before."""
        if old_row and old_row["size"] == stat.st_size and old_row["mtime_ns"] == stat.st_mtime_ns:
            return "unchanged", False
        if old_row:
            # ON DELETE CASCADE (foreign_keys=ON, set in connect()) takes
            # the old row's anchors with it; the FTS row is removed by the
            # records_ad trigger.
            db.execute("DELETE FROM records WHERE id=?", (old_row["id"],))
        row = self._build_row(full, rel, stat)
        malformed = row.get("status") == "json_malformed"
        record_id = _deterministic_record_id(rel)
        evidence_uid = _evidence_uid(rel)
        db.execute(
            "INSERT INTO records(id,evidence_uid,path,size,mtime_ns,ext,dir_hint,target,target_hash,"
            "operation,tool,id_hash,session_id,status,summary,parse_error,record_time,indexed_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record_id, evidence_uid, rel, stat.st_size, stat.st_mtime_ns, row["ext"], row["dir_hint"],
                row["target"], row["target_hash"], row["operation"], row["tool"], row["id_hash"],
                row["session_id"], row["status"], row["summary"], row["parse_error"], row["record_time"],
                _now_iso(),
            ),
        )
        db.execute(
            "INSERT INTO records_fts(rowid,path,target,tool,operation,summary,body) VALUES(?,?,?,?,?,?,?)",
            (record_id, rel, row["target"] or "", row["tool"] or "", row["operation"] or "",
             row["summary"] or "", row["body_excerpt"] or ""),
        )
        if row["anchors"]:
            db.executemany(
                "INSERT OR IGNORE INTO anchors(record_id,kind,value) VALUES(?,?,?)",
                [(record_id, kind, value) for kind, value in row["anchors"]],
            )
        return "changed", malformed

    def refresh(self, max_files=300_000):
        """Incremental: an unchanged (size, mtime_ns) file is skipped
        entirely (no re-open, no re-parse). Malformed JSON is recorded as a
        row with status='json_malformed' and counted in `malformed`, never
        raised -- one bad/partially-written record must not abort the run
        for the other ~80k.

        This is the REPAIR/full-rebuild path (also the only path that can
        ever discover a DELETED file, via the seen-set subtraction below) --
        the normal path to freshness is now ``index_one()``/``record_write``
        (write-time incremental indexing hooked into evidence-writing
        helpers), which makes a fresh record queryable in milliseconds
        without paying this walk's directory-traversal cost. See the module
        docstring's write-time-indexing note."""
        import time

        max_files = max(1, min(int(max_files), 1_000_000))
        started = _now_iso()
        t0 = time.monotonic()
        if not self.root.is_dir():
            return {
                "ok": False, "tool": "evidence_index", "operation": "refresh", "error": "EVIDENCE_ROOT_NOT_FOUND",
                "root": str(self.root),
            }
        with self._write_guard(), self._session() as db:
            run_id = db.execute("INSERT INTO index_runs(started_at) VALUES(?)", (started,)).lastrowid
            existing = {row["path"]: row for row in db.execute("SELECT id,path,size,mtime_ns FROM records")}
            seen = set()
            changed = unchanged = malformed = errors = 0
            candidates = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                for name in filenames:
                    full = Path(dirpath) / name
                    try:
                        if full.resolve() == self.db_path.resolve() or (
                            full.parent.resolve() == self.db_path.parent.resolve()
                            and full.name.startswith(self.db_path.name + "-")
                        ):
                            continue
                    except OSError:
                        pass
                    candidates.append(full)
                if len(candidates) >= MAX_WALK_CANDIDATES:
                    break
            walk_truncated = len(candidates) >= MAX_WALK_CANDIDATES
            total_eligible = len(candidates)
            candidates = candidates[:max_files]
            for full in candidates:
                try:
                    rel = full.relative_to(self.root).as_posix()
                    stat = full.stat()
                except OSError:
                    errors += 1
                    continue
                seen.add(rel)
                action, is_malformed = self._upsert_record(db, full, rel, stat, existing.get(rel))
                if action == "unchanged":
                    unchanged += 1
                    continue
                changed += 1
                if is_malformed:
                    malformed += 1
            saw_everything = not walk_truncated and total_eligible <= max_files
            removed_paths = sorted(set(existing) - seen) if saw_everything else []
            for rel in removed_paths:
                old = existing[rel]
                db.execute("DELETE FROM records WHERE id=?", (old["id"],))
            elapsed = time.monotonic() - t0
            truncated = int(not saw_everything)
            db.execute(
                "UPDATE index_runs SET completed_at=?,scanned=?,changed=?,unchanged=?,removed=?,malformed=?,"
                "errors=?,truncated=?,elapsed_seconds=? WHERE id=?",
                (_now_iso(), len(candidates), changed, unchanged, len(removed_paths), malformed, errors,
                 truncated, elapsed, run_id),
            )
        return {
            "ok": True, "tool": "evidence_index", "operation": "refresh", "root": str(self.root),
            "database": str(self.db_path), "scanned": len(candidates), "changed": changed, "unchanged": unchanged,
            "removed": len(removed_paths), "malformed": malformed, "errors": errors, "truncated": bool(truncated),
            "elapsed_seconds": round(elapsed, 3), "run_id": run_id,
        }

    def index_one(self, path, lock_timeout_seconds=5):
        """Incrementally index ONE just-written file, without walking the
        corpus -- the write-time hook (see ``record_write`` below and the
        module docstring). Deliberately the opposite failure posture from
        every other method here: a full exception barrier, because this
        runs on an evidence-WRITE hot path where the caller's own write must
        always win. Any failure at all -- the path resolving outside
        ``self.root``, a vanished file, a locked/corrupt database -- comes
        back as ``{"ok": False, ...}``, never a raised exception.

        Uses a SHORT lock timeout (``lock_timeout_seconds``, default 5s) --
        deliberately much shorter than ``refresh()``'s 600s repair-path
        timeout -- so a contended index during a burst of concurrent
        writers degrades to a skipped index update in seconds, never a
        multi-minute stall on the evidence write itself; a skipped update
        here is self-healing at the next ``refresh()``, which is why this
        can fail cheaply and safely where ``refresh()`` cannot."""
        try:
            full = Path(path)
            try:
                full = full.resolve()
            except OSError:
                pass
            try:
                rel = full.relative_to(self.root).as_posix()
            except ValueError:
                return {
                    "ok": False, "tool": "evidence_index", "operation": "index_one",
                    "error": "PATH_OUTSIDE_ROOT", "path": str(full), "root": str(self.root),
                }
            try:
                stat = full.stat()
            except OSError as exc:
                return {
                    "ok": False, "tool": "evidence_index", "operation": "index_one",
                    "error": f"STAT_FAILED: {type(exc).__name__}: {exc}", "path": rel,
                }
            lock = DurableLock(
                self.db_path.parent / (self.db_path.name + "-writelock"),
                stale_seconds=30, timeout_seconds=max(0.1, float(lock_timeout_seconds)),
            )
            with lock, self._session() as db:
                old = db.execute(
                    "SELECT id,path,size,mtime_ns FROM records WHERE path=?", (rel,),
                ).fetchone()
                action, is_malformed = self._upsert_record(db, full, rel, stat, old)
            return {
                "ok": True, "tool": "evidence_index", "operation": "index_one", "path": rel,
                "action": action, "malformed": is_malformed,
            }
        except Exception as exc:  # noqa: BLE001 - a write-time index hook must never propagate
            return {
                "ok": False, "tool": "evidence_index", "operation": "index_one",
                "error": f"{type(exc).__name__}: {exc}",
            }

    def _build_row(self, full: Path, rel: str, stat):
        ext = full.suffix.lower()
        parts = Path(rel).parts
        dir_hint = parts[0] if len(parts) > 1 else ""
        stem = full.stem
        target, operation, id_hash, _suffix = _parse_filename(stem)
        tool = None
        status = "non_json"
        summary = f"{ext or '(no ext)'} file, {stat.st_size} bytes"
        parse_error = None
        record_time = _mtime_iso(stat.st_mtime_ns)
        body_excerpt = ""
        target_hash = None
        session_id = None
        anchors = []
        if dir_hint == "ledger" and len(parts) > 2:
            # dataset/evidence/ledger/<session_id>/EV-*.txt -- the session
            # id is the one piece of structured identity these raw content
            # bodies carry in their PATH (they carry none in their own
            # filename or bytes; see the module docstring).
            session_id = parts[1]
        if ext in JSON_EXTENSIONS:
            text, read_error = _read_bounded(full, MAX_CONTENT_BYTES)
            if text is None:
                status, summary, parse_error = "read_error", "unreadable", read_error
            else:
                body_excerpt = text
                try:
                    # a size-capped read can cut a valid JSON document mid-
                    # token; only trust json.loads on a read that wasn't
                    # truncated, otherwise this is an honest MALFORMED_OR_
                    # TRUNCATED rather than a false "matches its schema".
                    if read_error == "TRUNCATED":
                        raise ValueError("content read was truncated before parsing")
                    payload = json.loads(text)
                except Exception as exc:  # noqa: BLE001 - any malformed/partial write must be skipped, not fatal
                    status = "json_malformed"
                    parse_error = f"{type(exc).__name__}: {exc}"[:300]
                    summary = "malformed or truncated-on-read JSON"
                else:
                    status = "json_ok"
                    if isinstance(payload, dict):
                        tool = payload.get("tool") or payload.get("backend") or None
                        if not isinstance(tool, str):
                            tool = None
                        for candidate_key in ("target", "target_sha256", "program"):
                            candidate = payload.get(candidate_key)
                            if isinstance(candidate, str) and candidate and target in (stem, None, ""):
                                target = candidate
                                break
                        target_hash = _extract_target_hash(payload)
                        session_id = session_id or _extract_session_id(payload)
                    summary = _summarize_json(payload)
                    anchors = _extract_anchors(payload, body_excerpt)
        if not tool and dir_hint:
            tool = dir_hint
        return {
            "ext": ext, "dir_hint": dir_hint, "target": target, "target_hash": target_hash, "operation": operation,
            "tool": tool, "id_hash": id_hash, "session_id": session_id, "status": status, "summary": summary,
            "parse_error": parse_error, "record_time": record_time, "body_excerpt": body_excerpt, "anchors": anchors,
        }

    # -- query -------------------------------------------------------------
    def status(self):
        with self._session() as db:
            counts = {
                "records": db.execute("SELECT COUNT(*) FROM records").fetchone()[0],
                "json_ok": db.execute("SELECT COUNT(*) FROM records WHERE status='json_ok'").fetchone()[0],
                "malformed": db.execute("SELECT COUNT(*) FROM records WHERE status='json_malformed'").fetchone()[0],
                "non_json": db.execute("SELECT COUNT(*) FROM records WHERE status='non_json'").fetchone()[0],
                "distinct_targets": db.execute("SELECT COUNT(DISTINCT target) FROM records WHERE target IS NOT NULL").fetchone()[0],
                "distinct_tools": db.execute("SELECT COUNT(DISTINCT tool) FROM records WHERE tool IS NOT NULL").fetchone()[0],
                "records_with_target_hash": db.execute("SELECT COUNT(*) FROM records WHERE target_hash IS NOT NULL").fetchone()[0],
                "records_with_session_id": db.execute("SELECT COUNT(*) FROM records WHERE session_id IS NOT NULL").fetchone()[0],
                "records_with_any_anchor": db.execute("SELECT COUNT(DISTINCT record_id) FROM anchors").fetchone()[0],
                "anchors_total": db.execute("SELECT COUNT(*) FROM anchors").fetchone()[0],
                "anchors_by_kind": {
                    r["kind"]: r["n"] for r in db.execute("SELECT kind,COUNT(*) AS n FROM anchors GROUP BY kind")
                },
            }
            last = db.execute("SELECT * FROM index_runs ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "ok": True, "tool": "evidence_index", "operation": "status", "root": str(self.root),
            "database": str(self.db_path), "schema_version": SCHEMA_VERSION, **counts,
            "last_run": dict(last) if last else None,
        }

    @staticmethod
    def _hit(row):
        return {
            "id": row["id"], "evidence_uid": row["evidence_uid"], "path": row["path"], "target": row["target"],
            "target_hash": row["target_hash"], "tool": row["tool"], "operation": row["operation"],
            "session_id": row["session_id"], "status": row["status"], "summary": row["summary"],
            "size": row["size"], "record_time": row["record_time"],
        }

    def _page(self, db, sql, params, limit, offset):
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        rows = db.execute(sql, params + (limit + 1, offset)).fetchall()
        truncated = len(rows) > limit
        rows = rows[:limit]
        return rows, truncated, (offset + limit if truncated else None)

    def by_target(self, target, limit=20, offset=0, strict=False):
        """"What do we already know about X" by target name -- CONTENT-
        INCLUSIVE by default (``strict=False``): identity match (target/path
        LIKE) UNIONED with a full-text content match over the same
        path/target/tool/operation/summary/body-excerpt index ``search()``
        uses, so a caller who reaches for this obviously-named operation
        gets the complete answer rather than only the identity-scoped
        quarter of it. Measured on the real corpus: identity-only scoping
        for ``ring0_keygenme`` returned 4 records where ``search()`` found
        17 -- a confidently incomplete answer, which is worse than a slow
        one. ``identity_count``/``content_match_count``/``content_only_
        count`` in the response make the split visible rather than silently
        merging it away; ``note`` is set whenever content-only hits exist,
        so a caller cannot miss that more was found than an identity lookup
        alone would show. Pass ``strict=True`` to restrict to the old
        identity-only (target/path LIKE) behavior when that narrower
        scoping is actually what is wanted -- e.g. for an exact "list every
        record this target's own filenames were stamped with" question."""
        target = str(target or "").strip()
        if not target:
            return {"ok": False, "error": "TARGET_REQUIRED"}
        identity_sql = (
            "SELECT * FROM records WHERE target LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' "
            "ORDER BY mtime_ns DESC"
        )
        identity_params = (f"%{_like_escape(target)}%", f"%{_like_escape(target)}%")
        with self._session() as db:
            if strict:
                rows, truncated, next_offset = self._page(
                    db, identity_sql + " LIMIT ? OFFSET ?", identity_params, limit, offset,
                )
                return {
                    "ok": True, "tool": "evidence_index", "operation": "by_target", "target": target,
                    "strict": True, "results": [self._hit(r) for r in rows], "count": len(rows),
                    "truncated": truncated, "next_offset": next_offset,
                }
            identity_rows = db.execute(identity_sql, identity_params).fetchall()
            identity_ids = {r["id"] for r in identity_rows}
            tokens = re.findall(r"[\w.$:/-]{2,}", target, re.UNICODE)[:12]
            content_rows = []
            if tokens:
                match_parts = []
                for t in tokens:
                    match_parts.append('"' + t.replace('"', '') + '"')
                    if re.fullmatch(r"[A-Za-z0-9_]+", t):
                        match_parts.append(t + "*")
                match = " OR ".join(match_parts)
                content_rows = db.execute(
                    "SELECT r.* FROM records_fts JOIN records r ON r.id=records_fts.rowid "
                    "WHERE records_fts MATCH ? ORDER BY bm25(records_fts)",
                    (match,),
                ).fetchall()
            combined = {r["id"]: r for r in identity_rows}
            for r in content_rows:
                combined.setdefault(r["id"], r)
            content_only_count = len(combined) - len(identity_ids)
            ordered = sorted(combined.values(), key=lambda r: r["mtime_ns"], reverse=True)
            limit_n = max(1, min(int(limit), 500))
            offset_n = max(0, int(offset))
            page = ordered[offset_n: offset_n + limit_n + 1]
            truncated = len(page) > limit_n
            page = page[:limit_n]
        return {
            "ok": True, "tool": "evidence_index", "operation": "by_target", "target": target, "strict": False,
            "results": [self._hit(r) for r in page], "count": len(page),
            "identity_count": len(identity_ids), "content_match_count": len(combined),
            "content_only_count": content_only_count,
            "truncated": truncated, "next_offset": (offset_n + limit_n) if truncated else None,
            "note": (
                f"content-inclusive: {content_only_count} additional record(s) mention '{target}' outside the "
                "target/path identity fields (pass strict=True for identity-only scoping)"
            ) if content_only_count else None,
        }

    def by_tool(self, tool, limit=20, offset=0):
        tool = str(tool or "").strip()
        if not tool:
            return {"ok": False, "error": "TOOL_REQUIRED"}
        with self._session() as db:
            rows, truncated, next_offset = self._page(
                db, "SELECT * FROM records WHERE tool LIKE ? ESCAPE '\\' ORDER BY mtime_ns DESC LIMIT ? OFFSET ?",
                (f"%{_like_escape(tool)}%",), limit, offset,
            )
        return {
            "ok": True, "tool": "evidence_index", "operation": "by_tool", "tool_filter": tool,
            "results": [self._hit(r) for r in rows], "count": len(rows), "truncated": truncated,
            "next_offset": next_offset,
        }

    def search(self, query, target="", tool="", limit=20, offset=0):
        """The anti-re-derivation query: full-text across path/target/tool/
        operation/summary/bounded-body-excerpt (an address like
        ``14005d340`` or a symbol like ``FUN_140001000`` is a plain FTS
        token match), optionally narrowed by target/tool. Never returns
        record bodies -- one-line summaries only; fetch a body with
        ``record()`` by id.

        Each token is matched BOTH as an exact phrase and (for a plain
        alnum/underscore token) as a prefix query (``token*``) -- FTS5's
        default tokenizer only matches whole tokens, so a query for
        ``CreateWindow`` would otherwise silently miss a real hit whose
        actual token is ``CreateWindowExW`` (grep's substring match finds
        it, a naive exact-token FTS match does not; measured as a real miss
        against this corpus before this fix -- see this module's report)."""
        query = str(query or "").strip()
        tokens = re.findall(r"[\w.$:/-]{2,}", query, re.UNICODE)[:12]
        with self._session() as db:
            limit_n = max(1, min(int(limit), 500))
            offset_n = max(0, int(offset))
            if tokens:
                match_parts = []
                for t in tokens:
                    match_parts.append('"' + t.replace('"', '') + '"')
                    if re.fullmatch(r"[A-Za-z0-9_]+", t):
                        match_parts.append(t + "*")
                match = " OR ".join(match_parts)
                sql = (
                    "SELECT r.* FROM records_fts JOIN records r ON r.id=records_fts.rowid WHERE records_fts MATCH ?"
                )
                params = [match]
                if target:
                    sql += " AND r.target LIKE ? ESCAPE '\\'"
                    params.append(f"%{_like_escape(target)}%")
                if tool:
                    sql += " AND r.tool LIKE ? ESCAPE '\\'"
                    params.append(f"%{_like_escape(tool)}%")
                sql += " ORDER BY bm25(records_fts) LIMIT ? OFFSET ?"
                params += [limit_n + 1, offset_n]
                rows = db.execute(sql, params).fetchall()
            else:
                sql = "SELECT * FROM records WHERE 1=1"
                params = []
                if target:
                    sql += " AND target LIKE ? ESCAPE '\\'"
                    params.append(f"%{_like_escape(target)}%")
                if tool:
                    sql += " AND tool LIKE ? ESCAPE '\\'"
                    params.append(f"%{_like_escape(tool)}%")
                sql += " ORDER BY mtime_ns DESC LIMIT ? OFFSET ?"
                params += [limit_n + 1, offset_n]
                rows = db.execute(sql, params).fetchall()
        truncated = len(rows) > limit_n
        rows = rows[:limit_n]
        return {
            "ok": True, "tool": "evidence_index", "operation": "search", "query": query, "target": target,
            "tool_filter": tool, "results": [self._hit(r) for r in rows], "count": len(rows),
            "truncated": truncated, "next_offset": (offset_n + limit_n) if truncated else None,
        }

    def record(self, record_id=None, path=None):
        """Retrieve ONE record's real content, read fresh from the corpus
        file on disk (bounded to MAX_RECORD_BYTES) -- the only operation
        here that returns a body. Everything else returns ids+summaries."""
        with self._session() as db:
            if isinstance(record_id, str) and record_id.startswith("EVX-"):
                row = db.execute("SELECT * FROM records WHERE evidence_uid=?", (record_id,)).fetchone()
            elif record_id:
                row = db.execute("SELECT * FROM records WHERE id=?", (int(record_id),)).fetchone()
            elif path:
                rel = Path(str(path)).as_posix().lstrip("./")
                row = db.execute("SELECT * FROM records WHERE path=?", (rel,)).fetchone()
            else:
                return {"ok": False, "error": "ID_OR_PATH_REQUIRED"}
        if not row:
            return {"ok": False, "error": "NOT_INDEXED"}
        full = self.root / row["path"]
        content, read_error = _read_bounded(full, MAX_RECORD_BYTES)
        return {
            "ok": content is not None, "tool": "evidence_index", "operation": "record", "id": row["id"],
            "evidence_uid": row["evidence_uid"], "path": row["path"], "target": row["target"],
            "target_hash": row["target_hash"], "tool_name": row["tool"], "operation_name": row["operation"],
            "session_id": row["session_id"], "status": row["status"], "summary": row["summary"],
            "record_time": row["record_time"], "content": content, "read_error": read_error,
            "error": read_error if content is None else None,
        }

    # -- canonical (anti-re-derivation) lookup -----------------------------
    def by_anchor(self, kind, value, target="", limit=20, offset=0):
        """Exact-match canonical lookup on a subject anchor (address/
        function/api/session), optionally narrowed to a target. This is the
        precise half of the anti-re-derivation query: if it returns hits,
        that exact subject has DEFINITELY already been touched by prior
        analysis on this target -- not a fuzzy guess. Only covers records
        whose anchors were actually extracted (see the module docstring's
        anchor-presence inventory); a record with no structured items/
        api_calls field and no FUN_/hex token in its body has NO anchor row
        and will not appear here even if it is genuinely relevant -- that
        gap is real and is why ``already_answered`` falls back to
        ``search`` rather than reporting a bare miss as a confident "no"."""
        kind = str(kind or "").strip().lower()
        norm_value = _normalize_anchor_value(kind, value)
        if not kind or not norm_value:
            return {"ok": False, "error": "KIND_AND_VALUE_REQUIRED"}
        with self._session() as db:
            sql = (
                "SELECT r.* FROM anchors a JOIN records r ON r.id=a.record_id "
                "WHERE a.kind=? AND a.value=?"
            )
            params = [kind, norm_value]
            if target:
                sql += " AND (r.target LIKE ? ESCAPE '\\' OR r.target_hash=?)"
                params += [f"%{_like_escape(target)}%", target]
            sql += " ORDER BY r.mtime_ns DESC LIMIT ? OFFSET ?"
            rows, truncated, next_offset = self._page(db, sql, tuple(params), limit, offset)
        return {
            "ok": True, "tool": "evidence_index", "operation": "by_anchor", "kind": kind, "value": norm_value,
            "target": target, "results": [self._hit(r) for r in rows], "count": len(rows),
            "truncated": truncated, "next_offset": next_offset,
        }

    def already_answered(self, target, kind="", value="", query="", limit=10, offset=0):
        """"Has this question already been answered for this target?" --
        the anti-re-derivation query the owner's escalation asked for by
        name. Tries the canonical anchor lookup first (kind+value, e.g.
        kind='address', value='14005d340'); if that returns nothing (either
        because the subject was truly never touched, OR because this
        record's envelope shape has no extractable anchor -- the two are
        NOT distinguishable from an empty anchor result alone), falls back
        to a target-scoped full-text search over `query` (or kind/value as
        text) so a caller still gets a usable, if fuzzier, answer instead
        of a bare miss. `confidence` in the response tells the caller which
        path produced the result: EXACT_ANCHOR (trustworthy "yes, already
        answered") or FUZZY_TEXT (a plausible lead, not a guarantee) or
        NONE (genuinely nothing found either way)."""
        target = str(target or "").strip()
        if not target:
            return {"ok": False, "error": "TARGET_REQUIRED"}
        if kind and value:
            anchor_result = self.by_anchor(kind, value, target=target, limit=limit, offset=offset)
            if anchor_result.get("ok") and anchor_result.get("count"):
                return {
                    **anchor_result, "operation": "already_answered", "confidence": "EXACT_ANCHOR",
                    "already_answered": True,
                }
        fallback_query = query or value or kind
        if not fallback_query:
            return {
                "ok": True, "tool": "evidence_index", "operation": "already_answered", "target": target,
                "confidence": "NONE", "already_answered": False, "results": [], "count": 0,
                "truncated": False, "next_offset": None,
                "reason": "no anchor hit and no query text given for a fallback search",
            }
        text_result = self.search(fallback_query, target=target, limit=limit, offset=offset)
        confidence = "FUZZY_TEXT" if text_result.get("count") else "NONE"
        return {
            **text_result, "operation": "already_answered", "confidence": confidence,
            "already_answered": bool(text_result.get("count")),
        }


def _like_escape(value):
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# -- write-time incremental indexing (the normal path to freshness) --------
#
# refresh() re-walks and stat()s the entire corpus (measured: 53.2s over
# ~80k files even when only 2 changed -- the cost is directory traversal,
# not parsing) -- an index that is only ever fresh 53 seconds after a
# refresh() call will simply not get called before every query, so the
# anti-re-derivation point of this module quietly stops being true. Fixing
# this at the write side rather than the walk side: a caller that already
# knows exactly which one file it just wrote can index that ONE file in
# milliseconds via EvidenceIndex.index_one(), without walking anything.
# ``record_write`` below is the hookable one-line entry point for that --
# see e.g. ``research_state.add_tool_result``'s (upstream-only; not part of the published package) call to it right after it
# writes a ledger evidence file. refresh() remains the repair mechanism
# (also the only path that can discover a DELETED file) and stays exactly
# as it was.
#
# EvidenceIndex instances are cached per (root, db_path) so a hot write
# path pays SQLite connection/schema-check setup once per process, not once
# per evidence write -- constructing EvidenceIndex fresh every call would
# itself acquire the (long-timeout) schema write-lock every time.
_INDEX_CACHE: dict = {}
_INDEX_CACHE_LOCK = threading.Lock()


def _cached_index(root=None, db_path=None):
    resolved_root = Path(root).expanduser().resolve() if root else EVIDENCE_ROOT_DEFAULT.resolve()
    key = (str(resolved_root), str(db_path) if db_path else "")
    with _INDEX_CACHE_LOCK:
        index = _INDEX_CACHE.get(key)
        if index is None:
            index = EvidenceIndex(root=resolved_root, db_path=db_path)
            _INDEX_CACHE[key] = index
        return index


def record_write(path, root=None, db_path=None, lock_timeout_seconds=5):
    """Best-effort, NEVER-raising incremental index of ONE freshly written
    evidence file -- the one-line call an evidence-writing helper hooks
    right after it writes its file to disk. Every failure mode -- the
    index locked/corrupt/missing, the given path outside ``root``, a
    vanished file, anything -- degrades to ``{"ok": False, ...}``, wrapped
    in its own exception barrier on top of ``EvidenceIndex.index_one``'s
    own (constructing the cached ``EvidenceIndex`` itself could still raise,
    e.g. an unwritable ``INDEX_ROOT``): the caller's real evidence write
    must never be broken, slowed materially, or blocked by this."""
    try:
        index = _cached_index(root=root, db_path=db_path)
        return index.index_one(path, lock_timeout_seconds=lock_timeout_seconds)
    except Exception as exc:  # noqa: BLE001 - see docstring: this must never propagate
        return {"ok": False, "tool": "evidence_index", "operation": "index_one", "error": f"{type(exc).__name__}: {exc}"}


def evidence_index(operation="status", root=None, target="", tool="", query="", record_id=None, path="",
                    limit=20, offset=0, max_files=300_000, db_path=None, kind="", value="", strict=False):
    index = EvidenceIndex(root, db_path=db_path)
    if operation in {"build", "refresh"}:
        result = index.refresh(max_files=max_files)
    elif operation == "status":
        result = index.status()
    elif operation == "by_target":
        result = index.by_target(target or query, limit=limit, offset=offset, strict=strict)
    elif operation == "by_tool":
        result = index.by_tool(tool or query, limit=limit, offset=offset)
    elif operation == "search":
        result = index.search(query, target=target, tool=tool, limit=limit, offset=offset)
    elif operation == "by_anchor":
        result = index.by_anchor(kind, value or query, target=target, limit=limit, offset=offset)
    elif operation == "already_answered":
        result = index.already_answered(target, kind=kind, value=value, query=query, limit=limit, offset=offset)
    elif operation == "record":
        result = index.record(record_id=record_id, path=path or None)
    else:
        result = {"ok": False, "tool": "evidence_index", "error": "UNKNOWN_OPERATION"}
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)
