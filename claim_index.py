"""Claim/provenance layer on top of ``evidence_index.py`` -- turns immutable
tool-output evidence into queryable, status-tracked ASSERTIONS about a
target, with automatic contradiction detection. Built because of a real,
named failure: four successive claims about one target (trybypassme/TBM.exe)
were each refuted by later evidence and none of them was marked superseded
anywhere automatically -- one ("the kernel process-kill was defeated and the
process survives 240s+") sat in ``docs/PROJECT_STATE.md`` (upstream-only; not part of the published package) as fact for three
weeks after evidence contradicted it, corrected only by a human pass. See
``tests/test_claim_index.py``'s ``RealCaseValidationTests`` for that exact
chain re-encoded and proven to land as ``CONTRADICTED`` automatically.

THE MODEL
---------
An EVIDENCE record (``evidence_index.py``) is an immutable observation --
unchanged here, never mutated by anything in this module.

A CLAIM is a structured, comparable ASSERTION:
    (target_identity, subject_kind, subject_value, predicate) -> asserted_value
i.e. "for this target, about this subject, regarding this specific
question, the answer is this value." Free-text claims ("the target hangs")
cannot be compared to each other by a machine -- there is no honest way to
semantic-diff prose. This 4-tuple is the minimum structure that makes
"do these two claims answer the same question with a different answer"
mechanically decidable without guessing:
  - ``subject_kind``/``subject_value`` reuses ``evidence_index``'s own
    anchor vocabulary (address/function/api) plus ``topic`` for a claim not
    tied to one code location (e.g. "does the kill routine actually
    terminate the process") and ``session`` for parity -- so a claim's
    subject is directly cross-referenceable against
    ``evidence_index.by_anchor`` with the exact same normalization
    (``evidence_index._normalize_anchor_value``, imported not reimplemented).
  - ``predicate`` is a short, caller-chosen, normalized slug naming the
    QUESTION ("root_cause", "process_survival_after_kill",
    "token_elevation_state") -- NOT the answer. Two claims are only ever
    comparable when they share the same predicate for the same subject:
    that is the honest boundary of what this module can safely judge. A
    different predicate about the same subject is a DIFFERENT question and
    is never silently treated as agreeing or conflicting -- see
    UNCOMPARABLE below.
  - ``asserted_value`` is the answer, compared only by normalized (trimmed,
    collapsed-whitespace, lowercased) STRING EQUALITY -- no NLP, no
    semantic diff, because pretending to understand prose well enough to
    diff it is exactly the kind of unproven claim this module exists to
    prevent. ``statement`` carries the free-text human-readable claim for
    display; it is never compared or reasoned over.
  - ``target_identity`` mirrors evidence_index's own measured reality
    (module docstring there): a real sha256 target hash is present on only
    ~1.4% of the corpus, a target NAME on ~93%. Identity here is
    ``hash:<sha256>`` when a caller supplies one, else ``name:<lowercased
    target>`` -- so claims group correctly for the vast majority of real
    callers without demanding a hash nobody has.

STATUS AND ITS TRANSITIONS (PROVEN / CANDIDATE / CONTRADICTED / INSUFFICIENT)
------------------------------------------------------------------------
  - PROVEN may only be asserted WITH at least one SUPPORTS evidence_uid at
    creation (``PROVEN_REQUIRES_SUPPORTING_EVIDENCE`` otherwise) -- a
    "proven" claim with no evidence link is exactly the failure this module
    exists to prevent.
  - CONTRADICTED can never be requested as an initial status (it is a
    consequence, not an assertion) -- ``CONTRADICTED_NOT_A_VALID_INITIAL_STATUS``.
  - THE load-bearing rule: any REFUTES evidence link added to a claim --
    regardless of current status, PROVEN included -- immediately and
    unconditionally flips it to CONTRADICTED (``_apply_evidence_link``).
    This is mechanical, not a judgment call, precisely because the
    motivating failure was a human judgment call never being made. Adding
    more SUPPORTS evidence afterward does NOT revive it -- once
    CONTRADICTED, only a new claim explicitly superseding it
    (``supersede_claim``) can move the story forward, so a correction is
    always a new, visible, provenance-linked event, never a silent status
    flip back.
  - Claim-vs-claim conflict is handled the same way, automatically, inside
    ``create_claim``: when a new claim shares (target_identity, subject_kind,
    subject_value, predicate) with an existing non-CONTRADICTED claim but a
    DIFFERENT normalized asserted_value, a CONFLICTS_WITH edge is recorded
    and the OLDER claim is immediately demoted to CONTRADICTED -- a PROVEN
    claim can never keep looking uncontested once something incompatible
    has been asserted about the exact same question.
  - When the same subject is claimed again with a DIFFERENT predicate, the
    two claims are NOT compared for compatibility at all (this module has
    no way to know if they agree) -- an UNCOMPARABLE edge is recorded so a
    caller can SEE that a related-but-unjudged claim exists, rather than
    the pair silently defaulting to "no conflict" (the worst outcome named
    in the brief this module answers).

FILES REMAIN THE SOURCE OF TRUTH -- SQLITE IS DERIVED
-------------------------------------------------------
Every mutation this module makes (a claim created, an evidence link added,
a status change, a supersede/conflict/uncomparable edge) is FIRST written as
its own small, immutable, timestamp-prefixed JSON event file under
``dataset/claims/`` (mirroring ``dataset/evidence/``'s own local, gitignored,
append-only corpus convention) and only THEN applied to the SQLite
projection -- the event file is authoritative, the SQLite row is a cache of
it. ``rebuild_from_events()`` replays every event file in chronological
(lexicographic-by-timestamp-prefix) filename order and reconstructs the
SQLite tables byte-for-byte-equivalent from nothing but those files, exactly
mirroring ``evidence_index.refresh()``'s own disposable-derived-cache
contract -- reused deliberately, not reinvented, because claims genuinely
need the same property evidence does: a corrupted/deleted database must
never be able to lose a claim, only cost a replay.

This is a deliberate, documented DIVERGENCE from evidence_index.py's own
schema-version-bump behaviour: evidence_index wipes-and-rebuilds on a schema
bump because its SQLite db is disposable cache over a corpus it does not
own. This module's SQLite db is ALSO disposable (see rebuild_from_events
above) -- but only because the event-file corpus under dataset/claims/ is
the thing that is never wiped. A schema bump here still wipes+rebuilds the
derived tables (same SCHEMA_VERSION guard, same DurableLock write
discipline, same gitignored dataset/metadata/claim_indexes/ location as
evidence_index's own evidence_indexes/) but the source-of-truth event files
survive it untouched, and ``rebuild_from_events()`` (not a fresh empty
corpus) is what repopulates the tables afterward.

Evidence is referenced ONLY by ``evidence_index``'s own ``evidence_uid``
(the "EVX-<sha256-of-relative-path>" identifier evidence_index.py already
designed forward-compatibly for exactly this purpose -- see its module
docstring), never by its integer row id or its file path directly, so the
link survives a full evidence_index rebuild-from-scratch (evidence_uid is
deterministic from the relative path alone, unaffected by reindexing) --
verified directly in ``tests/test_claim_index.py::
test_claim_link_survives_full_evidence_index_rebuild``.

BACK-FILL STANCE
-----------------
No attempt is made to mine 80k heterogeneous historical evidence files into
claims automatically -- target-NAME identity and anchors exist on ~93% of
records (already established by evidence_index's own measurement) but that
is nowhere near enough structure to safely infer WHAT was being asserted,
only what was TOUCHED. New claims are recorded going forward by callers
that know what they are asserting. Any retroactive claim is created with
``inferred=True`` and a ``source`` note explaining it was backfilled after
the fact from a real historical record (e.g. project-state prose, a
session's own narrative) -- never presented as if it had been a
structured, machine-checked assertion at the time. See
``tests/test_claim_index.py``'s real-case validation, which backfills
exactly four such claims and marks every one ``inferred``.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from evidence_index import EvidenceIndex, _normalize_anchor_value
from process_lock import DurableLock

from tools_workspace import PROJECT_ROOT as APP
EVENTS_ROOT_DEFAULT = APP / "dataset" / "claims"
CLAIM_INDEX_ROOT = APP / "dataset" / "metadata" / "claim_indexes"

# See module docstring: a bump here wipes+rebuilds the DERIVED tables only
# (same discipline as evidence_index.SCHEMA_VERSION) -- the event-file
# corpus under EVENTS_ROOT is never touched by this and is what
# rebuild_from_events() replays afterward.
SCHEMA_VERSION = "1"

VALID_STATUSES = {"PROVEN", "CANDIDATE", "CONTRADICTED", "INSUFFICIENT"}
INITIAL_STATUSES = {"PROVEN", "CANDIDATE", "INSUFFICIENT"}  # CONTRADICTED is never an initial status
VALID_RELATIONS = {"SUPPORTS", "REFUTES"}
MAX_STATEMENT_CHARS = 2000


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _ts_compact():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")


def _claim_uid():
    return "CLM-" + uuid.uuid4().hex[:20]


def _index_key(root: Path):
    return hashlib.sha256(str(root.resolve()).encode("utf-8", "replace")).hexdigest()[:16]


def _normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def _resolve_target_identity(target, target_hash=None):
    target_raw = str(target or "").strip()
    if target_hash:
        h = str(target_hash).strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", h):
            return target_raw, f"hash:{h}", "hash"
    return target_raw, f"name:{target_raw.lower()}", "name"


def _normalize_subject(kind, value):
    kind = str(kind or "").strip().lower()
    if kind in ("address", "function", "api"):
        return kind, _normalize_anchor_value(kind, value)
    return kind, _normalize_text(value)


class ClaimError(Exception):
    def __init__(self, code, detail=""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class ClaimIndex:
    """Query+mutate surface for the claim/provenance layer. See module
    docstring for the full model. ``evidence_index`` (an ``EvidenceIndex``
    instance), when supplied, is used to (a) validate an ``evidence_uid``
    actually resolves to an indexed record before linking it, and (b)
    resolve a one-line, body-free summary for provenance queries -- both
    best-effort: a claim can still be created and evidence still linked
    with no bound EvidenceIndex (e.g. a claim about a target whose evidence
    has not been indexed yet), the link is simply unvalidated in that case.
    """

    def __init__(self, db_path=None, events_root=None, evidence_index=None):
        self.events_root = Path(events_root) if events_root else EVENTS_ROOT_DEFAULT
        self.events_root.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else CLAIM_INDEX_ROOT / f"{_index_key(self.events_root)}.sqlite"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_index: EvidenceIndex | None = evidence_index
        self._ensure_schema()

    # -- plumbing (mirrors evidence_index.py's own shape deliberately) -----
    def connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextlib.contextmanager
    def _session(self):
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
        return DurableLock(
            self.db_path.parent / (self.db_path.name + "-writelock"), stale_seconds=30, timeout_seconds=600,
        )

    def _schema_sql(self):
        return """
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS claims(
                id INTEGER PRIMARY KEY,
                claim_uid TEXT NOT NULL UNIQUE,
                target_raw TEXT NOT NULL,
                target_identity TEXT NOT NULL,
                target_identity_kind TEXT NOT NULL,
                subject_kind TEXT NOT NULL,
                subject_value TEXT NOT NULL,
                predicate TEXT NOT NULL,
                predicate_norm TEXT NOT NULL,
                asserted_value TEXT NOT NULL,
                asserted_value_norm TEXT NOT NULL,
                statement TEXT,
                status TEXT NOT NULL,
                inferred INTEGER NOT NULL DEFAULT 0,
                source TEXT,
                superseded_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS claims_target_idx ON claims(target_identity);
            CREATE INDEX IF NOT EXISTS claims_subject_idx ON claims(target_identity, subject_kind, subject_value);
            CREATE INDEX IF NOT EXISTS claims_status_idx ON claims(status);
            CREATE TABLE IF NOT EXISTS claim_evidence(
                id INTEGER PRIMARY KEY,
                claim_uid TEXT NOT NULL,
                evidence_uid TEXT NOT NULL,
                relation TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS claim_evidence_claim_idx ON claim_evidence(claim_uid);
            CREATE INDEX IF NOT EXISTS claim_evidence_uid_idx ON claim_evidence(evidence_uid);
            CREATE TABLE IF NOT EXISTS claim_edges(
                id INTEGER PRIMARY KEY,
                from_claim_uid TEXT NOT NULL,
                to_claim_uid TEXT NOT NULL,
                relation TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS claim_edges_from_idx ON claim_edges(from_claim_uid);
            CREATE INDEX IF NOT EXISTS claim_edges_to_idx ON claim_edges(to_claim_uid);
            CREATE TABLE IF NOT EXISTS claim_status_history(
                id INTEGER PRIMARY KEY,
                claim_uid TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                reason TEXT,
                caused_by TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS claim_status_history_claim_idx ON claim_status_history(claim_uid);
        """

    def _ensure_schema(self):
        with self._write_guard(), self._session() as db:
            existing_version = None
            try:
                row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                existing_version = row[0] if row else None
            except sqlite3.OperationalError:
                pass
            needs_rebuild = existing_version is not None and existing_version != SCHEMA_VERSION
            if needs_rebuild:
                # See module docstring's divergence note: safe to wipe here
                # ONLY because the event-file corpus under self.events_root
                # is the real source of truth and is never touched by this.
                db.executescript(
                    "DROP TABLE IF EXISTS claim_status_history; DROP TABLE IF EXISTS claim_edges; "
                    "DROP TABLE IF EXISTS claim_evidence; DROP TABLE IF EXISTS claims;"
                )
            db.executescript(self._schema_sql())
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))
        # Mirrors evidence_index.py's own _ensure_schema exactly: a wipe
        # here does NOT auto-repopulate -- the caller/entry point is
        # expected to call rebuild_from_events() next (the explicit
        # recovery path), same as evidence_index requires an explicit
        # refresh() after its own schema-bump wipe.

    # -- event-file persistence (source of truth) ---------------------------
    def _write_event(self, event_type, payload):
        record = {"event": event_type, "at": _now_iso(), **payload}
        claim_uid = payload.get("claim_uid", "unclaimed")
        name = f"{_ts_compact()}__{claim_uid}__{event_type}.json"
        path = self.events_root / name
        # Collision-proof: the timestamp is microsecond-resolution and this
        # call always runs inside self._write_guard() (single writer at a
        # time across processes), so a duplicate name is not expected; guard
        # anyway rather than silently overwrite an existing immutable event.
        suffix = 0
        while path.exists():
            suffix += 1
            path = self.events_root / f"{_ts_compact()}__{claim_uid}__{event_type}__{suffix}.json"
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return record

    # -- internal appliers (used by both the live path and event replay) ---
    def _apply_claim_created(self, db, ev):
        db.execute(
            "INSERT OR IGNORE INTO claims(claim_uid,target_raw,target_identity,target_identity_kind,subject_kind,"
            "subject_value,predicate,predicate_norm,asserted_value,asserted_value_norm,statement,status,inferred,"
            "source,superseded_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ev["claim_uid"], ev["target_raw"], ev["target_identity"], ev["target_identity_kind"],
                ev["subject_kind"], ev["subject_value"], ev["predicate"], ev["predicate_norm"],
                ev["asserted_value"], ev["asserted_value_norm"], ev.get("statement"), ev["status"],
                int(ev.get("inferred", 0)), ev.get("source"), None, ev["at"], ev["at"],
            ),
        )

    def _apply_evidence_linked(self, db, ev):
        db.execute(
            "INSERT INTO claim_evidence(claim_uid,evidence_uid,relation,note,created_at) VALUES(?,?,?,?,?)",
            (ev["claim_uid"], ev["evidence_uid"], ev["relation"], ev.get("note"), ev["at"]),
        )

    def _apply_status_changed(self, db, ev):
        db.execute(
            "UPDATE claims SET status=?, updated_at=? WHERE claim_uid=?",
            (ev["new_status"], ev["at"], ev["claim_uid"]),
        )
        db.execute(
            "INSERT INTO claim_status_history(claim_uid,old_status,new_status,reason,caused_by,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (ev["claim_uid"], ev.get("old_status"), ev["new_status"], ev.get("reason"), ev.get("caused_by"), ev["at"]),
        )

    def _apply_edge(self, db, ev):
        db.execute(
            "INSERT INTO claim_edges(from_claim_uid,to_claim_uid,relation,note,created_at) VALUES(?,?,?,?,?)",
            (ev["from_claim_uid"], ev["to_claim_uid"], ev["relation"], ev.get("note"), ev["at"]),
        )
        if ev["relation"] == "SUPERSEDES":
            db.execute(
                "UPDATE claims SET superseded_by=?, updated_at=? WHERE claim_uid=?",
                (ev["from_claim_uid"], ev["at"], ev["to_claim_uid"]),
            )

    _APPLIERS = {
        "claim_created": "_apply_claim_created",
        "evidence_linked": "_apply_evidence_linked",
        "status_changed": "_apply_status_changed",
        "edge": "_apply_edge",
    }

    def rebuild_from_events(self):
        """Replay every event file under self.events_root, in chronological
        (timestamp-prefixed filename) order, and reconstruct the SQLite
        tables from nothing else -- the recovery path a schema bump or a
        deleted/corrupted database relies on. Mirrors evidence_index
        .refresh()'s own "files are the source of truth" contract."""
        files = sorted(self.events_root.glob("*.json"))
        applied = 0
        malformed = 0
        with self._write_guard(), self._session() as db:
            db.executescript(
                "DELETE FROM claim_status_history; DELETE FROM claim_edges; "
                "DELETE FROM claim_evidence; DELETE FROM claims;"
            )
            for path in files:
                try:
                    ev = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    malformed += 1
                    continue
                method_name = self._APPLIERS.get(ev.get("event"))
                if not method_name:
                    malformed += 1
                    continue
                getattr(self, method_name)(db, ev)
                applied += 1
        return {
            "ok": True, "tool": "claim_index", "operation": "rebuild_from_events",
            "events_scanned": len(files), "events_applied": applied, "malformed": malformed,
        }

    # -- evidence validation --------------------------------------------
    def _evidence_summary(self, evidence_uid):
        if not self.evidence_index:
            return None
        try:
            record = self.evidence_index.record(record_id=evidence_uid)
        except Exception:  # noqa: BLE001 - a broken lookup must not break claim provenance
            return None
        if not record.get("ok") and record.get("error") != "NOT_INDEXED":
            return None
        if record.get("error") == "NOT_INDEXED" or not record.get("path"):
            return None
        return {
            "evidence_uid": evidence_uid, "path": record.get("path"), "target": record.get("target"),
            "tool": record.get("tool_name"), "summary": record.get("summary"),
            "record_time": record.get("record_time"),
        }

    # -- mutation: create_claim -------------------------------------------
    def create_claim(
        self, target, subject_kind, subject_value, predicate, asserted_value, statement="",
        status="CANDIDATE", target_hash=None, inferred=False, source="", initial_evidence=None,
    ):
        target_raw, target_identity, target_identity_kind = _resolve_target_identity(target, target_hash)
        if not target_raw:
            raise ClaimError("TARGET_REQUIRED")
        norm_subject_kind, norm_subject_value = _normalize_subject(subject_kind, subject_value)
        if not norm_subject_kind or not norm_subject_value:
            raise ClaimError("SUBJECT_REQUIRED")
        predicate = str(predicate or "").strip()
        predicate_norm = _normalize_text(predicate)
        if not predicate_norm:
            raise ClaimError("PREDICATE_REQUIRED")
        asserted_value = str(asserted_value or "").strip()
        asserted_value_norm = _normalize_text(asserted_value)
        if not asserted_value_norm:
            raise ClaimError("ASSERTED_VALUE_REQUIRED")
        status = str(status or "CANDIDATE").strip().upper()
        if status not in INITIAL_STATUSES:
            raise ClaimError(
                "CONTRADICTED_NOT_A_VALID_INITIAL_STATUS" if status == "CONTRADICTED" else "INVALID_INITIAL_STATUS",
                status,
            )
        initial_evidence = list(initial_evidence or [])
        for entry in initial_evidence:
            if str(entry.get("relation", "")).strip().upper() not in VALID_RELATIONS:
                raise ClaimError("INVALID_EVIDENCE_RELATION", entry.get("relation"))
        has_initial_support = any(
            str(e.get("relation", "")).strip().upper() == "SUPPORTS" for e in initial_evidence
        )
        if status == "PROVEN" and not has_initial_support:
            raise ClaimError("PROVEN_REQUIRES_SUPPORTING_EVIDENCE")

        claim_uid = _claim_uid()
        with self._write_guard(), self._session() as db:
            create_event = self._write_event("claim_created", {
                "claim_uid": claim_uid, "target_raw": target_raw, "target_identity": target_identity,
                "target_identity_kind": target_identity_kind, "subject_kind": norm_subject_kind,
                "subject_value": norm_subject_value, "predicate": predicate, "predicate_norm": predicate_norm,
                "asserted_value": asserted_value, "asserted_value_norm": asserted_value_norm,
                "statement": str(statement or "")[:MAX_STATEMENT_CHARS], "status": status,
                "inferred": bool(inferred), "source": str(source or ""),
            })
            self._apply_claim_created(db, create_event)

            conflicts = []
            uncomparable = []
            # Automatic contradiction detection: only claims sharing the
            # exact (target_identity, subject_kind, subject_value) group are
            # ever compared -- see module docstring for why a different
            # subject is never compared at all.
            prior = db.execute(
                "SELECT * FROM claims WHERE target_identity=? AND subject_kind=? AND subject_value=? "
                "AND claim_uid != ? AND status != 'CONTRADICTED'",
                (target_identity, norm_subject_kind, norm_subject_value, claim_uid),
            ).fetchall()
            for row in prior:
                if row["predicate_norm"] != predicate_norm:
                    edge_event = self._write_event("edge", {
                        "claim_uid": claim_uid, "from_claim_uid": claim_uid, "to_claim_uid": row["claim_uid"],
                        "relation": "UNCOMPARABLE",
                        "note": "same subject, different predicate -- not automatically comparable",
                    })
                    self._apply_edge(db, edge_event)
                    uncomparable.append(row["claim_uid"])
                    continue
                if row["asserted_value_norm"] == asserted_value_norm:
                    continue  # same question, same answer -- reinforcing, not a conflict
                edge_event = self._write_event("edge", {
                    "claim_uid": claim_uid, "from_claim_uid": claim_uid, "to_claim_uid": row["claim_uid"],
                    "relation": "CONFLICTS_WITH",
                    "note": "same subject and predicate, incompatible asserted_value",
                })
                self._apply_edge(db, edge_event)
                status_event = self._write_event("status_changed", {
                    "claim_uid": row["claim_uid"], "old_status": row["status"], "new_status": "CONTRADICTED",
                    "reason": f"conflicts with newly created claim {claim_uid} asserting a different value "
                              f"for the same predicate '{predicate_norm}'",
                    "caused_by": claim_uid,
                })
                self._apply_status_changed(db, status_event)
                conflicts.append(row["claim_uid"])

            for entry in initial_evidence:
                self._link_evidence_locked(
                    db, claim_uid, entry.get("evidence_uid"), str(entry["relation"]).strip().upper(),
                    entry.get("note", ""),
                )

        return {
            "ok": True, "tool": "claim_index", "operation": "create_claim", "claim_uid": claim_uid,
            "status": self._current_status(claim_uid), "target_identity": target_identity,
            "subject_kind": norm_subject_kind, "subject_value": norm_subject_value,
            "conflicts_with": conflicts, "uncomparable_with": uncomparable,
        }

    def _current_status(self, claim_uid):
        with self._session() as db:
            row = db.execute("SELECT status FROM claims WHERE claim_uid=?", (claim_uid,)).fetchone()
        return row["status"] if row else None

    # -- mutation: add_evidence -------------------------------------------
    def _link_evidence_locked(self, db, claim_uid, evidence_uid, relation, note):
        """Caller already holds self._write_guard()/self._session()."""
        row = db.execute("SELECT status FROM claims WHERE claim_uid=?", (claim_uid,)).fetchone()
        if not row:
            raise ClaimError("CLAIM_NOT_FOUND", claim_uid)
        evidence_uid = str(evidence_uid or "").strip()
        if not evidence_uid:
            raise ClaimError("EVIDENCE_UID_REQUIRED")
        if self.evidence_index is not None:
            summary = self._evidence_summary(evidence_uid)
            if summary is None:
                raise ClaimError("EVIDENCE_NOT_FOUND", evidence_uid)
        link_event = self._write_event("evidence_linked", {
            "claim_uid": claim_uid, "evidence_uid": evidence_uid, "relation": relation, "note": str(note or ""),
        })
        self._apply_evidence_linked(db, link_event)
        if relation == "REFUTES" and row["status"] != "CONTRADICTED":
            # The load-bearing rule (see module docstring): refuting
            # evidence on ANY status, PROVEN included, is an unconditional,
            # immediate transition -- never a silent no-op.
            status_event = self._write_event("status_changed", {
                "claim_uid": claim_uid, "old_status": row["status"], "new_status": "CONTRADICTED",
                "reason": f"refuting evidence {evidence_uid} attached", "caused_by": evidence_uid,
            })
            self._apply_status_changed(db, status_event)

    def add_evidence(self, claim_uid, evidence_uid, relation, note=""):
        relation = str(relation or "").strip().upper()
        if relation not in VALID_RELATIONS:
            raise ClaimError("INVALID_EVIDENCE_RELATION", relation)
        with self._write_guard(), self._session() as db:
            self._link_evidence_locked(db, claim_uid, evidence_uid, relation, note)
        return {
            "ok": True, "tool": "claim_index", "operation": "add_evidence", "claim_uid": claim_uid,
            "evidence_uid": evidence_uid, "relation": relation, "status": self._current_status(claim_uid),
        }

    # -- mutation: supersede_claim -----------------------------------------
    def supersede_claim(self, new_claim_uid, old_claim_uid, reason=""):
        if new_claim_uid == old_claim_uid:
            raise ClaimError("CANNOT_SUPERSEDE_SELF")
        with self._write_guard(), self._session() as db:
            new_row = db.execute("SELECT * FROM claims WHERE claim_uid=?", (new_claim_uid,)).fetchone()
            old_row = db.execute("SELECT * FROM claims WHERE claim_uid=?", (old_claim_uid,)).fetchone()
            if not new_row:
                raise ClaimError("CLAIM_NOT_FOUND", new_claim_uid)
            if not old_row:
                raise ClaimError("CLAIM_NOT_FOUND", old_claim_uid)
            edge_event = self._write_event("edge", {
                "claim_uid": new_claim_uid, "from_claim_uid": new_claim_uid, "to_claim_uid": old_claim_uid,
                "relation": "SUPERSEDES", "note": str(reason or ""),
            })
            self._apply_edge(db, edge_event)
            if old_row["status"] != "CONTRADICTED":
                status_event = self._write_event("status_changed", {
                    "claim_uid": old_claim_uid, "old_status": old_row["status"], "new_status": "CONTRADICTED",
                    "reason": f"superseded by {new_claim_uid}" + (f": {reason}" if reason else ""),
                    "caused_by": new_claim_uid,
                })
                self._apply_status_changed(db, status_event)
        return {
            "ok": True, "tool": "claim_index", "operation": "supersede_claim", "new_claim_uid": new_claim_uid,
            "old_claim_uid": old_claim_uid, "old_status": self._current_status(old_claim_uid),
        }

    # -- queries (ids + one-line summaries + pagination, never bulk bodies) -
    @staticmethod
    def _claim_hit(row):
        return {
            "claim_uid": row["claim_uid"], "target": row["target_raw"], "subject_kind": row["subject_kind"],
            "subject_value": row["subject_value"], "predicate": row["predicate"],
            "asserted_value": row["asserted_value"], "status": row["status"], "inferred": bool(row["inferred"]),
            "statement": (row["statement"] or "")[:200], "created_at": row["created_at"],
            "updated_at": row["updated_at"], "superseded_by": row["superseded_by"],
        }

    def _page(self, db, sql, params, limit, offset):
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        rows = db.execute(sql, params + (limit + 1, offset)).fetchall()
        truncated = len(rows) > limit
        rows = rows[:limit]
        return rows, truncated, (offset + limit if truncated else None)

    def claims_for_target(self, target, target_hash=None, status="", limit=20, offset=0):
        target_raw, target_identity, _kind = _resolve_target_identity(target, target_hash)
        if not target_raw:
            return {"ok": False, "error": "TARGET_REQUIRED"}
        sql = "SELECT * FROM claims WHERE (target_identity=? OR target_raw LIKE ? ESCAPE '\\')"
        params = [target_identity, f"%{_like_escape(target_raw)}%"]
        if status:
            sql += " AND status=?"
            params.append(str(status).strip().upper())
        sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        with self._session() as db:
            rows, truncated, next_offset = self._page(db, sql, tuple(params), limit, offset)
        return {
            "ok": True, "tool": "claim_index", "operation": "claims_for_target", "target": target_raw,
            "results": [self._claim_hit(r) for r in rows], "count": len(rows), "truncated": truncated,
            "next_offset": next_offset,
        }

    def claim_provenance(self, claim_uid):
        with self._session() as db:
            claim_row = db.execute("SELECT * FROM claims WHERE claim_uid=?", (claim_uid,)).fetchone()
            if not claim_row:
                return {"ok": False, "error": "CLAIM_NOT_FOUND"}
            evidence_rows = db.execute(
                "SELECT * FROM claim_evidence WHERE claim_uid=? ORDER BY created_at", (claim_uid,),
            ).fetchall()
            outgoing = db.execute(
                "SELECT * FROM claim_edges WHERE from_claim_uid=? ORDER BY created_at", (claim_uid,),
            ).fetchall()
            incoming = db.execute(
                "SELECT * FROM claim_edges WHERE to_claim_uid=? ORDER BY created_at", (claim_uid,),
            ).fetchall()
            history = db.execute(
                "SELECT * FROM claim_status_history WHERE claim_uid=? ORDER BY created_at", (claim_uid,),
            ).fetchall()
        supports = []
        refutes = []
        for row in evidence_rows:
            entry = {"evidence_uid": row["evidence_uid"], "note": row["note"], "created_at": row["created_at"]}
            summary = self._evidence_summary(row["evidence_uid"])
            if summary:
                entry["evidence_summary"] = summary
            (supports if row["relation"] == "SUPPORTS" else refutes).append(entry)
        return {
            "ok": True, "tool": "claim_index", "operation": "claim_provenance",
            "claim": self._claim_hit(claim_row),
            "supports": supports, "refutes": refutes,
            "supersedes": [dict(r) for r in outgoing if r["relation"] == "SUPERSEDES"],
            "superseded_by_edges": [dict(r) for r in incoming if r["relation"] == "SUPERSEDES"],
            "conflicts_with": [dict(r) for r in outgoing + incoming if r["relation"] == "CONFLICTS_WITH"],
            "uncomparable_with": [dict(r) for r in outgoing + incoming if r["relation"] == "UNCOMPARABLE"],
            "status_history": [dict(r) for r in history],
        }

    def contradicted_claims(self, target="", target_hash=None, limit=20, offset=0):
        sql = "SELECT * FROM claims WHERE status='CONTRADICTED'"
        params = []
        if target:
            target_raw, target_identity, _kind = _resolve_target_identity(target, target_hash)
            sql += " AND (target_identity=? OR target_raw LIKE ? ESCAPE '\\')"
            params += [target_identity, f"%{_like_escape(target_raw)}%"]
        sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        with self._session() as db:
            rows, truncated, next_offset = self._page(db, sql, tuple(params), limit, offset)
            hits = []
            for row in rows:
                hit = self._claim_hit(row)
                reason_row = db.execute(
                    "SELECT reason FROM claim_status_history WHERE claim_uid=? AND new_status='CONTRADICTED' "
                    "ORDER BY created_at DESC LIMIT 1",
                    (row["claim_uid"],),
                ).fetchone()
                hit["contradicted_reason"] = reason_row["reason"] if reason_row else None
                hits.append(hit)
        return {
            "ok": True, "tool": "claim_index", "operation": "contradicted_claims", "target": target,
            "results": hits, "count": len(hits), "truncated": truncated, "next_offset": next_offset,
        }

    def already_claimed(self, target, subject_kind, subject_value, predicate="", target_hash=None, limit=20, offset=0):
        """"Is this already claimed?" for a (target, anchor[, predicate])
        pair -- pairs with evidence_index.already_answered as the anti-waste
        query for the claim layer: before asserting a new claim, a caller
        checks here first.

        Target matching deliberately mirrors ``claims_for_target`` and
        ``contradicted_claims`` (``target_identity=? OR target_raw LIKE ?``)
        instead of exact ``target_identity`` equality alone. Demonstrated
        live failure this fixes: a claim recorded under
        target='trybypassme/TBM.exe' produced ``already_claimed=True`` when
        queried with that exact spelling but a bare ``False`` -- no prior
        claim found -- when queried with target='trybypassme', even though
        it is the same recorded claim. Since this query's entire purpose is
        to stop a future session from re-investigating a settled question,
        answering a confident "no" on a spelling variant is the worst
        failure mode this module exists to prevent -- so it must match at
        least as generously as its siblings, never more strictly.

        When the exact (target, subject_kind, subject_value[, predicate])
        query comes up empty, a second, broader query for any OTHER claim
        about the same target (any subject/predicate) is run and returned
        under ``near_matches`` (capped small, never the primary answer) --
        this does not solve subject_value/predicate slug drift (two
        sessions choosing different slugs for the same real question still
        will not appear as an exact hit), but it turns a bare, confident
        miss into "nothing exact, but here are N other claims about this
        target" so a caller can look before asserting a duplicate/
        conflicting claim under a new slug.
        """
        target_raw, target_identity, _kind = _resolve_target_identity(target, target_hash)
        if not target_raw:
            return {"ok": False, "error": "TARGET_REQUIRED"}
        norm_subject_kind, norm_subject_value = _normalize_subject(subject_kind, subject_value)
        if not norm_subject_kind or not norm_subject_value:
            return {"ok": False, "error": "SUBJECT_REQUIRED"}
        target_match_sql = "(target_identity=? OR target_raw LIKE ? ESCAPE '\\')"
        target_match_params = [target_identity, f"%{_like_escape(target_raw)}%"]
        sql = f"SELECT * FROM claims WHERE {target_match_sql} AND subject_kind=? AND subject_value=?"
        params = target_match_params + [norm_subject_kind, norm_subject_value]
        if predicate:
            sql += " AND predicate_norm=?"
            params.append(_normalize_text(predicate))
        sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        with self._session() as db:
            rows, truncated, next_offset = self._page(db, sql, tuple(params), limit, offset)
            near_matches = []
            if not rows:
                near_sql = (
                    f"SELECT * FROM claims WHERE {target_match_sql} "
                    "ORDER BY updated_at DESC LIMIT 5"
                )
                near_rows = db.execute(near_sql, tuple(target_match_params)).fetchall()
                near_matches = [self._claim_hit(r) for r in near_rows]
        return {
            "ok": True, "tool": "claim_index", "operation": "already_claimed", "target": target_raw,
            "subject_kind": norm_subject_kind, "subject_value": norm_subject_value,
            "already_claimed": bool(rows), "results": [self._claim_hit(r) for r in rows], "count": len(rows),
            "truncated": truncated, "next_offset": next_offset,
            "near_matches": near_matches,
            "near_matches_note": (
                "no exact (target, subject, predicate) match -- these are other claims about the same "
                "target (any subject/predicate) that may answer the same question under a different slug"
            ) if near_matches else None,
        }

    def status(self):
        with self._session() as db:
            counts = {
                "claims": db.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
                "by_status": {
                    r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) AS n FROM claims GROUP BY status")
                },
                "evidence_links": db.execute("SELECT COUNT(*) FROM claim_evidence").fetchone()[0],
                "edges": db.execute("SELECT COUNT(*) FROM claim_edges").fetchone()[0],
                "edges_by_relation": {
                    r["relation"]: r["n"] for r in db.execute("SELECT relation,COUNT(*) AS n FROM claim_edges GROUP BY relation")
                },
                "inferred_claims": db.execute("SELECT COUNT(*) FROM claims WHERE inferred=1").fetchone()[0],
            }
        return {
            "ok": True, "tool": "claim_index", "operation": "status", "database": str(self.db_path),
            "events_root": str(self.events_root), "schema_version": SCHEMA_VERSION, **counts,
        }


def _like_escape(value):
    return str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def claim_index(
    operation="status", target="", target_hash="", subject_kind="", subject_value="", predicate="",
    asserted_value="", statement="", claim_status="CANDIDATE", inferred=False, source="", initial_evidence=None,
    claim_uid="", new_claim_uid="", old_claim_uid="", evidence_uid="", relation="", note="", reason="",
    status_filter="", limit=20, offset=0, events_root=None, db_path=None, evidence_root=None, evidence_db_path=None,
):
    """Top-level dispatcher, JSON-string-returning (mirrors
    evidence_index.evidence_index's own top-level convention)."""
    bound_evidence = EvidenceIndex(root=evidence_root, db_path=evidence_db_path) if (evidence_root or evidence_db_path) else None
    index = ClaimIndex(db_path=db_path, events_root=events_root, evidence_index=bound_evidence)
    try:
        if operation == "create_claim":
            result = index.create_claim(
                target, subject_kind, subject_value, predicate, asserted_value, statement=statement,
                status=claim_status, target_hash=target_hash or None, inferred=inferred, source=source,
                initial_evidence=initial_evidence,
            )
        elif operation == "add_evidence":
            result = index.add_evidence(claim_uid, evidence_uid, relation, note=note)
        elif operation == "supersede_claim":
            result = index.supersede_claim(new_claim_uid, old_claim_uid, reason=reason)
        elif operation == "claims_for_target":
            result = index.claims_for_target(target, target_hash=target_hash or None, status=status_filter, limit=limit, offset=offset)
        elif operation == "claim_provenance":
            result = index.claim_provenance(claim_uid)
        elif operation == "contradicted_claims":
            result = index.contradicted_claims(target, target_hash=target_hash or None, limit=limit, offset=offset)
        elif operation == "already_claimed":
            result = index.already_claimed(
                target, subject_kind, subject_value, predicate=predicate, target_hash=target_hash or None,
                limit=limit, offset=offset,
            )
        elif operation == "rebuild_from_events":
            result = index.rebuild_from_events()
        elif operation == "status":
            result = index.status()
        else:
            result = {"ok": False, "tool": "claim_index", "error": "UNKNOWN_OPERATION"}
    except ClaimError as exc:
        result = {"ok": False, "tool": "claim_index", "error": exc.code, "detail": exc.detail}
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)
