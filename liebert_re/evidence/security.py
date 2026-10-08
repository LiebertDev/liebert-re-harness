"""Deterministic evidence integrity checksums and staleness checks.

The model never calls this module directly.  A trusted runtime dispatcher
stamps tool output with a self-consistency checksum before a claim can use it
as PROVEN evidence.

WHAT THIS DOES AND DOES NOT GUARANTEE.  ``integrity_sha256`` is
``sha256(canonical_json(record))`` with no secret and no per-session key: the
algorithm and every input are public and in this file, so anyone who can
construct a record can compute a checksum that matches it.  That makes this
mechanism genuinely useful for detecting *accidental* corruption (a bit flip,
a truncated write, a stale copy) and for deduplication -- it is NOT proof
that the record was produced by this codebase's trusted runtime dispatcher
rather than hand-assembled by a deliberate forger, because nothing here is
kept secret from a forger.  Do not read ``integrity_status ==
"CONTENT_HASH_MATCHES"`` or ``evaluate_record(...)["trusted"] is True`` as an
authenticity/cryptographic-attestation claim; read it as "the record is
internally self-consistent and its target/content have not drifted since it
was written".  The one property in this codebase that *does* resist
deliberate forgery is binding an evidence record to a ``result_id`` a live
``ToolResultStore`` actually produced during this process's own tool
dispatch (see ``research_state.evidence_ledger_v2``, upstream-only; not part of the published package); that binding, not this
module's checksum, is what should be cited as the anti-forgery property.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROVENANCE_SCHEMA_VERSION = 1
TRUSTED_SOURCE_KINDS = {"RUNTIME_TOOL", "TRUSTED_CACHE", "TRUSTED_EXTERNAL"}


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")


def _repository_commit(root: Path) -> str | None:
    """Read local Git identity without invoking Git or touching the network."""
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            loose = git / ref
            if loose.is_file():
                return loose.read_text(encoding="utf-8").strip() or None
            packed = git / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line and not line.startswith(("#", "^")):
                        commit, name = line.split(" ", 1)
                        if name.strip() == ref:
                            return commit
        return head or None
    except (OSError, ValueError):
        return None


def local_git_commit(root: Path) -> str | None:
    """Return the local HEAD without invoking Git or contacting a remote."""
    return _repository_commit(Path(root))


def workspace_ref(workspace: Path) -> str:
    normalized = str(Path(workspace).resolve()).replace("\\", "/").casefold()
    return "WSR-" + sha256_text(normalized)[:20]


def tool_version(tool: str, project_root: Path) -> str:
    registry = Path(project_root) / "tool_registry.py"
    return "tool-registry:" + (sha256_file(registry) or sha256_text(tool))[:16]


def _integrity_checksum(provenance: dict) -> str:
    """Unkeyed SHA-256 over every other field of ``provenance``.

    This is a corruption/tamper-EVIDENT checksum, not a tamper-PROOF seal:
    the algorithm and the payload are both public, so a party constructing
    ``provenance`` from scratch can compute a value that matches it. It
    catches accidental drift (a byte flipped on disk, a stale copy) and
    supports deduplication; it cannot distinguish a record this runtime
    actually produced from one a forger hand-built to match.
    """
    payload = {key: value for key, value in provenance.items() if key != "integrity_sha256"}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def build_provenance(
    *,
    evidence_id: str,
    invocation_id: str | None,
    source_kind: str,
    tool: str,
    raw_output: str,
    stored_content: str,
    target: str,
    target_sha256: str | None,
    workspace: Path,
    project_root: Path,
    timestamp: str,
    version: str | None = None,
) -> dict:
    source_kind = str(source_kind or "UNATTESTED").upper()
    invocation = str(invocation_id or "").strip()
    provenance = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "producer": "teacher_runtime_tool_dispatch",
        "source_kind": source_kind,
        # Records that a trusted source_kind + a real invocation_id were
        # present when this was built. This is bookkeeping about the
        # declared source, not a cryptographic guarantee -- see the module
        # docstring for what actually resists forgery in this codebase.
        "integrity_status": "CONTENT_HASH_MATCHES" if invocation and source_kind in TRUSTED_SOURCE_KINDS else "NO_TRUSTED_INVOCATION",
        "evidence_id": str(evidence_id),
        "invocation_ids": [invocation] if invocation else [],
        "tool": str(tool),
        "tool_version": str(version or tool_version(tool, project_root)),
        "raw_output_sha256": sha256_text(raw_output),
        "raw_output_chars": len(str(raw_output)),
        "stored_content_sha256": sha256_text(stored_content),
        "stored_content_chars": len(str(stored_content)),
        "target": str(target or ""),
        "target_sha256": target_sha256,
        "workspace_ref": workspace_ref(workspace),
        "repository_commit": _repository_commit(Path(project_root)),
        "timestamp": str(timestamp),
    }
    provenance["integrity_sha256"] = _integrity_checksum(provenance)
    return provenance


def append_invocation(provenance: dict, invocation_id: str | None, source_kind: str | None = None) -> dict:
    updated = dict(provenance or {})
    invocation = str(invocation_id or "").strip()
    ids = list(dict.fromkeys([*(updated.get("invocation_ids") or []), *([invocation] if invocation else [])]))
    updated["invocation_ids"] = ids
    if source_kind:
        updated["source_kind"] = str(source_kind).upper()
    if ids and updated.get("source_kind") in TRUSTED_SOURCE_KINDS:
        updated["integrity_status"] = "CONTENT_HASH_MATCHES"
    updated["integrity_sha256"] = _integrity_checksum(updated)
    return updated


def evaluate_record(record: dict, *, stored_content: str | None = None, workspace: Path | None = None) -> dict:
    """Check a record's self-consistency and freshness.

    ``trusted: True`` means the record's declared checksum matches a fresh
    recomputation, its declared source/invocation bookkeeping is present,
    and its stored content and (when the record pins a target hash) target
    file still hash to what the record recorded. A check whose input was not
    supplied (``stored_content``; ``workspace`` for a hash-pinned target) did
    not run, so the result is ``UNVERIFIABLE`` and ``trusted`` is False --
    never ``CURRENT``. It does NOT mean the record was
    cryptographically authenticated against a deliberate forger -- see the
    module docstring. A hand-constructed record with a self-consistent
    checksum passes exactly the same as a genuine one; that is a known,
    accepted limitation of an unkeyed integrity checksum, pinned down by
    ``tests/test_evidence_attestation_honesty.py``.
    """
    provenance = record.get("provenance") if isinstance(record, dict) else None
    if not isinstance(provenance, dict):
        return {"trusted": False, "status": "LEGACY_NO_PROVENANCE", "reason": "missing evidence provenance"}
    if provenance.get("integrity_status") != "CONTENT_HASH_MATCHES" or not provenance.get("invocation_ids"):
        return {"trusted": False, "status": "NO_TRUSTED_INVOCATION", "reason": "no trusted runtime invocation"}
    if provenance.get("source_kind") not in TRUSTED_SOURCE_KINDS:
        return {"trusted": False, "status": "UNTRUSTED_SOURCE", "reason": provenance.get("source_kind")}
    if provenance.get("evidence_id") != record.get("evidence_id"):
        return {"trusted": False, "status": "EVIDENCE_ID_MISMATCH", "reason": "record/provenance identity mismatch"}
    if provenance.get("integrity_sha256") != _integrity_checksum(provenance):
        return {"trusted": False, "status": "INTEGRITY_HASH_MISMATCH", "reason": "checksummed provenance changed"}
    if stored_content is not None and provenance.get("stored_content_sha256") != sha256_text(stored_content):
        return {"trusted": False, "status": "CONTENT_HASH_MISMATCH", "reason": "stored evidence content changed"}
    target_hash = provenance.get("target_sha256")
    target = str(provenance.get("target") or record.get("target") or "")
    # A check that was not run is not a check that passed: CURRENT is only returned once the
    # content comparison ran and, where the record pins a target hash, the target comparison ran.
    # Checks that can run still run first, so a detectable mismatch is never hidden by a skipped one.
    skipped = []
    if stored_content is None:
        skipped.append("stored_content")
    if target_hash and (workspace is None or not target):
        skipped.append("target_file")
    if target_hash and workspace is not None and target:
        candidate = Path(target)
        try:
            path = candidate.resolve() if candidate.is_absolute() else (Path(workspace) / candidate).resolve()
            path.relative_to(Path(workspace).resolve())
        except (OSError, ValueError):
            return {"trusted": False, "status": "TARGET_OUTSIDE_WORKSPACE", "reason": target}
        current = sha256_file(path)
        if current is None:
            return {"trusted": False, "status": "TARGET_MISSING", "reason": target}
        if current != target_hash:
            return {"trusted": False, "status": "STALE_TARGET", "reason": target, "expected": target_hash, "current": current}
    if skipped:
        return {
            "trusted": False, "status": "UNVERIFIABLE", "checks_not_performed": skipped,
            "reason": "freshness checks could not run: " + ", ".join(skipped),
        }
    return {"trusted": True, "status": "CURRENT", "reason": None}
