"""Generic evidence-bound security hypotheses, counter-evidence and reports.

This layer consumes normalized observable records.  It does not execute a
target, infer exploitability, or upgrade static evidence to a confirmed
vulnerability.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from liebert_re import strict_json
from liebert_re.evidence.index import EvidenceIndex, _record_resolves
from liebert_re.report.exploit_validation import _normalize_sha256


# UNVERIFIED: evidence IDs are cited but were never resolved against an evidence index, so
# SUPPORTED (which means "the cited evidence exists") cannot be claimed.
HYPOTHESIS_STATUSES = frozenset({"SUPPORTED", "UNVERIFIED", "NEEDS_MORE_ANALYSIS", "REFUTED", "UNSUPPORTED"})
COUNTER_KINDS = frozenset({
    "CALLER_VALIDATION", "WRAPPER_VALIDATION", "BOUNDS_CHECK", "ACL_CHECK",
    "TOKEN_CHECK", "PRIVILEGE_CHECK", "SIGNATURE_VALIDATION", "INTEGRITY_CHECK",
    "SANITIZER", "EARLIER_GUARD", "STATE_VALIDATION",
})
FINDING_FACETS = frozenset({
    "CRACK", "KEYGEN", "PATCH", "LICENSE_BYPASS", "ANTI_CHEAT_BYPASS",
    "EXPLOIT", "CHEAT", "UNSPECIFIED",
})
FINDING_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})


def _id(prefix: str, *parts: object) -> str:
    material = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return prefix + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _store_resolves(store: EvidenceIndex, evidence_id: str) -> bool:
    """True only when ``evidence_id`` is an ``EVX-`` identity the store itself returns a
    readable record for, under that same identity, whose bytes on disk NOW were read completely
    and, for a ``.json`` record, parse. The store's cached metadata is not what is checked: a
    record that was good when indexed but is truncated or corrupt today resolves nothing. A
    lookup that raises is not a hit."""
    if not evidence_id.startswith("EVX-"):
        return False
    try:
        record = store.record(record_id=evidence_id)
    except Exception:  # noqa: BLE001 - an unreadable store resolves nothing
        return False
    return _record_resolves(record, evidence_id)  # shared rule: ok, same UID, fully read, .json parses now


def _evidence_binding(
    support: Iterable[str], known_evidence_ids: Iterable[str] | None = None,
    evidence_store: EvidenceIndex | None = None,
) -> tuple[str, list[str]]:
    """``(binding, unresolved)``: NONE (nothing cited), UNCHECKED (no evidence store to check
    against), UNRESOLVED (some cited ID is not in the store, or not in the caller's list) or
    VERIFIED.

    Only the store can verify. ``known_evidence_ids`` is the caller's own assertion of what
    exists and cannot stand in for it: it may narrow what is accepted (an ID outside it is
    unresolved) but never widen it, and with no store the binding is UNCHECKED whatever the
    list says. A store that is not an :class:`EvidenceIndex` is no store."""
    cited = sorted({str(item) for item in support if str(item)})
    if not cited:
        return "NONE", []
    if not isinstance(evidence_store, EvidenceIndex):
        return "UNCHECKED", []
    allowed = None if known_evidence_ids is None else {str(item) for item in known_evidence_ids}
    unresolved = [
        item for item in cited
        if (allowed is not None and item not in allowed) or not _store_resolves(evidence_store, item)
    ]
    return ("UNRESOLVED", unresolved) if unresolved else ("VERIFIED", [])


def build_security_hypothesis(
    *, artifact_id: str, category: str, function_id: str = "UNKNOWN",
    location: str = "UNKNOWN", observed_pattern: str,
    supporting_evidence: Iterable[str] = (), missing_evidence: Iterable[str] = (),
    facet: str = "UNSPECIFIED", attacker_goal: str = "", attacker_effort: str = "UNKNOWN",
    severity: str = "UNKNOWN", remediation: str = "",
    claim_type: str = "", claim_target: str = "", claim_address: Any = None,
    claim_address_kind: str = "va", claim_constant_value: Any = None,
    known_evidence_ids: Iterable[str] | None = None, evidence_store: EvidenceIndex | None = None,
) -> dict[str, Any]:
    """``evidence_store`` (an :class:`~liebert_re.evidence.index.EvidenceIndex`) is what the
    cited ``supporting_evidence`` is resolved against. ``SUPPORTED`` requires every cited ID
    to resolve in it; with no store the status is ``UNVERIFIED``, and an ID the store does not
    know leaves the hypothesis at ``NEEDS_MORE_ANALYSIS``.

    ``known_evidence_ids`` is kept for backward compatibility but is a caller-supplied list and
    proves nothing: it can only narrow what the store accepts. Passing it without a store
    yields ``UNVERIFIED``, never ``SUPPORTED``.

    ``claim_type``/``claim_target``/``claim_address``/``claim_address_kind``/
    ``claim_constant_value`` are additive, opt-in (GAP-061 step 4): passing
    none of them leaves every existing caller's finding byte-for-byte
    unchanged. Setting ``claim_type="constant_at_address"`` (with
    ``claim_target``, ``claim_address`` and ``claim_constant_value``) makes
    ``assessment_run._bind_findings_to_run`` independently re-verify this
    finding's own predicate against the real bytes via
    ``constant_at_address_verifier`` instead of only checking that its cited
    evidence IDs exist -- see ``assessment_run._constant_at_address_verdict``,
    which reads these exact field names off the finding dict this function
    returns."""
    support = sorted({str(item) for item in supporting_evidence if str(item)})
    missing = sorted({str(item) for item in missing_evidence if str(item)})
    hypothesis_id = _id("HYP-IR-", artifact_id, category, function_id, location, observed_pattern)
    facet_norm = str(facet or "UNSPECIFIED").upper()
    if facet_norm not in FINDING_FACETS:
        facet_norm = "UNSPECIFIED"
    severity_norm = str(severity or "UNKNOWN").upper()
    if severity_norm not in FINDING_SEVERITIES:
        severity_norm = "UNKNOWN"
    binding, _unresolved = _evidence_binding(support, known_evidence_ids, evidence_store)
    if missing or binding in {"NONE", "UNRESOLVED"}:
        status, confidence = "NEEDS_MORE_ANALYSIS", "LOW"
    elif binding == "UNCHECKED":
        status, confidence = "UNVERIFIED", "LOW"
    else:
        status, confidence = "SUPPORTED", "MEDIUM"
    return {
        "schema_version": 1,
        "hypothesis_id": hypothesis_id,
        "artifact_id": str(artifact_id),
        "function_id": str(function_id or "UNKNOWN"),
        "location": str(location or "UNKNOWN"),
        "category": str(category).upper(),
        "observed_pattern": str(observed_pattern),
        "supporting_evidence": support,
        "counter_evidence": [],
        "missing_evidence": missing,
        "status": status,
        "confidence": confidence,
        "validation_required": True,
        "confirmed_vulnerability": False,
        "facet": facet_norm,
        "attacker_goal": str(attacker_goal or ""),
        "attacker_effort": str(attacker_effort or "UNKNOWN"),
        "severity": severity_norm,
        "remediation": str(remediation or ""),
        "claim_type": str(claim_type or ""),
        "claim_target": str(claim_target or ""),
        "claim_address": claim_address,
        "claim_address_kind": str(claim_address_kind or "va"),
        "claim_constant_value": claim_constant_value,
    }


def verify_counter_evidence(
    hypothesis: dict[str, Any], candidates: Iterable[dict[str, Any]],
    *, known_evidence_ids: Iterable[str] | None = None, searched_scope: Iterable[str] = (),
    evidence_store: EvidenceIndex | None = None,
) -> dict[str, Any]:
    """Bind only evidence the ``evidence_store`` resolves; unproved counter claims cannot refute
    and, with no store, nothing is bound. ``known_evidence_ids`` can only narrow (see
    :func:`_evidence_binding`)."""
    if known_evidence_ids is not None:
        known_evidence_ids = frozenset(str(item) for item in known_evidence_ids)  # a generator is read once
    accepted = []
    rejected = []
    for raw in candidates:
        row = dict(raw)
        kind = str(row.get("kind") or "").upper()
        evidence_ids = sorted({str(item) for item in row.get("evidence_ids") or []})
        if kind not in COUNTER_KINDS:
            rejected.append({"reason": "UNSUPPORTED_COUNTER_KIND", "kind": kind})
            continue
        if _evidence_binding(evidence_ids, known_evidence_ids, evidence_store)[0] != "VERIFIED":
            rejected.append({"reason": "UNBOUND_COUNTER_EVIDENCE", "kind": kind, "evidence_ids": evidence_ids})
            continue
        accepted.append({
            "counter_id": _id("CE-", hypothesis.get("hypothesis_id"), kind, evidence_ids),
            "kind": kind,
            "summary": str(row.get("summary") or ""),
            "evidence_ids": evidence_ids,
            "scope": sorted({str(item) for item in row.get("scope") or searched_scope}),
        })
    result = dict(hypothesis)
    result["counter_evidence"] = sorted(accepted, key=lambda item: item["counter_id"])
    result["counter_search"] = {
        "searched_scope": sorted({str(item) for item in searched_scope}),
        "accepted": len(accepted), "rejected": rejected,
    }
    if accepted:
        result["status"] = "REFUTED"
        result["confidence"] = "HIGH" if len(accepted) > 1 else "MEDIUM"
    elif (
        result.get("supporting_evidence") and not result.get("missing_evidence")
        and _evidence_binding(result["supporting_evidence"], known_evidence_ids, evidence_store)[0] == "VERIFIED"
    ):
        result["status"] = "SUPPORTED"
        result["confidence"] = "MEDIUM"
    else:
        result["status"] = "NEEDS_MORE_ANALYSIS"
        result["confidence"] = "LOW"
    result["confirmed_vulnerability"] = False
    return result


def validate_finding(
    hypothesis: dict[str, Any], *, known_evidence_ids: Iterable[str] | None = None,
    evidence_store: EvidenceIndex | None = None,
) -> dict[str, Any]:
    issues = []
    status = str(hypothesis.get("status") or "").upper()
    if status not in HYPOTHESIS_STATUSES:
        issues.append("INVALID_STATUS")
    for field in ("hypothesis_id", "artifact_id", "category", "observed_pattern"):
        if not str(hypothesis.get(field) or "").strip():
            issues.append(f"MISSING_{field.upper()}")
    if status == "SUPPORTED" and not hypothesis.get("supporting_evidence"):
        issues.append("SUPPORTED_WITHOUT_EVIDENCE")
    binding, unresolved = _evidence_binding(hypothesis.get("supporting_evidence") or [], known_evidence_ids, evidence_store)
    if status == "SUPPORTED" and binding == "UNRESOLVED":
        issues.append("SUPPORTED_WITH_UNKNOWN_EVIDENCE")
    elif status == "SUPPORTED" and binding == "UNCHECKED":
        # SUPPORTED asserts the cited evidence exists. PASS needs that checked against a store.
        issues.append("SUPPORTED_EVIDENCE_NOT_VERIFIED")
    if status == "REFUTED" and not hypothesis.get("counter_evidence"):
        issues.append("REFUTED_WITHOUT_COUNTER_EVIDENCE")
    if hypothesis.get("confirmed_vulnerability"):
        issues.append("STATIC_CONFIRMATION_FORBIDDEN")
    return {
        "ok": not issues, "status": "PASS" if not issues else "FAIL", "issues": issues,
        "evidence_binding": binding, "unresolved_evidence": unresolved,
    }


def _bool_or_unknown(value: Any) -> bool | str:
    """A real bool as is; anything else (``"false"``, ``0``, ``None``) is ``"UNKNOWN"``, since
    ``bool("false")`` is True and a text flag must not decide whether validation is required."""
    return value if isinstance(value, bool) else "UNKNOWN"


def _reproduction_verdict(
    hypothesis: dict[str, Any], artifact_sha256: str = "UNKNOWN", evidence_store: EvidenceIndex | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """The reproduction status a report may state, plus a record of any claim it refused.

    ``CONFIRMED`` is accepted only when the hypothesis carries a ``validation_plan`` and
    ``validation_result`` for this very hypothesis and
    :func:`exploit_validation.verify_validation_result` confirms them against ``evidence_store``,
    and the plan's target hash is the artifact hash the report itself states for this finding
    (``artifact_sha256``; "UNKNOWN" confirms nothing). A bare
    ``reproduction_status: "CONFIRMED"`` in free JSON is a claim, not a result: it is
    reported as ``CONFIRMATION_UNVERIFIED`` and never counts as dynamic validation.
    """
    claimed = str(hypothesis.get("reproduction_status") or "NOT_EXECUTED")
    if claimed.strip().upper() != "CONFIRMED":
        return claimed, None
    plan, result = hypothesis.get("validation_plan"), hypothesis.get("validation_result")
    if not isinstance(plan, dict) or not isinstance(result, dict):
        return "CONFIRMATION_UNVERIFIED", {"claimed": claimed, "verified": False, "reason": "NO_VALIDATION_PLAN_AND_RESULT"}
    if not hypothesis.get("hypothesis_id") or plan.get("hypothesis_id") != hypothesis.get("hypothesis_id"):
        return "CONFIRMATION_UNVERIFIED", {"claimed": claimed, "verified": False, "reason": "PLAN_NOT_FOR_THIS_HYPOTHESIS"}
    reported = _normalize_sha256(artifact_sha256)
    if reported is None:
        return "CONFIRMATION_UNVERIFIED", {"claimed": claimed, "verified": False, "reason": "ARTIFACT_HASH_UNKNOWN"}
    if _normalize_sha256(plan.get("target_sha256")) != reported:
        return "CONFIRMATION_UNVERIFIED", {"claimed": claimed, "verified": False, "reason": "PLAN_TARGET_NOT_REPORTED_ARTIFACT"}
    from liebert_re.report.exploit_validation import verify_validation_result

    verdict = verify_validation_result(plan, result, evidence_store=evidence_store)
    if verdict.get("status") != "CONFIRMED":
        codes = sorted({str(issue.get("code")) for issue in verdict.get("issues") or [] if issue.get("severity") == "REJECT"})
        return "CONFIRMATION_UNVERIFIED", {"claimed": claimed, "verified": False, "reason": "VERIFIER_REJECTED", "issues": codes}
    return "CONFIRMED", {"claimed": claimed, "verified": True, "reason": None}


def render_finding_report(
    findings: Iterable[dict[str, Any]], *, artifact_hashes: dict[str, str] | None = None,
    scope_notes: Iterable[str] = (), known_evidence_ids: Iterable[str] | None = None,
    evidence_store: EvidenceIndex | None = None,
) -> dict[str, Any]:
    known = None if known_evidence_ids is None else {str(item) for item in known_evidence_ids}
    rows = []
    for hypothesis in findings:
        validation = validate_finding(hypothesis, known_evidence_ids=known, evidence_store=evidence_store)
        status = hypothesis.get("status")
        confidence = hypothesis.get("confidence", "LOW")
        if str(status or "").upper() == "SUPPORTED" and validation["evidence_binding"] != "VERIFIED":
            # A SUPPORTED label asserts the cited evidence exists. Without an index to check
            # it against that is unverified; with an index that lacks an ID it is unproven.
            status = "UNVERIFIED" if validation["evidence_binding"] == "UNCHECKED" else "NEEDS_MORE_ANALYSIS"
            confidence = "LOW"
        artifact_sha256 = (artifact_hashes or {}).get(str(hypothesis.get("artifact_id")), "UNKNOWN")
        reproduction_status, reproduction_claim = _reproduction_verdict(hypothesis, artifact_sha256, evidence_store)
        if reproduction_claim is not None:
            validation = {**validation, "reproduction_claim": reproduction_claim}
        facet = str(hypothesis.get("facet") or "UNSPECIFIED").upper()
        if facet not in FINDING_FACETS:
            facet = "UNSPECIFIED"
        severity = str(hypothesis.get("severity") or "UNKNOWN").upper()
        if severity not in FINDING_SEVERITIES:
            severity = "UNKNOWN"
        rows.append({
            "finding_id": _id("FND-", hypothesis.get("hypothesis_id")),
            "artifact_id": hypothesis.get("artifact_id"),
            "artifact_sha256": artifact_sha256,
            "function_id": hypothesis.get("function_id", "UNKNOWN"),
            "location": hypothesis.get("location", "UNKNOWN"),
            "observed_behavior": hypothesis.get("observed_pattern"),
            "hypothesis": hypothesis.get("category"),
            "supporting_evidence": list(hypothesis.get("supporting_evidence") or []),
            "counter_evidence": list(hypothesis.get("counter_evidence") or []),
            "missing_validation": list(hypothesis.get("missing_evidence") or []),
            "confidence": confidence,
            "status": status,
            "validation_required": _bool_or_unknown(hypothesis.get("validation_required", True)),
            "facet": facet,
            "attacker_goal": str(hypothesis.get("attacker_goal") or ""),
            "attacker_effort": str(hypothesis.get("attacker_effort") or "UNKNOWN"),
            "severity": severity,
            "remediation": str(hypothesis.get("remediation") or ""),
            # "CONFIRMED" is never derived from confirmed_vulnerability (guarded to False by
            # validate_finding) and never taken on the hypothesis dict's word alone: it needs
            # a plan/result pair that exploit_validation.verify_validation_result confirms.
            "reproduction_status": reproduction_status,
            "reproduction_ref": hypothesis.get("reproduction_ref"),
            "scope_notes": sorted({str(item) for item in scope_notes}),
            "contract_validation": validation,
        })
    rows.sort(key=lambda item: item["finding_id"])
    coverage: dict[str, str] = {}
    for row in rows:
        state = "RESOLVED" if row["reproduction_status"] == "CONFIRMED" else "UNKNOWN"
        prior = coverage.get(row["facet"])
        if prior is None:
            coverage[row["facet"]] = state
        elif prior != state:
            coverage[row["facet"]] = "PARTIAL"
    # True only when at least one finding's own reproduction_status is the
    # real isolated-runtime CONFIRMED verdict (set by
    # assessment_run._attach_dynamic_validation_verdict, never invented
    # here) -- the same predicate the coverage loop above already uses to
    # call a row RESOLVED. Previously hardcoded False unconditionally, which
    # meant a run that genuinely validated a finding in an isolated VM still
    # rendered "Validated in an isolated real runtime: No" (see
    # attack_resistance_report.py's own read of this field). An
    # ISOLATED_RUNTIME_INCONCLUSIVE reproduction_status deliberately does
    # NOT set this True: a real attempt that did not confirm anything must
    # never render as validated.
    dynamic_validation_performed = any(row["reproduction_status"] == "CONFIRMED" for row in rows)
    return {
        "schema_version": 1,
        "status": "PASS" if all(row["contract_validation"]["ok"] for row in rows) else "FAIL",
        "finding_count": len(rows),
        "findings": rows,
        "dynamic_validation_performed": dynamic_validation_performed,
        "exploit_code_generated": False,
        "coverage": coverage,
    }


def _store_from_paths(evidence_root: str | None, evidence_db_path: str | None) -> EvidenceIndex | None:
    """The evidence store a JSON tool call names, or None when it names neither path."""
    if not (evidence_root or evidence_db_path):
        return None
    return EvidenceIndex(root=evidence_root, db_path=evidence_db_path)


def counter_evidence_verify(
    hypothesis_json: str, candidates_json: str, known_evidence_ids: list[str] | None = None,
    searched_scope: list[str] | None = None, evidence_root: str | None = None,
    evidence_db_path: str | None = None,
) -> str:
    """Counter evidence is bound only when the evidence index at ``evidence_root`` /
    ``evidence_db_path`` resolves it; with neither given nothing is bound and nothing refutes.
    ``known_evidence_ids`` can only narrow what that index accepts."""
    try:
        hypothesis = strict_json.loads(hypothesis_json)
        candidates = strict_json.loads(candidates_json)
    except strict_json.StrictJSONError as exc:
        return json.dumps({"ok": False, "status": "INVALID_JSON", "reason": exc.reason})
    if not isinstance(hypothesis, dict) or not isinstance(candidates, list):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    result = verify_counter_evidence(
        hypothesis, candidates, known_evidence_ids=known_evidence_ids,
        searched_scope=searched_scope or (), evidence_store=_store_from_paths(evidence_root, evidence_db_path),
    )
    return json.dumps({"ok": True, "status": result.get("status"), "hypothesis": result}, ensure_ascii=False, indent=2, sort_keys=True)


def finding_report_generate(
    findings_json: str, artifact_hashes_json: str = "{}", scope_notes: list[str] | None = None,
    evidence: str | None = None, known_evidence_ids: list[str] | None = None,
    evidence_root: str | None = None, evidence_db_path: str | None = None,
) -> str:
    """Render the finding report and, when ``evidence`` is supplied, audit its claims.

    ``SUPPORTED`` findings are kept only when the evidence index named by ``evidence_root`` /
    ``evidence_db_path`` resolves every cited ID; with neither given they are reported
    ``UNVERIFIED``. ``known_evidence_ids`` is a caller-supplied list that can only narrow that.

    The added ``claim_guard`` field has three distinguishable states:
    ``CHECKED_CLEAN`` (guard ran, no issues), ``CHECKED_ISSUES`` (guard ran and
    found claims with no counterpart in ``evidence``) and ``NOT_CHECKED``
    (no evidence text supplied, so nothing was audited; ``issues`` is ``None``,
    not ``[]``). Issues never flip ``ok``/``status``: the guard is regex based
    and can produce false positives, so it informs the reader instead of
    rejecting the report.
    """
    try:
        findings = strict_json.loads(findings_json)
        artifact_hashes = strict_json.loads(artifact_hashes_json or "{}")
    except strict_json.StrictJSONError as exc:
        return json.dumps({"ok": False, "status": "INVALID_JSON", "reason": exc.reason})
    if not isinstance(findings, list) or not isinstance(artifact_hashes, dict):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    report = render_finding_report(
        findings, artifact_hashes=artifact_hashes, scope_notes=scope_notes or (), known_evidence_ids=known_evidence_ids,
        evidence_store=_store_from_paths(evidence_root, evidence_db_path),
    )
    guard: dict[str, Any] = {
        "checked": False, "state": "NOT_CHECKED", "issues": None, "contains_unproven_claims": None,
        "note": "No evidence text was supplied, so the report's claims were not audited.",
        "caveat": "The claim guard is regex based and can produce false positives; it flags, it does not reject.",
    }
    if evidence is not None and str(evidence).strip():
        from liebert_re.evidence.claim_guard import claim_guard_issues

        claim_text = "\n".join(
            str(row.get(key) or "")
            for row in report["findings"]
            for key in ("observed_behavior", "hypothesis", "attacker_goal", "remediation", "location")
        )
        issues = claim_guard_issues(claim_text, evidence)
        guard.update(
            checked=True, state="CHECKED_ISSUES" if issues else "CHECKED_CLEAN", issues=issues,
            contains_unproven_claims=bool(issues),
            note="Claims were compared with the supplied evidence text.",
        )
    return json.dumps({"ok": report["status"] == "PASS", **report, "claim_guard": guard}, ensure_ascii=False, indent=2, sort_keys=True)


__all__ = [
    "HYPOTHESIS_STATUSES", "COUNTER_KINDS", "FINDING_FACETS", "FINDING_SEVERITIES",
    "build_security_hypothesis", "verify_counter_evidence", "validate_finding",
    "render_finding_report", "counter_evidence_verify", "finding_report_generate",
]
