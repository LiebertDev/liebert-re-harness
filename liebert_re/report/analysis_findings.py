"""Generic evidence-bound security hypotheses, counter-evidence and reports.

This layer consumes normalized observable records.  It does not execute a
target, infer exploitability, or upgrade static evidence to a confirmed
vulnerability.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


HYPOTHESIS_STATUSES = frozenset({"SUPPORTED", "NEEDS_MORE_ANALYSIS", "REFUTED", "UNSUPPORTED"})
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


def build_security_hypothesis(
    *, artifact_id: str, category: str, function_id: str = "UNKNOWN",
    location: str = "UNKNOWN", observed_pattern: str,
    supporting_evidence: Iterable[str] = (), missing_evidence: Iterable[str] = (),
    facet: str = "UNSPECIFIED", attacker_goal: str = "", attacker_effort: str = "UNKNOWN",
    severity: str = "UNKNOWN", remediation: str = "",
    claim_type: str = "", claim_target: str = "", claim_address: Any = None,
    claim_address_kind: str = "va", claim_constant_value: Any = None,
) -> dict[str, Any]:
    """``claim_type``/``claim_target``/``claim_address``/``claim_address_kind``/
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
        "status": "NEEDS_MORE_ANALYSIS" if missing or not support else "SUPPORTED",
        "confidence": "LOW" if missing or not support else "MEDIUM",
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
    *, known_evidence_ids: Iterable[str], searched_scope: Iterable[str] = (),
) -> dict[str, Any]:
    """Bind only known evidence; unproved counter claims cannot refute."""
    known = {str(item) for item in known_evidence_ids}
    accepted = []
    rejected = []
    for raw in candidates:
        row = dict(raw)
        kind = str(row.get("kind") or "").upper()
        evidence_ids = sorted({str(item) for item in row.get("evidence_ids") or []})
        if kind not in COUNTER_KINDS:
            rejected.append({"reason": "UNSUPPORTED_COUNTER_KIND", "kind": kind})
            continue
        if not evidence_ids or any(item not in known for item in evidence_ids):
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
    elif result.get("supporting_evidence") and not result.get("missing_evidence"):
        result["status"] = "SUPPORTED"
        result["confidence"] = "MEDIUM"
    else:
        result["status"] = "NEEDS_MORE_ANALYSIS"
        result["confidence"] = "LOW"
    result["confirmed_vulnerability"] = False
    return result


def validate_finding(hypothesis: dict[str, Any]) -> dict[str, Any]:
    issues = []
    status = str(hypothesis.get("status") or "").upper()
    if status not in HYPOTHESIS_STATUSES:
        issues.append("INVALID_STATUS")
    for field in ("hypothesis_id", "artifact_id", "category", "observed_pattern"):
        if not str(hypothesis.get(field) or "").strip():
            issues.append(f"MISSING_{field.upper()}")
    if status == "SUPPORTED" and not hypothesis.get("supporting_evidence"):
        issues.append("SUPPORTED_WITHOUT_EVIDENCE")
    if status == "REFUTED" and not hypothesis.get("counter_evidence"):
        issues.append("REFUTED_WITHOUT_COUNTER_EVIDENCE")
    if hypothesis.get("confirmed_vulnerability"):
        issues.append("STATIC_CONFIRMATION_FORBIDDEN")
    return {"ok": not issues, "status": "PASS" if not issues else "FAIL", "issues": issues}


def render_finding_report(
    findings: Iterable[dict[str, Any]], *, artifact_hashes: dict[str, str] | None = None,
    scope_notes: Iterable[str] = (),
) -> dict[str, Any]:
    rows = []
    for hypothesis in findings:
        validation = validate_finding(hypothesis)
        facet = str(hypothesis.get("facet") or "UNSPECIFIED").upper()
        if facet not in FINDING_FACETS:
            facet = "UNSPECIFIED"
        severity = str(hypothesis.get("severity") or "UNKNOWN").upper()
        if severity not in FINDING_SEVERITIES:
            severity = "UNKNOWN"
        rows.append({
            "finding_id": _id("FND-", hypothesis.get("hypothesis_id")),
            "artifact_id": hypothesis.get("artifact_id"),
            "artifact_sha256": (artifact_hashes or {}).get(str(hypothesis.get("artifact_id")), "UNKNOWN"),
            "function_id": hypothesis.get("function_id", "UNKNOWN"),
            "location": hypothesis.get("location", "UNKNOWN"),
            "observed_behavior": hypothesis.get("observed_pattern"),
            "hypothesis": hypothesis.get("category"),
            "supporting_evidence": list(hypothesis.get("supporting_evidence") or []),
            "counter_evidence": list(hypothesis.get("counter_evidence") or []),
            "missing_validation": list(hypothesis.get("missing_evidence") or []),
            "confidence": hypothesis.get("confidence", "LOW"),
            "status": hypothesis.get("status"),
            "validation_required": bool(hypothesis.get("validation_required", True)),
            "facet": facet,
            "attacker_goal": str(hypothesis.get("attacker_goal") or ""),
            "attacker_effort": str(hypothesis.get("attacker_effort") or "UNKNOWN"),
            "severity": severity,
            "remediation": str(hypothesis.get("remediation") or ""),
            # "CONFIRMED" is never derived from confirmed_vulnerability (guarded to False by
            # validate_finding); it only ever arrives here already-set on the hypothesis dict
            # by a dynamic layer (exploit_validation.verify_validation_result), never invented.
            "reproduction_status": str(hypothesis.get("reproduction_status") or "NOT_EXECUTED"),
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


def counter_evidence_verify(hypothesis_json: str, candidates_json: str, known_evidence_ids: list[str], searched_scope: list[str] | None = None) -> str:
    try:
        hypothesis = json.loads(hypothesis_json)
        candidates = json.loads(candidates_json)
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "status": "INVALID_JSON"})
    if not isinstance(hypothesis, dict) or not isinstance(candidates, list):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    result = verify_counter_evidence(
        hypothesis, candidates, known_evidence_ids=known_evidence_ids,
        searched_scope=searched_scope or (),
    )
    return json.dumps({"ok": True, "status": result.get("status"), "hypothesis": result}, ensure_ascii=False, indent=2, sort_keys=True)


def finding_report_generate(
    findings_json: str, artifact_hashes_json: str = "{}", scope_notes: list[str] | None = None,
    evidence: str | None = None,
) -> str:
    """Render the finding report and, when ``evidence`` is supplied, audit its claims.

    The added ``claim_guard`` field has three distinguishable states:
    ``CHECKED_CLEAN`` (guard ran, no issues), ``CHECKED_ISSUES`` (guard ran and
    found claims with no counterpart in ``evidence``) and ``NOT_CHECKED``
    (no evidence text supplied, so nothing was audited; ``issues`` is ``None``,
    not ``[]``). Issues never flip ``ok``/``status``: the guard is regex based
    and can produce false positives, so it informs the reader instead of
    rejecting the report.
    """
    try:
        findings = json.loads(findings_json)
        artifact_hashes = json.loads(artifact_hashes_json or "{}")
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "status": "INVALID_JSON"})
    if not isinstance(findings, list) or not isinstance(artifact_hashes, dict):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    report = render_finding_report(findings, artifact_hashes=artifact_hashes, scope_notes=scope_notes or ())
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
