"""Deterministic native cross-reference resolution for Analysis IR v1.

This module does not disassemble bytes.  It consumes the normalized facts
produced by :mod:`native_function_analysis` (upstream-only; not part of the
published package) -- or any other complete Analysis IR document a caller
supplies -- plus optional, explicitly proven decoder observations, and
resolves only endpoints supported by those facts.  Indirect or ambiguous
targets remain ``UNKNOWN``.  This package itself contains no tool that
extracts an Analysis IR from a binary; see ``analysis_ir.py`` for the node
types (``Artifact``, ``Module``, ``Function``, ``Import``, ...) and the
``AnalysisIR.add()``/``.validate()``/``.to_dict()`` methods a caller uses to
build and serialize one by hand.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable
import json

from liebert_re import strict_json
from liebert_re.recover.analysis_ir import (
    UNKNOWN,
    AnalysisIR,
    Call,
    Evidence,
    Function,
    Import,
    Reference,
    StringLiteral,
    Symbol,
    stable_id,
)


SUPPORTED_REFERENCE_KINDS = frozenset({"IMPORT_CALL", "STRING_REFERENCE", "SYMBOL_REFERENCE"})
_CONFIDENCE_RANK = {UNKNOWN: 0, "HEURISTIC": 1, "METADATA_PROVEN": 2, "SYMBOL_PROVEN": 3}


@dataclass(frozen=True)
class AddressResolution:
    target_id: str = UNKNOWN
    resolution: str = "UNRESOLVED"
    confidence: str = UNKNOWN


def _as_int(value: Any) -> int | None:
    if value is None or value == UNKNOWN or isinstance(value, bool):
        return None
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _bounded_confidence(ir: AnalysisIR, evidence_ids: Iterable[str], endpoint_confidence: str) -> str:
    """A relationship cannot be stronger than its weakest required premise."""
    values = [endpoint_confidence]
    values.extend(
        str(node.claim_status)
        for value in evidence_ids
        if isinstance((node := ir.get(value)), Evidence)
    )
    normalized = [value if value in _CONFIDENCE_RANK else UNKNOWN for value in values]
    return min(normalized, key=lambda value: _CONFIDENCE_RANK[value]) if normalized else UNKNOWN


def resolve_rva_to_function(
    ir: AnalysisIR,
    rva: Any,
    *,
    module_id: str | None = None,
    allow_containing_range: bool = True,
) -> AddressResolution:
    """Resolve an RVA to one unambiguous function.

    An exact start is strongest.  A containing-range result is accepted only
    when exactly one declared range contains the RVA; overlapping metadata is
    surfaced as ambiguous rather than selected heuristically.
    """
    address = _as_int(rva)
    if address is None or address < 0:
        return AddressResolution(resolution="INVALID_RVA")
    rows = [
        node for node in ir.nodes("function")
        if isinstance(node, Function) and (module_id is None or node.module_id == module_id)
    ]
    exact = [node for node in rows if node.start_rva == address]
    if len(exact) == 1:
        return AddressResolution(exact[0].id, "EXACT_FUNCTION_START", exact[0].confidence)
    if len(exact) > 1:
        return AddressResolution(resolution="AMBIGUOUS_EXACT_START")
    if not allow_containing_range:
        return AddressResolution(resolution="NO_EXACT_FUNCTION_START")
    containing = []
    for node in rows:
        end = _as_int(node.end_rva)
        if end is not None and node.start_rva <= address < end:
            containing.append(node)
    if len(containing) == 1:
        node = containing[0]
        return AddressResolution(node.id, "UNIQUE_CONTAINING_RANGE", node.confidence)
    if len(containing) > 1:
        return AddressResolution(resolution="AMBIGUOUS_CONTAINING_RANGE")
    return AddressResolution(resolution="NO_FUNCTION_RANGE")


def resolve_symbol_to_function(ir: AnalysisIR, symbol: Symbol | str) -> AddressResolution:
    node = ir.get(symbol) if isinstance(symbol, str) else symbol
    if not isinstance(node, Symbol):
        return AddressResolution(resolution="SYMBOL_NOT_FOUND")
    if node.function_id != UNKNOWN:
        target = ir.get(node.function_id)
        if isinstance(target, Function):
            return AddressResolution(target.id, "SYMBOL_FUNCTION_LINK", node.confidence)
        return AddressResolution(resolution="INVALID_SYMBOL_FUNCTION_LINK")
    return resolve_rva_to_function(ir, node.rva, module_id=node.module_id)


def _source_function(ir: AnalysisIR, observation: dict[str, Any]) -> AddressResolution:
    explicit = str(observation.get("source_function_id") or "").strip()
    if explicit:
        node = ir.get(explicit)
        return (
            AddressResolution(node.id, "EXPLICIT_FUNCTION_ID", node.confidence)
            if isinstance(node, Function)
            else AddressResolution(resolution="SOURCE_FUNCTION_NOT_FOUND")
        )
    return resolve_rva_to_function(
        ir,
        observation.get("source_rva", observation.get("callsite_rva")),
        module_id=observation.get("module_id"),
    )


def _unique_by_rva(nodes: Iterable[Any], field: str, rva: Any, module_id: str | None) -> list[Any]:
    address = _as_int(rva)
    if address is None:
        return []
    return [
        node for node in nodes
        if _as_int(getattr(node, field, UNKNOWN)) == address
        and (module_id is None or node.module_id == module_id)
    ]


def resolve_native_xrefs(
    ir: AnalysisIR,
    observations: Iterable[dict[str, Any]] = (),
    *,
    include_existing_calls: bool = True,
) -> dict[str, Any]:
    """Resolve normalized decoder observations into calls/references.

    Supported observations are ``CALL``, ``IMPORT_CALL``,
    ``STRING_REFERENCE`` and ``SYMBOL_REFERENCE``.  Each observation should
    carry an evidence ID already present in the IR (or ``evidence_ids``).
    Duplicate observations collapse by stable semantic identity.  Self-calls
    are preserved and labeled; traversal code can then handle cycles without
    losing the edge.
    """
    calls: dict[str, Call] = {}
    references: dict[str, Reference] = {}
    rejected: list[dict[str, Any]] = []

    if include_existing_calls:
        for node in ir.nodes("call"):
            assert isinstance(node, Call)
            if not node.evidence_ids or any(not isinstance(ir.get(value), Evidence) for value in node.evidence_ids):
                rejected.append({"index": None, "reason": "UNPROVEN_EXISTING_CALL", "id": node.id})
                continue
            resolution = node.resolution
            target_id = node.target_function_id
            confidence = node.confidence
            if target_id == UNKNOWN and node.target_rva != UNKNOWN and "INDIRECT" not in str(resolution):
                source = ir.get(node.source_function_id)
                module = source.module_id if isinstance(source, Function) else None
                resolved = resolve_rva_to_function(ir, node.target_rva, module_id=module)
                target_id, resolution = resolved.target_id, resolved.resolution
                confidence = _bounded_confidence(ir, node.evidence_ids, resolved.confidence)
            calls[node.id] = Call(
                id=node.id,
                source_function_id=node.source_function_id,
                target_function_id=target_id,
                callsite_rva=node.callsite_rva,
                target_rva=node.target_rva,
                resolution=resolution,
                confidence=confidence,
                evidence_ids=node.evidence_ids,
                raw_provenance={
                    **node.raw_provenance,
                    "resolver": "native_xref/v1",
                    "cycle_candidate": target_id != UNKNOWN and target_id == node.source_function_id,
                },
                metadata=node.metadata,
            )

    for index, raw in enumerate(observations):
        if not isinstance(raw, dict):
            rejected.append({"index": index, "reason": "MALFORMED_OBSERVATION"})
            continue
        row = dict(raw)
        kind = str(row.get("kind") or row.get("reference_kind") or "").upper()
        source = _source_function(ir, row)
        if source.target_id == UNKNOWN:
            rejected.append({"index": index, "reason": source.resolution})
            continue
        callsite = _as_int(row.get("callsite_rva", row.get("source_rva")))
        if callsite is None:
            rejected.append({"index": index, "reason": "MISSING_SOURCE_RVA"})
            continue
        evidence_ids = tuple(sorted({str(value) for value in row.get("evidence_ids", ()) if str(value)}))
        if row.get("evidence_id"):
            evidence_ids = tuple(sorted({*evidence_ids, str(row["evidence_id"])}))
        missing_evidence = [value for value in evidence_ids if not isinstance(ir.get(value), Evidence)]
        if not evidence_ids or missing_evidence:
            rejected.append({"index": index, "reason": "MISSING_EVIDENCE", "evidence_ids": missing_evidence})
            continue
        provenance = {
            "resolver": "native_xref/v1",
            "observation_locator": row.get("locator", UNKNOWN),
            "decoder": row.get("decoder", UNKNOWN),
            "operand": row.get("operand", UNKNOWN),
        }

        if kind == "CALL":
            target_rva = _as_int(row.get("target_rva"))
            indirect = bool(row.get("indirect")) or target_rva is None
            target = AddressResolution(resolution="INDIRECT_UNRESOLVED") if indirect else resolve_rva_to_function(
                ir, target_rva, module_id=row.get("target_module_id") or ir.get(source.target_id).module_id,
            )
            identity = (source.target_id, callsite, target_rva if target_rva is not None else UNKNOWN)
            call = Call(
                id=stable_id("call", *identity),
                source_function_id=source.target_id,
                target_function_id=target.target_id,
                callsite_rva=callsite,
                target_rva=target_rva if not indirect else UNKNOWN,
                resolution=target.resolution,
                confidence=_bounded_confidence(ir, evidence_ids, target.confidence),
                evidence_ids=evidence_ids,
                raw_provenance={
                    **provenance,
                    "indirect_target_not_inferred": indirect,
                    "cycle_candidate": target.target_id == source.target_id and target.target_id != UNKNOWN,
                },
            )
            previous = calls.get(call.id)
            if previous is not None and previous != call:
                rejected.append({"index": index, "reason": "DUPLICATE_CALL_CONFLICT", "id": call.id})
            else:
                calls[call.id] = call
            continue

        if kind not in SUPPORTED_REFERENCE_KINDS:
            rejected.append({"index": index, "reason": "UNSUPPORTED_REFERENCE_KIND", "kind": kind})
            continue
        candidates: list[Any]
        if kind == "IMPORT_CALL":
            candidates = _unique_by_rva(ir.nodes("import"), "iat_rva", row.get("iat_rva", row.get("target_rva")), row.get("target_module_id"))
        elif kind == "STRING_REFERENCE":
            candidates = _unique_by_rva(ir.nodes("string_literal"), "rva", row.get("string_rva", row.get("target_rva")), row.get("target_module_id"))
        else:
            symbol_id = str(row.get("symbol_id") or "")
            candidates = [ir.get(symbol_id)] if symbol_id else _unique_by_rva(ir.nodes("symbol"), "rva", row.get("symbol_rva", row.get("target_rva")), row.get("target_module_id"))
            candidates = [item for item in candidates if isinstance(item, Symbol)]
        target_id = candidates[0].id if len(candidates) == 1 else UNKNOWN
        resolution = "EXACT_UNIQUE_TARGET" if target_id != UNKNOWN else "AMBIGUOUS_TARGET" if candidates else "TARGET_NOT_FOUND"
        target_rva = _as_int(row.get("target_rva", row.get("iat_rva", row.get("string_rva", row.get("symbol_rva")))))
        target_rva_value = target_rva if target_rva is not None else UNKNOWN
        reference = Reference(
            id=stable_id("reference", kind, source.target_id, callsite, target_rva_value),
            source_id=source.target_id,
            target_id=target_id,
            reference_kind=kind,
            source_rva=callsite,
            target_rva=target_rva_value,
            confidence=_bounded_confidence(ir, evidence_ids, "METADATA_PROVEN") if target_id != UNKNOWN else UNKNOWN,
            evidence_ids=evidence_ids,
            raw_provenance={**provenance, "resolution": resolution, "ambiguous_candidate_count": len(candidates)},
        )
        previous = references.get(reference.id)
        if previous is not None and previous != reference:
            rejected.append({"index": index, "reason": "DUPLICATE_REFERENCE_CONFLICT", "id": reference.id})
        else:
            references[reference.id] = reference

    call_rows = sorted(calls.values(), key=lambda item: item.id)
    reference_rows = sorted(references.values(), key=lambda item: item.id)
    import_callers: dict[str, set[str]] = defaultdict(set)
    string_referrers: dict[str, set[str]] = defaultdict(set)
    for row in reference_rows:
        if row.target_id == UNKNOWN:
            continue
        if row.reference_kind == "IMPORT_CALL":
            import_callers[row.target_id].add(row.source_id)
        elif row.reference_kind == "STRING_REFERENCE":
            string_referrers[row.target_id].add(row.source_id)
    return {
        "schema": "native-xref/v1",
        "status": "PARTIAL" if (
            rejected
            or any(row.target_function_id == UNKNOWN for row in call_rows)
            or any(row.target_id == UNKNOWN for row in reference_rows)
        ) else "PROVEN",
        "calls": [row.to_dict() for row in call_rows],
        "references": [row.to_dict() for row in reference_rows],
        "import_callers": {key: sorted(value) for key, value in sorted(import_callers.items())},
        "string_referrers": {key: sorted(value) for key, value in sorted(string_referrers.items())},
        "rejected": rejected,
        "limitations": ["Indirect targets remain UNKNOWN", "Ambiguous ranges and duplicate targets are not guessed"],
        "runtime_behavior_claimed": False,
    }


def analysis_ir_graph_relationships(
    ir: AnalysisIR,
    xref_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Adapt proven Analysis IR CALLS/REFERENCES facts for ResearchGraph ingestion.

    ``xref_report`` may be the direct result of :func:`resolve_native_xrefs`;
    this avoids mutating the caller-owned IR merely to persist graph edges.
    """
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    call_values = [node.to_dict() for node in ir.nodes("call")]
    reference_values = [node.to_dict() for node in ir.nodes("reference")]
    if xref_report:
        call_values.extend(item for item in xref_report.get("calls", ()) if isinstance(item, dict))
        reference_values.extend(item for item in xref_report.get("references", ()) if isinstance(item, dict))
    for node in call_values:
        if node.get("target_function_id") == UNKNOWN:
            continue
        if not isinstance(ir.get(str(node.get("source_function_id"))), Function) or not isinstance(ir.get(str(node.get("target_function_id"))), Function):
            continue
        key = (str(node["source_function_id"]), str(node["target_function_id"]), "CALLS")
        rows[key] = {
            "source": {"kind": "function", "key": node["source_function_id"]},
            "target": {"kind": "function", "key": node["target_function_id"]},
            "relation": "CALLS",
            "metadata": {
                "callsite_rva": node.get("callsite_rva", UNKNOWN), "resolution": node.get("resolution", UNKNOWN),
                "ir_node_id": node["id"], "ir_evidence_ids": node.get("evidence_ids", []),
            },
        }
    for node in reference_values:
        if node.get("target_id") == UNKNOWN or not isinstance(ir.get(str(node.get("source_id"))), Function):
            continue
        target = ir.get(str(node["target_id"]))
        if target is None:
            continue
        target_kind = "symbol" if isinstance(target, (Import, StringLiteral, Symbol)) else target.kind
        key = (str(node["source_id"]), str(node["target_id"]), "REFERENCES")
        rows[key] = {
            "source": {"kind": "function", "key": node["source_id"]},
            "target": {"kind": target_kind, "key": node["target_id"], "metadata": {"ir_kind": target.kind}},
            "relation": "REFERENCES",
            "metadata": {
                "reference_kind": node.get("reference_kind", UNKNOWN), "source_rva": node.get("source_rva", UNKNOWN),
                "ir_node_id": node["id"], "ir_evidence_ids": node.get("evidence_ids", []),
            },
        }
    return [rows[key] for key in sorted(rows)]


__all__ = [
    "AddressResolution", "SUPPORTED_REFERENCE_KINDS", "resolve_rva_to_function",
    "resolve_symbol_to_function", "resolve_native_xrefs", "analysis_ir_graph_relationships",
]


def native_xref_analyze(ir_json: str, observations_json: str, max_observations: int = 5000) -> str:
    try:
        ir = AnalysisIR.from_dict(strict_json.loads(ir_json))
        observations = strict_json.loads(observations_json)
    except (ValueError, TypeError) as exc:
        body = {"ok": False, "status": "INVALID_INPUT", "error_type": type(exc).__name__}
        if isinstance(exc, strict_json.StrictJSONError):
            body["reason"] = exc.reason
        return json.dumps(body)
    if not isinstance(observations, list):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    limit = max(1, min(int(max_observations), 20_000))
    report = resolve_native_xrefs(ir, observations[:limit])
    not_examined = max(0, len(observations) - limit)
    report["observations_received"] = len(observations)
    report["observations_examined"] = len(observations) - not_examined
    report["observations_not_examined"] = not_examined
    report["observations_truncated"] = not_examined > 0
    report["limit_reached"] = "max_observations" if not_examined else None
    if not_examined:
        # A claim over a subset of the observations is not proven for the rest.
        report["status"] = "PARTIAL"
        report["limitations"] = [*report["limitations"],
                                 f"{not_examined} observation(s) beyond max_observations={limit} were not examined"]
    report["ir"] = ir.to_dict()
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str)


__all__.append("native_xref_analyze")
