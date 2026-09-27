"""Static, evidence-bounded relationships across multiple Analysis IRs."""
from __future__ import annotations

from pathlib import PurePath
from typing import Any, Iterable
import json

from analysis_ir import UNKNOWN, AnalysisIR, Evidence, Export, Function, Import, Module, Reference


_AUXILIARY_RELATIONS = frozenset({
    "CONFIG_REFERENCES_MODULE", "LOG_MENTIONS_MODULE", "SOURCE_REFERENCES_MODULE",
})


def _module_key(value: str) -> str:
    name = PurePath(str(value or "").replace("\\", "/")).name.casefold()
    return name[:-4] if name.endswith((".dll", ".sys", ".exe")) else name


def _export_key(node: Export) -> tuple[str, str]:
    if node.name != UNKNOWN:
        return "name", str(node.name).casefold()
    if node.ordinal != UNKNOWN:
        return "ordinal", str(node.ordinal)
    return "unknown", UNKNOWN


def _import_key(node: Import) -> tuple[str, str]:
    if node.name != UNKNOWN:
        return "name", str(node.name).casefold()
    if node.ordinal != UNKNOWN:
        return "ordinal", str(node.ordinal)
    return "unknown", UNKNOWN


def build_cross_binary_relationships(
    irs: Iterable[AnalysisIR],
    *,
    auxiliary_observations: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Match static imports to exports and explicit auxiliary observations.

    Module-level linkage is emitted when one import library/name maps to one
    supplied export.  A function-level edge additionally requires an explicit
    ``IMPORT_CALL`` Reference in the importing IR.  This makes no process-load,
    reachability, execution or runtime-effect claim.
    """
    documents = list(irs)
    modules: dict[str, tuple[AnalysisIR, Module]] = {}
    proven_evidence_ids: set[str] = set()
    exports: dict[tuple[str, str, str], dict[str, Export]] = {}
    for ir in documents:
        proven_evidence_ids.update(node.id for node in ir.nodes("evidence") if isinstance(node, Evidence))
        for module in ir.nodes("module"):
            assert isinstance(module, Module)
            modules[module.id] = (ir, module)
            for node in ir.nodes("export"):
                if isinstance(node, Export) and node.module_id == module.id:
                    kind, value = _export_key(node)
                    exports.setdefault((_module_key(module.name), kind, value), {})[node.id] = node

    relationships: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    ambiguous: list[dict[str, Any]] = []
    import_callers: dict[str, dict[str, set[str]]] = {}
    for ir in documents:
        for node in ir.nodes("reference"):
            if isinstance(node, Reference) and node.reference_kind == "IMPORT_CALL" and node.target_id != UNKNOWN:
                if not isinstance(ir.get(node.source_id), Function) or not isinstance(ir.get(node.target_id), Import):
                    continue
                if not node.evidence_ids or any(value not in proven_evidence_ids for value in node.evidence_ids):
                    continue
                callers = import_callers.setdefault(node.target_id, {})
                callers.setdefault(node.source_id, set()).update(node.evidence_ids)

    for ir in documents:
        for imported in ir.nodes("import"):
            assert isinstance(imported, Import)
            kind, value = _import_key(imported)
            candidate_map = exports.get((_module_key(imported.library), kind, value), {}) if kind != "unknown" else {}
            candidates = [candidate_map[key] for key in sorted(candidate_map)]
            if len(candidates) != 1:
                if candidates:
                    ambiguous.append({"import_id": imported.id, "reason": "AMBIGUOUS_EXPORT", "candidate_ids": sorted(row.id for row in candidates)})
                continue
            exported = candidates[0]
            source_module = modules[imported.module_id][1]
            target_module = modules[exported.module_id][1]
            evidence_ids = tuple(sorted({*imported.evidence_ids, *exported.evidence_ids}))
            if not evidence_ids or any(value not in proven_evidence_ids for value in evidence_ids):
                ambiguous.append({"import_id": imported.id, "reason": "MISSING_IR_EVIDENCE"})
                continue
            module_key = (source_module.id, target_module.id, "STATIC_IMPORT_MATCH", imported.id)
            relationships[module_key] = {
                "source": {"kind": "module", "key": source_module.id, "label": source_module.name},
                "target": {"kind": "module", "key": target_module.id, "label": target_module.name},
                "relation": "IMPORTS",
                "evidence_ids": list(evidence_ids),
                "metadata": {
                    "relationship_class": "STATIC_IMPORT_MATCH", "import_id": imported.id,
                    "export_id": exported.id, "match_kind": kind, "match_value": value,
                    "runtime_behavior_claimed": False,
                },
            }
            if exported.function_id == UNKNOWN:
                continue
            target_ir = modules[exported.module_id][0]
            if not isinstance(target_ir.get(exported.function_id), Function):
                continue
            for caller, reference_evidence in sorted(import_callers.get(imported.id, {}).items()):
                function_key = (caller, exported.function_id, "STATIC_CROSS_MODULE_CALL", imported.id)
                function_evidence_ids = tuple(sorted({*evidence_ids, *reference_evidence}))
                relationships[function_key] = {
                    "source": {"kind": "function", "key": caller},
                    "target": {"kind": "function", "key": exported.function_id},
                    "relation": "CALLS",
                    "evidence_ids": list(function_evidence_ids),
                    "metadata": {
                        "relationship_class": "STATIC_CROSS_MODULE_CALL", "via_import_id": imported.id,
                        "via_export_id": exported.id, "runtime_behavior_claimed": False,
                    },
                }

    rejected: list[dict[str, Any]] = []
    for index, value in enumerate(auxiliary_observations):
        if not isinstance(value, dict):
            rejected.append({"index": index, "reason": "MALFORMED_AUXILIARY_OBSERVATION"})
            continue
        relation_class = str(value.get("relationship_class") or "").upper()
        source_id = str(value.get("source_id") or "").strip()
        target_module_id = str(value.get("target_module_id") or "").strip()
        evidence_ids = tuple(sorted({str(item) for item in value.get("evidence_ids", ()) if str(item)}))
        if relation_class not in _AUXILIARY_RELATIONS:
            rejected.append({"index": index, "reason": "UNSUPPORTED_AUXILIARY_RELATION"})
            continue
        if not source_id or target_module_id not in modules or not evidence_ids:
            rejected.append({"index": index, "reason": "UNPROVEN_AUXILIARY_ENDPOINT"})
            continue
        key = (source_id, target_module_id, relation_class, str(value.get("locator") or ""))
        relationships[key] = {
            "source": {"kind": "file", "key": source_id},
            "target": {"kind": "module", "key": target_module_id, "label": modules[target_module_id][1].name},
            "relation": "REFERENCES",
            "evidence_ids": list(evidence_ids),
            "metadata": {
                "relationship_class": relation_class, "locator": value.get("locator", UNKNOWN),
                "observed_text": value.get("observed_text", UNKNOWN), "runtime_behavior_claimed": False,
            },
        }

    return {
        "schema": "cross-binary-relationships/v1",
        "status": "PARTIAL" if ambiguous or rejected else "PROVEN",
        "relationships": [relationships[key] for key in sorted(relationships)],
        "ambiguous": ambiguous,
        "rejected": rejected,
        "runtime_behavior_claimed": False,
        "limitations": [
            "Static import/export matches do not prove module loading or execution",
            "Function-level edges require an explicit IMPORT_CALL reference",
            "Auxiliary config/log/source links are observations, not runtime effects",
        ],
    }


__all__ = ["build_cross_binary_relationships"]


def cross_binary_relationship_analyze(irs_json: str, auxiliary_observations_json: str = "[]") -> str:
    try:
        payloads = json.loads(irs_json); auxiliary = json.loads(auxiliary_observations_json or "[]")
        irs = [AnalysisIR.from_dict(item) for item in payloads]
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return json.dumps({"ok": False, "status": "INVALID_INPUT", "error_type": type(exc).__name__})
    if not isinstance(payloads, list) or not isinstance(auxiliary, list):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    return json.dumps(build_cross_binary_relationships(irs, auxiliary_observations=auxiliary), ensure_ascii=False, indent=2, sort_keys=True, default=str)


__all__.append("cross_binary_relationship_analyze")
