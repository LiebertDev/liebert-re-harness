"""Bounded semantic diff for two authorized local Analysis IR dictionaries.

The matcher deliberately never treats RVA equality as cross-version identity.
It prefers unique semantic names, then exact structural fingerprints, and only
then a conservative feature-similarity match.  It does not read or execute raw
binaries.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from typing import Any, Iterable

from analysis_ir import UNKNOWN, stable_id


SCHEMA_VERSION = "binary-version-diff/v1"
SUPPORTED_IR_SCHEMA = "analysis-ir/v1"


def _rows(ir: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    entities = ir.get("entities") if isinstance(ir, dict) else None
    value = entities.get(kind, []) if isinstance(entities, dict) else []
    return [row for row in value if isinstance(row, dict) and row.get("id")]


def _unknown(value: Any) -> bool:
    return value in (None, "", UNKNOWN)


def _name(row: dict[str, Any]) -> str:
    for key in ("qualified_name", "demangled_name", "name"):
        if not _unknown(row.get(key)):
            return str(row[key]).strip()
    aliases = [str(value).strip() for value in row.get("aliases", []) if not _unknown(value)]
    return sorted(aliases, key=str.casefold)[0] if aliases else UNKNOWN


def _semantic_name(row: dict[str, Any]) -> str:
    name = _name(row)
    if name == UNKNOWN:
        return UNKNOWN
    module = row.get("module_name") or row.get("metadata", {}).get("module_name")
    return f"{module}!{name}".casefold() if not _unknown(module) else name.casefold()


def _sha(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _string_label(row: dict[str, Any]) -> str:
    value = str(row.get("value", UNKNOWN))
    if value == UNKNOWN:
        return UNKNOWN
    return f"sha256:{hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()}"


def _import_label(row: dict[str, Any]) -> str:
    library = row.get("library", UNKNOWN)
    name = row.get("name", UNKNOWN)
    ordinal = row.get("ordinal", UNKNOWN)
    symbol = name if not _unknown(name) else f"ordinal:{ordinal}" if not _unknown(ordinal) else UNKNOWN
    return f"{library}!{symbol}".casefold()


def _normalized_instruction(instruction: Any) -> str:
    if not isinstance(instruction, dict):
        return str(instruction).strip().casefold()[:128]
    mnemonic = str(instruction.get("mnemonic", instruction.get("opcode", UNKNOWN))).casefold()
    operand_kind = instruction.get("operand_kind", instruction.get("kind", UNKNOWN))
    # Raw immediates/addresses are intentionally excluded: they are unstable
    # across links and cannot establish cross-version identity.
    return f"{mnemonic}:{str(operand_kind).casefold()}"


def _sensitive_paths(row: dict[str, Any]) -> set[str]:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    values: list[Any] = []
    for source in (row, metadata):
        for key in ("sensitive_paths", "security_flows", "flows", "sinks", "security_events"):
            candidate = source.get(key)
            if isinstance(candidate, list):
                values.extend(candidate)
    output = set()
    for value in values:
        if isinstance(value, dict):
            normalized = {
                key: value[key]
                for key in sorted(value)
                if key not in {"rva", "address", "offset", "line", "id", "event_id"}
            }
            output.add(_sha(normalized))
        elif not _unknown(value):
            output.add(str(value)[:512])
    return output


class _IRView:
    def __init__(self, ir: dict[str, Any]) -> None:
        self.ir = ir
        self.by_id = {
            row["id"]: row
            for kind in ("artifact", "module", "function", "basic_block", "import", "string_literal", "reference", "call")
            for row in _rows(ir, kind)
        }
        self.functions = {row["id"]: row for row in _rows(ir, "function")}
        self.blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in _rows(ir, "basic_block"):
            if row.get("function_id") in self.functions:
                self.blocks[row["function_id"]].append(row)
        self.calls: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in _rows(ir, "call"):
            if row.get("source_function_id") in self.functions:
                self.calls[row["source_function_id"]].append(row)
        self.references: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in _rows(ir, "reference"):
            source_id = row.get("source_id")
            if source_id in self.functions:
                self.references[source_id].append(row)
            else:
                block = self.by_id.get(source_id)
                if block and block.get("function_id") in self.functions:
                    self.references[block["function_id"]].append(row)

    def call_labels(self, function_id: str) -> set[str]:
        labels = set()
        for call in self.calls.get(function_id, []):
            target = self.functions.get(call.get("target_function_id"))
            if target:
                labels.add(_semantic_name(target))
            else:
                resolution = call.get("resolution", UNKNOWN)
                labels.add(f"unresolved:{resolution}".casefold())
        return labels

    def import_labels(self, function_id: str) -> set[str]:
        labels = set()
        for ref in self.references.get(function_id, []):
            target = self.by_id.get(ref.get("target_id"))
            if target and target.get("kind") == "import":
                labels.add(_import_label(target))
        return labels

    def string_labels(self, function_id: str) -> set[str]:
        labels = set()
        for ref in self.references.get(function_id, []):
            target = self.by_id.get(ref.get("target_id"))
            if target and target.get("kind") == "string_literal":
                labels.add(_string_label(target))
        return labels

    def cfg_signature(self, function_id: str) -> dict[str, Any]:
        blocks = self.blocks.get(function_id, [])
        normalized = []
        edge_count = 0
        for block in blocks:
            metadata = block.get("metadata") if isinstance(block.get("metadata"), dict) else {}
            successors = metadata.get("successors", block.get("successors", []))
            edge_count += len(successors) if isinstance(successors, list) else 0
            normalized.append({
                "instructions": [_normalized_instruction(item) for item in block.get("instructions", [])],
                "successor_count": len(successors) if isinstance(successors, list) else UNKNOWN,
            })
        normalized.sort(key=lambda row: json.dumps(row, sort_keys=True, default=str))
        return {"block_count": len(blocks), "edge_count": edge_count, "shape_sha256": _sha(normalized)}

    def features(self, function_id: str) -> dict[str, Any]:
        row = self.functions[function_id]
        start = row.get("start_rva")
        end = row.get("end_rva")
        size = end - start if isinstance(start, int) and isinstance(end, int) and end >= start else UNKNOWN
        cfg = self.cfg_signature(function_id)
        return {
            "name": _semantic_name(row),
            "calls": sorted(self.call_labels(function_id)),
            "imports": sorted(self.import_labels(function_id)),
            "strings": sorted(self.string_labels(function_id)),
            "cfg": cfg,
            "sensitive_paths": sorted(_sensitive_paths(row)),
            "size": size,
        }


def _fingerprint(features: dict[str, Any]) -> str | None:
    structural = {
        "calls": features["calls"], "imports": features["imports"],
        "strings": features["strings"], "cfg": features["cfg"],
        "sensitive_paths": features["sensitive_paths"], "size": features["size"],
    }
    has_signal = any((features["calls"], features["imports"], features["strings"], features["sensitive_paths"]))
    has_signal = has_signal or features["cfg"]["block_count"] > 0 or features["size"] != UNKNOWN
    return _sha(structural) if has_signal else None


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float | None:
    a, b = set(left), set(right)
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def _similarity(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    evidence = []
    weighted = []
    for key, weight in (("calls", 0.25), ("imports", 0.25), ("strings", 0.15), ("sensitive_paths", 0.15)):
        value = _jaccard(left[key], right[key])
        if value is not None:
            weighted.append((value, weight))
            evidence.append({"feature": key, "similarity": round(value, 6)})
    if left["cfg"]["block_count"] or right["cfg"]["block_count"]:
        same = float(left["cfg"]["shape_sha256"] == right["cfg"]["shape_sha256"])
        weighted.append((same, 0.15))
        evidence.append({"feature": "cfg", "similarity": same})
    if left["size"] != UNKNOWN and right["size"] != UNKNOWN:
        maximum = max(1, left["size"], right["size"])
        value = max(0.0, 1.0 - abs(left["size"] - right["size"]) / maximum)
        weighted.append((value, 0.05))
        evidence.append({"feature": "size", "similarity": round(value, 6)})
    denominator = sum(weight for _, weight in weighted)
    return (sum(value * weight for value, weight in weighted) / denominator if denominator else 0.0), evidence


def _match_functions(old: _IRView, new: _IRView) -> list[dict[str, Any]]:
    remaining_old = set(old.functions)
    remaining_new = set(new.functions)
    matches: list[dict[str, Any]] = []

    def accept(old_id: str, new_id: str, strategy: str, confidence: str, evidence: Any) -> None:
        remaining_old.discard(old_id)
        remaining_new.discard(new_id)
        matches.append({
            "old_function_id": old_id, "new_function_id": new_id,
            "strategy": strategy, "confidence": confidence, "evidence": evidence,
            "rva_equality_not_used": old.functions[old_id].get("start_rva") == new.functions[new_id].get("start_rva"),
        })

    old_names: dict[str, list[str]] = defaultdict(list)
    new_names: dict[str, list[str]] = defaultdict(list)
    for function_id in remaining_old:
        name = _semantic_name(old.functions[function_id])
        if name != UNKNOWN:
            old_names[name].append(function_id)
    for function_id in remaining_new:
        name = _semantic_name(new.functions[function_id])
        if name != UNKNOWN:
            new_names[name].append(function_id)
    for name in sorted(set(old_names) & set(new_names)):
        if len(old_names[name]) == len(new_names[name]) == 1:
            old_id, new_id = old_names[name][0], new_names[name][0]
            confidence = "SYMBOL_PROVEN" if all(
                view.functions[node_id].get("confidence") == "SYMBOL_PROVEN"
                for view, node_id in ((old, old_id), (new, new_id))
            ) else "METADATA_PROVEN"
            accept(old_id, new_id, "UNIQUE_SEMANTIC_NAME", confidence, {"semantic_name": name})

    old_features = {function_id: old.features(function_id) for function_id in remaining_old}
    new_features = {function_id: new.features(function_id) for function_id in remaining_new}
    old_fp: dict[str, list[str]] = defaultdict(list)
    new_fp: dict[str, list[str]] = defaultdict(list)
    for function_id, features in old_features.items():
        fingerprint = _fingerprint(features)
        if fingerprint:
            old_fp[fingerprint].append(function_id)
    for function_id, features in new_features.items():
        fingerprint = _fingerprint(features)
        if fingerprint:
            new_fp[fingerprint].append(function_id)
    for fingerprint in sorted(set(old_fp) & set(new_fp)):
        if len(old_fp[fingerprint]) == len(new_fp[fingerprint]) == 1:
            accept(old_fp[fingerprint][0], new_fp[fingerprint][0], "UNIQUE_STRUCTURAL_FINGERPRINT", "METADATA_PROVEN", {"sha256": fingerprint})

    candidates = []
    for old_id in sorted(remaining_old):
        for new_id in sorted(remaining_new):
            score, evidence = _similarity(old.features(old_id), new.features(new_id))
            # Require at least two independently observed feature categories.
            if score >= 0.72 and len(evidence) >= 2:
                candidates.append((-score, old_id, new_id, evidence))
    for negative_score, old_id, new_id, evidence in sorted(candidates):
        if old_id in remaining_old and new_id in remaining_new:
            accept(old_id, new_id, "BOUNDED_FEATURE_SIMILARITY", "HEURISTIC", {"score": round(-negative_score, 6), "features": evidence})
    return sorted(matches, key=lambda row: (row["old_function_id"], row["new_function_id"]))


def _set_delta(old_values: Iterable[str], new_values: Iterable[str]) -> dict[str, list[str]]:
    old_set, new_set = set(old_values), set(new_values)
    return {"added": sorted(new_set - old_set), "removed": sorted(old_set - new_set)}


def diff_analysis_ir(
    old_ir: dict[str, Any],
    new_ir: dict[str, Any],
    *,
    max_functions: int = 20_000,
    max_changes: int = 50_000,
) -> dict[str, Any]:
    """Compare two Analysis IR dictionaries without touching raw artifacts."""
    if not isinstance(old_ir, dict) or not isinstance(new_ir, dict):
        return {"ok": False, "status": "INVALID_INPUT", "schema": SCHEMA_VERSION, "error": "TWO_IR_DICTIONARIES_REQUIRED"}
    if old_ir.get("schema") != SUPPORTED_IR_SCHEMA or new_ir.get("schema") != SUPPORTED_IR_SCHEMA:
        return {"ok": False, "status": "UNSUPPORTED_SCHEMA", "schema": SCHEMA_VERSION, "error": "ANALYSIS_IR_V1_REQUIRED"}
    max_functions = max(1, min(int(max_functions), 100_000))
    max_changes = max(1, min(int(max_changes), 250_000))
    if len(_rows(old_ir, "function")) > max_functions or len(_rows(new_ir, "function")) > max_functions:
        return {
            "ok": False, "status": "ANALYSIS_LIMITED", "schema": SCHEMA_VERSION,
            "error": "FUNCTION_LIMIT_EXCEEDED", "maximum": max_functions,
        }
    old, new = _IRView(old_ir), _IRView(new_ir)
    matches = _match_functions(old, new)
    matched_old = {row["old_function_id"] for row in matches}
    matched_new = {row["new_function_id"] for row in matches}
    changes = []
    for match in matches:
        old_id, new_id = match["old_function_id"], match["new_function_id"]
        old_features, new_features = old.features(old_id), new.features(new_id)
        dimensions = {
            "imports": _set_delta(old_features["imports"], new_features["imports"]),
            "strings": _set_delta(old_features["strings"], new_features["strings"]),
            "calls": _set_delta(old_features["calls"], new_features["calls"]),
            "sensitive_paths": _set_delta(old_features["sensitive_paths"], new_features["sensitive_paths"]),
            "cfg": {
                "changed": old_features["cfg"] != new_features["cfg"],
                "before": old_features["cfg"], "after": new_features["cfg"],
            },
        }
        if any(value["added"] or value["removed"] for key, value in dimensions.items() if key != "cfg") or dimensions["cfg"]["changed"]:
            changes.append({
                "id": stable_id("binary-function-change", old_id, new_id, dimensions),
                "kind": "FUNCTION_CHANGED", "old_function_id": old_id, "new_function_id": new_id,
                "old_name": _name(old.functions[old_id]), "new_name": _name(new.functions[new_id]),
                "match_confidence": match["confidence"], "match_strategy": match["strategy"],
                "dimensions": dimensions,
                "evidence": {
                    "old_ir_entity_id": old_id, "new_ir_entity_id": new_id,
                    "old_features_sha256": _sha(old_features), "new_features_sha256": _sha(new_features),
                },
                "provenance": {"source": "ANALYSIS_IR_V1", "raw_binary_execution": False},
            })
    changes.sort(key=lambda row: row["id"])
    truncated = len(changes) > max_changes
    changes = changes[:max_changes]
    added_ids = sorted(set(new.functions) - matched_new)
    removed_ids = sorted(set(old.functions) - matched_old)
    old_imports = {_import_label(row) for row in _rows(old_ir, "import")}
    new_imports = {_import_label(row) for row in _rows(new_ir, "import")}
    return {
        "ok": True,
        "status": "PARTIAL" if truncated else "COMPLETE",
        "schema": SCHEMA_VERSION,
        "analysis_scope": "STATIC_ANALYSIS_IR_DIFF",
        "old_artifact_ids": sorted(row["id"] for row in _rows(old_ir, "artifact")),
        "new_artifact_ids": sorted(row["id"] for row in _rows(new_ir, "artifact")),
        "function_matches": matches,
        "added_functions": [
            {"function_id": function_id, "name": _name(new.functions[function_id]), "evidence": {"new_ir_entity_id": function_id}}
            for function_id in added_ids
        ],
        "removed_functions": [
            {"function_id": function_id, "name": _name(old.functions[function_id]), "evidence": {"old_ir_entity_id": function_id}}
            for function_id in removed_ids
        ],
        "function_changes": changes,
        "artifact_import_changes": _set_delta(old_imports, new_imports),
        "counts": {
            "matched_functions": len(matches), "added_functions": len(added_ids),
            "removed_functions": len(removed_ids), "changed_functions": len(changes),
        },
        "truncated": truncated,
        "execution_performed": False,
        "identity_policy": "RVA_EQUALITY_NEVER_USED_AS_SOLE_CROSS_VERSION_IDENTITY",
        "limitations": [
            "Diff quality is bounded by facts already present in Analysis IR.",
            "HEURISTIC matches are review leads, not proof of semantic identity.",
            "String values are represented by hashes to avoid copying embedded secrets into reports.",
        ],
    }


def binary_version_diff(old_ir_json: str, new_ir_json: str, max_changes: int = 5000) -> str:
    try:
        old_ir = json.loads(old_ir_json); new_ir = json.loads(new_ir_json)
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "status": "INVALID_JSON"})
    return json.dumps(diff_analysis_ir(old_ir, new_ir, max_changes=max_changes), ensure_ascii=False, indent=2, sort_keys=True, default=str)


__all__ = ["SCHEMA_VERSION", "diff_analysis_ir", "binary_version_diff"]
