"""Model-independent, deterministic Analysis IR v1.

The IR is deliberately smaller than any decompiler-specific schema.  It keeps
facts, unresolved facts and their evidence separate, so downstream agents do
not have to infer certainty from missing JSON keys.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
import hashlib
import json
from typing import Any, ClassVar, Iterable


SCHEMA_VERSION = "analysis-ir/v1"
UNKNOWN = "UNKNOWN"
CONFIDENCE_LEVELS = frozenset({"SYMBOL_PROVEN", "METADATA_PROVEN", "HEURISTIC", UNKNOWN})


def _canonical(value: Any) -> Any:
    """Return a JSON-safe value with deterministic mapping order."""
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, set):
        return sorted((_canonical(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    return value


def stable_id(kind: str, *identity_parts: object) -> str:
    """Build an opaque stable ID from semantic identity, never display text."""
    payload = json.dumps(
        [str(kind).strip().lower(), *[_canonical(part) for part in identity_parts]],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:24]
    prefix = "".join(ch for ch in str(kind).lower() if ch.isalnum())[:12] or "entity"
    return f"{prefix}:{digest}"


def artifact_id(sha256: str) -> str:
    return stable_id("artifact", str(sha256).lower())


def module_id(artifact_sha256: str, module_name: str = "primary") -> str:
    return stable_id("module", str(artifact_sha256).lower(), module_name)


def function_id(artifact_sha256: str, start_rva: int) -> str:
    """Canonical function identity required by v1: artifact SHA-256 + RVA."""
    return stable_id("function", str(artifact_sha256).lower(), f"rva:{int(start_rva):x}")


@dataclass(frozen=True, kw_only=True)
class IRNode:
    kind: ClassVar[str] = "node"
    id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["kind"] = self.kind
        return _canonical(value)


@dataclass(frozen=True, kw_only=True)
class Artifact(IRNode):
    kind: ClassVar[str] = "artifact"
    sha256: str
    path: str = UNKNOWN
    format: str = UNKNOWN
    size_bytes: int | str = UNKNOWN


@dataclass(frozen=True, kw_only=True)
class Module(IRNode):
    kind: ClassVar[str] = "module"
    artifact_id: str
    name: str = UNKNOWN
    architecture: str = UNKNOWN
    image_base: int | str = UNKNOWN


@dataclass(frozen=True, kw_only=True)
class Section(IRNode):
    kind: ClassVar[str] = "section"
    module_id: str
    name: str = UNKNOWN
    start_rva: int | str = UNKNOWN
    virtual_size: int | str = UNKNOWN
    raw_offset: int | str = UNKNOWN
    raw_size: int | str = UNKNOWN
    characteristics: int | str = UNKNOWN


@dataclass(frozen=True, kw_only=True)
class Function(IRNode):
    kind: ClassVar[str] = "function"
    module_id: str
    start_rva: int
    end_rva: int | str = UNKNOWN
    name: str = UNKNOWN
    aliases: tuple[str, ...] = ()
    discovery_sources: tuple[str, ...] = ()
    confidence: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class BasicBlock(IRNode):
    kind: ClassVar[str] = "basic_block"
    function_id: str
    start_rva: int
    end_rva: int | str = UNKNOWN
    instructions: tuple[dict[str, Any], ...] = ()
    confidence: str = UNKNOWN


@dataclass(frozen=True, kw_only=True)
class Symbol(IRNode):
    kind: ClassVar[str] = "symbol"
    module_id: str
    name: str
    rva: int | str = UNKNOWN
    function_id: str = UNKNOWN
    symbol_kind: str = UNKNOWN
    confidence: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Import(IRNode):
    kind: ClassVar[str] = "import"
    module_id: str
    library: str
    name: str = UNKNOWN
    ordinal: int | str = UNKNOWN
    iat_rva: int | str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Export(IRNode):
    kind: ClassVar[str] = "export"
    module_id: str
    name: str = UNKNOWN
    ordinal: int | str = UNKNOWN
    rva: int | str = UNKNOWN
    function_id: str = UNKNOWN
    forwarder: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class StringLiteral(IRNode):
    kind: ClassVar[str] = "string_literal"
    module_id: str
    rva: int
    value: str
    encoding: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Reference(IRNode):
    kind: ClassVar[str] = "reference"
    source_id: str
    target_id: str = UNKNOWN
    reference_kind: str = UNKNOWN
    source_rva: int | str = UNKNOWN
    target_rva: int | str = UNKNOWN
    confidence: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()
    raw_provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Call(IRNode):
    kind: ClassVar[str] = "call"
    source_function_id: str
    target_function_id: str = UNKNOWN
    callsite_rva: int | str = UNKNOWN
    target_rva: int | str = UNKNOWN
    resolution: str = UNKNOWN
    confidence: str = UNKNOWN
    evidence_ids: tuple[str, ...] = ()
    raw_provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class Evidence(IRNode):
    kind: ClassVar[str] = "evidence"
    artifact_id: str
    source: str
    claim_status: str = UNKNOWN
    raw_provenance: dict[str, Any] = field(default_factory=dict)


ENTITY_CLASSES = {
    cls.kind: cls
    for cls in (
        Artifact, Module, Section, Function, BasicBlock, Symbol, Import, Export,
        StringLiteral, Reference, Call, Evidence,
    )
}


class AnalysisIRValidationError(ValueError):
    def __init__(self, errors: Iterable[str]):
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


class AnalysisIR:
    """Small entity graph with deterministic serialization and strict links."""

    def __init__(self, nodes: Iterable[IRNode] = ()) -> None:
        self._nodes: dict[str, IRNode] = {}
        for node in nodes:
            self.add(node)

    @classmethod
    def from_dict(cls, payload: dict[str, Any], *, validate: bool = True) -> "AnalysisIR":
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA_VERSION:
            raise AnalysisIRValidationError(["unsupported or missing Analysis IR schema"])
        entities = payload.get("entities")
        if not isinstance(entities, dict):
            raise AnalysisIRValidationError(["Analysis IR entities must be an object"])
        nodes = []
        for kind in sorted(entities):
            node_class = ENTITY_CLASSES.get(kind)
            if node_class is None:
                raise AnalysisIRValidationError([f"unsupported entity kind: {kind}"])
            rows = entities[kind]
            if not isinstance(rows, list):
                raise AnalysisIRValidationError([f"entity group must be a list: {kind}"])
            allowed = set(node_class.__dataclass_fields__) - {"kind"}
            for row in rows:
                if not isinstance(row, dict) or set(row) - (allowed | {"kind"}):
                    raise AnalysisIRValidationError([f"invalid fields for {kind}"])
                values = {key: value for key, value in row.items() if key != "kind"}
                for key in ("aliases", "discovery_sources", "evidence_ids", "instructions"):
                    if key in values and isinstance(values[key], list):
                        values[key] = tuple(values[key])
                nodes.append(node_class(**values))
        output = cls(nodes)
        if validate:
            output.validate()
        return output

    def add(self, node: IRNode) -> IRNode:
        if not isinstance(node, IRNode):
            raise TypeError("AnalysisIR accepts IRNode instances only")
        previous = self._nodes.get(node.id)
        if previous is not None and previous != node:
            raise AnalysisIRValidationError([f"duplicate id with different content: {node.id}"])
        self._nodes[node.id] = node
        return node

    def get(self, node_id: str) -> IRNode | None:
        return self._nodes.get(node_id)

    def nodes(self, kind: str | None = None) -> tuple[IRNode, ...]:
        values = self._nodes.values()
        if kind is not None:
            values = (node for node in values if node.kind == kind)
        return tuple(sorted(values, key=lambda node: (node.kind, node.id)))

    def validate(self, *, raise_on_error: bool = True) -> list[str]:
        errors: list[str] = []

        def require(node: IRNode, field_name: str, expected_kind: str, *, allow_unknown: bool = False) -> None:
            endpoint = getattr(node, field_name)
            if endpoint == UNKNOWN and allow_unknown:
                return
            target = self._nodes.get(endpoint)
            if target is None:
                errors.append(f"{node.id}.{field_name} references missing endpoint {endpoint}")
            elif target.kind != expected_kind:
                errors.append(f"{node.id}.{field_name} expected {expected_kind}, got {target.kind}")

        for node in self._nodes.values():
            if not node.id or node.id == UNKNOWN:
                errors.append(f"{node.kind} has invalid id")
            if isinstance(node, Module):
                require(node, "artifact_id", "artifact")
            elif isinstance(node, Section):
                require(node, "module_id", "module")
            elif isinstance(node, Function):
                require(node, "module_id", "module")
            elif isinstance(node, BasicBlock):
                require(node, "function_id", "function")
            elif isinstance(node, (Symbol, Import, Export, StringLiteral)):
                require(node, "module_id", "module")
                if isinstance(node, (Symbol, Export)):
                    require(node, "function_id", "function", allow_unknown=True)
            elif isinstance(node, Reference):
                if node.source_id not in self._nodes:
                    errors.append(f"{node.id}.source_id references missing endpoint {node.source_id}")
                if node.target_id != UNKNOWN and node.target_id not in self._nodes:
                    errors.append(f"{node.id}.target_id references missing endpoint {node.target_id}")
            elif isinstance(node, Call):
                require(node, "source_function_id", "function")
                require(node, "target_function_id", "function", allow_unknown=True)
            elif isinstance(node, Evidence):
                require(node, "artifact_id", "artifact")

            confidence = getattr(node, "confidence", None)
            if confidence is not None and confidence not in CONFIDENCE_LEVELS:
                errors.append(f"{node.id}.confidence has unsupported value {confidence}")
            for evidence_id_value in getattr(node, "evidence_ids", ()):
                target = self._nodes.get(evidence_id_value)
                if target is None:
                    errors.append(f"{node.id}.evidence_ids references missing endpoint {evidence_id_value}")
                elif target.kind != "evidence":
                    errors.append(f"{node.id}.evidence_ids expected evidence, got {target.kind}")

        if errors and raise_on_error:
            raise AnalysisIRValidationError(errors)
        return sorted(errors)

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validate()
        grouped = {kind: [] for kind in ENTITY_CLASSES}
        for node in self.nodes():
            grouped[node.kind].append(node.to_dict())
        return {
            "schema": SCHEMA_VERSION,
            "entities": grouped,
            "counts": {kind: len(grouped[kind]) for kind in sorted(grouped)},
        }

    def to_json(self, *, validate: bool = True, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(validate=validate),
            ensure_ascii=False,
            indent=indent,
            separators=None if indent is not None else (",", ":"),
            sort_keys=True,
        )


__all__ = [
    "SCHEMA_VERSION", "UNKNOWN", "CONFIDENCE_LEVELS", "stable_id",
    "artifact_id", "module_id", "function_id", "IRNode", "Artifact",
    "Module", "Section", "Function", "BasicBlock", "Symbol", "Import",
    "Export", "StringLiteral", "Reference", "Call", "Evidence",
    "AnalysisIR", "AnalysisIRValidationError",
]
