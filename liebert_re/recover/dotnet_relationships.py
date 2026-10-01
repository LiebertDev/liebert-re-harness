"""Deterministic relationships over already-parsed .NET metadata and IL.

This module intentionally does not open assemblies or implement a metadata
parser.  It consumes the bounded dictionaries emitted by :mod:`dotnet_il` or
an equivalent richer canonical adapter.  Missing metadata tokens stay
explicitly UNKNOWN rather than being guessed.
"""
from __future__ import annotations

from typing import Any, Iterable
import json

from liebert_re.recover.analysis_ir import UNKNOWN, stable_id


SCHEMA_VERSION = "dotnet-relationships/v1"
CALL_OPCODES = frozenset({"call", "callvirt", "calli", "newobj"})
FIELD_OPCODES = frozenset({"ldfld", "ldflda", "ldsfld", "ldsflda", "stfld", "stsfld"})
STRING_OPCODES = frozenset({"ldstr"})


def _bounded_text(value: Any, limit: int = 4096) -> str:
    return str(value if value is not None else "")[:limit]


def _token(value: Any) -> str:
    """Normalize an ECMA-335 token, including little-endian IL operands."""
    if value in (None, "", UNKNOWN):
        return UNKNOWN
    if isinstance(value, int):
        return f"0x{value:08X}"
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return f"0x{int(text, 16):08X}"
        compact = text.replace(" ", "").replace("-", "")
        if len(compact) == 8 and all(char in "0123456789abcdefABCDEF" for char in compact):
            # dotnet_il.parse_il_body serializes the four operand bytes in file
            # order.  ECMA-335 metadata tokens are little-endian operands.
            return f"0x{int.from_bytes(bytes.fromhex(compact), 'little'):08X}"
        return f"0x{int(text):08X}"
    except (TypeError, ValueError):
        return UNKNOWN


def _rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in (value or []) if isinstance(row, dict)]


def _assembly_name(canonical: dict[str, Any]) -> str:
    assembly = canonical.get("assembly")
    if isinstance(assembly, dict):
        return _bounded_text(assembly.get("name") or UNKNOWN, 512) or UNKNOWN
    return _bounded_text(canonical.get("assembly_name") or UNKNOWN, 512) or UNKNOWN


def _declaring_type(row: dict[str, Any]) -> str:
    value = row.get("declaring_type", row.get("type", UNKNOWN))
    return _bounded_text(value, 1024) or UNKNOWN


def _qualified_member(assembly: str, declaring_type: str, name: str, signature: str = "") -> str:
    suffix = signature if signature else ""
    return f"{assembly}::{declaring_type}::{name}{suffix}"


def _entity(kind: str, identity: Iterable[Any], **fields: Any) -> dict[str, Any]:
    return {"id": stable_id(f"dotnet-{kind}", *identity), "kind": kind, **fields}


def _relationship(
    kind: str,
    source_id: str,
    target_id: str,
    *,
    confidence: str,
    provenance: dict[str, Any],
    target_token: str = UNKNOWN,
) -> dict[str, Any]:
    clean_provenance = {
        str(key): (_bounded_text(value) if isinstance(value, str) else value)
        for key, value in sorted(provenance.items(), key=lambda pair: str(pair[0]))
    }
    evidence = {
        "source": clean_provenance.get("source", "CANONICAL_DOTNET_INTERMEDIATE"),
        "metadata_token": target_token,
        "opcode": clean_provenance.get("opcode", UNKNOWN),
        "il_offset": clean_provenance.get("il_offset", UNKNOWN),
    }
    return {
        "id": stable_id("dotnet-relationship", kind, source_id, target_id, target_token, clean_provenance),
        "kind": kind,
        "source_id": source_id,
        "target_id": target_id,
        "target_token": target_token,
        "confidence": confidence,
        "evidence": evidence,
        "provenance": clean_provenance,
    }


def build_dotnet_relationships(
    canonical: dict[str, Any],
    *,
    max_entities: int = 10_000,
    max_relationships: int = 50_000,
) -> dict[str, Any]:
    """Build a bounded .NET inventory and relationship graph.

    Supported input is the current ``parse_dotnet_metadata`` /
    ``parse_dotnet_il`` result, plus optional canonical ``fields``, ``strings``,
    ``member_refs`` and per-type ``base_type`` rows.  No assembly is loaded or
    executed.  A token that is absent from these inputs is retained as UNKNOWN.
    """
    if not isinstance(canonical, dict):
        return {"ok": False, "status": "INVALID_INPUT", "schema": SCHEMA_VERSION, "error": "CANONICAL_DICT_REQUIRED"}
    max_entities = max(1, min(int(max_entities), 100_000))
    max_relationships = max(1, min(int(max_relationships), 250_000))
    assembly_name = _assembly_name(canonical)
    artifact_sha256 = _bounded_text(canonical.get("artifact_sha256") or canonical.get("sha256") or UNKNOWN, 128) or UNKNOWN

    entities: dict[str, list[dict[str, Any]]] = {
        "assembly": [], "type": [], "method": [], "field": [], "string": [], "external_member": [],
    }
    relationships: list[dict[str, Any]] = []
    token_index: dict[str, dict[str, Any]] = {}
    truncated = False

    assembly = _entity(
        "assembly", (artifact_sha256, assembly_name), name=assembly_name,
        version=_bounded_text((canonical.get("assembly") or {}).get("version", UNKNOWN), 128)
        if isinstance(canonical.get("assembly"), dict) else UNKNOWN,
        artifact_sha256=artifact_sha256,
    )
    entities["assembly"].append(assembly)

    type_rows = canonical.get("types") or []
    normalized_types: list[dict[str, Any]] = []
    for position, item in enumerate(type_rows):
        row = item if isinstance(item, dict) else {"name": item}
        name = _bounded_text(row.get("name", row.get("full_name", item)), 1024) or UNKNOWN
        token = _token(row.get("token"))
        entity = _entity(
            "type", (artifact_sha256, assembly_name, token, name), name=name,
            assembly=assembly_name, token=token,
            provenance={"source": "TYPE_DEF", "row_index": position},
        )
        normalized_types.append(entity)
        if token != UNKNOWN:
            token_index[token] = entity
    entities["type"] = normalized_types[:max_entities]
    type_by_name = {row["name"]: row for row in entities["type"]}

    method_rows = [*(_rows(canonical.get("methods")))]
    il_rows = _rows(canonical.get("il_methods"))
    by_token = {_token(row.get("token")): row for row in method_rows if _token(row.get("token")) != UNKNOWN}
    for il_row in il_rows:
        token = _token(il_row.get("token"))
        if token != UNKNOWN and token in by_token:
            by_token[token] = {**by_token[token], **il_row}
        elif token == UNKNOWN or token not in by_token:
            method_rows.append(il_row)
    if by_token:
        token_backed = [by_token[key] for key in sorted(by_token)]
        tokenless = [row for row in method_rows if _token(row.get("token")) == UNKNOWN]
        method_rows = token_backed + tokenless

    method_row_by_id: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(method_rows):
        declaring = _declaring_type(row)
        name = _bounded_text(row.get("name") or UNKNOWN, 1024) or UNKNOWN
        signature = _bounded_text(row.get("signature") or "", 2048)
        token = _token(row.get("token"))
        qualified = _qualified_member(assembly_name, declaring, name, signature)
        entity = _entity(
            "method", (artifact_sha256, token, qualified), name=name,
            qualified_name=qualified, declaring_type=declaring, signature=signature or UNKNOWN,
            token=token, rva=row.get("rva", UNKNOWN), assembly=assembly_name,
            provenance={"source": "METHOD_DEF", "row_index": position},
        )
        entities["method"].append(entity)
        method_row_by_id[entity["id"]] = row
        if token != UNKNOWN:
            token_index[token] = entity

    field_rows = _rows(canonical.get("fields"))
    # Rich adapters may keep fields nested beneath each type, as tools_dotnet does.
    for item in type_rows:
        if isinstance(item, dict):
            for field in _rows(item.get("fields")):
                field_rows.append({"declaring_type": item.get("name", UNKNOWN), **field})
    for position, row in enumerate(field_rows):
        declaring = _declaring_type(row)
        name = _bounded_text(row.get("name") or UNKNOWN, 1024) or UNKNOWN
        token = _token(row.get("token"))
        entity = _entity(
            "field", (artifact_sha256, token, declaring, name), name=name,
            qualified_name=_qualified_member(assembly_name, declaring, name),
            declaring_type=declaring, token=token, assembly=assembly_name,
            provenance={"source": "FIELD_DEF", "row_index": position},
        )
        entities["field"].append(entity)
        if token != UNKNOWN:
            token_index[token] = entity

    for position, row in enumerate(_rows(canonical.get("strings"))):
        token = _token(row.get("token"))
        value = _bounded_text(row.get("value", UNKNOWN)) or UNKNOWN
        entity = _entity(
            "string", (artifact_sha256, token, value), value=value, token=token,
            provenance={"source": "USER_STRING_HEAP", "row_index": position},
        )
        entities["string"].append(entity)
        if token != UNKNOWN:
            token_index[token] = entity

    member_refs = _rows(canonical.get("member_refs"))
    for position, row in enumerate(member_refs):
        token = _token(row.get("token"))
        member_assembly = _bounded_text(row.get("assembly") or UNKNOWN, 512) or UNKNOWN
        declaring = _declaring_type(row)
        name = _bounded_text(row.get("name") or UNKNOWN, 1024) or UNKNOWN
        member_kind = _bounded_text(row.get("member_kind") or row.get("kind") or "member", 64).lower()
        entity = _entity(
            "external_member", (member_assembly, declaring, name, token), name=name,
            declaring_type=declaring, assembly=member_assembly, token=token,
            member_kind=member_kind,
            provenance={"source": "MEMBER_REF", "row_index": position},
        )
        entities["external_member"].append(entity)
        if token != UNKNOWN:
            token_index[token] = entity

    # Type hierarchy is emitted only when the canonical adapter observed it.
    for position, item in enumerate(type_rows):
        if not isinstance(item, dict):
            continue
        source = type_by_name.get(_bounded_text(item.get("name", item.get("full_name", UNKNOWN)), 1024))
        base_token = _token(item.get("base_type_token", item.get("extends_token")))
        base_name = _bounded_text(item.get("base_type", item.get("extends", UNKNOWN)), 1024) or UNKNOWN
        target = token_index.get(base_token) if base_token != UNKNOWN else type_by_name.get(base_name)
        if source and (base_token != UNKNOWN or base_name != UNKNOWN):
            relationships.append(_relationship(
                "TYPE_INHERITS", source["id"], target["id"] if target else UNKNOWN,
                confidence="METADATA_PROVEN" if target else UNKNOWN,
                target_token=base_token,
                provenance={"source": "TYPE_DEF_EXTENDS", "row_index": position, "base_type_name": base_name},
            ))

    for method in entities["method"]:
        row = method_row_by_id[method["id"]]
        for instruction_index, instruction in enumerate(_rows(row.get("instructions"))):
            opcode = _bounded_text(instruction.get("mnemonic", instruction.get("opcode", UNKNOWN)), 64).lower()
            if opcode not in CALL_OPCODES | FIELD_OPCODES | STRING_OPCODES:
                continue
            target_token = _token(instruction.get("operand_token", instruction.get("token", instruction.get("operand"))))
            target = token_index.get(target_token)
            relationship_kind = (
                "METHOD_CALL" if opcode in CALL_OPCODES else
                "FIELD_ACCESS" if opcode in FIELD_OPCODES else "STRING_USE"
            )
            expected_kind = (
                {"method", "external_member"} if relationship_kind == "METHOD_CALL" else
                {"field", "external_member"} if relationship_kind == "FIELD_ACCESS" else {"string"}
            )
            resolved = target is not None and target.get("kind") in expected_kind
            relationships.append(_relationship(
                relationship_kind, method["id"], target["id"] if resolved else UNKNOWN,
                confidence="METADATA_PROVEN" if resolved else UNKNOWN,
                target_token=target_token,
                provenance={
                    "source": "STRUCTURAL_IL", "opcode": opcode,
                    "il_offset": instruction.get("offset", UNKNOWN),
                    "instruction_index": instruction_index,
                    "unresolved_reason": UNKNOWN if resolved else "TOKEN_NOT_PRESENT_IN_CANONICAL_INPUT",
                },
            ))
            if resolved and target.get("kind") == "external_member" and target.get("assembly") not in {UNKNOWN, assembly_name}:
                relationships.append(_relationship(
                    "CROSS_ASSEMBLY_MEMBER_REFERENCE", method["id"], target["id"],
                    confidence="METADATA_PROVEN", target_token=target_token,
                    provenance={
                        "source": "MEMBER_REF_AND_STRUCTURAL_IL", "opcode": opcode,
                        "il_offset": instruction.get("offset", UNKNOWN),
                        "target_assembly": target.get("assembly", UNKNOWN),
                    },
                ))

    refs = canonical.get("references", canonical.get("assembly_refs", []))
    for position, row in enumerate(_rows(refs)):
        name = _bounded_text(row.get("name") or UNKNOWN, 512) or UNKNOWN
        target = _entity(
            "assembly", (UNKNOWN, name), name=name,
            version=_bounded_text(row.get("version") or UNKNOWN, 128), artifact_sha256=UNKNOWN,
        )
        entities["assembly"].append(target)
        relationships.append(_relationship(
            "ASSEMBLY_REFERENCE", assembly["id"], target["id"], confidence="METADATA_PROVEN",
            provenance={"source": "ASSEMBLY_REF", "row_index": position, "version": target["version"]},
        ))

    for kind in entities:
        rows = sorted({row["id"]: row for row in entities[kind]}.values(), key=lambda row: row["id"])
        if len(rows) > max_entities:
            rows = rows[:max_entities]
            truncated = True
        entities[kind] = rows
    relationships = sorted({row["id"]: row for row in relationships}.values(), key=lambda row: row["id"])
    if len(relationships) > max_relationships:
        relationships = relationships[:max_relationships]
        truncated = True
    unresolved = sum(row["target_id"] == UNKNOWN for row in relationships)
    return {
        "ok": True,
        "status": "PARTIAL" if unresolved or truncated else "COMPLETE",
        "schema": SCHEMA_VERSION,
        "analysis_scope": "STATIC_CANONICAL_DOTNET_INTERMEDIATE",
        "entities": entities,
        "relationships": relationships,
        "counts": {
            **{kind: len(rows) for kind, rows in sorted(entities.items())},
            "relationships": len(relationships), "unresolved_relationships": unresolved,
        },
        "truncated": truncated,
        "execution_performed": False,
        "limitations": [
            "Resolution is limited to tokens present in the supplied canonical metadata input.",
            "Reflection, dynamic dispatch, generics instantiation and runtime binding are not inferred.",
        ],
    }


def dotnet_relationship_analyze(canonical_json: str, max_entities: int = 10000, max_relationships: int = 20000) -> str:
    try:
        canonical = json.loads(canonical_json)
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "status": "INVALID_JSON"})
    if not isinstance(canonical, dict):
        return json.dumps({"ok": False, "status": "INVALID_SCHEMA"})
    return json.dumps(build_dotnet_relationships(canonical, max_entities=max_entities, max_relationships=max_relationships), ensure_ascii=False, indent=2, sort_keys=True, default=str)


__all__ = ["SCHEMA_VERSION", "build_dotnet_relationships", "dotnet_relationship_analyze"]
