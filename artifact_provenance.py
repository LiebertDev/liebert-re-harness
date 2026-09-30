"""Deterministic, privacy-safe provenance and stale-artifact helpers."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

APP = Path(__file__).resolve().parent
PRODUCER_VERSION = "p0.5.0"
DATASET_SCHEMA_VERSION = 3
TRAJECTORY_COMPILER_VERSION = "2.1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str | None:
    path = Path(path)
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_hashes(paths) -> dict[str, str]:
    result = {}
    for raw in sorted((Path(x) for x in paths), key=lambda x: x.as_posix().lower()):
        if raw.is_file():
            try:
                key = raw.resolve().relative_to(APP.resolve()).as_posix()
            except ValueError:
                key = raw.name
            result[key] = sha256_file(raw)
    return result


def combined_hash(hashes: dict[str, str]) -> str:
    payload = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def anonymous_workspace_id(workspace: str | Path, max_files: int = 20000) -> str:
    root = Path(workspace).resolve()
    ignored = {".git", ".venv", "__pycache__", "node_modules", "cache", "models", "checkpoints"}
    rows = []
    if root.is_dir():
        for path in sorted(root.rglob("*"), key=lambda x: x.as_posix().lower()):
            if len(rows) >= max_files:
                break
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            if any(part.lower() in ignored for part in rel.parts) or not path.is_file():
                continue
            try:
                rows.append({"path": rel.as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
            except OSError:
                continue
    digest = sha256_bytes(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"WS-{digest[:20]}"


def _component(name: str, path: Path, version: str = PRODUCER_VERSION) -> dict:
    return {"name": name, "version": version, "sha256": sha256_file(path)}


def safe_model_identifier(model: str | None) -> str:
    value = str(model or "UNKNOWN")
    if "://" in value or value.startswith(("/", "\\")) or (len(value) > 2 and value[1:3] in (":\\", ":/")):
        return Path(value.replace("\\", "/")).name or "LOCAL_MODEL"
    return value


ABSENT = "ABSENT"


def trajectory_provenance(workspace: str | Path, teacher_model: str | None) -> dict:
    """Provenance record for a trajectory.

    Every required input is hashed; one that is missing from this checkout
    (the published tree ships none of the prompt/registry/router/planner/
    verifier inputs) is recorded as the explicit string ``ABSENT`` in its hash
    field, never as a silent null, and is listed in ``absent_inputs``.
    ``provenance_valid`` is False whenever anything is absent. The record is
    still returned rather than raising: teacher logging calls this on every
    run and must not die on a checkout that lacks the inputs; consumers that
    need real provenance gate on ``provenance_valid``.
    """
    prompt = APP / "prompts" / "teacher_system.md"
    registry = APP / "tool_registry.json"
    router = _component("file_router", APP / "file_router.py")
    planner = _component("deterministic_planner", APP / "deterministic_planner.py")
    verifier = _component("claim_verifier", APP / "claim_verifier.py")
    prompt_hash = sha256_file(prompt)
    registry_hash = sha256_file(registry)
    absent = [name for name, value in (
        ("system_prompt", prompt_hash), ("tool_registry", registry_hash),
        ("file_router", router["sha256"]), ("deterministic_planner", planner["sha256"]),
        ("claim_verifier", verifier["sha256"]),
    ) if value is None]
    for comp in (router, planner, verifier):
        comp["sha256"] = comp["sha256"] or ABSENT
    return {
        "provenance_valid": not absent,
        "absent_inputs": absent,
        "schema_version": DATASET_SCHEMA_VERSION,
        "producer_version": PRODUCER_VERSION,
        "created_at": utc_now(),
        "teacher_model": safe_model_identifier(teacher_model),
        "teacher_model_identifier": safe_model_identifier(teacher_model),
        "teacher_model_version": "runtime-configured",
        "system_prompt_sha256": prompt_hash or ABSENT,
        "tool_registry_hash": registry_hash or ABSENT,
        "tool_registry_version": PRODUCER_VERSION,
        "router_hash": router["sha256"], "router_version": router["version"],
        "planner_hash": planner["sha256"], "planner_version": planner["version"],
        "claim_verifier_hash": verifier["sha256"], "claim_verifier_version": verifier["version"],
        "trajectory_compiler_version": TRAJECTORY_COMPILER_VERSION,
        "dataset_schema_version": DATASET_SCHEMA_VERSION,
        "workspace_id": anonymous_workspace_id(workspace),
    }


def artifact_record(inputs, outputs, producer: str) -> dict:
    hashes = input_hashes(inputs)
    return {
        "schema_version": DATASET_SCHEMA_VERSION,
        "producer_version": PRODUCER_VERSION,
        "producer": producer,
        "created_at": utc_now(),
        "input_hashes": hashes,
        "input_digest": combined_hash(hashes),
        "output_hashes": input_hashes(outputs),
    }


def stale_status(manifest: str | Path, inputs) -> dict:
    path = Path(manifest)
    current = input_hashes(inputs)
    if not path.is_file():
        return {"status": "MISSING", "manifest": path.name, "current_input_digest": combined_hash(current)}
    try:
        saved = json.loads(path.read_text(encoding="utf-8")).get("input_hashes", {})
    except (OSError, json.JSONDecodeError):
        return {"status": "INVALID", "manifest": path.name}
    return {
        "status": "CURRENT" if saved == current else "STALE",
        "manifest": path.name,
        "saved_input_digest": combined_hash(saved),
        "current_input_digest": combined_hash(current),
    }
