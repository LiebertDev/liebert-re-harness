"""Bounded, non-executing static probe shared by every file domain."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections import Counter
from pathlib import Path

from liebert_re.tools.formats import file_identity
from liebert_re.workspace import PROJECT_ROOT as APP_DIR
from liebert_re.workspace import relative, safe_path

try:
    from liebert_re.evidence.index import _evidence_uid_for_path
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except ImportError:  # pragma: no cover - an indexing dependency must never block the probe
    def _evidence_uid_for_path(*_args, **_kwargs):
        return None

    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

# Module attribute deliberately named EVIDENCE (tests/conftest.py redirects every
# module's EVIDENCE away from the real ledger for the duration of a test).
EVIDENCE = APP_DIR / "dataset" / "evidence" / "generic_static_probe"


MAX_SAMPLE_BYTES = 256 * 1024
MAX_HASH_BYTES = 512_000_000
MAX_EXACT_TEXT_BYTES = 4_000_000
MAX_STRINGS = 80


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()), 4)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _samples(path: Path) -> tuple[bytes, int]:
    size = path.stat().st_size
    half = MAX_SAMPLE_BYTES // 2
    with path.open("rb") as stream:
        head = stream.read(min(size, half))
        tail = b""
        if size > half:
            stream.seek(max(0, size - half))
            tail = stream.read(half)
    return head + tail, len(head) + len(tail)


def _encoding(sample: bytes) -> str | None:
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return None


# The status vocabulary tool results are normalised against. Module level so the
# CLI can share it instead of keeping a second copy that could drift.
ALLOWED_STATUSES = frozenset({"READY", "PARTIAL", "TOOL_MISSING", "NOT_TESTED", "UNSUPPORTED", "ANALYSIS_LIMITED", "FAILED", "TIMEOUT", "TRUNCATED", "UNKNOWN"})


def normalize_tool_result(result, *, tool: str, target: str, file_type: str = "UNKNOWN",
                          capability_status: str = "UNKNOWN", reliability: str = "LOW") -> dict:
    """Normalize bounded tool output without converting failure kinds into UNSUPPORTED."""
    if isinstance(result, str):
        try:
            payload = json.loads(result)
        except json.JSONDecodeError:
            # Text that is not JSON carries no success field: it is summarised, never taken as READY.
            payload = {"summary": result[:2000], "truncated": len(result) > 2000,
                       "limitations": ["tool output was not JSON; its status could not be determined"]}
    else:
        payload = dict(result or {})
    if not isinstance(payload, dict):
        payload = {"value": payload, "limitations": ["tool output was JSON but not an object; its status could not be determined"]}
    # Success comes only from an explicit status or an explicit ok field; neither present is UNKNOWN.
    if payload.get("status"):
        raw_status = str(payload["status"]).upper()
    elif "ok" in payload:
        raw_status = "READY" if payload["ok"] is True else "FAILED"
    else:
        raw_status = "UNKNOWN"
        payload = {**payload, "limitations": [*(payload.get("limitations") or []), "tool output carried neither status nor ok; success was not assumed"]}
    allowed = ALLOWED_STATUSES
    status = raw_status if raw_status in allowed else "READY" if raw_status in {"PASS", "OK"} else "FAILED"
    return {
        "status": status,
        "tool": tool,
        "target": target,
        "file_type": file_type,
        "evidence_id": payload.get("evidence_id"),
        "summary": payload.get("summary") or payload.get("error") or f"{tool} returned {status}",
        "locations": payload.get("locations", []),
        "truncated": bool(payload.get("truncated", status == "TRUNCATED")),
        "reliability": reliability,
        "limitations": list(payload.get("limitations") or []),
        "next_tool": payload.get("next_tool"),
        "capability_status": capability_status,
        "details": payload,
    }


def generic_static_probe(path: str, max_strings: int = MAX_STRINGS) -> str:
    target = safe_path(path)
    if not target.is_file():
        return json.dumps(normalize_tool_result({"ok": False, "status": "FAILED", "error": "FILE_NOT_FOUND"}, tool="generic_static_probe", target=str(path)), ensure_ascii=False, indent=2)
    identity = json.loads(file_identity(str(target)))
    sample, bytes_read = _samples(target)
    size = target.stat().st_size
    encoding = _encoding(sample) if identity.get("text") else None
    strings = [match.group(0).decode("ascii", errors="replace") for match in re.finditer(rb"[ -~]{5,}", sample)]
    unique_strings = list(dict.fromkeys(strings))
    line_count = None
    line_count_exact = False
    if identity.get("text") and size <= MAX_EXACT_TEXT_BYTES:
        with target.open("r", encoding=encoding or "utf-8", errors="replace") as stream:
            line_count = sum(1 for _ in stream)
        line_count_exact = True
    limitations = list(identity.get("limitations") or [])
    digest = identity.get("sha256")
    if size > MAX_HASH_BYTES:
        digest = None
        limitations.append(f"SHA256 skipped above {MAX_HASH_BYTES} bytes")
    elif digest is None:
        digest = _sha256(target)
    truncated = size > bytes_read or len(unique_strings) > max_strings
    route_status = "READY" if identity.get("type") not in {None, "UNKNOWN"} else "PARTIAL"
    result = {
        "status": route_status,
        "tool": "generic_static_probe",
        "target": relative(target),
        "file_type": identity.get("type", "UNKNOWN"),
        "category": identity.get("category", "UNKNOWN_BINARY"),
        "evidence_id": None,
        "summary": f"Static {identity.get('type', 'UNKNOWN')} probe; {size} bytes; no execution performed.",
        "locations": [{"kind": "sample", "head_offset": 0, "tail_offset": max(0, size - MAX_SAMPLE_BYTES // 2)}],
        "truncated": truncated,
        "reliability": "HIGH" if identity.get("confidence", 0) >= 0.95 else "MEDIUM" if identity.get("confidence", 0) >= 0.7 else "LOW",
        "limitations": list(dict.fromkeys(limitations)),
        "next_tool": (identity.get("recommended_capabilities") or [None])[0],
        "capability_status": "READY",
        "identity": identity,
        "sha256": digest,
        "entropy_sample": _entropy(sample),
        "sample_bytes_read": bytes_read,
        "printable_strings": unique_strings[:max(1, min(int(max_strings), MAX_STRINGS))],
        "text_encoding": encoding,
        "line_count": line_count,
        "line_count_exact": line_count_exact,
        "execution_performed": False,
        "full_file_loaded_to_memory": False,
    }
    _attach_evidence(result, target)
    return json.dumps(result, ensure_ascii=False, indent=2)


def _attach_evidence(result: dict, target: Path) -> None:
    """Write the probe result to the evidence ledger and bind its identity into the result.
    The identity (``EVX-...``) is the one the evidence index gives that file, derived from its
    path, so it is quoted before the result is written and the file carries it too. When the file
    cannot be written the result says so and ``evidence_id`` stays None: an id is never invented."""
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", target.stem)[:60] or "input"
    out = Path(EVIDENCE) / f"{stem}_{uuid.uuid4().hex[:8]}_generic_static_probe.json"
    evidence_id = _evidence_uid_for_path(out)
    if evidence_id is None:
        result["evidence_error"] = "EVIDENCE_PATH_OUTSIDE_INDEX_ROOT: no evidence identity can be derived for this path"
        return
    result["evidence_id"] = evidence_id
    result["evidence_file"] = out.name
    try:
        Path(EVIDENCE).mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        result["evidence_id"] = None
        result.pop("evidence_file", None)
        result["evidence_error"] = f"EVIDENCE_NOT_WRITTEN: {type(exc).__name__}"
        return
    _evidence_index_record_write(out)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    print(generic_static_probe(args.path))
