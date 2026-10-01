"""Dependency-free Electron ASAR P0/P1 parser with fail-closed extraction."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

MAX_ASAR_BYTES = 64 * 1024 * 1024
MAX_HEADER_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_EXTRACT_FILE = 8 * 1024 * 1024
MAX_EXTRACT_TOTAL = 32 * 1024 * 1024
MAX_DEPTH = 32


def _fail(code: str, **detail) -> dict:
    return {
        "ok": False,
        "tool": "asar_parser",
        "status": "ANALYSIS_LIMITED",
        "error": code,
        "detail": detail,
        "execution_performed": False,
    }


def detect_asar(data: bytes) -> dict:
    if len(data) < 8:
        return {"ok": False, "detected": False, "error": "HEADER_TRUNCATED", "size": len(data)}
    pickle_size = int.from_bytes(data[:4], "little")
    json_size = int.from_bytes(data[4:8], "little")
    if pickle_size == 0 or json_size == 0 or pickle_size > MAX_HEADER_BYTES or json_size > MAX_JSON_BYTES:
        return {"ok": False, "detected": False, "error": "INVALID_HEADER", "pickle_size": pickle_size, "json_size": json_size}
    if 4 + pickle_size > len(data) or 8 + json_size > len(data):
        return {"ok": False, "detected": False, "error": "HEADER_TRUNCATED", "pickle_size": pickle_size, "json_size": json_size}
    blob = data[8:8 + json_size].lstrip()
    if not blob.startswith(b"{") and not blob.startswith(b"["):
        return {"ok": False, "detected": False, "error": "HEADER_NOT_JSON"}
    return {
        "ok": True,
        "detected": True,
        "pickle_size": pickle_size,
        "json_size": json_size,
        "header_bytes": 4 + pickle_size,
    }


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _walk_files(node: dict, prefix: str, *, depth: int, entries: list, errors: list) -> None:
    if depth > MAX_DEPTH:
        errors.append({"error": "TREE_TOO_DEEP", "path": prefix, "depth": depth})
        return
    if not isinstance(node, dict):
        errors.append({"error": "UNEXPECTED_FIELD_TYPE", "path": prefix, "expected": "object"})
        return
    files = node.get("files")
    if files is None:
        return
    if not isinstance(files, dict):
        errors.append({"error": "UNEXPECTED_FIELD_TYPE", "path": prefix or "/", "field": "files"})
        return
    for name, child in files.items():
        if not isinstance(name, str) or not name or "/" in name or "\\" in name or name in {".", ".."} or str(name).startswith(".."):
            errors.append({"error": "INVALID_ENTRY_NAME", "path": prefix, "name": name})
            continue
        rel = f"{prefix}/{name}" if prefix else name
        if not isinstance(child, dict):
            errors.append({"error": "UNEXPECTED_FIELD_TYPE", "path": rel})
            continue
        if "files" in child:
            entries.append({
                "path": rel,
                "kind": "directory",
                "unpacked": bool(child.get("unpacked")),
            })
            _walk_files(child, rel, depth=depth + 1, entries=entries, errors=errors)
            continue
        size = child.get("size", 0)
        offset = child.get("offset", "0")
        try:
            size_i = int(size)
            offset_i = int(offset)
        except (TypeError, ValueError):
            errors.append({"error": "MALFORMED_OFFSET_OR_SIZE", "path": rel, "offset": offset, "size": size})
            continue
        if size_i < 0 or offset_i < 0:
            errors.append({"error": "NEGATIVE_OFFSET_OR_SIZE", "path": rel})
            continue
        entries.append({
            "path": rel,
            "kind": "file",
            "size": size_i,
            "offset": offset_i,
            "unpacked": bool(child.get("unpacked")),
            "executable": bool(child.get("executable")),
            "integrity": child.get("integrity"),
        })
        if len(entries) > MAX_ENTRIES:
            errors.append({"error": "TOO_MANY_ENTRIES", "limit": MAX_ENTRIES})
            return


def parse_asar(path: str | Path | None = None, *, data: bytes | None = None) -> dict:
    if data is None:
        if path is None:
            return _fail("NO_INPUT")
        target = Path(path)
        try:
            size = target.stat().st_size
            if size > MAX_ASAR_BYTES:
                return _fail("ASAR_TOO_LARGE", size=size, maximum=MAX_ASAR_BYTES)
            data = target.read_bytes()
        except OSError as exc:
            return _fail(type(exc).__name__)
    else:
        data = bytes(data)
        target = Path(path) if path else None
        if len(data) > MAX_ASAR_BYTES:
            return _fail("ASAR_TOO_LARGE", size=len(data), maximum=MAX_ASAR_BYTES)
    detected = detect_asar(data)
    if not detected.get("ok"):
        return {
            **_fail(detected.get("error") or "NOT_ASAR"),
            "detected": False,
            "format": "asar",
        }
    json_size = detected["json_size"]
    header_bytes = detected["header_bytes"]
    try:
        header_obj = json.loads(data[8:8 + json_size].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        return _fail("MALFORMED_HEADER_JSON", detail=str(exc)[:200])
    if not isinstance(header_obj, dict):
        return _fail("UNEXPECTED_FIELD_TYPE", field="root")
    entries: list[dict] = []
    errors: list[dict] = []
    _walk_files(header_obj, "", depth=0, entries=entries, errors=errors)
    payload_base = header_bytes
    payload_size = len(data) - payload_base
    files = [row for row in entries if row.get("kind") == "file" and not row.get("unpacked")]
    for row in files:
        end = row["offset"] + row["size"]
        if row["offset"] > payload_size or end > payload_size:
            errors.append({
                "error": "FILE_OFFSET_OR_SIZE_OOB",
                "path": row["path"],
                "offset": row["offset"],
                "size": row["size"],
                "payload_size": payload_size,
            })
            row["oob"] = True
    ok = not any(e.get("error") in {
        "TREE_TOO_DEEP", "TOO_MANY_ENTRIES", "FILE_OFFSET_OR_SIZE_OOB", "MALFORMED_OFFSET_OR_SIZE",
        "UNEXPECTED_FIELD_TYPE", "INVALID_ENTRY_NAME", "NEGATIVE_OFFSET_OR_SIZE",
    } for e in errors)
    report = {
        "ok": ok,
        "tool": "asar_parser",
        "status": "PARTIAL" if ok else "ANALYSIS_LIMITED",
        "format": "asar",
        "detected": True,
        "header": {
            "pickle_size": detected["pickle_size"],
            "json_size": json_size,
            "header_bytes": header_bytes,
        },
        "payload_base": payload_base,
        "payload_size": payload_size,
        "entry_count": len(entries),
        "file_count": sum(1 for row in entries if row.get("kind") == "file"),
        "directory_count": sum(1 for row in entries if row.get("kind") == "directory"),
        "unpacked_count": sum(1 for row in entries if row.get("unpacked")),
        "entries": entries,
        "errors": errors,
        "claims_ceiling": {
            "inventory": "PROVEN" if ok else "REJECTED",
            "extraction": "UNKNOWN",
            "javascript_semantics": "UNKNOWN",
        },
        "limitations": [
            "ASAR header/tree/metadata only unless extract is requested",
            "No JS semantic analysis or source-map recovery",
        ],
        "execution_performed": False,
    }
    if target is not None:
        report["path"] = str(target)
    return report


def build_synthetic_asar(files: dict[str, bytes], *, unpacked: set[str] | None = None) -> bytes:
    """Build a minimal valid ASAR. `files` keys are posix relative paths."""
    unpacked = unpacked or set()
    root: dict = {"files": {}}

    def ensure_dir(parts: list[str]) -> dict:
        node = root
        for part in parts:
            node = node.setdefault("files", {}).setdefault(part, {})
            node.setdefault("files", {})
        return node

    blobs: list[bytes] = []
    offset = 0
    for rel, blob in files.items():
        parts = [p for p in PurePosixPath(rel).parts if p not in {".", ""}]
        if not parts:
            continue
        parent = ensure_dir(parts[:-1]) if len(parts) > 1 else root
        name = parts[-1]
        entry: dict = {"size": len(blob)}
        if rel in unpacked:
            entry["unpacked"] = True
        else:
            entry["offset"] = str(offset)
            blobs.append(blob)
            offset += len(blob)
        parent.setdefault("files", {})[name] = entry
    payload = json.dumps(root, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    json_size = len(payload)
    pickle_payload_size = 4 + _align4(json_size)
    header = (
        pickle_payload_size.to_bytes(4, "little")
        + json_size.to_bytes(4, "little")
        + payload
        + (b"\0" * (_align4(json_size) - json_size))
    )
    return header + b"".join(blobs)


def _unsafe_extract_path(rel: str) -> str | None:
    text = str(rel or "").replace("\\", "/")
    if not text or text.startswith("/") or text.startswith("~"):
        return "ABSOLUTE_OR_EMPTY_PATH"
    if ":" in text.split("/", 1)[0] and len(text) >= 2 and text[1] == ":":
        return "DRIVE_PATH"
    if text.startswith("//") or text.startswith("\\\\"):
        return "UNC_PATH"
    parts = []
    for part in PurePosixPath(text).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return "PATH_TRAVERSAL"
        parts.append(part)
    if not parts:
        return "EMPTY_PATH"
    return None


def extract_asar(path: str | Path, destination: str | Path, *, max_files: int = 256) -> dict:
    from liebert_re.workspace import relative, safe_path

    archive = safe_path(path)
    dest_root = safe_path(destination)
    dest_root.mkdir(parents=True, exist_ok=True)
    parsed = parse_asar(archive)
    if not parsed.get("ok"):
        parsed["extraction"] = {"ok": False, "error": parsed.get("error") or "PARSE_FAILED"}
        return parsed
    data = archive.read_bytes()
    base = int(parsed["payload_base"])
    written = []
    blocked = []
    total = 0
    files = [row for row in parsed.get("entries") or [] if row.get("kind") == "file"]
    for row in files[: max(1, int(max_files))]:
        rel = row["path"]
        reason = _unsafe_extract_path(rel)
        if reason:
            blocked.append({"path": rel, "error": reason})
            continue
        if row.get("unpacked"):
            written.append({"path": rel, "status": "SKIPPED_UNPACKED"})
            continue
        if row.get("oob"):
            blocked.append({"path": rel, "error": "FILE_OFFSET_OR_SIZE_OOB"})
            continue
        size = int(row.get("size") or 0)
        if size > MAX_EXTRACT_FILE or total + size > MAX_EXTRACT_TOTAL:
            blocked.append({"path": rel, "error": "EXTRACT_SIZE_LIMIT"})
            continue
        start = base + int(row.get("offset") or 0)
        blob = data[start:start + size]
        if len(blob) != size:
            blocked.append({"path": rel, "error": "TRUNCATED_PAYLOAD"})
            continue
        target = (dest_root / rel).resolve()
        try:
            target.relative_to(dest_root.resolve())
        except ValueError:
            blocked.append({"path": rel, "error": "DESTINATION_ESCAPE"})
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_symlink():
            blocked.append({"path": rel, "error": "SYMLINK_ESCAPE"})
            continue
        target.write_bytes(blob)
        total += size
        written.append({"path": rel, "bytes": size, "dest": relative(target)})
    parsed["extraction"] = {
        "ok": not blocked,
        "written": written,
        "blocked": blocked,
        "bytes_written": total,
        "destination": relative(dest_root),
    }
    parsed["claims_ceiling"]["extraction"] = "PROVEN" if not blocked else "REJECTED"
    parsed["status"] = "PARTIAL"
    return parsed


def asar_inspect(path: str, operation: str = "summary", destination: str = "", max_files: int = 256) -> str:
    from liebert_re.workspace import relative, safe_path

    target = safe_path(path)
    if operation == "extract":
        dest = destination or str(Path("dataset") / "tmp" / "asar_extract")
        report = extract_asar(target, dest, max_files=max_files)
    else:
        report = parse_asar(target)
    report["tool"] = "asar_inspect"
    report["path"] = relative(target)
    report["operation"] = operation
    return json.dumps(report, ensure_ascii=False, indent=2)
