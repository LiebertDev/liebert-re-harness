"""Bounded, model-callable wrapper around lzma1_range_decoder.py's
generic, from-scratch LZMA1 stream decoder (see that module's own
docstring for provenance and its non-circular verification against
Python's stdlib lzma module).

Exposes ONLY the standard top-level decode loop (decode_lzma1_stream) --
NOT LzmaState's individual step-level primitives (decode_literal_step /
decode_match_or_rep_step). Those exist specifically so a caller can
hand-drive a *non-standard* control flow (e.g. a packer's reduced or
customized range-coder stub) once that control flow has been traced from
the real target -- wrapping that into a single bounded tool call would
mean baking in assumptions about one specific packer's opcode ordering,
exactly the kind of benchmark-specific logic that correctly stays in a
bespoke script rather than becoming a generic registered capability.
decode_lzma1_stream itself has no such assumptions: it is the standard
LZMA1 top-level loop, applicable to any real LZMA1 stream regardless of
which packer or archiver produced it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time

from liebert_re.recover.lzma1_range_decoder import LzmaFormatError, decode_lzma1_stream
from liebert_re.workspace import relative, safe_path

MAX_OUT_SIZE = 64 * 1024 * 1024
MAX_INPUT_READ_BYTES = 200 * 1024 * 1024
MAX_INLINE_OUTPUT_BYTES = 4 * 1024 * 1024


def lzma1_decode(path, offset=0, lc=3, lp=0, pb=2, out_size=0):
    started = time.monotonic()
    try:
        offset = int(offset)
        lc, lp, pb = int(lc), int(lp), int(pb)
        out_size = int(out_size)
    except (TypeError, ValueError):
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "INVALID_PARAMETERS", "detail": "offset/lc/lp/pb/out_size must be integers"}, indent=2)
    if offset < 0:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "INVALID_OFFSET"}, indent=2)
    if out_size <= 0:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "OUT_SIZE_REQUIRED", "detail": "out_size must be a positive integer (the expected decompressed length)"}, indent=2)
    if out_size > MAX_OUT_SIZE:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "OUT_SIZE_TOO_LARGE", "detail": f"out_size {out_size} exceeds MAX_OUT_SIZE={MAX_OUT_SIZE}"}, indent=2)

    try:
        p = safe_path(path)
        size = p.stat().st_size
        if size - offset > MAX_INPUT_READ_BYTES:
            return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "INPUT_TOO_LARGE", "detail": f"remaining file bytes from offset exceed MAX_INPUT_READ_BYTES={MAX_INPUT_READ_BYTES}"}, indent=2)
        with p.open("rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError as exc:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "FILE_NOT_ACCESSIBLE", "error_type": type(exc).__name__, "path": str(path)}, ensure_ascii=False, indent=2)

    if not data:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "NO_DATA_AT_OFFSET", "path": relative(p), "offset": offset}, indent=2)

    try:
        decoded = decode_lzma1_stream(data, lc, lp, pb, out_size, offset=0)
    except LzmaFormatError as exc:
        return json.dumps({"ok": False, "tool": "lzma1_decode", "error": "LZMA_FORMAT_ERROR", "detail": str(exc), "elapsed_ms": int((time.monotonic() - started) * 1000)}, ensure_ascii=False, indent=2)

    digest = hashlib.sha256(decoded).hexdigest()
    truncated = len(decoded) > MAX_INLINE_OUTPUT_BYTES
    payload = {
        "ok": True,
        "tool": "lzma1_decode",
        "path": relative(p),
        "offset": offset,
        "params": {"lc": lc, "lp": lp, "pb": pb, "out_size": out_size},
        "decoded_bytes": len(decoded),
        "decoded_sha256": digest,
        "decoded_base64": base64.b64encode(decoded[:MAX_INLINE_OUTPUT_BYTES]).decode("ascii"),
        "truncated_output": truncated,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
