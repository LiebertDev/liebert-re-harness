"""Detect It Easy (horsicq/DetectItEasy, GPL-3.0) packer/protector/compiler
identification -- closes CAND-003 half (a) in docs/TOOL_GAP_BACKLOG.md: the
harness had no answer to the first question asked of any hard target, "what
is this protected with?" (Themida / VMProtect / Enigma / ASProtect / a
layered combination / a custom packer / nothing at all), and picking an
unpacking or bypass approach before knowing that wastes the engagement.

Deliberately narrow, matching tools_upx.py's discipline: this wraps DIE's
own console binary `diec.exe -j` -- a mature, actively-maintained,
signature-driven identifier -- and never re-implements packer/protector
signature matching itself (the operator's standing rule: never write a
signature engine from scratch, wrap an existing tool). diec.exe only READS
the target file (no execution of untrusted code, same trust model as
capa/floss/rizin), so this is a HOST-side static tool like capa_analyze or
upx_unpack, not an isolated-backend tool like memory_scan.

DIE is a signature MATCHER, not a probabilistic classifier: it does not
emit a numeric confidence score, so this module does not invent one --
every match reported here is a deterministic byte-pattern/heuristic hit
from DIE's own signature database, surfaced as `confidence:
"signature_match"` rather than a fabricated number.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.workspace import safe_path, relative

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
EVIDENCE = APP_DIR / "dataset" / "evidence" / "die_identify"
EVIDENCE.mkdir(parents=True, exist_ok=True)

_DEFAULT_TIMEOUT_SECONDS = 60
_MIN_TIMEOUT_SECONDS = 5
_MAX_TIMEOUT_SECONDS = 300
# A signature-matched protector/packer/compiler detection list for one PE is
# small (DIE's real output on the samples this module was verified against
# is a few KB); bounded well above that rather than left unbounded.
_MAX_OUTPUT_CHARS = 4 * 1024 * 1024

# DIE's own `type` strings (lower-cased) that answer "what packed/protected
# this" -- the question this tool exists for.
_PROTECTOR_TYPES = {"packer", "protector", "protection", "installer", "cryptor", "obfuscator"}
_COMPILER_TYPES = {"compiler"}
_LINKER_TYPES = {"linker"}


def _die_binary():
    explicit = os.getenv("DIE_HOME", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        candidate = p / "diec.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("diec") or shutil.which("diec.exe")
    if found:
        return found
    return None


def die_available():
    return _die_binary() is not None


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _value_entry(value):
    return {
        "type": (value.get("type") or "").strip(),
        "name": value.get("name"),
        "version": value.get("version") or None,
        "info": value.get("info") or None,
        "string": value.get("string"),
    }


def _normalize(raw):
    """Reduce DIE's `{"detects": [...]}` into the structured fields this
    tool promises: file type, protector/packer matches (with version and
    DIE's own deterministic confidence label), compiler, linker, and the
    full raw per-value detection list (never flattened to a single string).
    """
    detects = raw.get("detects", []) if isinstance(raw, dict) else []
    file_type = None
    raw_detections = []
    protectors = []
    compilers = []
    linkers = []
    for block in detects:
        if not isinstance(block, dict):
            continue
        block_filetype = block.get("filetype")
        if file_type is None and block_filetype:
            file_type = block_filetype
        for value in block.get("values", []) or []:
            if not isinstance(value, dict):
                continue
            entry = _value_entry(value)
            entry["filetype"] = block_filetype
            entry["parentfilepart"] = block.get("parentfilepart")
            raw_detections.append(entry)
            vtype = entry["type"].lower()
            if vtype in _PROTECTOR_TYPES:
                protectors.append({**entry, "confidence": "signature_match"})
            elif vtype in _COMPILER_TYPES:
                compilers.append(entry)
            elif vtype in _LINKER_TYPES:
                linkers.append(entry)
    return {
        "file_type": file_type,
        "protected": bool(protectors),
        "protectors": protectors,
        "compiler": compilers[0] if compilers else None,
        "linker": linkers[0] if linkers else None,
        "detections": raw_detections,
    }


def die_identify(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Identify the packer/protector/compiler/linker DIE's signature
    database recognizes in `path` via the real `diec.exe -j`.

    Status vocabulary matches the repo's other static-tool wrappers: OK,
    TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED (diec ran but produced no usable output), and
    RESULT_PARSE_FAILED (diec's own JSON did not parse -- a version-drift
    signal, not this tool's bug).

    `status: "OK"` with `protected: false` is a real NEGATIVE result (DIE
    looked and found no packer/protector signature), not an error -- most
    binaries in this repo's corpora are legitimately unprotected.
    """
    exe = _die_binary()
    if not exe:
        return _j({
            "ok": False, "tool": "die_identify", "status": "TOOL_MISSING",
            "required_capability": "Detect It Easy console build (diec.exe)",
            "detail": (
                "diec.exe was not found. Set the DIE_HOME environment "
                "variable to its install directory or full path (e.g. "
                r"C:\tools\die\diec.exe), or put it on PATH."
            ),
        })

    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "die_identify", "status": "PATH_REFUSED", "error": str(exc)})

    if not p.is_file():
        return _j({
            "ok": False, "tool": "die_identify", "status": "NOT_FOUND",
            "path": str(path),
        })

    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))

    cp = run_bounded_process(
        [exe, "-j", str(p)],
        timeout_seconds=timeout_seconds,
        cancellation_token=cancellation_token,
        max_output_chars=_MAX_OUTPUT_CHARS,
    )
    if cp.cancelled:
        return _j({
            "ok": False, "tool": "die_identify", "status": "CANCELLED",
            "error": "DIE_CANCELLED_PROCESS_TREE_TERMINATED",
        })
    if cp.timed_out:
        return _j({
            "ok": False, "tool": "die_identify", "status": "TIMEOUT",
            "timeout_seconds": timeout_seconds,
            "error": "DIE_TIMEOUT_PROCESS_TREE_TERMINATED",
        })
    if cp.returncode not in (0, None):
        return _j({
            "ok": False, "tool": "die_identify", "status": "ANALYSIS_LIMITED",
            "exit_code": cp.returncode,
            "stderr_tail": (cp.stderr or "")[-2000:],
            "stdout_tail": (cp.stdout or "")[-500:],
        })

    stdout = cp.stdout or ""
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end < start:
        return _j({
            "ok": False, "tool": "die_identify", "status": "ANALYSIS_LIMITED",
            "error": "DIE_NO_JSON_OUTPUT",
            "output_truncated": cp.output_truncated,
            "stdout_tail": stdout[-2000:],
            "stderr_tail": (cp.stderr or "")[-2000:],
        })

    try:
        raw = json.loads(stdout[start:end + 1])
    except Exception as exc:  # noqa: BLE001
        return _j({
            "ok": False, "tool": "die_identify", "status": "RESULT_PARSE_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "output_truncated": cp.output_truncated,
        })

    if not isinstance(raw, dict):
        return _j({
            "ok": False, "tool": "die_identify", "status": "RESULT_PARSE_FAILED",
            "error": "DIE_OUTPUT_NOT_AN_OBJECT",
        })

    raw_out = EVIDENCE / f"{p.stem}_{uuid.uuid4().hex[:8]}_die.json"
    raw_out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    try:
        _evidence_index_record_write(raw_out)
    except Exception:
        pass

    normalized = _normalize(raw)
    return _j({
        "ok": True, "tool": "die_identify", "status": "OK",
        "path": relative(p),
        **normalized,
        "internal_evidence_name": raw_out.name,
        "evidence_access": "Full unmodified diec -j JSON saved; this response is the structured, un-flattened summary of it.",
        "note": "DIE is a signature matcher, not a probabilistic classifier -- protectors[].confidence is always the literal 'signature_match' (a deterministic pattern hit), never a fabricated score. It does not perform OEP detection (see CAND-003 in docs/TOOL_GAP_BACKLOG.md).",
    })
