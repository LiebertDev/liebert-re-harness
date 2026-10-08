"""Detect It Easy (horsicq/DetectItEasy, GPL-3.0) packer/protector/compiler
identification, plus the rest of what `diec.exe` actually exposes: section
entropy with DIE's own packed/not-packed verdict, file-format identity,
format-anomaly warnings, cryptographic hashes, and which signature database
produced a detection.

The first question asked of any hard target is "what is this protected
with?" (Themida / VMProtect / Enigma / ASProtect / a layered combination /
a custom packer / nothing at all) -- picking an unpacking or bypass
approach before knowing that wastes the engagement. Protection classes and
what each implies are in `docs/PROTECTION_CLASSES.md`; what this install
can and cannot answer is in `docs/CAPABILITIES_AND_LIMITS.md`.

Deliberately a wrapper, matching upx.py's discipline: this drives DIE's own
console binary and never re-implements signature matching itself (standing
rule: never write a signature engine from scratch, wrap an existing tool).
`diec.exe` only READS the target file -- no execution of untrusted code,
the same trust model as rizin -- so this is a HOST-side static tool.

DIE is a signature MATCHER, not a probabilistic classifier: it emits no
numeric confidence score, so this module does not invent one. Every match
is a deterministic byte-pattern/heuristic hit from DIE's own database,
surfaced as `confidence: "signature_match"` rather than a fabricated
number.

**A detection is only reproducible if the invocation is known.** `diec`
changes what it finds depending on scan depth (`-d` deep, `-u` heuristic,
`-g` aggressive, `-a` all types) and on which signature database is
loaded (`-D`/`-E`/`-C`). Every result from this module therefore echoes
the exact flags used back in `scan_flags`, and `die_database_info()`
reports the loaded database and its per-format signature counts. A
"nothing found" from a plain scan and a "nothing found" from a deep
heuristic scan are different claims; the output says which one was made.

Four distinct `diec` output shapes are handled, measured against DIE 3.21
rather than assumed:

* `-j`          -> ``{"detects": [...]}``          (signature matches)
* `-j -e`       -> ``{"records": [...]}``          (per-section entropy)
* `-j -i` / `-j -S <struct>` -> ``{"data": {...}}`` (info, hashes, format check)
* `-w` / `-s`   -> plain text, *even with* `-j`    (struct list, database info)
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from liebert_re import strict_json
from liebert_re.bounded_subprocess import launch_failure, run_bounded_process
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
# A signature-matched detection list for one PE is small (a few KB on the
# samples this module was verified against). Section-entropy output scales
# with section count and stays in the same order of magnitude. Bounded well
# above both rather than left unbounded.
_MAX_OUTPUT_CHARS = 4 * 1024 * 1024

# DIE's own `type` strings (lower-cased) that answer "what packed/protected
# this" -- the question this tool exists for.
_PROTECTOR_TYPES = {"packer", "protector", "protection", "installer", "cryptor", "obfuscator"}
_COMPILER_TYPES = {"compiler"}
_LINKER_TYPES = {"linker"}

# Scan-depth switches, in the order diec documents them. Each one changes
# what a scan finds, so each is reported back in `scan_flags`.
_DEPTH_FLAGS = (
    ("deep", "-d"),            # --deepscan        thorough analysis
    ("heuristic", "-u"),       # --heuristicscan   heuristics; finds unsignatured packers
    ("aggressive", "-g"),      # --aggressivecscan
    ("all_types", "-a"),       # --alltypes        do not stop at the primary file type
    ("verbose", "-b"),         # --verbose         detailed per-match information
    ("hide_unknown", "-U"),    # --hideunknown
    ("profiling", "-l"),       # --profiling       signature profiling during the scan
)
# Database overrides, each taking a path argument.
_DATABASE_FLAGS = (
    ("database", "-D"),
    ("extra_database", "-E"),
    ("custom_database", "-C"),
)


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


def _tool_missing(tool):
    return _j({
        "ok": False, "tool": tool, "status": "TOOL_MISSING",
        "required_capability": "Detect It Easy console build (diec.exe)",
        "detail": (
            "diec.exe was not found. Set the DIE_HOME environment "
            "variable to its install directory or full path (e.g. "
            r"C:\tools\die\diec.exe), or put it on PATH."
        ),
    })


def _scan_flags(options):
    """The depth/database switches actually passed, as a reportable dict.
    Absent and false are the same thing here: the flag was not passed."""
    out = {name: True for name, _ in _DEPTH_FLAGS if options.get(name)}
    for name, _ in _DATABASE_FLAGS:
        value = options.get(name)
        if value:
            out[name] = str(value)
    return out


def _build_args(options):
    args = []
    for name, flag in _DEPTH_FLAGS:
        if options.get(name):
            args.append(flag)
    for name, flag in _DATABASE_FLAGS:
        value = options.get(name)
        if value:
            args.extend([flag, str(value)])
    return args


def _checked_path(path, tool):
    """safe_path + existence, as the two failures callers must tell apart."""
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return None, _j({"ok": False, "tool": tool, "status": "NOT_FOUND", "path": str(path)})
    return p, None


def _run(exe, argv, tool, timeout_seconds, cancellation_token):
    """One bounded diec run. Returns ``(BoundedProcessResult, None)`` or
    ``(None, json_failure_string)``. Never raises."""
    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
    cp = run_bounded_process(
        [exe, *argv],
        timeout_seconds=timeout_seconds,
        cancellation_token=cancellation_token,
        max_output_chars=_MAX_OUTPUT_CHARS,
    )
    if cp.launch_failed is True:
        return None, _j(launch_failure(cp, tool, "DIE_LAUNCH_FAILED"))
    if cp.cancelled:
        return None, _j({
            "ok": False, "tool": tool, "status": "CANCELLED",
            "error": "DIE_CANCELLED_PROCESS_TREE_TERMINATED",
        })
    if cp.timed_out:
        return None, _j({
            "ok": False, "tool": tool, "status": "TIMEOUT",
            "timeout_seconds": timeout_seconds,
            "error": "DIE_TIMEOUT_PROCESS_TREE_TERMINATED",
        })
    if cp.returncode not in (0, None):
        return None, _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "exit_code": cp.returncode,
            "stderr_tail": (cp.stderr or "")[-2000:],
            "stdout_tail": (cp.stdout or "")[-500:],
        })
    return cp, None


def _parse_json(cp, tool):
    """diec prints its JSON object to stdout, sometimes with surrounding
    noise. Returns ``(dict, None)`` or ``(None, json_failure_string)``.
    A non-object top level is a parse failure, not an empty result."""
    stdout = cp.stdout or ""
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None, _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "error": "DIE_NO_JSON_OUTPUT",
            "output_truncated": cp.output_truncated,
            "stdout_tail": stdout[-2000:],
            "stderr_tail": (cp.stderr or "")[-2000:],
        })
    try:
        raw = strict_json.loads(stdout[start:end + 1])
    except strict_json.StrictJSONError as exc:
        return None, _j({
            "ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
            "error": f"{type(exc).__name__}: {exc}", "reason": exc.reason,
            "output_truncated": cp.output_truncated,
        })
    if not isinstance(raw, dict):
        return None, _j({
            "ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
            "error": "DIE_OUTPUT_NOT_AN_OBJECT",
        })
    return raw, None


def _save_evidence(stem, suffix, raw):
    """Write the unmodified diec payload next to the other evidence and
    return its file name. Indexing failure never fails the write."""
    out = EVIDENCE / f"{stem}_{uuid.uuid4().hex[:8]}_{suffix}.json"
    try:
        out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    try:
        _evidence_index_record_write(out)
    except Exception:
        pass
    return out.name, None


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


def die_identify(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None,
                 deep=False, heuristic=False, aggressive=False, all_types=False,
                 verbose=False, hide_unknown=False, profiling=False,
                 database=None, extra_database=None, custom_database=None):
    """Identify the packer/protector/compiler/linker DIE's signature
    database recognizes in `path`, via the real `diec.exe -j`.

    Scan depth is off by default, so the default call is the cheap,
    reproducible baseline. Turn depth on deliberately:

    * `deep=True` (`-d`)        thorough analysis
    * `heuristic=True` (`-u`)   heuristics -- the switch that can flag a
                                packer with no signature of its own, which
                                is the common case for a custom or
                                in-house protector
    * `aggressive=True` (`-g`)
    * `all_types=True` (`-a`)   do not stop at the primary file type
    * `verbose=True` (`-b`)     detailed per-match information
    * `hide_unknown=True` (`-U`), `profiling=True` (`-l`)

    `database`/`extra_database`/`custom_database` map to `-D`/`-E`/`-C`
    and let a local or vendored signature set be used instead of the
    bundled one. Whatever was passed comes back in `scan_flags`, because a
    detection without its invocation is not reproducible.

    Status vocabulary matches the repo's other static-tool wrappers: OK,
    TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED (diec ran but produced no usable output), and
    RESULT_PARSE_FAILED (diec's own JSON did not parse -- a version-drift
    signal, not this tool's bug).

    `status: "OK"` with `protected: false` is a real NEGATIVE result (DIE
    looked and found no packer/protector signature at the depth used), not
    an error -- most binaries in this repo's corpora are legitimately
    unprotected.
    """
    tool = "die_identify"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    options = {
        "deep": deep, "heuristic": heuristic, "aggressive": aggressive,
        "all_types": all_types, "verbose": verbose, "hide_unknown": hide_unknown,
        "profiling": profiling, "database": database,
        "extra_database": extra_database, "custom_database": custom_database,
    }
    flags = _scan_flags(options)

    cp, fail = _run(exe, ["-j", *_build_args(options), str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail
    # `{"detects": []}` is a measured negative; a document with no `detects`
    # list at all (e.g. `{}`) is no measurement, so it must not become
    # `protected: false`.
    if not isinstance(raw.get("detects"), list):
        return _j({
            "ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
            "error": "DIE_OUTPUT_MISSING_DETECTS",
            "output_truncated": cp.output_truncated,
            "stdout_tail": (cp.stdout or "")[-500:],
        })

    evidence_name, evidence_error = _save_evidence(p.stem, "die", raw)
    normalized = _normalize(raw)
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "scan_flags": flags,
        "scan_depth": "baseline" if not flags else "extended",
        **normalized,
        "internal_evidence_name": evidence_name,
        "evidence_write_error": evidence_error,
        "evidence_access": "Full unmodified diec -j JSON saved; this response is the structured, un-flattened summary of it.",
        "note": (
            "DIE is a signature matcher, not a probabilistic classifier -- protectors[].confidence is "
            "always the literal 'signature_match' (a deterministic pattern hit), never a fabricated "
            "score. A negative result is only as strong as scan_flags: an empty protectors[] from a "
            "baseline scan does not rule out an unsignatured packer, which is what heuristic=True and "
            "die_entropy() are for. DIE does not perform OEP detection."
        ),
    })


def die_entropy(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Per-section Shannon entropy with DIE's own packed/not-packed verdict
    per region (`diec -j -e`), plus a whole-file rollup.

    This is the signature-independent half of "is this packed". A custom or
    in-house packer has no signature for `die_identify` to match, but it
    still leaves a high-entropy code section behind. DIE's own `status`
    string per region is reported verbatim and never recomputed here; the
    rollup only counts and ranks what DIE already decided.

    Status vocabulary as `die_identify`.
    """
    tool = "die_entropy"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-j", "-e", str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail

    records = raw.get("records") if isinstance(raw.get("records"), list) else []
    regions = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        regions.append({
            "name": rec.get("name"),
            "offset": rec.get("offset"),
            "size": rec.get("size"),
            "entropy": rec.get("entropy"),
            "die_status": rec.get("status"),
        })
    packed = [r for r in regions if str(r.get("die_status") or "").strip().lower() == "packed"]
    numeric = [r for r in regions if isinstance(r.get("entropy"), (int, float))]
    highest = max(numeric, key=lambda r: r["entropy"]) if numeric else None

    evidence_name, evidence_error = _save_evidence(p.stem, "die_entropy", raw)
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "region_count": len(regions),
        "regions_die_calls_packed": [r["name"] for r in packed],
        "any_region_packed": bool(packed),
        "highest_entropy_region": highest,
        "regions": regions,
        "internal_evidence_name": evidence_name,
        "evidence_write_error": evidence_error,
        "note": (
            "die_status is DIE 3.21's own per-region verdict, reported verbatim and never recomputed "
            "here. A packed verdict on a resource or compressed-data section is normal and is not by "
            "itself evidence the executable is packed; a packed verdict on the primary code section "
            "is the signal worth following. Entropy is a necessary, not sufficient, indicator."
        ),
    })


def die_file_info(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """DIE's own file identity block (`diec -j -i`): architecture,
    endianness, bitness, file type, subsystem/Type, MIME, target OS, size.

    A cheap first call that settles which downstream reader applies (PE64
    native vs PE32 vs a managed or interpreted container) before anything
    expensive runs. Values are DIE's, reported verbatim.
    """
    tool = "die_file_info"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-j", "-i", str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    info = data.get("Info") if isinstance(data.get("Info"), dict) else {}
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "info": info,
        "info_present": bool(info),
        "note": "Fields are DIE's own Info structure, reported verbatim. An empty info block means DIE recognised no file identity, which is itself a finding on a corrupted or non-standard container.",
    })


def die_format_check(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Format-anomaly warnings from DIE's "Check format" structure
    (`diec -j -S "Check format"`).

    Malformed or self-inconsistent header fields are a protector tell: a
    zeroed OptionalHeader.CheckSum, an impossible section layout or a size
    that disagrees with the file on disk are the kind of thing a packer
    leaves behind and a compiler does not. Each warning is reported as DIE
    wrote it; nothing is classified or scored here.
    """
    tool = "die_format_check"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-j", "-S", "Check format", str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    # DIE returns the warnings as a string-keyed map ("0", "1", ...), not a list.
    findings = [data[k] for k in sorted(data, key=lambda k: (len(k), k)) if isinstance(data[k], str)]
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "anomaly_count": len(findings),
        "anomalies": findings,
        "clean": not findings,
        "note": "Strings are DIE's own Check-format output, verbatim and unclassified. An anomaly is a lead, not a verdict: linkers and legitimate post-build tooling also leave zeroed checksums. No anomalies means DIE's checks passed, not that the file is unmodified.",
    })


def die_hashes(path, algorithm=None, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Cryptographic hashes of the whole file from DIE's Hash structure
    (`diec -j -S Hash`, or `-S Hash#<ALGO>` for one of them).

    `docs/CORPUS.md` cites samples by SHA-256 rather than redistributing
    them, so this is the call that produces a citable sample identity
    without reading the file into this process. `algorithm` accepts the
    names DIE uses (MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512).
    """
    tool = "die_hashes"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    struct = "Hash" if not algorithm else f"Hash#{str(algorithm).strip()}"
    cp, fail = _run(exe, ["-j", "-S", struct, str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    hashes = data.get("Hash") if isinstance(data.get("Hash"), dict) else {}
    if algorithm and not hashes:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "path": relative(p), "requested_struct": struct,
            "error": "DIE_RETURNED_NO_HASH_BLOCK",
            "detail": "DIE accepted the struct request but returned no Hash block; the algorithm name is probably not one this DIE build knows. die_structures() lists the structures this file supports.",
        })
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "requested_struct": struct,
        "hashes": hashes,
        "note": "Hashes cover the whole file on disk, including any appended overlay -- not the unpacked image, and not a section-wise hash.",
    })


def die_structures(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Which special structures this DIE build can report for this file
    (`diec -w`).

    `-w` prints plain text even when `-j` is passed, so this parses the
    text rather than pretending the output is JSON. The result is the
    authoritative list of names `die_struct_raw()`/`die_hashes()` may ask
    for on this file -- the answer to "what else can DIE tell me about
    this", asked of the tool instead of guessed.
    """
    tool = "die_structures"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-w", str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail

    lines = [ln.strip() for ln in (cp.stdout or "").splitlines()]
    structures = [ln for ln in lines if ln and not ln.lower().startswith("structures")]
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "structures": structures,
        "structure_count": len(structures),
        "note": "diec -w emits plain text even with -j; this list is parsed from that text. An empty list means DIE offers no special structure for this file type, not that the call failed.",
    })


def die_struct_raw(path, struct, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Any structure `die_structures()` lists, by name (`diec -j -S <name>`),
    returned as the unmodified `data` block.

    The escape hatch for structures this module has no dedicated reader
    for, so a DIE build that gains a new structure does not need a code
    change here to be usable.
    """
    tool = "die_struct_raw"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    name = str(struct or "").strip()
    if not name:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "STRUCT_NAME_REQUIRED"})

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-j", "-S", name, str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail
    raw, fail = _parse_json(cp, tool)
    if fail:
        return fail

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "requested_struct": name,
        "data": data,
        "data_present": bool(data),
        "note": "The data block is DIE's, verbatim and unparsed. An empty block means DIE knows no structure by that name for this file; die_structures() lists the valid names.",
    })


def die_database_info(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Which signature database is loaded, and how many signatures it holds
    per format (`diec -s`).

    A detection is a claim about a signature set. Two scans of the same
    file against different databases are different claims, and "DIE found
    nothing" is only as strong as the database behind it. `-s` prints plain
    text even with `-j`, so the text is parsed.
    """
    tool = "die_database_info"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    cp, fail = _run(exe, ["-s", str(p)], tool, timeout_seconds, cancellation_token)
    if fail:
        return fail

    databases = {}
    signature_counts = {}
    for ln in (cp.stdout or "").splitlines():
        stripped = ln.strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip(), value.strip()
        if ln.startswith((" ", "\t")) and value.isdigit():
            signature_counts[key] = int(value)
        elif key.lower().endswith("database"):
            databases[key] = value
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "databases": databases,
        "signature_counts": signature_counts,
        "total_signatures": sum(signature_counts.values()) if signature_counts else None,
        "note": "diec -s emits plain text even with -j; these fields are parsed from that text. Cite them alongside any negative detection: 'no protector found' means no match in THIS database at the depth used.",
    })


def die_status():
    """Whether diec is reachable, where from, and which version -- the
    capability probe to run before reporting DIE as unavailable."""
    tool = "die_status"
    exe = _die_binary()
    if not exe:
        return _tool_missing(tool)
    cp, fail = _run(exe, ["--version"], tool, _MIN_TIMEOUT_SECONDS, None)
    if fail:
        return fail
    version = (cp.stdout or "").strip().splitlines()
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "binary": exe,
        "version": version[0] if version else None,
        "resolved_by": "DIE_HOME" if os.getenv("DIE_HOME", "").strip() else "PATH",
        "operations": [
            "die_identify", "die_entropy", "die_file_info", "die_format_check",
            "die_hashes", "die_structures", "die_struct_raw", "die_database_info",
        ],
        "note": "Output shapes were measured against DIE 3.21. A different major version may change them; RESULT_PARSE_FAILED from any operation is the version-drift signal.",
    })
