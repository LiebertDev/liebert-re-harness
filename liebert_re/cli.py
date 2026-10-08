"""The one command-line entrypoint: ``liebert-re <command> ...``.

Output is JSON on stdout and nothing else, so a result cannot be phrased into a
stronger claim than the payload carries. The wrapper in this file may only ADD a
``command`` key to what a module returned; it never rewrites, upgrades or drops
one, so a module's PARTIAL or TOOL_MISSING stays exactly that.

Workspace: ``--workspace DIR`` sets the sandbox root. Without it the root is the current
directory, or the target file's own directory when the target lies outside it; the
choice is echoed under the ``workspace`` key.

Exit codes
  0  the command answered (a true negative, e.g. "not packed", is an answer)
  3  structured refusal: the question is answerable, but not by this install
     (TOOL_MISSING, UNSUPPORTED, ANALYSIS_LIMITED, PATH_REFUSED, TIMEOUT, or a
     module's own NOT_FOUND / UPX_UNPACK_FAILED)
  2  bad invocation (argparse, a module's RULES_MISSING, or TOOL_USAGE from `tool`)
  1  unexpected internal failure; still JSON with status FAILED, never a traceback. Also a result the
     CLI cannot read as a success or a stated failure (status UNKNOWN: text with no fitting grammar, an
     `ok` that is not a bool, a bare `failed`/`error`, no result at all): never exit 0 for an unverified answer

`tool run` answers additionally carry ``schema_version`` ``liebert-re.tool-run/1`` and ``tool``,
``outcome`` (OK|FAILED|REFUSED|UNKNOWN), ``exit_code``, ``duration_ms``, ``payload``, ``truncated``,
``fallback_taken`` (None = not known); ``tool list`` carries ``liebert-re.tool-list/1``.

Each command imports its module lazily inside its handler, so ``identify`` does
not pay for pefile/capstone and a missing optional dependency is reported as a
TOOL_MISSING refusal instead of crashing. This file never imports
``liebert_re.dynamic.frida_trace_client``.
"""
import argparse
import ast
import functools
import importlib
import json
import os
import re
import sys
import time
from pathlib import Path

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_REFUSED = 0, 1, 2, 3

# The refusal statuses. All but PATH_REFUSED are members of the vocabulary that
# generic_static_probe.normalize_tool_result normalises against (ALLOWED_STATUSES);
# PATH_REFUSED is what die/yara/upx already emit for a workspace-containment refusal.
REFUSAL_STATUSES = frozenset({"TOOL_MISSING", "UNSUPPORTED", "ANALYSIS_LIMITED", "PATH_REFUSED", "TIMEOUT"})
# Module-specific statuses outside that vocabulary that still mean "this install
# could not answer", not "a bug".
# pe-sieve (liebert_re.tools.pe_sieve): none of these is a finding about the process. A report
# that is partial or empty is a refusal to claim "clean", and still carries whatever was found.
_MODULE_REFUSALS = frozenset({"NOT_FOUND", "UPX_UNPACK_FAILED", "PID_REQUIRED", "ACCESS_DENIED",
                              "PROCESS_NOT_OPENED", "SCANNER_MISMATCH", "NOTHING_SCANNED", "SCAN_PARTIAL",
                              # the dynamic-lab gate (liebert_re.dynamic.lab_gate): a refusal to touch a process,
                              # never a finding about it
                              "ISOLATION_REQUIRED", "AUTHORIZATION_REQUIRED", "UNKNOWN_OPERATION",
                              "PROCESS_NOT_OWNED", "OWNERSHIP_UNVERIFIABLE", "SAMPLE_HASH_REQUIRED",
                              "SAMPLE_HASH_MISMATCH", "SAMPLE_HASH_UNVERIFIABLE", "BOUNDS_REQUIRED",
                              "RESOURCE_LIMIT_UNAVAILABLE",
                              # the emulation gate (liebert_re.recover.emulate): a refusal to run, never a finding
                              "TARGET_CLASS_REQUIRED", "CLASS_CONFLICT"})
_MODULE_USAGE = frozenset({"RULES_MISSING", "TOOL_USAGE"})
# A status that says "this did not work" without being a refusal. Read as a failure (exit 1) even when the dict
# carries no ``ok``. FAILED is in the package's status vocabulary (generic_static_probe.ALLOWED_STATUSES); the
# others are the spellings a tool could use for the same thing.
_FAILURE_STATUSES = frozenset({"FAILED", "FAIL", "FAILURE", "ERROR"})
_REFUSAL_ERRORS = frozenset({"FILE_NOT_FOUND", "FILE_NOT_ACCESSIBLE"})

# The text-returning pe/disasm functions answer with a listing. A failure either is
# a structured dict (disassemble_pe) or starts with a stable machine code; the CLI
# never matches prose. Anything else must fit the command's known listing shape,
# otherwise it is an unclassifiable answer and exits 1 (see _decode).
_TEXT_LIMITED_PREFIXES = ("IMPORT_DIRECTORY_UNREADABLE", "EXPORT_DIRECTORY_UNREADABLE",
                          "DOTNET_METADATA_UNREADABLE", "DISASSEMBLY_FAILED")
_TEXT_UNSUPPORTED_PREFIXES = ("Authenticode verification requires Windows",)
# "Nothing found" is an answer, not a failure: a text that starts with this prefix is ok=true and
# carries ``empty: true`` (see _decode). Pinned equal to liebert_re.tools.binary.EMPTY_RESULT_PREFIX.
_TEXT_EMPTY_PREFIX = "EMPTY_RESULT: "
# The end-of-list line liebert_re.workspace._limit_marker writes for a listing cut at its cap.
# Anchored and numeric on purpose: only this exact form is read as "truncated", nothing looser.
_TRUNCATION_MARKER = r"\[limit:(\d+); truncated=true; returned=(\d+); total=(\d+|unknown \(more exist\))\]"
_MARKER = rf"\[(?:limit:\d+|[A-Z_]+: .*)\]|{_TRUNCATION_MARKER}"
# command/mode -> regex every line of a successful text answer must match.
_TEXT_SHAPES = {
    "imports": re.compile(rf"(?:\S+!.+ @IAT 0x[0-9a-f]+|EMPTY_RESULT: No import table\.|EMPTY_RESULT: No matches\.|{_MARKER})"),
    "exports": re.compile(rf"(?:.+ RVA=0x[0-9a-f]+ ordinal=\d+|EMPTY_RESULT: No export table\.|{_MARKER})"),
    "disasm": re.compile(rf"(?:0x[0-9A-F]+: .+|{_MARKER})"),
}


# The read-only operations liebert_re.tools.ida accepts. Kept here because this
# file imports each tool lazily; tests/test_tools_ida.py pins the two lists equal.
_IDA_OPERATIONS = ("summary", "list_functions", "segments", "function_at_address",
                   "decompile_function", "xrefs_to", "imports_exports", "strings",
                   "read_bytes", "xrefs_from", "callers_of_import",
                   "disasm_range", "basic_blocks", "callgraph", "stack_frame", "local_variables",
                   "find_bytes", "find_immediate", "list_structs", "get_struct", "flirt_signatures")
# The microcode maturity levels ida_microcode_cfg accepts (same lazy-import reason; pinned by the same test file).
_IDA_MATURITIES = ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", "MMAT_CALLS",
                   "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3", "MMAT_LVARS")


def _classify_tool_text(tool, raw):
    """The fields for a `tool run` plain-text answer (see TEXT_GRAMMARS)."""
    from liebert_re.cli_text_grammars import TEXT_GRAMMARS  # lazy: the module imports this one's constants
    grammar = TEXT_GRAMMARS.get(tool)
    if grammar:
        for prefix, status in grammar["failures"]:
            if raw.startswith(prefix):
                return {"ok": False, "status": status, "classified": True}
        truncation = _truncation(raw)
        if truncation == "INCONSISTENT":
            return {"ok": False, "status": "FAILED", "error": "UNCLASSIFIED_OUTPUT", "classified": False,
                    "message": "The listing's truncation marker contradicts itself, so it is not trusted."}
        extras = grammar["success"](raw) if grammar["success"] else None
        if extras is not None:
            if truncation and "truncation" not in extras:
                extras = {**extras, "truncation": truncation}
            return {"ok": True, "status": "OK", "classified": True, **extras}
    why = ("does not fit the grammar declared for this tool" if grammar
           else "comes from a tool with no declared text grammar")
    return {"ok": False, "status": "UNKNOWN", "error": "UNCLASSIFIED_OUTPUT", "classified": False,
            "message": f"The tool returned text that {why}, with no known failure code. The CLI cannot tell an answer "
                       "from a failure written as prose, so it does not call it a success; read text."}


RUN_SCHEMA = "liebert-re.tool-run/1"
LIST_SCHEMA = "liebert-re.tool-list/1"


def _outcome(payload, code):
    """Coarse, closed vocabulary for ``tool run``: OK | FAILED | REFUSED | UNKNOWN. The module's own ``status`` is
    left untouched next to it. UNKNOWN is "could not be classified", which is neither an answer nor a failure."""
    if payload is None or (isinstance(payload, dict) and (payload.get("error") in ("UNCLASSIFIED_OUTPUT", "NO_RESULT")
                                                           or str(payload.get("status") or "").upper() == "UNKNOWN")):
        return "UNKNOWN"
    if code == EXIT_OK:
        return "OK"
    if code in (EXIT_REFUSED, EXIT_USAGE):
        return "REFUSED"
    if isinstance(payload, dict) and payload.get("ok") is not False \
            and str(payload.get("status") or "").upper() not in _FAILURE_STATUSES and _dict_unreadable(payload):
        return "UNKNOWN"  # a dict the CLI could not read as success or as a stated failure
    return "FAILED"


def _run_fields(run, payload, code):
    """The versioned `tool run` fields. Nothing host-specific goes in: no argv, no paths, only the tool name.

    ``truncated`` and ``fallback_taken`` are True/False only when the result states them (the listing's own
    truncation marker, or a boolean the module returned under that key); otherwise None, i.e. not known."""
    is_dict = isinstance(payload, dict)
    is_text = is_dict and payload.get("result_format") == "text"
    truncation = payload.get("truncation") if is_text else None
    if isinstance(truncation, dict):
        truncated = True
    elif is_dict and isinstance(payload.get("truncated"), bool):
        truncated = payload["truncated"]
    else:
        truncated = None
    fallback = payload.get("fallback_taken") if is_dict and isinstance(payload.get("fallback_taken"), bool) else None
    fields = {"schema_version": RUN_SCHEMA, "tool": run["tool"], "outcome": _outcome(payload, code), "exit_code": code,
              "duration_ms": int((time.monotonic() - run["t0"]) * 1000),
              "payload": payload if run.get("structured") and not is_text else None,
              "truncated": truncated, "fallback_taken": fallback}
    if is_text:
        fields["text"] = payload.get("text")
    return fields


def _envelope(command, payload, workspace=None, run=None, code=None):
    """Add ``command`` (and the chosen ``workspace``); never touch a key the module returned.

    For `tool run` (``run`` given) the versioned fields are added too; when the module returned a key of the same
    name with a different value, the module's whole result goes under ``module_result`` instead."""
    extra = {"workspace": workspace} if workspace else {}
    fields = _run_fields(run, payload, code) if run else {}
    if isinstance(payload, dict):
        if "command" in payload or "workspace" in payload or any(k in payload and payload[k] != v for k, v in fields.items()):
            return {"command": command, **fields, **extra, "module_result": payload}
        return {"command": command, **fields, **extra, **payload}
    return {"command": command, **fields, **extra, "result": payload}


def _no_result():
    return {"ok": False, "status": "UNKNOWN", "error": "NO_RESULT",
            "message": "The command returned no result (None or JSON null); that is not an answer."}


def _decode(raw, shape=None, tool=None):
    """Module return value -> JSON-able. Text that is not JSON is carried verbatim.

    ``tool`` is set by ``tool run`` only: the text is then the answer of a registry tool, wrapped
    in the generic envelope ``{"tool": name, "text": ...}`` with no per-tool shape. Such a text has
    per-tool shape of ``_TEXT_SHAPES``. It is a success only if the tool declares a grammar in
    ``TEXT_GRAMMARS`` and the text fits it (``classified: true``); a failure is recognised by a status
    prefix (``_TEXT_UNSUPPORTED_PREFIXES``, ``_TEXT_LIMITED_PREFIXES``) or a failure prefix the tool's
    grammar lists. Any other text cannot be told from a failure written as prose, so it is
    ``ok: false``, ``status: "UNKNOWN"``, ``error: "UNCLASSIFIED_OUTPUT"``, ``classified: false``
    (exit 1), with the text still carried verbatim: never a silent success.

    Empty result rule: a text that starts with ``_TEXT_EMPTY_PREFIX`` (``"EMPTY_RESULT: "`` followed
    by the tool's own sentence, e.g. ``EMPTY_RESULT: No strings found.``) is a genuine "nothing
    found" answer. It is not a failure: ``ok: true``, ``status: "OK"`` and the extra field
    ``empty: true``. ``empty`` is present only when true; its absence means the text was not
    stated as empty, not that it is non-empty.

    Text is an answer only if it carries a known failure code or every line fits
    ``shape``; otherwise it is an unclassifiable result and becomes a FAILED
    payload (exit 1), never a silent success.

    Contract: a text result always carries ``ok``. ``ok: true`` means the text passed the shape
    check (complete, or cut at its cap with ``truncation`` saying so); ``ok: false`` means it did
    not. The two known-code answers (UNSUPPORTED, ANALYSIS_LIMITED) are not successes: they carry
    ``ok: false`` plus their ``status``, and ``_exit_code`` maps both statuses to EXIT_REFUSED (3)
    before it looks at ``ok``, so adding ``ok`` changes no exit code. Absence of ``ok`` is not a state."""
    if not isinstance(raw, str):
        return raw if raw is not None else _no_result()
    try:
        parsed = json.loads(raw)
        return parsed if parsed is not None else _no_result()
    except ValueError:
        pass
    out = {"result_format": "text", "text": raw}
    if tool is not None:
        out = {"tool": tool, **out}
    if raw.startswith(_TEXT_UNSUPPORTED_PREFIXES):
        out.update(ok=False, status="UNSUPPORTED")
    elif raw.startswith(_TEXT_LIMITED_PREFIXES):
        out.update(ok=False, status="ANALYSIS_LIMITED")
    elif tool is not None:
        out.update(_classify_tool_text(tool, raw))
    elif shape is None or not all(shape.fullmatch(line) for line in raw.splitlines() if line):
        out.update(ok=False, status="FAILED", error="UNCLASSIFIED_OUTPUT",
                   message="The command returned text the CLI cannot classify as an answer or a known failure.")
    else:
        truncation = _truncation(raw)
        if truncation == "INCONSISTENT":
            out.update(ok=False, status="FAILED", error="UNCLASSIFIED_OUTPUT",
                       message="The listing's truncation marker contradicts itself, so it is not trusted.")
        elif truncation:
            # A listing cut at its cap is a correct answer that says so: success, with the cut made
            # visible as data (not only as the last line of text). Exit 0.
            out.update(ok=True, status="OK", truncation=truncation)
        else:
            out.update(ok=True, status="OK")
        if out["ok"] and raw.startswith(_TEXT_EMPTY_PREFIX):
            out["empty"] = True
    if tool is not None and out.get("status") in ("UNSUPPORTED", "ANALYSIS_LIMITED"):
        out.setdefault("classified", True)  # a recognised failure code
    return out


def _truncation(raw):
    """The structured form of a listing's truncation marker, None if it has none, or
    ``"INCONSISTENT"`` if the marker's own numbers contradict each other."""
    for line in raw.splitlines():
        m = re.fullmatch(_TRUNCATION_MARKER, line)
        if not m:
            continue
        limit, returned = int(m.group(1)), int(m.group(2))
        total = None if m.group(3).startswith("unknown") else int(m.group(3))
        if returned > limit or (total is not None and total < returned):
            return "INCONSISTENT"
        return {"truncated": True, "limit": limit, "returned": returned, "total": total,
                "omitted": None if total is None else total - returned}
    return None


def _dict_unreadable(payload):
    """True when a dict result is neither a success nor a stated failure the CLI recognises.

    A dict may carry no ``ok`` and no ``status`` at all (``hash_file`` returns only its digests; that is a
    structured answer and stays one). What it may not do is say something the CLI cannot read: an ``ok`` that is
    not a bool, ``ok: true`` next to ``failed: true``, or a bare ``failed: true`` / non-empty ``error`` with no
    ``ok`` to say what it means."""
    if "ok" in payload:
        ok = payload["ok"]
        return not isinstance(ok, bool) or (ok and payload.get("failed") is True)
    return payload.get("failed") is True or bool(payload.get("error"))


def _exit_code(payload):
    if payload is None:
        return EXIT_FAILED  # no result at all is not an answer (a tool that returned None, or JSON null)
    if not isinstance(payload, dict):
        return EXIT_OK
    status = str(payload.get("status") or "").upper()
    if status in REFUSAL_STATUSES or status in _MODULE_REFUSALS:
        return EXIT_REFUSED
    if status in _MODULE_USAGE:
        return EXIT_USAGE
    if payload.get("ok") is False:
        return EXIT_REFUSED if payload.get("error") in _REFUSAL_ERRORS else EXIT_FAILED
    if status in _FAILURE_STATUSES or _dict_unreadable(payload):
        return EXIT_FAILED
    return EXIT_OK


def _emit(command, payload, workspace=None, run=None):
    code = _exit_code(payload)
    sys.stdout.write(json.dumps(_envelope(command, payload, workspace, run, code), indent=2, default=str) + "\n")
    return code


def _fail(command, status, exc, workspace=None, run=None):
    code = EXIT_REFUSED if status in REFUSAL_STATUSES else EXIT_FAILED
    body = {"ok": False, "status": status, "error_type": type(exc).__name__, "error": str(exc)}
    # `error` here is an exception's message and may carry a host path: it stays in the legacy keys only, never in
    # the versioned fields (which carry no payload for a CLI-made failure).
    head = {"command": command, **(_run_fields(run, body, code) if run else {}),
            **({"workspace": workspace} if workspace else {})}
    sys.stdout.write(json.dumps({**head, **body}, indent=2, default=str) + "\n")
    return code


def _load(module, name):
    return getattr(importlib.import_module(module), name)


def _identify(a):
    return _load("liebert_re.tools.formats", "file_identity")(a.path)


def _probe(a):
    return _load("liebert_re.tools.generic_static_probe", "generic_static_probe")(a.path, max_strings=a.max_strings)


def _pe(a):
    name = {"sections": "pe_sections", "imports": "pe_imports", "exports": "pe_exports",
            "resources": "pe_resources", "signature": "authenticode_signature"}[a.mode]
    return _load("liebert_re.tools.binary", name)(a.path)


def _disasm(a):
    return _load("liebert_re.tools.binary", "disassemble_pe")(a.path, va=a.va, max_instructions=a.count)


def _packer(a):
    # Scan depth is off unless asked for: the default call stays the cheap,
    # reproducible baseline, and the result echoes whichever switches were used
    # (a detection without its invocation is not reproducible).
    return _load("liebert_re.tools.die", "die_identify")(
        a.path, timeout_seconds=a.timeout,
        deep=a.deep, heuristic=a.heuristic, aggressive=a.aggressive,
        all_types=a.all_types, verbose=a.verbose, hide_unknown=a.hide_unknown,
        profiling=a.profiling, database=a.database or None,
        extra_database=a.extra_database or None, custom_database=a.custom_database or None,
    )


def _die(a):
    name = {"entropy": "die_entropy", "info": "die_file_info",
            "format_check": "die_format_check", "hashes": "die_hashes",
            "structs": "die_structures", "struct": "die_struct_raw",
            "sigdb": "die_database_info"}[a.mode]
    fn = _load("liebert_re.tools.die", name)
    if a.mode == "hashes":
        return fn(a.path, algorithm=a.algorithm or None, timeout_seconds=a.timeout)
    if a.mode == "struct":
        return fn(a.path, a.name, timeout_seconds=a.timeout)
    return fn(a.path, timeout_seconds=a.timeout)


def _die_status(a):
    return _load("liebert_re.tools.die", "die_status")()


def _capa(a):
    return _load("liebert_re.tools.capa", "capa_analyze")(
        a.path, backend=a.backend or None, file_format=a.format or None,
        os_name=a.os or None, rules=a.rules or None, signatures=a.signatures or None,
        tag=a.tag or None, restrict_to_functions=a.functions or None,
        timeout_seconds=a.timeout,
    )


def _capa_status(a):
    return _load("liebert_re.tools.capa", "capa_status")()


def _rzbin(a):
    name = {"imports": "rz_bin_imports", "sections": "rz_bin_sections",
            "headers": "rz_bin_headers", "relocations": "rz_bin_relocations"}[a.mode]
    return _load("liebert_re.tools.rizin", name)(a.path, timeout_seconds=a.timeout)


def _rzbin_status(a):
    return _load("liebert_re.tools.rizin", "rz_bin_status")()


def _flirt(a):
    mod = "liebert_re.tools.rizin"
    if a.sig_file:
        return _load(mod, "rizin_flirt_match_file")(a.path, a.sig_file, timeout_seconds=a.timeout)
    return _load(mod, "rizin_flirt_match")(a.path, signature_filter=a.filter, timeout_seconds=a.timeout)


def _sieve(a):
    return _load("liebert_re.tools.pe_sieve", "pe_sieve_scan")(
        a.pid, timeout_seconds=a.timeout, iat=a.iat, shellcode=a.shellcode, obfuscation=a.obfuscation,
        data=a.data, dotnet_policy=a.dotnet_policy, threads=a.threads,
        authorization=a.authorization, sample_sha256=a.sample_sha256)


def _labgate(a):
    return _load("liebert_re.dynamic.lab_gate", "dynamic_lab_gate")(
        a.operation, a.pid, authorization=a.authorization, sample_sha256=a.sample_sha256,
        guest_measurement_path=a.guest_measurement, local_vm_id=a.local_vm_id, max_age_s=a.max_age_s)


def _labregister(a):
    return _load("liebert_re.dynamic.lab_gate", "dynamic_lab_register_owned_process")(a.pid)


def _reg_assignment(text):
    name, sep, value = text.partition("=")
    if not sep or not name.strip() or not value.strip():
        raise argparse.ArgumentTypeError("expected NAME=VALUE, for example rcx=0x10")
    return name.strip(), value.strip()


def _address_int(text):
    """An address written ``0x``-hex (base 16) or plain digits (base 10, so ``010`` is ten); nothing else."""
    text = text.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
        return int(text, 16)
    if re.fullmatch(r"[0-9]+", text):
        return int(text, 10)
    raise ValueError(text)


def _mem_watch(text):
    """``START:END[:r|w|rw]`` (END exclusive) into a memory_watch range for ``emulate_range``."""
    parts = text.split(":")
    access = {"r": "read", "w": "write", "rw": "both"}
    if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] not in access):
        raise argparse.ArgumentTypeError("expected START:END or START:END:r|w|rw, for example 0x140002000:0x140002100:w")
    try:
        start, end = _address_int(parts[0]), _address_int(parts[1])
    except ValueError:
        raise argparse.ArgumentTypeError("START and END must be integers: 0x-prefixed hex, otherwise decimal "
                                         "(a leading zero does not mean octal)") from None
    return {"start": start, "end": end, "access": access[parts[2]] if len(parts) == 3 else "both"}


def _emulate_inputs(a):
    """``(keyword arguments for emulate_range, None)`` or ``(None, usage answer)`` from the input flags.

    ``--input-file`` and ``--variants-file`` are read through the workspace sandbox and refused above the
    input size bound before they are read; a variants file holds one hex buffer per line, a blank line is an
    error (not an empty buffer)."""
    emulate = importlib.import_module("liebert_re.recover.emulate")

    def usage(message):
        return None, {"ok": False, "status": "TOOL_USAGE", "error": "BAD_INPUT", "message": message}

    def read(path, limit):
        target = _load("liebert_re.workspace", "safe_path")(path)
        if not target.is_file():
            raise ValueError("%s is not a file" % path)
        if target.stat().st_size > limit:
            raise ValueError("%s is larger than %d bytes" % (path, limit))
        return target.read_bytes()

    given = [name for name, value in (("--input-hex", a.input_hex), ("--input-file", a.input_file),
                                      ("--variants-file", a.variants_file)) if value is not None]
    if not given:
        if a.input_at is not None or a.total_timeout is not None:
            return usage("--input-at and --total-timeout need --input-hex, --input-file or --variants-file")
        return {}, None
    if len(given) > 1:
        return usage("give one of --input-hex, --input-file, --variants-file (got %s)" % ", ".join(given))
    kwargs = {"input_at": a.input_at, "total_timeout_s": a.total_timeout}
    try:
        if a.input_hex is not None:
            kwargs["input_data"] = a.input_hex
        elif a.input_file is not None:
            kwargs["input_data"] = read(a.input_file, emulate.MAX_INPUT_BYTES)
        else:
            lines = read(a.variants_file, 2 * emulate.MAX_VARIANT_INPUT_BYTES + 4096).decode("ascii").splitlines()
            if any(not line.strip() for line in lines):
                return usage("--variants-file has a blank line; every line is one hex buffer")
            kwargs["input_variants"] = [line.strip() for line in lines]
    except PermissionError:
        raise
    except UnicodeDecodeError:
        return usage("the variants file is not ASCII hex")
    except ValueError as exc:
        return usage(str(exc))
    except OSError as exc:
        return usage("the input could not be read (%s)" % type(exc).__name__)
    return kwargs, None


def _emulate(a):
    inputs, refused = _emulate_inputs(a)
    if refused is not None:
        return refused
    authorization = None
    if a.authorized_by or a.purpose:
        authorization = {"authorized_by": a.authorized_by, "purpose": a.purpose, "sample_sha256": a.sha256}
    stub_options = {}
    if a.stub_tick_count is not None:
        stub_options["tick_count"] = a.stub_tick_count
    if a.stub_heap_bytes is not None:
        stub_options["heap_bytes"] = a.stub_heap_bytes
    return _load("liebert_re.recover.emulate", "emulate_range")(
        a.path, a.start, stop_at=a.stop_at or (), max_instructions=a.max_instructions, timeout_s=a.timeout,
        watch_writes=a.watch_writes, registers=dict(a.reg) or None, perm_mode=a.perm_mode,
        target_class=a.target_class, authorization=authorization, sample_sha256=a.sha256,
        allow_stubs=a.allow_stub or None, stub_options=stub_options or None,
        memory_watch=a.mem_watch or None, memory_watch_limit=a.mem_watch_limit, **inputs)


def _sieve_status(a):
    return _load("liebert_re.tools.pe_sieve", "pe_sieve_status")()


def _yara_x_status(a):
    return _load("liebert_re.tools.yara_x", "yara_x_status")()


def _upx_status(a):
    return _load("liebert_re.tools.upx", "upx_status")()


def _il2cpp_status(a):
    return _load("liebert_re.tools.il2cpp", "il2cpp_status")()


def _dex_status(a):
    return _load("liebert_re.tools.dex", "dex_status")()


def _jvm_status(a):
    return _load("liebert_re.tools.jvm", "jvm_status")()


def _flirt_inventory(a):
    return _load("liebert_re.tools.rizin", "rizin_flirt_inventory")(timeout_seconds=a.timeout)


def _unpack(a):
    return _load("liebert_re.tools.upx", "upx_unpack")(a.path, timeout_seconds=a.timeout)


def _scan(a):
    return _load("liebert_re.tools.yara_x", "yara_x_scan")(a.path, rules_path=a.rules)


def _resolve_for_report(raw):
    """Resolve ``raw`` (``..`` and links followed) and say where it landed. Never refuses: a dump
    and its PE in different directories is normal, so OUTSIDE_WORKSPACE is information. Returns
    (path_to_use, {"resolved", "scope"}); the path shown is workspace-relative when inside, else
    abbreviated by the same helper the Ghidra wrapper uses so no home or user name is exposed."""
    try:
        real = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return raw, {"resolved": None, "scope": "UNRESOLVABLE"}
    root = _current_root()
    if root is None:
        return str(real), {"resolved": None, "scope": "UNRESOLVABLE"}
    try:
        shown = real.relative_to(Path(root).resolve()).as_posix()
        return str(real), {"resolved": shown, "scope": "INSIDE_WORKSPACE"}
    except ValueError:
        shown = _load("liebert_re.tools.ghidra", "_shown_path")(real, 3)
        return str(real), {"resolved": shown, "scope": "OUTSIDE_WORKSPACE"}


def _minidump(a):
    resolution = {}
    paths = {}
    for key, raw in (("path", a.path), ("pe", a.pe), ("pdb", a.pdb)):
        if raw:
            paths[key], resolution[key] = _resolve_for_report(raw)
        else:
            paths[key] = raw
    report = _load("liebert_re.recover.minidump_analyzer", "analyze_minidump")(
        paths["path"], pe_path=paths["pe"], pdb_path=paths["pdb"])
    if isinstance(report, dict):
        report["path_resolution"] = resolution
    return report


def _ida(a):
    return _load("liebert_re.tools.ida", "ida_query")(
        a.path, operation=a.operation, query=a.query, max_results=a.max_results,
        offset=a.offset, timeout_seconds=a.timeout, max_chars=a.max_chars, backend=a.backend,
    )


def _ida_script(a):
    # The gate (LIEBERT_RE_IDA_SCRIPT) is checked by ida_script itself, before anything else. The script file is
    # read through the same workspace rule as every other path argument.
    try:
        source = _load("liebert_re.workspace", "safe_path")(a.script_file).read_text(encoding="utf-8")
    except PermissionError as exc:
        return {"ok": False, "status": "PATH_REFUSED", "tool": "ida_script", "error": str(exc)}
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "status": "ANALYSIS_LIMITED", "tool": "ida_script", "error": "SCRIPT_FILE_UNREADABLE",
                "error_type": type(exc).__name__}
    return _load("liebert_re.tools.ida", "ida_script")(
        a.path, source, timeout_seconds=a.timeout, max_result_chars=a.max_result_chars, max_chars=a.max_chars,
        backend=a.backend,
    )


def _ida_microcode(a):
    return _load("liebert_re.tools.ida", "ida_microcode_cfg")(
        a.path, a.function, maturity=a.maturity, deobfuscate=a.deobfuscate, d810_project=a.d810_project,
        max_results=a.max_results, timeout_seconds=a.timeout, max_chars=a.max_chars,
    )


def _ida_status(a):
    return _load("liebert_re.tools.ida", "ida_status")()


def _kernel_triage(a):
    return _load("liebert_re.tools.binary", "kernel_triage")(a.path)


def _kernel_dispatch(a):
    return _load("liebert_re.tools.binary", "driver_major_function_scan")(a.path, max_bytes=a.max_bytes)


def _kernel_iat(a):
    return _load("liebert_re.tools.binary", "rip_relative_iat_scan")(a.path, max_findings=a.max_findings)


def _pdata(a):
    if a.address is not None:
        return _load("liebert_re.tools.pe_unwind", "pe_function_extent")(a.path, a.address, address_kind=a.address_kind)
    return _load("liebert_re.tools.pe_unwind", "pe_runtime_functions")(a.path, max_entries=a.max_entries, offset=a.offset)


def _trailing(a):
    return _load("liebert_re.tools.pe_trailing", "pe_trailing_data")(a.path)


def _kernel_callbacks(a):
    return _load("liebert_re.tools.binary", "kernel_callback_registrations")(a.path)


def _ioctl_decode(a):
    # Integers, not a file. A token that is not an integer literal is passed on as the string, so the
    # module reports NOT_AN_INTEGER itself; the CLI does not rule on it.
    codes = []
    for token in a.codes:
        try:
            codes.append(int(token, 0))
        except ValueError:
            codes.append(token)
    return _load("liebert_re.tools.binary", "ioctl_control_code_decode")(codes)


def _ghidra_status(a):
    return _load("liebert_re.tools.ghidra", "ghidra_status")()


def _ghidra_facts(a):
    return _load("liebert_re.tools.ghidra", "ghidra_program_facts")(a.path, timeout_seconds=a.timeout)


def _ghidra_decompile(a):
    return _load("liebert_re.tools.ghidra", "ghidra_decompile")(
        a.path, a.function, per_function_timeout_seconds=a.function_timeout, timeout_seconds=a.timeout)


def _ida_annotations(a):
    return _load("liebert_re.tools.ida", "ida_annotations")(a.path, max_results=a.max_results, max_chars=a.max_chars)


def _capabilities(a):
    # families: the existing {family: [named, implemented]} pair, unchanged.
    # unimplemented: FAMILIES minus published_tools() per family -- the roadmap
    # entries the counts only hinted at. Listed in full (about 100 short names,
    # not worth a limit), so unimplemented_truncated is always False.
    # unimplemented_total: DISTINCT missing names ("how many tools are missing").
    # unimplemented_family_entries: sum of the per-family list lengths; a name
    # declared in several families is counted once per family there, so it is
    # larger. The per-family lists are NOT deduplicated.
    families = _load("liebert_re.report.tool_families", "FAMILIES")
    published = _load("liebert_re.report.tool_families", "published_tools")
    missing = {f: sorted(set(names) - published(f)) for f, names in families.items()}
    missing = {f: names for f, names in missing.items() if names}
    return {"families": _load("liebert_re.report.tool_families", "published_family_report")(),
            "unimplemented": missing,
            "unimplemented_total": len({n for v in missing.values() for n in v}),
            "unimplemented_family_entries": sum(len(v) for v in missing.values()),
            "unimplemented_truncated": False}


def _shape(a):
    if a.command == "tool":
        return None  # `tool run` text answers use the generic envelope (see _decode), not a per-tool shape
    return _TEXT_SHAPES.get(a.mode) if a.command == "pe" else _TEXT_SHAPES.get(a.command)


def _current_root():
    """The workspace root this process would use by default, or None if that root is
    refused as over-broad (the library fails closed on it at import)."""
    try:
        return importlib.import_module("liebert_re.workspace").WORKSPACE_ROOT
    except PermissionError:
        return None


def _select_workspace(args):
    """Return (root, source, absolute_target_or_None) for this invocation.

    ``--workspace`` wins. Otherwise the library's own default root is kept when it
    contains the target; if it does not (or that root is over-broad), the root
    becomes the target file's own parent directory, so containment still applies
    but a file on another drive is usable. The caller reports the choice."""
    if args.workspace:
        return Path(args.workspace).expanduser().resolve(), "--workspace", None
    current = _current_root()
    target = Path(args.path).expanduser()
    target = (target if target.is_absolute() else Path.cwd() / target).resolve()
    if current is not None:
        try:
            target.relative_to(current)
            return current, "default", None
        except ValueError:
            pass
    return target.parent, "target_parent", str(target)


def _apply_workspace(root):
    """Point the sandbox at ``root``; return an undo callable. Same over-broad rule as at import."""
    if not root.is_dir():
        raise NotADirectoryError(f"workspace is not a directory: {root}")
    if "liebert_re.workspace" not in sys.modules:
        # First import reads the cwd: import from inside the chosen root so an
        # over-broad cwd cannot make the library refuse before the choice applies.
        here = os.getcwd()
        os.chdir(root)
        try:
            importlib.import_module("liebert_re.workspace")
        finally:
            os.chdir(here)
    ws = sys.modules["liebert_re.workspace"]
    if ws.WORKSPACE_ROOT == root:
        return lambda: None
    if ws._is_over_broad_root(root) and not ws._acknowledged_broad():
        raise PermissionError(f"Workspace root '{root}' is over-broad; choose a narrower --workspace "
                              f"or set {ws.WORKSPACE_ACK_BROAD_ENV}=1 to acknowledge broad access.")
    prev = (ws.WORKSPACE_ROOT, ws.WORKSPACE)
    ws.WORKSPACE_ROOT = ws.WORKSPACE = root

    def undo():
        ws.WORKSPACE_ROOT, ws.WORKSPACE = prev
    return undo


# Generic dispatcher: `tool list | describe | run`. Names and modules come from
# liebert_re.report.tool_families (a source scan); signatures are read with ast, so `describe` (and every
# check before the call) never imports the tool's module and optional dependencies stay unloaded.
# Never accepted here: destinations a tool would write to, and a live Python object JSON cannot carry.
# A tool whose docstring declares `CLI: python-only: <reason>` is answered UNSUPPORTED with that reason.
_TOOL_REFUSED_PARAMS = frozenset({"dest_path", "destination", "output_path", "backup_path", "cancellation_token"})
_TOOL_KINDS = ("positional_or_keyword", "keyword_only")


def _tool_usage(code, message, **more):
    return {"ok": False, "status": "TOOL_USAGE", "error": code, "message": message, **more}


@functools.lru_cache(maxsize=1)
def _tool_registry():
    return (_load("liebert_re.report.tool_families", "tool_modules")(),
            _load("liebert_re.report.tool_families", "python_only_declarations")())


def _tool_node(module, name):
    """The top-level ``def name`` of ``module``, parsed from source (never imported); None if not found."""
    parts = module.split(".")[1:]
    base = Path(__file__).resolve().parent
    for source in (base.joinpath(*parts).with_suffix(".py"), base.joinpath(*parts, "__init__.py")):
        if source.is_file():
            tree = ast.parse(source.read_text(encoding="utf-8-sig", errors="ignore"), filename=str(source))
            return next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)
    return None


def _tool_params(node):
    """Parameters of a parsed function: name, kind, required, annotation and default (``default`` only
    when the default is a literal; ``default_source`` is always the source text, never an evaluated guess)."""
    a = node.args
    pos = a.posonlyargs + a.args
    rows = [(x, d, "positional_only" if i < len(a.posonlyargs) else "positional_or_keyword")
            for i, (x, d) in enumerate(zip(pos, [None] * (len(pos) - len(a.defaults)) + a.defaults))]
    rows += [(x, d, "keyword_only") for x, d in zip(a.kwonlyargs, a.kw_defaults)]
    out = []
    for x, d, kind in rows:
        row = {"name": x.arg, "kind": kind, "required": d is None}
        if x.annotation is not None:
            row["annotation"] = ast.unparse(x.annotation)
        if d is not None:
            row["default_source"] = ast.unparse(d)
            try:
                row["default"] = ast.literal_eval(d)
            except (ValueError, TypeError, SyntaxError):
                pass
        out.append(row)
    out += [{"name": x.arg, "kind": kind, "required": False} for kind, x in (("var_positional", a.vararg), ("var_keyword", a.kwarg)) if x]
    return out


def _is_path_param(name):
    return name in ("path", "paths") or name.endswith(("_path", "_file"))


def _tool_prepare(a):
    """Checks a `tool` invocation before the workspace is chosen. Returns a payload to emit when it is refused,
    else None. For `run` it leaves the parsed kwargs on ``a`` and, if a path argument is given, sets
    ``a.path``/``a.needs_file`` so main() applies the same workspace rules as every other command."""
    if a.tool_command == "list":
        return None
    modules, declared = _tool_registry()
    if a.name not in modules:
        return _tool_usage("UNKNOWN_TOOL", f"no published tool named {a.name!r}; `tool list` shows them")
    if a.tool_command == "describe":
        return None
    if a.name in declared:
        return {"ok": False, "status": "UNSUPPORTED", "error": "PYTHON_ONLY", "tool": a.name, "reason": declared[a.name]}
    try:
        kwargs = json.loads(a.args)
    except ValueError as exc:
        return _tool_usage("BAD_ARGS_JSON", f"--args is not valid JSON: {exc}")
    if not isinstance(kwargs, dict):
        return _tool_usage("ARGS_NOT_OBJECT", "--args must be a JSON object of keyword arguments")
    node = _tool_node(modules[a.name], a.name)
    if node is None:
        return {"ok": False, "status": "FAILED", "error": "SIGNATURE_UNREADABLE", "tool": a.name, "module": modules[a.name]}
    if isinstance(node, ast.AsyncFunctionDef):
        return {"ok": False, "status": "UNSUPPORTED", "error": "ASYNC_TOOL", "tool": a.name,
                "reason": "an async function; the generic path does not run an event loop"}
    params = _tool_params(node)
    accepted = sorted(p["name"] for p in params if p["kind"] in _TOOL_KINDS)
    if not any(p["kind"] == "var_keyword" for p in params) and set(kwargs) - set(accepted):
        return _tool_usage("UNKNOWN_ARGUMENT", f"{a.name} does not take {sorted(set(kwargs) - set(accepted))}", accepted=accepted)
    if set(kwargs) & _TOOL_REFUSED_PARAMS:
        return _tool_usage("ARGUMENT_NOT_ACCEPTED", f"{sorted(set(kwargs) & _TOOL_REFUSED_PARAMS)} is never accepted by the generic "
                           "path (a write destination or a live object); use the Python API")
    missing = [p["name"] for p in params if p["required"] and p["kind"] in _TOOL_KINDS and p["name"] not in kwargs]
    if missing:
        return _tool_usage("MISSING_ARGUMENT", f"{a.name} needs {missing}", accepted=accepted)
    paths = {k: v for k, v in kwargs.items() if _is_path_param(k) and v is not None}
    for k, v in paths.items():
        if not (isinstance(v, str) or (k == "paths" and isinstance(v, list) and all(isinstance(i, str) for i in v))):
            return _tool_usage("BAD_ARGUMENT_TYPE", f"{k} must be a string" + (" or a list of strings" if k == "paths" else ""))
    a.tool_kwargs = kwargs
    primary = next((k for k in sorted(paths) if isinstance(paths[k], str) and (k == "path" or k.endswith("_path"))), None)
    a.tool_primary = primary
    if primary:
        a.path, a.needs_file = paths[primary], True
    return None


class _TextAnswer(str):
    """A ``str`` a registry tool returned; tells main() to apply the generic text envelope."""


def _tool(a):
    modules, declared = _tool_registry()
    if a.tool_command == "list":
        return {"schema_version": LIST_SCHEMA, "ok": True, "status": "OK", "count": len(modules),
                "tools": [{"name": n, "module": m, "python_only": declared.get(n)} for n, m in sorted(modules.items())]}
    if a.tool_command == "describe":
        node = _tool_node(modules[a.name], a.name)
        if node is None:
            return {"ok": False, "status": "FAILED", "error": "SIGNATURE_UNREADABLE", "tool": a.name, "module": modules[a.name]}
        summary = " ".join((ast.get_docstring(node) or "").split("\n\n")[0].split())
        return {"ok": True, "status": "OK", "tool": a.name, "module": modules[a.name], "python_only": declared.get(a.name),
                "async": isinstance(node, ast.AsyncFunctionDef), "summary": summary or None, "parameters": _tool_params(node)}
    kwargs = dict(a.tool_kwargs)
    if a.tool_primary:
        kwargs[a.tool_primary] = a.path  # main() may have made it absolute when the target lies outside the root
    safe_path = _load("liebert_re.workspace", "safe_path")
    for key, value in kwargs.items():
        if _is_path_param(key) and value is not None:
            for item in value if isinstance(value, list) else [value]:
                safe_path(item)  # PermissionError -> PATH_REFUSED, before the tool's module is imported
    result = _load(modules[a.name], a.name)(**kwargs)
    if isinstance(result, (bytes, bytearray)):
        try:
            result = bytes(result).decode("utf-8")
        except UnicodeDecodeError:
            return {"ok": False, "status": "FAILED", "error": "BINARY_OUTPUT", "tool": a.name,
                    "message": "the tool returned bytes that are not UTF-8 text; use the Python API"}
    return _TextAnswer(result) if isinstance(result, str) else result


def _gate_args(sp):
    sp.add_argument("--authorization", default=None, metavar="JSON",
                    help='JSON object {"authorized_by","purpose","operations":[...],"pids":[...]}; also needs '
                         'LIEBERT_RE_DYNAMIC_LAB=authorized in the environment. Default: closed')
    sp.add_argument("--sample-sha256", dest="sample_sha256", default=None, help="declared sha256 of the target process image")


def _build_parser():
    from liebert_re import __version__
    p = argparse.ArgumentParser(prog="liebert-re", description="Static reverse-engineering analysis. JSON output only.")
    p.add_argument("--version", action="version", version=f"liebert-re {__version__}")
    p.add_argument("--workspace", metavar="DIR", default=None,
                   help="workspace root for this invocation (default: the current directory, or the "
                        "target file's own directory when the target lies outside it)")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name, fn, help_, path=True):
        sp = sub.add_parser(name, help=help_, description=help_)
        if path:
            sp.add_argument("path", help="file to analyse (must be inside the workspace root; see --workspace)")
        sp.set_defaults(handler=fn, needs_file=path)
        return sp

    add("identify", _identify, "identify a file's format")
    add("probe", _probe, "generic static probe").add_argument("--max-strings", type=int, default=200)
    sp = add("pe", _pe, "inspect a PE (choose exactly one mode)")
    g = sp.add_mutually_exclusive_group(required=True)
    for m in ("sections", "imports", "exports", "resources", "signature"):
        g.add_argument(f"--{m}", dest="mode", action="store_const", const=m)
    sp = add("disasm", _disasm, "disassemble a PE at a virtual address")
    sp.add_argument("--va", required=True, help="virtual address, decimal or 0x-hex")
    sp.add_argument("--count", type=int, default=250, help="maximum instructions")
    sp = add("packer", _packer, "identify packers/protectors (Detect It Easy)")
    sp.add_argument("--timeout", type=int, default=60)
    # Scan-depth switches, straight through to diec. --heuristic is the one that
    # can flag a packer with no signature of its own, the common case for an
    # in-house protector.
    for flag, dest, helptext in (
        ("--deep", "deep", "diec -d: thorough analysis"),
        ("--heuristic", "heuristic", "diec -u: heuristic scan; finds unsignatured packers"),
        ("--aggressive", "aggressive", "diec -g: aggressive scan"),
        ("--all-types", "all_types", "diec -a: do not stop at the primary file type"),
        ("--verbose", "verbose", "diec -b: detailed per-match information"),
        ("--hide-unknown", "hide_unknown", "diec -U: omit unknown file types"),
        ("--profiling", "profiling", "diec -l: profile signatures during the scan"),
    ):
        sp.add_argument(flag, dest=dest, action="store_true", help=helptext)
    for flag, dest, helptext in (
        ("--database", "database", "diec -D: main signature database path"),
        ("--extra-database", "extra_database", "diec -E: extra signature database path"),
        ("--custom-database", "custom_database", "diec -C: custom signature database path"),
    ):
        sp.add_argument(flag, dest=dest, default="", metavar="DIR", help=helptext)
    sp = add("die", _die, "the rest of Detect It Easy's file readers (choose exactly one mode)")
    sp.add_argument("--timeout", type=int, default=60)
    sp.add_argument("--algorithm", default="", metavar="ALGO", help="--hashes only: one of DIE's names (MD5, SHA256, ...) instead of all")
    sp.add_argument("--name", default="", metavar="STRUCT", help="--struct only: a structure name as --structs lists it")
    g = sp.add_mutually_exclusive_group(required=True)
    for flag, mode, helptext in (
        ("--entropy", "entropy", "per-section entropy with DIE's own packed verdict"),
        ("--info", "info", "DIE's file identity block"),
        ("--format-check", "format_check", "format-anomaly warnings (a protector tell)"),
        ("--hashes", "hashes", "whole-file cryptographic hashes"),
        ("--structs", "structs", "which special structures this file supports"),
        ("--struct", "struct", "one structure by name, unparsed (needs --name)"),
        ("--sigdb", "sigdb", "which signature database answered, and its size"),
    ):
        g.add_argument(flag, dest="mode", action="store_const", const=mode, help=helptext)
    sp = add("rzbin", _rzbin, "read a binary's structure with rz-bin (choose exactly one mode)")
    sp.add_argument("--timeout", type=int, default=120, help="seconds, clamped to 10-600")
    g = sp.add_mutually_exclusive_group(required=True)
    for m in ("imports", "sections", "headers", "relocations"):
        g.add_argument(f"--{m}", dest="mode", action="store_const", const=m)
    sp = add("flirt", _flirt, "name library functions by FLIRT matching, with rizin's bundled sigdb "
                              "or one .sig/.pat file")
    sp.add_argument("--timeout", type=int, default=120, help="seconds, clamped to 10-600")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--filter", help="only signature sets whose file name contains this text (sigdb mode)")
    g.add_argument("--sig-file", help="apply this .sig or .pat file instead of the sigdb")
    sp = add("flirtinventory", _flirt_inventory, "list the signature files in rizin's sigdb, by format/arch/bits",
             path=False)
    sp.add_argument("--timeout", type=int, default=120, help="seconds, clamped to 10-600")
    # pe-sieve: the PID is deliberately NOT an argparse-required argument. A missing or "all" PID must
    # reach the module and come back as a structured PID_REQUIRED refusal, not an argparse usage error.
    sp = add("sieve", _sieve, "scan ONE running process by PID with pe-sieve for in-memory differences from disk "
                              "(scan only: nothing is dumped; there is no all-processes mode)", path=False)
    sp.add_argument("--pid", default=None, help="process id of a process you started (required)")
    sp.add_argument("--timeout", type=int, default=120, help="seconds, clamped to 10-600")
    sp.add_argument("--iat", type=int, default=None, help="IAT hook scan 0-3 (default 1)")
    sp.add_argument("--shellcode", type=int, default=None, help="shellcode detection 0-4 (default 3)")
    sp.add_argument("--obfuscation", type=int, default=None, help="obfuscated-area detection 0-3 (default 0)")
    sp.add_argument("--data", type=int, default=None, help="non-executable page scan 0-5 (default 0)")
    sp.add_argument("--dotnet-policy", dest="dotnet_policy", type=int, default=None, help="managed-process policy 0-4 (default 0)")
    sp.add_argument("--threads", action="store_true", help="also scan thread call stacks")
    _gate_args(sp)
    sp = add("labgate", _labgate, "evaluate the dynamic-lab gate for one operation on one process and record the decision "
                                  "(reports what it verified and what it could not: isolation is verified only from a "
                                  "fresh guest measurement named with --guest-measurement)", path=False)
    sp.add_argument("--operation", default=None, help="the operation to gate, e.g. pe_sieve_scan")
    sp.add_argument("--pid", default=None, help="process id the operation would touch")
    sp.add_argument("--guest-measurement", dest="guest_measurement", default=None, metavar="FILE",
                    help="measurement JSON written by scripts/measure_guest.ps1; read only for operations that "
                         "need isolation. No environment variable or default location is used")
    sp.add_argument("--local-vm-id", dest="local_vm_id", default=None, metavar="GUID",
                    help="VM id of the machine this gate runs on; the measurement must be about that VM")
    sp.add_argument("--max-age-s", dest="max_age_s", type=float, default=900.0, metavar="SECONDS",
                    help="oldest measurement that still counts (default 900)")
    _gate_args(sp)
    sp = add("labregister", _labregister, "record that a process is a direct child of this process (harness-owned)", path=False)
    sp.add_argument("--pid", default=None, help="process id of a direct child of this process")
    add("sievestatus", _sieve_status, "report whether pe-sieve is reachable, from where, which scanner bitness and its version", path=False)
    add("rzbinstatus", _rzbin_status, "report whether rz-bin is reachable, from where, and its version", path=False)
    add("diestatus", _die_status, "report whether Detect It Easy is reachable, from where, and its version", path=False)
    add("yarastatus", _yara_x_status, "report whether YARA-X is reachable, from where, and its version", path=False)
    add("upxstatus", _upx_status, "report whether UPX is reachable, from where, and its version", path=False)
    add("il2cppstatus", _il2cpp_status, "report whether Il2CppDumper is reachable, from where, and its version", path=False)
    add("dexstatus", _dex_status, "report whether JADX (used by the DEX decompiler) is reachable, from where, and its version", path=False)
    add("jvmstatus", _jvm_status, "report whether JADX (used by the JVM decompiler) is reachable, from where, and its version", path=False)
    # capa's default backend takes MINUTES (measured 3m48s for a 1.2 MB PE), so the
    # default timeout is minutes too; --functions is how to bound a run instead.
    sp = add("capa", _capa, "identify capabilities, ATT&CK techniques and MBC behaviours (capa)")
    sp.add_argument("--timeout", type=int, default=600, help="seconds; capa's default backend needs minutes")
    sp.add_argument("--backend", default="", metavar="NAME", help="capa -b; 'ida' needs a licensed IDA, 'pefile' is broken on capa 9.4.0")
    sp.add_argument("--format", default="", metavar="FMT", help="capa -f")
    sp.add_argument("--os", default="", metavar="OS", help="capa --os")
    sp.add_argument("--rules", default="", metavar="PATH", help="capa -r: rule file or directory instead of the embedded set")
    sp.add_argument("--signatures", default="", metavar="PATH", help="capa -s: .sig/.pat library-function signatures")
    sp.add_argument("--tag", default="", metavar="TAG", help="capa -t: filter on a rule meta field value")
    sp.add_argument("--functions", default="", metavar="VAS", help="capa --restrict-to-functions: comma-separated VAs, to bound the run")
    add("capastatus", _capa_status, "report whether capa is reachable, from where, its version and which backends it accepts", path=False)
    # IDA is licensed and headless here. The first look at a file pays for IDA's own analysis (the database is
    # cached by the file's SHA-256 under dataset/ida_cache/, size-capped), later calls reuse it.
    sp = add("ida", _ida, "query a binary through headless IDA Pro: functions, segments, imports, strings, xrefs, decompiled code, disassembly ranges, basic blocks, call graph, stack frame, local variables, byte and immediate search, structs, FLIRT signatures")
    sp.add_argument("--operation", default="summary", choices=_IDA_OPERATIONS, help="what to ask (default: summary)")
    sp.add_argument("--query", default="", metavar="TEXT", help="a symbol name or virtual address (function_at_address, decompile_function, xrefs_to, xrefs_from, basic_blocks, callgraph, stack_frame, local_variables), an import name (callers_of_import), a text filter (strings, list_structs), a type name (get_struct), ADDRESS SIZE / JSON {\"address\",\"size\"} (read_bytes, size 1-4096), ADDRESS COUNT / JSON {\"address\",\"count\"|\"end\"} (disasm_range, count 1-2000), a byte pattern such as \"48 8B ?? 05\" (find_bytes), a number (find_immediate); find_bytes and find_immediate also take JSON with start/end/segment, callgraph JSON {\"function\",\"depth\",\"max_nodes\"}")
    sp.add_argument("--max-results", type=int, default=200, help="1-1000")
    sp.add_argument("--offset", type=int, default=0, help="page offset for the listing operations")
    sp.add_argument("--max-chars", type=int, default=60000, help="bound on the JSON response")
    sp.add_argument("--timeout", type=int, default=180, help="seconds for the whole call, clamped to 5-600; the first analysis of a file may use all of it, the session that answers is capped at 300")
    sp.add_argument("--backend", default="auto", choices=("auto", "idat", "idalib"), help="engine that answers: idat (batch binary), idalib (the idapro package in the interpreter named by LIEBERT_RE_IDALIB_PYTHON) or auto (idalib only when that variable is set and `import idapro` works there, else idat); every answer says which was used")
    sp = add("idascript", _ida_script, "run a caller-written IDAPython script on a discarded copy of the cached IDA database and print the JSON it leaves in `result` (idalib backend only; gated: needs LIEBERT_RE_IDA_SCRIPT=authorized; NOT a sandbox)")
    sp.add_argument("--script-file", required=True, metavar="FILE", help="the IDAPython source (UTF-8, at most 64 KiB, inside the workspace); its answer is the JSON-serialisable variable `result`")
    sp.add_argument("--timeout", type=int, default=120, help="seconds for the script session, clamped to 5-300; the process tree is killed at the limit")
    sp.add_argument("--max-result-chars", type=int, default=60000, help="bound on the script's `result` as JSON text; a larger one is withheld, never cut")
    sp.add_argument("--max-chars", type=int, default=60000, help="bound on the whole JSON response; a result that does not fit is withheld, never cut")
    sp.add_argument("--backend", default="auto", choices=("auto", "idat", "idalib"), help="only idalib can run a script: idat is refused UNSUPPORTED, auto means idalib (LIEBERT_RE_IDALIB_PYTHON must name an interpreter that imports idapro)")
    sp = add("idamicrocode", _ida_microcode, "read one function's microcode from headless IDA as a control-flow graph (raw by default; --deobfuscate runs the optional d810 pass and says so)")
    sp.add_argument("--function", required=True, metavar="TEXT", help="a symbol name or a virtual address inside the function")
    sp.add_argument("--maturity", default="MMAT_LVARS", choices=_IDA_MATURITIES, help="microcode maturity level (default: MMAT_LVARS)")
    sp.add_argument("--deobfuscate", action="store_true", help="install the third-party d810 optimizer for the generation; the answer is labelled a d810 pass, lists the rules that fired and says whether the output differs from the raw microcode. Off by default")
    sp.add_argument("--d810-project", default="default_instruction_only", metavar="NAME", help="d810 project (rule set) to load with --deobfuscate")
    sp.add_argument("--max-results", type=int, default=2000, help="instructions listed, 1-5000 (block edges are always complete)")
    sp.add_argument("--max-chars", type=int, default=60000, help="bound on the JSON response")
    sp.add_argument("--timeout", type=int, default=180, help="seconds for the whole call, clamped to 5-600; the session that builds the microcode is capped at 300")
    add("idastatus", _ida_status, "report whether IDA is reachable, from where, its version and whether the decompiler initialises (runs idat once)", path=False)
    sp = add("idaannotations", _ida_annotations, "read the log of renames and comments this package recorded for a file's content (a plain file read: no IDA is started)")
    sp.add_argument("--max-results", type=int, default=500, help="newest entries returned, 1-5000")
    sp.add_argument("--max-chars", type=int, default=60000, help="bound on the JSON response")
    sp = add("kerneltriage", _kernel_triage, "read-only first look at a PE that might be a Windows kernel driver (driver_likelihood stays UNKNOWN unless the evidence supports more)")
    sp = add("kerneldispatch", _kernel_dispatch, "byte-pattern first pass for DriverObject->MajorFunction stores (candidates only: proves_dispatch stays false, no dispatch table is claimed)")
    sp.add_argument("--max-bytes", type=int, default=1024, help="size of the window scanned from the entry point")
    sp = add("kerneliat", _kernel_iat, "which imports are reached through RIP-relative import-table slots, and from where (read-only, no disassembler)")
    sp.add_argument("--max-findings", type=int, default=200, help="cap on returned findings; a cut is reported, not hidden")
    sp = add("pdata", _pdata, "read a 64-bit PE's RUNTIME_FUNCTION table (.pdata); with --address, the function extent containing it (no disassembler; leaf functions have no entry, so absence proves nothing)")
    sp.add_argument("--address", default=None, help="return the entry containing this address instead of the whole table")
    sp.add_argument("--address-kind", dest="address_kind", default="va", choices=("va", "rva", "file_offset"), help="representation of --address")
    sp.add_argument("--max-entries", type=int, default=1000, help="entries per page of the whole-table read; a cut is reported")
    sp.add_argument("--offset", type=int, default=0, help="first entry of the page")
    add("trailing", _trailing, "what lies past the end of a PE's last section (the overlay): offset, size, fraction of the file, and the part explained by the security directory or a COFF symbol table; the rest is reported as UNKNOWN purpose (read-only)")
    add("kernelcallbacks", _kernel_callbacks, "which kernel callback-registration imports a driver calls; NOT_FOUND speaks only for the names listed in names_checked")
    sp = add("ioctldecode", _ioctl_decode, "split CTL_CODE integers into device type, function, method and access (takes integers, not a file)", path=False)
    sp.add_argument("codes", nargs="+", metavar="CODE", help="one or more CTL_CODE integers (decimal or 0x hex); a non-integer is reported per code, not dropped")
    add("ghidrastatus", _ghidra_status, "report where Ghidra's analyzeHeadless is, its version and the Java it needs (does not launch Ghidra)", path=False)
    sp = add("ghidrafacts", _ghidra_facts, "import a file into a throwaway Ghidra project, run default analysis and report read-only facts about the program (the source file is not modified)")
    sp.add_argument("--timeout", type=int, default=300, help="seconds for the whole headless run")
    sp = add("ghidradecompile", _ghidra_decompile, "import a file into a throwaway Ghidra project, run default analysis and decompile selected functions with Ghidra's decompiler (read-only: nothing is saved; a function that does not decompile has c_code null and a reason)")
    sp.add_argument("--function", required=True, nargs="+", metavar="FUNCTION", help="one or more function addresses written 0x... or function names, at most 16; a string not written 0x... is a name")
    sp.add_argument("--function-timeout", dest="function_timeout", type=int, default=30, help="seconds for one function's decompilation (5-120)")
    sp.add_argument("--timeout", type=int, default=None, help="seconds for the whole headless run (default: 300 plus the per-function bound for each function)")
    sp = add("emulate", _emulate, "emulate a bounded range of an x86-64 PE with Unicorn in a separate process (a process boundary, not a sandbox): imports and syscalls stop the run, memory written by the code is dumped as raw bytes. Refused unless --target-class declares a public crackme or a target you own")
    sp.add_argument("--start", required=True, metavar="VA", help="address to start at, decimal or 0x-hex")
    sp.add_argument("--target-class", dest="target_class", default=None,
                    help="required: public_crackme or owned_target (anything else, or nothing, is refused). owned_target also needs --authorized-by, --purpose and --sha256")
    sp.add_argument("--authorized-by", dest="authorized_by", default=None, help="owned_target: who authorised the run")
    sp.add_argument("--purpose", default=None, help="owned_target: why")
    sp.add_argument("--sha256", default=None, help="the file's SHA-256 (required for owned_target, optional for public_crackme)")
    sp.add_argument("--stop-at", dest="stop_at", nargs="+", default=None, metavar="VA", help="stop before executing any of these addresses (at most 64)")
    sp.add_argument("--max-instructions", dest="max_instructions", type=int, default=5_000_000, help="instruction bound (1-50000000)")
    sp.add_argument("--timeout", type=float, default=120, help="seconds the emulation may run (above 0, at most 600)")
    sp.add_argument("--watch-writes", dest="watch_writes", choices=("image", "all"), default="image", help="which writes are recorded")
    sp.add_argument("--perm-mode", dest="perm_mode", choices=("as_declared", "rwx"), default="as_declared",
                    help="section permissions as declared, or all read-write-execute (an approximation, reported as one)")
    sp.add_argument("--reg", action="append", type=_reg_assignment, default=[], metavar="NAME=VALUE", help="initial register value; repeatable")
    sp.add_argument("--allow-stub", dest="allow_stub", action="append", default=[], metavar="NAME",
                    help="answer this kernel32 import with an assumed model instead of stopping at it; repeatable, off by default "
                         "(GetTickCount, GetTickCount64, GetLastError, SetLastError, VirtualAlloc, HeapAlloc, lstrlenA, lstrlenW). Every answer is an assumption and is listed in the result")
    sp.add_argument("--mem-watch", dest="mem_watch", action="append", type=_mem_watch, default=[], metavar="START:END[:rw]",
                    help="record the code's reads and/or writes (r, w or rw, default rw) that touch [START, END); repeatable (at most 16 "
                         "ranges, each at most 0x10000000 bytes, no overlap); off by default. Lands in memory_trace")
    sp.add_argument("--mem-watch-limit", dest="mem_watch_limit", type=int, default=1000, metavar="N",
                    help="most memory-trace events kept (1-10000, default 1000); past it the run continues and memory_trace_truncated is set")
    sp.add_argument("--input-hex", dest="input_hex", default=None, metavar="HEX",
                    help="one input buffer, as hex (1 to 65536 bytes), placed before the first instruction at --input-at; "
                         "only its SHA-256 and length are reported")
    sp.add_argument("--input-file", dest="input_file", default=None, metavar="FILE",
                    help="one input buffer read from a file inside the workspace (1 to 65536 bytes)")
    sp.add_argument("--variants-file", dest="variants_file", default=None, metavar="FILE",
                    help="run once per line of FILE, each line one hex buffer (at most 32 lines, 1 MiB together), each variant in a "
                         "fresh emulator so none sees another's writes; --max-instructions and --timeout apply to each variant")
    sp.add_argument("--input-at", dest="input_at", default=None, metavar="ADDR|reg:NAME",
                    help="where the input goes: a mapped writable address (0x-hex or decimal), or reg:RCX (also RDX, R8, R9, "
                         "any general register but RSP) to map a private region, write the buffer there and put its address in "
                         "that register; required with an input, and the register may not also be set with --reg")
    sp.add_argument("--total-timeout", dest="total_timeout", type=float, default=None, metavar="SECONDS",
                    help="with --variants-file: seconds all variants may take together (above 0, at most 600; default "
                         "--timeout times the variant count, capped at 600); a variant that would start after it is reported as not run")
    sp.add_argument("--stub-tick-count", dest="stub_tick_count", type=lambda t: int(t, 0), default=None, metavar="N",
                    help="the value GetTickCount / GetTickCount64 return (required when either is allowed)")
    sp.add_argument("--stub-heap-bytes", dest="stub_heap_bytes", type=lambda t: int(t, 0), default=None, metavar="N",
                    help="size of the region VirtualAlloc / HeapAlloc stubs allocate from (multiple of 0x1000, default 0x100000)")
    add("unpack", _unpack, "statically unpack a UPX-packed PE (output goes to the evidence cache)").add_argument("--timeout", type=int, default=60)
    add("scan", _scan, "scan with YARA-X rules").add_argument("--rules", required=True, help="rules file")
    sp = add("minidump", _minidump, "analyse a Windows minidump")
    sp.add_argument("--pe", default="", help="matching PE, for symbolization")
    sp.add_argument("--pdb", default="", help="matching PDB, for symbolization")
    sp = add("tool", _tool, "registry-driven access to every published tool: list, describe (signature, no import) or "
                            "run with JSON keyword arguments", path=False)
    tsub = sp.add_subparsers(dest="tool_command", required=True, metavar="ACTION")
    tsub.add_parser("list", help="every published tool: name, module, python-only reason if declared")
    tsub.add_parser("describe", help="a tool's signature and summary, read from source").add_argument("name")
    sp = tsub.add_parser("run", help="call a tool with keyword arguments given as a JSON object")
    sp.add_argument("name")
    sp.add_argument("--args", default="{}", metavar="JSON", help="JSON object of keyword arguments (default: {})")
    add("capabilities", _capabilities, "report which routed tool families this install can reach", path=False)
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)
    command = args.command
    info = None
    run = ({"tool": args.name, "t0": time.monotonic()}
           if command == "tool" and args.tool_command == "run" else None)  # versioned fields for `tool run` only
    try:
        refusal = _tool_prepare(args) if command == "tool" else None
        if refusal:
            return _emit(command, refusal, run=run)
        if args.needs_file and not os.path.exists(args.path):
            return _emit(command, {"ok": False, "status": "PATH_REFUSED", "error": "FILE_NOT_FOUND", "path": args.path}, run=run)
        undo = (lambda: None)
        if args.needs_file:
            root, source, new_path = _select_workspace(args)
            info = {"root": str(root), "source": source}
            if new_path:
                args.path = new_path
            undo = _apply_workspace(root)
        try:
            raw = args.handler(args)
            tool = args.name if isinstance(raw, _TextAnswer) else None
            return _emit(command, _decode(raw, _shape(args), tool), info, run and {**run, "structured": True})
        finally:
            undo()
    except PermissionError as exc:
        return _fail(command, "PATH_REFUSED", exc, info, run)
    except ImportError as exc:
        return _fail(command, "TOOL_MISSING", exc, info, run)
    except Exception as exc:  # noqa: BLE001 - a CLI must answer in JSON, never a traceback
        if type(exc).__name__ == "PEFormatError":
            return _fail(command, "ANALYSIS_LIMITED", exc, info, run)
        return _fail(command, "FAILED", exc, info, run)
