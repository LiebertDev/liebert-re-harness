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
  2  bad invocation (argparse, or a module's RULES_MISSING)
  1  unexpected internal failure; still JSON with status FAILED, never a traceback

Each command imports its module lazily inside its handler, so ``identify`` does
not pay for pefile/capstone and a missing optional dependency is reported as a
TOOL_MISSING refusal instead of crashing. This file never imports
``liebert_re.dynamic.frida_trace_client``.
"""
import argparse
import importlib
import json
import os
import re
import sys
from pathlib import Path

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_REFUSED = 0, 1, 2, 3

# The refusal statuses. All but PATH_REFUSED are members of the vocabulary that
# generic_static_probe.normalize_tool_result normalises against (ALLOWED_STATUSES);
# PATH_REFUSED is what die/yara/upx already emit for a workspace-containment refusal.
REFUSAL_STATUSES = frozenset({"TOOL_MISSING", "UNSUPPORTED", "ANALYSIS_LIMITED", "PATH_REFUSED", "TIMEOUT"})
# Module-specific statuses outside that vocabulary that still mean "this install
# could not answer", not "a bug".
_MODULE_REFUSALS = frozenset({"NOT_FOUND", "UPX_UNPACK_FAILED"})
_MODULE_USAGE = frozenset({"RULES_MISSING"})
_REFUSAL_ERRORS = frozenset({"FILE_NOT_FOUND", "FILE_NOT_ACCESSIBLE"})

# The text-returning pe/disasm functions answer with a listing. A failure either is
# a structured dict (disassemble_pe) or starts with a stable machine code; the CLI
# never matches prose. Anything else must fit the command's known listing shape,
# otherwise it is an unclassifiable answer and exits 1 (see _decode).
_TEXT_LIMITED_PREFIXES = ("IMPORT_DIRECTORY_UNREADABLE", "EXPORT_DIRECTORY_UNREADABLE")
_TEXT_UNSUPPORTED_PREFIXES = ("Authenticode verification requires Windows",)
_MARKER = r"\[(?:limit:\d+|[A-Z_]+: .*)\]"
# command/mode -> regex every line of a successful text answer must match.
_TEXT_SHAPES = {
    "imports": re.compile(rf"(?:\S+!.+ @IAT 0x[0-9a-f]+|No import table\.|No matches\.|{_MARKER})"),
    "exports": re.compile(rf"(?:.+ RVA=0x[0-9a-f]+ ordinal=\d+|No export table\.|{_MARKER})"),
    "disasm": re.compile(rf"(?:0x[0-9A-F]+: .+|No instruction could be decoded\.|{_MARKER})"),
}


def _envelope(command, payload, workspace=None):
    """Add ``command`` (and the chosen ``workspace``); never touch a key the module returned."""
    extra = {"workspace": workspace} if workspace else {}
    if isinstance(payload, dict):
        if "command" in payload or "workspace" in payload:
            return {"command": command, **extra, "module_result": payload}
        return {"command": command, **extra, **payload}
    return {"command": command, **extra, "result": payload}


def _decode(raw, shape=None):
    """Module return value -> JSON-able. Text that is not JSON is carried verbatim.

    Text is an answer only if it carries a known failure code or every line fits
    ``shape``; otherwise it is an unclassifiable result and becomes a FAILED
    payload (exit 1), never a silent success."""
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        pass
    out = {"result_format": "text", "text": raw}
    if raw.startswith(_TEXT_UNSUPPORTED_PREFIXES):
        out["status"] = "UNSUPPORTED"
    elif raw.startswith(_TEXT_LIMITED_PREFIXES):
        out["status"] = "ANALYSIS_LIMITED"
    elif shape is None or not all(shape.fullmatch(line) for line in raw.splitlines() if line):
        out.update(ok=False, status="FAILED", error="UNCLASSIFIED_OUTPUT",
                   message="The command returned text the CLI cannot classify as an answer or a known failure.")
    return out


def _exit_code(payload):
    if not isinstance(payload, dict):
        return EXIT_OK
    status = str(payload.get("status") or "").upper()
    if status in REFUSAL_STATUSES or status in _MODULE_REFUSALS:
        return EXIT_REFUSED
    if status in _MODULE_USAGE:
        return EXIT_USAGE
    if payload.get("ok") is False:
        return EXIT_REFUSED if payload.get("error") in _REFUSAL_ERRORS else EXIT_FAILED
    return EXIT_OK


def _emit(command, payload, workspace=None):
    sys.stdout.write(json.dumps(_envelope(command, payload, workspace), indent=2, default=str) + "\n")
    return _exit_code(payload)


def _fail(command, status, exc, workspace=None):
    body = {"command": command, **({"workspace": workspace} if workspace else {}), "ok": False, "status": status,
            "error_type": type(exc).__name__, "error": str(exc)}
    sys.stdout.write(json.dumps(body, indent=2, default=str) + "\n")
    return EXIT_REFUSED if status in REFUSAL_STATUSES else EXIT_FAILED


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


def _unpack(a):
    return _load("liebert_re.tools.upx", "upx_unpack")(a.path, timeout_seconds=a.timeout)


def _scan(a):
    return _load("liebert_re.tools.yara_x", "yara_x_scan")(a.path, rules_path=a.rules)


def _minidump(a):
    return _load("liebert_re.recover.minidump_analyzer", "analyze_minidump")(a.path, pe_path=a.pe, pdb_path=a.pdb)


def _capabilities(a):
    return {"families": _load("liebert_re.report.tool_families", "published_family_report")()}


def _shape(a):
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
    add("diestatus", _die_status, "report whether Detect It Easy is reachable, from where, and its version", path=False)
    add("unpack", _unpack, "statically unpack a UPX-packed PE (output goes to the evidence cache)").add_argument("--timeout", type=int, default=60)
    add("scan", _scan, "scan with YARA-X rules").add_argument("--rules", required=True, help="rules file")
    sp = add("minidump", _minidump, "analyse a Windows minidump")
    sp.add_argument("--pe", default="", help="matching PE, for symbolization")
    sp.add_argument("--pdb", default="", help="matching PDB, for symbolization")
    add("capabilities", _capabilities, "report which routed tool families this install can reach", path=False)
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)
    command = args.command
    info = None
    try:
        if args.needs_file and not os.path.exists(args.path):
            return _emit(command, {"ok": False, "status": "PATH_REFUSED", "error": "FILE_NOT_FOUND", "path": args.path})
        undo = (lambda: None)
        if args.needs_file:
            root, source, new_path = _select_workspace(args)
            info = {"root": str(root), "source": source}
            if new_path:
                args.path = new_path
            undo = _apply_workspace(root)
        try:
            return _emit(command, _decode(args.handler(args), _shape(args)), info)
        finally:
            undo()
    except PermissionError as exc:
        return _fail(command, "PATH_REFUSED", exc, info)
    except ImportError as exc:
        return _fail(command, "TOOL_MISSING", exc, info)
    except Exception as exc:  # noqa: BLE001 - a CLI must answer in JSON, never a traceback
        if type(exc).__name__ == "PEFormatError":
            return _fail(command, "ANALYSIS_LIMITED", exc, info)
        return _fail(command, "FAILED", exc, info)
