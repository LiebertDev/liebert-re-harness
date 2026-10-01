"""The one command-line entrypoint: ``liebert-re <command> ...``.

Output is JSON on stdout and nothing else, so a result cannot be phrased into a
stronger claim than the payload carries. The wrapper in this file may only ADD a
``command`` key to what a module returned; it never rewrites, upgrades or drops
one, so a module's PARTIAL or TOOL_MISSING stays exactly that.

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
import sys

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

# Plain-text failure markers the text-returning pe/disasm functions use.
_TEXT_LIMITED_PREFIXES = (
    "IMPORT_DIRECTORY_UNREADABLE", "EXPORT_DIRECTORY_UNREADABLE",
    "Gecersiz", "Desteklenmeyen", "Section not found.", "va ",
)
_TEXT_UNSUPPORTED_PREFIXES = ("Authenticode verification requires Windows",)


def _envelope(command, payload):
    """Add ``command``; never touch a key the module returned."""
    if isinstance(payload, dict):
        if "command" in payload:
            return {"command": command, "module_result": payload}
        return {"command": command, **payload}
    return {"command": command, "result": payload}


def _decode(raw):
    """Module return value -> JSON-able. Text that is not JSON is carried verbatim."""
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


def _emit(command, payload):
    sys.stdout.write(json.dumps(_envelope(command, payload), indent=2, default=str) + "\n")
    return _exit_code(payload)


def _fail(command, status, exc):
    body = {"command": command, "ok": False, "status": status,
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
    return _load("liebert_re.tools.die", "die_identify")(a.path, timeout_seconds=a.timeout)


def _unpack(a):
    return _load("liebert_re.tools.upx", "upx_unpack")(a.path, timeout_seconds=a.timeout)


def _scan(a):
    return _load("liebert_re.tools.yara_x", "yara_x_scan")(a.path, rules_path=a.rules)


def _minidump(a):
    return _load("liebert_re.recover.minidump_analyzer", "analyze_minidump")(a.path, pe_path=a.pe, pdb_path=a.pdb)


def _capabilities(a):
    return {"families": _load("liebert_re.report.tool_families", "published_family_report")()}


def _build_parser():
    from liebert_re import __version__
    p = argparse.ArgumentParser(prog="liebert-re", description="Static reverse-engineering analysis. JSON output only.")
    p.add_argument("--version", action="version", version=f"liebert-re {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name, fn, help_, path=True):
        sp = sub.add_parser(name, help=help_, description=help_)
        if path:
            sp.add_argument("path", help="file to analyse (must be inside the workspace root, default: current directory)")
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
    add("packer", _packer, "identify packers/protectors (Detect It Easy)").add_argument("--timeout", type=int, default=60)
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
    try:
        if args.needs_file and not os.path.exists(args.path):
            return _emit(command, {"ok": False, "status": "PATH_REFUSED", "error": "FILE_NOT_FOUND", "path": args.path})
        return _emit(command, _decode(args.handler(args)))
    except PermissionError as exc:
        return _fail(command, "PATH_REFUSED", exc)
    except ImportError as exc:
        return _fail(command, "TOOL_MISSING", exc)
    except Exception as exc:  # noqa: BLE001 - a CLI must answer in JSON, never a traceback
        if type(exc).__name__ == "PEFormatError":
            return _fail(command, "ANALYSIS_LIMITED", exc)
        return _fail(command, "FAILED", exc)
