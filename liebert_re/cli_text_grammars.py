"""Plain-text answer grammars for ``liebert-re tool run``.

A plain-text answer from a registry tool is a success only if its tool DECLARES a grammar in ``TEXT_GRAMMARS`` and the
text fits it; a failure is only what the tool's own code is known to emit as a failure line. Anything else is
UNKNOWN (exit 1): the CLI cannot tell an answer from a failure written as prose. Every rule was written from the
tool's code (``liebert_re/tools/binary.py``, ``liebert_re/workspace.py``), not from a guess.

A tool with no entry is either in ``UNDECLARED_TEXT_TOOLS`` or not text-capable at all;
``tests/test_cli_text_grammars.py`` makes a new text-capable tool join one of the two. This is a module of its own
(not part of ``cli.py``) so the tool names it holds are not read as ``cli.py`` naming a dedicated subcommand.

``cli._classify_tool_text`` applies these rules; this module holds only data and the pure matchers.
"""
import re

from liebert_re.cli import _TEXT_EMPTY_PREFIX, _TRUNCATION_MARKER

_OLD_LIMIT = re.compile(r"\[limit:(\d+)\]")  # workspace.list_directory / search_text: a cap with no numbers behind it
_DISASM_STOP = re.compile(r"\[ANALYSIS_LIMITED: stopped after max_instructions=(\d+); more code follows at 0x[0-9A-F]+\]")
_READ_HEADER = re.compile(r"\[.+ \| lines (\d+)-(\d+)/(\d+)\]")
_READ_MORE = re.compile(r"\[more follows: start_line=(\d+)\]")
_READ_FILES_TAIL = re.compile(_TRUNCATION_MARKER + r" the remaining paths were not read")


def _cut(limit, returned, total=None):
    return {"truncated": True, "limit": limit, "returned": returned, "total": total,
            "omitted": None if total is None else total - returned}


def _listing(line, *, empty=(), old_limit=False, disasm_stop=False):
    """Success rule for a listing: one data line per row, optionally closed by a cap marker. Returns a function
    ``text -> extras dict | None`` (``None``: does not fit). At least one data line is required; blank lines and
    any other line shape do not fit. A cap marker with numbers is checked for consistency by the caller."""
    line = re.compile(line)

    def success(raw):
        if raw in empty:
            return {"empty": True}
        rows, extras = 0, {}
        for text in raw.splitlines():
            if line.fullmatch(text):
                rows += 1
            elif re.fullmatch(_TRUNCATION_MARKER, text):
                continue
            elif old_limit and _OLD_LIMIT.fullmatch(text):
                extras["truncation"] = _cut(int(_OLD_LIMIT.fullmatch(text).group(1)), None)
            elif disasm_stop and _DISASM_STOP.fullmatch(text):
                extras["truncation"] = _cut(int(_DISASM_STOP.fullmatch(text).group(1)), None)
            else:
                return None
        if not rows:
            return None
        if "truncation" in extras:
            extras["truncation"]["returned"] = rows
        return extras
    return success


def _read_file_success(raw):
    """``workspace.read_file``: a ``[path | lines a-b/T]`` header, then one ``N: text`` row per line, then an
    optional ``[more follows: start_line=N]``. The row count must equal the range the header states. The
    ``N line(s) total.`` answer (a start line past the end) is deliberately not accepted: it cannot be told
    from a failure by form, so it stays UNKNOWN."""
    lines = raw.split("\n")
    head = _READ_HEADER.fullmatch(lines[0])
    if not head:
        return None
    start, end, total = (int(g) for g in head.groups())
    more = _READ_MORE.fullmatch(lines[-1]) if len(lines) > 1 else None
    rows = lines[1:-1] if more else lines[1:]
    if not all(re.fullmatch(r"\d+: .*", r) for r in rows) or len(rows) != max(0, end - start + 1):
        return None
    if more:
        if int(more.group(1)) != end + 1:
            return None
        return {"truncation": {"truncated": True, "limit": None, "returned": len(rows), "total": total,
                               "omitted": total - end}}
    return {}


def _read_files_success(raw):
    """``workspace.read_files``: ``read_file`` answers joined by a blank line (a row is never blank, so the split is
    exact), optionally closed by a cap marker. Every segment must be a successful read; one failed read among
    them makes the whole answer UNKNOWN rather than a success with a hidden failure."""
    segments = raw.split("\n\n")
    extras = {}
    if _READ_FILES_TAIL.fullmatch(segments[-1]):
        limit, returned, total = re.match(_TRUNCATION_MARKER, segments[-1]).groups()
        extras["truncation"] = _cut(int(limit), int(returned), None if total.startswith("unknown") else int(total))
        segments = segments[:-1]
    if not segments or not all(_read_file_success(s) is not None for s in segments):
        return None
    return extras


_EMPTY = _TEXT_EMPTY_PREFIX
TEXT_GRAMMARS = {
    "binary_strings": {"success": _listing(r"0x[0-9A-F]+ \[(?:ascii|utf16)\] .*", empty=(_EMPTY + "No strings found.",)),
                       "failures": ()},
    "find_binaries": {"success": _listing(r".+ \(\d+ bytes\)", empty=(_EMPTY + "No binary found.",)), "failures": ()},
    "search_binary_bytes": {"success": _listing(r"file_offset=0x[0-9A-F]+", empty=(_EMPTY + "No matches.",)), "failures": ()},
    # a [..._PARTIAL: ...] line (a directory that could only be read in part) fits no rule here: UNKNOWN
    "pe_imports": {"success": _listing(r"\S+!.+ @IAT 0x[0-9a-f]+", empty=(_EMPTY + "No import table.", _EMPTY + "No matches.")),
                   "failures": ()},
    "pe_exports": {"success": _listing(r".+ RVA=0x[0-9a-f]+ ordinal=\d+", empty=(_EMPTY + "No export table.",)), "failures": ()},
    # failures of disassemble_pe are structured dicts or the DISASSEMBLY_FAILED code (a generic prefix above)
    "disassemble_pe": {"success": _listing(r"0x[0-9A-F]+: .+", disasm_stop=True), "failures": ()},
    # the only failure form is the DOTNET_METADATA_UNREADABLE code (a generic prefix); a type name has no whitespace
    # here, so an obfuscated name with a space makes the listing UNKNOWN rather than being guessed at
    "dotnet_metadata": {"success": _listing(r"\S+", empty=(_EMPTY + "No CLR/.NET header present.",
                                                          _EMPTY + ".NET assembly parsed, but TypeDef table is empty.")),
                        "failures": ()},
    "list_directory": {"success": _listing(r"(?:DIR|FILE): .+", empty=("Directory is empty.",), old_limit=True),
                       "failures": (("Directory not found: ", "NOT_FOUND"),)},
    "find_files": {"success": _listing(r"(?!Directory not found: ).+", empty=("File not found.",)),
                   "failures": (("Directory not found: ", "NOT_FOUND"),)},
    "search_text": {"success": _listing(r".+:\d+: .*", empty=("No results found.",), old_limit=True),
                    "failures": (("Directory not found: ", "NOT_FOUND"),)},
    "get_file_info": {"success": None, "failures": (("Not found: ", "NOT_FOUND"),)},  # success is a JSON document
    "read_file": {"success": _read_file_success,
                  "failures": (("File not found:", "NOT_FOUND"), ("File too large (", "ANALYSIS_LIMITED"),
                               ("Binary file; use", "UNSUPPORTED"))},
    "read_files": {"success": _read_files_success, "failures": ()},
}
# Tools whose text answer has NO declared grammar: any plain text from them is UNKNOWN. These are the `-> str`
# tools that return one JSON document; a non-JSON text from them is not a form this CLI knows. The list may only
# shrink: tests/test_cli_text_grammars.py pins its size and makes a new text-capable tool join TEXT_GRAMMARS or this.
UNDECLARED_TEXT_TOOLS = frozenset({
    "api_hash_recover", "binary_version_diff", "counter_evidence_verify", "crash_symbolize",
    "cross_binary_relationship_analyze", "dotnet_il_inspect", "dotnet_metadata_inspect",
    "dotnet_relationship_analyze", "finding_report_generate", "generic_static_probe", "minidump_analyzer",
    "minidump_structural_analyze", "msf_pdb_inspect", "native_xref_analyze", "pdb_symbols",
    "rizin_disasm_listing", "rizin_flirt_inventory", "rizin_flirt_match", "rizin_flirt_match_file",
    "rizin_functions", "rizin_patch_plan", "rizin_status", "rz_bin_headers", "rz_bin_imports",
    "rz_bin_relocations", "rz_bin_sections", "rz_bin_status"})
