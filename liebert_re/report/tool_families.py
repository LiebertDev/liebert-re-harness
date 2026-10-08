"""Deterministic progressive-disclosure families; no model dependency.

Tool exposure is staged and content/state driven, never extension driven:

    Stage A  — small core/discovery surface (always present)
    Stage B  — specialist family activated by artifact classification
    Stage C  — correlation / verification activated by analysis state

Keyword signals remain only as a fallback for rounds that have not yet produced
an artifact classification.  The ``.dll`` extension alone never selects the
``dotnet`` family: a PE is ``dotnet`` only when its metadata shows a CLR
directory, and ``native`` otherwise.

FAMILIES ITSELF IS AN UPSTREAM ROUTING MANIFEST, NOT A LIST OF THIS PACKAGE'S
CAPABILITIES.  It records how tool routing works across the full private
working tree this project is developed in, which is far larger than what is
published here (see README.md, "What is in this repository, and what is
not"). Most names below are not implemented anywhere in this published
package -- ``"windows-kernel"`` is the extreme case: of its 19 named tools,
only ten are defined here: the generic ``tool_missing`` sentinel,
``kernel_triage``, ``ioctl_control_code_decode``, ``ioctl_candidate_scan``,
``driver_major_function_scan``, ``rip_relative_iat_scan``,
``kernel_callback_registrations``, ``pe_runtime_functions``,
``pe_function_extent`` and ``ida_query`` (which needs a licensed IDA
present on the machine and returns a tool-missing result without one).
The two ``pe_*`` tools read a 64-bit PE's RUNTIME_FUNCTION table for exact
function extents; leaf functions have no entry, so they never give a
complete function list.
``kernel_triage`` is a first look only: it reports indicators and a
``driver_likelihood`` of LIKELY or UNKNOWN (``proves_driver`` is always
false). Three of the other four are byte-pattern searches over the image with
no disassembler, and none of them proves what it finds: ``proves_dispatch``
and ``proves_call`` are always false, and ``kernel_callback_registrations``
never recovers the callback address. ``ioctl_control_code_decode`` is not a
scan at all: it splits caller-supplied CTL_CODE integers into their bit fields
and reads no file. ``ioctl_candidate_scan`` scans a code region for compared immediates and decodes
each with that function; it proves nothing (``proves_ioctl`` is false). The
remaining nine names are roadmap. This package
therefore still cannot
analyse a kernel driver in any real depth even though the family exists and
routes for one. Do not read membership in a ``FAMILIES[...]`` set as "this
package can do that."  Call :func:`published_tools` for the subset of a
family this package can actually dispatch (a real, locally-defined function),
computed by introspection so it can never silently drift from reality the
way a hand-maintained "is this shipped" list would.

A name in a family that is not locally defined is a ROADMAP entry: it records
where the tool would route, not that it exists here. Nothing in the set marks
it, so the machine-readable form of "not implemented" is the difference
between ``FAMILIES[family]`` and :func:`published_tools` (counts per family:
:func:`published_family_report`). Measured at the time of writing, from
:func:`published_family_report` (named / locally defined): workspace 15/10,
identity 14/4, source 7/3, binary 4/4,
native 85/63, windows-kernel 19/10, dotnet 9/4, archive 2/2, android 6/6,
game-engine 11/9, network 3/3, database 2/2, structured 3/2, jvm 5/5,
webassembly 2/2, correlation 18/5, debug 9/6, web 2/2, dynamic 39/9,
crypto 7/5, emulation 6/2. Re-measure rather than trust this list.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Any

FAMILIES = {
    "workspace": {"list_directory", "find_files", "read_file", "search_text", "get_file_info", "workspace_index", "hybrid_retrieve", "evidence_index", "claim_index", "find_binaries", "get_tool_result_page", "hybrid_rag_retrieve", "project_rag_refresh", "read_files", "security_rag_search"},
    "identity": {"file_identity", "generic_static_probe", "route_file", "capability_lookup", "capability_registry_v2", "capability_gap_report", "framework_detect", "specialist_gap_report", "tool_missing", "research_plan", "tool_provision_acquire", "tool_provision_status", "opencode_ask", "opencode_status"},
    "source": {"source_inspect", "semantic_security_analyze", "deep_source_analyze", "attack_surface_map", "project_inspect", "cross_file_graph", "research_graph"},
    "binary": {"binary_summary", "binary_strings", "search_binary_bytes", "hash_file"},
    "native": {"native_inspect", "native_function_inventory", "native_xref_analyze", "binary_version_diff", "binary_security_analyze", "capa_analyze", "floss_analyze", "patch_preflight", "known_plaintext_scan", "pe_sections", "pe_imports", "pe_exports", "disassemble_pe", "disassemble_pe_structured", "ghidra_query", "ida_query", "ida_script", "ida_microcode_cfg", "ida_type_member_offset", "ida_rename_plan", "ida_annotations_apply", "ida_annotations_purge", "ida_set_comments_plan", "ida_annotations", "decompile_coverage_check", "runtime_resolved_api_recover", "resolve_incoming_parameter_source", "stack_string_recover", "upx_unpack", "cfg_deobfuscate", "vb6_inspect", "delphi_inspect", "cpp_rtti_inspect", "vb6_pcode", "analyze_obfuscation", "authenticode_signature", "plist_inspect", "analyze_tls_directory", "binary_patch", "dataflow_recover", "detection_reason_map", "decompiler_status", "die_identify", "die_entropy", "die_file_info", "die_format_check", "die_hashes", "die_structures", "die_struct_raw", "die_database_info", "die_status", "capa_status", "find_import_references", "find_code_references", "setopt_call_arguments", "find_function_by_body_shape", "functional_verification_evaluate", "ghidra_decompile", "ghidra_status", "ghidra_program_facts", "ida_disasm_listing", "ida_patch_plan", "ida_status", "pe_resources", "rizin_disasm_listing", "rizin_functions", "rizin_patch_apply", "rizin_patch_plan", "rizin_status", "rz_bin_imports", "rz_bin_sections", "rz_bin_headers", "rz_bin_relocations", "rz_bin_status", "rizin_flirt_match", "rizin_flirt_match_file", "rizin_flirt_inventory", "yara_x_scan", "yara_x_status", "upx_status", "binary_summary", "binary_strings", "pe_runtime_functions", "pe_function_extent", "pe_trailing_data"},
    "windows-kernel": {"kernel_triage", "kernel_debug_analyze", "kernel_security_analyze", "semantic_security_analyze", "native_inspect", "ghidra_query", "ida_query", "ioctl_control_code_decode", "ioctl_candidate_scan", "ioctl_code_recovery", "tool_missing", "kernel_callback_registrations", "detection_reason_map", "driver_major_function_scan", "iat_call_argument_recover", "passive_object_namespace_probe", "rip_relative_iat_scan", "pe_runtime_functions", "pe_function_extent"},
    "dotnet": {"dotnet_inspect", "dotnet_security_analyze", "dotnet_relationship_analyze", "dotnet_metadata", "decompile_dotnet", "decompiler_status", "dotnet_deobfuscate", "dotnet_il_inspect", "dotnet_metadata_inspect"},
    "archive": {"archive_inspect", "rar_7z"},
    "android": {"archive_inspect", "framework_detect", "dex_decompiler", "dex_status", "android_resource_analyzer", "tool_missing"},
    "game-engine": {"framework_detect", "archive_inspect", "native_inspect", "dotnet_inspect", "godot_asset_analyzer", "unity_asset_analyzer", "unreal_asset_analyzer", "dart_aot_recovery", "il2cpp_mapper", "il2cpp_status", "tool_missing"},
    "network": {"har_inspect", "pcap_analyzer", "tool_missing"},
    "database": {"sqlite_inspect", "structured_inspect"},
    "structured": {"structured_inspect", "log_inspect", "log_triage_inspect"},
    "jvm": {"java_class_inspect", "archive_inspect", "jvm_decompiler", "jvm_status", "tool_missing"},
    "webassembly": {"wasm_inspect", "tool_missing"},
    "correlation": {"attack_surface_map", "research_graph", "cross_binary_relationship_analyze", "counter_evidence_verify", "finding_report_generate", "attack_resistance_report", "attack_resistance_assess", "coverage_report", "exploit_validation_plan", "exploit_validation_result_verify", "claim_verify", "decompiler_fabrication_audit", "decompiler_trust_audit", "deep_security_verify", "evidence_graph_inspect", "evidence_ledger_v2", "red_finding_validate", "functional_verification_evaluate"},
    "debug": {"minidump_structural_analyze", "minidump_analyzer", "msf_pdb_inspect", "pdb_symbols", "crash_symbolize", "tool_missing", "windbg_dump_analyze", "windbg_run_commands", "windbg_symbol_status"},
    "web": {"asar_inspect", "tool_missing"},
    # Not classification-driven like the families above: none of these tools
    # analyze a target file's type, they launch/control a harness-owned
    # fixture or the operator's isolated Hyper-V (KERNEL tier) guest. They
    # activate only via explicit SIGNALS keywords (Stage C style, like
    # "correlation"), never via file_for_artifact_classification, so they
    # stay off the default surface for ordinary static-analysis sessions.
    # This family also carries every guest_*/procmon_*/windbg live-debug/
    # x64dbg live-debug/API-Monitor tool: all of them execute, attach to, or
    # otherwise touch a live process, and per this project's blanket policy
    # (tools_windbg.py/tools_x64dbg.py module docstrings -- both upstream-only; not part of the published package)
    # no such tool is
    # ever auto-invoked by file routing -- they only ever reach the model via
    # this keyword/state-driven family, never via artifact classification.
    "dynamic": {"pe_sieve_scan", "pe_sieve_status", "frida_status", "dynamic_owned_process_scan", "dynamic_owned_process_diff_scan", "isolated_dynamic_validate", "tool_missing",
                "api_catalog", "apimonitor_status", "differential_execution_validate", "dynamic_lab_gate", "dynamic_lab_register_owned_process",
                "environment_contamination_check", "guest_analyze_static", "guest_checkpoint_create",
                "guest_checkpoint_delete", "guest_checkpoint_list", "guest_checkpoint_restore",
                "guest_concurrent_watch", "guest_fetch_file", "guest_frida_breakpoint_inspect", "guest_frida_trace",
                "guest_gui_launch", "guest_key_sequence", "guest_screen_capture", "guest_thread_waits",
                "guest_watch_collect", "image_address_map", "inproc_bootstrap_plan", "isolated_artifact_analyze",
                "memory_scan", "procmon_status", "procmon_trace_start", "procmon_trace_stop", "unpack_iat_rebuild",
                "windbg_live_kernel_debug", "windbg_user_mode_live_debug", "x64dbg_script_run", "x64dbg_status"},
    # Same "not classification-driven" shape as "dynamic" above: lattice_reduce
    # takes a raw integer basis, not a target file, so it has no file-type
    # classification to key off of. lzma1_decode does take a file, but a raw
    # LZMA1 stream is an arbitrary-offset embedded blob, not a recognized
    # top-level format either -- both activate only via explicit SIGNALS
    # keywords (Stage C style), never file_for_artifact_classification.
    # constraint_solve is the same shape again: a z3 constraint system over
    # caller-declared variables, not a target file at all.
    "crypto": {"lattice_reduce", "constraint_solve", "lzma1_decode", "crypto_constant_scan", "license_check_analyze", "api_hash_recover", "tool_missing"},
    # Deliberately its own family rather than a member of "native": emulation
    # sits at the weakest evidence rung this project recognizes (see
    # tools_emulation.py), so it must not appear on the default native surface
    # beside static tools whose output IS an observed fact. It activates only
    # on an explicit emulation request, the same Stage-C shape as "dynamic"
    # and "crypto" above.
    "emulation": {"emulate_binary", "emulation_status", "emulate_range",
                  "emulation_unpack",
                  "emulate_range_status", "tool_missing"},
}


_DEF_PATTERN = re.compile(r"^(?:async )?def ([A-Za-z_][A-Za-z0-9_]*)\(", re.MULTILINE)


def _definitions_by_name(package_dir: Path) -> dict[str, list[tuple[str, Path]]]:
    """``{function name: [(module path, source file), ...]}`` for ``package_dir``.

    Scans source text for ``def <name>(`` at column 0 in every ``.py`` file
    under ``package_dir`` (excluding any file named like this module and
    ``test_*`` files). A name defined in several files lists each of them.
    The module path is relative to ``package_dir.parent``.
    """
    found: dict[str, list[tuple[str, Path]]] = {}
    for path in sorted(package_dir.rglob("*.py")):
        if path.name == Path(__file__).name or path.stem.startswith("test_"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        parts = path.relative_to(package_dir.parent).with_suffix("").parts
        module = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        for name in _DEF_PATTERN.findall(text):
            entries = found.setdefault(name, [])
            if all(existing != path for _, existing in entries):
                entries.append((module, path))
    return found


@functools.lru_cache(maxsize=1)
def _locally_defined_tool_names() -> frozenset[str]:
    """Every top-level function this package's own ``.py`` files define.

    This is the ground truth for "is a FAMILIES name actually callable
    here" -- computed by scanning source text for ``def <name>(`` in every
    sibling module (excluding this module and tests), not by importing those
    modules (several have optional native dependencies -- pefile, capstone,
    yara-x, androguard, ... -- that need not be installed just to answer
    this question) and not by a hand-maintained list (see the NATIVE_CORE_
    TOOLS/NATIVE_DEEP_TOOLS comment above for what happened the one time
    this project tried that: a hand-maintained tuple silently stopped
    tracking FAMILIES and 27 registered tools went unreachable for months).
    """
    package_dir = Path(__file__).resolve().parent.parent
    return frozenset(_definitions_by_name(package_dir))


def published_tools(family: str) -> frozenset[str]:
    """Subset of ``FAMILIES[family]`` this package can actually dispatch.

    ``FAMILIES`` records upstream routing across a much larger private tree
    (see the module docstring); most of its names have no implementation in
    this published package. This returns only the names that do -- a
    top-level function of that name is defined somewhere in this repo.
    """
    return frozenset(FAMILIES[family]) & _locally_defined_tool_names()


def published_family_report() -> dict[str, tuple[int, int]]:
    """``{family: (named_count, published_count)}`` for every family.

    A diagnostic/documentation helper: how much of each routing family this
    published package can actually reach, versus how much it merely names.
    """
    return {name: (len(tools), len(published_tools(name))) for name, tools in FAMILIES.items()}


def _published_definitions(package_dir: Path | None) -> dict[str, tuple[str, Path]]:
    """Published tool name -> its single defining (module, file); ``ValueError`` on a clash."""
    root = Path(__file__).resolve().parent.parent if package_dir is None else Path(package_dir)
    named = set().union(*FAMILIES.values())
    result: dict[str, tuple[str, Path]] = {}
    for name, entries in sorted(_definitions_by_name(root).items()):
        if name not in named:
            continue
        if len(entries) > 1:
            raise ValueError(
                f"tool {name!r} is defined in more than one module: "
                + ", ".join(sorted(module for module, _ in entries))
            )
        result[name] = entries[0]
    return result


def tool_modules(package_dir: Path | None = None) -> dict[str, str]:
    """``{published tool name: dotted module path that defines it}``.

    Same ground truth as :func:`published_tools` (source scan, no imports),
    over the union of every family. A name defined in more than one module
    raises ``ValueError`` naming the tool and the modules, never picks one.
    ``package_dir`` is for tests; the default is this package.
    """
    return {name: module for name, (module, _) in _published_definitions(package_dir).items()}


_PYTHON_ONLY_LINE = re.compile(r"^\s*CLI:\s*python-only(?![\w-])(?:\s*:\s*(.*?))?\s*$")


def python_only_declarations(package_dir: Path | None = None) -> dict[str, str]:
    """``{published tool name: reason}`` for tools declared python-only.

    A tool declares it with one docstring line ``CLI: python-only: <reason>``.
    The docstring is read with ``ast`` (the module is never imported, so
    optional dependencies are not loaded). A declaration with an empty
    reason, or more than one declaration in one docstring, raises
    ``ValueError``; a tool with no such line is simply absent.
    ``package_dir`` is for tests; the default is this package.
    """
    import ast

    declared: dict[str, str] = {}
    trees: dict[Path, ast.Module] = {}  # a file defining many tools is parsed once, not once per tool
    for name, (module, path) in _published_definitions(package_dir).items():
        try:
            if path not in trees:
                trees[path] = ast.parse(path.read_text(encoding="utf-8-sig", errors="ignore"), filename=str(path))
            tree = trees[path]
        except SyntaxError as exc:
            raise ValueError(f"cannot parse {module} to read the docstring of {name!r}: {exc}") from exc
        node = next(
            (n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name),
            None,
        )
        if node is None:
            continue
        lines = [m for m in map(_PYTHON_ONLY_LINE.match, (ast.get_docstring(node) or "").splitlines()) if m]
        if not lines:
            continue
        if len(lines) > 1:
            raise ValueError(f"tool {name!r} in {module} declares 'CLI: python-only' more than once")
        reason = (lines[0].group(1) or "").strip()
        if not reason:
            raise ValueError(f"tool {name!r} in {module} declares 'CLI: python-only' with an empty reason")
        declared[name] = reason
    return declared


BASE_FAMILIES = ("workspace", "identity", "source")

# Stage A: the small always-present core/discovery surface.
CORE_TOOLS = (
    "list_directory", "find_files", "read_file", "get_file_info",
    "file_identity", "generic_static_probe", "route_file", "hash_file",
    "capability_lookup", "tool_missing", "get_tool_result_page",
)

# Within the native family, deep tools are exposed only after structural
# analysis (sections/imports/exports) has already produced a classification.
#
# The core/deep split is a *tier* over FAMILIES["native"], not a second copy
# of it. Only the "core" side is hand-curated below (the small, always-safe
# structural surface); "deep" is everything else FAMILIES["native"] contains,
# computed live. This closes a gap a 2026-09-26 measurement found: when these
# two tuples were both hand-maintained tuples disconnected from FAMILIES,
# FAMILIES["native"] grew to 41 tools (a same-day 71-tool registration sweep)
# while NATIVE_CORE_TOOLS/NATIVE_DEEP_TOOLS stayed frozen at 7+9=16 -- so 27
# registered native tools (ida_query, ghidra_decompile, every rizin_*,
# yara_x_scan, vb6_/delphi_/cpp_rtti_ inspectors, binary_patch, upx_unpack,
# cfg_deobfuscate, etc.) were reachable via capability_lookup but could never
# be *recommended* by tools_for_state/families_for_state for a classified
# native PE, no matter how deep the analysis. Deriving NATIVE_DEEP_TOOLS from
# FAMILIES["native"] means a tool added to that family automatically starts
# flowing (as "deep") instead of silently sitting inert. Every name in
# _NATIVE_CORE_TOOL_NAMES must also be a member of FAMILIES["native"]
# (enforced by tests/test_cli_capabilities_roadmap.py,
# test_native_core_tools_are_all_in_the_native_family); binary_summary/
# binary_strings were added to FAMILIES["native"] alongside this change so
# that invariant holds without dropping them from the core native surface --
# they previously lived only in FAMILIES["binary"], which state-driven
# tools_for_state never reaches for a native classification.
_NATIVE_CORE_TOOL_NAMES = frozenset({
    "native_inspect", "binary_summary", "binary_strings", "pe_sections",
    "pe_imports", "pe_exports", "authenticode_signature",
})
NATIVE_CORE_TOOLS = tuple(sorted(_NATIVE_CORE_TOOL_NAMES))
NATIVE_DEEP_TOOLS = tuple(sorted(FAMILIES["native"] - _NATIVE_CORE_TOOL_NAMES))

# Second, orthogonal split over FAMILIES["native"]/["windows-kernel"]: schema
# auto-invocability (can this tool run given nothing but {"path": ...}?),
# needed by file_router.py's recommended_tools/targeted_tools split
# (test_file_router_targeted_tools.py). This is NOT the same axis as
# NATIVE_CORE/NATIVE_DEEP above (structural-analysis-readiness tiering) --
# e.g. ghidra_query and binary_security_analyze are "deep" by that tier yet
# are bare-path callable, so file_router.py has always recommended them
# immediately. Every name below was checked against its own function
# signature (measured 2026-09-26): *_PATH_ONLY_TOOLS take `path` and nothing
# else required; *_NOT_FILE_ROUTABLE take no `path` at all (a prior tool's
# IR/JSON, a bare status check, or a caller-declared code list) so they
# cannot appear in file_router.py's per-file output either way; everything
# else remaining in the family is schema-real but coordinate-requiring
# (an address, an API name, a byte range, patch bytes, a rule set, a second
# file, ...) and belongs in targeted_tools. Before this, file_router.py hard-
# coded its own native/windows-kernel tool lists with no link to FAMILIES at
# all, so a tool added to FAMILIES here never reached file_router.py's
# recommendations no matter how simple its schema.
_NATIVE_PATH_ONLY_TOOL_NAMES = frozenset({
    "native_inspect", "binary_summary", "binary_strings", "pe_sections",
    "pe_imports", "pe_exports", "authenticode_signature", "plist_inspect",
    "binary_security_analyze", "analyze_obfuscation", "die_identify",
    # DIE's other single-path reads: section entropy with its own packed verdict,
    # file identity, format-anomaly warnings, whole-file hashes, the per-file
    # structure list, and which signature database answered.
    "die_entropy", "die_file_info", "die_format_check", "die_hashes",
    "die_structures", "die_database_info",
    # rz-bin's structural reads: imports, sections, header fields, relocations.
    "rz_bin_imports", "rz_bin_sections", "rz_bin_headers", "rz_bin_relocations",
    # FLIRT matching through rizin's `F` commands: sigdb and single-file matching take a path.
    "rizin_flirt_match", "rizin_flirt_match_file",
    "upx_unpack", "ghidra_query", "ida_query", "vb6_inspect", "vb6_pcode",
    "delphi_inspect", "cpp_rtti_inspect", "capa_analyze", "floss_analyze",
    "patch_preflight", "known_plaintext_scan", "native_function_inventory", "rizin_functions", "disassemble_pe",
    "disassemble_pe_structured",  # same selection and defaults as disassemble_pe, dict instead of text
    "pe_resources", "analyze_tls_directory",
    # Headless import into a throwaway project; the path is the only required argument.
    "ghidra_program_facts",
    # The whole RUNTIME_FUNCTION table read needs only the path. Its sibling pe_function_extent
    # takes an address and is deliberately not here (coordinate tier).
    "pe_runtime_functions",
    # What lies past the last section: the path is the only argument, and a bare call answers.
    "pe_trailing_data",
})
NATIVE_NOT_FILE_ROUTABLE = tuple(sorted({
    "native_xref_analyze",  # consumes ir_json + observations_json, no path
    "binary_version_diff",  # consumes old_ir_json + new_ir_json, no path
    "ida_status", "rizin_status", "decompiler_status",  # backend health, zero args
    "ghidra_status",  # install, version and Java check, zero args
    "die_status",  # backend health + the operation list, zero args
    "rz_bin_status",  # backend health, zero args
    "rizin_flirt_inventory",  # lists the sigdb, zero args
    "capa_status",  # backend health + which backends capa accepts, zero args
    "yara_x_status", "upx_status",  # backend health, zero args
}))
NATIVE_PATH_ONLY_TOOLS = tuple(sorted(_NATIVE_PATH_ONLY_TOOL_NAMES))
NATIVE_COORDINATE_TOOLS = tuple(sorted(
    FAMILIES["native"] - _NATIVE_PATH_ONLY_TOOL_NAMES - set(NATIVE_NOT_FILE_ROUTABLE)
))

_WINDOWS_KERNEL_PATH_ONLY_TOOL_NAMES = frozenset({
    "kernel_triage", "kernel_security_analyze", "semantic_security_analyze",
    "native_inspect", "ghidra_query", "kernel_callback_registrations", "driver_major_function_scan",
    "ida_query",  # bare {"path": ...} works (operation defaults to "summary"); needs a licensed IDA on
        # the machine and returns a tool-missing result without one. Same schema as in the native set.
    "rip_relative_iat_scan",  # schema's only required param is "path" (a no-capstone
        # RIP-relative byte-pattern first pass), genuinely callable bare like
        # driver_major_function_scan.
    "pe_runtime_functions",  # bare {"path": ...} reads the whole table; same schema as in the native set.
})
# Deliberately NOT in the set above: pe_function_extent, whose address argument is required
# (a bare path call would be refused, the b411965 failure mode); it is a coordinate tool.
# Deliberately NOT in the set above either: ioctl_candidate_scan. Its schema requires
# only a path, so the rule would admit it, but a bare call scans from the entry
# point -- not where the compared immediates are. Its docstring says the start
# RVA should come from driver_major_function_scan and that nothing is chained
# automatically. Admitting it would repeat the b411965 regression recorded just
# below, where a coordinate tool in the path-only set made file_router
# recommend and auto-invoke it with a bare path.
WINDOWS_KERNEL_NOT_FILE_ROUTABLE = tuple(sorted({
    "ioctl_control_code_decode",  # consumes a caller-declared code list, no path
    "tool_missing",  # generic sentinel, added separately by file_router.py
    "passive_object_namespace_probe",  # live-OS enumeration (QueryDosDeviceW /
        # NtQuerySystemInformation), never a file path -- takes target_keywords,
        # not $.path; a bare {"path": ...} call trips UNKNOWN_ARGUMENT on $.path.
        # Regression fixed 2026-09-26/27: added to _WINDOWS_KERNEL_PATH_ONLY_TOOL_NAMES
        # by b411965, which made file_router recommend/auto-invoke it with a bare
        # path -- caught by tests/test_assessment_run.py,
        # tests/test_file_router_targeted_tools.py.
}))
WINDOWS_KERNEL_PATH_ONLY_TOOLS = tuple(sorted(_WINDOWS_KERNEL_PATH_ONLY_TOOL_NAMES))
WINDOWS_KERNEL_COORDINATE_TOOLS = tuple(sorted(
    FAMILIES["windows-kernel"] - _WINDOWS_KERNEL_PATH_ONLY_TOOL_NAMES - set(WINDOWS_KERNEL_NOT_FILE_ROUTABLE)
))

# Relationship/verification trigger words are natural-language terms, not the
# internal tool names ("xref", "graph", "cross-file").  The model never needs to
# know internal terminology for Stage C to activate.
RELATIONSHIP_SIGNAL_WORDS = (
    "compare", "shared", "identical", "same", "difference", "between", "both",
    "cross", "relat", "correlat", "match", "common", "versus", "overlap",
    "consisten", "correspond",
)

# Deep-native escalation words: the model explicitly asks for decompilation,
# cross-reference, or function-level analysis, so deep native tools become
# reachable without permanently loading every schema.
NATIVE_DEEP_SIGNALS = (
    "ghidra", "xref", "decompile", "disassemble", "call graph", "caller",
    "callee", "function inventory", "basic block", "disassembly",
)

# ``.dll`` is intentionally absent: extension alone cannot decide native vs
# managed.  Content (CLR directory presence) is the only reliable signal.
SIGNALS = {
    "native": ("pe_native", " elf", "macho", "mach-o", ".exe", ".so", ".dylib", "ghidra", "native"),
    "windows-kernel": ("windows_kernel_driver", ".sys", "driverentry", "ioctl", "kmdf", "wdm", "kernel driver"),
    "debug": (".pdb", ".dmp", ".mdmp", "minidump", "portable pdb", "debug symbols"),
    "binary": ("binary", "strings", "hex", "hash"),
    "dotnet": ("pe_dotnet", ".net", "ilspy", "assembly-csharp", " clr", "managed assembly", "c#"),
    "archive": ("archive", ".zip", ".tar", ".jar", ".whl", ".nupkg"),
    "android": (".apk", ".aab", ".dex", "apk", " aab", " dex", "android"),
    "game-engine": ("unity", "unreal", "godot", "flutter", "electron", "il2cpp"),
    "web": ("asar",),
    "network": (".har", ".pcap", "pcapng", "network capture"),
    "database": ("sqlite", ".db", "database"),
    "structured": (".json", ".xml", ".yaml", ".toml", ".log", "config"),
    "source": ("source", "source code", "kaynak kod", "semantic", "taint"),
    # Multi-word phrases only (not bare "dynamic"/"runtime"/"memory", which
    # collide with common English words and this project's own vocabulary
    # -- e.g. "memory" alone appears constantly in unrelated static-analysis
    # discussion of PE headers, dumps, etc.). Learned from the earlier
    # "source"/"resource" and "hex"/"hexadecimal" substring-collision
    # findings in this same SIGNALS dict: prefer specific phrases over
    # single common words for a new entry.
    "dynamic": ("dynamic analysis", "runtime behavior", "attach debugger", "live memory scan", "launch and observe", "process scan", "reproduce the crash", "isolated vm validation", "exploit validation plan"),
    "jvm": (".class", "java bytecode", " jvm"),
    "webassembly": ("wasm", ".wat"),
    "correlation": ("xref", "cross-file", "correlat", "coverage", "graph"),
    "crypto": ("lattice", "lll reduc", "knapsack", "subset-sum", "svp", "short vector", "cryptanalysis", "cryptanalytic", "lzma1", "lzma stream", "range coder", "range decoder"),
    "emulation": ("emulat", "speakeasy", "fake winapi", "synthetic winapi", "unpack at runtime", "run until import", "import resolution"),
}


def _signal_hit(word: str, text: str) -> bool:
    """Substring match, with one exception: bare "source" is also a
    substring of "resource"/"resources" (index 2 onward), which spuriously
    activated the whole source family for any corpus merely mentioning a
    resource. Every occurrence of "source" immediately preceded by "re" is
    excluded; genuine mentions ("source code", "the source", "opensource")
    are unaffected. Scoped to this one word rather than a general word-
    boundary rule for every SIGNALS entry, since several other entries rely
    on plain substring matching for inflected/compound forms (e.g. "kernel
    driver" must still match within "kernel drivers").
    """
    if word != "source":
        return word in text
    start = 0
    while True:
        idx = text.find("source", start)
        if idx < 0:
            return False
        if text[max(0, idx - 2):idx] != "re":
            return True
        start = idx + 1


def families_for_context(corpus: str) -> list[str]:
    text = str(corpus).lower()
    selected = list(BASE_FAMILIES)
    for family, words in SIGNALS.items():
        if any(_signal_hit(word, text) for word in words):
            selected.append(family)
    return list(dict.fromkeys(selected))


def tools_for_context(corpus: str) -> set[str]:
    names: set[str] = set()
    for family in families_for_context(corpus):
        names.update(FAMILIES[family])
    return names


def family_catalog(registry_rows: list[dict]) -> list[dict]:
    by_name = {row["name"]: row for row in registry_rows}
    output = []
    for family, tools in FAMILIES.items():
        available = sorted(name for name in tools if by_name.get(name, {}).get("installed"))
        missing = sorted(name for name in tools if name in by_name and not by_name[name].get("installed"))
        output.append({"family": family, "available_tools": available, "missing_tools": missing, "status": "READY" if available and not missing else "PARTIAL" if available else "TOOL_MISSING"})
    return output


def _classification_dict(value: Any) -> dict[str, Any] | None:
    """Normalize a route_file / file_identity result (JSON string or dict)."""
    if value is None:
        return None
    if isinstance(value, str):
        import json as _json
        try:
            value = _json.loads(value)
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) else None


def family_for_artifact_classification(classification: Any) -> str | None:
    """Content-aware family for one route_file / file_identity classification.

    Never infers a family from extension alone.  ``tool_family`` from
    :func:`route_file` is already content-aware; otherwise ``runtime`` is used
    (``dotnet`` only when a CLR directory was observed, else ``native``).
    """
    value = _classification_dict(classification)
    if not value:
        return None

    family = str(value.get("tool_family") or value.get("family") or "").strip().casefold()
    if family in FAMILIES:
        return family

    runtime = str(value.get("runtime") or "").strip().casefold()
    kind = str(value.get("type") or value.get("format") or "").strip().upper()
    domain = str(value.get("domain") or "").strip().upper()

    if runtime == "dotnet" or "DOTNET" in kind or "DOTNET" in domain or "CLR" in kind:
        return "dotnet"
    if runtime == "native" or kind in {"PE_NATIVE", "PE", "ELF", "MACHO", "WINDOWS_NATIVE_KERNEL_CANDIDATE"}:
        return "native"
    if "WINDOWS_KERNEL" in domain or "WINDOWS_KERNEL" in kind:
        return "windows-kernel"
    if kind in {"JSON", "JSONL", "XML", "YAML", "TOML", "INI", "CONFIG", "CSV", "LOG", "HAR"}:
        return "network" if kind == "HAR" else "structured"
    if kind == "SQLITE":
        return "database"
    if kind in {"WASM", "WAT"}:
        return "webassembly"
    if kind in {"JAVA_CLASS"} or runtime == "jvm":
        return "jvm"
    if kind in {"ZIP", "TAR", "APK", "AAB", "APKS", "JAR", "WAR", "EAR", "IPA", "PYTHON_WHEEL", "NUGET", "MSIX", "APPX", "7Z", "RAR", "GZIP", "XZ", "BZIP2", "ZSTD"}:
        return "android" if kind in {"APK", "AAB", "APKS"} else "jvm" if kind in {"JAR", "WAR", "EAR"} else "archive"
    if kind == "ASAR":
        return "web"
    if kind in {"MINIDUMP", "PDB", "PORTABLE_PDB"}:
        return "debug"
    if kind in {"PYTHON", "JAVASCRIPT", "TYPESCRIPT", "CSHARP", "JAVA", "C", "C_HEADER", "CPP", "CPP_HEADER", "GO", "RUST", "LUA", "POWERSHELL", "SHELL", "RUBY", "PHP", "TEXT", "PROTO", "GRAPHQL"}:
        return "source"
    return None


def _relationship_needed(state: dict[str, Any], corpus_text: str = "") -> bool:
    if state.get("relationship_needed") or state.get("conflicting_evidence"):
        return True
    if state.get("claim_verification_needed"):
        return True
    text = str(corpus_text or "").casefold()
    has_relationship_word = any(word in text for word in RELATIONSHIP_SIGNAL_WORDS)
    multiple_artifacts = int(state.get("artifacts_analyzed") or 0) >= 2 or int(state.get("artifacts_discovered") or 0) >= 2
    return bool(has_relationship_word and multiple_artifacts)


def _native_deep_ready(state: dict[str, Any]) -> bool:
    if state.get("deep_analysis_done"):
        return False  # already escalated
    if state.get("native_pe_detected") and state.get("structural_analysis_done"):
        return True
    return bool(state.get("native_deep_requested"))


def families_for_state(artifact_state: dict[str, Any] | None = None, *, corpus_text: str = "") -> list[str]:
    """Staged, state-driven family selection (Stage A -> B -> C)."""
    state = dict(artifact_state or {})
    selected: list[str] = []

    # Stage A is represented by CORE_TOOLS, not a whole family; still, mark the
    # families that own core tools so callers can reason about the surface.
    selected.extend(["workspace", "identity"])

    # Stage B: specialist families from artifact classification.
    for item in state.get("classifications") or []:
        family = family_for_artifact_classification(item)
        if family and family not in selected:
            selected.append(family)

    # Stage C: correlation / verification, plus deep-native escalation.
    if _relationship_needed(state, corpus_text):
        selected.append("correlation")

    # Fallback keyword signals for pre-classification rounds (excluding base
    # families so the core surface stays small).
    text = str(corpus_text or "").casefold()
    for family, words in SIGNALS.items():
        if family in selected:
            continue
        if any(_signal_hit(word, text) for word in words):
            selected.append(family)

    return list(dict.fromkeys(selected))


def tools_for_state(artifact_state: dict[str, Any] | None = None, *, corpus_text: str = "") -> list[str]:
    """Ordered, deduplicated tool-name list for progressive exposure.

    Stage A core tools are always first.  Stage B specialist tools follow the
    artifact classification.  Stage C correlation/verification tools are added
    only when analysis state justifies them.  Keyword signals act as a fallback
    only, and never re-add a large static surface on their own.
    """
    state = dict(artifact_state or {})
    names: list[str] = [name for name in CORE_TOOLS]

    def extend(tools) -> None:
        for tool in sorted(tools):
            if tool not in names:
                names.append(tool)

    # Stage B: specialist tools from classification.
    for item in state.get("classifications") or []:
        family = family_for_artifact_classification(item)
        if not family:
            continue
        if family == "native":
            extend(NATIVE_CORE_TOOLS)
            if _native_deep_ready(state):
                extend(NATIVE_DEEP_TOOLS)
        else:
            extend(FAMILIES.get(family, ()))

    # Fallback: signal families for rounds without a classification yet, but
    # only their specialist tools (not base workspace/identity/source).
    text = str(corpus_text or "").casefold()
    for family, words in SIGNALS.items():
        if not any(_signal_hit(word, text) for word in words):
            continue
        if family == "native":
            extend(NATIVE_CORE_TOOLS)
            if _native_deep_ready(state) or any(word in text for word in NATIVE_DEEP_SIGNALS):
                extend(NATIVE_DEEP_TOOLS)
        else:
            extend(FAMILIES.get(family, ()))

    # Stage C: correlation/verification.
    if _relationship_needed(state, text):
        extend(FAMILIES.get("correlation", ()))

    return names
