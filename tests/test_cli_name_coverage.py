"""Upper-bound measure of published tools whose name never appears in ``cli.py``.

WHAT THIS MEASURES: for every tool in the union of ``published_tools(family)``
(not the raw ``FAMILIES`` manifest, which is upstream routing and names tools
this package does not ship), whether its name occurs as a whole identifier in
the text of ``liebert_re/cli.py``.

WHAT THIS IS NOT: proof of CLI reachability. ``cli.py`` loads modules lazily
through ``importlib`` (``_load()``), so a tool can be reachable without its
name appearing literally, and a name can appear without being wired to a
command. The result is a deliberate upper bound on the gap, nothing more.

The list below may only shrink. Growth fails the test; so does a silent drop
(the pinned total must be lowered together with the list).
"""
import re
from pathlib import Path

from liebert_re.report.tool_families import FAMILIES, published_tools

CLI_SRC = Path(__file__).resolve().parent.parent / "liebert_re" / "cli.py"

PUBLISHED_TOTAL = 133
NOT_NAMED_IN_CLI = (
    "analyze_tls_directory",
    "android_resource_analyzer",
    "api_catalog",
    "api_hash_recover",
    "apimonitor_status",
    "archive_inspect",
    "asar_inspect",
    "binary_patch",
    "binary_summary",
    "binary_version_diff",
    "claim_index",
    "counter_evidence_verify",
    "cpp_rtti_inspect",
    "crash_symbolize",
    "cross_binary_relationship_analyze",
    "cross_file_graph",
    "crypto_constant_scan",
    "dart_aot_recovery",
    "delphi_inspect",
    "dex_decompiler",
    "disassemble_pe_structured",
    "dotnet_il_inspect",
    "dotnet_metadata",
    "dotnet_metadata_inspect",
    "dotnet_relationship_analyze",
    "evidence_index",
    "exploit_validation_plan",
    "exploit_validation_result_verify",
    "find_binaries",
    "find_files",
    "finding_report_generate",
    "framework_detect",
    "frida_status",
    "get_file_info",
    "godot_asset_analyzer",
    "har_inspect",
    "hash_file",
    "ida_annotations_apply",
    "ida_annotations_purge",
    "ida_patch_plan",
    "ida_rename_plan",
    "ida_set_comments_plan",
    "ida_type_member_offset",
    "il2cpp_mapper",
    "image_address_map",
    "ioctl_candidate_scan",
    "java_class_inspect",
    "jvm_decompiler",
    "lattice_reduce",
    "list_directory",
    "log_inspect",
    "lzma1_decode",
    "minidump_structural_analyze",
    "msf_pdb_inspect",
    "native_xref_analyze",
    "pcap_analyzer",
    "pdb_symbols",
    "plist_inspect",
    "project_inspect",
    "rar_7z",
    "read_file",
    "read_files",
    "rizin_disasm_listing",
    "rizin_functions",
    "rizin_patch_apply",
    "rizin_patch_plan",
    "rizin_status",
    "search_binary_bytes",
    "search_text",
    "source_inspect",
    "sqlite_inspect",
    "structured_inspect",
    "tool_missing",
    "unity_asset_analyzer",
    "unreal_asset_analyzer",
    "vb6_inspect",
    "vb6_pcode",
    "wasm_inspect",
    "workspace_index",
)


def _published():
    return set().union(*(published_tools(f) for f in FAMILIES))


def _not_named_in_cli():
    text = CLI_SRC.read_text(encoding="utf-8")
    return {n for n in _published()
            if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", text)}


def test_published_baseline_is_published_tools_not_raw_families():
    assert len(_published()) == PUBLISHED_TOTAL


def test_not_named_in_cli_list_only_shrinks():
    grown = _not_named_in_cli() - set(NOT_NAMED_IN_CLI)
    assert not grown, f"published tools newly absent from cli.py: {sorted(grown)}"


def test_not_named_in_cli_count_is_pinned_exactly():
    # A shrink must also shrink the list above; otherwise the list goes stale.
    stale = set(NOT_NAMED_IN_CLI) - _not_named_in_cli()
    assert not stale, f"now named in cli.py or unpublished, remove from list: {sorted(stale)}"
    assert len(_not_named_in_cli()) == len(NOT_NAMED_IN_CLI) == 79
