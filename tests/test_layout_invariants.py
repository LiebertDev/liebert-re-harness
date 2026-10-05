"""Fingerprints that must hold unchanged across the package move.

Both exist because a layout change can break a guarantee while the suite stays
green: nothing fails loudly, the protection just quietly stops applying.
"""
import hashlib
import importlib
import subprocess
import sys
from pathlib import Path

from tests import conftest

import liebert_re.report.tool_families as tool_families

# Every module that owns an EVIDENCE directory. The set is the pin: adding a
# module here is the reviewed edit that says conftest is expected to redirect
# it during tests. The count is deliberately not in the test name -- the set
# below is what must be read and edited, and a number in the name only
# duplicates it.
EVIDENCE_OWNERS = {
    "liebert_re.dynamic.apimonitor", "liebert_re.dynamic.lab_gate", "liebert_re.tools.binary", "liebert_re.tools.capa",
    "liebert_re.tools.die", "liebert_re.tools.generic_static_probe", "liebert_re.tools.ghidra",
    "liebert_re.tools.ida",
    "liebert_re.tools.pe_sieve", "liebert_re.tools.rizin",
    "liebert_re.tools.upx", "liebert_re.tools.yara_x",
}


def test_exactly_the_declared_evidence_owners_resolve_under_the_real_ledger():
    # If a module's EVIDENCE stopped resolving under <repo>/dataset/evidence,
    # conftest would stop redirecting it per test and tests would write against
    # the real ledger with no failure. Uses conftest's own classifier.
    for name in EVIDENCE_OWNERS:
        importlib.import_module(name)
    owners = {m.__name__ for m, _ in conftest._evidence_owning_modules()}
    assert owners == EVIDENCE_OWNERS
    # conftest redirects each module's live EVIDENCE during a test, so read the
    # true import-time value in a fresh interpreter.
    code = (
        "import importlib, sys; "
        "[print(n, importlib.import_module(n).EVIDENCE.resolve()) for n in sys.argv[1:]]"
    )
    out = subprocess.run(
        [sys.executable, "-c", code, *sorted(EVIDENCE_OWNERS)],
        cwd=conftest.REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert len(out) == len(EVIDENCE_OWNERS)
    for line in out:
        name, _, path = line.partition(" ")
        assert conftest.REAL_EVIDENCE_ROOT in Path(path).parents, name


def test_published_tool_name_set_is_unchanged():
    # Must stay identical across the package move. A change is only legitimate
    # when public functions are deliberately added or removed.
    #
    # Updated once since: liebert_re/tools/die.py gained the rest of what diec.exe
    # exposes (die_entropy, die_file_info, die_format_check, die_hashes,
    # die_structures, die_struct_raw, die_database_info, die_status) alongside the
    # existing die_identify, which previously used one flag (-j) of the tool's real
    # surface. All eight are registered in tool_families.FAMILIES["native"], and cli.py gained
    # the `die`/`diestatus` commands that reach them.
    #
    # Updated again: liebert_re/tools/capa.py wraps capa (capa_analyze was already
    # a FAMILIES name with no implementation here; capa_status is new), reached from
    # the CLI as `capa` and `capastatus`.
    #
    # Updated again: liebert_re/tools/ida.py wraps IDA Pro's headless batch mode. The public
    # functions added on purpose are ida_query (already a FAMILIES name with no implementation
    # here) and ida_status (new); the CLI reaches them as `ida` and `idastatus` through the
    # handlers _ida and _ida_status in cli.py. The set pinned below counts every top-level
    # function name, private helpers included, so the module's own underscore helpers moved
    # the digest too; only the two public names are a claim about the published surface.
    # The IDAPython worker it drives is a data file (ida_scripts/query_program.idapy), not a
    # module, so it adds no names here.
    #
    # Updated again: liebert_re/tools/rizin.py gained the rz-bin reads. The public functions
    # added on purpose are rz_bin_imports, rz_bin_sections, rz_bin_headers, rz_bin_relocations
    # and rz_bin_status, registered in tool_families.FAMILIES["native"]; the CLI reaches them as
    # `rzbin` and `rzbinstatus`. The shared runner is a private class (_RzBin) rather than
    # top-level functions, so no underscore helper joined the pinned set.
    #
    # Updated again: liebert_re/recover/vex.py gained one top-level helper on purpose,
    # _run_with_faulthandler_off. It is the single shared copy of the faulthandler-off-around-a-call
    # logic that self_check uses around Uc.mem_map and that tests/test_vex_layer.py reuses; it is
    # private and not a published tool, and it is a top-level def (not nested) so the pin counts it.
    #
    # Updated again: liebert_re/tools/rizin.py gained FLIRT signature matching done by rizin
    # itself. The public functions added on purpose are rizin_flirt_match (sigdb, `Fa`),
    # rizin_flirt_match_file (one .sig/.pat file, `Fs`) and rizin_flirt_inventory (`Fl`),
    # registered in tool_families.FAMILIES["native"]; the CLI reaches them as `flirt` and
    # `flirtinventory`. The shared runner is the private class _RzFlirt, so no underscore
    # helper joined the pinned set.
    #
    # Updated again: liebert_re/tools/pe_sieve.py wraps pe-sieve, the scan of ONE running process the
    # caller started, by PID. The public functions added on purpose are pe_sieve_scan (PID required,
    # scan only, no dump switch ever passed) and pe_sieve_status (zero arguments), registered in
    # tool_families.FAMILIES["dynamic"]; the CLI reaches them as `sieve` and `sievestatus`. The
    # scanner helpers live in the private class _PeSieve; the only other names that joined the
    # pinned set are the two CLI handlers in liebert_re/cli.py, _sieve and _sieve_status.
    #
    # Updated again: liebert_re/dynamic/lab_gate.py implements dynamic_lab_gate (a name already
    # declared in tool_families.FAMILIES["dynamic"] with no implementation) and adds
    # dynamic_lab_register_owned_process, registered in the same family. The gate's helpers live in
    # the class LabGate, so only those two public names joined the pin from that module. The
    # CLI joined three top-level names on purpose: the handlers _labgate and _labregister and the
    # shared argument helper _gate_args, reached as `labgate` and `labregister`; pe_sieve_scan
    # now takes the gate's authorization arguments through the same helper.
    #
    # Updated again: liebert_re/tools/ida.py gained microcode (ida_microcode_cfg, already a
    # FAMILIES["native"] name with no implementation here), a read of one function's microcode as a
    # control-flow graph, raw by default, with an opt-in d810 deobfuscation pass that labels its own
    # output. Three top-level names joined the pin and the digest was recomputed from the source, not
    # edited by hand: the public ida_microcode_cfg; the private _locked_call in ida.py, which is the
    # hash-the-input / take-the-slot-lock / run-the-sessions / enforce-the-budget tail that ida_query had
    # inline and that both now share (a top-level def, not nested, because two public functions call it);
    # and the handler _ida_microcode in liebert_re/cli.py, reached as `idamicrocode`. Everything else the
    # change needs rides in the existing call chain as a plain `profile` dict (no new defs), and the
    # validation and label check specific to the microcode call are nested inside ida_microcode_cfg. The
    # second IDAPython worker, ida_scripts/microcode_cfg.idapy, is a data file like the first and adds
    # no names here.
    # Updated again: status probes for the tools that had none, so a driver can ask "is this tool
    # resolvable and does it run" instead of guessing. The public functions added on purpose are
    # yara_x_status and upx_status (registered in tool_families.FAMILIES["native"]), il2cpp_status
    # (["game-engine"]), dex_status (["android"]), jvm_status (["jvm"]) and frida_status (["dynamic"],
    # defined in liebert_re/dynamic/lab_gate.py, because the frida client module is guest-only and
    # the CLI source may not mention frida). The CLI reaches the first five as `yarastatus`,
    # `upxstatus`, `il2cppstatus`, `dexstatus` and `jvmstatus` through the handlers _yara_x_status,
    # _upx_status, _il2cpp_status, _dex_status and _jvm_status in liebert_re/cli.py; frida_status
    # has no CLI command on purpose. Eleven top-level names joined the pin (6 public + 5 handlers),
    # 644 -> 655, and the digest was recomputed from the source, not edited by hand. The resolver
    # logic for "where was it found" lives nested inside each status function, so no private
    # helper joined the set. No module was added: the CI module count stays 70.
    #
    # Updated again, once for three merged branches (655 -> 667, twelve top-level names, digest
    # recomputed from the source). IDA read/plan branch, three public functions in
    # liebert_re/tools/ida.py: ida_annotations (annotation reader), ida_type_member_offset (type
    # member offset) and ida_patch_plan (patch plan; nothing persists). Evidence-chain branch,
    # private top-level helpers that the pin counts because they are top-level defs: _parse_jsonl,
    # _jsonl_row_fields, _jsonl_field_values, _summarize_jsonl (line-by-line JSONL evidence),
    # _limit_marker (marks truncated lists), _attach_evidence and _evidence_uid_for_path (bind probe
    # and gate evidence) and _engine_tag (IDA cache key carries the engine version).
    # API monitor refusals branch: _working_operations_note. The new patch_plan.idapy is a data
    # file, not a module: the CI module count stays 70.
    #
    # IDA annotated write path and purge branch (two commits, recomputed once for their total effect
    # by diffing the sorted top-level name lists of the two trees: 667 names before, 706 after, none
    # removed, 39 added). Public: ida_rename_plan, ida_annotations_apply, ida_annotations_purge. The
    # other 36 are private top-level helpers of the annotated subsystem in liebert_re/tools/ida.py:
    # _annotated_budget_bytes, _annotated_root, _annotated_session, _annotated_state,
    # _annotated_total_bytes, _apply_locked, _copy_into_budget, _copy_pristine, _file_sha256,
    # _fsync_path, _journal_append, _journal_path, _journal_records, _label_dir, _label_refusal,
    # _lock_annotated, _manifest_read, _manifest_write, _marker_matches, _opening_checks,
    # _overlap_refusal, _plan_problem, _purge_confirmation, _purge_inventory, _purge_locked,
    # _purge_remove, _recover_pending, _refuse, _remove_owned_work, _replace_file, _roots_apart,
    # _sha256_text, _tree_bytes, _utc_now, _valid_label, _version_file. The new annotate_write.idapy
    # is a data file, not a module: the CI module count stays 70.
    #
    # kernel_triage slice, on top of the comment plan slice below: 707 -> 711 (main's written pin was
    # 440a45bb..., 707 names; measured after this change: 711), four top-level names added, none
    # removed. Public: kernel_triage, already declared in FAMILIES["windows-kernel"], the family's
    # first defined tool (liebert_re/tools/binary.py). Private helpers there: _kt_refuse (refusal
    # envelope) and _kt_indicators (per-indicator confidence labels). Fixture builder in
    # liebert_re/recover/owned_binary_fixtures.py: build_owned_pe_sections. No new module: the CI
    # module count is unchanged. Digest recomputed from the source, not merged by hand.
    # process_lock slice: 711 -> 713, two private top-level names added in
    # liebert_re/evidence/process_lock.py, none removed: _windows_api (the kernel32 seam) and
    # _windows_pid_alive (the three-valued Windows liveness decision). The binding class _WinApi is not
    # a def. No new module. Digest recomputed from the source.
    # IDA comment plan slice: 706 -> 707, one top-level name added, none removed:
    # ida_set_comments_plan (public, liebert_re/tools/ida.py; plan only, nothing persists, apply is a
    # later slice). In tool_families.FAMILIES["native"] the never-implemented name ida_set_comments was
    # replaced by ida_set_comments_plan (a manifest string, not a def, so it does not change the count
    # by itself). The new nested helper `digest` is not top-level. Worker annotate_write.idapy gained
    # a comment_plan operation (data file): the CI module count stays 70. Digest recomputed from the
    # source with sha256(repr(sorted(tool_families._locally_defined_tool_names())).encode()).
    # IDA engine-log slice: 711 -> 714, three private top-level helpers in liebert_re/tools/ida.py,
    # none removed: _read_log_tail (bounded, redacted tail of ida.log; absent told apart from unreadable),
    # _keep_failed_scratch and _retained_scratch (the default-off LIEBERT_RE_KEEP_FAILED_SCRATCH switch and
    # its response part). No new module. Digest recomputed from the source, not edited by hand.
    # Ghidra headless slice 1, on top of the slices above (716 -> 737 once rebased onto main), twenty-one
    # top-level names added, none removed (checked by diffing the sorted name sets of the two trees).
    # Public: ghidra_status, ghidra_program_facts (liebert_re/tools/ghidra.py, both registered in
    # tool_families.FAMILIES["native"]; the second is path-only, the first is listed under
    # NATIVE_NOT_FILE_ROUTABLE). Private top-level helpers of that module: _count_error_lines,
    # _discover_installs, _display_candidate, _facts_in_work, _headless_in, _int_or_none,
    # _java_executable, _known_roots, _normalise_facts, _parse_java_major, _probe_java,
    # _read_properties, _read_result, _remove_work, _scan_failures, _select_install, _sha256_file,
    # _shown_path, _version_key. The other helpers it defines (_j, _redact, _tail, _checked_path,
    # _tool_missing) share a name with existing ones, and the pin is a set, so they add nothing.
    # (Within this slice's own history: 18 names at first, then the audit-fix commit added
    # _facts_in_work, _normalise_facts, _remove_work, _shown_path and dropped _refusal: 18 + 4 - 1 = 21.)
    # The new ghidra_scripts/ProgramFacts.java is a data file, not a module. One module was added
    # (liebert_re/tools/ghidra.py): the CI module count is now 71. Digest recomputed from the source
    # with sha256(repr(sorted(tool_families._locally_defined_tool_names())).encode()).
    digest = hashlib.sha256(
        repr(sorted(tool_families._locally_defined_tool_names())).encode()
    ).hexdigest()
    # Merged tree (engine-log + process-lock): 714 + 2 = 716 names; with the Ghidra slice's 21 names
    # on top, 716 + 21 = 737 (measured, not summed); digest recomputed from the merged source.
    # verified-copy slice: 737 -> 738, one private top-level name added in liebert_re/tools/ida.py,
    # none removed: _verified_copy. No new module. Digest recomputed from the source.
    # decompiled-class identity slice: 738 -> 740, two private top-level names added, none removed,
    # the same pair in liebert_re/tools/dex.py and liebert_re/tools/jvm.py (the pin is a set, so the
    # twin definitions count once each): _name_stays_in_root and _find_decompiled. No new module.
    # Digest recomputed from the source.
    # crash-symbolize PE binding slice: 740 -> 741, one private top-level name added in
    # liebert_re/recover/crash_symbolize.py, none removed: _bind_pe_to_dump_module. No new module.
    # Digest recomputed from the source.
    # frida init-error slice: 741 -> 742, one private top-level function added in
    # liebert_re/dynamic/frida_trace_client.py, none removed: _classify_rpc_init_error (the marker
    # tuple is an assignment, not a def, so it adds nothing). No new module.
    # Digest recomputed from the source.
    # CLI read-only wiring slice: 742 -> 746, four top-level handlers added in liebert_re/cli.py,
    # none removed: _kernel_triage, _ghidra_status, _ghidra_facts, _ida_annotations (reached as
    # `kerneltriage`, `ghidrastatus`, `ghidrafacts`, `idaannotations`). No new module. Digest
    # recomputed from the source.
    # guest-marker slice: 746 -> 748, two private top-level functions added in
    # liebert_re/dynamic/frida_trace_client.py, none removed: _read_guest_marker and
    # _guest_marker_refusal. No new module. Digest recomputed from the source.
    # control-code decode slice: 748 -> 750, two top-level names added in liebert_re/tools/binary.py,
    # none removed: ioctl_control_code_decode (public; declared in FAMILIES["windows-kernel"] but
    # undefined until now) and _icd_one (private). No new module. Digest recomputed from the source.
    # CLI minidump provenance slice: 750 -> 751, one private top-level function added in
    # liebert_re/cli.py, none removed: _resolve_for_report. No new module. Digest recomputed from
    # the source.
    # dispatch-table first-pass slice: 751 -> 755, four top-level names added in liebert_re/tools/binary.py,
    # none removed: driver_major_function_scan (public; declared in FAMILIES["windows-kernel"] but undefined
    # until now) and the private _dmf_refuse, _dmf_index, _dmf_find. No new module. Digest recomputed
    # from the source.
    # dispatch-scan tail-jump slice: 755 -> 757, two private top-level functions added in
    # liebert_re/tools/binary.py, none removed: _dmf_read and _dmf_tail_jump (the two constants are
    # assignments and add nothing). No new module. Digest recomputed from the source.
    # import-slot scan slice: 757 -> 761, four top-level names added in liebert_re/tools/binary.py,
    # none removed: rip_relative_iat_scan (public; declared in FAMILIES["windows-kernel"] but undefined
    # until now) and the private _ria_refuse, _ria_slots, _ria_find. No new module. Digest recomputed
    # from the source.
    # api-hash name-mapping slice: 761 -> 762, one public top-level function added in
    # liebert_re/recover/api_hash_recover.py, none removed: api_hash_recover (declared in
    # FAMILIES["crypto"] but defined only as crack_api_hash / api_hash_recover_tool, so the def-line
    # scan counted it missing). No new module. Digest recomputed from the source.
    # callback-registration filter slice: 762 -> 765, three top-level names added in liebert_re/tools/binary.py,
    # none removed: kernel_callback_registrations (public; declared in FAMILIES["windows-kernel"] but undefined
    # until now) and the private _kcr_norm_dll, _kcr_lookup. No new module. Digest recomputed from the source.
    # CLI truncated-listing slice: 765 -> 766 (measured), one private top-level function added in
    # liebert_re/cli.py, none removed: _truncation. No new module. Digest recomputed from the source.
    # DriverEntry call-trampoline slice: 766 -> 767 (measured), one private top-level function added in
    # liebert_re/tools/binary.py, none removed: _dmf_calls. No new module. Digest recomputed from the source.
    # CLI kernel-operations slice: 767 -> 771 (measured), four private top-level handlers added in
    # liebert_re/cli.py, none removed: _kernel_dispatch, _kernel_iat, _kernel_callbacks, _ioctl_decode.
    # No new module. Digest recomputed from the source.
    # structured disassembly slice: 771 -> 775 (measured), four top-level names added in liebert_re/tools/binary.py,
    # none removed: disassemble_pe_structured (public) and the private _dpe_open, _dps_form, _dps_entry.
    # No new module. Digest recomputed from the source.
    # control-code scan slice: 775 -> 778 (measured), three top-level names added in liebert_re/tools/binary.py,
    # none removed: ioctl_candidate_scan (public) and the private _ics_fail, _ics_walk. No new module.
    # Digest recomputed from the source.
    assert digest == "df5ec6647a02f0cde09ded0de6217635d7ac0a12fa161cf9e034e12f144dbe3a"


def test_the_imported_package_is_this_checkout():
    # A stale editable install elsewhere on the machine can shadow the checkout
    # when the working directory is not the repo root; the suite would then
    # measure the wrong code without failing. Root comes from conftest.
    import liebert_re

    root = conftest.REPO_ROOT
    actual = Path(liebert_re.__file__).resolve()
    assert root in actual.parents, (
        f"liebert_re was imported from {actual}, expected a path under {root}. "
        "Another installation is probably shadowing this checkout."
    )
