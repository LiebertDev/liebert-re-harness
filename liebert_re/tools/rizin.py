"""rizin headless static-analysis adapter -- a third, independent decompiler
engine alongside IDA (tools_ida.py (upstream-only; not part of the published package)) and Ghidra (tools_decompiler.py (upstream-only; not part of the published package)).

Why this exists: on a real packed corpus binary
(benchmarks/windows_native_ladder/corpus/tier2/decryption_key1/elevenpack.exe)
the three engines disagreed wildly -- rizin reported 7 functions, IDA 1,
Ghidra 366. Three of Ghidra's 366 were decompiled and every one returned
Ghidra's own halt_baddata()/bad-instruction warning: Ghidra had carved
imaginary functions out of packed bytes in an executable section. On two
unpacked corpus binaries (tier2/anti_debug/Anti-Debugging.exe: rizin 90 /
IDA 97 / Ghidra 102) the three engines agreed within a normal spread.
Engine disagreement is therefore not noise -- on packed/obfuscated targets
it identifies a decompiler that is wrong, and the harness needs a third,
cheap, independent engine that can say so rather than trusting a single
possibly-fabricated function count as evidence.

rizin 0.9.1 (LGPL-3.0, https://rizin.re) is expected either on PATH or at
the directory named by the ``RIZIN_HOME`` environment variable, e.g. a
portable install such as ``C:\tools\rizin-portable\bin\rizin.exe``.

Deliberately narrow, matching tools_ida.py's shape (upstream-only; not part of the published package): locate the binary
(env override -> PATH -> known install dir, TOOL_MISSING if absent, never
raise/guess), run ONE headless rizin process per query (`aaa; aflj; iIj` --
rizin's own JSON, never scraped human-readable text; the trailing `iIj` is
a per-call "did you actually load this file" probe, because rizin exits 0
whether it did or not), bound it with a timeout and an output-size cap, and
return the repo's usual JSON status vocabulary (OK / TOOL_MISSING /
TIMEOUT / CANCELLED / ANALYSIS_LIMITED / RESULT_PARSE_FAILED /
NOT_RECOVERABLE / NOT_FOUND / PATH_REFUSED) so capability-gap
classification (capability_gap.py (upstream-only; not part of the published package)) can read it like any other tool.

NOT_RECOVERABLE is load-bearing and distinct from every "no" above: it
means the question could not be answered on this call (rizin returned an
empty function list without confirming it loaded the binary; the bytes at a
patch site were never decoded), never that the answer was negative.

Not wired into routing/registry/cross-check -- that is a separate task
owned elsewhere; see the module for what a caller would need.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
import zlib
from pathlib import Path

from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.recover.pe_address import AddressForm, normalize_address, resolve_address_form
from liebert_re.workspace import safe_path, relative

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP
# Same convention tools_binary.py/tools_decompiler.py (upstream-only; not part of the published package) use (module-level
# attribute deliberately named EVIDENCE): tests/conftest.py's per-test
# isolation guard auto-discovers every imported module's EVIDENCE attribute
# by this exact name and redirects it to a scratch directory for the test's
# duration, so writes below never land in the real shipped ledger during a
# test run.
EVIDENCE = APP / "dataset" / "evidence" / "binary_patch"
EVIDENCE.mkdir(parents=True, exist_ok=True)

_DEFAULT_TIMEOUT_SECONDS = 120
_MIN_TIMEOUT_SECONDS = 10
_MAX_TIMEOUT_SECONDS = 600
_MAX_FUNCTIONS_RETURNED = 5000
_MAX_DISASM_COUNT = 2000

# PE IMAGE_FILE_HEADER.Machine -> rizin's own `-a`/`-b` architecture/bits
# flags, so the assembler/disassembler is driven by the PE's real header
# instead of rizin's own (occasionally wrong on raw driver images)
# auto-detection.
_MACHINE_TO_ARCH_BITS = {
    0x14C: ("x86", 32),
    0x8664: ("x86", 64),
}

_ADDRESS_ERROR_TO_STATUS = {
    "FILE_NOT_FOUND": "FILE_NOT_FOUND",
    "PE_PARSE_FAILED": "NOT_A_PE",
    "RVA_NOT_IN_ANY_SECTION": "ADDRESS_OUTSIDE_SECTION",
    "FILE_OFFSET_NOT_MAPPED": "ADDRESS_OUTSIDE_SECTION",
    "RVA_HAS_NO_FILE_OFFSET": "ADDRESS_OUTSIDE_SECTION",
    "VA_BELOW_IMAGE_BASE": "ADDRESS_OUTSIDE_SECTION",
    "INVALID_ADDRESS": "INVALID_ADDRESS",
    "UNKNOWN_ADDRESS_KIND": "INVALID_ADDRESS_KIND",
}
# rizin's own stdout for `aflj` on a several-thousand-function binary is
# still well under a few MB of JSON; bound generously above that so a
# legitimate large binary is not silently truncated mid-JSON (which would
# turn a real result into a false RESULT_PARSE_FAILED), while still being
# nowhere near "unbounded" -- a hostile/pathological binary that somehow
# inflated this past the cap gets ANALYSIS_LIMITED via the truncation
# path in run_bounded_process, never an unbounded read.
_MAX_OUTPUT_CHARS = 16 * 1024 * 1024

# rizin's own per-instruction markers for bytes it could NOT decode. An
# undecodable byte is a COVERAGE FACT that must reach the caller, never a
# silent gap: the defect class this module was audited against is "a tool
# returns a result it did not produce on this call, and the result looks
# complete" (capstone sweeps stopping at the first bad byte and reporting
# the partial run as whole was the same shape).
_RIZIN_UNDECODABLE_TYPES = {"invalid", "illegal", "unknown", "undefined"}

# MEASURED on this machine (rizin 0.9.1, 2026-09-27), and the reason none of
# the consumers below treats the exit code as proof of anything:
#   rizin -q -c '?e MARK' <file>
#     -> stderr "ERROR: core: Error while parsing command: `?e MARK`"
#     -> stdout EMPTY, exit code 0
# i.e. a -c chain that failed to parse in its entirety still exits 0, so
# `returncode == 0` is a filter for hard launch failures only. The only
# trustworthy per-call evidence is rizin's own structured output for the
# very subcommands this call issued. Same measurement also showed rizin
# exits 0 and still answers `aaa; aflj` with a FABRICATED function on a
# 20-byte text file, which is why `rizin_functions` asks `iIj` in the same
# process (see `_rizin_load_probe`) instead of reading a function count as
# self-evidently meaningful.


def _extract_json_array(text: str):
    """Extract exactly ONE complete JSON array out of rizin's stdout.

    ``json.JSONDecoder.raw_decode`` (which reports where the decoded value
    ENDS) replaces the previous ``find("[")`` / ``rfind("]")`` bracket-span
    guess, for two reasons that guess could not cover:

    1. this module now issues more than one rizin subcommand per process
       (``aaa; aflj; iIj``), so the array has to be delimited by the parser
       rather than by the last bracket anywhere in the buffer;
    2. a stdout buffer truncated at ``_MAX_OUTPUT_CHARS`` can end INSIDE the
       array, and a bracket-span guess can hand a silently PARTIAL list to
       the caller as though it were whole -- raw_decode fails on it instead.

    Returns ``(list, end_index, "OK")``, ``(None, None, "ABSENT")`` when no
    ``[`` appears at all, or ``(None, None, "MALFORMED")`` when one appears
    but no complete array can be decoded from it. Those two failure reasons
    are kept apart deliberately: "rizin printed no JSON" and "rizin printed
    broken JSON" are different diagnoses.
    """
    decoder = json.JSONDecoder()
    pos = text.find("[")
    if pos == -1:
        return None, None, "ABSENT"
    while pos != -1:
        try:
            value, end = decoder.raw_decode(text, pos)
        except ValueError:
            pos = text.find("[", pos + 1)
            continue
        if isinstance(value, list):
            return value, end, "OK"
        pos = text.find("[", pos + 1)
    return None, None, "MALFORMED"


def _rizin_load_probe(text: str) -> dict:
    """Did rizin actually LOAD a binary on THIS call?

    ``rizin_functions`` asks for ``iIj`` (rizin's own binary-info JSON) in
    the SAME single process as ``aaa; aflj``, so a suspicious function list
    can be attributed instead of guessed at. Measured on this machine: for
    a real PE, ``iIj`` carries ``arch``/``bintype``/``os`` and
    ``havecode: true``; for a 20-byte text file rizin exits 0 and still
    answers, but with none of those and ``havecode: false``.

    A NAMED status with three values, not a bool -- because the difference
    between the last two is exactly the difference between "there are no
    functions" and "I cannot tell whether there are functions":
    ``BINARY_LOADED`` / ``NO_BINARY_LOADED`` / ``PROBE_UNAVAILABLE``.
    """
    start = text.find("{")
    if start == -1:
        return {"status": "PROBE_UNAVAILABLE", "reason": "RIZIN_IIJ_NO_JSON_OBJECT"}
    try:
        info, _end = json.JSONDecoder().raw_decode(text, start)
    except ValueError as exc:
        return {"status": "PROBE_UNAVAILABLE", "reason": f"RIZIN_IIJ_UNPARSEABLE: {type(exc).__name__}"}
    if not isinstance(info, dict):
        return {"status": "PROBE_UNAVAILABLE", "reason": "RIZIN_IIJ_NOT_AN_OBJECT"}
    loaded = bool(info.get("havecode")) or (bool(info.get("arch")) and bool(info.get("bintype")))
    return {
        "status": "BINARY_LOADED" if loaded else "NO_BINARY_LOADED",
        "bintype": info.get("bintype"), "arch": info.get("arch"),
        "bits": info.get("bits"), "havecode": bool(info.get("havecode")),
    }


def _instruction_decode_status(ins: dict) -> str:
    """One rizin ``pdj`` entry's own decode verdict as a named status --
    ``DECODED`` or ``UNDECODABLE`` -- read from rizin's ``type``/``opcode``
    fields rather than assumed. rizin happily returns an entry for a byte it
    could not decode (``"type": "invalid"``, ``"opcode": "invalid"``); such
    an entry is not an instruction and must never be counted as one by a
    caller planning a patch over it."""
    ins_type = str(ins.get("type") or "").strip().lower()
    opcode = str(ins.get("opcode") or ins.get("disasm") or "").strip().lower()
    if ins_type in _RIZIN_UNDECODABLE_TYPES:
        return "UNDECODABLE"
    if not opcode or opcode.split(None, 1)[0] in _RIZIN_UNDECODABLE_TYPES:
        return "UNDECODABLE"
    return "DECODED"


def _rizin_binary() -> str | None:
    """env override -> PATH -> known portable install. Never raises."""
    explicit = os.getenv("RIZIN_HOME", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        for candidate in (p / "rizin.exe", p / "bin" / "rizin.exe"):
            if candidate.exists():
                return str(candidate)
    found = shutil.which("rizin") or shutil.which("rizin.exe")
    if found:
        return found
    return None


def _rizin_asm_binary() -> str | None:
    """Same resolution order as ``_rizin_binary`` for rizin's standalone
    assembler/disassembler CLI (``rz-asm.exe``), which ships next to
    ``rizin.exe`` in the same ``bin`` directory."""
    explicit = os.getenv("RIZIN_HOME", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            p = p.parent
        for candidate in (p / "rz-asm.exe", p / "bin" / "rz-asm.exe"):
            if candidate.exists():
                return str(candidate)
    found = shutil.which("rz-asm") or shutil.which("rz-asm.exe")
    if found:
        return found
    return None


def _resolve_address(path: str, address, address_kind: str):
    """Resolve one address (given as va/rva/file_offset) to all four forms
    via ``pe_address.normalize_address`` -- the same real-PE-section-table
    resolver ``constant_at_address_verifier.py`` uses -- plus the rizin
    ``-a``/``-b`` flags for the PE's real architecture. Returns
    ``(resolved_dict, None)`` or ``(None, fail_dict)``, never raises."""
    resolved = normalize_address(path, address, address_kind)
    if not resolved.get("ok"):
        status = _ADDRESS_ERROR_TO_STATUS.get(resolved.get("error"), "ADDRESS_UNRESOLVED")
        return None, {"ok": False, "status": status, "address_kind": address_kind, "address_resolution": resolved}
    machine_int = int(resolved["machine"], 16)
    arch_bits = _MACHINE_TO_ARCH_BITS.get(machine_int)
    if arch_bits is None:
        return None, {"ok": False, "status": "ARCHITECTURE_NOT_SUPPORTED", "machine": resolved["machine"]}
    resolved["rizin_arch"], resolved["bits"] = arch_bits
    resolved["given_as"] = address_kind
    return resolved, None


def _address_form(path: str, va_hex: str) -> dict:
    """The shared ``pe_address.AddressForm`` contract, serialised, for one
    absolute VA -- or a ``{"resolved": False, "error": ...}`` marker if it
    falls outside every real PE section. Every address this module reports
    (an instruction's own location, a branch target, a patch site) goes
    through this one call, so the listing and the patch planner return the
    identical shape the IDA-engine path (tools_ida.py (upstream-only; not part of the published package)) also returns."""
    form, err = resolve_address_form(path, va_hex, "va")
    if form is None:
        return {"resolved": False, "error": err.get("error")}
    return form.to_dict()


def _start_address_form(resolved: dict) -> dict:
    """AddressForm for a start address already resolved by
    ``_resolve_address`` (which additionally carries ``machine``/``bits``
    this helper does not need)."""
    return AddressForm(
        file_offset=resolved["file_offset"], rva=resolved["rva"], va=resolved["va"],
        image_base=resolved["image_base"], section=resolved["section"],
    ).to_dict()


def _pdj(exe: str, path: str, resolved: dict, count: int, timeout_seconds, cancellation_token):
    """Run one headless rizin process (`pdj <count> @ <va>`, rizin's own
    JSON instruction listing) and return ``(list_of_raw_instructions,
    None)`` or ``(None, fail_dict)``. Architecture/bits are pinned to the
    PE's real header (``resolved['rizin_arch']``/``resolved['bits']``),
    never rizin's own auto-detection."""
    va = resolved["va"]
    cmd = [exe, "-q", "-a", resolved["rizin_arch"], "-b", str(resolved["bits"]), "-c", f"pdj {count} @ {va}", str(path)]
    cp = run_bounded_process(cmd, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token, max_output_chars=_MAX_OUTPUT_CHARS)
    if cp.cancelled:
        return None, {"ok": False, "status": "CANCELLED", "error": "RIZIN_CANCELLED_PROCESS_TREE_TERMINATED"}
    if cp.timed_out:
        return None, {"ok": False, "status": "TIMEOUT", "timeout_seconds": timeout_seconds, "error": "RIZIN_TIMEOUT_PROCESS_TREE_TERMINATED"}
    if cp.returncode not in (0, None):
        return None, {"ok": False, "status": "ANALYSIS_LIMITED", "exit_code": cp.returncode, "stderr_tail": (cp.stderr or "")[-2000:], "stdout_tail": (cp.stdout or "")[-500:]}
    # A stdout buffer that hit the output cap is a PARTIAL listing: never
    # parse it as if it were the whole answer. run_bounded_process reports
    # this on its ordinary (returncode 0) return path, so the check has to
    # live here rather than only inside an error branch.
    if getattr(cp, "output_truncated", False):
        return None, {"ok": False, "status": "ANALYSIS_LIMITED", "error": "RIZIN_OUTPUT_TRUNCATED_AT_CAP",
                      "max_output_chars": _MAX_OUTPUT_CHARS, "output_truncated": True}
    stdout = cp.stdout or ""
    raw, _end, extraction = _extract_json_array(stdout)
    if extraction == "ABSENT":
        return None, {"ok": False, "status": "ANALYSIS_LIMITED", "error": "RIZIN_NO_JSON_OUTPUT", "stdout_tail": stdout[-2000:], "stderr_tail": (cp.stderr or "")[-2000:]}
    if extraction == "MALFORMED":
        return None, {"ok": False, "status": "RESULT_PARSE_FAILED", "error": "RIZIN_PDJ_JSON_MALFORMED",
                      "stdout_tail": stdout[-2000:], "stderr_tail": (cp.stderr or "")[-2000:]}
    if not raw:
        return None, {"ok": False, "status": "DISASSEMBLY_FAILED", "error": "RIZIN_PDJ_EMPTY_OR_NOT_A_LIST"}
    return raw, None


def _instruction_entry(path: str, ins: dict) -> dict:
    """One rizin `pdj` instruction normalized into the flat four-address-
    form contract this module and the IDA path (tools_ida.py (upstream-only; not part of the published package)) both return,
    so a caller can switch engines without changing how it reads results."""
    opcode = str(ins.get("opcode") or ins.get("disasm") or "").strip()
    parts = opcode.split(None, 1)
    mnemonic = parts[0] if parts else ""
    operands = parts[1] if len(parts) > 1 else ""
    offset = ins.get("offset")
    try:
        address = _address_form(path, hex(int(offset)))
    except (TypeError, ValueError):
        address = {"resolved": False, "error": "RIZIN_INSTRUCTION_HAS_NO_USABLE_OFFSET"}
    entry = {
        "address": address,
        "bytes": ins.get("bytes", ""),
        "mnemonic": mnemonic,
        "operands": operands,
        "length": ins.get("size"),
        # Named per-instruction verdict, so a caller reading this listing can
        # never mistake a byte rizin failed to decode for a decoded one.
        "decode_status": _instruction_decode_status(ins),
    }
    jump = ins.get("jump")
    if jump is not None:
        try:
            entry["branch_target"] = _address_form(path, hex(int(jump)))
        except (TypeError, ValueError):
            entry["branch_target"] = {"resolved": False, "error": "RIZIN_BRANCH_TARGET_NOT_AN_INTEGER"}
    return entry


def rizin_disasm_listing(
    path,
    address,
    address_kind: str = "va",
    count: int = 20,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    cancellation_token=None,
) -> str:
    """Raw rizin instruction listing (`pdj`, rizin's own JSON disassembly)
    starting at ``address`` -- given as ``address_kind``: ``"va"``
    (default), ``"rva"`` or ``"file_offset"``, resolved through
    ``pe_address.normalize_address`` against the real PE section table,
    never a hardcoded/assumed delta. Every instruction, and the resolved
    branch target for every branch/call, is returned in all four address
    forms together (file_offset + rva + va + section) -- address-space
    confusion between these caused a wrong diagnosis in this project, so
    the four-form return is not optional. Architecture is read from the
    PE's own IMAGE_FILE_HEADER.Machine and passed to rizin explicitly
    (`-a`/`-b`), never taken as a parameter or left to auto-detection.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND,
    INVALID_ADDRESS, INVALID_ADDRESS_KIND, ADDRESS_OUTSIDE_SECTION,
    ARCHITECTURE_NOT_SUPPORTED, TIMEOUT, CANCELLED, ANALYSIS_LIMITED,
    RESULT_PARSE_FAILED, DISASSEMBLY_FAILED.
    """
    exe = _rizin_binary()
    if not exe:
        return _j({"ok": False, "tool": "rizin_disasm_listing", "status": "TOOL_MISSING", "required_capability": "rizin (rizin.exe)"})
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "rizin_disasm_listing", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "rizin_disasm_listing", "status": "NOT_FOUND", "path": str(path)})

    resolved, err = _resolve_address(str(p), address, address_kind)
    if err is not None:
        return _j({"tool": "rizin_disasm_listing", **err})

    count = max(1, min(int(count), _MAX_DISASM_COUNT))
    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))

    raw, err = _pdj(exe, p, resolved, count, timeout_seconds, cancellation_token)
    if err is not None:
        return _j({"tool": "rizin_disasm_listing", **err})

    instructions = [_instruction_entry(str(p), ins) for ins in raw[:count] if isinstance(ins, dict)]
    if not instructions:
        return _j({"ok": False, "tool": "rizin_disasm_listing", "status": "DISASSEMBLY_FAILED", "error": "RIZIN_PDJ_NO_INSTRUCTION_DICTS"})

    # Honest coverage, as a named status rather than a bool: a listing that
    # contains bytes rizin could not decode is NOT the same answer as a
    # fully decoded one, and the caller has to be able to tell without
    # re-deriving it from the per-instruction entries.
    undecodable = sum(1 for e in instructions if e["decode_status"] == "UNDECODABLE")
    decoded = len(instructions) - undecodable
    if undecodable == 0:
        coverage = "FULLY_DECODED"
    elif decoded == 0:
        coverage = "NOTHING_DECODED"
    else:
        coverage = "PARTIALLY_DECODED"
    covered_bytes = sum(int(e["length"]) for e in instructions if isinstance(e.get("length"), int))

    return _j({
        "ok": True, "tool": "rizin_disasm_listing", "status": "OK",
        "engine": "rizin", "path": relative(p), "architecture": f"{resolved['rizin_arch']}_{resolved['bits']}",
        "given_as": address_kind,
        "start": _start_address_form(resolved),
        "count_requested": count, "count_returned": len(instructions),
        "decode_coverage": {
            "status": coverage,
            "instructions_decoded": decoded,
            "instructions_undecodable": undecodable,
            "bytes_covered": covered_bytes,
        },
        "instructions": instructions,
    })


def _rz_asm_encode(exe_asm: str, resolved: dict, va: str, line: str, timeout_seconds, cancellation_token):
    """Assemble one instruction line at ``va`` via `rz-asm.exe` (never
    writing anything to disk -- this is a standalone assembler CLI call,
    not a file open). Returns ``(bytes, None)`` or ``(None, fail_dict)``."""
    cmd = [exe_asm, "-a", resolved["rizin_arch"], "-b", str(resolved["bits"]), "-o", va, line]
    cp = run_bounded_process(cmd, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token, max_output_chars=_MAX_OUTPUT_CHARS)
    if cp.cancelled:
        return None, {"ok": False, "status": "CANCELLED", "error": "RZ_ASM_CANCELLED_PROCESS_TREE_TERMINATED"}
    if cp.timed_out:
        return None, {"ok": False, "status": "TIMEOUT", "error": "RZ_ASM_TIMEOUT_PROCESS_TREE_TERMINATED"}
    out = (cp.stdout or "").strip()
    if cp.returncode not in (0, None) or not out or "ERROR" in out.upper():
        return None, {"ok": False, "status": "ASSEMBLY_FAILED", "instruction": line, "exit_code": cp.returncode, "stderr_tail": (cp.stderr or "")[-1000:], "stdout_tail": out[-1000:]}
    try:
        encoded = bytes.fromhex(out.split()[0])
    except ValueError as exc:
        return None, {"ok": False, "status": "ASSEMBLY_FAILED", "instruction": line, "error": f"{type(exc).__name__}: {exc}", "stdout_tail": out[-1000:]}
    if not encoded:
        return None, {"ok": False, "status": "ASSEMBLY_FAILED", "instruction": line, "error": "RZ_ASM_EMPTY_ENCODING"}
    return encoded, None


def _rz_asm_disasm(exe_asm: str, resolved: dict, va: str, data: bytes, timeout_seconds, cancellation_token):
    """Round-trip ``data`` (raw bytes, e.g. a just-planned patch) back
    through rz-asm's disassembler at ``va``, returning one text line per
    decoded instruction (``["mnemonic operands", ...]``) or a fail dict."""
    cmd = [exe_asm, "-a", resolved["rizin_arch"], "-b", str(resolved["bits"]), "-o", va, "-d", data.hex()]
    cp = run_bounded_process(cmd, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token, max_output_chars=_MAX_OUTPUT_CHARS)
    if cp.cancelled:
        return None, {"ok": False, "status": "CANCELLED", "error": "RZ_ASM_CANCELLED_PROCESS_TREE_TERMINATED"}
    if cp.timed_out:
        return None, {"ok": False, "status": "TIMEOUT", "error": "RZ_ASM_TIMEOUT_PROCESS_TREE_TERMINATED"}
    out = cp.stdout or ""
    if cp.returncode not in (0, None) or not out.strip():
        return None, {"ok": False, "status": "DISASSEMBLY_FAILED", "exit_code": cp.returncode, "stderr_tail": (cp.stderr or "")[-1000:]}
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    # This round trip is the ONLY verification the patch planners have that
    # the bytes they are about to hand a caller really decode back into the
    # instructions they intended. rz-asm prints "invalid" and still exits 0
    # for bytes it cannot decode, so accepting such a line would turn the
    # verification into decoration and let a plan be returned with
    # `disasm_after: ["invalid"]` and `ok: true`.
    bad = [ln for ln in lines if ln.split(None, 1)[0].strip(".").lower() in _RIZIN_UNDECODABLE_TYPES]
    if bad:
        return None, {"ok": False, "status": "DISASSEMBLY_FAILED",
                      "error": "RZ_ASM_ROUNDTRIP_UNDECODABLE",
                      "detail": "rz-asm could not decode the planned bytes back into instructions, "
                                "so the round-trip verification this plan depends on did not happen",
                      "undecodable_lines": bad[:16], "disasm_lines": lines[:16]}
    return lines, None


def _instruction_size_and_bytes(ins: dict, index: int):
    """``(size, raw_bytes, None)`` for one rizin ``pdj`` entry, or
    ``(None, None, fail_dict)``. rizin's own entry is not guaranteed to
    carry a usable ``size``/``bytes`` pair (version drift, undecodable
    bytes); reading them with ``ins["size"]`` raised a KeyError straight out
    of a patch-planning path, and guessing a length here would be worse
    still -- a patch plan built on a length nobody measured is exactly the
    "result the tool did not produce" shape this module was audited for."""
    try:
        size = int(ins["size"])
        raw = bytes.fromhex(str(ins["bytes"]))
    except (KeyError, TypeError, ValueError) as exc:
        return None, None, {"ok": False, "status": "NOT_RECOVERABLE",
                            "error": "RIZIN_INSTRUCTION_SIZE_OR_BYTES_MISSING",
                            "instruction_index": index,
                            "detail": f"{type(exc).__name__}: {exc}"}
    if size <= 0 or len(raw) != size:
        return None, None, {"ok": False, "status": "NOT_RECOVERABLE",
                            "error": "RIZIN_INSTRUCTION_SIZE_BYTES_INCONSISTENT",
                            "instruction_index": index, "size": size, "bytes_length": len(raw)}
    return size, raw, None


def _plan_force_branch(path, exe_asm, resolved, first_ins, timeout_seconds, cancellation_token):
    ins_type = str(first_ins.get("type") or "").strip().lower()
    opcode = str(first_ins.get("opcode") or first_ins.get("disasm") or "").strip()
    # "I could not determine what this instruction is" is NOT the answer
    # "this is not a conditional branch". Collapsing the two renders a
    # missing measurement as a definite negative -- the same polarity of
    # defect as a slicer reporting "no write found" for a question that
    # never applied. rizin returns an entry (type "invalid", or no type at
    # all) for bytes it failed to decode, and exits 0 either way.
    if _instruction_decode_status(first_ins) == "UNDECODABLE" or not ins_type:
        return {"ok": False, "status": "NOT_RECOVERABLE",
                "error": "RIZIN_INSTRUCTION_TYPE_NOT_RECOVERABLE",
                "detail": "rizin returned no usable instruction classification at this address, so "
                          "whether it is a conditional branch CANNOT be determined -- this is not "
                          "the same answer as NOT_A_CONDITIONAL_BRANCH",
                "instruction": opcode, "rizin_type": ins_type or None}
    if ins_type != "cjmp":
        return {"ok": False, "status": "NOT_A_CONDITIONAL_BRANCH", "instruction": opcode}
    target = first_ins.get("jump")
    if target is None:
        return {"ok": False, "status": "NO_DIRECT_BRANCH_TARGET", "instruction": opcode}

    original_length, original_bytes, size_err = _instruction_size_and_bytes(first_ins, 0)
    if size_err is not None:
        return size_err
    va = resolved["va"]
    try:
        target_hex = hex(int(target))
    except (TypeError, ValueError):
        return {"ok": False, "status": "NOT_RECOVERABLE", "error": "RIZIN_BRANCH_TARGET_NOT_AN_INTEGER",
                "instruction": opcode, "jump": target}

    new_jmp, err = _rz_asm_encode(exe_asm, resolved, va, f"jmp {target_hex}", timeout_seconds, cancellation_token)
    if err is not None:
        return err
    if len(new_jmp) > original_length:
        return {
            "ok": False, "status": "TARGET_TOO_FAR_FOR_ORIGINAL_LENGTH",
            "original_length": original_length, "unconditional_jump_length": len(new_jmp),
        }

    pad = original_length - len(new_jmp)
    patched = new_jmp + b"\x90" * pad

    after_lines, err = _rz_asm_disasm(exe_asm, resolved, va, patched, timeout_seconds, cancellation_token)
    if err is not None:
        return err

    warnings = []
    if len(after_lines) != 1:
        warnings.append(
            f"instruction boundaries inside the patched region changed: 1 instruction "
            f"({original_length} byte(s)) became {len(after_lines)} instructions "
            f"({len(new_jmp)}-byte jmp + {pad} NOP byte(s)); total region length is "
            f"unchanged so every address AFTER this region is unaffected."
        )

    return {
        "ok": True, "status": "OK",
        "address": _start_address_form(resolved),
        "original_length": original_length, "patched_length": len(patched),
        "original_bytes": original_bytes.hex(), "patched_bytes": patched.hex(),
        "branch_target": _address_form(path, target_hex),
        "disasm_before": [opcode],
        "disasm_after": after_lines,
        "warnings": warnings,
    }


def _plan_nop_out(path, exe_asm, resolved, instructions, instruction_count, timeout_seconds, cancellation_token):
    if len(instructions) < instruction_count:
        return {"ok": False, "status": "NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW", "requested": instruction_count, "decoded": len(instructions)}

    window = instructions[:instruction_count]
    # A byte rizin could not decode is not an instruction. NOP-ing over a
    # window that contains one would report "N instructions replaced" for a
    # region whose contents were never actually decoded -- a partial result
    # dressed as a complete one, and here it also decides what gets written
    # to a file.
    undecodable = [i for i, ins in enumerate(window) if _instruction_decode_status(ins) == "UNDECODABLE"]
    if undecodable:
        return {"ok": False, "status": "NOT_RECOVERABLE",
                "error": "UNDECODABLE_INSTRUCTION_IN_WINDOW",
                "detail": "rizin marked at least one entry in the requested window as undecodable, so "
                          "the window's real instruction boundaries are unknown and no patch length "
                          "can be honestly computed for it",
                "undecodable_indices": undecodable, "requested": instruction_count}
    total_length = 0
    original_chunks = []
    for i, ins in enumerate(window):
        size, raw, size_err = _instruction_size_and_bytes(ins, i)
        if size_err is not None:
            return size_err
        total_length += size
        original_chunks.append(raw)
    original_bytes = b"".join(original_chunks)
    patched = b"\x90" * total_length
    disasm_before = [str(i.get("opcode") or i.get("disasm") or "").strip() for i in window]

    after_lines, err = _rz_asm_disasm(exe_asm, resolved, resolved["va"], patched, timeout_seconds, cancellation_token)
    if err is not None:
        return err

    warnings = []
    if len(after_lines) != len(window):
        warnings.append(
            f"instruction boundaries inside the patched region changed: {len(window)} "
            f"instruction(s) became {len(after_lines)} NOP instruction(s); total region "
            f"length ({total_length} byte(s)) is unchanged so every address AFTER this "
            f"region is unaffected."
        )

    return {
        "ok": True, "status": "OK",
        "address": _start_address_form(resolved),
        "instruction_count": instruction_count,
        "original_length": total_length, "patched_length": len(patched),
        "original_bytes": original_bytes.hex(), "patched_bytes": patched.hex(),
        "disasm_before": disasm_before,
        "disasm_after": after_lines,
        "warnings": warnings,
    }


def rizin_patch_plan(
    path,
    address,
    operation: str,
    address_kind: str = "va",
    instruction_count: int = 1,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    cancellation_token=None,
) -> str:
    """Plan -- and NEVER apply -- a byte-level patch at ``address`` (same
    ``address_kind`` convention as ``rizin_disasm_listing``) inside a real
    PE, built on rizin's own assembler/disassembler (`rz-asm.exe`). This
    function never opens the target file for writing; it only computes and
    returns the bytes a separate, explicit ``rizin_patch_apply`` call would
    need to write to a NEW output file.

    ``operation``:
      - ``"force_branch"``: the conditional jump at ``address`` becomes an
        unconditional jump to the SAME target with the SAME total
        instruction length -- rz-asm's shorter unconditional-jump encoding
        (e.g. ``0F 84 rel32`` (6 bytes) -> ``E9 rel32`` (5 bytes)) is padded
        with ``0x90`` so every byte after this instruction keeps its
        original address.
      - ``"nop_out"``: the ``instruction_count`` real instructions starting
        at ``address`` become ``0x90`` padding of exactly their combined
        original length.

    Returns file_offset/rva/va/section, original_bytes/patched_bytes (hex),
    a round-tripped disassembly of both the original and the patched bytes
    (``disasm_before``/``disasm_after``), and a ``warnings`` list whenever
    the patch changes the instruction count inside the patched region.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND,
    INVALID_ADDRESS, INVALID_ADDRESS_KIND, ADDRESS_OUTSIDE_SECTION,
    ARCHITECTURE_NOT_SUPPORTED, UNKNOWN_OPERATION, NOT_A_CONDITIONAL_BRANCH,
    NO_DIRECT_BRANCH_TARGET, TARGET_TOO_FAR_FOR_ORIGINAL_LENGTH,
    NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW, ASSEMBLY_FAILED, DISASSEMBLY_FAILED,
    TIMEOUT, CANCELLED, ANALYSIS_LIMITED, RESULT_PARSE_FAILED,
    NOT_RECOVERABLE.

    ``NOT_RECOVERABLE`` is deliberately distinct from
    ``NOT_A_CONDITIONAL_BRANCH``: it means rizin did not decode/classify the
    bytes at this address at all (undecodable byte, missing size/bytes,
    non-integer branch target), so the question could not be answered --
    never that the answer was no.
    """
    exe = _rizin_binary()
    if not exe:
        return _j({"ok": False, "tool": "rizin_patch_plan", "status": "TOOL_MISSING", "required_capability": "rizin (rizin.exe)"})
    exe_asm = _rizin_asm_binary()
    if not exe_asm:
        return _j({"ok": False, "tool": "rizin_patch_plan", "status": "TOOL_MISSING", "required_capability": "rizin (rz-asm.exe)"})
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "rizin_patch_plan", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "rizin_patch_plan", "status": "NOT_FOUND", "path": str(path)})

    op = str(operation or "").strip().lower()
    if op not in {"force_branch", "nop_out"}:
        return _j({"ok": False, "tool": "rizin_patch_plan", "status": "UNKNOWN_OPERATION", "operation": operation, "allowed": ["force_branch", "nop_out"]})

    resolved, err = _resolve_address(str(p), address, address_kind)
    if err is not None:
        return _j({"tool": "rizin_patch_plan", "operation": op, **err})

    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
    instruction_count = max(1, min(int(instruction_count), 64))
    fetch_count = 1 if op == "force_branch" else instruction_count

    raw, err = _pdj(exe, p, resolved, fetch_count, timeout_seconds, cancellation_token)
    if err is not None:
        return _j({"tool": "rizin_patch_plan", "operation": op, **err})
    instructions = [ins for ins in raw if isinstance(ins, dict)]
    if not instructions:
        return _j({"ok": False, "tool": "rizin_patch_plan", "operation": op, "status": "NOT_RECOVERABLE",
                    "error": "RIZIN_PDJ_NO_INSTRUCTION_DICTS",
                    "detail": "rizin returned a JSON array with no instruction objects in it, so nothing "
                              "at this address was decoded and no patch can be planned against it"})

    if op == "force_branch":
        plan = _plan_force_branch(str(p), exe_asm, resolved, instructions[0], timeout_seconds, cancellation_token)
    else:
        plan = _plan_nop_out(str(p), exe_asm, resolved, instructions, instruction_count, timeout_seconds, cancellation_token)

    return _j({"tool": "rizin_patch_plan", "operation": op, "engine": "rizin", "path": relative(p), **plan})


def rizin_patch_apply(path, file_offset, patched_bytes: str, output_path=None, expected_bytes=None) -> str:
    """Apply-only step, deliberately separate from ``rizin_patch_plan``: it
    never touches ``path``. It copies ``path`` to a NEW ``output_path``
    (default: ``<name>.patched<suffix>`` next to the original, inside the
    same workspace) and overwrites the bytes at ``file_offset`` with
    ``patched_bytes`` (lowercase hex, no separators -- exactly the
    ``patched_bytes`` field a prior ``rizin_patch_plan`` call returned).
    Returns the output path and its sha256 -- read back FROM DISK after the
    write, never hashed from the in-memory buffer -- so the write is
    verifiable evidence, not a claim.

    ``expected_bytes`` (optional hex, e.g. the ``original_bytes`` a prior
    ``rizin_patch_plan`` returned) is a precondition, not a comment: when
    given, the bytes currently at ``file_offset`` must equal it or the call
    is refused with ``EXPECTED_BYTES_MISMATCH`` and nothing is written --
    the same gate ``binary_patch`` makes mandatory. It is optional here only
    because this function never modifies its input file (it always writes a
    separate copy, so the original remains its own backup); the returned
    ``expected_bytes_verification`` says which of VERIFIED /
    NOT_REQUESTED actually happened, so an unverified write can never read
    as a verified one.

    Status vocabulary: OK, PATH_REFUSED, NOT_FOUND, INVALID_FILE_OFFSET,
    INVALID_PATCH_BYTES, INVALID_EXPECTED_BYTES, EXPECTED_BYTES_MISMATCH,
    OUTPUT_PATH_EQUALS_INPUT, READ_FAILED, WRITE_FAILED,
    WRITE_VERIFICATION_FAILED.
    """
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "NOT_FOUND", "path": str(path)})

    try:
        offset = int(str(file_offset), 0)
    except (TypeError, ValueError):
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "INVALID_FILE_OFFSET", "file_offset": file_offset})
    try:
        patch_bytes = bytes.fromhex(str(patched_bytes))
    except ValueError as exc:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "INVALID_PATCH_BYTES", "error": f"{type(exc).__name__}: {exc}"})

    if output_path:
        try:
            out = safe_path(output_path)
        except PermissionError as exc:
            return _j({"ok": False, "tool": "rizin_patch_apply", "status": "PATH_REFUSED", "error": str(exc)})
    else:
        out = p.with_name(f"{p.stem}.patched{p.suffix}")

    if out.resolve() == p.resolve():
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "OUTPUT_PATH_EQUALS_INPUT", "output_path": str(out)})

    expected = None
    if expected_bytes not in (None, ""):
        expected = _parse_hex_bytes(expected_bytes)
        if not expected:
            return _j({"ok": False, "tool": "rizin_patch_apply", "status": "INVALID_EXPECTED_BYTES",
                        "expected_bytes": expected_bytes})

    try:
        data = bytearray(p.read_bytes())
    except OSError as exc:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "READ_FAILED", "error": str(exc)})
    if offset < 0 or offset + len(patch_bytes) > len(data):
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "INVALID_FILE_OFFSET", "file_offset": hex(offset), "file_size": len(data)})

    if expected is not None:
        current = bytes(data[offset:offset + len(expected)])
        if offset + len(expected) > len(data) or current != expected:
            return _j({"ok": False, "tool": "rizin_patch_apply", "status": "EXPECTED_BYTES_MISMATCH",
                        "file_offset": hex(offset), "expected": expected.hex(), "found": current.hex(),
                        "detail": "the bytes currently at this offset are not the bytes the plan was "
                                  "built against; nothing was written"})

    data[offset:offset + len(patch_bytes)] = patch_bytes
    intended = bytes(data)

    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        out.write_bytes(intended)
    except OSError as exc:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "WRITE_FAILED", "error": str(exc)})

    # Read the result BACK FROM DISK and hash that, not the buffer we meant
    # to write: hashing the in-memory bytes reports a digest for a file that
    # may never have been fully written, which is precisely the "result the
    # tool did not produce on this call" shape -- and the digest is published
    # as evidence.
    try:
        written = out.read_bytes()
    except OSError as exc:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "WRITE_VERIFICATION_FAILED",
                    "error": f"OUTPUT_UNREADABLE: {exc}", "output_path": relative(out)})
    if written != intended:
        return _j({"ok": False, "tool": "rizin_patch_apply", "status": "WRITE_VERIFICATION_FAILED",
                    "output_path": relative(out),
                    "intended_size": len(intended), "written_size": len(written),
                    "sha256_intended": hashlib.sha256(intended).hexdigest(),
                    "sha256_written": hashlib.sha256(written).hexdigest(),
                    "detail": "the bytes on disk after the write do not match the bytes this call "
                              "computed; the output file is NOT the planned patch"})
    digest = hashlib.sha256(written).hexdigest()

    form, _err = resolve_address_form(str(p), hex(offset), "file_offset")
    return _j({
        "ok": True, "tool": "rizin_patch_apply", "status": "OK",
        "input_path": relative(p), "output_path": relative(out),
        "address": form.to_dict() if form is not None else {"resolved": False, "file_offset": hex(offset)},
        "bytes_written": len(patch_bytes),
        "expected_bytes_verification": "VERIFIED" if expected is not None else "NOT_REQUESTED",
        "sha256": digest,
        "sha256_source": "READ_BACK_FROM_DISK",
    })


_NOP_BYTE = b"\x90"
_MAX_PATCHES_PER_CALL = 64


def _default_backup_path(p: Path) -> Path:
    """One deterministic sidecar per target, next to it, inside the same
    workspace -- ``rizin_patch_apply`` above never touches the input at all
    (it always writes a new ``.patched`` copy, so the original already IS
    its own backup); ``binary_patch`` below can write IN PLACE instead
    (operator's ``trybypassme``-class requirement: the target's own bytes on
    disk change, no new file, no new module, no new thread), so this is
    the one thing that must exist before that first in-place write ever
    happens. Never overwritten by a later ``apply`` call (see
    ``binary_patch``'s own in-place branch) so it always holds the ORIGINAL,
    pre-any-patch bytes, not the last patch's state."""
    return p.with_name(p.name + ".liebert_orig_backup")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_hex_bytes(value):
    """Tolerant hex-bytes parser (``"90 90"``, ``"9090"``, ``"0x90,0x90"``
    all accepted) -- ``None``/odd-length/non-hex input returns ``None``,
    never raises."""
    if value in (None, ""):
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(value))
    if not cleaned or len(cleaned) % 2:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _open_pe_from_bytes(data: bytes):
    """Same owned-bytes convention ``tools_binary._pe``/``pe_address._open_pe``
    already use: parse from bytes already in memory, never
    ``pefile.PE(str(path))``, so no Windows file handle is ever retained
    after this call returns."""
    import pefile
    return pefile.PE(data=data, fast_load=False)


_MACHINE_TO_KEYSTONE_BITS = {0x14C: 32, 0x8664: 64}


def _assemble_with_keystone(asm_text: str, bits: int, va_int: int):
    """Assemble ``asm_text`` (one or more ';'-separated x86/x64 instructions,
    e.g. ``"mov eax, 1; ret"``) at ``va_int`` via Keystone -- the repo's
    already-installed assembler this task named explicitly (distinct from
    ``rizin_patch_plan``'s rz-asm-subprocess path above, which was built to
    avoid a Keystone dependency for ITS narrower force_branch/nop_out
    operations; this general-purpose patch path has no such constraint and
    Keystone lets it assemble without spawning rizin at all, so it also
    works wherever rizin/rz-asm are not installed). Returns ``(bytes, None)``
    or ``(None, error_string)``, never raises."""
    try:
        from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks, KsError
    except Exception as exc:  # pragma: no cover - keystone is a hard requirement of this path
        return None, f"KEYSTONE_UNAVAILABLE: {type(exc).__name__}: {exc}"
    mode = KS_MODE_64 if bits == 64 else KS_MODE_32
    try:
        ks = Ks(KS_ARCH_X86, mode)
        encoding, count = ks.asm(asm_text, addr=va_int)
    except KsError as exc:
        return None, f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"
    if not encoding or not count:
        return None, "EMPTY_ASSEMBLY_OUTPUT"
    return bytes(encoding), None


def _section_boundary_check(pe, rva: int, length: int) -> dict:
    """A patch that runs off the end of its own section's RAW data is not a
    smaller version of the same mistake as an out-of-section RVA -- it is a
    silent file-layout corruption (writing into the next section's bytes, or
    past what the file actually stores on disk for a virtual-only/BSS
    range). Checked directly against ``pefile``'s own section table, not a
    fixed alignment guess."""
    section = pe.get_section_by_rva(rva)
    if section is None:
        return {"ok": False, "error": "RVA_NOT_IN_ANY_SECTION", "rva": hex(rva)}
    end_rva = rva + length - 1
    end_section = pe.get_section_by_rva(end_rva)
    if end_section is None or int(end_section.VirtualAddress) != int(section.VirtualAddress):
        return {"ok": False, "error": "PATCH_CROSSES_SECTION_BOUNDARY",
                "section": section.Name.rstrip(b"\x00").decode(errors="replace")}
    local_offset = rva - int(section.VirtualAddress)
    if local_offset + length > int(section.SizeOfRawData):
        return {"ok": False, "error": "PATCH_BEYOND_RAW_DATA",
                "section": section.Name.rstrip(b"\x00").decode(errors="replace"),
                "raw_size": int(section.SizeOfRawData)}
    return {"ok": True, "section": section.Name.rstrip(b"\x00").decode(errors="replace")}


_CRC_VARIANT_ALIASES = {"crc32", "ieee", "zlib", "crc32_ieee", "crc-32", "crc-32/iso-hdlc"}
_CRC_FIX_WINDOW_LENGTH = 4  # only length with a guaranteed unique closed-form solution
# (window_length*8 unknown bits must equal the CRC's 32-bit output width for the
# per-window linear system below to be square/invertible; 1-3 bytes are generically
# overdetermined [no solution], >4 bytes underdetermined [many solutions, not "the"
# unique fix] -- rejected explicitly rather than silently picked/iterated).


def _gf2_solve_linear(cols: list, target: int, n: int):
    """Solve ``sum_i x_i * cols[i] = target`` over GF(2) for the n-bit unknown
    vector ``x``, where each ``cols[i]`` is an n-bit int (column i of an n x n
    matrix over GF(2)) and ``target`` is an n-bit int. Plain Gauss-Jordan
    elimination (rows built by transposing the column list) -- O(n^3),
    trivial at n=32. Returns ``x`` as an int, or ``None`` if the system is
    singular (no unique solution) -- never guesses/iterates."""
    if len(cols) != n:
        return None
    rows = [0] * n
    for i, c in enumerate(cols):
        for r in range(n):
            if (c >> r) & 1:
                rows[r] |= (1 << i)
    rhs = [(target >> r) & 1 for r in range(n)]
    for col in range(n):
        pivot = None
        for i in range(col, n):
            if (rows[i] >> col) & 1:
                pivot = i
                break
        if pivot is None:
            return None  # singular: no unique solution
        rows[col], rows[pivot] = rows[pivot], rows[col]
        rhs[col], rhs[pivot] = rhs[pivot], rhs[col]
        for i in range(n):
            if i != col and (rows[i] >> col) & 1:
                rows[i] ^= rows[col]
                rhs[i] ^= rhs[col]
    x = 0
    for i in range(n):
        if rhs[i]:
            x |= (1 << i)
    return x


def solve_crc32_correction(data: bytes, window_offset: int, window_length: int, target_crc: int):
    """Closed-form (no trial-and-error) CRC-32 correction: return the
    ``window_length``-byte value to place at ``window_offset`` in ``data`` so
    that ``zlib.crc32`` of the WHOLE resulting buffer equals ``target_crc``
    (matching zlib's/PKZIP's/gzip's/PNG's standard IEEE 802.3 CRC-32, i.e.
    the same algorithm and convention ``zlib.crc32(bytes)`` implements --
    reflected, poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF).

    Math: ``zlib.crc32(buf, seed)`` is an AFFINE function of ``seed`` for
    fixed ``buf`` (a fact zlib's own ``crc32_combine`` relies on: any CRC
    built from a linear-feedback shift register is linear in its running
    state, with the processed bytes contributing only a fixed additive
    constant). That lets the 32x32 GF(2) linear map ``L(seed) =
    zlib.crc32(buf, seed) XOR zlib.crc32(buf, 0)`` be read off directly by
    probing zlib.crc32 with each of the 32 single-bit seeds -- no polynomial
    table, no manual LFSR stepping, just zlib's own (fast, C, trusted)
    implementation used as an oracle. Two such maps solve this in two steps:
    first invert the SUFFIX's map to find what CRC state must exist right
    after the window (given the target and the suffix, which is fixed);
    then invert the WINDOW's own map (this time varying the window's BYTES,
    not a seed, from the fixed prefix's CRC state) to find the exact window
    bytes that produce that state. Both maps are genuinely linear (not just
    affine-in-appearance) in their respective unknowns because a CRC table
    lookup is itself GF(2)-linear in its index; the closed-form Gauss-Jordan
    solve in ``_gf2_solve_linear`` inverts each one exactly, no search.

    Only ``window_length == 4`` (``_CRC_FIX_WINDOW_LENGTH``) has a
    guaranteed-unique solution (32 unknown bits against a 32-bit target);
    other lengths return ``None`` immediately. The caller MUST verify the
    result against a live ``zlib.crc32`` call on the fully reconstructed
    buffer before trusting it (``binary_patch`` below does exactly that,
    treating a mismatch as a hard failure, not a fallback).

    Returns the window bytes, or ``None`` if out of range or the derived
    linear system is singular (should not happen for a well-formed 4-byte
    window against the standard CRC-32 polynomial, which is designed to be
    invertible -- a ``None`` here is itself diagnostic evidence, not a bug
    to paper over)."""
    if window_length != _CRC_FIX_WINDOW_LENGTH:
        return None
    if window_offset < 0 or window_length <= 0 or window_offset + window_length > len(data):
        return None

    prefix = data[:window_offset]
    suffix = data[window_offset + window_length:]
    target = int(target_crc) & 0xFFFFFFFF
    n = 32

    crc_prefix = zlib.crc32(prefix) & 0xFFFFFFFF

    # Step 1: invert the suffix's affine map to find the CRC state (`g`)
    # that must exist right after the window, for the WHOLE file to end at
    # `target` once the (fixed) suffix is processed from that state.
    k_suf = zlib.crc32(suffix, 0) & 0xFFFFFFFF
    cols_suf = [(zlib.crc32(suffix, 1 << i) & 0xFFFFFFFF) ^ k_suf for i in range(n)]
    g = _gf2_solve_linear(cols_suf, target ^ k_suf, n)
    if g is None:
        return None

    # Step 2: invert the window's own affine map (fixed seed = crc_prefix,
    # UNKNOWN input = the window's own bytes) to find the window value that
    # drives the running CRC from crc_prefix to exactly `g`.
    bits = window_length * 8
    zero_window = bytes(window_length)
    k_win = zlib.crc32(zero_window, crc_prefix) & 0xFFFFFFFF

    def _probe(bit_index: int) -> bytes:
        return (1 << bit_index).to_bytes(window_length, "big")

    cols_win = [(zlib.crc32(_probe(i), crc_prefix) & 0xFFFFFFFF) ^ k_win for i in range(bits)]
    w_bits = _gf2_solve_linear(cols_win, g ^ k_win, bits)
    if w_bits is None:
        return None

    return w_bits.to_bytes(window_length, "big")


def _plan_one_patch(path_str: str, pe, orig_data: bytes, patch: dict, index: int, default_bits: int):
    """Resolve, VALIDATE (existing-bytes + section-boundary) and encode one
    patch entry against the ORIGINAL (pre-write) bytes/PE -- never mutates
    anything. Returns ``((file_offset, new_bytes, record), None)`` on
    success or ``(None, error_dict)`` on the first failure; the caller
    (``binary_patch``) aborts the WHOLE batch on any single failure, so a
    multi-patch call is all-or-nothing, never a partial write."""
    address = patch.get("address")
    address_kind = str(patch.get("address_kind") or "va").strip().lower()
    fmt = str(patch.get("format") or "hex").strip().lower()
    expected_hex = patch.get("expected_bytes")

    if address in (None, ""):
        return None, {"error": "ADDRESS_REQUIRED", "patch_index": index}
    if not expected_hex:
        return None, {"error": "EXPECTED_BYTES_REQUIRED", "patch_index": index,
                       "detail": "Guvenlik kontrolu: bu adresteki mevcut baytlar (expected_bytes) "
                                 "verilip dogrulanmadan yazma yapilmaz."}
    expected_bytes = _parse_hex_bytes(expected_hex)
    if not expected_bytes:
        return None, {"error": "INVALID_EXPECTED_BYTES", "patch_index": index, "expected_bytes": expected_hex}

    resolved = normalize_address(path_str, address, address_kind)
    if not resolved.get("ok"):
        return None, {"error": resolved.get("error", "ADDRESS_UNRESOLVED"), "patch_index": index,
                       "address_resolution": resolved}

    file_offset = int(resolved["file_offset"], 16)
    rva = int(resolved["rva"], 16)
    length = len(expected_bytes)

    if file_offset < 0 or file_offset + length > len(orig_data):
        return None, {"error": "PATCH_BEYOND_FILE_SIZE", "patch_index": index,
                       "file_offset": hex(file_offset), "length": length, "file_size": len(orig_data)}

    current = orig_data[file_offset:file_offset + length]
    if current != expected_bytes:
        return None, {"error": "EXPECTED_BYTES_MISMATCH", "patch_index": index,
                       "file_offset": hex(file_offset), "expected": expected_bytes.hex(), "found": current.hex()}

    bound = _section_boundary_check(pe, rva, length)
    if not bound.get("ok"):
        bound["patch_index"] = index
        return None, bound

    machine = int(resolved["machine"], 16)
    bits = _MACHINE_TO_KEYSTONE_BITS.get(machine, default_bits)

    asm_source = None
    padded_with_nop = False
    if fmt == "hex":
        new_bytes = _parse_hex_bytes(patch.get("value"))
        if not new_bytes:
            return None, {"error": "INVALID_PATCH_VALUE", "patch_index": index, "format": fmt}
        if len(new_bytes) != length:
            return None, {"error": "PATCH_LENGTH_MISMATCH", "patch_index": index,
                           "expected_length": length, "given_length": len(new_bytes)}
    elif fmt == "nop":
        nop_count = patch.get("nop_count")
        if nop_count not in (None, ""):
            try:
                nop_count = int(nop_count)
            except (TypeError, ValueError):
                return None, {"error": "INVALID_NOP_COUNT", "patch_index": index}
            if nop_count != length:
                return None, {"error": "NOP_COUNT_MISMATCH", "patch_index": index,
                               "expected_length": length, "nop_count": nop_count}
        new_bytes = _NOP_BYTE * length
    elif fmt == "asm":
        asm_source = str(patch.get("value") or "").strip()
        if not asm_source:
            return None, {"error": "ASM_VALUE_REQUIRED", "patch_index": index}
        arch_override = str(patch.get("arch") or "").strip().lower()
        if arch_override in ("x86", "x86_32", "32"):
            bits = 32
        elif arch_override in ("x64", "x86_64", "64"):
            bits = 64
        va_int = int(resolved["va"], 16)
        encoded, err = _assemble_with_keystone(asm_source, bits, va_int)
        if encoded is None:
            return None, {"error": "ASSEMBLY_FAILED", "patch_index": index, "detail": err, "asm": asm_source}
        if len(encoded) > length:
            return None, {"error": "ASSEMBLED_PATCH_TOO_LONG", "patch_index": index,
                           "expected_length": length, "assembled_length": len(encoded), "asm": asm_source}
        if len(encoded) < length:
            padded_with_nop = True
        new_bytes = encoded + _NOP_BYTE * (length - len(encoded))
    elif fmt == "crc_fix":
        # Whole-file CRC-32 correction: the caller supplies the 4 bytes
        # CURRENTLY at this window as expected_bytes (same mandatory safety
        # check every other format gets); the REPLACEMENT bytes are not
        # caller-supplied -- they are solved for (solve_crc32_correction,
        # closed form) once the full patched buffer (this window plus every
        # OTHER patch in the same call) is known, which binary_patch() does
        # in a deferred second pass after every patch is planned (this
        # window's own bytes are not part of that dependency, only where it
        # sits and what surrounds it). new_bytes is a same-length PLACEHOLDER
        # here (kept identical to old_bytes) purely so length/overlap
        # checks below have real bytes to reason about; it is replaced with
        # the solved correction (and re-verified with a live zlib.crc32
        # call) before any dry-run plan or real write is returned.
        if length != _CRC_FIX_WINDOW_LENGTH:
            return None, {"error": "CRC_FIX_WINDOW_MUST_BE_4_BYTES", "patch_index": index,
                           "length": length, "required_length": _CRC_FIX_WINDOW_LENGTH}
        variant = str(patch.get("crc_variant") or "crc32").strip().lower()
        if variant not in _CRC_VARIANT_ALIASES:
            return None, {"error": "UNSUPPORTED_CRC_VARIANT", "patch_index": index,
                           "crc_variant": variant, "supported": sorted(_CRC_VARIANT_ALIASES)}
        target_raw = patch.get("target_crc")
        if target_raw in (None, ""):
            return None, {"error": "TARGET_CRC_REQUIRED", "patch_index": index}
        try:
            if isinstance(target_raw, str):
                target_str = target_raw.strip()
                target_int = int(target_str, 16) if target_str.lower().startswith("0x") else int(target_str, 10)
            elif isinstance(target_raw, bool):
                raise ValueError("bool is not a valid target_crc")
            elif isinstance(target_raw, int):
                target_int = target_raw
            else:
                raise ValueError(f"unsupported target_crc type {type(target_raw).__name__}")
        except (TypeError, ValueError):
            return None, {"error": "INVALID_TARGET_CRC", "patch_index": index, "target_crc": target_raw}
        target_int &= 0xFFFFFFFF
        new_bytes = expected_bytes  # placeholder, see docstring above
    else:
        return None, {"error": "UNKNOWN_PATCH_FORMAT", "patch_index": index, "format": fmt,
                       "allowed": ["hex", "asm", "nop", "crc_fix"]}

    record = {
        "patch_index": index, "format": fmt,
        "address": {"va": resolved["va"], "rva": resolved["rva"], "file_offset": resolved["file_offset"],
                     "section": bound["section"], "image_base": resolved["image_base"]},
        "length": length, "old_bytes": expected_bytes.hex(), "new_bytes": new_bytes.hex(),
        "asm_source": asm_source, "padded_with_nop": padded_with_nop,
    }
    if fmt == "crc_fix":
        record["crc_fix_pending"] = True
        record["target_crc"] = hex(target_int)
        record["crc_variant"] = variant
    return (file_offset, new_bytes, record), None


def _check_no_overlap(planned) -> dict:
    spans = sorted((fo, fo + len(nb)) for fo, nb, _rec in planned)
    for i in range(1, len(spans)):
        if spans[i][0] < spans[i - 1][1]:
            return {"ok": False, "error": "OVERLAPPING_PATCHES"}
    return {"ok": True}


def _write_patch_evidence(p: Path, kind: str, record: dict) -> None:
    """Deposit one evidence file per call under ``EVIDENCE`` (never inline
    in the returned JSON only) -- same convention ``tools_binary.py``'s
    ``_save_resource_bytes`` uses (sha256-keyed filename, best-effort
    ``evidence_index`` registration, never lets an indexing failure block
    the write). Mutates ``record`` in place to add its own ``evidence_file``
    path before serializing, so the returned tool JSON and the on-disk
    ledger entry are identical."""
    try:
        key = hashlib.sha256((str(p) + kind + str(time.time())).encode()).hexdigest()[:12]
        out = EVIDENCE / f"{p.stem}_{key}_binary_patch_{kind}.json"
        record["evidence_file"] = str(out)
        record["evidence_write_status"] = "WRITTEN"
        out.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        try:
            _evidence_index_record_write(out)
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        # An evidence-write failure must never block the patch result, but it
        # must not be invisible either: the docstring promises every call
        # deposits an evidence file, so a caller has to be able to see when
        # that promise was not kept on this call.
        record["evidence_file"] = None
        record["evidence_write_status"] = f"FAILED: {type(exc).__name__}: {exc}"


def binary_patch(path, operation="apply", patches=None, dry_run=True, backup=True,
                  in_place=True, output_path=None, backup_path=None, arch=None) -> str:
    """General-purpose, reusable disk-patch capability (this task's own
    reason for existing: a class of protections, observed live on
    ``trybypassme``'s ``Guard10``, flags DLL injection via module-list
    change -- the structurally correct vector is patching the TARGET's own
    bytes on disk, never injecting/mapping/threading into it. Extends the
    ``rizin_patch_plan``/``rizin_patch_apply`` pair above -- same address
    resolver (``pe_address.normalize_address`` via ``address_kind``:
    va/rva/file_offset, never a hand-computed delta), same ``_j`` JSON
    envelope, same workspace-scoped ``safe_path`` -- with what that pair
    does not have: an arbitrary address list (not just the two canned
    force_branch/nop_out operations), MANDATORY existing-bytes verification
    before any write, a PE-section-table boundary check, an automatic
    pristine backup + explicit restore, a post-write PE-validity re-parse
    (auto-reverted if it fails), and a single ``dry_run`` flag (default
    True) that plans and returns the exact bytes without ever opening the
    file for writing.

    ``operation``:
      - ``"apply"`` (default): plan+validate every entry in ``patches``
        against the file's CURRENT bytes; on any single failure the WHOLE
        batch is rejected, nothing is written. If ``dry_run`` (default
        True), returns the full plan (old/new bytes per patch, resolved
        VA/RVA/file_offset/section) and writes NOTHING. If ``dry_run=False``,
        writes for real: ``in_place=True`` (default) copies the file to a
        pristine sidecar backup first (``<name>.liebert_orig_backup``,
        created ONCE -- a later apply call never overwrites an existing
        backup, so it always holds the true original) then patches ``path``
        itself; ``in_place=False`` instead writes an untouched-original
        ``<name>.patched<suffix>`` copy (same shape as ``rizin_patch_apply``).
        Every write is re-parsed as a PE afterward; an invalid result is
        automatically reverted from the backup when one exists.
      - ``"restore"``: copies ``backup_path`` (default: the sidecar above)
        back onto ``path``, verifying the restored file's sha256 against the
        backup's own sha256.

    Each entry in ``patches`` is a dict: ``address`` (required),
    ``address_kind`` (``"va"``/``"rva"``/``"file_offset"``, default
    ``"va"``), ``expected_bytes`` (REQUIRED hex -- the bytes currently
    expected at that location; a mismatch rejects the entire call, nothing
    is written), ``format`` (``"hex"``/``"asm"``/``"nop"``/``"crc_fix"``, default
    ``"hex"``), ``value`` (hex bytes for ``"hex"``, or ';'-separated x86/x64
    assembly text for ``"asm"``, assembled via Keystone -- e.g.
    ``"nop"``/``"jmp short label"`` is not directly resolvable without a
    label, so short relative jumps should be given as an immediate target
    VA, e.g. ``"jmp 0x401050"``; ``"mov eax, 1; ret"``), ``nop_count``
    (optional consistency check for ``"nop"``), ``arch`` (optional
    ``"x86"``/``"x64"`` override for ``"asm"``, otherwise taken from the
    PE's own Machine field). ``"asm"`` output shorter than
    ``expected_bytes`` is padded with ``0x90`` NOP to fill the exact region
    (``padded_with_nop`` reports this); longer is rejected
    (``ASSEMBLED_PATCH_TOO_LONG``) rather than silently overflowing into the
    next bytes. ``"hex"`` requires an EXACT length match (no padding) --
    the caller controls every byte.

    ``"crc_fix"`` is different in kind from the other three: it does not
    take a caller-supplied ``value`` at all. Instead it takes ``target_crc``
    (REQUIRED -- hex string like ``"0x688ffe38"`` or an int) and optional
    ``crc_variant`` (default ``"crc32"``, the same IEEE 802.3 CRC-32
    ``zlib.crc32``/PKZIP/gzip/PNG use; other variant names are refused as
    ``UNSUPPORTED_CRC_VARIANT`` rather than silently computed wrong). The
    window ``expected_bytes`` still MUST be given and MUST be exactly 4
    bytes (``CRC_FIX_WINDOW_MUST_BE_4_BYTES`` otherwise -- 4 bytes is the
    only length with a guaranteed unique closed-form solution). The 4
    replacement bytes are SOLVED (``solve_crc32_correction``, closed-form
    GF(2) linear algebra, no trial-and-error) once every other patch in the
    same call is known, so that ``zlib.crc32`` of the FINAL whole file
    equals ``target_crc`` -- e.g. to keep an external whole-file CRC-32
    integrity check (one that reads the file from disk independently of
    whatever else in it changed) satisfied after patching code elsewhere in
    the same file. The chosen window must not be read by anything at
    runtime (the caller's responsibility to pick a dead byte range, e.g.
    section raw-data padding beyond ``Misc.VirtualSize`` -- never mapped
    into memory at all -- or an unused DOS-stub gap); this call only
    guarantees the ARITHMETIC, not that the location is safe to repurpose.
    A live ``zlib.crc32`` check on the reconstructed buffer verifies the
    solve before it is ever trusted (``CRC_FIX_VERIFICATION_FAILED`` if
    that check somehow fails; ``CRC_FIX_UNSOLVABLE`` if the linear system
    is singular). Works in both ``dry_run`` and real-write mode -- a
    dry-run plan reports the actual solved bytes, not a placeholder.

    Every ``apply``/``restore`` call (dry-run or real) deposits one evidence
    JSON under ``dataset/evidence/binary_patch/`` (target path, sha256
    before/after, the resolved patch list, backup path) -- an in-place write
    is never just a claim.

    Status vocabulary: OK, DRY_RUN, REVERTED_INVALID_PE,
    INVALID_PE_AFTER_PATCH, PATH_REFUSED, NOT_FOUND, NOT_A_PE,
    PATCHES_REQUIRED, TOO_MANY_PATCHES, INVALID_PATCH_ENTRY,
    ADDRESS_REQUIRED, EXPECTED_BYTES_REQUIRED, INVALID_EXPECTED_BYTES,
    EXPECTED_BYTES_MISMATCH, PATCH_BEYOND_FILE_SIZE,
    RVA_NOT_IN_ANY_SECTION, PATCH_CROSSES_SECTION_BOUNDARY,
    PATCH_BEYOND_RAW_DATA, OVERLAPPING_PATCHES, UNKNOWN_PATCH_FORMAT,
    INVALID_PATCH_VALUE, PATCH_LENGTH_MISMATCH, INVALID_NOP_COUNT,
    NOP_COUNT_MISMATCH, ASM_VALUE_REQUIRED, ASSEMBLY_FAILED,
    ASSEMBLED_PATCH_TOO_LONG, OUTPUT_PATH_EQUALS_INPUT, READ_FAILED,
    WRITE_FAILED, WRITE_VERIFICATION_FAILED (the bytes on disk after the
    write do not match the bytes this call computed -- auto-reverted when an
    in-place backup exists), BACKUP_FAILED, BACKUP_VERIFICATION_FAILED (a
    backup created by THIS call does not match the file being patched, so an
    in-place write would not be reversible; nothing is written),
    BACKUP_NOT_FOUND, RESTORE_HASH_MISMATCH, UNKNOWN_OPERATION,
    CRC_FIX_WINDOW_MUST_BE_4_BYTES, UNSUPPORTED_CRC_VARIANT, TARGET_CRC_REQUIRED,
    INVALID_TARGET_CRC, CRC_FIX_UNSOLVABLE, CRC_FIX_VERIFICATION_FAILED.
    """
    op = str(operation or "apply").strip().lower()
    if op not in ("apply", "restore"):
        return _j({"ok": False, "tool": "binary_patch", "status": "UNKNOWN_OPERATION",
                    "operation": operation, "allowed": ["apply", "restore"]})

    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "binary_patch", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "binary_patch", "status": "NOT_FOUND", "path": str(path)})

    default_backup = _default_backup_path(p)

    if op == "restore":
        try:
            bak = safe_path(backup_path) if backup_path else default_backup
        except PermissionError as exc:
            return _j({"ok": False, "tool": "binary_patch", "operation": "restore",
                        "status": "PATH_REFUSED", "error": str(exc)})
        if not bak.is_file():
            return _j({"ok": False, "tool": "binary_patch", "operation": "restore",
                        "status": "BACKUP_NOT_FOUND", "backup_path": str(bak)})
        before_sha = _sha256_bytes(p.read_bytes())
        shutil.copy2(bak, p)
        after_sha = _sha256_bytes(p.read_bytes())
        backup_sha = _sha256_bytes(bak.read_bytes())
        ok = after_sha == backup_sha
        record = {
            "ok": ok, "tool": "binary_patch", "operation": "restore",
            "status": "OK" if ok else "RESTORE_HASH_MISMATCH",
            "path": relative(p), "backup_path": str(bak),
            "sha256_before_restore": before_sha, "sha256_after_restore": after_sha,
            "sha256_backup": backup_sha,
        }
        _write_patch_evidence(p, "restore", record)
        return _j(record)

    # operation == "apply"
    try:
        orig_data = p.read_bytes()
    except OSError as exc:
        return _j({"ok": False, "tool": "binary_patch", "status": "READ_FAILED", "error": str(exc)})
    try:
        pe = _open_pe_from_bytes(orig_data)
    except Exception as exc:
        return _j({"ok": False, "tool": "binary_patch", "status": "NOT_A_PE",
                    "error": f"{type(exc).__name__}: {exc}"})

    if not isinstance(patches, list) or not patches:
        return _j({"ok": False, "tool": "binary_patch", "status": "PATCHES_REQUIRED"})
    if len(patches) > _MAX_PATCHES_PER_CALL:
        return _j({"ok": False, "tool": "binary_patch", "status": "TOO_MANY_PATCHES",
                    "max": _MAX_PATCHES_PER_CALL})

    default_bits = 64
    arch_str = str(arch or "").strip().lower()
    if arch_str in ("x86", "x86_32", "32"):
        default_bits = 32
    elif arch_str in ("x64", "x86_64", "64"):
        default_bits = 64

    planned = []
    for i, patch in enumerate(patches):
        if not isinstance(patch, dict):
            return _j({"ok": False, "tool": "binary_patch", "status": "INVALID_PATCH_ENTRY", "patch_index": i})
        result, err = _plan_one_patch(str(p), pe, orig_data, patch, i, default_bits)
        if err is not None:
            return _j({"ok": False, "tool": "binary_patch", "status": err.get("error", "PATCH_PLAN_FAILED"), **err})
        planned.append(result)

    overlap = _check_no_overlap(planned)
    if not overlap.get("ok"):
        return _j({"ok": False, "tool": "binary_patch", "status": "OVERLAPPING_PATCHES"})

    # Deferred crc_fix resolution: every OTHER patch's bytes are baked in
    # first (a crc_fix window's own correction depends on the full buffer
    # around it, including sibling patches in the SAME call), then each
    # crc_fix window is solved in call order against that running buffer
    # (so a later crc_fix patch correctly sees an earlier one's already-
    # solved bytes as fixed context) and the live zlib.crc32 result is
    # verified before anything is trusted -- this runs before dry_run too,
    # so a dry-run plan reports the real computed correction bytes, never a
    # placeholder.
    if any(rec.get("crc_fix_pending") for _fo, _nb, rec in planned):
        interim = bytearray(orig_data)
        for file_offset, new_bytes, rec in planned:
            if not rec.get("crc_fix_pending"):
                interim[file_offset:file_offset + len(new_bytes)] = new_bytes
        resolved_planned = []
        for file_offset, new_bytes, rec in planned:
            if rec.get("crc_fix_pending"):
                length = rec["length"]
                target_int = int(rec["target_crc"], 16)
                window = solve_crc32_correction(bytes(interim), file_offset, length, target_int)
                if window is None:
                    return _j({"ok": False, "tool": "binary_patch", "status": "CRC_FIX_UNSOLVABLE",
                                "patch_index": rec["patch_index"], "target_crc": rec["target_crc"],
                                "file_offset": hex(file_offset), "length": length})
                interim[file_offset:file_offset + length] = window
                check_crc = zlib.crc32(bytes(interim)) & 0xFFFFFFFF
                if check_crc != target_int:
                    return _j({"ok": False, "tool": "binary_patch", "status": "CRC_FIX_VERIFICATION_FAILED",
                                "patch_index": rec["patch_index"], "target_crc": rec["target_crc"],
                                "computed_crc": hex(check_crc)})
                rec = dict(rec)
                rec["new_bytes"] = window.hex()
                rec["crc_fix_pending"] = False
                rec["resulting_file_crc32"] = hex(check_crc)
                new_bytes = window
            resolved_planned.append((file_offset, new_bytes, rec))
        planned = resolved_planned

    records = [rec for _fo, _nb, rec in planned]
    sha_before = _sha256_bytes(orig_data)

    if dry_run:
        record = {
            "ok": True, "tool": "binary_patch", "operation": "apply", "status": "DRY_RUN",
            "path": relative(p), "dry_run": True, "in_place": bool(in_place),
            "sha256_before": sha_before, "patch_count": len(records), "patches": records,
        }
        _write_patch_evidence(p, "apply_dry_run", record)
        return _j(record)

    new_data = bytearray(orig_data)
    for file_offset, new_bytes, _rec in planned:
        new_data[file_offset:file_offset + len(new_bytes)] = new_bytes
    new_data = bytes(new_data)

    backup_written = None
    backup_verification = "NOT_REQUESTED"
    if in_place:
        target = p
        if backup:
            try:
                bak = safe_path(backup_path) if backup_path else default_backup
            except PermissionError as exc:
                return _j({"ok": False, "tool": "binary_patch", "status": "PATH_REFUSED", "error": str(exc)})
            # The backup is the ONLY route back once an in-place write lands,
            # and `restore` above can only ever prove "restored == backup" --
            # it cannot prove "backup == the bytes that were there". So a
            # backup CREATED HERE is verified against the bytes we just read,
            # rather than trusted because shutil.copy2 returned. A
            # PRE-EXISTING backup is deliberately NOT compared: by contract
            # it holds the true pre-ANY-patch original, which legitimately
            # differs from an already-patched `path` on a second call.
            if bak.is_file():
                backup_verification = "PRE_EXISTING_NOT_COMPARED"
            else:
                try:
                    shutil.copy2(p, bak)
                except OSError as exc:
                    return _j({"ok": False, "tool": "binary_patch", "status": "BACKUP_FAILED",
                                "backup_path": str(bak), "error": str(exc)})
                try:
                    backup_sha = _sha256_bytes(bak.read_bytes())
                except OSError as exc:
                    return _j({"ok": False, "tool": "binary_patch", "status": "BACKUP_VERIFICATION_FAILED",
                                "backup_path": str(bak), "error": f"BACKUP_UNREADABLE: {exc}"})
                if backup_sha != sha_before:
                    return _j({"ok": False, "tool": "binary_patch", "status": "BACKUP_VERIFICATION_FAILED",
                                "backup_path": str(bak), "sha256_backup": backup_sha,
                                "sha256_expected": sha_before,
                                "detail": "the backup just written does not match the file being patched, "
                                          "so an in-place write would not be reversible; nothing was "
                                          "written to the target"})
                backup_verification = "CREATED_AND_VERIFIED"
            backup_written = str(bak)
    else:
        try:
            target = safe_path(output_path) if output_path else p.with_name(f"{p.stem}.patched{p.suffix}")
        except PermissionError as exc:
            return _j({"ok": False, "tool": "binary_patch", "status": "PATH_REFUSED", "error": str(exc)})
        if target.resolve() == p.resolve():
            return _j({"ok": False, "tool": "binary_patch", "status": "OUTPUT_PATH_EQUALS_INPUT",
                        "output_path": str(target)})
        # The untouched original IS the backup in this mode.

    try:
        target.write_bytes(new_data)
    except OSError as exc:
        return _j({"ok": False, "tool": "binary_patch", "status": "WRITE_FAILED", "error": str(exc)})

    # Everything below is judged on the bytes that are ACTUALLY ON DISK, read
    # back after the write -- not on `new_data`. Re-parsing the in-memory
    # buffer answered "are the bytes I computed a valid PE", which is not the
    # question: a short/partial/redirected write would still have been
    # reported as `ok: true, status: "OK"` with a sha256_after that nothing
    # compared against anything.
    try:
        written = target.read_bytes()
    except OSError as exc:
        return _j({"ok": False, "tool": "binary_patch", "status": "WRITE_VERIFICATION_FAILED",
                    "output_path": str(target), "error": f"OUTPUT_UNREADABLE: {exc}"})
    sha_after = _sha256_bytes(written)

    if written != new_data:
        reverted_mismatch = False
        if in_place and backup_written:
            try:
                shutil.copy2(backup_written, target)
                # `reverted` is claimed only when the restored bytes hash to the backup's bytes.
                reverted_mismatch = (_sha256_bytes(target.read_bytes())
                                     == _sha256_bytes(Path(backup_written).read_bytes()))
            except OSError:
                reverted_mismatch = False
        record = {
            "ok": False, "tool": "binary_patch", "operation": "apply",
            "status": "WRITE_VERIFICATION_FAILED",
            "path": relative(p), "output_path": str(target), "in_place": bool(in_place),
            "dry_run": False, "backup_path": backup_written,
            "backup_verification": backup_verification,
            "sha256_before": sha_before, "sha256_after": sha_after,
            "sha256_intended": _sha256_bytes(new_data),
            "intended_size": len(new_data), "written_size": len(written),
            "reverted": reverted_mismatch,
            "detail": "the bytes on disk after the write do not match the bytes this call computed; "
                      "the file is NOT the planned patch",
            "patch_count": len(records), "patches": records,
        }
        _write_patch_evidence(p, "apply", record)
        return _j(record)

    pe_valid_after = True
    pe_error_after = None
    try:
        _open_pe_from_bytes(written)
    except Exception as exc:
        pe_valid_after = False
        pe_error_after = f"{type(exc).__name__}: {exc}"

    reverted = False
    if not pe_valid_after and in_place and backup_written:
        try:
            shutil.copy2(backup_written, target)
            reverted = (_sha256_bytes(target.read_bytes())
                        == _sha256_bytes(Path(backup_written).read_bytes()))
        except OSError:
            reverted = False
    if reverted:
        sha_after = _sha256_bytes(target.read_bytes()) if target.is_file() else None

    status = "OK" if pe_valid_after else ("REVERTED_INVALID_PE" if reverted else "INVALID_PE_AFTER_PATCH")
    record = {
        "ok": pe_valid_after, "tool": "binary_patch", "operation": "apply", "status": status,
        "path": relative(p), "output_path": str(target), "in_place": bool(in_place),
        "dry_run": False, "backup_path": backup_written,
        "backup_verification": backup_verification,
        "sha256_before": sha_before, "sha256_after": sha_after,
        "sha256_verified_from": "READ_BACK_FROM_DISK",
        "pe_valid_after": pe_valid_after, "pe_error_after": pe_error_after,
        "patch_count": len(records), "patches": records,
    }
    _write_patch_evidence(p, "apply", record)
    return _j(record)


def _j(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def rizin_status() -> str:
    """Cheap presence probe -- same shape as ida_status()/similar."""
    exe = _rizin_binary()
    return _j({"rizin_exe": exe, "available": exe is not None})


def rizin_functions(
    path,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    max_functions: int = 2000,
    cancellation_token=None,
) -> str:
    """Headless rizin function inventory: `aaa` (analyze all) then `aflj`
    (list functions as JSON), a single rizin process per call. Returns
    address/name/size per function plus the analysis wall-clock seconds.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT,
    CANCELLED, ANALYSIS_LIMITED (rizin ran but produced no usable output, or
    its stdout hit the output cap and the inventory is therefore partial),
    RESULT_PARSE_FAILED (rizin's own JSON did not parse -- a rizin-side
    bug/version-drift signal), NOT_RECOVERABLE (rizin's function list -- empty
    OR non-empty -- cannot be trusted because its own per-call binary-info
    probe does not confirm it loaded the file: an empty list is "unknown", not
    "zero functions", and a non-empty list whose probe says NO_BINARY_LOADED
    is fabricated entries carved from a file rizin never recognised as a
    binary, not a real inventory).

    On success, ``analysis_completeness`` is a named status (COMPLETE /
    COMPLETE_NO_FUNCTIONS_FOUND / LIST_CAPPED_AT_MAX_FUNCTIONS) and
    ``load_probe`` carries rizin's own answer to "did I load this file"
    (BINARY_LOADED / NO_BINARY_LOADED / PROBE_UNAVAILABLE).
    """
    exe = _rizin_binary()
    if not exe:
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "TOOL_MISSING",
            "required_capability": "rizin (rizin.exe)",
        })

    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "rizin_functions", "status": "PATH_REFUSED", "error": str(exc)})

    if not p.is_file():
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "NOT_FOUND",
            "path": str(path),
        })

    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
    max_functions = max(1, min(int(max_functions), _MAX_FUNCTIONS_RETURNED))

    # -q: quiet/no prompt, quit after -c. -c 'aaa; aflj; iIj': analyze all
    # referenced code, dump the function list as JSON, then dump rizin's own
    # binary-info JSON. One process, no interactive rizin session, no
    # separate analyze+query calls. `iIj` is a PER-CALL load probe, not
    # decoration: rizin exits 0 whether or not it recognised the file, so an
    # empty function list is otherwise indistinguishable between "this
    # binary genuinely has no functions" and "rizin never loaded it"
    # (see `_rizin_load_probe`). It is consulted only when the list is
    # empty, so a rizin build without `iIj` can never break the main path.
    cmd = [exe, "-q", "-c", "aaa; aflj; iIj", str(p)]

    started = time.monotonic()
    cp = run_bounded_process(
        cmd,
        timeout_seconds=timeout_seconds,
        cancellation_token=cancellation_token,
        max_output_chars=_MAX_OUTPUT_CHARS,
    )
    elapsed = time.monotonic() - started

    if cp.cancelled:
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "CANCELLED",
            "error": "RIZIN_CANCELLED_PROCESS_TREE_TERMINATED",
        })
    if cp.timed_out:
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "TIMEOUT",
            "timeout_seconds": timeout_seconds,
            "error": "RIZIN_TIMEOUT_PROCESS_TREE_TERMINATED",
        })
    if cp.returncode not in (0, None):
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "ANALYSIS_LIMITED",
            "exit_code": cp.returncode,
            "stderr_tail": (cp.stderr or "")[-2000:],
            "stdout_tail": (cp.stdout or "")[-500:],
        })

    # An output buffer that hit `_MAX_OUTPUT_CHARS` holds a PARTIAL function
    # inventory. run_bounded_process reports that on its ordinary
    # (returncode 0) return path, so this must be checked before parsing --
    # previously `output_truncated` was only ever reported from inside
    # already-failing branches, which left the one case that matters (a
    # truncated buffer that still happens to parse) reportable as a complete
    # inventory. This is also what the module docstring's "gets
    # ANALYSIS_LIMITED via the truncation path" claim actually requires.
    if getattr(cp, "output_truncated", False):
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "ANALYSIS_LIMITED",
            "error": "RIZIN_OUTPUT_TRUNCATED_AT_CAP",
            "output_truncated": True, "max_output_chars": _MAX_OUTPUT_CHARS,
        })

    stdout = cp.stdout or ""
    # rizin's own `-q` output for `aflj` is the bare JSON array, but be
    # defensive about incidental banner/warning text landing on stdout
    # (version drift, plugin warnings) rather than assuming byte-exact
    # output -- decode the first complete JSON array instead of scraping
    # text, and keep the load-probe object that follows it separate.
    raw_functions, array_end, extraction = _extract_json_array(stdout)
    if extraction == "ABSENT":
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "ANALYSIS_LIMITED",
            "error": "RIZIN_NO_JSON_OUTPUT",
            "output_truncated": cp.output_truncated,
            "stdout_tail": stdout[-2000:],
            "stderr_tail": (cp.stderr or "")[-2000:],
        })
    if extraction == "MALFORMED":
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "RESULT_PARSE_FAILED",
            "error": "RIZIN_AFLJ_JSON_MALFORMED",
            "output_truncated": cp.output_truncated,
            "stdout_tail": stdout[-2000:],
        })

    load_probe = _rizin_load_probe(stdout[array_end:])
    # A rizin function list -- of ANY length -- is a real measurement only if
    # rizin actually loaded the binary on THIS call. Two fabrication shapes,
    # both measured on this machine (rizin 0.9.1, 2026-09-27), are refused
    # here so a fabricated count never leaves this wrapper and enters
    # cross-engine comparison (decompiler_trust.py) as if it were real:
    #
    #   * EMPTY list, load NOT confirmed -> "0 functions" is not a real zero,
    #     it is "unknown". Saying 0 would feed a fabricated data point into
    #     the comparison. (The original zero-case guard.)
    #   * NON-EMPTY list, probe says it did NOT load -> on a 20-byte text file
    #     rizin exits 0 and answers `aflj` with a FABRICATED function
    #     (function_count 1, fcn.00000000) while `iIj` reports havecode:false
    #     and no arch/bintype (load_probe NO_BINARY_LOADED). A non-zero count
    #     carved from bytes rizin never recognised as a binary is no more real
    #     than a fabricated zero, and previously sailed through as ok/OK --
    #     a false CONSISTENT (if it landed under the divergence ratio) or a
    #     false disagreement that discredits a correct engine.
    #
    # The two branches use DIFFERENT probe thresholds on purpose. The empty
    # list needs a POSITIVE confirmation to be trusted as a real zero, so it
    # rejects on anything other than BINARY_LOADED (including
    # PROBE_UNAVAILABLE). A non-empty list is rejected ONLY on rizin's
    # positive "I did not load this" answer (NO_BINARY_LOADED): a rizin build
    # that does not answer `iIj` at all (PROBE_UNAVAILABLE) must still be able
    # to return a real inventory -- this module's standing promise that a
    # probe-less build can never break the main path -- so absence of a probe
    # answer must not discard real functions.
    load_status = load_probe["status"]
    empty_unconfirmed = (not raw_functions) and load_status != "BINARY_LOADED"
    nonempty_not_loaded = bool(raw_functions) and load_status == "NO_BINARY_LOADED"
    if empty_unconfirmed or nonempty_not_loaded:
        return _j({
            "ok": False, "tool": "rizin_functions", "status": "NOT_RECOVERABLE",
            "error": (
                "RIZIN_EMPTY_FUNCTION_LIST_WITHOUT_LOADED_BINARY" if empty_unconfirmed
                else "RIZIN_FABRICATED_FUNCTIONS_WITHOUT_LOADED_BINARY"
            ),
            "detail": (
                "rizin returned an empty function list and its own binary-info probe does "
                "not confirm it loaded this file on this call, so the function count is "
                "unknown -- not zero"
                if empty_unconfirmed else
                "rizin returned a non-empty function list but its own binary-info probe reports "
                "it did not load this file on this call (e.g. an unrecognised or non-binary "
                "input), so the listed functions are fabricated and the count is unknown -- not "
                "a real inventory"
            ),
            # Published so a caller can SEE the fabricated size that was
            # refused, without it ever being usable as `function_count`.
            "fabricated_function_count": len(raw_functions) if nonempty_not_loaded else 0,
            "path": relative(p), "load_probe": load_probe,
            "analysis_wall_clock_seconds": round(elapsed, 3),
            "stderr_tail": (cp.stderr or "")[-2000:],
        })

    total_found = len(raw_functions)
    functions = [
        {
            "address": fn.get("offset"),
            "name": fn.get("name"),
            "size": fn.get("size"),
        }
        for fn in raw_functions[:max_functions]
        if isinstance(fn, dict)
    ]
    truncated = total_found > len(functions)
    # Named completeness, alongside the (two-state, list-capped-or-not)
    # `truncated` flag kept for existing callers: a bool standing in for
    # three or more states is how this repo's `truncated`-stayed-false
    # defect happened.
    if truncated:
        completeness = "LIST_CAPPED_AT_MAX_FUNCTIONS"
    elif total_found == 0:
        completeness = "COMPLETE_NO_FUNCTIONS_FOUND"
    else:
        completeness = "COMPLETE"

    return _j({
        "ok": True, "tool": "rizin_functions", "status": "OK",
        "path": relative(p),
        "engine": "rizin", "engine_version": "0.9.1",
        "function_count": total_found,
        "functions": functions,
        "truncated": truncated,
        "analysis_completeness": completeness,
        "load_probe": load_probe,
        "analysis_wall_clock_seconds": round(elapsed, 3),
    })


# ---------------------------------------------------------------------------
# rz-bin: the structural reader that ships next to rizin.exe. Four read-only
# operations (imports, sections, headers, relocations) plus a status probe,
# all driven through one shared runner so that the sub-tool lookup, path
# gate, bounded run, status vocabulary, environment-error reporting and
# evidence write cannot drift between them. The runner lives on a class on
# purpose: the layout pin counts top-level function names, and only the five
# public entry points below are meant to be published surface.
#
# Measured on rizin 0.9.1 (rz-bin.exe sits in the install ROOT, not in bin/):
#   -j -i  -> {"imports":[{ordinal,bind,type,name,libname,plt}]}
#   -j -S  -> {"sections":[{name,size,vsize,perm,flags,paddr,vaddr}]}
#   -j -H  -> {"fields":[{name,vaddr,paddr,comment,format,pf}]}
#   -j -R  -> {"relocs":[{name,type,vaddr,paddr,sym_va,is_ifunc}]}
# rz-bin exits 0 with an EMPTY list on a file it did not recognise as a
# binary ({"imports":[]} for a text file), exactly the trap rizin_functions
# guards against, so an empty list is only reported as a real zero after
# `-j -I` confirms a bintype. `-S` carries no entropy field; section entropy
# is die_entropy's job and is reported here as absent, not invented.
# ---------------------------------------------------------------------------
_RZ_BIN_OPERATIONS = ("rz_bin_imports", "rz_bin_sections", "rz_bin_headers", "rz_bin_relocations")


class _RzBin:
    @staticmethod
    def binary() -> str | None:
        """env (RIZIN_HOME: file, root dir or bin dir) -> PATH. Never raises.
        Like the other rizin lookups there is no embedded install path."""
        names = ("rz-bin.exe", "rz-bin")
        explicit = os.getenv("RIZIN_HOME", "").strip()
        if explicit:
            try:
                p = Path(explicit)
                if p.is_file():
                    p = p.parent
                for name in names:
                    for candidate in (p / name, p / "bin" / name):
                        if candidate.is_file():
                            return str(candidate)
            except OSError:
                pass
        return shutil.which("rz-bin") or shutil.which("rz-bin.exe")

    @staticmethod
    def missing(tool: str) -> str:
        return _j({
            "ok": False, "tool": tool, "status": "TOOL_MISSING",
            "required_capability": "rizin (rz-bin.exe)",
            "detail": "rz-bin was not found. Set RIZIN_HOME to the rizin install directory (the folder "
                      "holding rz-bin.exe, or its bin subfolder) or put rz-bin on PATH.",
        })

    @staticmethod
    def env_failure(tool: str, exc: BaseException, error: str) -> str:
        if isinstance(exc, OSError):
            return _j({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": error,
                "environment_error": {
                    "type": type(exc).__name__, "errno": getattr(exc, "errno", None),
                    "strerror": getattr(exc, "strerror", None) or type(exc).__name__,
                },
                "detail": "A local operating-system error stopped this call before rz-bin produced a "
                          "result. It describes this machine's environment, not the input file or rz-bin's "
                          "findings; no answer was produced.",
            })
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "RZ_BIN_UNEXPECTED_ERROR",
            "detail": f"{type(exc).__name__}: {exc}",
        })

    @staticmethod
    def run(tool, op, flags, key, shape, rollup, path, timeout_seconds, max_items, cancellation_token):
        exe = _RzBin.binary()
        if not exe:
            return _RzBin.missing(tool)
        try:
            p = safe_path(path)
        except PermissionError as exc:
            return _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
            return _RzBin.env_failure(tool, exc, "RZ_BIN_PATH_CHECK_FAILED")
        try:
            is_file = p.is_file()
        except OSError as exc:
            return _RzBin.env_failure(tool, exc, "RZ_BIN_PATH_CHECK_FAILED")
        if not is_file:
            return _j({"ok": False, "tool": tool, "status": "NOT_FOUND", "path": str(path)})
        try:
            timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
            max_items = max(1, min(int(max_items), _MAX_FUNCTIONS_RETURNED))
        except (TypeError, ValueError):
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                       "error": "RZ_BIN_BAD_NUMERIC_ARGUMENT"})

        def run_once(argv):
            return run_bounded_process(
                [exe, *argv, str(p)], timeout_seconds=timeout_seconds,
                cancellation_token=cancellation_token, max_output_chars=_MAX_OUTPUT_CHARS,
            )

        try:
            started = time.monotonic()
            cp = run_once(flags)
            elapsed = time.monotonic() - started
        except Exception as exc:  # noqa: BLE001
            return _RzBin.env_failure(tool, exc, "RZ_BIN_COULD_NOT_START")
        if cp.cancelled:
            return _j({"ok": False, "tool": tool, "status": "CANCELLED",
                       "error": "RZ_BIN_CANCELLED_PROCESS_TREE_TERMINATED"})
        if cp.timed_out:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "timeout_seconds": timeout_seconds,
                       "error": "RZ_BIN_TIMEOUT_PROCESS_TREE_TERMINATED"})
        stdout = cp.stdout or ""
        if cp.returncode not in (0, None) or not stdout.strip():
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                       "exit_code": cp.returncode, "error": "RZ_BIN_FAILED_OR_EMPTY_OUTPUT",
                       "stderr_tail": (cp.stderr or "")[-2000:], "stdout_tail": stdout[-500:]})
        if getattr(cp, "output_truncated", False):
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                       "error": "RZ_BIN_OUTPUT_TRUNCATED_AT_CAP", "output_truncated": True,
                       "max_output_chars": _MAX_OUTPUT_CHARS})
        try:
            raw = json.loads(stdout)
            items = raw[key] if isinstance(raw, dict) else None
        except (ValueError, KeyError) as exc:
            return _j({"ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
                       "error": f"{type(exc).__name__}: {exc}", "stdout_tail": stdout[-500:]})
        if not isinstance(items, list):
            return _j({"ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
                       "error": f"RZ_BIN_OUTPUT_MISSING_{key.upper()}_LIST"})

        load_probe = "BINARY_LOADED"
        if not items:
            # Empty is only a real zero if rz-bin says it recognised a binary.
            load_probe = "PROBE_UNAVAILABLE"
            try:
                info = run_once(["-j", "-I"])
                parsed = json.loads(info.stdout or "")["info"] if info.returncode in (0, None) else None
                if isinstance(parsed, dict):
                    load_probe = "BINARY_LOADED" if parsed.get("bintype") else "NO_BINARY_LOADED"
            except Exception:  # noqa: BLE001 - an unanswered probe stays PROBE_UNAVAILABLE
                pass
            if load_probe != "BINARY_LOADED":
                return _j({
                    "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                    "error": "RZ_BIN_EMPTY_RESULT_WITHOUT_LOADED_BINARY", "load_probe": load_probe,
                    "path": relative(p),
                    "detail": "rz-bin returned an empty list and its own binary-info probe does not confirm "
                              "it recognised this file, so the count is unknown, not zero.",
                })

        # Full unmodified rz-bin JSON as evidence, written best-effort.
        evidence_name, evidence_error = None, None
        try:
            directory = EVIDENCE.parent / "rz_bin"
            directory.mkdir(parents=True, exist_ok=True)
            stem = re.sub(r"[^A-Za-z0-9._-]", "_", p.stem)[:80] or "input"
            out = directory / f"{stem}_{uuid.uuid4().hex[:8]}_{op}.json"
            out.write_text(stdout, encoding="utf-8")
            evidence_name = out.name
            try:
                _evidence_index_record_write(out)
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001 - an evidence failure never blocks the result
            evidence_error = f"{type(exc).__name__}: {exc}"

        total = len(items)
        shaped = [shape(i) for i in items[:max_items] if isinstance(i, dict)]
        return _j({
            "ok": True, "tool": tool, "status": "OK", "path": relative(p),
            "engine": "rz-bin", "engine_version": "0.9.1",
            "count": total, "returned": len(shaped),
            "truncated": total > len(shaped),
            "analysis_completeness": (
                "LIST_CAPPED_AT_MAX_ITEMS" if total > len(shaped)
                else ("COMPLETE_NONE_FOUND" if total == 0 else "COMPLETE")
            ),
            key: shaped,
            **rollup(items),
            "load_probe": load_probe,
            "wall_clock_seconds": round(elapsed, 3),
            "internal_evidence_name": evidence_name,
            "evidence_write_error": evidence_error,
        })


def rz_bin_imports(path, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                   max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Import table via `rz-bin -j -i`: name, library, per-library ordinal, address.
    `address` is rz-bin's `plt` value, the import's slot address in the loaded image.
    `ordinal` is rz-bin's per-library index, not the DLL's export ordinal. Counts are
    of the full table; `max_items` only caps the listed entries (`truncated`).
    Status: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, CANCELLED, TIMEOUT,
    ANALYSIS_LIMITED (failure, empty output, truncated output, an environment error
    carrying `environment_error`, or an empty list rz-bin cannot confirm it loaded),
    RESULT_PARSE_FAILED."""
    def shape(i):
        plt = i.get("plt")
        return {"name": i.get("name"), "library": i.get("libname"), "ordinal": i.get("ordinal"),
                "address": plt, "address_hex": hex(plt) if isinstance(plt, int) else None,
                "type": i.get("type"), "bind": i.get("bind")}

    def rollup(items):
        libs: dict = {}
        for i in items:
            if isinstance(i, dict):
                lib = i.get("libname") or "(none)"
                libs[lib] = libs.get(lib, 0) + 1
        return {"library_count": len(libs), "imports_per_library": dict(sorted(libs.items()))}

    return _RzBin.run("rz_bin_imports", "imports", ["-j", "-i"], "imports", shape, rollup,
                      path, timeout_seconds, max_items, cancellation_token)


def rz_bin_sections(path, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                    max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Section table via `rz-bin -j -S`: name, file size, virtual size, file offset,
    virtual address, permissions and flags. rz-bin 0.9.1 reports no entropy, so none is
    given (`entropy_available` is false); use die_entropy for that. Sections that are
    both writable and executable are listed under `writable_executable_sections`.
    Same status vocabulary as rz_bin_imports."""
    def shape(s):
        va = s.get("vaddr")
        return {"name": s.get("name"), "size": s.get("size"), "virtual_size": s.get("vsize"),
                "file_offset": s.get("paddr"), "virtual_address": va,
                "virtual_address_hex": hex(va) if isinstance(va, int) else None,
                "permissions": s.get("perm"), "flags": s.get("flags") or []}

    def rollup(items):
        wx = [s.get("name") for s in items if isinstance(s, dict)
              and "w" in str(s.get("perm") or "") and "x" in str(s.get("perm") or "")]
        return {"writable_executable_sections": wx, "entropy_available": False}

    return _RzBin.run("rz_bin_sections", "sections", ["-j", "-S"], "sections", shape, rollup,
                      path, timeout_seconds, max_items, cancellation_token)


def rz_bin_headers(path, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                   max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Header fields via `rz-bin -j -H` (PE: Rich entries, DOS/NT/optional header).
    `value` is rz-bin's own rendered `comment` text (e.g. "0x00000102"); the raw
    `pf` decode rz-bin 0.9.1 attaches is dropped because it is wrong for many
    fields (all-ones hex values, empty strings). `rich_entries` groups the
    RICH_ENTRY_* rows; `named` maps each single-occurrence field name to its value.
    Same status vocabulary as rz_bin_imports."""
    def shape(f):
        return {"name": str(f.get("name") or "").strip(), "file_offset": f.get("paddr"),
                "virtual_address": f.get("vaddr"), "value": f.get("comment"), "format": f.get("format")}

    def rollup(items):
        rich, named, seen = [], {}, {}
        for f in items:
            if not isinstance(f, dict):
                continue
            name = str(f.get("name") or "").strip()
            if name.startswith("RICH_ENTRY_"):
                if name == "RICH_ENTRY_NAME" or not rich:
                    rich.append({})
                rich[-1][name[len("RICH_ENTRY_"):].lower()] = f.get("comment")
                continue
            seen[name] = seen.get(name, 0) + 1
            named[name] = f.get("comment")
        return {"rich_entries": rich,
                "named": {k: v for k, v in named.items() if seen[k] == 1}}

    return _RzBin.run("rz_bin_headers", "headers", ["-j", "-H"], "fields", shape, rollup,
                      path, timeout_seconds, max_items, cancellation_token)


def rz_bin_relocations(path, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                       max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Relocation table via `rz-bin -j -R`: name, type, virtual address, file offset,
    target (`sym_va`). `by_type` counts the full table. An empty table on a recognised
    binary is a real zero (many images are linked without relocations).
    Same status vocabulary as rz_bin_imports."""
    def shape(r):
        return {"name": r.get("name"), "type": r.get("type"), "virtual_address": r.get("vaddr"),
                "file_offset": r.get("paddr"), "target_address": r.get("sym_va"),
                "is_ifunc": r.get("is_ifunc")}

    def rollup(items):
        by_type: dict = {}
        for r in items:
            if isinstance(r, dict):
                t = r.get("type") or "(none)"
                by_type[t] = by_type.get(t, 0) + 1
        return {"by_type": dict(sorted(by_type.items()))}

    return _RzBin.run("rz_bin_relocations", "relocations", ["-j", "-R"], "relocs", shape, rollup,
                      path, timeout_seconds, max_items, cancellation_token)


def rz_bin_status() -> str:
    """rz-bin reachability, resolution source and version. A separate probe from
    rizin_status on purpose: rizin_status answers about rizin.exe in a fixed
    two-key shape existing callers and tests rely on, while rz-bin is its own
    executable that can be missing while rizin.exe is present (or the reverse)."""
    tool = "rz_bin_status"
    exe = _RzBin.binary()
    if not exe:
        return _RzBin.missing(tool)
    try:
        cp = run_bounded_process([exe, "-v"], timeout_seconds=_MIN_TIMEOUT_SECONDS, max_output_chars=4096)
    except Exception as exc:  # noqa: BLE001
        return _RzBin.env_failure(tool, exc, "RZ_BIN_COULD_NOT_START")
    if cp.timed_out:
        return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "error": "RZ_BIN_VERSION_TIMEOUT"})
    lines = ((cp.stdout or "") + (cp.stderr or "")).strip().splitlines()
    if cp.returncode not in (0, None) or not lines:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "exit_code": cp.returncode,
                   "error": "RZ_BIN_VERSION_FAILED", "stderr_tail": (cp.stderr or "")[-500:]})
    from_env = bool(os.getenv("RIZIN_HOME", "").strip()) and not (shutil.which("rz-bin") == exe
                                                                  or shutil.which("rz-bin.exe") == exe)
    return _j({
        "ok": True, "tool": tool, "status": "OK", "binary": exe,
        "version": lines[0],
        "resolved_by": "RIZIN_HOME" if from_env else "PATH",
        "operations": list(_RZ_BIN_OPERATIONS) + ["rz_bin_status"],
        "not_wrapped": ["-z strings", "-K checksums", "-P pdb"],
    })


# ---------------------------------------------------------------------------
# FLIRT signature matching, done by rizin itself (its `F` command space) -- not
# rz-sign (generates/dumps, never matches) and not rz-gg (shellcode/egg
# generator). MEASURED on rizin 0.9.1, and the reason for each choice below:
#   * `Fa [filter]` applies the embedded sigdb, `Fs <file>` applies one .sig or
#     .pat file, `Fl` lists the sigdb. There is no zignature system in this build.
#   * `Fl` prints a text table only: `Fl,:json` and friends are rejected, so the
#     inventory parser checks the header and refuses a row it cannot read instead
#     of skipping it.
#   * `aaa` applies the sigdb BY ITSELF (analysis.apply.signature=true), so a
#     later `Fa`/`Fs` would be confounded by names that were already there. Every
#     call here turns that off and applies exactly what it was asked to.
#   * A match RENAMES the function to `flirt.<name>`; the names are read from the
#     function list (`afl`), not from `Ff`, which prints the byte pattern of one
#     function at the current seek, not match results.
#   * Unfiltered `Fa` silently skips sets for another CPU; with a filter it tries
#     every sigdb directory holding that file name and reports an architecture
#     error for the foreign ones. So the compatible sets are taken from `Fl`
#     (bin + arch + bits against `iIj`) and applied one at a time, which is also
#     what attributes each match to a set; the union equalled unfiltered `Fa` on
#     five real PEs. A target no set was built for is NO_COMPATIBLE_SIGNATURES,
#     never a zero.
#   * `Fs` checks the CPU family only: an x86-64 .sig applied to a 32-bit binary
#     is accepted and finds nothing, with no error. A zero from a caller-supplied
#     file therefore says so (`compatibility_verified: false`).
#   * The signature path and the filter are spliced into a rizin command string,
#     so both are allow-listed before anything runs.
# ---------------------------------------------------------------------------


class _RzFlirt:
    SET_FILTER = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
    SIG_PATH = re.compile(r"^[\w ._+\-():/\\~]+$")  # ~ is Windows 8.3 short names; safe inside the quotes
    ROW = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*(.*?)\s*$")
    FUNC = re.compile(r"^(0x[0-9a-fA-F]+)\s+\d+\s+(\d+)\s.*?(flirt\.\S+)\s*$")
    APPLYING = re.compile(r"^Applying (\S+) signature file", re.M)
    SET_ERROR = re.compile(r"error while parsing the file (.+?)\. Sorry\.")
    HEADER = ("bin", "arch", "bits", "name", "modules", "details")
    ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")  # rizin writes a clear-line escape while it analyses

    @staticmethod
    def missing(tool: str) -> str:
        return _j({
            "ok": False, "tool": tool, "status": "TOOL_MISSING",
            "required_capability": "rizin (rizin.exe)",
            "detail": "rizin was not found. Set RIZIN_HOME to the rizin install directory or put rizin on PATH.",
        })

    @staticmethod
    def env_failure(tool: str, exc: BaseException, error: str) -> str:
        if isinstance(exc, OSError):
            return _j({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": error,
                "environment_error": {
                    "type": type(exc).__name__, "errno": getattr(exc, "errno", None),
                    "strerror": getattr(exc, "strerror", None) or type(exc).__name__,
                },
                "detail": "A local operating-system error stopped this call before rizin produced a "
                          "result. It describes this machine's environment, not the input file or the "
                          "signatures; no answer was produced.",
            })
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                   "error": "RIZIN_FLIRT_UNEXPECTED_ERROR", "detail": f"{type(exc).__name__}: {exc}"})

    @staticmethod
    def launch(tool, exe, commands, target, timeout_seconds, cancellation_token):
        """One rizin process. Returns (completed, elapsed, None) or (None, 0, error_json)."""
        argv = [exe, "-e", "scr.color=0", "-e", "analysis.apply.signature=false", "-q", "-c", commands]
        if target is not None:
            argv.append(str(target))
        try:
            started = time.monotonic()
            cp = run_bounded_process(argv, timeout_seconds=timeout_seconds,
                                     cancellation_token=cancellation_token, max_output_chars=_MAX_OUTPUT_CHARS)
            elapsed = time.monotonic() - started
        except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
            return None, 0.0, _RzFlirt.env_failure(tool, exc, "RIZIN_FLIRT_COULD_NOT_START")
        if cp.cancelled:
            return None, 0.0, _j({"ok": False, "tool": tool, "status": "CANCELLED",
                                  "error": "RIZIN_FLIRT_CANCELLED_PROCESS_TREE_TERMINATED"})
        if cp.timed_out:
            return None, 0.0, _j({"ok": False, "tool": tool, "status": "TIMEOUT",
                                  "timeout_seconds": timeout_seconds,
                                  "error": "RIZIN_FLIRT_TIMEOUT_PROCESS_TREE_TERMINATED"})
        if cp.returncode not in (0, None) or not (cp.stdout or "").strip():
            return None, 0.0, _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                                  "exit_code": cp.returncode, "error": "RIZIN_FLIRT_FAILED_OR_EMPTY_OUTPUT",
                                  "stderr_tail": (cp.stderr or "")[-2000:],
                                  "stdout_tail": (cp.stdout or "")[-500:]})
        if getattr(cp, "output_truncated", False):
            return None, 0.0, _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                                  "error": "RIZIN_FLIRT_OUTPUT_TRUNCATED_AT_CAP", "output_truncated": True,
                                  "max_output_chars": _MAX_OUTPUT_CHARS})
        return cp, elapsed, None

    @staticmethod
    def numbers(tool, timeout_seconds, max_items):
        try:
            return (max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS)),
                    max(1, min(int(max_items), _MAX_FUNCTIONS_RETURNED)), None)
        except (TypeError, ValueError):
            return None, None, _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                                   "error": "RIZIN_FLIRT_BAD_NUMERIC_ARGUMENT"})

    @staticmethod
    def resolve(tool, path, what="path"):
        """safe_path, then an existence check, both before any subprocess."""
        try:
            p = safe_path(path)
        except PermissionError as exc:
            return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            return None, _RzFlirt.env_failure(tool, exc, "RIZIN_FLIRT_PATH_CHECK_FAILED")
        try:
            is_file = p.is_file()
        except OSError as exc:
            return None, _RzFlirt.env_failure(tool, exc, "RIZIN_FLIRT_PATH_CHECK_FAILED")
        if not is_file:
            return None, _j({"ok": False, "tool": tool, "status": "NOT_FOUND", what: str(path)})
        return p, None

    @staticmethod
    def parse_table(text):
        """The `Fl` table -> (rows, None) or (None, reason). A line that is neither the
        header, the rule under it nor a readable row is a parse failure, not a skip."""
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines or tuple(lines[0].split()[:6]) != _RzFlirt.HEADER:
            return None, "RIZIN_FL_HEADER_NOT_RECOGNISED"
        rows = []
        for ln in lines[1:]:
            if not any(ch.isalnum() for ch in ln):
                continue
            m = _RzFlirt.ROW.match(ln)
            if not m:
                return None, "RIZIN_FL_ROW_NOT_RECOGNISED"
            rows.append({"bin": m.group(1), "arch": m.group(2), "bits": int(m.group(3)),
                         "name": m.group(4), "modules": int(m.group(5)), "details": m.group(6),
                         "path": f"{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}"})
        return rows, None

    @staticmethod
    def split_sections(text, markers):
        """stdout -> {marker: lines that FOLLOW it up to the next marker}; '' holds the head."""
        out, current, buf = {}, "", []
        for ln in text.splitlines():
            if ln.strip() in markers:
                out[current] = "\n".join(buf)
                current, buf = ln.strip(), []
            else:
                buf.append(ln)
        out[current] = "\n".join(buf)
        return out

    @staticmethod
    def write_evidence(p, op, stdout, stderr, commands):
        try:
            directory = EVIDENCE.parent / "rizin_flirt"
            directory.mkdir(parents=True, exist_ok=True)
            stem = re.sub(r"[^A-Za-z0-9._-]", "_", p.stem)[:80] or "input"
            out = directory / f"{stem}_{uuid.uuid4().hex[:8]}_{op}.txt"
            out.write_text(f"# rizin -c {commands!r}\n# --- stdout ---\n{stdout}\n# --- stderr ---\n{stderr or ''}\n",
                           encoding="utf-8")
            try:
                _evidence_index_record_write(out)
            except Exception:  # noqa: BLE001
                pass
            return out.name, None
        except Exception as exc:  # noqa: BLE001 - an evidence failure never blocks the result
            return None, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def functions_after(text, owner, seen):
        """Fold `afl~flirt` lines into ``seen`` (address -> record); the latest set to name it owns it."""
        for ln in text.splitlines():
            m = _RzFlirt.FUNC.match(ln.strip())
            if not m:
                continue
            addr = int(m.group(1), 16)
            name = m.group(3)[len("flirt."):]
            rec = seen.get(addr)
            if rec is None or rec["name"] != name:
                seen[addr] = {"address": addr, "address_hex": hex(addr), "size": int(m.group(2)),
                              "name": name, "signature_set": owner}

    @staticmethod
    def not_loaded(tool, p, probe):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                   "error": "RIZIN_FLIRT_NO_LOADED_BINARY", "load_probe": probe["status"], "path": relative(p),
                   "detail": "rizin's own binary-info probe does not confirm it recognised this file, so "
                             "there is nothing to match signatures against."})

    @staticmethod
    def apply(tool, op, path, signature_filter, sig_file, timeout_seconds, max_items, cancellation_token):
        exe = _rizin_binary()
        if not exe:
            return _RzFlirt.missing(tool)
        if sig_file is None and signature_filter is not None and (
                not isinstance(signature_filter, str) or not _RzFlirt.SET_FILTER.match(signature_filter)):
            return _j({"ok": False, "tool": tool, "status": "INVALID_ARGUMENT", "error": "FLIRT_FILTER_NOT_ALLOWED",
                       "detail": "signature_filter is matched by rizin against a signature file name; only "
                                 "letters, digits and . _ + - (1-64 characters) are accepted."})
        p, err = _RzFlirt.resolve(tool, path)
        if err:
            return err
        sig_p, sig_posix = None, None
        if sig_file is not None:
            sig_p, err = _RzFlirt.resolve(tool, sig_file, "signature_file")
            if err:
                return err
            if sig_p.suffix.lower() not in (".sig", ".pat"):
                return _j({"ok": False, "tool": tool, "status": "INVALID_ARGUMENT",
                           "error": "FLIRT_FILE_EXTENSION_NOT_SUPPORTED", "signature_file": str(sig_file),
                           "detail": "rizin loads FLIRT files by extension: .sig or .pat."})
            sig_posix = sig_p.as_posix()
            if not _RzFlirt.SIG_PATH.match(sig_posix):
                return _j({"ok": False, "tool": tool, "status": "INVALID_ARGUMENT",
                           "error": "FLIRT_SIGNATURE_PATH_NOT_ALLOWED", "signature_file": str(sig_file),
                           "detail": "The path is placed inside a rizin command, so only word characters, "
                                     "spaces and . _ + - ( ) : / \\ ~ are accepted; move or rename the file."})
        timeout_seconds, max_items, err = _RzFlirt.numbers(tool, timeout_seconds, max_items)
        if err:
            return err

        # Phase 1 (sigdb mode) -- what is this file, and which sets were built for it.
        probe, names, compatible = None, [], []
        if sig_p is None:
            cp, _elapsed, err = _RzFlirt.launch(tool, exe, "iIj; echo FLIRT_PROBE_END; Fl", p, timeout_seconds,
                                                cancellation_token)
            if err:
                return err
            head, _, table = _RzFlirt.ANSI.sub("", cp.stdout).partition("FLIRT_PROBE_END")
            probe = _rizin_load_probe(head)
            if probe["status"] != "BINARY_LOADED":
                return _RzFlirt.not_loaded(tool, p, probe)
            rows, why = _RzFlirt.parse_table(table)
            if rows is None:
                return _j({"ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED", "error": why,
                           "stdout_tail": table[-500:]})
            compatible = [r for r in rows if r["bin"] == probe.get("bintype") and r["arch"] == probe.get("arch")
                          and r["bits"] == probe.get("bits")
                          and (not signature_filter or signature_filter in r["name"])]
            if not compatible:
                return _j({
                    "ok": False, "tool": tool, "status": "NO_COMPATIBLE_SIGNATURES", "path": relative(p),
                    "target": {"bintype": probe.get("bintype"), "arch": probe.get("arch"),
                               "bits": probe.get("bits")},
                    "signature_filter": signature_filter, "sigdb_files": len(rows),
                    "sigdb_targets": sorted({f"{r['bin']}/{r['arch']}/{r['bits']}" for r in rows}),
                    "detail": "No signature set in the sigdb matches this binary's format, architecture and "
                              "bit width" + (f" and the filter {signature_filter!r}" if signature_filter else "")
                              + ", so nothing was applied. This is not a 'no match' result: a match was never "
                                "possible.",
                })
            for r in compatible:
                if r["name"] not in names:
                    names.append(r["name"])
            apply_cmds = "".join(f"Fa {n}; echo FLIRT_SET {n}; afl~flirt; " for n in names)
            markers = {f"FLIRT_SET {n}" for n in names}
        else:
            apply_cmds = f'Fs "{sig_posix}"; echo FLIRT_SET FILE; afl~flirt; '
            markers = {"FLIRT_SET FILE"}

        # Phase 2 -- analyse once with the sigdb switched off, then apply and read the names back.
        cmds = ("iIj; echo FLIRT_PROBE_END; aaa; afl~?; echo FLIRT_BASELINE; afl~flirt; " + apply_cmds).rstrip("; ")
        cp, elapsed, err = _RzFlirt.launch(tool, exe, cmds, p, timeout_seconds, cancellation_token)
        if err:
            return err
        evidence = _RzFlirt.write_evidence(p, op, cp.stdout, cp.stderr, cmds)
        stderr_text = _RzFlirt.ANSI.sub("", cp.stderr or "")
        head, _, rest = _RzFlirt.ANSI.sub("", cp.stdout).partition("FLIRT_PROBE_END")
        if probe is None:
            probe = _rizin_load_probe(head)
            if probe["status"] != "BINARY_LOADED":
                return _RzFlirt.not_loaded(tool, p, probe)
        count_text, _, after_baseline = rest.partition("FLIRT_BASELINE")
        count_lines = [ln.strip() for ln in count_text.splitlines() if ln.strip().isdigit()]
        functions_analyzed = int(count_lines[0]) if count_lines else None
        stderr_lines = [ln.strip() for ln in stderr_text.splitlines() if ln.strip()]
        if functions_analyzed == 0 or any("no analyzed functions" in ln for ln in stderr_lines):
            return _j({"ok": False, "tool": tool, "status": "NO_FUNCTIONS_TO_MATCH", "path": relative(p),
                       "functions_analyzed": functions_analyzed or 0, "load_probe": probe["status"],
                       "internal_evidence_name": evidence[0],
                       "detail": "rizin's analysis found no functions, so signatures had nothing to name. "
                                 "This is not a 'no match' result."})
        sections = _RzFlirt.split_sections(after_baseline, markers)
        seen: dict = {}
        _RzFlirt.functions_after(sections.get("", ""), None, seen)
        baseline = len(seen)
        target = {"bintype": probe.get("bintype"), "arch": probe.get("arch"), "bits": probe.get("bits")}
        if sig_p is not None:
            problems = [ln for ln in stderr_lines if ln.startswith("ERROR: FLIRT:")]
            if any("Can't open" in ln for ln in problems):
                return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                           "error": "FLIRT_SIGNATURE_FILE_NOT_OPENED", "signature_file": relative(sig_p),
                           "internal_evidence_name": evidence[0],
                           "detail": "rizin could not open a signature file that exists; this describes the "
                                     "machine, not the signatures."})
            if problems:
                mismatch = any("architecture did not match" in ln for ln in problems)
                return _j({"ok": False, "tool": tool,
                           "status": "SIGNATURE_ARCH_MISMATCH" if mismatch else "SIGNATURE_FILE_REJECTED",
                           "path": relative(p), "signature_file": relative(sig_p), "target": target,
                           "rizin_messages": problems[:10], "internal_evidence_name": evidence[0],
                           "detail": "rizin refused the signature file; nothing was matched, which is not a "
                                     "'no match' result."})
            _RzFlirt.functions_after(sections.get("FLIRT_SET FILE", ""), sig_p.name, seen)
            found = re.search(r"Found (\d+) FLIRT signatures via", after_baseline)
            extra = {"signature_source": "file", "signature_file": relative(sig_p),
                     "rizin_reported_signature_count": int(found.group(1)) if found else None,
                     "compatibility_verified": False,
                     "compatibility_note": "rizin checks the CPU family of a caller-supplied file but not its "
                                           "bit width, so a zero here does not prove the file was built for "
                                           "this binary."}
            completeness = "COMPLETE" if len(seen) > baseline else "COMPLETE_NO_MATCH_COMPATIBILITY_UNVERIFIED"
        else:
            for n in names:
                _RzFlirt.functions_after(sections.get(f"FLIRT_SET {n}", ""), n, seen)
            allowed = {r["path"] for r in compatible}
            errors = set()
            for m in _RzFlirt.SET_ERROR.finditer(stderr_text):
                tail = "/".join([x for x in re.split(r"[\\/]", m.group(1)) if x][-4:])
                if tail in allowed:  # an error on a foreign-arch set sharing the file name is expected noise
                    errors.add(tail)
            applied = sorted({a for a in _RzFlirt.APPLYING.findall(after_baseline) if a in allowed} - errors)
            extra = {"signature_source": "sigdb", "signature_filter": signature_filter,
                     "signature_sets_considered": sorted(allowed), "signature_sets_applied": applied,
                     "signature_sets_with_errors": sorted(errors)}
            completeness = ("PARTIAL_SIGNATURE_ERRORS" if errors
                            else ("COMPLETE" if len(seen) > baseline else "COMPLETE_NO_MATCH"))
        for rec in seen.values():
            if rec["signature_set"] is None:
                rec["signature_set"] = "(named before any signature was applied)"
        ordered = sorted(seen.values(), key=lambda r: r["address"])
        shaped = ordered[:max_items]
        per_set: dict = {}
        for r in ordered:
            per_set[r["signature_set"]] = per_set.get(r["signature_set"], 0) + 1
        return _j({
            "ok": True, "tool": tool, "status": "OK", "path": relative(p),
            "engine": "rizin", "target": target, "load_probe": probe["status"],
            "functions_analyzed": functions_analyzed,
            "match_count": len(ordered), "returned": len(shaped), "truncated": len(ordered) > len(shaped),
            "analysis_completeness": "LIST_CAPPED_AT_MAX_ITEMS" if len(ordered) > len(shaped) else completeness,
            "matches_per_signature_set": dict(sorted(per_set.items())),
            "named_functions": shaped,
            **extra,
            "wall_clock_seconds": round(elapsed, 3),
            "internal_evidence_name": evidence[0], "evidence_write_error": evidence[1],
        })


def rizin_flirt_match(path, signature_filter=None, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                      max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Name library functions by matching the sigdb bundled with rizin (`Fa`) against
    `path`. No signature files are needed. Only the sets built for the binary's own format,
    architecture and bit width are applied, one at a time, so every named function carries
    the `signature_set` that named it (as `<bin>/<arch>/<bits>/<file>.sig`). `signature_filter`
    narrows the sets by a case-sensitive part of the file name (`winsdk`, `VisualStudio2019`).
    Each hit is a function rizin renamed: `address`, `size`, `name` (without rizin's `flirt.`
    prefix). `analysis_completeness` is COMPLETE, COMPLETE_NO_MATCH (the compatible sets were
    applied and none matched: a real negative), PARTIAL_SIGNATURE_ERRORS or
    LIST_CAPPED_AT_MAX_ITEMS; `match_count` is the full count.
    Status: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, INVALID_ARGUMENT, CANCELLED, TIMEOUT,
    RESULT_PARSE_FAILED, ANALYSIS_LIMITED (failure, empty/truncated output, an environment
    error carrying `environment_error`, or a file rizin did not recognise as a binary),
    NO_COMPATIBLE_SIGNATURES (no set exists for this format/arch/bits, or none survives the
    filter: a match was never possible) and NO_FUNCTIONS_TO_MATCH (the analysis found no
    functions). The last two are never a zero."""
    return _RzFlirt.apply("rizin_flirt_match", "fa", path, signature_filter, None, timeout_seconds,
                          max_items, cancellation_token)


def rizin_flirt_match_file(path, signature_file, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
                           max_items: int = _MAX_FUNCTIONS_RETURNED, cancellation_token=None) -> str:
    """Apply one FLIRT file (`.sig` or `.pat`, `Fs`) to `path`, e.g. one of an IDA install's
    `sig` files. `signature_file` goes through the workspace sandbox like `path`. Result shape
    as rizin_flirt_match with `signature_source: "file"`. rizin checks only the CPU family of
    such a file, never its bit width, so a zero is reported as
    COMPLETE_NO_MATCH_COMPATIBILITY_UNVERIFIED with `compatibility_verified: false`.
    Extra statuses: SIGNATURE_FILE_REJECTED (not a FLIRT file / corrupt) and
    SIGNATURE_ARCH_MISMATCH (different CPU family); a missing file is NOT_FOUND and any
    other extension is INVALID_ARGUMENT."""
    return _RzFlirt.apply("rizin_flirt_match_file", "fs", path, None, signature_file, timeout_seconds,
                          max_items, cancellation_token)


def rizin_flirt_inventory(timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS, cancellation_token=None) -> str:
    """What the sigdb holds (`Fl`): one entry per signature file with `bin`, `arch`, `bits`,
    `name`, `module` count, `details` and `path` (`<bin>/<arch>/<bits>/<file>`), plus
    `by_target` totals so a caller can see whether a binary's architecture is covered before
    matching. A separate operation, not part of rizin_status: that call has a fixed two-key
    shape callers rely on, and the sigdb can be missing or empty while rizin.exe is present
    (SIGDB_EMPTY_OR_UNAVAILABLE, not a zero-file success). rizin 0.9.1 has no JSON form of
    `Fl`; the table is parsed strictly. Status: OK, TOOL_MISSING, CANCELLED, TIMEOUT,
    ANALYSIS_LIMITED, RESULT_PARSE_FAILED, SIGDB_EMPTY_OR_UNAVAILABLE."""
    tool = "rizin_flirt_inventory"
    exe = _rizin_binary()
    if not exe:
        return _RzFlirt.missing(tool)
    timeout_seconds, _unused, err = _RzFlirt.numbers(tool, timeout_seconds, 1)
    if err:
        return err
    cp, elapsed, err = _RzFlirt.launch(tool, exe, "Fl", None, timeout_seconds, cancellation_token)
    if err:
        return err
    table = _RzFlirt.ANSI.sub("", cp.stdout)
    rows, why = _RzFlirt.parse_table(table)
    if rows is None:
        return _j({"ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED", "error": why,
                   "stdout_tail": table[-500:]})
    if not rows:
        return _j({"ok": False, "tool": tool, "status": "SIGDB_EMPTY_OR_UNAVAILABLE",
                   "stderr_tail": (cp.stderr or "")[-500:],
                   "detail": "rizin listed no signature files. The embedded sigdb may be missing from this "
                             "install; supply files with rizin_flirt_match_file instead."})
    by_target: dict = {}
    for r in rows:
        t = by_target.setdefault((r["bin"], r["arch"], r["bits"]), {"files": 0, "modules": 0})
        t["files"] += 1
        t["modules"] += r["modules"]
    return _j({
        "ok": True, "tool": tool, "status": "OK", "engine": "rizin",
        "file_count": len(rows), "module_count": sum(r["modules"] for r in rows),
        "by_target": [{"bin": b, "arch": a, "bits": n, **v} for (b, a, n), v in sorted(by_target.items())],
        "signature_files": rows,
        "wall_clock_seconds": round(elapsed, 3),
    })
