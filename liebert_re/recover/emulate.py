"""Bounded emulation of a code range inside a PE32+ (x86-64) image, behind a declared-target-class gate.

One public operation, :func:`emulate_range`. It maps the image the way a loader would at its preferred
base (no relocation), points every import slot at an unmapped trap address, and runs the Unicorn engine
from a caller-chosen address until something stops it. It EXECUTES NOTHING NATIVELY on the host: the
instructions run inside the emulator, in a separate interpreter. That interpreter is a process boundary
(timeout, memory limit, no inherited stdin), NOT a sandbox: ``host_isolation`` says so on every response.

What stops a run (``stop_reason``). Every stop is a measurement, never a guess about what would have
happened next:

  ``RETURNED``          the entry routine returned to the sentinel return address pushed on the stack: the last
                        instruction run was a ``ret`` and the stack pointer is where that ``ret`` leaves it
  ``SENTINEL_REACHED``  control reached the sentinel address some other way (a ``jmp``, a ``call``, a ``ret`` with the
                        stack elsewhere) or the last instruction could not be read; this is not a return, and
                        ``stop_detail.not_verified_because`` says which check failed
  ``STOP_ADDRESS``      execution reached an address in ``stop_at`` (before executing it)
  ``IMPORT_CALL``       control reached an import slot's trap address; ``stop_detail.import`` is ``dll!name``
  ``SYSCALL``           a ``syscall`` or ``sysenter`` instruction (``stop_detail.number`` is RAX)
  ``INTERRUPT``         an ``int n`` other than 3, or a CPU exception delivered as an interrupt
  ``INT3`` ``UD2`` ``HLT``
  ``UNMAPPED_READ`` ``UNMAPPED_WRITE`` ``UNMAPPED_FETCH``   access to memory that is not mapped
  ``WRITE_PROTECT``     a write to a page the image declares non-writable (``perm_mode="as_declared"``)
  ``READ_PROTECT`` ``FETCH_PROTECT`` ``INVALID_INSTRUCTION`` ``PORT_IO``   as named
  ``INSN_LIMIT`` ``TIMEOUT``   the caller's bounds
  ``UNMODELLED_VEX``    a VEX instruction :mod:`liebert_re.recover.vex` does not model (see that module)
  ``ENGINE_ERROR``      the engine raised an error this module has no name for
  ``ENGINE_CRASH``      the emulator process died; whatever it had written is listed and ``unverified``
  ``UNKNOWN_STOP``      the engine returned and nothing explains why

``ok`` only says a result record exists. ``completion`` says whether the routine finished: ``RETURNED`` (only for a
verified ``ret`` to the sentinel),
``STOPPED_AT_IMPORT``, ``STOPPED_AT_SYSCALL``, ``INSN_LIMIT``, ``TIMEOUT``, ``FAULT`` (a memory fault, a protection
fault, ``UD2`` or an invalid encoding) or ``UNKNOWN`` (any other stop, including ``STOP_ADDRESS`` and
``SENTINEL_REACHED``); ``null`` when
nothing ran. ``limitations`` lists what weakens this particular run; an unreadable import directory is one (no slot
is trapped, so the IMPORT_CALL guarantee is gone, and the run is kept because everything up to the call is still a
real measurement).

There are NO API stubs: a call into an import stops the run, it is not answered. Nothing here fakes a
Windows environment beyond the minimal TEB/PEB declared in ``teb_peb_model``.

The target gate (:class:`EmulationGate`) is a declaration plus a hash, and nothing more. ``target_class``
is required: ``public_crackme`` (a challenge written to be solved) or ``owned_target`` (the caller owns
it: an ``authorization`` object names who authorised the run and why, and its ``sample_sha256`` must
equal the file's real SHA-256). Anything else, including a missing value, is ``TARGET_CLASS_REQUIRED``.
A ``public_crackme`` whose file name matches a name listed in the optional operator registry
``~/.liebert-re/targets.txt`` is ``CLASS_CONFLICT``; the registry is best effort and ``registry_checked``
says whether it was read. There is deliberately no environment-variable key.

Evidence goes under ``dataset/evidence/emulate_range/``; memory dumps (raw bytes, NOT PE files) under
``dataset/emulation/<input_sha16>/<run_id>/``. If the final evidence record cannot be written the result
is withheld (``EVIDENCE_FINALIZE_FAILED``): a run without a record is not returned. Responses carry no
file-system path.

Not modelled, so a run that depends on any of it stops or silently differs: TLS callbacks and loader
initialisers (they do not run; the caller supplies ``start_va``), delay-load and bound imports, relocation,
exceptions and SEH, threads, any OS state, ``cpuid``/``rdtsc`` values (Unicorn's own CPU model answers),
32-bit images. See ``limits`` in every result.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
import time
import uuid
from pathlib import Path

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
from liebert_re.workspace import safe_path

EVIDENCE = APP_DIR / "dataset" / "evidence" / "emulate_range"
DUMP_ROOT = APP_DIR / "dataset" / "emulation"

TOOL = "emulate_range"
HOST_ISOLATION = "process boundary; not a sandbox"
DEFAULT_MAX_MEMORY_BYTES = 2 * 1024 ** 3
WALL_GRACE_SECONDS = 30
MAX_INSTRUCTIONS_CEILING = 50_000_000
TIMEOUT_CEILING_SECONDS = 600
MAX_IMAGE_BYTES = 256 * 1024 ** 2
MAX_STOP_ADDRESSES = 64
MAX_REGISTERS = 24
MAX_REGIONS_REPORTED = 256
MAX_CHILD_OUTPUT_CHARS = 4 * 1024 ** 2    # the result line is bounded far below this; a cut line would not parse

# Fixed layout of everything that is not the image. The image sits at its preferred base; a collision with
# any of these is MAP_CONFLICT, never a silent relocation.
PAGE = 0x1000
STACK_HIGH = 0x7FFC0000
TEB_VA, TEB_SIZE = 0x7FFDA000, 0x2000
PEB_VA, PEB_SIZE = 0x7FFDE000, 0x1000
SENTINEL_VA = 0x7FEE00000000
TRAP_BASE = 0x7FEF00000000
TRAP_STRIDE = 16

_GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
_SETTABLE = frozenset(_GPRS) | {"eflags", "rflags"}

_LIMITS = (
    "x86-64 PE32+ images only; a 32-bit PE is refused (UNSUPPORTED_ARCHITECTURE)",
    "no relocation: the image is mapped at its preferred base or the run is refused (MAP_CONFLICT)",
    "TLS callbacks, loader initialisers and entry-point wrappers do not run; the caller names start_va",
    "import slots point at unmapped trap addresses; a call into one stops the run, nothing is answered",
    "delay-load and bound imports are not read; only the ordinary import directory is",
    "no OS state: no handles, files, threads, exceptions/SEH, or syscalls (a syscall stops the run)",
    "cpuid and rdtsc answer from Unicorn's synthetic CPU model, not from any real machine",
    "an executable-only page is readable (Unicorn does not model execute-only)",
    "memory beyond the stack, image, TEB and PEB is unmapped; the stack does not grow",
    "a section's bytes past VirtualSize are zero; the loader's exposure of raw bytes there is not modelled",
)
_COUNT_BASIS = ("instructions the engine dispatched (counted by a per-instruction hook), not counting one "
                "refused before it ran (INSN_LIMIT, STOP_ADDRESS, TIMEOUT) or one that faulted on a data "
                "access or an invalid encoding; a trapping instruction (syscall, int, hlt) is counted")
_RIP_BASIS = "the 64 most recently dispatched instruction addresses, oldest first"
_REG_BASIS = ("registers as the engine holds them when the run stops; an instruction that trapped "
              "(syscall, int3) has already advanced RIP past itself")

# ``completion`` says whether the routine finished, which ``ok`` does not ("a result record exists"). It is derived
# from ``stop_reason`` and from nothing else: a reason that is not listed here is UNKNOWN, never a guess.
_COMPLETION = {
    "RETURNED": "RETURNED", "IMPORT_CALL": "STOPPED_AT_IMPORT", "SYSCALL": "STOPPED_AT_SYSCALL",
    "INSN_LIMIT": "INSN_LIMIT", "TIMEOUT": "TIMEOUT",
    "UNMAPPED_READ": "FAULT", "UNMAPPED_WRITE": "FAULT", "UNMAPPED_FETCH": "FAULT", "READ_PROTECT": "FAULT",
    "WRITE_PROTECT": "FAULT", "FETCH_PROTECT": "FAULT", "INVALID_INSTRUCTION": "FAULT", "UD2": "FAULT",
}
_COMPLETION_BASIS = ("completion is derived from stop_reason alone: RETURNED only when the last instruction run was a "
                     "ret and it left the stack pointer where a return to the sentinel leaves it; reaching the sentinel "
                     "by a jmp, a call or any other path is SENTINEL_REACHED, not a return; a stop this table does not "
                     "name (STOP_ADDRESS, SENTINEL_REACHED, INT3, INTERRUPT, HLT, PORT_IO, UNMODELLED_VEX, "
                     "ENGINE_ERROR, ENGINE_CRASH, MEMORY_LIMIT, UNKNOWN_STOP) is UNKNOWN, and null means no emulation "
                     "ran. ok only says a result record exists")
_IMPORT_UNREADABLE = {
    "code": "IMPORT_DIRECTORY_UNREADABLE",
    "detail": "the import directory could not be read, so no slot was trapped and the guarantee that a call into an "
              "import stops as IMPORT_CALL does not hold for this run; a call through an import slot ends as some "
              "other stop (usually an unmapped fetch) and cannot be told apart from a wild jump"}


def _ret_check(code, rsp, slot):
    """Why a fetch at the sentinel is not proven to be a ``ret`` returning to it, or None when it is proven.

    ``code`` is the bytes of the last instruction run, ``rsp`` the stack pointer after it, ``slot`` the address of
    the stack cell that held the sentinel at the start. Only ``ret`` / ``ret imm16`` (optionally after a REX or a
    rep/bnd prefix) pops its target from the stack, and a pop of that cell leaves rsp at ``slot + 8 (+ imm16)``;
    a ``jmp`` or ``call`` to the sentinel, or a ``ret`` that popped something else, fails one of the two."""
    if not code:
        return "the last executed instruction could not be read"
    i = 0
    if code[i] in (0xF2, 0xF3):
        i += 1
    if i < len(code) and 0x40 <= code[i] <= 0x4F:
        i += 1
    if i >= len(code):
        return "the last executed instruction is not a ret"
    if code[i] == 0xC3:
        extra = 0
    elif code[i] == 0xC2 and len(code) >= i + 3:
        extra = code[i + 1] | (code[i + 2] << 8)
    else:
        return "the last executed instruction is not a ret"
    if rsp != slot + 8 + extra:
        return "the stack pointer is not where a ret that popped the sentinel slot leaves it"
    return None


def _completion(stop_reason):
    """The completion value for a stop reason; None when there is no stop reason (nothing ran)."""
    return None if stop_reason is None else _COMPLETION.get(stop_reason, "UNKNOWN")


_STATUS_PREFIX = {"public_crackme": "a challenge written to be solved (declared, not verified)",
                  "owned_target": "a target the caller owns, with a named authorizer and a bound hash"}


def _j(payload):
    return json.dumps(payload, ensure_ascii=True, indent=2, default=str)


def _hx(value):
    return None if value is None else "0x%x" % value


def _align_up(value, boundary):
    return (value + boundary - 1) & ~(boundary - 1)


def _safe_text(raw, limit=64):
    """A PE-supplied name made printable: attacker-controlled bytes never reach a record verbatim."""
    text = raw.decode("latin-1") if isinstance(raw, (bytes, bytearray)) else str(raw)
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in text)[:limit]


def _utc_stamp():
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _int_value(value):
    """An int from an int or a ``0x...``/decimal string; None for anything else (a bool is not a number)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*(?:0[xX][0-9a-fA-F]+|\d+)\s*", value):
        return int(value.strip(), 0)
    return None


# ---------------------------------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------------------------------

class EmulationGate:
    """What must be declared before a file is emulated. A class, so the layout pin counts no helper."""

    CLASSES = ("public_crackme", "owned_target")

    @staticmethod
    def registry():
        """``(names, note)``: lower-cased entries of ``~/.liebert-re/targets.txt``, or ``(None, why)``."""
        try:
            text = (Path.home() / ".liebert-re" / "targets.txt").read_text(encoding="utf-8", errors="replace")
        except (OSError, RuntimeError) as exc:
            return None, ("no registry file" if isinstance(exc, FileNotFoundError)
                          else "the registry could not be read (%s)" % type(exc).__name__)
        names = set()
        for line in text.splitlines():
            entry = line.split("#", 1)[0].strip().lower()
            if entry:
                names.add(entry)
                names.add(Path(entry).stem)
        return names, None

    @staticmethod
    def _authorization(value):
        """``(clean, None)`` or ``(None, (status, reason))``."""
        if value is None:
            return None, ("AUTHORIZATION_REQUIRED", "owned_target needs an authorization object")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None, ("AUTHORIZATION_REQUIRED", "the authorization is not valid JSON")
        if not isinstance(value, dict):
            return None, ("AUTHORIZATION_REQUIRED", "the authorization must be an object")
        for key in ("authorized_by", "purpose"):
            field = value.get(key)
            if not isinstance(field, str) or not field.strip() or len(field) > 200:
                return None, ("AUTHORIZATION_REQUIRED",
                              "%s must be a non-empty string of at most 200 characters" % key)
        declared = value.get("sample_sha256")
        if not isinstance(declared, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared.strip()):
            return None, ("SAMPLE_HASH_REQUIRED", "the authorization must carry sample_sha256 as 64 hex characters")
        return {"authorized_by": value["authorized_by"].strip(), "purpose": value["purpose"].strip(),
                "sample_sha256": declared.strip().lower()}, None

    @staticmethod
    def evaluate(file_stem, sha256, target_class, authorization=None, sample_sha256=None):
        """The decision as a dict. Never raises. ``ok`` is True only if every check passed; a refusal
        carries ``status`` (the machine-readable reason) and ``detail``."""
        decision = {"ok": False, "status": None, "target_class": target_class if isinstance(target_class, str) else None,
                    "checks": [], "registry_checked": False, "authorization": None,
                    "declaration_only": True,
                    "note": "a declaration bound to a hash, not a proof about the file or who owns it"}

        def refuse(name, status, detail):
            decision["checks"].append({"check": name, "result": "failed", "detail": detail})
            decision.update(ok=False, status=status, detail=detail)
            return decision

        def passed(name, detail):
            decision["checks"].append({"check": name, "result": "passed", "detail": detail})

        if target_class not in EmulationGate.CLASSES:
            return refuse("target_class", "TARGET_CLASS_REQUIRED",
                          "target_class must be exactly one of %s; anything else, including a third-party "
                          "product, is refused" % ", ".join(EmulationGate.CLASSES))
        passed("target_class", "%s: %s" % (target_class, _STATUS_PREFIX[target_class]))
        declared = None
        if sample_sha256 is not None:
            if not isinstance(sample_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sample_sha256.strip()):
                return refuse("sample_hash", "SAMPLE_HASH_REQUIRED", "sample_sha256 must be 64 hex characters")
            declared = sample_sha256.strip().lower()
        if target_class == "owned_target":
            clean, why = EmulationGate._authorization(authorization)
            if clean is None:
                return refuse("authorization", why[0], why[1])
            if declared is not None and declared != clean["sample_sha256"]:
                return refuse("sample_hash", "SAMPLE_HASH_MISMATCH",
                              "sample_sha256 and the authorization's sample_sha256 disagree")
            declared = clean["sample_sha256"]
            decision["authorization"] = clean
            passed("authorization", "authorized_by, purpose and sample_sha256 declared")
        if declared is not None:
            if declared != sha256:
                return refuse("sample_hash", "SAMPLE_HASH_MISMATCH",
                              "the declared sha256 does not match the file's real sha256")
            passed("sample_hash", "declared sha256 equals the file's sha256")
        else:
            passed("sample_hash", "no sha256 declared (optional for public_crackme)")
        if target_class == "public_crackme":
            names, note = EmulationGate.registry()
            decision["registry_checked"] = names is not None
            if names is None:
                decision["registry_note"] = note
                passed("registry", "not checked: %s" % note)
            else:
                stem = (file_stem or "").lower()
                if stem and stem in names:
                    return refuse("registry", "CLASS_CONFLICT",
                                  "the file name matches an entry in the operator's target registry, so it "
                                  "cannot be declared a public crackme")
                passed("registry", "no registry entry matches the file name")
        decision.update(ok=True, status="GATE_PASSED")
        return decision


# ---------------------------------------------------------------------------------------------------
# Evidence (parent side)
# ---------------------------------------------------------------------------------------------------

class _Ledger:
    @staticmethod
    def write(name, record):
        """None on success, else an environment_error dict."""
        try:
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            destination = EVIDENCE / name
            if destination.resolve().parent != EVIDENCE.resolve():
                return {"type": "EvidencePathEscape", "errno": None,
                        "strerror": "the evidence file would resolve outside the evidence folder; nothing was written"}
            destination.write_text(json.dumps(record, ensure_ascii=True, default=str), encoding="utf-8")
            return None
        except OSError as exc:
            return {"type": type(exc).__name__, "errno": exc.errno, "strerror": exc.strerror or type(exc).__name__}


# ---------------------------------------------------------------------------------------------------
# The parent: validate, gate, spawn, interpret
# ---------------------------------------------------------------------------------------------------

_BOOT = ("import sys; sys.path.insert(0, sys.argv[1]); "
         "from liebert_re.recover.emulate import _child_main; raise SystemExit(_child_main(sys.argv[2]))")


class _Runner:
    @staticmethod
    def usage(error, message):
        return {"ok": False, "tool": TOOL, "status": "TOOL_USAGE", "error": error, "message": message}

    @staticmethod
    def validate(start_va, stop_at, max_instructions, timeout_s, watch_writes, registers, stack_size, perm_mode):
        """``(params, None)`` or ``(None, usage dict)``."""
        start = _int_value(start_va)
        if start is None or not 0 <= start < 1 << 64:
            return None, _Runner.usage("BAD_START_VA", "start_va must be an integer or a 0x... string below 2**64")
        stops = []
        if stop_at is not None:
            if isinstance(stop_at, (str, bytes)) or not hasattr(stop_at, "__iter__"):
                return None, _Runner.usage("BAD_STOP_AT", "stop_at must be a list of addresses")
            for item in stop_at:
                value = _int_value(item)
                if value is None or not 0 <= value < 1 << 64:
                    return None, _Runner.usage("BAD_STOP_AT", "every stop_at entry must be an integer or 0x... string")
                stops.append(value)
        if len(stops) > MAX_STOP_ADDRESSES:
            return None, _Runner.usage("BAD_STOP_AT", "at most %d stop addresses" % MAX_STOP_ADDRESSES)
        if start in stops:
            return None, _Runner.usage("BAD_STOP_AT", "start_va is in stop_at, so nothing could run")
        if isinstance(max_instructions, bool) or not isinstance(max_instructions, int) \
                or not 1 <= max_instructions <= MAX_INSTRUCTIONS_CEILING:
            return None, _Runner.usage("BAD_MAX_INSTRUCTIONS", "max_instructions must be an integer from 1 to %d"
                                       % MAX_INSTRUCTIONS_CEILING)
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) \
                or not 0 < timeout_s <= TIMEOUT_CEILING_SECONDS:
            return None, _Runner.usage("BAD_TIMEOUT", "timeout_s must be a number above 0 and at most %d"
                                       % TIMEOUT_CEILING_SECONDS)
        if watch_writes not in ("image", "all"):
            return None, _Runner.usage("BAD_WATCH_WRITES", "watch_writes must be 'image' or 'all'")
        if perm_mode not in ("as_declared", "rwx"):
            return None, _Runner.usage("BAD_PERM_MODE", "perm_mode must be 'as_declared' or 'rwx'")
        size = _int_value(stack_size)
        if size is None or size % PAGE or not 0x4000 <= size <= 0x4000000:
            return None, _Runner.usage("BAD_STACK_SIZE", "stack_size must be a multiple of 0x1000 from 0x4000 to 0x4000000")
        regs = {}
        if registers is not None:
            if not isinstance(registers, dict) or len(registers) > MAX_REGISTERS:
                return None, _Runner.usage("BAD_REGISTERS", "registers must be an object of at most %d entries" % MAX_REGISTERS)
            for name, raw in registers.items():
                key = str(name).lower()
                value = _int_value(raw)
                if key not in _SETTABLE or value is None or not 0 <= value < 1 << 64:
                    return None, _Runner.usage("BAD_REGISTERS", "registers accepts %s with integer values below 2**64"
                                               % ", ".join(sorted(_SETTABLE)))
                regs["eflags" if key == "rflags" else key] = value
        return {"start_va": start, "stop_at": sorted(set(stops)), "max_instructions": max_instructions,
                "timeout_s": float(timeout_s), "watch_writes": watch_writes, "registers": regs,
                "stack_size": size, "perm_mode": perm_mode}, None

    @staticmethod
    def child_command(job_path):
        root = str(Path(__file__).resolve().parents[2])
        return [sys.executable, "-I", "-c", _BOOT, root, str(job_path)]

    @staticmethod
    def child_environment():
        keep = ("SystemRoot", "SYSTEMROOT", "windir", "PATH", "TEMP", "TMP", "LANG", "LC_ALL")
        return {key: os.environ[key] for key in keep if key in os.environ}

    @staticmethod
    def sha256_of(path):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def finish(result):
        result["tool"] = TOOL
        result["host_isolation"] = HOST_ISOLATION
        result.setdefault("completion", None)      # a refusal or a usage error ran nothing
        return result

    @staticmethod
    def interpret(outcome, run_dir):
        """The child's ``BoundedProcessResult`` -> a result dict (before gate/evidence fields)."""
        from liebert_re.bounded_subprocess import launch_failure
        if getattr(outcome, "launch_failed", False) is True:
            return launch_failure(outcome, TOOL, "EMULATOR_LAUNCH_FAILED")
        if outcome.resource_limit_unavailable:
            return {"ok": False, "status": "RESOURCE_LIMIT_UNAVAILABLE", "error": "MEMORY_MONITOR_UNUSABLE",
                    "detail": "this host cannot measure process memory, so the memory limit could not be "
                              "enforced and nothing was run"}
        if outcome.timed_out:
            return {"ok": False, "status": "TIMEOUT", "error": "EMULATOR_WALL_TIMEOUT", "stop_reason": "TIMEOUT",
                    "state_available": False, "process_tree_terminated": outcome.process_tree_terminated,
                    "detail": "the emulator process did not finish inside the wall bound and was terminated; "
                              "no register or memory state was recovered"}
        if outcome.memory_exceeded:
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "MEMORY_LIMIT_EXCEEDED",
                    "stop_reason": "MEMORY_LIMIT", "state_available": False,
                    "process_tree_terminated": outcome.process_tree_terminated,
                    "detail": "the emulator process exceeded its memory bound and was terminated"}
        lines = [ln for ln in (outcome.stdout or "").splitlines() if ln.strip()]
        body = None
        if outcome.returncode == 0 and lines:
            try:
                parsed = json.loads(lines[-1])
                body = parsed if isinstance(parsed, dict) else None
            except ValueError:
                body = None
        if body is None:
            partial = []
            try:
                for item in sorted(Path(run_dir).iterdir()):
                    if item.is_file() and item.name not in ("input.bin", "job.json"):
                        partial.append({"file": _safe_text(item.name), "size": item.stat().st_size,
                                        "sha256": _Runner.sha256_of(item), "unverified": True})
            except OSError:
                pass
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "ENGINE_CRASH", "stop_reason": "ENGINE_CRASH",
                    "state_available": False, "emulator_exit_code": outcome.returncode,
                    "stderr_chars": len(outcome.stderr or ""), "partial_dumps": partial,
                    "detail": "the emulator process ended without a result (a native crash or a kill). Whatever "
                              "it had written is listed under partial_dumps and is unverified: it may be cut "
                              "short and says nothing about where the run stopped."}
        return body

    @staticmethod
    def run(path, params):
        started = time.time()
        run_id = "%s_%s" % (_utc_stamp(), uuid.uuid4().hex[:8])
        try:
            target = safe_path(path)
        except PermissionError as exc:
            return {"ok": False, "status": "PATH_REFUSED", "error": str(exc)}
        if not target.is_file():
            return {"ok": False, "status": "NOT_FOUND", "error": "FILE_NOT_FOUND"}
        try:
            size = target.stat().st_size
            if size > MAX_IMAGE_BYTES:
                return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "FILE_TOO_LARGE",
                        "detail": "the file is larger than the %d bytes this tool will map" % MAX_IMAGE_BYTES}
            data = target.read_bytes()
        except OSError as exc:
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "FILE_UNREADABLE",
                    "environment_error": {"type": type(exc).__name__, "errno": exc.errno}}
        sha = hashlib.sha256(data).hexdigest()
        gate = EmulationGate.evaluate(target.stem, sha, params.pop("_target_class"),
                                      params.pop("_authorization"), params.pop("_sample_sha256"))
        record = {"run_id": run_id, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
                  "input": {"sha256": sha, "size": size, "name_omitted": True}, "gate": gate,
                  "bounds": {"max_instructions": params["max_instructions"], "timeout_s": params["timeout_s"],
                             "memory_bytes": DEFAULT_MAX_MEMORY_BYTES, "stack_size": params["stack_size"],
                             "watch_writes": params["watch_writes"], "perm_mode": params["perm_mode"]},
                  "request": {"start_va": _hx(params["start_va"]), "stop_at": [_hx(a) for a in params["stop_at"]],
                              "registers": {k: _hx(v) for k, v in params["registers"].items()}}}
        if not gate["ok"]:
            name = "%s_refused.json" % run_id
            record.update(status=gate["status"], detail=gate["detail"])
            return {"ok": False, "status": gate["status"], "error": "GATE_REFUSED", "detail": gate["detail"],
                    "gate": gate, "run_id": run_id, "input": record["input"], "evidence_name": name,
                    "evidence_write_error": _Ledger.write(name, record)}
        gate_name = "%s_gate.json" % run_id
        error = _Ledger.write(gate_name, record)
        if error:
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "GATE_EVIDENCE_UNWRITABLE",
                    "environment_error": error, "gate": gate, "run_id": run_id, "operation_ran": False,
                    "detail": "the gate record could not be written; a run without evidence is refused. This "
                              "describes this machine, not the target."}
        run_dir = DUMP_ROOT / sha[:16] / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "input.bin").write_bytes(data)
            job = dict(params, input_sha256=sha, dump_dir=str(run_dir), input_file="input.bin")
            (run_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "DUMP_DIRECTORY_UNWRITABLE",
                    "environment_error": {"type": type(exc).__name__, "errno": exc.errno}, "gate": gate,
                    "run_id": run_id, "operation_ran": False}
        from liebert_re.bounded_subprocess import run_bounded_process
        try:
            outcome = run_bounded_process(
                _Runner.child_command(run_dir / "job.json"), timeout_seconds=params["timeout_s"] + WALL_GRACE_SECONDS,
                cwd=run_dir, environment=_Runner.child_environment(), max_memory_bytes=DEFAULT_MAX_MEMORY_BYTES,
                max_output_chars=MAX_CHILD_OUTPUT_CHARS)
            result = _Runner.interpret(outcome, run_dir)
        finally:
            for scratch in ("input.bin", "job.json"):
                try:
                    (run_dir / scratch).unlink()
                except OSError:
                    pass
        ran = bool(result.get("ok")) or result.get("stop_reason") is not None
        result.setdefault("completion", _completion(result.get("stop_reason")))
        result.update(run_id=run_id, gate=gate, input=record["input"], bounds=record["bounds"],
                      request=record["request"], operation_ran=ran,
                      dump={"location": "dataset/emulation/<input_sha16>/<run_id>/", "input_sha16": sha[:16],
                            "run_id": run_id, "format": "raw memory bytes (.bin); NOT a PE file"})
        result["limits"] = list(_LIMITS)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        final = dict(result, evidence_name=gate_name)
        error = _Ledger.write(gate_name, {**record, "result": final})
        if error:
            return {"ok": False, "status": "EVIDENCE_FINALIZE_FAILED", "error": "RESULT_WITHHELD_EVIDENCE_NOT_WRITTEN",
                    "operation_ran": ran, "result_withheld": True, "environment_error": error, "gate": gate,
                    "run_id": run_id, "dumps_retained": ran,
                    "detail": "the emulation " + ("ran" if ran else "did not start") + ", but its final evidence "
                              "record could not be written, so its result is withheld; a result without evidence "
                              "is not returned. This describes this machine, not the target."}
        result["evidence_name"] = gate_name
        return result


def emulate_range(path, start_va, *, stop_at=(), max_instructions=5_000_000, timeout_s=120,
                  watch_writes="image", registers=None, stack_size=0x100000, perm_mode="as_declared",
                  target_class=None, authorization=None, sample_sha256=None):
    """Emulate a bounded range of a PE32+ (x86-64) image from ``start_va`` and report why and where it stopped.

    Runs inside the Unicorn engine in a separate interpreter (a process boundary, not a sandbox; nothing
    runs natively on the host). Imports are trapped, not answered; a syscall stops the run. Returns JSON.

    ``target_class`` is required: ``public_crackme`` or ``owned_target`` (the latter also needs an
    ``authorization`` object with ``authorized_by``, ``purpose`` and ``sample_sha256``, the last equal to the
    file's real SHA-256). Anything else is ``TARGET_CLASS_REQUIRED``. ``stop_at`` lists addresses at which to
    stop before executing; ``registers`` sets initial values (``rsp`` is where the return sentinel is
    written). ``perm_mode="rwx"`` maps every section read-write-execute and is reported as an approximation.
    ``watch_writes`` is ``"image"`` or ``"all"``: which writes are recorded in ``written_regions``.

    ``ok`` is true when the engine ran and reports a stop; ``stop_reason`` says which, and ``completion`` says
    whether the routine finished (``RETURNED``, ``STOPPED_AT_IMPORT``, ``STOPPED_AT_SYSCALL``, ``INSN_LIMIT``,
    ``TIMEOUT``, ``FAULT``, ``UNKNOWN``; ``null`` if nothing ran). ``limitations`` lists what weakens this run. Memory dumps are raw
    bytes under ``dataset/emulation/`` and the response names no path. Statuses other than ``OK``:
    ``TARGET_CLASS_REQUIRED``, ``CLASS_CONFLICT``, ``AUTHORIZATION_REQUIRED``, ``SAMPLE_HASH_REQUIRED``,
    ``SAMPLE_HASH_MISMATCH`` (nothing ran), ``TOOL_USAGE``, ``PATH_REFUSED``, ``NOT_FOUND``, ``NOT_A_PE``,
    ``UNSUPPORTED_ARCHITECTURE``, ``MALFORMED_PE``, ``MAP_CONFLICT``, ``RESOURCE_LIMIT_UNAVAILABLE``,
    ``TIMEOUT`` (the process was killed), ``ANALYSIS_LIMITED`` (``ENGINE_CRASH``, ``MEMORY_LIMIT_EXCEEDED``,
    unwritable evidence) and ``EVIDENCE_FINALIZE_FAILED`` (it ran; the result is withheld).
    """
    try:
        params, bad = _Runner.validate(start_va, stop_at, max_instructions, timeout_s, watch_writes,
                                       registers, stack_size, perm_mode)
        if bad is not None:
            return _j(_Runner.finish(bad))
        params.update(_target_class=target_class, _authorization=authorization, _sample_sha256=sample_sha256)
        return _j(_Runner.finish(_Runner.run(path, params)))
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j(_Runner.finish({"ok": False, "status": "ANALYSIS_LIMITED", "error": "EMULATE_UNEXPECTED_ERROR",
                                  "detail": type(exc).__name__}))


# ---------------------------------------------------------------------------------------------------
# The child: everything below runs in the emulator process
# ---------------------------------------------------------------------------------------------------

class _Refusal(Exception):
    def __init__(self, status, error, detail):
        super().__init__(detail)
        self.status, self.error, self.detail = status, error, detail


class _WriteLog:
    """Which bytes the emulated code wrote, and which of those it later executed.

    Two byte bitmaps per 4 KiB page, created on first write: ``pages`` (written) and ``xpages`` (a written byte
    was inside an instruction dispatched after the write). Tests and updates are O(1) per access, which is what
    keeps a decrypt loop affordable; the merged regions are derived once, at the end."""

    def __init__(self):
        self.pages = {}
        self.xpages = {}
        self.first = []          # time-ordered addresses of instructions that first executed written bytes

    def note(self, address, size):
        pages = self.pages
        end = address + size
        while address < end:
            page = address >> 12
            pg = pages.get(page)
            if pg is None:
                pg = pages[page] = bytearray(4096)
            off = address & 0xFFF
            take = min(end - address, 4096 - off)
            pg[off:off + take] = b"" * take
            address += take

    def executed(self, address, size):
        end = address + size
        pages = self.pages
        while address < end:
            page = address >> 12
            off = address & 0xFFF
            take = min(end - address, 4096 - off)
            pg = pages.get(page)
            if pg is not None:
                hit = pg.find(1, off, off + take)
                if hit >= 0:
                    xpg = self.xpages.get(page)
                    if xpg is None:
                        xpg = self.xpages[page] = bytearray(4096)
                    if not xpg[hit]:
                        for i in range(off, off + take):
                            if pg[i]:
                                xpg[i] = 1
                        self.first.append(address)
            address += take

    @staticmethod
    def _addresses(pages):
        import numpy as np
        parts = [(page << 12) + np.flatnonzero(np.frombuffer(bytes(pg), np.uint8)).astype(np.int64)
                 for page, pg in sorted(pages.items())]
        parts = [p for p in parts if p.size]
        return np.concatenate(parts) if parts else np.zeros(0, np.int64)

    def regions(self):
        """``[(start, end, executed_after_write, first_executed_va)]``: written bytes merged where they touch."""
        import numpy as np
        written = self._addresses(self.pages)
        if not written.size:
            return []
        cuts = np.flatnonzero(np.diff(written) != 1) + 1
        starts = written[np.concatenate(([0], cuts))]
        ends = written[np.concatenate((cuts - 1, [written.size - 1]))] + 1
        flagged = self._addresses(self.xpages)
        out = []
        for lo, hi in zip(starts.tolist(), ends.tolist()):
            at = int(np.searchsorted(flagged, lo))
            hit = at < flagged.size and int(flagged[at]) < hi
            first = next((a for a in self.first if lo <= a < hi or lo <= a + 14 and a < hi), None) if hit else None
            out.append((lo, hi, bool(hit), first))
        return out


class _Engine:
    def __init__(self, job):
        self.job = job

    # -- PE ---------------------------------------------------------------

    @staticmethod
    def parse_pe(data):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise _Refusal("NOT_A_PE", "NOT_A_PE", "no MZ header")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if e + 24 > len(data) or data[e:e + 4] != b"PE\0\0":
            raise _Refusal("NOT_A_PE", "NOT_A_PE", "no PE signature")
        machine, nsec, _stamp, _symptr, _nsym, optsize, _chars = struct.unpack_from("<HHIIIHH", data, e + 4)
        opt = e + 24
        if opt + 2 > len(data):
            raise _Refusal("MALFORMED_PE", "OPTIONAL_HEADER_TRUNCATED", "the optional header is cut off")
        magic = struct.unpack_from("<H", data, opt)[0]
        if machine != 0x8664 or magic != 0x20B:
            raise _Refusal("UNSUPPORTED_ARCHITECTURE", "NOT_X64_PE32_PLUS",
                           "only x86-64 PE32+ images are emulated (machine 0x%04x, optional magic 0x%03x)" % (machine, magic))
        if optsize < 112 or opt + optsize > len(data):
            raise _Refusal("MALFORMED_PE", "OPTIONAL_HEADER_SIZE", "the optional header size is not usable")
        base = struct.unpack_from("<Q", data, opt + 24)[0]
        s_align, _f_align = struct.unpack_from("<II", data, opt + 32)
        size_of_image, size_of_headers = struct.unpack_from("<II", data, opt + 56)
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
        imp = struct.unpack_from("<II", data, opt + 120) if ndirs > 1 and optsize >= 128 else (0, 0)
        if not 1 <= nsec <= 96 or opt + optsize + 40 * nsec > len(data):
            raise _Refusal("MALFORMED_PE", "SECTION_TABLE", "the section table is not usable")
        if s_align < PAGE or s_align % PAGE:
            raise _Refusal("UNSUPPORTED_ARCHITECTURE", "SECTION_ALIGNMENT",
                           "a SectionAlignment below or not a multiple of 0x1000 is not mapped by this tool")
        if base % PAGE or base == 0 or base + size_of_image >= 1 << 63:
            raise _Refusal("MALFORMED_PE", "IMAGE_BASE", "ImageBase is zero, unaligned or out of range")
        if not 0 < size_of_image <= MAX_IMAGE_BYTES or size_of_image % s_align:
            raise _Refusal("MALFORMED_PE", "SIZE_OF_IMAGE", "SizeOfImage is zero, too large or not aligned")
        if not 0 < size_of_headers <= min(len(data), size_of_image):
            raise _Refusal("MALFORMED_PE", "SIZE_OF_HEADERS", "SizeOfHeaders does not fit the file or the image")
        sections = []
        for k in range(nsec):
            at = opt + optsize + 40 * k
            raw_name = data[at:at + 8].rstrip(b"\0")
            vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", data, at + 8)
            chars = struct.unpack_from("<I", data, at + 36)[0]
            span = vsize or rawsize
            if rva % PAGE or rva + span > size_of_image or span == 0:
                raise _Refusal("MALFORMED_PE", "SECTION_RANGE", "section %d lies outside the image" % k)
            if rawsize and (rawptr + rawsize > len(data)):
                raise _Refusal("MALFORMED_PE", "SECTION_RAW_DATA", "section %d raw data lies past the end of the file" % k)
            sections.append({"index": k, "name": _safe_text(raw_name, 8), "rva": rva, "span": span,
                             "rawptr": rawptr, "rawsize": rawsize, "chars": chars})
        return {"base": base, "size_of_image": size_of_image, "size_of_headers": size_of_headers,
                "sections": sections, "import_dir": imp, "alignment": s_align}

    @staticmethod
    def perms(chars, mode):
        from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
        if mode == "rwx":
            return UC_PROT_ALL
        return ((UC_PROT_READ if chars & 0x40000000 else 0) | (UC_PROT_WRITE if chars & 0x80000000 else 0)
                | (UC_PROT_EXEC if chars & 0x20000000 else 0))

    @staticmethod
    def flat_image(data, info):
        """The image laid out by RVA, as the loader would copy it (before any import slot is rewritten)."""
        flat = bytearray(info["size_of_image"])
        flat[:info["size_of_headers"]] = data[:info["size_of_headers"]]
        for sec in info["sections"]:
            take = min(sec["rawsize"], sec["span"])
            flat[sec["rva"]:sec["rva"] + take] = data[sec["rawptr"]:sec["rawptr"] + take]
        return flat

    @staticmethod
    def trap_imports(flat, info):
        """Point every ordinary-import slot at its own unmapped trap address. Returns ``(table, report)``."""
        rva, size = info["import_dir"]
        limit = len(flat)
        report = {"directory": "import", "status": "NONE", "slots_trapped": 0, "dlls": 0,
                  "not_modelled": ["delay-load imports", "bound imports"]}
        table, pending = {}, []
        if rva == 0 or size == 0:
            return table, report
        try:
            at, dlls, slots = rva, 0, 0
            while True:
                if at + 20 > limit:
                    raise ValueError("the import descriptor table runs past the image")
                oft, _stamp, _chain, name_rva, first = struct.unpack_from("<IIIII", flat, at)
                if not (oft or name_rva or first):
                    break
                dlls += 1
                if dlls > 256:
                    raise ValueError("more than 256 import descriptors")
                end = flat.find(b"\0", name_rva, min(limit, name_rva + 256)) if name_rva < limit else -1
                dll = _safe_text(flat[name_rva:end]) if end > name_rva else "?"
                walk = oft or first
                for n in range(20000):
                    if walk + 8 * n + 8 > limit or first + 8 * n + 8 > limit:
                        raise ValueError("an import thunk array runs past the image")
                    thunk = struct.unpack_from("<Q", flat, walk + 8 * n)[0]
                    if thunk == 0:
                        break
                    if thunk >> 63:
                        label = "#%d" % (thunk & 0xFFFF)
                    else:
                        hint_at = thunk & 0x7FFFFFFF
                        stop = flat.find(b"\0", hint_at + 2, min(limit, hint_at + 2 + 256)) if hint_at + 2 < limit else -1
                        label = _safe_text(flat[hint_at + 2:stop]) if stop > hint_at + 2 else "?"
                    slot = TRAP_BASE + TRAP_STRIDE * slots
                    table[slot] = "%s!%s" % (dll, label)
                    pending.append((first + 8 * n, slot))
                    slots += 1
                else:
                    raise ValueError("an import thunk array has no terminator")
                at += 20
            for where, slot in pending:      # applied only once the whole directory has been read
                struct.pack_into("<Q", flat, where, slot)
            report.update(status="TRAPPED", slots_trapped=slots, dlls=dlls)
        except (ValueError, struct.error) as exc:
            table.clear()
            report.update(status="UNREADABLE", reason=str(exc), slots_trapped=0,
                          note="the import directory could not be read, so NO slot was rewritten; a call "
                               "through one will not be recognised as an import")
        return table, report

    # -- the run ----------------------------------------------------------

    def run(self):
        import numpy as np
        from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INSN_INVALID, UC_HOOK_INTR,
                             UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_PROT,
                             UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_PROT,
                             UC_HOOK_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_PROT,
                             UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_PROT, UC_MEM_WRITE_UNMAPPED, UC_MODE_64,
                             UC_PROT_READ, UC_PROT_WRITE, Uc, UcError)
        from unicorn import x86_const as UX

        from liebert_re.recover.vex import UnmodelledVex, VexLayer, _run_with_faulthandler_off

        job = self.job
        run_dir = Path(job["dump_dir"])
        data = (run_dir / job["input_file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != job["input_sha256"]:
            raise _Refusal("ANALYSIS_LIMITED", "INPUT_CHANGED", "the staged input does not match the gated sha256")
        info = self.parse_pe(data)
        base, image_end = info["base"], info["base"] + _align_up(info["size_of_image"], PAGE)
        flat = self.flat_image(data, info)
        trap_table, import_report = self.trap_imports(flat, info)

        stack_low = STACK_HIGH - job["stack_size"]
        aux = [("stack", stack_low, STACK_HIGH), ("teb", TEB_VA, TEB_VA + TEB_SIZE), ("peb", PEB_VA, PEB_VA + PEB_SIZE),
               ("sentinel", SENTINEL_VA, SENTINEL_VA + PAGE),
               ("import traps", TRAP_BASE, TRAP_BASE + _align_up(TRAP_STRIDE * (len(trap_table) + 1), PAGE))]
        for label, lo, hi in aux:
            if lo < image_end and base < hi:
                raise _Refusal("MAP_CONFLICT", "IMAGE_OVERLAPS_FIXED_REGION",
                               "the image's preferred range collides with the %s region; the image is not relocated" % label)
        spans = [("headers", 0, _align_up(info["size_of_headers"], PAGE), 0)]
        for sec in info["sections"]:
            spans.append((sec["name"], sec["rva"], sec["rva"] + _align_up(sec["span"], PAGE), sec["index"]))
        ordered = sorted(spans, key=lambda s: s[1])
        for prev, cur in zip(ordered, ordered[1:]):
            if cur[1] < prev[2]:
                raise _Refusal("MAP_CONFLICT", "SECTIONS_SHARE_A_PAGE", "two sections (or the headers) share a page")

        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        def map_region(address, size, perms):
            _run_with_faulthandler_off(uc.mem_map, address, size, perms)

        map_region(base, _align_up(info["size_of_headers"], PAGE), UC_PROT_READ)
        uc.mem_write(base, bytes(flat[:info["size_of_headers"]]))
        section_report = []
        for sec in info["sections"]:
            declared = self.perms(sec["chars"], "as_declared")
            applied = self.perms(sec["chars"], job["perm_mode"])
            size = _align_up(sec["span"], PAGE)
            map_region(base + sec["rva"], size, applied)
            uc.mem_write(base + sec["rva"], bytes(flat[sec["rva"]:sec["rva"] + size]))
            section_report.append({"index": sec["index"], "name": sec["name"], "rva": _hx(sec["rva"]), "size": sec["span"],
                                   "declared": self.perm_text(declared), "applied": self.perm_text(applied)})
        map_region(stack_low, job["stack_size"], UC_PROT_READ | UC_PROT_WRITE)
        map_region(TEB_VA, TEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        map_region(PEB_VA, PEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        # Minimal TEB/PEB. Only the fields listed in teb_peb_model are assigned; every other byte is zero.
        teb = bytearray(TEB_SIZE)
        struct.pack_into("<QQ", teb, 0x08, STACK_HIGH, stack_low)
        struct.pack_into("<Q", teb, 0x30, TEB_VA)
        struct.pack_into("<Q", teb, 0x60, PEB_VA)
        peb = bytearray(PEB_SIZE)
        peb[0x02] = 0
        struct.pack_into("<Q", peb, 0x10, base)
        struct.pack_into("<Q", peb, 0x18, 0)
        uc.mem_write(TEB_VA, bytes(teb))
        uc.mem_write(PEB_VA, bytes(peb))
        uc.reg_write(UX.UC_X86_REG_GS_BASE, TEB_VA)

        regs = {"rsp": STACK_HIGH - 0x100 + 8, "eflags": 0x202}
        regs.update(job["registers"])
        try:
            uc.mem_write(regs["rsp"], struct.pack("<Q", SENTINEL_VA))
        except UcError:
            raise _Refusal("TOOL_USAGE", "BAD_REGISTERS", "rsp does not point into writable mapped memory") from None
        for name, value in regs.items():
            uc.reg_write(getattr(UX, "UC_X86_REG_" + name.upper()), value)
        baseline = {s["index"]: bytes(flat[s["rva"]:s["rva"] + s["span"]]) for s in info["sections"]}

        layer = VexLayer(uc, 64)
        wlog = _WriteLog()
        stops = frozenset(job["stop_at"])
        max_n = job["max_instructions"]
        budget = job["timeout_s"]
        t0 = time.monotonic()
        deadline = t0 + budget
        ring = [0] * 64
        outcome = {"reason": None, "detail": {}}
        fault = []
        executed = 0
        ring_i = 0
        last_addr = 0
        stopped = False

        def stop(reason, **detail):
            nonlocal stopped
            stopped = True
            if outcome["reason"] is None:
                outcome["reason"], outcome["detail"] = reason, detail
            uc.emu_stop()

        # Addresses already decoded as "not a VEX instruction" and not written since. The layer's own cache drops a
        # whole page on any write, which makes a decrypt loop that shares a page with its data re-decode every
        # instruction; this one is dropped exactly, over the 15 bytes an instruction at a written byte could span.
        checked, cpages = set(), set()
        wpages = wlog.pages
        wexec = wlog.executed
        clock = time.monotonic

        def on_code(_uc, address, size, _data):
            nonlocal executed, ring_i, last_addr
            if stopped:             # a stop requested from an instruction hook takes effect one instruction late
                return
            if address in stops:
                stop("STOP_ADDRESS", address=_hx(address))
                return
            if executed >= max_n:
                stop("INSN_LIMIT", limit=max_n)
                return
            if not (executed & 1023) and clock() >= deadline:
                stop("TIMEOUT", bound_s=budget, enforced_by="instruction hook")
                return
            executed += 1
            ring[ring_i & 63] = address
            ring_i += 1
            last_addr = address
            if wpages:
                pg = wpages.get(address >> 12)
                off = address & 0xFFF
                if pg is not None:
                    if off + size > 4096 or pg.find(1, off, off + size) >= 0:
                        wexec(address, size)
                elif off + size > 4096 and ((address + size - 1) >> 12) in wpages:
                    wexec(address, size)
            if base <= address < image_end:
                if address in checked:
                    return
            else:
                layer.invalidate(address, 16)   # writes outside the image may not be hooked; never trust a cached decode there
            try:
                if not layer.step(address, size) and base <= address < image_end:
                    checked.add(address)
                    cpages.add(address >> 12)
            except UnmodelledVex as exc:
                stop("UNMODELLED_VEX", mnemonic=_safe_text(exc.mnemonic), instruction_va=_hx(exc.address))
            except UcError as exc:
                stop("ENGINE_ERROR", error=str(exc), where="inside the VEX layer", errno=exc.errno)

        ones = [b"" * n for n in range(65)]

        def on_write(_uc, _access, address, size, _value, _data):
            off = address & 0xFFF
            if off + size <= 4096 and size <= 64:
                page = address >> 12
                pg = wpages.get(page)
                if pg is None:
                    pg = wpages[page] = bytearray(4096)
                pg[off:off + size] = ones[size]
            else:
                wlog.note(address, size)
            if cpages and ((address >> 12) in cpages or ((address - 14) >> 12) in cpages):
                for stale in range(address - 14, address + size):
                    checked.discard(stale)
            if layer._pages:
                layer.invalidate(address, size)

        kinds = {UC_MEM_READ_UNMAPPED: "UNMAPPED_READ", UC_MEM_WRITE_UNMAPPED: "UNMAPPED_WRITE",
                 UC_MEM_FETCH_UNMAPPED: "UNMAPPED_FETCH", UC_MEM_READ_PROT: "READ_PROTECT",
                 UC_MEM_WRITE_PROT: "WRITE_PROTECT", UC_MEM_FETCH_PROT: "FETCH_PROTECT"}

        def on_fault(_uc, access, address, size, _value, _data):
            fault.append((kinds.get(access, "ENGINE_ERROR"), address, size))
            return False

        def on_intr(_uc, number, _data):
            if number == 3:
                stop("INT3", instruction_va=_hx(last_addr))
            else:
                stop("INTERRUPT", number=number, instruction_va=_hx(last_addr))

        def on_syscall(_uc, _data):
            stop("SYSCALL", instruction="syscall", number=_hx(uc.reg_read(UX.UC_X86_REG_RAX)), instruction_va=_hx(last_addr))

        def on_sysenter(_uc, _data):
            stop("SYSCALL", instruction="sysenter", number=_hx(uc.reg_read(UX.UC_X86_REG_RAX)), instruction_va=_hx(last_addr))

        def on_in(_uc, port, size, _data):
            stop("PORT_IO", direction="in", port=_hx(port), width=size, instruction_va=_hx(last_addr))
            return 0

        def on_out(_uc, port, size, _value, _data):
            stop("PORT_IO", direction="out", port=_hx(port), width=size, instruction_va=_hx(last_addr))

        def on_invalid(_uc, _data):
            rip = uc.reg_read(UX.UC_X86_REG_RIP)
            try:
                two = bytes(uc.mem_read(rip, 2))
            except UcError:
                two = b""
            fault.append(("UD2" if two == b"\x0f\x0b" else "INVALID_INSTRUCTION", rip, 0))
            return False

        uc.hook_add(UC_HOOK_CODE, on_code)
        if job["watch_writes"] == "image":
            uc.hook_add(UC_HOOK_MEM_WRITE, on_write, None, base, image_end - 1)
        else:
            uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED
                    | UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT, on_fault)
        uc.hook_add(UC_HOOK_INTR, on_intr)
        uc.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UX.UC_X86_INS_SYSCALL)
        uc.hook_add(UC_HOOK_INSN, on_sysenter, None, 1, 0, UX.UC_X86_INS_SYSENTER)
        uc.hook_add(UC_HOOK_INSN, on_in, None, 1, 0, UX.UC_X86_INS_IN)
        uc.hook_add(UC_HOOK_INSN, on_out, None, 1, 0, UX.UC_X86_INS_OUT)
        uc.hook_add(UC_HOOK_INSN_INVALID, on_invalid)

        engine_error = None
        t_run = time.monotonic()
        try:
            uc.emu_start(job["start_va"], 0xFFFFFFFFFFFFFFFF, timeout=int((budget + 2) * 1_000_000))
        except UcError as exc:
            engine_error = exc
        elapsed = time.monotonic() - t_run
        rip = uc.reg_read(UX.UC_X86_REG_RIP)

        reason, detail = outcome["reason"], dict(outcome["detail"])
        if reason is None and fault:
            kind, address, size = fault[-1]
            if kind == "UNMAPPED_FETCH" and address == SENTINEL_VA:
                try:
                    last_code = bytes(uc.mem_read(last_addr, 16)) if executed else b""
                except UcError:
                    try:
                        last_code = bytes(uc.mem_read(last_addr, 1)) if executed else b""
                    except UcError:
                        last_code = b""
                detail = {"sentinel": _hx(SENTINEL_VA), "rax": _hx(uc.reg_read(UX.UC_X86_REG_RAX))}
                why = _ret_check(last_code, uc.reg_read(UX.UC_X86_REG_RSP), regs["rsp"])
                if why is None:
                    reason = "RETURNED"
                else:
                    reason = "SENTINEL_REACHED"
                    detail["not_verified_because"] = why
                    detail["last_instruction_va"] = _hx(last_addr) if executed else None
            elif kind == "UNMAPPED_FETCH" and address in trap_table:
                rsp = uc.reg_read(UX.UC_X86_REG_RSP)
                try:
                    top = _hx(struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0])
                except UcError:
                    top = None
                reason, detail = "IMPORT_CALL", {"import": trap_table[address], "trap_va": _hx(address),
                                                 "qword_at_rsp": top}
            else:
                reason = kind
                if kind in ("UD2", "INVALID_INSTRUCTION"):
                    detail = {"instruction_va": _hx(address)}
                else:
                    detail = {"address": _hx(address), "access_size": size or None}
                # An instruction that faulted on a data access or an invalid encoding did not complete.
                # (A fetch fault is raised by the NEXT instruction's fetch, so the one before it did.)
                if kind not in ("UNMAPPED_FETCH", "FETCH_PROTECT") and rip == last_addr and executed:
                    executed -= 1
        if reason is None and engine_error is not None:
            reason, detail = "ENGINE_ERROR", {"error": str(engine_error), "errno": engine_error.errno}
        if reason is None:
            try:
                tail = bytes(uc.mem_read(last_addr, 1)) if executed else b""
            except UcError:
                tail = b""
            if tail[:1] == b"\xf4":
                reason, detail = "HLT", {"instruction_va": _hx(last_addr)}
            elif time.monotonic() >= deadline:
                reason, detail = "TIMEOUT", {"bound_s": budget, "enforced_by": "engine timeout"}
            else:
                reason, detail = "UNKNOWN_STOP", {"note": "the engine returned and no hook recorded a cause"}

        # -- results --------------------------------------------------------
        written = []
        regions = wlog.regions()
        total = len(regions)
        for start, end, hit, first in regions[:MAX_REGIONS_REPORTED]:
            written.append({"va": _hx(start), "size": end - start,
                            "sha256": hashlib.sha256(bytes(uc.mem_read(start, end - start))).hexdigest(),
                            "executed_after_write": hit, "first_executed_va": _hx(first)})
        diffs, files = [], []
        run_dir.mkdir(parents=True, exist_ok=True)
        for sec in info["sections"]:
            final = bytes(uc.mem_read(base + sec["rva"], sec["span"]))
            was = baseline[sec["index"]]
            changed = int(np.count_nonzero(np.frombuffer(final, np.uint8) != np.frombuffer(was, np.uint8)))
            row = {"index": sec["index"], "name": sec["name"], "rva": _hx(sec["rva"]), "size": sec["span"],
                   "changed_bytes": changed, "final_sha256": hashlib.sha256(final).hexdigest(),
                   "baseline_sha256": hashlib.sha256(was).hexdigest(), "dump_file": None, "dump_sha256": None}
            if changed:
                name = "section%02d_%s.bin" % (sec["index"], re.sub(r"[^A-Za-z0-9_]", "_", sec["name"]) or "x")
                (run_dir / name).write_bytes(final)
                row.update(dump_file=name, dump_sha256=row["final_sha256"])
                files.append(name)
            diffs.append(row)
        registers = {name: _hx(uc.reg_read(getattr(UX, "UC_X86_REG_" + name.upper()))) for name in _GPRS}
        registers["eflags"] = _hx(uc.reg_read(UX.UC_X86_REG_EFLAGS))
        n_ring = min(ring_i, 64)
        recent = [ring[(ring_i - n_ring + k) & 63] for k in range(n_ring)]
        return {
            "ok": True, "status": "OK", "stop_reason": reason, "stop_detail": detail,
            "completion": _completion(reason), "completion_basis": _COMPLETION_BASIS,
            "limitations": [dict(_IMPORT_UNREADABLE)] if import_report["status"] == "UNREADABLE" else [],
            "instructions": executed, "instruction_count_basis": _COUNT_BASIS,
            "rip": _hx(rip), "registers": registers, "registers_basis": _REG_BASIS,
            "recent_rips": [_hx(a) for a in recent], "recent_rips_basis": _RIP_BASIS,
            "written_regions": written, "written_regions_total": total,
            "written_regions_truncated": total > MAX_REGIONS_REPORTED,
            "written_regions_basis": ("writes by the emulated code to %s, merged where they touch; "
                                      "executed_after_write: an instruction was dispatched from inside the "
                                      "region after it was written" % ("the mapped image" if job["watch_writes"] == "image" else "all memory")),
            "section_diffs": diffs, "dump_files": files,
            "image": {"machine": "x86-64", "image_base": _hx(base), "size_of_image": info["size_of_image"],
                      "sections": section_report, "relocation": "none; mapped at the preferred base",
                      "imports": import_report, "headers": "read-only"},
            "perm_mode": job["perm_mode"],
            "perm_mode_note": ("every section mapped read-write-execute: an APPROXIMATION of the loader that "
                               "hides write-protection and no-execute faults" if job["perm_mode"] == "rwx"
                               else "section permissions exactly as the section headers declare them"),
            "watch_writes": job["watch_writes"],
            "teb_peb_model": {
                "teb_va": _hx(TEB_VA), "peb_va": _hx(PEB_VA), "gs_base": _hx(TEB_VA),
                "assigned": {"TEB.NtTib.StackBase": _hx(STACK_HIGH), "TEB.NtTib.StackLimit": _hx(stack_low),
                             "TEB.NtTib.Self": _hx(TEB_VA), "TEB.ProcessEnvironmentBlock": _hx(PEB_VA),
                             "PEB.BeingDebugged": 0, "PEB.ImageBaseAddress": _hx(base), "PEB.Ldr": "NULL"},
                "everything_else": "zero-filled; a zero there is not a Windows value, it is the absence of a model"},
            "stack": {"low": _hx(stack_low), "high": _hx(STACK_HIGH), "initial_rsp": _hx(regs["rsp"]),
                      "return_sentinel": _hx(SENTINEL_VA)},
            "vex": {"instructions_executed_by_layer": layer.executed, "mnemonics": dict(layer.mnemonics)},
            "elapsed_s": round(elapsed, 3),
            "instructions_per_second": int(executed / elapsed) if elapsed > 0 else None,
        }

    @staticmethod
    def perm_text(perms):
        from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
        return ("r" if perms & UC_PROT_READ else "-") + ("w" if perms & UC_PROT_WRITE else "-") + \
               ("x" if perms & UC_PROT_EXEC else "-")


def _child_main(job_path):
    """Entry point of the emulator process: read the job, run it, print one JSON line."""
    try:
        job = json.loads(Path(job_path).read_text(encoding="utf-8"))
        result = _Engine(job).run()
    except _Refusal as exc:
        result = {"ok": False, "status": exc.status, "error": exc.error, "detail": exc.detail, "stop_reason": None}
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed
        result = {"ok": False, "status": "ANALYSIS_LIMITED", "error": "EMULATOR_PROCESS_ERROR",
                  "detail": type(exc).__name__}
    sys.stdout.write(json.dumps(result, ensure_ascii=True, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # python -I -m liebert_re.recover.emulate --job <file>  (the gate lives in emulate_range)
    if len(sys.argv) == 3 and sys.argv[1] == "--job":
        raise SystemExit(_child_main(sys.argv[2]))
    raise SystemExit("usage: python -m liebert_re.recover.emulate --job <job.json>; use emulate_range for the gated entry")
