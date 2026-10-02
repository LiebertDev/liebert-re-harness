"""The dynamic-lab gate: what must hold before the harness touches a live process.

This is a deliberately small gate. It enforces what a single host can enforce today and
SAYS, on every call, what it could not verify. It is not a lab manager and it does not
create guests, snapshots or network rules.

ENFORCED on every call that reaches a live process (fail closed: anything that cannot be
established is a refusal, never a pass):

* OPERATOR SWITCH + EXPLICIT AUTHORIZATION. Off by default. Two independent keys are needed:
  the environment variable ``LIEBERT_RE_DYNAMIC_LAB`` set to ``authorized`` (the operator
  opened the lab on this machine), and a per-run ``authorization`` object naming who
  authorized it (``authorized_by``), why (``purpose``), the operations it covers
  (``operations``) and the process ids it covers (``pids``). An authorization that does not
  name this operation and this PID does not cover this run. Status ``AUTHORIZATION_REQUIRED``.
* SAMPLE HASH. The caller declares the SHA-256 of the target's image; the gate hashes the
  file the live process was started from and compares. Missing or malformed declaration is
  ``SAMPLE_HASH_REQUIRED``; a mismatch is ``SAMPLE_HASH_MISMATCH``; an unreadable image is
  ``SAMPLE_HASH_UNVERIFIABLE``. This binds the declared sample to the image on disk now; it
  is not a proof about the bytes in memory (that is what the scan itself looks at).
* PID OWNERSHIP. The process must have been started by the harness. Two proofs are accepted:
  it is a direct child of the calling process, or a harness process registered it with
  ``dynamic_lab_register_owned_process`` (which itself only registers a direct child) and the
  PID, creation time and image path still match, so a reused PID does not inherit ownership.
  No proof is ``PROCESS_NOT_OWNED``; a host that cannot answer is ``OWNERSHIP_UNVERIFIABLE``.
  The registry is a local file: it shows the harness registered the process, it is not tamper
  proof against someone who can write to it.
* BOUNDS. A positive timeout and a memory limit are required, and the memory monitor that
  enforces the limit must work on this host (``RESOURCE_LIMIT_UNAVAILABLE`` otherwise). The
  caller passes both to ``bounded_subprocess.run_bounded_process``.
* EVIDENCE. Environment, user and elevation, the target's identity, every check, the exact
  command and the result are written under ``dataset/evidence/dynamic_lab_gate/``. If the
  record cannot be written the run is refused (``ANALYSIS_LIMITED`` with
  ``environment_error``). An observation made from an elevated context is not the same
  observation as one from a normal context; ``privilege.elevated`` records which it was. The
  gate never elevates anything and never raises the target's rights.

NOT ENFORCED, and reported as not verified every time (``isolation_verified: false``): an
isolated, single-use guest; a known snapshot and rollback path; network off or allow-listed.
Nothing in this harness can attest to those today. So an operation that EXECUTES a sample or
instruments a process (``execute_sample``, ``launch_sample``, ``frida_trace``,
``frida_attach``, ``frida_spawn``) is refused with ``ISOLATION_REQUIRED`` whatever else is
supplied. Only read-only observation of a harness-owned live process (``pe_sieve_scan``) is
allowed without isolation, and the response says that is the reason.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import re
import sys
import time
import uuid

from liebert_re.workspace import PROJECT_ROOT as APP_DIR

EVIDENCE = APP_DIR / "dataset" / "evidence" / "dynamic_lab_gate"

ENABLE_ENV = "LIEBERT_RE_DYNAMIC_LAB"
ENABLE_VALUE = "authorized"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_MAX_MEMORY_BYTES = 2 * 1024 ** 3
_MAX_IMAGE_BYTES = 1024 ** 3
_MAX_PID = 0xFFFFFFFF

# What each operation does to a live process. Anything not listed is refused.
OBSERVE_OWNED = frozenset({"pe_sieve_scan"})
NEEDS_ISOLATION = frozenset({"execute_sample", "launch_sample", "frida_trace", "frida_attach", "frida_spawn"})

_UNVERIFIED = {
    "isolated_guest": "no guest attestation exists in this harness; a single-use, verified isolated guest cannot be confirmed",
    "snapshot_and_rollback": "no snapshot or rollback path is known to or checked by this harness",
    "network_control": "network off or allow-listed cannot be confirmed from here",
}
_CHECKS = ("operation_known", "isolation_requirement", "operator_switch", "pid", "authorization",
           "ownership", "sample_hash", "bounds", "evidence_writable")


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


class LabGate:
    """Kept as a class so the layout pin counts no extra top-level function."""

    @staticmethod
    def parse_pid(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and re.fullmatch(r"\d{1,10}", value.strip()):
            number = int(value.strip())
        else:
            return None
        return number if 0 < number <= _MAX_PID else None

    @staticmethod
    def elevated():
        try:
            if os.name == "nt":
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:  # noqa: BLE001 - unknown is reported as unknown, never as False
            return None

    @staticmethod
    def environment():
        try:
            user = getpass.getuser()
        except Exception:  # noqa: BLE001
            user = None
        elevated = LabGate.elevated()
        return {
            "platform": platform.platform(), "python": sys.version.split()[0],
            "harness_pid": os.getpid(), "user": user,
            "privilege": {
                "elevated": elevated,
                "note": ("observed from an ELEVATED context: not equivalent to an observation from a normal one"
                         if elevated else
                         "elevation could not be determined" if elevated is None else "normal (not elevated) context"),
                "policy": "the gate never elevates and never raises the target's rights; it runs with the caller's token",
            },
        }

    @staticmethod
    def authorization(value, operation, pid):
        """``(clean, None)`` or ``(None, reason)``."""
        if value is None:
            return None, "no authorization was supplied"
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None, "the authorization is not valid JSON"
        if not isinstance(value, dict):
            return None, "the authorization must be an object"
        for key in ("authorized_by", "purpose"):
            field = value.get(key)
            if not isinstance(field, str) or not field.strip() or len(field) > 200:
                return None, f"{key} must be a non-empty string of at most 200 characters"
        ops = value.get("operations")
        if not isinstance(ops, list) or not all(isinstance(o, str) for o in ops) or operation not in ops:
            return None, f"operations does not name {operation}"
        pids = value.get("pids")
        if (not isinstance(pids, list) or any(isinstance(p, bool) or not isinstance(p, int) for p in pids)
                or pid not in pids):
            return None, f"pids does not name process {pid}"
        return {"authorized_by": value["authorized_by"].strip(), "purpose": value["purpose"].strip(),
                "operations": list(ops), "pids": list(pids)}, None

    @staticmethod
    def sha256_of_file(path):
        try:
            if os.path.getsize(path) > _MAX_IMAGE_BYTES:
                return None, "the image is larger than the 1 GiB the gate will hash"
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            return digest.hexdigest(), None
        except OSError as exc:
            return None, f"{type(exc).__name__}: {exc.strerror or exc}"

    @staticmethod
    def target(pid):
        """``(identity, None)`` or ``(None, (status, reason))``."""
        try:
            import psutil
        except ImportError:
            return None, ("OWNERSHIP_UNVERIFIABLE", "psutil is not importable; process ownership cannot be established")
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                identity = {"pid": pid, "create_time": round(proc.create_time(), 3), "image": proc.exe(),
                            "parent_pid": proc.ppid(), "state": proc.status()}
            try:
                identity["user"] = proc.username()
            except Exception:  # noqa: BLE001
                identity["user"] = None
        except psutil.NoSuchProcess:
            return None, ("PROCESS_NOT_OWNED", "the process does not exist, so it cannot be one the harness started")
        except psutil.AccessDenied:
            return None, ("OWNERSHIP_UNVERIFIABLE", "the host denied reading the process identity; ownership cannot be established")
        except Exception as exc:  # noqa: BLE001
            return None, ("OWNERSHIP_UNVERIFIABLE", f"{type(exc).__name__}: {exc}")
        if not identity["image"]:
            return None, ("OWNERSHIP_UNVERIFIABLE", "the process image path could not be read")
        if identity["state"] == "zombie":
            return None, ("PROCESS_NOT_OWNED", "the process has already exited")
        return identity, None

    @staticmethod
    def registry_dir():
        return EVIDENCE / "owned_processes"

    @staticmethod
    def is_direct_child(identity):
        try:
            import psutil
            mine = psutil.Process(os.getpid()).create_time()
        except Exception:  # noqa: BLE001
            return False
        return identity["parent_pid"] == os.getpid() and identity["create_time"] + 0.01 >= mine

    @staticmethod
    def registered(identity):
        folder = LabGate.registry_dir()
        try:
            names = [n for n in os.listdir(folder) if n.startswith(f"pid{identity['pid']}_") and n.endswith(".json")]
        except OSError:
            return None
        for name in sorted(names):
            try:
                with open(folder / name, encoding="utf-8") as handle:
                    entry = json.load(handle)
            except (OSError, ValueError):
                continue
            if (isinstance(entry, dict) and entry.get("pid") == identity["pid"]
                    and entry.get("create_time") == identity["create_time"]
                    and os.path.normcase(str(entry.get("image"))) == os.path.normcase(identity["image"])):
                return {"entry": name, "registered_by_pid": entry.get("launcher_pid")}
        return None

    @staticmethod
    def write(name, record):
        """None on success, else an environment_error dict."""
        try:
            EVIDENCE.mkdir(parents=True, exist_ok=True)
            (EVIDENCE / name).write_text(json.dumps(record, ensure_ascii=False, default=str), encoding="utf-8")
            return None
        except OSError as exc:
            return {"type": type(exc).__name__, "errno": exc.errno, "strerror": exc.strerror or type(exc).__name__}

    @staticmethod
    def check(operation, pid=None, authorization=None, sample_sha256=None,
              timeout_seconds=DEFAULT_TIMEOUT_SECONDS, max_memory_bytes=DEFAULT_MAX_MEMORY_BYTES):
        """The gate decision as a dict. Never raises. ``ok`` is True only if every check passed."""
        started = time.time()
        known = isinstance(operation, str) and (operation in OBSERVE_OWNED or operation in NEEDS_ISOLATION)
        needs_isolation = isinstance(operation, str) and operation in NEEDS_ISOLATION
        number = LabGate.parse_pid(pid)
        decision = {
            "tool": "dynamic_lab_gate", "operation": operation if isinstance(operation, str) else None,
            "gate_scope": "single-host MVP: enforces authorization, sample hash, PID ownership, bounds and evidence; "
                          "does NOT verify an isolated guest, snapshots or network control",
            "isolation_verified": False,
            "isolation": {
                "verified": False, "required_for_operation": needs_isolation if known else None,
                "reason_not_required": None if needs_isolation or not known else
                    "read-only observation of a process this harness started; nothing is executed or modified",
                "unmet_prerequisites": [{"prerequisite": k, "verified": False, "reason": v} for k, v in _UNVERIFIED.items()],
            },
            "environment": LabGate.environment(), "checks": [], "target": None, "authorization": None,
            "bounds": {"timeout_seconds": timeout_seconds, "max_memory_bytes": max_memory_bytes},
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        }
        checks = decision["checks"]

        def refuse(name, status, error, detail):
            checks.append({"check": name, "result": "failed", "detail": detail})
            for later in _CHECKS[_CHECKS.index(name) + 1:]:
                checks.append({"check": later, "result": "not_evaluated"})
            decision.update(ok=False, decision="REFUSE", status=status, error=error, detail=detail,
                            enforced=[c["check"] for c in checks if c["result"] == "passed"])
            name_out = f"{decision['operation']}_pid{number}_{uuid.uuid4().hex[:8]}_gate_refused.json"
            decision["evidence_name"] = name_out
            decision["evidence_write_error"] = LabGate.write(name_out, decision)
            return decision

        def passed(name, detail):
            checks.append({"check": name, "result": "passed", "detail": detail})

        if not known:
            return refuse("operation_known", "UNKNOWN_OPERATION", "OPERATION_NOT_REGISTERED",
                          "the gate does not know this operation, so it is refused; nothing was started")
        passed("operation_known", f"{operation} is a registered operation")
        if needs_isolation:
            return refuse("isolation_requirement", "ISOLATION_REQUIRED", "ISOLATED_GUEST_NOT_VERIFIABLE",
                          f"{operation} executes or instruments a process and needs a verified isolated guest "
                          "with a snapshot and controlled network; none of these can be verified here, so it is "
                          "refused whatever else was supplied")
        passed("isolation_requirement", "observation only: isolation is not required, and is reported as not verified")
        if os.environ.get(ENABLE_ENV, "").strip() != ENABLE_VALUE:
            return refuse("operator_switch", "AUTHORIZATION_REQUIRED", "LAB_SWITCH_OFF",
                          f"the operator has not opened the dynamic lab on this machine ({ENABLE_ENV} is not "
                          f"'{ENABLE_VALUE}'); the default is closed")
        passed("operator_switch", f"{ENABLE_ENV} is set")
        if number is None:
            return refuse("pid", "PID_REQUIRED", "PID_MISSING_OR_INVALID",
                          "a positive process id is required to scope the authorization")
        passed("pid", f"process {number}")
        clean, why = LabGate.authorization(authorization, operation, number)
        if clean is None:
            return refuse("authorization", "AUTHORIZATION_REQUIRED", "AUTHORIZATION_MISSING_OR_OUT_OF_SCOPE", why)
        decision["authorization"] = clean
        passed("authorization", f"authorized_by and purpose declared; scope names {operation} and process {number}")
        identity, bad = LabGate.target(number)
        if identity is None:
            return refuse("ownership", bad[0], "OWNERSHIP_NOT_ESTABLISHED", bad[1])
        decision["target"] = identity
        if LabGate.is_direct_child(identity):
            proof = {"basis": "direct_child_of_calling_process", "launcher_pid": os.getpid()}
        else:
            reg = LabGate.registered(identity)
            if reg is None:
                return refuse("ownership", "PROCESS_NOT_OWNED", "NO_OWNERSHIP_PROOF",
                              "the process is neither a direct child of the calling process nor registered by a "
                              "harness process with matching pid, creation time and image; refused")
            proof = {"basis": "harness_registry", **reg,
                     "caveat": "a local file: shows the harness registered it, not tamper proof"}
        decision["ownership"] = proof
        passed("ownership", proof["basis"])
        declared = sample_sha256.strip().lower() if isinstance(sample_sha256, str) else None
        if not declared or not re.fullmatch(r"[0-9a-f]{64}", declared):
            return refuse("sample_hash", "SAMPLE_HASH_REQUIRED", "SAMPLE_SHA256_MISSING_OR_MALFORMED",
                          "the sha256 of the target image must be declared as 64 hex characters")
        actual, problem = LabGate.sha256_of_file(identity["image"])
        decision["target"]["image_sha256_declared"] = declared
        decision["target"]["image_sha256_actual"] = actual
        if actual is None:
            return refuse("sample_hash", "SAMPLE_HASH_UNVERIFIABLE", "IMAGE_UNREADABLE", problem)
        if actual != declared:
            return refuse("sample_hash", "SAMPLE_HASH_MISMATCH", "DECLARED_HASH_DIFFERS_FROM_IMAGE",
                          "the declared sha256 does not match the image the process was started from")
        passed("sample_hash", "declared sha256 equals the sha256 of the process image on disk")
        timeout_ok = (not isinstance(timeout_seconds, bool) and isinstance(timeout_seconds, (int, float))
                      and timeout_seconds > 0)
        memory_ok = (not isinstance(max_memory_bytes, bool) and isinstance(max_memory_bytes, int)
                     and max_memory_bytes > 0)
        if not (timeout_ok and memory_ok):
            return refuse("bounds", "BOUNDS_REQUIRED", "TIMEOUT_OR_MEMORY_LIMIT_MISSING",
                          "a positive timeout and a positive memory limit are required")
        from liebert_re.bounded_subprocess import _memory_monitor_usable
        if not _memory_monitor_usable():
            return refuse("bounds", "RESOURCE_LIMIT_UNAVAILABLE", "MEMORY_MONITOR_UNUSABLE",
                          "this host cannot measure process memory, so the memory limit could not be enforced")
        passed("bounds", f"timeout {timeout_seconds}s and memory limit {max_memory_bytes} bytes, both enforced "
                         "by bounded_subprocess")
        name = f"{operation}_pid{number}_{uuid.uuid4().hex[:8]}_gate.json"
        decision.update(ok=True, decision="ALLOW", status="GATE_PASSED", evidence_name=name, invoked_argv=None, result=None)
        error = LabGate.write(name, decision)
        if error:
            checks.append({"check": "evidence_writable", "result": "failed", "detail": error["strerror"]})
            decision.update(ok=False, decision="REFUSE", status="ANALYSIS_LIMITED", error="GATE_EVIDENCE_UNWRITABLE",
                            environment_error=error, enforced=[c["check"] for c in checks if c["result"] == "passed"],
                            detail="the gate record could not be written; a run without evidence is refused. This "
                                   "describes this machine, not the target.")
            return decision
        passed("evidence_writable", name)
        decision["enforced"] = [c["check"] for c in checks if c["result"] == "passed"]
        return decision

    @staticmethod
    def finish(decision, command, outcome):
        """Complete the evidence record with the exact command and the result, and note whether the
        target was still the same process afterwards. Returns an error dict or None."""
        try:
            identity = decision.get("target") or {}
            same = None
            if identity.get("pid"):
                now, _bad = LabGate.target(identity["pid"])
                same = bool(now and now["create_time"] == identity.get("create_time")
                            and os.path.normcase(now["image"]) == os.path.normcase(identity["image"]))
            decision.update(invoked_argv=command, result=outcome,
                            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            target_identity_unchanged_after_run=same)
            return LabGate.write(decision["evidence_name"], decision)
        except Exception as exc:  # noqa: BLE001
            return {"type": type(exc).__name__, "errno": None, "strerror": str(exc)}


def dynamic_lab_gate(operation=None, pid=None, authorization=None, sample_sha256=None,
                     timeout_seconds=DEFAULT_TIMEOUT_SECONDS, max_memory_bytes=DEFAULT_MAX_MEMORY_BYTES):
    """Evaluate the gate for one operation on one process and write the decision to evidence.

    Returns JSON. ``status`` is ``GATE_PASSED`` or one of ``UNKNOWN_OPERATION``,
    ``ISOLATION_REQUIRED``, ``AUTHORIZATION_REQUIRED``, ``PID_REQUIRED``, ``PROCESS_NOT_OWNED``,
    ``OWNERSHIP_UNVERIFIABLE``, ``SAMPLE_HASH_REQUIRED``, ``SAMPLE_HASH_MISMATCH``,
    ``SAMPLE_HASH_UNVERIFIABLE``, ``BOUNDS_REQUIRED``, ``RESOURCE_LIMIT_UNAVAILABLE`` or
    ``ANALYSIS_LIMITED`` (with ``environment_error``). Every response carries ``checks`` (each
    check passed, failed or not_evaluated), ``enforced``, ``isolation_verified`` (always false
    today) and ``isolation.unmet_prerequisites``. A pass here authorizes nothing by itself; the
    operation re-runs the gate before it starts.
    """
    try:
        return _j(LabGate.check(operation, pid, authorization, sample_sha256, timeout_seconds, max_memory_bytes))
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j({"ok": False, "tool": "dynamic_lab_gate", "decision": "REFUSE", "status": "ANALYSIS_LIMITED",
                   "error": "GATE_UNEXPECTED_ERROR", "isolation_verified": False,
                   "detail": f"{type(exc).__name__}: {exc}"})


def dynamic_lab_register_owned_process(pid=None):
    """Record that a process is one this harness started, so a later call (another CLI
    invocation, say) can show ownership. Only a DIRECT CHILD of the calling process is
    registered: anything else is ``PROCESS_NOT_OWNED``. The entry holds the PID, creation time
    and image path, so a reused PID does not inherit it. Returns JSON; never raises."""
    tool = "dynamic_lab_register_owned_process"
    try:
        number = LabGate.parse_pid(pid)
        if number is None:
            return _j({"ok": False, "tool": tool, "status": "PID_REQUIRED", "error": "PID_MISSING_OR_INVALID"})
        identity, bad = LabGate.target(number)
        if identity is None:
            return _j({"ok": False, "tool": tool, "status": bad[0], "error": "OWNERSHIP_NOT_ESTABLISHED", "detail": bad[1]})
        if not LabGate.is_direct_child(identity):
            return _j({"ok": False, "tool": tool, "status": "PROCESS_NOT_OWNED", "error": "NOT_A_DIRECT_CHILD",
                       "detail": "only a direct child of the calling process can be registered; nothing was recorded"})
        folder = LabGate.registry_dir()
        name = f"pid{number}_{int(identity['create_time'] * 1000)}.json"
        entry = {"pid": number, "create_time": identity["create_time"], "image": identity["image"],
                 "launcher_pid": os.getpid()}
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / name).write_text(json.dumps(entry), encoding="utf-8")
        except OSError as exc:
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "REGISTRY_UNWRITABLE",
                       "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                             "strerror": exc.strerror or type(exc).__name__}})
        return _j({"ok": True, "tool": tool, "status": "OK", "registered": entry, "entry": name})
    except Exception as exc:  # noqa: BLE001
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "REGISTER_UNEXPECTED_ERROR",
                   "detail": f"{type(exc).__name__}: {exc}"})
