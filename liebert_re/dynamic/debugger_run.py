"""Gate-first, bounded run of one target inside a lab guest (guest_run, slice 2: orchestration).

WHAT THIS MODULE IS. The order of operations and the refusal rules for starting one target in a
Hyper-V guest under a job object: gate, push, create suspended, assign to the job, VERIFY the
assignment, resume, wait to a deadline, collect bounded output, terminate the job. It never
raises: every outcome is a dict with a ``status`` from ``STATUSES``.

WHAT IT IS NOT. It does not implement the guest side. ``GuestLauncher`` is a protocol; the real
implementation (a guest-side script reached over PowerShell Direct) is NOT in this slice, so
nothing here has run against a real guest, a real job object or a real debugger. Tests drive the
orchestration with a fake launcher and a fake transport. No debugger attaches in this slice: the
operation name ``debugger_run`` is the lab gate's name for the debugger-class run, so that the
gate treats it as one that executes a sample (``NEEDS_ISOLATION``). The transport module
(``hyperv_transport``) keeps its contract of never starting a target; starting is a separate
capability and lives behind ``GuestLauncher``.

ORDER (each step runs only if every earlier one succeeded and was confirmed):

1. Arguments are checked; anything malformed is ``REFUSED`` with zero guest calls.
2. The lab gate is asked (``LabGate.check``, operation ``debugger_run``). The run goes on only if
   the decision says ``ok`` is ``True``, ``decision`` is ``ALLOW``, ``status`` is
   ``GATE_PASSED``, ``isolation_verified`` is ``True``, ``isolation.verified`` is ``True`` and
   ``isolation.attestation.verdict`` is exactly ``"VERIFIED"``, and the decision names this
   operation. Truthy non-booleans, a missing verdict, ``UNKNOWN`` and ``FAILED`` are refusals.
   A gate that raises is a refusal. Zero transport and zero launcher calls happen before this.
3. ``transport.push_file`` (hash-verified). The pushed bytes must equal the SHA-256 the caller
   declared. Any other outcome is ``TRANSPORT_ERROR`` and nothing is started.
4. ``create_suspended``: the launcher must say the process exists and is suspended.
5. ``assign_to_job`` then ``verify_job_assignment``: the launcher must confirm the process is in
   the job and that the limits were applied. Anything else is ``JOB_ASSIGNMENT_UNCONFIRMED`` and
   the process is NEVER resumed (it is terminated).
6. ``resume``, ``wait`` to the deadline. A process that did not exit by the deadline is
   ``TIMED_OUT``.
7. ``terminate_job`` always runs once the process exists, then ``collect_output`` with a byte cap.
   Output beyond the cap is ``OUTPUT_TRUNCATED``, never ``COMPLETED``; the bytes kept are kept and
   marked.

``COMPLETED`` needs ALL of: the process exited by the deadline with an integer exit code, the
output reply was complete and within the cap, and job termination was confirmed. A non-zero exit
code is still ``COMPLETED`` (the run finished; the code is reported, not judged).

WHAT ``COMPLETED`` MEANS, AND WHAT IT DOES NOT. It means the target process and its job ended, and
nothing more. It does NOT mean that all activity the target caused in the guest has ended: a target
that asks a guest service to start an independent process OUTSIDE the job leaves that process behind
a ``COMPLETED`` run, and nothing inside the guest can prove "all execution has finished" (a process
the target started elsewhere is by definition not in the job that is being counted). This is not
closed by code; it is stated. The result therefore carries ``guest_residual_activity``: ``NONE_VM_RESET``
only when the VM was powered off after the run and the launcher read it back as ``Off`` (the
``VM_TURNED_OFF`` termination path, or a collect reply that says ``vm_reset`` is exactly ``True`` for
this run), otherwise ``NOT_VERIFIED``. ``NONE_VM_RESET`` means no guest process is still running; it says
nothing about what the target left on disk (a service it installed starts again with the guest), so the
guest still has to be reverted to its checkpoint before reuse.

What the result never carries: a host path, a user name, the gate decision's environment block,
or the credential. Output bytes are guest-controlled and untrusted; they are reported as base64
with their SHA-256 and the counts, and the result says so.

Cleanup outranks the cause. Once a process exists, a run whose job termination is not confirmed
(a reply that says so, no reply, or a reply about another process) is ``TRANSPORT_ERROR`` /
``JOB_TERMINATION_NOT_CONFIRMED`` whatever else happened; the status it would otherwise have had is
kept in ``primary_status`` / ``primary_reason``. The deadline is checked by this module's own clock
as well: an exit reported after ``timeout_s`` has passed since resume is ``TIMED_OUT``
(``EXIT_NOT_PROVEN_WITHIN_DEADLINE``), because nothing shows when it happened. The same holds for a clock
that raises, returns a non-finite or non-numeric value, or runs backwards: the deadline is then not
proven, ``elapsed_s`` is ``None`` rather than a guess, and the result is still built. Once the process
exists, any internal error ends in a termination attempt and ``TRANSPORT_ERROR``, never ``COMPLETED``.
Identities and counts in launcher replies must be built-in ``int`` / ``str`` / ``dict`` objects
(subclasses can redefine comparison), and a termination is never confirmed for a process whose pid
``create_suspended`` did not give.

Provenance. The result carries ``provenance``: the exit code, the output and the job confirmations are
``GUEST_REPORTED`` (a process in the guest under the target's own account says so), and
``termination_path`` says how the end of the job was confirmed when the launcher says: ``AGENT``,
``HOST_JOB_KILL`` or ``VM_TURNED_OFF`` (with ``termination_reason``). A launcher that gives no path leaves it
``None``. ``termination_confirmation`` says where that confirmation was read: ``AGENT`` is the agent's own
reply and ``HOST_JOB_KILL`` is read from a NEW PowerShell Direct session, independent of the agent process
but still run INSIDE the guest (an operating-system call made by a process in the guest), so both are
``GUEST_REPORTED``; only ``VM_TURNED_OFF`` is ``HOST_MEASURED`` (the Hyper-V host read the VM state). When the
job end is not confirmed there is no numeric ``exit_code`` and no ``COMPLETED``: what the guest said is kept
apart as ``exit_code_unconfirmed``.

Limits stated plainly. The gate's pid, ownership and image-hash checks are shaped for a process on
THIS host; a guest run has no host pid. This slice passes the caller's ``gate_args`` through
unchanged and does not decide which host process the authorization should scope. A launcher's
confirmations are checked for shape, for being about the process this run created (``run_id`` and
``pid``) and against the host's own deadline; they are not checked for honesty. The launcher is
trusted to tell the truth about the guest. Job limits do not stop a target from using the network inside the
guest (that is the attestation's job, and the attestation is a spoofable file).
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
import time
from typing import Any, Callable, Mapping, Protocol

from liebert_re.dynamic.hyperv_transport import ERROR_CLASSES

__all__ = ["OPERATION", "SCHEMA", "STATUSES", "RESIDUAL_ACTIVITY", "DebuggerRun", "GuestLauncher"]

SCHEMA = "liebert-re.debugger-run/1"
_TERMINATION_PATHS = frozenset({"AGENT", "HOST_JOB_KILL", "VM_TURNED_OFF"})
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
# Where each termination path was read. HOST_JOB_KILL runs in a new session but INSIDE the guest.
_CONFIRMATION_SOURCE = {"AGENT": "GUEST_REPORTED", "HOST_JOB_KILL": "GUEST_REPORTED", "VM_TURNED_OFF": "HOST_MEASURED"}
RESIDUAL_ACTIVITY = ("NOT_VERIFIED", "NONE_VM_RESET")
OPERATION = "debugger_run"

STATUSES = (
    "COMPLETED", "REFUSED", "TRANSPORT_ERROR", "TIMED_OUT", "OUTPUT_TRUNCATED",
    "JOB_ASSIGNMENT_UNCONFIRMED",
)

DEFAULT_TIMEOUT_S = 60.0
MAX_TIMEOUT_S = 600.0
DEFAULT_OUTPUT_CAP = 64 * 1024
MAX_OUTPUT_CAP = 1024 * 1024
DEFAULT_MEMORY_BYTES = 512 * 1024 ** 2
MAX_MEMORY_BYTES = 2 * 1024 ** 3

_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_:]{0,63}")


class GuestLauncher(Protocol):
    """What a guest-side launcher must offer. Every method returns a dict and must not raise.

    ``create_suspended(vm, guest_path)`` -> ``{"ok": True, "run_id": str, "pid": int > 0, "suspended": True}``.
    Every later reply must repeat that ``run_id`` and ``pid`` (the process and job the call is about);
    a missing, mismatched or non-integer identity means the reply is about something else and
    confirms nothing.
    ``assign_to_job(vm, run_id, limits)`` -> ``{"ok": True, <identity>}``; ``limits`` has ``memory_bytes``.
    ``verify_job_assignment(vm, run_id)`` -> ``{"ok": True, <identity>, "in_job": True, "limits_applied": True}``.
    ``resume(vm, run_id)`` -> ``{"ok": True, <identity>, "resumed": True}``.
    ``wait(vm, run_id, timeout_s)`` -> ``{"ok": True, <identity>, "exited": bool, "exit_code": int | None}``.
    ``terminate_job(vm, run_id)`` -> ``{"ok": True, <identity>, "terminated": True}``; it must also kill a
    process that was never assigned to the job.
    ``collect_output(vm, run_id, max_bytes)`` -> ``{"ok": True, <identity>, "data": bytes, "total_bytes": int}``
    with ``len(data) <= max_bytes``; ``total_bytes`` is how much the target produced. A launcher that powered
    the guest off after the run and read it back as ``Off`` adds ``"vm_reset": True`` (an exact ``True``, on
    any reply about this run, also a failed one); that is the only thing that makes
    ``guest_residual_activity`` ``NONE_VM_RESET`` besides the ``VM_TURNED_OFF`` termination path.
    Any key that is missing, or any value of another type, means "not confirmed".
    """

    def create_suspended(self, vm: str, guest_path: str) -> dict[str, Any]: ...
    def assign_to_job(self, vm: str, run_id: str, limits: Mapping[str, Any]) -> dict[str, Any]: ...
    def verify_job_assignment(self, vm: str, run_id: str) -> dict[str, Any]: ...
    def resume(self, vm: str, run_id: str) -> dict[str, Any]: ...
    def wait(self, vm: str, run_id: str, timeout_s: float) -> dict[str, Any]: ...
    def terminate_job(self, vm: str, run_id: str) -> dict[str, Any]: ...
    def collect_output(self, vm: str, run_id: str, max_bytes: int) -> dict[str, Any]: ...


def _code(value: object, fallback: str) -> str:
    """A short fixed-shape code, else the fallback: reasons never echo free text from a callee."""
    return value if isinstance(value, str) and _CODE.fullmatch(value) else fallback


def _is_int(value: object) -> bool:
    """A built-in int only (a bool, or a subclass that can redefine ``==`` and ``<``, is not one)."""
    return type(value) is int


def _positive_number(value: object, ceiling: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and 0 < value <= ceiling
    except (OverflowError, ValueError):
        return False


class DebuggerRun:
    """Kept as a class so the module adds no public top-level function to the published surface."""

    def __init__(self, transport: Any, launcher: GuestLauncher, *, gate: Callable[..., Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._transport = transport
        self._launcher = launcher
        self._gate = gate
        self._clock = clock
        self._termination: tuple[str | None, str | None] = (None, None)   # (path, reason) of the last confirmed end
        self._residual = "NOT_VERIFIED"                                      # guest_residual_activity of the last run

    # ---- time

    def _now(self) -> float | None:
        """One clock reading, or None when the clock raised or gave anything but a finite number."""
        try:
            value = self._clock()
            if type(value) not in (int, float) or not math.isfinite(value):
                return None
            return float(value)
        except Exception:  # noqa: BLE001 - a broken clock proves nothing and must not break the result
            return None

    @staticmethod
    def _since(start: float | None, end: float | None) -> float | None:
        """Seconds from ``start`` to ``end``; None when either reading is missing or time ran backwards."""
        if start is None or end is None or end < start:
            return None
        return end - start

    # ---- result

    def _result(self, started: float | None, status: str, reason: str | None, steps: list[str],
                **more: Any) -> dict[str, Any]:
        assert status in STATUSES
        elapsed = self._since(started, self._now())
        body: dict[str, Any] = {
            "schema": SCHEMA, "operation": OPERATION, "ok": status == "COMPLETED", "status": status,
            "reason": reason, "steps": list(steps), "elapsed_s": None if elapsed is None else round(elapsed, 3),
            "gate": None, "transport": None, "exit_code": None, "exit_code_unconfirmed": None, "output": None,
            "guest_residual_activity": self._residual,
            "job": {"assignment_confirmed": False, "terminated": None},
            "primary_status": None, "primary_reason": None,
            "provenance": {
                # Where the facts in this result come from. Everything below is reported by a process inside
                # the guest. That includes HOST_JOB_KILL: the job accounting is read by a new PowerShell
                # Direct session, independent of the agent process but still executed inside the guest. Only
                # VM_TURNED_OFF is read from outside it (the Hyper-V host reads the VM state).
                "exit_code": "GUEST_REPORTED", "output": "GUEST_REPORTED", "job_confirmations": "GUEST_REPORTED",
                "termination_path": self._termination[0], "termination_reason": self._termination[1],
                "termination_confirmation": _CONFIRMATION_SOURCE.get(self._termination[0]),
            },
            "not_verified": [
                "the launcher's confirmations are taken as given; no real guest launcher exists in this slice",
                "network use by the target inside the guest is not limited by the job object",
                "COMPLETED means the target process and its job ended, not that all guest activity ended: a process the "
                "target had a guest service start outside the job is not reached by the job (see guest_residual_activity; "
                "NONE_VM_RESET only after the VM was powered off and read back Off)",
                "the guest agent and the target run under the same account, so a target with that account's rights "
                "could forge what the guest reports (exit code, job confirmation, output); running the target under a "
                "separate non-administrator account is recommended and is not done here",
            ],
        }
        body.update(more)
        return body

    # ---- gate

    @staticmethod
    def admitted(decision: object) -> bool:
        """True only for a gate decision that proves a VERIFIED isolated guest AND a passed gate."""
        if not isinstance(decision, dict):
            return False
        isolation = decision.get("isolation")
        if not isinstance(isolation, dict):
            return False
        attestation = isolation.get("attestation")
        if not isinstance(attestation, dict):
            return False
        return (decision.get("ok") is True and decision.get("decision") == "ALLOW"
                and decision.get("status") == "GATE_PASSED" and decision.get("operation") == OPERATION
                and decision.get("isolation_verified") is True and isolation.get("verified") is True
                and attestation.get("verdict") == "VERIFIED")

    @staticmethod
    def _gate_summary(decision: object) -> dict[str, Any]:
        """Only fixed-shape codes from the decision: never its environment, user or target blocks."""
        if not isinstance(decision, dict):
            return {"status": None, "error": None, "verdict": None}
        isolation = decision.get("isolation")
        attestation = isolation.get("attestation") if isinstance(isolation, dict) else None
        verdict = attestation.get("verdict") if isinstance(attestation, dict) else None
        return {"status": _code(decision.get("status"), "UNKNOWN"),
                "error": _code(decision.get("error"), "NONE") if decision.get("error") else None,
                "verdict": verdict if verdict in ("VERIFIED", "UNKNOWN", "FAILED") else None}

    # ---- the run

    def run(self, vm: str, host_path: str, sample_sha256: str, guest_dir: str, *,
            gate_args: Mapping[str, Any] | None = None, timeout_s: float = DEFAULT_TIMEOUT_S,
            output_cap_bytes: int = DEFAULT_OUTPUT_CAP,
            memory_bytes: int = DEFAULT_MEMORY_BYTES) -> dict[str, Any]:
        started = self._now()
        steps: list[str] = []
        self._termination = (None, None)
        self._residual = "NOT_VERIFIED"

        def refuse(reason: str, **more: Any) -> dict[str, Any]:
            return self._result(started, "REFUSED", reason, steps, **more)

        # 1. arguments (zero guest calls on any failure)
        if not (isinstance(vm, str) and vm and isinstance(host_path, str) and host_path
                and isinstance(guest_dir, str) and guest_dir):
            return refuse("ARGUMENT_REJECTED")
        digest = sample_sha256.strip().lower() if isinstance(sample_sha256, str) else ""
        if not _HEX64.fullmatch(digest):
            return refuse("SAMPLE_SHA256_REQUIRED")
        if not _positive_number(timeout_s, MAX_TIMEOUT_S):
            return refuse("TIMEOUT_OUT_OF_RANGE")
        if not _is_int(output_cap_bytes) or not 0 < output_cap_bytes <= MAX_OUTPUT_CAP:
            return refuse("OUTPUT_CAP_OUT_OF_RANGE")
        if not _is_int(memory_bytes) or not 0 < memory_bytes <= MAX_MEMORY_BYTES:
            return refuse("MEMORY_LIMIT_OUT_OF_RANGE")
        if gate_args is not None and (not isinstance(gate_args, Mapping) or "operation" in gate_args
                                      or not all(isinstance(k, str) for k in gate_args)):
            return refuse("GATE_ARGS_REJECTED")
        if not callable(getattr(self._transport, "push_file", None)):
            return refuse("TRANSPORT_NOT_USABLE")
        if not all(callable(getattr(self._launcher, n, None)) for n in (
                "create_suspended", "assign_to_job", "verify_job_assignment", "resume", "wait",
                "terminate_job", "collect_output")):
            return refuse("LAUNCHER_NOT_USABLE")

        # 2. the gate, before any guest contact
        gate = self._gate
        if gate is None:
            from liebert_re.dynamic.lab_gate import LabGate
            gate = LabGate.check
        gate_kwargs = {"timeout_seconds": timeout_s, **(dict(gate_args) if gate_args else {})}
        steps.append("gate")
        try:
            decision = gate(OPERATION, **gate_kwargs)
        except Exception as exc:  # noqa: BLE001 - a gate that raises is a refusal, never a pass
            return refuse("GATE_RAISED", gate={"status": None, "error": type(exc).__name__, "verdict": None})
        summary = self._gate_summary(decision)
        if not self.admitted(decision):
            return refuse("GATE_NOT_PASSED_OR_ISOLATION_NOT_VERIFIED", gate=summary)

        # 3. push, hash-verified, and equal to the declared sample
        steps.append("push_file")

        def transport_error(reason: str, **more: Any) -> dict[str, Any]:
            return self._result(started, "TRANSPORT_ERROR", reason, steps, gate=summary, **more)

        try:
            pushed = self._transport.push_file(vm, host_path, guest_dir)
        except Exception as exc:  # noqa: BLE001
            return transport_error("TRANSPORT_RAISED", transport={"error_class": "UNKNOWN", "reason": type(exc).__name__})
        if not isinstance(pushed, dict):
            return transport_error("TRANSPORT_REPLY_INVALID", transport={"error_class": "UNKNOWN", "reason": None})
        cls = pushed.get("error_class")
        if cls in ERROR_CLASSES:
            shown_class = cls
        else:
            shown_class = None if cls is None and pushed.get("ok") is True else "UNKNOWN"
        tsummary = {"error_class": shown_class,
                    "reason": _code(pushed.get("reason"), "NONE") if pushed.get("reason") else None}
        measured = pushed.get("measured") if isinstance(pushed.get("measured"), dict) else {}
        guest_path = measured.get("guest_path")
        pushed_ok = (pushed.get("ok") is True and pushed.get("status") == "OK" and cls is None
                     and measured.get("hashes_equal") is True and isinstance(guest_path, str) and guest_path
                     and measured.get("host_sha256") == digest and measured.get("guest_sha256") == digest)
        if not pushed_ok:
            if pushed.get("ok") is True and tsummary["error_class"] is None:
                tsummary = {"error_class": "HASH_MISMATCH", "reason": "PUSH_NOT_PROVEN_EQUAL_TO_DECLARED_SAMPLE"}
            return transport_error(tsummary["reason"] or "PUSH_FAILED", transport=tsummary)

        # 4. suspended creation
        steps.append("create_suspended")
        created = self._call("create_suspended", vm, guest_path)
        run_id = created.get("run_id") if isinstance(created, dict) else None
        pid = created.get("pid") if isinstance(created, dict) else None
        named = type(run_id) is str and _RUN_ID.fullmatch(run_id) is not None
        if not (isinstance(created, dict) and created.get("ok") is True and named
                and _is_int(pid) and pid > 0 and created.get("suspended") is True):
            # An id we can name is a process that may exist; make sure it does not run.
            if named:
                steps.append("terminate_job")
                done = self._terminated(vm, run_id, (run_id, pid if _is_int(pid) and pid > 0 else None))
                return self._finish(started, steps, "TRANSPORT_ERROR", "CREATE_SUSPENDED_NOT_CONFIRMED",
                                    done, gate=summary, job={"assignment_confirmed": False, "terminated": done})
            return transport_error("CREATE_SUSPENDED_NOT_CONFIRMED",
                                   job={"assignment_confirmed": False, "terminated": None})
        ident = (run_id, pid)
        try:
            return self._supervise(started, steps, summary, vm, run_id, ident, timeout_s, output_cap_bytes, memory_bytes)
        except Exception:  # noqa: BLE001 - whatever broke, the process that exists must still be terminated
            steps.append("terminate_job")
            done = self._terminated(vm, run_id, ident)
            return self._finish(started, steps, "TRANSPORT_ERROR", "RUN_INTERNAL_ERROR", done, gate=summary,
                                job={"assignment_confirmed": None, "terminated": done})

    def _supervise(self, started: float | None, steps: list[str], summary: dict[str, Any], vm: str, run_id: str,
                   ident: tuple[str, int], timeout_s: float, output_cap_bytes: int,
                   memory_bytes: int) -> dict[str, Any]:
        """Everything after the suspended process exists. Raises only for a bug; ``run`` then terminates."""

        # 5. job assignment, confirmed before anything runs
        def unconfirmed(reason: str) -> dict[str, Any]:
            steps.append("terminate_job")
            done = self._terminated(vm, run_id, ident)
            return self._finish(started, steps, "JOB_ASSIGNMENT_UNCONFIRMED", reason, done, gate=summary,
                                job={"assignment_confirmed": False, "terminated": done})

        steps.append("assign_to_job")
        assigned = self._call("assign_to_job", vm, run_id, {"memory_bytes": memory_bytes})
        if not (self._about(assigned, ident) and assigned.get("ok") is True):
            return unconfirmed("ASSIGN_TO_JOB_FAILED")
        steps.append("verify_job_assignment")
        verified = self._call("verify_job_assignment", vm, run_id)
        if not (self._about(verified, ident) and verified.get("ok") is True and verified.get("in_job") is True
                and verified.get("limits_applied") is True):
            return unconfirmed("JOB_ASSIGNMENT_NOT_VERIFIED")

        # 6. resume and wait; from here the target runs
        steps.append("resume")
        resumed_at = self._now()
        resumed = self._call("resume", vm, run_id)
        if not (self._about(resumed, ident) and resumed.get("ok") is True and resumed.get("resumed") is True):
            steps.append("terminate_job")
            done = self._terminated(vm, run_id, ident)
            return self._finish(started, steps, "TRANSPORT_ERROR", "RESUME_NOT_CONFIRMED", done, gate=summary,
                                job={"assignment_confirmed": True, "terminated": done})
        steps.append("wait")
        waited = self._call("wait", vm, run_id, float(timeout_s))
        spent = self._since(resumed_at, self._now())
        within_deadline = spent is not None and spent <= timeout_s   # no proof of when it exited is no proof
        about = self._about(waited, ident)
        exited = about and waited.get("ok") is True and waited.get("exited") is True
        code = waited.get("exit_code") if about else None
        wait_valid = (about and waited.get("ok") is True and isinstance(waited.get("exited"), bool)
                      and (waited["exited"] is False or _is_int(code)))
        steps.append("terminate_job")
        terminated = self._terminated(vm, run_id, ident)
        steps.append("collect_output")
        output = self._collect(vm, run_id, output_cap_bytes, ident)
        common = {"gate": summary, "job": {"assignment_confirmed": True, "terminated": terminated}, "output": output}
        if not wait_valid:
            return self._finish(started, steps, "TRANSPORT_ERROR", "WAIT_REPLY_INVALID", terminated, **common)
        if not exited:
            return self._finish(started, steps, "TIMED_OUT", "DEADLINE_REACHED_BEFORE_EXIT", terminated, **common)
        if not within_deadline:
            return self._finish(started, steps, "TIMED_OUT", "EXIT_NOT_PROVEN_WITHIN_DEADLINE", terminated, **common)
        common["exit_code"] = code
        if output is None:
            return self._finish(started, steps, "TRANSPORT_ERROR", "OUTPUT_REPLY_INVALID", terminated, **common)
        if output["truncated"]:
            return self._finish(started, steps, "OUTPUT_TRUNCATED", output["truncated_reason"], terminated, **common)
        return self._finish(started, steps, "COMPLETED", None, terminated, **common)


    def _finish(self, started: float | None, steps: list[str], status: str, reason: str | None, terminated: object,
                **more: Any) -> dict[str, Any]:
        """Unconfirmed job termination outranks every other status; the cause is kept beside it."""
        if terminated is True:
            return self._result(started, status, reason, steps, **more)
        if "exit_code" in more:       # a run whose end is not proven has no exit code of its own: keep the claim apart
            more["exit_code_unconfirmed"] = more.pop("exit_code")
        if status == "COMPLETED":     # the label itself must not survive: nothing proved the run completed
            status, reason = None, "EXIT_REPORTED_JOB_END_NOT_CONFIRMED"
        return self._result(started, "TRANSPORT_ERROR", "JOB_TERMINATION_NOT_CONFIRMED", steps,
                            primary_status=status, primary_reason=reason, **more)

    @staticmethod
    def _about(reply: object, ident: tuple[str, int | None]) -> bool:
        """True only for a dict that names the process this run created (a pid is compared when known)."""
        if type(reply) is not dict or type(reply.get("run_id")) is not str or reply["run_id"] != ident[0]:
            return False
        if ident[1] is None:
            return True
        return type(reply.get("pid")) is int and reply["pid"] == ident[1]

    # ---- launcher calls

    def _call(self, name: str, *args: Any) -> Any:
        try:
            reply = getattr(self._launcher, name)(*args)
        except Exception:  # noqa: BLE001 - a launcher that raises has confirmed nothing
            return None
        return reply if type(reply) is dict else None   # a dict subclass can run code on every lookup

    def _terminated(self, vm: str, run_id: str, ident: tuple[str, int | None]) -> bool:
        reply = self._call("terminate_job", vm, run_id)
        if ident[1] is None:   # the process this run created was never identified: nothing can be confirmed
            return False
        confirmed = self._about(reply, ident) and reply.get("ok") is True and reply.get("terminated") is True
        if confirmed:
            path, reason = reply.get("termination_path"), reply.get("termination_reason")
            self._termination = (
                path if type(path) is str and path in _TERMINATION_PATHS else None,
                reason if type(reason) is str and _REASON_CODE.fullmatch(reason) else None)
            if self._termination[0] == "VM_TURNED_OFF":   # the guest was powered off and read back Off
                self._residual = "NONE_VM_RESET"
        return confirmed

    def _collect(self, vm: str, run_id: str, cap: int, ident: tuple[str, int | None]) -> dict[str, Any] | None:
        reply = self._call("collect_output", vm, run_id, cap)
        if self._about(reply, ident) and reply.get("vm_reset") is True:   # read even when the output is not usable
            self._residual = "NONE_VM_RESET"
        if not (self._about(reply, ident) and reply.get("ok") is True and isinstance(reply.get("data"), (bytes, bytearray))
                and _is_int(reply.get("total_bytes"))):
            return None
        data, total = bytes(reply["data"]), reply["total_bytes"]
        if total < len(data):
            return None
        reason = None
        if len(data) > cap:
            data, reason = data[:cap], "LAUNCHER_RETURNED_MORE_THAN_THE_CAP"
        if total > len(data):
            reason = reason or "TARGET_PRODUCED_MORE_THAN_THE_CAP"
        return {
            "untrusted": True, "bytes_kept": len(data), "total_bytes": total, "cap_bytes": cap,
            "truncated": total > len(data), "truncated_reason": reason,
            "sha256_of_kept": hashlib.sha256(data).hexdigest(),
            "data_b64": base64.b64encode(data).decode("ascii"),
        }
