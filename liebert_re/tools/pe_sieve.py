"""pe-sieve (hasherezade/pe-sieve, BSD-2-Clause) scan of ONE running process the
caller owns: "is this live process different from the image on disk?"

Disk-reading tools (rizin, DIE, capa) cannot see anything that only exists at
run time: an inline hook or patch applied after load, an IAT hook, a replaced or
hollowed image, a PE or shellcode implanted into private memory. pe-sieve
compares the process against the files it was loaded from, which is the one
question the rest of this package cannot answer.

Design decisions, each fixed on purpose (none is a gate preference):

* SCAN ONLY. The scanner is always started with `/ofilter 2` (dump nothing) and
  never with a dump, import-recovery, minidump or rebase switch. A PE dumped out
  of a live process is an artefact, not a finding; this module reports what was
  found and writes nothing of the target to disk.
* A PID IS REQUIRED. There is no whole-system mode: a missing PID, a non-numeric
  one, zero, a negative one and every "scan everything" spelling are refused with
  `PID_REQUIRED` before any process is started. Scanning is something done to a
  process the caller names, never a sweep.
* STRUCTURED OUTPUT ONLY. `/json /jlvl 2` is requested and the report is read as
  JSON; the text log is never parsed for results. The few text matches that exist
  (scanner/target bitness mismatch, process could not be opened) are for refusals
  that arrive WITHOUT a report, and are labelled as text-derived.
* ONE SCANNER, ALWAYS 64-BIT WHEN PRESENT. Measured against 0.4.1.1: the 32-bit
  scanner cannot scan a 64-bit target (it prints a report-shaped JSON with zero
  modules scanned and exits non-zero), while the 64-bit scanner scans 32-bit
  (WOW64) targets fully and additionally sees the native modules those load. So
  the choice does not depend on the target; only a machine with the 32-bit
  scanner alone can mismatch, and that is reported as `SCANNER_MISMATCH`.

**"Nothing found" is only ever one of several outcomes.** `OK` with
`anomalies_found: false` means every module and region pe-sieve looked at matched
disk, at the scan depth in `scan_flags`. It is NOT said when the process could
not be opened (`ACCESS_DENIED`, `PROCESS_NOT_OPENED`), when the scanner and
target bitness disagree (`SCANNER_MISMATCH`), when nothing was scanned at all
(`NOTHING_SCANNED`, which pe-sieve reports as an all-zero, clean-looking report),
or when some modules could not be read (`SCAN_PARTIAL`, which still lists
whatever WAS found). The exact argument vector of the call is echoed in
`invoked_argv`, because a flag that was altered on its way to a Windows tool
makes it run with defaults, silently.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import uuid

from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.dynamic.lab_gate import LabGate

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
EVIDENCE = APP_DIR / "dataset" / "evidence" / "pe_sieve_scan"
EVIDENCE.mkdir(parents=True, exist_ok=True)

_DEFAULT_TIMEOUT_SECONDS = 120
_MIN_TIMEOUT_SECONDS = 10
# A scan reads every executable page of the process (more with `data`/`threads`).
# 600 s is a ceiling on one scan, set by this module, not by the shared runner.
_MAX_TIMEOUT_SECONDS = 600
_MAX_OUTPUT_CHARS = 8 * 1024 * 1024
# Memory ceiling for the scanner's process tree, enforced by run_bounded_process and required by the lab gate.
_MAX_SCANNER_MEMORY_BYTES = 2 * 1024 ** 3
_KNOWN_INSTALL_DIR = r"C:\Tools\pe-sieve"
_ENV_VAR = "PE_SIEVE_HOME"
_BINARY_NAMES = ("pe-sieve64.exe", "pe-sieve32.exe")
_MAX_PID = 0xFFFFFFFF
# Spellings of "all processes". Refused by name so the reason is not "not a number".
_ALL_PROCESS_SPELLINGS = frozenset({"all", "*", "-1", "any", "every", "everything", "system", "all-processes"})

# Fixed, never caller-controlled. `/ofilter 2` is the no-dump guarantee; `/report 5` asks
# for suspicious results AND errors, so an unreadable module appears in the report.
_FIXED_FLAGS = ("/json", "/jlvl", "2", "/ofilter", "2", "/report", "5", "/quiet")
# option -> (switch, minimum, maximum, default). Every one is passed explicitly, defaults
# included, so the invocation is complete and reproducible from `scan_flags`.
_NUMERIC_OPTIONS = {
    "iat": ("/iat", 0, 3, 1),
    "shellcode": ("/shellc", 0, 4, 3),
    "obfuscation": ("/obfusc", 0, 3, 0),
    "data": ("/data", 0, 5, 0),
    "dotnet_policy": ("/dnet", 0, 4, 0),
}
# t_scan_status in pe-sieve: 1 suspicious, 0 not suspicious, -1 error. Only 0 and 1 have
# been observed locally; -1 is from the scanner's documented enum, not from a run here.
_STATUS_SUSPICIOUS, _STATUS_CLEAN, _STATUS_ERROR = 1, 0, -1

_NOT_COVERED = (
    "Not covered unless requested: non-executable pages (`data`), thread call stacks (`threads`), "
    "other processes, kernel memory, and anything the process does after this scan."
)


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


class _PeSieve:
    """Helpers kept off module level so the published tool-name set stays exactly
    the two public operations (the layout pin counts every top-level `def`)."""

    @staticmethod
    def candidates():
        """Every pe-sieve binary reachable, in resolution order, as
        ``(path, resolved_by)``: env, then PATH, then the known install directory."""
        found = []
        seen = set()

        def add(path, how):
            try:
                key = os.path.normcase(os.path.abspath(path))
            except (OSError, ValueError):
                return
            if key not in seen and os.path.isfile(path):
                seen.add(key)
                found.append((str(path), how))

        explicit = os.getenv(_ENV_VAR, "").strip()
        if explicit:
            if os.path.isfile(explicit):
                add(explicit, _ENV_VAR)
            else:
                for name in _BINARY_NAMES:
                    add(os.path.join(explicit, name), _ENV_VAR)
        for name in _BINARY_NAMES:
            hit = shutil.which(name) or shutil.which(name[:-4])
            if hit:
                add(hit, "PATH")
        for name in _BINARY_NAMES:
            add(os.path.join(_KNOWN_INSTALL_DIR, name), "known_install_path")
        return found

    @staticmethod
    def bitness(path):
        name = os.path.basename(path).lower()
        if "64" in name:
            return 64
        if "32" in name:
            return 32
        return None

    @staticmethod
    def pick():
        """The scanner to use: an explicit file wins; otherwise the first 64-bit
        candidate, then the first of any kind."""
        found = _PeSieve.candidates()
        if not found:
            return None, None, found
        explicit = os.getenv(_ENV_VAR, "").strip()
        if explicit and os.path.isfile(explicit):
            return found[0][0], found[0][1], found
        for path, how in found:
            if _PeSieve.bitness(path) == 64:
                return path, how, found
        return found[0][0], found[0][1], found

    @staticmethod
    def missing(tool):
        return _j({
            "ok": False, "tool": tool, "status": "TOOL_MISSING",
            "required_capability": "pe-sieve (pe-sieve64.exe)",
            "detail": (
                "pe-sieve was not found. Set PE_SIEVE_HOME to its install directory or to the "
                "executable itself, or put pe-sieve64.exe on PATH. The default install location "
                r"checked last is C:\Tools\pe-sieve."
            ),
        })

    @staticmethod
    def env_failure(tool, exc, extra=None):
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_COULD_NOT_RUN",
            "environment_error": {
                "type": type(exc).__name__, "errno": getattr(exc, "errno", None),
                "strerror": getattr(exc, "strerror", None) or type(exc).__name__,
            },
            "detail": (
                "A local operating-system error stopped this call before pe-sieve produced a result. "
                "It describes this machine's environment, not the target process and not pe-sieve's "
                "findings; no answer was produced."
            ),
            **(extra or {}),
        })

    @staticmethod
    def pid_refusal(tool, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            code, why = "PID_MISSING", "no process id was given"
        elif isinstance(value, str) and value.strip().lower() in _ALL_PROCESS_SPELLINGS:
            code, why = "ALL_PROCESSES_REFUSED", "scanning every process is not offered; name one process id"
        else:
            code, why = "PID_INVALID", "the process id must be a positive decimal integer"
        return _j({
            "ok": False, "tool": tool, "status": "PID_REQUIRED", "error": code,
            "requested_pid": value if isinstance(value, (int, str)) else repr(type(value).__name__),
            "detail": (
                f"{why}. pe_sieve_scan scans exactly one process the caller started and names by PID; "
                "there is no whole-system mode, by design, and nothing was started."
            ),
        })

    @staticmethod
    def parse_pid(value):
        """A positive int, or None. A bool is not a PID."""
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
    def options(iat, shellcode, obfuscation, data, dotnet_policy, threads):
        """Validated switches as ``(argv_tail, scan_flags, None)`` or ``(None, None, error)``."""
        supplied = {"iat": iat, "shellcode": shellcode, "obfuscation": obfuscation,
                    "data": data, "dotnet_policy": dotnet_policy}
        argv, flags = [], {}
        for name, (switch, low, high, default) in _NUMERIC_OPTIONS.items():
            value = default if supplied[name] is None else supplied[name]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                return None, None, f"{name} must be an integer from {low} to {high}"
            argv += [switch, str(value)]
            flags[name] = value
        if not isinstance(threads, bool):
            return None, None, "threads must be true or false"
        if threads:
            argv.append("/threads")
        flags["threads"] = threads
        return argv, flags, None

    @staticmethod
    def extract_report(stdout):
        """The JSON object pe-sieve prints, or None. Never raises."""
        start = (stdout or "").find("{")
        end = (stdout or "").rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            raw = json.loads(stdout[start:end + 1])
        except ValueError:
            return None
        return raw if isinstance(raw, dict) else None

    @staticmethod
    def save_evidence(pid, raw):
        out = EVIDENCE / f"pid{pid}_{uuid.uuid4().hex[:8]}_pe_sieve_scan.json"
        try:
            out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            return None, f"{type(exc).__name__}: {exc}"
        try:
            _evidence_index_record_write(out)
        except Exception:
            pass
        return out.name, None

    @staticmethod
    def tail(text, limit=1500):
        return (text or "")[-limit:]

    @staticmethod
    def as_int(value):
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def interpret(report):
        """Reduce `scan_report` to what a caller needs, without renaming anything the
        scanner reported. Returns a dict; every category name is the scanner's own."""
        scanned = report.get("scanned") if isinstance(report.get("scanned"), dict) else {}
        modified = scanned.get("modified") if isinstance(scanned.get("modified"), dict) else {}
        categories = {k: v for k, v in modified.items() if k != "total"}
        entries = report.get("scans") if isinstance(report.get("scans"), list) else []
        kinds, findings, error_entries, unrecognised = {}, [], [], []
        for entry in entries:
            if not isinstance(entry, dict):
                unrecognised.append({"entry": repr(entry)[:200]})
                continue
            for kind, body in entry.items():
                kinds[kind] = kinds.get(kind, 0) + 1
                status = _PeSieve.as_int(body.get("status")) if isinstance(body, dict) else None
                item = {"scan_kind": kind, **(body if isinstance(body, dict) else {"value": body})}
                if status == _STATUS_SUSPICIOUS:
                    findings.append(item)
                elif status == _STATUS_ERROR:
                    error_entries.append(item)
                elif status != _STATUS_CLEAN:
                    unrecognised.append(item)
        total = _PeSieve.as_int(scanned.get("total"))
        skipped = _PeSieve.as_int(scanned.get("skipped")) or 0
        errors = _PeSieve.as_int(scanned.get("errors")) or 0
        counted = [v for v in (_PeSieve.as_int(x) for x in categories.values()) if v]
        return {
            "total": total, "skipped": skipped, "errors": max(errors, len(error_entries)),
            "categories": categories,
            "categories_nonzero": {k: v for k, v in categories.items() if _PeSieve.as_int(v)},
            "modified_total": _PeSieve.as_int(modified.get("total")),
            "anomalies_found": bool(findings or counted or (_PeSieve.as_int(modified.get("total")) or 0) > 0),
            "findings": findings, "error_entries": error_entries, "unrecognised_entries": unrecognised,
            "scan_kinds": kinds,
        }

    @staticmethod
    def with_gate(out, gate):
        """Attach the gate record to a result and finish its evidence with the exact command."""
        result = json.loads(out)
        outcome = {"status": result.get("status"), "ok": result.get("ok"), "error": result.get("error")}
        gate["evidence_finalize_error"] = LabGate.finish(gate, result.get("invoked_argv"), outcome)
        result["lab_gate"] = gate
        return _j(result)

    @staticmethod
    def execute(tool, number, iat, shellcode, obfuscation, data, dotnet_policy, threads,
                timeout_seconds, cancellation_token):
        """Everything that happens AFTER the lab gate passed. Returns the JSON string."""
        tail_args, flags, bad = _PeSieve.options(iat, shellcode, obfuscation, data, dotnet_policy, threads)
        if bad:
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                       "error": "INVALID_OPTION", "detail": bad})
        exe, how, _found = _PeSieve.pick()
        if not exe:
            return _PeSieve.missing(tool)
        argv = [exe, "/pid", str(number), *_FIXED_FLAGS, *tail_args]
        # An MSYS shell rewrites a "/flag" argument into a path and the tool then runs with
        # defaults; this call is a direct, list-form spawn, and the guard variables are belt
        # and braces. `invoked_argv` below is what a reader checks.
        env = {**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"}
        base = {"tool": tool, "pid": number, "scanner": exe, "scanner_bitness": _PeSieve.bitness(exe),
                "resolved_by": how, "invoked_argv": argv, "scan_flags": flags}
        cp = run_bounded_process(argv, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
                                 environment=env, max_output_chars=_MAX_OUTPUT_CHARS,
                                 max_memory_bytes=_MAX_SCANNER_MEMORY_BYTES)
        if cp.resource_limit_unavailable:
            return _j({**base, "ok": False, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_RESOURCE_LIMIT_UNAVAILABLE",
                       "detail": "The memory limit could not be enforced on this host, so nothing was started."})
        if cp.cancelled:
            return _j({**base, "ok": False, "status": "CANCELLED", "error": "PE_SIEVE_CANCELLED_PROCESS_TREE_TERMINATED"})
        if cp.memory_exceeded:
            return _j({**base, "ok": False, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_MEMORY_LIMIT_EXCEEDED_PROCESS_TREE_TERMINATED",
                       "max_memory_bytes": _MAX_SCANNER_MEMORY_BYTES,
                       "detail": "The scanner exceeded its memory limit and was stopped; this says nothing about the process."})
        if cp.timed_out:
            return _j({**base, "ok": False, "status": "TIMEOUT", "timeout_seconds": timeout_seconds,
                       "error": "PE_SIEVE_TIMEOUT_PROCESS_TREE_TERMINATED",
                       "detail": "The scan did not finish; this says nothing about the process."})
        text = (cp.stdout or "") + "\n" + (cp.stderr or "")
        low = text.lower()
        exit_code = cp.returncode
        message = _PeSieve.tail(text, 600)
        # Refusals that come WITHOUT a usable report, recognised from the scanner's text.
        if "scanner mismatch" in low:
            return _j({**base, "ok": False, "status": "SCANNER_MISMATCH", "exit_code": exit_code,
                       "scanner_message": message, "text_derived": True,
                       "detail": "The scanner's bitness does not match the target's. Any report-shaped "
                                 "output that accompanied this is not a scan of the process."})
        raw = _PeSieve.extract_report(cp.stdout)
        report = raw.get("scan_report") if raw else None
        if "could not open the process" in low and not isinstance(report, dict):
            denied = "access is denied" in low or "access denied" in low
            return _j({**base, "ok": False, "status": "ACCESS_DENIED" if denied else "PROCESS_NOT_OPENED",
                       "exit_code": exit_code, "scanner_message": message, "text_derived": True,
                       "detail": "pe-sieve could not open the process (it has exited, does not exist, or "
                                 "needs higher privileges). This is NOT a finding that the process is clean."})
        if raw is None:
            return _j({**base, "ok": False, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_NO_JSON_OUTPUT",
                       "exit_code": exit_code, "output_truncated": cp.output_truncated, "scanner_message": message})
        if not isinstance(report, dict):
            return _j({**base, "ok": False, "status": "RESULT_PARSE_FAILED", "error": "PE_SIEVE_NO_SCAN_REPORT",
                       "exit_code": exit_code, "output_truncated": cp.output_truncated})
        reported_pid = _PeSieve.as_int(report.get("pid"))
        evidence_name, evidence_error = _PeSieve.save_evidence(number, raw)
        summary = _PeSieve.interpret(report)
        common = {
            **base, "exit_code": exit_code,
            "target": {"is_64_bit": report.get("is_64_bit"), "is_managed": report.get("is_managed"),
                       "main_image_path": report.get("main_image_path"),
                       "used_reflection": report.get("used_reflection")},
            "scanner_version": report.get("scanner_version"),
            "coverage": {"scanned_modules": summary["total"], "skipped": summary["skipped"],
                         "errors": summary["errors"], "scan_kinds": summary["scan_kinds"]},
            "categories": summary["categories"], "categories_nonzero": summary["categories_nonzero"],
            "modified_total": summary["modified_total"], "anomalies_found": summary["anomalies_found"],
            "findings": summary["findings"], "error_entries": summary["error_entries"],
            "unrecognised_entries": summary["unrecognised_entries"],
            "internal_evidence_name": evidence_name, "evidence_write_error": evidence_error,
            "evidence_access": "Full unmodified pe-sieve JSON report saved; this response is the structured summary of it.",
        }
        if reported_pid is not None and reported_pid != number:
            return _j({**common, "ok": False, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_PID_MISMATCH",
                       "reported_pid": reported_pid,
                       "detail": "The report names a different process than the one requested; the call "
                                 "was altered on the way to the scanner. Compare invoked_argv."})
        if exit_code is not None and exit_code & 0xFFFFFFFF == 0xFFFFFFFF:
            return _j({**common, "ok": False, "status": "ANALYSIS_LIMITED", "error": "PE_SIEVE_REPORTED_FAILURE_EXIT",
                       "detail": "pe-sieve exited with its error code although a report was printed; the "
                                 "report is not treated as a completed scan."})
        if not summary["total"] and not summary["findings"]:
            return _j({**common, "ok": False, "status": "NOTHING_SCANNED", "verdict": "INCONCLUSIVE",
                       "detail": "pe-sieve reported zero modules scanned. An all-zero report here is the "
                                 "absence of a scan, not the absence of anomalies."})
        if summary["errors"] or summary["unrecognised_entries"] or summary["skipped"]:
            return _j({**common, "ok": False, "status": "SCAN_PARTIAL",
                       "verdict": "ANOMALIES_FOUND_IN_PART" if summary["anomalies_found"] else "INCONCLUSIVE",
                       "detail": "Some modules or regions could not be read, were skipped, or came back with a "
                                 "status this module does not recognise. Findings listed are real; the absence "
                                 "of findings is NOT established for the unread part.",
                       "not_covered": _NOT_COVERED})
        return _j({**common, "ok": True, "status": "OK",
                   "verdict": "ANOMALIES_FOUND" if summary["anomalies_found"] else "NO_ANOMALIES_IN_SCANNED_MODULES",
                   "not_covered": _NOT_COVERED,
                   "note": ("Category names and counts are pe-sieve's own, read from its JSON. A clean result "
                            "covers the modules and regions scanned at the depth in scan_flags, on this run; "
                            "it is not a statement that the process is benign.")})


def pe_sieve_status():
    """Whether pe-sieve is reachable, from where, which scanner bitness would be used,
    and its version. Zero arguments; runs `/version` once, which scans nothing."""
    tool = "pe_sieve_status"
    try:
        exe, how, found = _PeSieve.pick()
        if not exe:
            return _PeSieve.missing(tool)
        argv = [exe, "/version"]
        cp = run_bounded_process(argv, timeout_seconds=_MIN_TIMEOUT_SECONDS,
                                 environment={**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"},
                                 max_output_chars=65536)
        if cp.timed_out or cp.cancelled:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "binary": exe,
                       "error": "PE_SIEVE_VERSION_TIMEOUT"})
        text = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        match = re.search(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b", text)
        if cp.returncode != 0 or not match:
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "binary": exe,
                       "error": "PE_SIEVE_VERSION_UNREADABLE", "exit_code": cp.returncode,
                       "output_tail": _PeSieve.tail(text, 500)})
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": how, "scanner_bitness": _PeSieve.bitness(exe),
            "version": match.group(0),
            "binaries_found": [{"path": p, "resolved_by": h, "bitness": _PeSieve.bitness(p)} for p, h in found],
            "invoked_argv": argv,
            "operations": ["pe_sieve_scan"],
            "policy": {
                "scan_only": True, "dump_switches_never_passed": True, "pid_required": True,
                "whole_system_mode": "refused with PID_REQUIRED", "output_filter": "/ofilter 2 (no dumps)",
            },
            "note": (
                "The 64-bit scanner is used whenever it is present: measured against 0.4.1.1 it scans "
                "both 64-bit and 32-bit targets, while the 32-bit scanner cannot scan a 64-bit target. "
                "Output shapes were measured on this version; a different one may change them, and "
                "RESULT_PARSE_FAILED from a scan is the drift signal."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        if isinstance(exc, OSError):
            return _PeSieve.env_failure(tool, exc)
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                   "error": "PE_SIEVE_UNEXPECTED_ERROR", "detail": f"{type(exc).__name__}: {exc}"})


def pe_sieve_scan(pid=None, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None,
                  iat=None, shellcode=None, obfuscation=None, data=None, dotnet_policy=None,
                  threads=False, authorization=None, sample_sha256=None):
    """Scan ONE running process, by PID, for in-memory differences from its on-disk
    image, via the real `pe-sieve /json /jlvl 2`. Scan only: nothing is dumped.

    LAB GATE (behaviour change): this scan now runs only behind `dynamic_lab_gate`
    (liebert_re.dynamic.lab_gate). It needs the operator switch (LIEBERT_RE_DYNAMIC_LAB=authorized),
    an `authorization` object naming who, why, this operation and this PID, the declared
    `sample_sha256` of the process image, and a process this harness started (a direct child of
    the caller, or one registered with `dynamic_lab_register_owned_process`). Any of these missing
    or unverifiable refuses the call with the gate's status and starts nothing. The response
    carries `lab_gate`: what was checked, what was NOT verified (`isolation_verified: false`:
    guest, snapshot, network) and the evidence file. Observation of a harness-owned process is
    allowed without isolation; executing or instrumenting one is not offered here.

    `pid` is required. A missing, non-numeric, zero or negative PID, or any
    "all processes" spelling, returns `PID_REQUIRED` and starts nothing.

    Depth switches (each passed explicitly, echoed in `scan_flags`):

    * `iat` 0-3 (`/iat`, default 1)       IAT hook scan; 0 off, 3 unfiltered
    * `shellcode` 0-4 (`/shellc`, default 3)  shellcode detection by patterns / statistics
    * `obfuscation` 0-3 (`/obfusc`, default 0) encrypted or obfuscated areas
    * `data` 0-5 (`/data`, default 0)     also scan non-executable pages
    * `dotnet_policy` 0-4 (`/dnet`, default 0) treatment of managed processes
    * `threads` (`/threads`, default off) scan thread call stacks

    Statuses:

    * `OK`             the scan completed with no unreadable or skipped part.
                       `anomalies_found` says whether anything was reported;
                       `categories` and `categories_nonzero` carry the scanner's
                       own category names and counts; `findings` the detail.
    * `SCAN_PARTIAL`   some modules were unreadable or skipped. Whatever was
                       found is still listed. Never a clean result.
    * `NOTHING_SCANNED` the scanner reported zero modules scanned.
    * `ACCESS_DENIED` / `PROCESS_NOT_OPENED`  the process could not be opened
                       (text-derived; carried with `scanner_message`). Not a
                       negative result.
    * `SCANNER_MISMATCH` 32-bit scanner against a 64-bit target.
    * `AUTHORIZATION_REQUIRED`, `SAMPLE_HASH_REQUIRED`, `SAMPLE_HASH_MISMATCH`,
      `SAMPLE_HASH_UNVERIFIABLE`, `PROCESS_NOT_OWNED`, `OWNERSHIP_UNVERIFIABLE`,
      `RESOURCE_LIMIT_UNAVAILABLE`: refused by the lab gate before anything started.
    * `PID_REQUIRED`, `TOOL_MISSING`, `TIMEOUT`, `CANCELLED`, `ANALYSIS_LIMITED`
      (including `environment_error` for a local OS failure),
      `RESULT_PARSE_FAILED`.
    """
    tool = "pe_sieve_scan"
    gate = None
    try:
        number = _PeSieve.parse_pid(pid)
        if number is None:
            return _PeSieve.pid_refusal(tool, pid)
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            timeout_seconds = _DEFAULT_TIMEOUT_SECONDS
        timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
        gate = LabGate.check("pe_sieve_scan", number, authorization, sample_sha256,
                             timeout_seconds, _MAX_SCANNER_MEMORY_BYTES)
        if not gate["ok"]:
            refused = {"ok": False, "tool": tool, "pid": number, "status": gate["status"], "error": gate["error"],
                       "detail": gate["detail"] + " Nothing was started.", "lab_gate": gate}
            if gate.get("environment_error"):
                refused["environment_error"] = gate["environment_error"]
            return _j(refused)
        out = _PeSieve.execute(tool, number, iat, shellcode, obfuscation, data, dotnet_policy, threads,
                               timeout_seconds, cancellation_token)
        return _PeSieve.with_gate(out, gate)
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        if isinstance(exc, OSError):
            result = json.loads(_PeSieve.env_failure(tool, exc))
        else:
            result = {"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
                      "error": "PE_SIEVE_UNEXPECTED_ERROR", "detail": f"{type(exc).__name__}: {exc}"}
        if gate is not None and gate.get("ok"):
            result["lab_gate"] = gate
            gate["evidence_finalize_error"] = LabGate.finish(gate, None, {"status": result["status"], "error": result["error"]})
        return _j(result)
