"""IDA Pro (Hex-Rays) headless queries: functions, segments, imports/exports,
strings, cross-references and decompiled pseudocode, from a cached analysis
database.

This is the decompiler question that `native_xref.py`, `rizin.py` and
`capa.py` do not answer: *what does this function look like as C, and who
calls it*. Deliberately a wrapper, the same discipline as `die.py` and
`capa.py`: it drives IDA's own batch interface (`idat -A -S<script>`) and
never reimplements analysis. IDA only READS the target (no execution of
untrusted code), so this is a HOST-side static tool.

IDA is commercial and is not shipped, bundled or downloaded by this package.
It needs a licensed IDA Pro 9.x on the machine. Without one every operation
returns TOOL_MISSING; nothing here falls back to another engine, because a
result from a different engine is a different claim.

**Isolation.** Every call is a bounded subprocess (`run_bounded_process`), not
the in-process `idalib` API: an analysis-kernel crash takes down idat, not the
caller. The query itself is the read-only worker `ida_scripts/query_program.idapy`
(a data file, not a module: it imports IDA's own modules and cannot be imported here),
copied into a private work directory and driven through a JSON job file named
in the `LIEBERT_IDA_JOB` environment variable (not through `-S`'s own argument
re-splitting, which corrupts quotes and spaces).

**Database cache -- content-hash keyed, one slot per input, LRU capped.**
The first query on a file pays for IDA's auto-analysis; later queries reopen
the cached `.i64`. The key is the SHA-256 of the INPUT FILE, never of a
database: IDA rewrites an analysed database on every open, so a database's own
hash changes per call. Cloning an already-analysed database into the cache on
every call would therefore grow disk use without bound. Here that cannot
happen: a slot is named by the input hash, a database file is refused as an
input, and the total is held under a byte budget
(`LIEBERT_IDA_CACHE_BYTES`, default 5 GiB) by least-recently-used eviction of
whole slots after every query. A first analysis happens in a scratch directory
and is promoted into its slot only when every success signal agrees.

**A query cannot change the cache.** The first call on a file runs one
session that only analyses and saves (`summary`); the question itself is
answered from a second, reopen session that tells IDA to discard its changes
on exit. Measured on IDA 9.4: without that, decompiling one function persisted
the types the decompiler inferred, so a later `list_functions` answered
differently depending on what had been asked before it, and every reopen
rewrote the whole `.i64`. With it the database file is byte-identical across
reopens.

**Success is never read from the exit code.** Four things must agree: exit
status, the IDA log (no fatal markers), the packed `.i64` on disk, and the
worker's JSON result file carrying its completion marker. A broken script exits
1, produces no `.i64` and leaves unpacked `.id0/.id1/.id2/.nam/.til` files; a
script that raised before writing can still exit 0. The log counts as a signal only if it was readable and
non-empty; the result must answer the operation that was asked; and a reopen
result must carry `database_changes_discarded: true` (the worker also refuses
to run the operation when it cannot set that up). Any disagreement is
ANALYSIS_LIMITED with the signals reported, and the scratch directory (or, for
a reopen, the possibly half-written slot) is deleted.

**No outbound symbol lookups.** Left at its default, IDA's PDB plugin
downloads symbols from a public symbol server during analysis and writes them
under the user's temp directory. That breaks determinism (the same file
analyses differently with and without network) and tells a third party which
file is being analysed. Every launch passes `-Opdb:off` (documented in IDA's
own `cfg/pdb.cfg` and `idat -h`), and the log is scanned for any sign it
happened anyway (`network_lookup_detected`). Symbols from a PDB you place next
to the input are therefore NOT loaded by this tool.

**Privacy of what is reported.** IDA's log carries a licence line and absolute
paths. Anything from the log that leaves this module (failure tails) goes
through `_redact`: the licence line is replaced, home-directory paths become
`<HOME>`, and the scratch and input paths become `<WORK>` / `<INPUT>`.

**Microcode (`ida_microcode_cfg`).** One function's microcode as a control-flow
graph at one of the eight maturity levels, read in the same temporary reopen
session as a question (`ida_scripts/microcode_cfg.idapy`, a second worker, so
`query_program.idapy` stays free of the decompiler's microcode API and of any
third-party import). Raw microcode is the default. `deobfuscate=True` is an
opt-in pass of the third-party d810 plugin over the same generation: the answer
then says it is a d810 pass, which project was loaded, which rules fired, and
whether the output differs from the raw microcode of the same function built in
the same session. If d810 is missing or does not start, the answer is a status
with no microcode, never raw microcode under a deobfuscation request. d810 is
driven against a private configuration directory (its `options.json` is the
user's own file); see `microcode_cfg.idapy`. The pass targets instruction-level obfuscation and
control-flow flattening patterns. It does not handle virtualised (VM-based) code: that logic lives in bytecode data, which microcode rules cannot rewrite.

**Type members, patch plans, annotation log.** Three more top-level operations, none of which
persists anything. `ida_type_member_offset` reads one member's offset from the database's type
information (a third operation of `query_program.idapy`'s session, kept off `ida_query`'s menu).
`ida_patch_plan` is NOT a pure read: its worker (`ida_scripts/patch_plan.idapy`) calls IDA's patch
API in an in-memory copy of the database inside the same discard guarantee, so the wrapper hashes
the cached database file before and after and answers `PATCH_PLAN_CACHE_VIOLATION` (slot dropped, no
plan) if the two differ. `ida_annotations` is a file-system read of the per-hash write log next to
the cache slots and never starts IDA. These three keep the target's name and path out of their
answers and out of their evidence file names (the input hash names them), and each of the first two
has its own reopen-session ceiling constant.

**Annotations that persist (`ida_rename_plan`, `ida_annotations_apply`).** A plan and an apply are two
operations with two names, not a flag: a flag can be closed with the wrong default, a separate name cannot.
The plan reads the scope's current names and binds itself to the annotation version it read; the apply
cannot be called without a plan, recomputes the plan's digest, refuses a stale plan, and writes a NEW
immutable version (one manifest pointer publishes it) into the ANNOTATED root: its own tree beside, not
inside, the cache, with its own locks, which the cache's eviction, slot deletion and scratch cleanup never
see. The write happens in a session of a scratch COPY (never of the pristine cache database, never of a
published version); the candidate is synced and kept in a recovery directory until promoted; an audit
journal gets a `batch_prepared` record before the promotion and `batch_committed` after it; and a NEW
engine process reads the stored version back (names and the annotation marker stored inside the database)
before the pointer is published. Concurrent writers are blocked, not merged (`concurrency_policy` in every
answer). The write worker is its own data file, `ida_scripts/annotate_write.idapy`, and the only one that
contains write calls.

Scope of this module: `ida_query`, `ida_microcode_cfg`, `ida_type_member_offset`, `ida_patch_plan`
and `ida_annotations` (none of them writes the input or persists anything), `ida_rename_plan` and
`ida_annotations_apply` (the one persistent write path; comments are not here yet), `ida_annotations_purge`
(the only deletion of annotated data: named targets, report first, a confirmation bound to what it reports) and `ida_status`.
"""
from __future__ import annotations

import collections
import datetime
import getpass
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.workspace import safe_path, relative

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
EVIDENCE = APP_DIR / "dataset" / "evidence" / "ida_query"
EVIDENCE.mkdir(parents=True, exist_ok=True)
EVIDENCE_MICROCODE = APP_DIR / "dataset" / "evidence" / "ida_microcode_cfg"
EVIDENCE_MICROCODE.mkdir(parents=True, exist_ok=True)
# The three operations below write their evidence directory on first use (`_write_evidence` creates it),
# so importing this module leaves nothing on disk. Tests patch these names.
EVIDENCE_TYPE_MEMBER = APP_DIR / "dataset" / "evidence" / "ida_type_member_offset"
EVIDENCE_PATCH_PLAN = APP_DIR / "dataset" / "evidence" / "ida_patch_plan"
EVIDENCE_ANNOTATIONS = APP_DIR / "dataset" / "evidence" / "ida_annotations"
EVIDENCE_RENAME_PLAN = APP_DIR / "dataset" / "evidence" / "ida_rename_plan"
EVIDENCE_ANNOTATE_APPLY = APP_DIR / "dataset" / "evidence" / "ida_annotations_apply"
# Annotated data has its OWN root, a sibling of the cache and never inside it: the cache evicts, rebuilds
# and deletes whole slots, and a person's annotations are not re-derivable. Created lazily. Tests patch this name.
ANNOTATED_ROOT = APP_DIR / "dataset" / "ida_annotated"
# Created lazily, on first use: a status call on a machine without IDA must
# not leave an empty directory behind. Tests patch this name.
CACHE_ROOT = APP_DIR / "dataset" / "ida_cache"

_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "query_program.idapy"
_MICROCODE_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "microcode_cfg.idapy"
_PATCH_PLAN_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "patch_plan.idapy"
_ANNOTATE_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "annotate_write.idapy"
_JOB_ENV = "LIEBERT_IDA_JOB"
_JOB_SCRIPT = "liebert_ida_job.py"
_LOG_NAME = "ida.log"
_DB_NAME = "db.i64"
_RESULT_NAME = "result.json"

# Part of the cache key. Bump it when a launch flag that changes what the
# analysis contains changes (it is "pdb off, worker v1" today), so a database
# built under the old settings is not reused under the new ones.
_ANALYSIS_PROFILE = "p0v1"

_DEFAULT_TIMEOUT_SECONDS = 180
_MIN_TIMEOUT_SECONDS = 5
# Two ceilings, on purpose. A question (a reopen session) is capped at 300 s,
# the same ceiling as the other wrappers. The first analysis of a file is a
# different class of operation: it builds the index once per input content and
# the result is cached, so its cost scales with the size of the binary and is
# paid a single time. Capping it at 300 s would make a large binary permanently
# unqueryable (the analysis would time out on every attempt and be discarded), a
# capability gap rather than an honest limit. Exceeding either ceiling still
# returns TIMEOUT. `timeout_seconds` is one shared budget clamped to the larger
# ceiling; a reopen session never gets more than the smaller one.
_MAX_QUERY_TIMEOUT_SECONDS = 300
_MAX_CREATE_TIMEOUT_SECONDS = 600
_STATUS_TIMEOUT_SECONDS = 60
# The microcode session's own ceiling, separate from the question ceiling above
# on purpose: it is this operation's constant, not shared infrastructure. It is
# one reopen session (one or, with the d810 pass, two microcode generations of a
# single function), so it is the same size as a question; the first analysis
# keeps the larger create ceiling. Exceeding it is TIMEOUT, never "no microcode".
_MAX_MICROCODE_TIMEOUT_SECONDS = 300
# The reopen-session ceilings of the type-member lookup and the patch plan. Each is its own constant,
# like the microcode one: these are these operations' numbers, not shared infrastructure. Both are one
# temporary reopen session that reads a type or plans one patch (the patch plan also hashes the cached
# database twice), so they are the same size as a question; the first analysis keeps the create ceiling.
# Exceeding one is TIMEOUT, never "no such member" or "no plan".
_MAX_TYPE_MEMBER_TIMEOUT_SECONDS = 300
_MAX_PATCH_PLAN_TIMEOUT_SECONDS = 300
# The annotation write path's own session ceiling (one session: a plan read, the write, or the read-back
# of the stored version; the first analysis of a file keeps the create ceiling). TIMEOUT, never "nothing written".
_MAX_ANNOTATE_TIMEOUT_SECONDS = 300
# The annotated byte ceiling: annotated data is never evicted, so a full budget refuses the next write
# and asks for a decision. 2 GiB is a reasonable starting value, not a measured threshold.
_ANNOTATED_BUDGET_DEFAULT = 2 * 1024 ** 3
# How long a file move that Windows refuses because another handle is open is retried (100 ms apart).
_PROMOTE_RETRY_SECONDS = 10
_LABEL = re.compile(r"[A-Za-z0-9._-]{1,48}")
_NEW_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,254}")
_RENAME_MAX_ITEMS = 200
_PLAN_SCHEMA = 1
_VERSION_DIR = re.compile(r"v(\d{6})")
# idat's own stdout/stderr is a few KB; the result travels in a file.
_MAX_OUTPUT_CHARS = 1024 * 1024
_MIN_RESPONSE_CHARS = 2000
_MAX_RESPONSE_CHARS = 1_000_000
_MAX_RESULTS_CAP = 1000

_CACHE_BUDGET_DEFAULT = 5 * 1024 ** 3  # 5 GiB
# Never evict a slot touched this recently: another process may have it open,
# and deleting a database under a live idat is worse than a late eviction.
_EVICT_SKIP_RECENT_SECONDS = 300
_LOCK_WAIT_SECONDS = 30
_LOCK_STALE_SECONDS = _MAX_CREATE_TIMEOUT_SECONDS + 120
# A lock whose recorded owner is still a running process is honoured past the
# age above (a suspended or very slow owner is not a dead one), but not forever:
# no legitimate call holds a slot for twice the stale age, so beyond this the
# pid is taken to have been reused or the owner to be hung.
_LOCK_OWNER_ALIVE_CEILING_SECONDS = 2 * _LOCK_STALE_SECONDS
_SLOT_NAME = re.compile(r"^[0-9a-f]{64}(?:\.[A-Za-z0-9]+)+$")

# The eight levels microcode passes through (MMAT_ZERO is "not built yet", not a level).
_MICROCODE_MATURITIES = (
    "MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", "MMAT_CALLS",
    "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3", "MMAT_LVARS",
)
_MICROCODE_DEFAULT_MAXIMUM = 2000
_MICROCODE_INSTRUCTION_CAP = 5000
_MICROCODE_DEFAULT_D810_PROJECT = "default_instruction_only"
_D810_PROJECT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
# d810 writes log files about 70 characters deeper than the state directory it is
# given; past Windows' 260-character path limit its logging setup fails to
# configure. A state directory path longer than this is not used.
_D810_STATE_PATH_LIMIT = 150
# A worker error that names a missing prerequisite rather than a failed analysis.
_MICROCODE_ERROR_STATUS = {"D810_NOT_INSTALLED": "TOOL_MISSING"}

# A struct, union or member name: a C identifier, with the `::` of a C++ scope allowed in a type name.
_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
_MEMBER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TYPE_NAME_MAX = 256

_PATCH_OPERATIONS = ("force_branch", "nop_out")
_PATCH_ADDRESS_KINDS = ("va", "rva", "file_offset")
_PATCH_INSTRUCTION_CAP = 64
# The patch plan's own domain refusals carry their name as the status, the same vocabulary the rizin
# planner uses, so a caller switching engines reads the same answer.
_PATCH_PLAN_ERROR_STATUS = {name: name for name in (
    "NOT_A_CONDITIONAL_BRANCH", "NO_DIRECT_BRANCH_TARGET", "TARGET_TOO_FAR_FOR_ORIGINAL_LENGTH",
    "NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW", "ASSEMBLY_FAILED", "DISASSEMBLY_FAILED", "INVALID_ADDRESS",
    "INVALID_ADDRESS_KIND", "ADDRESS_OUTSIDE_SECTION", "ARCHITECTURE_NOT_SUPPORTED")}

# The write log of annotations made through this package (one append-only JSON-lines file per input
# hash, in the annotated root; each record carries the scope label). `ida_annotations` only READS it and
# never starts IDA for that; `ida_annotations_apply` is the one writer.
_ANNOTATION_LOG_SUFFIX = ".writes.jsonl"
_ANNOTATION_DEFAULT_MAXIMUM = 500
_ANNOTATION_MAX_ENTRIES = 5000
# A line longer than this is not read into memory; it is counted as unreadable.
_ANNOTATION_MAX_LINE_BYTES = 1024 * 1024

_KNOWN_INSTALL_GLOBS = ("IDA Professional 9*", "IDA Pro 9*")

_ALLOWED_OPERATIONS = (
    "summary", "list_functions", "segments", "function_at_address",
    "decompile_function", "xrefs_to", "imports_exports", "strings",
)
_DATABASE_SUFFIXES = {".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"}
_LOOSE_COMPONENTS = (".id0", ".id1", ".id2", ".nam", ".til")

# Lines in idat's log, stdout or stderr that mean the run did not work even if
# the process exited 0. Matched case-insensitively.
_FATAL_MARKERS = (
    "fatal error",
    "failed to initialize ida",
    "internal error",
    "invalid non-printable character",
    "traceback (most recent call last)",
    "switch '-o' can be used only when loading a new file",
)
# Any of these in the log means a symbol lookup left the machine (or was at
# least attempted). With -Opdb:off none is expected.
_NETWORK_MARKERS = ("pdb: downloading", "http://", "https://")

_WORKER_BOOKKEEPING = {"ok", "tool", "script_completed", "engine_input_sha256", "engine_input_md5"}
# Operations whose `offset` indexes the result sequence, so a response that
# had to be trimmed can report where to resume.
_PAGED_OPERATIONS = {"list_functions", "segments", "xrefs_to", "imports_exports", "strings"}


# --------------------------------------------------------------------------
# binary resolution and the shared response helpers
# --------------------------------------------------------------------------

def _binary_in(directory):
    for name in ("idat.exe", "idat"):
        candidate = Path(directory) / name
        if candidate.is_file():
            return str(candidate)
    return None


def _resolved_by_and_binary():
    """(how it was found, path) or (None, None). Order: IDAT_EXE, IDA_HOME,
    PATH, then the installer's default folders. Never raises."""
    try:
        explicit = os.getenv("IDAT_EXE", "").strip()
        if explicit:
            p = Path(explicit)
            if p.is_file():
                return "IDAT_EXE", str(p)
            found = _binary_in(p) if p.is_dir() else None
            if found:
                return "IDAT_EXE", found
        home = os.getenv("IDA_HOME", "").strip()
        if home:
            found = _binary_in(home)
            if found:
                return "IDA_HOME", found
        found = shutil.which("idat") or shutil.which("idat.exe")
        if found:
            return "PATH", found
        roots = [os.environ.get("ProgramFiles", ""), "C:/Program Files"]
        for root in dict.fromkeys(r for r in roots if r):
            for pattern in _KNOWN_INSTALL_GLOBS:
                for folder in sorted(Path(root).glob(pattern), reverse=True):
                    found = _binary_in(folder)
                    if found:
                        return "known_install", found
    except OSError:
        pass
    return None, None


def _ida_binary():
    return _resolved_by_and_binary()[1]


def ida_available():
    return _ida_binary() is not None


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _tool_missing(tool):
    return _j({
        "ok": False, "tool": tool, "status": "TOOL_MISSING",
        "required_capability": "IDA Pro 9.x with a licensed decompiler, headless (idat)",
        "detail": (
            "idat was not found. Set IDAT_EXE to its full path (or its install folder), set "
            "IDA_HOME to the install folder, or put idat on PATH. IDA is commercial and is not "
            "shipped or downloaded by this package. The fallback this module checks is the "
            "installer's default 'IDA Professional 9*' folder under Program Files."
        ),
    })


def _checked_path(path, tool, echo_path=True):
    """`echo_path=False` is for the operations whose answers never carry the target's name or path."""
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
    except (OSError, ValueError) as exc:     # a path the operating system cannot even resolve (an embedded NUL, ...)
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": type(exc).__name__})
    if not p.is_file():
        body = {"ok": False, "tool": tool, "status": "NOT_FOUND"}
        if echo_path:
            body["path"] = str(path)
        else:
            body["detail"] = "The input is not a file inside the workspace."
        return None, _j(body)
    return p, None


def _clamp(value, low, high, default):
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _redact(text, *, work=None, target=None):
    """Make idat output safe to return or store: the licence line, home-directory
    paths, the account name, and the scratch and input paths. The log of a
    default IDA install prints a line starting 'License:' with the licence id."""
    text = text or ""
    for needle, token in ((str(work) if work else "", "<WORK>"), (str(target) if target else "", "<INPUT>")):
        if needle:
            for variant in {needle, needle.replace("\\", "/"), needle.replace("/", "\\")}:
                text = text.replace(variant, token)
    text = re.sub(r"(?im)^([ \t]*)licen[sc]e\b.*$", r"\1License: <REDACTED>", text)
    text = re.sub(r"[A-Za-z]:(?:\\+|/)Users(?:\\+|/)[^\\/\s\"'<>|:*?]+", "<HOME>", text, flags=re.I)
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = ""
    if len(user) >= 3:
        text = re.sub(rf"(?<![A-Za-z0-9]){re.escape(user)}(?![A-Za-z0-9])", "<USER>", text, flags=re.I)
    return text


def _tail(text, work=None, target=None, limit=2000):
    return _redact(text, work=work, target=target)[-limit:]


def _sha256_md5(path):
    # md5 is only compared with the digest idat records for its input; it is not a security use
    # (and `usedforsecurity=False` keeps it working on FIPS-restricted Python builds).
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


# --------------------------------------------------------------------------
# the cache: one slot per input hash, LRU eviction, scratch-then-promote
# --------------------------------------------------------------------------

def _cache_root():
    return Path(CACHE_ROOT)


def _cache_budget_bytes():
    try:
        return max(1, int(os.getenv("LIEBERT_IDA_CACHE_BYTES", _CACHE_BUDGET_DEFAULT)))
    except (TypeError, ValueError):
        return _CACHE_BUDGET_DEFAULT


_ENGINE_FILES = ("ida.dll", "ida64.dll", "libida.so", "libida64.so", "libida.dylib", "libida64.dylib")


def _engine_tag(exe):
    """A short, stable label of the analysis engine that would build a database:
    a hash of the name, size and modification time of the resolved idat binary
    and of the IDA kernel library beside it. IDA is not asked for its version
    (that costs a launch), so an update or reinstall changes the tag and a
    database built by the old engine is not reused. A binary that cannot be
    inspected gives the fixed tag `unversioned`, never an exception."""
    parts = []
    try:
        if exe:
            folder = Path(exe).parent
            for candidate in (Path(exe), *(folder / name for name in _ENGINE_FILES)):
                if candidate.is_file():
                    info = candidate.stat()
                    parts.append(f"{candidate.name}:{info.st_size}:{info.st_mtime_ns}")
    except OSError:
        parts = []
    if not parts:
        return "unversioned"
    return "e" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def _slot_dir(sha256, exe=None):
    """Cache key: sha256(input) + analysis profile + engine tag."""
    return _cache_root() / f"{sha256}.{_ANALYSIS_PROFILE}.{_engine_tag(exe or _ida_binary())}"


def _lock_path(slot):
    return slot.with_name(slot.name + ".lock")


def _dir_bytes(directory):
    total = 0
    for root, _dirs, files in os.walk(directory):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


class _ProcessProbe:
    """Is a process id still a running process? True / False, or None when
    this host cannot tell (then the caller falls back to the lock's age).
    One method per platform so each branch can be tested on its own."""

    @staticmethod
    def alive(pid, create_time=None):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return None
        if pid <= 0:
            return None
        try:
            import psutil  # a declared dependency; the branches below cover its absence
        except ImportError:
            return _ProcessProbe._windows(pid) if os.name == "nt" else _ProcessProbe._posix(pid)
        return _ProcessProbe._psutil(psutil, pid, create_time)

    @staticmethod
    def _psutil(psutil, pid, create_time):
        try:
            if not psutil.pid_exists(pid):
                return False
            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                return False
            if create_time is not None and abs(proc.create_time() - float(create_time)) > 2.0:
                return False  # the id now belongs to a different process
            return True
        except psutil.NoSuchProcess:
            return False
        except (psutil.Error, OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _windows(pid):
        # Never os.kill here: on Windows it TERMINATES the process for any signal
        # other than the console-control ones, so `os.kill(pid, 0)` is not a probe.
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                error = ctypes.GetLastError()
                if error == 87:       # ERROR_INVALID_PARAMETER: no such process
                    return False
                return True if error == 5 else None  # access denied: it exists
            try:
                code = ctypes.c_ulong()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return None
                return code.value == 259  # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:  # noqa: BLE001 - a probe that cannot run says "unknown"
            return None

    @staticmethod
    def _posix(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return None


class _SlotLock:
    """Ownership of one slot lock: a file holding {pid, token, started,
    create_time}. The token is unique to the acquiring call, and `release`
    removes the file only while it still carries that token, so a call whose
    lock was taken over as stale can never delete its successor's lock."""

    def __init__(self, path, token):
        self.path = path
        self.token = token

    @staticmethod
    def raw(path):
        try:
            return Path(path).read_text(encoding="utf-8")
        except (OSError, ValueError):
            return None

    @staticmethod
    def read(path):
        """The owner record, or None when absent, unreadable or not ours to
        parse (an older or half-written lock then falls back to its age)."""
        text = _SlotLock.raw(path)
        try:
            record = json.loads(text) if text else None
        except ValueError:
            return None
        return record if isinstance(record, dict) else None

    @staticmethod
    def create(path, token):
        """Create the lock with its record already inside it, atomically:
        the record is written to a private file and hard-linked into place,
        which fails with FileExistsError if a lock exists (O_EXCL semantics)
        and never exposes a half-written file. A file system without hard
        links falls back to O_EXCL; a reader that catches that file mid-write
        sees an unparseable record and judges the lock by its age."""
        create_time = None
        try:
            import psutil
            create_time = psutil.Process(os.getpid()).create_time()
        except Exception:  # noqa: BLE001
            pass
        record = json.dumps({"pid": os.getpid(), "token": token, "started": time.time(),
                             "create_time": create_time})
        staging = path.with_name(f"{path.name}.{token[:8]}.tmp")
        staging.write_text(record, encoding="utf-8")
        try:
            try:
                os.link(str(staging), str(path))
            except FileExistsError:
                raise
            except OSError:
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(record)
        finally:
            try:
                staging.unlink()
            except OSError:
                pass

    def release(self):
        owner = self.read(self.path)
        if owner is None or owner.get("token") != self.token:
            return False  # taken over, or already gone: not ours to delete
        try:
            self.path.unlink()
        except OSError:
            return False
        return True


def _lock_is_live(lock):
    """Whether the lock still excludes others. By age alone for a lock with no
    readable owner; otherwise the owner process decides: one that is gone
    leaves a lock that goes stale after `_LOCK_STALE_SECONDS`, one that is
    still running keeps it until `_LOCK_OWNER_ALIVE_CEILING_SECONDS`."""
    try:
        age = time.time() - lock.stat().st_mtime
    except OSError:
        return False
    owner = _SlotLock.read(lock)
    if owner is not None and owner.get("pid") is not None:
        alive = _ProcessProbe.alive(owner.get("pid"), owner.get("create_time"))
        if alive is True:
            return age < _LOCK_OWNER_ALIVE_CEILING_SECONDS
    return age < _LOCK_STALE_SECONDS


def _acquire_slot_lock(slot, cancellation_token):
    """Exclusive, cross-process lock for one slot. Returns a `_SlotLock` or
    None when another live process holds it past the bounded wait."""
    lock = _lock_path(slot)
    lock.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            _SlotLock.create(lock, token)
        except FileExistsError:
            seen = _SlotLock.raw(lock)
            if not _lock_is_live(lock):
                # Re-read just before removing: if the lock changed since it was
                # judged stale, someone else already took it over and it is theirs.
                if _SlotLock.raw(lock) == seen:
                    try:
                        lock.unlink()
                    except OSError:
                        pass
                continue
            if time.monotonic() >= deadline or bool(getattr(cancellation_token, "cancelled", False)):
                return None
            time.sleep(0.25)
            continue
        return _SlotLock(lock, token)


def _release_slot_lock(lock):
    """Release only a lock that is still this call's own."""
    lock.release()


def _evict_slot(slot):
    shutil.rmtree(slot, ignore_errors=True)
    return not slot.exists()


def _slot_is_healthy(slot):
    db = slot / _DB_NAME
    try:
        if not db.is_file() or db.stat().st_size <= 0:
            return False
    except OSError:
        return False
    stem = db.stem
    # Loose unpacked components beside a packed database are the residue of a
    # session that did not exit cleanly; reopening such a state has been
    # observed to crash idat ("internal error"), so the slot is rebuilt.
    return not any((slot / f"{stem}{suffix}").exists() for suffix in _LOOSE_COMPONENTS)


def _touch_meta(slot, sha256, *, created=False):
    meta = slot / "meta.json"
    record = {}
    try:
        record = json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    now = time.time()
    record.update({"sha256": sha256, "profile": _ANALYSIS_PROFILE, "engine": slot.name.rsplit(".", 1)[-1], "last_used": now})
    if created or "created" not in record:
        record["created"] = now
    try:
        meta.write_text(json.dumps(record), encoding="utf-8")
    except OSError:
        pass


def _slot_last_used(slot):
    try:
        return (slot / "meta.json").stat().st_mtime
    except OSError:
        try:
            return slot.stat().st_mtime
        except OSError:
            return 0.0


def _enforce_cache_budget(keep):
    """LRU-evict whole slots until the cache is within budget. `keep` is the
    slot this call just used; it is never evicted, nor is any slot touched
    within the skip window or holding a live lock. Returns
    (evicted_slot_names, evicted_bytes, budget_bytes)."""
    budget = _cache_budget_bytes()
    root = _cache_root()
    if not os.path.isdir(root):
        return [], 0, budget
    slots = []
    total = 0
    # os.path.isdir, not Path.is_dir: before Python 3.13 Path.is_dir re-raises a
    # PermissionError from stat(); os.path.isdir treats any OSError as "not a directory".
    for child in root.iterdir():
        if not (os.path.isdir(child) and _SLOT_NAME.match(child.name)):
            continue
        size = _dir_bytes(child)
        total += size
        slots.append((child, size, _slot_last_used(child)))
    if total <= budget:
        return [], 0, budget
    now = time.time()
    evicted, freed = [], 0
    for slot, size, used in sorted(slots, key=lambda s: s[2]):
        if total <= budget:
            break
        if slot == keep or (now - used) < _EVICT_SKIP_RECENT_SECONDS or _lock_is_live(_lock_path(slot)):
            continue
        if _evict_slot(slot):
            total -= size
            freed += size
            evicted.append(slot.name)
    return evicted, freed, budget


def _cache_summary():
    root = _cache_root()
    slots = 0
    total = 0
    if os.path.isdir(root):
        for child in root.iterdir():
            if os.path.isdir(child) and _SLOT_NAME.match(child.name):
                slots += 1
                total += _dir_bytes(child)
    return {"root": _display_cache_root(), "slot_count": slots, "total_bytes": total,
            "budget_bytes": _cache_budget_bytes(), "key": f"sha256(input file) + profile {_ANALYSIS_PROFILE} + engine tag (size/mtime of idat and the IDA kernel library)"}


def _display_cache_root():
    try:
        return _cache_root().relative_to(APP_DIR).as_posix()
    except ValueError:
        return "<cache root>"


# --------------------------------------------------------------------------
# one idat launch and its four-signal verdict
# --------------------------------------------------------------------------

class _EnvironmentFailure(Exception):
    """The local environment refused something the wrapper needs (the cache
    directory, the packaged worker, process launch). Carries the OSError so
    the response can name its type and errno without claiming anything about
    the input file, the cached database or IDA's analysis."""

    def __init__(self, error, exc):
        super().__init__(error)
        self.error = error
        self.exc = exc

    def body(self, tool, **extra):
        text = _redact(getattr(self.exc, "strerror", None) or type(self.exc).__name__)
        body = {
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": self.error,
            "environment_error": {"type": type(self.exc).__name__, "errno": getattr(self.exc, "errno", None),
                                  "strerror": text},
            "detail": (
                "A local operating-system error stopped this call before it produced a result. It is a "
                "statement about this machine's environment (a path, a permission, a file system), not "
                "about the input file, the cached databases or what IDA would have found. No answer was "
                "produced; fix the environment and retry."
            ),
        }
        body.update(extra)
        return body


def _write_worker(work, worker_source=None):
    """Copy the worker into the work directory, BOM-free. IDAPython refuses a
    script that starts with a UTF-8 BOM (`invalid non-printable character
    U+FEFF`), so the bytes are normalised here instead of trusting the file.
    `worker_source` is the microcode worker for that operation; the default is
    the query worker."""
    try:
        source = (worker_source or _WORKER_SOURCE).read_bytes()
    except OSError as exc:
        raise _EnvironmentFailure("IDA_WORKER_UNREADABLE", exc) from exc
    if source.startswith(b"\xef\xbb\xbf"):
        source = source[3:]
    (work / _JOB_SCRIPT).write_bytes(source.replace(b"\r\n", b"\n"))


def _job_environment(job_path):
    env = dict(os.environ)
    env[_JOB_ENV] = str(job_path)
    return env


def _launch(exe, work, job, *, mode, target, timeout_seconds, cancellation_token, empty_database=False,
            worker_source=None):
    """Run idat once in `work`. `mode` is "create" (analyse `target` into
    work/db.i64) or "reopen" (open `target`, an existing database).
    Returns (process_result, command)."""
    _write_worker(work, worker_source)
    job_path = work / "job.json"
    try:
        job_path.write_text(json.dumps(job), encoding="utf-8")
    except OSError as exc:
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
    common = ["-A", "-Opdb:off", f"-L{_LOG_NAME}", f"-S{_JOB_SCRIPT}"]
    if mode == "create":
        command = [exe, "-A", "-c", "-Opdb:off", f"-L{_LOG_NAME}", f"-o{_DB_NAME}", f"-S{_JOB_SCRIPT}"]
        if empty_database:
            command[2:2] = ["-t", "-pmetapc"]
        else:
            command.append(str(target))
    else:
        command = [exe, *common, str(target)]
    try:
        cp = run_bounded_process(
            command, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
            cwd=work, environment=_job_environment(job_path), max_output_chars=_MAX_OUTPUT_CHARS,
        )
    except OSError as exc:  # the file exists but the OS would not start it (not executable, denied, ...)
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
    return cp, command


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _verdict(cp, work, db_path, *, expect_database, expect_operation=None, require_discard=False):
    """The four signals, read together. Returns (data, failure_error,
    signals). `failure_error` is None only when every signal agrees.

    The log is one of the four, so it has to be readable and non-empty to
    count: a log that could not be read, or that idat never wrote to, is
    IDA_LOG_UNREADABLE rather than "no fatal marker found". When
    `expect_operation` is given, the result must be an answer to THAT
    operation. `require_discard` (a reopen session) makes the worker's
    `database_changes_discarded: true` mandatory: false or absent is a failure,
    so a worker that could not set up the discard guarantee never yields a
    success."""
    try:
        log = Path(work / _LOG_NAME).read_text(encoding="utf-8", errors="replace")
        log_readable = True
    except OSError:
        log, log_readable = "", False
    combined = "\n".join((log, cp.stdout or "", cp.stderr or "")).lower()
    markers = sorted({m for m in _FATAL_MARKERS if m in combined})
    network = sorted({m for m in _NETWORK_MARKERS if m in log.lower()})
    try:
        db_bytes = db_path.stat().st_size if db_path.is_file() else 0
    except OSError:
        db_bytes = 0
    loose = sorted(p.name for p in work.iterdir() if p.suffix.lower() in _LOOSE_COMPONENTS) if work.is_dir() else []
    result_path = work / _RESULT_NAME
    result_present = result_path.is_file()
    data, parse_error, completed = None, None, False
    operation_matches = expect_operation is None
    if result_present:
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
            completed = isinstance(data, dict) and data.get("script_completed") is True
            if expect_operation is not None:
                operation_matches = completed and data.get("operation") == expect_operation
        except (OSError, ValueError) as exc:
            parse_error = f"{type(exc).__name__}: {exc}"
    signals = {
        "exit_code": cp.returncode,
        "log_present": bool(log),
        "log_readable": log_readable,
        "log_fatal_markers": markers,
        "database_present": db_bytes > 0,
        "database_bytes": db_bytes,
        "loose_components": loose,
        "result_file_present": result_present,
        "result_script_completed": completed,
        "result_operation_matches": operation_matches,
        "network_lookup_detected": bool(network),
    }
    if require_discard:
        signals["database_changes_discarded"] = data.get("database_changes_discarded") if completed else None
    if parse_error:
        return None, "RESULT_PARSE_FAILED", {**signals, "parse_error": parse_error}
    if cp.returncode not in (0, None):
        return data, "IDA_EXITED_NONZERO", signals
    if markers:
        return data, "IDA_LOG_REPORTS_FAILURE", signals
    if not log_readable or not log:
        return data, "IDA_LOG_UNREADABLE", signals
    if not result_present:
        return None, "IDA_NO_OUTPUT", signals
    if not completed:
        return None, "IDA_OUTPUT_INCOMPLETE", signals
    if not operation_matches:
        return data, "IDA_RESULT_OPERATION_MISMATCH", signals
    if require_discard and data.get("database_changes_discarded") is not True:
        return data, "DATABASE_CHANGES_NOT_DISCARDED", signals
    if expect_database and (db_bytes <= 0 or loose):
        return data, "IDA_NO_DATABASE", signals
    return data, None, signals


def _failure_response(tool, status, error, *, operation, signals, cp, work, target, extra=None):
    body = {
        "ok": False, "tool": tool, "status": status, "error": error, "operation": operation,
        "signals": signals,
        "log_tail": _tail(_read_text(work / _LOG_NAME), work, target),
        "stdout_tail": _tail(getattr(cp, "stdout", ""), work, target),
        "stderr_tail": _tail(getattr(cp, "stderr", ""), work, target),
        "detail": (
            "Success is read from four signals together (exit status, log, database file, result file), "
            "never from the exit code alone. Nothing from this attempt was kept in the database cache."
        ),
    }
    if extra:
        body.update(extra)
    return body


def _provenance(sha256, md5, data):
    engine_sha = (data or {}).get("engine_input_sha256")
    engine_md5 = (data or {}).get("engine_input_md5")
    if engine_sha:
        status = "VERIFIED" if str(engine_sha).lower() == sha256 else "MISMATCH"
    elif engine_md5:
        status = "VERIFIED" if str(engine_md5).lower() == md5 else "MISMATCH"
    else:
        status = "UNVERIFIABLE"
    return {"status": status, "requested_sha256": sha256, "engine_input_sha256": engine_sha or None}


# --------------------------------------------------------------------------
# response shaping
# --------------------------------------------------------------------------

def _fit(body, max_chars):
    """Shrink `body` until its rendered JSON fits `max_chars`, so the result
    is always a parseable document (a raw string slice can cut one in half):
    long pseudocode is cut first, then list-valued fields lose their last
    element one at a time. Returns True if anything was dropped."""
    trimmed = False
    rendered = _j(body)
    text = body.get("decompiled")
    if len(rendered) > max_chars and isinstance(text, str):
        keep = max(500, len(text) - (len(rendered) - max_chars) - 200)
        if keep < len(text):
            body["decompiled"] = text[:keep]
            trimmed = True
            rendered = _j(body)
    list_keys = [k for k in ("items", "exports") if isinstance(body.get(k), list)]
    while len(rendered) > max_chars and any(body.get(k) for k in list_keys):
        for key in list_keys:
            if body.get(key):
                body[key].pop()
                break
        trimmed = True
        rendered = _j(body)
    return trimmed


def _walk_limit_text(walk_limit):
    """Name the ceiling that tripped and its value, never just 'partial'."""
    walk = walk_limit.get("walk")
    reason = walk_limit.get("reason")
    visited = walk_limit.get("items_visited")
    if reason == "MAX_ITEMS":
        return (f"{walk} walk stopped at its item ceiling of {walk_limit.get('max_items')} items "
                f"({visited} visited); the listing is incomplete")
    if reason == "MAX_SECONDS":
        return (f"{walk} walk stopped at its time ceiling of {walk_limit.get('max_seconds')} s "
                f"({visited} items visited); the listing is incomplete")
    return f"{walk} walk stopped early ({reason}); the listing is incomplete"


def _success_response(tool, p, sha256, md5, operation, data, *, cache_state, signals, invocation,
                      max_chars, evidence, note=None, omit_path=False):
    body = {k: v for k, v in data.items() if k not in _WORKER_BOOKKEEPING}
    limitations = []
    walk_limit = body.get("walk_limit")
    if walk_limit:
        limitations.append(_walk_limit_text(walk_limit))
    if body.get("instructions_truncated"):
        limitations.append(
            f"the microcode listing was cut at {body.get('instructions_returned')} of "
            f"{body.get('instruction_count')} instructions (max_results); block edges are complete"
        )
    head = {
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p), "target_sha256": sha256,
        "database_cache": cache_state,
        "invocation": invocation,
        "provenance": _provenance(sha256, md5, data),
        "signals": signals,
        "pdb_lookup": "disabled",
    }
    if omit_path:
        del head["path"]       # the answer is keyed by the hash; the target's name and path stay out of it
    merged = {**head, **body}
    merged["internal_evidence_name"] = evidence[0]
    merged["evidence_write_error"] = evidence[1]
    merged["evidence_access"] = (
        "The worker's full unmodified JSON result was saved; this response is the same data, "
        "trimmed only if it exceeded max_chars."
    )
    merged["note"] = note or (
        "Results come from IDA's analysis of the file as loaded, with symbol-server lookups "
        "disabled; names that exist only in a PDB are absent. Auto-analysis can miss or "
        "mis-split code in obfuscated or packed targets, so an absent function or xref is not "
        "proof of absence. Decompiled pseudocode is IDA's reading, not the original source."
    )
    trimmed = _fit(merged, max_chars)
    if trimmed:
        limitations.append(
            f"response-size ceiling reached: the answer was cut to fit max_chars={max_chars}; "
            "the evidence file holds the full result"
        )
        merged["truncated"] = True
    if limitations:
        merged["status"] = "PARTIAL"
        merged["limitations"] = limitations
        if trimmed:
            _fit(merged, max_chars)      # the fields just added count against the bound too
    if trimmed and isinstance(merged.get("items"), list):
        if operation in _PAGED_OPERATIONS:
            merged["next_offset"] = invocation["offset"] + len(merged["items"])   # where to resume
        for key in ("returned_count", "count"):
            if key in merged:
                merged[key] = len(merged["items"])
    return merged


def _write_evidence(p, operation, data, directory=None, stem=None):
    """`stem` replaces the input's file name in the evidence file's name (a caller that keeps the
    target's name out of its answers passes the start of the input hash)."""
    out = (directory or EVIDENCE) / f"{stem or p.stem}_{uuid.uuid4().hex[:8]}_{operation}.json"
    error = None
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        _evidence_index_record_write(out)
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"
    except Exception:  # noqa: BLE001
        pass
    return out.name, error


# --------------------------------------------------------------------------
# ida_query
# --------------------------------------------------------------------------

def ida_query(path, operation="summary", query="", max_results=200, offset=0,
              timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, max_chars=60000, cancellation_token=None):
    """Ask IDA one read-only question about `path` (a PE or other binary IDA
    can load; an IDA database file is refused, see below).

    `operation` (default "summary"):

    * `summary`             function / segment counts, processor, bitness, file
                            type, decompiler availability.
    * `list_functions`      name / address / signature, paged.
    * `segments`            name, range, permissions, paged.
    * `function_at_address` `query` is a symbol name or a virtual address
                            (e.g. "0x140001000"); resolves the containing function.
    * `decompile_function`  same `query`; returns Hex-Rays pseudocode.
    * `xrefs_to`            `query` is a symbol name or virtual address; any
                            target, including import-table slots. Calls are
                            flagged (`is_call`); jumps are not calls.
    * `imports_exports`     IDA's own import resolution plus entry points.
    * `strings`             IDA's string list; a non-empty `query` filters
                            case-insensitively on the decoded text.

    `max_results` is clamped to 1..1000; `offset` pages the operations that
    list; `next_offset` is null once the end is reached. `timeout_seconds` is
    one budget for the whole call, clamped to 5..600. The first analysis of a
    file may use all of it (up to 600 s: it runs once per file content and is
    cached); the session that answers the question never runs longer than
    300 s. A timed-out analysis is discarded, never half-cached.
    The first call on a file runs two idat sessions (analyse and save, then
    the question); later calls run one.
    `max_chars` bounds the response without breaking its JSON.

    Status vocabulary matches the repo's other static-tool wrappers: OK,
    PARTIAL (a walk limit or the response bound cut the answer short; says
    which), TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED (IDA ran and failed, an argument it would reject, a
    database file as input, a busy cache slot, an input-identity mismatch,
    a result that does not answer the operation asked or that lacks the
    discard guarantee, or a local environment error: an unusable cache
    directory, an unreadable packaged worker, an idat the operating system
    would not start -- those carry `environment_error` with the errno and make
    no claim about the input or about IDA), READ_FAILED (the input could not
    be read), RESULT_PARSE_FAILED.
    """
    tool = "ida_query"
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    p, fail = _checked_path(path, tool)
    if fail:
        return fail
    if operation not in _ALLOWED_OPERATIONS:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "UNKNOWN_OPERATION",
            "given": str(operation), "accepted": list(_ALLOWED_OPERATIONS),
        })
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
            "path": relative(p),
            "detail": (
                "An existing IDA database is not accepted as input. IDA rewrites a database on every "
                "open, so its content hash changes per call, and caching copies of it is exactly how "
                "tens of gigabytes of identical databases accumulate. Pass the original binary; the "
                "cache keys on that file's hash."
            ),
        })
    if not _WORKER_SOURCE.is_file():
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "The packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem)."})
    timeout_seconds = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    max_results = _clamp(max_results, 1, _MAX_RESULTS_CAP, 200)
    offset = _clamp(offset, 0, 10 ** 9, 0)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    query = "" if query is None else str(query)
    invocation = {"operation": operation, "query": query, "max_results": max_results, "offset": offset,
                  "timeout_seconds": timeout_seconds}

    return _locked_call(tool, exe, p, invocation, max_chars, cancellation_token)


def _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile=None):
    """The part every question shares: hash the input, take its slot lock, run
    the staged session(s) under it, enforce the cache budget on success. Returns
    the finished JSON string. `profile` (None for `ida_query`) carries what a
    different operation changes: its worker, the extra job fields, the ceiling
    of its reopen session, its evidence directory and its note."""
    try:
        sha256, md5 = _sha256_md5(p)
    except OSError as exc:
        return _j({
            "ok": False, "tool": tool, "status": "READ_FAILED", "error": "IDA_INPUT_UNREADABLE",
            "path": relative(p),
            "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                  "strerror": _redact(exc.strerror or type(exc).__name__)},
            "detail": "The input file could not be read; no claim is made about its content.",
        })
    slot = _slot_dir(sha256, exe)
    try:
        lock = _acquire_slot_lock(slot, cancellation_token)
    except OSError as exc:
        return _j(_EnvironmentFailure("IDA_CACHE_ROOT_UNUSABLE", exc).body(
            tool, target_sha256=sha256, invocation=invocation))
    if lock is None:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_CACHE_SLOT_BUSY",
            "target_sha256": sha256, "invocation": invocation,
            "detail": "Another process is analysing this exact file; retry when it finishes.",
        })
    try:
        outcome = _query_locked(exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile)
        if isinstance(outcome, dict) and outcome.get("ok") is True:
            outcome_evict = _enforce_cache_budget(slot)
            if outcome_evict[0]:
                outcome["cache_evicted_slots"] = outcome_evict[0]
                outcome["cache_evicted_bytes"] = outcome_evict[1]
                outcome["cache_budget_bytes"] = outcome_evict[2]
        return _j(outcome)
    except OSError as exc:  # the cache directory failed under us (full disk, vanished, denied)
        return _j(_EnvironmentFailure("IDA_CACHE_IO_ERROR", exc).body(
            tool, target_sha256=sha256, invocation=invocation))
    finally:
        _release_slot_lock(lock)


def ida_microcode_cfg(path, function, maturity="MMAT_LVARS", deobfuscate=False,
                      d810_project=_MICROCODE_DEFAULT_D810_PROJECT, max_results=_MICROCODE_DEFAULT_MAXIMUM,
                      timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, max_chars=60000, cancellation_token=None):
    """Read one function's microcode from IDA as a control-flow graph: blocks,
    their predecessors and successors, their instructions, every address in the
    shared five-field address form (file offset, RVA, VA, image base, section).

    `function` is a symbol name or a virtual address inside the function.
    `maturity` is one of the eight levels `MMAT_GENERATED`, `MMAT_PREOPTIMIZED`,
    `MMAT_LOCOPT`, `MMAT_CALLS`, `MMAT_GLBOPT1`, `MMAT_GLBOPT2`, `MMAT_GLBOPT3`,
    `MMAT_LVARS` (default; the `MMAT_` prefix may be left off). The answer says
    which level was actually reached. `max_results` bounds the instructions
    LISTED (1..5000); block edges are always complete, and a cut is reported as
    PARTIAL with the totals.

    **Raw is the default.** `deobfuscate` must be exactly `True` or `False` (a
    truthy string is refused, not guessed at). With `False` no third-party code
    runs and the answer is `microcode_kind: "raw"`, Hex-Rays' own output.

    With `deobfuscate=True` the third-party d810 plugin's optimizer is installed
    for the generation and the answer is `microcode_kind: "d810_pass"`. It says,
    under `deobfuscation`: which d810 project was loaded (`project.loaded`, with
    its active rule counts; `d810_project` picks it, default
    `default_instruction_only`, a different project is a different rule set),
    which rules and optimizers fired and how often (`rules_fired`,
    `optimizers_fired`), the raw microcode of the same function from the same
    session (`raw_baseline`) and whether the output differs from it
    (`transformed`). A rule firing is not proof that the function was
    obfuscated, and a project whose rules did not fire is not proof that it
    wasn't. d810 missing is `TOOL_MISSING`; d810 present but not startable (no
    such project, did not load, optimizer not started) is `ANALYSIS_LIMITED`.
    In neither case does this return raw microcode in place of what was asked.
    The pass is not a devirtualiser: it targets instruction-level obfuscation (MBA, opaque predicates,
    constant folding) and control-flow flattening patterns, and does not handle virtualised (VM-based)
    code. Whether its rules fire on a given function is a measurement; that the rewritten control flow
    is correct is not checked here.
    d810's own `options.json` writes go to a private directory; the user's copy
    is hashed before and after and the result reports it (`config_isolation`).

    The first analysis of a file, the discard guarantee (the session is
    temporary, nothing it does is saved), the slot lock, the four-signal
    verdict and the status vocabulary are `ida_query`'s. `timeout_seconds` is
    one budget for the whole call, clamped to 5..600; the session that builds
    the microcode never runs longer than 300 s (`_MAX_MICROCODE_TIMEOUT_SECONDS`).
    The worker's full result is saved under `dataset/evidence/ida_microcode_cfg/`.
    """
    tool = "ida_microcode_cfg"
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    p, fail = _checked_path(path, tool)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
            "path": relative(p),
            "detail": "An existing IDA database is not accepted as input; pass the original binary (see ida_query).",
        })
    if not isinstance(function, str) or not function.strip() or len(function) > 512:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "FUNCTION_REQUIRED",
                   "detail": "`function` is a symbol name or a virtual address, a non-empty string of at most 512 characters."})
    level = str(maturity).strip().upper() if isinstance(maturity, str) else ""
    if level and not level.startswith("MMAT_"):
        level = "MMAT_" + level
    if level not in _MICROCODE_MATURITIES:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "UNKNOWN_MATURITY",
                   "given": str(maturity), "accepted": list(_MICROCODE_MATURITIES)})
    if deobfuscate is not True and deobfuscate is not False:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "INVALID_DEOBFUSCATE_ARGUMENT",
                   "given": repr(deobfuscate)[:80],
                   "detail": "`deobfuscate` must be exactly True or False. It is never inferred from a string or a number."})
    if not isinstance(d810_project, str) or not _D810_PROJECT_NAME.match(d810_project):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "INVALID_D810_PROJECT",
                   "given": repr(d810_project)[:80],
                   "detail": "A d810 project is named by its configuration file name (letters, digits, '_', '.', '-')."})
    if not (_MICROCODE_WORKER_SOURCE.is_file() and _WORKER_SOURCE.is_file()):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "A packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem)."})
    timeout_seconds = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    max_results = _clamp(max_results, 1, _MICROCODE_INSTRUCTION_CAP, _MICROCODE_DEFAULT_MAXIMUM)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    function = function.strip()
    invocation = {"operation": "microcode_cfg", "function": function, "maturity": level,
                  "deobfuscate": deobfuscate, "d810_project": d810_project if deobfuscate else None,
                  "max_results": max_results, "offset": 0, "timeout_seconds": timeout_seconds}

    def label_problem(data):
        """The result must say what it is, in the terms this call asked for."""
        kind, info = data.get("microcode_kind"), data.get("deobfuscation")
        info = info if isinstance(info, dict) else {}
        if not isinstance(data.get("items"), list) or not data["items"] or not data.get("instruction_count"):
            return "MICROCODE_EMPTY"
        if deobfuscate:
            project = info.get("project") if isinstance(info.get("project"), dict) else {}
            labelled = (kind == "d810_pass" and info.get("requested") is True and info.get("pass") == "d810"
                        and isinstance(info.get("rules_fired"), list) and isinstance(info.get("transformed"), bool)
                        and bool(project.get("loaded")) and isinstance(info.get("config_isolation"), dict))
            return None if labelled else "DEOBFUSCATION_RESULT_UNLABELLED"
        return None if kind == "raw" and info.get("requested") is False else "MICROCODE_KIND_MISMATCH"

    note = (
        "Microcode of one function from IDA, generated in a temporary session of the cached database "
        "(nothing was saved). "
        + ("This is a d810 pass: the microcode was produced WITH d810's optimizer installed, so it is "
           "transformed output, not Hex-Rays' own. `deobfuscation` names the project that was loaded, the "
           "rules that fired and whether the output differs from the raw microcode of the same function. "
           "Which rules fired is a measurement of the rules on this function, not a verdict that it was "
           "obfuscated or that the result is correct. The pass does not handle virtualised (VM-based) code."
           if deobfuscate else
           "This is raw microcode: no third-party pass ran. Hex-Rays can fail or time out on obfuscated "
           "functions, so an absent block or a missing function is not proof of absence.")
    )
    profile = {
        "tool": tool, "worker": _MICROCODE_WORKER_SOURCE, "reopen_ceiling": _MAX_MICROCODE_TIMEOUT_SECONDS,
        "job_fields": {"query": function, "maturity": level, "deobfuscate": deobfuscate,
                       "d810_project": d810_project, "max_results": max_results},
        "isolated_state_dir": deobfuscate, "evidence_dir": EVIDENCE_MICROCODE,
        "error_status": _MICROCODE_ERROR_STATUS, "validate": label_problem, "note": note,
    }
    return _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile)


def ida_type_member_offset(path, struct_name=None, member_name=None, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
                           max_chars=60000, cancellation_token=None):
    """The byte offset of one direct member of a named struct or union, read from the type
    information the cached IDA database holds (its own types plus the type libraries it loaded):
    a settled fact in place of a remembered or guessed displacement.

    `struct_name` is the type's name as the type information spells it, `_LIST_ENTRY` or
    `LIST_ENTRY` (both spellings are tried: Windows headers declare `_FOO` and typedef `FOO`); a
    C identifier, with `::` allowed between scope parts. `member_name` is a direct member's name: a
    member of a nested or anonymous type is not searched. The answer gives the offset in bits and in
    bytes (`byte_aligned` says whether the two agree; a bit-field is not byte aligned), the member's
    size and type text, the type's size and whether it is a union.

    **A negative is an answer about the type information, not about the program.** A type that is not
    in the loaded information (`TYPE_NOT_FOUND`), a name that is not a struct or union
    (`TYPE_NOT_STRUCT_OR_UNION`) and a type without that member (`MEMBER_NOT_FOUND`, which lists the
    members it does have, cut at a stated limit) are three different refusals, each `ANALYSIS_LIMITED`.
    A found offset is the loaded type library's layout; it is not proof that the analysed program was
    built against that definition (version, packing and compiler can differ).

    Runs in the same temporary reopen session as a question: nothing it does is saved, the first
    analysis of a file, the slot lock, the four-signal verdict and the statuses are `ida_query`'s.
    `timeout_seconds` is one budget for the whole call, clamped to 5..600; the session that reads
    the type never runs longer than 300 s (`_MAX_TYPE_MEMBER_TIMEOUT_SECONDS`). The answer carries no
    path or file name of the input, only its hash. The worker's full result is saved under
    `dataset/evidence/ida_type_member_offset/`. The offset is not an address, so the shared address
    form does not apply.
    """
    tool = "ida_type_member_offset"
    for field, value, pattern, example in (
            ("struct_name", struct_name, _TYPE_NAME, "_LIST_ENTRY"), ("member_name", member_name, _MEMBER_NAME, "Blink")):
        if not isinstance(value, str) or len(value) > _TYPE_NAME_MAX or not pattern.match(value):
            return _j({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": field.upper() + "_REQUIRED",
                "field": field, "given": repr(value)[:80],
                "detail": (
                    f"`{field}` is required: a non-empty string of at most {_TYPE_NAME_MAX} characters that is a "
                    f"C identifier (letters, digits and '_', not starting with a digit"
                    + ("; '::' may join scope parts" if field == "struct_name" else "")
                    + f"), for example `{example}`."
                ),
            })
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
                   "detail": "An existing IDA database is not accepted as input; pass the original binary (see ida_query)."})
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    if not _WORKER_SOURCE.is_file():
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "The packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem)."})
    timeout_seconds = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    invocation = {"operation": "type_member_offset", "struct_name": struct_name, "member_name": member_name,
                  "max_results": 1, "offset": 0, "timeout_seconds": timeout_seconds}

    def incomplete(data):
        """A found member must carry its offset as integers; anything else is not an answer."""
        numbers = (data.get("offset_bits"), data.get("offset_bytes"), data.get("member_size_bits"))
        return None if all(isinstance(n, int) and not isinstance(n, bool) for n in numbers) else "TYPE_MEMBER_RESULT_INCOMPLETE"

    profile = {
        "tool": tool, "reopen_ceiling": _MAX_TYPE_MEMBER_TIMEOUT_SECONDS,
        "job_fields": {"query": json.dumps({"struct_name": struct_name, "member_name": member_name})},
        "evidence_dir": EVIDENCE_TYPE_MEMBER, "evidence_on_refusal": True, "omit_path": True, "strip_fields": ("items", "count"),
        "validate": incomplete,
        "refusal_note": (
            "A type or member that is absent is a statement about the type information loaded in this "
            "database (its own types and the type libraries it loaded), not about the program."
        ),
        "note": (
            "The offset comes from the type information of the cached database (its own types plus the "
            "type libraries it loaded), read in a temporary session: nothing was saved. It is that "
            "definition's layout, not proof that the analysed program was built against it. Only direct "
            "members are searched."
        ),
    }
    return _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile)


def ida_patch_plan(path, address=None, operation=None, address_kind="va", instruction_count=1,
                   timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, max_chars=60000, cancellation_token=None):
    """PLAN, never apply, a byte-level patch at `address` of a PE: the bytes an explicit apply step
    would write and how IDA reads them. The input file is never written. Same operations, address
    forms and answer shape as `rizin_patch_plan`, so a caller can switch engines.

    `operation` is `force_branch` (the conditional jump at `address` becomes an unconditional jump to
    the same target, padded with NOPs to the same length, so every later address stays put) or
    `nop_out` (`instruction_count` instructions, 1..64, become NOPs of exactly their combined length).
    `address_kind` is `va` (default), `rva` or `file_offset`. x86 and x86-64 only.

    **This is not a pure read.** The plan calls IDA's patch API in an in-memory copy of the database,
    and undoes it before the session ends, inside the same temporary session as a question (nothing
    is saved). It therefore carries a cache-violation status: the cached database file is hashed
    before and after the session, the two hashes are in the answer (`signals.database_integrity`), and
    if they differ the answer is `PATCH_PLAN_CACHE_VIOLATION`, the slot is deleted and no plan is
    returned. `plan_only` is always true and `applied_to_file` always false.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, UNKNOWN_OPERATION, INVALID_ADDRESS,
    INVALID_ADDRESS_KIND, ADDRESS_OUTSIDE_SECTION, ARCHITECTURE_NOT_SUPPORTED, NOT_A_CONDITIONAL_BRANCH,
    NO_DIRECT_BRANCH_TARGET, TARGET_TOO_FAR_FOR_ORIGINAL_LENGTH, NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW,
    ASSEMBLY_FAILED, DISASSEMBLY_FAILED, PATCH_PLAN_CACHE_VIOLATION, TIMEOUT, CANCELLED, ANALYSIS_LIMITED,
    RESULT_PARSE_FAILED. `timeout_seconds` is one budget for the whole call, clamped to 5..600; the
    session that plans never runs longer than 300 s (`_MAX_PATCH_PLAN_TIMEOUT_SECONDS`). The answer
    carries no path or file name of the input, only its hash; the worker's full result is saved under
    `dataset/evidence/ida_patch_plan/`.
    """
    tool = "ida_patch_plan"
    if not isinstance(operation, str) or operation.strip().lower() not in _PATCH_OPERATIONS:
        return _j({"ok": False, "tool": tool, "status": "UNKNOWN_OPERATION", "error": "UNKNOWN_OPERATION",
                   "operation": repr(operation)[:80], "allowed": list(_PATCH_OPERATIONS),
                   "detail": "`operation` is required and is one of the names in `allowed`."})
    patch_operation = operation.strip().lower()
    kind = address_kind.strip().lower() if isinstance(address_kind, str) else None
    if kind not in _PATCH_ADDRESS_KINDS:
        return _j({"ok": False, "tool": tool, "status": "INVALID_ADDRESS_KIND", "error": "INVALID_ADDRESS_KIND",
                   "given": repr(address_kind)[:80], "accepted": list(_PATCH_ADDRESS_KINDS)})
    try:
        if isinstance(address, bool) or not isinstance(address, (int, str)):
            raise ValueError
        value = address if isinstance(address, int) else int(address.strip(), 0)
        if not 0 <= value < 1 << 64:
            raise ValueError
    except ValueError:
        return _j({"ok": False, "tool": tool, "status": "INVALID_ADDRESS", "error": "INVALID_ADDRESS",
                   "given": repr(address)[:80], "address_kind": kind,
                   "detail": "`address` is required: a non-negative integer, or a string such as \"0x140001002\" "
                             "or \"4198402\", read as an address of the kind named by `address_kind`."})
    if isinstance(instruction_count, bool) or not isinstance(instruction_count, int):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "INVALID_INSTRUCTION_COUNT",
                   "given": repr(instruction_count)[:80],
                   "detail": f"`instruction_count` is an integer from 1 to {_PATCH_INSTRUCTION_CAP}; only `nop_out` uses it."})
    count = max(1, min(instruction_count, _PATCH_INSTRUCTION_CAP))
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
                   "detail": "An existing IDA database is not accepted as input; pass the original binary (see ida_query)."})
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    if not (_PATCH_PLAN_WORKER_SOURCE.is_file() and _WORKER_SOURCE.is_file()):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "A packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem)."})
    timeout_seconds = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    invocation = {"operation": "patch_plan", "patch_operation": patch_operation, "address": hex(value),
                  "address_kind": kind, "instruction_count": count if patch_operation == "nop_out" else None,
                  "max_results": 1, "offset": 0, "timeout_seconds": timeout_seconds}

    def incomplete(data):
        """A plan must say it is only a plan and carry matching, non-empty hex byte strings."""
        original, patched = data.get("original_bytes"), data.get("patched_bytes")
        hexes = all(isinstance(b, str) and b and len(b) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", b) for b in (original, patched))
        sound = (data.get("plan_only") is True and data.get("applied_to_file") is False and hexes
                 and len(original) == len(patched) and isinstance(data.get("address"), dict))
        return None if sound else "PATCH_PLAN_RESULT_INCOMPLETE"

    profile = {
        "tool": tool, "worker": _PATCH_PLAN_WORKER_SOURCE, "reopen_ceiling": _MAX_PATCH_PLAN_TIMEOUT_SECONDS,
        "job_fields": {"address": hex(value), "address_kind": kind, "patch_operation": patch_operation,
                       "instruction_count": count},
        "evidence_dir": EVIDENCE_PATCH_PLAN, "evidence_on_refusal": True, "omit_path": True, "strip_fields": ("items", "count"),
        "error_status": _PATCH_PLAN_ERROR_STATUS, "validate": incomplete,
        "verify_database_unchanged": True, "cache_violation_error": "PATCH_PLAN_CACHE_VIOLATION",
        "note": (
            "A PLAN: the bytes a separate apply step would write and IDA's reading of them. Nothing was "
            "written to the input file. IDA's patch API was called in an in-memory copy of the cached "
            "database inside a temporary session; the database file's hash before and after is in "
            "`signals.database_integrity`. The disassembly of the patched bytes is IDA's reading, and "
            "whether the patched program behaves as intended is not checked."
        ),
    }
    return _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile)


def ida_annotations(path, max_results=_ANNOTATION_DEFAULT_MAXIMUM, max_chars=60000):
    """Read the log of annotations (renames and comments) this package has recorded for `path`'s
    content, keyed by the input file's SHA-256. A plain file read: no analysis engine is started, IDA
    does not need to be installed, and no database is opened.

    The newest `max_results` entries (1..5000) are returned in the order they were written. When
    there are more, the answer is `PARTIAL`, says `truncated: true` and how many older entries were
    left out (`omitted_older_entries`); the same when `max_chars` forces entries out (the oldest go
    first). Lines of the log that are not readable JSON objects are counted in `unreadable_lines`
    and are never silently dropped; a log with no readable line at all is `ANALYSIS_LIMITED`
    (`ANNOTATION_LOG_UNREADABLE`), not an empty list.

    `found: false` (no log for this hash) means this package recorded no annotation for this input.
    It does NOT mean the database has no names or comments of its own: IDA's analysis and any loaded
    symbols are not logged here. The only operation that writes annotations is `ida_annotations_apply`,
    so no log exists until one has been applied. The log lives in the annotated root (its own tree,
    never inside the cache), one file per input hash; each record carries its scope label. The answer carries the input's hash, not its name or path, and every
    string from the log passes the same scrubbing as IDA's output (home paths, account name).

    Status vocabulary: OK, PARTIAL, PATH_REFUSED, NOT_FOUND, READ_FAILED, ANALYSIS_LIMITED.
    """
    tool = "ida_annotations"
    if isinstance(max_results, bool) or not isinstance(max_results, int):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "INVALID_MAX_RESULTS",
                   "given": repr(max_results)[:80],
                   "detail": f"`max_results` is an integer from 1 to {_ANNOTATION_MAX_ENTRIES} "
                             f"(default {_ANNOTATION_DEFAULT_MAXIMUM}); a value outside the range is clamped."})
    limit = _clamp(max_results, 1, _ANNOTATION_MAX_ENTRIES, _ANNOTATION_DEFAULT_MAXIMUM)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
                   "detail": "An existing IDA database is not accepted as input; pass the original binary (see ida_query)."})
    try:
        sha256 = _sha256_md5(p)[0]
    except OSError as exc:
        return _j({"ok": False, "tool": tool, "status": "READ_FAILED", "error": "IDA_INPUT_UNREADABLE",
                   "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                         "strerror": _redact(exc.strerror or type(exc).__name__)},
                   "detail": "The input file could not be read; no claim is made about its annotations."})
    log = _journal_path(sha256)       # the annotated root's journal, not the cache's: see ANNOTATED_ROOT
    kept = collections.deque(maxlen=limit)
    total = unreadable = oversized = 0
    present = True
    try:
        with open(log, "rb") as handle:
            while True:
                line = handle.readline(_ANNOTATION_MAX_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > _ANNOTATION_MAX_LINE_BYTES and not line.endswith(b"\n"):
                    while True:           # an oversized line is skipped to its end without being held
                        rest = handle.readline(_ANNOTATION_MAX_LINE_BYTES)
                        if not rest or rest.endswith(b"\n"):
                            break
                    unreadable += 1
                    oversized += 1
                    continue
                if not line.strip():
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                except (ValueError, RecursionError):   # ValueError covers UnicodeDecodeError and json's decode error
                    unreadable += 1
                    continue
                if not isinstance(record, dict):
                    unreadable += 1
                    continue
                total += 1
                kept.append(record)
    except FileNotFoundError:
        present = False
    except OSError as exc:
        return _j({"ok": False, "tool": tool, "status": "READ_FAILED", "error": "ANNOTATION_LOG_UNREADABLE_OS",
                   "target_sha256": sha256,
                   "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                         "strerror": _redact(exc.strerror or type(exc).__name__)},
                   "detail": "The annotation log exists but could not be read; no claim is made about its content."})
    if present and total == 0 and unreadable:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "ANNOTATION_LOG_UNREADABLE",
                   "target_sha256": sha256, "unreadable_lines": unreadable,
                   "detail": "The annotation log exists but not one line of it is a readable JSON object. This is "
                             "not 'no annotations'; the log needs inspection."})

    def scrub(value):
        """Strings from the log go through the same redaction as IDA's output."""
        if isinstance(value, str):
            return _redact(value)
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, dict):
            return {str(k): scrub(v) for k, v in value.items()}
        return value

    entries = [scrub(r) for r in kept]
    body = {
        "ok": True, "tool": tool, "status": "OK", "target_sha256": sha256,
        "engine_started": False, "found": present, "log_name": log.name if present else None,
        "invocation": {"max_results": limit, "max_chars": max_chars},
        "total_entries": total, "returned_entries": len(entries), "omitted_older_entries": total - len(entries),
        "unreadable_lines": unreadable, "entries": entries,
        "note": (
            "Annotations this package recorded for this input content; IDA's own names, comments and any "
            "loaded symbols are not in this log. "
            + ("" if present else "No log exists for this input hash: this package has recorded no annotation for it. "
               "The only operation that writes annotations is ida_annotations_apply, so a log does not exist until "
               "one has been applied.")
        ),
    }
    evidence = _write_evidence(p, "annotations", body, EVIDENCE_ANNOTATIONS, stem=sha256[:16])
    body["internal_evidence_name"], body["evidence_write_error"] = evidence
    limitations = []
    if body["omitted_older_entries"]:
        limitations.append(f"the newest {len(entries)} of {total} entries are listed (max_results={limit}); "
                           f"{total - len(entries)} older entries were left out")
    if unreadable:
        limitations.append(f"{unreadable} line(s) of the log are not readable JSON objects and are not listed"
                           + (f" ({oversized} longer than {_ANNOTATION_MAX_LINE_BYTES} bytes)" if oversized else ""))
    if limitations:
        body["status"], body["limitations"], body["truncated"] = "PARTIAL", limitations, bool(body["omitted_older_entries"])
    cut = False
    while len(_j(body)) > max_chars and body["entries"]:
        drop = max(1, len(body["entries"]) // 10)
        del body["entries"][:drop]       # the oldest go first
        cut = True
        body["returned_entries"] = len(body["entries"])
        body["omitted_older_entries"] = total - len(body["entries"])
    if cut:
        body["status"], body["truncated"] = "PARTIAL", True
        limitations = [x for x in limitations if not x.startswith("the newest ")]
        limitations.insert(0, f"response-size ceiling reached: the newest {len(body['entries'])} of {total} entries "
                              f"are listed (max_chars={max_chars}); the evidence file holds every entry that was read")
        body["limitations"] = limitations
        while len(_j(body)) > max_chars and body["entries"]:     # the limitation text counts against the bound too
            del body["entries"][0]
            body["returned_entries"] = len(body["entries"])
            body["omitted_older_entries"] = total - len(body["entries"])
    return _j(body)


class _StageFailure(Exception):
    """One idat launch did not produce a usable answer; carries the response."""

    def __init__(self, body):
        super().__init__(body.get("error"))
        self.body = body


def _run_stage(exe, p, sha256, md5, slot, *, mode, operation, invocation, timeout_seconds, cancellation_token,
               profile=None):
    """One idat launch in its own scratch directory and its four-signal
    verdict. `mode` "create" analyses `p` into a new database and, only if
    every signal agrees, promotes it into `slot`; "reopen" queries the cached
    database in place. Returns (data, signals, provenance); raises
    _StageFailure with the finished response body otherwise.

    The scratch directory is always deleted, so a failed first analysis
    leaves neither a database nor the unpacked .id0/.id1/.id2/.nam/.til
    components IDA scatters while it works."""
    profile = profile or {}
    tool = profile.get("tool", "ida_query")
    # The first analysis is always the query worker's `summary`; only the reopen
    # session runs the operation's own worker, with its own job fields and ceiling.
    creating = mode == "create"
    reopen_ceiling = profile.get("reopen_ceiling", _MAX_QUERY_TIMEOUT_SECONDS)
    work = slot / f"work-{uuid.uuid4().hex[:8]}"
    work.mkdir()
    job = {"output": str(work / _RESULT_NAME), "operation": operation, "query": invocation.get("query", ""),
           "max_results": invocation["max_results"], "offset": invocation["offset"], "mode": mode}
    state_dir = None
    if not creating:
        job.update(profile.get("job_fields") or {})
    # An operation that mutates the session's in-memory database on purpose (the patch plan) is held to
    # a measurement, not to the flag alone: the cached database file is hashed before and after.
    verify = not creating and bool(profile.get("verify_database_unchanged"))
    db_before = None
    try:
        if verify:
            try:
                db_before = _sha256_md5(slot / _DB_NAME)[0]
            except OSError as exc:
                raise _StageFailure(_EnvironmentFailure("IDA_DATABASE_UNREADABLE", exc).body(
                    tool, invocation=invocation, target_sha256=sha256)) from exc
        if not creating and profile.get("isolated_state_dir"):
            # d810's private configuration directory (see microcode_cfg.idapy): a short path next to
            # the slots, or under the OS temp directory when the cache root is too deep; removed below.
            state_dir = _cache_root() / f"d810-{uuid.uuid4().hex[:8]}"
            if len(str(state_dir)) > _D810_STATE_PATH_LIMIT:
                state_dir = Path(tempfile.gettempdir()) / f"liebert-d810-{uuid.uuid4().hex[:8]}"
            state_dir.mkdir(parents=True)
            job["d810_state_dir"] = str(state_dir)
        timeout_seconds = min(timeout_seconds, _MAX_CREATE_TIMEOUT_SECONDS if creating else reopen_ceiling)
        try:
            cp, _command = _launch(
                exe, work, job, mode=mode, target=p if creating else slot / _DB_NAME,
                timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
                worker_source=None if creating else profile.get("worker"),
            )
        except _EnvironmentFailure as failure:
            # Nothing was launched, so the database was not touched: the slot stays.
            raise _StageFailure(failure.body(tool, invocation=invocation, target_sha256=sha256)) from failure
        if cp.cancelled or cp.timed_out:
            if not creating:
                _evict_slot(slot)  # killed mid-session: do not trust the file
            body = {"ok": False, "tool": tool, "status": "CANCELLED" if cp.cancelled else "TIMEOUT",
                    "invocation": invocation, "target_sha256": sha256,
                    "error": "IDA_CANCELLED_PROCESS_TREE_TERMINATED" if cp.cancelled
                    else "IDA_TIMEOUT_PROCESS_TREE_TERMINATED"}
            if cp.timed_out:
                body["timeout_seconds"] = timeout_seconds
                body["timed_out_stage"] = "analysis" if creating else "query"
                body["stage_ceiling_seconds"] = _MAX_CREATE_TIMEOUT_SECONDS if creating else reopen_ceiling
                body["detail"] = (
                    "The first analysis of a large file can exceed the timeout; an incomplete analysis is "
                    "discarded, so the next call starts over. Do not read a timeout as 'nothing found'."
                )
            raise _StageFailure(body)
        integrity = None
        if verify:
            violation = profile.get("cache_violation_error", "CACHE_VIOLATION")
            try:
                db_after = _sha256_md5(slot / _DB_NAME)[0]
            except OSError:
                db_after = None
            integrity = {"database_sha256_before": db_before, "database_sha256_after": db_after,
                         "unchanged": db_after == db_before}
            if db_after != db_before:
                # The guarantee that this session leaves the cached database as it found it did not hold.
                # The slot is dropped (it is rebuilt from the input on the next call), and the answer is
                # withheld even if the worker reported a plan.
                _evict_slot(slot)
                raise _StageFailure({
                    "ok": False, "tool": tool, "status": violation, "error": violation,
                    "invocation": invocation, "target_sha256": sha256, "database_integrity": integrity,
                    "detail": (
                        "The cached database file differed after the session (or could not be read again), "
                        "although the session was marked temporary. The cache slot was deleted and no plan is "
                        "returned; the next call analyses the input again."
                    ),
                })
        data, error, signals = _verdict(
            cp, work, (work / _DB_NAME) if creating else (slot / _DB_NAME), expect_database=creating,
            expect_operation=operation, require_discard=not creating,
        )
        if integrity is not None:
            signals["database_integrity"] = integrity
        if error:
            # A reopen whose result is missing, or is not a trustworthy answer
            # (wrong operation, no discard guarantee), may have left the
            # database in a state nobody vouches for: the slot is dropped.
            if not creating and (not signals["result_script_completed"] or error in (
                    "IDA_RESULT_OPERATION_MISMATCH", "DATABASE_CHANGES_NOT_DISCARDED")):
                _evict_slot(slot)
            extra = {"invocation": invocation, "target_sha256": sha256}
            if isinstance(data, dict) and data.get("error"):
                extra["worker_error"] = data.get("error")
                if data.get("detail"):
                    extra["worker_detail"] = _redact(str(data["detail"]), work=work, target=p)[:2000]
            raise _StageFailure(_failure_response(
                tool, "RESULT_PARSE_FAILED" if error == "RESULT_PARSE_FAILED" else "ANALYSIS_LIMITED", error,
                operation=operation, signals=signals, cp=cp, work=work, target=p, extra=extra,
            ))
        provenance = _provenance(sha256, md5, data)
        if provenance["status"] == "MISMATCH":
            _evict_slot(slot)
            raise _StageFailure({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_INPUT_HASH_MISMATCH",
                "target_sha256": sha256, "provenance": provenance, "invocation": invocation, "signals": signals,
                "detail": "idat's recorded input is not the file that was hashed; refusing to return a result computed over other bytes.",
            })
        if creating:
            os.replace(work / _DB_NAME, slot / _DB_NAME)
            _touch_meta(slot, sha256, created=True)
        else:
            _touch_meta(slot, sha256)
        return data, signals, provenance
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if state_dir is not None:
            shutil.rmtree(state_dir, ignore_errors=True)


def _query_locked(exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile=None):
    profile = profile or {}
    tool = profile.get("tool", "ida_query")
    reopen_ceiling = profile.get("reopen_ceiling", _MAX_QUERY_TIMEOUT_SECONDS)
    operation = invocation["operation"]
    total = invocation["timeout_seconds"]
    deadline = time.monotonic() + total
    slot.mkdir(parents=True, exist_ok=True)
    # Under the lock, any scratch directory here is an abandoned earlier attempt.
    for stale in slot.glob("work-*"):
        shutil.rmtree(stale, ignore_errors=True)

    cache_state = "HIT"
    if (slot / _DB_NAME).exists() and not _slot_is_healthy(slot):
        _evict_slot(slot)
        slot.mkdir(parents=True, exist_ok=True)
        cache_state = "REBUILT"
    elif not (slot / _DB_NAME).exists():
        cache_state = "CREATED"

    def remaining():
        """Whole seconds left of the one shared budget, never rounded up and
        never raised to a floor: a stage that would start with none left is
        not started (see the TIMEOUT below), so the declared budget is the
        most a call can take."""
        return int(deadline - time.monotonic())

    try:
        data = signals = provenance = None
        if cache_state != "HIT":
            # First analysis. Only `summary` runs here: it cannot change the
            # database, so what is cached is the pristine analysis. Any other
            # operation is answered from the reopen session below.
            data, signals, provenance = _run_stage(
                exe, p, sha256, md5, slot, mode="create", operation="summary", invocation=invocation,
                timeout_seconds=total, cancellation_token=cancellation_token, profile=profile,
            )
        if operation != "summary" or cache_state == "HIT":
            left = remaining()
            if left < 1:
                # The first analysis used the whole shared budget. Granting the
                # question a few more seconds would exceed the budget the caller
                # was told, so it is not run. The analysed database was already
                # saved, so a retry is a cache hit.
                raise _StageFailure({
                    "ok": False, "tool": tool, "status": "TIMEOUT", "invocation": invocation,
                    "target_sha256": sha256, "error": "IDA_TIMEOUT_BUDGET_EXHAUSTED",
                    "timeout_seconds": total, "timed_out_stage": "query",
                    "stage_ceiling_seconds": reopen_ceiling,
                    "database_cache": cache_state,
                    "detail": (
                        "The first analysis used the whole timeout_seconds budget, so the question was not "
                        "started. The analysed database is cached: repeat the call (it will be a cache hit). "
                        "Do not read this as 'nothing found'."
                    ),
                })
            data, signals, provenance = _run_stage(
                exe, p, sha256, md5, slot, mode="reopen", operation=operation, invocation=invocation,
                timeout_seconds=left, cancellation_token=cancellation_token, profile=profile,
            )
        if data.get("ok") is False:
            # The worker ran and answered "no" (unknown symbol, decompiler refused). The database is fine.
            refusal = {
                "ok": False, "tool": tool,
                "status": (profile.get("error_status") or {}).get(data.get("error"), "ANALYSIS_LIMITED"),
                "error": data.get("error", "UNKNOWN_ERROR"),
                **{k: v for k, v in data.items() if k not in _WORKER_BOOKKEEPING and k not in ("error", "items", "traceback")},
                "path": relative(p), "target_sha256": sha256, "database_cache": cache_state,
                "invocation": invocation, "provenance": provenance,
                "traceback": _redact(data.get("traceback", ""), work=slot, target=p) or None,
            }
            if profile.get("omit_path"):
                del refusal["path"]
            if "database_integrity" in signals:
                refusal["database_integrity"] = signals["database_integrity"]
            if profile.get("evidence_on_refusal"):
                # The worker's raw refusal is evidence too (it is how a negative can be told from a failure).
                refusal["internal_evidence_name"], refusal["evidence_write_error"] = _write_evidence(
                    p, operation, data, profile.get("evidence_dir"), stem=sha256[:16])
            if profile.get("refusal_note"):
                refusal["note"] = profile["refusal_note"]
            if isinstance(refusal.get("detail"), str):
                refusal["detail"] = _redact(refusal["detail"], work=slot, target=p)   # an exception text can carry a path
            return refusal
        mislabelled = profile["validate"](data) if profile.get("validate") else None
        if mislabelled:
            # The answer does not say what it is (raw or d810-processed) the way the call asked for it.
            # Returning it would present transformed microcode as raw, or the reverse.
            unlabelled = {
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": mislabelled,
                "path": relative(p), "target_sha256": sha256, "database_cache": cache_state,
                "invocation": invocation, "provenance": provenance,
                "detail": "The worker's result did not carry the label this call requires; no result is returned.",
            }
            if profile.get("omit_path"):
                del unlabelled["path"]
            return unlabelled
        evidence = _write_evidence(p, operation, data, profile.get("evidence_dir"),
                                   stem=sha256[:16] if profile.get("omit_path") else None)
        # Fields the worker's shared envelope adds that mean nothing for this operation (an `items` list
        # that is always empty would read as "found nothing") are left out of the answer, not of the evidence.
        data = {k: v for k, v in data.items() if k not in profile.get("strip_fields", ())}
        return _success_response(
            tool, p, sha256, md5, operation, data, cache_state=cache_state, signals=signals,
            invocation=invocation, max_chars=max_chars, evidence=evidence, note=profile.get("note"),
            omit_path=bool(profile.get("omit_path")),
        )
    except _StageFailure as failure:
        return failure.body
    finally:
        if not (slot / _DB_NAME).exists():
            shutil.rmtree(slot, ignore_errors=True)  # a slot with no database is never kept


# --------------------------------------------------------------------------
# the annotation write path: ida_rename_plan + ida_annotations_apply
# --------------------------------------------------------------------------
#
# Lifecycle (Z1): the annotated data lives in its OWN root (`ANNOTATED_ROOT`), never under the cache
# root, with its own lock files. Nothing in this section calls the slot-eviction helper, the cache
# budget enforcement or a recursive delete on a cache path, and nothing in the cache lifecycle is ever
# handed a path under the annotated root; a test reads this section's source and pins both. The one
# recursive delete here (`_remove_owned_work`) removes only work directories this call created itself
# (`scratch-*` or `recovery/<write id>`), and only after a successful promotion or a plain refusal.
#
# Layout under ANNOTATED_ROOT:
#   <sha256>.lock                       one writer at a time per input hash (the cache's lock class)
#   <sha256>.writes.jsonl               the append-only audit journal (what `ida_annotations` reads)
#   annotated-budget.lock               short lock around the byte-budget decision
#   <sha256>/<label>/manifest.json      THE pointer: the one published version (written atomically)
#   <sha256>/<label>/versions/vNNNNNN/db.i64     immutable once placed; never opened in place
#   <sha256>/<label>/recovery/<write id>/        the candidate before promotion (kept if promotion fails)
#   <sha256>/<label>/scratch-<id>/               a throwaway copy for a read session; deleted after

_CONCURRENCY_POLICY = {
    "policy": "base_version_precondition",
    "merges": False,
    "lost_updates": "blocked",
    "summary": (
        "A plan is bound to the annotation version it was read from (base_version and, after the first "
        "write, that version's database hash). Writers of one input hash are serialised by one lock, and "
        "an apply whose plan base is no longer the published version is refused with PRECONDITION_FAILED "
        "(STALE_BASE_VERSION) and writes nothing. Two writers never merge and never silently replace each "
        "other: the later one must plan again. Every item also carries its own `expect` precondition."
    ),
}
_ANNOTATED_STATE_UNVERIFIED = "ANNOTATED_STATE_UNVERIFIED"


def _annotated_root():
    return Path(ANNOTATED_ROOT)


def _roots_apart():
    """The annotated root and the cache root are different, unrelated trees: neither is, contains or
    sits inside the other. If they ever overlap the write path refuses to run, so a misconfiguration
    cannot put annotated data back under the cache's eviction."""
    try:
        annotated = os.path.normcase(os.path.realpath(_annotated_root()))
        cache = os.path.normcase(os.path.realpath(_cache_root()))
    except (OSError, ValueError):
        return False
    return not (annotated == cache or annotated.startswith(cache + os.sep) or cache.startswith(annotated + os.sep))


def _annotated_budget_bytes():
    try:
        return max(1, int(os.getenv("LIEBERT_IDA_ANNOTATED_BYTES", _ANNOTATED_BUDGET_DEFAULT)))
    except (TypeError, ValueError):
        return _ANNOTATED_BUDGET_DEFAULT


def _annotated_total_bytes():
    """Bytes under the annotated root, or None when that cannot be measured (an unreadable entry is
    not skipped: a budget decision over a partial count would be a guess)."""
    root = _annotated_root()
    if not os.path.isdir(root):
        return 0
    total = 0
    problems = []
    for directory, _dirs, files in os.walk(root, onerror=problems.append):
        for name in files:
            try:
                total += os.stat(os.path.join(directory, name)).st_size
            except OSError:
                return None
    return None if problems else total


def _journal_path(sha256):
    return _annotated_root() / f"{sha256}{_ANNOTATION_LOG_SUFFIX}"


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fsync_path(path):
    """Flush a file's data to the disk. Returns an error name, or None."""
    try:
        with open(path, "r+b") as handle:
            os.fsync(handle.fileno())
    except OSError as exc:
        return type(exc).__name__
    return None


def _replace_file(source, destination):
    """`os.replace` with the bounded retry the Windows sharing rules need: another handle on the target
    (winerror 5) or on the source (winerror 32) makes it fail and a retry succeeds once the holder lets
    go. Only those two codes are retried, for at most `_PROMOTE_RETRY_SECONDS`. Returns an error name or None."""
    deadline = time.monotonic() + _PROMOTE_RETRY_SECONDS
    while True:
        try:
            os.replace(source, destination)
            return None
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in (5, 32) or time.monotonic() >= deadline:
                return type(exc).__name__
            time.sleep(0.1)
        except OSError as exc:
            return type(exc).__name__


def _journal_append(sha256, record):
    """Append one record to the audit journal: one JSON object per line, flushed and synced to disk
    before this returns. Returns (True, None) or (False, error name); it never raises. A journal that
    cannot be written is a failed write to the caller's answer, never a hidden one. This is NOT the
    best-effort evidence writer: that one swallows its errors."""
    body = {"schema": 1, "ts": _utc_now(), "target_sha256": sha256, **record}
    body["record_sha256"] = _sha256_text(_canonical(body))
    line = (_canonical(body) + "\n").encode("utf-8")
    path = _journal_path(sha256)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        torn = False
        if path.exists() and path.stat().st_size > 0:
            with open(path, "rb") as reader:
                reader.seek(-1, os.SEEK_END)
                torn = reader.read(1) != b"\n"
        with open(path, "ab") as handle:
            if torn:
                handle.write(b"\n")     # a torn last line must not swallow this record
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        return False, type(exc).__name__
    return True, None


def _journal_records(sha256):
    """(records in file order, count of unreadable lines, error name or None)."""
    path = _journal_path(sha256)
    records, unreadable = [], 0
    try:
        with open(path, "rb") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                except (ValueError, RecursionError):
                    unreadable += 1
                    continue
                if isinstance(record, dict):
                    records.append(record)
                else:
                    unreadable += 1
    except FileNotFoundError:
        return [], 0, None
    except OSError as exc:
        return [], 0, type(exc).__name__
    return records, unreadable, None


def _label_dir(sha256, label):
    """One directory per (input hash, label), named by a digest of the label so that no label can be a
    reserved device name, a dot name or a case variant of another on this file system; the full label is
    stored in the manifest and compared on every access."""
    return _annotated_root() / sha256 / hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]


def _version_file(label_dir, version):
    return label_dir / "versions" / f"v{version:06d}" / _DB_NAME


def _manifest_read(label_dir):
    """(manifest, problem). Absent is (None, None); anything else that is not a well-formed manifest is
    a named problem, never treated as 'absent'."""
    path = label_dir / "manifest.json"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "MANIFEST_UNREADABLE"
    try:
        record = json.loads(text)
    except ValueError:
        return None, "MANIFEST_MALFORMED"
    required = (("version", int), ("db_sha256", str), ("write_id", str), ("sha256", str), ("label", str))
    if not isinstance(record, dict) or not all(isinstance(record.get(k), t) and not isinstance(record.get(k), bool)
                                               for k, t in required) or record["version"] < 1:
        return None, "MANIFEST_MALFORMED"
    return record, None


def _manifest_write(label_dir, record):
    """Publish the pointer: write a private file, sync it, then replace the manifest in one step.
    Returns an error name or None."""
    temporary = label_dir / f"manifest.{uuid.uuid4().hex[:8]}.tmp"
    try:
        temporary.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        return type(exc).__name__
    error = _fsync_path(temporary) or _replace_file(temporary, label_dir / "manifest.json")
    if error:
        try:
            temporary.unlink()
        except OSError:
            pass
    return error


def _file_sha256(path):
    """(hex digest, None) or (None, error name)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return None, type(exc).__name__
    return digest.hexdigest(), None


def _remove_owned_work(path):
    """Delete a work directory this call created: `scratch-*` or `recovery/<write id>`, under the
    annotated root, and nothing else. The only recursive delete in the annotated section."""
    try:
        target = Path(os.path.realpath(path))
        root = Path(os.path.realpath(_annotated_root()))
        inside = root in target.parents
    except (OSError, ValueError):
        return False
    owned = target.name.startswith("scratch-") or target.parent.name == "recovery"
    if not (inside and owned):
        return False
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()


def _refuse(tool, status, error, *, fixable, fix, **extra):
    """A teaching refusal: the field or condition by name, what is accepted, and whether the caller can
    correct it (`fixable` true), must wait and retry (`"retry_later"`) or cannot (`false`: the state or
    the environment needs an operator)."""
    body = {"ok": False, "tool": tool, "status": status, "error": error, "fixable": fixable, "fix": fix}
    body.update(extra)
    return _j(body)


def _annotated_state(sha256, label):
    """The published state of one (input hash, label): (state, None) or (None, refusal parts).
    State: version (0 = nothing published yet), db path, db sha256, the manifest. The manifest is read
    with the file it points at: the version file must exist and hash to the manifest's value, and the
    manifest must name this exact hash and this exact label (not a prefix, not a case variant)."""
    label_dir = _label_dir(sha256, label)
    manifest, problem = _manifest_read(label_dir)
    if problem:
        return None, {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": problem}
    if manifest is None:
        return {"version": 0, "db": None, "db_sha256": None, "manifest": None, "label_dir": label_dir}, None
    if manifest["sha256"] != sha256 or manifest["label"] != label:
        return None, {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": "MANIFEST_NAMES_ANOTHER_SCOPE"}
    db = _version_file(label_dir, manifest["version"])
    digest, failure = _file_sha256(db)
    if failure:
        return None, {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": "VERSION_FILE_UNREADABLE:" + failure}
    if digest != manifest["db_sha256"]:
        return None, {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": "VERSION_FILE_HASH_MISMATCH"}
    return {"version": manifest["version"], "db": db, "db_sha256": digest, "manifest": manifest,
            "label_dir": label_dir}, None


def _recover_pending(sha256):
    """Write-ahead recovery, at the start of every operation that touches this input's annotated data,
    under the lock. A `batch_prepared` record with no `batch_committed` / `batch_aborted` for its write
    id is an interrupted write. The decision uses the files, never the clock:

    * the manifest already publishes that write (same write id and hash): the commit record is all that
      was missing; it is written (`recovered: true`);
    * otherwise the manifest must still be the state the write started from. Then nothing was published:
      the write is closed with an abort record, and the candidate stays where it is (in `recovery/` if it
      was never promoted, in `versions/` if it was promoted but not published; a promoted but unpublished
      version is NOT trusted, because its verification may not have run);
    * a manifest that is neither makes that label `unverified`: reported by name, never repaired.

    Returns {label: reason} for the labels left unverified, plus the list of actions taken."""
    records, _unreadable, error = _journal_records(sha256)
    if error:
        return {"*": "JOURNAL_UNREADABLE:" + error}, []
    closed = {r.get("write_id") for r in records if r.get("event") in ("batch_committed", "batch_aborted")}
    unverified, actions = {}, []
    for prepared in (r for r in records if r.get("event") == "batch_prepared" and r.get("write_id") not in closed):
        label, write_id = prepared.get("label"), prepared.get("write_id")
        if not (isinstance(label, str) and _LABEL.fullmatch(label) and isinstance(write_id, str)):
            unverified["*"] = "PREPARED_RECORD_MALFORMED"
            continue
        label_dir = _label_dir(sha256, label)
        manifest, problem = _manifest_read(label_dir)
        if problem:
            unverified[label] = problem
            continue
        if manifest and manifest["write_id"] == write_id and manifest["db_sha256"] == prepared.get("candidate_db_sha256"):
            ok, why = _journal_append(sha256, {"event": "batch_committed", "write_id": write_id, "label": label,
                                               "version": manifest["version"], "db_sha256": manifest["db_sha256"],
                                               "recovered": True})
            actions.append({"label": label, "write_id": write_id, "action": "commit_recorded" if ok else "commit_pending"})
            if not ok:
                unverified[label] = "JOURNAL_UNWRITABLE:" + str(why)
            continue
        current = manifest["version"] if manifest else 0
        current_hash = manifest["db_sha256"] if manifest else None
        if current != prepared.get("prior_version") or current_hash != prepared.get("prior_db_sha256"):
            unverified[label] = "MANIFEST_DIFFERS_FROM_PRIOR_STATE"
            continue
        number = prepared.get("version")
        promoted = _version_file(label_dir, number if isinstance(number, int) and not isinstance(number, bool) else 0)
        retained = "versions" if promoted.exists() else (
            "recovery" if (label_dir / "recovery" / write_id / _DB_NAME).exists() else "none")
        ok, why = _journal_append(sha256, {"event": "batch_aborted", "write_id": write_id, "label": label,
                                           "reason": "interrupted_before_publication", "retained": retained,
                                           "recovered": True})
        actions.append({"label": label, "write_id": write_id, "action": "abort_recorded" if ok else "abort_pending",
                        "candidate_retained_in": retained})
        if not ok:
            unverified[label] = "JOURNAL_UNWRITABLE:" + str(why)
    return unverified, actions


def _lock_annotated(tool, sha256, cancellation_token):
    """(lock, None) or (None, refusal JSON). One writer at a time per input hash, in the annotated root's
    own lock file: the cache's locks are never taken for annotated data."""
    try:
        lock = _acquire_slot_lock(_annotated_root() / sha256, cancellation_token)
    except OSError as exc:
        return None, _j(_EnvironmentFailure("IDA_ANNOTATED_ROOT_UNUSABLE", exc).body(tool, target_sha256=sha256))
    if lock is None:
        return None, _refuse(tool, "ANALYSIS_LIMITED", "ANNOTATED_BUSY", fixable="retry_later",
                             fix="Another call is writing or planning against this input's annotations; retry when it "
                                 "finishes.", target_sha256=sha256)
    return lock, None


def _overlap_refusal(tool):
    """Refusal JSON when the annotated and cache roots are not separate trees, else None."""
    if _roots_apart():
        return None
    return _refuse(tool, "ANALYSIS_LIMITED", "ANNOTATED_ROOT_OVERLAPS_CACHE", fixable=False,
                   fix="The annotated root and the cache root must be separate trees (the cache evicts and "
                       "deletes; annotations are never evicted). Correct the configuration.")


def _opening_checks(tool, sha256, label, unverified):
    """The checks that precede every annotated operation. Returns a refusal JSON or None."""
    reason = unverified.get(label) or unverified.get("*")
    if reason:
        return _refuse(tool, "ANALYSIS_LIMITED", _ANNOTATED_STATE_UNVERIFIED, fixable=False, reason=reason,
                       target_sha256=sha256, label=label,
                       fix="This scope's recorded state cannot be confirmed. It is not repaired automatically and "
                           "is not served as if it were fine. No operation in this build clears it; an operator "
                           "must inspect the annotated root and the journal.")
    return None


def _copy_pristine(exe, p, sha256, md5, destination, total_seconds, cancellation_token):
    """Copy the analysed pristine database into `destination` (building it first when the slot is
    absent or unhealthy), under the pristine slot's own lock. The pristine file is only read here."""
    slot = _slot_dir(sha256)
    try:
        lock = _acquire_slot_lock(slot, cancellation_token)
    except OSError as exc:
        raise _StageFailure(_EnvironmentFailure("IDA_CACHE_ROOT_UNUSABLE", exc).body(
            "ida_annotations_apply", target_sha256=sha256)) from exc
    if lock is None:
        raise _StageFailure({"ok": False, "tool": "ida_annotations_apply", "status": "ANALYSIS_LIMITED",
                             "error": "IDA_CACHE_SLOT_BUSY", "target_sha256": sha256, "fixable": "retry_later",
                             "fix": "Another process is analysing this exact file; retry when it finishes."})
    try:
        if not _slot_is_healthy(slot):
            invocation = {"operation": "summary", "query": "", "max_results": 1, "offset": 0,
                          "timeout_seconds": total_seconds}
            # The shared first-analysis path writes an evidence file and an answer; here both are keyed by the
            # input hash (`omit_path`, own evidence directory), so the target's name never reaches either.
            outcome = _query_locked(exe, p, sha256, md5, slot, invocation, _MIN_RESPONSE_CHARS, cancellation_token,
                                    {"tool": "ida_annotations_apply", "omit_path": True,
                                     "evidence_dir": EVIDENCE_ANNOTATE_APPLY})
            if not (isinstance(outcome, dict) and outcome.get("ok") is True):
                raise _StageFailure(outcome if isinstance(outcome, dict) else {
                    "ok": False, "tool": "ida_annotations_apply", "status": "ANALYSIS_LIMITED",
                    "error": "PRISTINE_ANALYSIS_FAILED"})
            _enforce_cache_budget(slot)
        try:
            shutil.copyfile(slot / _DB_NAME, destination)
        except OSError as exc:
            raise _StageFailure(_EnvironmentFailure("IDA_DATABASE_UNREADABLE", exc).body(
                "ida_annotations_apply", target_sha256=sha256)) from exc
        _touch_meta(slot, sha256)
    finally:
        _release_slot_lock(lock)


def _copy_into_budget(source, destination, tool, sha256, cancellation_token):
    """Copy a base database to its work location while the byte budget is decided: one short global
    lock, the current total plus this copy against the ceiling, and the copy itself is the reservation
    (it counts in every later total). Raises _StageFailure with a refusal body."""
    try:
        need = os.stat(source).st_size
    except OSError as exc:
        raise _StageFailure(_EnvironmentFailure("IDA_DATABASE_UNREADABLE", exc).body(tool, target_sha256=sha256)) from exc
    try:
        lock = _acquire_slot_lock(_annotated_root() / "annotated-budget", cancellation_token)
    except OSError as exc:
        raise _StageFailure(_EnvironmentFailure("IDA_ANNOTATED_ROOT_UNUSABLE", exc).body(tool, target_sha256=sha256)) from exc
    if lock is None:
        raise _StageFailure(json.loads(_refuse(tool, "ANALYSIS_LIMITED", "ANNOTATED_BUSY", fixable="retry_later",
                                               fix="The annotated byte budget is being decided by another call; retry.")))
    try:
        total, budget = _annotated_total_bytes(), _annotated_budget_bytes()
        if total is None:
            raise _StageFailure(json.loads(_refuse(
                tool, "ANALYSIS_LIMITED", "ANNOTATED_BUDGET_UNVERIFIABLE", fixable=False,
                fix="The bytes held under the annotated root could not be measured (an entry could not be read), "
                    "so no budget decision can be made and nothing was written. Fix the file-system problem.")))
        if total + need > budget:
            raise _StageFailure(json.loads(_refuse(
                tool, "ANALYSIS_LIMITED", "ANNOTATED_BUDGET_EXHAUSTED", fixable=False,
                fix="Annotated data is never evicted automatically, so a full budget needs an operator decision: "
                    "raise LIEBERT_IDA_ANNOTATED_BYTES or remove scopes that are no longer needed. Nothing was written.",
                annotated_bytes=total, needed_bytes=need, budget_bytes=budget)))
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        except OSError as exc:
            raise _StageFailure(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256)) from exc
    finally:
        _release_slot_lock(lock)


def _annotated_session(exe, work, job, *, tool, sha256, md5, invocation, temporary, seconds, cancellation_token):
    """One idat launch of the annotation worker over `work/db.i64`, with the four-signal verdict.
    `temporary` sessions (plan, verify) must report the discard guarantee; the write session must report
    that it did NOT discard (its changes are the point). Returns (data, signals, provenance) or raises
    _StageFailure. Nothing here deletes a database: a failed session leaves its directory for the caller."""
    operation = job["operation"]
    job = {"output": str(work / _RESULT_NAME), "mode": "reopen" if temporary else "write",
           "max_results": 1, "offset": 0, "query": "", **job}
    try:
        cp, _command = _launch(exe, work, job, mode="reopen", target=work / _DB_NAME, timeout_seconds=seconds,
                               cancellation_token=cancellation_token, worker_source=_ANNOTATE_WORKER_SOURCE)
    except _EnvironmentFailure as failure:
        raise _StageFailure(failure.body(tool, invocation=invocation, target_sha256=sha256)) from failure
    if cp.cancelled or cp.timed_out:
        raise _StageFailure({
            "ok": False, "tool": tool, "status": "CANCELLED" if cp.cancelled else "TIMEOUT",
            "invocation": invocation, "target_sha256": sha256, "timeout_seconds": seconds,
            "stage_ceiling_seconds": _MAX_ANNOTATE_TIMEOUT_SECONDS,
            "error": "IDA_CANCELLED_PROCESS_TREE_TERMINATED" if cp.cancelled else "IDA_TIMEOUT_PROCESS_TREE_TERMINATED",
            "detail": "Do not read this as 'no names' or 'nothing written'. A write that was cut off left its "
                      "candidate in the recovery directory and published nothing.",
        })
    data, error, signals = _verdict(cp, work, work / _DB_NAME, expect_database=not temporary,
                                    expect_operation=operation, require_discard=temporary)
    if not error and not temporary and isinstance(data, dict) and data.get("ok") is True \
            and data.get("database_changes_discarded") is not False:
        error = "WRITE_SESSION_REPORTS_DISCARD"
    if error:
        extra = {"invocation": invocation, "target_sha256": sha256}
        if isinstance(data, dict) and data.get("error"):
            extra["worker_error"] = data.get("error")
        raise _StageFailure(_failure_response(
            tool, "RESULT_PARSE_FAILED" if error == "RESULT_PARSE_FAILED" else "ANALYSIS_LIMITED", error,
            operation=operation, signals=signals, cp=cp, work=work, target=None, extra=extra))
    provenance = _provenance(sha256, md5, data)
    if provenance["status"] == "MISMATCH":
        raise _StageFailure({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_INPUT_HASH_MISMATCH",
                             "target_sha256": sha256, "provenance": provenance, "invocation": invocation,
                             "detail": "The database's recorded input is not the file that was hashed; the result was refused."})
    return data, signals, provenance


def _marker_matches(marker, sha256, label, state):
    """Does the annotation marker stored INSIDE the database say what the manifest says? This is the
    provenance check that covers the annotation version, not only the input hash."""
    if state["version"] == 0:
        return marker is None
    manifest = state["manifest"]
    return (isinstance(marker, dict) and marker.get("version") == manifest["version"]
            and marker.get("label") == label and marker.get("write_id") == manifest["write_id"]
            and marker.get("target_sha256") == sha256)


def _valid_label(value):
    return isinstance(value, str) and bool(_LABEL.fullmatch(value))


def _label_refusal(tool, value):
    return _refuse(tool, "ANALYSIS_LIMITED", "LABEL_REQUIRED", fixable=True, field="label", given=repr(value)[:80],
                   accepted=_LABEL.pattern,
                   fix="`label` is required and explicit (it is never inferred): 1 to 48 characters from letters, "
                       "digits, '.', '_' and '-'. It names the scope of the annotations, for example `first-pass`.")


def ida_rename_plan(path, label=None, renames=None, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
                    cancellation_token=None):
    """PLAN renames of items in the analysis database of `path`; nothing is written. The plan is read
    from the annotation scope `label` as it is now (the published annotation version, or the pristine
    analysis when nothing has been published for that label), so each item carries the name it expects to
    find. Apply it with `ida_annotations_apply`.

    `label` is required and explicit: 1 to 48 characters of letters, digits, '.', '_', '-'. `renames` is
    a list of 1 to 200 objects: `address` (an integer or a string such as "0x140001000"), `new_name`
    (a C identifier of at most 255 characters), and optionally `address_kind` (`va` default, `rva` or
    `file_offset`). The address must be the start of an item, and the name must differ from the current one.

    The answer carries `plan` and `plan_sha256` (a digest over the canonical plan: input hash, label, base
    version and database hash, and every item with its precondition). The digest catches an altered or
    mixed-up plan; it is not a signature and not an authorisation. The plan states the concurrency policy
    in `concurrency_policy`: it is bound to a base version, and a later write to the same scope makes it
    stale (it is refused at apply, not merged).

    The database is read through a throwaway COPY in a temporary session (nothing it does is saved). When
    a version has been published, the copy is of that version, and the answer says which annotation
    version it read (`annotated_view`), checked against the marker stored inside the database as well
    as the manifest. The answer carries the input's hash, not its name or path. Every list in the answer is
    complete (`items_listed_complete: true`); an input over 200 renames is refused, not cut.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED, ANALYSIS_LIMITED
    (every refusal names the field, what is accepted, and `fixable`), RESULT_PARSE_FAILED.
    """
    tool = "ida_rename_plan"
    if not _valid_label(label):
        return _label_refusal(tool, label)
    if not isinstance(renames, list) or not 1 <= len(renames) <= _RENAME_MAX_ITEMS:
        return _refuse(tool, "ANALYSIS_LIMITED", "RENAMES_REQUIRED", fixable=True, field="renames",
                       given=f"{type(renames).__name__}" + (f" of {len(renames)}" if isinstance(renames, list) else ""),
                       accepted=f"a list of 1 to {_RENAME_MAX_ITEMS} objects with address and new_name",
                       fix="Pass the renames as a list of objects; a longer list is refused rather than cut, so split it.")
    items, seen_addresses, seen_names = [], set(), set()
    for index, entry in enumerate(renames):
        problem = None
        if not isinstance(entry, dict):
            problem = ("RENAME_ITEM_NOT_AN_OBJECT", None)
        elif set(entry) - {"address", "new_name", "address_kind"}:
            problem = ("RENAME_ITEM_UNKNOWN_FIELD", sorted(set(entry) - {"address", "new_name", "address_kind"})[:5])
        elif isinstance(entry.get("address"), bool) or not isinstance(entry.get("address"), (int, str)) \
                or (isinstance(entry.get("address"), int) and not 0 <= entry["address"] < 1 << 64):
            problem = ("RENAME_ITEM_ADDRESS_INVALID", None)
        elif not isinstance(entry.get("new_name"), str) or not _NEW_NAME.fullmatch(entry["new_name"]):
            problem = ("RENAME_ITEM_NAME_INVALID", None)
        elif entry.get("address_kind", "va") not in _PATCH_ADDRESS_KINDS:
            problem = ("INVALID_ADDRESS_KIND", list(_PATCH_ADDRESS_KINDS))
        if problem is None:
            try:
                value = entry["address"] if isinstance(entry["address"], int) else int(entry["address"].strip(), 0)
                if not 0 <= value < 1 << 64:
                    raise ValueError
            except ValueError:
                problem = ("RENAME_ITEM_ADDRESS_INVALID", None)
        if problem is None:
            key = (entry.get("address_kind", "va"), value)
            if key in seen_addresses:
                problem = ("DUPLICATE_ADDRESS", None)
            elif entry["new_name"] in seen_names:
                problem = ("DUPLICATE_NEW_NAME", None)
            seen_addresses.add(key)
            seen_names.add(entry["new_name"])
        if problem:
            return _refuse(tool, "ANALYSIS_LIMITED", problem[0], fixable=True, field="renames", item_index=index,
                           accepted=problem[1] if problem[1] else {
                               "address": "an integer or a string like \"0x140001000\"",
                               "new_name": _NEW_NAME.pattern, "address_kind": list(_PATCH_ADDRESS_KINDS)},
                           fix="Correct that item and plan again; nothing was read.")
        items.append({"address": hex(value), "address_kind": entry.get("address_kind", "va"), "new_name": entry["new_name"]})
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _refuse(tool, "ANALYSIS_LIMITED", "DATABASE_INPUT_NOT_SUPPORTED", fixable=True,
                       fix="Pass the original binary: the cache and the annotation versions key on that file's hash.")
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    if not (_ANNOTATE_WORKER_SOURCE.is_file() and _WORKER_SOURCE.is_file()):
        return _refuse(tool, "ANALYSIS_LIMITED", "IDA_WORKER_MISSING", fixable=False,
                       fix="A packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem).")
    total = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    try:
        sha256, md5 = _sha256_md5(p)
    except OSError as exc:
        return _j({"ok": False, "tool": tool, "status": "READ_FAILED", "error": "IDA_INPUT_UNREADABLE",
                   "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                         "strerror": _redact(exc.strerror or type(exc).__name__)},
                   "detail": "The input file could not be read; no plan was made."})
    invocation = {"operation": "rename_plan", "label": label, "item_count": len(items), "timeout_seconds": total}
    overlap = _overlap_refusal(tool)
    if overlap:
        return overlap
    lock, busy = _lock_annotated(tool, sha256, cancellation_token)
    if busy:
        return busy
    work = None
    try:
        unverified, _actions = _recover_pending(sha256)
        refusal = _opening_checks(tool, sha256, label, unverified)
        if refusal:
            return refusal
        state, problem = _annotated_state(sha256, label)
        if problem:
            return _refuse(tool, "ANALYSIS_LIMITED", problem["error"], fixable=False, reason=problem["reason"],
                           target_sha256=sha256, label=label,
                           fix="The published state of this scope cannot be confirmed; it is neither repaired nor "
                               "served. An operator must inspect the annotated root.")
        deadline = time.monotonic() + total
        work = state["label_dir"] / f"scratch-{uuid.uuid4().hex[:8]}"
        work.mkdir(parents=True)
        try:
            if state["version"] > 0:
                shutil.copyfile(state["db"], work / _DB_NAME)
            else:
                _copy_pristine(exe, p, sha256, md5, work / _DB_NAME, total, cancellation_token)
            left = int(deadline - time.monotonic())
            if left < 1:
                raise _StageFailure({"ok": False, "tool": tool, "status": "TIMEOUT", "invocation": invocation,
                                     "target_sha256": sha256, "error": "IDA_TIMEOUT_BUDGET_EXHAUSTED"})
            data, signals, provenance = _annotated_session(
                exe, work, {"operation": "rename_plan", "write_mode": "plan", "items": items}, tool=tool,
                sha256=sha256, md5=md5, invocation=invocation, temporary=True,
                seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
        except OSError as exc:
            return _j(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256, invocation=invocation))
        except _StageFailure as failure:
            return _j(failure.body)
        if data.get("ok") is False:
            refusal = {"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": data.get("error", "UNKNOWN_ERROR"),
                       **{k: v for k, v in data.items() if k in ("item_index", "item_error", "given", "accepted",
                                                                  "current_name", "item_start", "address_kind")},
                       "target_sha256": sha256, "label": label, "invocation": invocation, "fixable": True,
                       "fix": "Correct the item named by item_index and plan again. This is about the database as it is "
                              "now, not about the program."}
            return _j(refusal)
        marker = data.get("annotation_marker")
        if not _marker_matches(marker, sha256, label, state):
            return _refuse(tool, "ANALYSIS_LIMITED", "ANNOTATION_VERSION_MISMATCH", fixable=False, target_sha256=sha256,
                           label=label, manifest_version=state["version"],
                           marker_version=marker.get("version") if isinstance(marker, dict) else None,
                           fix="The annotation marker stored inside the database does not match the published "
                               "manifest, so what was read is not the version the manifest names. Nothing is planned "
                               "from it; an operator must inspect the scope.")
        rows = data.get("plan_items") or []
        if len(rows) != len(items) or len({r["address"]["va"] for r in rows}) != len(rows):
            return _refuse(tool, "ANALYSIS_LIMITED", "DUPLICATE_ADDRESS_AFTER_RESOLUTION", fixable=True,
                           fix="Two items resolve to the same address. Give each item one address and plan again.")
        plan = {"schema": _PLAN_SCHEMA, "kind": "rename", "target_sha256": sha256, "label": label,
                "base_version": state["version"], "base_db_sha256": state["db_sha256"],
                "items": [{"index": r["index"], "address": r["address"]["va"], "address_kind": "va",
                           "new_name": r["new_name"], "expect_name": r["old_name"]} for r in rows]}
        body = {
            "ok": True, "tool": tool, "status": "OK", "target_sha256": sha256, "label": label,
            "plan": plan, "plan_sha256": _sha256_text(_canonical(plan)), "item_count": len(rows),
            "items_detail": rows, "items_listed_complete": True,
            "annotated_view": {"state": "verified", "version": state["version"],
                               "read_from": "published annotation version" if state["version"] else "pristine analysis",
                               "marker_checked": True},
            "concurrency_policy": _CONCURRENCY_POLICY, "provenance": provenance, "signals": signals,
            "invocation": invocation,
            "note": ("A PLAN: nothing was written. It binds to the annotation version it read; if another write "
                     "to this scope lands first, applying it is refused as stale. Apply with ida_annotations_apply."),
        }
        body["internal_evidence_name"], body["evidence_write_error"] = _write_evidence(
            p, "rename_plan", body, EVIDENCE_RENAME_PLAN, stem=sha256[:16])
        return _j(body)
    finally:
        if work is not None:
            _remove_owned_work(work)
        _release_slot_lock(lock)


def _plan_problem(plan):
    """(error, field) when `plan` is not a well-formed rename plan, else (None, None). Pure."""
    if not isinstance(plan, dict):
        return "PLAN_NOT_AN_OBJECT", None
    for field, kind in (("schema", int), ("kind", str), ("target_sha256", str), ("label", str), ("base_version", int),
                        ("items", list), ("plan_sha256", str)):
        if not isinstance(plan.get(field), kind) or isinstance(plan.get(field), bool):
            return "PLAN_FIELD_MISSING_OR_WRONG_TYPE", field
    if plan["schema"] != _PLAN_SCHEMA or plan["kind"] != "rename":
        return "PLAN_SCHEMA_UNSUPPORTED", "schema"
    if not re.fullmatch(r"[0-9a-f]{64}", plan["target_sha256"]) or not _valid_label(plan["label"]) or plan["base_version"] < 0:
        return "PLAN_FIELD_INVALID", "target_sha256/label/base_version"
    if "base_db_sha256" not in plan or not (plan["base_db_sha256"] is None or isinstance(plan["base_db_sha256"], str)):
        return "PLAN_FIELD_MISSING_OR_WRONG_TYPE", "base_db_sha256"
    if not 1 <= len(plan["items"]) <= _RENAME_MAX_ITEMS:
        return "PLAN_ITEMS_OUT_OF_RANGE", "items"
    for item in plan["items"]:
        if not (isinstance(item, dict) and set(item) == {"index", "address", "address_kind", "new_name", "expect_name"}
                and isinstance(item["index"], int) and isinstance(item["address"], str)
                and item["address_kind"] == "va" and isinstance(item["expect_name"], str)
                and isinstance(item["new_name"], str) and _NEW_NAME.fullmatch(item["new_name"])):
            return "PLAN_ITEM_MALFORMED", "items"
    return None, None


def ida_annotations_apply(path, plan=None, allow_partial=False, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
                          cancellation_token=None):
    """APPLY a plan from `ida_rename_plan`: write its renames into a new, immutable annotation version of
    the scope it names. It cannot be called without a plan, and the plan must be unaltered (its digest is
    recomputed), made for this input (hash), and still current (its base version and database hash must be
    the published ones, and every item's `expect` name must be what the database holds now).

    `plan` is the plan object (or its JSON text). `allow_partial` must be exactly True or False. The
    default is atomic: the first item that fails stops everything, nothing is promoted (`ABORTED_ATOMIC`).
    `allow_partial=True` applies the items whose preconditions hold and reports the rest (`PARTIAL_FAILURE`,
    or `ALL_FAILED` and no new version).

    Order of events: the audit journal gets `batch_prepared` (synced to disk, before anything is promoted);
    the candidate is promoted to an immutable version file; a NEW engine process then opens a copy of that
    stored version and reads the names and the annotation marker back (a read in the writing session proves
    nothing); only when that matches is the one manifest pointer published; then `batch_committed` is
    journalled. If promotion fails the candidate stays in its recovery directory; if the read-back does not
    match, the version file stays unpublished and the answer says `VERIFICATION_FAILED`. Nothing is ever
    published unverified. A journal that cannot be written blocks the write (before the prepared record) or
    is reported as `commit_record_pending` (after publication). The next operation on the scope finishes or
    closes whatever a crash left open.

    Concurrent writers are blocked, not merged: see `concurrency_policy` in the answer. The pristine cache
    database is only read; annotated versions live in their own root and are never evicted.

    Status vocabulary: OK, PARTIAL_FAILURE, ALL_FAILED, ABORTED_ATOMIC, PRECONDITION_FAILED, VERIFICATION_FAILED,
    ANNOTATED_PROMOTION_BLOCKED, JOURNAL_UNWRITABLE, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED, RESULT_PARSE_FAILED, INVALID_PLAN. Refusals say `fixable`.
    """
    tool = "ida_annotations_apply"
    if isinstance(plan, str):
        try:
            plan = json.loads(plan)
        except ValueError:
            return _refuse(tool, "INVALID_PLAN", "PLAN_NOT_JSON", fixable=True, field="plan",
                           fix="`plan` is the object `ida_rename_plan` returned under `plan`, or its JSON text.")
    if plan is None:
        return _refuse(tool, "INVALID_PLAN", "PLAN_REQUIRED", fixable=True, field="plan",
                       fix="There is no apply without a plan. Call ida_rename_plan, then pass its `plan` here, with "
                           "the `plan_sha256` it returned inside the plan object as `plan_sha256`.")
    if isinstance(plan, dict) and "items" not in plan and isinstance(plan.get("plan"), dict):
        plan = {**plan["plan"], "plan_sha256": plan.get("plan_sha256")}      # the whole plan answer is also accepted
    error, field = _plan_problem(plan)
    if error:
        return _refuse(tool, "INVALID_PLAN", error, fixable=True, field=field,
                       accepted="the `plan` object of ida_rename_plan with its `plan_sha256` added",
                       fix="Pass the plan exactly as returned (add the answer's `plan_sha256` as the key "
                           "`plan_sha256` of the plan, or pass the whole answer).")
    body_without_digest = {k: v for k, v in plan.items() if k != "plan_sha256"}
    if _sha256_text(_canonical(body_without_digest)) != plan["plan_sha256"]:
        return _refuse(tool, "INVALID_PLAN", "PLAN_HASH_MISMATCH", fixable=True, field="plan_sha256",
                       fix="The plan's content does not match its digest: it was altered or mixed up. Plan again; "
                           "the digest is not a signature, only a guard against accidents.")
    if allow_partial is not True and allow_partial is not False:
        return _refuse(tool, "ANALYSIS_LIMITED", "INVALID_ALLOW_PARTIAL", fixable=True, field="allow_partial",
                       given=repr(allow_partial)[:80], accepted=[True, False],
                       fix="`allow_partial` must be exactly True or False; it is never inferred from a string or a number.")
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _refuse(tool, "ANALYSIS_LIMITED", "DATABASE_INPUT_NOT_SUPPORTED", fixable=True,
                       fix="Pass the original binary (the plan names its hash).")
    exe = _ida_binary()
    if not exe:
        return _tool_missing(tool)
    if not (_ANNOTATE_WORKER_SOURCE.is_file() and _WORKER_SOURCE.is_file()):
        return _refuse(tool, "ANALYSIS_LIMITED", "IDA_WORKER_MISSING", fixable=False,
                       fix="A packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem).")
    total = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    try:
        sha256, md5 = _sha256_md5(p)
    except OSError as exc:
        return _j({"ok": False, "tool": tool, "status": "READ_FAILED", "error": "IDA_INPUT_UNREADABLE",
                   "environment_error": {"type": type(exc).__name__, "errno": exc.errno,
                                         "strerror": _redact(exc.strerror or type(exc).__name__)},
                   "detail": "The input file could not be read; nothing was written."})
    if sha256 != plan["target_sha256"]:
        return _refuse(tool, "INVALID_PLAN", "PLAN_TARGET_MISMATCH", fixable=True, field="plan.target_sha256",
                       target_sha256=sha256, plan_target_sha256=plan["target_sha256"],
                       fix="The plan was made for different input content. Plan again for this file.")
    label = plan["label"]
    invocation = {"operation": "annotations_apply", "label": label, "plan_sha256": plan["plan_sha256"],
                  "item_count": len(plan["items"]), "allow_partial": allow_partial, "timeout_seconds": total}
    overlap = _overlap_refusal(tool)
    if overlap:
        return overlap
    lock, busy = _lock_annotated(tool, sha256, cancellation_token)
    if busy:
        return busy
    try:
        return _apply_locked(tool, exe, p, sha256, md5, label, plan, allow_partial, total, invocation, cancellation_token)
    except OSError as exc:
        return _j(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256, invocation=invocation))
    finally:
        _release_slot_lock(lock)


def _apply_locked(tool, exe, p, sha256, md5, label, plan, allow_partial, total, invocation, cancellation_token):
    """The body of `ida_annotations_apply`, under the per-hash lock. Returns the finished JSON."""
    unverified, recovered = _recover_pending(sha256)
    refusal = _opening_checks(tool, sha256, label, unverified)
    if refusal:
        return refusal
    state, problem = _annotated_state(sha256, label)
    if problem:
        return _refuse(tool, "ANALYSIS_LIMITED", problem["error"], fixable=False, reason=problem["reason"],
                       target_sha256=sha256, label=label,
                       fix="The published state of this scope cannot be confirmed; it is neither repaired nor served.")
    if state["version"] != plan["base_version"] or state["db_sha256"] != plan["base_db_sha256"]:
        return _j({"ok": False, "tool": tool, "status": "PRECONDITION_FAILED", "error": "STALE_BASE_VERSION",
                   "target_sha256": sha256, "label": label, "plan_base_version": plan["base_version"],
                   "published_version": state["version"], "fixable": True, "concurrency_policy": _CONCURRENCY_POLICY,
                   "fix": "Another write changed this scope after the plan was made. Nothing was written. Plan again "
                          "against the current version.", "written": False})
    deadline = time.monotonic() + total
    label_dir = state["label_dir"]
    write_id = uuid.uuid4().hex[:12]
    # Never reuse a number: not one a directory holds, and not one the journal ever prepared (a purged
    # version's number stays taken, so a record's version always means one write).
    journalled = [r["version"] for r in _journal_records(sha256)[0] if r.get("event") == "batch_prepared"
                  and r.get("label") == label and isinstance(r.get("version"), int)]
    version = max([state["version"]] + journalled + [int(m.group(1)) for d in (label_dir / "versions").glob("v*")
                                                      if (m := _VERSION_DIR.fullmatch(d.name))]) + 1
    rdir = label_dir / "recovery" / write_id
    verify_dir = label_dir / f"scratch-{uuid.uuid4().hex[:8]}"
    journal = {"prepared": None, "committed": None}
    marker = {"schema": 1, "label": label, "version": version, "write_id": write_id,
              "plan_sha256": plan["plan_sha256"], "target_sha256": sha256}
    result = {"ok": False, "tool": tool, "target_sha256": sha256, "label": label, "invocation": invocation,
              "write_id": write_id, "concurrency_policy": _CONCURRENCY_POLICY, "written": False}
    if recovered:
        result["recovery_actions"] = recovered

    def remaining():
        return int(deadline - time.monotonic())

    try:
        # 1. the candidate, in its own recovery directory, from the published version (or the pristine analysis)
        try:
            rdir.mkdir(parents=True)
            if state["version"] > 0:
                _copy_into_budget(state["db"], rdir / _DB_NAME, tool, sha256, cancellation_token)
            else:
                staging = rdir / "pristine.copy"
                _copy_pristine(exe, p, sha256, md5, staging, total, cancellation_token)
                _copy_into_budget(staging, rdir / _DB_NAME, tool, sha256, cancellation_token)
                staging.unlink()
            left = remaining()
            if left < 1:
                _remove_owned_work(rdir)
                return _j({**result, "status": "TIMEOUT", "error": "IDA_TIMEOUT_BUDGET_EXHAUSTED"})
            # 2. the write session (an ordinary session of the candidate; not temporary)
            job = {"operation": "rename_apply", "write_mode": "write", "allow_partial": allow_partial, "marker": marker,
                   "items": [{"address": i["address"], "address_kind": "va", "new_name": i["new_name"],
                              "expect_name": i["expect_name"]} for i in plan["items"]]}
            data, signals, provenance = _annotated_session(
                exe, rdir, job, tool=tool, sha256=sha256, md5=md5, invocation=invocation, temporary=False,
                seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
        except _StageFailure as failure:
            return _j({**failure.body, "written": False, "candidate_retained": rdir.exists(),
                       "concurrency_policy": _CONCURRENCY_POLICY})
        if data.get("ok") is False:
            reasons = {"ABORTED_ATOMIC": "ABORTED_ATOMIC", "ALL_FAILED": "ALL_FAILED"}
            status = reasons.get(data.get("error"), "ANALYSIS_LIMITED")
            _remove_owned_work(rdir)              # nothing was promoted and the candidate holds no change
            return _j({**result, "status": status, "error": data.get("error", "UNKNOWN_ERROR"),
                       "applied": data.get("applied", []), "failed": data.get("failed", []),
                       "save_returned": data.get("save_returned"), "marker_stored": data.get("marker_stored"),
                       "fixable": status in ("ABORTED_ATOMIC", "ALL_FAILED"),
                       "fix": "Nothing was promoted and the published version is unchanged. Plan again (or pass "
                              "allow_partial=True to apply the items whose preconditions hold).", "provenance": provenance})
        candidate_db = rdir / _DB_NAME
        sync_error = _fsync_path(candidate_db)
        candidate_sha, hash_error = _file_sha256(candidate_db)
        if sync_error or hash_error or candidate_sha is None:
            return _j({**result, "status": "ANALYSIS_LIMITED", "error": "CANDIDATE_NOT_SYNCABLE",
                       "candidate_retained": True, "fixable": "retry_later",
                       "fix": "The candidate could not be synced to disk or read back; it is kept in its recovery "
                              "directory and nothing was promoted.", "environment_error": sync_error or hash_error})
        candidate_bytes = candidate_db.stat().st_size
        total_now = _annotated_total_bytes()
        if total_now is None or total_now > _annotated_budget_bytes():
            return _j({**result, "status": "ANALYSIS_LIMITED", "candidate_retained": True, "fixable": False,
                       "error": "ANNOTATED_BUDGET_UNVERIFIABLE" if total_now is None else "ANNOTATED_BUDGET_EXHAUSTED",
                       "fix": "The candidate grew past the annotated byte budget (or the bytes could not be measured). "
                              "It is kept in recovery and nothing was promoted; an operator decides about the budget."})
        applied = data.get("applied", [])
        # 3. write-ahead: batch_prepared, synced, BEFORE the promotion
        journal["prepared"] = {
            "event": "batch_prepared", "operation": "rename", "write_id": write_id, "label": label, "version": version,
            "prior_version": state["version"], "prior_db_sha256": state["db_sha256"], "candidate_db_sha256": candidate_sha,
            "candidate_bytes": candidate_bytes, "candidate_location": f"recovery/{write_id}/{_DB_NAME}",
            "plan_sha256": plan["plan_sha256"], "item_count": len(applied),
            "items": [{"index": a["index"], "address": a["address"], "old_name": a["old_name"], "new_name": a["new_name"]}
                      for a in applied],
        }
        written, why = _journal_append(sha256, journal["prepared"])
        if not written:
            return _j({**result, "status": "JOURNAL_UNWRITABLE", "error": "PREPARED_RECORD_NOT_WRITTEN",
                       "journal_error": why, "candidate_retained": True, "fixable": "retry_later",
                       "fix": "The audit journal could not be written, so nothing was promoted. The candidate is "
                              "kept in its recovery directory. Fix the journal's location or permissions and retry."})
        # 4. promotion into an immutable version file (a new path: nothing is overwritten)
        version_dir = label_dir / "versions" / f"v{version:06d}"
        try:
            version_dir.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            promote_error = type(exc).__name__
        else:
            promote_error = _replace_file(candidate_db, version_dir / _DB_NAME)
        if promote_error:
            if version_dir.is_dir() and not any(version_dir.iterdir()):
                version_dir.rmdir()
            _journal_append(sha256, {"event": "batch_aborted", "write_id": write_id, "label": label,
                                     "reason": "promotion_failed", "error": promote_error, "retained": "recovery"})
            return _j({**result, "status": "ANNOTATED_PROMOTION_BLOCKED", "error": "PROMOTION_FAILED",
                       "environment_error": promote_error, "candidate_retained": True, "candidate_sha256": candidate_sha,
                       "fixable": "retry_later",
                       "fix": "Another handle held the file (a retry of up to 10 s was made) or the file system refused "
                              "the move. The candidate is intact in its recovery directory; nothing was published."})
        # 5. verification in a NEW engine process, over a copy of the promoted file
        promoted = version_dir / _DB_NAME
        promoted_sha, _ = _file_sha256(promoted)
        verify = {"separate_process": True, "names_matched": 0, "names_expected": len(applied),
                  "marker_matched": False, "write_session_pid": data.get("engine_pid")}

        def abort(reason, **extra):
            ok, _why = _journal_append(sha256, {"event": "batch_aborted", "write_id": write_id, "label": label,
                                                "reason": reason, "retained": "versions"})
            return _j({**result, "status": "VERIFICATION_FAILED" if reason == "verification_failed" else "ANALYSIS_LIMITED",
                       "error": reason.upper(), "version_retained_unpublished": f"v{version:06d}", "verification": verify,
                       "abort_record_written": ok, "fixable": False,
                       "fix": "The stored version was not published. It is kept, unreferenced, as evidence; the "
                              "published version is unchanged. Plan again.", **extra})

        if promoted_sha != candidate_sha:
            return abort("promoted_file_differs_from_candidate")
        left = remaining()
        if left < 1:
            return abort("timeout_before_verification")
        verify_dir.mkdir(parents=True)
        shutil.copyfile(promoted, verify_dir / _DB_NAME)
        try:
            checked, _signals, _prov = _annotated_session(
                exe, verify_dir, {"operation": "rename_verify", "write_mode": "verify",
                                  "items": [{"address": a["address"], "address_kind": "va"} for a in applied]},
                tool=tool, sha256=sha256, md5=md5, invocation=invocation, temporary=True,
                seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
        except _StageFailure as failure:
            return abort("verification_session_failed", verification_failure=failure.body.get("error"))
        verify["verify_session_pid"] = checked.get("engine_pid")
        verify["harness_pid"] = os.getpid()
        got = {row["address"]: row["actual_name"] for row in checked.get("verified_items") or []}
        verify["names_matched"] = sum(1 for a in applied if got.get(a["address"]) == a["new_name"])
        stored = checked.get("annotation_marker")
        verify["marker_matched"] = isinstance(stored, dict) and all(stored.get(k) == marker[k] for k in marker)
        verify["marker_version"] = stored.get("version") if isinstance(stored, dict) else None
        if checked.get("ok") is not True or verify["names_matched"] != len(applied) or not verify["marker_matched"] \
                or verify["verify_session_pid"] in (None, verify["write_session_pid"], verify["harness_pid"]):
            return abort("verification_failed")
        # 6. publish the single pointer
        manifest = {"schema": 1, "sha256": sha256, "label": label, "version": version, "write_id": write_id,
                    "db_sha256": candidate_sha, "db_bytes": candidate_bytes, "plan_sha256": plan["plan_sha256"],
                    "previous_version": state["version"], "published": _utc_now(), "profile": _ANALYSIS_PROFILE}
        manifest_error = _manifest_write(label_dir, manifest)
        if manifest_error:
            return abort("manifest_unwritable", environment_error=manifest_error)
        # 7. commit record; failing to write it does not undo the (verified, published) write
        journal["committed"] = {"event": "batch_committed", "write_id": write_id, "label": label, "version": version,
                                "db_sha256": candidate_sha, "plan_sha256": plan["plan_sha256"],
                                "items": journal["prepared"]["items"]}
        committed, commit_why = _journal_append(sha256, journal["committed"])
        _remove_owned_work(rdir)
        failed = data.get("failed", [])
        status = "PARTIAL_FAILURE" if failed else "OK"
        body = {**result, "ok": True, "status": status, "written": True, "version": version,
                "db_sha256": candidate_sha, "db_bytes": candidate_bytes, "prior_version": state["version"],
                "applied": applied, "failed": failed, "applied_count": len(applied), "failed_count": len(failed),
                "items_listed_complete": True, "atomic": not allow_partial,
                "save_returned": data.get("save_returned"), "verification": verify,
                "provenance": provenance, "journal": {"prepared": True, "committed": committed},
                "annotated_view": {"state": "verified", "version": version},
                "note": ("A new immutable annotation version was published after a separate engine process read its "
                         "names and marker back from the stored file. The pristine cache database was not changed."
                         + ("" if not failed else " Some items were not applied (allow_partial=True); see `failed`."))}
        if not committed:
            body["commit_record_pending"] = True
            body["journal"]["commit_error"] = commit_why
            body["note"] += (" The commit record could not be written; the version IS published (the manifest "
                             "points at it) and the next operation on this scope records it from the files.")
        body["internal_evidence_name"], body["evidence_write_error"] = _write_evidence(
            p, "annotations_apply", body, EVIDENCE_ANNOTATE_APPLY, stem=sha256[:16])
        return _j(body)
    finally:
        _remove_owned_work(verify_dir)


# --------------------------------------------------------------------------
# ida_annotations_purge: the only way annotated data is ever deleted
# --------------------------------------------------------------------------
#
# Mirror of the cache separation: this operation reaches ONLY the annotated root. It never references
# the cache root, a cache slot, the evidence directories or a pristine database (a test reads its source
# and pins that), writes no evidence file (the journal is its trace) and deletes only artifacts that are
# NAMED in the call and that the call's confirmation token was issued for.

_PURGE_MAX_TARGETS = 50
_PURGE_INVENTORY_LIMIT = 100
_PURGE_TARGET = re.compile(r"(?:version|published):[1-9][0-9]{0,5}|candidate:[0-9a-f]{12}|scratch:[0-9a-f]{8}|unverified-state")
_PURGE_ACCEPTED = ["version:<N> (an unpublished or older version)", "published:<N> (the published version; removes the pointer first)",
                   "candidate:<12 hex> (a kept candidate under recovery/)", "scratch:<8 hex> (a leftover work directory)",
                   "unverified-state (clears an unverified scope; says so)"]


def _tree_bytes(path):
    """Bytes under `path`, or None when any entry cannot be measured (never a partial count)."""
    total, problems = 0, []
    if os.path.isfile(path):
        try:
            return os.stat(path).st_size
        except OSError:
            return None
    for directory, _dirs, files in os.walk(path, onerror=problems.append):
        for name in files:
            try:
                total += os.stat(os.path.join(directory, name)).st_size
            except OSError:
                return None
    return None if problems else total


def _purge_remove(path, label_dir):
    """Delete one NAMED artifact of one scope: exactly `versions/vNNNNNN`, `recovery/<id>` or `scratch-<id>`
    directly under that scope's directory, which itself must sit two levels under the annotated root.
    Anything else is refused. The second recursive delete of the annotated section, with its own guard."""
    try:
        target = Path(os.path.realpath(path))
        scope = Path(os.path.realpath(label_dir))
        root = Path(os.path.realpath(_annotated_root()))
    except (OSError, ValueError):
        return False
    shaped = (scope.parent.parent == root and re.fullmatch(r"[0-9a-f]{64}", scope.parent.name) is not None)
    named = ((target.parent == scope / "versions" and _VERSION_DIR.fullmatch(target.name) is not None)
             or (target.parent == scope / "recovery" and re.fullmatch(r"[0-9a-f]{12}", target.name) is not None)
             or (target.parent == scope and re.fullmatch(r"scratch-[0-9a-f]{8}", target.name) is not None))
    if not (shaped and named):
        return False
    shutil.rmtree(target, ignore_errors=True)
    return not target.exists()


def _purge_inventory(sha256, label, state, problem):
    """What this scope holds, measured: (inventory, fingerprints keyed by target name). None for a value
    that could not be measured is reported as such, never as zero."""
    label_dir = _label_dir(sha256, label)
    published = state["version"] if state else None
    entries, prints = [], {}
    versions = label_dir / "versions"
    for d in sorted(versions.glob("v*")) if versions.is_dir() else []:
        match = _VERSION_DIR.fullmatch(d.name)
        if not (d.is_dir() and match):
            continue
        number = int(match.group(1))
        digest, _err = _file_sha256(d / _DB_NAME)
        size = _tree_bytes(d)
        kind = "published" if number == published else "version"
        entries.append({"target": f"{kind}:{number}", "kind": kind, "bytes": size,
                        "state": "published" if kind == "published" else (
                            "older version" if published and number < published else "unpublished (never verified or aborted)")})
        prints[f"{kind}:{number}"] = [digest, size]
    recovery = label_dir / "recovery"
    for d in sorted(recovery.glob("*")) if recovery.is_dir() else []:
        if d.is_dir() and re.fullmatch(r"[0-9a-f]{12}", d.name):
            digest, _err = _file_sha256(d / _DB_NAME)
            size = _tree_bytes(d)
            entries.append({"target": f"candidate:{d.name}", "kind": "candidate", "bytes": size,
                            "state": "kept candidate (never promoted)"})
            prints[f"candidate:{d.name}"] = [digest, size]
    for d in sorted(label_dir.glob("scratch-*")) if label_dir.is_dir() else []:
        if d.is_dir() and re.fullmatch(r"scratch-[0-9a-f]{8}", d.name):
            size = _tree_bytes(d)
            entries.append({"target": f"scratch:{d.name[8:]}", "kind": "scratch", "bytes": size, "state": "leftover work directory"})
            prints[f"scratch:{d.name[8:]}"] = [None, size]
    if problem:
        manifest_digest, _err = _file_sha256(label_dir / "manifest.json")
        entries.append({"target": "unverified-state", "kind": "unverified-state", "bytes": 0,
                        "state": "scope is unverified: " + str(problem["reason"])})
        prints["unverified-state"] = [str(problem["reason"]), manifest_digest]
    return entries, prints


def _purge_confirmation(sha256, label, names, prints, published):
    return _sha256_text(_canonical({"purge": 1, "target_sha256": sha256, "label": label, "targets": sorted(names),
                                    "published_version": published, "fingerprints": {n: prints.get(n) for n in sorted(names)}}))


def ida_annotations_purge(path, label=None, targets=None, confirm_token=None, cancellation_token=None):
    """Report, and on explicit confirmation delete, NAMED annotated artifacts of one scope (`path`'s input
    hash plus `label`). Nothing is deleted by default; the call without `confirm_token` is the dry run and
    its answer is the report (`status: REPORT_ONLY`).

    `targets` is a list of exact names, never a pattern: `version:<N>`, `published:<N>`, `candidate:<12 hex>`,
    `scratch:<8 hex>` and `unverified-state`. A wildcard or `all` is refused. The report lists everything
    the scope holds (`inventory`, cut at 100 entries and saying so), measures what the named targets
    would free, and returns a `confirm_token` bound to this input hash, this label, exactly these targets
    and their measured state (file digests and sizes, the published version). Pass the same targets and the
    token back to delete. If anything changed in between, the answer is `STALE_CONFIRMATION` and nothing is
    deleted. A published version is deleted only by naming it as `published:<N>`; its pointer is removed
    first. `version:<N>` refuses the published one.

    `unverified-state` clears a scope whose recorded state could not be confirmed (a pointer that does not
    match its file, an interrupted write that cannot be reconciled): it removes the pointer, closes the open
    write records with an abort record, and says `unverified_cleared: true` with the reason it cleared. The
    versions stay (name them to delete them). A damaged or unreadable JOURNAL is not clearable here.

    Only the annotated root is touched: never the cache, a pristine database or the evidence directories.
    Every deletion is journalled (`purge_prepared`, synced, before the first delete; `purge_committed` after).
    Statuses: REPORT_ONLY, OK, PARTIAL_FAILURE, STALE_CONFIRMATION, JOURNAL_UNWRITABLE, ANALYSIS_LIMITED
    (named error, `fixable`), PATH_REFUSED, NOT_FOUND, READ_FAILED.
    """
    tool = "ida_annotations_purge"
    if not _valid_label(label):
        return _label_refusal(tool, label)
    names = []
    if targets is not None:
        if not isinstance(targets, list) or len(targets) > _PURGE_MAX_TARGETS or not all(isinstance(t, str) for t in targets):
            return _refuse(tool, "ANALYSIS_LIMITED", "TARGETS_INVALID", fixable=True, field="targets",
                           accepted=_PURGE_ACCEPTED, fix=f"`targets` is a list of at most {_PURGE_MAX_TARGETS} exact names, or omitted for the report.")
        for entry in targets:
            if entry.strip().lower() in ("all", "*") or any(c in entry for c in "*?[]"):
                return _refuse(tool, "ANALYSIS_LIMITED", "WILDCARD_REFUSED", fixable=True, field="targets", given=entry[:40],
                               accepted=_PURGE_ACCEPTED,
                               fix="There is no 'delete everything' form. Run the report and name each thing to delete.")
            if not _PURGE_TARGET.fullmatch(entry):
                return _refuse(tool, "ANALYSIS_LIMITED", "TARGET_NAME_INVALID", fixable=True, field="targets", given=entry[:40],
                               accepted=_PURGE_ACCEPTED, fix="Use the exact `target` names the report lists.")
            if entry in names:
                return _refuse(tool, "ANALYSIS_LIMITED", "DUPLICATE_TARGET", fixable=True, field="targets", given=entry,
                               fix="Name each target once.")
            names.append(entry)
    if confirm_token is not None and (not isinstance(confirm_token, str) or not names):
        return _refuse(tool, "ANALYSIS_LIMITED", "CONFIRMATION_NEEDS_TARGETS", fixable=True, field="confirm_token",
                       accepted="the `confirm_token` string of a report, with the same `targets`",
                       fix="A confirmation is bound to the targets it was issued for: pass the same `targets` list with it.")
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    try:
        sha256 = _sha256_md5(p)[0]
    except OSError as exc:
        return _j({"ok": False, "tool": tool, "status": "READ_FAILED", "error": "IDA_INPUT_UNREADABLE",
                   "environment_error": {"type": type(exc).__name__, "errno": exc.errno, "strerror": _redact(exc.strerror or type(exc).__name__)},
                   "detail": "The input file could not be read; nothing was deleted."})
    overlap = _overlap_refusal(tool)
    if overlap:
        return overlap
    lock, busy = _lock_annotated(tool, sha256, cancellation_token)
    if busy:
        return busy
    try:
        return _purge_locked(tool, sha256, label, names, confirm_token)
    except OSError as exc:
        return _j(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256))
    finally:
        _release_slot_lock(lock)


def _purge_locked(tool, sha256, label, names, confirm_token):
    unverified, _actions = _recover_pending(sha256)
    if "*" in unverified:
        return _refuse(tool, "ANALYSIS_LIMITED", "JOURNAL_NOT_CLEARABLE", fixable=False, reason=unverified["*"], target_sha256=sha256,
                       fix="The audit journal itself is damaged or unreadable. Purge does not clear that: an operator must "
                           "inspect the annotated root. Nothing was deleted.")
    state, problem = _annotated_state(sha256, label)
    if state is None and label in unverified and problem is None:
        problem = {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": unverified[label]}
    if state is None and problem is None:
        problem = {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": "UNKNOWN"}
    if state is not None and label in unverified:
        state, problem = None, {"error": _ANNOTATED_STATE_UNVERIFIED, "reason": unverified[label]}
    label_dir = _label_dir(sha256, label)
    published = state["version"] if state else None
    if state is None and _manifest_read(label_dir)[0]:
        published = None
    entries, prints = _purge_inventory(sha256, label, state, problem)
    if any(e["bytes"] is None for e in entries):
        return _refuse(tool, "ANALYSIS_LIMITED", "SIZES_UNVERIFIABLE", fixable=False, target_sha256=sha256,
                       fix="An entry under this scope could not be measured, so no honest report or token can be made. Nothing was deleted.")
    by_name = {e["target"]: e for e in entries}
    for name in names:
        if name.startswith("version:") and f"published:{name.split(':')[1]}" in by_name:
            return _refuse(tool, "ANALYSIS_LIMITED", "PUBLISHED_VERSION_PROTECTED", fixable=True, field="targets", given=name,
                           fix="That version is the published one. To delete it, name it `published:<N>`; its pointer is removed first.")
        if name not in by_name and confirm_token is not None:
            # a confirmed target that is no longer there: the scope changed since the report
            return _j({"ok": False, "tool": tool, "status": "STALE_CONFIRMATION", "error": "STALE_CONFIRMATION", "deleted": False,
                       "fixable": True, "target_sha256": sha256, "label": label, "missing_target": name,
                       "inventory": entries[:_PURGE_INVENTORY_LIMIT], "inventory_cut": len(entries) > _PURGE_INVENTORY_LIMIT,
                       "fix": "A named target is no longer in the scope, so the confirmation is stale. Nothing was deleted. "
                              "Run the report again and confirm with its new `confirm_token`."})
        if name not in by_name:
            return _refuse(tool, "ANALYSIS_LIMITED", "TARGET_NOT_FOUND", fixable=True, field="targets", given=name,
                           accepted=sorted(by_name)[:_PURGE_INVENTORY_LIMIT],
                           fix="Name only what the report lists for this scope; the scope may have changed since.")
    if problem and any(n.startswith("published:") for n in names):
        return _refuse(tool, "ANALYSIS_LIMITED", "PUBLISHED_NAME_NOT_AVAILABLE", fixable=True,
                       fix="The scope is unverified, so no version is known to be the published one. Clear the state with "
                           "`unverified-state` first, then name versions with `version:<N>`.")
    selected = [by_name[n] for n in names]
    freed = sum(e["bytes"] for e in selected)
    token = _purge_confirmation(sha256, label, names, prints, published) if names else None
    shown = entries[:_PURGE_INVENTORY_LIMIT]
    held, budget = _annotated_total_bytes(), _annotated_budget_bytes()
    report = {"target_sha256": sha256, "label": label, "published_version": published,
              "inventory": shown, "inventory_total": len(entries), "inventory_cut": len(entries) > len(shown),
              "annotated_bytes_held": held, "annotated_budget_bytes": budget,
              "would_delete": [{"target": e["target"], "bytes": e["bytes"], "state": e["state"]} for e in selected],
              "would_free_bytes": freed, "scope_unverified": bool(problem),
              "unverified_reason": problem["reason"] if problem else None}
    if report["inventory_cut"]:
        report["inventory_note"] = f"the inventory is cut at {_PURGE_INVENTORY_LIMIT} of {len(entries)} entries"
    if confirm_token is None:
        return _j({"ok": True, "tool": tool, "status": "REPORT_ONLY", "deleted": False, **report, "confirm_token": token,
                   "note": ("Nothing was deleted. " + ("To delete exactly the targets named in `would_delete`, call again with "
                            "the same `targets` and this `confirm_token`." if names else "Name targets from `inventory` to get a "
                            "confirmation token for them."))})
    if confirm_token != token:
        return _j({"ok": False, "tool": tool, "status": "STALE_CONFIRMATION", "error": "STALE_CONFIRMATION", "deleted": False,
                   "fixable": True, **report, "confirm_token": token,
                   "fix": "The confirmation does not match the scope as it is now (a different token, other targets, or a change "
                          "since the report). Nothing was deleted. Read this report and confirm with the new `confirm_token`."})
    cleared = "unverified-state" in names
    if cleared and str(problem["reason"]).startswith("JOURNAL_UNREADABLE"):
        return _refuse(tool, "ANALYSIS_LIMITED", "JOURNAL_NOT_CLEARABLE", fixable=False, reason=problem["reason"])
    ok, why = _journal_append(sha256, {"event": "purge_prepared", "label": label, "targets": names, "bytes": freed,
                                       "published_version": published, "unverified_reason": problem["reason"] if cleared else None})
    if not ok:
        return _j({"ok": False, "tool": tool, "status": "JOURNAL_UNWRITABLE", "error": "PURGE_RECORD_NOT_WRITTEN", "deleted": False,
                   "journal_error": why, "fixable": "retry_later",
                   "fix": "The audit journal could not be written, so nothing was deleted. Fix its location or permissions and retry."})
    results = []
    for name in names:
        entry = by_name[name]
        if name == "unverified-state":
            manifest = label_dir / "manifest.json"
            digest = _file_sha256(manifest)[0]
            done = True
            try:
                manifest.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                done = False
            records = _journal_records(sha256)[0]
            closed = {r.get("write_id") for r in records if r.get("event") in ("batch_committed", "batch_aborted")}
            for r in records:
                if r.get("event") == "batch_prepared" and r.get("label") == label and r.get("write_id") not in closed:
                    done = _journal_append(sha256, {"event": "batch_aborted", "write_id": r["write_id"], "label": label,
                                                    "reason": "cleared_by_purge", "retained": "none"})[0] and done
            results.append({"target": name, "deleted": done, "removed_manifest_sha256": digest})
            continue
        path = label_dir / ("versions/v%06d" % int(name.split(":")[1]) if name.split(":")[0] in ("version", "published")
                            else "recovery/" + name.split(":")[1] if name.startswith("candidate:") else "scratch-" + name.split(":")[1])
        if name.startswith("published:"):
            try:
                (label_dir / "manifest.json").unlink()
            except FileNotFoundError:
                pass
            except OSError:
                results.append({"target": name, "deleted": False, "error": "POINTER_NOT_REMOVED"})
                continue
        results.append({"target": name, "deleted": _purge_remove(path, label_dir), "bytes": entry["bytes"]})
    state_after, problem_after = _annotated_state(sha256, label)
    deleted_all = all(r["deleted"] for r in results)
    committed, commit_why = _journal_append(sha256, {"event": "purge_committed", "label": label, "results": results,
                                                     "state_clean_after": problem_after is None})
    body = {"ok": deleted_all, "tool": tool, "status": "OK" if deleted_all else "PARTIAL_FAILURE", "deleted": any(r["deleted"] for r in results),
            "results": results, "freed_bytes": sum(r.get("bytes", 0) for r in results if r["deleted"]),
            "target_sha256": sha256, "label": label, "journal": {"prepared": True, "committed": committed},
            "published_version_after": state_after["version"] if state_after else None,
            "scope_unverified_after": problem_after is not None}
    if cleared:
        body["unverified_cleared"] = deleted_all and problem_after is None
        body["unverified_reason_was"] = problem["reason"]
        body["note"] = ("The unverified state was cleared by this call: the pointer was removed (its digest is in the results and the "
                        "journal), open write records were closed as `cleared_by_purge`, and the scope now has no published version. "
                        "The version files that remain are unreferenced; name them to delete them.")
        if problem_after is not None:
            body["note"] = "The unverified state could NOT be cleared: " + str(problem_after["reason"])
    if not committed:
        body["commit_record_pending"] = True
        body["journal"]["commit_error"] = commit_why
    if not deleted_all:
        body["fix"] = "Some targets were not deleted (a handle may hold them). Run the report again and retry what remains."
    return _j(body)


# --------------------------------------------------------------------------
# ida_status
# --------------------------------------------------------------------------

def ida_status():
    """Whether IDA is reachable, where from, and whether it actually works
    headless -- the probe to run before reporting IDA as unavailable.

    Launches idat once on an EMPTY database (`-t -pmetapc`, about a second, no
    input file) and reads back the kernel version and whether the decompiler
    initialises, so `status: "OK"` means idat started without a dialog or a
    licence prompt, not merely that a file named idat exists. The probe runs
    in a throwaway directory under the cache root and leaves nothing behind.
    """
    tool = "ida_status"
    resolved_by, exe = _resolved_by_and_binary()
    if not exe:
        return _tool_missing(tool)
    root = _cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        for old in root.glob("status-*"):            # a probe that was killed mid-run
            try:
                if time.time() - old.stat().st_mtime > _LOCK_STALE_SECONDS:
                    shutil.rmtree(old, ignore_errors=True)
            except OSError:
                pass
        probe_root = root / f"status-{uuid.uuid4().hex[:8]}"
        probe_root.mkdir()
    except OSError as exc:
        return _j(_EnvironmentFailure("IDA_CACHE_ROOT_UNUSABLE", exc).body(
            tool, binary=exe, resolved_by=resolved_by))
    try:
        job = {"output": str(probe_root / _RESULT_NAME), "operation": "summary", "query": "",
               "max_results": 1, "offset": 0, "mode": "create"}
        try:
            cp, _command = _launch(exe, probe_root, job, mode="create", target=None,
                                   timeout_seconds=_STATUS_TIMEOUT_SECONDS, cancellation_token=None,
                                   empty_database=True)
        except _EnvironmentFailure as failure:
            return _j(failure.body(tool, binary=exe, resolved_by=resolved_by))
        if cp.timed_out:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "binary": exe,
                       "error": "IDA_PROBE_TIMEOUT"})
        data, error, signals = _verdict(cp, probe_root, probe_root / _DB_NAME, expect_database=True,
                                        expect_operation="summary")
        if error:
            return _j(_failure_response(
                tool, "ANALYSIS_LIMITED", error, operation="summary", signals=signals, cp=cp,
                work=probe_root, target=None,
                extra={"binary": exe, "resolved_by": resolved_by,
                       "detail": "idat was found but did not complete a headless probe; see signals and log_tail."},
            ))
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": resolved_by,
            "ida_kernel_version": data.get("ida_kernel_version"),
            "decompiler_available": bool(data.get("hexrays_available")),
            "decompiler_version": data.get("hexrays_version"),
            "pdb_lookup": "disabled (-Opdb:off on every launch)",
            "network_lookup_detected": signals["network_lookup_detected"],
            "cache": _cache_summary(),
            "operations": ["ida_query", "ida_microcode_cfg", "ida_type_member_offset", "ida_patch_plan",
                           "ida_annotations", "ida_rename_plan", "ida_annotations_apply", "ida_annotations_purge",
                           "ida_status"],
            "query_operations": list(_ALLOWED_OPERATIONS),
            "note": (
                "OK means idat launched headless and exited cleanly on an empty database; it does not "
                "mean a particular file will analyse. decompiler_available false means decompile_function "
                "will fail; every other operation still works. Only IDA 9.x is supported."
            ),
        })
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
