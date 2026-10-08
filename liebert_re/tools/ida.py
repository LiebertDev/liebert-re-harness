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

**Isolation.** Every call is a bounded subprocess (`run_bounded_process`), never
the in-process `idalib` API: an analysis-kernel crash takes down the worker, not the
caller. There are two engines for `ida_query` (`backend=`, default "auto"):
`idat -A` as described here, and **idalib** (Hex-Rays' `idapro` package) run by a
worker (`ida_scripts/idalib_worker.idapy`) in a SEPARATE interpreter, the one named by
`LIEBERT_RE_IDALIB_PYTHON` (never guessed; unset means idalib is not configured and "auto"
is idat). Both run the same operation functions of `query_program.idapy` (the idalib worker
loads that file as a module), share the cache slots, and put `backend: {requested, used,
reason}` in every answer. The idalib rules: ONE database per worker process (a second
`open_database` in a process silently SAVES and closes the first one, measured, so the
worker opens once and always ends with `close_database(False)`); a cached database is never
opened in place (a copy is opened in the scratch directory and the slot's hash is taken
before and after: `CACHE_VIOLATION`, slot dropped, if it moved; a timeout or cancellation
does not cost the slot); a first analysis answers the question in the same session but
saves the pristine analysis BEFORE running it; the result comes back through a JSON file
with a size ceiling, never from stdout (IDA plugins print banners there); the other IDA
tools (`ida_microcode_cfg`, `ida_type_member_offset`, `ida_patch_plan`, the annotation
tools) stay on idat. The idat query itself is the read-only worker `ida_scripts/query_program.idapy`
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
happened anyway (`log_network_text_found`, a text scan with a stated limit:
it sees only the listed markers, so a lookup that writes none of them is not
seen). `pdb_lookup_declared` is a statement about OUR command line, not a
measurement of IDA's behaviour. Symbols from a PDB you place next
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

**Annotations that persist (`ida_rename_plan`, `ida_set_comments_plan`, `ida_annotations_apply`).** A plan and an apply are two
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

**Caller-written IDAPython (`ida_script`).** The one operation that runs code this package did not write. It is
gated (`LIEBERT_RE_IDA_SCRIPT=authorized`, off by default), idalib-only (it opens a COPY of the cached database,
never the slot; `backend="idat"` is UNSUPPORTED), and it is NOT a sandbox: an AST accident guard refuses the
usual mistakes (`os`, `open`, `save_database`, a debugger start) before anything starts, but the script runs with
the operator's rights and the child inherits the environment, the network and the file system. Every answer says
`NOT_ENFORCED` for those, labels the script's `result` as `SCRIPT_REPORTED` (the script's claim, not a measurement),
and keeps the full record under `dataset/evidence/ida_script/`; if that record cannot be written the result is
withheld. The worker is a mode (`script`) of `ida_scripts/idalib_worker.idapy`, so the one `open_database` and the
`close_database(False)` stay the only ones in the project.

Scope of this module: `ida_query`, `ida_script` (gated, see above), `ida_microcode_cfg`, `ida_type_member_offset`, `ida_patch_plan`
and `ida_annotations` (none of them writes the input or persists anything), `ida_rename_plan` and
`ida_set_comments_plan` and `ida_annotations_apply` (the one persistent write path: it applies a rename plan or a
comments plan), `ida_annotations_purge`
(the only deletion of annotated data: named targets, report first, a confirmation bound to what it reports) and `ida_status`.
"""
from __future__ import annotations

import ast
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
EVIDENCE_SCRIPT = APP_DIR / "dataset" / "evidence" / "ida_script"      # created on first use; tests patch this name
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

# The second backend: idalib (Hex-Rays' `idapro` package), driven in a SEPARATE interpreter. The
# interpreter is never guessed: it is the one named by this variable, or idalib is "not configured".
IDALIB_PYTHON_ENV = "LIEBERT_RE_IDALIB_PYTHON"
_BACKENDS = ("auto", "idat", "idalib")
_IDALIB_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "idalib_worker.idapy"
_IDALIB_JOB_SCRIPT = "liebert_idalib_job.py"     # the worker, copied into the scratch directory
_IDALIB_OPS_NAME = "liebert_query_ops.py"        # query_program.idapy, copied beside it (shared operations)
_IDALIB_JOB_NAME = "idalib_job.json"
_IDALIB_RESULT_NAME = "idalib_result.json"
_IDALIB_PROBE_TIMEOUT_SECONDS = 30
_IDALIB_PROBE_CACHE_SECONDS = 120                # a successful probe is reused this long (it costs ~0.5 s)
_IDALIB_MAX_RESULT_BYTES = 16 * 1024 * 1024      # the worker refuses to write more, the wrapper refuses to read more
_IDALIB_MAX_OUTPUT_CHARS = 64 * 1024             # stdout/stderr of the worker: diagnosis only, bounded, never parsed
_IDALIB_PROBE_CACHE = {}                         # (interpreter, stat, IDADIR) -> (monotonic time, probe)

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
# Comment plans: only the two plain disassembly comment kinds. Decompiler (pseudocode) comments are NOT
# supported and are refused by name, never mapped to one of these. The length ceiling is a chosen bound
# for a reviewable plan, not a measured IDA limit.
_COMMENT_KINDS = ("regular", "repeatable")
_COMMENT_MAX_CHARS = 1024
_PLAN_KINDS = ("rename", "comments")
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
    "read_bytes", "xrefs_from", "callers_of_import",
    "disasm_range", "basic_blocks", "callgraph", "stack_frame", "local_variables",
    "find_bytes", "find_immediate", "list_structs", "get_struct", "flirt_signatures",
)
# `read_bytes` takes 1..this many bytes; the worker enforces the same window.
_READ_BYTES_MAX_SIZE = 4096
# The bounds of the listing operations added after `read_bytes`; the worker enforces the same ones.
_U64 = 0xFFFFFFFFFFFFFFFF
_DISASM_MAX_ROWS = 2000
_CALLGRAPH_MAX_DEPTH = 4
_CALLGRAPH_MAX_NODES = 500
_CALLGRAPH_DEFAULT_DEPTH = 2
_CALLGRAPH_DEFAULT_NODES = 100
_PATTERN_MAX_TOKENS = 256
_FUNCTION_QUERY_MAX = 512
_TYPE_NAME_QUERY_MAX = 256
_SEGMENT_NAME_MAX = 64
_FUNCTION_QUERY_OPERATIONS = ("basic_blocks", "stack_frame", "local_variables")
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
# Text patterns searched for in IDA's log. Finding one is a hint that a lookup
# was attempted; NOT finding one proves nothing, because a lookup that does not
# write any of these strings is invisible to the scan.
_NETWORK_MARKERS = ("pdb: downloading", "http://", "https://")
_NETWORK_SCAN_LIMIT = (
    "text scan of IDA's log for the listed markers only; this is not a network observation. "
    "A lookup that writes none of these strings is not detected, so false does not mean no query was sent."
)
_PDB_LOOKUP_DECLARED = {
    "declared": "off",
    "basis": "the command line passes -Opdb:off on every launch (declaration, not an observation)",
    "observed_by": "log_network_text_found (log text scan, limited evidence)",
}

_WORKER_BOOKKEEPING = {"ok", "tool", "script_completed", "engine_input_sha256", "engine_input_md5"}
# The worker's own outcome of the lookup. `status` would collide with the response's run-level `status`
# (OK / PARTIAL / TIMEOUT ...), so the response carries both under `query_result` and the worker's `status`
# and `partial` are not copied to the top level. `lookup_errors` stays at the top level as well.
_WORKER_QUERY_FIELDS = {"status", "partial"}
_QUERY_STATUSES = ("OK", "NOT_FOUND", "UNRESOLVED", "QUERY_FAILED")


def _query_result(data):
    """{"status", "partial", "lookup_errors"} as the worker reported them, carried over unchanged. A result that
    carries no (or an unknown) status is "UNKNOWN", never a guessed OK."""
    status = data.get("status")
    errors = data.get("lookup_errors")
    return {
        "status": status if status in _QUERY_STATUSES else "UNKNOWN",
        "partial": data.get("partial") if isinstance(data.get("partial"), bool) else None,
        "lookup_errors": [str(e) for e in errors] if isinstance(errors, list) else [],
    }


def _tag_query_failure(text):
    """A failed `ida_query` response that carries no `query_result` (the question never reached the worker, or
    the run around it failed) gets `QUERY_FAILED` with the wrapper's own error code as the lookup error."""
    try:
        body = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(body, dict) or body.get("ok") is not False or "query_result" in body:
        return text
    reason = body.get("error") or body.get("status") or "FAILED"
    body["query_result"] = {"status": "QUERY_FAILED", "partial": False,
                            "lookup_errors": ["IDA_QUERY_WRAPPER: %s" % reason]}
    return _j(body)
# Operations whose `offset` indexes the result sequence, so a response that
# had to be trimmed can report where to resume.
_PAGED_OPERATIONS = {"list_functions", "segments", "xrefs_to", "imports_exports", "strings",
                     "xrefs_from", "callers_of_import", "disasm_range", "basic_blocks", "callgraph", "stack_frame",
                     "local_variables", "find_bytes", "find_immediate", "list_structs", "get_struct",
                     "flirt_signatures"}


def _read_bytes_request_problem(query):
    """None when `query` is a usable `read_bytes` request, else the error code the worker would give.
    Same grammar as the worker: a JSON object {"address", "size"} or the text "ADDRESS SIZE" (hex or
    decimal numbers). Checked here too so a bad request never starts IDA."""
    try:
        text = (query or "").strip()
        if text.startswith("{"):
            request = json.loads(text)
            address, size = request.get("address"), request.get("size")
        else:
            parts = text.replace(",", " ").split()
            address, size = parts if len(parts) == 2 else (None, None)
    except Exception:  # noqa: BLE001
        return "INVALID_READ_BYTES_REQUEST"
    if address is None or size is None or isinstance(address, bool) or isinstance(size, bool):
        return "INVALID_READ_BYTES_REQUEST"

    def number(value):
        if isinstance(value, int):
            return value
        try:
            return int(str(value), 0)
        except ValueError:
            return None

    ea, count = number(address), number(size)
    if ea is None or ea < 0 or ea == 0xFFFFFFFFFFFFFFFF:
        return "INVALID_ADDRESS"
    if count is None or not 1 <= count <= _READ_BYTES_MAX_SIZE:
        return "INVALID_SIZE"
    return None


def _to_int(value):
    """An int from a JSON number or a numeric string (decimal or 0x hex); never from a bool or a float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _json_fields(text, allowed):
    """The dict when `text` is a JSON object whose keys are all in `allowed`, else None."""
    try:
        request = json.loads(text)
    except Exception:  # noqa: BLE001
        return None
    return request if isinstance(request, dict) and set(request) <= set(allowed) else None


def _address_ok(value):
    ea = _to_int(value)
    return ea is not None and 0 <= ea < _U64


def _range_fields_problem(fields):
    """The error code for the optional start / end / segment fields of a find_* request, or None."""
    start, end, segment = fields.get("start"), fields.get("end"), fields.get("segment")
    if segment is not None:
        if not isinstance(segment, str) or not segment.strip() or len(segment) > _SEGMENT_NAME_MAX \
                or start is not None or end is not None:
            return "INVALID_RANGE"
        return None
    low = high = None
    if start is not None:
        if not _address_ok(start):
            return "INVALID_ADDRESS"
        low = _to_int(start)
    if end is not None:
        high = _to_int(end)
        if high is None or not 0 < high <= _U64:
            return "INVALID_ADDRESS"
    if low is not None and high is not None and high <= low:
        return "INVALID_RANGE"
    return None


def _disasm_range_request_problem(query):
    text = (query or "").strip()
    bad = "INVALID_DISASM_RANGE_REQUEST"
    if text.startswith("{"):
        fields = _json_fields(text, ("address", "count", "end"))
        if fields is None:
            return bad
        address, count, end = fields.get("address"), fields.get("count"), fields.get("end")
    else:
        parts = text.replace(",", " ").split()
        if len(parts) != 2:
            return bad
        address, count, end = parts[0], parts[1], None
    if address is None or (count is None) == (end is None):
        return bad
    if not _address_ok(address):
        return "INVALID_ADDRESS"
    if count is not None:
        number = _to_int(count)
        return None if number is not None and 1 <= number <= _DISASM_MAX_ROWS else "INVALID_COUNT"
    stop = _to_int(end)
    return None if stop is not None and _to_int(address) < stop <= _U64 else "INVALID_END_ADDRESS"


def _function_query_problem(query):
    text = (query or "").strip()
    return None if text and len(text) <= _FUNCTION_QUERY_MAX else "FUNCTION_REQUIRED"


def _callgraph_request_problem(query):
    text = (query or "").strip()
    depth, nodes = _CALLGRAPH_DEFAULT_DEPTH, _CALLGRAPH_DEFAULT_NODES
    if text.startswith("{"):
        fields = _json_fields(text, ("function", "depth", "max_nodes"))
        if fields is None or not isinstance(fields.get("function"), str):
            return "INVALID_CALLGRAPH_REQUEST"
        function = fields["function"].strip()
        if "depth" in fields:
            depth = _to_int(fields["depth"])
        if "max_nodes" in fields:
            nodes = _to_int(fields["max_nodes"])
    else:
        function = text
    if _function_query_problem(function):
        return "FUNCTION_REQUIRED"
    if depth is None or not 1 <= depth <= _CALLGRAPH_MAX_DEPTH:
        return "INVALID_DEPTH"
    if nodes is None or not 1 <= nodes <= _CALLGRAPH_MAX_NODES:
        return "INVALID_MAX_NODES"
    return None


def _find_bytes_request_problem(query):
    text = (query or "").strip()
    fields = {}
    if text.startswith("{"):
        fields = _json_fields(text, ("pattern", "start", "end", "segment"))
        if fields is None or not isinstance(fields.get("pattern"), str):
            return "INVALID_FIND_BYTES_REQUEST"
        pattern = fields["pattern"]
    else:
        pattern = text
    tokens = pattern.split()
    if not 1 <= len(tokens) <= _PATTERN_MAX_TOKENS:
        return "INVALID_PATTERN"
    for token in tokens:
        if token not in ("?", "??") and (len(token) != 2 or any(c not in "0123456789abcdefABCDEF" for c in token)):
            return "INVALID_PATTERN"
    if all(token in ("?", "??") for token in tokens):
        return "INVALID_PATTERN"
    return _range_fields_problem(fields)


def _find_immediate_request_problem(query):
    text = (query or "").strip()
    fields = {}
    if text.startswith("{"):
        fields = _json_fields(text, ("value", "start", "end", "segment"))
        if fields is None or "value" not in fields:
            return "INVALID_FIND_IMMEDIATE_REQUEST"
        raw = fields["value"]
    else:
        raw = text
    value = _to_int(raw)
    if value is None or not 0 <= value <= _U64:
        return "INVALID_VALUE"
    return _range_fields_problem(fields)


def _printable_name_problem(query, required, error):
    text = (query or "").strip()
    if (required and not text) or len(text) > _TYPE_NAME_QUERY_MAX or not text.isprintable():
        return error
    return None


# what the caller should have sent, for the refusal's `detail` (nothing was started)
_QUERY_FORMS = {
    "disasm_range": "JSON {\"address\": \"0x...\", \"count\": N} or {\"address\": \"0x...\", \"end\": \"0x...\"}, "
                    f"or the text \"0x... N\", with 1 <= N <= {_DISASM_MAX_ROWS}",
    "callgraph": "a function name or address, or JSON {\"function\": ..., \"depth\": "
                 f"1-{_CALLGRAPH_MAX_DEPTH}, \"max_nodes\": 1-{_CALLGRAPH_MAX_NODES}}}",
    "find_bytes": "a pattern of hex bytes with ? / ?? wildcards and at least one concrete byte "
                  f"(at most {_PATTERN_MAX_TOKENS} tokens), or JSON {{\"pattern\", \"start\"?, \"end\"?, \"segment\"?}}",
    "find_immediate": "a number 0 .. 2**64-1 (decimal or 0x hex), or JSON {\"value\", \"start\"?, \"end\"?, \"segment\"?}",
    "get_struct": f"a type name of at most {_TYPE_NAME_QUERY_MAX} printable characters",
    "list_structs": f"an optional name filter of at most {_TYPE_NAME_QUERY_MAX} printable characters",
    "flirt_signatures": "empty (this operation takes no query)",
    **{name: f"a function name or address (1..{_FUNCTION_QUERY_MAX} characters)" for name in _FUNCTION_QUERY_OPERATIONS},
}

_QUERY_CHECKS = {
    "disasm_range": _disasm_range_request_problem,
    "callgraph": _callgraph_request_problem,
    "find_bytes": _find_bytes_request_problem,
    "find_immediate": _find_immediate_request_problem,
    "get_struct": lambda q: _printable_name_problem(q, True, "INVALID_TYPE_NAME"),
    "list_structs": lambda q: _printable_name_problem(q, False, "INVALID_FILTER"),
    "flirt_signatures": lambda q: "UNEXPECTED_QUERY" if (q or "").strip() else None,
    **{name: _function_query_problem for name in _FUNCTION_QUERY_OPERATIONS},
}


def _query_request_problem(operation, query):
    """The error code the worker would give for a malformed `query` of a listing operation added after
    `read_bytes`, or None. Same grammar as the worker's request readers; checked here too so a bad request
    never starts IDA."""
    check = _QUERY_CHECKS.get(operation)
    return check(query) if check else None


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


_LOG_TAIL_LIMIT = 4000          # characters of ida.log kept, from the end
_LOG_READ_WINDOW = 64 * 1024    # bytes read from the end of the file before redaction
KEEP_FAILED_SCRATCH_ENV = "LIEBERT_RE_KEEP_FAILED_SCRATCH"


def _read_log_tail(work, target=None, limit=_LOG_TAIL_LIMIT):
    """The end of `work/ida.log`, redacted, with how it was measured. idat prints "Check ida.log!" when
    it cannot start; this is that check. Returns a dict:
    ida_log_status   "READ" | "EMPTY" | "ABSENT" (no such file) | "UNREADABLE" (it exists, reading failed)
    ida_log_tail     the redacted last `limit` characters, or None unless status is READ
    ida_log_tail_truncated  True when text before the tail exists, None when nothing was read
    ida_log_redacted True when redaction changed the text, None when nothing was read
    Absent and unreadable are different findings and are never merged."""
    path = Path(work) / _LOG_NAME
    out = {"ida_log_status": None, "ida_log_tail": None, "ida_log_tail_truncated": None, "ida_log_redacted": None}
    try:
        if not path.is_file():
            out["ida_log_status"] = "ABSENT"
            return out
        size = path.stat().st_size
        with path.open("rb") as handle:
            cut_front = size > _LOG_READ_WINDOW
            if cut_front:
                handle.seek(size - _LOG_READ_WINDOW)
            raw = handle.read(_LOG_READ_WINDOW)
    except OSError:
        out["ida_log_status"] = "UNREADABLE"
        return out
    text = raw.decode("utf-8", errors="replace")
    if cut_front:
        # drop the partial first line: a licence line cut in half would no longer be recognised by redaction
        text = text.partition("\n")[2]
    if not text.strip():
        out["ida_log_status"] = "EMPTY" if not cut_front else "READ"
        if not cut_front:
            return out
    clean = _redact(text, work=work, target=target)
    out.update({"ida_log_status": "READ", "ida_log_tail": clean[-limit:],
                "ida_log_tail_truncated": cut_front or len(clean) > limit,
                "ida_log_redacted": clean != text})
    return out


def _keep_failed_scratch():
    return os.getenv(KEEP_FAILED_SCRATCH_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _retained_scratch(path, root, root_token):
    """The response part that says a failed run's scratch directory was kept, where (root-relative, never an
    absolute path) and that it holds sensitive content."""
    try:
        where = f"{root_token}/" + Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (OSError, ValueError):
        where = None
    return {"retained": True, "location": where, "contains_sensitive_content": True,
            "enabled_by": KEEP_FAILED_SCRATCH_ENV,
            "warning": ("Kept because " + KEEP_FAILED_SCRATCH_ENV + " is set. This directory holds the engine's log "
                        "and the database it was working on, which carry absolute paths and the comment text of "
                        "the input; treat it as sensitive and delete it when finished. It is off by default.")}


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


# idat.exe is not long-path aware. Measured against IDA Pro 9.4 on Windows (LongPathsEnabled on, so the
# harness itself can create these directories): a working directory of up to 257 characters can be started,
# a script or database path of 259 characters is found and one of 260 is not (the log then says
# "could not locate file" or "Can't open for read file", and there is no result). It is the limit the Win32
# MAX_PATH names, for the FULL path idat resolves, not for the directory alone.
_IDA_PATH_LIMIT = 259
_IDA_PATH_LIMITED = os.name == "nt"   # the limit was measured on Windows; elsewhere every path is accepted
_IDA_LONGEST_NAME = max(len(n) for n in (_JOB_SCRIPT, _DB_NAME, _LOG_NAME, _RESULT_NAME, "job.json"))


def _ida_path_fit(work, target):
    """How the paths idat will be handed compare with `_IDA_PATH_LIMIT` (Windows only; elsewhere they always
    fit). Returns a dict of measured lengths (no path text) with `fits`."""
    work_chars = len(str(work))
    longest_in_work = work_chars + 1 + _IDA_LONGEST_NAME
    target_chars = len(str(target)) if target is not None else None
    fits = not _IDA_PATH_LIMITED or (longest_in_work <= _IDA_PATH_LIMIT
                               and (target_chars is None or target_chars <= _IDA_PATH_LIMIT))
    return {"fits": fits, "limit_chars": _IDA_PATH_LIMIT, "work_directory_chars": work_chars,
            "longest_file_in_work_chars": longest_in_work, "target_chars": target_chars}


class _IdaPathTooLong(_EnvironmentFailure):
    """Even a short scratch directory cannot hold what idat needs, or the input file's own path is over the
    limit. A classed refusal carrying the measured lengths, never a launch that fails with an unreadable log."""

    def __init__(self, measured, why):
        super().__init__("IDA_PATH_TOO_LONG", OSError(None, why))
        self.measured = measured

    def body(self, tool, **extra):
        body = super().body(tool, **extra)
        body["path_measurement"] = self.measured
        body["detail"] = (
            f"idat.exe cannot open a file whose full path is longer than {_IDA_PATH_LIMIT} characters. The call "
            "was refused before anything was started, with the measured lengths in `path_measurement`. It says "
            "nothing about the input file or what IDA would have found. Use a shorter location for the input "
            "or a shorter temporary directory.")
        body.update(extra)
        return body


def _rebase_paths(value, old, new):
    """`value` with every string that names a path under `old` moved under `new` (job fields that point at
    files in the work directory)."""
    if isinstance(value, str):
        if value.startswith(old) and (len(value) == len(old) or value[len(old)] in ("\\", "/")):
            return new + value[len(old):]
        return value
    if isinstance(value, dict):
        return {k: _rebase_paths(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_rebase_paths(v, old, new) for v in value]
    return value


def _launch(exe, work, job, *, mode, target, timeout_seconds, cancellation_token, empty_database=False,
            worker_source=None):
    """Run idat once in `work`. `mode` is "create" (analyse `target` into
    work/db.i64) or "reopen" (open `target`, an existing database).
    Returns (process_result, command).

    When the work directory (or the file idat would open) is too deep for idat's path limit, the session runs
    in a short scratch directory and what it leaves is copied back into `work`, so callers read their usual
    files. The process result then carries `liebert_short_path_session` (measured, path free), which
    `_verdict` reports in the signals. If even that cannot work, the call is refused as IDA_PATH_TOO_LONG."""
    fit = _ida_path_fit(work, target)
    if fit["fits"]:
        return _launch_in(exe, work, job, mode=mode, target=target, timeout_seconds=timeout_seconds,
                          cancellation_token=cancellation_token, empty_database=empty_database,
                          worker_source=worker_source)
    stage = Path(tempfile.mkdtemp(prefix="lre-"))
    try:
        staged_fit = _ida_path_fit(stage, None)
        measured = {**fit, "short_directory_chars": staged_fit["work_directory_chars"]}
        if not staged_fit["fits"]:
            raise _IdaPathTooLong(measured, "the temporary directory is too deep for idat")
        target_in_work = target is not None and Path(target).parent == Path(work)
        staged_target, copied_in = target, False
        if mode == "reopen":
            staged_target = stage / Path(target).name
            try:
                shutil.copyfile(target, staged_target)
            except OSError as exc:
                raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
            copied_in = True
        elif target is not None and len(str(target)) > _IDA_PATH_LIMIT:
            raise _IdaPathTooLong(measured, "the input file path is too long for idat")
        cp, command = _launch_in(
            exe, stage, _rebase_paths(job, str(work), str(stage)), mode=mode, target=staged_target,
            timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
            empty_database=empty_database, worker_source=worker_source)
        # What the session left behind comes back into `work`. A database opened from OUTSIDE `work` (a cached
        # slot) is not copied back: that session works on a throw-away copy.
        db_stays_out = mode == "reopen" and not target_in_work
        try:
            for child in stage.iterdir():
                if child.is_file() and not (db_stays_out and child.name == Path(target).name):
                    shutil.copyfile(child, Path(work) / child.name)
        except OSError as exc:
            raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
        note = {**measured, "staged": True, "database_copied_in": copied_in,
                "database_copied_back": mode == "reopen" and not db_stays_out}
        try:
            object.__setattr__(cp, "liebert_short_path_session", note)
        except (AttributeError, TypeError):
            pass
        return cp, command
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _launch_in(exe, work, job, *, mode, target, timeout_seconds, cancellation_token, empty_database=False,
               worker_source=None):
    """One idat launch with `work` as its working directory (see `_launch`)."""
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
    except OSError as exc:  # defensive: the runner reports a failed launch itself (below)
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
    if cp.launch_failed is True:  # the file exists but the OS would not start it (not executable, denied, ...)
        # The runner already reduced the OSError to a path-free cause; carry it as the strerror.
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", OSError(None, cp.launch_error))
    return cp, command


def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# Log forms that were actually observed when idat exited non-zero. The rule below names ONLY these; a log that
# shows none of them is "UNKNOWN". There is deliberately no licence, concurrency or database-lock class: no such
# log text has been observed here, and naming one without it would be a guess presented as a diagnosis.
_LOG_DB_EMPTY = "database is empty"
_LOG_DB_INIT_FAILED = re.compile(r"database initialization failed with error (\d+)", re.I)
_LOG_DB_OPEN_FAILED = re.compile(r"open database failed with result:? *(\d+)", re.I)
_LOG_SCRIPT_NOT_LOCATED = re.compile(r"liebert_ida_job\.py: could not locate file", re.I)


def _classify_exit_log(log):
    """What idat's own log says about a non-zero exit, from observed forms only. Returns
    {"class", "error_code", "evidence"}; `evidence` names the fixed patterns that matched (never log text, so
    nothing in it needs redaction).
    DATABASE_OPEN_FAILED_EMPTY   "Database is empty" and an open/initialization failure with a numeric code
                                 (observed with code 4). The log shows IDA saw an empty database; it does NOT
                                 say why, so this class names the symptom, not a cause.
    DATABASE_OPEN_FAILED         an open/initialization failure with a numeric code and no "Database is empty"
    SCRIPT_NOT_LOCATED           idat could not find the worker script it was told to run (observed with a
                                 scratch path near the Windows path-length limit)
    UNKNOWN                      none of the above, an unreadable log, or no log text: nothing is guessed."""
    text = log if isinstance(log, str) else ""
    init, opened = _LOG_DB_INIT_FAILED.search(text), _LOG_DB_OPEN_FAILED.search(text)
    empty = _LOG_DB_EMPTY in text.lower()
    code = None
    for hit in (init, opened):
        if hit:
            code = int(hit.group(1))
            break
    evidence = [name for name, found in (("database_is_empty", empty), ("database_initialization_failed", init),
                                         ("open_database_failed", opened)) if found]
    if init or opened:
        return {"class": "DATABASE_OPEN_FAILED_EMPTY" if empty else "DATABASE_OPEN_FAILED",
                "error_code": code, "evidence": evidence}
    if _LOG_SCRIPT_NOT_LOCATED.search(text):
        return {"class": "SCRIPT_NOT_LOCATED", "error_code": None, "evidence": ["script_could_not_locate_file"]}
    return {"class": "UNKNOWN", "error_code": None, "evidence": []}


def _verdict(cp, work, db_path, *, expect_database, expect_operation=None, require_discard=False,
             require_root_info=False):
    """The four signals, read together. Returns (data, failure_error,
    signals). `failure_error` is None only when every signal agrees.

    The log is one of the four, so it has to be readable and non-empty to
    count: a log that could not be read, or that idat never wrote to, is
    IDA_LOG_UNREADABLE rather than "no fatal marker found". When
    `expect_operation` is given, the result must be an answer to THAT
    operation. `require_discard` (a reopen session) makes the worker's
    `database_changes_discarded: true` mandatory: false or absent is a failure,
    so a worker that could not set up the discard guarantee never yields a
    success. `require_root_info` (a session that reopens a database built from
    an input file) makes the engine's record of that input mandatory: measured
    on IDA Pro 9.4, about 1 in 70 loads of a perfectly good database comes up
    with its root information empty (no input hash, no path, image base 0), and
    such a session must neither answer nor save, so it is IDA_ENGINE_ROOT_INFO_MISSING."""
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
        "log_network_text_found": bool(network),
        "log_network_text_markers_scanned": list(_NETWORK_MARKERS),
        "log_network_text_evidence_limit": _NETWORK_SCAN_LIMIT,
    }
    if require_discard:
        signals["database_changes_discarded"] = data.get("database_changes_discarded") if completed else None
    staged = getattr(cp, "liebert_short_path_session", None)
    if staged:
        signals["short_path_session"] = staged
    if parse_error:
        return None, "RESULT_PARSE_FAILED", {**signals, "parse_error": parse_error}
    if cp.returncode not in (0, None):
        # The exit code decides the error, but every other signal was already read above and is reported
        # with it: a non-zero exit after a complete result is a different event from one with no result.
        if completed:
            kind, meaning = "NONZERO_EXIT_RESULT_COMPLETE", (
                "The worker finished and wrote a complete result file, and the process still exited non-zero. "
                "This rules out 'the database never opened'; the failure is in how the process ended.")
        elif result_present:
            kind, meaning = "NONZERO_EXIT_RESULT_INCOMPLETE", (
                "A result file exists but the worker did not mark it complete: the script started and stopped "
                "part-way, or the file is not the worker's final write.")
        else:
            kind, meaning = "NONZERO_EXIT_NO_RESULT", (
                "No result file was written. This is consistent with the database never opening or the worker "
                "never running, but the log markers and stderr are the evidence for which.")
        signals["exit_diagnosis"] = {"class": kind, "meaning": meaning, "exit_code": cp.returncode,
                                     "result_file_present": result_present, "script_completed": completed,
                                     "log_fatal_markers": markers,
                                     "log_class": _classify_exit_log(log if log_readable else None)}
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
    if require_root_info:
        root_info = bool(data.get("engine_input_sha256") or data.get("engine_input_md5"))
        signals["engine_root_info_present"] = root_info
        if not root_info:
            return data, "IDA_ENGINE_ROOT_INFO_MISSING", signals
    if expect_database and (db_bytes <= 0 or loose):
        return data, "IDA_NO_DATABASE", signals
    return data, None, signals


def _failure_response(tool, status, error, *, operation, signals, cp, work, target, extra=None):
    body = {
        "ok": False, "tool": tool, "status": status, "error": error, "operation": operation,
        "signals": signals,
        "log_tail": _tail(_read_text(work / _LOG_NAME), work, target),
        **_read_log_tail(work, target),
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
    list_keys = [k for k in ("items", "nodes", "exports", "loaded_ranges", "unloaded_ranges")
                 if isinstance(body.get(k), list)]
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
                      max_chars, evidence, note=None, omit_path=False, query_worker=False):
    body = {k: v for k, v in data.items() if k not in _WORKER_BOOKKEEPING}
    limitations = []
    if query_worker:
        for key in _WORKER_QUERY_FIELDS:
            body.pop(key, None)
        body["query_result"] = _query_result(data)
        if body["query_result"]["partial"] and body["query_result"]["lookup_errors"]:
            limitations.append(
                f"{len(body['query_result']['lookup_errors'])} sub-step(s) of the lookup failed (see lookup_errors); "
                "what is listed is what could be read, and an absent entry is not proof of absence"
            )
    walk_limit = body.get("walk_limit")
    if walk_limit:
        limitations.append(_walk_limit_text(walk_limit))
    if body.get("instructions_truncated"):
        limitations.append(
            f"the microcode listing was cut at {body.get('instructions_returned')} of "
            f"{body.get('instruction_count')} instructions (max_results); block edges are complete"
        )
    if body.get("nodes_truncated"):
        limitations.append(
            f"the call graph reached its node cap of {body.get('max_nodes')}: {body.get('dropped_node_count')} "
            "further functions were not added and the edges to them are not listed"
        )
    head = {
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p), "target_sha256": sha256,
        "database_cache": cache_state,
        "invocation": invocation,
        "provenance": _provenance(sha256, md5, data),
        "signals": signals,
        "pdb_lookup_declared": dict(_PDB_LOOKUP_DECLARED),
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
              timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, max_chars=60000, cancellation_token=None, backend="auto"):
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
    * `xrefs_to`            `query` is a symbol name or virtual address. A name is
                            resolved exact name, then demangled name, then import name
                            (any module; the import slot is added to the candidates);
                            `resolved_by` says how, `candidates` lists EVERY address the
                            name pointed at (none is chosen) and each item carries `to`.
                            Items split code and data by `kind`; calls are flagged
                            (`is_call`), jumps are not calls. A name that resolves to
                            nothing is `SYMBOL_NOT_FOUND`, never an empty OK.
    * `xrefs_from`          `query` is a symbol name or address. A function (its name
                            or start address) gives the code and data references out of
                            every instruction in it (`scope: function`); any other
                            address gives that one item's (`scope: address`). Paged,
                            `truncated` while `next_offset` is not null.
    * `callers_of_import`   `query` is an import name (any module). Lists the
                            functions that reference its import slot, with function name
                            and address and the call site; a reference from a jump thunk
                            is followed one level (`via_thunk`). Computed calls are not
                            searched: an empty list is "none found", not "never called".
                            An unknown import is `IMPORT_NOT_FOUND`.
    * `read_bytes`          `query` is JSON `{"address": "0x...", "size": N}` or the text
                            "0x... N", 1 <= N <= 4096 (larger is refused before IDA
                            starts). Reads the database as IDA mapped it. A byte IDA has
                            no value for is never reported as a number: `bytes_hex` is
                            null unless every byte is loaded, `loaded_ranges` hold the
                            loaded runs and `unloaded_ranges` the rest. An address outside
                            every segment is `ADDRESS_NOT_MAPPED`.
    * `imports_exports`     IDA's own import resolution plus entry points.
    * `strings`             IDA's string list; a non-empty `query` filters
                            case-insensitively on the decoded text.
    * `disasm_range`        `query` is JSON `{"address": "0x...", "count": N}` (N <= 2000), `{"address",
                            "end"}` or the text "0x... N". Rows say what each item is: `instruction`
                            (mnemonic and operands, no comments), `data`, `undefined` (never
                            disassembled) or `inside_item`; the walk stops at the end of the mapped
                            segments (`stop_reason`).
    * `basic_blocks`        `query` is a function name or address. IDA's flow chart: start, end, type
                            and successor / predecessor starts of every block.
    * `callgraph`           `query` is a function name or address, or JSON `{"function", "depth" (1-4),
                            "max_nodes" (1-500)}`. Nodes (address, name, import or not) and edges
                            (`items`, paged); calls through a register or a non-import memory operand
                            are counted per node (`indirect_call_count`), never resolved.
    * `stack_frame`         `query` is a function name or address. Frame sizes, IDA's landmark offsets
                            and the members with offset, size, type and region (local, saved
                            registers, return address, argument); no frame is `NO_STACK_FRAME`.
    * `local_variables`     same `query`. The decompiler's variable list (name, type, argument or
                            not, location); no decompiler or a failed decompile is an error.
    * `find_bytes`          `query` is a pattern ("48 8B ?? 05": hex bytes and ? / ?? wildcards) or
                            JSON `{"pattern", "start"?, "end"?, "segment"?}`. Matches in address
                            order with the function containing each; `max_results` caps the matches.
    * `find_immediate`      `query` is a number (0 .. 2**64-1) or JSON `{"value", "start"?, "end"?,
                            "segment"?}`. Instructions with that immediate operand, by IDA's own
                            immediate search; the same constant written negated or sign-extended is
                            a different number and is not found.
    * `list_structs`        a non-empty `query` filters the local type library's struct and union
                            names; size and member count each.
    * `get_struct`          `query` is a type name. Members with offset, size and type text.
    * `flirt_signatures`    no `query`. The FLIRT signature list with each signature's state and
                            matched-function count (listing only; nothing is applied).

    `max_results` is clamped to 1..1000; `offset` pages the operations that
    list; `next_offset` is null once the end is reached. `timeout_seconds` is
    one budget for the whole call, clamped to 5..600. The first analysis of a
    file may use all of it (up to 600 s: it runs once per file content and is
    cached); the session that answers the question never runs longer than
    300 s. A timed-out analysis is discarded, never half-cached.
    The first call on a file runs two idat sessions (analyse and save, then
    the question); later calls run one.
    `max_chars` bounds the response without breaking its JSON.

    `query_result` says what the LOOKUP found, apart from the run-level `status` below: `status` is `OK`,
    `NOT_FOUND` (the lookup ran to the end and found nothing), `UNRESOLVED` (the name or address could not be
    resolved to anything to look at) or `QUERY_FAILED` (a step of the lookup raised, or the run failed), and
    `UNKNOWN` when the worker did not say. `partial` is true when something is listed but a sub-step failed or a walk hit its ceiling;
    `lookup_errors` (also at the top level) names each failed sub-step and exception class, without paths.
    An empty `items` with no `NOT_FOUND` status is not a finding. A field IDA could not be asked is null
    (`is_bitfield` included), never a default.

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

    `backend` (keyword, last) picks the engine: "idat" is the batch binary (two sessions on a first
    analysis), "idalib" is Hex-Rays' `idapro` package run in the interpreter named by
    LIEBERT_RE_IDALIB_PYTHON (one session per question; a COPY of a cached database is opened and the
    slot is measured before and after), and "auto" (the default) is idalib only when that variable is
    set and `import idapro` works in that interpreter, else idat. The interpreter is never guessed.
    Every response carries `backend: {requested, used, reason}`; an idalib that was requested but is
    not usable is TOOL_MISSING, never a silent switch to idat, and a session that failed on the chosen
    engine is not retried on the other one.
    """
    choice = _choose_backend(backend)
    if choice["failure"] is not None:
        return _tag_query_failure(_tag_backend(_j(choice["failure"]), choice["info"]))
    return _tag_query_failure(_tag_backend(_ida_query(path, operation, query, max_results, offset, timeout_seconds,
                                                      max_chars, cancellation_token, choice), choice["info"]))


def _ida_query(path, operation, query, max_results, offset, timeout_seconds, max_chars, cancellation_token, choice):
    """`ida_query` after the engine has been chosen (see there for the arguments)."""
    tool = "ida_query"
    idalib = choice["used"] == "idalib"
    exe = choice["engine_exe"] if idalib else _ida_binary()
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
    if operation == "read_bytes":
        problem = _read_bytes_request_problem(query)
        if problem:
            return _j({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": problem, "path": relative(p),
                "detail": (
                    "`query` for read_bytes must be a JSON object {\"address\": \"0x...\", \"size\": N} or the "
                    f"text \"0x... N\", with 1 <= size <= {_READ_BYTES_MAX_SIZE}. Nothing was started."
                ),
            })
    problem = _query_request_problem(operation, query)
    if problem:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": problem, "path": relative(p),
            "detail": f"`query` for {operation} must be {_QUERY_FORMS[operation]}. Nothing was started.",
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
    if not _WORKER_SOURCE.is_file() or (idalib and not _IDALIB_WORKER_SOURCE.is_file()):
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "The packaged IDAPython worker is absent from this install (a packaging defect, not an IDA problem)."})
    timeout_seconds = _clamp(timeout_seconds, _MIN_TIMEOUT_SECONDS, _MAX_CREATE_TIMEOUT_SECONDS, _DEFAULT_TIMEOUT_SECONDS)
    max_results = _clamp(max_results, 1, _MAX_RESULTS_CAP, 200)
    offset = _clamp(offset, 0, 10 ** 9, 0)
    max_chars = _clamp(max_chars, _MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    query = "" if query is None else str(query)
    invocation = {"operation": operation, "query": query, "max_results": max_results, "offset": offset,
                  "timeout_seconds": timeout_seconds}

    profile = {"backend": "idalib", "python": choice["python"]} if idalib else None
    return _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile)


def _locked_call(tool, exe, p, invocation, max_chars, cancellation_token, profile=None):
    """The part every question shares: hash the input, take its slot lock, run
    the staged session(s) under it, enforce the cache budget on success. Returns
    the finished JSON string. `profile` (None for an idat `ida_query`) carries what a
    different operation changes: its worker, the extra job fields, the ceiling
    of its reopen session, its evidence directory and its note; for the idalib
    backend it is `{"backend": "idalib", "python": <interpreter>}` and `exe` is the
    nominal idat path that names the engine in the slot key."""
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
        if (profile or {}).get("script"):
            run = _script_locked
        else:
            run = _query_locked_idalib if (profile or {}).get("backend") == "idalib" else _query_locked
        outcome = run(exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile)
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
    (`transformed`; `transform_equivalence` is always `NOT_CHECKED`: a changed listing
    is not a verified-equivalent one). A rule firing is not proof that the function was
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
                        and info.get("transform_equivalence") == "NOT_CHECKED"
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
    keep_work = False
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
            expect_operation=operation, require_discard=not creating, require_root_info=not creating,
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
    except _StageFailure as failure:
        if _keep_failed_scratch() and work.is_dir():
            keep_work = True
            failure.body["scratch_retained"] = _retained_scratch(work, _cache_root(), "<CACHE>")
        raise
    finally:
        if not keep_work:
            shutil.rmtree(work, ignore_errors=True)
        if state_dir is not None:
            shutil.rmtree(state_dir, ignore_errors=True)


# A load of a good database that comes up with empty root information (IDA_ENGINE_ROOT_INFO_MISSING) is an
# intermittent engine fault, not a property of the file: the same file loads correctly the next time. The
# session is repeated, up to this many launches, and the repeats are reported.
_ROOT_INFO_ATTEMPTS = 3


def _run_stage_checked(*args, **kwargs):
    """`_run_stage`, repeated while the engine reports a reopen with empty root information. The failed
    session answered nothing and (being temporary) saved nothing, so repeating it is safe; a second
    failure of another kind is returned as it is."""
    attempts = 0
    while True:
        attempts += 1
        try:
            data, signals, provenance = _run_stage(*args, **kwargs)
        except _StageFailure as failure:
            if failure.body.get("error") == "IDA_ENGINE_ROOT_INFO_MISSING" and attempts < _ROOT_INFO_ATTEMPTS:
                continue
            if attempts > 1:
                failure.body["engine_root_info_attempts"] = attempts
            raise
        if attempts > 1:
            signals["engine_root_info_repeats"] = attempts - 1
        return data, signals, provenance


def _query_locked(exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile=None):
    profile = profile or {}
    tool = profile.get("tool", "ida_query")
    reopen_ceiling = profile.get("reopen_ceiling", _MAX_QUERY_TIMEOUT_SECONDS)
    operation = invocation["operation"]
    total = invocation["timeout_seconds"]
    deadline = time.monotonic() + total
    scratch_kept = False      # a failed stage's scratch kept on request lives inside the slot, which then stays
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
            data, signals, provenance = _run_stage_checked(
                exe, p, sha256, md5, slot, mode="reopen", operation=operation, invocation=invocation,
                timeout_seconds=left, cancellation_token=cancellation_token, profile=profile,
            )
        return _answer_from_worker(
            tool, p, sha256, md5, slot, operation, data, signals, provenance, cache_state=cache_state,
            invocation=invocation, max_chars=max_chars, profile=profile,
        )
    except _StageFailure as failure:
        scratch_kept = "scratch_retained" in failure.body
        return failure.body
    finally:
        if not (slot / _DB_NAME).exists() and not scratch_kept:
            shutil.rmtree(slot, ignore_errors=True)  # a slot with no database is never kept (unless it holds a retained failed scratch)


def _answer_from_worker(tool, p, sha256, md5, slot, operation, data, signals, provenance, *, cache_state,
                      invocation, max_chars, profile):
    """The part of a question that comes AFTER a verified worker result, shared by both backends: a worker
    that answered "no" (unknown symbol, decompiler refused) is a named refusal, an answer that is not
    labelled the way the call asked is withheld, otherwise the evidence file is written and the response
    is shaped. `slot` is only used to redact scratch paths out of exception text."""
    # The shared query worker reports a lookup outcome (`status`, `partial`, `lookup_errors`); the
    # microcode and patch-plan workers are their own scripts and do not.
    query_worker = not profile.get("worker")
    if data.get("ok") is False:
        # The worker ran and answered "no" (unknown symbol, decompiler refused). The database is fine.
        refusal = {
            "ok": False, "tool": tool,
            "status": (profile.get("error_status") or {}).get(data.get("error"), "ANALYSIS_LIMITED"),
            "error": data.get("error", "UNKNOWN_ERROR"),
            **{k: v for k, v in data.items() if k not in _WORKER_BOOKKEEPING and k not in ("error", "items", "traceback")
               and not (query_worker and k in _WORKER_QUERY_FIELDS)},
            **({"query_result": _query_result(data)} if query_worker else {}),
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
        omit_path=bool(profile.get("omit_path")), query_worker=query_worker,
    )



# --------------------------------------------------------------------------
# the idalib backend: one database per worker process, shared query operations
# --------------------------------------------------------------------------
#
# `ida_query(..., backend=)` picks the engine that answers: "idat" (the batch binary, above), "idalib"
# (Hex-Rays' `idapro` package in a separate interpreter) or "auto". The questions are the same ones:
# both workers run the operation functions of `query_program.idapy` (the idalib worker loads that file
# as a module), and the response shape is the same plus `backend`.
#
# What differs, and why:
#   * one session answers a question even on a first analysis (idat needs two: analyse-and-save, then
#     reopen). The idalib worker saves the pristine analysis BEFORE it runs the operation and closes
#     without saving, so what is cached is still the pristine analysis;
#   * the cached database is never opened in place. A COPY is opened in the scratch directory and the
#     slot's hash is taken before and after (`CACHE_VIOLATION` if it moved), instead of the idat
#     path's "mark the session temporary" guarantee;
#   * a timed-out or cancelled session does not cost the slot (the copy was open, not the slot);
#   * one database per process, always `close_database(False)`: a second `open_database` in a process
#     silently saves and closes the first one (measured), so the worker has exactly one open.

_IDALIB_PROBE_CODE = r'''
import json, sys
out = sys.argv[1]
info = {"import_ok": False}
try:
    import idapro
    info["import_ok"] = True
    try:
        import os
        from importlib import metadata
        # The version of the distribution that OWNS the imported module. A same-named dist-info that
        # merely sits on sys.path says nothing about this module, so every distribution is scanned and
        # none owning it is reported as None.
        module_file = os.path.normcase(os.path.realpath(idapro.__file__))
        info["idapro_version"] = None
        for dist in metadata.distributions(name="idapro"):
            if any(os.path.normcase(os.path.realpath(str(dist.locate_file(f)))) == module_file
                   for f in (dist.files or [])):
                info["idapro_version"] = dist.version
                break
    except Exception:
        info["idapro_version"] = None
    try:
        info["library_version"] = list(idapro.get_library_version())
    except Exception:
        info["library_version"] = None
    try:
        info["install_dir"] = str(idapro.get_ida_install_dir())
    except Exception:
        info["install_dir"] = None
except BaseException as exc:
    info["error"] = type(exc).__name__ + ": " + str(exc)[:300]
with open(out, "w", encoding="utf-8") as handle:
    json.dump(info, handle)
'''


def _idalib_probe(*, use_cache=True):
    """Can the interpreter named by LIEBERT_RE_IDALIB_PYTHON `import idapro`? Returns `(public, private)`.

    `public` is safe to return (paths redacted); `private` carries the raw interpreter and install
    directory for the caller. The probe is an import and nothing else: it does not open a database and
    it does not prove a licence, so `status: OK` means "the package imports", not "a file will analyse".
    A successful probe is cached for `_IDALIB_PROBE_CACHE_SECONDS`; a failure never is. The interpreter is
    never guessed: no variable, no idalib."""
    raw = os.environ.get(IDALIB_PYTHON_ENV, "").strip()
    public = {"env_var": IDALIB_PYTHON_ENV, "configured": bool(raw), "status": "NOT_CONFIGURED",
              "interpreter": None, "idapro_version": None, "library_version": None, "install_dir": None,
              "measured_by": ("ran `import idapro` in that interpreter; no database was opened and no licence "
                              "check was made")}
    if not raw:
        public["reason"] = f"{IDALIB_PYTHON_ENV} is not set; no interpreter is guessed"
        return public, {}
    interpreter = Path(raw)
    public["interpreter"] = _redact(str(interpreter))
    try:
        info = interpreter.stat()
    except OSError:
        info = None
    if info is None or not interpreter.is_file():
        public.update(status="INTERPRETER_NOT_FOUND", reason=f"{IDALIB_PYTHON_ENV} does not name an existing file")
        return public, {}
    key = (str(interpreter), info.st_mtime_ns, info.st_size, os.environ.get("IDADIR", ""))
    cached = _IDALIB_PROBE_CACHE.get(key) if use_cache else None
    if cached and time.monotonic() - cached[0] < _IDALIB_PROBE_CACHE_SECONDS:
        return dict(cached[1][0]), dict(cached[1][1])
    try:
        scratch = tempfile.TemporaryDirectory(prefix="liebert-idalib-probe-")
    except OSError as exc:
        public.update(status="PROBE_FAILED", reason=f"{type(exc).__name__}: no scratch directory for the probe")
        return public, {}
    with scratch as directory:
        out = Path(directory) / "probe.json"
        try:
            cp = run_bounded_process(
                [str(interpreter), "-I", "-X", "utf8", "-c", _IDALIB_PROBE_CODE, str(out)],
                timeout_seconds=_IDALIB_PROBE_TIMEOUT_SECONDS, cwd=directory, environment=dict(os.environ),
                max_output_chars=_IDALIB_MAX_OUTPUT_CHARS,
            )
        except OSError as exc:
            public.update(status="INTERPRETER_NOT_LAUNCHABLE", reason=f"{type(exc).__name__}: the interpreter did not start")
            return public, {}
        if cp.launch_failed is True:
            public.update(status="INTERPRETER_NOT_LAUNCHABLE", reason=_redact(str(cp.launch_error or "the interpreter did not start")))
            return public, {}
        if cp.timed_out:
            public.update(status="PROBE_TIMEOUT", reason=f"`import idapro` did not finish in {_IDALIB_PROBE_TIMEOUT_SECONDS} s")
            return public, {}
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict):
            public.update(status="PROBE_FAILED", exit_code=cp.returncode,
                          reason="the probe wrote no readable result", stderr_tail=_tail(cp.stderr, limit=500))
            return public, {}
    if data.get("import_ok") is not True:
        public.update(status="IDAPRO_IMPORT_FAILED", reason=_redact(str(data.get("error") or "import idapro failed")))
        return public, {}
    version, library, install = data.get("idapro_version"), data.get("library_version"), data.get("install_dir")
    public.update(idapro_version=version if isinstance(version, str) else None,
                  library_version=library if isinstance(library, list) else None,
                  install_dir=_redact(install) if isinstance(install, str) and install else None)
    if not (isinstance(install, str) and install):
        # Cache slots are keyed by the engine that built them; an engine that cannot be identified cannot key one.
        public.update(status="ENGINE_UNIDENTIFIED",
                      reason="`import idapro` worked but the IDA install directory could not be read, so the "
                             "cache cannot tell which engine built a database")
        return public, {}
    public["status"] = "OK"
    public["reason"] = "`import idapro` succeeded in that interpreter"
    private = {"python": str(interpreter), "install_dir": install}
    if use_cache:
        _IDALIB_PROBE_CACHE[key] = (time.monotonic(), (dict(public), dict(private)))
    return public, private


def _idalib_engine_exe(install_dir):
    """The path whose neighbours name the engine in a slot's key: idat in the same install when there is one
    (so both backends share slots built by the same IDA), else a nominal idat path whose neighbouring
    kernel library still identifies the install."""
    return _binary_in(install_dir) or str(Path(install_dir) / "idat.exe")


def _choose_backend(requested):
    """Decide which engine answers. Returns `{"info", "used", "python", "engine_exe", "failure"}`.

    `info` is the `backend` object of every response: `{"requested", "used", "reason"}` (plus the idalib
    interpreter and versions when idalib is used). `failure` is a finished refusal body (or None).
    "auto" is idalib only when LIEBERT_RE_IDALIB_PYTHON is set AND `import idapro` works in that
    interpreter; otherwise idat, and `reason` says which of the two it was. A fallback is announced, and a
    session that failed on the selected backend is not retried on the other one."""
    requested = str(requested)
    info = {"requested": requested, "used": None, "reason": ""}
    out = {"info": info, "used": None, "python": None, "engine_exe": None, "failure": None}
    if requested not in _BACKENDS:
        info["reason"] = "backend must be one of " + ", ".join(_BACKENDS)
        out["failure"] = {"ok": False, "tool": "ida_query", "status": "ANALYSIS_LIMITED", "error": "UNKNOWN_BACKEND",
                          "given": requested, "accepted": list(_BACKENDS)}
        return out
    if requested == "idat":
        info.update(used="idat", reason="requested explicitly")
        out["used"] = "idat"
        return out
    public, private = _idalib_probe()
    if requested == "idalib":
        if public["status"] != "OK":
            info["reason"] = f"idalib was requested but is not usable: {public['status']}"
            out["failure"] = {
                "ok": False, "tool": "ida_query", "status": "TOOL_MISSING",
                "error": "IDALIB_NOT_CONFIGURED" if public["status"] == "NOT_CONFIGURED" else "IDALIB_UNUSABLE",
                "required_capability": "an interpreter with Hex-Rays' `idapro` package (idalib)",
                "idalib": public,
                "detail": (f"Set {IDALIB_PYTHON_ENV} to the full path of a Python interpreter in which `import idapro` "
                           "works (pip install the `idapro` package that ships with IDA and run its py-activate-idalib). "
                           "Nothing was started and no other backend was used."),
            }
            return out
        used, why = "idalib", f"requested explicitly; {IDALIB_PYTHON_ENV} is set and `import idapro` succeeded"
    elif public["status"] == "OK":
        used, why = "idalib", f"{IDALIB_PYTHON_ENV} is set and `import idapro` succeeded in that interpreter"
    elif public["status"] == "NOT_CONFIGURED":
        info.update(used="idat", reason=f"{IDALIB_PYTHON_ENV} is not set, so idalib is not configured (no interpreter is guessed)")
        out["used"] = "idat"
        return out
    else:
        info.update(used="idat", reason=(f"{IDALIB_PYTHON_ENV} is set but the idalib probe failed ({public['status']}: "
                                         f"{public.get('reason')}); fell back to idat"))
        out["used"] = "idat"
        return out
    info.update(used=used, reason=why, interpreter=public["interpreter"], idapro_version=public["idapro_version"],
                library_version=public["library_version"])
    out.update(used=used, python=private["python"], engine_exe=_idalib_engine_exe(private["install_dir"]))
    return out


def _tag_backend(text, info):
    """Put the `backend` object into a finished JSON response (every response of `ida_query` carries it)."""
    try:
        body = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(body, dict):
        return text
    body["backend"] = info
    return _j(body)


def _write_idalib_files(work, job, *, with_ops=True):
    """The worker, the shared operations file and the job, in the scratch directory (BOM-free, LF).
    `with_ops=False` (a script session) leaves the operations file out: that mode does not run it."""
    try:
        sources = [(_IDALIB_JOB_SCRIPT, _IDALIB_WORKER_SOURCE.read_bytes())]
        if with_ops:
            sources.append((_IDALIB_OPS_NAME, _WORKER_SOURCE.read_bytes()))
    except OSError as exc:
        raise _EnvironmentFailure("IDA_WORKER_UNREADABLE", exc) from exc
    try:
        for name, raw in sources:
            if raw.startswith(b"\xef\xbb\xbf"):
                raw = raw[3:]
            (work / name).write_bytes(raw.replace(b"\r\n", b"\n"))
        (work / _IDALIB_JOB_NAME).write_text(json.dumps(job), encoding="utf-8")
    except OSError as exc:
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc


def _launch_idalib(python, work, job, *, timeout_seconds, cancellation_token, max_memory_bytes=None):
    """Run the idalib worker once in `work`. `-I` keeps the interpreter from reading PYTHON* variables, the
    user site or the working directory's modules; `-X utf8` fixes the encoding of the (ignored) console output.
    `max_memory_bytes` (a script session only) is polled against the process tree's resident size."""
    _write_idalib_files(work, job, with_ops=job.get("mode") != "script")
    command = [str(python), "-I", "-X", "utf8", _IDALIB_JOB_SCRIPT, _IDALIB_JOB_NAME]
    limits = {} if max_memory_bytes is None else {"max_memory_bytes": max_memory_bytes}
    try:
        cp = run_bounded_process(
            command, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token, cwd=work,
            environment=dict(os.environ), max_output_chars=_IDALIB_MAX_OUTPUT_CHARS, **limits,
        )
    except OSError as exc:
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", exc) from exc
    if cp.launch_failed is True:
        raise _EnvironmentFailure("IDA_LAUNCH_FAILED", OSError(None, cp.launch_error))
    return cp, command


def _verdict_idalib(cp, work, *, creating, operations):
    """The idalib session's signals, read together (the idat `_verdict` for a worker that answers a list
    of operations). Returns `(envelope, first_result, error, signals)`; `error` is None only when every
    signal agrees. stdout is deliberately NOT scanned for failure markers: IDA plugins print banners and
    warnings there; only the log and stderr are."""
    try:
        log = Path(work / _LOG_NAME).read_text(encoding="utf-8", errors="replace")
        log_readable = True
    except OSError:
        log, log_readable = "", False
    combined = "\n".join((log, cp.stderr or "")).lower()
    markers = sorted({m for m in _FATAL_MARKERS if m in combined})
    network = sorted({m for m in _NETWORK_MARKERS if m in log.lower()})
    db_path = work / _DB_NAME
    try:
        db_bytes = db_path.stat().st_size if db_path.is_file() else 0
    except OSError:
        db_bytes = 0
    loose = sorted(q.name for q in work.iterdir() if q.suffix.lower() in _LOOSE_COMPONENTS) if work.is_dir() else []
    result_path = work / _IDALIB_RESULT_NAME
    result_present = result_path.is_file()
    try:
        result_bytes = result_path.stat().st_size if result_present else 0
    except OSError:
        result_bytes = 0
    envelope, parse_error, completed, too_large = None, None, False, False
    if result_present and result_bytes > _IDALIB_MAX_RESULT_BYTES:
        too_large = True
    elif result_present:
        try:
            envelope = json.loads(result_path.read_text(encoding="utf-8"))
            completed = isinstance(envelope, dict) and envelope.get("script_completed") is True
        except (OSError, ValueError) as exc:
            parse_error = f"{type(exc).__name__}: {exc}"
    if not isinstance(envelope, dict):
        envelope = None
    results = envelope.get("results") if envelope else None
    expected = [o["operation"] for o in operations]
    operation_matches = bool(completed and isinstance(results, list) and len(results) == len(expected)
                             and all(isinstance(r, dict) and r.get("operation") == name for r, name in zip(results, expected)))
    signals = {
        "exit_code": cp.returncode,
        "log_present": bool(log),
        "log_readable": log_readable,
        "log_fatal_markers": markers,
        "database_present": db_bytes > 0,
        "database_bytes": db_bytes,
        "loose_components": loose,
        "result_file_present": result_present,
        "result_file_bytes": result_bytes,
        "result_script_completed": completed,
        "result_operation_matches": operation_matches,
        "database_closed_without_save": (envelope or {}).get("database_closed_without_save") is True,
        "log_network_text_found": bool(network),
        "log_network_text_markers_scanned": list(_NETWORK_MARKERS),
        "log_network_text_evidence_limit": _NETWORK_SCAN_LIMIT,
        "worker": {"idapro_version": (envelope or {}).get("idapro_version"),
                   "library_version": (envelope or {}).get("library_version"),
                   "open_rc": (envelope or {}).get("open_rc"),
                   "database_saved_before_queries": (envelope or {}).get("database_saved_before_queries")},
    }
    first = results[0] if operation_matches and results else None     # a script session answers no operation
    if too_large:
        return None, None, "IDALIB_RESULT_TOO_LARGE", {**signals, "result_limit_bytes": _IDALIB_MAX_RESULT_BYTES}
    if parse_error:
        return None, None, "RESULT_PARSE_FAILED", {**signals, "parse_error": parse_error}
    if cp.returncode not in (0, None):
        if completed:
            kind = "NONZERO_EXIT_RESULT_COMPLETE"
        elif result_present:
            kind = "NONZERO_EXIT_RESULT_INCOMPLETE"
        else:
            kind = "NONZERO_EXIT_NO_RESULT"
        signals["exit_diagnosis"] = {"class": kind, "exit_code": cp.returncode, "result_file_present": result_present,
                                     "script_completed": completed, "log_fatal_markers": markers,
                                     "log_class": _classify_exit_log(log if log_readable else None)}
        return envelope, None, "IDA_EXITED_NONZERO", signals
    if markers:
        return envelope, None, "IDA_LOG_REPORTS_FAILURE", signals
    if not log_readable or not log:
        return envelope, None, "IDA_LOG_UNREADABLE", signals
    if not result_present:
        return None, None, "IDA_NO_OUTPUT", signals
    if not completed:
        return None, None, "IDA_OUTPUT_INCOMPLETE", signals
    if envelope.get("ok") is False and envelope.get("error"):
        return envelope, None, "IDALIB_WORKER_FAILED", signals
    if not operation_matches:
        return envelope, None, "IDA_RESULT_OPERATION_MISMATCH", signals
    if not signals["database_closed_without_save"]:
        return envelope, first, "DATABASE_CHANGES_NOT_DISCARDED", signals
    if creating and (envelope.get("database_saved_before_queries") is not True or db_bytes <= 0 or loose):
        return envelope, first, "IDA_NO_DATABASE", signals
    return envelope, first, None, signals


def _run_idalib_session(python, p, sha256, md5, slot, *, creating, invocation, cancellation_token):
    """One idalib worker process in its own scratch directory, and its verdict. `creating` analyses `p` into
    the scratch directory and, only if every signal agrees, promotes the saved database into `slot`; otherwise
    a COPY of the cached database is opened and the slot is measured before and after. Returns
    `(data, signals, provenance)` (`data` is the one query result) or raises `_StageFailure`.

    The scratch directory is always deleted. A timed-out or cancelled session leaves the slot alone (the
    slot was not what was open); only a measured change of the slot, a provenance mismatch or an unreadable
    slot drops it."""
    tool = "ida_query"
    operation = invocation["operation"]
    total = invocation["timeout_seconds"]
    timeout_seconds = min(total, _MAX_CREATE_TIMEOUT_SECONDS if creating else _MAX_QUERY_TIMEOUT_SECONDS)
    work = slot / f"work-{uuid.uuid4().hex[:8]}"
    work.mkdir()
    job = {
        "schema": 1, "mode": "create" if creating else "copy", "output": str(work / _IDALIB_RESULT_NAME),
        "ops_path": str(work / _IDALIB_OPS_NAME), "database_name": _DB_NAME, "log_name": _LOG_NAME,
        "max_result_bytes": _IDALIB_MAX_RESULT_BYTES,
        "operations": [{"operation": operation, "query": invocation.get("query", ""),
                        "max_results": invocation["max_results"], "offset": invocation["offset"]}],
    }
    if creating:
        job["input"] = str(p)
    keep_work = False
    try:
        db_before = None
        if not creating:
            try:
                db_before = _sha256_md5(slot / _DB_NAME)[0]
                shutil.copyfile(slot / _DB_NAME, work / _DB_NAME)
            except OSError as exc:
                raise _StageFailure(_EnvironmentFailure("IDA_DATABASE_UNREADABLE", exc).body(
                    tool, invocation=invocation, target_sha256=sha256)) from exc
        started = time.monotonic()
        try:
            cp, _command = _launch_idalib(python, work, job, timeout_seconds=timeout_seconds,
                                          cancellation_token=cancellation_token)
        except _EnvironmentFailure as failure:
            raise _StageFailure(failure.body(tool, invocation=invocation, target_sha256=sha256)) from failure
        elapsed = round(time.monotonic() - started, 3)
        integrity = None
        if not creating:
            try:
                db_after = _sha256_md5(slot / _DB_NAME)[0]
            except OSError:
                db_after = None
            integrity = {"database_sha256_before": db_before, "database_sha256_after": db_after,
                         "unchanged": db_after == db_before, "opened": "a copy in the scratch directory"}
            if db_after != db_before:
                _evict_slot(slot)
                raise _StageFailure({
                    "ok": False, "tool": tool, "status": "CACHE_VIOLATION", "error": "CACHE_VIOLATION",
                    "invocation": invocation, "target_sha256": sha256, "database_integrity": integrity,
                    "detail": (
                        "The cached database file differed after the session (or could not be read again), "
                        "although only a copy of it was opened. The cache slot was deleted and no answer is "
                        "returned; the next call analyses the input again."
                    ),
                })
        if cp.cancelled or cp.timed_out:
            body = {"ok": False, "tool": tool, "status": "CANCELLED" if cp.cancelled else "TIMEOUT",
                    "invocation": invocation, "target_sha256": sha256,
                    "error": "IDA_CANCELLED_PROCESS_TREE_TERMINATED" if cp.cancelled
                    else "IDA_TIMEOUT_PROCESS_TREE_TERMINATED"}
            if integrity is not None:
                body["database_integrity"] = integrity
            if cp.timed_out:
                body["timeout_seconds"] = timeout_seconds
                body["timed_out_stage"] = "analysis" if creating else "query"
                body["stage_ceiling_seconds"] = _MAX_CREATE_TIMEOUT_SECONDS if creating else _MAX_QUERY_TIMEOUT_SECONDS
                body["detail"] = (
                    "The first analysis of a large file can exceed the timeout; an incomplete analysis is "
                    "discarded, so the next call starts over. A question on a cached database ran on a copy, "
                    "so the cache slot was kept. Do not read a timeout as 'nothing found'."
                )
            raise _StageFailure(body)
        envelope, data, error, signals = _verdict_idalib(cp, work, creating=creating, operations=job["operations"])
        signals["elapsed_seconds"] = elapsed
        if integrity is not None:
            signals["database_integrity"] = integrity
        if error:
            extra = {"invocation": invocation, "target_sha256": sha256}
            if isinstance(envelope, dict) and envelope.get("error"):
                extra["worker_error"] = envelope.get("error")
                if envelope.get("traceback"):
                    extra["worker_traceback"] = _redact(str(envelope["traceback"]), work=work, target=p)[-2000:]
            raise _StageFailure(_failure_response(
                tool, "RESULT_PARSE_FAILED" if error == "RESULT_PARSE_FAILED" else "ANALYSIS_LIMITED", error,
                operation=operation, signals=signals, cp=cp, work=work, target=p, extra=extra,
            ))
        # The verdict above already required the worker's `database_closed_without_save`; the answer carries
        # the same field the idat path's reopen session reports, so the two backends' answers have one shape.
        data["database_changes_discarded"] = True
        provenance = _provenance(sha256, md5, data)
        if provenance["status"] == "MISMATCH":
            if not creating:
                _evict_slot(slot)
            raise _StageFailure({
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_INPUT_HASH_MISMATCH",
                "target_sha256": sha256, "provenance": provenance, "invocation": invocation, "signals": signals,
                "detail": "the engine's recorded input is not the file that was hashed; refusing to return a result computed over other bytes.",
            })
        if creating:
            os.replace(work / _DB_NAME, slot / _DB_NAME)
            _touch_meta(slot, sha256, created=True)
        else:
            _touch_meta(slot, sha256)
        return data, signals, provenance
    except _StageFailure as failure:
        if _keep_failed_scratch() and work.is_dir():
            keep_work = True
            failure.body["scratch_retained"] = _retained_scratch(work, _cache_root(), "<CACHE>")
        raise
    finally:
        if not keep_work:
            shutil.rmtree(work, ignore_errors=True)


def _query_locked_idalib(engine_exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile):
    """`_query_locked` for the idalib backend: the same slot lifecycle, one session per question (a first
    analysis answers the question in the session that builds the database)."""
    tool = "ida_query"
    operation = invocation["operation"]
    scratch_kept = False
    slot.mkdir(parents=True, exist_ok=True)
    for stale in slot.glob("work-*"):       # under the lock, any scratch directory here is an abandoned attempt
        shutil.rmtree(stale, ignore_errors=True)
    cache_state = "HIT"
    if (slot / _DB_NAME).exists() and not _slot_is_healthy(slot):
        _evict_slot(slot)
        slot.mkdir(parents=True, exist_ok=True)
        cache_state = "REBUILT"
    elif not (slot / _DB_NAME).exists():
        cache_state = "CREATED"
    try:
        data, signals, provenance = _run_idalib_session(
            profile["python"], p, sha256, md5, slot, creating=cache_state != "HIT", invocation=invocation,
            cancellation_token=cancellation_token,
        )
        return _answer_from_worker(
            tool, p, sha256, md5, slot, operation, data, signals, provenance, cache_state=cache_state,
            invocation=invocation, max_chars=max_chars, profile=profile,
        )
    except _StageFailure as failure:
        scratch_kept = "scratch_retained" in failure.body
        return failure.body
    finally:
        if not (slot / _DB_NAME).exists() and not scratch_kept:
            shutil.rmtree(slot, ignore_errors=True)


# --------------------------------------------------------------------------
# ida_script: caller-written IDAPython on a discarded copy of the database (idalib backend only)
# --------------------------------------------------------------------------
#
# What this is: the caller (a model or a person) hands over IDAPython source; it runs inside an idalib worker
# on a COPY of the cached database and the answer is the JSON value the script leaves in `result`.
# What it is NOT: a sandbox. The script runs with the operator's rights, inheriting the environment, the
# network and the file system. The accident guard below refuses the mistakes a model makes by accident (an
# `os` import, a `save_database` call, an `open`); it does not stop a determined script, and every answer
# says so (`guard.kind`, `execution.*: NOT_ENFORCED`). The key (`LIEBERT_RE_IDA_SCRIPT=authorized`) is the
# operator's decision to allow that, made per machine.
#
# Why idalib only: the idalib backend already opens a COPY of the cached database (never the slot) and
# measures the slot before and after. idat opens the slot itself and relies on a flag a script could clear,
# so `ida_script` has no idat path at all.
#
# Why a mode of the idalib worker and not a second worker file: the worker has exactly one
# `open_database` and one `close_database(False)` in a `finally`, pinned by a test. A second worker file
# would be a second place to get that wrong, and a second open in one process silently SAVES the first
# database (measured).
#
# Session: first analysis (only when the slot is absent), in its own `summary` session that promotes the
# pristine database; then the script session: hash the slot, copy it into a scratch directory, hash the
# copy, run the worker on the copy, hash the slot again. A changed slot is CACHE_VIOLATION (slot dropped,
# no result); a timeout or cancellation does not cost the slot (it was never open).

SCRIPT_GATE_ENV = "LIEBERT_RE_IDA_SCRIPT"
SCRIPT_GATE_VALUE = "authorized"
_DEFAULT_SCRIPT_TIMEOUT_SECONDS = 120
_MIN_SCRIPT_TIMEOUT_SECONDS = 5
_MAX_SCRIPT_TIMEOUT_SECONDS = 300
_SCRIPT_MAX_BYTES = 64 * 1024
_SCRIPT_DEFAULT_MEMORY_BYTES = 4 * 1024 ** 3
_SCRIPT_MIN_MEMORY_BYTES = 512 * 1024 ** 2
_SCRIPT_MAX_MEMORY_BYTES = 64 * 1024 ** 3
_SCRIPT_FILE_NAME = "script.py"
_SCRIPT_MIN_RESPONSE_CHARS = 8000
_SCRIPT_GUARD = {"kind": "ACCIDENT_GUARD_NOT_A_SANDBOX", "version": 1}
_SCRIPT_NOT_A_SANDBOX = (
    "This guard refuses the mistakes a model makes by accident. It is not a sandbox: a script can still reach the "
    "host in ways it does not look for, and the process inherits the environment, the network and the file system."
)

# Modules a script may not import. Anything not in the allow-list below is also refused (IMPORT_NOT_ALLOWED);
# this list only gives the common ones a clearer name.
_GUARD_FORBIDDEN_MODULES = frozenset({
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "ctypes", "importlib", "builtins", "urllib", "http",
    "multiprocessing", "threading", "asyncio", "ida_dbg", "ida_idd", "ida_fpro", "ida_expr", "ida_registry", "idapro",
})
_GUARD_ALLOWED_STDLIB = frozenset({
    "re", "struct", "math", "collections", "itertools", "functools", "hashlib", "binascii", "json", "bisect",
    "heapq", "array", "typing", "string", "operator", "enum",
})
_GUARD_ALLOWED_IDA = frozenset({"idaapi", "idc", "idautils"})        # plus every `ida_*` module not forbidden above
# Builtins a script may not use by name.
_GUARD_FORBIDDEN_BUILTINS = frozenset({
    "open", "exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "vars", "locals",
    "input", "breakpoint", "help",
})
# IDA API names that start a debugger (the sample would run on the host), load or run code, write files,
# evaluate IDC, or save / reopen the database (`open_database` / `close_database` / `save_database` / `idapro`:
# a second open in one process silently saves and closes the first database, measured). Matched as attribute
# names and as used or imported names.
_GUARD_FORBIDDEN_API = frozenset({
    "idapro", "open_database", "close_database", "save_database", "save_database_ex", "gen_file", "gen_exe_file",
    "GenerateFile", "savefile", "loadfile", "fopen", "qfopen", "start_process", "attach_process", "detach_process",
    "exit_process", "run_to", "continue_process", "suspend_process", "load_debugger", "load_plugin", "run_plugin",
    "load_and_run_plugin", "IDAPython_ExecScript", "exec_system_script", "exec_idc_script",
})
_GUARD_FORBIDDEN_API_PREFIXES = ("eval_idc", "gen_", "dbg_")
# The two underscore attributes ordinary IDAPython needs: `ida_hexrays.ctree_visitor_t.__init__(self, flags)` is the
# canonical way to start a visitor, and `__name__` is harmless. Every other attribute starting with `_` is refused
# (`__class__`, `__dict__`, `__globals__`, `__subclasses__`, ... are how a script walks out of its namespace).
_GUARD_ALLOWED_DUNDER_ATTRIBUTES = frozenset({"__init__", "__name__"})
_GUARD_MAX_FINDINGS = 40


def _guard_module_rule(name):
    top = str(name).split(".")[0]
    if top in _GUARD_FORBIDDEN_MODULES:
        return "FORBIDDEN_IMPORT"
    if top in _GUARD_ALLOWED_STDLIB or top in _GUARD_ALLOWED_IDA or top.startswith("ida_"):
        return None
    return "IMPORT_NOT_ALLOWED"


def _guard_api_forbidden(name):
    return name in _GUARD_FORBIDDEN_API or name.startswith(_GUARD_FORBIDDEN_API_PREFIXES)


def _script_guard_findings(tree):
    """The accident guard over a parsed script. Returns `(findings, total)`: findings is a list of
    `{"rule", "name", "line", "column"}` (at most `_GUARD_MAX_FINDINGS`), total the number found; an empty list
    means nothing was refused. A syntactic check on names: it cannot see a name built at run time."""
    found = []

    def add(rule, name, node):
        found.append({"rule": rule, "name": str(name)[:80], "line": getattr(node, "lineno", None),
                      "column": getattr(node, "col_offset", None)})

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                rule = _guard_module_rule(alias.name)
                if rule:
                    add(rule, alias.name, node)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                add("RELATIVE_IMPORT", "." * node.level + (node.module or ""), node)
                continue
            rule = _guard_module_rule(node.module or "")
            if rule:
                add(rule, node.module or "", node)
            for alias in node.names:
                if alias.name in _GUARD_FORBIDDEN_MODULES or _guard_api_forbidden(alias.name) \
                        or alias.name in _GUARD_FORBIDDEN_BUILTINS or alias.name.startswith("_"):
                    add("FORBIDDEN_IMPORTED_NAME", alias.name, node)
        elif isinstance(node, ast.Name):
            if node.id in _GUARD_FORBIDDEN_BUILTINS or _guard_api_forbidden(node.id):
                add("FORBIDDEN_NAME", node.id, node)
            elif node.id.startswith("__") and node.id != "__name__":
                add("DUNDER_NAME", node.id, node)
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_") and node.attr not in _GUARD_ALLOWED_DUNDER_ATTRIBUTES:
                add("PRIVATE_ATTRIBUTE", node.attr, node)
            elif node.attr in _GUARD_FORBIDDEN_MODULES or _guard_api_forbidden(node.attr):
                add("FORBIDDEN_ATTRIBUTE", node.attr, node)
    found.sort(key=lambda f: (f["line"] or 0, f["column"] or 0, f["rule"]))
    unique, seen = [], set()
    for item in found:
        key = (item["rule"], item["name"], item["line"], item["column"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique[:_GUARD_MAX_FINDINGS], len(unique)


def _script_refusal(error, status="ANALYSIS_LIMITED", **fields):
    body = {"ok": False, "tool": "ida_script", "status": status, "error": error}
    body.update(fields)
    return body


def _script_precheck(script):
    """Every check that needs no IDA. Returns `(checked_script, None)` or `(None, refusal_body)`.

    The order: type / size / encoding, then Python syntax (`compiled_by: harness_python`; the worker compiles
    again with IDA's own interpreter), then the accident guard."""
    if not isinstance(script, str) or not script.strip():
        return None, _script_refusal("SCRIPT_INVALID", reason="SCRIPT_EMPTY",
                                     detail="`script` must be a non-empty string of IDAPython source. Nothing was started.")
    try:
        raw = script.encode("utf-8")
    except UnicodeEncodeError:
        return None, _script_refusal("SCRIPT_INVALID", reason="SCRIPT_NOT_UTF8",
                                     detail="The script cannot be encoded as UTF-8. Nothing was started.")
    if len(raw) > _SCRIPT_MAX_BYTES:
        return None, _script_refusal("SCRIPT_INVALID", reason="SCRIPT_TOO_LARGE", bytes=len(raw),
                                     limit_bytes=_SCRIPT_MAX_BYTES, detail="The script is larger than the limit. Nothing was started.")
    if "\x00" in script:
        return None, _script_refusal("SCRIPT_INVALID", reason="SCRIPT_CONTAINS_NUL",
                                     detail="The script contains a NUL character. Nothing was started.")
    try:
        tree = ast.parse(script, filename="<liebert_script>")
        compile(tree, "<liebert_script>", "exec", dont_inherit=True)
    except SyntaxError as exc:
        return None, _script_refusal("SCRIPT_SYNTAX_ERROR", compiled_by="harness_python", line=exc.lineno,
                                     offset=exc.offset, message=_redact(str(exc.msg))[:300],
                                     detail="Nothing was started.")
    except (ValueError, RecursionError, MemoryError) as exc:
        return None, _script_refusal("SCRIPT_SYNTAX_ERROR", compiled_by="harness_python",
                                     message=type(exc).__name__, detail="Nothing was started.")
    findings, total = _script_guard_findings(tree)
    if findings:
        return None, _script_refusal(
            "SCRIPT_GUARD_REFUSED", findings=findings, finding_count=total, guard=dict(_SCRIPT_GUARD),
            detail=f"The script uses something the accident guard refuses. Nothing was started. {_SCRIPT_NOT_A_SANDBOX}")
    return {
        "raw": raw, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "lines": script.count("\n") + (0 if script.endswith("\n") else 1),
    }, None


def _script_summary(script):
    return {"sha256": script["sha256"], "bytes": script["bytes"], "lines": script["lines"], "guard": dict(_SCRIPT_GUARD)}


def _redact_value(value, *, target=None):
    """`_redact` over every string of a JSON value (keys are left alone). Returns `(value, changed)`."""
    changed = False

    def walk(item):
        nonlocal changed
        if isinstance(item, str):
            clean = _redact(item, target=target)
            changed = changed or clean != item
            return clean
        if isinstance(item, list):
            return [walk(x) for x in item]
        if isinstance(item, dict):
            return {k: walk(v) for k, v in item.items()}
        return item
    return walk(value), changed


def ida_script(path, script, *, timeout_seconds=_DEFAULT_SCRIPT_TIMEOUT_SECONDS, max_result_chars=60000,
               max_stdout_chars=16384, max_memory_bytes=_SCRIPT_DEFAULT_MEMORY_BYTES, max_chars=60000,
               backend="auto", cancellation_token=None):
    """Run caller-written IDAPython against `path` in an idalib session on a DISCARDED COPY of its cached
    database, and return the JSON value the script left in the variable `result`.

    **Not a sandbox.** The script runs with your rights; the child process inherits the environment, the
    network and the file system, and none of that is restricted (every answer says `NOT_ENFORCED`). An
    accident guard refuses the usual mistakes before anything starts (imports outside `re struct math
    collections itertools functools hashlib binascii json bisect heapq array typing string operator enum` and
    `ida_* / idaapi / idc / idautils`; `open exec eval compile getattr setattr globals vars __import__`;
    attributes starting with `_`; `idapro`, `open_database`, `close_database`, `save_database`; debugger,
    file-writing and IDC-evaluating IDA calls; `ida_dbg` so the sample is never run). It is a syntactic check
    and can be evaded; it is a guard against accidents, not against a script written to get out.

    **Gate.** Off unless the environment variable `LIEBERT_RE_IDA_SCRIPT` is exactly `authorized` in the
    environment this process was started from (`AUTHORIZATION_REQUIRED`, nothing started, otherwise).

    **Backend.** idalib only: the interpreter named by `LIEBERT_RE_IDALIB_PYTHON`. `backend="idat"`, or an
    idalib that is not configured or does not import, is `UNSUPPORTED` and nothing starts. The cached
    database is never opened: a copy is, and the cache slot's hash is taken before and after (`CACHE_VIOLATION`,
    slot dropped, no result, if it moved). A first call on a file also pays for the analysis in an earlier,
    separate session (the `summary` session of `ida_query`).

    **The script.** UTF-8 text of at most 64 KiB, run once with `exec`. Its answer is the variable `result`,
    which must be JSON (`NaN` is not). `LIEBERT_CONTEXT` (a dict: `input_sha256`, `max_result_chars`) is in
    scope. stdout and stderr are captured into a buffer of `max_stdout_chars` (the tail is returned); a
    result is never read from stdout. Whatever the script does to the open database stays in the copy, which
    is closed without saving; the answer is the state the script saw.

    **Limits.** `timeout_seconds` (5..300, default 120) bounds the script session (the process tree is
    killed; the slot is kept). `max_memory_bytes` (512 MiB..64 GiB, default 4 GiB) is polled against the
    process tree's resident size; a host that cannot measure it is `RESOURCE_LIMIT_UNAVAILABLE` (fail closed).
    `max_result_chars` bounds the script's `result` (larger: `PARTIAL`, `script_result_withheld`); `max_chars`
    bounds the whole response and is never met by cutting the result: a result that does not fit is withheld
    (`PARTIAL`, `TOO_LARGE_FOR_MAX_CHARS`; the evidence file holds it).

    **Status vocabulary.** OK, PARTIAL (a result withheld because of a size limit; says which),
    AUTHORIZATION_REQUIRED, UNSUPPORTED, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT
    (`timed_out_stage: "script"`), CANCELLED, MEMORY_LIMIT, RESOURCE_LIMIT_UNAVAILABLE, CACHE_VIOLATION,
    RESULT_PARSE_FAILED, ANALYSIS_LIMITED with `error` one of SCRIPT_INVALID, SCRIPT_SYNTAX_ERROR,
    SCRIPT_GUARD_REFUSED, SCRIPT_EXCEPTION (redacted traceback and stdout tail), SCRIPT_NO_RESULT,
    SCRIPT_RESULT_NOT_JSON, SCRIPT_HASH_MISMATCH, SCRIPT_COPY_MISMATCH, DATABASE_CHANGES_NOT_DISCARDED,
    EVIDENCE_WRITE_FAILED (the result is withheld when the evidence record cannot be written) and the
    environment errors of `ida_query`.

    **What the answer claims.** `result_kind: "SCRIPT_REPORTED"`: the harness verified the input hash, that
    this script text ran to completion inside IDA on this input, and that the cached database was unchanged.
    `script_result` is the script's claim; the harness did not verify its content. The full record (script
    text, worker result, stdout tail, signals) is saved under `dataset/evidence/ida_script/`.

    No script is stored in this repository for any real product; examples in docs use code-built fixtures.
    """
    tool = "ida_script"
    if os.environ.get(SCRIPT_GATE_ENV, "").strip() != SCRIPT_GATE_VALUE:
        return _j({
            "ok": False, "tool": tool, "status": "AUTHORIZATION_REQUIRED", "error": "SCRIPT_GATE_CLOSED",
            "required_environment": f"{SCRIPT_GATE_ENV}={SCRIPT_GATE_VALUE}",
            "detail": ("Running caller-written IDAPython is off by default. The operator opens it for this machine by "
                       f"setting {SCRIPT_GATE_ENV}={SCRIPT_GATE_VALUE} in the environment the harness is started from. "
                       "Nothing was started and nothing was read."),
        })
    if backend not in _BACKENDS:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "UNKNOWN_BACKEND",
                   "given": str(backend), "accepted": list(_BACKENDS)})
    unsupported = {
        "ok": False, "tool": tool, "status": "UNSUPPORTED", "error": "IDALIB_BACKEND_REQUIRED",
        "reason": f"requires the idalib copy-on-open backend (set {IDALIB_PYTHON_ENV})",
        "detail": ("ida_script runs only where a COPY of the cached database is opened and the cache slot is measured "
                   "before and after, which is the idalib backend. It has no idat path. Nothing was started."),
    }
    if backend == "idat":
        return _j(unsupported)
    checked, refusal = _script_precheck(script)
    if refusal:
        return _j(refusal)
    p, fail = _checked_path(path, tool, echo_path=False)
    if fail:
        return fail
    if p.suffix.lower() in _DATABASE_SUFFIXES:
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "DATABASE_INPUT_NOT_SUPPORTED",
                   "detail": "An existing IDA database is not accepted as input; pass the original binary (see ida_query)."})
    if not _IDALIB_WORKER_SOURCE.is_file():
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "IDA_WORKER_MISSING",
                   "detail": "The packaged idalib worker is absent from this install (a packaging defect, not an IDA problem)."})
    choice = _choose_backend("idalib")
    if choice["failure"] is not None:
        public = choice["failure"].get("idalib")
        unsupported["idalib"] = public
        if public and public.get("status") not in (None, "NOT_CONFIGURED"):
            unsupported["reason"] = (f"requires the idalib copy-on-open backend; the interpreter named by "
                                     f"{IDALIB_PYTHON_ENV} is not usable ({public.get('status')})")
        return _j(unsupported)
    from liebert_re.bounded_subprocess import _memory_monitor_usable
    if not _memory_monitor_usable():
        return _j({"ok": False, "tool": tool, "status": "RESOURCE_LIMIT_UNAVAILABLE", "error": "MEMORY_MONITOR_UNUSABLE",
                   "detail": ("This host cannot measure process memory (psutil), so the memory limit could not be "
                              "enforced. Nothing was started; the call fails closed.")})
    info = dict(choice["info"], requested=str(backend))
    timeout_seconds = _clamp(timeout_seconds, _MIN_SCRIPT_TIMEOUT_SECONDS, _MAX_SCRIPT_TIMEOUT_SECONDS,
                             _DEFAULT_SCRIPT_TIMEOUT_SECONDS)
    max_result_chars = _clamp(max_result_chars, 100, _MAX_RESPONSE_CHARS, 60000)
    max_stdout_chars = _clamp(max_stdout_chars, 0, 65536, 16384)
    max_memory_bytes = _clamp(max_memory_bytes, _SCRIPT_MIN_MEMORY_BYTES, _SCRIPT_MAX_MEMORY_BYTES,
                              _SCRIPT_DEFAULT_MEMORY_BYTES)
    max_chars = _clamp(max_chars, _SCRIPT_MIN_RESPONSE_CHARS, _MAX_RESPONSE_CHARS, 60000)
    invocation = {"timeout_seconds": timeout_seconds, "max_result_chars": max_result_chars,
                  "max_stdout_chars": max_stdout_chars, "max_memory_bytes": max_memory_bytes, "max_chars": max_chars}
    profile = {"backend": "idalib", "python": choice["python"], "script": checked, "backend_info": info}
    return _locked_call(tool, choice["engine_exe"], p, invocation, max_chars, cancellation_token, profile)


def _script_locked(exe, p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile):
    """`ida_script` under the slot lock: make sure the pristine database exists, then run the script session."""
    tool = "ida_script"
    summary = _script_summary(profile["script"])
    slot.mkdir(parents=True, exist_ok=True)
    for stale in slot.glob("work-*"):       # under the lock, any scratch directory here is an abandoned attempt
        shutil.rmtree(stale, ignore_errors=True)
    cache_state = "HIT"
    if (slot / _DB_NAME).exists() and not _slot_is_healthy(slot):
        _evict_slot(slot)
        slot.mkdir(parents=True, exist_ok=True)
        cache_state = "REBUILT"
    elif not (slot / _DB_NAME).exists():
        cache_state = "CREATED"
    scratch_kept = False
    try:
        if cache_state != "HIT":
            try:
                _run_idalib_session(
                    profile["python"], p, sha256, md5, slot, creating=True,
                    invocation={"operation": "summary", "query": "", "max_results": 1, "offset": 0,
                                "timeout_seconds": _MAX_CREATE_TIMEOUT_SECONDS},
                    cancellation_token=cancellation_token)
            except _StageFailure as failure:
                failure.body.update(tool=tool, invocation=invocation, script=summary, failed_stage="first_analysis",
                                    backend=profile["backend_info"], database_cache=cache_state)
                raise
        return _run_script_session(p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile,
                                   cache_state, summary)
    except _StageFailure as failure:
        scratch_kept = "scratch_retained" in failure.body
        return failure.body
    finally:
        if not (slot / _DB_NAME).exists() and not scratch_kept:
            shutil.rmtree(slot, ignore_errors=True)


def _script_evidence(p, sha256, profile, job, envelope, signals, body):
    """The full record of one script run, written whatever the outcome. Returns `(name, error)`."""
    worker, _changed = _redact_value(envelope, target=p) if isinstance(envelope, dict) else (envelope, False)
    record = {
        "schema": 1, "tool": "ida_script", "target_sha256": sha256,
        "script": {"sha256": profile["script"]["sha256"], "text": profile["script"]["raw"].decode("utf-8")},
        "job": {k: v for k, v in job.items() if k not in ("output", "script_path", "ops_path")},
        "worker_result": worker, "signals": signals, "response": body,
    }
    return _write_evidence(p, "script", record, directory=EVIDENCE_SCRIPT, stem=sha256[:16])


def _run_script_session(p, sha256, md5, slot, invocation, max_chars, cancellation_token, profile, cache_state, summary):
    """One idalib worker process running the script on a scratch copy of the slot database. Returns the finished
    response dict (every ending is a response) or raises `_StageFailure` for an environment error."""
    tool = "ida_script"
    script = profile["script"]
    work = slot / f"work-{uuid.uuid4().hex[:8]}"
    work.mkdir()
    job = {
        "schema": 1, "mode": "script", "output": str(work / _IDALIB_RESULT_NAME), "database_name": _DB_NAME,
        "log_name": _LOG_NAME, "max_result_bytes": _IDALIB_MAX_RESULT_BYTES,
        "script_path": str(work / _SCRIPT_FILE_NAME), "script_sha256": script["sha256"], "input_sha256": sha256,
        "max_result_chars": invocation["max_result_chars"], "max_stdout_chars": invocation["max_stdout_chars"],
    }
    keep_work = False
    try:
        base = {"tool": tool, "target_sha256": sha256, "invocation": invocation, "script": summary,
                "backend": profile["backend_info"], "database_cache": cache_state}
        execution = {
            "session": "open_of_scratch_copy", "backend": "idalib", "copy_discarded": None,
            "slot_database_integrity": None, "elapsed_seconds": None,
            "timeout_seconds": invocation["timeout_seconds"], "memory_limit_bytes": invocation["max_memory_bytes"],
            "memory_limit": "POLLED_PROCESS_TREE_RESIDENT_SIZE", "child_processes": "NOT_ENFORCED",
            "network": "NOT_ENFORCED", "filesystem": "NOT_ENFORCED", "environment": "INHERITED",
        }
        context = {"envelope": None, "signals": None}

        def respond(body):
            """Finish a refusal or failure: its evidence record is written best effort, and a failed run's scratch
            directory is kept only when the operator asked for that."""
            nonlocal keep_work
            if _keep_failed_scratch() and work.is_dir():
                keep_work = True
                body["scratch_retained"] = _retained_scratch(work, _cache_root(), "<CACHE>")
            name, error = _script_evidence(p, sha256, profile, job, context["envelope"], context["signals"], body)
            body["internal_evidence_name"] = name
            body["evidence_write_error"] = error
            return body

        def refuse(status, error, **extra):
            return respond({"ok": False, "status": status, "error": error, **base, "execution": execution, **extra})

        (work / _SCRIPT_FILE_NAME).write_bytes(script["raw"])
        try:
            before = _sha256_md5(slot / _DB_NAME)[0]
            shutil.copyfile(slot / _DB_NAME, work / _DB_NAME)
            copy_hash = _sha256_md5(work / _DB_NAME)[0]
        except OSError as exc:
            raise _StageFailure(_EnvironmentFailure("IDA_DATABASE_UNREADABLE", exc).body(
                tool, invocation=invocation, target_sha256=sha256)) from exc
        if copy_hash != before:
            return refuse("ANALYSIS_LIMITED", "SCRIPT_COPY_MISMATCH", database_sha256_slot=before,
                          database_sha256_copy=copy_hash,
                          detail="The scratch copy of the cached database differs from the original; nothing was run.")
        execution["scratch_copy_sha256"] = copy_hash
        started = time.monotonic()
        try:
            cp, _command = _launch_idalib(
                profile["python"], work, job, timeout_seconds=invocation["timeout_seconds"],
                cancellation_token=cancellation_token, max_memory_bytes=invocation["max_memory_bytes"])
        except _EnvironmentFailure as failure:
            raise _StageFailure(failure.body(tool, invocation=invocation, target_sha256=sha256)) from failure
        execution["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            after = _sha256_md5(slot / _DB_NAME)[0]
        except OSError:
            after = None
        integrity = {"database_sha256_before": before, "database_sha256_after": after, "unchanged": after == before,
                     "opened": "a copy in the scratch directory"}
        execution["slot_database_integrity"] = integrity
        if after != before:
            _evict_slot(slot)
            return refuse("CACHE_VIOLATION", "SCRIPT_CACHE_VIOLATION",
                          detail=("The cached database file differed after the session (or could not be read again), "
                                  "although only a copy of it was opened. The cache slot was deleted and no result is "
                                  "returned; the next call analyses the input again."))
        if getattr(cp, "resource_limit_unavailable", False):
            return refuse("RESOURCE_LIMIT_UNAVAILABLE", "MEMORY_MONITOR_UNUSABLE",
                          detail="The memory limit could not be enforced on this host; the process tree was stopped.")
        if getattr(cp, "memory_exceeded", False):
            return refuse("MEMORY_LIMIT", "SCRIPT_MEMORY_LIMIT_EXCEEDED_PROCESS_TREE_TERMINATED",
                          memory_limit_bytes=invocation["max_memory_bytes"],
                          detail="The script session exceeded its memory limit and its process tree was terminated. No result.")
        if cp.cancelled:
            return refuse("CANCELLED", "SCRIPT_CANCELLED_PROCESS_TREE_TERMINATED")
        if cp.timed_out:
            return refuse("TIMEOUT", "SCRIPT_TIMEOUT_PROCESS_TREE_TERMINATED", timeout_seconds=invocation["timeout_seconds"],
                          timed_out_stage="script",
                          detail=("The script session did not finish and its process tree was terminated. The cache slot "
                                  "was kept (only a copy was open). Do not read a timeout as 'nothing found'."))
        envelope, _first, error, signals = _verdict_idalib(cp, work, creating=False, operations=[])
        signals["elapsed_seconds"] = execution["elapsed_seconds"]
        signals["database_integrity"] = integrity
        context.update(envelope=envelope, signals=signals)
        execution["copy_discarded"] = signals.get("database_closed_without_save") is True
        if error:
            extra = {"signals": signals}
            if isinstance(envelope, dict) and envelope.get("error"):
                extra["worker_error"] = envelope.get("error")
                if envelope.get("traceback"):
                    extra["worker_traceback"] = _redact(str(envelope["traceback"]), work=work, target=p)[-2000:]
            failure = _failure_response(tool, "RESULT_PARSE_FAILED" if error == "RESULT_PARSE_FAILED" else "ANALYSIS_LIMITED",
                                        error, operation="script", signals=signals, cp=cp, work=work, target=p, extra=extra)
            failure.update(base)
            failure["execution"] = execution
            return respond(failure)
        outcome = envelope.get("script") if isinstance(envelope, dict) else None
        if not isinstance(outcome, dict):
            return refuse("ANALYSIS_LIMITED", "SCRIPT_OUTCOME_MISSING", signals=signals,
                          detail="The worker finished without reporting what the script did.")
        provenance = _provenance(sha256, md5, outcome)
        if provenance["status"] == "MISMATCH":
            _evict_slot(slot)
            return refuse("ANALYSIS_LIMITED", "IDA_INPUT_HASH_MISMATCH", provenance=provenance, signals=signals,
                          detail=("The database's recorded input is not the file that was hashed; the slot was dropped and "
                                  "no result is returned."))
        status = outcome.get("status")
        tail, _ = _redact_value(str(outcome.get("stdout_tail") or ""), target=p)
        stdout = {"stdout_tail": tail, "stdout_chars": outcome.get("stdout_chars"),
                  "stdout_truncated": outcome.get("stdout_truncated")}
        common = {"signals": signals, "provenance": provenance, **stdout}
        if status == "HASH_MISMATCH":
            return refuse("ANALYSIS_LIMITED", "SCRIPT_HASH_MISMATCH", **common,
                          detail="The script file the worker read is not the text that was submitted; it was not run.")
        if status == "UNREADABLE":
            return refuse("ANALYSIS_LIMITED", "SCRIPT_UNREADABLE", **common)
        if status == "SYNTAX_ERROR":
            return refuse("ANALYSIS_LIMITED", "SCRIPT_SYNTAX_ERROR", compiled_by="ida_python", line=outcome.get("line"),
                          message=_redact(str(outcome.get("error") or ""), work=work, target=p)[:300], **common)
        if status == "EXCEPTION":
            exc = outcome.get("exception") if isinstance(outcome.get("exception"), dict) else {}
            return refuse("ANALYSIS_LIMITED", "SCRIPT_EXCEPTION", **common, exception={
                "type": str(exc.get("type"))[:120],
                "message": _redact(str(exc.get("message") or ""), work=work, target=p)[:2000],
                "traceback": _redact(str(exc.get("traceback") or ""), work=work, target=p)[-6000:]},
                detail=("The script raised. The database copy was discarded. No result. stdout_tail holds what it printed "
                        "before failing."))
        if status == "NO_RESULT":
            return refuse("ANALYSIS_LIMITED", "SCRIPT_NO_RESULT", **common,
                          detail="The script finished without setting `result`. stdout never substitutes for it.")
        if status == "NOT_JSON":
            return refuse("ANALYSIS_LIMITED", "SCRIPT_RESULT_NOT_JSON", result_type=str(outcome.get("result_type"))[:80],
                          message=_redact(str(outcome.get("error") or ""))[:300], **common,
                          detail="`result` is not a JSON value (NaN and infinity are not JSON either).")
        if status not in ("OK", "TOO_LARGE"):
            return refuse("ANALYSIS_LIMITED", "SCRIPT_OUTCOME_UNRECOGNISED", status_seen=str(status)[:80], **common)
        body = {
            "ok": True, "status": "OK", **base, "provenance": provenance, "signals": signals, "execution": execution,
            "result_kind": "SCRIPT_REPORTED", **stdout,
            "claim_basis": (
                "Harness verified: the input hash, that this script text completed inside IDA on this input, and that the "
                "cached database was unchanged. script_result is the script's claim; the harness did not verify its "
                "content. The script may have modified the database inside the session (the copy was discarded); the "
                "result reflects that state."),
            "note": "Not a sandbox. " + _SCRIPT_NOT_A_SANDBOX,
        }
        if status == "TOO_LARGE":
            body.update(status="PARTIAL", script_result_withheld="TOO_LARGE_FOR_MAX_RESULT_CHARS",
                        script_result_chars=outcome.get("result_chars"), max_result_chars=invocation["max_result_chars"],
                        limitations=["the script's result is larger than max_result_chars and was not returned (never truncated)"])
        else:
            value, changed = _redact_value(outcome.get("result"), target=p)
            body.update(script_result=value, script_result_redacted=changed, script_result_chars=outcome.get("result_chars"))
        name, error = _script_evidence(p, sha256, profile, job, envelope, signals, body)
        if error and status == "OK":
            # The record is the audit trail of a run that cannot be undone; without it the result is withheld.
            return {"ok": False, "status": "ANALYSIS_LIMITED", "error": "EVIDENCE_WRITE_FAILED", **base,
                    "execution": execution, "evidence_write_error": error, "result_withheld": True,
                    "detail": ("The script ran to completion, but its evidence record could not be written, so its "
                               "result is withheld. Fix the evidence directory and run it again.")}
        body["internal_evidence_name"] = name
        body["evidence_write_error"] = error
        if len(_j(body)) > max_chars and "script_result" in body:
            body.pop("script_result")
            body.update(status="PARTIAL", script_result_withheld="TOO_LARGE_FOR_MAX_CHARS",
                        limitations=[f"the result does not fit max_chars={max_chars} and was not returned (never truncated); "
                                     "the evidence file holds the full record"])
            if len(_j(body)) > max_chars:
                body["stdout_tail"], body["stdout_tail_withheld"] = "", True
        return body
    finally:
        if not keep_work:
            shutil.rmtree(work, ignore_errors=True)


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
    # os.path.isdir() folds every OSError into False, so an existing root that cannot be stat'ed
    # (permissions, I/O error) would read as "no root, zero bytes". Only a root that is really
    # absent is zero; any other failure to look at it is "cannot be measured".
    try:
        os.stat(root)
    except FileNotFoundError:
        return 0
    except OSError:
        return None
    if not os.path.isdir(root):
        return None
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


def _verified_copy(source, destination, tool, sha256, *, expected_sha256=None, io_error="IDA_COPY_FAILED"):
    """Copy a database for a child process, then prove the copy before anything opens it: flush the
    file, hash it, and compare with the source's SHA-256 (`expected_sha256` when the caller already
    holds it, else the source is hashed here). A size match is not accepted as proof: a same-length
    corruption is caught only by the hash. On any mismatch this raises _StageFailure with
    COPY_INTEGRITY_FAILED carrying both hashes (never a path); it never retries, because a retry would
    hide a damaged file. A copy that raises becomes a structured refusal under `io_error`."""
    expected = expected_sha256
    if expected is None:
        expected, why = _file_sha256(source)
        if expected is None:
            raise _StageFailure(json.loads(_refuse(
                tool, "ANALYSIS_LIMITED", "COPY_INTEGRITY_UNVERIFIABLE", fixable=False, target_sha256=sha256,
                environment_error=why, fix="The source database could not be read to verify the copy; nothing was "
                                           "launched. Fix the file-system problem.")))
    try:
        shutil.copyfile(source, destination)
    except OSError as exc:
        raise _StageFailure(_EnvironmentFailure(io_error, exc).body(tool, target_sha256=sha256)) from exc
    sync_error = _fsync_path(destination)
    found, why = _file_sha256(destination)
    if sync_error or found is None:
        raise _StageFailure(json.loads(_refuse(
            tool, "ANALYSIS_LIMITED", "COPY_INTEGRITY_UNVERIFIABLE", fixable=False, target_sha256=sha256,
            environment_error=sync_error or why, expected_sha256=expected,
            fix="The copy could not be flushed or read back, so it was not verified and nothing was launched.")))
    if found != expected:
        raise _StageFailure(json.loads(_refuse(
            tool, "ANALYSIS_LIMITED", "COPY_INTEGRITY_FAILED", fixable=False, target_sha256=sha256,
            expected_sha256=expected, found_sha256=found,
            fix="The copy does not hash to its source, so no session was started on it and it was not retried. "
                "Check the disk and the file system holding the annotated or cache root.")))


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
            _verified_copy(slot / _DB_NAME, destination, "ida_annotations_apply", sha256,
                           io_error="IDA_DATABASE_UNREADABLE")
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
            _verified_copy(source, destination, tool, sha256, io_error="IDA_ANNOTATED_IO_ERROR")
        except OSError as exc:
            raise _StageFailure(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256)) from exc
    finally:
        _release_slot_lock(lock)


def _annotated_session(exe, work, job, *, tool, sha256, md5, invocation, temporary, seconds, cancellation_token):
    """`_annotated_session_once`, repeated for a TEMPORARY session (plan, verify) that the engine loaded with
    empty root information (IDA_ENGINE_ROOT_INFO_MISSING): it answered nothing and saved nothing, so the same
    directory is reused after its result and log are cleared. A write session is not repeated here: what it
    saved may be unopenable, so its caller starts again from a fresh copy of the base."""
    attempts = 0
    while True:
        attempts += 1
        try:
            data, signals, provenance = _annotated_session_once(
                exe, work, job, tool=tool, sha256=sha256, md5=md5, invocation=invocation, temporary=temporary,
                seconds=seconds, cancellation_token=cancellation_token)
        except _StageFailure as failure:
            if not temporary or failure.body.get("error") != "IDA_ENGINE_ROOT_INFO_MISSING":
                raise
            if attempts >= _ROOT_INFO_ATTEMPTS:
                failure.body["engine_root_info_attempts"] = attempts
                raise
            for name in (_RESULT_NAME, _LOG_NAME):
                (work / name).unlink(missing_ok=True)
            continue
        if attempts > 1:
            signals["engine_root_info_repeats"] = attempts - 1
        return data, signals, provenance


def _annotated_session_once(exe, work, job, *, tool, sha256, md5, invocation, temporary, seconds, cancellation_token):
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
                                    expect_operation=operation, require_discard=temporary, require_root_info=True)
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
                _verified_copy(state["db"], work / _DB_NAME, tool, sha256, expected_sha256=state["db_sha256"],
                               io_error="IDA_ANNOTATED_IO_ERROR")
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


def ida_set_comments_plan(path, label=None, comments=None, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
                          cancellation_token=None):
    """PLAN comments on items in the analysis database of `path`; nothing is written. Mirrors
    `ida_rename_plan`: the plan is read from the annotation scope `label` as it is now, so each item carries
    the comment it expects to find (`expect_comment`, `null` when the address has none).

    `label` is required and explicit (1 to 48 characters of letters, digits, '.', '_', '-'). `comments` is
    a list of 1 to 200 objects: `address` (an integer or a string such as "0x140001000"), `comment` (text,
    1 to 1024 characters, no NUL), `comment_kind` (REQUIRED, never defaulted: `regular` or `repeatable`;
    decompiler comments are not supported and are refused as UNSUPPORTED_COMMENT_KIND), and optionally
    `address_kind` (`va` default, `rva` or `file_offset`). The address must be the start of an item, and the
    comment must differ from the current one of that kind. Comment text that `_redact` would change (a home
    path, the account name, a licence line) is refused, not silently altered.

    The answer has the keys of `ida_rename_plan`. The plan carries the comment text (apply needs it); the
    evidence file written beside the answer carries only its SHA-256 and length. Nothing in this operation
    writes the audit journal. Apply is not available for this plan kind yet.

    Status vocabulary: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED, ANALYSIS_LIMITED
    (every refusal names the field, what is accepted, and `fixable`), RESULT_PARSE_FAILED.
    """
    tool = "ida_set_comments_plan"
    if not _valid_label(label):
        return _label_refusal(tool, label)
    if not isinstance(comments, list) or not 1 <= len(comments) <= _RENAME_MAX_ITEMS:
        return _refuse(tool, "ANALYSIS_LIMITED", "COMMENTS_REQUIRED", fixable=True, field="comments",
                       given=f"{type(comments).__name__}" + (f" of {len(comments)}" if isinstance(comments, list) else ""),
                       accepted=f"a list of 1 to {_RENAME_MAX_ITEMS} objects with address, comment and comment_kind",
                       fix="Pass the comments as a list of objects; a longer list is refused rather than cut, so split it.")
    allowed_fields = {"address", "comment", "comment_kind", "address_kind"}
    items, seen_addresses = [], set()
    for index, entry in enumerate(comments):
        problem, value = None, None
        if not isinstance(entry, dict):
            problem = ("COMMENT_ITEM_NOT_AN_OBJECT", None)
        elif set(entry) - allowed_fields:
            problem = ("COMMENT_ITEM_UNKNOWN_FIELD", sorted(set(entry) - allowed_fields)[:5])
        elif isinstance(entry.get("address"), bool) or not isinstance(entry.get("address"), (int, str)) \
                or (isinstance(entry.get("address"), int) and not 0 <= entry["address"] < 1 << 64):
            problem = ("COMMENT_ITEM_ADDRESS_INVALID", None)
        elif entry.get("comment_kind") not in _COMMENT_KINDS:
            problem = ("UNSUPPORTED_COMMENT_KIND", list(_COMMENT_KINDS))
        elif not isinstance(entry.get("comment"), str) or "\x00" in entry["comment"]:
            problem = ("COMMENT_ITEM_COMMENT_INVALID", None)
        elif not entry["comment"].strip():
            problem = ("COMMENT_ITEM_COMMENT_EMPTY", None)
        elif len(entry["comment"]) > _COMMENT_MAX_CHARS:
            problem = ("COMMENT_ITEM_COMMENT_TOO_LONG", f"at most {_COMMENT_MAX_CHARS} characters")
        elif _redact(entry["comment"]) != entry["comment"]:
            problem = ("COMMENT_TEXT_NEEDS_REDACTION", "text without a home path, account name or licence line")
        elif entry.get("address_kind", "va") not in _PATCH_ADDRESS_KINDS:
            problem = ("INVALID_ADDRESS_KIND", list(_PATCH_ADDRESS_KINDS))
        if problem is None:
            try:
                value = entry["address"] if isinstance(entry["address"], int) else int(entry["address"].strip(), 0)
                if not 0 <= value < 1 << 64:
                    raise ValueError
            except ValueError:
                problem = ("COMMENT_ITEM_ADDRESS_INVALID", None)
        if problem is None:
            key = (entry.get("address_kind", "va"), value)
            if key in seen_addresses:
                problem = ("DUPLICATE_ADDRESS", None)
            seen_addresses.add(key)
        if problem:
            # A refusal never echoes the comment text.
            return _refuse(tool, "ANALYSIS_LIMITED", problem[0], fixable=True, field="comments", item_index=index,
                           accepted=problem[1] if problem[1] else {
                               "address": "an integer or a string like \"0x140001000\"",
                               "comment": f"text, 1 to {_COMMENT_MAX_CHARS} characters",
                               "comment_kind": list(_COMMENT_KINDS), "address_kind": list(_PATCH_ADDRESS_KINDS)},
                           fix=("Correct that item and plan again; nothing was read. Decompiler comments are not supported."
                                if problem[0] == "UNSUPPORTED_COMMENT_KIND" else
                                "Correct that item and plan again; nothing was read."))
        items.append({"address": hex(value), "address_kind": entry.get("address_kind", "va"),
                      "comment_kind": entry["comment_kind"], "comment": entry["comment"]})
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
    invocation = {"operation": "comment_plan", "label": label, "item_count": len(items), "timeout_seconds": total}
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
                _verified_copy(state["db"], work / _DB_NAME, tool, sha256, expected_sha256=state["db_sha256"],
                               io_error="IDA_ANNOTATED_IO_ERROR")
            else:
                _copy_pristine(exe, p, sha256, md5, work / _DB_NAME, total, cancellation_token)
            left = int(deadline - time.monotonic())
            if left < 1:
                raise _StageFailure({"ok": False, "tool": tool, "status": "TIMEOUT", "invocation": invocation,
                                     "target_sha256": sha256, "error": "IDA_TIMEOUT_BUDGET_EXHAUSTED"})
            data, signals, provenance = _annotated_session(
                exe, work, {"operation": "comment_plan", "write_mode": "plan", "items": items}, tool=tool,
                sha256=sha256, md5=md5, invocation=invocation, temporary=True,
                seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
        except OSError as exc:
            return _j(_EnvironmentFailure("IDA_ANNOTATED_IO_ERROR", exc).body(tool, target_sha256=sha256, invocation=invocation))
        except _StageFailure as failure:
            return _j(failure.body)
        if data.get("ok") is False:
            # No current comment text is echoed (the rename plan's `current_name` has no counterpart here).
            refusal = {"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": data.get("error", "UNKNOWN_ERROR"),
                       **{k: v for k, v in data.items() if k in ("item_index", "item_error", "given", "accepted",
                                                                  "item_start", "address_kind")},
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
        if len(rows) != len(items) or len({r["address"]["va"] for r in rows}) != len(rows) \
                or any(r.get("index") != i or r.get("comment_kind") != items[i]["comment_kind"]
                       or not (r.get("expect_comment") is None or isinstance(r.get("expect_comment"), str))
                       for i, r in enumerate(rows)):
            return _refuse(tool, "ANALYSIS_LIMITED", "DUPLICATE_ADDRESS_AFTER_RESOLUTION", fixable=True,
                           fix="Two items resolve to the same address, or the engine's rows do not match the request. "
                               "Give each item one address and plan again; nothing is guessed.")
        if any(r["expect_comment"] is not None and _redact(r["expect_comment"]) != r["expect_comment"] for r in rows):
            return _refuse(tool, "ANALYSIS_LIMITED", "EXISTING_COMMENT_NEEDS_REDACTION", fixable=False,
                           target_sha256=sha256, label=label,
                           fix="An existing comment holds text that must not leave the database (a home path, an account "
                               "name or a licence line), so it is neither returned nor used as a precondition.")
        plan = {"schema": _PLAN_SCHEMA, "kind": "comments", "target_sha256": sha256, "label": label,
                "base_version": state["version"], "base_db_sha256": state["db_sha256"],
                "items": [{"index": r["index"], "address": r["address"]["va"], "address_kind": "va",
                           "comment": items[i]["comment"], "comment_kind": r["comment_kind"],
                           "expect_comment": r["expect_comment"]} for i, r in enumerate(rows)]}

        def digest(text):      # Privacy decision: comment text is never written to a log; hash and length only.
            return None if text is None else {"sha256": _sha256_text(text), "length": len(text)}

        detail = [{"index": it["index"], "address": rows[it["index"]]["address"], "comment_kind": it["comment_kind"],
                   "comment_sha256": digest(it["comment"])["sha256"], "comment_length": len(it["comment"]),
                   "expect_comment": digest(it["expect_comment"])} for it in plan["items"]]
        body = {
            "ok": True, "tool": tool, "status": "OK", "target_sha256": sha256, "label": label,
            "plan": plan, "plan_sha256": _sha256_text(_canonical(plan)), "item_count": len(rows),
            "items_detail": detail, "items_listed_complete": True,
            "annotated_view": {"state": "verified", "version": state["version"],
                               "read_from": "published annotation version" if state["version"] else "pristine analysis",
                               "marker_checked": True},
            "concurrency_policy": _CONCURRENCY_POLICY, "provenance": provenance, "signals": signals,
            "invocation": invocation,
            "note": ("A PLAN: nothing was written. It binds to the annotation version it read; if another write "
                     "to this scope lands first, applying it is refused as stale. The comment-plan apply is not "
                     "available yet."),
        }
        evidence = {k: v for k, v in body.items() if k != "plan"}
        evidence["plan"] = {**plan, "items": [
            {**{k: v for k, v in it.items() if k not in ("comment", "expect_comment")},
             "comment": digest(it["comment"]), "expect_comment": digest(it["expect_comment"])} for it in plan["items"]]}
        body["internal_evidence_name"], body["evidence_write_error"] = _write_evidence(
            p, "comment_plan", evidence, EVIDENCE_RENAME_PLAN, stem=sha256[:16])
        return _j(body)
    finally:
        if work is not None:
            _remove_owned_work(work)
        _release_slot_lock(lock)


def _plan_problem(plan, kinds=("rename",)):
    """(error, field) when `plan` is not a well-formed plan of one of `kinds`, else (None, None). Pure.
    The default is rename only; a comments plan is checked by naming "comments" in `kinds` (apply
    passes both). Each kind has its own item field set."""
    if not isinstance(plan, dict):
        return "PLAN_NOT_AN_OBJECT", None
    for field, kind in (("schema", int), ("kind", str), ("target_sha256", str), ("label", str), ("base_version", int),
                        ("items", list), ("plan_sha256", str)):
        if not isinstance(plan.get(field), kind) or isinstance(plan.get(field), bool):
            return "PLAN_FIELD_MISSING_OR_WRONG_TYPE", field
    if plan["schema"] != _PLAN_SCHEMA or plan["kind"] not in _PLAN_KINDS or plan["kind"] not in kinds:
        return "PLAN_SCHEMA_UNSUPPORTED", "schema"
    if not re.fullmatch(r"[0-9a-f]{64}", plan["target_sha256"]) or not _valid_label(plan["label"]) or plan["base_version"] < 0:
        return "PLAN_FIELD_INVALID", "target_sha256/label/base_version"
    if "base_db_sha256" not in plan or not (plan["base_db_sha256"] is None or isinstance(plan["base_db_sha256"], str)):
        return "PLAN_FIELD_MISSING_OR_WRONG_TYPE", "base_db_sha256"
    if not 1 <= len(plan["items"]) <= _RENAME_MAX_ITEMS:
        return "PLAN_ITEMS_OUT_OF_RANGE", "items"
    for item in plan["items"]:
        if plan["kind"] == "comments":
            if not (isinstance(item, dict)
                    and set(item) == {"index", "address", "address_kind", "comment", "comment_kind", "expect_comment"}
                    and isinstance(item["index"], int) and not isinstance(item["index"], bool)
                    and isinstance(item["address"], str) and item["address_kind"] == "va"
                    and item["comment_kind"] in _COMMENT_KINDS
                    and isinstance(item["comment"], str) and 1 <= len(item["comment"]) <= _COMMENT_MAX_CHARS
                    and (item["expect_comment"] is None or isinstance(item["expect_comment"], str))):
                return "PLAN_ITEM_MALFORMED", "items"
            continue
        if not (isinstance(item, dict) and set(item) == {"index", "address", "address_kind", "new_name", "expect_name"}
                and isinstance(item["index"], int) and isinstance(item["address"], str)
                and item["address_kind"] == "va" and isinstance(item["expect_name"], str)
                and isinstance(item["new_name"], str) and _NEW_NAME.fullmatch(item["new_name"])):
            return "PLAN_ITEM_MALFORMED", "items"
    return None, None


def ida_annotations_apply(path, plan=None, allow_partial=False, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
                          cancellation_token=None):
    """APPLY a plan from `ida_rename_plan` (kind "rename") or `ida_set_comments_plan` (kind "comments"):
    write its renames or comments into a new, immutable annotation version of the scope it names. A
    comment's text never reaches the audit journal or the evidence file, only its sha256 and length; the
    answer to the caller carries it (after redaction). It cannot be called without a plan, and the plan must be unaltered (its digest is
    recomputed), made for this input (hash), and still current (its base version and database hash must be
    the published ones, and every item's `expect` name or comment must be what the database holds now).

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

    CLI: python-only: writes a new annotation version into the IDA scope store; the generic path never writes
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
    error, field = _plan_problem(plan, ("rename", "comments"))
    if error:
        return _refuse(tool, "INVALID_PLAN", error, fixable=True, field=field,
                       accepted="the `plan` object of ida_rename_plan or ida_set_comments_plan with its `plan_sha256` added",
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
    comments = plan["kind"] == "comments"
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
    kept_scratch = set()      # failed-attempt directories kept on request (LIEBERT_RE_KEEP_FAILED_SCRATCH)
    journal = {"prepared": None, "committed": None}
    marker = {"schema": 1, "label": label, "version": version, "write_id": write_id,
              "plan_sha256": plan["plan_sha256"], "target_sha256": sha256}
    result = {"ok": False, "tool": tool, "target_sha256": sha256, "label": label, "invocation": invocation,
              "write_id": write_id, "concurrency_policy": _CONCURRENCY_POLICY, "written": False}
    if recovered:
        result["recovery_actions"] = recovered

    def remaining():
        return int(deadline - time.monotonic())

    def comment_digest(text):
        """What a log may hold of a comment: its sha256 and length. None stays None (no comment there)."""
        return None if text is None else {"sha256": _sha256_text(text), "length": len(text)}

    def scrub_text_files(directory):
        """Best-effort removal of the job and result files of a work directory (they hold comment text)."""
        for name in ("job.json", _RESULT_NAME):
            try:
                (Path(directory) / name).unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                # Reported, never swallowed: the file may still hold comment text. Only the file name and the
                # error type go into the answer (no text, no path, no OS message).
                result.setdefault("signals", {}).setdefault("text_scrub_failures", []).append(
                    {"file": name, "directory": f"recovery/{write_id}", "error_type": type(exc).__name__,
                     "errno": exc.errno, "text_may_remain_on_disk": True})

    try:
        # 1. the candidate, in its own recovery directory, from the published version (or the pristine analysis)
        try:
            rdir.mkdir(parents=True)

            def prepare_candidate():
                if state["version"] > 0:
                    _copy_into_budget(state["db"], rdir / _DB_NAME, tool, sha256, cancellation_token)
                else:
                    staging = rdir / "pristine.copy"
                    _copy_pristine(exe, p, sha256, md5, staging, total, cancellation_token)
                    _copy_into_budget(staging, rdir / _DB_NAME, tool, sha256, cancellation_token)
                    staging.unlink()

            prepare_candidate()
            left = remaining()
            if left < 1:
                _remove_owned_work(rdir)
                return _j({**result, "status": "TIMEOUT", "error": "IDA_TIMEOUT_BUDGET_EXHAUSTED"})
            # 2. the write session (an ordinary session of the candidate; not temporary)
            if comments:
                job = {"operation": "comment_apply", "write_mode": "write", "allow_partial": allow_partial,
                       "marker": marker,
                       "items": [{"address": i["address"], "address_kind": "va", "comment": i["comment"],
                                  "comment_kind": i["comment_kind"], "expect_comment": i["expect_comment"]}
                                 for i in plan["items"]]}
            else:
                job = {"operation": "rename_apply", "write_mode": "write", "allow_partial": allow_partial, "marker": marker,
                       "items": [{"address": i["address"], "address_kind": "va", "new_name": i["new_name"],
                                  "expect_name": i["expect_name"]} for i in plan["items"]]}
            # An engine load with empty root information saves a database IDA cannot open again, so that
            # candidate is never kept: it is deleted and the write is repeated from a fresh copy of the
            # same base, up to _ROOT_INFO_ATTEMPTS launches. Nothing was promoted or journalled yet.
            write_launches = 0
            while True:
                write_launches += 1
                try:
                    data, signals, provenance = _annotated_session(
                        exe, rdir, job, tool=tool, sha256=sha256, md5=md5, invocation=invocation, temporary=False,
                        seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
                    break
                except _StageFailure as failure:
                    if failure.body.get("error") != "IDA_ENGINE_ROOT_INFO_MISSING":
                        raise
                    _remove_owned_work(rdir)
                    left = remaining()
                    if write_launches >= _ROOT_INFO_ATTEMPTS or left < 1:
                        failure.body["engine_root_info_attempts"] = write_launches
                        raise
                    rdir.mkdir(parents=True)
                    prepare_candidate()
                finally:
                    if comments:      # the job and result files hold comment text; a kept candidate must not
                        scrub_text_files(rdir)
            if write_launches > 1:
                result["engine_root_info_repeats"] = write_launches - 1
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
        if comments and not all(isinstance(a, dict) and isinstance(a.get("index"), int) and isinstance(a.get("address"), str)
                                and a.get("comment_kind") in _COMMENT_KINDS and isinstance(a.get("new_comment"), str)
                                and (a.get("old_comment") is None or isinstance(a.get("old_comment"), str))
                                for a in applied):
            return _j({**result, "status": "ANALYSIS_LIMITED", "error": "WORKER_APPLIED_ROWS_MALFORMED",
                       "candidate_retained": True, "fixable": False,
                       "fix": "The engine's report of what it wrote is not in the expected shape, so nothing was "
                              "promoted. The candidate is kept in its recovery directory."})
        # 3. write-ahead: batch_prepared, synced, BEFORE the promotion
        if comments:      # Privacy decision: comment text is never journalled; hash and length only.
            logged = [{"index": a["index"], "address": a["address"], "comment_kind": a["comment_kind"],
                       "old_comment": comment_digest(a["old_comment"]), "new_comment": comment_digest(a["new_comment"])}
                      for a in applied]
        else:
            logged = [{"index": a["index"], "address": a["address"], "old_name": a["old_name"], "new_name": a["new_name"]}
                      for a in applied]
        journal["prepared"] = {
            "event": "batch_prepared", "operation": "comments" if comments else "rename", "write_id": write_id,
            "label": label, "version": version,
            "prior_version": state["version"], "prior_db_sha256": state["db_sha256"], "candidate_db_sha256": candidate_sha,
            "candidate_bytes": candidate_bytes, "candidate_location": f"recovery/{write_id}/{_DB_NAME}",
            "plan_sha256": plan["plan_sha256"], "item_count": len(applied),
            "items": logged,
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
        # None means "not measured", never a measurement of zero or false. `verification_measured` turns true
        # only once a separate verification session returned and the counts below were computed from it.
        verify = {"separate_process": True, "verification_measured": False, "marker_matched": None,
                  "write_session_pid": data.get("engine_pid"), "attempt_count": 0, "attempts": [],
                  "retried": False, "passed_on_retry": False}
        verify.update({"comments_matched": None, "comments_expected": len(applied)} if comments
                      else {"names_matched": None, "names_expected": len(applied)})

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
        # One retry, announced. The published pointer moves only at step 6, after verification passed, so a
        # second read-back of the same immutable stored file cannot publish anything the first one refused.
        # Each attempt gets a NEW scratch directory and a fresh copy of the promoted file. Only a failed
        # session is retried (not a timeout or cancellation, which would spend the caller's budget twice).
        checked = None
        while checked is None:
            verify["attempt_count"] += 1
            attempt = {"attempt": verify["attempt_count"], "scratch": verify_dir.name}
            verify["attempts"].append(attempt)
            verify_dir.mkdir(parents=True)
            try:
                _verified_copy(promoted, verify_dir / _DB_NAME, tool, sha256, expected_sha256=promoted_sha)
            except _StageFailure as failure:
                # A damaged or unverifiable copy is refused, not retried: no verification session is started
                # on it and a second copy would only hide the first one's damage.
                bad = failure.body
                attempt.update({"error": bad.get("error"), "copy_verified": False})
                verify["retried"] = verify["attempt_count"] > 1
                return abort("copy_integrity_failed" if bad.get("error") == "COPY_INTEGRITY_FAILED"
                             else "copy_unverifiable",
                             copy_failure=bad.get("error"),
                             **{k: bad[k] for k in ("expected_sha256", "found_sha256", "environment_error") if k in bad})
            try:
                verify_job = (
                    {"operation": "comment_verify", "write_mode": "verify",
                     "items": [{"address": a["address"], "address_kind": "va", "comment_kind": a["comment_kind"]}
                               for a in applied]} if comments else
                    {"operation": "rename_verify", "write_mode": "verify",
                     "items": [{"address": a["address"], "address_kind": "va"} for a in applied]})
                checked, _signals, _prov = _annotated_session(
                    exe, verify_dir, verify_job,
                    tool=tool, sha256=sha256, md5=md5, invocation=invocation, temporary=True,
                    seconds=min(left, _MAX_ANNOTATE_TIMEOUT_SECONDS), cancellation_token=cancellation_token)
            except _StageFailure as failure:
                # Diagnosis only: what the separate verification process said. The tails were already passed
                # through `_redact` (work directory, home paths, account name, licence line) by the failure body.
                fb = failure.body
                sig = fb.get("signals") or {}
                tails = {k: (fb.get(f"{k}_tail") or None) for k in ("stderr", "stdout")}
                attempt.update({"error": fb.get("error"), "status": fb.get("status"), "exit_code": sig.get("exit_code"),
                                "result_file_present": sig.get("result_file_present"),
                                "script_completed": sig.get("result_script_completed"),
                                "log_fatal_markers": sig.get("log_fatal_markers"),
                                "exit_diagnosis": sig.get("exit_diagnosis"),
                                "ida_log_file": _LOG_NAME if sig.get("log_present") else None})
                for k, text in tails.items():
                    attempt[f"{k}_excerpt"] = text
                    attempt[f"{k}_excerpt_truncated"] = bool(text) and len(text) >= 2000   # `_tail` keeps the last 2000
                attempt["excerpt_redacted"] = any(t and re.search(r"<(?:WORK|INPUT|HOME|USER)>|License: <REDACTED>", t)
                                                  for t in tails.values()) or bool(fb.get("ida_log_redacted"))
                # the engine's own log, which idat tells us to check (bounded and redacted by the failure body)
                for k in ("ida_log_status", "ida_log_tail", "ida_log_tail_truncated", "ida_log_redacted"):
                    attempt[k] = fb.get(k)
                if _keep_failed_scratch() and verify_dir.is_dir():
                    kept_scratch.add(verify_dir)
                    attempt["scratch_retained"] = _retained_scratch(verify_dir, _annotated_root(), "<ANNOTATED>")
                # the last attempt's diagnosis also stays at the top level (the shape before the retry existed)
                for k in ("exit_code", "stderr_excerpt", "stderr_excerpt_truncated", "stdout_excerpt",
                          "stdout_excerpt_truncated", "excerpt_redacted", "ida_log_file", "ida_log_status",
                          "ida_log_tail", "ida_log_tail_truncated", "ida_log_redacted"):
                    verify[k] = attempt[k]
                verify["retried"] = verify["attempt_count"] > 1
                if fb.get("status") in ("TIMEOUT", "CANCELLED") or verify["attempt_count"] >= 2 or remaining() < 1:
                    return abort("verification_session_failed", verification_failure=fb.get("error"))
                if verify_dir not in kept_scratch:
                    _remove_owned_work(verify_dir)
                verify_dir = label_dir / f"scratch-{uuid.uuid4().hex[:8]}"
                left = remaining()
        verify["retried"] = verify["attempt_count"] > 1
        verify["passed_on_retry"] = verify["retried"]
        if verify["retried"]:
            verify["retry_note"] = ("The first verification session failed and was retried once in a new scratch "
                                    "directory; attempt 1's diagnosis is in `attempts`. Nothing was published "
                                    "between the attempts.")
        verify["verify_session_pid"] = checked.get("engine_pid")
        verify["harness_pid"] = os.getpid()
        if comments:
            got = {(row.get("address"), row.get("comment_kind")): row.get("actual_comment")
                   for row in checked.get("verified_items") or [] if isinstance(row, dict)}
            verify["comments_matched"] = sum(1 for a in applied if got.get((a["address"], a["comment_kind"])) == a["new_comment"])
            matched, expected = verify["comments_matched"], verify["comments_expected"]
        else:
            got = {row["address"]: row["actual_name"] for row in checked.get("verified_items") or []}
            verify["names_matched"] = sum(1 for a in applied if got.get(a["address"]) == a["new_name"])
            matched, expected = verify["names_matched"], verify["names_expected"]
        stored = checked.get("annotation_marker")
        verify["marker_matched"] = isinstance(stored, dict) and all(stored.get(k) == marker[k] for k in marker)
        verify["verification_measured"] = True
        verify["marker_version"] = stored.get("version") if isinstance(stored, dict) else None
        if checked.get("ok") is not True or matched != expected or not verify["marker_matched"] \
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
        shown = [{**a, "old_comment": None if a["old_comment"] is None else _redact(a["old_comment"]),
                  "new_comment": _redact(a["new_comment"])} for a in applied] if comments else applied
        body = {**result, "ok": True, "status": status, "written": True, "version": version,
                "db_sha256": candidate_sha, "db_bytes": candidate_bytes, "prior_version": state["version"],
                "applied": shown, "failed": failed, "applied_count": len(applied), "failed_count": len(failed),
                "items_listed_complete": True, "atomic": not allow_partial,
                "save_returned": data.get("save_returned"), "verification": verify,
                "provenance": provenance, "journal": {"prepared": True, "committed": committed},
                "annotated_view": {"state": "verified", "version": version},
                "note": ("A new immutable annotation version was published after a separate engine process read its "
                         + ("comments" if comments else "names") + " and marker back from the stored file. The pristine cache database was not changed."
                         + ("" if not failed else " Some items were not applied (allow_partial=True); see `failed`."))}
        if not committed:
            body["commit_record_pending"] = True
            body["journal"]["commit_error"] = commit_why
            body["note"] += (" The commit record could not be written; the version IS published (the manifest "
                             "points at it) and the next operation on this scope records it from the files.")
        evidence = body
        if comments:      # the evidence file carries hash and length of each comment, never the text
            evidence = {**body, "applied": journal["prepared"]["items"]}
        body["internal_evidence_name"], body["evidence_write_error"] = _write_evidence(
            p, "annotations_apply", evidence, EVIDENCE_ANNOTATE_APPLY, stem=sha256[:16])
        return _j(body)
    finally:
        if verify_dir not in kept_scratch:
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

    CLI: python-only: deletes annotation versions on confirmation; the generic path never deletes
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


class _NotPurgeable:
    """Read-only survey of artifact classes that sit on disk next to an annotated scope but are NOT purge targets.
    It lives outside the purge functions on purpose: the purge source must never name the cache or evidence roots,
    and this survey is the only place that reads them (listing and counting; it opens, writes and deletes nothing)."""

    @staticmethod
    def survey(sha256):
        """Artifact classes that sit on disk next to this scope but are NOT purge targets. Listing and counting
        only: no file is opened, nothing is written or deleted. Paths are fixed relative labels, and only counts
        and byte totals come back, never a file name. A directory that is missing says so; one that cannot be read
        says so too, with the error type, and is never reported as empty."""
        dataset = Path(EVIDENCE_ANNOTATIONS).parent.parent
        classes = [
            ("pristine_target_database", "dataset/ida_cache", Path(CACHE_ROOT), None,
             "The cache holds the pristine analysed database that annotated versions are copied from. It is owned by the "
             "cache's own eviction and budget, not by this tool."),
            ("evidence_files", "dataset/evidence/ida_*", Path(EVIDENCE_ANNOTATIONS).parent, "ida_",
             "Evidence is the ledger of what the tools reported. Removing it would erase the record of what was done."),
            ("write_journals", "dataset/ida_annotated/<sha256>.writes.jsonl", _annotated_root(), "=" + sha256 + _ANNOTATION_LOG_SUFFIX,
             "This target's append-only audit journal (counted for this input hash only) is the record every purge itself is written to, and it is not re-derivable."),
            ("claims", "dataset/claims", dataset / "claims", None,
             "Claim event files are the source of truth for recorded claims; they belong to the claims ledger."),
            ("claim_indexes", "dataset/metadata/claim_indexes", dataset / "metadata" / "claim_indexes", None,
             "A derived index owned by the claims module; it is rebuilt by that module, not by purge."),
            ("evidence_indexes", "dataset/metadata/evidence_indexes", dataset / "metadata" / "evidence_indexes", None,
             "A derived index owned by the evidence module; it is rebuilt by that module, not by purge."),
        ]
        out = []
        for name, label_text, root, marker, why in classes:
            row = {"class": name, "path": label_text, "purgeable": False, "why_not_a_purge_target": why,
                   "present": None, "files": None, "bytes": None, "read_errors": 0}
            files, size, errors = 0, 0, []
            try:
                if not root.is_dir():
                    row["present"] = False
                else:
                    row["present"] = True
                    stack = [(root, True)]
                    while stack:
                        here, top = stack.pop()
                        try:
                            with os.scandir(here) as it:
                                children = list(it)
                        except OSError as exc:
                            errors.append(type(exc).__name__)
                            continue
                        for child in children:
                            try:
                                is_dir = child.is_dir(follow_symlinks=False)
                                if top and marker:
                                    if marker.startswith("ida_"):
                                        if not child.name.startswith(marker):
                                            continue
                                    elif is_dir or child.name != marker[1:]:
                                        continue
                                if is_dir:
                                    stack.append((Path(child.path), False))
                                    continue
                                files += 1
                                size += child.stat(follow_symlinks=False).st_size
                            except OSError as exc:
                                errors.append(type(exc).__name__)
                    row["files"], row["bytes"] = files, size
            except OSError as exc:
                errors.append(type(exc).__name__)
                row["present"] = None
            if errors:
                row["read_errors"] = len(errors)
                row["read_error_types"] = sorted(set(errors))
                row["files"] = row["bytes"] = None
            out.append(row)
        return {"note": "These classes remain on disk after a purge. None is a purge target; this call cannot delete them.",
                "classes": out}


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
              "unverified_reason": problem["reason"] if problem else None,
              "not_purgeable": _NotPurgeable.survey(sha256)}
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

_D810_PROJECT_LIST_LIMIT = 50


def _d810_probe():
    """What `ida_microcode_cfg(deobfuscate=True)` depends on, read WITHOUT starting IDA
    (file system and the registry only: the d810 package is never imported here).

    Three answers, never merged: `FOUND` (a copy was seen, with its version and project
    names), `NOT_FOUND` (the place that would hold it was read and has none) and
    `UNKNOWN` (the place could not be read or located; `reason` says why). Two places are
    looked at, each reported on its own: the pip copy in the site-packages of the Python
    that IDA is registered to use, and the plugin copy under IDA's user plugins directory.
    Which of them IDA's Python imports is not observable without running IDA, so
    `loaded_copy` is `UNKNOWN` unless exactly one copy exists and the other place is
    known to hold none."""
    home = str(Path.home())

    def shown(path):
        text = str(path)
        return "<HOME>" + text[len(home):] if home and text.lower().startswith(home.lower()) else text

    def version_of(package_dir, dist_dirs):
        for dist in dist_dirs:
            try:
                for line in (dist / "METADATA").read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip() or None
            except OSError:
                continue
        try:
            match = re.search(r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
                              (package_dir / "__init__.py").read_text(encoding="utf-8", errors="replace"), re.M)
            return match.group(1) if match else None
        except OSError:
            return None

    def describe(kind, package_dir, dist_dirs=()):
        entry = {"kind": kind, "status": "FOUND", "package": shown(package_dir),
                 "version": version_of(package_dir, dist_dirs)}
        if entry["version"] is None:
            entry["version_note"] = "UNKNOWN: no readable version in the package metadata or __init__"
        try:
            names = sorted(f.stem for f in (package_dir / "conf").glob("*.json") if f.stem != "options")
            entry["projects_total"] = len(names)
            entry["projects"] = names[:_D810_PROJECT_LIST_LIMIT]
            entry["projects_truncated"] = len(names) > _D810_PROJECT_LIST_LIMIT
        except OSError as exc:
            entry.update(projects="UNKNOWN", projects_total=None, projects_truncated=None,
                         projects_reason=f"{type(exc).__name__}: conf directory unreadable")
        return entry

    def pip_copy():
        base = {"kind": "pip", "status": "UNKNOWN"}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Hex-Rays\\IDA") as key:
                dll, _kind = winreg.QueryValueEx(key, "Python3TargetDLL")
        except ImportError:
            return dict(base, reason="registry unavailable on this platform: IDA's Python is not located")
        except Exception as exc:
            return dict(base, reason=f"{type(exc).__name__}: IDA's Python (Python3TargetDLL) could not be read")
        if not isinstance(dll, str) or not dll.strip():
            return dict(base, reason="Python3TargetDLL is not a path")
        site = Path(dll).parent / "Lib" / "site-packages"
        try:
            if not site.is_dir():
                return dict(base, reason="the Python named by Python3TargetDLL has no Lib/site-packages here",
                            site_packages=shown(site))
            package = site / "d810"
            if not (package / "__init__.py").is_file():
                return {"kind": "pip", "status": "NOT_FOUND", "site_packages": shown(site)}
            return dict(describe("pip", package, sorted(site.glob("d810*.dist-info"))),
                        site_packages=shown(site))
        except OSError as exc:
            return dict(base, reason=f"{type(exc).__name__}: site-packages unreadable")

    def plugin_copy():
        base = {"kind": "plugins", "status": "UNKNOWN"}
        user = os.environ.get("IDAUSR", "").strip()
        if not user:
            appdata = os.environ.get("APPDATA", "").strip()
            if not appdata:
                return dict(base, reason="neither IDAUSR nor APPDATA is set: IDA's user directory is not located")
            user = str(Path(appdata) / "Hex-Rays" / "IDA Pro")
        plugins = Path(user.split(os.pathsep)[0]) / "plugins"
        try:
            if not plugins.is_dir():
                return {"kind": "plugins", "status": "NOT_FOUND", "plugins_dir": shown(plugins)}
            for candidate in sorted(plugins.glob("d810*/src/d810")) + sorted(plugins.glob("d810*")):
                if (candidate / "__init__.py").is_file():
                    return dict(describe("plugins", candidate), plugins_dir=shown(plugins))
            return {"kind": "plugins", "status": "NOT_FOUND", "plugins_dir": shown(plugins)}
        except OSError as exc:
            return dict(base, reason=f"{type(exc).__name__}: plugins directory unreadable")

    try:
        copies = [pip_copy(), plugin_copy()]
    except Exception as exc:                                    # a probe never takes the status down
        return {"status": "UNKNOWN", "reason": f"{type(exc).__name__}: d810 could not be looked for",
                "copies": [], "loaded_copy": "UNKNOWN"}
    states = [c["status"] for c in copies]
    found = [c for c in copies if c["status"] == "FOUND"]
    overall = "FOUND" if found else ("UNKNOWN" if "UNKNOWN" in states else "NOT_FOUND")
    out = {"status": overall, "copies": copies,
           "measured_by": "file system and registry reads; IDA was not started and d810 was not imported"}
    if len(found) == 1 and all(c["status"] in ("FOUND", "NOT_FOUND") for c in copies):
        out["loaded_copy"] = found[0]["kind"]
        out["loaded_copy_basis"] = "the only copy present; not observed in a running IDA"
    else:
        out["loaded_copy"] = "UNKNOWN"
        out["loaded_copy_basis"] = ("which copy IDA's Python imports first cannot be read without running IDA"
                                    if len(found) > 1 else "a place that may hold a copy could not be read")
    if found:
        versions = {c["version"] for c in found}
        out["version"] = versions.pop() if len(versions) == 1 and None not in versions else "UNKNOWN"
    if overall == "NOT_FOUND":
        out["reason"] = "neither the IDA Python's site-packages nor the user plugins directory holds d810"
    return out


def ida_status():
    """Whether IDA is reachable, where from, and whether it actually works
    headless -- the probe to run before reporting IDA as unavailable. The
    `idalib` block reports the second backend (the interpreter named by
    LIEBERT_RE_IDALIB_PYTHON, redacted; the `idapro` version; the result of an
    `import idapro` probe) and `auto_backend` says which engine `backend="auto"` would use.

    Launches idat once on an EMPTY database (`-t -pmetapc`, about a second, no
    input file) and reads back the kernel version and whether the decompiler
    initialises, so `status: "OK"` means idat started without a dialog or a
    licence prompt, not merely that a file named idat exists. The probe runs
    in a throwaway directory under the cache root and leaves nothing behind.
    """
    tool = "ida_status"

    def read_lumina_config() -> dict:
        """Read IDA's per-user `AutoUseLumina` setting. A CONFIGURATION READ: it says
        what the setting is, not whether any query was or was not sent. Anything
        that stops the read yields UNKNOWN, never "off"."""
        source = "HKCU\\Software\\Hex-Rays\\IDA\\AutoUseLumina"
        out = {"kind": "configuration read (registry value), not an observation of network traffic",
               "source": source, "measurement": "UNKNOWN", "value": None, "auto_lumina": "UNKNOWN",
               "warning": None}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Hex-Rays\\IDA") as key:
                value, _kind = winreg.QueryValueEx(key, "AutoUseLumina")
        except ImportError:
            out["reason"] = "registry unavailable on this platform"
            return out
        except Exception as exc:                       # missing key/value, access denied, anything else
            out["reason"] = f"{type(exc).__name__}: could not read the value"
            return out
        if isinstance(value, bool) or not isinstance(value, int):
            out["reason"] = "value is not an integer"
            return out
        out.update(measurement="MEASURED", value=value)
        if value == 0:
            out["auto_lumina"] = "off"
        else:
            out["auto_lumina"] = "on"
            out["warning"] = ("AutoUseLumina is not 0: IDA may send function hashes, the input file name, "
                              "the IDB name and the input file MD5 to a Lumina server, identifying the target")
        return out

    idalib, _private = _idalib_probe(use_cache=False)
    auto_backend = {"selects": "idalib" if idalib["status"] == "OK" else "idat",
                    "basis": (f"{IDALIB_PYTHON_ENV} is set and the idalib probe succeeded" if idalib["status"] == "OK"
                              else "idalib is not usable (see idalib.status), so auto uses idat")}
    resolved_by, exe = _resolved_by_and_binary()
    if not exe:
        body = json.loads(_tool_missing(tool))
        body.update(idalib=idalib, auto_backend=auto_backend)
        return _j(body)
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
        lumina = read_lumina_config()
        warnings = [lumina["warning"]] if lumina.get("warning") else []
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": resolved_by,
            "ida_kernel_version": data.get("ida_kernel_version"),
            "decompiler_available": bool(data.get("hexrays_available")),
            "decompiler_version": data.get("hexrays_version"),
            "pdb_lookup_declared": dict(_PDB_LOOKUP_DECLARED),
            "log_network_text_found": signals["log_network_text_found"],
            "log_network_text_evidence_limit": _NETWORK_SCAN_LIMIT,
            "lumina_config": lumina,
            "idalib": idalib,
            "auto_backend": auto_backend,
            "d810": _d810_probe(),
            "warnings": warnings,
            "cache": _cache_summary(),
            "operations": ["ida_query", "ida_microcode_cfg", "ida_type_member_offset", "ida_patch_plan",
                           "ida_annotations", "ida_rename_plan", "ida_set_comments_plan", "ida_annotations_apply",
                           "ida_annotations_purge", "ida_status"],
            "query_operations": list(_ALLOWED_OPERATIONS),
            "note": (
                "OK means idat launched headless and exited cleanly on an empty database; it does not "
                "mean a particular file will analyse. decompiler_available false means decompile_function "
                "will fail; every other operation still works. Only IDA 9.x is supported. `idalib` is a separate "
                "report on the second backend: its probe is an `import idapro` in the interpreter named by "
                f"{IDALIB_PYTHON_ENV}, not a database open or a licence check."
            ),
        })
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
