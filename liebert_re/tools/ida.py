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

Scope of this module: `ida_query` and `ida_microcode_cfg` (read-only) and
`ida_status`. Writing operations (rename, comments, patch planning) are not here.
"""
from __future__ import annotations

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
# Created lazily, on first use: a status call on a machine without IDA must
# not leave an empty directory behind. Tests patch this name.
CACHE_ROOT = APP_DIR / "dataset" / "ida_cache"

_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "query_program.idapy"
_MICROCODE_WORKER_SOURCE = Path(__file__).resolve().parent / "ida_scripts" / "microcode_cfg.idapy"
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
_SLOT_NAME = re.compile(r"^[0-9a-f]{64}\.[A-Za-z0-9]+$")

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


def _checked_path(path, tool):
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return None, _j({"ok": False, "tool": tool, "status": "NOT_FOUND", "path": str(path)})
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


def _slot_dir(sha256):
    return _cache_root() / f"{sha256}.{_ANALYSIS_PROFILE}"


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
    record.update({"sha256": sha256, "profile": _ANALYSIS_PROFILE, "last_used": now})
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
            "budget_bytes": _cache_budget_bytes(), "key": f"sha256(input file) + profile {_ANALYSIS_PROFILE}"}


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
                      max_chars, evidence, note=None):
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


def _write_evidence(p, operation, data, directory=None):
    out = (directory or EVIDENCE) / f"{p.stem}_{uuid.uuid4().hex[:8]}_{operation}.json"
    error = None
    try:
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
    slot = _slot_dir(sha256)
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
    try:
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
        data, error, signals = _verdict(
            cp, work, (work / _DB_NAME) if creating else (slot / _DB_NAME), expect_database=creating,
            expect_operation=operation, require_discard=not creating,
        )
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
            if isinstance(refusal.get("detail"), str):
                refusal["detail"] = _redact(refusal["detail"], work=slot, target=p)   # an exception text can carry a path
            return refusal
        mislabelled = profile["validate"](data) if profile.get("validate") else None
        if mislabelled:
            # The answer does not say what it is (raw or d810-processed) the way the call asked for it.
            # Returning it would present transformed microcode as raw, or the reverse.
            return {
                "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": mislabelled,
                "path": relative(p), "target_sha256": sha256, "database_cache": cache_state,
                "invocation": invocation, "provenance": provenance,
                "detail": "The worker's result did not carry the label this call requires; no microcode is returned.",
            }
        evidence = _write_evidence(p, operation, data, profile.get("evidence_dir"))
        return _success_response(
            tool, p, sha256, md5, operation, data, cache_state=cache_state, signals=signals,
            invocation=invocation, max_chars=max_chars, evidence=evidence, note=profile.get("note"),
        )
    except _StageFailure as failure:
        return failure.body
    finally:
        if not (slot / _DB_NAME).exists():
            shutil.rmtree(slot, ignore_errors=True)  # a slot with no database is never kept


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
            "operations": ["ida_query", "ida_microcode_cfg", "ida_status"],
            "query_operations": list(_ALLOWED_OPERATIONS),
            "note": (
                "OK means idat launched headless and exited cleanly on an empty database; it does not "
                "mean a particular file will analyse. decompiler_available false means decompile_function "
                "will fail; every other operation still works. Only IDA 9.x is supported."
            ),
        })
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
