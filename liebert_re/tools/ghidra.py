"""Ghidra headless wrapper: install status, read-only program facts and read-only decompilation.

Three operations, both of which drive Ghidra's own ``support/analyzeHeadless``
and never reimplement analysis:

* ``ghidra_status`` measures the install (where ``analyzeHeadless`` is, which
  Ghidra version, the Java it needs and the Java found). It does not launch
  Ghidra, so ``OK`` means "the files are there and Java is new enough", not
  "a headless run will succeed".
* ``ghidra_program_facts`` imports one file into a throwaway project and reads
  back facts that need no judgement: loader, language, entry points, memory
  blocks, function count, imported library names. The source file is only
  read (its SHA-256 is compared before and after and reported).
* ``ghidra_decompile`` runs the same import and analysis, then decompiles at most 16 named or
  addressed functions with Ghidra's own decompiler (``ghidra_scripts/DecompileFunctions.java``). A
  function that cannot be resolved or decompiled has ``c_code: null`` and its reason; nothing is saved
  back to the program. It shares the facts operation's run, refusal and cleanup path
  (``_headless_run``).

**Exit code 0 is not success.** Measured on Ghidra 12.1.3: a post-script that
fails to run (a Jython ``.py`` script on a build without PyGhidra, a Java
script that fails to compile, a script that throws) still lets
``analyzeHeadless`` exit 0. This module therefore treats the process exit
code as one signal among several: the log is scanned for the failure markers
in ``_FAILURE_MARKERS``, the result file the script was told to write must
exist, parse, and carry the script's own completion flag. Any of them missing
is a refusal, never a success. The scripts are Java data files
(``ghidra_scripts/ProgramFacts.java``, ``ghidra_scripts/DecompileFunctions.java``) because Java post-scripts run on a
stock install, with no PyGhidra; PyGhidra is deliberately not used.

Every run gets its own project directory, so two concurrent runs cannot hit
Ghidra's per-project lock. A ``LockException`` is still reported with its own
status if one occurs. The subprocess is run through
``bounded_subprocess.run_bounded_process`` with this module's own timeout;
Ghidra's ``-analysisTimeoutPerFile`` is only a second, softer bound.

Privacy: logs and errors are passed through ``_redact`` (home directory,
account name, scratch and input paths) before they are returned or stored.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import shutil
import tempfile
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

EVIDENCE = APP_DIR / "dataset" / "evidence" / "ghidra_program_facts"
# The scratch parent. None means the system temp directory. Ghidra refuses a project path with any
# element that starts with a dot (measured: 'Path element starting with .'), so the scratch is NOT
# placed under the checkout, which can itself live under a dot-directory.
WORK_ROOT = None

_SCRIPT_SOURCE = Path(__file__).resolve().parent / "ghidra_scripts" / "ProgramFacts.java"
_SCRIPT_NAME = "ProgramFacts.java"
_RESULT_NAME = "facts.json"
_PROJECT_NAME = "liebert_facts"
_RESULT_SCHEMA = 1

_DEFAULT_TIMEOUT_SECONDS = 300
_MIN_TIMEOUT_SECONDS = 10
_MAX_TIMEOUT_SECONDS = 1800
_JAVA_PROBE_TIMEOUT_SECONDS = 20
_MAX_OUTPUT_CHARS = 8 * 1024 * 1024
_LOG_TAIL_CHARS = 2000

# In the combined analyzeHeadless output, any of these means the run did not
# work even when the process exited 0. Matched case-insensitively.
# 'SCRIPT ERROR' is what a failed post-script prints; the PyGhidra line is the
# measured text when a .py script is given to a build started without it.
_FAILURE_MARKERS = (
    ("script error", "SCRIPT_ERROR"),
    ("ghidra was not started with pyghidra", "SCRIPT_RUNTIME_UNAVAILABLE"),
    ("ghidrascriptloadexception", "SCRIPT_LOAD_FAILED"),
    ("unable to compile", "SCRIPT_COMPILE_FAILED"),
    ("failed to compile", "SCRIPT_COMPILE_FAILED"),
    ("script not found", "SCRIPT_NOT_FOUND"),
    ("unable to find script", "SCRIPT_NOT_FOUND"),
    ("unable to lock project", "PROJECT_LOCKED"),
    ("lockexception", "PROJECT_LOCKED"),
    ("import failed", "IMPORT_FAILED"),
    ("unable to import", "IMPORT_FAILED"),
    ("no load spec found", "IMPORT_FAILED"),
    ("unsupported file format", "IMPORT_FAILED"),
    ("abort due to headless analyzer error", "HEADLESS_ABORT"),
    ("exception in thread", "JVM_EXCEPTION"),
    ("unsupportedclassversionerror", "JAVA_TOO_OLD"),
)

_OPERATIONS = ["ghidra_status", "ghidra_program_facts", "ghidra_decompile"]

# The fact keys ProgramFacts.java must write, with the type each must have when it is not null.
# This is the contract the reader enforces: a key missing from the result is "not measured", never
# an empty value, and a result carrying none of them is refused.
_FACT_SPEC = {
    "loader": str, "language_id": str, "processor": str, "endian": str, "variant": str,
    "address_size_bits": int, "compiler_spec": str, "image_base": str,
    "entry_point_count": int, "entry_points": list,
    "memory_block_count": int, "memory_blocks": list,
    "function_count": int,
    "external_library_count": int, "external_libraries": list,
    "errors": list,
}

_FACT_CONTRACT_KEYS = tuple(key for key in _FACT_SPEC if key != "errors")

_KNOWN_INSTALL_GLOBS = (
    "ghidra*", "*/ghidra*",
)


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


_ABS_DRIVE = re.compile(r"(?<![A-Za-z0-9<>])[A-Za-z]:[\\/][^\s\"'<>|*?]*")
_ABS_UNC = re.compile(r"\\\\[A-Za-z0-9_.$-]+\\[^\s\"'<>|*?]*")
_ABS_POSIX = re.compile(r"(?<![A-Za-z0-9_.<>/:-])/(?:[A-Za-z0-9_.@+-]+/)+[A-Za-z0-9_.@+-]*")


def _redact(text, *, work=None, target=None, generic=True):
    """Make Ghidra output safe to return or store: the scratch and input paths,
    home-directory paths and the account name. With ``generic`` (the default) any
    other absolute path becomes <PATH> too, so an install on another drive or a
    system directory in a log line does not leak. Callers that show a path on
    purpose pass ``generic=False`` and abbreviate it with ``_shown_path``."""
    text = text or ""
    for needle, token in ((str(work) if work else "", "<WORK>"), (str(target) if target else "", "<INPUT>")):
        if needle:
            for variant in {needle, needle.replace("\\", "/"), needle.replace("/", "\\")}:
                text = text.replace(variant, token)
    text = re.sub(r"[A-Za-z]:(?:\\+|/)Users(?:\\+|/)[^\\/\s\"'<>|:*?]+", "<HOME>", text, flags=re.I)
    text = re.sub(r"(?<![A-Za-z0-9])/(?:home|Users)/[^/\s\"'<>|:*?]+", "<HOME>", text)
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = ""
    if len(user) >= 3:
        text = re.sub(rf"(?<![A-Za-z0-9]){re.escape(user)}(?![A-Za-z0-9])", "<USER>", text, flags=re.I)
    try:
        home = str(Path.home())
    except Exception:  # noqa: BLE001
        home = ""
    if len(home) > 3:
        for variant in {home, home.replace("\\", "/"), home.replace("/", "\\")}:
            text = text.replace(variant, "<HOME>")
    if generic:
        text = _ABS_DRIVE.sub("<PATH>", text)
        text = _ABS_UNC.sub("<PATH>", text)
        text = _ABS_POSIX.sub("<PATH>", text)
    return text


def _shown_path(path, keep):
    """A path this module shows on purpose: a home path becomes <HOME>/..., any other absolute
    path keeps only its last ``keep`` components behind <ABS>."""
    text = _redact(str(path), generic=False)
    if text.startswith("<HOME>") or not re.match(r"[A-Za-z]:|[\\/]", text):
        return text
    parts = [x for x in re.split(r"[\\/]+", text) if x and not re.fullmatch(r"[A-Za-z]:", x)]
    return "<ABS>/" + "/".join(parts[-keep:])


def _tail(text, work=None, target=None, limit=_LOG_TAIL_CHARS):
    return _redact(text, work=work, target=target)[-limit:]


def _checked_path(path, tool):
    try:
        p = safe_path(path)
    except PermissionError as exc:
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": str(exc)})
    except (OSError, ValueError) as exc:
        return None, _j({"ok": False, "tool": tool, "status": "PATH_REFUSED", "error": type(exc).__name__})
    if not p.is_file():
        return None, _j({"ok": False, "tool": tool, "status": "NOT_FOUND", "path": _redact(str(path))})
    return p, None


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# install discovery
# --------------------------------------------------------------------------

def _headless_in(install_dir):
    """The analyzeHeadless launcher under an install directory, or None."""
    names = ("analyzeHeadless.bat", "analyzeHeadless") if os.name == "nt" else ("analyzeHeadless",)
    for name in names:
        candidate = Path(install_dir) / "support" / name
        if candidate.is_file():
            return candidate
    return None


def _read_properties(install_dir):
    """Ghidra/application.properties as a dict, or None when unreadable."""
    path = Path(install_dir) / "Ghidra" / "application.properties"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    props = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    return props


def _version_key(version):
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts)


def _known_roots():
    roots = []
    try:
        home = Path.home()
        roots += [home, home / "Desktop", home / "Downloads"]
    except (RuntimeError, OSError):
        pass
    if os.name == "nt":
        roots += [Path("C:/"), Path("C:/Tools")]
        for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            value = os.environ.get(var, "").strip()
            if value:
                roots.append(Path(value))
    else:
        roots += [Path("/opt"), Path("/usr/local"), Path("/usr/share")]
    seen, ordered = set(), []
    for root in roots:
        key = str(root)
        if key not in seen:
            seen.add(key)
            ordered.append(root)
    return ordered


def _discover_installs():
    """Every Ghidra install directory that has an analyzeHeadless launcher, as
    a list of (resolved_by, install_dir) in discovery order, plus the list of
    explicit settings that were set but unusable. Order: GHIDRA_INSTALL_DIR,
    GHIDRA_HOME, PATH, then the known locations (sorted, so the order is stable).
    A directory seen twice is kept once, under its first source. Never raises."""
    found, skipped, seen = [], [], set()

    def add(resolved_by, directory):
        try:
            key = os.path.normcase(str(Path(directory).resolve()))
        except OSError:
            return
        if key in seen:
            return
        seen.add(key)
        found.append((resolved_by, Path(directory)))

    try:
        for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
            value = os.getenv(var, "").strip()
            if not value:
                continue
            if Path(value).is_dir() and _headless_in(value):
                add(var, value)
            else:
                skipped.append({"setting": var, "reason": "no support/analyzeHeadless under it"})
        on_path = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        if on_path:
            add("PATH", Path(on_path).resolve().parent.parent)
        for root in _known_roots():
            # A filesystem root (C:/) is searched one level deep only: "*/ghidra*" there would list every
            # top-level directory on the drive; C:/Tools, Program Files and LOCALAPPDATA are separate roots.
            globs = _KNOWN_INSTALL_GLOBS[:1] if root == Path(root.anchor) else _KNOWN_INSTALL_GLOBS
            for pattern in globs:
                try:
                    matches = sorted(root.glob(pattern))
                except (OSError, ValueError):
                    continue
                for directory in matches:
                    if directory.is_dir() and _headless_in(directory):
                        add("known_install", directory)
    except OSError:
        pass
    return found, skipped


def _select_install():
    """(selection, candidates, skipped). The selection is None when nothing was
    found. An explicit GHIDRA_INSTALL_DIR/GHIDRA_HOME that is valid wins; with
    no explicit setting the highest Ghidra version wins and an equal version
    keeps discovery order. ``selected_by`` says which rule decided."""
    found, skipped = _discover_installs()
    candidates = []
    for resolved_by, directory in found:
        props = _read_properties(directory)
        candidates.append({
            "resolved_by": resolved_by,
            "install_dir": directory,
            "headless": _headless_in(directory),
            "version": (props or {}).get("application.version") or None,
            "java_min": (props or {}).get("application.java.min") or None,
            "properties_readable": props is not None,
        })
    if not candidates:
        return None, candidates, skipped
    explicit = [c for c in candidates if c["resolved_by"] in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME")]
    if explicit:
        return dict(explicit[0], selected_by="explicit environment setting"), candidates, skipped
    best = max(range(len(candidates)),
               key=lambda i: (_version_key(candidates[i]["version"]), -i))
    rule = ("only install found" if len(candidates) == 1
            else "highest application.version; equal versions keep discovery order")
    return dict(candidates[best], selected_by=rule), candidates, skipped


def _java_executable():
    home = os.getenv("JAVA_HOME", "").strip()
    if home:
        for name in ("java.exe", "java"):
            candidate = Path(home) / "bin" / name
            if candidate.is_file():
                return str(candidate), "JAVA_HOME"
    found = shutil.which("java")
    if found:
        return found, "PATH"
    return None, None


def _parse_java_major(text):
    """Major version from `java -version` output, or None. '1.8.0_x' is 8."""
    match = re.search(r'version "(\d+)(?:\.(\d+))?', text or "")
    if not match:
        return None
    major = int(match.group(1))
    if major == 1 and match.group(2):
        return int(match.group(2))
    return major


def _probe_java():
    """(info dict). 'major' is None when it could not be determined; that is
    reported as unknown, never as a pass."""
    exe, via = _java_executable()
    if not exe:
        return {"found": False, "major": None, "resolved_by": None, "version_line": None}
    cp = run_bounded_process([exe, "-version"], timeout_seconds=_JAVA_PROBE_TIMEOUT_SECONDS,
                                 max_output_chars=4096)
    if cp.launch_failed is True:
        return {"found": True, "major": None, "resolved_by": via, "version_line": None,
                "error": f"JAVA_LAUNCH_FAILED: {cp.launch_error}"}
    if cp.timed_out:
        return {"found": True, "major": None, "resolved_by": via, "version_line": None,
                "error": "JAVA_VERSION_PROBE_TIMEOUT"}
    text = ((cp.stderr or "") + "\n" + (cp.stdout or "")).strip()
    lines = text.splitlines()
    return {"found": True, "major": _parse_java_major(text), "resolved_by": via,
            "version_line": _redact(lines[0]) if lines else None}


def _int_or_none(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _display_candidate(candidate, selected):
    return {
        "resolved_by": candidate["resolved_by"],
        "install_dir": _shown_path(candidate["install_dir"], 1),
        "version": candidate["version"],
        "selected": candidate["install_dir"] == selected["install_dir"] if selected else False,
    }


def _tool_missing(tool, skipped=()):
    body = {
        "ok": False, "tool": tool, "status": "TOOL_MISSING",
        "required_capability": "Ghidra with support/analyzeHeadless (Java 21 or newer for Ghidra 12)",
        "detail": (
            "analyzeHeadless was not found. Set GHIDRA_INSTALL_DIR (or GHIDRA_HOME) to the Ghidra "
            "install folder, or put its support folder on PATH. Ghidra is not shipped or downloaded "
            "by this package. Checked after those: ghidra* folders directly under the home directory, "
            "its Desktop and Downloads, one level below the home directory, under C:/ and "
            "C:/Tools and Program Files (or /opt, /usr/local on other systems)."
        ),
    }
    if skipped:
        body["unusable_settings"] = list(skipped)
    return _j(body)


def ghidra_status():
    """Where Ghidra's analyzeHeadless is, which Ghidra version, the Java it
    needs and the Java that was found, and the operations this module offers.

    Measures files and one ``java -version``; it does NOT launch Ghidra, so
    ``OK`` is not a promise that a headless run works (run
    ``ghidra_program_facts`` on a fixture for that). When several installs
    exist, ``installs`` lists them all and ``selected_by`` names the rule that
    chose one. ``java.satisfies_minimum`` is null (unknown) when either side
    could not be read, never a guess.
    """
    tool = "ghidra_status"
    selection, candidates, skipped = _select_install()
    if selection is None:
        return _tool_missing(tool, skipped)
    java = _probe_java()
    java_min = _int_or_none(selection["java_min"])
    satisfies = None
    if java["major"] is not None and java_min is not None:
        satisfies = java["major"] >= java_min
    base = {
        "tool": tool,
        "binary": _shown_path(selection["headless"], 3),
        "version": selection["version"],
        "resolved_by": selection["resolved_by"],
        "selected_by": selection["selected_by"],
        "installs": [_display_candidate(c, selection) for c in candidates],
        "unusable_settings": skipped,
        "java": {
            "found": java["found"],
            "found_major": java["major"],
            "version_line": java["version_line"],
            "resolved_by": java["resolved_by"],
            "required_minimum": java_min,
            "satisfies_minimum": satisfies,
        },
        "operations": list(_OPERATIONS),
        "launcher_verified": False,
        "launcher_check": "file present; analyzeHeadless was not executed by this call",
    }
    if os.name != "nt" and not os.access(selection["headless"], os.X_OK):
        return _j(dict(base, ok=False, status="INSTALL_INCOMPLETE", error="LAUNCHER_NOT_EXECUTABLE",
                       detail="analyzeHeadless exists but is not marked executable."))
    if not selection["properties_readable"] or selection["version"] is None:
        return _j(dict(base, ok=False, status="INSTALL_INCOMPLETE",
                       error="GHIDRA_APPLICATION_PROPERTIES_UNREADABLE",
                       detail="analyzeHeadless exists but Ghidra/application.properties could not be read, "
                              "so the version and the Java requirement are unknown."))
    if satisfies is False:
        return _j(dict(base, ok=False, status="JAVA_TOO_OLD",
                       error="JAVA_BELOW_REQUIRED_MINIMUM",
                       detail="The Java found is older than application.java.min; analyzeHeadless will not start."))
    if not java["found"]:
        return _j(dict(base, ok=False, status="JAVA_MISSING", error="JAVA_NOT_FOUND",
                       detail="No java on JAVA_HOME or PATH."))
    return _j(dict(base, ok=True, status="OK", note=(
        "OK means analyzeHeadless and application.properties were found and the Java found meets "
        "the minimum (null satisfies_minimum would mean it could not be read). Ghidra was NOT "
        "launched by this call, so launcher_verified is false: a launcher that exists but cannot start "
        "still reads OK here. ghidra_program_facts is the check that a headless run completes. "
        "Python post-scripts need PyGhidra and are not used: the scripts here are Java."
    )))


# --------------------------------------------------------------------------
# program facts
# --------------------------------------------------------------------------

def _scan_failures(log):
    """The failure codes whose marker appears in the log, in marker order."""
    lowered = (log or "").lower()
    seen = []
    for marker, code in _FAILURE_MARKERS:
        if marker in lowered and code not in seen:
            seen.append(code)
    return seen


def _count_error_lines(log):
    return sum(1 for line in (log or "").splitlines() if re.match(r"\s*ERROR\b", line))


def _read_result(result_path, contract_keys=None):
    """(data, error_code). Anything short of a complete, schema-matching file is an error code and no
    data. ``contract_keys``: at least one of them must be present (the facts keys by default)."""
    if contract_keys is None:
        contract_keys = _FACT_CONTRACT_KEYS
    try:
        raw = result_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, "GHIDRA_NO_RESULT_FILE"
    except OSError:
        return None, "GHIDRA_RESULT_UNREADABLE"
    try:
        data = json.loads(raw)
    except ValueError:
        return None, "GHIDRA_RESULT_NOT_JSON"
    if not isinstance(data, dict):
        return None, "GHIDRA_RESULT_NOT_AN_OBJECT"
    if data.get("script_completed") is not True:
        return None, "GHIDRA_RESULT_INCOMPLETE"
    if data.get("schema") != _RESULT_SCHEMA:
        return None, "GHIDRA_RESULT_SCHEMA_MISMATCH"
    if not any(key in data for key in contract_keys):
        return None, "GHIDRA_RESULT_CONTRACT_VIOLATION"
    return data, None


def ghidra_program_facts(path, timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Import `path` into a throwaway Ghidra project, let Ghidra's default
    analysis run, and return read-only facts about the resulting program.

    Facts: loader, language id and processor, endianness, address size,
    compiler spec, image base, entry points, memory blocks, function count and
    imported library names. A fact the script could not read is null and is
    named in ``facts_unreadable``; nothing is guessed. The function count is
    what analysis found within the time bound, not a complete inventory.

    The source file is not modified; its SHA-256 is taken before and after and
    ``source_unchanged`` says whether they match. The project directory is
    unique to the call and is removed at the end.

    Status vocabulary: OK, TOOL_MISSING, JAVA_TOO_OLD, JAVA_MISSING,
    INSTALL_INCOMPLETE, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED (Ghidra started and the run failed: see ``error`` and
    ``failure_signals``), PROJECT_LOCKED (Ghidra's own LockException),
    ENVIRONMENT_ERROR (scratch directory or script file unusable). Exit code 0
    with a failure marker in the log, or without a complete result file, is
    ANALYSIS_LIMITED, never OK.
    """
    tool = "ghidra_program_facts"
    selection, p, refusal = _preflight(tool, path)
    if refusal:
        return refusal
    timeout = _clamp_timeout(timeout_seconds)
    analysis_timeout = max(5, int(timeout * 0.6))
    before, refusal = _hash_source(tool, p)
    if refusal:
        return refusal
    return _j(_scratch_run(tool, lambda work: _facts_in_work(
        tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token)))


def _preflight(tool, path):
    """The checks every headless operation starts with. (selection, path, None) when a run may
    start, else (None, None, refusal JSON): no install, a path the workspace refuses or that is not a
    file, an unreadable application.properties, no Java, or a Java below the install's minimum."""
    selection, _candidates, skipped = _select_install()
    if selection is None:
        return None, None, _tool_missing(tool, skipped)
    p, fail = _checked_path(path, tool)
    if fail:
        return None, None, fail
    if not selection["properties_readable"]:
        return None, None, _j({"ok": False, "tool": tool, "status": "INSTALL_INCOMPLETE",
                               "error": "GHIDRA_APPLICATION_PROPERTIES_UNREADABLE"})
    java = _probe_java()
    java_min = _int_or_none(selection["java_min"])
    if not java["found"]:
        return None, None, _j({"ok": False, "tool": tool, "status": "JAVA_MISSING", "error": "JAVA_NOT_FOUND"})
    if java["major"] is not None and java_min is not None and java["major"] < java_min:
        return None, None, _j({"ok": False, "tool": tool, "status": "JAVA_TOO_OLD",
                               "error": "JAVA_BELOW_REQUIRED_MINIMUM",
                               "java_found_major": java["major"], "java_required_minimum": java_min})
    return selection, p, None


def _clamp_timeout(value, default=_DEFAULT_TIMEOUT_SECONDS):
    try:
        return max(_MIN_TIMEOUT_SECONDS, min(int(value), _MAX_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return default


def _hash_source(tool, p):
    """(sha256, None), or (None, refusal JSON) when the source cannot be read."""
    try:
        return _sha256_file(p), None
    except OSError as exc:
        return None, _j({"ok": False, "tool": tool, "status": "NOT_FOUND", "error": type(exc).__name__})


def _scratch_run(tool, run):
    """Call ``run(work)`` inside a unique scratch directory and remove it afterwards. Returns the
    response dict; a directory that could not be removed is reported in ``cleanup_failures``."""
    try:
        work = Path(tempfile.mkdtemp(prefix="liebert-ghidra-", dir=str(WORK_ROOT) if WORK_ROOT else None))
    except OSError as exc:
        return {"ok": False, "tool": tool, "status": "ENVIRONMENT_ERROR",
                "error": "GHIDRA_WORK_OR_SCRIPT_UNUSABLE",
                "detail": f"{type(exc).__name__} while creating the scratch directory."}
    try:
        body = run(work)
    finally:
        cleanup_failure = _remove_work(work)
    if cleanup_failure:
        body["cleanup_failures"] = [cleanup_failure]
    return body


def _remove_work(work):
    """Remove the scratch project. Best effort, never raises; a directory that could not be
    removed is returned as a failure record instead of being ignored (None when it is gone)."""
    error = None
    try:
        shutil.rmtree(work)
    except OSError as exc:
        error = type(exc).__name__
        shutil.rmtree(work, ignore_errors=True)
    if work.exists():
        return {"directory": work.name, "error": error or "STILL_PRESENT",
                "may_remain_on_disk": True,
                "detail": "The temporary Ghidra project could not be removed and may still be on disk."}
    return None


def _normalise_facts(raw):
    """(facts, unreadable, missing, malformed). Every key in ``_FACT_SPEC`` is present in the
    returned facts. A key the script reported as null is unreadable; a key the result did not
    carry at all is missing (never measured); a key of the wrong type is malformed and is
    treated as unreadable. None of them is turned into zero or an empty list."""
    facts, unreadable, missing, malformed = {}, [], [], []
    for key, kind in _FACT_SPEC.items():
        if key not in raw:
            facts[key] = None
            missing.append(key)
            unreadable.append(key)
            continue
        value = raw[key]
        if value is None:
            facts[key] = None
            unreadable.append(key)
        elif isinstance(value, bool) or not isinstance(value, kind):
            facts[key] = None
            malformed.append(key)
            unreadable.append(key)
        else:
            facts[key] = value
    return facts, sorted(unreadable), sorted(missing), sorted(malformed)


def _fail(tool, status, error, **extra):
    return dict({"ok": False, "tool": tool, "status": status, "error": error}, **extra)


def _headless_run(tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token,
                  script, contract_keys, extra_files=None, extra_args=()):
    """One analyzeHeadless run with a Java post-script, inside an already created scratch directory.
    Returns ``(failure, raw, common)``: ``failure`` is a response dict when the run must be refused
    (then ``raw`` and ``common`` are None); otherwise ``raw`` is the script's parsed result and
    ``common`` the invocation and log facts every response carries.

    ``script`` is ``(source_path, script_name, result_name)``. The script gets the result file path
    as its first argument, then ``extra_args``; an extra argument ``"@work/<name>"`` is replaced by
    the absolute path of ``extra_files[<name>]``, a text file written into the scratch directory
    (request data goes through a file, never through the command line: analyzeHeadless splits
    arguments on whitespace and its Windows launcher is a batch file).

    Exit code 0 is not trusted, see the module docstring. The source file's hash is re-taken after
    the run and a change is a refusal."""
    source_path, script_name, result_name = script

    def fail(status, error, **extra):
        return _fail(tool, status, error, **extra), None, None

    if any(part.startswith(".") and part not in (".", "..") for part in work.parts):
        return fail("ENVIRONMENT_ERROR", "GHIDRA_SCRATCH_PATH_HAS_DOT_ELEMENT",
                    detail="Ghidra rejects a project path with a dot-prefixed element; the "
                           "system temp directory is under one.")
    try:
        scripts = work / "scripts"
        scripts.mkdir()
        projects = work / "project"
        projects.mkdir()
        source = Path(source_path).read_bytes()
        if source.startswith(b"\xef\xbb\xbf"):
            source = source[3:]
        (scripts / script_name).write_bytes(source.replace(b"\r\n", b"\n"))
        for name, text in (extra_files or {}).items():
            (work / name).write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        return fail("ENVIRONMENT_ERROR", "GHIDRA_WORK_OR_SCRIPT_UNUSABLE",
                    detail=f"{type(exc).__name__} while preparing the scratch directory or script.")
    result_path = work / result_name
    script_args = [str(result_path)]
    for arg in extra_args:
        arg = str(arg)
        script_args.append(str(work / arg[len("@work/"):]) if arg.startswith("@work/") else arg)
    argv = [
        str(selection["headless"]), str(projects), _PROJECT_NAME,
        "-import", str(p),
        "-scriptPath", str(scripts),
        "-postScript", script_name, *script_args,
        "-analysisTimeoutPerFile", str(analysis_timeout),
        "-deleteProject",
    ]
    try:
        cp = run_bounded_process(argv, timeout_seconds=timeout, cancellation_token=cancellation_token,
                                 max_output_chars=_MAX_OUTPUT_CHARS)
    except OSError as exc:  # defensive: the runner reports a failed launch itself (below)
        return fail("ENVIRONMENT_ERROR", "GHIDRA_LAUNCH_FAILED",
                    detail=f"analyzeHeadless was found but could not be started ({type(exc).__name__}).",
                    launcher_executed=False)
    if cp.launch_failed is True:
        return fail("ENVIRONMENT_ERROR", "GHIDRA_LAUNCH_FAILED",
                    detail=f"analyzeHeadless was found but could not be started ({cp.launch_error}).",
                    launch_error=cp.launch_error, launcher_executed=False)
    log = (cp.stdout or "") + "\n" + (cp.stderr or "")
    invocation = {"timeout_seconds": timeout, "analysis_timeout_seconds": analysis_timeout}
    if cp.cancelled or cp.timed_out:
        terminated = bool(cp.process_tree_terminated)
        what = "CANCELLED" if cp.cancelled else "TIMEOUT"
        error = (f"GHIDRA_{what}_PROCESS_TREE_TERMINATED" if terminated
                 else f"GHIDRA_{what}_PROCESS_TREE_NOT_CONFIRMED_TERMINATED")
        extra = {"invocation": invocation, "process_tree_terminated": terminated}
        if not terminated:
            extra["detail"] = ("The bounded runner did not confirm that the Ghidra process tree was "
                               "terminated; a JVM may still be running.")
        if cp.timed_out:
            extra["log_tail"] = _tail(log, work, p)
            extra.setdefault("detail", "Raise timeout_seconds; a timeout is not 'no result' and no "
                                       "partial result is used.")
        return fail(what, error, **extra)
    signals = _scan_failures(log)
    common = {"invocation": invocation, "exit_code": cp.returncode, "failure_signals": signals,
              "log_error_lines": _count_error_lines(log), "log_tail": _tail(log, work, p)}
    if "PROJECT_LOCKED" in signals:
        return fail("PROJECT_LOCKED", "GHIDRA_PROJECT_LOCKED", **dict(
            common, detail="Ghidra reported its project lock. Each run uses its own "
                           "project directory, so another process is using this one."))
    if signals:
        return fail("ANALYSIS_LIMITED", "GHIDRA_FAILURE_MARKER_IN_LOG", **dict(
            common, detail=("The log carries a failure marker. analyzeHeadless can exit 0 while the "
                            "script or the import failed, so the exit code was not trusted and any "
                            "result file was ignored.")))
    if cp.returncode != 0:
        return fail("ANALYSIS_LIMITED", "GHIDRA_EXITED_NONZERO", **common)
    raw, error = _read_result(result_path, contract_keys)
    if error:
        return fail("ANALYSIS_LIMITED", error, **dict(
            common, detail="Exit code 0 and no failure marker, but the script's result file is "
                           "missing, incomplete or does not match the contract; nothing is reported."))
    try:
        after = _sha256_file(p)
    except OSError as exc:
        return fail("ANALYSIS_LIMITED", "SOURCE_UNVERIFIED", source_sha256_before=before,
                    detail=f"The source could not be re-read after the run ({type(exc).__name__}), so "
                           "it is not known whether it was left unmodified; nothing is reported.")
    if after != before:
        return fail("ANALYSIS_LIMITED", "SOURCE_MODIFIED", source_sha256_before=before,
                    source_sha256_after=after,
                    detail="The input file changed during the run. The import is read-only by design, so "
                           "nothing is reported.")
    return None, raw, common


def _facts_in_work(tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token):
    """The facts run, inside an already created scratch directory. Returns the response as a dict."""
    failure, raw, common = _headless_run(
        tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token,
        (_SCRIPT_SOURCE, _SCRIPT_NAME, _RESULT_NAME), _FACT_CONTRACT_KEYS)
    if failure:
        return failure
    invocation = common["invocation"]
    facts, unreadable, missing, malformed = _normalise_facts(raw)
    facts["errors"] = [_redact(str(e), work=work, target=p) for e in (facts.get("errors") or [])]
    unreadable = [k for k in unreadable if k != "errors"]
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"{p.stem}_{uuid.uuid4().hex[:8]}_facts.json"
    evidence_error = None
    try:
        out.write_text(json.dumps({"source_sha256": before, "facts": facts}, ensure_ascii=False),
                       encoding="utf-8")
        _evidence_index_record_write(out)
    except OSError as exc:
        evidence_error = type(exc).__name__
    except Exception:  # noqa: BLE001
        pass
    return {
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "ghidra_version": selection["version"],
        "resolved_by": selection["resolved_by"],
        "invocation": invocation,
        "source_sha256": before,
        "source_unchanged": True,
        "facts": facts,
        "facts_unreadable": unreadable,
        "facts_missing_from_result": [k for k in missing if k != "errors"],
        "facts_malformed": [k for k in malformed if k != "errors"],
        "log_error_lines": common["log_error_lines"],
        "internal_evidence_name": out.name,
        "evidence_write_error": evidence_error,
        "note": (
            "Read-only facts from Ghidra's own import and default analysis. function_count is what "
            "analysis found inside the time bound (invocation.analysis_timeout_seconds), not a "
            "complete inventory. facts_unreadable lists every fact that is null: the script reported "
            "it unreadable, or the result did not carry the key at all (facts_missing_from_result), "
            "or it had the wrong type (facts_malformed); none of those is zero or empty. Lists are "
            "capped in the script; the *_count fields carry the true totals."
        ),
    }


# --------------------------------------------------------------------------
# decompile
# --------------------------------------------------------------------------

_DECOMPILE_SCRIPT_SOURCE = Path(__file__).resolve().parent / "ghidra_scripts" / "DecompileFunctions.java"
_DECOMPILE_SCRIPT_NAME = "DecompileFunctions.java"
_DECOMPILE_RESULT_NAME = "decompile.json"
_DECOMPILE_REQUEST_NAME = "requests.txt"
_DECOMPILE_MAX_FUNCTIONS = 16
_DECOMPILE_DEFAULT_PER_FUNCTION_SECONDS = 30
_DECOMPILE_MIN_PER_FUNCTION_SECONDS = 5
_DECOMPILE_MAX_PER_FUNCTION_SECONDS = 120
_DECOMPILE_BASE_TIMEOUT_SECONDS = 300
_DECOMPILE_MAX_NAME_CHARS = 512
_ADDRESS_TEXT = re.compile(r"0[xX]([0-9a-fA-F]{1,16})")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# What one entry of the script's "functions" list must carry, with the type each has when not null.
_DECOMPILE_ENTRY_SPEC = {
    "requested": str, "address": str, "name": str, "signature": str, "decompiled_signature": str,
    "c_code": str, "c_code_truncated": bool, "decompile_completed": bool, "warnings": list, "error": str,
}


def _usage(tool, error, detail, **extra):
    return _j(dict({"ok": False, "tool": tool, "status": "TOOL_USAGE", "error": error, "detail": detail}, **extra))


def _function_requests(functions):
    """(requests, None) or (None, (error, detail)). A request is ``("A", hex)`` for an address or
    ``("N", name)`` for a function name. An ``int`` and a string written ``0x...`` are addresses; every
    other string is a name, so a name that happens to look like hex (``deadbeef``) is never taken for
    an address. Nothing is guessed: an unusable item refuses the whole call."""
    if functions is None:
        return None, ("FUNCTIONS_REQUIRED", "name at least one function address (0x...) or name")
    items = [functions] if isinstance(functions, (str, int)) and not isinstance(functions, bool) else functions
    if not isinstance(items, (list, tuple)):
        return None, ("FUNCTION_SPEC_INVALID", "functions must be a list of addresses and names")
    if not items:
        return None, ("FUNCTIONS_REQUIRED", "name at least one function address (0x...) or name")
    if len(items) > _DECOMPILE_MAX_FUNCTIONS:
        return None, ("TOO_MANY_FUNCTIONS",
                      f"{len(items)} requested, at most {_DECOMPILE_MAX_FUNCTIONS} per call; split the call")
    requests = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            return None, ("FUNCTION_SPEC_INVALID", f"{type(item).__name__} is not an address or a name")
        if isinstance(item, int):
            if not 0 <= item < 1 << 64:
                return None, ("FUNCTION_SPEC_INVALID", "an integer address must fit in 64 bits")
            requests.append(("A", format(item, "x")))
            continue
        text = item.strip()
        if not text or len(text) > _DECOMPILE_MAX_NAME_CHARS or _CONTROL_CHARS.search(text):
            return None, ("FUNCTION_SPEC_INVALID",
                          "a function name must be non-empty, without control characters, and at most "
                          f"{_DECOMPILE_MAX_NAME_CHARS} characters")
        match = _ADDRESS_TEXT.fullmatch(text)
        requests.append(("A", match.group(1).lower()) if match else ("N", text))
    return requests, None


def ghidra_decompile(path, functions, per_function_timeout_seconds=_DECOMPILE_DEFAULT_PER_FUNCTION_SECONDS,
                     timeout_seconds=None, cancellation_token=None):
    """Import `path` into a throwaway Ghidra project, let Ghidra's default analysis run, and decompile
    the selected functions with Ghidra's own decompiler. Read-only: nothing is saved, renamed, created
    or retyped, and the source file is only read.

    `functions` is a list (one string or integer is accepted too) of at most 16 items. An item is an
    address (an ``int`` or a string written ``0x140001000``; the function containing it is decompiled
    and the answer carries that function's entry address) or a function name as Ghidra knows it,
    including its auto names such as ``FUN_140001000``. A string that is not written ``0x...`` is
    always a name. A name that matches no function is ``FUNCTION_NOT_FOUND``; a name shared by several
    functions is ``AMBIGUOUS_FUNCTION_NAME`` and lists their addresses, never a pick.

    Each requested item gets one entry in ``functions``, in request order: ``requested``, ``address``,
    ``name``, ``signature`` (Ghidra's listing prototype), ``decompiled_signature``, ``c_code``,
    ``c_code_truncated``, ``decompile_completed`` (bool), ``warnings`` (decompiler markers found in the
    code, e.g. ``halt_baddata``: the bytes did not decode, the C is not trustworthy) and ``error``. A
    function that did not decompile has ``c_code: null`` and the reason in ``error``; the call as a
    whole is ``OK`` when every function decompiled, ``PARTIAL`` when some did, and
    ``ANALYSIS_LIMITED`` when none did.

    `per_function_timeout_seconds` (5..120, default 30) bounds one decompilation inside the decompiler.
    `timeout_seconds` bounds the whole headless run (import, analysis and decompiling); by default it
    is 300 plus the per-function bound for each requested function, and it is clamped to 10..1800.

    Status vocabulary as ``ghidra_program_facts``, plus TOOL_USAGE for a request that is refused before
    anything starts (FUNCTIONS_REQUIRED, TOO_MANY_FUNCTIONS, FUNCTION_SPEC_INVALID).
    """
    tool = "ghidra_decompile"
    requests, bad = _function_requests(functions)
    if bad:
        return _usage(tool, *bad)
    selection, p, refusal = _preflight(tool, path)
    if refusal:
        return refusal
    try:
        per_function = int(per_function_timeout_seconds)
    except (TypeError, ValueError):
        per_function = _DECOMPILE_DEFAULT_PER_FUNCTION_SECONDS
    per_function = max(_DECOMPILE_MIN_PER_FUNCTION_SECONDS, min(per_function, _DECOMPILE_MAX_PER_FUNCTION_SECONDS))
    decompile_budget = per_function * len(requests)
    default_timeout = _clamp_timeout(_DECOMPILE_BASE_TIMEOUT_SECONDS + decompile_budget)
    timeout = default_timeout if timeout_seconds is None else _clamp_timeout(timeout_seconds, default_timeout)
    analysis_timeout = max(5, int(max(timeout - decompile_budget, timeout // 2) * 0.6))
    before, refusal = _hash_source(tool, p)
    if refusal:
        return refusal
    return _j(_scratch_run(tool, lambda work: _decompile_in_work(
        tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token,
        requests, per_function)))


def _normalise_entry(raw, work, target):
    """(entry, problems). Every key of ``_DECOMPILE_ENTRY_SPEC`` is present in the entry. A key the
    script left null stays null; a key of the wrong type is null and listed in problems. An entry
    that claims a completed decompile without code is not completed, and a failure without a reason
    gets one that says the reason is unknown."""
    entry, problems = {}, []
    if not isinstance(raw, dict):
        raw = {}
        problems.append("entry_not_an_object")
    for key, kind in _DECOMPILE_ENTRY_SPEC.items():
        value = raw.get(key)
        if value is None:
            entry[key] = None
        elif (kind is bool and not isinstance(value, bool)) or (kind is not bool and (
                isinstance(value, bool) or not isinstance(value, kind))):
            entry[key] = None
            problems.append(key)
        else:
            entry[key] = value
    entry["warnings"] = [] if entry["warnings"] is None else [str(w) for w in entry["warnings"]]
    if entry["c_code_truncated"] is None:
        entry["c_code_truncated"] = False
    if entry["decompile_completed"] is True and entry["c_code"] is None:
        entry["decompile_completed"] = False
        entry["error"] = entry["error"] or "DECOMPILE_RESULT_MALFORMED: completed without C code"
    if entry["decompile_completed"] is not True:
        entry["decompile_completed"] = False
        entry["c_code"] = None
        entry["error"] = entry["error"] or "DECOMPILE_NOT_COMPLETED: the script gave no reason"
    if entry["error"] is not None:
        entry["error"] = _redact(entry["error"], work=work, target=target)
    return entry, problems


def _decompile_in_work(tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token,
                       requests, per_function):
    """The decompile run, inside an already created scratch directory. Returns the response as a dict."""
    request_text = "".join(f"{kind}\t{value}\n" for kind, value in requests)
    failure, raw, common = _headless_run(
        tool, selection, p, before, timeout, analysis_timeout, work, cancellation_token,
        (_DECOMPILE_SCRIPT_SOURCE, _DECOMPILE_SCRIPT_NAME, _DECOMPILE_RESULT_NAME), ("functions",),
        extra_files={_DECOMPILE_REQUEST_NAME: request_text},
        extra_args=("@work/" + _DECOMPILE_REQUEST_NAME, per_function, _DECOMPILE_MAX_FUNCTIONS))
    if failure:
        return failure
    rows = raw.get("functions")
    if not isinstance(rows, list) or len(rows) != len(requests):
        return _fail(tool, "ANALYSIS_LIMITED", "GHIDRA_RESULT_CONTRACT_VIOLATION", **dict(
            common, detail="The script's result does not carry exactly one entry per requested function; "
                           "nothing is reported."))
    functions, problems = [], {}
    for index, row in enumerate(rows):
        entry, bad = _normalise_entry(row, work, p)
        functions.append(entry)
        if bad:
            problems[str(index)] = bad
    done = sum(1 for e in functions if e["decompile_completed"])
    script_errors = [_redact(str(e), work=work, target=p) for e in (raw.get("errors") or [])]
    summary = {
        "path": relative(p),
        "ghidra_version": selection["version"],
        "resolved_by": selection["resolved_by"],
        "invocation": dict(common["invocation"], per_function_timeout_seconds=per_function),
        "source_sha256": before,
        "source_unchanged": True,
        "requested_count": len(requests),
        "decompiled_count": done,
        "failed_count": len(functions) - done,
        "functions": functions,
        "entries_malformed": problems,
        "script_errors": script_errors,
        "log_error_lines": common["log_error_lines"],
    }
    if done == 0:
        return _fail(tool, "ANALYSIS_LIMITED", "NO_FUNCTION_DECOMPILED", **dict(
            summary, detail="Ghidra ran, but none of the requested functions decompiled; see each entry's error."))
    out_dir = EVIDENCE.parent / "ghidra_decompile"
    out = out_dir / f"{p.stem}_{uuid.uuid4().hex[:8]}_decompile.json"
    evidence_error = None
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"source_sha256": before, "functions": functions}, ensure_ascii=False),
                       encoding="utf-8")
        _evidence_index_record_write(out)
    except OSError as exc:
        evidence_error = type(exc).__name__
    except Exception:  # noqa: BLE001
        pass
    return dict(summary, **{
        "ok": True, "tool": tool, "status": "OK" if done == len(functions) else "PARTIAL",
        "internal_evidence_name": out.name,
        "evidence_write_error": evidence_error,
        "note": (
            "Read-only C from Ghidra's own decompiler after its default analysis. The code is Ghidra's "
            "reading of the bytes, not source: types, names and control flow are inferred and can be "
            "wrong, and a non-empty `warnings` (for example halt_baddata) means Ghidra met bytes it could "
            "not decode, so that function's C is not evidence of what the code does. c_code is returned as "
            "Ghidra produced it, without path redaction, and can contain strings from the target. A "
            "function with decompile_completed false has c_code null and its reason in `error`; it is not "
            "empty code."
        ),
    })
