"""capa (mandiant/capa, Apache-2.0) capability identification: which
behaviours a binary's code actually contains, mapped to MITRE ATT&CK and the
Malware Behavior Catalog.

This answers the question that comes immediately after "what is this
protected with?" (`die.py`): *what does it do*. capa matches FLARE's rule
set against real extracted features -- disassembly, API references, strings,
structure -- and reports each hit with the rule's own namespace, ATT&CK
technique and MBC objective. For a protected ring-3 target the
`anti-analysis` namespace is the first thing to read: anti-debugging,
anti-VM and packer-recognition rules are what distinguish a hardened binary
from an ordinary one.

Deliberately a wrapper, the same discipline as `die.py` and `upx.py`: this
drives capa's own console binary and never reimplements rule matching.
capa only READS the target (no execution of untrusted code), so this is a
HOST-side static tool.

**What a capa hit is and is not.** A match means the rule's feature
combination is *present in the file*. It is not proof the code path runs,
and capa publishes no per-match confidence score, so none is invented here.
Reported matches keep capa's own structure; the rollups below only count and
group what capa already decided.

**This tool is slow, and the wrapper does not hide that.** Measured on this
install (capa 9.4.0, default vivisect backend): a 1.2 MB PE took 3 minutes
48 seconds and produced 1.4 MB of JSON. The default timeout is therefore
minutes, not seconds, and `backend`/`restrict_to_functions` exist so a
caller can trade coverage for time deliberately rather than by accident.

**Measured backend limitation.** `-b pefile` (documented as "file features
only", which would be the fast triage path) raises `NotImplementedError` and
exits non-zero on capa 9.4.0 here. This module does not silently retry with
another backend when a requested one fails: it reports ANALYSIS_LIMITED and
names the backend, because a result from a different engine than the one
asked for is a different claim.

`-b ida` runs capa against IDA through idalib. That is safe from this side:
capa is already an isolated, bounded subprocess here, so an analysis kernel
crash takes capa down and not the caller. It needs a licensed IDA on the
machine and is slower still.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from liebert_re.bounded_subprocess import launch_failure, run_bounded_process
from liebert_re.workspace import safe_path, relative

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP_DIR
EVIDENCE = APP_DIR / "dataset" / "evidence" / "capa_analyze"
EVIDENCE.mkdir(parents=True, exist_ok=True)

# Measured: 3m48s for a 1.2 MB PE on the default backend. A ceiling below
# that would make this tool report TIMEOUT on ordinary inputs.
_DEFAULT_TIMEOUT_SECONDS = 600
_MIN_TIMEOUT_SECONDS = 30
_MAX_TIMEOUT_SECONDS = 3600
# Measured: 1.4 MB of JSON for 39 matched rules on a 1.2 MB PE. A target with
# more matched rules scales past that, so this is bounded an order of
# magnitude above the measurement rather than at it.
_MAX_OUTPUT_CHARS = 64 * 1024 * 1024

_KNOWN_INSTALL = Path("C:/Tools/capa/capa.exe")

# capa's own accepted values, from `capa --help` on 9.4.0. Validated here so
# a typo fails as an argument error rather than as capa's own usage dump.
_BACKENDS = {"auto", "vivisect", "ida", "pefile", "binja", "dotnet",
             "binexport2", "ghidra", "freeze", "cape", "drakvuf", "vmray"}
_FORMATS = {"auto", "pe", "dotnet", "elf", "sc32", "sc64", "cape", "drakvuf",
            "vmray", "freeze", "binexport2", "binja_database"}
_OS_NAMES = {"auto", "linux", "macos", "windows"}

# The namespace root that answers "is this target hardened against being
# analysed", which is the reason this tool runs first on a protected binary.
_ANTI_ANALYSIS_ROOT = "anti-analysis"


def _capa_binary():
    explicit = os.getenv("CAPA_EXE", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        candidate = p / "capa.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("capa") or shutil.which("capa.exe")
    if found:
        return found
    if _KNOWN_INSTALL.exists():
        return str(_KNOWN_INSTALL)
    return None


def capa_available():
    return _capa_binary() is not None


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _tool_missing(tool):
    return _j({
        "ok": False, "tool": tool, "status": "TOOL_MISSING",
        "required_capability": "capa (mandiant/capa) console build",
        "detail": (
            "capa.exe was not found. Set the CAPA_EXE environment variable to "
            "its full path or install directory, or put it on PATH. The "
            r"known-install fallback this module checks is C:\Tools\capa\capa.exe."
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


def _choice(value, allowed, field, tool):
    """Validate one capa enum argument. Returns (value_or_None, fail_or_None)."""
    if value is None or value == "":
        return None, None
    v = str(value).strip()
    if v not in allowed:
        return None, _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "error": f"UNKNOWN_{field.upper()}",
            "given": v, "accepted": sorted(allowed),
            "detail": f"capa does not accept this {field}; capa_status() lists what this build takes.",
        })
    return v, None


def _rollup(rules):
    """Group capa's matched rules the three ways a report needs them:
    by namespace, by ATT&CK technique, by MBC behavior. Every value is
    capa's own -- nothing is reclassified or scored here."""
    by_namespace = {}
    attack = {}
    mbc = {}
    capabilities = []
    for name, rule in sorted(rules.items()):
        meta = rule.get("meta", {}) if isinstance(rule, dict) else {}
        namespace = meta.get("namespace") or None
        entry = {
            "name": name,
            "namespace": namespace,
            "scopes": meta.get("scopes"),
            "description": meta.get("description") or None,
            "is_library_rule": bool(meta.get("lib")),
            "match_count": len(rule.get("matches") or []) if isinstance(rule, dict) else 0,
            "attack": meta.get("attack") or [],
            "mbc": meta.get("mbc") or [],
        }
        capabilities.append(entry)
        by_namespace.setdefault(namespace or "(none)", []).append(name)
        for a in entry["attack"]:
            if isinstance(a, dict) and a.get("id"):
                attack.setdefault(a["id"], {
                    "id": a["id"], "tactic": a.get("tactic"),
                    "technique": a.get("technique"), "subtechnique": a.get("subtechnique") or None,
                    "rules": [],
                })["rules"].append(name)
        for b in entry["mbc"] or []:
            if isinstance(b, dict) and b.get("id"):
                mbc.setdefault(b["id"], {
                    "id": b["id"], "objective": b.get("objective"),
                    "behavior": b.get("behavior"), "method": b.get("method") or None,
                    "rules": [],
                })["rules"].append(name)
    anti_analysis = sorted(
        c["name"] for c in capabilities
        if (c["namespace"] or "").split("/")[0] == _ANTI_ANALYSIS_ROOT
    )
    return {
        "capability_count": len(capabilities),
        "capabilities": capabilities,
        "by_namespace": {k: sorted(v) for k, v in sorted(by_namespace.items())},
        "namespace_roots": sorted({(c["namespace"] or "(none)").split("/")[0] for c in capabilities}),
        "attack_techniques": [attack[k] for k in sorted(attack)],
        "mbc_behaviors": [mbc[k] for k in sorted(mbc)],
        "anti_analysis_capabilities": anti_analysis,
        "anti_analysis_present": bool(anti_analysis),
    }


def capa_analyze(path, backend=None, file_format=None, os_name=None, rules=None,
                 signatures=None, tag=None, restrict_to_functions=None,
                 timeout_seconds=_DEFAULT_TIMEOUT_SECONDS, cancellation_token=None):
    """Identify the capabilities capa's rule set recognizes in `path`, via the
    real `capa -j -q`.

    Arguments map straight to capa's own switches, and whatever was passed
    comes back in `invocation` -- a capability list is a claim about a rule
    set and an extractor, so it is not interpretable without them:

    * `backend` (`-b`)   `auto` (default, vivisect for a PE), `ida` (idalib,
                         needs a licensed IDA), `dotnet`, `ghidra`, `binja`,
                         ... `pefile` is accepted by capa's argument parser
                         but **crashes on capa 9.4.0 here** -- see the module
                         docstring; this tool reports that rather than
                         quietly using another engine.
    * `file_format` (`-f`), `os_name` (`--os`)
    * `rules` (`-r`)     a rule file or directory, instead of the embedded set
    * `signatures` (`-s`) .sig/.pat library-function signatures
    * `tag` (`-t`)       filter on a rule meta field value
    * `restrict_to_functions` a comma-separated list of function virtual
                         addresses -- the way to bound a run on a large
                         target instead of raising the timeout

    Status vocabulary matches the repo's other static-tool wrappers: OK,
    TOOL_MISSING, PATH_REFUSED, NOT_FOUND, TIMEOUT, CANCELLED,
    ANALYSIS_LIMITED (capa ran and failed, or an argument it would reject),
    RESULT_PARSE_FAILED (capa's own JSON did not parse -- a version-drift
    signal, not this tool's bug).

    `status: "OK"` with `capability_count: 0` is a real negative result: capa
    looked and matched nothing. On a packed target that is expected and is
    itself a finding -- there is no unpacked code for the rules to see yet.
    """
    tool = "capa_analyze"
    exe = _capa_binary()
    if not exe:
        return _tool_missing(tool)

    p, fail = _checked_path(path, tool)
    if fail:
        return fail

    backend, fail = _choice(backend, _BACKENDS, "backend", tool)
    if fail:
        return fail
    file_format, fail = _choice(file_format, _FORMATS, "format", tool)
    if fail:
        return fail
    os_name, fail = _choice(os_name, _OS_NAMES, "os", tool)
    if fail:
        return fail

    argv = ["-j", "-q"]
    invocation = {}
    for value, flag, key in (
        (backend, "-b", "backend"),
        (file_format, "-f", "format"),
        (os_name, "--os", "os"),
        (rules, "-r", "rules"),
        (signatures, "-s", "signatures"),
        (tag, "-t", "tag"),
        (restrict_to_functions, "--restrict-to-functions", "restrict_to_functions"),
    ):
        if value:
            argv.extend([flag, str(value)])
            invocation[key] = str(value)
    argv.append(str(p))

    timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
    cp = run_bounded_process(
        [exe, *argv],
        timeout_seconds=timeout_seconds,
        cancellation_token=cancellation_token,
        max_output_chars=_MAX_OUTPUT_CHARS,
    )
    if cp.launch_failed is True:
        return _j(launch_failure(cp, tool, "CAPA_LAUNCH_FAILED"))
    if cp.cancelled:
        return _j({
            "ok": False, "tool": tool, "status": "CANCELLED",
            "error": "CAPA_CANCELLED_PROCESS_TREE_TERMINATED", "invocation": invocation,
        })
    if cp.timed_out:
        return _j({
            "ok": False, "tool": tool, "status": "TIMEOUT",
            "timeout_seconds": timeout_seconds, "invocation": invocation,
            "error": "CAPA_TIMEOUT_PROCESS_TREE_TERMINATED",
            "detail": (
                "capa's default backend takes minutes on a megabyte-scale PE (measured: 3m48s for "
                "1.2 MB). Either raise timeout_seconds or bound the work with restrict_to_functions; "
                "do not read a timeout as 'no capabilities'."
            ),
        })
    if cp.returncode not in (0, None):
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "exit_code": cp.returncode, "invocation": invocation,
            "error": "CAPA_EXITED_NONZERO",
            "stderr_tail": (cp.stderr or "")[-2000:],
            "stdout_tail": (cp.stdout or "")[-2000:],
            "detail": (
                "capa ran and failed. This is reported rather than retried with a different engine: "
                "a result from another backend is a different claim. Known on capa 9.4.0: backend "
                "'pefile' raises NotImplementedError and exits non-zero."
            ),
        })

    stdout = cp.stdout or ""
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end < start:
        return _j({
            "ok": False, "tool": tool, "status": "ANALYSIS_LIMITED",
            "error": "CAPA_NO_JSON_OUTPUT", "invocation": invocation,
            "output_truncated": cp.output_truncated,
            "stdout_tail": stdout[-2000:], "stderr_tail": (cp.stderr or "")[-2000:],
        })
    try:
        raw = json.loads(stdout[start:end + 1])
    except Exception as exc:  # noqa: BLE001
        return _j({
            "ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
            "error": f"{type(exc).__name__}: {exc}", "invocation": invocation,
            "output_truncated": cp.output_truncated,
        })
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), dict):
        return _j({
            "ok": False, "tool": tool, "status": "RESULT_PARSE_FAILED",
            "error": "CAPA_OUTPUT_MISSING_RULES_OBJECT", "invocation": invocation,
        })

    meta = raw.get("meta", {}) if isinstance(raw.get("meta"), dict) else {}
    analysis = meta.get("analysis", {}) if isinstance(meta.get("analysis"), dict) else {}
    sample = meta.get("sample", {}) if isinstance(meta.get("sample"), dict) else {}

    out = EVIDENCE / f"{p.stem}_{uuid.uuid4().hex[:8]}_capa.json"
    evidence_error = None
    try:
        out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        _evidence_index_record_write(out)
    except OSError as exc:
        evidence_error = f"{type(exc).__name__}: {exc}"
    except Exception:
        pass

    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "path": relative(p),
        "invocation": invocation,
        "capa_version": meta.get("version"),
        "flavor": meta.get("flavor"),
        "sample_sha256": sample.get("sha256"),
        "sample_md5": sample.get("md5"),
        "analysis": {
            "format": analysis.get("format"),
            "arch": analysis.get("arch"),
            "os": analysis.get("os"),
            "extractor": analysis.get("extractor"),
            "base_address": analysis.get("base_address"),
            "rule_set_size": analysis.get("rules"),
            "feature_counts": analysis.get("feature_counts"),
            "library_function_count": len(analysis.get("library_functions") or []),
        },
        **_rollup(raw["rules"]),
        "internal_evidence_name": out.name,
        "evidence_write_error": evidence_error,
        "evidence_access": "Full unmodified capa -j JSON saved; this response is the structured rollup of it, including every matched rule name.",
        "note": (
            "A capa match means the rule's feature combination is PRESENT in the file -- not that the "
            "code path executes, and not with any confidence score (capa publishes none, so none is "
            "invented). capability_count 0 is a real negative; on a packed target it is expected, "
            "because there is no unpacked code for the rules to see. analysis.library_function_count "
            "is how much code capa attributed to known library functions via signatures: a very low "
            "count on a large binary means the signatures did not apply, so the capability list "
            "covers less of the file than it appears to."
        ),
    })


def capa_status():
    """Whether capa is reachable, where from, which version, and what this
    build accepts -- the capability probe to run before reporting capa as
    unavailable or a backend as usable."""
    tool = "capa_status"
    exe = _capa_binary()
    if not exe:
        return _tool_missing(tool)
    cp = run_bounded_process([exe, "--version"], timeout_seconds=_MIN_TIMEOUT_SECONDS,
                             max_output_chars=4096)
    if cp.launch_failed is True:
        return _j(launch_failure(cp, tool, "CAPA_LAUNCH_FAILED"))
    if cp.timed_out:
        return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "error": "CAPA_VERSION_TIMEOUT"})
    version = ((cp.stdout or "") + (cp.stderr or "")).strip().splitlines()
    return _j({
        "ok": True, "tool": tool, "status": "OK",
        "binary": exe,
        "version": version[0] if version else None,
        "resolved_by": ("CAPA_EXE" if os.getenv("CAPA_EXE", "").strip()
                        else ("PATH" if shutil.which("capa") or shutil.which("capa.exe") else "known_install")),
        "backends_capa_accepts": sorted(_BACKENDS),
        "formats_capa_accepts": sorted(_FORMATS),
        "known_broken_backends": {
            "pefile": "raises NotImplementedError and exits non-zero on capa 9.4.0 (measured on this install)",
        },
        "operations": ["capa_analyze", "capa_status"],
        "note": (
            "backends_capa_accepts is what capa's argument parser takes, NOT what works here: 'ida' "
            "additionally needs a licensed IDA on the machine, and the backends listed in "
            "known_broken_backends fail on this version. Expect minutes, not seconds, from "
            "capa_analyze on the default backend."
        ),
    })
