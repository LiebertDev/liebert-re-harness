"""VirusTotal YARA-X (github.com/VirusTotal/yara-x, Apache-2.0/BSD dual,
official Rust reimplementation of YARA) pattern-scan wrapper -- closes the
other half of this turn's "installed tool is not yet a capability" gap
(capa_analyze/floss_analyze in tools_capability_extract.py (upstream-only; not part of the published package) already answer
"what does this binary DO"; this answers "does this specific byte/string
pattern or published signature EXIST in this binary", the question a real
engagement asks when it already has a rule -- a vendor's public detection
rule, a community YARA-Forge pack, a hand-written IOC for one sample family
-- and needs to know whether THIS target matches it).

Matches this repo's other external console-tool wrappers (tools_die.py /
tools_capability_extract.py's capa_analyze (upstream-only; not part of the published package): TOOL_MISSING (never a raised
exception) when the yr.exe binary is absent, run_bounded_process for the
subprocess with an explicit timeout, structured JSON evidence with the full
unmodified tool output always saved to disk first, and no fabricated
confidence score -- a YARA-X match is a deterministic rule-condition
evaluation, not a probabilistic classifier, so every match is reported
as-is (rule name + matched strings/offsets), never re-scored.

Rule source is deliberately parametric (rules_path, rules_text, or ruleset),
never embedded in this module: the operator's standing rule is that a
signature engine is never reimplemented and its rule set is never
hard-coded into the wrapper -- callers bring their own .yar/.yara file, a
directory of them, inline rule text (written to a throwaway temp file for
exactly one scan, never persisted into the repo), or select a locally
PROVISIONED public rule pack by name (`ruleset`, e.g. `"yara_forge_core"`)
so a caller never has to spell out a full filesystem path to reach a rule
set this repo already acquired via tool_provision_acquire (see
`config/dependencies.manifest.json`'s `YARA-Forge Core` entry (upstream-only; not part of the published package) and
`_KNOWN_RULESETS` below). The ruleset registry only ever names a LOCAL path
already verified+published by tool_provisioning.py's (upstream-only; not part of the published package) digest-checked
acquisition path -- this module still never downloads, reimplements, or
embeds rule text itself.

yr.exe's own behavior this wrapper works around:
  - `scan -o json` writes ONLY the JSON result document to stdout; every
    compiler warning/error and the "can't open <file>" message for a
    missing/unreadable target go to stderr and are never valid JSON --
    verified directly against the installed v1.20.0 binary (see this
    module's docstring history / the worker report that added it), not
    assumed from --help text.
  - yr.exe exits 0 with `{"matches": []}` even when the TARGET file does not
    exist (it treats scan as "found nothing", not an error) -- this module
    does its own existence check on the target before ever invoking yr.exe,
    so RULE_TARGET_NOT_FOUND is reported instead of a false-negative OK.
  - yr.exe exits 1 with EMPTY stdout when the RULE source fails to compile
    (syntax error) -- this module treats returncode!=0 as RULE_COMPILE_FAILED
    when no rules_path/rules_text ambiguity is possible, distinct from the
    TARGET_NOT_FOUND case above.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from bounded_subprocess import run_bounded_process
from tools_workspace import safe_path, relative

try:
    from evidence_index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

APP_DIR = Path(__file__).resolve().parent
EVIDENCE = APP_DIR / "dataset" / "evidence" / "yara_x_scan"
EVIDENCE.mkdir(parents=True, exist_ok=True)

_KNOWN_INSTALL = Path(r"C:\Tools\yara-x\yr.exe")
_DEFAULT_TIMEOUT_SECONDS = 60
_MIN_TIMEOUT_SECONDS = 5
_MAX_TIMEOUT_SECONDS = 300
# Same reasoning as capa_analyze/floss_analyze in tools_capability_extract.py (upstream-only; not part of the published package):
# a large ruleset (e.g. a full YARA-Forge pack) against one binary can emit a
# match list well past run_bounded_process's 128 KiB default capture cap, and
# truncating mid-JSON breaks parsing entirely -- bounded generously, not left
# unbounded.
_MAX_OUTPUT_CHARS = 16 * 1024 * 1024
# Bounded excerpt shown inline; the FULL normalized match list is always
# written to EVIDENCE first (never lost), same content_offset paging
# contract ghidra_decompile/decompile_dotnet use (tools_decompiler.py (upstream-only; not part of the published package)).
_DEFAULT_INLINE_CHARS = 8000
_MAX_INLINE_CHARS = 120000


def _yara_x_binary():
    explicit = os.getenv("YARA_X_EXE", "").strip()
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        candidate = p / "yr.exe"
        if candidate.exists():
            return str(candidate)
    home = os.getenv("YARA_X_HOME", "").strip()
    if home:
        candidate = Path(home) / "yr.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("yr") or shutil.which("yr.exe")
    if found:
        return found
    if _KNOWN_INSTALL.exists():
        return str(_KNOWN_INSTALL)
    return None


# Locally-provisioned public rule packs, selectable by name via yara_x_scan's
# `ruleset` parameter instead of a caller having to spell out a filesystem
# path. Every entry here is acquired through this repo's OWN existing
# manifest-driven acquisition path (tool_provisioning.acquire_from_manifest_
# entry, and config/dependencies.manifest.json's `detected_but_not_
# required_adapters` array -- both upstream-only, not part of the published
# package), never downloaded or embedded by this module
# itself -- this dict only records WHERE an already-verified+published rule
# file is expected to live, same resolution shape as _yara_x_binary above
# (an explicit env var override first, then a known default install path
# under C:\Tools, never a silent network fetch).
#
# "yara_forge_core": YARA-Forge (github.com/YARAHQ/yara-forge) is a curated,
# deduplicated, actively-maintained aggregation of public community YARA
# rules (Yara-Rules/rules, Neo23x0/signature-base, ReversingLabs, CAPE,
# Elastic, and others) built specifically for production scanning -- its
# "core" package is the highest-confidence/lowest-false-positive tier
# (quality-filtered by YARA-Forge's own build process), chosen here over
# "extended"/"full" precisely because a false positive on a client's real
# binary is a worse failure for this product than a missed detection (see
# config/dependencies.manifest.json's `YARA-Forge Core` entry (upstream-only;
# not part of the published package) for the pinned release tag/digest). It includes real packer/protector/obfuscator
# detection rules directly on point for this repo's own job -- e.g.
# COD3NYM_SUSP_OBF_NET_Confuserex_Packer_Jan24 and CAPE_Themida -- not a
# generic malware-family pack repurposed for this.
_KNOWN_RULESETS_HOME = Path(r"C:\Tools\yara-rulesets")
_RULESETS = {
    "yara_forge_core": "yara-forge-core/yara-rules-core.yar",
}


def _rulesets_home():
    explicit = os.getenv("YARA_RULESETS_HOME", "").strip()
    return Path(explicit) if explicit else _KNOWN_RULESETS_HOME


def _resolve_ruleset(name):
    """Returns the resolved Path for a known, currently-installed ruleset
    name, or None (a caller-facing distinction between "not a name this
    module knows about" and "known but not provisioned on this machine" is
    made by yara_x_scan itself, not swallowed here)."""
    rel = _RULESETS.get(name)
    if not rel:
        return None
    p = _rulesets_home() / rel
    return p if p.is_file() else None


def known_rulesets():
    """Read-only listing (name -> resolved path + installed bool) -- no
    subprocess, no network, same shape as yara_x_available(); used by this
    module's own error messages and by tests, never hard-codes install
    state."""
    out = {}
    for name, rel in _RULESETS.items():
        p = _rulesets_home() / rel
        out[name] = {"path": str(p), "installed": p.is_file()}
    return out


def yara_x_available():
    return _yara_x_binary() is not None


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _normalize(raw):
    """Reduce yr's `{"version": ..., "matches": [...]}` into a bounded,
    model-usable finding list -- never flattened past rule/namespace/
    meta/tags/matched-strings, since those are exactly what a caller needs
    to decide whether a match is a real hit or a coincidental byte pattern.
    """
    matches = raw.get("matches", []) if isinstance(raw, dict) else []
    findings = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        strings = [
            {"identifier": s.get("identifier"), "offset": s.get("offset"), "match": s.get("match")}
            for s in (m.get("strings") or []) if isinstance(s, dict)
        ]
        findings.append({
            "rule": m.get("rule"),
            "namespace": m.get("namespace"),
            "meta": m.get("meta") or {},
            "tags": m.get("tags") or [],
            "matched_strings": strings,
        })
    return {
        "yara_x_version": raw.get("version") if isinstance(raw, dict) else None,
        "match_count": len(findings),
        "matched": bool(findings),
        "findings": findings,
    }


def yara_x_scan(
    path,
    rules_path="",
    rules_text="",
    ruleset="",
    timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
    max_chars=_DEFAULT_INLINE_CHARS,
    content_offset=0,
    cancellation_token=None,
):
    """Scan `path` against a YARA-X rule source (compiled with the real
    yr.exe, never a reimplemented matcher) and report every rule match with
    its matched strings/offsets.

    Exactly one of `rules_path` (a .yar/.yara file or a directory of them,
    workspace-scoped like `path`), `rules_text` (inline rule source, written
    to a throwaway temp file for this one scan and never persisted), or
    `ruleset` (the NAME of a locally-provisioned public rule pack, e.g.
    `"yara_forge_core"` -- see `known_rulesets()`/`_RULESETS` for the full
    registry; resolved from a fixed install location, never a caller-
    supplied path, so it is never subject to the workspace path-scoping
    `rules_path` needs) must be given. Precedence when more than one is
    given: rules_text, then rules_path, then ruleset -- same
    caller-forgiveness as the pre-existing rules_text/rules_path pair, never
    an error for redundant input. Status vocabulary matches this repo's
    other static-tool wrappers: OK, TOOL_MISSING, PATH_REFUSED, NOT_FOUND
    (target), RULES_MISSING (no rule source given, an unknown `ruleset`
    name, or a known `ruleset` name that is not currently provisioned on
    this machine -- see `error` for which), RULE_COMPILE_FAILED (yr's own
    compiler rejected the rule source -- see its stderr_tail),
    TIMEOUT, CANCELLED, ANALYSIS_LIMITED, RESULT_PARSE_FAILED.

    `status: "OK"` with `matched: false` is a real NEGATIVE result (yr
    compiled the rules and scanned the target but nothing matched), not an
    error.

    The response's `content` field is a bounded, content_offset-pageable
    excerpt of the full normalized findings (same contract as
    ghidra_decompile/decompile_dotnet in tools_decompiler.py (upstream-only; not part of the published package)); the complete
    unmodified yr JSON is always saved to EVIDENCE first regardless of this
    bound, retrievable via `internal_evidence_name`.
    """
    exe = _yara_x_binary()
    if not exe:
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "TOOL_MISSING",
            "required_capability": "YARA-X console build (yr.exe)",
            "expected_path": str(_KNOWN_INSTALL),
        })

    try:
        p = safe_path(path)
    except PermissionError as exc:
        return _j({"ok": False, "tool": "yara_x_scan", "status": "PATH_REFUSED", "error": str(exc)})
    if not p.is_file():
        return _j({"ok": False, "tool": "yara_x_scan", "status": "NOT_FOUND", "path": str(path)})

    rules_text = (rules_text or "").strip()
    rules_path = (rules_path or "").strip()
    ruleset = (ruleset or "").strip()
    if not rules_path and not rules_text and not ruleset:
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "RULES_MISSING",
            "error": (
                "Provide rules_path (a .yar/.yara file or directory), rules_text "
                "(inline rule source), or ruleset (the name of a provisioned rule "
                f"pack -- known names: {sorted(_RULESETS)})."
            ),
        })

    tmp_dir = None
    try:
        if rules_text:
            tmp_dir = tempfile.TemporaryDirectory(prefix="teacher_yarax_rule_")
            rule_file = Path(tmp_dir.name) / "inline_rules.yar"
            rule_file.write_text(rules_text, encoding="utf-8")
            rules_arg = str(rule_file)
            rules_source_label = "inline_rules_text"
        elif rules_path:
            try:
                rules_arg_path = safe_path(rules_path)
            except PermissionError as exc:
                return _j({"ok": False, "tool": "yara_x_scan", "status": "PATH_REFUSED", "error": str(exc)})
            if not rules_arg_path.exists():
                return _j({
                    "ok": False, "tool": "yara_x_scan", "status": "RULES_MISSING",
                    "error": f"rules_path does not exist: {rules_path}",
                })
            rules_arg = str(rules_arg_path)
            rules_source_label = relative(rules_arg_path)
        else:
            if ruleset not in _RULESETS:
                return _j({
                    "ok": False, "tool": "yara_x_scan", "status": "RULES_MISSING",
                    "error": f"unknown ruleset name {ruleset!r} -- known names: {sorted(_RULESETS)}",
                })
            resolved = _resolve_ruleset(ruleset)
            if resolved is None:
                return _j({
                    "ok": False, "tool": "yara_x_scan", "status": "RULES_MISSING",
                    "error": (
                        f"ruleset {ruleset!r} is a known name but is not provisioned on this "
                        f"machine (expected at {_rulesets_home() / _RULESETS[ruleset]}) -- "
                        "acquire it via tool_provision_acquire against its "
                        "config/dependencies.manifest.json entry first (upstream-only; not runnable from this published package)."
                    ),
                })
            rules_arg = str(resolved)
            rules_source_label = f"ruleset:{ruleset}"

        timeout_seconds = max(_MIN_TIMEOUT_SECONDS, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
        max_chars = max(1000, min(int(max_chars), _MAX_INLINE_CHARS))
        offset = max(0, int(content_offset or 0))

        cp = run_bounded_process(
            [exe, "scan", "-o", "json", "-m", "-g", "-e", "-s", "--disable-console-logs", rules_arg, str(p)],
            timeout_seconds=timeout_seconds,
            cancellation_token=cancellation_token,
            max_output_chars=_MAX_OUTPUT_CHARS,
        )
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()

    if cp.cancelled:
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "CANCELLED",
            "error": "YARA_X_CANCELLED_PROCESS_TREE_TERMINATED",
        })
    if cp.timed_out:
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "TIMEOUT",
            "timeout_seconds": timeout_seconds,
            "error": "YARA_X_TIMEOUT_PROCESS_TREE_TERMINATED",
        })
    if cp.output_truncated:
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "ANALYSIS_LIMITED",
            "error": "YARA_X_OUTPUT_EXCEEDED_BOUND",
        })
    if cp.returncode not in (0, None):
        # yr.exe exits non-zero with EMPTY stdout specifically when the RULE
        # source fails to compile (verified directly, see module docstring);
        # a target-side failure (missing/unreadable file) still exits 0 with
        # an empty match list, which this module already refuses upstream
        # via its own p.is_file() check -- so a non-zero exit here is always
        # a rule-compile failure, not a target problem.
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "RULE_COMPILE_FAILED",
            "rules_source": rules_source_label,
            "exit_code": cp.returncode,
            "stderr_tail": (cp.stderr or "")[-4000:],
        })

    stdout = cp.stdout or ""
    try:
        raw = json.loads(stdout)
    except Exception as exc:  # noqa: BLE001
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "RESULT_PARSE_FAILED",
            "error": f"{type(exc).__name__}: {exc}",
            "stdout_tail": stdout[-2000:],
            "stderr_tail": (cp.stderr or "")[-2000:],
        })
    if not isinstance(raw, dict):
        return _j({
            "ok": False, "tool": "yara_x_scan", "status": "RESULT_PARSE_FAILED",
            "error": "YARA_X_OUTPUT_NOT_AN_OBJECT",
        })

    raw_out = EVIDENCE / f"{p.stem}_{uuid.uuid4().hex[:8]}_yarax.json"
    raw_out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    try:
        _evidence_index_record_write(raw_out)
    except Exception:
        pass

    normalized = _normalize(raw)
    full_content = json.dumps(normalized["findings"], ensure_ascii=False, indent=2)
    total = len(full_content)
    offset = min(offset, total)
    chunk = full_content[offset:offset + max_chars]
    has_more = (offset + len(chunk)) < total

    return _j({
        "ok": True, "tool": "yara_x_scan", "status": "OK",
        "path": relative(p),
        "rules_source": rules_source_label,
        "yara_x_version": normalized["yara_x_version"],
        "match_count": normalized["match_count"],
        "matched": normalized["matched"],
        "content": chunk,
        "content_offset": offset,
        "content_returned_chars": len(chunk),
        "content_total_chars": total,
        "content_has_more": has_more,
        "truncated": has_more,
        "internal_evidence_name": raw_out.name,
        "evidence_access": "Full unmodified `yr scan -o json` output saved; `content` is a bounded, content_offset-pageable JSON excerpt of the normalized findings list.",
        "note": "YARA-X is a deterministic rule-condition matcher, not a probabilistic classifier: every finding here is a real compiled-rule match yr.exe itself evaluated, never a fabricated confidence score.",
    })
