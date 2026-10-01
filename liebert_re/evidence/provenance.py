"""Provenance assertion for database-backed reverse-engineering engine
wrappers (IDA's ida_query / ida_microcode_cfg, Ghidra's ghidra_query /
ghidra_decompile).

This closes the *second* half of the defect class behind the two worst
incidents on 2026-09-27. The first half -- "the engine failed to analyse the
input, yet a stale artifact was reported as a real result" -- was closed at
the file-freshness level (delete-before-invoke `out.json`; recency-gated
`T_<hash>.*` sibling cleanup). The half that remained open is stronger:

    the engine analysed a DIFFERENT file than the caller asked about and
    returned a confident, genuinely-computed answer describing the wrong
    bytes.

Path alone does not catch it -- a persistent database or cached project can
carry the right *name* while holding the wrong *bytes* (exactly how the
leftover-sibling incidents presented: the correct `T_<hash>.i64` slot opened
in a state belonging to an earlier run). The content-hash cache key names the
slot but never independently re-verifies that the slot's bytes still match
that name; that invariant lives only in wrapper code and today's incidents
proved on-disk state around those slots can diverge from what the wrapper
assumes.

The assertion here is deliberately a POSITIVE signal the engine itself
reports -- IDA's `retrieve_input_file_sha256()`/`get_input_file_path()`,
Ghidra's `getExecutableSHA256()`/`getExecutablePath()` -- compared against the
hash the caller actually asked about. It is a NAMED three-valued status
(mirroring tools_rizin.py's `load_probe.status` and
tools_runtime_api_resolve.py's `NOT_RECOVERABLE` vocabulary), never a bool,
because a provenance mismatch must be a DISTINCT outcome from both "did not
analyse" and a real result:

    PROVENANCE_VERIFIED    -- engine's own recorded input hash == requested
    PROVENANCE_MISMATCH    -- engine's own recorded input hash != requested
                              (the defect; the result must NOT be returned)
    PROVENANCE_UNVERIFIABLE -- the engine exposed no comparable input hash,
                              or the comparison does not apply (e.g. the
                              caller pointed directly at an already-analysed
                              .i64 whose engine-recorded input is the ORIGINAL
                              import, not the database file). An honest label,
                              never a guessed pass.

Degrading to UNVERIFIABLE (never to a false MISMATCH) when the engine reports
nothing means a wrapper can adopt this before the engine-side script emission
has been proven on a real engine, without risk of a false positive.
"""
from __future__ import annotations

PROVENANCE_VERIFIED = "PROVENANCE_VERIFIED"
PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
PROVENANCE_UNVERIFIABLE = "PROVENANCE_UNVERIFIABLE"


def _norm(value):
    """A hash string normalised for comparison, or None when absent/blank.
    Engines report hashes in mixed case and occasionally with stray
    whitespace; comparison must be case-insensitive on the hex value alone."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    return v or None


def assess_provenance(
    requested_sha256=None,
    requested_md5=None,
    engine_sha256=None,
    engine_md5=None,
    engine_input_path=None,
    unverifiable_reason=None,
):
    """Compare what the caller asked about against what the engine reports it
    actually has open. Returns a dict whose ``status`` is one of the three
    module constants; callers store it under ``provenance`` and, on
    PROVENANCE_MISMATCH, refuse to return the result as if it were real.

    ``unverifiable_reason`` short-circuits to PROVENANCE_UNVERIFIABLE -- used
    when the comparison structurally does not apply (an already-analysed
    database target, whose engine-recorded input is the original import rather
    than the file the caller named).

    Hash preference is strongest-first: sha256 when both sides report it, else
    md5 when both report it, else UNVERIFIABLE. A hash present on only one side
    is never treated as agreement.
    """
    if unverifiable_reason:
        return {
            "status": PROVENANCE_UNVERIFIABLE,
            "reason": unverifiable_reason,
            "engine_input_path": engine_input_path,
        }

    req_s, eng_s = _norm(requested_sha256), _norm(engine_sha256)
    req_m, eng_m = _norm(requested_md5), _norm(engine_md5)

    if req_s and eng_s:
        algorithm, requested_value, engine_value = "sha256", req_s, eng_s
    elif req_m and eng_m:
        algorithm, requested_value, engine_value = "md5", req_m, eng_m
    else:
        return {
            "status": PROVENANCE_UNVERIFIABLE,
            "reason": "ENGINE_REPORTED_NO_COMPARABLE_INPUT_HASH",
            "engine_input_path": engine_input_path,
        }

    if requested_value == engine_value:
        return {
            "status": PROVENANCE_VERIFIED,
            "algorithm": algorithm,
            "engine_input_path": engine_input_path,
        }
    return {
        "status": PROVENANCE_MISMATCH,
        "algorithm": algorithm,
        "requested_input_hash": requested_value,
        "engine_input_hash": engine_value,
        "engine_input_path": engine_input_path,
    }
