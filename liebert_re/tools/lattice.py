"""Bounded, model-callable wrapper around lll_exact.py's generic exact-
arithmetic lattice-reduction primitives.

lll_exact.py was originally built to solve WNL-T2-082's Merkle-Hellman
knapsack cryptanalysis, but the primitives themselves (lll_reduce,
enumerate_short_vectors, is_lll_reduced) were always generic: arbitrary
integer basis in, no benchmark-specific data anywhere in the module. This
promotes them from "a script one benchmark's solve happened to use" into a
reusable, registered, structured-I/O capability -- the harness's own
generic cryptographic/mathematical tooling, not tied to any one fixture,
provider, or model. Any lattice-reduction/short-vector-enumeration problem
(subset-sum/knapsack cryptanalysis, NTRU-style attacks, coefficient-
recovery problems reducible to SVP/CVP) can reach it the same way.
"""
from __future__ import annotations

import json
import time
from fractions import Fraction

from liebert_re.recover.lll_exact import (
    _HAVE_MPMATH,
    EnumerationBudgetExceeded,
    LLLError,
    enumerate_short_vectors,
    is_lll_reduced,
    lll_reduce,
)

OPERATIONS = ("reduce", "reduce_and_enumerate", "is_reduced")
# Real, checked resource bounds -- this runs in-process (pure Python/mpmath,
# no external tool to subprocess-isolate), so the bound has to be algorithmic
# rather than a wall-clock kill: dimension and per-entry bit-length caps
# bound the O(n^2) Gram-Schmidt cost and prevent a pathological input from
# blowing up working-set memory; lll_reduce's own max_iterations and
# enumerate_short_vectors' own max_nodes already bound the reduction and
# enumeration loops respectively (an honest EnumerationBudgetExceeded, never
# a silent partial result presented as complete).
MAX_DIMENSION = 200
MAX_BASIS_ENTRY_BITS = 8_192


def _validate_basis(basis) -> None:
    if not isinstance(basis, list) or not basis:
        raise ValueError("basis must be a non-empty list of rows")
    if len(basis) > MAX_DIMENSION:
        raise ValueError(f"basis dimension {len(basis)} exceeds MAX_DIMENSION={MAX_DIMENSION}")
    dim = None
    for row in basis:
        if not isinstance(row, list) or not row:
            raise ValueError("each basis row must be a non-empty list of integers")
        if dim is None:
            dim = len(row)
        elif len(row) != dim:
            raise ValueError("inconsistent row dimensions")
        for entry in row:
            if not isinstance(entry, int) or isinstance(entry, bool):
                raise ValueError("basis entries must be integers")
            if entry.bit_length() > MAX_BASIS_ENTRY_BITS:
                raise ValueError(f"a basis entry exceeds MAX_BASIS_ENTRY_BITS={MAX_BASIS_ENTRY_BITS}")


def lattice_reduce(
    basis,
    operation: str = "reduce",
    delta: float = 0.75,
    max_norm_sq=None,
    max_nodes: int = 5_000_000,
    max_results: int = 200,
    dps: int = 200,
):
    """LLL-reduce an arbitrary integer lattice basis, optionally followed by
    bounded Fincke-Pohst/Kannan short-vector enumeration over the reduced
    basis.

    ``basis``: list of rows (each a list of Python ints), the lattice basis
    to reduce -- e.g. a subset-sum/knapsack weight system augmented with a
    target, or any other integer lattice.
    ``operation``: "reduce" (LLL only), "reduce_and_enumerate" (LLL then
    enumerate all vectors with squared norm <= max_norm_sq, which is then
    required), or "is_reduced" (checks an already-reduced basis without
    modifying it).
    Returns structured JSON; never raises to the caller -- LLLError and
    EnumerationBudgetExceeded are both reported as an honest, typed failure
    rather than propagating as a Python exception or a silent partial answer.
    """
    started = time.monotonic()
    try:
        if operation not in OPERATIONS:
            return json.dumps({"ok": False, "tool": "lattice_reduce", "error": "UNKNOWN_OPERATION", "allowed": list(OPERATIONS)}, indent=2)
        _validate_basis(basis)
    except ValueError as exc:
        return json.dumps({"ok": False, "tool": "lattice_reduce", "error": "INVALID_BASIS", "detail": str(exc)}, ensure_ascii=False, indent=2)

    # Fail closed on the optional high-precision backend. mpmath drives the
    # reduction/enumeration Gram-Schmidt; without it those operations cannot
    # run, so report a structured TOOL_MISSING (matching this tool's declared
    # fallback=['tool_missing']) rather than crashing. "is_reduced" uses only
    # exact Fraction arithmetic and stays available.
    if operation in ("reduce", "reduce_and_enumerate") and not _HAVE_MPMATH:
        return json.dumps({
            "ok": False, "tool": "lattice_reduce", "status": "TOOL_MISSING",
            "error": "MPMATH_UNAVAILABLE", "missing_dependency": "mpmath",
            "operation": operation,
            "detail": (
                "operation '%s' needs high-precision arithmetic from the optional "
                "'mpmath' package, which is not installed (pip install mpmath). "
                "The 'is_reduced' operation works without it." % operation
            ),
        }, ensure_ascii=False, indent=2)

    try:
        if operation == "is_reduced":
            reduced_ok = is_lll_reduced(basis, delta=Fraction(delta).limit_denominator(10**6))
            return json.dumps({
                "ok": True, "tool": "lattice_reduce", "operation": operation,
                "is_reduced": reduced_ok, "dimension": len(basis),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }, indent=2)

        reduced = lll_reduce(basis, delta=delta, dps=dps)
        payload = {
            "ok": True, "tool": "lattice_reduce", "operation": operation,
            "reduced_basis": reduced, "dimension": len(basis),
        }
        if operation == "reduce_and_enumerate":
            if max_norm_sq is None:
                return json.dumps({"ok": False, "tool": "lattice_reduce", "error": "MAX_NORM_SQ_REQUIRED_FOR_ENUMERATE"}, indent=2)
            try:
                vectors, nodes = enumerate_short_vectors(reduced, int(max_norm_sq), dps=dps, max_nodes=max_nodes, max_results=max_results)
                payload.update(short_vectors=vectors, nodes_visited=nodes, enumeration_status="COMPLETE")
            except EnumerationBudgetExceeded as exc:
                payload.update(short_vectors=[], nodes_visited=max_nodes, enumeration_status="BUDGET_EXCEEDED", enumeration_note=str(exc))
        payload["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    except LLLError as exc:
        return json.dumps({
            "ok": False, "tool": "lattice_reduce", "error": "LLL_ERROR", "detail": str(exc),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }, ensure_ascii=False, indent=2)
