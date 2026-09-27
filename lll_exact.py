"""From-scratch LLL lattice basis reduction, high-precision (mpmath) GSO
with an exact-rational (Fraction) verifier on the output.

Tier2 capability remediation Phase 5 Priority 5 (derived from
`docs/TIER2_FAILURE_MATRIX.md`'s root-cause frequency table: "cryptanalysis
limitation" is the cleanest single-cause recurring blocker with a
validated-correct attack methodology already blocked purely by tooling --
GAP-028, `WNL-T2-082`). sympy's `Matrix.lll()` was independently confirmed
(by the original GAP-028 investigation) to hit an internal `AssertionError`
in its Gram-Schmidt-coefficient-reduction invariant check at the real
problem's scale (65-dimensional lattice, ~96-100-bit entries), reproduced
across three scaling factors and two delta representations -- ruling out a
usage/parameter fix. No `fpylll`/`sage`/`python-flint` is installed in this
environment.

Design note (revised after direct benchmarking this session): an earlier
version of this module used Python's exact `fractions.Fraction` for every
intermediate Gram-Schmidt coefficient. It is correct but was measured to be
far too slow to reach the real problem's scale (a 24-dimensional synthetic
test alone took minutes; 65 dimensions with ~100-bit entries would be
impractical) -- exact-rational LLL suffers from denominator blow-up as
dimension grows, a well-known practical limitation, which is exactly why
real implementations (including `fpylll` itself) use high-precision
floating point internally rather than exact rationals. This version follows
that same standard, well-justified practice: `mpmath.mpf` at a generous,
tunable precision (default 200 decimal digits -- vastly more headroom than
the ~100-bit entry magnitudes involved, and nothing like the fixed 53-bit
`float` precision that is the most likely root cause of sympy's assertion
failure at this exact scale) drives the iterative Gram-Schmidt/size-
reduction/swap loop, while the lattice basis vectors themselves remain
exact Python `int` throughout -- only the internal orthogonalization
bookkeeping is approximate. `is_lll_reduced()` re-derives the Gram-Schmidt
data with exact `Fraction` arithmetic (cheap: it runs once, on the final
result, not in the hot loop) to independently verify the reduction
actually satisfies the LLL conditions before any caller trusts it.

See tests/test_lll_exact.py for the offline, non-circular verification
suite.
"""
from __future__ import annotations

from fractions import Fraction

try:
    import mpmath

    _HAVE_MPMATH = True
except ImportError:  # pragma: no cover - only hit on a stripped install lacking the optional dep
    mpmath = None
    _HAVE_MPMATH = False

DEFAULT_PRECISION_DPS = 200


class LLLError(Exception):
    pass


def _require_mpmath():
    """Fail closed when the optional high-precision backend is absent.

    ``mpmath`` drives the internal Gram-Schmidt of the reduction and
    enumeration routines. It is an optional dependency, so rather than
    letting an ``AttributeError`` escape from ``mpmath.workdps`` -- or an
    ``ImportError`` crash the whole harness at import time (this module is
    eager-imported through ``tools_lattice`` at ``teacher.py`` startup) --
    the routines that need it raise a typed, self-describing ``LLLError``
    that callers already handle, and ``tools_lattice`` maps to a structured
    ``TOOL_MISSING`` result.
    """
    if not _HAVE_MPMATH:
        raise LLLError(
            "MPMATH_UNAVAILABLE: high-precision lattice reduction requires the "
            "optional 'mpmath' package (pip install mpmath); it is not installed"
        )


def _dot(u, v):
    return sum(a * b for a, b in zip(u, v))


def _mp_gram_schmidt(basis, dps):
    """High-precision (mpmath) Gram-Schmidt, used only to drive the
    iterative reduction loop's rounding decisions -- never treated as the
    final source of truth for correctness (see is_lll_reduced)."""
    with mpmath.workdps(dps):
        n = len(basis)
        gs = []
        mu = [[mpmath.mpf(0)] * n for _ in range(n)]
        for i in range(n):
            v = [mpmath.mpf(x) for x in basis[i]]
            for j in range(i):
                num = sum(mpmath.mpf(basis[i][t]) * gs[j][t] for t in range(len(basis[i])))
                den = sum(gs[j][t] * gs[j][t] for t in range(len(gs[j])))
                if den == 0:
                    raise LLLError(f"linearly dependent basis: gs[{j}] is (numerically) the zero vector")
                mu[i][j] = num / den
                v = [vc - mu[i][j] * gc for vc, gc in zip(v, gs[j])]
            gs.append(v)
        return gs, mu


def lll_reduce(basis, delta=0.75, dps=DEFAULT_PRECISION_DPS):
    """Reduces an integer lattice basis (list of lists/tuples of int) via
    LLL, using high-precision floating-point Gram-Schmidt internally.
    Returns a new list of lists of exact Python int (the reduced basis,
    same rank/lattice, same dimension). Raises LLLError on a degenerate
    (linearly dependent, or empty) basis.
    """
    _require_mpmath()
    if not basis:
        raise LLLError("empty basis")
    n = len(basis)
    dim = len(basis[0])
    if any(len(row) != dim for row in basis):
        raise LLLError("inconsistent row dimensions")
    if not (0.25 < delta <= 1.0):
        raise LLLError(f"delta must be in (0.25, 1.0], got {delta}")

    b = [list(int(x) for x in row) for row in basis]
    gs, mu = _mp_gram_schmidt(b, dps)

    with mpmath.workdps(dps):
        delta_mp = mpmath.mpf(delta)
        gs_norm2 = [sum(c * c for c in v) for v in gs]
        k = 1
        max_iterations = 200 * n * n + 10000  # generous non-termination guard
        iterations = 0
        while k < n:
            iterations += 1
            if iterations > max_iterations:
                raise LLLError(f"LLL did not terminate within {max_iterations} iterations (possible precision issue -- try a higher dps)")
            for j in range(k - 1, -1, -1):
                q_mp = mu[k][j]
                if abs(q_mp) > 0.5:
                    qr = int(mpmath.nint(q_mp))
                    if qr != 0:
                        b[k] = [bk - qr * bj for bk, bj in zip(b[k], b[j])]
                        # Incremental mu update (size-reduction never
                        # changes the Gram-Schmidt vectors themselves,
                        # only the mu coefficients for indices <= j) --
                        # far cheaper than a full recompute.
                        mu[k][j] -= qr
                        for i in range(j):
                            mu[k][i] -= qr * mu[j][i]
            lovasz_rhs = (delta_mp - mu[k][k - 1] * mu[k][k - 1]) * gs_norm2[k - 1]
            if gs_norm2[k] >= lovasz_rhs:
                k += 1
            else:
                _swap_update(b, gs, mu, gs_norm2, k, n)
                k = max(k - 1, 1)
    reduced = b
    if not is_lll_reduced(reduced, delta=Fraction(delta).limit_denominator(10**6)):
        # Safety net: the incremental swap-update math below is derived
        # from the standard reference formulas, but if it ever has a
        # transcription bug, the *worst* consequence must be "slower or
        # wrong stopping decisions", never a silently-wrong basis handed
        # to a caller. Fall back to the simple, unambiguously-correct
        # full-recompute-per-swap algorithm rather than return an
        # unverified result.
        reduced = _lll_reduce_full_recompute(basis, delta, dps)
    return reduced


def _swap_update(b, gs, mu, gs_norm2, k, n):
    """Incremental Gram-Schmidt update after swapping b[k] and b[k-1],
    following the standard reference formulas (see e.g. Cohen, "A Course
    in Computational Algebraic Number Theory", Algorithm 2.6.3) -- O(n)
    per swap instead of a full O(n^2) Gram-Schmidt recompute, which is
    what makes n~65 with ~100-bit entries tractable. Mutates b, gs, mu,
    gs_norm2 in place.
    """
    b[k], b[k - 1] = b[k - 1], b[k]
    mu_val = mu[k][k - 1]
    B_km1 = gs_norm2[k - 1]
    B_k = gs_norm2[k]
    B_new_km1 = B_k + mu_val * mu_val * B_km1
    old_gs_km1 = gs[k - 1]
    old_gs_k = gs[k]
    new_gs_km1 = [gk + mu_val * gkm1 for gk, gkm1 in zip(old_gs_k, old_gs_km1)]
    new_mu_k_km1 = (mu_val * B_km1) / B_new_km1
    new_gs_k = [gkm1 - new_mu_k_km1 * g for gkm1, g in zip(old_gs_km1, new_gs_km1)]
    gs[k - 1] = new_gs_km1
    gs[k] = new_gs_k
    gs_norm2[k - 1] = B_new_km1
    gs_norm2[k] = (B_km1 * B_k) / B_new_km1
    mu[k][k - 1] = new_mu_k_km1
    for i in range(k - 1):
        mu[k - 1][i], mu[k][i] = mu[k][i], mu[k - 1][i]
    for i in range(k + 1, n):
        old_mu_i_km1 = mu[i][k - 1]
        old_mu_i_k = mu[i][k]
        new_mu_i_k = old_mu_i_km1 - mu_val * old_mu_i_k
        mu[i][k] = new_mu_i_k
        mu[i][k - 1] = old_mu_i_k + new_mu_k_km1 * new_mu_i_k


def _lll_reduce_full_recompute(basis, delta, dps):
    """Simple, unambiguously-correct fallback: full Gram-Schmidt recompute
    after every swap (no incremental-update formulas to get wrong).
    Slower, only used if the optimized path's own output ever fails its
    independent is_lll_reduced() check.
    """
    n = len(basis)
    b = [list(int(x) for x in row) for row in basis]
    gs, mu = _mp_gram_schmidt(b, dps)
    with mpmath.workdps(dps):
        delta_mp = mpmath.mpf(delta)
        k = 1
        max_iterations = 200 * n * n + 10000
        iterations = 0
        while k < n:
            iterations += 1
            if iterations > max_iterations:
                raise LLLError(f"fallback LLL did not terminate within {max_iterations} iterations")
            for j in range(k - 1, -1, -1):
                q_mp = mu[k][j]
                if abs(q_mp) > 0.5:
                    qr = int(mpmath.nint(q_mp))
                    if qr != 0:
                        b[k] = [bk - qr * bj for bk, bj in zip(b[k], b[j])]
                        gs, mu = _mp_gram_schmidt(b, dps)
            gs_kk = sum(c * c for c in gs[k])
            gs_k1 = sum(c * c for c in gs[k - 1])
            lovasz_rhs = (delta_mp - mu[k][k - 1] * mu[k][k - 1]) * gs_k1
            if gs_kk >= lovasz_rhs:
                k += 1
            else:
                b[k], b[k - 1] = b[k - 1], b[k]
                gs, mu = _mp_gram_schmidt(b, dps)
                k = max(k - 1, 1)
    return b


class EnumerationBudgetExceeded(LLLError):
    """Raised by enumerate_short_vectors() when its node budget is
    exhausted before the search tree completes -- distinct from other
    LLLError cases so a caller can tell 'genuinely exhausted the space,
    found nothing' apart from 'ran out of patience, inconclusive'."""


def enumerate_short_vectors(reduced_basis, max_norm_sq, dps=DEFAULT_PRECISION_DPS,
                             max_nodes=5_000_000, max_results=200):
    """Bounded Fincke-Pohst/Kannan short-vector enumeration over an
    ALREADY LLL-REDUCED basis -- the standard next step after plain LLL
    when a target vector of known small norm isn't itself one of the
    reduced basis rows (see Tier2 remediation roadmap Priority 5's
    WNL-T2-082 status update). This is, in effect, a single full-size
    "block" of what BKZ does internally (BKZ = LLL + repeated bounded
    enumeration over sliding blocks; here the block is the whole
    dimension, i.e. HKZ-style, which is enumeration-tractable at n~65
    once the basis is already well LLL-reduced and the target norm is
    known and small).

    Returns (results, nodes_visited) where results is a list of integer
    coordinate vectors x (each len(reduced_basis) long) such that
    ||sum_i x_i * reduced_basis[i]||^2 <= max_norm_sq and the vector is
    nonzero. Raises EnumerationBudgetExceeded if max_nodes is exhausted
    before the search completes (an honest "inconclusive", never a
    silent partial result presented as complete).
    """
    _require_mpmath()
    n = len(reduced_basis)
    if n == 0:
        raise LLLError("empty basis")
    gs, mu = _mp_gram_schmidt(reduced_basis, dps)
    with mpmath.workdps(dps):
        gs_norm2 = [sum(c * c for c in v) for v in gs]
        budget_top = mpmath.mpf(max_norm_sq)
        results = []
        nodes = [0]
        x = [0] * n

        def recurse(k, partial, budget):
            nodes[0] += 1
            if nodes[0] > max_nodes:
                raise EnumerationBudgetExceeded(
                    f"enumeration exceeded {max_nodes} nodes without completing "
                    f"(found {len(results)} candidates so far, search not exhaustive)"
                )
            if len(results) >= max_results:
                return
            if gs_norm2[k] <= 0 or budget < 0:
                return
            bound = mpmath.sqrt(budget / gs_norm2[k])
            lo = int(mpmath.ceil(-partial - bound))
            hi = int(mpmath.floor(-partial + bound))
            for xi in range(lo, hi + 1):
                l_k = xi + partial
                used = gs_norm2[k] * l_k * l_k
                if used > budget:
                    continue
                x[k] = xi
                new_budget = budget - used
                if k == 0:
                    if any(x):
                        v = [0] * len(reduced_basis[0])
                        for i in range(n):
                            if x[i] == 0:
                                continue
                            for t in range(len(v)):
                                v[t] += x[i] * reduced_basis[i][t]
                        exact_norm2 = sum(c * c for c in v)
                        if 0 < exact_norm2 <= max_norm_sq:
                            results.append(list(v))
                            if len(results) >= max_results:
                                return
                else:
                    new_partial = sum(mu[i][k - 1] * x[i] for i in range(k, n))
                    recurse(k - 1, new_partial, new_budget)

        recurse(n - 1, mpmath.mpf(0), budget_top)
    return results, nodes[0]


def is_lll_reduced(basis, delta=Fraction(3, 4)) -> bool:
    """Independent, EXACT (fractions.Fraction) check that a basis
    actually satisfies the LLL size-reduction and Lovász conditions --
    runs once on a result, not in any hot loop, so exact arithmetic's
    cost here is a non-issue. Used to verify lll_reduce()'s output rather
    than trusting the high-precision-float internal loop blindly.
    """
    if not isinstance(delta, Fraction):
        delta = Fraction(delta)
    n = len(basis)
    gs = []
    mu = [[Fraction(0)] * n for _ in range(n)]
    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            num = _dot(basis[i], gs[j])
            den = _dot(gs[j], gs[j])
            if den == 0:
                return False
            mu[i][j] = Fraction(num, den) if not isinstance(num, Fraction) else num / den
            v = [vc - mu[i][j] * gc for vc, gc in zip(v, gs[j])]
        gs.append(v)
    for i in range(n):
        for j in range(i):
            if abs(mu[i][j]) > Fraction(1, 2):
                return False
    for k in range(1, n):
        gs_kk = _dot(gs[k], gs[k])
        gs_k1 = _dot(gs[k - 1], gs[k - 1])
        if gs_kk < (delta - mu[k][k - 1] * mu[k][k - 1]) * gs_k1:
            return False
    return True
