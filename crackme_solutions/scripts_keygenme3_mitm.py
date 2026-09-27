"""WNL-T2-093 memory-efficient, hash-bucketed meet-in-the-middle search.

Tier2 capability remediation Phase 5 Priority 5, Phase B (per explicit
operator direction, following WNL-T2-082's closure): profiled before any
significant computation (see docs/PROJECT_STATE.md and
benchmarks/windows_native_ladder/results/tier2/WNL-T2-093.md for the full
numbers), then implemented the lowest-complexity approach the profiling
actually justified.

Problem shape (see scripts_keygenme3_siphash_attack.py for the verified
hash primitive): 16 independent code-byte positions, each contributing
one of 256 fully-precomputable 64-bit values; the sum mod 2**64 must hit
a target derived from the (freely chosen) name. Full search space is
256**16 = 2**128; the modular *target* space is only 2**64, so this is a
birthday-bound / meet-in-the-middle problem, not a problem requiring
2**128 work -- but a complete two-table split (2 halves of 8 positions
each) would still need 256**8 = 2**64 entries per side, which is
genuinely infeasible on any realistic hardware (storage and enumeration
time both scale with 2**64, not a "just add more RAM" problem). This is
therefore inherently a PROBABILISTIC, bounded search, not a "run it to
completion, guaranteed" one -- matching the birthday-collision math the
original WNL-T2-093 investigation had already derived correctly.

Two real, measured facts from this pass's profiling materially changed
the plan from the original attempt:
  1. A naive Python-level implementation runs at ~93,000 SipHash
     evaluations/second -- a numpy-vectorized batch implementation
     (`siphash24_batch_8byte` here) runs at ~2,000,000/second, a ~22x
     table-construction speedup, independently cross-validated against
     the already-verified scalar `siphash24()` across all 4096 real
     (position, byte_value) combinations with zero mismatches.
  2. `numpy.searchsorted` -- the "obvious" way to check table membership
     -- was directly benchmarked at real scale (200M-element sorted
     array) and measured at only ~392,000 queries/second, apparently
     memory-bandwidth-bound from cache-unfriendly binary search access
     patterns, NOT the ~10^8-10^9/sec initially assumed. A hash-bucketed
     direct-index lookup (this module's `HashBucketTable`) was benchmarked
     at the same scale and measured at ~72,000,000 queries/second -- a
     ~185x speedup over searchsorted, making the whole search tractable
     within a bounded time budget where the searchsorted-based design
     was not (searchsorted's real cost projected to tens of hours; the
     hash-bucketed design projects to tens of minutes -- see the
     profiling doc for the exact numbers this comparison is based on).

Safety/resource discipline (explicit operator requirement): every call
into this module's search functions is bounded by an explicit node/time
budget and raises rather than silently truncating; table sizes are
chosen with a documented, checked memory estimate well under available
RAM (never approaching a level that risks swapping); progress is
reported via a caller-supplied logging callback at a bounded interval,
never silently running for a long time with no feedback.
"""
from __future__ import annotations

import time

import numpy as np

from scripts_keygenme3_siphash_attack import KEY_SERIAL, MASK64, name_target

N_FULL_POSITIONS = 3   # positions fully enumerated (0..255) per MITM group
GROUP_BASE = 256 ** N_FULL_POSITIONS  # 16,777,216


class SearchBudgetExceeded(Exception):
    pass


def rotl_np(x: np.ndarray, b: int) -> np.ndarray:
    return (x << np.uint64(b)) | (x >> np.uint64(64 - b))


def _sipround_np(v0, v1, v2, v3):
    v0 = v0 + v1
    v1 = rotl_np(v1, 13)
    v1 = v1 ^ v0
    v0 = rotl_np(v0, 32)
    v2 = v2 + v3
    v3 = rotl_np(v3, 16)
    v3 = v3 ^ v2
    v0 = v0 + v3
    v3 = rotl_np(v3, 21)
    v3 = v3 ^ v0
    v2 = v2 + v1
    v1 = rotl_np(v1, 17)
    v1 = v1 ^ v2
    v2 = rotl_np(v2, 32)
    return v0, v1, v2, v3


def siphash24_batch_8byte(key: bytes, m1_array: np.ndarray) -> np.ndarray:
    """Vectorized SipHash-2-4 for the fixed-8-byte-message case this
    attack needs (see scripts_keygenme3_siphash_attack.py's module
    docstring for the derivation of the fixed length-trailer block).
    m1_array: uint64 array, each element the little-endian-packed 8-byte
    message for one hash instance. Cross-validated against the scalar,
    externally-verified siphash24() -- see
    tests/test_keygenme3_mitm.py.
    """
    k0 = np.uint64(int.from_bytes(key[0:8], "little"))
    k1 = np.uint64(int.from_bytes(key[8:16], "little"))
    n = m1_array.shape[0]
    v0 = np.full(n, k0 ^ np.uint64(0x736F6D6570736575), dtype=np.uint64)
    v1 = np.full(n, k1 ^ np.uint64(0x646F72616E646F6D), dtype=np.uint64)
    v2 = np.full(n, k0 ^ np.uint64(0x6C7967656E657261), dtype=np.uint64)
    v3 = np.full(n, k1 ^ np.uint64(0x7465646279746573), dtype=np.uint64)
    m1 = m1_array.astype(np.uint64)
    v3 = v3 ^ m1
    v0, v1, v2, v3 = _sipround_np(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround_np(v0, v1, v2, v3)
    v0 = v0 ^ m1
    m2 = np.uint64(0x0800000000000000)  # fixed length-trailer block for an 8-byte message
    v3 = v3 ^ m2
    v0, v1, v2, v3 = _sipround_np(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround_np(v0, v1, v2, v3)
    v0 = v0 ^ m2
    v2 = v2 ^ np.uint64(0xFF)
    for _ in range(4):
        v0, v1, v2, v3 = _sipround_np(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


DEFAULT_CHUNK_SIZE = 8_000_000  # see module docstring's scaling-investigation note


def build_group_table(base_positions, extra_position, m, log=None, chunk_size=DEFAULT_CHUNK_SIZE):
    """Builds the sum-table for one MITM group: `base_positions` (exactly
    N_FULL_POSITIONS position indices) fully enumerated over all 256
    byte values, plus one `extra_position` restricted to byte values
    0..m-1. Returns (sums: uint64[GROUP_BASE*m], byte_values: uint8[GROUP_BASE*m, 4])
    where byte_values[i] gives the actual (b0,b1,b2,b3) byte assignment
    for sums[i], in (base_positions[0..2], extra_position) order.

    Processes in chunks of `chunk_size` rather than one N-sized vectorized
    pass. This is not a micro-optimization: a dedicated scaling
    investigation (graduated 1M-64M profiling with psutil-measured RSS,
    working-set, page-fault, and CPU-time instrumentation at every phase --
    see benchmarks/windows_native_ladder/results/tier2/WNL-T2-093.md)
    found the un-chunked, single-N-sized-array version has essentially
    perfect linear CPU-time scaling (no algorithmic issue) but a
    stubbornly high, N-independent PEAK working-set overhead of ~124
    bytes/table-entry (converged, measured consistently from N=4M through
    N=64M) -- driven by the several full-size uint64 temporary arrays
    `_sipround_np`'s non-in-place arithmetic creates internally, all alive
    simultaneously at N's full size. The persisted output only needs 12
    bytes/entry (8-byte sum + 4-byte index). At the real problem's ~134M-
    entry scale, ~124 bytes/entry peak means ~15.9GB of transient working
    set -- enough to exceed available RAM on this host and trigger real
    OS-level paging (independently confirmed via a ~29% CPU-utilization
    anomaly observed during an un-chunked real attempt). Chunking bounds
    the *transient* peak to O(chunk_size) regardless of how large the
    *total* table is, while the persisted sums/byte_values arrays are
    pre-allocated once at their final (cheap, 12-bytes/entry) size and
    filled incrementally -- turning an O(N)-memory problem into an
    O(chunk_size)-memory one.
    """
    if len(base_positions) != N_FULL_POSITIONS:
        raise ValueError(base_positions)
    if not (1 <= m <= 256):
        raise ValueError(m)
    n = GROUP_BASE * m
    sums = np.empty(n, dtype=np.uint64)
    byte_values = np.empty((n, 4), dtype=np.uint8)
    positions = base_positions + [extra_position]
    for start in range(0, n, chunk_size):
        end = min(start + chunk_size, n)
        # Index decomposition for this chunk only: idx = ((b0*256+b1)*256+b2)*m + b3, b3 in [0,m)
        idx = np.arange(start, end, dtype=np.uint64)
        b3 = (idx % np.uint64(m)).astype(np.uint8)
        rest = idx // np.uint64(m)
        b2 = (rest % np.uint64(256)).astype(np.uint8)
        rest = rest // np.uint64(256)
        b1 = (rest % np.uint64(256)).astype(np.uint8)
        b0 = (rest // np.uint64(256)).astype(np.uint8)

        chunk_total = np.zeros(end - start, dtype=np.uint64)
        for pos, bcol in zip(positions, (b0, b1, b2, b3)):
            m1 = bcol.astype(np.uint64) | (np.uint64(pos) << np.uint64(8))
            chunk_total = chunk_total + siphash24_batch_8byte(KEY_SERIAL, m1)
        sums[start:end] = chunk_total
        byte_values[start:end, 0] = b0
        byte_values[start:end, 1] = b1
        byte_values[start:end, 2] = b2
        byte_values[start:end, 3] = b3
        if log:
            log(f"  chunk [{start}:{end}] of {n} done")
    if log:
        log(f"built group table: positions={positions} m={m} entries={n} (chunk_size={chunk_size})")
    return sums, byte_values


class HashBucketTable:
    """A direct-indexed (numpy fancy-indexing) hash structure for fast
    approximate membership testing, with exact-value verification for
    candidates (measured ~185x faster than numpy.searchsorted at
    real-world table sizes -- see module docstring)."""

    def __init__(self, values: np.ndarray, bucket_bits: int):
        # bucket_bits sized so nbuckets is comparable to len(values) (~1-2
        # entries/bucket average) -- NOT a large multiple. bucket_start
        # has nbuckets+1 elements, so an oversized bucket_bits directly
        # blows up memory (a real bug caught during this pass's own
        # profiling: an earlier version used ~4x buckets/entry, which at
        # real problem scale would have needed a >17GB bucket_start array
        # alone -- exactly the kind of unbounded-memory mistake this
        # module's own safety discipline exists to catch before it runs).
        if len(values) > 2_000_000_000:
            raise ValueError("values array too large for int32 indexing (>2B entries)")
        # bucket_bits is sized so nbuckets ~ len(values) (see class docstring),
        # so nbuckets always fits comfortably in int32 given the >2B-entries
        # check above. A dedicated profiling pass found the original
        # argsort-based construction (sorting the full uint64 `values`
        # directly, then re-deriving bucket ids via an int64 re-mask+upcast
        # of the sorted values, then an int64 arange(nbuckets+1) for
        # searchsorted) carried ~52 bytes/entry of PEAK transient overhead
        # at real problem scale (N=134M -> ~7.5GB just for this step) on
        # top of the persisted arrays' ~12 bytes/entry -- multiple full-N,
        # 8-byte-wide temporaries alive at once. Computing the (small,
        # int32) bucket ids ONCE and sorting/reusing THAT array instead of
        # the full-width values -- and keeping searchsorted's probe array
        # int32 instead of int64 -- removes those redundant 8-byte temps
        # without changing the algorithm or its output.
        self.values = values
        self.nbuckets = 1 << bucket_bits
        self.bucket_mask = np.uint64(self.nbuckets - 1)
        buckets = (values & self.bucket_mask).astype(np.int32)
        order = np.argsort(buckets, kind="stable").astype(np.int32)
        self.sorted_by_bucket = values[order]
        self.orig_index = order
        buckets_sorted = buckets[order]
        del buckets
        self.bucket_start = np.searchsorted(buckets_sorted, np.arange(self.nbuckets + 1, dtype=np.int32)).astype(np.int32)

    def query_exact_match_indices(self, query_values: np.ndarray, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Returns (query_positions, left_indices) arrays of matched pairs
        where query_values[query_positions[k]] == values[left_indices[k]]
        for all k -- exact matches only, false positives from bucketing
        are filtered out here, not left for the caller to re-check.

        Processes `query_values` in chunks for the same reason
        build_group_table does (see its docstring): the (N,
        max_bucket_size) 2D broadcast this method builds is dominated by
        the single LARGEST bucket any query happens to land in -- a real
        profiling pass found one query call over N=16,777,216 synthetic
        values added +3.09GB peak transient (~193 bytes/query, driven by
        a handful of buckets with several entries each even at this
        table's 0.5-entries/bucket average load factor), which
        extrapolates to a wholly infeasible ~25GB for a single attempt at
        the real WNL-T2-093 m=8 scale (134,217,728 entries/table) -- i.e.
        an un-chunked query call would have crashed the very first search
        attempt even after the table-construction fix. Chunking bounds
        the 2D broadcast to O(chunk_size * local_max_bucket_size) instead
        of O(N * global_max_bucket_size); the search() attempt loop calls
        this once per attempt, so this is on the hot path and must stay
        cheap in both time and memory per call.
        """
        n = len(query_values)
        qpos_parts = []
        left_idx_parts = []
        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            chunk = query_values[start:end]
            qbuckets = (chunk & self.bucket_mask).astype(np.int64)
            starts = self.bucket_start[qbuckets]
            ends = self.bucket_start[qbuckets + 1]
            max_bucket_size = int((ends - starts).max()) if len(starts) else 0
            if max_bucket_size == 0:
                continue
            offsets = np.arange(max_bucket_size, dtype=np.int64)
            cand_slot = starts[:, None] + offsets[None, :]
            valid = cand_slot < ends[:, None]
            cand_slot_clamped = np.where(valid, cand_slot, 0)
            cand_vals = self.sorted_by_bucket[cand_slot_clamped]
            match = valid & (cand_vals == chunk[:, None])
            local_qpos, slot_col = np.nonzero(match)
            if len(local_qpos) == 0:
                continue
            left_idx_parts.append(self.orig_index[cand_slot[local_qpos, slot_col]])
            qpos_parts.append(local_qpos + start)
        if not qpos_parts:
            return np.array([], dtype=np.int64), np.array([], dtype=np.int64)
        return np.concatenate(qpos_parts), np.concatenate(left_idx_parts)


MEASURED_PIPELINE_BYTES_PER_ENTRY = 80  # see search()'s memory-estimate note


DEFAULT_QUERY_CHUNK_SIZE = 2_000_000  # see query_exact_match_indices's docstring


def search(target: int, m: int = 16, max_seconds: float = 600.0,
           max_attempts: int = 2_000_000, max_memory_gb: float = 6.0,
           log=print, rng_seed: int = 0, chunk_size: int = DEFAULT_CHUNK_SIZE,
           query_chunk_size: int = DEFAULT_QUERY_CHUNK_SIZE):
    """Bounded, instrumented hash-bucketed MITM search for a 16-byte code
    matching `target`. Positions 0-2 + 3 (restricted to m) form the LEFT
    group; positions 4-6 + 7 (restricted to m) form the RIGHT group;
    positions 8-15 are swept via random sampling per attempt (a genuinely
    complete sweep of 256**8 middle combinations is itself infeasible --
    this is an inherent property of the problem's birthday-bound
    structure, not a shortcut this implementation is taking). Returns a
    dict with the outcome (found + code, or not-found + stats) -- never
    silently returns partial/inconclusive results as if they were
    complete.

    Each attempt's cost is dominated by one query_exact_match_indices
    call scanning the full RIGHT-sized query array against the LEFT hash-
    bucket table -- an O(n_entries) chunked scan, NOT O(1) or O(log n).
    Measured directly at real problem scale (m=8, 134,217,728 entries):
    ~19s/attempt. This means the attempt loop explores only a few dozen
    attempts within a several-hundred-second budget, not thousands --
    plan `max_seconds` accordingly; this is a genuine, characterized cost
    of exact-match verification at this scale, not an unbounded search
    silently doing less work than it appears to.

    `max_seconds` bounds the WHOLE call (table construction included, not
    just the attempt loop) -- checked between each major phase. Note this
    is necessarily coarse-grained: a single phase (building one table) is
    not preemptible mid-flight, so an individual phase that runs far
    longer than its own benchmark-based estimate can still overrun the
    budget by up to that one phase's duration before the next check fires
    -- an honest, documented limitation (real-world table-construction
    time was observed, during this item's own development, to
    substantially exceed small-scale benchmark extrapolation at ~134M-
    entry scale, for reasons not fully characterized -- see the
    WNL-T2-093 results doc), not a silently-unbounded loop.

    Before building anything, estimates peak memory and raises
    SearchBudgetExceeded rather than proceeding if the estimate exceeds
    `max_memory_gb` -- a hard, checked limit, not a hope. The estimate
    (MEASURED_PIPELINE_BYTES_PER_ENTRY = 80 bytes/entry) is grounded in
    direct psutil peak-working-set measurement of this exact
    LEFT+RIGHT+HashBucketTable sequence at real problem scale (m=8,
    134,217,728 entries/table: measured peak 8.02GB = 64.2 bytes/entry;
    m=4, 67,108,864 entries/table: measured peak 4.02GB = 64.4
    bytes/entry -- see benchmarks/windows_native_ladder/results/tier2/
    WNL-T2-093.md), with ~25% headroom over the ~64.3 bytes/entry
    measured average rather than the measured value itself, since this
    gate must fail closed on an untested m rather than exactly hug real
    behavior. An earlier version of this estimate (28 bytes/entry, tuned
    to persisted-array size alone) did not account for HashBucketTable's
    own construction-time transient overhead and would have UNDER-
    estimated real peak memory by more than 2x -- exactly the kind of
    silent-gate failure this check exists to prevent.
    """
    est_entries = GROUP_BASE * m
    est_bytes = est_entries * MEASURED_PIPELINE_BYTES_PER_ENTRY
    est_gb = est_bytes / (1024 ** 3)
    if est_gb > max_memory_gb:
        raise SearchBudgetExceeded(
            f"estimated memory {est_gb:.2f}GB for m={m} exceeds max_memory_gb={max_memory_gb} -- refusing to build (reduce m)"
        )

    t0 = time.time()

    def check_time_budget(elapsed_desc):
        if time.time() - t0 > max_seconds:
            raise SearchBudgetExceeded(f"time budget ({max_seconds}s) exceeded during {elapsed_desc} (est. memory was {est_gb:.2f}GB)")

    log(f"[{time.time()-t0:6.1f}s] estimated peak memory for m={m}: {est_gb:.2f}GB (limit {max_memory_gb}GB)")
    log(f"[{time.time()-t0:6.1f}s] building LEFT table (positions 0,1,2,3; m={m})...")
    left_sums, left_bytes = build_group_table([0, 1, 2], 3, m, log=log, chunk_size=chunk_size)
    check_time_budget("LEFT table construction")
    log(f"[{time.time()-t0:6.1f}s] building RIGHT table (positions 4,5,6,7; m={m})...")
    right_sums, right_bytes = build_group_table([4, 5, 6], 7, m, log=log, chunk_size=chunk_size)
    check_time_budget("RIGHT table construction")

    n_entries = GROUP_BASE * m
    bucket_bits = max(1, n_entries.bit_length())  # nbuckets ~ n_entries (see HashBucketTable's own memory-safety note)
    log(f"[{time.time()-t0:6.1f}s] building hash-bucket table over LEFT ({n_entries} entries, {1<<bucket_bits} buckets)...")
    table = HashBucketTable(left_sums, bucket_bits)
    check_time_budget("hash-bucket table construction")
    build_elapsed = time.time() - t0
    log(f"[{time.time()-t0:6.1f}s] tables ready, entering search loop (max_seconds={max_seconds}, max_attempts={max_attempts})")

    rng = np.random.default_rng(rng_seed)
    attempts = 0
    last_report = time.time()
    while True:
        if time.time() - t0 > max_seconds:
            return {"found": False, "reason": "time_budget_exceeded", "attempts": attempts,
                    "elapsed_seconds": time.time() - t0, "build_seconds": build_elapsed}
        if attempts >= max_attempts:
            return {"found": False, "reason": "attempt_budget_exceeded", "attempts": attempts,
                    "elapsed_seconds": time.time() - t0, "build_seconds": build_elapsed}
        middle_bytes = rng.integers(0, 256, size=8, dtype=np.uint8)
        middle_sum = 0
        for pos, bv in zip(range(8, 16), middle_bytes.tolist()):
            m1 = bv | (pos << 8)
            middle_sum = (middle_sum + int(siphash24_batch_8byte(KEY_SERIAL, np.array([m1], dtype=np.uint64))[0])) & MASK64
        needed = (target - middle_sum) & MASK64
        query = (np.uint64(needed) - right_sums) & np.uint64(MASK64)
        qpos, left_idx = table.query_exact_match_indices(query, chunk_size=query_chunk_size)
        attempts += 1
        if len(qpos) > 0:
            r = int(qpos[0])
            l = int(left_idx[0])
            code = np.zeros(16, dtype=np.uint8)
            code[0:3] = left_bytes[l, 0:3]
            code[3] = left_bytes[l, 3]
            code[4:7] = right_bytes[r, 0:3]
            code[7] = right_bytes[r, 3]
            code[8:16] = middle_bytes
            return {"found": True, "code": bytes(code.tolist()), "attempts": attempts,
                    "elapsed_seconds": time.time() - t0, "build_seconds": build_elapsed}
        if time.time() - last_report > 15:
            log(f"[{time.time()-t0:6.1f}s] attempts={attempts} no match yet")
            last_report = time.time()
