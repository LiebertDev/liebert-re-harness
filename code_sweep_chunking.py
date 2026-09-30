"""Shared, generic chunked capstone disassembly sweep for code sections too
large to safely hand to ``capstone.Cs.disasm()`` in one call.

WHY this exists (measured, 2026-09-26, this session, on this machine): this
repo's pinned capstone Python binding (5.0.1) does not expose the native
``cs_disasm_iter`` incremental API. ``Cs.disasm()`` is a thin generator
wrapper around a SINGLE ``cs_disasm()`` native call that disassembles the
ENTIRE input buffer up front, allocating one native ``cs_insn`` (+
``cs_detail``, since ``detail=True``) struct per decoded/skipped item BEFORE
the Python-side generator yields its first item -- see the binding's own
source, ``capstone/__init__.py``, ``Cs.disasm()``::

    res = _cs.cs_disasm(self.csh, code, size, offset, count, ctypes.byref(all_insn))
    if res > 0:
        try:
            for i in range(res):
                yield CsInsn(self, all_insn[i])
        finally:
            _cs.cs_free(all_insn, res)

The ONLY thing that bounds ``all_insn``'s native (non-``tracemalloc``-
visible) allocation is the size of ``code`` passed to a SINGLE ``disasm()``
call. A Python-side generator loop that only retains a small bounded window
(e.g. a ``collections.deque(maxlen=60)``) changes NOTHING about this,
because the entire native allocation already happened before that loop's
body ever ran once -- this is exactly why this session's earlier
streaming/deque rewrite of ``driver_dispatch_scan.py`` /
``iat_call_arg_recover.py`` did not actually bound memory: it bounded the
Python-retained window, not the native buffer capstone itself allocates per
``disasm()`` call.

Measured proof (this session, this machine, ``.venv``'s pinned capstone):
pointing ``disasm()`` at a 500,000-byte buffer filled with an undecodable
opcode byte (0x06, UD in CS_MODE_64, so ``skipdata=True`` emits one
pseudo-instruction per byte -- the worst case) raised this process's
private/commit bytes by ~118.6 MB after pulling exactly ONE item from the
generator -- i.e. ~248.64 bytes of native memory per input byte, entirely
before the per-instruction loop body executes even once, and entirely
invisible to ``tracemalloc`` (which stayed within ~0.01 MB the whole time --
this is native C heap, never routed through Python's allocator). A second,
end-to-end measurement against the REAL (unmodified at the time) 4 MB
synthetic-section test already in this repo
(``tests/test_driver_dispatch_scan_and_iat_call_arg_recover_memory.py``)
showed the same thing at a larger scale: that test's own
``tracemalloc``-based assertion (peak < 60 MB) passed, while this process's
actual private bytes peaked at ~2.59 GB during the same call -- proof the
existing test was validating the wrong axis and gave false confidence.
Extrapolated to the real 79.2 MB ``.grfn1``-class section this incident was
first measured on: ~79,200,000 * 248.64 =~ 19.7 GB for ONE ``disasm()`` call
alone, before any realloc-growth overhead -- consistent in order of
magnitude with the operator's own measured ~36 GB-and-rising before the
process was killed (realloc-doubling overhead during the single native call
plausibly accounts for the rest).

THE FIX: never call ``disasm()`` over more than a small, fixed-size slice of
a section at once. Partition a section into non-overlapping "credited"
windows of ``chunk_bytes`` (default 1,000,000 -- sized so this session's
measured worst-case ~248.64 bytes/input-byte native cost caps a single
chunk's peak native allocation at roughly 250 MB, comfortably under any
reasonable ceiling with a wide margin for concurrent processes), feed
capstone a slightly WIDER physical slice than each credited window
(``overlap_bytes`` extra on each side, default 4096): x86-64 has no fixed
instruction length, so a chunk cut can start mid-instruction, and the
worst-case backward-lookback context this codebase's resolvers ever need
(``lookback_instructions=60`` * 15 bytes -- the longest legal x86-64
instruction -- = 900 bytes) must fit inside that overlap for argument
resolution to stay correct right at a chunk's start; 4096 leaves >4x margin
plus headroom for the decoder itself to resynchronise after starting
mid-instruction. Each chunk's ``disasm()`` generator is explicitly closed
before the next chunk's call runs -- CPython's reference counting runs the
binding's ``finally: _cs.cs_free(...)`` deterministically the instant a
generator with no other live reference stops being iterated (not on GC's own
schedule), so this bounds peak native memory to O(chunk_bytes), never
O(section_bytes), for a section of ANY size.

Exactly-once correctness across a chunk boundary: an instruction is
"credited" (counted toward coverage, eligible to produce a match) by chunk N
iff its start VA lies in chunk N's own non-overlapping partition
``[true_start_N, true_end_N)``. Bytes in the surrounding ``overlap_bytes`` on
either side are still fed to capstone -- so decode context/backward-lookback
is correct across the seam -- but are never credited by more than one
chunk, because every absolute VA belongs to exactly one partition by
construction. A ``call``/``mov`` instruction whose bytes straddle a
partition boundary is still credited exactly once, by whichever chunk's
partition contains its START address (its full bytes just need to fit
inside that chunk's wider physical slice, which is what the trailing half of
``overlap_bytes`` is for). Callers should still feed EVERY yielded
instruction (credited or not) into their own backward-lookback window, since
the un-credited leading-overlap instructions are exactly the context a match
near a chunk's start needs to resolve correctly.
"""
from __future__ import annotations

from typing import Iterator, Tuple

DEFAULT_CHUNK_BYTES = 1_000_000
DEFAULT_CHUNK_OVERLAP_BYTES = 4096


def chunk_boundaries(size: int, chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> Iterator[Tuple[int, int]]:
    """Pure partition math: non-overlapping ``(true_start, true_end)`` pairs
    covering ``[0, size)`` in steps of at most ``chunk_bytes``. Separated out
    from ``disasm_chunk`` so a caller can check a budget (or anything else)
    between chunks without needing capstone/pefile involved at all."""
    if size <= 0 or chunk_bytes <= 0:
        return
    true_start = 0
    while true_start < size:
        true_end = min(size, true_start + chunk_bytes)
        yield true_start, true_end
        true_start = true_end


def disasm_chunk(md, data, file_offset, va_base, true_start, true_end,
                  overlap_bytes: int = DEFAULT_CHUNK_OVERLAP_BYTES):
    """Disassemble ONE chunk of a section -- ``data[file_offset + true_start
    : file_offset + true_end]`` plus ``overlap_bytes`` of extra context on
    each side (clamped to the section's own bounds; a caller must pass the
    section's own ``size`` in via how it computed ``true_start``/``true_end``
    -- this function does not know the section's total size itself, only the
    absolute file offsets the caller derived from ``chunk_boundaries``).

    Yields ``(insn, credited)``. See module docstring for the memory
    mechanism and the exactly-once boundary argument. Never raises: any
    capstone-side stop is a plain ``StopIteration`` and simply ends the chunk
    early -- callers already have their own per-instruction budget checks.
    """
    slice_start = max(0, true_start - overlap_bytes)
    slice_end = true_end + overlap_bytes  # caller already clamps true_end to section size;
    # reading `overlap_bytes` past it is fine as long as `data` itself extends that far (it is
    # the whole file's bytes, not just this section) -- worst case capstone decodes a few extra
    # un-credited instructions into the next section's raw bytes, which are discarded anyway
    # because they fall outside [true_start, true_end) and are therefore never credited.
    chunk_va_base = va_base + slice_start
    chunk_code = data[file_offset + slice_start: file_offset + slice_end]
    credit_lo = va_base + true_start
    credit_hi = va_base + true_end

    gen = md.disasm(chunk_code, chunk_va_base)
    try:
        for insn in gen:
            yield insn, (credit_lo <= insn.address < credit_hi)
    finally:
        # Deterministic in CPython: closing a generator with no other live
        # reference runs its `finally` clause (capstone's own
        # `_cs.cs_free(all_insn, res)`) immediately via refcounting, not
        # whenever the GC gets around to it -- THIS is what actually bounds
        # peak native memory to one chunk at a time. If the caller breaks out
        # of the loop that is iterating `disasm_chunk(...)` before it is
        # exhausted, Python raises GeneratorExit here on next resume, which
        # still reaches this `finally` and frees the buffer just as promptly.
        gen.close()
