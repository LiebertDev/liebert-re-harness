"""Offline, non-circular verification of lzma1_range_decoder.py.

Every known-good compressed/decompressed pair here is produced by
Python's stdlib `lzma` module (a mature, C-based, independently
implemented LZMA encoder/decoder that is not part of this repository and
was not written to match this decoder). This is deliberately NOT a
round-trip-against-itself test: lzma1_range_decoder.py never encodes
anything, only decodes streams stdlib produced, so there is no way for a
shared bug in "my own encoder + my own decoder" to silently agree with
itself.

Built for WNL-T2-091 (GAP-029, Tier2 capability remediation Phase 5
Priority 4 continuation): this suite validates the *general LZMA1 engine*
in isolation from Upack's own stub-specific framing/opcode differences,
which are traced and tested separately against the real target.
"""
from __future__ import annotations

import lzma
import os
import random
import unittest

from liebert_re.recover.lzma1_range_decoder import LzmaFormatError, decode_lzma1_stream


def _lzma1_raw_stream(data: bytes, lc: int = 3, lp: int = 0, pb: int = 2, preset: int = 6):
    """Compress with stdlib lzma (FORMAT_ALONE, so we get a real header we
    can also cross-check), then strip the header to hand back the raw
    LZMA1 bitstream plus the exact properties/size stdlib itself used.
    """
    filt = [{"id": lzma.FILTER_LZMA1, "preset": preset, "lc": lc, "lp": lp, "pb": pb}]
    packed = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=filt)
    props_byte = packed[0]
    got_lc = props_byte % 9
    rem = props_byte // 9
    got_lp = rem % 5
    got_pb = rem // 5
    assert (got_lc, got_lp, got_pb) == (lc, lp, pb), (got_lc, got_lp, got_pb)
    raw_stream = packed[13:]
    return raw_stream, lc, lp, pb


class Lzma1RangeDecoderKnownVectorTests(unittest.TestCase):
    def _check(self, data: bytes, lc=3, lp=0, pb=2, preset=6):
        raw, lc2, lp2, pb2 = _lzma1_raw_stream(data, lc, lp, pb, preset)
        got = decode_lzma1_stream(raw, lc2, lp2, pb2, len(data))
        self.assertEqual(got, data, f"mismatch for len={len(data)} lc={lc} lp={lp} pb={pb} preset={preset}")

    def test_empty_input(self):
        self._check(b"")

    def test_single_byte(self):
        self._check(b"\x00")
        self._check(b"\xff")
        self._check(b"A")

    def test_short_literal_run_no_matches_possible(self):
        # No repeats -> pure literal-coding path only.
        self._check(bytes(range(256)))

    def test_highly_repetitive_triggers_matches_and_reps(self):
        self._check(b"ABCD" * 500)
        self._check(b"the quick brown fox " * 200)

    def test_mixed_literal_and_match_content(self):
        rng = random.Random(1234)
        chunk = bytes(rng.randrange(256) for _ in range(64))
        data = chunk + chunk + chunk[:30] + bytes(rng.randrange(256) for _ in range(40)) + chunk
        self._check(data)

    def test_many_random_inputs_various_sizes(self):
        rng = random.Random(42)
        for trial in range(40):
            size = rng.choice([0, 1, 2, 5, 17, 100, 999, 4096, 20000])
            # Mix of pure-random (stresses literal path) and repetitive
            # (stresses match/rep path) content per trial.
            if trial % 2 == 0:
                data = bytes(rng.randrange(256) for _ in range(size))
            else:
                unit = bytes(rng.randrange(256) for _ in range(max(1, size // 20 or 1)))
                data = (unit * (size // max(1, len(unit)) + 1))[:size]
            self._check(data)

    def test_non_default_lc_lp_pb_settings(self):
        data = b"repeated pattern repeated pattern repeated pattern " * 20
        # lc+lp<=4 is stdlib lzma's own accepted-options constraint.
        for lc, lp, pb in [(0, 0, 0), (0, 2, 0), (4, 0, 0), (2, 2, 2), (0, 4, 0)]:
            self._check(data, lc=lc, lp=lp, pb=pb)

    def test_preset_0_fast_shallow_search_still_decodes(self):
        # Different preset changes match-finding aggressiveness (encoder
        # side only) but must still produce a stream this decoder reads
        # correctly -- proves the decoder isn't accidentally tuned to one
        # specific encoder search strategy's output shape.
        data = (b"alpha beta gamma delta " * 80) + os.urandom(200)
        self._check(data, preset=0)
        self._check(data, preset=9)

    def test_binary_like_data_with_long_range_matches(self):
        rng = random.Random(7)
        base = bytes(rng.randrange(256) for _ in range(2000))
        data = base + base + base
        self._check(data)


class Lzma1RangeDecoderNegativeControlTests(unittest.TestCase):
    """Corruption / malformed-input handling: a decoder that silently
    produces *some* output on garbage input (instead of visibly failing
    or producing wrong bytes) would be dangerous to trust against a real
    target -- these prove it does not quietly succeed on non-LZMA1 input.
    """

    def test_corrupted_stream_does_not_silently_reproduce_original(self):
        raw, lc, lp, pb = _lzma1_raw_stream(b"the quick brown fox jumps over the lazy dog " * 30)
        corrupted = bytearray(raw)
        # Flip a bit roughly in the middle of the compressed stream.
        mid = len(corrupted) // 2
        corrupted[mid] ^= 0x40
        original = b"the quick brown fox jumps over the lazy dog " * 30
        try:
            got = decode_lzma1_stream(bytes(corrupted), lc, lp, pb, len(original))
        except LzmaFormatError:
            return  # an explicit, honest failure is an acceptable outcome
        self.assertNotEqual(got, original, "corrupted stream must not silently decode to the original plaintext")

    def test_wrong_lc_lp_pb_does_not_silently_reproduce_original(self):
        original = b"consistent structured text " * 50
        raw, lc, lp, pb = _lzma1_raw_stream(original, lc=3, lp=0, pb=2)
        try:
            got = decode_lzma1_stream(raw, lc=0, lp=2, pb=0, out_size=len(original))
        except LzmaFormatError:
            return  # an explicit, honest failure is an acceptable outcome
        self.assertNotEqual(got, original)

    def test_truncated_stream_raises_or_produces_wrong_output(self):
        original = b"data with enough repetition to build a real match table " * 10
        raw, lc, lp, pb = _lzma1_raw_stream(original)
        truncated = raw[: len(raw) // 3]
        try:
            got = decode_lzma1_stream(truncated, lc, lp, pb, len(original))
        except LzmaFormatError:
            return
        self.assertNotEqual(got, original)

    def test_empty_data_raises_format_error(self):
        with self.assertRaises(LzmaFormatError):
            decode_lzma1_stream(b"", lc=3, lp=0, pb=2, out_size=10)

    def test_first_byte_nonzero_raises_format_error(self):
        raw, lc, lp, pb = _lzma1_raw_stream(b"abc" * 20)
        bad = bytes([raw[0] | 0x01]) + raw[1:]
        with self.assertRaises(LzmaFormatError):
            decode_lzma1_stream(bad, lc, lp, pb, out_size=60)

    def test_back_reference_past_start_of_output_raises(self):
        # A hand-crafted stream is not needed: directly drive LzmaState's
        # copy_match to prove the bounds check itself, independent of
        # whether any real stream could produce this shape.
        from liebert_re.recover.lzma1_range_decoder import LzmaState, RangeDecoder
        raw, lc, lp, pb = _lzma1_raw_stream(b"x")
        rc = RangeDecoder(raw, 0)
        st = LzmaState(rc, lc, lp, pb)
        with self.assertRaises(LzmaFormatError):
            st.copy_match(distance=5, length=1)


if __name__ == "__main__":
    unittest.main()
