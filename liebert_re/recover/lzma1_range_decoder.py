"""Standalone, from-scratch LZMA1 range-coder decoder.

Written directly from the public LZMA1 algorithm specification (the
classic "lzma-specification.txt" structure: 12-state state machine,
11-bit binary range coder, bit-tree symbol decoders, literal/match/rep
opcodes, position-slot distance decoding). Not derived from or copied out
of any existing Python LZMA implementation's source -- an independent
authorship, so that validating it against Python's own stdlib `lzma`
module (a completely separate, mature, C-based implementation) is a
genuine cross-implementation check, not a circular one.

Built for WNL-T2-091 (GAP-029, Upack packer): Upack's unpacking stub was
statically traced (raw Capstone disassembly, no execution) to be a
customized/reduced LZMA-variant range coder -- this module's `LzmaState`
class exposes the individual range-coder/bit-tree primitives (not just a
single opaque `decompress()` entry point) specifically so a caller can
drive them according to Upack's own opcode sequence once that is traced,
rather than assuming Upack's control flow exactly matches standard
LZMA1's `while` loop structure. `decode_lzma1_stream()` is the standard
LZMA1 top-level loop, useful both as its own regression-tested capability
and as the reference each traced Upack opcode gets compared against.

See tests/test_lzma1_range_decoder.py for the offline verification suite
(Python stdlib `lzma`-generated known-good vectors, since the stdlib
module is a separate, independently maintained implementation -- not
authored as part of this decoder).
"""
from __future__ import annotations

kNumBitModelTotalBits = 11
kBitModelTotal = 1 << kNumBitModelTotalBits
kNumMoveBits = 5
kTopValue = 1 << 24
kNumPosBitsMax = 4
kNumStates = 12
kNumLenToPosStates = 4
kNumAlignBits = 4
kEndPosModelIndex = 14
kNumFullDistances = 1 << (kEndPosModelIndex >> 1)
kMatchMinLen = 2


class LzmaFormatError(Exception):
    pass


class RangeDecoder:
    __slots__ = ("data", "pos", "code", "range")

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.pos = offset
        if offset >= len(data):
            raise LzmaFormatError("range coder: no data for 5-byte init")
        first = data[offset]
        if first != 0:
            raise LzmaFormatError(f"range coder: init byte must be 0, got {first}")
        self.pos = offset + 1
        code = 0
        for i in range(4):
            code = (code << 8) | self._read_byte()
        self.code = code
        self.range = 0xFFFFFFFF

    def _read_byte(self) -> int:
        if self.pos >= len(self.data):
            # LZMA streams may end exactly at the last real symbol without
            # trailing padding; treat EOF-reads-during-normalize as 0 so a
            # stream that naturally terminates via the caller's byte-count
            # limit doesn't spuriously raise -- callers who need strict
            # end-of-stream validation should check bytes_consumed().
            return 0
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _normalize(self):
        if self.range < kTopValue:
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | self._read_byte()) & 0xFFFFFFFF

    def decode_direct_bits(self, num_bits: int) -> int:
        result = 0
        for _ in range(num_bits):
            self.range >>= 1
            self.code = (self.code - self.range) & 0xFFFFFFFF
            t = 0 - (self.code >> 31)
            self.code = (self.code + (self.range & t)) & 0xFFFFFFFF
            self._normalize()
            result = (result << 1) + (t + 1)
        return result & 0xFFFFFFFF

    def decode_bit(self, probs: list, index: int) -> int:
        prob = probs[index]
        bound = (self.range >> kNumBitModelTotalBits) * prob
        if self.code < bound:
            self.range = bound
            probs[index] = prob + ((kBitModelTotal - prob) >> kNumMoveBits)
            bit = 0
        else:
            self.range -= bound
            self.code -= bound
            probs[index] = prob - (prob >> kNumMoveBits)
            bit = 1
        self._normalize()
        return bit

    def bit_tree_decode(self, probs: list, base: int, num_bits: int) -> int:
        m = 1
        for _ in range(num_bits):
            m = (m << 1) + self.decode_bit(probs, base + m)
        return m - (1 << num_bits)

    def bit_tree_reverse_decode(self, probs: list, base: int, num_bits: int) -> int:
        m = 1
        result = 0
        for i in range(num_bits):
            bit = self.decode_bit(probs, base + m)
            m = (m << 1) + bit
            result |= bit << i
        return result


def _literal_state_after_literal(state: int) -> int:
    if state < 4:
        return 0
    if state < 10:
        return state - 3
    return state - 6


def _state_after_match(state: int) -> int:
    return 7 if state < 7 else 10


def _state_after_rep(state: int) -> int:
    return 8 if state < 7 else 11


def _state_after_shortrep(state: int) -> int:
    return 9 if state < 7 else 11


class LzmaState:
    """Holds the full LZMA1 probability model + range coder + output
    window. Exposes step-level methods (decode_literal_step,
    decode_match_or_rep_step) so a caller tracing a *non-standard*
    control-flow (e.g. Upack's reduced stub) can drive the primitives in
    whatever opcode order the traced disassembly actually shows, instead
    of being forced through decode_lzma1_stream()'s standard top-level
    loop.
    """

    def __init__(self, rc: RangeDecoder, lc: int, lp: int, pb: int):
        if not (0 <= lc <= 8 and 0 <= lp <= 4 and 0 <= pb <= 4):
            raise LzmaFormatError(f"lc/lp/pb out of range: {lc}/{lp}/{pb}")
        self.rc = rc
        self.lc = lc
        self.lp = lp
        self.pb = pb
        self.pos_mask = (1 << pb) - 1
        self.lit_pos_mask = (1 << lp) - 1

        num_pos_states = 1 << pb
        self.is_match = [kBitModelTotal >> 1] * (kNumStates * num_pos_states)
        self.is_rep = [kBitModelTotal >> 1] * kNumStates
        self.is_rep_g0 = [kBitModelTotal >> 1] * kNumStates
        self.is_rep_g1 = [kBitModelTotal >> 1] * kNumStates
        self.is_rep_g2 = [kBitModelTotal >> 1] * kNumStates
        self.is_rep0_long = [kBitModelTotal >> 1] * (kNumStates * num_pos_states)

        self.pos_slot_decoder = [[kBitModelTotal >> 1] * (1 << 6) for _ in range(kNumLenToPosStates)]
        self.spec_pos = [kBitModelTotal >> 1] * (kNumFullDistances - kEndPosModelIndex)
        self.align_decoder = [kBitModelTotal >> 1] * (1 << kNumAlignBits)

        self.len_choice = [kBitModelTotal >> 1] * 2
        self.len_low = [[kBitModelTotal >> 1] * (1 << 3) for _ in range(num_pos_states)]
        self.len_mid = [[kBitModelTotal >> 1] * (1 << 3) for _ in range(num_pos_states)]
        self.len_high = [kBitModelTotal >> 1] * (1 << 8)

        self.rep_len_choice = [kBitModelTotal >> 1] * 2
        self.rep_len_low = [[kBitModelTotal >> 1] * (1 << 3) for _ in range(num_pos_states)]
        self.rep_len_mid = [[kBitModelTotal >> 1] * (1 << 3) for _ in range(num_pos_states)]
        self.rep_len_high = [kBitModelTotal >> 1] * (1 << 8)

        self.lit_probs = [[kBitModelTotal >> 1] * 0x300 for _ in range(1 << (lc + lp))]

        self.state = 0
        self.rep0 = 0
        self.rep1 = 0
        self.rep2 = 0
        self.rep3 = 0
        self.out = bytearray()

    def _pos_state(self) -> int:
        return len(self.out) & self.pos_mask

    def _decode_len(self, choice, low, mid, high, pos_state) -> int:
        if self.rc.decode_bit(choice, 0) == 0:
            return self.rc.bit_tree_decode(low[pos_state], 0, 3)
        if self.rc.decode_bit(choice, 1) == 0:
            return 8 + self.rc.bit_tree_decode(mid[pos_state], 0, 3)
        return 16 + self.rc.bit_tree_decode(high, 0, 8)

    def decode_literal_step(self):
        prev_byte = self.out[-1] if self.out else 0
        lit_state = ((len(self.out) & self.lit_pos_mask) << self.lc) + (prev_byte >> (8 - self.lc))
        probs = self.lit_probs[lit_state]
        if self.state >= 7:
            match_byte = self.out[len(self.out) - self.rep0 - 1]
            symbol = 1
            while symbol < 0x100:
                match_bit = (match_byte >> 7) & 1
                match_byte = (match_byte << 1) & 0xFF
                bit = self.rc.decode_bit(probs, ((1 + match_bit) << 8) + symbol)
                symbol = (symbol << 1) | bit
                if match_bit != bit:
                    break
            while symbol < 0x100:
                symbol = (symbol << 1) | self.rc.decode_bit(probs, symbol)
        else:
            symbol = 1
            while symbol < 0x100:
                symbol = (symbol << 1) | self.rc.decode_bit(probs, symbol)
        self.out.append(symbol & 0xFF)
        self.state = _literal_state_after_literal(self.state)

    def decode_distance(self, length: int) -> int:
        len_to_pos_state = min(length - kMatchMinLen, kNumLenToPosStates - 1)
        pos_slot = self.rc.bit_tree_decode(self.pos_slot_decoder[len_to_pos_state], 0, 6)
        if pos_slot < 4:
            return pos_slot
        num_direct_bits = (pos_slot >> 1) - 1
        dist = (2 | (pos_slot & 1)) << num_direct_bits
        if pos_slot < kEndPosModelIndex:
            dist += self.rc.bit_tree_reverse_decode(self.spec_pos, dist - pos_slot - 1, num_direct_bits)
        else:
            dist = (dist + (self.rc.decode_direct_bits(num_direct_bits - kNumAlignBits) << kNumAlignBits)) & 0xFFFFFFFF
            dist += self.rc.bit_tree_reverse_decode(self.align_decoder, 0, kNumAlignBits)
        return dist & 0xFFFFFFFF

    def copy_match(self, distance: int, length: int):
        start = len(self.out) - distance - 1
        if start < 0:
            raise LzmaFormatError(f"back-reference distance {distance} exceeds output length {len(self.out)}")
        for i in range(length):
            self.out.append(self.out[start + i])

    def decode_match_or_rep_step(self) -> bool:
        """Returns True if this was the end-of-stream marker (rep0 became
        0xFFFFFFFF on a fresh MATCH); caller should stop after this."""
        pos_state = self._pos_state()
        if self.rc.decode_bit(self.is_rep, self.state) == 0:
            self.rep3, self.rep2, self.rep1 = self.rep2, self.rep1, self.rep0
            length = self._decode_len(self.len_choice, self.len_low, self.len_mid, self.len_high, pos_state) + kMatchMinLen
            self.state = _state_after_match(self.state)
            self.rep0 = self.decode_distance(length)
            if self.rep0 == 0xFFFFFFFF:
                return True
            self.copy_match(self.rep0, length)
            return False
        if self.rc.decode_bit(self.is_rep_g0, self.state) == 0:
            if self.rc.decode_bit(self.is_rep0_long, self.state * (1 << self.pb) + pos_state) == 0:
                self.state = _state_after_shortrep(self.state)
                self.out.append(self.out[len(self.out) - self.rep0 - 1])
                return False
        else:
            if self.rc.decode_bit(self.is_rep_g1, self.state) == 0:
                dist = self.rep1
            else:
                if self.rc.decode_bit(self.is_rep_g2, self.state) == 0:
                    dist = self.rep2
                else:
                    dist = self.rep3
                    self.rep3 = self.rep2
                self.rep2 = self.rep1
            self.rep1 = self.rep0
            self.rep0 = dist
        length = self._decode_len(self.rep_len_choice, self.rep_len_low, self.rep_len_mid, self.rep_len_high, pos_state) + kMatchMinLen
        self.state = _state_after_rep(self.state)
        self.copy_match(self.rep0, length)
        return False

    def decode_symbol_step(self) -> bool:
        """One full LZMA1 opcode (literal, or match/rep family). Returns
        True on the end-of-stream marker."""
        pos_state = self._pos_state()
        if self.rc.decode_bit(self.is_match, self.state * (1 << self.pb) + pos_state) == 0:
            self.decode_literal_step()
            return False
        return self.decode_match_or_rep_step()


def decode_lzma1_stream(data: bytes, lc: int, lp: int, pb: int, out_size: int, offset: int = 0) -> bytes:
    """Standard LZMA1 top-level decode loop: produce exactly out_size
    bytes (the common case when the original size is known, e.g. from a
    packer header field) or stop early on an end-of-stream marker.
    """
    rc = RangeDecoder(data, offset)
    st = LzmaState(rc, lc, lp, pb)
    while len(st.out) < out_size:
        if st.decode_symbol_step():
            break
    return bytes(st.out[:out_size])
