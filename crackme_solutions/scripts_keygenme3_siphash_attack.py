"""WNL-T2-093 "keygenme_3" (dcoder) additive-SipHash keygen attack.

Tier2 capability remediation Phase 5 Priority 5 continuation, Phase B
(memory-efficient MITM redesign, per explicit operator direction: profile
before computing, no unbounded search).

Algorithm (traced from the already-decompiled `FUN_00401000` and
`FUN_00401432`/`main`, both already present in `dataset/evidence/` from
the original investigation -- reused, not rediscovered):

  - `FUN_00401000` is standard SipHash-2-4 (confirmed unambiguously: its
    round constants XOR to the literal "somepseudorandomlygeneratedbytes",
    the canonical SipHash initialization string, and its ARX structure --
    2 compression rounds per 8-byte block including the last partial
    block, 4 finalization rounds after `v2 ^= 0xff` -- matches the
    reference algorithm exactly). `siphash24()` below is validated
    against the algorithm's own official published reference test vectors
    (Aumasson & Bernstein's reference C implementation), an external,
    non-circular source -- not anything derived from this codebase or
    this specific crackme.
  - The two 128-bit keys are read directly as raw bytes from the real
    target binary at the exact addresses `main`'s disassembly showed
    being loaded into EAX before each call (`0x4030fc` for the name hash,
    `0x4030ec` for the per-code-byte hash) -- not assumed from the
    (shorter than 16 bytes) ASCII strings alone, since SipHash reads a
    full 16-byte key and the two extra bytes past each string's null
    terminator matter. Confirmed to be zero-padding, not adjacent-string
    garbage, by reading the raw file bytes directly.
  - Per `main`'s decompile: `target = siphash24(KEY_NAME, name.encode())`
    (length = strlen(name), no padding). For code position i (0-15):
    `contrib(i, code_byte) = siphash24(KEY_SERIAL, bytes([code_byte, i, 0,0,0,0,0,0]))`
    -- confirmed via the exact stack-adjacency trick in `main`'s
    decompile (`local_cc = code_byte | (i << 8)`, `local_c8` -- the next
    stack slot -- always 0 for i in 0..15 since `i >> 24 == 0`, so the
    8-byte read at `&local_cc` really is `[code_byte, i, 0,0,0,0,0,0]`).
    The check passes iff `sum(contrib(i, code[i]) for i in 0..15) mod 2**64 == target`.

See tests/test_keygenme3_siphash_attack.py for the offline, non-circular
verification suite.
"""
from __future__ import annotations

MASK64 = 0xFFFFFFFFFFFFFFFF

# Read directly from the real, frozen kgme3.exe (sha256
# f96ca663723578e3fcef30d5665d879a206b0e7c9f5e78bbe0c78747a272f214) at file
# offsets corresponding to VA 0x4030fc / 0x4030ec (.rdata, delta =
# image_base(0x400000) + section_rva(0x3000) - section_raw_offset(0x1600)
# = 0x401A00) -- not assumed from the ASCII strings alone.
KEY_NAME = b"key for name\x00\x00\x00\x00"      # 16 bytes, verified zero-padded
KEY_SERIAL = b"key for serial\x00\x00"           # 16 bytes, verified zero-padded

TARGET_PATH = "benchmarks/windows_native_ladder/corpus/tier2/keygenme3_dcoder/inner/kgme3.exe"
N_POSITIONS = 16
N_BYTE_VALUES = 256


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & MASK64


def _sipround(v0: int, v1: int, v2: int, v3: int):
    v0 = (v0 + v1) & MASK64
    v1 = _rotl(v1, 13)
    v1 ^= v0
    v0 = _rotl(v0, 32)
    v2 = (v2 + v3) & MASK64
    v3 = _rotl(v3, 16)
    v3 ^= v2
    v0 = (v0 + v3) & MASK64
    v3 = _rotl(v3, 21)
    v3 ^= v0
    v2 = (v2 + v1) & MASK64
    v1 = _rotl(v1, 17)
    v1 ^= v2
    v2 = _rotl(v2, 32)
    return v0, v1, v2, v3


def siphash24(key: bytes, data: bytes) -> int:
    """Standard SipHash-2-4 (2 compression rounds/block, 4 finalization
    rounds). See module docstring for the external-reference-vector
    validation this is checked against.
    """
    if len(key) != 16:
        raise ValueError(f"SipHash key must be 16 bytes, got {len(key)}")
    k0 = int.from_bytes(key[0:8], "little")
    k1 = int.from_bytes(key[8:16], "little")
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    b = len(data)
    end = b - (b % 8)
    for off in range(0, end, 8):
        m = int.from_bytes(data[off:off + 8], "little")
        v3 ^= m
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0 ^= m

    last = bytearray(8)
    last[0:b - end] = data[end:b]
    last[7] = b & 0xFF
    m = int.from_bytes(bytes(last), "little")
    v3 ^= m
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def contrib(position: int, byte_value: int) -> int:
    if not (0 <= position < N_POSITIONS):
        raise ValueError(position)
    if not (0 <= byte_value < N_BYTE_VALUES):
        raise ValueError(byte_value)
    msg = bytes([byte_value, position, 0, 0, 0, 0, 0, 0])
    return siphash24(KEY_SERIAL, msg)


def name_target(name: str) -> int:
    return siphash24(KEY_NAME, name.encode("ascii"))


def verify(name: str, code_hex: str) -> bool:
    """Independent re-check of the real keygenme's actual validation
    equation -- code_hex must decode to exactly 16 bytes."""
    code = bytes.fromhex(code_hex)
    if len(code) != N_POSITIONS:
        raise ValueError(f"code must decode to {N_POSITIONS} bytes, got {len(code)}")
    total = 0
    for i, b in enumerate(code):
        total = (total + contrib(i, b)) & MASK64
    return total == name_target(name)


# ---------------------------------------------------------------------------
# Wagner k-tree solver (the completing breakthrough over the earlier MITM).
#
# The accept equation is a modular subset-sum: choose one byte per position so
# that sum_i contrib(i, code[i]) == name_target(name)  (mod 2**64). The earlier
# scripts_keygenme3_mitm.py validated the algorithm but a plain 2-list meet-in-
# the-middle needs 256**8 (~2**64) per half at real scale and never completed.
#
# Wagner's generalized-birthday k-tree solves it in ~2**16 time/space: pair up
# the 16 positions into 8 "super-lists" of 256*256 = 2**16 partial sums each,
# fold the target -T into one super-list, then merge LSB-first in 16-bit slices
# (level 1: low16==0, level 2: bits[16:32]==0, level 3: bits[32:48]==0), and at
# the final level pick the entry whose top 16 bits are also 0 -- a full 64-bit
# zero, i.e. a selection summing to T. Modular addition is carry-safe built
# LSB-first because each already-zeroed low slice contributes no carry upward
# and every real carry is retained in the stored 64-bit running sum.
def wagner_keygen(name: str, cap: int = 300_000, pairing=None):
    """Return a 32-hex-char code string that verify(name, code) accepts, or
    None if this pairing/pass found no collision (call again with a different
    pairing -- see keygen). ``pairing`` is a permutation of the 16 positions
    whose consecutive pairs form the 8 super-lists; reshuffling it gives an
    independent k-tree and thus an independent chance of a final collision (a
    single pass succeeds for ~5/6 of targets, so a few reshuffles are certain)."""
    target = name_target(name)
    tab = [[contrib(i, b) for b in range(N_BYTE_VALUES)] for i in range(N_POSITIONS)]
    if pairing is None:
        pairing = list(range(N_POSITIONS))

    def superlist(j, fold):
        pa, pb = pairing[2 * j], pairing[2 * j + 1]
        ta, tb = tab[pa], tab[pb]
        out = []
        for b0 in range(N_BYTE_VALUES):
            base = (ta[b0] - fold) & MASK64
            for b1 in range(N_BYTE_VALUES):
                out.append(((base + tb[b1]) & MASK64, {pa: b0, pb: b1}))
        return out

    lists = [superlist(j, target if j == 0 else 0) for j in range(8)]

    def merge(a_list, b_list, shift):
        bucket = {}
        for s, ch in b_list:
            bucket.setdefault((s >> shift) & 0xFFFF, []).append((s, ch))
        res = []
        for s, ch in a_list:
            need = (-((s >> shift) & 0xFFFF)) & 0xFFFF
            for s2, ch2 in bucket.get(need, ()):
                total = (s + s2) & MASK64
                if ((total >> shift) & 0xFFFF) == 0:
                    res.append((total, {**ch, **ch2}))
                    if len(res) >= cap:
                        return res
        return res

    m01 = merge(lists[0], lists[1], 0)
    m23 = merge(lists[2], lists[3], 0)
    m45 = merge(lists[4], lists[5], 0)
    m67 = merge(lists[6], lists[7], 0)
    m0123 = merge(m01, m23, 16)
    m4567 = merge(m45, m67, 16)
    final = merge(m0123, m4567, 32)
    for total, ch in final:
        if ((total >> 48) & 0xFFFF) == 0:  # full 64-bit sum == target
            code = bytes(ch[p] for p in range(N_POSITIONS))
            code_hex = code.hex()
            if verify(name, code_hex):  # independent re-check via the sum equation
                return code_hex
    return None


def keygen(name: str, max_attempts: int = 24):
    """Robust wrapper: retry the k-tree with reshuffled position pairings until
    a collision is found. The first attempt uses the natural pairing (so a given
    name maps to a stable code); subsequent attempts use deterministic Fisher-
    Yates shuffles seeded by the attempt index, each an independent k-tree, which
    makes finding a collision effectively certain within a handful of tries."""
    import random

    code_hex = wagner_keygen(name)
    if code_hex is not None:
        return code_hex
    for attempt in range(1, max_attempts):
        rng = random.Random(attempt)
        pairing = list(range(N_POSITIONS))
        rng.shuffle(pairing)
        code_hex = wagner_keygen(name, pairing=pairing)
        if code_hex is not None:
            return code_hex
    return None


if __name__ == "__main__":
    import sys
    who = sys.argv[1] if len(sys.argv) > 1 else "Liebert"
    ch = keygen(who)
    print(f"name={who!r}  code={ch}  verify={verify(who, ch) if ch else False}")
