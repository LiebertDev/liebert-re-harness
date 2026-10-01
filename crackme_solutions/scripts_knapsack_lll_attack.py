"""Lagarias-Odlyzko low-density subset-sum attack against WNL-T2-082
"knapsack_decodeme" (GAP-028, Tier2 remediation Phase 5 Priority 5).

Parses the real, frozen `public.dat` (64 little-endian 12-byte/96-bit
weights) and encodes the real target ciphertext from the challenge
author's own stated readme value, then runs the standard construction
through `lll_exact.lll_reduce()`.

Byte-order/target derivation traced directly from the provided
`encoder.ASM` source (not assumed):
  - each public.dat weight[i] is NOT a single 12-byte little-endian
    integer (an earlier version of this module assumed this and was
    WRONG -- see the Phase 5 Priority 5 BKZ/enumeration-follow-up note
    in docs/PROJECT_STATE.md for how this was caught: exhaustive
    enumeration proved, for five different lattice scale factors, that
    no lattice vector of the mathematically-required target norm existed
    at all, which is only possible if the weight/target parsing itself
    is wrong, not the attack). Re-deriving byte-by-byte from
    `calcencode`'s three `mov eax,[edx+N]` / `add`/`adc` instructions
    (`encoder.ASM` lines 93-99): `[edx+8]` (weight bytes 8-11) adds into
    `ciphertextbin+0` (the LOW dword), `[edx+4]` (bytes 4-7) adds into
    `ciphertextbin+4` (the MID dword), `[edx+0]` (bytes 0-3) adds into
    `ciphertextbin+8` (the HIGH dword) -- i.e. the three 4-byte groups
    are each read as a standard little-endian x86 dword individually,
    but the GROUPS themselves are arranged high-to-low in REVERSE file
    order (first 4 file bytes = most significant 32 bits), not as one
    single 96-bit little-endian integer. Correct parse:
    `weight[i] = int.from_bytes(chunk[8:12],'little') | (int.from_bytes(chunk[4:8],'little')<<32) | (int.from_bytes(chunk[0:4],'little')<<64)`.
  - plaintext_int = int.from_bytes(bytes.fromhex(input_string), 'little')
    (traced from the `.loopconvert` byte-pairing logic)
  - ciphertext = sum(weight[i] for i in range(64) if (plaintext_int >> i) & 1)
    (LSB-first bit order, matching the `shr`/`rcr` 64-bit right-shift loop)
  - the displayed/readme hex string is a normal big-endian hex rendering
    of the ciphertext integer (traced from `convertencode`'s low-nibble-
    first-to-rightmost-position byte layout, and confirmed with a
    concrete worked example: a ciphertextbin of 0x42 in the lowest byte
    renders as "...00042" reading left to right) -- i.e.
    target = int(hex, 16) directly, no reversal needed (this half of the
    original derivation was re-checked and confirmed correct).
"""
from __future__ import annotations

from pathlib import Path

from liebert_re.recover.lll_exact import lll_reduce

PUBLIC_DAT_PATH = "benchmarks/windows_native_ladder/corpus/tier2/knapsack_decodeme_blueowl/extracted/inner/public.dat"
TARGET_HEX = "B75B63369A52F5F30CFE5E642"  # from the author's own readme.txt
N_ITEMS = 64
WEIGHT_BYTES = 12


def _weight_from_chunk(chunk: bytes) -> int:
    """chunk is 12 raw bytes for one weight. The real layout (traced from
    encoder.ASM's calcencode, see module docstring) is three individually
    little-endian 32-bit dwords arranged high-to-low in REVERSE file
    order: bytes[0:4] are the most significant 32 bits, bytes[8:12] the
    least significant -- NOT a single 96-bit little-endian integer.
    """
    lo = int.from_bytes(chunk[8:12], "little")
    mid = int.from_bytes(chunk[4:8], "little")
    hi = int.from_bytes(chunk[0:4], "little")
    return lo | (mid << 32) | (hi << 64)


def load_weights(path: str = PUBLIC_DAT_PATH):
    data = Path(path).read_bytes()
    if len(data) != N_ITEMS * WEIGHT_BYTES:
        raise ValueError(f"expected {N_ITEMS * WEIGHT_BYTES} bytes, got {len(data)}")
    return [_weight_from_chunk(data[i * WEIGHT_BYTES:(i + 1) * WEIGHT_BYTES]) for i in range(N_ITEMS)]


def load_target(hex_str: str = TARGET_HEX) -> int:
    return int(hex_str, 16)


def build_basis(weights, target, scale):
    n = len(weights)
    rows = []
    for i in range(n):
        row = [0] * n + [scale * weights[i]]
        row[i] = 2
        rows.append(row)
    rows.append([1] * n + [scale * target])
    return rows


def recover_bits(reduced, weights, target):
    n = len(weights)
    for row in reduced:
        if len(row) != n + 1 or row[-1] != 0:
            continue
        if not all(abs(c) == 1 for c in row[:n]):
            continue
        for bits in (
            [(1 if c == 1 else 0) for c in row[:n]],
            [(1 if c == -1 else 0) for c in row[:n]],
        ):
            if sum(w for w, x in zip(weights, bits) if x) == target:
                return bits
    return None


def attack(scales=(1, 2, 4, 8, 16), dps=250, log=print):
    weights = load_weights()
    target = load_target()
    log(f"loaded {len(weights)} weights, target=0x{target:X} ({target.bit_length()} bits)")
    for scale in scales:
        log(f"--- trying scale={scale} ---")
        basis = build_basis(weights, target, scale)
        reduced = lll_reduce(basis, dps=dps)
        log(f"scale={scale}: LLL reduction complete")
        bits = recover_bits(reduced, weights, target)
        if bits is None:
            log(f"scale={scale}: no verified solution row found")
            continue
        plaintext_int = sum(b << i for i, b in enumerate(bits))
        # The real plaintext string is bytes.fromhex(input_str) read back
        # -- render as the shortest hex string with no leading zero byte
        # pairs (matches how a user would actually type it), falling back
        # to the full 16-hex-digit form.
        raw = plaintext_int.to_bytes(8, "little")
        trimmed = raw.rstrip(b"\x00") if raw.rstrip(b"\x00") else raw[:1]
        log(f"scale={scale}: SOLVED. plaintext_int=0x{plaintext_int:X} candidate_input_hex={trimmed.hex().upper()}")
        return {"scale": scale, "plaintext_int": plaintext_int, "candidate_input_hex": trimmed.hex().upper(), "bits": bits}
    return None
