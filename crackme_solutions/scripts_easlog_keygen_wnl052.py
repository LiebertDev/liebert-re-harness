"""WNL-T2-052 ("crackMe", easlog): the key hash, transcribed and verified, and a keygen.

The entry's record said `main` reads no input. It does -- through `std::cin`,
inside `FUN_140015120`, the same function whose return value is the integer
after `Result: `. That function reads one token into a `std::string`, copies
it into a `std::vector<char>`, hashes it with `FUN_140014800` into exactly
32 alphanumeric characters, and compares those against a constant in
`.rdata` at `0x140051230`: `XSpuwQqtoGlPRUgwtw0rqldqozERMvko`. Equal means
`Result: 1`.

The hash (`hash32`), read from the disassembly and bound to the target's own
`Result:` verdict under `emulate_range` by `tests/test_easlog_keygen_wnl052.py`:

1. `S = norm(sum(input) - len(input) + 256)`.
2. Pad the input up to a power-of-two length `L` (>= 64, and at least 64
   padding characters): `v[i] = norm(v[i] * S * i + 256)` for `i = 1 .. P`,
   appended in place, so late padding characters read earlier ones.
3. Fold pairwise sums until 32 integers remain.
4. Output character `i` is `norm(fold[i] + 256 + i*i)`.

`norm` is the target's own loop at `0x1400148a0`: while the value is not
`[0-9A-Za-z]`, subtract 47 if it is >= 0x30, else add 24. It is many-to-one,
which is why a preimage is cheap to find and why the search below is a
sampler with a wall-clock bound rather than an enumeration.

Usage:
    python scripts_easlog_keygen_wnl052.py            # find a key
    python scripts_easlog_keygen_wnl052.py --hash TEXT  # hash a candidate
"""
from __future__ import annotations

import random
import sys
import time

TARGET_HASH = b"XSpuwQqtoGlPRUgwtw0rqldqozERMvko"
ALNUM = tuple(c for c in range(0x30, 0x7B) if chr(c).isalnum())
_ALNUM_BITS = 0x7FFFFFE03FF   # the bt mask at 0x140014893: digits and A-Z


def is_alnum(c: int) -> bool:
    c &= 0xFFFFFFFF
    d = (c - 0x30) & 0xFFFFFFFF
    if d <= 0x2A and (_ALNUM_BITS >> d) & 1:
        return True
    return ((c - 0x61) & 0xFFFFFFFF) <= 0x19


def norm_reference(c: int) -> int:
    """The loop exactly as the target runs it (signed compare at 0x1400148bf)."""
    c &= 0xFFFFFFFF
    while not is_alnum(c):
        c = (c - 0x2F) if 0x30 <= c < 0x80000000 else (c + 0x18)
        c &= 0xFFFFFFFF
    return c


_TABLE = tuple(norm_reference(v) for v in range(256))


def norm(c: int) -> int:
    """Closed form: every value >= 0x7b is non-alphanumeric, so the 47-steps
    down to the first value below 0x7b can be taken at once."""
    c &= 0xFFFFFFFF
    if c >= 0x80000000:
        return norm_reference(c)
    if c >= 0x7B:
        c = 0x4C + (c - 0x4C) % 0x2F
    return _TABLE[c]


def _s8(b: int) -> int:
    return b - 256 if b >= 128 else b


def hash32(data: bytes) -> bytes:
    n = len(data)
    if n < 2:
        # The padding loop reads v[i] before it has appended v[n+i-1], so for
        # n < 2 the target itself reads past its vector (the empty case faults
        # at 0x1400148e3). Undefined there, refused here.
        raise ValueError("the target reads past a vector shorter than 2 characters")
    v = list(data)
    ecx = 0x40
    while ecx < n:
        ecx *= 2
    padding = (ecx if (ecx - n) >= 0x40 else 2 * ecx) - n
    seed = norm((sum(_s8(x) for x in v) - n + 0x100) & 0xFFFFFFFF)
    for i in range(1, padding + 1):
        v.append(norm((_s8(v[i]) * seed * i + 0x100) & 0xFFFFFFFF))
    ints = [_s8(x) for x in v]
    while len(ints) != 32:
        ints = [(ints[2 * k] + ints[2 * k + 1]) & 0xFFFFFFFF
                for k in range(len(ints) // 2)]
    return bytes(norm((ints[i] + 0x100 + i * i) & 0xFFFFFFFF) & 0xFF
                 for i in range(32))


def _attempt(rnd: random.Random, target: bytes):
    """One sampled 64-character candidate (L = 128, four characters per output
    character). Blocks are fixed left to right; only the closing character
    of each block is scanned. Returns None when a block cannot be closed."""
    seed = rnd.choice(ALNUM)
    inp = [0] * 64
    pad = [0] * 64

    def padc(k):
        return norm(inp[k + 1] * seed * (k + 1) + 0x100)

    def ok_block(i):
        return norm(sum(inp[4 * i:4 * i + 4]) + 0x100 + i * i) == target[i]

    def ok_pad(m):
        return norm(sum(pad[4 * m:4 * m + 4]) + 0x100 + (16 + m) ** 2) == target[16 + m]

    def close_block(i):
        for _ in range(200):
            inp[4 * i + 1], inp[4 * i + 2] = rnd.choice(ALNUM), rnd.choice(ALNUM)
            choices = []
            for c in ALNUM:
                inp[4 * i + 3] = c
                if ok_block(i):
                    choices.append(c)
            if choices:
                inp[4 * i + 3] = rnd.choice(choices)
                return True
        return False

    inp[0] = rnd.choice(ALNUM)
    if not close_block(0):
        return None
    for k in range(3):
        pad[k] = padc(k)
    for m in range(15):
        for _ in range(200):
            choices = []
            for c in ALNUM:
                inp[4 * m + 4] = c
                pad[4 * m + 3] = padc(4 * m + 3)
                if ok_pad(m):
                    choices.append(c)
            if choices:
                break
            if not close_block(m):
                return None
            for k in range(4 * m, 4 * m + 3):
                pad[k] = padc(k)
        else:
            return None
        inp[4 * m + 4] = rnd.choice(choices)
        pad[4 * m + 3] = padc(4 * m + 3)
        if m + 1 < 15:
            if not close_block(m + 1):
                return None
            for k in range(4 * m + 4, 4 * m + 7):
                pad[k] = padc(k)
    # Block 15 closes both its own output and the last padding block, whose
    # fourth character is derived from pad[0].
    for _ in range(3000):
        inp[61], inp[62] = rnd.choice(ALNUM), rnd.choice(ALNUM)
        pad[60], pad[61] = padc(60), padc(61)
        pad[63] = norm(pad[0] * seed * 64 + 0x100)
        choices = []
        for c in ALNUM:
            inp[63] = c
            pad[62] = padc(62)
            if ok_block(15) and ok_pad(15):
                choices.append(c)
        if choices:
            inp[63] = rnd.choice(choices)
            break
    else:
        return None
    if norm(sum(inp) - 64 + 0x100) != seed:
        return None
    return bytes(inp)


def find_key(target: bytes = TARGET_HASH, *, seed: int = 1, wall_seconds: float = 60.0,
             max_attempts: int = 100_000):
    """A 64-character key whose hash32 is `target`, or None within the bound."""
    rnd = random.Random(seed)
    deadline = time.monotonic() + wall_seconds
    for _ in range(max_attempts):
        if time.monotonic() > deadline:
            return None
        candidate = _attempt(rnd, target)
        if candidate is not None and hash32(candidate) == target:
            return candidate
    return None


def main(argv):
    if len(argv) >= 3 and argv[1] == "--hash":
        print(hash32(argv[2].encode("latin-1")).decode())
        return 0
    key = find_key()
    if key is None:
        print("no key found within the bound")
        return 1
    print(key.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
