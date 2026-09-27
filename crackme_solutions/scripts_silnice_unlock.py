"""WNL-T2-007 "silnice" -- reimplement its unlock check and generate valid codes.

The target is 7 KB of hand-written x86 with a `.protect` section that is
writable, executable, and encrypted in layers. Nothing here is guessed: the
encrypted payload is read from the binary's own bytes and every step below is the
arithmetic the program performs, with the address it performs it at.

**The shape of the check.** The unlock code is `XXXX-XXXX-XXXX-XXXX` over the
alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890` (the table at `0x401108`; the
window text is read at `0x40226e` into `0x401130`, and the format is enforced by
the WndProc at `0x402296`). There is no comparison against a stored serial. The
code's characters are used to PATCH THE IMMEDIATES of four arithmetic blocks
(`0x403438`, `0x403447`, `0x403456`, `0x403465`, written through the store at
`0x403413`), those blocks produce four register values, and the registers become
the key to a stream cipher that decrypts 182 bytes at `0x403258`.

**Why that is self-validating.** The decrypted bytes are then summed, and the sum
is folded into a call target at `0x4034ea`-`0x403529`:

    target = (((sum XOR 0x3a7e) + 0xc0de) * 0x777) >> 4  -  0x19c667

The program then does `call eax`. Only a running sum of exactly `0x3a7e` makes
that land on `0x0040352c`, which is precisely the end of `.protect` -- so a wrong
code does not print a failure message, it calls into unmapped memory. The correct
codes are the ones whose decryption produces a payload summing to `0x3a7e`, and
that payload is a `DestroyWindow` followed by a `MessageBoxA` reading
"CONGRATULATIONS!" / "You've made it! ... This is being executed from .protect
section :)".

**The sum gate is weaker than the real condition, and that distinction matters.**
Roughly one random code in 400,000 satisfies the sum and therefore reaches the
right call target -- but most of those decrypt to garbage, so executing them
would crash rather than unlock. A genuine key has to reproduce the exact
four-byte stream key; 3,000,000 random codes produced none. So `evaluate`
accepts only when BOTH hold: the program's gate, and the payload actually being
the program's own success code.

Nothing here executes the target. The only thing that runs is this arithmetic.
"""
from __future__ import annotations


MASK = 0xFFFFFFFF
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

# Where the encrypted payload lives, and how much of it there is: 182 bytes at
# 0x403258, decrypted to 0x40352c, which is exactly the end of .protect.
PAYLOAD_VA = 0x403258
PAYLOAD_SIZE = 0xB6
IMAGE_BASE = 0x00400000
ACCEPTED_SUM = 0x3A7E          # the value 0x4034ea XORs against
ACCEPTED_TARGET = 0x0040352C   # where `call eax` at 0x403529 must land
# A string from the payload the program decrypts on success. Used to tell a real
# key from one that merely satisfies the sum -- see `evaluate`.
PAYLOAD_MARKER = b"CONGRATULATIONS!"

TARGET = ("benchmarks/windows_native_ladder/corpus/tier2/silnice/silnice.exe")


def _rol8(value, count):
    count &= 7
    if not count:
        return value & 0xFF
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _signed(value):
    return value - 256 if value > 127 else value


def payload_bytes(path=None):
    """The 182 encrypted bytes, straight out of the target's own image."""
    import pefile

    with open(path or TARGET, "rb") as stream:
        data = stream.read()
    image = pefile.PE(data=data)
    return bytes(image.get_data(PAYLOAD_VA - IMAGE_BASE, PAYLOAD_SIZE))


def evaluate(code, encrypted):
    """Run the program's own arithmetic for one candidate code.

    Returns (accepted, call_target, decrypted) -- or (False, None, None) when the
    code contains a character the translation loop at `0x4033c6` rejects.
    """
    raw = code.encode("ascii")
    if len(raw) != 19:
        return False, None, None

    # 0x4030c0-0x4030cc: a rotate-and-sum over the 19 typed bytes.
    rolling = 0
    for index, byte in enumerate(raw):
        rolling = (rolling + _rol8(byte, (19 - index) & 0x1F)) & MASK

    # 0x403380-0x403395: normalise the low byte, then divide the sum by it and
    # recombine quotient and remainder.
    low = rolling & 0xFF
    spins = 7
    while spins and low == 0:
        low = _rol8(low, 1)
        spins -= 1
    if low == 0:
        edx = 0
    else:
        quotient, remainder = divmod(rolling, low)
        edx = ((remainder << 16) + quotient) & MASK

    # 0x4033c6: each character is looked up in the alphabet and turned into
    # `ch - 0x2d`. A dash maps to zero and is skipped -- which works only because
    # table[0] - 0x14 is itself 0x2d (`0x4033e9`), the author's own trick.
    # `eax` starts at 0x4010f8 and the loop overwrites its LOW BYTE with each
    # translated character in turn, so after the loop it carries the LAST one.
    # That detail matters: it is one of the four values the arithmetic blocks
    # below start from.
    immediates = {}
    eax_low = 0
    for index, byte in enumerate(raw):
        character = chr(byte)
        if character not in ALPHABET and character != "-":
            return False, None, None
        value = (byte - 0x2D) & 0xFF
        eax_low = value
        if value:
            immediates[index] = value

    def group(positions):
        defaults = (0, 0, 0x33, 0x33)
        return [_signed(immediates.get(p, d)) for p, d in zip(positions, defaults)]

    a = group((0, 1, 2, 3))
    b = group((5, 6, 7, 8))
    c = group((10, 11, 12, 13))
    d = group((15, 16, 17, 18))

    # 0x403434-0x40346f: four add/sub blocks whose immediates the code patched.
    ecx = (edx + a[0] - a[1] + a[2] - a[3]) & MASK
    edx = (edx + b[0] - b[1] + b[2] - b[3]) & MASK
    eax = (((0x4010F8 & ~0xFF) | eax_low) + c[0] - c[1] + c[2] - c[3]) & MASK
    ebx = (low + d[0] - d[1] + d[2] - d[3]) & MASK
    ecx ^= edx

    # 0x403471's `je` can never fire: ch is at most 0x1f and no table character
    # is that low, so the multiply path at 0x4034a7 is always taken.
    if ((ecx >> 8) & 0xFF) != raw[18]:
        eax = (eax * edx) & MASK
        eax = (eax - ecx) & MASK
        eax = (eax * ebx) & MASK

    # 0x403338: the stream key comes out of the registers.
    combined = ((ebx + eax) & MASK) >> 16
    rotate = eax & 0xFF
    add_high = (eax >> 8) & 0xFF
    xor_low = combined & 0xFF
    add_low = (combined >> 8) & 0xFF

    decrypted = bytearray()
    total = 0
    for byte in encrypted:
        value = _rol8(byte, rotate)
        value = (value + add_high) & 0xFF
        value ^= xor_low
        value = (value + add_low) & 0xFF
        decrypted.append(value)
        total = (total + value) & MASK

    # 0x4034ea-0x403529: the sum folds into the address `call eax` jumps to.
    folded = total ^ ACCEPTED_SUM
    target = (((folded + 0xC0DE) * 0x777) & MASK) >> 4
    target = (target - 0x19C667) & MASK
    decrypted = bytes(decrypted)

    # The program's own gate is only the sum, and a 32-bit sum landing on one
    # value is not the same thing as the key being right: some codes reach the
    # correct call target while decrypting to garbage, and executing that would
    # crash rather than unlock. So acceptance here requires BOTH -- the gate the
    # program checks, and the payload actually being the program's own success
    # code. `PAYLOAD_MARKER` is a string out of that payload, so nothing is
    # hardcoded that the binary does not contain.
    return (target == ACCEPTED_TARGET and PAYLOAD_MARKER in decrypted,
            target, decrypted)


def accepts(code, encrypted=None):
    accepted, _, _ = evaluate(code, encrypted if encrypted is not None else payload_bytes())
    return accepted


# There is deliberately no random keygen here. The program's own gate is only the
# 32-bit sum, and roughly one random code in 400,000 satisfies it -- but most of
# those decrypt to garbage and would crash rather than unlock, so the sum is not
# the validity criterion. A real key must reproduce the exact four-byte stream
# key, which random search does not reach: 3,000,000 random codes were tried in
# 279 seconds and produced ZERO. The accepted code below came from a
# constructive solve (a meet-in-the-middle over the admissible register values
# and per-group sum tables), which is recorded in this entry's write-up. Anyone
# extending this should start there rather than from a search.
ACCEPTED_CODE = "AA96-X0X0-1Z0X-P0Z0"


def main():
    encrypted = payload_bytes()
    for code in (ACCEPTED_CODE,
                 "W3HP-B7N3-DPIC-UQWH",   # satisfies the sum gate, decrypts to garbage
                 "AAAA-AAAA-AAAA-AAAA"):
        accepted, target, decrypted = evaluate(code, encrypted)
        print("%-22s accepted=%-5s call target=%s"
              % (code, accepted, hex(target) if target is not None else None))
        if accepted:
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in decrypted)
            print("    payload: %s" % text[:110])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
