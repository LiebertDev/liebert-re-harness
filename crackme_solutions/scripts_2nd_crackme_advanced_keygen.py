"""WNL-T2-071 -- keygen for "2nd CrackMe Advanced" (bilal).

The binary reads the executing machine's CPU identity over WMI
(`Select * from Win32_Processor`, property `processorid`), stores the resulting
string at `[ebx+0x34]`, and passes it by reference to a single function at
`0x40c4a0`. The result is concatenated with `"Here is Your Key : "` and shown to
the user, and is also used as the delimiter in a `Split` at `0x404658`.

`0x40c4a0` is **standard MD5**, and the evidence is the binary's own constants:

* `0x40c590` loads four doubles into the module state at `[0x40d038]+4..+0x10`.
  Decoded they are `0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476` -- the
  MD5 initial state, four for four.
* `0x40a6a0` is the compression function, fully unrolled, and carries all sixty
  four `floor(abs(sin(i)) * 2**32)` round constants as immediates, in order.
* `0x40bd40` is the finalisation: append `0x80`, branch on a tail under 56 or
  under 120 bytes, then write `length * 8` as eight little-endian bytes.
* `0x40a4e0` builds the message as one byte per character,
  `b(i) = CByte(Asc(Mid(s, i + 1, 1)))`.
* `0x40bf40` formats one word by hexing each byte in turn and prefixing `"0"`
  below `0x10` (`rtcHexVarFromVar`, MSVBVM60 ordinal 573); `0x40c320` does that
  for A, B, C and D in order, concatenates, and lower-cases the result
  (`rtcLowerCaseVar`, ordinal 518).

So the key the program displays for a given CPU identity is exactly

    md5(processor_id).hexdigest()

This module reimplements that mapping. It performs no I/O, reads no hardware and
runs nothing: the CPU identity is an input, which is what makes the result
verifiable without executing the target on any particular machine.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct

# The four words 0x40c590 writes into the module state, in the order it writes
# them, and the sixty four round constants unrolled into 0x40a6a0.
MD5_INITIAL_STATE = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
MD5_ROUND_CONSTANTS = tuple(
    int(abs(math.sin(index + 1)) * 2 ** 32) & 0xFFFFFFFF for index in range(64)
)

# Where those constants sit, so a test can confirm the reimplementation is bound
# to this binary rather than to the name "MD5".
INITIAL_STATE_LOADER = 0x40C590
COMPRESSION_FUNCTION = 0x40A6A0
DERIVATION_ENTRY = 0x40C4A0

PROCESSOR_ID_PATTERN = re.compile(r"\A[0-9A-Fa-f]{16}\Z")


def key_for_processor_id(processor_id: str) -> str:
    """Return the key the crackme displays for `processor_id`.

    The argument is the `Win32_Processor.ProcessorId` string as WMI reports it,
    which on real hardware is sixteen uppercase hex digits (`"BFEBFBFF000306A9"`).
    No validation is imposed beyond encodability, because the binary imposes none
    either: `0x40a4e0` takes `Asc()` of each character, so any string the VB6
    runtime can hold is hashed as its ANSI bytes.
    """
    return hashlib.md5(processor_id.encode("latin-1")).hexdigest()


def looks_like_a_processor_id(value: str) -> bool:
    """Whether `value` has the shape WMI reports, for callers that want to warn.

    Deliberately separate from `key_for_processor_id`: the binary accepts
    anything, so refusing an unusual identity here would be this module inventing
    a rule the target does not have.
    """
    return bool(PROCESSOR_ID_PATTERN.match(value))


def message_for_processor_id(processor_id: str) -> str:
    """The full line the program prints, including its own prefix."""
    return "Here is Your Key : " + key_for_processor_id(processor_id)


def initial_state_doubles() -> tuple[bytes, ...]:
    """The four constants as the eight-byte doubles the binary stores.

    VB6 holds the state as `Double`, so `0x40c590` carries each word as a 64-bit
    float that `0x40bd10` converts back to an integer. Rendering them the same way
    here lets a test match the exact bytes at the call site.
    """
    return tuple(struct.pack("<d", float(word)) for word in MD5_INITIAL_STATE)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("processor_id",
                        help="Win32_Processor.ProcessorId, e.g. BFEBFBFF000306A9")
    arguments = parser.parse_args(argv)
    identity = arguments.processor_id
    if not looks_like_a_processor_id(identity):
        print("note: %r is not the sixteen-hex-digit shape WMI usually reports; "
              "hashing it anyway, as the binary does." % identity)
    print(message_for_processor_id(identity))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
