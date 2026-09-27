"""WNL-T2-079 "SoN CrackMe Cubed" -- derive and check its serial statically.

The target is a VB6 program compiled to P-Code: there is no application x86
code, so nothing here is read from a disassembly. Everything is read out of the
program's own bytecode through `vb6_pcode`, and the check is reimplemented from
the opcodes rather than described.

What the binary does (every claim below is anchored to the instruction address
it was read at, in the decode of the two procedures named):

* Procedure `0x409c58` is `f(ByRef S As String) As Boolean`. It first builds
  `S & "-"` (literal 30 at `0x409815`, `__vbaStrCat` at `0x409818`) and compares
  it with `S` itself (`fb30` at `0x409822`). Opcode `0x1c` branches when the
  comparison is FALSE -- its handler is `pop ecx; or cx, cx; je <relocation>` --
  and a string can never equal itself with a character appended, so the branch at
  `0x409824` is ALWAYS taken. Everything between there and `0x409bb1` is
  unreachable: no branch in the procedure targets it (the only five branch
  instructions target `0x409bb1`, `0x409bb1`, `0x409bc1`, `0x409c4c` and
  `0x409c51`). That dead region is where the literal
  `f0ac12637fe916f5449fc93ea63c71c1` is compared (`0x40982a`) and where the
  message "Oops.. you didn't really crack it!" is assembled character by
  character (`0x409863`-`0x409b19`) and shown via `rtcMsgBox`. So that constant
  is a TRAP, not the serial: entering it would have shown the taunt.

* The reachable check, `0x409bb1`-`0x409c51`, is

      acc = 0
      For i = 1 To Len(S)                      ' __vbaLenBstr at 0x409bb9
          acc = acc + (Asc(Mid$(S, i, 1))      ' Mid at 0x409bd8, Asc at 0x409be4
                 Xor  Asc(Mid$(expected, i, 1)))   ' member 0x74 read at 0x409bf5
      Next                                     ' 0x409c2d
      f = ((acc + 12523) = 12523)              ' 0x409c35, 0x409c3b, 0x409c40

  `fb12` at `0x409c11` is the XOR and `0xaa` at `0x409c14` the add; `0xc7` at
  `0x409c40` is integer equality (`sub eax, edx; cmp eax, 1; sbb eax, eax`).
  Every XOR term is a non-negative byte, so the sum is zero exactly when every
  character of `S` matches the corresponding character of `expected`.

* `expected` is the form field at member offset `0x74`. Across all 4,670
  decoded instructions of all 33 procedures, that member is touched exactly
  TWICE: the read above, and a single store at `0x40d1ec` (`fd91 7400`) in
  procedure `0x40d278`. What that store writes is a 32-character string the
  program assembles one character at a time from immediates at
  `0x40cf69`-`0x40d1d1` -- it is in no string table and no literal table, and
  the bytes do not appear anywhere in the file.

This module derives that string from the binary rather than hardcoding it, so
running it proves the derivation and not a transcription.
"""
from __future__ import annotations

import json
from pathlib import Path

TARGET = ("benchmarks/windows_native_ladder/corpus/tier2/son_crackme_cubed/"
          "extracted/inner/SoN CrackMe Cubed.exe")

# The form method that assembles the expected string and stores it into the
# field the check reads.
SETTER_DESCRIPTOR = "0x40d278"
# The constant the check adds to the accumulator and compares against, pushed
# twice as an immediate at 0x409c35 and 0x409c3b.
BIAS = 12523


def expected_serial(target_path=None):
    """Read the expected serial out of the binary's own bytecode.

    Returns the 32-character string that procedure `0x40d278` assembles from
    immediates and stores into member `0x74`, or None if the decode does not
    produce exactly one 32-character run (which would mean the binary is not
    the frozen one this was derived from).
    """
    from tools_vb6_pcode import vb6_pcode

    path = Path(target_path) if target_path else Path(TARGET)
    result = json.loads(vb6_pcode(path=str(path), operation="procedure",
                                  descriptor_address=SETTER_DESCRIPTOR,
                                  max_instructions=6000, max_chars=3000000))
    if not result.get("ok"):
        return None
    runs = [run["text"] for run in result["assembled_strings"]
            if len(run["text"]) == 32]
    if len(runs) != 1:
        return None
    return runs[0]


def accepts(candidate, expected):
    """Reimplementation of procedure 0x409c58's reachable check.

    Faithful to the bytecode, including its weaknesses: the loop runs
    `Len(candidate)` times, not `Len(expected)` times, so a PREFIX of the
    expected serial also sums to zero and is accepted. A candidate longer than
    the expected string makes VB6's `Mid$` return "" and `Asc("")` raise
    runtime error 5, which is modelled here as a rejection rather than an
    acceptance.
    """
    total = 0
    for index, character in enumerate(candidate):
        if index >= len(expected):
            return False  # Asc("") -> VB6 runtime error 5
        total += ord(character) ^ ord(expected[index])
    return (total + BIAS) == BIAS


def main():
    expected = expected_serial()
    if expected is None:
        print("could not derive the expected serial from the binary")
        return 1
    print("expected serial (read from the bytecode): %s" % expected)
    print("accepts(expected)          =", accepts(expected, expected))
    print("accepts(decoy f0ac...)     =",
          accepts("f0ac12637fe916f5449fc93ea63c71c1", expected))
    print("accepts(one char changed)  =",
          accepts("0" + expected[1:], expected))
    print("accepts(a 16-char prefix)  =", accepts(expected[:16], expected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
