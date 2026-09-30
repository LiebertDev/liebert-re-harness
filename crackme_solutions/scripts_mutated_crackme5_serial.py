"""WNL-T2-002 "mutated crackme 5/10" -- run its own check and read its own answer.

This target does not reward a reimplementation. Its control flow is mutated three
ways at once -- hundreds of opaque predicates (`mov rX,rY; or rX,1; or rX,rX;
jne`), API calls resolved by constant arithmetic instead of by name, and, most
awkwardly, **every `cmp` replaced by mixed boolean-arithmetic flag synthesis**:
ZF/SF/OF/CF/AF/PF are computed bit by bit into a register, shifted, loaded with
`sahf`, and branched on. That is why both decompilers and the harness's own
`cfg_deobfuscate` report no comparisons -- there genuinely are none in the
instruction stream.

So the check is verified by running it rather than by rewriting it. `emulate_range`
maps the image in a sandboxed unicorn CPU in a separate process, redirects the
import table to Python stand-ins, serves the candidate on a synthetic console, and
returns whatever the program writes back. The target is never executed on this
host.

**What the program does with a serial** (addresses from the static trace, which
the emulation then confirms end to end):

* `0x140023c32` resolves `GetStdHandle(STD_INPUT_HANDLE)` and `0x140023f16` the
  output handle -- both through the constant-arithmetic pattern, both landing on
  real import thunks in `0x140003000`-`0x140003220`.
* `0x14002461f` prints `Enter serial (XXXX-YYYY-ZZZZ): ` and `0x140024c50` reads
  the line.
* Three gates then decide. Gate 1 (`0x14000e070`) requires the arithmetic sum of
  the first group's four characters to be `0xf0`. Gate 2 (`0x14001207d`) packs the
  low nibble of each character of the second group and requires `0x15b7`. Gate 3
  (`0x140016739`) is a 16-bit hash over the whole serial that must equal `0x5ac3`.
* `0x14002c3e0` writes `Krasavchik bro` or `Fail`.

The `/RTC` stack-variable descriptor at `0x140003330` names the locals the gates
use -- `g1`, `g2`, `g3`, `seed`, `seed2` -- which is the group layout recovered
from a table rather than from a decompiler.
"""
from __future__ import annotations

import json

TARGET = "benchmarks/windows_native_ladder/corpus/tier2/mutated_crackme5/Demo.mut.exe"
CHECK_ENTRY = "0x140023ba0"

ACCEPTED_CODE = "<<<<-15K7-A9eg"
SUCCESS_TEXT = "Krasavchik bro"
FAILURE_TEXT = "Fail"

# Gate constants, each read at the address that compares against it.
GATE1_SUM = 0xF0        # 0x14000e070: sum of group 1's four characters
GATE2_NIBBLES = 0x15B7  # 0x14001207d: low nibbles of group 2, packed
GATE3_HASH = 0x5AC3     # 0x140016739: 16-bit hash over the whole serial


def run(code, path=None, max_instructions=40_000_000, timeout_seconds=240):
    """Feed one candidate to the program's own check and return what it prints."""
    try:
        from tools_emulate_range import emulate_range
    except ImportError as exc:
        raise RuntimeError(
            "This solution script documents an analysis that used a harness component "
            "(tools_emulate_range) which is not part of the public release, so run() "
            "cannot execute here as-is. The recovered algorithm in this file is the "
            "documentation; the entry point is not runnable.") from exc

    stdin = (code + "\r\n").encode("ascii", "replace").hex()
    result = json.loads(emulate_range(
        path=str(path or TARGET), operation="call", start_address=CHECK_ENTRY,
        stdin_hex=stdin, synthetic_environment=True,
        max_instructions=int(max_instructions),
        timeout_seconds=int(timeout_seconds), max_chars=30_000))
    return result


def accepts(code, path=None):
    result = run(code, path=path)
    if not result.get("ok"):
        return False
    return SUCCESS_TEXT in (result.get("output_text") or "")


def main():
    for label, code in (("accepted", ACCEPTED_CODE),
                        ("also accepted", "<<<<-15K7-A9fD"),
                        ("gates 1 and 2 only", "<<<<-15;7-A9eg"),
                        ("wrong", "AAAA-AAAA-AAAA")):
        result = run(code)
        text = (result.get("output_text") or "").strip()
        print("%-20s %-16r -> %s" % (label, code, text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
