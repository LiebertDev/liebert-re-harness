"""A bounded VB6 P-Code interpreter, driven entirely by `tools_vb6_pcode`'s own output.

`GAP-051`/`CAND-010` established that a P-Code procedure decodes into a listing
with names -- `PUSH_LOCAL_ADDRESS`, `CALL_THROUGH_LITERAL`, `rtcHexVarFromVar`
-- but a listing is not a value. `WNL-T2-077`'s acceptance test at `0x403276`
compares two strings, and the only way to know what either one actually IS is
to execute the bytecode with real inputs. That is what this module does: it
walks the real control flow (`GOTO`, `BRANCH_IF_WORD_ZERO`) of one decoded
procedure, maintaining a stack and a frame keyed by signed 16-bit offset, and
calls real Python implementations of the runtime helpers the procedure invokes.

**This module owns no opcode table.** Every instruction it executes carries a
`semantics` name, a `calls` hint, or a `calls_runtime` name that came from
`vb6_pcode`'s own reading of the installed runtime's handler blocks -- see
`tools_vb6_pcode.py`'s module docstring for how those names are derived. A
hardcoded table here would rot the moment a different runtime build or a
different target used opcodes this file had never seen; reading the name off
the tool's output is what keeps this generic.

**Two calling conventions were settled by reading the runtime, not by guessing,
and are recorded in `benchmarks/windows_native_ladder/results/tier2/WNL-T2-077.md`
(2026-08-30 onward):**

* A `CALL_THROUGH_LITERAL` instruction's second 16-bit operand is the argument
  BYTE COUNT a stdcall callee pops (`operand // 4` gives the argument count,
  not a stack offset) -- read from the handler's own `mov edi, esp; add edi,
  operand; ...; call eax; cmp edi, esp` continuation. An `rtc*` helper's FIRST
  argument is its result, passed BY REFERENCE: the value on top of the VM
  stack right before the call is the destination frame slot, and the
  remaining `operand // 4 - 1` values below it are the source arguments, in
  REVERSE of VB's own source order (stdcall pushes right to left).
* `p1/0x30` and `p1/0x3d` are handlers whose entire body is a call to
  `__vbaStrComp` -- no operand-shape classifier ever named them because they
  carry no operand at all, just a fixed pop-two-and-call. `0x30` pushes VB
  `True` when the strings are equal, `0x3d` when they are not.

**What this deliberately does not do.** It does not model VB6's Variant type
tags, object references, or COM lifetime (`Set`/`Release`); frame slots hold
plain Python `str`/`int` values and a `Ref` is a slot number PLUS the frame
dict it targets (see below for why the frame identity matters once calls can
nest). Two real ambiguities were found and are handled by stopping rather
than guessing: `_handler_semantics`'s shape matcher names an opcode from a
CONTIGUOUS PREFIX of its handler, so a handler that starts with the exact
bytes of `PUSH_LOCAL_ADDRESS` and then keeps going (`__vbaVarCat`'s handler is
exactly this) carries BOTH a `semantics` name and a `calls` hint on the same
instruction -- `calls` is treated as authoritative when both are present,
since a direct runtime call is never a coincidental prefix match. And a
handful of arithmetic/comparison shapes (`COMPARE_STACK_TOP`,
`INCREMENT_THROUGH_POINTER` when it classifies as a conditional branch) name
what their PREFIX does without saying which relational predicate the full
handler applies, which this interpreter cannot execute correctly without
guessing -- so it halts on them exactly as it halts on a wholly unnamed
opcode.

**Following a `CALL_THROUGH_LITERAL` into the target's own code (2026-08-31).**
`GAP-051` measured that every reachable `CALL_THROUGH_LITERAL` in
`WNL-T2-077`'s `Sub Main` whose literal is not a named MSVBVM60 export
resolves to an address INSIDE the target's own image. Disassembling those
addresses directly (never guessed) found two distinct compiler-emitted stub
shapes sharing the same 12 bytes -- `mov edx, imm32; mov ecx, imm32; jmp ecx`
-- distinguished only by which MSVBVM60 export the `ecx` thunk ultimately
reaches:

* `ecx` thunks to `ProcCallEngine` -- this is a call into another P-Code
  procedure IN THE SAME TARGET, and `edx` is that procedure's own descriptor
  address (`0x401974` for `WNL-T2-077`'s stub at `0x4012ac`). Confirmed by
  disassembling `ProcCallEngine` itself out of the installed `MSVBVM60.DLL`:
  its prologue does `mov eax, [edx]; pop ecx; ...; push [eax+0x10]; push ecx;
  push ebp; mov ebp, esp`. The stub reaches `ProcCallEngine` with `jmp`, not
  `call`, so `pop ecx` recovers the return address the ORIGINAL `call eax` in
  the CALL_THROUGH_LITERAL handler itself pushed -- no new stack frame is
  interposed. Working through that sequence by hand: `[ebp+0x0C]` ends up
  holding whichever value the CALLER most recently pushed before the
  `CALL_THROUGH_LITERAL` executed. Independently corroborated (not merely
  derived): `WNL-T2-077`'s own callee at descriptor `0x401974` reads its
  first parameter with `PUSH_LOCAL_VALUE` at offset `0x0C`. So: pop
  `count = operand // 4` values off the SHARED vm stack (same `count` rule as
  a runtime helper's argument count, see above), UNDEREFERENCED -- a `Ref`
  stays a `Ref`, which is what makes a ByRef parameter alias the caller's own
  local rather than receive a copy -- and place `popped[i]` at the callee's
  fresh frame offset `0x0C + 4*i`. There is no destination slot the way an
  `rtc*` helper has one; a callee that returns a value leaves it on the
  SHARED stack itself before its own terminator, exactly like a
  `_DIRECT_HELPERS` call already does, so nothing extra needs modelling for
  that direction.
* `ecx` thunks to `DllFunctionCall` -- a `Declare ... Lib` call to a REAL,
  non-P-Code DLL function (`WNL-T2-077`'s own first `CALL_THROUGH_LITERAL`,
  at `0x4019ab`, is exactly this: `kernel32!GetSystemInfo`, read out of the
  descriptor `DllFunctionCall` itself is handed at `0x4015f8`). This
  interpreter does not execute native code, so this halts with a specific,
  named reason distinct from "unresolved".

Any other shape at that address, or a thunk naming neither export, halts as
`"unrecognised_stub"`/`"unrecognised_call_target"` rather than being guessed
at. A call-depth cap (`max_call_depth`, `DEFAULT_MAX_CALL_DEPTH`) bounds
recursion; decoded callees are cached by descriptor address
(`_make_call_resolver`'s `cache`) since the same handful of procedures is
called repeatedly.
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from typing import Any

import liebert_re.tools.vb6_pcode as pcode

DEFAULT_MAX_STEPS = 20000
DEFAULT_MAX_CALL_DEPTH = 16

TARGET = (
    "benchmarks/windows_native_ladder/corpus/tier2/son_console2_revised/"
    "extracted/inner/SoN Console CrackMe 2.exe"
)
SUB_MAIN_DESCRIPTOR = "0x403a7c"


class InterpreterHalt(Exception):
    """The interpreter reached something it will not guess at.

    Raised for an opcode with no `semantics`/`calls`/`calls_runtime` and a
    `kind` that is not `terminator`/`operand_list`, for a helper name this
    module has not implemented, for a call whose literal target does not
    resolve to a named helper, and for a conditional branch whose predicate
    is not one of the two verified branch shapes (`GOTO`, `BRANCH_IF_WORD_ZERO`).
    """


class VBRuntimeError(Exception):
    """An error the TARGET PROGRAM would itself raise, e.g. `Asc("")`.

    This is not a limitation of the interpreter -- it is what running the
    real bytecode with the given inputs actually does, recorded because
    `WNL-T2-077.md` uses exactly this error to show the file-input accept
    path is unreachable.
    """


@dataclass(frozen=True)
class Ref:
    """A frame slot number PLUS the specific frame dict it targets.

    A slot number alone was enough while only one frame was ever live. Once
    a `CALL_THROUGH_LITERAL` can enter another procedure's own bytecode, TWO
    frames are live at once -- the caller's and the callee's -- and a `Ref`
    the caller pushed (a ByRef argument) must keep pointing at the CALLER's
    local even while the callee's frame is `vm.frame`. That aliasing is
    exactly what makes a VB6 ByRef parameter a real alias rather than a copy
    on the actual machine (the callee's positive-offset parameter slots and
    the caller's negative-offset locals are literally the same stack memory);
    carrying the frame dict itself (not a copy) is what preserves it here.
    """
    frame: "dict[int, Any]"
    slot: int


class VM:
    """A stack plus a frame, both holding plain values: `str`, `int`, or `Ref`."""

    def __init__(self, literal_by_index):
        self.stack: list = []
        self.frame: dict[int, Any] = {}
        self.literal_by_index = literal_by_index
        # Call-following state; `execute_instructions` sets these explicitly.
        # Defaulted here too so a bare `VM(...)` (as the low-level unit tests
        # construct) never trips an AttributeError on an unused code path.
        self.steps = 0
        self.max_steps = DEFAULT_MAX_STEPS
        self.resolve_call = None
        self.max_call_depth = DEFAULT_MAX_CALL_DEPTH

    def push(self, value):
        self.stack.append(value)

    def pop(self):
        if not self.stack:
            raise InterpreterHalt("stack underflow")
        return self.stack.pop()

    def deref(self, value):
        """A local's CURRENT value if `value` is a `Ref`; the value itself otherwise.

        Every slot defaults to `0` when read before any write -- confirmed
        against the real target in `WNL-T2-077.md`'s "never assigned" section,
        where four locals handed to `__vbaStrI4` are read once and written
        nowhere, and the value that makes the rest of that section's byte
        counts line up is `Str$(0)`. A `Ref` reads from ITS OWN frame, not
        whichever frame happens to be current -- see the class docstring.
        """
        if isinstance(value, Ref):
            return value.frame.get(value.slot, 0)
        return value


# ---------------------------------------------------------------------------
# VB6 semantics for the runtime helpers this procedure calls. Each function
# takes and returns plain Python values; the by-reference/argument-count
# marshalling around them lives in `_execute_call_through_literal` and
# `_execute_direct_call`, not here, so these can be unit tested directly.

def _vb_str(value):
    """`Str$`/`rtcVarStrFromVar`/`__vbaStrI2`/`__vbaStrI4`: a LEADING SPACE for
    non-negative numbers, no leading space for negative ones (the minus sign
    already occupies that position). This is VB6's own documented behaviour,
    distinct from `CStr`, and is the fact `WNL-T2-077.md`'s "never assigned"
    section leans on: `Str$(0)` is `" 0"`, not `"0"`.
    """
    number = int(value)
    return (" " if number >= 0 else "") + str(number)


def _vb_hex(value):
    """`Hex$`/`rtcHexVarFromVar`: uppercase, no `0x` prefix.

    A negative value is rendered as its two's-complement bit pattern in VB6,
    but which WIDTH (Integer vs. Long) applies depends on the Variant's own
    subtype, which this interpreter's frame does not track. Every negative
    value reaching this helper is rendered as 32-bit two's complement -- the
    wider, Long-sized choice -- documented here rather than silently assumed;
    `WNL-T2-077`'s own `Hex$(667)` = `"29B"` never exercises this branch.
    """
    number = int(value)
    if number < 0:
        number &= 0xFFFFFFFF
    return format(number, "X")


def _vb_chr(value):
    """`Chr$`/`rtcVarBstrFromAnsi`: the ANSI character for a code point."""
    return chr(int(value))


def _vb_asc(value):
    """`Asc`/`rtcAnsiValueBstr`: the code point of a string's first character.

    `Asc("")` raises in real VB6 -- error 5, "Invalid procedure call or
    argument" -- which `WNL-T2-077.md` uses as the evidence that this
    target's file-input accept path can never succeed. Raising here rather
    than returning a placeholder is what lets that evidence carry over into
    an actual run instead of staying a claim about the runtime's behaviour.
    """
    text = str(value)
    if not text:
        raise VBRuntimeError('Asc("") raises VB error 5 (Invalid procedure '
                              'call or argument)')
    return ord(text[0])


def _vb_left(text, count):
    """`Left$`/`rtcLeftCharVar`: the first `count` characters, clamped."""
    n = max(0, int(count))
    return str(text)[:n]


def _vb_right(text, count):
    """`Right$`/`rtcRightCharVar`: the last `count` characters, clamped.

    `count == 0` has to be special-cased: Python's `s[-0:]` means `s[0:]`,
    the WHOLE string, not the empty one `Right$(s, 0)` actually returns.
    """
    n = max(0, int(count))
    text = str(text)
    return text[-n:] if n else ""


def _vb_mid(text, start, length=None):
    """`Mid$`/`rtcMidCharVar`: 1-BASED, both the 2- and 3-argument forms.

    A `start` below 1 raises in real VB6 (error 5); this interpreter mirrors
    that rather than silently clamping it, for the same reason `_vb_asc`
    raises on an empty string -- a wrong answer here would look like a
    result instead of the target's own refusal to run.
    """
    text = str(text)
    index = int(start)
    if index < 1:
        raise VBRuntimeError("Mid$ with start < 1 raises VB error 5")
    index -= 1
    if length is None:
        return text[index:]
    return text[index:index + max(0, int(length))]


def _vb_trim(text):
    """`Trim$`/`rtcTrimVar`: strips leading/trailing SPACE characters only,
    not all whitespace -- VB6's own `Trim$` never touches tabs or newlines.
    """
    return str(text).strip(" ")


def _vb_command():
    """`Command$`/`rtcCommandBstr`: the process command line.

    This interpreter runs no real process and is handed no argv, so this
    returns the empty string -- a stated assumption, not a discovered fact.
    Nothing in the reachable part of `WNL-T2-077`'s `Sub Main` (see the
    module report) currently depends on its value.
    """
    return ""


def _vb_strcat(left, right):
    """`__vbaStrCat`: BSTR concatenation, by value, no destination argument."""
    return str(left) + str(right)


def _vb_varcat(left, right):
    """`__vbaVarCat`: Variant concatenation. Same operation as `_vb_strcat`;
    kept separate because its calling convention differs (the destination is
    encoded in the instruction's own operand, not popped off the stack --
    see `_execute_direct_call`).
    """
    return str(left) + str(right)


def _vb_lenbstr(text):
    """`__vbaLenBstr`: BSTR length in characters."""
    return len(str(text))


def _vb_str_to_ansi(text):
    """`__vbaStrToAnsi`: a BSTR converted to an ANSI byte string.

    Modelled as identity on the character values, which is what it is for the
    Latin-1 range every serial in this corpus uses. Anything above U+00FF would
    lose information here, so the conversion is done explicitly and a character
    that will not encode raises rather than being silently mangled.
    """
    encoded = str(text).encode("latin-1")
    return encoded.decode("latin-1")


# Helpers reached through `CALL_THROUGH_LITERAL` (an `rtc*` name in
# `calls_runtime`), where the by-reference-result/argument-count convention
# in `_execute_call_through_literal` applies.
_LITERAL_HELPERS = {
    "rtcHexVarFromVar": _vb_hex,
    "rtcVarBstrFromAnsi": _vb_chr,
    "rtcVarStrFromVar": _vb_str,
    "rtcAnsiValueBstr": _vb_asc,
    "rtcLeftCharVar": _vb_left,
    "rtcRightCharVar": _vb_right,
    "rtcMidCharVar": _vb_mid,
    "rtcTrimVar": _vb_trim,
    "rtcCommandBstr": _vb_command,
}

# Helpers reached through a dedicated opcode (a `__vba*` name in `calls`),
# where the opcode itself has a FIXED, publicly-documented arity and pops
# straight off the VM stack -- no argument-count operand, no by-reference
# result. `__vbaVarCat` is handled separately: its handler additionally
# carries the destination as a signed 16-bit instruction operand (read
# directly out of the runtime, see `_execute_direct_call`'s docstring).
_DIRECT_HELPERS = {
    "__vbaStrCat": (2, _vb_strcat),
    "__vbaLenBstr": (1, _vb_lenbstr),
    "__vbaStrI2": (1, _vb_str),
    "__vbaStrI4": (1, _vb_str),
    "__vbaStrToAnsi": (1, _vb_str_to_ansi),
}

# `p1/0x30` and `p1/0x3d`: handlers whose entire body is a call to
# `__vbaStrComp`, carrying no operand of their own -- see the module
# docstring. Keyed by (page, opcode-as-hex-string) to match the tool's own
# per-instruction fields exactly, with no table of our own between them.
_STRING_COMPARISONS = {(1, "0x30"): "EQUAL", (1, "0x3d"): "NOT_EQUAL"}


def _header_length(instr):
    return 1 if instr["page"] == 0 else 2


def _operand_i16(instr, byte_offset):
    raw = bytes.fromhex(instr["bytes"])
    start = _header_length(instr) + byte_offset
    return struct.unpack_from("<h", raw, start)[0]


def _operand_u16(instr, byte_offset):
    raw = bytes.fromhex(instr["bytes"])
    start = _header_length(instr) + byte_offset
    return struct.unpack_from("<H", raw, start)[0]


def _operand_i32(instr, byte_offset=0):
    raw = bytes.fromhex(instr["bytes"])
    start = _header_length(instr) + byte_offset
    return struct.unpack_from("<i", raw, start)[0]


def _operand_i8(instr, byte_offset=0):
    raw = bytes.fromhex(instr["bytes"])
    start = _header_length(instr) + byte_offset
    return struct.unpack_from("<b", raw, start)[0]


def _to_i16(value):
    """Truncate to a signed 16-bit value -- the width every P-Code frame
    offset and every `_WORD` opcode's stated operation size actually uses.
    """
    number = int(value) & 0xFFFF
    return number - 0x10000 if number >= 0x8000 else number


def _trunc_div(a, b):
    """Truncate-toward-zero division: what x86 `idiv` does, unlike Python's `//`."""
    quotient = abs(int(a)) // abs(int(b))
    return quotient if (a < 0) == (b < 0) else -quotient


def _literal_text(vm, instr, index):
    """The text of `literal_by_index[index]`.

    Every use site of this helper is a shape the runtime's own handler
    identifies as a BSTR literal (`PUSH_LITERAL`, `PUSH_LITERAL_INDIRECT`,
    `STORE_LITERAL_BSTR`) -- so a missing/`None` table entry is read as the
    empty string rather than an unknown value: `_utf16` in `tools_vb6_pcode`
    returns `None` for a genuinely EMPTY string too (its own `"".join(out)
    or None` cannot tell the two apart), and only for a BSTR-typed literal
    is "no text decoded" indistinguishable from "the text is empty".
    """
    if index not in vm.literal_by_index:
        raise InterpreterHalt("literal index %d is not in the procedure's "
                               "literal table" % index)
    text = vm.literal_by_index[index]
    return text if text is not None else ""


# ---------------------------------------------------------------------------
# Opcode semantics -> VM effect. Each function takes (vm, instr) and returns
# None (advance to the next instruction in program order) -- branch-kind
# instructions are handled separately in `_step`, since only they can change
# control flow.

def _op_push_local_address(vm, instr):
    vm.push(Ref(vm.frame, _operand_i16(instr, 0)))


def _op_push_local_value(vm, instr):
    vm.push(vm.frame.get(_operand_i16(instr, 0), 0))


def _op_push_through_local_pointer(vm, instr):
    """Read a local as a pointer and push what it addresses.

    This is how a P-Code procedure reads a ByRef parameter: the slot holds a
    `Ref` to the caller's local, and the value wanted is the one behind it, not
    the reference itself. `deref` resolves that alias against the frame the
    `Ref` actually targets, which is why `Ref` carries its frame -- during a
    call the caller's frame is no longer `vm.frame`.
    """
    vm.push(vm.deref(vm.frame.get(_operand_i16(instr, 0), 0)))


def _op_push_local_word(vm, instr):
    vm.push(_to_i16(vm.frame.get(_operand_i16(instr, 0), 0)))


def _op_push_immediate_dword(vm, instr):
    vm.push(_operand_i32(instr, 0))


def _op_push_immediate_byte(vm, instr):
    vm.push(_operand_i8(instr, 0))


def _op_push_immediate_word(vm, instr):
    vm.push(_operand_i16(instr, 0))


def _op_push_literal(vm, instr):
    text = instr.get("literal_text")
    if text is None and "literal_index" in instr:
        text = _literal_text(vm, instr, instr["literal_index"])
    if text is None:
        raise InterpreterHalt("PUSH_LITERAL with no literal index or text")
    vm.push(text)


def _op_store_literal_bstr(vm, instr):
    # The tool's own generic literal extraction reads the literal index from
    # the FIRST word after the opcode header, which is correct for
    # `PUSH_LITERAL`/`CALL_THROUGH_LITERAL` but WRONG for this shape: its own
    # handler (`_SEMANTIC_SHAPES`) reads the destination offset first and the
    # literal index second, so `item['literal_index']` (if present at all) is
    # not trustworthy here and the two operands are read directly instead.
    dest = _operand_i16(instr, 0)
    index = _operand_u16(instr, 2)
    vm.frame[dest] = _literal_text(vm, instr, index)


def _op_store_integer_immediate(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = _operand_i16(instr, 2)


def _op_assign_local(vm, instr):
    dest = _operand_i16(instr, 0)
    value = vm.deref(vm.pop())
    vm.push(vm.frame.get(dest, 0))
    vm.frame[dest] = value


def _op_store_variant_push_address(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = vm.deref(vm.pop())
    vm.push(Ref(vm.frame, dest))


def _op_store_variant_typed_operand(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = vm.deref(vm.pop())


def _op_store_variant_word_push_address(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = _to_i16(vm.deref(vm.pop()))
    vm.push(Ref(vm.frame, dest))


def _op_store_local_word(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = _to_i16(vm.deref(vm.pop()))


def _op_pop_to_local_push_address(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = vm.deref(vm.pop())
    vm.push(Ref(vm.frame, dest))


def _op_pop_to_local_guarded(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = vm.deref(vm.pop())


def _op_pop_into_local(vm, instr):
    dest = _operand_i16(instr, 0)
    vm.frame[dest] = vm.deref(vm.pop())


def _op_bstr_out_of_variant(vm, instr):
    vm.push(vm.deref(vm.pop()))


def _op_add_into_stack_top(vm, instr):
    b = vm.deref(vm.pop())
    a = vm.deref(vm.pop())
    vm.push(int(a) + int(b))


def _op_subtract_from_stack_top(vm, instr):
    b = vm.deref(vm.pop())
    a = vm.deref(vm.pop())
    vm.push(int(a) - int(b))


def _op_multiply_stack_top(vm, instr):
    b = vm.deref(vm.pop())
    a = vm.deref(vm.pop())
    vm.push(int(a) * int(b))


def _op_signed_divide(vm, instr):
    b = vm.deref(vm.pop())
    a = vm.deref(vm.pop())
    vm.push(_trunc_div(a, b))


def _op_widen_word_to_dword(vm, instr):
    vm.push(_to_i16(vm.deref(vm.pop())))


def _op_increment_through_pointer(vm, instr):
    target = vm.pop()
    if not isinstance(target, Ref):
        raise InterpreterHalt("INCREMENT_THROUGH_POINTER popped a non-reference")
    target.frame[target.slot] = int(target.frame.get(target.slot, 0)) + 1


def _op_set_byref_flag_on_stack_top(vm, instr):
    # Peeks the pointer on top of stack and sets a Variant type flag this
    # interpreter does not model; a no-op here leaves the stack exactly as
    # the real handler leaves the pointer, which is the only observable
    # effect this module tracks.
    pass


def _op_release_local_object_guarded(vm, instr):
    pass  # object lifetime is not modelled; nothing this module reads changes.


def _op_set_current_object_from_local_guarded(vm, instr):
    pass  # `With` object binding; not modelled for the same reason.


_SEMANTIC_HANDLERS = {
    "PUSH_LOCAL_ADDRESS": _op_push_local_address,
    "PUSH_LOCAL_VALUE": _op_push_local_value,
    "PUSH_LOCAL_WORD": _op_push_local_word,
    "PUSH_THROUGH_LOCAL_POINTER": _op_push_through_local_pointer,
    "PUSH_IMMEDIATE_DWORD": _op_push_immediate_dword,
    "PUSH_IMMEDIATE_BYTE": _op_push_immediate_byte,
    "PUSH_IMMEDIATE_WORD": _op_push_immediate_word,
    "PUSH_LITERAL": _op_push_literal,
    "PUSH_LITERAL_INDIRECT": _op_push_literal,
    "STORE_LITERAL_BSTR": _op_store_literal_bstr,
    "STORE_INTEGER_IMMEDIATE": _op_store_integer_immediate,
    "ASSIGN_LOCAL": _op_assign_local,
    "STORE_VARIANT_PUSH_ADDRESS": _op_store_variant_push_address,
    "STORE_VARIANT_TYPED_OPERAND": _op_store_variant_typed_operand,
    "STORE_VARIANT_WORD_PUSH_ADDRESS": _op_store_variant_word_push_address,
    "STORE_LOCAL_WORD": _op_store_local_word,
    "STORE_LOCAL_WORD_AT_OFFSET": _op_store_local_word,
    "POP_TO_LOCAL_PUSH_ADDRESS": _op_pop_to_local_push_address,
    "POP_TO_LOCAL_GUARDED": _op_pop_to_local_guarded,
    "POP_INTO_LOCAL": _op_pop_into_local,
    # Only when `kind != "branch"` -- `_step` checks `kind == "branch"` FIRST
    # and never consults this dict for that case, which is exactly the
    # ambiguous shape the module docstring carves out (a conditional-branch
    # classification of this same semantics name, whose predicate is not
    # stated). The non-branch shape's own effect IS fully stated by its
    # handler (`inc word ptr [popped-pointer]`) and was already implemented
    # in `_op_increment_through_pointer`; it was simply never wired in here.
    "INCREMENT_THROUGH_POINTER": _op_increment_through_pointer,
    "BSTR_OUT_OF_VARIANT": _op_bstr_out_of_variant,
    "BSTR_OUT_OF_VARIANT_INDEXED": _op_bstr_out_of_variant,
    "ADD_INTO_STACK_TOP": _op_add_into_stack_top,
    "SUBTRACT_FROM_STACK_TOP": _op_subtract_from_stack_top,
    "SUBTRACT_STACK_TOP": _op_subtract_from_stack_top,
    "MULTIPLY_STACK_TOP": _op_multiply_stack_top,
    "SIGNED_DIVIDE": _op_signed_divide,
    "DIVIDE_WORD": _op_signed_divide,
    "WIDEN_WORD_TO_DWORD": _op_widen_word_to_dword,
    "SET_BYREF_FLAG_ON_STACK_TOP": _op_set_byref_flag_on_stack_top,
    "RELEASE_LOCAL_OBJECT_GUARDED": _op_release_local_object_guarded,
    "SET_CURRENT_OBJECT_FROM_LOCAL_GUARDED": _op_set_current_object_from_local_guarded,
}

# Semantics names this module recognises but deliberately does not execute,
# because the shape names only a PREFIX of the handler and the rest of its
# behaviour (which relational predicate, which object member) is not stated
# by the tool. Listed explicitly so a halt on one of these says WHY, instead
# of looking identical to a wholly unrecognised opcode.
_KNOWN_BUT_UNMODELLED = {
    "COMPARE_STACK_TOP": "names a comparison but not which relational operator "
                          "the full handler applies",
    "PUSH_INDIRECT_LOCAL_OFFSET_GUARDED": "object/member access; this "
                                          "interpreter has no object model",
    "NARROW_TO_WORD_CHECKED": "the overflow check itself is not modelled",
    "FOR_STEP_OVERFLOW_TRAP": "FOR-loop step arithmetic; not exercised by "
                              "Sub Main's construction and not modelled",
}


def _call_argument_count(instr):
    """`operand // 4`: the byte count a `CALL_THROUGH_LITERAL` callee pops.

    Read from the handler's own continuation (`mov edi, esp; add edi,
    operand; ...; call eax; cmp edi, esp`), not from a guess -- see the
    module docstring and `WNL-T2-077.md`'s "Corrected, from the handler
    rather than from a guess" section.
    """
    return _operand_u16(instr, 2) // 4


def _execute_call_through_literal(vm, instr, kind_by_index=None, depth=0):
    """Two shapes share this opcode -- see the module docstring's 2026-08-31
    section for how each was verified, never guessed:

    * `calls_runtime` names an MSVBVM60 helper: `popped[0]` (the value most
      recently pushed) is a BYREF DESTINATION, and the remaining
      `count - 1` popped values are dereferenced and handed to the Python
      implementation in VB's own source order (the reverse of pop order).
    * no `calls_runtime`, but the literal resolves (via `vm.resolve_call`) to
      a call into the TARGET's own code: every popped value is a genuine
      argument -- there is no destination slot -- placed UNDEREFERENCED
      (a `Ref` stays a `Ref`, preserving ByRef aliasing) into the callee's
      fresh frame at offset `0x0C + 4*i`.
    """
    helper_name = instr.get("calls_runtime")
    count = _call_argument_count(instr)
    if helper_name is not None:
        helper = _LITERAL_HELPERS.get(helper_name)
        if helper is None:
            raise InterpreterHalt("unimplemented helper %r" % helper_name)
        if count < 1:
            raise InterpreterHalt("CALL_THROUGH_LITERAL with no destination operand")
        popped = [vm.pop() for _ in range(count)]
        destination = popped[0]
        if not isinstance(destination, Ref):
            raise InterpreterHalt("call destination is not a frame reference")
        # `popped[1:]` is in STACK order (last source argument first); VB's own
        # source order is the reverse, per stdcall's right-to-left push.
        source_order = list(reversed(popped[1:]))
        values = [vm.deref(value) for value in source_order]
        result = helper(*values)
        destination.frame[destination.slot] = result
        return

    literal_value = instr.get("literal_value")
    resolution = None
    if literal_value is not None and vm.resolve_call is not None:
        resolution = vm.resolve_call(int(str(literal_value), 0))
    if resolution is None or resolution.get("kind") != "internal_call":
        kind = resolution.get("kind") if resolution else None
        detail = resolution.get("detail") if resolution else None
        extra = ""
        if kind:
            extra += ", kind=%r" % kind
        if detail:
            extra += ", detail=%r" % detail
        raise InterpreterHalt(
            "CALL_THROUGH_LITERAL's literal does not resolve to a named "
            "runtime helper (literal_index=%r, literal_value=%r%s)"
            % (instr.get("literal_index"), literal_value, extra))
    if depth + 1 > vm.max_call_depth:
        raise InterpreterHalt(
            "call depth limit (%d) reached calling descriptor %s"
            % (vm.max_call_depth, hex(resolution["descriptor_address"])))
    popped = [vm.pop() for _ in range(count)]
    callee_frame = {}
    for i, value in enumerate(popped):
        # UNDEREFERENCED: a `Ref` the caller pushed for a ByRef argument must
        # stay a `Ref` so a write inside the callee is visible to the caller.
        callee_frame[0x0C + 4 * i] = value
    by_offset = {item["offset"]: item for item in resolution["instructions"]}
    saved_frame, saved_literals = vm.frame, vm.literal_by_index
    vm.frame, vm.literal_by_index = callee_frame, resolution["literal_by_index"]
    _run_from(vm, by_offset, kind_by_index, resolution["start_offset"], depth + 1)
    vm.frame, vm.literal_by_index = saved_frame, saved_literals


def _execute_direct_call(vm, instr):
    name = instr["calls"]
    if name == "__vbaVarCat":
        # Read directly out of the runtime (see the module docstring): this
        # handler's destination is its OWN instruction operand, not a popped
        # reference, and it leaves that destination's address on the stack
        # afterward (`push edi` both before AND after the inner `call`).
        destination = _operand_i16(instr, 0)
        right = vm.deref(vm.pop())
        left = vm.deref(vm.pop())
        vm.frame[destination] = _vb_varcat(left, right)
        vm.push(Ref(vm.frame, destination))
        return
    entry = _DIRECT_HELPERS.get(name)
    if entry is None:
        raise InterpreterHalt("unimplemented helper %r" % name)
    arity, helper = entry
    popped = [vm.pop() for _ in range(arity)]
    values = [vm.deref(value) for value in reversed(popped)]
    vm.push(helper(*values))


def _execute_string_comparison(vm, mode):
    right = vm.deref(vm.pop())
    left = vm.deref(vm.pop())
    equal = str(left) == str(right)
    result = equal if mode == "EQUAL" else not equal
    vm.push(-1 if result else 0)  # VB6 True is -1, False is 0.


def _step(vm, instr, kind, kind_by_index=None, depth=0):
    """Execute one instruction. Returns a target offset for a branch taken,
    `"RETURN"` for a terminator, or `None` to fall through to the next
    instruction in program order.

    `kind_by_index` and `depth` matter ONLY for a `CALL_THROUGH_LITERAL` that
    turns out to be a call into the target's own code -- everything else
    ignores them, which is why the low-level unit tests can still call this
    (or `_execute_call_through_literal` directly) without supplying either.
    """
    if kind == "terminator":
        return "RETURN"
    if kind == "operand_list":
        # The variable-length prologue `_decode` already classifies and
        # sizes separately (see `tools_vb6_pcode.py`); its own effect --
        # almost certainly frame/error-handler bookkeeping the string
        # algorithm this module cares about never reads -- is not modelled.
        return None

    direct_call = instr.get("calls")
    semantics = instr.get("semantics")

    if kind == "branch":
        if semantics == "GOTO":
            return instr["branch_target_offset"]
        if semantics == "BRANCH_IF_WORD_ZERO":
            value = vm.deref(vm.pop())
            if _to_i16(value) == 0:
                return instr["branch_target_offset"]
            return None
        raise InterpreterHalt(
            "conditional branch with an unverified predicate (semantics=%r)"
            % semantics)

    # `calls` takes priority over `semantics`: a handler whose PREFIX happens
    # to match a push/store shape but whose full body calls a runtime helper
    # (confirmed for `__vbaVarCat`, see the module docstring) is a call, not
    # the shorter shape the prefix alone would suggest.
    if direct_call is not None:
        _execute_direct_call(vm, instr)
        return None
    if semantics == "CALL_THROUGH_LITERAL":
        _execute_call_through_literal(vm, instr, kind_by_index, depth)
        return None

    key = (instr["page"], instr["opcode"])
    if key in _STRING_COMPARISONS:
        _execute_string_comparison(vm, _STRING_COMPARISONS[key])
        return None

    if semantics in _SEMANTIC_HANDLERS:
        _SEMANTIC_HANDLERS[semantics](vm, instr)
        return None

    if semantics in _KNOWN_BUT_UNMODELLED:
        raise InterpreterHalt("%s: %s" % (semantics,
                                          _KNOWN_BUT_UNMODELLED[semantics]))

    raise InterpreterHalt("no semantics, no helper, kind=%r" % kind)


class _Propagate(Exception):
    """Carries a finished (non-`RETURN`) result dict up through however many
    nested `CALL_THROUGH_LITERAL` calls are on the Python call stack, so it
    becomes the OVERALL result unchanged -- with the address and reason of
    whichever instruction, at whatever depth, actually produced it, not the
    calling instruction's.
    """
    def __init__(self, result):
        super().__init__(result.get("status"))
        self.result = result


def _run_from(vm, by_offset, kind_by_index, offset, depth):
    """The instruction-stepping loop, usable at ANY call depth: depth 0 for
    the outermost procedure `execute_instructions` starts, deeper for every
    nested call `_execute_call_through_literal` follows into the target's
    own code. Returns the `RETURNED` result dict on a clean return; raises
    `_Propagate` for everything else.
    """
    while True:
        vm.steps += 1
        if vm.steps > vm.max_steps:
            raise _Propagate({"ok": False, "status": "STEP_LIMIT_REACHED",
                              "offset": offset, "steps": vm.steps,
                              "call_depth": depth, "frame": dict(vm.frame)})
        instr = by_offset.get(offset)
        if instr is None:
            raise _Propagate({"ok": False, "status": "ADDRESS_NOT_DECODED",
                              "offset": offset, "steps": vm.steps,
                              "call_depth": depth, "frame": dict(vm.frame)})
        kind = kind_by_index.get(instr["index"], "unknown")
        try:
            outcome = _step(vm, instr, kind, kind_by_index, depth)
        except InterpreterHalt as halt:
            raise _Propagate({"ok": False, "status": "HALTED", "reason": str(halt),
                              "offset": instr["offset"], "index": instr["index"],
                              "page": instr["page"], "opcode": instr["opcode"],
                              "address": instr.get("address"), "steps": vm.steps,
                              "call_depth": depth, "frame": dict(vm.frame)}) from None
        except VBRuntimeError as error:
            raise _Propagate({"ok": False, "status": "VB_RUNTIME_ERROR",
                              "reason": str(error), "offset": instr["offset"],
                              "address": instr.get("address"), "steps": vm.steps,
                              "call_depth": depth, "frame": dict(vm.frame)}) from None
        if outcome == "RETURN":
            return {"ok": True, "status": "RETURNED", "offset": instr["offset"],
                    "address": instr.get("address"), "steps": vm.steps,
                    "frame": dict(vm.frame)}
        offset = outcome if isinstance(outcome, int) else offset + instr["length"]


def execute_instructions(instructions, kind_by_index, literal_by_index,
                         start_offset, max_steps=DEFAULT_MAX_STEPS,
                         resolve_call=None, max_call_depth=DEFAULT_MAX_CALL_DEPTH):
    """Run a decoded instruction list from `start_offset`. The pure core.

    Kept separate from `run_procedure` (which drives the real tool and a
    real target) so it can be unit tested against small, synthetic
    instruction lists with no corpus and no installed VB6 runtime required.

    `resolve_call`, when given, is asked ONLY for a `CALL_THROUGH_LITERAL`
    whose literal is not a named runtime helper:
    `resolve_call(literal_value: int) -> dict | None`. `None` means "nothing
    known about this address" and halts exactly as it always did before this
    parameter existed. A dict needs a `"kind"` key -- `"internal_call"` (with
    `"descriptor_address"`, `"instructions"`, `"literal_by_index"` and
    `"start_offset"` for the callee) to be followed, recursively, on the
    SAME `vm.stack` and a FRESH `vm.frame`; any other `"kind"` halts with a
    specific reason instead of the generic unresolved one. Leaving
    `resolve_call` at its default keeps this function needing no corpus, no
    installed runtime and no PE parsing to test, exactly as before call-
    following was added. `max_call_depth` bounds recursion so a cyclic call
    graph halts instead of hanging or exhausting the real Python call stack.
    """
    by_offset = {item["offset"]: item for item in instructions}
    vm = VM(literal_by_index)
    vm.steps = 0
    vm.max_steps = max_steps
    vm.resolve_call = resolve_call
    vm.max_call_depth = max_call_depth
    try:
        return _run_from(vm, by_offset, kind_by_index, start_offset, depth=0)
    except _Propagate as propagated:
        return propagated.result


def _decode_procedure(path, descriptor_address, runtime_path="", max_instructions=6000):
    """Decode one procedure -- its instructions, its OWN literal table (each
    procedure has a different one; see `tools_vb6_pcode`'s
    `literal_table_va`), and its entry offset. No execution.

    Shared by `run_procedure`'s top-level call and every recursive call
    `_make_call_resolver`'s closure makes for a callee reached through
    `CALL_THROUGH_LITERAL`, so a callee's own bytecode is read the exact same
    way regardless of how the interpreter got to it.
    """
    procedure = json.loads(pcode.vb6_pcode(
        path=path, operation="procedure", descriptor_address=hex(descriptor_address),
        runtime_path=runtime_path, max_instructions=max_instructions,
        max_chars=1 << 24))
    if not procedure.get("ok"):
        return {"ok": False, "status": procedure.get("status") or procedure.get("error"),
                "detail": procedure}

    literals_result = json.loads(pcode.vb6_pcode(
        path=path, operation="literals", descriptor_address=hex(descriptor_address),
        runtime_path=runtime_path, max_instructions=1024, max_chars=1 << 22))
    literal_by_index = {}
    if literals_result.get("ok"):
        for entry in literals_result.get("entries", []):
            literal_by_index[entry["index"]] = entry.get("text")

    image_base = int(procedure["image_base"], 16)
    start_offset = int(procedure["start_address"], 16) - image_base
    return {"ok": True, "instructions": procedure["instructions"],
            "literal_by_index": literal_by_index, "start_offset": start_offset,
            "image_base": procedure["image_base"], "path": procedure["path"]}


def _ansi_cstring(stream, base, va, limit=64):
    """A NUL-terminated ANSI string at `va` -- what a `Declare ... Lib`
    stub's own descriptor holds for its DLL and function names (plain 8-bit
    C strings, unlike the literal table's UTF-16LE, confirmed by reading
    `WNL-T2-077`'s own descriptor at `0x4015f8`: `b"kernel32\\0"` then
    `b"GetSystemInfo\\0"`). `None` on anything not readable or not printable
    ASCII, the same discipline `tools_vb6_pcode._utf16` applies.
    """
    offset = va - base
    if not 0 <= offset < len(stream):
        return None
    out = bytearray()
    while len(out) < limit and offset < len(stream):
        byte = stream[offset]
        if byte == 0:
            break
        if not (0x20 <= byte < 0x7F):
            return None
        out.append(byte)
        offset += 1
    return out.decode("ascii") if out else None


def _resolve_internal_call_stub(stream, base, literal_value, thunks):
    """Classify a `CALL_THROUGH_LITERAL` literal that is NOT a named MSVBVM60
    export -- i.e. an address inside the TARGET's own image -- by reading the
    actual bytes there. Never a guess: both shapes below were found by
    disassembling `WNL-T2-077`'s own stubs (see the module docstring), byte
    for byte, not inferred from a general pattern.

    * `mov edx, imm32; mov ecx, imm32; jmp ecx`
      (`BA imm32; B9 imm32; FF E1`, 12 bytes) whose `ecx` thunk resolves (via
      `thunks`, the target's own import-thunk-VA -> name map, e.g.
      `tools_vb6_pcode._import_thunks`'s return value) to `ProcCallEngine`:
      a call into another P-Code procedure in this same target -- `edx` is
      that procedure's own descriptor address.
    * `mov eax, [imm32]; or eax, eax; je +2; jmp eax; push imm32;
      mov eax, imm32; call eax; jmp eax`
      (`A1 imm32; 0B C0; 74 02; FF E0; 68 imm32; B8 imm32; FF D0; FF E0`,
      25 bytes -- the lazily-cached-pointer trampoline VB6 emits for a
      `Declare ... Lib` statement) whose second `imm32` thunk resolves to
      `DllFunctionCall`: a call into a REAL, non-P-Code DLL function, which
      this interpreter does not execute. The first `push imm32` is the
      address of a small descriptor structure whose first two DWORDs point
      to the DLL name and the function name as plain ANSI C strings --
      `WNL-T2-077`'s own first `CALL_THROUGH_LITERAL` (`0x4019ab`) is
      exactly this, resolving to `kernel32!GetSystemInfo`.

    Returns `None` only when `literal_value` cannot be read at all (outside
    the mapped image). A recognised-but-different shape, or a thunk this
    module cannot name, is still a dict -- with `"kind"` naming what it is --
    rather than `None`, so a halt built from it says WHY rather than looking
    like a wholly unresolved address.
    """
    offset = literal_value - base
    if not 0 <= offset < len(stream):
        return None

    if offset <= len(stream) - 12:
        raw = stream[offset:offset + 12]
        if raw[0] == 0xBA and raw[5] == 0xB9 and raw[10:12] == b"\xff\xe1":
            descriptor = struct.unpack_from("<I", raw, 1)[0]
            thunk = struct.unpack_from("<I", raw, 6)[0]
            name = thunks.get(thunk)
            if name == "ProcCallEngine":
                return {"kind": "internal_call", "descriptor_address": descriptor}
            return {"kind": "unrecognised_call_target",
                    "detail": "stub's jmp target is %s, not ProcCallEngine"
                              % (name if name else hex(thunk))}

    if offset <= len(stream) - 25:
        raw = stream[offset:offset + 25]
        if (raw[0] == 0xA1 and raw[5:7] == b"\x0b\xc0" and raw[7] == 0x74
                and raw[9:11] == b"\xff\xe0" and raw[11] == 0x68
                and raw[16] == 0xB8 and raw[21:23] == b"\xff\xd0"
                and raw[23:25] == b"\xff\xe0"):
            descriptor_va = struct.unpack_from("<I", raw, 12)[0]
            thunk = struct.unpack_from("<I", raw, 17)[0]
            if thunks.get(thunk) == "DllFunctionCall":
                dll_va = _dword_at(stream, base, descriptor_va)
                func_va = _dword_at(stream, base, descriptor_va + 4)
                dll = _ansi_cstring(stream, base, dll_va) if dll_va is not None else None
                func = _ansi_cstring(stream, base, func_va) if func_va is not None else None
                target_name = "%s!%s" % (dll or "?", func or "?")
                return {"kind": "declare_external", "target": target_name,
                        "detail": "Declare...Lib call to %s; native code, not "
                                  "P-Code, is not executed by this interpreter"
                                  % target_name}

    return {"kind": "unrecognised_stub",
            "detail": "not a recognised call-stub shape"}


def _dword_at(stream, base, va):
    offset = va - base
    if not 0 <= offset <= len(stream) - 4:
        return None
    return struct.unpack_from("<I", stream, offset)[0]


def _make_call_resolver(stream, base, thunks, decode_fn, cache):
    """Build the `resolve_call` callback `execute_instructions` calls for a
    `CALL_THROUGH_LITERAL` whose literal is not a named runtime helper.

    `decode_fn(descriptor_address: int)` must return a `_decode_procedure`-
    shaped dict; it is called AT MOST ONCE per descriptor address -- the
    result is memoized in `cache` (keyed by descriptor, the same dict
    `run_procedure` seeds with its own top-level decode) since a
    construction routine like `WNL-T2-077`'s calls the same handful of
    procedures repeatedly, and decoding is the expensive part (a real
    `vb6_pcode` call, not a dict lookup).
    """
    def resolve(literal_value):
        classification = _resolve_internal_call_stub(stream, base, literal_value, thunks)
        if classification is None or classification.get("kind") != "internal_call":
            return classification
        descriptor = classification["descriptor_address"]
        if descriptor not in cache:
            cache[descriptor] = decode_fn(descriptor)
        decoded = cache[descriptor]
        if not decoded.get("ok"):
            return {"kind": "decode_failed", "detail": decoded}
        return {"kind": "internal_call", "descriptor_address": descriptor,
                "instructions": decoded["instructions"],
                "literal_by_index": decoded["literal_by_index"],
                "start_offset": decoded["start_offset"]}
    return resolve


def run_procedure(path, descriptor_address, runtime_path="",
                  max_steps=DEFAULT_MAX_STEPS, max_instructions=6000,
                  max_call_depth=DEFAULT_MAX_CALL_DEPTH, start_address=None):
    """Decode one procedure with `vb6_pcode` and execute it from its entry.

    `start_address` overrides where execution begins, which is how a region of
    interest is reached when the procedure's own entry halts earlier on
    something out of scope -- WNL-T2-077 opens with a `Declare...Lib` call to
    `kernel32!GetSystemInfo`, so its serial construction is unreachable from the
    entry no matter how much P-Code is modelled. A mid-procedure start has no
    prior stack or frame, so what it produces is a partial run by construction
    and must be read as one.

    This is the only function here that touches the tool, the target file,
    or the installed runtime -- everything downstream is `execute_instructions`,
    driven purely by what `vb6_pcode` and `_build_table` reported. Its
    `resolve_call` closure (`_make_call_resolver`) is what lets that pure
    core follow a `CALL_THROUGH_LITERAL` into the target's OWN code.
    """
    descriptor = int(str(descriptor_address), 0)
    procedure_cache = {}

    def decode_fn(address):
        return _decode_procedure(path, address, runtime_path, max_instructions)

    decoded = decode_fn(descriptor)
    procedure_cache[descriptor] = decoded
    if not decoded.get("ok"):
        return {"ok": False, "status": decoded.get("status"), "detail": decoded.get("detail")}

    # `kind` (terminator/operand_list/branch/...) is not carried on a
    # per-instruction basis in `procedure`'s own JSON -- only on the
    # runtime's full opcode table, which `_build_table` already derived and
    # cached. Reusing it here is reading the tool's own output a second way,
    # not building an opcode table of this module's own.
    runtime_file = pcode._runtime_path(runtime_path)
    runtime = pcode._Runtime(runtime_file)
    table = pcode._build_table(runtime)
    kind_by_index = {entry["index"]: entry["kind"] for entry in table["entries"]}

    resolve_call = None
    try:
        target = pcode.safe_path(path)
        base, stream = pcode._image(target)
        thunks = pcode._import_thunks(target, pcode._runtime_exports(runtime_file))
        resolve_call = _make_call_resolver(stream, base, thunks, decode_fn, procedure_cache)
    except Exception:
        # Antivirus removes corpus binaries in waves on this host, and a
        # malformed/partial read from `pefile` is not this interpreter's
        # concern to diagnose -- either way, every CALL_THROUGH_LITERAL just
        # halts exactly as it did before this capability existed, not a crash.
        resolve_call = None

    start_offset = decoded["start_offset"]
    if start_address is not None:
        wanted = int(str(start_address), 0)
        match = next((i for i in decoded["instructions"]
                      if int(i["address"], 16) == wanted), None)
        if match is None:
            return {"ok": False, "status": "START_ADDRESS_NOT_DECODED",
                    "detail": "no decoded instruction at %s" % hex(wanted)}
        start_offset = match["offset"]

    result = execute_instructions(decoded["instructions"], kind_by_index,
                                  decoded["literal_by_index"], start_offset,
                                  max_steps=max_steps, resolve_call=resolve_call,
                                  max_call_depth=max_call_depth)
    result["image_base"] = decoded["image_base"]
    result["path"] = decoded["path"]
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else TARGET
    descriptor = argv[1] if len(argv) > 1 else SUB_MAIN_DESCRIPTOR
    result = run_procedure(path, descriptor)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
