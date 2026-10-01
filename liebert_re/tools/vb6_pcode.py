"""VB6 P-Code decoding, with the opcode table read out of the VB6 runtime itself.

A P-Code-compiled VB6 executable carries **no application x86 code at all**: the
whole program is a bytecode stream interpreted inside `MSVBVM60.DLL`. Three
targets on this project's Windows ladder are blocked on exactly that
(`WNL-T2-077`, `-079`, `-084`, recorded as GAP-027), and the gap was written up
for a long time as "needs a from-scratch disassembler for an undocumented
format".

It is not undocumented. **The format's authority is the runtime, and the runtime
is installed on the machine.** This module reads it -- statically, with `pefile`
and Capstone; the DLL is never loaded, never executed, and never copied into
this repository -- and derives:

* **the dispatch table**, found by its own structure: the one long run of
  code pointers inside the runtime's `ENGINE` section. It proves itself, because
  the interpreter's own dispatch loop is one of the entries it contains;
* **the page layout**, from the handlers of the prefix opcodes: the table is
  six pages of 256 entries based at `table + 0x400 * page`, and a lead byte of
  `0xFB`-`0xFF` selects a page for the byte that follows;
* **which slots are empty**, and not by frequency alone: the handler that fills
  188 of the 1,351 slots is verified to be the runtime's own error raiser -- it
  pushes a VB error number and calls a routine that ORs it with `0x800A0000`,
  the HRESULT space VB6 runtime errors live in (the number is `0x33`, error 51,
  "Internal error"), so an opcode pointing there really has no implementation;
* **each opcode's instruction length**, from the dispatch site the handler ends
  at. Every dispatch in the runtime has the shape
  `xor eax, eax; mov al, [esi + K]; add esi, K+1; jmp [eax*4 + page]`, so a
  handler states how long its own instruction was. That is a reading, not a
  guess -- and an opcode whose length cannot be reached is reported as unknown
  rather than assumed to be one byte.

It also **names some opcodes without inventing anything**: 147 of the defined
opcodes call a named runtime helper on their handler's own straight line, so a
listing can say `__vbaLenBstr` or `__vbaStrToAnsi` next to a byte -- the same
vocabulary a *native*-compiled VB6 binary shows in its import table. That number
was 375 in a first attempt that read past the interpreter's own
`jmp [eax*4 + table]` and attributed whatever followed in memory, which named
opcode 0 -- the dispatch loop itself -- after a helper it never calls. Stopping
at any unconditional jump costs 228 names and removes the wrong ones.

It also finds a procedure's **literal table** the same way: `ProcCallEngine`
loads it as `*( *(descriptor) + 0x34 )` and keeps it in `[ebp - 0x54]` for the
opcodes that index it, so `operation="literals"` resolves the slots. On
`WNL-T2-077` that yields the program's own text -- `SoN Console CrackMe 2`,
`TopSecretKeyFile.SoN`, `Oh come on... Try!` -- while slots holding code
pointers are reported as addresses rather than dressed up as strings.

**What this does not do, and will not pretend to.** It does not name opcodes.
The runtime carries handlers, not mnemonics, so every opcode here is an index,
a page and a length. The `calls` field is a **hint** about what its handler
transfers to, not a claim about what the opcode means, and a handler that
converges on a shared block can be named after that block's helper. It does not
decompile, and it does not execute anything. A disassembly that runs into an
opcode with no handler stops and says so, because a stream decoded past a wrong
byte is worse than a short one.

Evidence rung: `observed_fact` for the table and for the bytes decoded. What an
instruction *means* is explicitly not established.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from liebert_re.workspace import safe_path, relative

TOOL = "vb6_pcode"
_ALLOWED_OPS = {"runtime_table", "disassemble", "procedure", "literals",
                "program_strings"}

# The runtime an ordinary 32-bit VB6 program binds to. A customer installs it;
# this project neither ships it nor requires this exact path -- `runtime_path`
# overrides it, and its absence is a TOOL_MISSING rather than a crash.
DEFAULT_RUNTIMES = (
    r"C:\Windows\SysWOW64\MSVBVM60.DLL",
    r"C:\Windows\System32\MSVBVM60.DLL",
)

ENGINE_SECTION = b"ENGINE"
PAGE_ENTRIES = 256
PAGE_STRIDE = 4 * PAGE_ENTRIES
FIRST_PREFIX = 0xFB          # 0xFB..0xFF select pages 1..5
# Where ProcCallEngine keeps the running procedure's literal table pointer.
LITERAL_TABLE_SLOT = "[ebp - 0x54]"
# ...and where that pointer comes from: *( *(descriptor) + LITERAL_TABLE_OFFSET ).
LITERAL_TABLE_OFFSET = 0x34
# Where the interpreter keeps the CURRENT PROCEDURE'S OWN bytecode base -- the
# same address `_entry_from_descriptor` computes. A branch opcode's 2-byte
# operand is an offset from this, not from the branch instruction itself.
BYTECODE_BASE_SLOT = "[ebp - 0x58]"
MAX_LITERAL_CHARS = 160
MIN_TABLE_RUN = 200
MAX_INSTRUCTIONS = 4096
# A run of immediate character codes shorter than this is far more likely to be
# ordinary small constants than a string the program is assembling.
MIN_ASSEMBLED_RUN = 6
# One push, its store and the index arithmetic between them; a gap wider than
# this is a different piece of code that happens to share the push opcode.
MAX_ASSEMBLED_GAP = 24


def _j(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _missing(operation, detail, required):
    return _j({"ok": False, "status": "TOOL_MISSING", "tool": TOOL,
               "operation": operation, "detail": detail,
               "required_capability": required})


class _Runtime:
    """A statically-parsed VB6 runtime. Nothing here is executed."""

    def __init__(self, path):
        import pefile

        self.path = Path(path)
        self.sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.pe = pefile.PE(str(self.path), fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = [(s.Name.rstrip(b"\0"), self.base + s.VirtualAddress,
                          s.Misc_VirtualSize, s.get_data(), s.Characteristics)
                         for s in self.pe.sections]
        self.engine = next((s for s in self.sections if s[0] == ENGINE_SECTION), None)
        self.exports = {}
        try:
            self.pe.parse_data_directories()
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    self.exports[self.base + symbol.address] = symbol.name.decode()
        except Exception:  # noqa: BLE001
            self.exports = {}

    def close(self):
        try:
            self.pe.close()
        except Exception:  # noqa: BLE001
            pass

    def _is_code(self, value):
        for _name, va, vsize, data, chars in self.sections:
            if chars & 0x20000000 and va <= value < va + max(vsize, len(data)):
                return True
        return False

    def find_table(self):
        """The dispatch table is the one long run of code pointers in ENGINE.

        Structural, not a signature: nothing else in that section is a few
        hundred consecutive words that all address executable memory."""
        _name, va, _vsize, blob, _chars = self.engine
        best = (0, None)
        run, start = 0, None
        for offset in range(0, len(blob) - 4, 4):
            value = struct.unpack_from("<I", blob, offset)[0]
            if self._is_code(value):
                if run == 0:
                    start = offset
                run += 1
                continue
            if run > best[0]:
                best = (run, start)
            run = 0
        if run > best[0]:
            best = (run, start)
        if best[0] < MIN_TABLE_RUN:
            return None, 0
        return va + best[1], best[0]


def _handlers(runtime, table_va, count):
    _name, va, _vsize, blob, _chars = runtime.engine
    offset = table_va - va
    return [struct.unpack_from("<I", blob, offset + 4 * i)[0] for i in range(count)]


def _branch_shape(recent, write_pos, term_pos):
    """Tell a genuine control-flow branch from an incidental `mov esi, ...`.

    A handful of handlers write `esi` from memory or another register instead
    of only advancing it before dispatch. Most of those are not branches --
    one family uses `esi` as a scratch pointer for a `rep movs` block copy and
    then restores it to keep reading operands linearly. What marks the real
    ones is that they relocate `esi` using the runtime's own bytecode-base
    slot, `[ebp - 0x58]` -- the same address `_entry_from_descriptor` computes
    for a procedure's own entry -- in one of two shapes seen in this runtime:

    * the operand is read directly: `movzx esi, word ptr [esi]`, then a later
      `add esi, [ebp - 0x58]` turns that procedure-relative offset into an
      address. The operand sits at the instruction's own start.
    * the base is loaded verbatim -- `mov esi, [ebp - 0x58]` -- and added to a
      register that was read from `[esi + N]` earlier in the same handler
      (the operand read happens before the relocation, not as part of it).

    Anything else that writes `esi` (a restore after a `rep movs`, for
    instance) returns None and falls back to ordinary length classification.

    Returns (operand_offset, conditional) or None. `conditional` is True when
    a jump earlier in the handler can skip straight past the relocation to
    the merge point the terminal read starts from -- a VB6 "loop, or fall
    through" opcode -- so the caller must follow both paths.
    """
    write = recent[write_pos]
    text = write.op_str

    def _guarded():
        merge_addrs = {insn.address for insn in recent[write_pos:term_pos + 1]}
        for insn in recent[:write_pos]:
            if (insn.mnemonic.startswith("j") and insn.mnemonic != "jmp"
                    and insn.op_str.startswith("0x")
                    and int(insn.op_str, 16) in merge_addrs):
                return True
        return False

    def _offset_in(op_str, prefix):
        if not op_str.startswith(prefix):
            return None
        if "+" not in op_str:
            return 0
        try:
            return int(op_str.split("[esi", 1)[1].split("+", 1)[1].strip(" ]"))
        except (IndexError, ValueError):
            return None

    if BYTECODE_BASE_SLOT.strip("[]") in text:
        register = None
        for insn in recent[write_pos + 1:term_pos]:
            if insn.mnemonic == "add" and insn.op_str.startswith("esi, "):
                register = insn.op_str.split(",", 1)[1].strip()
                break
        if register is None:
            return None
        for insn in reversed(recent[:write_pos]):
            if (insn.mnemonic in ("mov", "movzx", "movsx")
                    and insn.op_str.startswith(register + ", ")
                    and "[esi" in insn.op_str):
                offset = _offset_in(insn.op_str, register + ", ")
                if offset is None:
                    return None
                return offset, _guarded()
        return None
    for prefix in ("esi, word ptr [esi", "esi, dword ptr [esi", "esi, byte ptr [esi"):
        offset = _offset_in(text, prefix)
        if offset is not None:
            return offset, _guarded()
    return None


def _relocation_entry_offset(va, vsize, blob, md, target):
    """Whether `target` is itself the START of a branch-relocation shape.

    Some opcodes -- VB6's IF...THEN, verified on opcode 0x1c -- do not write
    `esi` in their own body at all; instead a plain conditional jump (`je`,
    not the interpreter's own `jmp [eax*4 + table]`) hands control straight to
    the code an unconditional branch opcode (0x1e, here) already runs, before
    this opcode has advanced `esi` past its own operand. That is the same
    relocation `_branch_shape` recognises, just reached by a jump into another
    opcode's handler rather than written inline, so it needs its own check:
    read a few instructions at `target` and look for the same
    read-then-add-the-bytecode-base shape.
    """
    if not (va <= target < va + vsize):
        return None
    insns = list(md.disasm(blob[target - va:target - va + 32], target))
    for pos, insn in enumerate(insns):
        if insn.mnemonic == "jmp" and "*4 + " in insn.op_str:
            return None
        if insn.mnemonic in ("mov", "movzx", "movsx") and insn.op_str.startswith("esi,"):
            text = insn.op_str
            offset = None
            for prefix in ("esi, word ptr [esi", "esi, dword ptr [esi", "esi, byte ptr [esi"):
                if text.startswith(prefix):
                    offset = 0
                    if "+" in text:
                        try:
                            offset = int(text.split("[esi", 1)[1].split("+", 1)[1]
                                         .strip(" ]"))
                        except (IndexError, ValueError):
                            return None
                    break
            if offset is None:
                return None
            for later in insns[pos + 1:pos + 4]:
                if later.mnemonic == "add" and BYTECODE_BASE_SLOT.strip("[]") in later.op_str:
                    return offset
            return None
    return None


def _esi_advance(insns):
    """Sum the `add esi, N` an opcode's handler performs in program order.

    A handler may consume its operand bytes itself and then jump to a shared
    dispatch tail rather than dispatching in its own body. The advance it
    already made belongs to the instruction's length, so it has to survive the
    hop to that tail.
    """
    total = 0
    for insn in insns:
        if insn.mnemonic == "add" and insn.op_str.startswith("esi, "):
            operand = insn.op_str.split(",", 1)[1].strip()
            try:
                total += int(operand, 0)
            except ValueError:
                pass
    return total


def _operand_list_shape(window):
    """Recognise the prologue of a variable-length "operand list" opcode.

    Three MSVBVM60 handlers -- aliased across six table slots -- read a 16-bit
    BYTE COUNT and then loop over that many bytes of 16-bit frame offsets,
    releasing an object or freeing a string for each. Their shape is

        movsx edi, word ptr [esi]   ; edi = N, in bytes
        add   esi, 2
        shr   edi, 1                ; edi = N / 2 elements
        jmp   <loop body>           ; body does `add esi, 2` per element

    so their length is `header + 2 + N` and is NOT readable from the terminal
    dispatch site: that site only ever states the fixed part. Read as a fixed
    length, the loop's per-element `add esi, 2` is counted once and every one of
    them is sized as if its list held a single element -- which desynchronises
    the whole decode from there on. `WNL-T2-079`'s `0x40d278` carries a 314-byte
    list, so the mis-size loses 312 bytes in one instruction.
    """
    loaded = advanced = False
    for insn in window:
        if (insn.mnemonic == "movsx"
                and insn.op_str.endswith(", word ptr [esi]")):
            loaded = True
            continue
        if loaded and insn.mnemonic == "add" and insn.op_str == "esi, 2":
            advanced = True
            continue
        if loaded and advanced and insn.mnemonic == "shr" and insn.op_str.endswith(", 1"):
            return True
        if insn.mnemonic == "jmp":
            break
    return False


def _register_load(insn, va, vsize):
    """Recognise `mov <reg>, <address inside ENGINE>` and return (reg, target).

    Only an immediate that lands inside the interpreter's own code section is
    accepted, so an ordinary constant is never mistaken for a jump target.
    """
    parts = insn.op_str.split(", ")
    if len(parts) != 2 or not parts[1].startswith("0x"):
        return None
    register = parts[0]
    if len(register) != 3 or not register.startswith("e"):
        return None
    try:
        target = int(parts[1], 16)
    except ValueError:
        return None
    if not va <= target < va + vsize:
        return None
    return register, target


def _classify_handler(runtime, handler, table_va, hops=10):
    """Read an opcode's shape off its handler.

    Every dispatch in this interpreter is
    `xor eax, eax; mov al, [esi + K]; add esi, K+1; jmp [eax*4 + page]`,
    so the site the handler ends at states how long the instruction just
    executed was. A handler that instead unwinds the interpreter's frame
    (`mov esp, ebp`, or returns) never dispatches, because it **is** the end of
    a procedure -- page 0's `0x13`-`0x18` are that family. Distinguishing the
    two matters: read as an unknown length, a procedure's last instruction ends
    the disassembly with a complaint instead of a full stop.

    A third family neither advances linearly nor terminates: it relocates
    `esi` to a computed target (see `_branch_shape`) instead of just moving it
    past its own operand bytes, so the walker cannot keep reading the next
    byte in program order -- it has to resolve the target and jump there
    itself. Lengths for these opcodes are read the same way as any other
    (the terminal dispatch site still states how many bytes this instruction
    occupies), but a length alone cannot say WHERE the next instruction is,
    so classification also returns where the 2-byte target operand sits and
    whether the relocation is conditional.

    Returns (kind, length, indexes_literals, branch) where kind is "length",
    "terminator", "branch" or "unknown". `indexes_literals` marks a handler
    that uses its 16-bit operand to index the procedure's literal table --
    the shape `mov edx, [ebp - 0x54]; mov eax, [edx + eax*4]`, where
    `[ebp - 0x54]` is the table pointer `ProcCallEngine` loads on entry.
    `branch` is None unless kind == "branch", in which case it is
    `{"operand_offset": int, "conditional": bool}`.
    """
    import capstone

    _name, va, vsize, blob, _chars = runtime.engine
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    table_prefix = hex(table_va)[:8]
    seen, queue = set(), [(handler, 0, {})]
    while queue and hops:
        current, carried, registers = queue.pop(0)
        if current in seen or not (va <= current < va + vsize):
            continue
        seen.add(current)
        hops -= 1
        recent = []
        indexes = False
        write_pos = None
        registers = dict(registers)
        conditional_targets = []
        window = list(md.disasm(blob[current - va:current - va + 64], current))
        if current == handler and _operand_list_shape(window):
            return "operand_list", None, False, None
        for insn in md.disasm(blob[current - va:current - va + 256], current):
            if insn.mnemonic == "mov" and LITERAL_TABLE_SLOT in insn.op_str:
                indexes = True
            if (write_pos is None
                    and insn.mnemonic in ("mov", "movzx", "movsx")
                    and insn.op_str.startswith("esi,")):
                write_pos = len(recent)
            if insn.mnemonic == "jmp" and "*4 + " + table_prefix in insn.op_str:
                window_start = max(len(recent) - 4, 0)
                term_pos, k = None, None
                for pos in range(len(recent) - 1, window_start - 1, -1):
                    candidate = recent[pos]
                    if (candidate.mnemonic == "mov"
                            and candidate.op_str.startswith("al, byte ptr [esi")):
                        text = candidate.op_str
                        if "+" in text:
                            try:
                                k = int(text.split("+")[1].strip(" ]"))
                            except ValueError:
                                return "unknown", None, indexes, None
                        else:
                            k = 0
                        term_pos = pos
                        break
                if term_pos is None:
                    return "unknown", None, indexes, None
                if write_pos is not None and write_pos <= term_pos:
                    branch = _branch_shape(recent, write_pos, term_pos)
                    if branch is not None:
                        operand_offset, conditional = branch
                        return ("branch", operand_offset + 2 + 1, indexes,
                                {"operand_offset": operand_offset,
                                 "conditional": conditional})
                # A conditional opcode does not always write `esi` in its own
                # body -- VB6's IF...THEN instead jumps straight into another
                # opcode's relocation code (0x1e's, on this runtime) before
                # advancing esi past its own operand at all, when the
                # condition holds. That is invisible to the check above
                # (there is no local `esi` write to find), so a plain
                # conditional jump into a relocation entry point is checked
                # for directly.
                for prior in recent[:term_pos]:
                    if (prior.mnemonic.startswith("j") and prior.mnemonic != "jmp"
                            and prior.op_str.startswith("0x")):
                        offset = _relocation_entry_offset(
                            va, vsize, blob, md, int(prior.op_str, 16))
                        if offset is not None:
                            return ("branch", offset + 2 + 1, indexes,
                                    {"operand_offset": offset, "conditional": True})
                # The terminal dispatch site states the length of the byte it
                # just read (K, plus the 1-byte opcode itself), but a family of
                # handlers consume their operand bytes EARLIER, with an interior
                # `add esi, N` before this terminal read, and dispatch off
                # `[esi]` with K=0. Summing those interior adds (strictly before
                # the terminal read -- the dispatch's own trailing `add esi,
                # K+1` comes after it and must stay excluded) recovers their
                # real length instead of mis-sizing them as one byte.
                interior = carried + _esi_advance(recent[:term_pos])
                return "length", k + 1 + interior, indexes, None
            if ((insn.mnemonic == "mov" and insn.op_str == "esp, ebp")
                    or insn.mnemonic == "ret"):
                # A terminator can still carry operand bytes -- index 0x52f reads
                # two 16-bit operands and does `add esi, 4` before unwinding.
                # Charging it only its opcode byte leaves those operands looking
                # like undecoded tail, which is what the coverage number then
                # reports.
                return ("terminator", None, indexes,
                        {"advance": carried + _esi_advance(recent)})
            # A handler may set up its continuation in a register
            # (`mov edi, <site>` ... `jmp edi`) instead of jumping to a literal
            # address. Without the register's value that indirect jump ends the
            # walk and the opcode is reported as an unknown length, even though
            # the site it names states one.
            if insn.mnemonic == "mov":
                register = _register_load(insn, va, vsize)
                if register is not None:
                    registers[register[0]] = register[1]
            if insn.mnemonic == "jmp" and (insn.op_str in registers
                                           or insn.op_str.startswith("0x")):
                target = (registers[insn.op_str] if insn.op_str in registers
                          else int(insn.op_str, 16))
                # The handler's own continuation goes in FRONT of any conditional
                # target found in this same hop. Both are one hop away, so the
                # queue's insertion order was deciding which stated the length --
                # and a conditional out of a handler leads to its error and
                # special-case code, which states a different one. Opcode 0x54
                # consumes four operand bytes and is five long; read off the
                # null-object error path it came back as six. The conditionals
                # are still followed, just second, because the branch-shape
                # detection depends on them.
                queue.append((target, carried + _esi_advance(recent), registers))
                queue.extend(conditional_targets)
                break
            if insn.mnemonic.startswith("j") and insn.op_str.startswith("0x"):
                conditional_targets.append((int(insn.op_str, 16),
                                            carried + _esi_advance(recent),
                                            registers))
            recent.append(insn)
        else:
            queue.extend(conditional_targets)
    return "unknown", None, False, None


# ---------------------------------------------------------------------------
# Opcode semantics
#
# `_classify_handler` answers "how long is this instruction and where is the
# next one". It says nothing about MEANING, which is why this tool reports
# WHAT_ANY_OPCODE_MEANS as not established -- a decoded procedure comes out as a
# byte stream rather than as a program.
#
# But a handler block is short, and its opening instructions ARE the semantics:
# the runtime reads the operand out of [esi], does one thing with it, and jumps
# back to the dispatch. Recognising those openings names an opcode from the
# runtime's own bytes, on the same footing as the lengths already derived here.
#
# Only exact shapes are matched. Anything else stays unnamed rather than
# becoming a vague label: a wrong name is worse than no name, because a reader
# would trust it. Frame offsets are signed 16-bit and read from [esi]; a "local"
# below always means [<offset> + ebp].

_SEMANTIC_SHAPES = (
    # (name, description, ordered list of instruction-text prefixes to match)
    ("PUSH_LOCAL_ADDRESS", "push the address of a local (ByRef argument)",
     ("movsx {r}, word ptr [esi]", "add {r}, ebp", "push {r}")),
    ("PUSH_THROUGH_LOCAL_POINTER",
     "read a local as a pointer and push the value it addresses -- how a ByRef "
     "parameter is read",
     ("movsx {r}, word ptr [esi]", "mov {r}, dword ptr [ebp + {r}]",
      "push dword ptr [{r}]")),
    ("PUSH_LOCAL_VALUE", "push a local's value",
     ("movsx {r}, word ptr [esi]", "push dword ptr [{r} + ebp]")),
    ("PUSH_LOCAL_WORD", "push a local's low 16 bits",
     ("movsx {r}, word ptr [esi]", "mov {r16}, word ptr [{r} + ebp]", "push {r}")),
    ("PUSH_IMMEDIATE_DWORD", "push a 32-bit immediate",
     ("mov {r}, dword ptr [esi]", "push {r}")),
    ("PUSH_IMMEDIATE_BYTE", "push a sign-extended byte immediate",
     ("movsx {r}, byte ptr [esi]", "push {r}")),
    ("PUSH_LITERAL", "push literal[index] as a value",
     ("movzx {r}, word ptr [esi]", "mov {r2}, dword ptr [ebp - 0x54]",
      "push dword ptr [{r2} + {r}*4]")),
    ("CALL_THROUGH_LITERAL", "call literal[index]; second operand is the argument stack offset",
     ("movzx {r}, word ptr [esi]", "movzx {r2}, word ptr [esi + 2]", "add {r2}, esp",
      "mov {r3}, dword ptr [ebp - 0x54]", "mov {r4}, dword ptr [{r3} + {r}*4]")),
    # The type word is loaded into a 16-bit register before anything binds, so
    # the first line is matched loosely; the four that follow are specific
    # enough that nothing else in the table matches them.
    ("STORE_VARIANT_PUSH_ADDRESS", "store the popped value into a local as a typed Variant, push its address",
     ("mov ", "pop {r2}", "movsx {r3}, word ptr [esi]", "add {r3}, ebp",
      "mov dword ptr [{r3} + 8], {r2}", "mov word ptr [{r3}], ")),
    ("POP_TO_LOCAL_PUSH_ADDRESS", "pop into a local and push its address",
     ("movsx {r}, word ptr [esi]", "add {r}, ebp", "pop dword ptr [{r}]", "push {r}")),
    # The store forms differ in where the Variant's type word comes from and in the
    # width of the value store, which is why one shape does not cover them.
    ("STORE_VARIANT_TYPED_OPERAND",
     "write a Variant into a local: type from the operand, value from the stack",
     ("movsx {r}, word ptr [esi]", "add {r}, ebp", "movzx {r2}, word ptr [esi + 2]",
      "mov {r3}, dword ptr [esp]")),
    ("STORE_INTEGER_IMMEDIATE",
     "store a 16-bit immediate into a local as a type-2 (Integer) Variant",
     ("movsx {r}, word ptr [esi]", "mov word ptr [{r} + ebp], ")),
    ("STORE_VARIANT_WORD_PUSH_ADDRESS",
     "store the popped value as a Variant with a word-sized value, push its address",
     ("mov ", "pop {r2}", "movsx {r3}, word ptr [esi]", "add {r3}, ebp",
      "mov word ptr [{r3} + 8], {r216}", "mov word ptr [{r3}], ")),
    ("STORE_LOCAL_WORD", "pop and store 16 bits into a local",
     ("movsx {r}, word ptr [esi]", "pop {r2}", "mov word ptr [{r} + ebp], {r216}")),
    ("BSTR_OUT_OF_VARIANT", "require a type-8 Variant on the stack and push its BSTR",
     ("pop {r}", "cmp word ptr [{r}], 8")),
    # Arithmetic against the value already on the stack, with an overflow trap.
    ("ADD_INTO_STACK_TOP", "add the popped value into the value below it, trapping overflow",
     ("pop {r}", "add {ptr:esp}, {rany}", "jo ")),
    ("SUBTRACT_FROM_STACK_TOP",
     "subtract the popped value from the value below it, trapping overflow",
     ("pop {r}", "sub {ptr:esp}, {rany}", "jo ")),
    ("MULTIPLY_STACK_TOP", "signed multiplication of the top two stack values",
     ("pop {r}", "pop {r2}", "imul {r}")),
    ("SUBTRACT_STACK_TOP", "subtract the top stack value from the one below it",
     ("pop {r}", "pop {r2}", "sub {r2}, {r}")),
    ("COMPARE_STACK_TOP", "compare the top two stack values",
     ("pop {r}", "pop {r2}", "cmp {r2}, {r}")),
    ("DIVIDE_WORD", "signed 16-bit division of the top two stack values",
     ("pop {r}", "pop {r2}", "cwd", "idiv {rany}")),
    ("INCREMENT_THROUGH_POINTER", "increment the 16-bit value the popped pointer addresses",
     ("movsx {r}, word ptr [esi]", "pop {r2}", "inc word ptr [{r2}]")),
    ("STORE_LOCAL_WORD_AT_OFFSET",
     "pop and store 16 bits into a local, two bytes past its start",
     ("movsx {r}, word ptr [esi]", "pop {r2}", "mov word ptr [{r} + ebp + 2], {r216}")),
    ("POP_INTO_LOCAL", "pop the stack directly into a local",
     ("movsx {r}, word ptr [esi]", "pop dword ptr [{r} + ebp]")),
    ("PUSH_IMMEDIATE_WORD", "push a sign-extended 16-bit immediate",
     ("movsx {r}, word ptr [esi]", "push {r}", "xor ")),
    # Object, control-flow and indirect-access forms, recovered from their handler
    # blocks. The guarded ones raise VB error 91 (object variable not set) when the
    # local they read is Nothing, which is why the null test is part of the shape.
    ("RELEASE_LOCAL_OBJECT_GUARDED",
     "release a local's object reference through vtable[+8] and set it to Nothing, "
     "skipping the call when it is already Nothing",
     ("mov edi, 1", "movsx {r}, word ptr [esi]", "add esi, 2",
      "mov {r2}, dword ptr [{r} + ebp]", "or {r2}, {r2}", "je ")),
    ("SET_CURRENT_OBJECT_FROM_LOCAL_GUARDED",
     "load a local's object pointer into the current-object slot, raising if it is Nothing",
     ("movsx {r}, word ptr [esi]", "add esi, 2", "mov {r}, dword ptr [{r} + ebp]",
      "or {r}, {r}", "je ", "mov dword ptr [ebp - 0x4c], {r}")),
    ("PUSH_INDIRECT_LOCAL_OFFSET_GUARDED",
     "push the dword at (a local's pointer + a second operand), raising if it is null",
     ("movsx {r}, word ptr [esi]", "movzx {r2}, word ptr [esi + 2]",
      "mov {r3}, dword ptr [{r} + ebp]", "or {r3}, {r3}", "je ")),
    ("PUSH_LITERAL_INDIRECT",
     "push literal[index] as a value, in the mov-then-push form",
     ("movzx {r}, word ptr [esi]", "mov {r2}, dword ptr [ebp - 0x54]",
      "mov {r}, dword ptr [{r2} + {r}*4]", "push {r}")),
    ("GOTO", "unconditional branch: set the bytecode pointer to base + operand",
     ("movzx esi, word ptr [esi]", "add esi, dword ptr [ebp - 0x58]")),
    ("SET_BYREF_FLAG_ON_STACK_TOP",
     "set 0x8000 in the 16-bit word the unpopped pointer on top of stack addresses",
     ("mov {r}, dword ptr [esp]", "or word ptr [{r}], 0x8000")),
    ("FOR_STEP_OVERFLOW_TRAP",
     "FOR iterate: add a local's step into the counter the popped pointer addresses, "
     "trapping overflow",
     ("movsx {r}, word ptr [esi]", "pop {r2}", "movsx {r3}, word ptr [{r2}]",
      "add ", "jo ")),
    ("WIDEN_WORD_TO_DWORD", "sign-extend the value on the stack from 16 to 32 bits",
     ("pop {r}", "cwde", "push {r}")),
    ("NARROW_TO_WORD_CHECKED",
     "narrow the value on the stack to 16 bits, raising on overflow",
     # `movsx` is matched loosely because the 16-bit placeholder cannot resolve
     # before the register it derives from is bound; the compare against the
     # popped register and the overflow branch carry the specificity.
     ("pop {r}", "movsx ", "cmp {r}, ", "jne ")),
    ("SIGNED_DIVIDE", "signed integer division of the top two stack values",
     ("pop {r}", "pop {r2}", "cdq", "idiv {r}")),
    ("BRANCH_IF_WORD_ZERO", "pop and branch when the low 16 bits are zero",
     ("pop {r}", "or {r16}, {r16}", "je ")),
    ("STORE_LITERAL_BSTR",
     "store literal[index] into a local as a type-8 (BSTR) Variant",
     ("movsx {r}, word ptr [esi]", "movzx {r2}, word ptr [esi + 2]",
      "mov {r3}, dword ptr [ebp - 0x54]", "mov {r4}, dword ptr [{r3} + {r2}*4]",
      "add {r}, ebp")),
    ("POP_TO_LOCAL_GUARDED", "pop into a local, guarded against a null value",
     ("movsx {r}, word ptr [esi]", "add {r}, ebp", "pop {r2}", "mov {r3}, {r2}",
      "or {r3}, {r3}")),
    ("BSTR_OUT_OF_VARIANT_INDEXED",
     "pop a Variant, require type 8, push its BSTR; the operand names a frame slot",
     ("pop {r}", "mov {r2}, dword ptr [{r} + 8]", "movsx {r3}, word ptr [esi]",
      "cmp word ptr [{r}], 8")),
    ("ASSIGN_LOCAL", "assign a local from the stack, pushing the previous contents first",
     ("movsx {r}, word ptr [esi]", "add esi, 2", "add {r}, ebp", "pop {r2}",
      "push dword ptr [{r}]", "mov dword ptr [{r}], {r2}")),
)

_REGISTERS_32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")
_LOW_16 = {"eax": "ax", "ebx": "bx", "ecx": "cx", "edx": "dx",
           "esi": "si", "edi": "di", "ebp": "bp"}
_SEMANTICS_CACHE = {}


def _matches_shape(texts, shape):
    """Whether `texts` opens with `shape`, with {r...} standing for any register.

    Placeholders bind on first use and must stay consistent afterwards, so a
    shape written with {r} twice only matches when the same register is used
    both times. `{r16}` matches the 16-bit half of whatever `{r}` bound to.
    """
    bindings = {}
    position = 0
    for pattern in shape:
        while True:
            if position >= len(texts):
                return False
            text = texts[position]
            position += 1
            expanded = pattern
            ok = True
            for key in ("{r}", "{r2}", "{r3}", "{r4}"):
                if key not in expanded:
                    continue
                if key in bindings:
                    expanded = expanded.replace(key, bindings[key])
                else:
                    candidate = next((reg for reg in _REGISTERS_32
                                      if expanded.replace(key, reg) in text
                                      or text.startswith(expanded.replace(key, reg))), None)
                    if candidate is None:
                        ok = False
                        break
                    bindings[key] = candidate
                    expanded = expanded.replace(key, candidate)
            if not ok:
                continue
            if "{rany}" in expanded or "{ptr:esp}" in expanded:
                # Either width of the register popped first: 0xa9 adds `ax` into a
                # word on the stack, 0xae adds `eax` into a dword. Same operation,
                # two widths, so the shape must admit both -- but still only that
                # register, which is what stops `add ebx, ecx` from matching. And
                # either width of the memory operand addressing the stack top,
                # written as a placeholder rather than a loose prefix because an
                # unbound `"add "` matched `add ebx, ecx` -- an operation on two
                # unrelated registers -- and the interpreter then executed it as
                # stack arithmetic. An independent review caught that with a direct
                # probe. Both placeholders can appear in the same pattern (`add
                # {ptr:esp}, {rany}`), so they must be resolved together: trying
                # them one at a time left the other's literal braces in the string,
                # which could never match real disassembly text.
                bound = bindings.get("{r}")
                rany_widths = [bound, _LOW_16.get(bound)] if bound else []
                rany_options = [w for w in rany_widths if w] if "{rany}" in expanded else [None]
                ptr_options = (["dword ptr [esp]", "word ptr [esp]", "byte ptr [esp]"]
                               if "{ptr:esp}" in expanded else [None])
                matched = None
                for ptr_width in ptr_options:
                    for rany_width in rany_options:
                        candidate = expanded
                        if ptr_width is not None:
                            candidate = candidate.replace("{ptr:esp}", ptr_width)
                        if rany_width is not None:
                            candidate = candidate.replace("{rany}", rany_width)
                        if text.startswith(candidate):
                            matched = candidate
                            break
                    if matched is not None:
                        break
                if matched is None:
                    ok = False
                else:
                    expanded = matched
            if not ok:
                continue
            for key, source in (("{r16}", "{r}"), ("{r216}", "{r2}")):
                if key in expanded:
                    if source not in bindings:
                        ok = False
                        break
                    expanded = expanded.replace(key, _LOW_16[bindings[source]])
            if ok and text.startswith(expanded):
                break
            # Matching is contiguous. Only the runtime's own bookkeeping may sit
            # between two instructions of a shape -- advancing `esi` past the
            # operand, or padding. Allowing arbitrary gaps made distinct opcodes
            # collide: `pop dword ptr [eax]; push eax` was matched by the plain
            # address-push shape, naming a store as a load.
            if text.startswith("nop"):
                continue
            if text.startswith("add esi,"):
                # Advancing esi is bookkeeping only while no later line of this
                # shape still reads an operand: `[esi + 2]` after an `add esi, 2`
                # addresses a different byte than the shape means. A synthetic
                # handler exploiting exactly that matched CALL_THROUGH_LITERAL
                # before this check existed.
                if any("[esi" in later for later in shape[shape.index(pattern):]):
                    return False
                continue
            return False
    return True


def _handler_semantics(runtime, handler_va, hops=2):
    """Name what an opcode does, read from its handler block.

    Returns (name, description) or (None, None) when the block does not match a
    known shape exactly.

    Several opcodes are a one-line preamble -- typically `mov bx, <Variant type>`
    -- followed by a jump into a body they share with a sibling opcode. Those are
    followed for a hop or two, keeping the preamble's instructions in front of
    the body's so a shape can still match across the join.
    """
    import capstone

    key = (runtime.sha256, handler_va)
    if key in _SEMANTICS_CACHE:
        return _SEMANTICS_CACHE[key]
    _name, va, vsize, blob, _chars = runtime.engine
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    texts, current, remaining = [], handler_va, hops
    while True:
        if not (va <= current < va + vsize):
            break
        target = None
        for insn in md.disasm(blob[current - va:current - va + 0x40], current):
            if insn.mnemonic == "jmp" and insn.op_str.startswith("0x"):
                try:
                    target = int(insn.op_str, 16)
                except ValueError:
                    target = None
                break
            texts.append("%s %s" % (insn.mnemonic, insn.op_str))
            if insn.mnemonic in ("jmp", "ret", "call") or len(texts) >= 14:
                target = None
                break
        if target is None or remaining <= 0:
            break
        current, remaining = target, remaining - 1
    answer = (None, None)
    for name, description, shape in _SEMANTIC_SHAPES:
        if _matches_shape(texts, shape):
            answer = (name, description)
            break
    _SEMANTICS_CACHE[key] = answer
    return answer


def _export_hint(runtime, handler, hops=3):
    """Name an opcode by the runtime helper its handler calls.

    Not an invented mnemonic: `__vbaPrintObj` or `__vbaAryMove` is the name
    Microsoft gave the function this opcode's handler transfers to, and it is
    the same vocabulary a *native*-compiled VB6 binary shows in its import
    table -- so a P-Code listing can be read with the knowledge an analyst
    already has. It names what the handler calls, which is weaker than naming
    what the opcode means, and the field is called a hint for that reason.
    """
    import capstone

    if not runtime.exports:
        return None
    _name, va, vsize, blob, _chars = runtime.engine
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    seen, queue = set(), [handler]
    while queue and hops:
        current = queue.pop(0)
        if current in seen or not (va <= current < va + vsize):
            continue
        seen.add(current)
        hops -= 1
        for insn in md.disasm(blob[current - va:current - va + 192], current):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                target = int(insn.op_str, 16)
                if target in runtime.exports:
                    return runtime.exports[target]
            elif insn.mnemonic == "jmp":
                # Any unconditional jump ends this handler's straight line. A
                # direct one is followed; an indirect one (the interpreter's own
                # `jmp [eax*4 + table]`) is where the handler hands control to
                # the *next* opcode, and reading past it attributes whatever
                # code happens to follow in memory to this opcode. That mistake
                # named opcode 0 -- the dispatch loop itself -- after a helper
                # it never calls.
                if insn.op_str.startswith("0x"):
                    queue.append(int(insn.op_str, 16))
                break
            elif insn.mnemonic == "ret":
                break
    return None


def _is_error_stub(runtime, handler):
    """Check that the slot-filler really is the runtime's \"no such opcode\" path.

    Choosing it by frequency is a heuristic; this turns it into a reading. The
    stub pushes a VB error number and calls a raiser whose body ORs the number
    with `0x800A0000` -- the HRESULT space VB6 runtime errors live in. On
    6.00.9848 the number is `0x33`, which is error 51, \"Internal error\".
    """
    import capstone

    _name, va, vsize, blob, _chars = runtime.engine
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if not (va <= handler < va + vsize):
        return False, None
    pushed = None
    for insn in md.disasm(blob[handler - va:handler - va + 48], handler):
        if insn.mnemonic == "push" and insn.op_str.startswith("0x"):
            pushed = int(insn.op_str, 16)
        elif insn.mnemonic == "call" and insn.op_str.startswith("0x") and pushed is not None:
            target = int(insn.op_str, 16)
            for _name2, va2, vsize2, blob2, _chars2 in runtime.sections:
                if not (va2 <= target < va2 + max(vsize2, len(blob2))):
                    continue
                body = blob2[target - va2:target - va2 + 96]
                for step in md.disasm(body, target):
                    if step.mnemonic == "or" and "0x800a0000" in step.op_str:
                        return True, pushed
                break
            return False, pushed
        elif insn.mnemonic in ("ret", "jmp"):
            break
    return False, pushed


_TABLE_CACHE = {}


def _build_table(runtime):
    """Derive the opcode table, once per runtime.

    Deriving it means disassembling 1,163 handlers, which is not something to
    repeat per procedure -- `program_strings` decodes every procedure a binary
    has, so on a 33-procedure target the uncached cost was paid 33 times. The
    cache key is the runtime's own content hash, so a different DLL still gets
    its own table.
    """
    if runtime.sha256 in _TABLE_CACHE:
        return _TABLE_CACHE[runtime.sha256]
    table = _build_table_uncached(runtime)
    _TABLE_CACHE[runtime.sha256] = table
    return table


def _build_table_uncached(runtime):
    table_va, count = runtime.find_table()
    if table_va is None:
        return None
    handlers = _handlers(runtime, table_va, count)
    # The handler shared by the largest number of entries is the runtime's own
    # "no such opcode" stub; entries pointing at it are undefined slots.
    tally = {}
    for value in handlers:
        tally[value] = tally.get(value, 0) + 1
    undefined_handler = max(tally.items(), key=lambda kv: kv[1])[0]
    is_stub, error_number = _is_error_stub(runtime, undefined_handler)
    entries = []
    for index, handler in enumerate(handlers):
        defined = handler != undefined_handler
        kind, length, indexes, branch = ("undefined", None, False, None)
        semantics, description = None, None
        if defined:
            kind, length, indexes, branch = _classify_handler(runtime, handler, table_va)
            semantics, description = _handler_semantics(runtime, handler)
            # A handler that calls a named runtime helper IS that call, whatever its
            # opening instructions look like. `__vbaVarCat`'s handler happens to begin
            # with the same three instructions as the plain address-push, and was
            # therefore named `PUSH_LOCAL_ADDRESS` on 277 instructions of one
            # procedure -- a wrong name, which is worse than none because a reader
            # trusts it. The helper name is the authoritative one.
            if _export_hint(runtime, handler):
                semantics, description = None, None
        advance = None
        if kind == "terminator" and branch:
            advance, branch = branch.get("advance"), None
        entries.append({
            "index": index,
            "page": index // PAGE_ENTRIES,
            "opcode": index % PAGE_ENTRIES,
            "handler_va": hex(handler),
            "defined": defined,
            "kind": kind,
            "length": length,
            "terminator_advance": advance,
            "indexes_literals": indexes,
            "branch": branch,
            "calls": _export_hint(runtime, handler) if defined else None,
            # What the opcode DOES, read from the handler block. None whenever
            # the block does not match a known shape exactly -- an unnamed
            # opcode is reported as unnamed rather than approximated.
            "semantics": semantics,
            "semantics_note": description,
        })
    return {
        "table_va": hex(table_va),
        "entry_count": count,
        "page_count": (count + PAGE_ENTRIES - 1) // PAGE_ENTRIES,
        "page_bases": [hex(table_va + PAGE_STRIDE * p)
                       for p in range((count + PAGE_ENTRIES - 1) // PAGE_ENTRIES)],
        "undefined_handler_va": hex(undefined_handler),
        # Not just "the most common handler": verified to be the runtime's own
        # error raiser, so an opcode pointing at it really has no implementation.
        "undefined_handler_is_error_stub": is_stub,
        "undefined_handler_error_number": (hex(error_number) if error_number is not None else None),
        "entries": entries,
    }


def _file_version(path):
    """The installed runtime's own file version, e.g. "6.0.98.48".

    Worth reporting next to the target's declared VB6 build: the opcode table is
    derived from whatever MSVBVM60 this machine has, and a target compiled
    against a different build can use an opcode this one does not implement.
    """
    try:
        import pefile

        image = pefile.PE(str(path), fast_load=True)
        try:
            image.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            info = getattr(image, "VS_FIXEDFILEINFO", None)
            if not info:
                return None
            fixed = info[0]
            return "%d.%d.%d.%d" % (fixed.FileVersionMS >> 16,
                                    fixed.FileVersionMS & 0xFFFF,
                                    fixed.FileVersionLS >> 16,
                                    fixed.FileVersionLS & 0xFFFF)
        finally:
            image.close()
    except Exception:
        return None


_EXPORT_CACHE = {}
_THUNK_CACHE = {}


def _runtime_exports(runtime_path):
    """Ordinal -> name for every export of the installed VB6 runtime.

    A P-Code binary imports MSVBVM60 almost entirely BY ORDINAL, so its own
    import table names nothing: `ord645` rather than `rtcDir`. The runtime that
    already supplies the opcode table also supplies those names, out of its own
    export directory. Nothing is guessed and no external ordinal list is
    consulted -- if the machine has the runtime, it has the names.
    """
    key = str(runtime_path)
    if key in _EXPORT_CACHE:
        return _EXPORT_CACHE[key]
    try:
        import pefile

        image = pefile.PE(key, fast_load=True)
        try:
            image.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            table = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
            found = ({} if table is None
                     else {symbol.ordinal: symbol.name.decode("ascii", "replace")
                           for symbol in table.symbols if symbol.name})
        finally:
            image.close()
    except Exception:
        found = {}
    _EXPORT_CACHE[key] = found
    return found


def _import_thunks(target_path, exports):
    """Thunk VA -> runtime function name, for the target's own import thunks.

    A P-Code instruction that calls a runtime helper carries the address of a
    one-instruction thunk (`jmp dword ptr [<IAT slot>]`). Following that slot
    into the import table gives an ordinal, and `exports` turns the ordinal into
    a name. The thunk address is what the bytecode actually holds, so this is
    the mapping that makes a decode readable.
    """
    key = str(target_path)
    if key in _THUNK_CACHE:
        return _THUNK_CACHE[key]
    _THUNK_CACHE[key] = {}
    try:
        import capstone
        import pefile

        image = pefile.PE(key)
        try:
            base = image.OPTIONAL_HEADER.ImageBase
            slots = {}
            for entry in getattr(image, "DIRECTORY_ENTRY_IMPORT", []) or []:
                library = entry.dll.decode("ascii", "replace")
                for item in entry.imports:
                    if item.name:
                        slots[item.address] = item.name.decode("ascii", "replace")
                    elif item.ordinal is not None:
                        slots[item.address] = exports.get(
                            item.ordinal, "%s!ord%d" % (library, item.ordinal))
            if not slots:
                return {}
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            thunks = {}
            for section in image.sections:
                if not section.IMAGE_SCN_MEM_EXECUTE:
                    continue
                start = base + section.VirtualAddress
                blob = section.get_data()
                # Thunks sit in a dense run; scanning the whole executable section
                # once is cheaper than probing addresses one at a time. The step is
                # one byte, not two: thunks are normally aligned, but "normally" is
                # not a reason to be unable to see one that is not.
                for offset in range(0, min(len(blob), 1 << 20) - 6):
                    if blob[offset] != 0xFF or blob[offset + 1] != 0x25:
                        continue
                    instruction = next(decoder.disasm(blob[offset:offset + 6],
                                                      start + offset), None)
                    if instruction is None or instruction.mnemonic != "jmp":
                        continue
                    text = instruction.op_str
                    if "[" not in text:
                        continue
                    try:
                        slot = int(text.split("[")[1].split("]")[0], 16)
                    except ValueError:
                        continue
                    if slot in slots:
                        thunks[start + offset] = slots[slot]
            _THUNK_CACHE[key] = thunks
            return thunks
        finally:
            image.close()
    except Exception:
        return {}


def _runtime_path(explicit):
    if explicit:
        candidate = Path(str(explicit))
        return candidate if candidate.is_file() else None
    for path in DEFAULT_RUNTIMES:
        if Path(path).is_file():
            return Path(path)
    return None


def _image(path):
    """A flat VA-addressed view of a PE. Read only; never mapped by the loader."""
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        size = pe.OPTIONAL_HEADER.SizeOfImage
        buffer = bytearray(size)
        for section in pe.sections:
            raw = section.get_data()[:section.SizeOfRawData]
            start = section.VirtualAddress
            if 0 <= start < size:
                buffer[start:start + len(raw)] = raw
        return base, bytes(buffer)
    finally:
        pe.close()


def _dword(stream, base, va):
    offset = va - base
    if not 0 <= offset <= len(stream) - 4:
        return None
    return struct.unpack_from("<I", stream, offset)[0]


def _utf16(stream, base, va, limit=MAX_LITERAL_CHARS):
    """The literal table's string entries are plain UTF-16LE in the image."""
    offset = va - base
    if not 0 <= offset < len(stream) - 1:
        return None
    out = []
    while len(out) < limit and offset + 1 < len(stream):
        code = struct.unpack_from("<H", stream, offset)[0]
        if code == 0:
            break
        if not (0x20 <= code < 0x7F or code in (9, 10, 13)):
            return None
        out.append(chr(code))
        offset += 2
    return "".join(out) or None


def _literal_table(stream, base, descriptor_va):
    """Where the running procedure's literals live, per `ProcCallEngine`.

    On entry it does `mov edi, [ebx]` (the descriptor's first field) and then
    `mov esi, [edi + 0x34]`, keeping that pointer in `[ebp - 0x54]` for the
    opcodes that index it. So the table is `*( *(descriptor) + 0x34 )` -- read
    out of the interpreter rather than recognised by shape.
    """
    first = _dword(stream, base, descriptor_va)
    if first is None:
        return None
    return _dword(stream, base, first + LITERAL_TABLE_OFFSET)


def _decode(stream, start_offset, table, limit, base=0, literal_table=None,
            code_end=None, thunks=None):
    """Walk the bytecode with the derived table. Stops rather than guesses.

    Most opcodes only ever advance `offset` linearly, so a plain walk used to
    be enough. A branch opcode (see `_classify_handler` / `_branch_shape`)
    relocates the interpreter's own bytecode pointer instead, so the walk
    keeps a worklist of offsets still to visit and a visited set to avoid
    re-decoding the same bytes twice: an unconditional branch just continues
    at its resolved target; a conditional one enqueues the target AND the
    fall-through, since either can execute. The branch's own 2-byte operand is
    a procedure-relative offset -- `_entry_from_descriptor`'s `start_offset`
    IS that procedure's own zero point, so `target = start_offset + operand`
    needs no separate "bytecode base" lookup.

    The decode stops at the FIRST terminator/undefined-opcode/unknown-length
    reached along any path explored so far, which is what `stop_reason`
    reports; any offsets still queued at that point go unexplored, the same
    way a linear walk never looked past its own single stopping point.
    """
    lookup = {entry["index"]: entry for entry in table["entries"]}
    out, status = [], "LIMIT_REACHED"
    reached_terminator = False
    visited = set()
    worklist = [start_offset]
    end = start_offset
    stopped = False
    while worklist and len(out) < limit and not stopped:
        offset = worklist.pop(0)
        while len(out) < limit:
            if offset in visited:
                break  # already decoded via another path; nothing new here
            visited.add(offset)
            if code_end is not None and offset >= code_end:
                # The descriptor states where this procedure's bytecode ends.
                # Reading past it is not a longer decode, it is a decode of
                # whatever follows -- padding, another procedure, or data.
                status, end, stopped = "DECLARED_END_REACHED", offset, True
                break
            if offset >= len(stream):
                status, end, stopped = "END_OF_IMAGE", offset, True
                break
            lead = stream[offset]
            if lead >= FIRST_PREFIX:
                page = lead - FIRST_PREFIX + 1
                if offset + 1 >= len(stream):
                    status, end, stopped = "END_OF_IMAGE", offset, True
                    break
                opcode = stream[offset + 1]
                index = page * PAGE_ENTRIES + opcode
                header = 2
            else:
                page, opcode, index, header = 0, lead, lead, 1
            entry = lookup.get(index)
            if entry is None or not entry["defined"]:
                status, end, stopped = "UNDEFINED_OPCODE", offset, True
                out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                            "index": index, "length": None, "bytes": None,
                            "note": "no handler in the runtime's table"})
                break
            if entry["kind"] == "terminator":
                total = header + (entry.get("terminator_advance") or 0)
                out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                            "index": index, "length": total,
                            "bytes": stream[offset:offset + total].hex(),
                            "note": "handler unwinds the interpreter frame: end of procedure"})
                # A terminator ends this PATH, not the procedure. A VB6
                # procedure with an `Exit Sub` or a branch has several, and
                # stopping the whole walk at the first one reached left the rest
                # of the bytecode unexplored and reported as if it had not
                # decoded -- on WNL-T2-077's Sub Main, two thirds of it.
                end = max(end, offset + total)
                reached_terminator = True
                break
            if entry["kind"] == "operand_list":
                if offset + header + 2 > len(stream):
                    status, end, stopped = "END_OF_IMAGE", offset, True
                    break
                listed = struct.unpack_from("<H", stream, offset + header)[0]
                total = header + 2 + listed
                if listed % 2 or offset + total > len(stream):
                    # The count is a byte count over 16-bit elements, so an odd
                    # one means this is not really an operand list here.
                    status, end, stopped = "UNKNOWN_LENGTH", offset, True
                    out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                                "index": index, "length": None, "bytes": None,
                                "note": "operand-list byte count is not a whole "
                                        "number of 16-bit elements"})
                    break
                out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                            "index": index, "length": total,
                            "bytes": stream[offset:offset + total].hex(),
                            "calls": entry.get("calls"),
                            **({"semantics": entry["semantics"]}
                               if entry.get("semantics") else {}),
                            "operand_list_bytes": listed,
                            "note": ("variable-length: a %d-byte list of 16-bit frame "
                                     "offsets" % listed)})
                offset += total
                end = max(end, offset)
                continue
            length = entry["length"]
            if length is None:
                status, end, stopped = "UNKNOWN_LENGTH", offset, True
                out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                            "index": index, "length": None, "bytes": None,
                            "note": "handler reaches no dispatch site and does not unwind; "
                                    "length not derived"})
                break
            total = header - 1 + length
            if entry["kind"] == "branch":
                branch = entry["branch"] or {}
                operand_pos = offset + header + branch.get("operand_offset", 0)
                if operand_pos + 2 > len(stream):
                    status, end, stopped = "UNKNOWN_LENGTH", offset, True
                    out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                                "index": index, "length": None, "bytes": None,
                                "note": "branch operand runs past the end of the image"})
                    break
                operand = struct.unpack_from("<H", stream, operand_pos)[0]
                target = start_offset + operand
                conditional = bool(branch.get("conditional"))
                raw = stream[offset:offset + total]
                out.append({"offset": offset, "page": page, "opcode": hex(opcode),
                            "index": index, "length": total, "bytes": raw.hex(),
                            "calls": entry.get("calls"),
                            **({"semantics": entry["semantics"]}
                               if entry.get("semantics") else {}),
                            "branch_target_offset": target,
                            "branch_conditional": conditional,
                            "note": ("conditional branch to offset " if conditional
                                     else "unconditional branch to offset ")
                                    + hex(target)})
                if conditional:
                    worklist.append(offset + total)
                offset = target
                continue
            raw = stream[offset:offset + total]
            item = {"offset": offset, "page": page, "opcode": hex(opcode),
                    "index": index, "length": total, "bytes": raw.hex(),
                    "calls": entry.get("calls")}
            if entry.get("semantics"):
                item["semantics"] = entry["semantics"]
            if entry.get("indexes_literals") and literal_table and total >= header + 2:
                slot = struct.unpack_from("<H", stream, offset + header)[0]
                value = _dword(stream, base, literal_table + 4 * slot)
                if value is not None:
                    item["literal_index"] = slot
                    item["literal_value"] = hex(value)
                    text = _utf16(stream, base, value)
                    if text is not None:
                        item["literal_text"] = text
                    elif thunks and value in thunks:
                        # Not a string: the slot holds the address of an import
                        # thunk, so this instruction calls a named VB6 runtime
                        # helper. A P-Code binary imports MSVBVM60 by ordinal,
                        # so the name comes from the runtime's export table.
                        item["calls_runtime"] = thunks[value]
            out.append(item)
            offset += total
            # `end` is the furthest byte any path reached, not the last one --
            # once branches are followed, the path decoded last is not
            # necessarily the one that got furthest.
            end = max(end, offset)
    if not stopped and not worklist and len(out) < limit:
        # Every path has been followed to its end. If at least one of them
        # reached a real frame-unwind opcode the procedure decoded; if none did,
        # every queued path folded back into bytes already visited (a cycle)
        # without ever reaching a terminator, undefined opcode or unknown
        # length -- distinct from simply running out of `limit`.
        status = "END_OF_PROCEDURE" if reached_terminator else "NO_TERMINAL_REACHED"
    return out, end, status


def _assembled_strings(decoded, base, minimum=MIN_ASSEMBLED_RUN,
                       max_gap=MAX_ASSEMBLED_GAP):
    """Recover strings a procedure builds one character at a time.

    A P-Code program does not have to keep a string in its literal table. It can
    push each character as an immediate and store it, and then the string exists
    nowhere in the file -- no string scanner, and no dump of the literal table,
    will ever show it. `WNL-T2-079` does exactly this with the URL it contacts.

    The characters are not adjacent in the bytecode: each push is followed by
    the store and the index arithmetic that put it somewhere, so a run has to be
    read along ONE opcode's occurrences rather than along the instruction
    stream. Grouping by opcode is also what keeps the result honest -- a single
    push opcode carrying a run of printable codes is a string being built; the
    same codes spread across different opcodes are just small constants.

    A run ends when that opcode's next immediate is not a printable character
    code, or when it appears more than `max_gap` bytes later. The result claims
    only what it observes: these are the characters this procedure pushes, in
    push order. It is not a proven concatenation and says nothing about use.
    """
    by_opcode = {}
    for item in sorted(decoded, key=lambda entry: entry["offset"]):
        raw = item.get("bytes")
        if not raw or item.get("length") != 5 or item.get("page"):
            continue
        by_opcode.setdefault(item["opcode"], []).append(
            (item["offset"], int.from_bytes(bytes.fromhex(raw)[1:5], "little")))

    runs = []
    for opcode, pushes in by_opcode.items():
        current, start = [], None
        previous = None
        for offset, value in pushes + [(None, None)]:
            printable = value is not None and 0x20 <= value <= 0x7E
            near = previous is None or (offset is not None
                                        and offset - previous <= max_gap)
            if printable and (near or not current):
                if not current:
                    start = offset
                current.append(chr(value))
                previous = offset
                continue
            if len(current) >= minimum and len(set(current)) >= 3:
                # A run of one repeated character -- a field of spaces, a rule of
                # dashes -- is padding being written, not a string worth naming.
                runs.append({"address": hex(base + start), "opcode": opcode,
                             "length": len(current), "text": "".join(current)})
            current, start = ([chr(value)], offset) if printable else ([], None)
            previous = offset
    return sorted(runs, key=lambda run: int(run["address"], 16))


def _entry_from_descriptor(stream, base, descriptor_va):
    """Where the engine itself starts executing, not where the bytes look right.

    `ProcCallEngine` does `movzx esi, word [ebx+8]; neg esi; add esi, ebx` with
    `ebx` holding the descriptor, so the bytecode begins at
    `descriptor - u16(descriptor + 8)`. `MethCallEngine` reaches the same three
    instructions. Reading it out of the interpreter is what keeps this from
    being a scan for plausible-looking bytes.
    """
    offset = descriptor_va - base + 8
    if not 0 <= offset < len(stream) - 2:
        return None, None
    delta = struct.unpack_from("<H", stream, offset)[0]
    return descriptor_va - delta, delta


def vb6_pcode(path="", operation="runtime_table", runtime_path="",
              start_address="", descriptor_address="", max_instructions=256,
              max_chars=60000):
    """Decode VB6 P-Code using the opcode table derived from the VB6 runtime."""
    if operation not in _ALLOWED_OPS:
        return _j({"ok": False, "error": "UNKNOWN_OPERATION", "tool": TOOL,
                   "allowed": sorted(_ALLOWED_OPS)})
    try:
        import pefile  # noqa: F401
        import capstone  # noqa: F401
    except ImportError as exc:
        return _missing(operation, str(exc), "pefile and capstone")

    runtime_file = _runtime_path(runtime_path)
    if runtime_file is None:
        return _missing(
            operation,
            "MSVBVM60.DLL was not found. It ships with the Visual Basic 6 runtime and "
            "is present on machines that run VB6 programs; this project does not "
            "redistribute it. Pass runtime_path to point at a copy.",
            "MSVBVM60.DLL (the VB6 runtime, installed by the user)")

    runtime = _Runtime(runtime_file)
    try:
        if runtime.engine is None:
            return _j({"ok": False, "status": "NOT_A_VB6_RUNTIME", "tool": TOOL,
                       "operation": operation, "runtime": str(runtime_file),
                       "detail": "no ENGINE section; this file does not carry the "
                                 "P-Code interpreter"})
        table = _build_table(runtime)
        if table is None:
            return _j({"ok": False, "status": "TABLE_NOT_FOUND", "tool": TOOL,
                       "operation": operation, "runtime": str(runtime_file),
                       "detail": "no run of consecutive code pointers long enough to "
                                 "be the dispatch table"})
        identity = {
            "runtime": str(runtime_file),
            "runtime_sha256": runtime.sha256,
            "runtime_file_version": _file_version(runtime_file),
            "runtime_image_base": hex(runtime.base),
            "engine_section_va": hex(runtime.engine[1]),
            "engine_section_size": hex(runtime.engine[2]),
        }
        common = {
            "ok": True, "status": "OK", "tool": TOOL, "operation": operation,
            "evidence_class": "observed_fact",
            "evidence_note": (
                "The opcode table is read from the installed VB6 runtime's own bytes, "
                "statically: the DLL is parsed with pefile, never loaded and never "
                "executed, and is not copied into this repository. The table is located "
                "by structure (the one long run of code pointers in ENGINE) and it "
                "contains the interpreter's own dispatch loop, which is what makes it "
                "self-verifying rather than a signature match."),
            "not_established": [
                "WHAT_MOST_OPCODES_MEAN",
                "WHICH_SOURCE_STATEMENT_A_BYTE_BELONGS_TO",
            ],
            "what_this_does_not_do": (
                "The runtime carries handlers, not mnemonics, so an opcode is an index, "
                "a page and a length. A minority of opcodes additionally carry a "
                "`semantics` name, read from the shape of their own handler block; the "
                "rest are reported without one rather than approximated. No "
                "decompilation, and no execution of either the runtime or the target."),
        }
        common.update(identity)

        if operation == "runtime_table":
            defined = [e for e in table["entries"] if e["defined"]]
            with_length = [e for e in defined if e["length"] is not None]
            terminators = [e for e in defined if e["kind"] == "terminator"]
            operand_lists = [e for e in defined if e["kind"] == "operand_list"]
            histogram = {}
            for entry in with_length:
                key = str(entry["length"])
                histogram[key] = histogram.get(key, 0) + 1
            result = dict(common)
            result.update({
                "table_va": table["table_va"],
                "entry_count": table["entry_count"],
                "page_count": table["page_count"],
                "page_bases": table["page_bases"],
                "prefix_opcodes": [hex(FIRST_PREFIX + i)
                                   for i in range(table["page_count"] - 1)],
                "defined_opcodes": len(defined),
                "undefined_opcodes": table["entry_count"] - len(defined),
                "undefined_handler_va": table["undefined_handler_va"],
                "undefined_handler_is_error_stub": table["undefined_handler_is_error_stub"],
                "undefined_handler_error_number": table["undefined_handler_error_number"],
                "lengths_derived": len(with_length),
                "terminator_opcodes": len(terminators),
                "terminator_sample": [e["index"] for e in terminators[:12]],
                "operand_list_opcodes": len(operand_lists),
                "operand_list_sample": [e["index"] for e in operand_lists],
                "operand_list_note": (
                    "Variable-length opcodes: a 16-bit BYTE COUNT followed by that many "
                    "bytes of 16-bit frame offsets, looped over by the handler. Their "
                    "length is not a table constant and cannot be read off the terminal "
                    "dispatch site, so they are classified rather than sized."),
                "unclassified": (len(defined) - len(with_length) - len(terminators)
                                 - len(operand_lists)),
                "opcodes_naming_a_runtime_helper": len([e for e in defined if e["calls"]]),
                # How many opcodes have a MEANING, not just a length. Read from
                # the handler blocks; an opcode whose block does not match a
                # known shape exactly is left unnamed rather than approximated,
                # so this number is a floor on what is understood.
                "opcodes_with_semantics": len([e for e in defined if e.get("semantics")]),
                "semantics_note": (
                    "Each name is the shape of the opcode's own handler block in the "
                    "installed runtime -- what it reads from [esi] and what it does with "
                    "it -- on the same footing as the lengths. Unnamed opcodes are reported "
                    "as unnamed."),
                "length_histogram": dict(sorted(histogram.items(), key=lambda kv: int(kv[0]))),
                "sample": table["entries"][:32],
            })
            return _j(result)

        if operation == "program_strings":
            target = safe_path(path)
            if not target.is_file():
                return _j({"ok": False, "error": "FILE_NOT_FOUND", "tool": TOOL,
                           "operation": operation, "path": str(path)})
            from liebert_re.tools.vb6 import vb6_inspect  # local: avoids an import cycle

            structure = json.loads(vb6_inspect(path=str(target),
                                               operation="pcode_methods"))
            stubs = structure.get("pcode_method_stubs") or []
            if not stubs:
                return _j({"ok": True, "status": "NO_PCODE_STUBS", "tool": TOOL,
                           "operation": operation, "path": relative(target),
                           "detail": ("no P-Code method stubs were found. On a "
                                      "packed binary this means the packing, not "
                                      "the absence of P-Code -- unpack first. On an "
                                      "unpacked one it is evidence the binary is "
                                      "native-compiled VB6, which vb6_inspect "
                                      "reports properly."),
                           "not_established": ["THAT_THIS_BINARY_IS_NOT_P_CODE"]})
            procedures, assembled, literals = [], [], {}
            covered = declared = 0
            for stub in stubs:
                one = json.loads(vb6_pcode(
                    path=str(target), operation="procedure",
                    descriptor_address=stub["descriptor_va"],
                    runtime_path=str(runtime_file),
                    max_instructions=MAX_INSTRUCTIONS, max_chars=1 << 24))
                if not one.get("ok"):
                    procedures.append({"descriptor_va": stub["descriptor_va"],
                                       "status": one.get("status") or one.get("error")})
                    continue
                size = one.get("declared_code_size") or 0
                declared += size
                covered += min(one.get("bytes_decoded") or 0, size)
                procedures.append({
                    "descriptor_va": stub["descriptor_va"],
                    "start_address": one["start_address"],
                    "declared_code_size": size,
                    "coverage": one["coverage_of_declared_code"],
                    "stop_reason": one["stop_reason"],
                    "instructions": one["instructions_decoded"],
                })
                for run in one["assembled_strings"]:
                    assembled.append(dict(run, descriptor_va=stub["descriptor_va"]))
                for item in one["instructions"]:
                    text = item.get("literal_text")
                    if text:
                        literals.setdefault(text, item["address"])
            result = dict(common)
            result.update({
                "path": relative(target),
                "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "target_runtime_build": structure.get("runtime_build"),
                "runtime_build_note": (
                    "The target's own VB header states which VB6 build compiled it. The "
                    "opcode table comes from the MSVBVM60 installed here "
                    "(runtime_file_version). They are reported side by side because a "
                    "mismatch is a real reason an opcode can come back undefined."),
                "procedure_count": len(stubs),
                "declared_code_size": declared,
                "bytes_decoded": covered,
                "coverage_of_declared_code": (round(covered / float(declared), 4)
                                              if declared else None),
                "assembled_strings": assembled,
                "assembled_strings_note": (
                    "Strings the program builds one character at a time from "
                    "immediates. These are in NO string table and NO literal table, "
                    "so a string scanner over the file cannot find them -- which is "
                    "exactly why they are worth a pass of their own. The order is "
                    "the push order, not a proven concatenation."),
                "literal_strings": [{"text": text, "first_reference": address}
                                    for text, address in literals.items()],
                "procedures": procedures,
            })
            rendered = _j(result)
            while len(rendered) > max_chars and result["procedures"]:
                result["procedures"] = result["procedures"][:len(result["procedures"]) // 2]
                result["procedures_truncated"] = True
                rendered = _j(result)
            return rendered

        # operation == "disassemble" or "procedure"
        target = safe_path(path)
        if not target.is_file():
            return _j({"ok": False, "error": "FILE_NOT_FOUND", "tool": TOOL,
                       "operation": operation, "path": str(path)})
        base, stream = _image(target)
        descriptor = None
        if operation == "literals":
            try:
                descriptor = int(str(descriptor_address), 0)
            except (TypeError, ValueError):
                return _j({"ok": False, "error": "BAD_REQUEST", "tool": TOOL,
                           "operation": operation,
                           "detail": "literals needs descriptor_address"})
            literals = _literal_table(stream, base, descriptor)
            if not literals:
                return _j({"ok": False, "status": "NO_LITERAL_TABLE", "tool": TOOL,
                           "operation": operation, "path": relative(target),
                           "descriptor_address": hex(descriptor)})
            entries = []
            for slot in range(max(1, min(int(max_instructions), 1024))):
                value = _dword(stream, base, literals + 4 * slot)
                if value is None:
                    break
                text = _utf16(stream, base, value)
                entries.append({"index": slot, "value": hex(value),
                                "text": text})
            result = dict(common)
            result.update({
                "path": relative(target),
                "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "image_base": hex(base),
                "descriptor_address": hex(descriptor),
                "literal_table_va": hex(literals),
                "literal_table_rule": ("literals = *( *(descriptor) + 0x34 ), the pointer "
                                       "ProcCallEngine keeps in [ebp-0x54] for the opcodes "
                                       "that index it"),
                "entry_count": len(entries),
                "strings": [e for e in entries if e["text"]],
                "entries": entries,
            })
            rendered = _j(result)
            while len(rendered) > max_chars and result["entries"]:
                result["entries"] = result["entries"][:len(result["entries"]) // 2]
                result["entries_truncated"] = True
                rendered = _j(result)
            return rendered
        if operation == "procedure":
            try:
                descriptor = int(str(descriptor_address), 0)
            except (TypeError, ValueError):
                return _j({"ok": False, "error": "BAD_REQUEST", "tool": TOOL,
                           "operation": operation,
                           "detail": "procedure needs descriptor_address -- the value "
                                     "vb6_inspect's pcode_methods reports as "
                                     "descriptor_va, e.g. '0x401974'"})
            start, delta = _entry_from_descriptor(stream, base, descriptor)
            if start is None:
                return _j({"ok": False, "status": "ADDRESS_NOT_MAPPED", "tool": TOOL,
                           "operation": operation, "path": relative(target),
                           "descriptor_address": hex(descriptor)})
        else:
            try:
                start = int(str(start_address), 0)
            except (TypeError, ValueError):
                return _j({"ok": False, "error": "BAD_REQUEST", "tool": TOOL,
                           "operation": operation,
                           "detail": "disassemble needs start_address, e.g. '0x40192c'"})
            delta = None
        offset = start - base
        if not 0 <= offset < len(stream):
            return _j({"ok": False, "status": "ADDRESS_NOT_MAPPED", "tool": TOOL,
                       "operation": operation, "path": relative(target),
                       "start_address": hex(start), "image_base": hex(base)})
        limit = max(1, min(int(max_instructions), MAX_INSTRUCTIONS))
        literals = _literal_table(stream, base, descriptor) if descriptor is not None else None
        code_end = descriptor - base if descriptor is not None else None
        thunks = _import_thunks(target, _runtime_exports(runtime_file))
        decoded, end, status = _decode(stream, offset, table, limit, base=base,
                                       literal_table=literals, code_end=code_end,
                                       thunks=thunks)
        decoded_bytes = sum(item["length"] for item in decoded
                            if item.get("length"))
        result = dict(common)
        result.update({
            "path": relative(target),
            "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "image_base": hex(base),
            "start_address": hex(start),
            "descriptor_address": hex(descriptor) if descriptor is not None else None,
            "descriptor_delta": hex(delta) if delta is not None else None,
            "entry_rule": ("bytecode = descriptor - u16(descriptor + 8), read from "
                           "ProcCallEngine's own prologue"
                           if descriptor is not None else None),
            "literal_table_va": hex(literals) if literals else None,
            "literal_table_rule": ("literals = *( *(descriptor) + 0x34 ), the pointer "
                                   "ProcCallEngine keeps in [ebp-0x54] for the opcodes "
                                   "that index it" if literals else None),
            "stop_reason": status,
            "stop_note": (
                "An opcode with no handler in this runtime's table means one of two "
                "things, and they are not distinguishable from the stop alone: a "
                "residual MISALIGNMENT (an earlier opcode's length is wrong, so this "
                "byte is not really an opcode), or an opcode THIS RUNTIME BUILD DOES "
                "NOT IMPLEMENT while the build the target was compiled against did. "
                "vb6_inspect reports the target's own declared runtime build; if it "
                "differs from this machine's MSVBVM60, pass a matching copy as "
                "runtime_path to tell the two apart. Decoding past the byte is not an "
                "option -- a wrong stream is worse than a short one."
                if status == "UNDEFINED_OPCODE" else None),
            "declared_code_size": (code_end - offset) if code_end is not None else None,
            "declared_end_reached": (code_end is not None and end >= code_end),
            "bytes_decoded": decoded_bytes,
            "coverage_of_declared_code": (
                round(min(decoded_bytes, code_end - offset) / float(code_end - offset), 4)
                if code_end is not None and code_end > offset else None),
            "coverage_note": (
                "The descriptor states the procedure's bytecode size, so the share of it "
                "this decode actually walked is a measurable quality signal rather than a "
                "claim: short of 1.0 means the walk stopped early (an opcode whose length "
                "the runtime table does not yield, or a misalignment), not that the "
                "procedure is short. It counts the bytes the decoded instructions "
                "actually occupy, not the span between the first and last of them: once "
                "branches are followed the walk is not contiguous, and measuring the span "
                "would report a procedure that jumps backwards as barely decoded."),
            "instructions_decoded": len(decoded),
            "bytes_consumed": end - offset,
            "end_address": hex(base + end),
            "table_va": table["table_va"],
            "runtime_helpers_named": len({item["calls_runtime"] for item in decoded
                                          if item.get("calls_runtime")}),
            "runtime_helpers_note": (
                "A P-Code binary imports MSVBVM60 almost entirely BY ORDINAL, so its "
                "own import table names nothing. `calls_runtime` on an instruction is "
                "the real function name, read out of the export table of the same "
                "installed runtime that supplies the opcode table -- not from a "
                "bundled ordinal list."),
            "assembled_strings": _assembled_strings(decoded, base),
            "assembled_strings_note": (
                "Characters this procedure pushes as immediates, in the order it pushes "
                "them. A string built this way is in no string table and no literal table, "
                "so a scanner cannot find it -- but the order is the push order, not a proven "
                "concatenation, and nothing here says what the string is used for."),
            # Reported in address order, not walk order: once branches are
            # followed the walk visits the procedure out of sequence, and a
            # listing in that order is unreadable.
            "instructions": [dict(item, address=hex(base + item["offset"]))
                             for item in sorted(decoded,
                                                key=lambda entry: entry["offset"])],
        })
        rendered = _j(result)
        while len(rendered) > max_chars and result["instructions"]:
            result["instructions"] = result["instructions"][:len(result["instructions"]) // 2]
            result["instructions_truncated"] = True
            rendered = _j(result)
        return rendered
    finally:
        runtime.close()
