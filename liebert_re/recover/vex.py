"""Correct execution of VEX-encoded (AVX) instructions.

Measured, not assumed. This engine decodes a VEX instruction as its legacy SSE
equivalent and ignores ``VEX.vvvv``, the second source operand:

    vpxor   xmm2, xmm0, xmm1   ->  xmm2 = xmm1              (should be xmm0^xmm1)
    vpaddb  xmm2, xmm0, xmm1   ->  xmm2 = xmm1              (should be a byte add)
    vpslldq xmm0, xmm4, 4      ->  xmm4 shifted in place, xmm0 untouched
    vaesenc xmm1, xmm0, xmm5   ->  an AES round over whatever xmm1 already held

There is no fault and no warning; the answer is simply wrong, and the legacy SSE
encodings of the same operations are correct on the same build. So the defect is
in the VEX decode path, not in AES-NI, and it is repaired here rather than
disclosed: this module recognises a VEX instruction before the engine runs it,
computes it itself, and moves the program counter past it.

Anything this module does not model raises :class:`UnmodelledVex`, which stops
the run. A wrong answer that looks plausible is the failure mode this exists to
prevent, so falling through to the engine is never an option.
"""

import math
import struct

import capstone
from capstone import x86_const as CX
from unicorn import x86_const as UX

__all__ = ["UnmodelledVex", "VexLayer", "self_check"]


class UnmodelledVex(Exception):
    """A VEX instruction this module cannot compute. The run stops here."""

    def __init__(self, mnemonic, op_str, address):
        super().__init__("%s %s at %#x" % (mnemonic, op_str, address))
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.address = address


_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_INV_SBOX = bytearray(256)
for _i, _b in enumerate(_SBOX):
    _INV_SBOX[_b] = _i
_INV_SBOX = bytes(_INV_SBOX)


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _shift_rows(s, inverse=False):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            src = ((c - r) % 4) if inverse else ((c + r) % 4)
            out[c * 4 + r] = s[src * 4 + r]
    return bytes(out)


def _mix_columns(s, inverse=False):
    coeffs = (0x0E, 0x0B, 0x0D, 0x09) if inverse else (0x02, 0x03, 0x01, 0x01)
    out = bytearray(16)
    for c in range(4):
        col = s[c * 4:c * 4 + 4]
        for r in range(4):
            out[c * 4 + r] = (
                _mul(col[0], coeffs[(0 - r) % 4]) ^ _mul(col[1], coeffs[(1 - r) % 4]) ^
                _mul(col[2], coeffs[(2 - r) % 4]) ^ _mul(col[3], coeffs[(3 - r) % 4]))
    return bytes(out)


def aes_enc(state, key, last=False):
    s = bytes(_SBOX[b] for b in state)
    s = _shift_rows(s)
    if not last:
        s = _mix_columns(s)
    return bytes(a ^ b for a, b in zip(s, key))


def aes_dec(state, key, last=False):
    s = _shift_rows(state, inverse=True)
    s = bytes(_INV_SBOX[b] for b in s)
    if not last:
        s = _mix_columns(s, inverse=True)
    return bytes(a ^ b for a, b in zip(s, key))


def aes_imc(state):
    return _mix_columns(state, inverse=True)


def aes_keygenassist(src, rcon):
    def sub_rot(word):
        subbed = bytes(_SBOX[b] for b in word)
        return subbed[1:] + subbed[:1]
    x1 = bytes(_SBOX[b] for b in src[4:8])
    x3 = bytes(_SBOX[b] for b in src[12:16])
    r1 = sub_rot(src[4:8])
    r3 = sub_rot(src[12:16])
    r1 = bytes([r1[0] ^ rcon]) + r1[1:]
    r3 = bytes([r3[0] ^ rcon]) + r3[1:]
    return x1 + r1 + x3 + r3


# -- register plumbing ------------------------------------------------------

_GPR64_PARENT = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
    "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    **{"r%dd" % n: "r%d" % n for n in range(8, 16)},
}


def _uc_reg(name):
    reg = getattr(UX, "UC_X86_REG_" + name.upper(), None)
    if reg is None:
        raise KeyError(name)
    return reg


class VexLayer:
    """Recognises and executes VEX instructions on behalf of the engine.

    One instance per emulation. It caches its decode per address, and the owner
    must call :meth:`invalidate` when code is written to, so self-modifying code
    never runs against a stale decode.
    """

    def __init__(self, uc, bits):
        self.uc = uc
        self.bits = bits
        self.md = capstone.Cs(capstone.CS_ARCH_X86,
                              capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
        self.md.detail = True
        self._cache = {}
        self._pages = {}
        self.executed = 0
        self.mnemonics = {}

    # -- cache ------------------------------------------------------------

    def invalidate(self, address, size):
        """Forget decodes covering a written range.

        This runs on every write in a packer's unpacking loop, so it is indexed
        by page: one dictionary lookup for the overwhelmingly common case where
        nothing has been decoded there. A stale decode would be a silent lie in
        exactly the self-modifying code this engine is used on.
        """
        if not self._pages:
            return
        first = (address - 16) >> 12
        last = (address + max(size, 1)) >> 12
        for page in range(first, last + 1):
            stale = self._pages.pop(page, None)
            if stale:
                for entry in stale:
                    self._cache.pop(entry, None)

    def _decode(self, address, size):
        cached = self._cache.get(address, None)
        if cached is not None:
            return cached
        # The size the hook reports is not trustworthy for an instruction the
        # engine itself cannot decode -- it can arrive as 1, which is not
        # enough to see a VEX prefix's operands, and the layer would then wave
        # through exactly the instructions it exists to catch. An x86
        # instruction is at most 15 bytes, so read that and let capstone say.
        data = b""
        for width in (15, max(size, 1)):
            try:
                data = bytes(self.uc.mem_read(address, width))
                break
            except Exception:
                continue
        entry = False
        if data[:1] in (b"\xc4", b"\xc5"):
            for insn in self.md.disasm(data, address, 1):
                entry = insn
                break
        self._cache[address] = entry
        self._pages.setdefault(address >> 12, set()).add(address)
        return entry

    # -- operand access ---------------------------------------------------

    def _mem_address(self, insn, op):
        mem = op.mem
        address = mem.disp
        if mem.base:
            name = insn.reg_name(mem.base)
            if name == "rip":
                address += insn.address + insn.size
            else:
                address += self.uc.reg_read(_uc_reg(name))
        if mem.index:
            address += self.uc.reg_read(_uc_reg(insn.reg_name(mem.index))) * mem.scale
        return address & ((1 << self.bits) - 1)

    def _read(self, insn, op, size=None):
        if op.type == CX.X86_OP_REG:
            name = insn.reg_name(op.reg)
            if name.startswith("zmm"):
                raise UnmodelledVex(insn.mnemonic, insn.op_str, insn.address)
            value = self.uc.reg_read(_uc_reg(name))
            if name.startswith("ymm"):
                return value.to_bytes(32, "little")
            if name.startswith("xmm"):
                return value.to_bytes(16, "little")
            width = size or op.size
            return value.to_bytes(width, "little")
        if op.type == CX.X86_OP_IMM:
            return op.imm & 0xFF
        if op.type == CX.X86_OP_MEM:
            return bytes(self.uc.mem_read(self._mem_address(insn, op), size or op.size))
        raise UnmodelledVex(insn.mnemonic, insn.op_str, insn.address)

    def _write(self, insn, op, blob):
        if op.type == CX.X86_OP_REG:
            name = insn.reg_name(op.reg)
            if name.startswith("zmm"):
                raise UnmodelledVex(insn.mnemonic, insn.op_str, insn.address)
            if name.startswith("ymm"):
                padded = (blob + bytes(32))[:32]
                self.uc.reg_write(_uc_reg(name), int.from_bytes(padded, "little"))
                return
            if name.startswith("xmm"):
                # A VEX instruction with a 128-bit destination zeroes the upper
                # half of the underlying ymm register. Not modelling that would
                # leave stale bytes behind for the next 256-bit read.
                self.uc.reg_write(_uc_reg(name), int.from_bytes(blob[:16], "little"))
                upper = getattr(UX, "UC_X86_REG_YMM" + name[3:], None)
                if upper is not None:
                    try:
                        self.uc.reg_write(upper, int.from_bytes(blob[:16], "little"))
                    except Exception:
                        pass
                return
            # A 32-bit destination zeroes the upper half of its 64-bit parent on
            # x86-64; write the parent so that is not left to the engine.
            parent = _GPR64_PARENT.get(name) if self.bits == 64 else None
            target = parent or name
            self.uc.reg_write(_uc_reg(target), int.from_bytes(blob, "little"))
            return
        if op.type == CX.X86_OP_MEM:
            self.uc.mem_write(self._mem_address(insn, op), blob)
            return
        raise UnmodelledVex(insn.mnemonic, insn.op_str, insn.address)

    # -- execution --------------------------------------------------------

    def step(self, address, size):
        """Execute the instruction at ``address`` if it is VEX-encoded.

        Returns True when this module took over, in which case the program
        counter has already been moved past the instruction.
        """
        insn = self._decode(address, size)
        if insn is False:
            return False
        self._execute(insn)
        self.executed += 1
        self.mnemonics[insn.mnemonic] = self.mnemonics.get(insn.mnemonic, 0) + 1
        self.uc.reg_write(UX.UC_X86_REG_RIP if self.bits == 64 else UX.UC_X86_REG_EIP,
                          insn.address + insn.size)
        return True

    def _execute(self, insn):
        name = insn.mnemonic
        ops = insn.operands
        handler = getattr(self, "_op_" + name, None)
        if handler is not None:
            return handler(insn, ops)
        for prefix, generic in _GENERIC.items():
            if name == prefix:
                return generic(self, insn, ops)
        raise UnmodelledVex(insn.mnemonic, insn.op_str, insn.address)

    # -- individual operations -------------------------------------------

    def _operand_width(self, insn, op):
        """128 or 256 bits, taken from the operand rather than assumed. A layer
        that assumed sixteen bytes would silently truncate every AVX
        instruction it touched."""
        if op.type == CX.X86_OP_REG:
            name = insn.reg_name(op.reg)
            if name.startswith("ymm"):
                return 32
            if name.startswith("xmm"):
                return 16
        if op.type == CX.X86_OP_MEM and op.size in (16, 32):
            return op.size
        return 16

    def _binary(self, insn, ops, fn):
        width = self._operand_width(insn, ops[0])
        a = self._read(insn, ops[1], width)
        b = self._read(insn, ops[2], width)
        self._write(insn, ops[0], fn(a[:width], b[:width]))

    def _lanes(self, blob, width):
        return [int.from_bytes(blob[i:i + width], "little")
                for i in range(0, len(blob), width)]

    def _pack(self, lanes, width):
        return b"".join((v & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
                        for v in lanes)

    def _move(self, insn, ops):
        size = max(self._operand_width(insn, ops[0]),
                   self._operand_width(insn, ops[1]))
        if ops[0].type == CX.X86_OP_MEM:
            size = ops[0].size
        elif ops[1].type == CX.X86_OP_MEM:
            size = ops[1].size
        blob = self._read(insn, ops[1], size)
        if ops[0].type == CX.X86_OP_REG:
            name = insn.reg_name(ops[0].reg)
            if name.startswith("ymm"):
                blob = (blob + bytes(32))[:32]
            elif name.startswith("xmm"):
                blob = (blob + bytes(16))[:16]
        else:
            blob = blob[:size]
        self._write(insn, ops[0], blob)

    def _op_vmovdqu(self, insn, ops):
        self._move(insn, ops)

    _op_vmovdqa = _op_vmovdqu
    _op_vmovups = _op_vmovdqu
    _op_vmovaps = _op_vmovdqu
    _op_vmovupd = _op_vmovdqu
    _op_vmovapd = _op_vmovdqu
    _op_vlddqu = _op_vmovdqu

    def _op_vmovq(self, insn, ops):
        blob = self._read(insn, ops[1], 8)[:8]
        if ops[0].type == CX.X86_OP_REG and insn.reg_name(ops[0].reg).startswith("xmm"):
            blob = blob + b"\0" * 8
        self._write(insn, ops[0], blob)

    def _op_vmovd(self, insn, ops):
        blob = self._read(insn, ops[1], 4)[:4]
        if ops[0].type == CX.X86_OP_REG and insn.reg_name(ops[0].reg).startswith("xmm"):
            blob = blob + b"\0" * 12
        self._write(insn, ops[0], blob)

    def _op_vpshufd(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        order = self._read(insn, ops[2])
        out = b"".join(src[((order >> (2 * i)) & 3) * 4:((order >> (2 * i)) & 3) * 4 + 4]
                       for i in range(4))
        self._write(insn, ops[0], out)

    def _op_vpshufb(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        table = self._read(insn, ops[2], 16)
        out = bytes(0 if table[i] & 0x80 else src[table[i] & 0x0F] for i in range(16))
        self._write(insn, ops[0], out)

    def _op_vpslldq(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        count = min(self._read(insn, ops[2]), 16)
        self._write(insn, ops[0], (b"\0" * count + src)[:16])

    def _op_vpsrldq(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        count = min(self._read(insn, ops[2]), 16)
        self._write(insn, ops[0], (src[count:] + b"\0" * count)[:16])

    def _shift_lanes(self, insn, ops, width, direction):
        src = self._read(insn, ops[1], 16)
        third = ops[2]
        if third.type == CX.X86_OP_IMM:
            count = third.imm & 0xFF
        else:
            count = int.from_bytes(self._read(insn, third, 16)[:8], "little")
        bits = 8 * width
        lanes = self._lanes(src, width)
        out = []
        for value in lanes:
            if count >= bits:
                out.append(0xFFFFFFFFFFFFFFFF if direction == "a" and
                           value >> (bits - 1) else 0)
            elif direction == "l":
                out.append((value << count) & ((1 << bits) - 1))
            elif direction == "r":
                out.append(value >> count)
            else:
                signed = value - (1 << bits) if value >> (bits - 1) else value
                out.append((signed >> count) & ((1 << bits) - 1))
        self._write(insn, ops[0], self._pack(out, width))

    def _op_vpmovmskb(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        mask = 0
        for i, byte in enumerate(src):
            if byte & 0x80:
                mask |= 1 << i
        self._write(insn, ops[0], mask.to_bytes(8, "little"))

    def _op_vzeroupper(self, insn, ops):
        """Zero bits 255:128 of every vector register, keeping the low half.

        Now that 256-bit state is modelled this has to actually happen: leaving
        it a no-op would hand stale upper bytes to the next ymm read, which is
        the same class of silent wrongness this module exists to remove."""
        for index in range(16 if self.bits == 64 else 8):
            reg = getattr(UX, "UC_X86_REG_YMM%d" % index, None)
            if reg is None:
                continue
            try:
                value = self.uc.reg_read(reg).to_bytes(32, "little")
                self.uc.reg_write(reg, int.from_bytes(value[:16], "little"))
            except Exception:
                pass

    def _op_vzeroall(self, insn, ops):
        for index in range(16 if self.bits == 64 else 8):
            for prefix in ("YMM", "XMM"):
                reg = getattr(UX, "UC_X86_REG_%s%d" % (prefix, index), None)
                if reg is not None:
                    try:
                        self.uc.reg_write(reg, 0)
                    except Exception:
                        pass

    def _op_vaesenc(self, insn, ops):
        self._binary(insn, ops, lambda s, k: aes_enc(s, k))

    def _op_vaesenclast(self, insn, ops):
        self._binary(insn, ops, lambda s, k: aes_enc(s, k, last=True))

    def _op_vaesdec(self, insn, ops):
        self._binary(insn, ops, lambda s, k: aes_dec(s, k))

    def _op_vaesdeclast(self, insn, ops):
        self._binary(insn, ops, lambda s, k: aes_dec(s, k, last=True))

    def _op_vaesimc(self, insn, ops):
        self._write(insn, ops[0], aes_imc(self._read(insn, ops[1], 16)))

    def _op_vaeskeygenassist(self, insn, ops):
        src = self._read(insn, ops[1], 16)
        rcon = self._read(insn, ops[2])
        self._write(insn, ops[0], aes_keygenassist(src, rcon))

    def _extract(self, insn, ops, width):
        src = self._read(insn, ops[1], 16)
        index = self._read(insn, ops[2]) % (16 // width)
        blob = src[index * width:index * width + width]
        if ops[0].type == CX.X86_OP_REG:
            blob = (blob + b"\0" * 8)[:8]
        self._write(insn, ops[0], blob)

    def _insert(self, insn, ops, width):
        dst = bytearray(self._read(insn, ops[1], 16))
        value = self._read(insn, ops[2], width)
        index = self._read(insn, ops[3]) % (16 // width)
        dst[index * width:index * width + width] = value[:width]
        self._write(insn, ops[0], bytes(dst))

    def _op_vpextrb(self, insn, ops):
        self._extract(insn, ops, 1)

    def _op_vpextrw(self, insn, ops):
        self._extract(insn, ops, 2)

    def _op_vpextrd(self, insn, ops):
        self._extract(insn, ops, 4)

    def _op_vpextrq(self, insn, ops):
        self._extract(insn, ops, 8)

    def _op_vpinsrb(self, insn, ops):
        self._insert(insn, ops, 1)

    def _op_vpinsrw(self, insn, ops):
        self._insert(insn, ops, 2)

    def _op_vpinsrd(self, insn, ops):
        self._insert(insn, ops, 4)

    def _op_vpinsrq(self, insn, ops):
        self._insert(insn, ops, 8)


def _bitwise(fn):
    def run(layer, insn, ops):
        layer._binary(insn, ops, lambda a, b: bytes(fn(x, y) for x, y in zip(a, b)))
    return run


def _lane_arith(width, fn):
    def run(layer, insn, ops):
        def combine(a, b):
            mask = (1 << (8 * width)) - 1
            return layer._pack([fn(x, y) & mask
                                for x, y in zip(layer._lanes(a, width),
                                                layer._lanes(b, width))], width)
        layer._binary(insn, ops, combine)
    return run


def _lane_compare(width, fn):
    def run(layer, insn, ops):
        def combine(a, b):
            mask = (1 << (8 * width)) - 1
            return layer._pack([mask if fn(x, y) else 0
                                for x, y in zip(layer._lanes(a, width),
                                                layer._lanes(b, width))], width)
        layer._binary(insn, ops, combine)
    return run


def _shift(width, direction):
    def run(layer, insn, ops):
        layer._shift_lanes(insn, ops, width, direction)
    return run


def _signed(value, width):
    bits = 8 * width
    return value - (1 << bits) if value >> (bits - 1) else value



# -- floating point ---------------------------------------------------------
#
# Packed and scalar IEEE-754 arithmetic, computed in Python doubles and rounded
# once on the way back into the lane. For float32 add, subtract and multiply
# that single rounding is exact -- a double holds every product of two float32
# values without loss -- so the result is correctly rounded. Division is the
# one case where computing in double and then rounding can, very rarely, differ
# from a hardware single-rounded divide; it is implemented rather than refused,
# and the caveat is recorded here rather than left to be discovered.

def _pack_float(fmt, value):
    """Round back into the lane, turning an overflow into a signed infinity
    the way the hardware does rather than raising."""
    try:
        return struct.pack(fmt, value)
    except OverflowError:
        return struct.pack(fmt, math.copysign(math.inf, value))


def _fp_apply(op, x, y):
    if op == "add":
        return x + y
    if op == "sub":
        return x - y
    if op == "mul":
        return x * y
    if op == "min":
        # SSE/AVX MIN returns the second operand when either input is NaN.
        return y if (math.isnan(x) or math.isnan(y)) else min(x, y)
    if op == "max":
        return y if (math.isnan(x) or math.isnan(y)) else max(x, y)
    if op == "div":
        if y == 0.0:
            if x == 0.0 or math.isnan(x):
                return math.nan
            sign = math.copysign(1.0, x) * math.copysign(1.0, y)
            return math.copysign(math.inf, sign)
        return x / y
    raise ValueError(op)


def _fp_packed(lane, op):
    fmt = "<f" if lane == 4 else "<d"

    def run(layer, insn, ops):
        def combine(a, b):
            out = bytearray()
            for offset in range(0, len(a), lane):
                x = struct.unpack_from(fmt, a, offset)[0]
                y = struct.unpack_from(fmt, b, offset)[0]
                out += _pack_float(fmt, _fp_apply(op, x, y))
            return bytes(out)
        layer._binary(insn, ops, combine)
    return run


def _fp_scalar(lane, op):
    """Only the low lane is computed; the rest come from the first source,
    which is what makes these merge rather than broadcast."""
    fmt = "<f" if lane == 4 else "<d"

    def run(layer, insn, ops):
        def combine(a, b):
            x = struct.unpack_from(fmt, a, 0)[0]
            y = struct.unpack_from(fmt, b, 0)[0]
            return _pack_float(fmt, _fp_apply(op, x, y)) + a[lane:]
        layer._binary(insn, ops, combine)
    return run


_GENERIC = {
    "vaddps": _fp_packed(4, "add"),
    "vsubps": _fp_packed(4, "sub"),
    "vmulps": _fp_packed(4, "mul"),
    "vdivps": _fp_packed(4, "div"),
    "vminps": _fp_packed(4, "min"),
    "vmaxps": _fp_packed(4, "max"),
    "vaddpd": _fp_packed(8, "add"),
    "vsubpd": _fp_packed(8, "sub"),
    "vmulpd": _fp_packed(8, "mul"),
    "vdivpd": _fp_packed(8, "div"),
    "vminpd": _fp_packed(8, "min"),
    "vmaxpd": _fp_packed(8, "max"),
    "vaddss": _fp_scalar(4, "add"),
    "vsubss": _fp_scalar(4, "sub"),
    "vmulss": _fp_scalar(4, "mul"),
    "vdivss": _fp_scalar(4, "div"),
    "vaddsd": _fp_scalar(8, "add"),
    "vsubsd": _fp_scalar(8, "sub"),
    "vmulsd": _fp_scalar(8, "mul"),
    "vdivsd": _fp_scalar(8, "div"),
    "vpxor": _bitwise(lambda a, b: a ^ b),
    "vpand": _bitwise(lambda a, b: a & b),
    "vpor": _bitwise(lambda a, b: a | b),
    "vpandn": _bitwise(lambda a, b: (~a) & b & 0xFF),
    "vxorps": _bitwise(lambda a, b: a ^ b),
    "vxorpd": _bitwise(lambda a, b: a ^ b),
    "vandps": _bitwise(lambda a, b: a & b),
    "vorps": _bitwise(lambda a, b: a | b),
    "vpaddb": _lane_arith(1, lambda a, b: a + b),
    "vpaddw": _lane_arith(2, lambda a, b: a + b),
    "vpaddd": _lane_arith(4, lambda a, b: a + b),
    "vpaddq": _lane_arith(8, lambda a, b: a + b),
    "vpsubb": _lane_arith(1, lambda a, b: a - b),
    "vpsubw": _lane_arith(2, lambda a, b: a - b),
    "vpsubd": _lane_arith(4, lambda a, b: a - b),
    "vpsubq": _lane_arith(8, lambda a, b: a - b),
    "vpcmpeqb": _lane_compare(1, lambda a, b: a == b),
    "vpcmpeqw": _lane_compare(2, lambda a, b: a == b),
    "vpcmpeqd": _lane_compare(4, lambda a, b: a == b),
    "vpcmpeqq": _lane_compare(8, lambda a, b: a == b),
    "vpcmpgtb": _lane_compare(1, lambda a, b: _signed(a, 1) > _signed(b, 1)),
    "vpcmpgtw": _lane_compare(2, lambda a, b: _signed(a, 2) > _signed(b, 2)),
    "vpcmpgtd": _lane_compare(4, lambda a, b: _signed(a, 4) > _signed(b, 4)),
    "vpminub": _lane_arith(1, min),
    "vpmaxub": _lane_arith(1, max),
    "vpsllw": _shift(2, "l"), "vpslld": _shift(4, "l"), "vpsllq": _shift(8, "l"),
    "vpsrlw": _shift(2, "r"), "vpsrld": _shift(4, "r"), "vpsrlq": _shift(8, "r"),
    "vpsraw": _shift(2, "a"), "vpsrad": _shift(4, "a"),
}


def self_check():
    """Run the four instructions that exposed the defect and report the verdict.

    Returns a dict with the engine's own answer and this module's, so a caller
    can state which one it is trusting rather than assert it.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE

    state = bytes(range(16))
    key = bytes(range(16, 32))
    probes = [
        ("vpxor xmm2, xmm0, xmm1", "c5f9efd1", UX.UC_X86_REG_XMM2,
         bytes(a ^ b for a, b in zip(state, key))),
        ("vpaddb xmm2, xmm0, xmm1", "c5f9fcd1", UX.UC_X86_REG_XMM2,
         bytes((a + b) & 0xFF for a, b in zip(state, key))),
        ("vpslldq xmm2, xmm0, 4", "c5e973f804", UX.UC_X86_REG_XMM2,
         (b"\0" * 4 + state)[:16]),
        ("vaesenc xmm2, xmm0, xmm1", "c4e279dcd1", UX.UC_X86_REG_XMM2,
         aes_enc(state, key)),
    ]
    report = {"engine_correct": True, "layer_correct": True, "probes": []}
    for label, encoding, reg, want in probes:
        for intercepted in (False, True):
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            uc.mem_map(0x1000, 0x1000)
            blob = bytes.fromhex(encoding)
            uc.mem_write(0x1000, blob + b"\x90" * 8)
            uc.reg_write(UX.UC_X86_REG_XMM0, int.from_bytes(state, "little"))
            uc.reg_write(UX.UC_X86_REG_XMM1, int.from_bytes(key, "little"))
            uc.reg_write(UX.UC_X86_REG_XMM2, 0)
            if intercepted:
                layer = VexLayer(uc, 64)
                uc.hook_add(UC_HOOK_CODE,
                            lambda u, a, s, _d, _l=layer: _l.step(a, s))
            try:
                uc.emu_start(0x1000, 0x1000 + len(blob), count=1)
                got = uc.reg_read(reg).to_bytes(16, "little")
            except Exception:
                got = None
            if intercepted:
                layer_ok = got == want
            else:
                engine_ok = got == want
        report["engine_correct"] &= engine_ok
        report["layer_correct"] &= layer_ok
        report["probes"].append({"instruction": label, "engine": engine_ok,
                                 "intercepted": layer_ok, "expected": want.hex()})
    return report
