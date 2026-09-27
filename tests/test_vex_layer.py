"""Regression tests for the VEX repair (GAP-036).

The defect these pin down was found the expensive way. `WNL-T2-005`'s stage-2
AES-128 key was read out of the emulator, used to decrypt 2.24 MB, and the
result was noise -- because the engine had computed the key derivation's own
`vpxor` and `vpaddb` as legacy SSE instructions, ignoring the second source
operand. Nothing faulted and nothing warned. An earlier session had already
mis-attributed the same defect to AES-NI; the legacy `aesenc` encoding is in
fact correct on this build, and the one-instruction probe below is what tells
those two apart.

So three things are pinned here:

1. The layer's own arithmetic is right, anchored to FIPS-197 rather than to
   what any engine happens to return.
2. Every instruction the layer models is executed correctly through a real
   emulator, compared against a value computed independently in the test.
3. A VEX instruction the layer does not model stops the run. A plausible wrong
   answer is the failure this exists to prevent, so falling through to the
   engine is never acceptable.

The engine's own verdict is deliberately NOT asserted: if a future unicorn
decodes VEX correctly, these tests must still pass.
"""
from __future__ import annotations

import unittest

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
    from unicorn import x86_const as UX
    import capstone  # noqa: F401  -- the layer decodes with it
    ENGINE = True
except Exception:  # pragma: no cover - environment without the engine
    ENGINE = False

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "emulation_scripts"))
import vex  # noqa: E402

CODE = 0x1000
A = bytes(range(16))
B = bytes(range(0x10, 0x20))



def _expand(key):
    """AES-128 key expansion, written here rather than imported, so the test
    does not check the layer against the layer."""
    rcon = (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
    words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [vex._SBOX[b] for b in temp]
            temp[0] ^= rcon[i // 4 - 1]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [bytes(sum(words[r * 4:r * 4 + 4], [])) for r in range(11)]


def _run(encoding, setup, count=1):
    """One instruction through a real emulator with the layer installed."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x4000)
    blob = bytes.fromhex(encoding)
    uc.mem_write(CODE, blob)
    uc.reg_write(UX.UC_X86_REG_RSP, CODE + 0x2000)
    for reg, value in setup:
        uc.reg_write(reg, value if isinstance(value, int)
                     else int.from_bytes(value, "little"))
    layer = vex.VexLayer(uc, 64)
    uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: layer.step(a, s))
    uc.emu_start(CODE, CODE + len(blob), count=count)
    return uc, layer


def _xmm(uc, index):
    return uc.reg_read(getattr(UX, "UC_X86_REG_XMM%d" % index)).to_bytes(16, "little")


class ArithmeticTests(unittest.TestCase):
    """The layer's own AES, anchored to the published vectors."""

    def test_the_aes_round_matches_fips_197(self):
        """FIPS-197 C.1: encrypting the published block with the published key
        must give the published ciphertext. Anything downstream of a wrong AES
        is worthless, so this is checked before the engine is involved."""
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        schedule = _expand(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        state = bytes(a ^ b for a, b in zip(plain, schedule[0]))
        for r in range(1, 10):
            state = vex.aes_enc(state, schedule[r])
        state = vex.aes_enc(state, schedule[10], last=True)
        self.assertEqual(state.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_keygenassist_matches_the_intel_definition(self):
        """SubWord on dwords 1 and 3, plus a rotate and the round constant on
        the copies. Computed here from the definition, not from the engine."""
        got = vex.aes_keygenassist(A, 1)
        sub = lambda w: bytes(vex._SBOX[b] for b in w)
        rot = lambda w: w[1:] + w[:1]
        x1, x3 = sub(A[4:8]), sub(A[12:16])
        r1 = bytes([rot(x1)[0] ^ 1]) + rot(x1)[1:]
        r3 = bytes([rot(x3)[0] ^ 1]) + rot(x3)[1:]
        self.assertEqual(got, x1 + r1 + x3 + r3)

    def test_the_decryption_round_recovers_the_fips_197_plaintext(self):
        """`aesdec` and `aesimc` are exercised the way real code uses them: the
        AES-NI decryption flow, run on the published C.1 ciphertext, must give
        back the published plaintext. That is an independent anchor -- a
        transposed inverse-MixColumns matrix passes a round-trip against my own
        encryption and fails this."""
        schedule = _expand(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        state = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        state = bytes(a ^ b for a, b in zip(state, schedule[10]))
        for r in range(9, 0, -1):
            state = vex.aes_dec(state, vex.aes_imc(schedule[r]))
        state = vex.aes_dec(state, schedule[0], last=True)
        self.assertEqual(state.hex(), "00112233445566778899aabbccddeeff")


@unittest.skipUnless(ENGINE, "unicorn/capstone not importable")
class InterceptionTests(unittest.TestCase):
    """Every modelled instruction, through a real emulator."""

    def test_the_engine_and_the_layer_are_both_measured_every_run(self):
        """The verdict a result carries has to be measured, not assumed. This
        asserts the mechanism: the probe reports both answers, and the layer's
        is correct. It deliberately does not assert the engine is wrong -- a
        fixed engine must not fail this test."""
        report = vex.self_check()
        self.assertTrue(report["layer_correct"])
        self.assertEqual(len(report["probes"]), 4)
        for probe in report["probes"]:
            self.assertTrue(probe["intercepted"], probe["instruction"])
            self.assertIn("engine", probe)

    def test_three_operand_forms_use_the_second_source(self):
        """The defect itself: `vpxor xmm2, xmm0, xmm1` must be xmm0 ^ xmm1, not
        xmm1. Same for the byte add. These two instructions are what corrupted
        a real key derivation."""
        uc, _ = _run("c5f9efd1", [(UX.UC_X86_REG_XMM0, A), (UX.UC_X86_REG_XMM1, B)])
        self.assertEqual(_xmm(uc, 2), bytes(a ^ b for a, b in zip(A, B)))
        uc, _ = _run("c5f9fcd1", [(UX.UC_X86_REG_XMM0, A), (UX.UC_X86_REG_XMM1, B)])
        self.assertEqual(_xmm(uc, 2), bytes((a + b) & 0xFF for a, b in zip(A, B)))

    def test_the_shift_group_writes_to_the_encoded_destination(self):
        """`vpslldq xmm0, xmm4, 4` leaves xmm4 alone. The engine shifts xmm4 in
        place instead, which is how a whole AES key schedule came out
        degenerate."""
        uc, _ = _run("c5f973fc04", [(UX.UC_X86_REG_XMM4, A)])
        self.assertEqual(_xmm(uc, 0), (b"\0" * 4 + A)[:16])
        self.assertEqual(_xmm(uc, 4), A)
        uc, _ = _run("c5f973dc04", [(UX.UC_X86_REG_XMM4, A)])
        self.assertEqual(_xmm(uc, 0), (A[4:] + b"\0" * 4)[:16])

    def test_the_aes_instructions(self):
        uc, _ = _run("c4e279dcd1", [(UX.UC_X86_REG_XMM0, A), (UX.UC_X86_REG_XMM1, B)])
        self.assertEqual(_xmm(uc, 2), vex.aes_enc(A, B))
        uc, _ = _run("c4e279ddd1", [(UX.UC_X86_REG_XMM0, A), (UX.UC_X86_REG_XMM1, B)])
        self.assertEqual(_xmm(uc, 2), vex.aes_enc(A, B, last=True))
        uc, _ = _run("c4e379dfd001", [(UX.UC_X86_REG_XMM0, A)])
        self.assertEqual(_xmm(uc, 2), vex.aes_keygenassist(A, 1))

    def test_moves_extracts_and_inserts(self):
        uc, _ = _run("c5f970d0ff", [(UX.UC_X86_REG_XMM0, A)])          # vpshufd ,0xff
        self.assertEqual(_xmm(uc, 2), A[12:16] * 4)
        uc, _ = _run("c4e1f97ec0", [(UX.UC_X86_REG_XMM0, A)])          # vmovq rax, xmm0
        self.assertEqual(uc.reg_read(UX.UC_X86_REG_RAX),
                         int.from_bytes(A[:8], "little"))
        uc, _ = _run("c4e3f916c101", [(UX.UC_X86_REG_XMM0, A)])        # vpextrq rcx,xmm0,1
        self.assertEqual(uc.reg_read(UX.UC_X86_REG_RCX),
                         int.from_bytes(A[8:], "little"))
        uc, _ = _run("c4e3f922c001", [(UX.UC_X86_REG_XMM0, A),
                                      (UX.UC_X86_REG_RAX, 0x1122334455667788)])
        self.assertEqual(_xmm(uc, 0),
                         A[:8] + (0x1122334455667788).to_bytes(8, "little"))

    def test_a_memory_destination_writes_only_its_own_width(self):
        """`vpextrb [rsp+0x40], xmm0, 7` writes one byte. A padded write would
        corrupt whatever the target put next to it -- and this target builds its
        counter block out of exactly these."""
        uc, _ = _run("c4e3791444244007", [(UX.UC_X86_REG_XMM0, A)])
        self.assertEqual(bytes(uc.mem_read(CODE + 0x2040, 2)), bytes([A[7], 0]))

    def test_an_unmodelled_vex_instruction_stops_rather_than_guesses(self):
        """Fail closed. The alternative is the engine's silent wrong answer,
        which is the entire reason this layer exists."""
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        # vpermq ymm0, ymm1, 0x1b -- a 256-bit form the layer does not model.
        uc.mem_write(CODE, bytes.fromhex("c4e3fd00c11b"))
        layer = vex.VexLayer(uc, 64)
        with self.assertRaises(vex.UnmodelledVex):
            layer.step(CODE, 6)

    def test_a_short_reported_size_does_not_wave_an_instruction_through(self):
        """The size a code hook reports is not trustworthy for an instruction
        the engine itself cannot decode -- it arrives as 1, and a layer that
        trusted it would silently pass exactly the instructions it exists to
        catch. Measured on a real target: `vmovups ymm0, [rip+0x20ddb]` in
        WNL-T2-023 was waved through and surfaced as an engine crash instead of
        a fail-closed stop."""
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        # vpermq ymm0, ymm1, 0x1b -- a 256-bit form the layer does not model.
        uc.mem_write(CODE, bytes.fromhex("c4e3fd00c11b"))
        layer = vex.VexLayer(uc, 64)
        with self.assertRaises(vex.UnmodelledVex):
            layer.step(CODE, 1)

    def test_a_modelled_instruction_is_executed_even_with_a_short_size(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        uc.mem_write(CODE, bytes.fromhex("c5f9efd1"))           # vpxor xmm2, xmm0, xmm1
        uc.reg_write(UX.UC_X86_REG_XMM0, int.from_bytes(A, "little"))
        uc.reg_write(UX.UC_X86_REG_XMM1, int.from_bytes(B, "little"))
        layer = vex.VexLayer(uc, 64)
        self.assertTrue(layer.step(CODE, 1))
        self.assertEqual(_xmm(uc, 2), bytes(a ^ b for a, b in zip(A, B)))

    def test_a_rewritten_instruction_is_decoded_again(self):
        """Self-modifying code is the normal case for the packers this runs on,
        so a cached decode has to be dropped when the bytes underneath it
        change."""
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        uc.mem_write(CODE, bytes.fromhex("c5f9efd1"))          # vpxor xmm2,xmm0,xmm1
        uc.reg_write(UX.UC_X86_REG_XMM0, int.from_bytes(A, "little"))
        uc.reg_write(UX.UC_X86_REG_XMM1, int.from_bytes(B, "little"))
        layer = vex.VexLayer(uc, 64)
        layer.step(CODE, 4)
        self.assertEqual(_xmm(uc, 2), bytes(a ^ b for a, b in zip(A, B)))
        uc.mem_write(CODE, bytes.fromhex("c5f9fcd1"))          # now vpaddb
        layer.invalidate(CODE, 4)
        layer.step(CODE, 4)
        self.assertEqual(_xmm(uc, 2), bytes((a + b) & 0xFF for a, b in zip(A, B)))


@unittest.skipUnless(ENGINE, "unicorn/capstone not importable")
class WideTests(unittest.TestCase):
    """256-bit AVX (GAP-037).

    The engine rejects these outright -- `UC_ERR_INSN_INVALID`, a hard stop
    rather than GAP-036's silent wrong answer -- and that is where WNL-T2-023
    ended after 175,459,147 instructions. The layer executes them instead: the
    code hook fires before the engine's rejection, and this build's ymm
    registers round-trip a full 32 bytes.
    """

    WIDE = bytes(range(32))
    OTHER = bytes((0x40 + i) & 0xFF for i in range(32))

    def _ymm(self, uc, index):
        return uc.reg_read(getattr(UX, "UC_X86_REG_YMM%d" % index)).to_bytes(32, "little")

    def test_a_wide_load_and_store(self):
        """`vmovups ymm0, [rip+8]` then `vmovups [rsp], ymm0`."""
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        # vmovups ymm0, ymmword ptr [rip + 0] -- rip is already past the
        # eight-byte instruction, so the source is CODE + 8.
        uc.mem_write(CODE, bytes.fromhex("c5fc100500000000"))
        uc.mem_write(CODE + 8, self.WIDE)
        uc.reg_write(UX.UC_X86_REG_RSP, CODE + 0x2000)
        layer = vex.VexLayer(uc, 64)
        uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: layer.step(a, s))
        uc.emu_start(CODE, CODE + 8, count=1)
        self.assertEqual(self._ymm(uc, 0), self.WIDE)
        # store it back out: vmovups ymmword ptr [rsp], ymm0 -> c5 fc 11 04 24
        uc.mem_write(CODE, bytes.fromhex("c5fc110424"))
        layer.invalidate(CODE, 8)
        uc.emu_start(CODE, CODE + 5, count=1)
        self.assertEqual(bytes(uc.mem_read(CODE + 0x2000, 32)), self.WIDE)

    def test_a_wide_bitwise_operation_uses_both_sources(self):
        """`vxorps ymm2, ymm0, ymm1` over the full 256 bits -- the defect this
        module exists for, one width up."""
        uc, layer = self._prepared("c5fc57d1")   # vxorps ymm2, ymm0, ymm1
        uc.emu_start(CODE, CODE + 4, count=1)
        self.assertEqual(self._ymm(uc, 2),
                         bytes(a ^ b for a, b in zip(self.WIDE, self.OTHER)))

    def test_packed_single_precision_arithmetic(self):
        """Eight float32 lanes, checked against the same arithmetic done in
        the test rather than against the engine."""
        import struct
        for encoding, op in (("c5fc58d1", lambda x, y: x + y),      # vaddps
                             ("c5fc5cd1", lambda x, y: x - y),      # vsubps
                             ("c5fc59d1", lambda x, y: x * y)):     # vmulps
            with self.subTest(encoding=encoding):
                uc, layer = self._prepared(encoding)
                uc.emu_start(CODE, CODE + 4, count=1)
                got = self._ymm(uc, 2)
                for lane in range(8):
                    x = struct.unpack_from("<f", self.WIDE, lane * 4)[0]
                    y = struct.unpack_from("<f", self.OTHER, lane * 4)[0]
                    want = struct.pack("<f", op(x, y))
                    self.assertEqual(got[lane * 4:lane * 4 + 4], want)

    def test_vzeroupper_clears_the_upper_half_and_keeps_the_lower(self):
        """It was a no-op while 256-bit state was unmodelled; now that the
        state exists, leaving it a no-op would hand stale bytes to the next
        read."""
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        uc.mem_write(CODE, bytes.fromhex("c5f877"))               # vzeroupper
        uc.reg_write(UX.UC_X86_REG_YMM0, int.from_bytes(self.WIDE, "little"))
        layer = vex.VexLayer(uc, 64)
        uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: layer.step(a, s))
        uc.emu_start(CODE, CODE + 3, count=1)
        self.assertEqual(self._ymm(uc, 0), self.WIDE[:16] + bytes(16))

    def _prepared(self, encoding):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x4000)
        uc.mem_write(CODE, bytes.fromhex(encoding))
        uc.reg_write(UX.UC_X86_REG_RSP, CODE + 0x2000)
        uc.reg_write(UX.UC_X86_REG_YMM0, int.from_bytes(self.WIDE, "little"))
        uc.reg_write(UX.UC_X86_REG_YMM1, int.from_bytes(self.OTHER, "little"))
        layer = vex.VexLayer(uc, 64)
        uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: layer.step(a, s))
        return uc, layer


class GenericityTests(unittest.TestCase):
    """The layer is a CPU, not a plugin for one sample."""

    def test_the_module_names_no_sample(self):
        text = (Path(vex.__file__)).read_text(encoding="utf-8")
        for forbidden in ("elevenpack", "WNL-T2", "crackme", "0x14078"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool (Ghidra analyzeHeadless, IDA idat.exe, angr, unicorn,
# frida, or a Hyper-V guest) or spawns a bounded subprocess -- these can be slow or hang,
# so they are excluded from the default run and must be run explicitly with `pytest -m heavy`.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
