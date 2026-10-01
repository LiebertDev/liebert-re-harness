"""code_sweep_chunking.py has no coverage anywhere in this repo (per the port
audit) -- this is new, written for the public port batch. Uses real
capstone disassembly (a core public dependency) over a small, real x86-64
byte buffer to prove both halves of the module's contract: the pure
partition math in chunk_boundaries(), and disasm_chunk()'s exactly-once
crediting across a chunk boundary."""
from __future__ import annotations

import unittest

import capstone

from liebert_re.recover.code_sweep_chunking import chunk_boundaries, disasm_chunk


class ChunkBoundariesTests(unittest.TestCase):
    def test_empty_or_non_positive_size_yields_nothing(self):
        self.assertEqual(list(chunk_boundaries(0)), [])
        self.assertEqual(list(chunk_boundaries(-5)), [])
        self.assertEqual(list(chunk_boundaries(10, chunk_bytes=0)), [])

    def test_exact_multiple_partitions_cleanly(self):
        bounds = list(chunk_boundaries(30, chunk_bytes=10))
        self.assertEqual(bounds, [(0, 10), (10, 20), (20, 30)])

    def test_remainder_produces_a_final_short_chunk(self):
        bounds = list(chunk_boundaries(25, chunk_bytes=10))
        self.assertEqual(bounds, [(0, 10), (10, 20), (20, 25)])

    def test_size_smaller_than_chunk_bytes_is_one_chunk(self):
        self.assertEqual(list(chunk_boundaries(5, chunk_bytes=1_000_000)), [(0, 5)])

    def test_partitions_cover_every_byte_exactly_once(self):
        size = 1_234_567
        bounds = list(chunk_boundaries(size, chunk_bytes=100_000))
        covered = 0
        for start, end in bounds:
            self.assertEqual(start, covered)  # contiguous, no gap
            covered = end
        self.assertEqual(covered, size)


class DisasmChunkTests(unittest.TestCase):
    def setUp(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = False
        # 4 real x86-64 instructions, each a distinct known length:
        # mov eax,1 (5) ; mov ebx,2 (5) ; mov ecx,3 (5) ; ret (1) = 16 bytes.
        self.code = (
            b"\xb8\x01\x00\x00\x00"
            b"\xbb\x02\x00\x00\x00"
            b"\xb9\x03\x00\x00\x00"
            b"\xc3"
        )
        self.va_base = 0x1000

    def test_disassembles_the_whole_buffer_in_one_chunk(self):
        insns = list(disasm_chunk(
            self.md, self.code, file_offset=0, va_base=self.va_base,
            true_start=0, true_end=len(self.code), overlap_bytes=0,
        ))
        self.assertEqual(len(insns), 4)
        self.assertTrue(all(credited for _, credited in insns))
        mnemonics = [insn.mnemonic for insn, _ in insns]
        self.assertEqual(mnemonics, ["mov", "mov", "mov", "ret"])

    def test_credits_only_instructions_starting_inside_the_true_window(self):
        # Split the same 16 bytes into two chunks at byte 10 (mid third
        # instruction... but instructions here are 5-byte aligned, so cut
        # exactly between instruction 2 and instruction 3: true_end=10).
        first = list(disasm_chunk(
            self.md, self.code, file_offset=0, va_base=self.va_base,
            true_start=0, true_end=10, overlap_bytes=16,
        ))
        second = list(disasm_chunk(
            self.md, self.code, file_offset=0, va_base=self.va_base,
            true_start=10, true_end=16, overlap_bytes=16,
        ))
        first_credited = [insn.mnemonic for insn, credited in first if credited]
        second_credited = [insn.mnemonic for insn, credited in second if credited]
        # Exactly-once: every instruction credited by exactly one side.
        self.assertEqual(len(first_credited) + len(second_credited), 4)
        self.assertEqual(first_credited, ["mov", "mov"])
        self.assertEqual(second_credited, ["mov", "ret"])

    def test_overlap_provides_backward_context_without_double_crediting(self):
        # true_start=5 with overlap=5 means capstone is fed bytes starting at
        # absolute offset 0 (context), but only the instruction at VA
        # va_base+5 or later is credited.
        insns = list(disasm_chunk(
            self.md, self.code, file_offset=0, va_base=self.va_base,
            true_start=5, true_end=10, overlap_bytes=5,
        ))
        credited = [insn.mnemonic for insn, c in insns if c]
        self.assertEqual(credited, ["mov"])  # only the second mov, not the first

    def test_generator_is_closed_even_on_early_break(self):
        gen = disasm_chunk(
            self.md, self.code, file_offset=0, va_base=self.va_base,
            true_start=0, true_end=len(self.code), overlap_bytes=0,
        )
        first_insn, _ = next(gen)
        self.assertEqual(first_insn.mnemonic, "mov")
        gen.close()  # must not raise (proves the finally: gen.close() path is safe)


if __name__ == "__main__":
    unittest.main()
