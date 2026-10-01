"""disassemble_pe must not let capstone allocate for a whole section.

``Cs.disasm()`` is one native call that allocates for its ENTIRE input before
yielding the first item (see ``code_sweep_chunking``), so the old
``for ins in md.disasm(data[start:], base): ... break`` bounded the returned
list but not the allocation. These tests pin the four properties of the fix:

a. output is byte-identical to the old single-call implementation;
b. process RSS does not scale with section size (native heap is invisible to
   tracemalloc, so psutil RSS is the measure);
c. an instruction straddling a chunk seam appears exactly once, and a
   many-chunk run equals a one-chunk run;
d. the structural guarantee behind (b): no single ``disasm`` call ever
   receives more than chunk + 2*overlap bytes.
"""
from __future__ import annotations

import shutil
import struct
import threading
import unittest
from pathlib import Path
from unittest import mock

import capstone
import pefile
import psutil

import liebert_re.recover.code_sweep_chunking as code_sweep_chunking
import liebert_re.tools.binary as tools_binary
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
from liebert_re.tools.binary import disassemble_pe

REPO_ROOT = Path(__file__).resolve().parent.parent
# safe_path confines to the workspace, so fixtures live under it (as siblings do).
SCRATCH = REPO_ROOT / "dataset" / "runtime" / "_test_disassemble_pe_chunking_scratch"

MOV_RAX_IMM64 = b"\x48\xb8" + struct.pack("<Q", 0x1122334455667788)  # 10 bytes
MOV_EAX_1 = b"\xb8\x01\x00\x00\x00"                                   # 5 bytes
PUSH_RBP = b"\x55"
RET = b"\xc3"


def _mixed_code(n_blocks: int) -> bytes:
    """Valid x86-64 of mixed lengths (1, 5, 10) so seams land mid-instruction."""
    return (PUSH_RBP + MOV_EAX_1 + MOV_RAX_IMM64 + RET) * n_blocks


def _legacy_listing(path: Path, start_offset: int = 0, max_instructions: int = 250) -> str:
    """The pre-fix loop, verbatim: one disasm() over the whole section."""
    pe = pefile.PE(data=path.read_bytes())
    sec = pe.sections[0]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    data = sec.get_data()
    start_offset = max(0, min(int(start_offset), len(data)))
    base = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress + start_offset
    out = []
    for ins in md.disasm(data[start_offset:], base):
        out.append(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}".rstrip())
        if len(out) >= max_instructions:
            break
    return "\n".join(out)


class _Scratch(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, ignore_errors=True)

    def _pe(self, code: bytes, name: str = "f.exe") -> Path:
        return build_owned_pe_with_code(SCRATCH / name, code)


class BehaviourCompatibilityTests(_Scratch):
    def test_small_section_matches_the_old_implementation_exactly(self):
        code = _mixed_code(40) + b"\x06\x06" + _mixed_code(5)  # 0x06 undecodable -> .byte
        path = self._pe(code)
        for start, cap in ((0, 10_000), (0, 7), (13, 50), (len(code) - 3, 100)):
            new = disassemble_pe(str(path), section=".text", start_offset=start, max_instructions=cap)
            old = _legacy_listing(path, start, cap)
            # A capped listing now carries one trailing marker line; everything
            # before it must be byte-identical to the old output.
            body = new.split("\n[ANALYSIS_LIMITED")[0]
            self.assertEqual(body, old, f"start={start} cap={cap}")

    def test_uncapped_output_has_no_marker_and_equals_old_exactly(self):
        path = self._pe(_mixed_code(20))
        new = disassemble_pe(str(path), section=".text", max_instructions=10_000)
        self.assertEqual(new, _legacy_listing(path, 0, 10_000))
        self.assertNotIn("ANALYSIS_LIMITED", new)

    def test_cap_landing_exactly_on_the_last_instruction_is_not_marked(self):
        # 30 blocks * 17 bytes + 2 nops = 512 = the whole raw section: no padding follows.
        path = self._pe(_mixed_code(30) + b"\x90\x90")
        n = 30 * 4 + 2
        out = disassemble_pe(str(path), section=".text", max_instructions=n)
        self.assertEqual(len(out.splitlines()), n)
        self.assertNotIn("ANALYSIS_LIMITED", out)

    def test_hitting_the_cap_is_visible_and_names_where_it_stopped(self):
        path = self._pe(_mixed_code(10))
        out = disassemble_pe(str(path), section=".text", max_instructions=4)
        lines = out.split("\n")
        self.assertEqual(len(lines), 5)
        self.assertTrue(lines[-1].startswith("[ANALYSIS_LIMITED:"))
        self.assertIn("max_instructions=4", lines[-1])
        # the resume address is the address of the 5th instruction
        full = _legacy_listing(path, 0, 5).split("\n")[-1].split(":")[0]
        self.assertIn(full, lines[-1])


class ChunkSeamTests(_Scratch):
    def test_many_chunks_equal_one_chunk_and_each_instruction_appears_once(self):
        code = _mixed_code(60)  # 960 bytes
        path = self._pe(code)
        one = disassemble_pe(str(path), section=".text", max_instructions=10_000)
        with mock.patch.object(tools_binary, "_DISASM_CHUNK_BYTES", 7):  # seams mid-instruction
            many = disassemble_pe(str(path), section=".text", max_instructions=10_000)
        self.assertEqual(many, one)
        addrs = [ln.split(":")[0] for ln in many.split("\n")]
        self.assertEqual(len(addrs), len(set(addrs)), "an instruction was credited twice")
        self.assertEqual(len(addrs), len(_legacy_listing(path, 0, 10**9).splitlines()))

    def test_instruction_straddling_a_seam_is_credited_once_by_its_start(self):
        # 10-byte movabs at offsets 1..10; a 4-byte chunk puts seams at 4 and 8.
        path = self._pe(PUSH_RBP + MOV_RAX_IMM64 + RET)
        with mock.patch.object(tools_binary, "_DISASM_CHUNK_BYTES", 4):
            out = disassemble_pe(str(path), section=".text", max_instructions=100)
        self.assertEqual(out.count("movabs"), 1)
        self.assertEqual(out.split("\n[ANALYSIS_LIMITED")[0], _legacy_listing(path, 0, 100))

    def test_start_offset_does_not_shift_addresses_across_chunks(self):
        path = self._pe(_mixed_code(30))
        with mock.patch.object(tools_binary, "_DISASM_CHUNK_BYTES", 9):
            out = disassemble_pe(str(path), section=".text", start_offset=1, max_instructions=10_000)
        self.assertEqual(out, _legacy_listing(path, 1, 10_000))
        self.assertTrue(out.startswith("0x140001001:"))


class BoundedAllocationTests(_Scratch):
    def test_structural_no_disasm_call_exceeds_one_chunk(self):
        """Structural guarantee behind the RSS test: spy on every disasm call."""
        chunk = 100
        overlap = code_sweep_chunking.DEFAULT_CHUNK_OVERLAP_BYTES
        path = self._pe(_mixed_code(3000))  # ~51 KB, ~500 chunks
        sizes = []
        real = capstone.Cs.disasm

        def spy(self_, code, *a, **k):
            sizes.append(len(code))
            return real(self_, code, *a, **k)

        with mock.patch.object(capstone.Cs, "disasm", spy), \
                mock.patch.object(tools_binary, "_DISASM_CHUNK_BYTES", chunk):
            disassemble_pe(str(path), section=".text", max_instructions=10_000)
        self.assertGreater(len(sizes), 1)
        self.assertLessEqual(max(sizes), chunk + 2 * overlap)
        section_len = len(pefile.PE(data=path.read_bytes()).sections[0].get_data())
        self.assertLess(max(sizes), section_len, "a call saw the whole section")

    def test_structural_capped_run_stops_decoding_further_chunks(self):
        path = self._pe(b"\x90" * 40_000)
        calls = []
        real = capstone.Cs.disasm

        def spy(self_, code, *a, **k):
            calls.append(len(code))
            return real(self_, code, *a, **k)

        with mock.patch.object(capstone.Cs, "disasm", spy), \
                mock.patch.object(tools_binary, "_DISASM_CHUNK_BYTES", 1000):
            disassemble_pe(str(path), section=".text", max_instructions=5)
        self.assertEqual(len(calls), 1, "cap reached in chunk 1 must not decode later chunks")

    def test_rss_growth_does_not_scale_with_section_size(self):
        """Native capstone heap is invisible to tracemalloc, so measure RSS.

        The old path costs ~248 native bytes per input byte, so a 24 MB
        section would need ~6 GB; we never run that path. The new path costs
        about one chunk (1 MB -> a few hundred MB) whatever the section size.
        """
        proc = psutil.Process()

        def peak_growth(size: int) -> int:
            path = self._pe(b"\x90" * size, name=f"big_{size}.exe")
            base = proc.memory_info().rss
            peak = [base]
            stop = threading.Event()

            def sample():
                while not stop.is_set():
                    peak[0] = max(peak[0], proc.memory_info().rss)
                    stop.wait(0.002)

            t = threading.Thread(target=sample, daemon=True)
            t.start()
            try:
                out = disassemble_pe(str(path), section=".text", max_instructions=50)
            finally:
                stop.set()
                t.join()
            self.assertIn("ANALYSIS_LIMITED", out)
            path.unlink()
            return peak[0] - base

        small = peak_growth(2_000_000)
        large = peak_growth(24_000_000)  # 12x larger; old path would be ~6 GB
        limit = 700 * 1024 * 1024
        self.assertLess(large, limit, f"large={large / 1e6:.0f} MB small={small / 1e6:.0f} MB")
        # not proportional to size: 12x the section must not cost anywhere near 12x
        self.assertLess(large, max(small, 50 * 1024 * 1024) * 3,
                        f"large={large / 1e6:.0f} MB small={small / 1e6:.0f} MB")


if __name__ == "__main__":
    unittest.main()
