"""The WNL-T2-005 packer's stage-2 decryption, reproduced offline.

Stage 2 is AES-128-CTR built from AES-NI at `0x14078efb0`-`0x14078f00c`, over
2,252,400 bytes at `0x140792000`. Its key is loaded from memory by
`vmovdqu xmm4, [rsp+0x30]` at `0x14078edd0`, one instruction before the key
schedule starts, and the CTR IV sits at `rsp+0x40`: eight nonce bytes and a
counter half that is zeroed, with the counter written big-endian into bytes
8-15 of each block.

Both values were *measured* from that stack frame rather than read out of xmm
registers, and getting there took two attempts. The first read the register
snapshot and produced a key that decrypted the region to noise, because this
engine executes VEX instructions as their legacy SSE equivalents (GAP-036) and
the packer's key derivation is built from `vpxor` and `vpaddb`. The frame
carries its own proof that the second attempt is right: the 16 bytes at
`rsp+0x68` are the stage-1 key, which `test_elevenpack_stage1_wnl005.py`
verifies byte-for-byte over 110,144 bytes without any emulator.

Like the stage-1 test, this one needs no emulator: stage 1 never touches the
stage-2 region, so the ciphertext is the corpus file's own bytes.

The oracle is the target's own code. Entropy cannot tell a right key from a
wrong one here -- both look random -- but the routine at `0x14078f16f` reads
the region's first dword as an FNV-1a-32 seed and the dwords after it as hashes
of the API names it resolves, so a correct key makes those hash real names.
"""
from __future__ import annotations

import collections
import hashlib
import math
import struct
import sys
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "emulation_scripts"))
import vex  # noqa: E402  -- for its FIPS-197-anchored AES round

TARGET_SHA256 = "00881b495de5fb85523a739f0367d14f89ac585925c5ca868255786cadf4cd5d"
SECTION_RVA = 0x700000
SECTION_VA = 0x140700000
STAGE2_OFFSET = 0x140792000 - SECTION_VA
STAGE2_BLOCKS = 0x225E7
STAGE2_KEY = bytes.fromhex("385e9921891db7700c11195d86c3fa43")
STAGE2_NONCE = bytes.fromhex("e2e2278ac4290135")
UNPACKED_SIZE = 0x233000
UNPACKED_SHA256 = "05017407c3a174fd908d17c651fbd68bd8b02281ee55d98c88ab934ca6dc9ccd"
UNPACKED_HEAD = bytes.fromhex("f0040200c0810700582f0900c0810700")
FNV_PRIME = 0x01000193
RESOLVED_NAMES = ("FlushInstructionCache", "LoadLibraryA", "GetProcAddress")


def _expand(key):
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


def _encrypt_block(schedule, block):
    state = bytes(a ^ b for a, b in zip(block, schedule[0]))
    for r in range(1, 10):
        state = vex.aes_enc(state, schedule[r])
    return vex.aes_enc(state, schedule[10], last=True)


def decrypt(cipher, blocks, key=STAGE2_KEY, nonce=STAGE2_NONCE, first=0):
    """CTR: keystream block i is E(key, nonce || counter-big-endian)."""
    schedule = _expand(key)
    out = bytearray()
    for i in range(first, first + blocks):
        keystream = _encrypt_block(schedule, nonce + i.to_bytes(8, "big"))
        chunk = cipher[STAGE2_OFFSET + 16 * i:STAGE2_OFFSET + 16 * i + 16]
        out += bytes(a ^ b for a, b in zip(keystream, chunk))
    return bytes(out)


def fnv1a(name, seed):
    """The hash at `0x14078f200`: FNV-1a-32 with A-Z lower-cased, seeded from
    the region's own first dword rather than the published basis."""
    h = seed
    for ch in name.encode("ascii"):
        if 0x41 <= ch <= 0x5A:
            ch |= 0x20
        h = ((h ^ ch) * FNV_PRIME) & 0xFFFFFFFF
    return h




def lzss_unpack(data, capacity):
    """The packer's decompressor, transcribed from 0x14078f851-0x14078f95a.

    A tag byte carries eight flags, LSB first. A set flag is a literal byte; a
    clear one is a 16-bit little-endian code whose low nibble plus three is the
    match length and whose top twelve bits are the distance backwards into the
    output already produced.
    """
    out = bytearray()
    i, n = 0, len(data)
    while i < n and len(out) < capacity:
        tag = data[i]
        i += 1
        for bit in range(8):
            if i >= n or len(out) >= capacity:
                break
            if tag & (1 << bit):
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= n:
                return bytes(out)
            code = data[i] | (data[i + 1] << 8)
            i += 2
            length, distance = (code & 0xF) + 3, code >> 4
            if distance == 0 or distance > len(out):
                return bytes(out)
            for _ in range(length):
                if len(out) >= capacity:
                    break
                out.append(out[len(out) - distance])
    return bytes(out)


def _entropy(data):
    counts = collections.Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _binary():
    p = Path("benchmarks/windows_native_ladder/corpus/tier2/decryption_key1/elevenpack.exe")
    if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == TARGET_SHA256:
        return p
    return None


class ElevenpackStage2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if _binary() is None:
            raise unittest.SkipTest("WNL-T2-005 corpus binary not present")
        try:
            import pefile
        except ImportError:
            raise unittest.SkipTest("pefile not available")
        pe = pefile.PE(str(_binary()), fast_load=True)
        section = [s for s in pe.sections if s.VirtualAddress == SECTION_RVA][0]
        cls.cipher = bytes(pe.__data__)[section.PointerToRawData:
                                        section.PointerToRawData + section.SizeOfRawData]
        pe.close()
        cls.head = decrypt(cls.cipher, 16)

    def test_the_region_ends_exactly_at_the_section_end(self):
        """A parameter check that costs nothing: the loop's own block count
        covers the section to its last 0x190 bytes, so a mis-read count would
        show here rather than in a wrong-looking plaintext."""
        self.assertEqual(STAGE2_OFFSET + 16 * STAGE2_BLOCKS, 0x2B7E70)
        self.assertLessEqual(STAGE2_OFFSET + 16 * STAGE2_BLOCKS, len(self.cipher))

    def test_the_first_dwords_are_the_hashes_the_target_resolves(self):
        """The oracle. `0x14078f16f` reads dword 0 as the seed and the dwords
        after it as name hashes; with the right key they are the three APIs a
        packer needs, in the order the code reads them."""
        words = struct.unpack_from("<4I", self.head)
        seed = words[0]
        for index, name in enumerate(RESOLVED_NAMES, start=1):
            with self.subTest(api=name):
                self.assertEqual(words[index], fnv1a(name, seed))

    def test_the_key_and_the_nonce_are_both_load_bearing(self):
        """Flip one bit of either and the resolver constants stop being
        hashes of anything. That is what makes them measurements."""
        wrong_key = bytearray(STAGE2_KEY)
        wrong_key[0] ^= 1
        wrong_nonce = bytearray(STAGE2_NONCE)
        wrong_nonce[0] ^= 1
        for label, blob in (("key", decrypt(self.cipher, 4, key=bytes(wrong_key))),
                            ("nonce", decrypt(self.cipher, 4, nonce=bytes(wrong_nonce)))):
            with self.subTest(changed=label):
                words = struct.unpack_from("<4I", blob)
                matches = [w for i, w in enumerate(words[1:])
                           if w == fnv1a(RESOLVED_NAMES[i], words[0])]
                self.assertEqual(matches, [])

    def test_the_counter_runs_big_endian_from_zero(self):
        """CTR mode is only reproducible if the counter is assembled the way
        the loop does it -- `bswap` then `vpinsrq ..., 1`. A little-endian
        counter reproduces block 0 and nothing after it."""
        schedule = _expand(STAGE2_KEY)
        little = _encrypt_block(schedule, STAGE2_NONCE + (1).to_bytes(8, "little"))
        big = _encrypt_block(schedule, STAGE2_NONCE + (1).to_bytes(8, "big"))
        self.assertNotEqual(little, big)
        block_one = decrypt(self.cipher, 1, first=1)
        chunk = self.cipher[STAGE2_OFFSET + 16:STAGE2_OFFSET + 32]
        self.assertEqual(block_one, bytes(a ^ b for a, b in zip(big, chunk)))

    def test_the_header_below_stage_two_is_structured(self):
        """Not an entropy claim in the other direction: the decrypted region
        opens with small, sane values -- a payload length that matches the
        region, and counts of 0x40/0x80 -- where the wrong key gave uniform
        noise with a longest zero run of two bytes."""
        self.assertEqual(struct.unpack_from("<I", self.head, 0x14)[0], 0x40)
        self.assertEqual(struct.unpack_from("<I", self.head, 0x1C)[0], 0x80)
        payload_length = struct.unpack_from("<I", self.head, 0x48)[0]
        self.assertEqual(payload_length, 0x225DEB)
        self.assertLess(payload_length, 16 * STAGE2_BLOCKS)

    def test_the_header_names_the_key_of_the_layer_below_it(self):
        """The stage-2 region is a header plus a payload, and the header
        carries its successor's key at +0x58, its nonce at +0x68 and its length
        at +0x48. Decrypting the payload the same way collapses the entropy;
        flipping one bit of that key restores it. Entropy is not the claim here
        -- it is the *difference* that is, and it is what a wrong reading
        cannot produce."""
        head = decrypt(self.cipher, 0x400)
        key, nonce = head[0x58:0x68], head[0x68:0x70]
        self.assertEqual(struct.unpack_from("<I", head, 0x48)[0], 0x225DEB)
        body = head[0x80:0x80 + 0x300]
        schedule = _expand(key)
        wrong = bytearray(key)
        wrong[0] ^= 1
        wrong_schedule = _expand(bytes(wrong))

        def unroll(sched):
            out = bytearray()
            for i in range(len(body) // 16):
                keystream = _encrypt_block(sched, nonce + i.to_bytes(8, "big"))
                out += bytes(a ^ b for a, b in zip(keystream, body[16 * i:16 * i + 16]))
            return bytes(out)

        right = _entropy(unroll(schedule))
        noise = _entropy(unroll(wrong_schedule))
        self.assertLess(right, 6.5, "the header's own key should expose structure")
        self.assertGreater(noise - right, 1.0,
                           "a one-bit change in that key must destroy the structure")

    # --- heavy marker (test-suite split: fast baseline vs. slow-but-correct) ---
    # Measured at ~100s standalone (8 passed, 5 subtests passed in 99.42s): two
    # full-region pure-Python AES-128-CTR decrypts (~280k blocks total, see
    # STAGE2_BLOCKS) plus an LZSS decompress over the ~0x233000-byte image.
    # This always completes and always passes; it is legitimately slow, not
    # stuck -- excluded from the default run and must be run explicitly with
    # `pytest -m heavy`.
    @pytest.mark.heavy
    def test_the_whole_packer_unpacks_offline(self):
        """End to end, from the corpus file's own bytes: stage 2, then the
        layer its header describes, then the decompressor at 0x14078f851. The
        check that it is right is not how the output looks -- it is that it
        fills the descriptor's declared 0x233000 bytes exactly, and that its
        first 16 bytes are the ones the emulator independently writes into the
        reserved section at 0x1404cd000, which every run before the VEX repair
        left zero."""
        stage2 = decrypt(self.cipher, STAGE2_BLOCKS)[:16 * STAGE2_BLOCKS]
        key, nonce = stage2[0x58:0x68], stage2[0x68:0x70]
        length = struct.unpack_from("<I", stage2, 0x48)[0]
        capacity = struct.unpack_from("<I", stage2, 0x44)[0]
        self.assertEqual(capacity, UNPACKED_SIZE)
        body = stage2[0x80:0x80 + length]
        schedule = _expand(key)
        layer3 = bytearray()
        for i in range((len(body) + 15) // 16):
            keystream = _encrypt_block(schedule, nonce + i.to_bytes(8, "big"))
            layer3 += bytes(a ^ b for a, b in zip(keystream, body[16 * i:16 * i + 16]))
        image = lzss_unpack(bytes(layer3)[:length], capacity)
        self.assertEqual(len(image), capacity,
                         "a wrong decompressor overshoots or falls short")
        self.assertEqual(image[:16], UNPACKED_HEAD)
        self.assertEqual(hashlib.sha256(image).hexdigest(), UNPACKED_SHA256)

    def test_the_ciphertext_is_not_already_the_plaintext(self):
        raw = self.cipher[STAGE2_OFFSET:STAGE2_OFFSET + 16]
        self.assertNotEqual(raw, self.head[:16])


if __name__ == "__main__":
    unittest.main()
