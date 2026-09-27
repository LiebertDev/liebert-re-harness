"""Tests for tools_crypto_id.crypto_constant_scan.

Two things are worth protecting here, and both are real rather than decorative:

1. THE CONSTANT TABLE ITSELF. A single mistyped hex digit would silently
   misidentify an algorithm on a real target, and nothing else in the system
   would catch it. So the table is not merely compared against a second copy of
   the same literals -- every derivable constant is RE-DERIVED from first
   principles (roots of primes, sin(), the hex expansion of pi, the GF(2^8)
   inverse plus the AES affine transform) and checked against the table.

2. THE HONESTY OF ATTRIBUTION. The tool's value depends on it refusing to name
   an algorithm it cannot distinguish, and refusing to treat ubiquitous
   low-entropy words as evidence. The second of those is a regression test for a
   real defect observed on a real target: the first version of this tool
   reported 0x00000000 and 0x00000001 as "distinctive" constants and
   manufactured bogus CRC-32 and SHA-3 candidates out of them.
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
import tempfile
import unittest
from decimal import Decimal, getcontext
from pathlib import Path

import tools_crypto_id
from tools_crypto_id import _SIGNATURES, crypto_constant_scan


def _primes(n):
    out = []
    candidate = 2
    while len(out) < n:
        if all(candidate % p for p in out if p * p <= candidate):
            out.append(candidate)
        candidate += 1
    return out


def _frac_bits(value, bits, root):
    getcontext().prec = 80
    d = Decimal(value) ** (Decimal(1) / Decimal(root))
    return int((d - int(d)) * (1 << bits))


def _aes_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
            ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


def _pi_hex_words(count):
    """Fractional hex digits of pi, as 32-bit words -- the Blowfish P array."""
    getcontext().prec = 120

    def arctan_inv(x):
        total = term = Decimal(1) / Decimal(x)
        i = 1
        xx = Decimal(x) * Decimal(x)
        while True:
            term /= -xx
            nxt = term / (2 * i + 1)
            if abs(nxt) < Decimal(10) ** -110:
                break
            total += nxt
            i += 1
        return total

    frac = (16 * arctan_inv(5) - 4 * arctan_inv(239)) - 3
    words = []
    for _ in range(count):
        frac *= 1 << 32
        words.append(int(frac))
        frac -= int(frac)
    return words


def _group(algorithm, name):
    return _SIGNATURES[algorithm][name]["values"]


def _blob(*chunks):
    return b"".join(chunks)


def _words_le(values):
    return b"".join(struct.pack("<I", v) for v in values)


def _words_be(values):
    return b"".join(struct.pack(">I", v) for v in values)


def _scan_bytes(data, **kwargs):
    with tempfile.TemporaryDirectory(dir=str(Path.cwd())) as tmp:
        target = Path(tmp) / "blob.bin"
        target.write_bytes(data)
        return json.loads(crypto_constant_scan(str(target), **kwargs))


def _named(result, algorithm):
    for candidate in result["candidates"]:
        if candidate["algorithm"] == algorithm:
            return candidate
    return None


class ConstantTableDerivationTests(unittest.TestCase):
    """Re-derive the table instead of trusting it."""

    def test_sha256_constants_come_from_roots_of_primes(self):
        primes = _primes(64)
        self.assertEqual(_group("SHA-256", "init_state"),
                         [_frac_bits(p, 32, 2) for p in primes[:8]])
        self.assertEqual(_group("SHA-256", "K_table_head"),
                         [_frac_bits(p, 32, 3) for p in primes[:8]])

    def test_sha512_and_sha384_constants_come_from_roots_of_primes(self):
        primes = _primes(64)
        self.assertEqual(_group("SHA-512", "init_state"),
                         [_frac_bits(p, 64, 2) for p in primes[:4]])
        self.assertEqual(_group("SHA-512", "K_table_head"),
                         [_frac_bits(p, 64, 3) for p in primes[:4]])
        self.assertEqual(_group("SHA-384", "init_state"),
                         [_frac_bits(p, 64, 2) for p in primes[8:12]])

    def test_sha224_init_is_the_second_32_bits_of_the_sha384_roots(self):
        """SHA-224 does NOT use the leading 32 bits -- FIPS 180-4 specifies bits
        33..64 of the same square roots. Deriving it the obvious (wrong) way
        yields the SHA-384 words instead, so this pins the right rule."""
        primes = _primes(16)
        expected = [_frac_bits(p, 64, 2) & 0xFFFFFFFF for p in primes[8:16]]
        self.assertEqual(_group("SHA-224", "init_state"), expected)

    def test_md5_t_table_comes_from_sin(self):
        expected = [int(abs(math.sin(i + 1)) * (2 ** 32)) for i in range(4)]
        self.assertEqual(_group("MD5", "T_table_head"), expected)

    def test_sha1_round_constants_come_from_square_roots(self):
        expected = [int(math.sqrt(v) * (2 ** 30)) for v in (2, 3, 5, 10)]
        self.assertEqual(_group("SHA-1", "round_constants"), expected)

    def test_blowfish_p_array_is_the_hex_expansion_of_pi(self):
        self.assertEqual(_group("Blowfish", "P_array_head"), _pi_hex_words(4))

    def test_aes_tables_come_from_the_galois_field_construction(self):
        sbox = _aes_sbox()
        self.assertEqual(_group("AES / Rijndael", "sbox_head")[0], bytes(sbox[:16]))
        inverse = [0] * 256
        for i, v in enumerate(sbox):
            inverse[v] = i
        self.assertEqual(_group("AES / Rijndael", "inv_sbox_head")[0], bytes(inverse[:16]))

        def xtime(a):
            return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

        te0 = []
        for i in range(4):
            s = sbox[i]
            te0.append((xtime(s) << 24) | (s << 16) | (s << 8) | (xtime(s) ^ s))
        self.assertEqual(_group("AES / Rijndael", "Te0_head"), te0)

    def test_aes_rcon_is_successive_xtime_of_one(self):
        expected = []
        value = 1
        for _ in range(10):
            expected.append(value)
            value = ((value << 1) ^ 0x1B) & 0xFF if value & 0x80 else (value << 1) & 0xFF
        self.assertEqual(_group("AES / Rijndael", "rcon")[0], bytes(expected))

    def test_fnv_and_tea_constants_come_from_their_definitions(self):
        self.assertEqual(_group("FNV-1 / FNV-1a (32-bit)", "prime"), [16777619])
        self.assertEqual(_group("FNV-1 / FNV-1a (32-bit)", "offset_basis"), [2166136261])
        self.assertEqual(_group("FNV-1 / FNV-1a (64-bit)", "prime"), [1099511628211])
        self.assertEqual(_group("FNV-1 / FNV-1a (64-bit)", "offset_basis"),
                         [14695981039346656037])
        golden = int((1 << 32) / ((1 + 5 ** 0.5) / 2))
        self.assertEqual(_group("TEA / XTEA / XXTEA", "delta"), [golden])
        self.assertEqual(_group("TEA / XTEA / XXTEA", "sum_after_32_rounds"),
                         [(golden * 32) & 0xFFFFFFFF])

    def test_crc32_table_head_is_generated_by_the_reflected_polynomial(self):
        poly = 0xEDB88320
        table = []
        for byte in range(4):
            crc = byte
            for _ in range(8):
                crc = (crc >> 1) ^ (poly if crc & 1 else 0)
            table.append(crc)
        self.assertEqual(_group("CRC-32 (IEEE)", "table_head"), table)
        self.assertIn(poly, _group("CRC-32 (IEEE)", "polynomial"))

    def test_every_shared_constant_is_shared_deliberately(self):
        """The MD4/MD5/SHA-1/RIPEMD-160 overlap is real and load-bearing for the
        ambiguity logic. If a future edit accidentally makes some other pair
        collide, the attribution logic silently weakens, so pin the set."""
        owners = tools_crypto_id._shared_index()
        shared = {v: sorted(a) for (k, v), a in owners.items() if len(a) > 1 and k != "bytes"}
        self.assertEqual(shared, {
            0x67452301: ["MD4", "MD5", "RIPEMD-160", "SHA-1"],
            0xEFCDAB89: ["MD4", "MD5", "RIPEMD-160", "SHA-1"],
            0x98BADCFE: ["MD4", "MD5", "RIPEMD-160", "SHA-1"],
            0x10325476: ["MD4", "MD5", "RIPEMD-160", "SHA-1"],
            0xC3D2E1F0: ["RIPEMD-160", "SHA-1"],
            0x5A827999: ["MD4", "RIPEMD-160", "SHA-1"],
            0x6ED9EBA1: ["MD4", "RIPEMD-160", "SHA-1"],
            0x8F1BBCDC: ["RIPEMD-160", "SHA-1"],
        })


class AttributionHonestyTests(unittest.TestCase):
    def test_shared_init_words_alone_never_name_one_algorithm(self):
        data = _blob(b"\x00" * 64, _words_le(_group("MD5", "init_state")), b"\x00" * 64)
        result = _scan_bytes(data)
        levels = {c["algorithm"]: c["attribution"]["level"] for c in result["candidates"]}
        self.assertTrue(levels, "the shared init words should still be reported")
        for algorithm, level in levels.items():
            self.assertEqual(level, "AMBIGUOUS_SHARED_CONSTANTS",
                             "%s was named from shared constants alone" % algorithm)
        for candidate in result["candidates"]:
            self.assertEqual(candidate["distinctive_constants_found"], [])
            self.assertTrue(candidate["also_consistent_with"])

    def test_a_distinctive_group_promotes_one_algorithm(self):
        data = _blob(b"\x11" * 32,
                     _words_le(_group("MD5", "init_state")),
                     _words_le(_group("MD5", "T_table_head")))
        result = _scan_bytes(data)
        md5 = _named(result, "MD5")
        self.assertEqual(md5["attribution"]["level"], "STRONG_CANDIDATE")
        self.assertTrue(md5["distinctive_constants_found"])
        self.assertEqual(_named(result, "MD4")["attribution"]["level"],
                         "AMBIGUOUS_SHARED_CONSTANTS")
        self.assertEqual(result["candidates"][0]["algorithm"], "MD5",
                         "the distinctively-identified algorithm must rank first")

    def test_a_lone_distinctive_constant_is_only_a_partial_candidate(self):
        data = _blob(b"\x22" * 40, _words_le([_group("SHA-256", "K_table_head")[0]]))
        result = _scan_bytes(data)
        sha256 = _named(result, "SHA-256")
        self.assertEqual(sha256["attribution"]["level"], "PARTIAL_CANDIDATE")

    def test_low_entropy_words_are_never_treated_as_evidence(self):
        """Regression test for a defect seen on a real target: 0x00000000 and
        0x00000001 were reported as distinctive constants, inventing CRC-32 and
        SHA-3 candidates out of ordinary zero padding."""
        for filler in (b"\x00" * 4096, b"\x01\x00\x00\x00" * 512):
            result = _scan_bytes(filler)
            self.assertEqual(result["candidates"], [],
                             "low-entropy filler produced candidates: %r" % filler[:8])

    def test_low_entropy_constants_are_declared_rather_than_hidden(self):
        data = _blob(_words_le(_group("CRC-32 (IEEE)", "table_head")))
        result = _scan_bytes(data)
        crc = _named(result, "CRC-32 (IEEE)")
        table = [g for g in crc["matched_groups"] if g["group"] == "table_head"][0]
        self.assertIn("0x0", table["constants_skipped_as_too_common"])
        self.assertEqual(table["constants_searchable"], 3)
        self.assertEqual(table["coverage"], 1.0,
                         "coverage must be measured against searchable constants only")

    def test_a_stored_table_is_distinguished_from_scattered_words(self):
        consecutive = _scan_bytes(_words_le(_group("SHA-256", "K_table_head")))
        scattered = _scan_bytes(b"".join(
            struct.pack("<I", v) + b"\xAB\xCD\xEF\x99"
            for v in _group("SHA-256", "K_table_head")))
        got = [g for g in _named(consecutive, "SHA-256")["matched_groups"]
               if g["group"] == "K_table_head"][0]
        missed = [g for g in _named(scattered, "SHA-256")["matched_groups"]
                  if g["group"] == "K_table_head"][0]
        self.assertTrue(got["stored_consecutively_in_table_order"])
        self.assertFalse(missed["stored_consecutively_in_table_order"])
        self.assertIn("consecutively", got["matches"] and
                      _named(consecutive, "SHA-256")["attribution"]["note"])

    def test_big_endian_tables_are_found_too(self):
        result = _scan_bytes(_blob(b"\x77" * 16, _words_be(_group("SHA-256", "init_state"))))
        sha256 = _named(result, "SHA-256")
        self.assertIsNotNone(sha256)
        encodings = {m["encoding"] for g in sha256["matched_groups"] for m in g["matches"]}
        self.assertIn("be32", encodings)

    def test_byte_signatures_are_found(self):
        result = _scan_bytes(_blob(b"\x00" * 8, b"expand 32-byte k", b"\x00" * 8))
        chacha = _named(result, "ChaCha / Salsa20")
        self.assertIsNotNone(chacha)
        self.assertEqual(chacha["attribution"]["level"], "STRONG_CANDIDATE")

    def test_the_result_always_states_that_absence_is_not_proof(self):
        result = _scan_bytes(b"\x5A" * 256)
        self.assertEqual(result["candidates"], [])
        self.assertIn("absence is not evidence of absence", result["evidence_note"])
        self.assertIn("negative search result", result["evidence_note"])


class ScanMechanicsTests(unittest.TestCase):
    def test_offset_and_length_bound_the_search(self):
        payload = _words_le(_group("MD5", "T_table_head"))
        data = _blob(b"\x00" * 256, payload, b"\x00" * 256)
        inside = _scan_bytes(data, offset="0x100", length=len(payload))
        outside = _scan_bytes(data, offset=0, length=64)
        self.assertIsNotNone(_named(inside, "MD5"))
        self.assertEqual(outside["candidates"], [])
        self.assertEqual(inside["scanned"]["bytes_scanned"], len(payload))

    def test_hits_report_absolute_file_offsets_not_window_relative_ones(self):
        payload = _words_le(_group("MD5", "T_table_head"))
        data = _blob(b"\x00" * 256, payload)
        result = _scan_bytes(data, offset="0x100")
        hit = _named(result, "MD5")["matched_groups"][0]["matches"][0]["hits"][0]
        self.assertEqual(hit["file_offset"], "0x100")

    def test_algorithms_filter_restricts_and_validates(self):
        data = _blob(_words_le(_group("MD5", "init_state")))
        only = _scan_bytes(data, algorithms="MD5")
        self.assertEqual([c["algorithm"] for c in only["candidates"]], ["MD5"])
        bad = _scan_bytes(data, algorithms="MD5,Enigma")
        self.assertEqual(bad["status"], "UNKNOWN_ALGORITHM")
        self.assertEqual(bad["unknown"], ["Enigma"])

    def test_bad_operation_and_missing_file_are_structured(self):
        self.assertEqual(json.loads(crypto_constant_scan("x", operation="nope"))["status"],
                         "BAD_OPERATION")
        self.assertEqual(json.loads(crypto_constant_scan("no_such_file_here.bin"))["status"],
                         "NOT_FOUND")

    def test_list_signatures_reports_the_whole_table(self):
        listed = json.loads(crypto_constant_scan("", operation="list_signatures"))
        self.assertEqual(listed["status"], "OK")
        self.assertEqual(listed["algorithms"], len(_SIGNATURES))
        self.assertIn("MD5", listed["table"])

    def test_crc16_and_adler32_are_deliberately_absent(self):
        """Their only constants fit in 16 bits, so they cannot be evidence.
        Re-adding them would advertise coverage that does not exist."""
        self.assertNotIn("CRC-16", _SIGNATURES)
        self.assertNotIn("Adler-32 / zlib", _SIGNATURES)


class RealTargetReplayTests(unittest.TestCase):
    """The case this tool was built for. The corpus is not committed, so this
    skips when it is absent rather than failing."""

    SHA256_PREFIX = "ce138d1316e7"

    def _target(self):
        root = Path("benchmarks/windows_native_ladder/corpus")
        if not root.exists():
            return None
        for f in root.rglob("*"):
            if f.is_file() and f.stat().st_size < 8_000_000:
                try:
                    if hashlib.sha256(f.read_bytes()).hexdigest().startswith(self.SHA256_PREFIX):
                        return f
                except OSError:
                    continue
        return None

    def test_wnl_t2_085_md5_is_rediscovered_at_the_hand_found_addresses(self):
        target = self._target()
        if target is None:
            self.skipTest("WNL-T2-085 corpus binary not present")
        result = json.loads(crypto_constant_scan(str(target)))
        self.assertEqual(result["status"], "OK")
        self.assertTrue(result["virtual_addresses_available"])

        self.assertEqual(result["candidates"][0]["algorithm"], "MD5")
        md5 = result["candidates"][0]
        self.assertEqual(md5["attribution"]["level"], "STRONG_CANDIDATE")

        # The four init words were originally located by an analyst reading a
        # disassembly listing. The tool must land on the same addresses.
        init = [g for g in md5["matched_groups"] if g["group"] == "init_state"][0]
        found = {m["constant"]: [h["virtual_address"] for h in m["hits"]] for m in init["matches"]}
        self.assertIn("0x40f347", found["0x67452301"])
        self.assertIn("0x40f351", found["0xefcdab89"])
        self.assertIn("0x40f35e", found["0x98badcfe"])
        self.assertIn("0x40f36b", found["0x10325476"])

        # ...and must still refuse to separate the algorithms that share them.
        for other in ("MD4", "SHA-1", "RIPEMD-160"):
            self.assertEqual(_named(result, other)["attribution"]["level"],
                             "AMBIGUOUS_SHARED_CONSTANTS")

        # The zero-word defect this tool was fixed for must not come back on a
        # real binary full of padding.
        self.assertIsNone(_named(result, "CRC-32 (IEEE)"))
        self.assertIsNone(_named(result, "SHA-3 / Keccak"))


if __name__ == "__main__":
    unittest.main()
