"""Decompression is bounded, not just the returned string.

``rar_7z`` used to call ``gzip.decompress`` / ``bz2.decompress`` /
``lzma.decompress`` / ``z.extract`` (to disk) and only then slice the text, so a
compression bomb fully expanded first. These tests pin:

a. small inputs return exactly what the pre-fix implementation returned (the
   legacy functions below are copied verbatim from ``git show HEAD:tools_archive2.py``);
b. a real bomb per codec is refused with DECOMPRESSED_SIZE_LIMIT_EXCEEDED and the
   process RSS does not grow with the decompressed size (psutil, as in
   test_disassemble_pe_chunking);
c. structurally, the decompressor is only ever asked for one chunk at a time.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import lzma
import shutil
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from unittest import mock

import psutil

import liebert_re.tools.archive2 as tools_archive2
from liebert_re.tools.archive2 import rar_7z

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH = REPO_ROOT / "dataset" / "runtime" / "_test_decompression_bounds_scratch"
MIB = 1024 * 1024
BOMB_BYTES = 96 * MIB  # 1.5x the 64 MiB cap; the old path would allocate all of it (and its str copy)


def _j(s):
    return json.loads(s)


def _legacy_stream(p: Path, fmt: str) -> bytes:
    data = p.read_bytes()
    if fmt == "GZIP":
        return gzip.decompress(data)
    if fmt == "BZIP2":
        return bz2.decompress(data)
    if fmt == "XZ":
        return lzma.decompress(data)
    from backports import zstd
    return zstd.decompress(data)


def _legacy_read(decompressed: bytes, max_chars: int) -> dict:
    text = decompressed.decode("utf-8", errors="replace")
    return {"content": text[:max_chars], "truncated": len(text) > max_chars, "byte_size": len(decompressed)}


def _legacy_7z_read(p, member, max_chars):
    import py7zr
    with py7zr.SevenZipFile(str(p)) as z:
        names = {f.filename for f in z.list()}
        if member not in names:
            return None
        with tempfile.TemporaryDirectory(prefix="sevenzip_out_") as tmp:
            z.extract(path=tmp, targets=[member])
            out = Path(tmp) / member
            data = out.read_bytes()
    text = data.decode("utf-8", errors="replace")
    return {"content": text[:max_chars], "truncated": len(text) > max_chars, "byte_size": len(data)}


def _compress_chunks(fmt: str, chunks) -> bytes:
    """Compress an iterable of chunks incrementally (building a bomb must not itself allocate it)."""
    if fmt == "GZIP":
        c = zlib.compressobj(9, zlib.DEFLATED, 31)
    elif fmt == "BZIP2":
        c = bz2.BZ2Compressor(9)
    elif fmt == "XZ":
        c = lzma.LZMACompressor()
    else:
        from backports import zstd
        c = zstd.ZstdCompressor()
    out = [c.compress(ch) for ch in chunks]
    out.append(c.flush())
    return b"".join(out)


def _zeros(total: int):
    block = bytes(MIB)
    for _ in range(total // MIB):
        yield block


SUFFIX = {"GZIP": ".gz", "BZIP2": ".bz2", "XZ": ".xz", "ZSTD": ".zst"}
try:  # optional dependencies: py7zr and backports.zstd are not in the published requirements
    import backports.zstd  # noqa: F401
    HAVE_ZSTD = True
except ImportError:
    HAVE_ZSTD = False
try:
    import py7zr  # noqa: F401
    HAVE_7Z = True
except ImportError:
    HAVE_7Z = False
FORMATS = ("GZIP", "BZIP2", "XZ") + (("ZSTD",) if HAVE_ZSTD else ())
needs_7z = unittest.skipUnless(HAVE_7Z, "py7zr not installed")


class _Scratch(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, ignore_errors=True)


class SmallInputsUnchanged(_Scratch):
    def _check_stream(self, fmt, payload, max_chars):
        p = SCRATCH / f"s{SUFFIX[fmt]}"
        p.write_bytes(_compress_chunks(fmt, [payload]))
        old = _legacy_stream(p, fmt)
        self.assertEqual(old, payload)
        read = _j(rar_7z(str(p), "read", max_chars=max_chars))
        expected = _legacy_read(old, max(1000, min(max_chars, 120000)))
        self.assertEqual({k: read[k] for k in expected}, expected, fmt)
        self.assertEqual(list(read)[-3:], ["content", "truncated", "byte_size"])  # same keys, same order
        # `content_kind` is new and is present on BOTH outcomes on purpose: a
        # caller must not have to read meaning into a key's absence. Every other
        # field still matches the old implementation exactly, which is what this
        # class exists to pin -- so the assertion is "identical apart from the
        # added key", not "identical", and it names the key so a future third
        # field cannot slip in under the same excuse.
        self.assertEqual(read["content_kind"], "text", fmt)
        summ = _j(rar_7z(str(p), "summary"))
        self.assertEqual(summ["decompressed_bytes"], len(old))
        self.assertEqual(summ["decompressed_sha256"], hashlib.sha256(old).hexdigest())

    def test_small_text_matches_the_old_implementation_for_every_codec(self):
        for fmt in FORMATS:
            self._check_stream(fmt, b"hello from a small text member\n" * 5, 30000)

    def test_truncated_multibyte_text_matches_the_old_implementation(self):
        # 2-byte characters, cut mid-stream by max_chars: head boundary must not leak a replacement char
        payload = ("é" * 300_000).encode("utf-8")
        for fmt in FORMATS:
            self._check_stream(fmt, payload, 1000)

    def test_exactly_max_chars_is_not_truncated(self):
        for fmt in FORMATS:
            self._check_stream(fmt, b"a" * 1000, 1000)

    def test_multi_member_gzip_is_still_concatenated(self):
        p = SCRATCH / "m.gz"
        p.write_bytes(gzip.compress(b"first ") + gzip.compress(b"second"))
        self.assertEqual(_j(rar_7z(str(p), "read"))["content"], "first second")

    def test_a_payload_between_head_and_cap_is_still_read_whole(self):
        # 3 MiB > the returned head, < the cap: total size and hash must still be exact.
        payload = bytes(range(32, 127)) * (3 * MIB // 95)
        p = SCRATCH / "mid.gz"
        p.write_bytes(gzip.compress(payload))
        summ = _j(rar_7z(str(p), "summary"))
        self.assertEqual(summ["decompressed_bytes"], len(payload))
        self.assertEqual(summ["decompressed_sha256"], hashlib.sha256(payload).hexdigest())
        read = _j(rar_7z(str(p), "read"))
        self.assertEqual(read["byte_size"], len(payload))
        self.assertTrue(read["truncated"])
        self.assertEqual(read["content"], payload[:30000].decode())

    @needs_7z
    def test_small_7z_member_matches_the_old_implementation(self):
        import py7zr
        for name, payload, cap in (("a.txt", b"seven zip text\n" * 10, 30000),
                                   ("b.txt", ("é" * 100_000).encode(), 1000)):
            p = SCRATCH / f"{name}.7z"
            with py7zr.SevenZipFile(str(p), "w") as z:
                z.writestr(payload, name)
            new = _j(rar_7z(str(p), "read", member=name, max_chars=cap))
            old = _legacy_7z_read(p, name, cap)
            self.assertEqual({k: new[k] for k in old}, old)
            self.assertEqual(list(new)[-3:], ["content", "truncated", "byte_size"])
        self.assertEqual(_j(rar_7z(str(p), "read", member="nope"))["error"], "MEMBER_NOT_FOUND")


def _peak_rss_growth(fn):
    proc = psutil.Process()
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
        result = fn()
    finally:
        stop.set()
        t.join()
    return result, peak[0] - base


def _write_zero_file(path: Path, total: int) -> None:
    with path.open("wb") as f:
        for blk in _zeros(total):
            f.write(blk)


class BombsAreRefusedNotAbsorbed(_Scratch):
    def test_each_stdlib_and_zstd_bomb_is_refused_without_proportional_memory(self):
        for fmt in FORMATS:
            p = SCRATCH / f"bomb{SUFFIX[fmt]}"
            p.write_bytes(_compress_chunks(fmt, _zeros(BOMB_BYTES)))
            self.assertLess(p.stat().st_size, 2 * MIB, fmt)
            for op in ("read", "summary"):
                out, growth = _peak_rss_growth(lambda: _j(rar_7z(str(p), op)))
                self.assertFalse(out["ok"], (fmt, op))
                self.assertEqual(out["error"], "DECOMPRESSED_SIZE_LIMIT_EXCEEDED")
                self.assertEqual(out["limit_bytes"], tools_archive2._MAX_DECOMPRESSED_BYTES)
                # the whole bomb is 96 MiB; absorbing it would cost >= that (plus a str copy)
                self.assertLess(growth, 40 * MIB, f"{fmt}/{op} grew {growth / MIB:.1f} MiB")
                print(f"BOMB {fmt}/{op}: compressed={p.stat().st_size}B decompressed={BOMB_BYTES // MIB}MiB "
                      f"rss_growth={growth / MIB:.1f}MiB")

    @needs_7z
    def test_7z_bomb_is_refused_from_the_declared_size_before_any_extraction(self):
        import py7zr
        big = SCRATCH / "z.bin"
        _write_zero_file(big, BOMB_BYTES)
        p = SCRATCH / "bomb.7z"
        with py7zr.SevenZipFile(str(p), "w") as z:
            z.write(big, "z.bin")
        big.unlink()
        with mock.patch.object(py7zr.SevenZipFile, "extract", side_effect=AssertionError("extracted")):
            out, growth = _peak_rss_growth(lambda: _j(rar_7z(str(p), "read", member="z.bin")))
        self.assertEqual(out["error"], "DECOMPRESSED_SIZE_LIMIT_EXCEEDED")
        self.assertEqual(out["bytes_seen_at_refusal"], BOMB_BYTES)
        self.assertLess(growth, 40 * MIB)
        print(f"BOMB 7Z declared-size: compressed={p.stat().st_size}B decompressed={BOMB_BYTES // MIB}MiB "
              f"rss_growth={growth / MIB:.1f}MiB")

    @needs_7z
    def test_7z_solid_block_bomb_ahead_of_a_small_member_is_aborted(self):
        # The requested member is tiny (passes the declared-size check) but sits behind a
        # huge member in the same solid block, which py7zr must decode to reach it.
        import py7zr

        def run(total):
            big = SCRATCH / "a_big.bin"
            _write_zero_file(big, total)
            small = SCRATCH / "z_small.txt"
            small.write_bytes(b"tiny")
            p = SCRATCH / f"solid{total}.7z"
            with py7zr.SevenZipFile(str(p), "w") as z:
                z.write(big, "a_big.bin")
                z.write(small, "z_small.txt")
            big.unlink()
            out, growth = _peak_rss_growth(lambda: _j(rar_7z(str(p), "read", member="z_small.txt")))
            self.assertFalse(out["ok"], out)
            self.assertEqual(out["error"], "DECOMPRESSED_SIZE_LIMIT_EXCEEDED")
            print(f"BOMB 7Z solid-block: compressed={p.stat().st_size}B decompressed={total // MIB}MiB "
                  f"rss_growth={growth / MIB:.1f}MiB")
            return growth

        small_growth = run(BOMB_BYTES)
        large_growth = run(256 * MIB)
        # py7zr decodes in blocks of up to 128 MB, so this is looser than the stdlib codecs' 40 MiB
        # bound: it plateaus at py7zr's block ceiling instead of scaling with the bomb.
        self.assertLess(large_growth, 400 * MIB)
        self.assertLess(large_growth, small_growth * 1.6, "growth scaled with bomb size")

    def test_structural_reads_are_chunked_and_stop_at_the_cap(self):
        """The property behind the RSS numbers: no read asks for the whole member."""
        p = SCRATCH / "bomb.gz"
        p.write_bytes(_compress_chunks("GZIP", _zeros(BOMB_BYTES)))
        sizes = []
        real_open = tools_archive2._open_stream

        class Spy:
            def __init__(self, f):
                self.f = f

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.f.close()

            def read(self, n=-1):
                sizes.append(n)
                return self.f.read(n)

        with mock.patch.object(tools_archive2, "_open_stream", lambda *a: Spy(real_open(*a))):
            out = _j(rar_7z(str(p), "read"))
        self.assertEqual(out["error"], "DECOMPRESSED_SIZE_LIMIT_EXCEEDED")
        self.assertTrue(sizes and all(0 < n <= tools_archive2._STREAM_CHUNK for n in sizes), sizes[:3])
        # 64 MiB cap / 1 MiB chunks: stopped after ~65 reads, not the 96 the whole bomb needs
        self.assertLessEqual(len(sizes), tools_archive2._MAX_DECOMPRESSED_BYTES // MIB + 1)

    def test_a_stream_exactly_at_the_cap_is_accepted_and_one_byte_over_is_refused(self):
        with mock.patch.object(tools_archive2, "_MAX_DECOMPRESSED_BYTES", 5 * MIB):
            p = SCRATCH / "edge.gz"
            p.write_bytes(_compress_chunks("GZIP", _zeros(5 * MIB)))
            self.assertTrue(_j(rar_7z(str(p), "summary"))["ok"])
            p.write_bytes(_compress_chunks("GZIP", list(_zeros(5 * MIB)) + [b"\0"]))
            self.assertEqual(_j(rar_7z(str(p), "summary"))["error"], "DECOMPRESSED_SIZE_LIMIT_EXCEEDED")


class BinaryStreamIsNotMangled(_Scratch):
    def test_invalid_utf8_stream_is_reported_as_binary_not_as_lossy_text(self):
        payload = b"text then \xff\xfe\x80 garbage" + bytes(range(256)) * 10
        for fmt in FORMATS:
            p = SCRATCH / f"bin{SUFFIX[fmt]}"
            p.write_bytes(_compress_chunks(fmt, [payload]))
            out = _j(rar_7z(str(p), "read"))
            self.assertTrue(out["ok"], out)
            self.assertEqual(out["content_kind"], "binary")
            self.assertNotIn("content", out)
            self.assertEqual(out["byte_size"], len(payload))
            self.assertEqual(out["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(out["first_invalid_utf8_offset"], payload.index(b"\xff"))
            self.assertNotIn("�", json.dumps(out, ensure_ascii=False))

    def test_invalid_byte_beyond_the_returned_head_is_still_caught(self):
        payload = b"a" * (3 * MIB) + b"\xff"
        p = SCRATCH / "late.gz"
        p.write_bytes(gzip.compress(payload))
        out = _j(rar_7z(str(p), "read"))
        self.assertEqual(out["content_kind"], "binary")
        self.assertEqual(out["first_invalid_utf8_offset"], 3 * MIB)


if __name__ == "__main__":
    unittest.main()
