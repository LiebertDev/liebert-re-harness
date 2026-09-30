"""Adapted from tests/test_tools_lzma1_decode.py: that file's
ToolsLzma1DecodeContractTests class already covers tools_lzma1_decode.py
end to end without touching any unpublished module -- reproduced here
verbatim. Only its second class (Lzma1DecodeRegisteredToolTests, which
imports the unpublished `teacher` dispatch module to prove registration)
is dropped, since dispatch-table wiring is out of scope for this port."""
from __future__ import annotations

import hashlib
import json
import lzma
import tempfile
import unittest
from pathlib import Path

import tools_workspace
from tools_lzma1_decode import MAX_OUT_SIZE, lzma1_decode


def _lzma1_raw_stream(data: bytes, lc: int = 3, lp: int = 0, pb: int = 2, preset: int = 6):
    filt = [{"id": lzma.FILTER_LZMA1, "preset": preset, "lc": lc, "lp": lp, "pb": pb}]
    packed = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=filt)
    return packed[13:]  # strip the FORMAT_ALONE header, keep the raw LZMA1 bitstream


class ToolsLzma1DecodeContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_decodes_a_real_lzma1_stream_at_a_nonzero_offset(self):
        original = b"the quick brown fox jumps over the lazy dog " * 40
        raw = _lzma1_raw_stream(original)
        prefix = b"\x00" * 17  # simulates the stream living inside a larger container/blob
        path = self._write("blob.bin", prefix + raw)
        result = json.loads(lzma1_decode(str(path), offset=len(prefix), lc=3, lp=0, pb=2, out_size=len(original)))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["decoded_bytes"], len(original))
        self.assertEqual(result["decoded_sha256"], hashlib.sha256(original).hexdigest())
        self.assertFalse(result["truncated_output"])

    def test_out_size_required(self):
        path = self._write("x.bin", b"\x00\x00\x00\x00\x00")
        result = json.loads(lzma1_decode(str(path), out_size=0))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "OUT_SIZE_REQUIRED")

    def test_out_size_too_large_is_rejected(self):
        path = self._write("x.bin", b"\x00\x00\x00\x00\x00")
        result = json.loads(lzma1_decode(str(path), out_size=MAX_OUT_SIZE + 1))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "OUT_SIZE_TOO_LARGE")

    def test_missing_file_is_a_structured_error_not_a_raw_traceback(self):
        result = json.loads(lzma1_decode(str(self.root / "does_not_exist.bin"), out_size=10))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "FILE_NOT_ACCESSIBLE")

    def test_corrupted_stream_fails_closed_with_a_structured_error(self):
        original = b"consistent structured text " * 50
        raw = bytearray(_lzma1_raw_stream(original))
        raw[len(raw) // 2] ^= 0x40
        path = self._write("corrupt.bin", bytes(raw))
        result = json.loads(lzma1_decode(str(path), out_size=len(original)))
        # Either an honest LZMA_FORMAT_ERROR, or (per lzma1_range_decoder's
        # own negative-control tests) a decode that does NOT silently
        # reproduce the original -- never a silent, wrong "success".
        if result["ok"]:
            self.assertNotEqual(result["decoded_sha256"], hashlib.sha256(original).hexdigest())
        else:
            self.assertEqual(result["error"], "LZMA_FORMAT_ERROR")

    def test_large_output_is_truncated_in_the_inline_payload_but_hash_covers_the_full_bytes(self):
        original = (b"ABCD" * 2_000_000)  # 8,000,000 bytes, well past MAX_INLINE_OUTPUT_BYTES
        raw = _lzma1_raw_stream(original, preset=1)
        path = self._write("big.bin", raw)
        result = json.loads(lzma1_decode(str(path), out_size=len(original)))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["truncated_output"])
        self.assertEqual(result["decoded_bytes"], len(original))
        self.assertEqual(result["decoded_sha256"], hashlib.sha256(original).hexdigest())


if __name__ == "__main__":
    unittest.main()
