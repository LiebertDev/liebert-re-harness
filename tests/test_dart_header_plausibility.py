"""Dart snapshot header plausibility: kInvalid is not a valid kind, and there is
no invented length ceiling."""
from __future__ import annotations

import struct
import unittest

from liebert_re.tools.dart import _scan_headers

_MAGIC = struct.pack("<I", 0xDCDCF5F5)


def _hdr(length_field: int, kind: int) -> bytes:
    return _MAGIC + struct.pack("<qq", length_field, kind) + b"\0" * 8


class DartPlausibility(unittest.TestCase):
    def test_kinvalid_is_not_plausible(self):
        (m,) = _scan_headers(_hdr(1000, 4), 5)
        self.assertEqual(m["kind"], "kInvalid")
        self.assertFalse(m["plausible"])

    def test_real_kind_is_plausible(self):
        (m,) = _scan_headers(_hdr(1000, 2), 5)
        self.assertTrue(m["plausible"])

    def test_length_above_two_gib_is_not_rejected_by_an_invented_ceiling(self):
        (m,) = _scan_headers(_hdr(3 << 30, 2), 5)
        self.assertTrue(m["plausible"])

    def test_non_positive_length_rejected(self):
        (m,) = _scan_headers(_hdr(-4, 2), 5)
        self.assertFalse(m["plausible"])


if __name__ == "__main__":
    unittest.main()
