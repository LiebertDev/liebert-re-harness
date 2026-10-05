"""ioctl_control_code_decode (liebert_re/tools/binary.py): pure bit arithmetic on caller-supplied CTL_CODE values.

CTL_CODE layout (winioctl.h): method 0-1, function 2-13 (12 bits, (code >> 2) & 0xFFF), access 14-15,
device_type 16-30, reserved 31. Function >= 0x800 is the vendor range.
Three outcomes are kept apart: decoded, invalid value (INVALID_VALUE), and decoded-but-device-unknown
(DECODED with device_type_known false -- not an error).
"""
from __future__ import annotations

import json

from liebert_re.tools.binary import ioctl_control_code_decode


def _one(code):
    return json.loads(ioctl_control_code_decode([code]))["results"][0]


def test_known_real_ioctl_value():
    # IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(FILE_DEVICE_DISK=7, 0, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
    # = (7 << 16) = 0x70000 (public winioctl.h).
    r = _one(0x70000)
    assert r["status"] == "DECODED"
    assert (r["device_type"], r["device_type_name"], r["device_type_known"]) == (7, "FILE_DEVICE_DISK", True)
    assert (r["function"], r["method"], r["method_name"]) == (0, 0, "METHOD_BUFFERED")
    assert (r["access"], r["access_name"], r["is_custom"]) == (0, "FILE_ANY_ACCESS", False)


def test_known_value_with_all_fields():
    # CTL_CODE(0x22 = FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER=3, FILE_READ_ACCESS=1)
    # = (0x22<<16) | (1<<14) | (0x800<<2) | 3 = 0x220000 | 0x4000 | 0x2000 | 3 = 0x226003.
    # 0x800 << 2 sets bit 13, which is the top bit of the 12-bit Function: function = 0x800, vendor range.
    r = _one(0x226003)
    assert r["device_type_name"] == "FILE_DEVICE_UNKNOWN"
    assert (r["method_name"], r["access_name"]) == ("METHOD_NEITHER", "FILE_READ_ACCESS")
    assert r["is_custom"] is True
    assert r["function"] == 0x800


def test_canonical_0x222000_reads_function_0x800():
    # CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x222000.
    r = _one(0x222000)
    assert (r["device_type"], r["function"], r["is_custom"], r["method"]) == (34, 0x800, True, 0)


def test_function_is_twelve_bits_and_0x800_marks_the_vendor_range():
    """Replaces test_bit_13_is_custom_and_does_not_leak_into_function.

    The old test pinned a WRONG convention: it treated function as 11 bits and bit 13 as a separate
    custom flag. CTL_CODE is ((Device)<<16)|((Access)<<14)|((Function)<<2)|(Method), so Function is
    bits 2-13 (12 bits, mask 0xFFF) and bit 13 is its top bit (0x800). is_custom is derived:
    function >= 0x800 (Microsoft reserves < 0x800, leaves 0x800 and above to vendors).
    """
    base = 0x220000 | (0x155 << 2)
    plain, vendor = _one(base), _one(base | (1 << 13))
    assert plain["function"] == 0x155 and plain["is_custom"] is False
    assert vendor["function"] == 0x155 | 0x800 and vendor["is_custom"] is True
    assert _one(0x220000 | (0x7FF << 2))["is_custom"] is False
    assert _one(0x220000 | (0xFFF << 2))["function"] == 0xFFF


def test_vendor_range_codes_are_valid_not_rejected():
    for f in (0x800, 0x801, 0xFFF):
        r = _one(0x220000 | (f << 2))
        assert r["status"] == "DECODED" and r["function"] == f and r["is_custom"] is True


def test_field_maxima_and_ranges():
    r = _one(0x7FFF << 16 | 0xFFF << 2)
    assert r["device_type"] == 0x7FFF and r["function"] == 0xFFF
    for m, n in enumerate(["METHOD_BUFFERED", "METHOD_IN_DIRECT", "METHOD_OUT_DIRECT", "METHOD_NEITHER"]):
        assert (_one(m)["method"], _one(m)["method_name"]) == (m, n)
    for a, n in enumerate(["FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "FILE_READ_ACCESS|FILE_WRITE_ACCESS"]):
        assert (_one(a << 14)["access"], _one(a << 14)["access_name"]) == (a, n)


def test_reserved_bit_is_reported_not_folded_into_device_type():
    r = _one(0x80000000)
    assert r["reserved_bit_set"] is True and r["device_type"] == 0
    assert _one(0)["reserved_bit_set"] is False


def test_invalid_values_are_refused_per_entry():
    for bad, err in [(-1, "NEGATIVE"), (1 << 32, "OUT_OF_RANGE_U32"), ("0x22", "NOT_AN_INTEGER"),
                     (1.5, "NOT_AN_INTEGER"), (True, "NOT_AN_INTEGER"), (None, "NOT_AN_INTEGER")]:
        r = _one(bad)
        assert r["status"] == "INVALID_VALUE" and r["error"] == err, bad
        assert "device_type" not in r


def test_input_that_is_not_a_list_is_refused():
    for bad in (5, "0x22", None, []):
        body = json.loads(ioctl_control_code_decode(bad))
        assert body["ok"] is False and body["status"] == "INVALID_INPUT", bad


def test_unrecognised_device_type_is_information_not_an_error():
    r = _one(0x7ABC << 16 | 0x801 << 2)
    assert r["status"] == "DECODED"
    assert r["device_type"] == 0x7ABC
    assert r["device_type_name"] is None
    assert r["device_type_known"] is False
    assert "error" not in r
    top = json.loads(ioctl_control_code_decode([0x7ABC << 16]))
    assert top["ok"] is True


def test_unknown_device_and_invalid_value_carry_different_codes():
    unk, bad = _one(0x7ABC << 16), _one(-5)
    assert unk["status"] != bad["status"]


def test_mixed_list_keeps_order_and_independence():
    out = json.loads(ioctl_control_code_decode([0x70000, -1, 0x7ABC << 16]))["results"]
    assert [r["status"] for r in out] == ["DECODED", "INVALID_VALUE", "DECODED"]
