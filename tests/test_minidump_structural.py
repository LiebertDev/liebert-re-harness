"""Hermetic Minidump Structural V1 fixtures and fail-closed cases."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from liebert_re.recover.minidump_structural import MAX_STREAMS, parse_minidump


def _utf16(value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def build_fixture(path: Path) -> None:
    streams = []
    payloads = []
    directory_rva = 32
    payload_rva = directory_rva + 4 * 12

    system = bytearray(56)
    struct.pack_into("<HHHBBIIIII", system, 0, 9, 6, 0x3A09, 8, 1, 10, 0, 22631, 2, 0)
    payloads.append(bytes(system)); streams.append((7, len(system), payload_rva)); payload_rva += len(system)

    module_name = _utf16(r"C:\Windows\System32\fixture.sys")
    module = bytearray(4 + 108)
    struct.pack_into("<I", module, 0, 1)
    name_rva = payload_rva + len(module)
    struct.pack_into("<QIIII", module, 4, 0x140000000, 0x5000, 7, 123456, name_rva)
    payloads.append(bytes(module) + module_name); streams.append((4, len(module), payload_rva)); payload_rva += len(module) + len(module_name)

    thread = bytearray(4 + 48)
    struct.pack_into("<I", thread, 0, 1)
    struct.pack_into("<IIIIQ", thread, 4, 99, 0, 32, 8, 0x7000)
    struct.pack_into("<QII", thread, 28, 0x8000, 0, 0)
    struct.pack_into("<II", thread, 44, 0, 0)
    payloads.append(bytes(thread)); streams.append((3, len(thread), payload_rva)); payload_rva += len(thread)

    exception = bytearray(168)
    struct.pack_into("<I", exception, 0, 99)
    struct.pack_into("<IIQQII", exception, 8, 0xC0000005, 0, 0, 0x140001234, 2, 0)
    struct.pack_into("<QQ", exception, 40, 0, 0xDEADBEEF)
    payloads.append(bytes(exception)); streams.append((6, len(exception), payload_rva))

    directory = b"".join(struct.pack("<III", *row) for row in streams)
    header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, len(streams), directory_rva, 0, 1700000000, 0)
    path.write_bytes(header + directory + b"".join(payloads))


class MinidumpStructuralTests(unittest.TestCase):
    def test_parses_system_modules_threads_and_exception_without_semantic_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "valid.dmp"
            build_fixture(target)
            report = parse_minidump(target)
        self.assertTrue(report["ok"])
        self.assertEqual(report["analysis_class"], "MINIDUMP_STRUCTURAL_V1")
        self.assertEqual(report["system_info"]["architecture"], "x86_64")
        self.assertEqual(report["system_info"]["os_version"], "10.0.22631")
        self.assertEqual(report["modules"]["count"], 1)
        self.assertTrue(report["modules"]["items"][0]["name"].endswith("fixture.sys"))
        self.assertEqual(report["threads"]["items"][0]["thread_id"], 99)
        self.assertFalse(report["threads"]["stacks_unwound"])
        self.assertEqual(report["exception"]["code"], "0xC0000005")
        self.assertEqual(report["exception"]["crash_cause"], "UNKNOWN")
        self.assertFalse(report["execution_performed"])
        self.assertFalse(report["debugger_attached"])

    def test_max_items_truncates_output_not_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "valid.dmp"
            build_fixture(target)
            report = parse_minidump(target, max_items=1)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["modules"]["items"]), 1)

    def test_rejects_truncated_header(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "short.dmp"; target.write_bytes(b"MDMP")
            report = parse_minidump(target)
        self.assertEqual(report["error"], "HEADER_TRUNCATED")

    def test_rejects_directory_and_stream_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "bad-directory.dmp"
            target.write_bytes(struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 0xFFFFFF00, 0, 0, 0))
            self.assertEqual(parse_minidump(target)["error"], "DIRECTORY_OUT_OF_BOUNDS")
            target.write_bytes(struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 32, 0, 0, 0) + struct.pack("<III", 7, 56, 0xFFFF))
            self.assertEqual(parse_minidump(target)["error"], "STREAM_OUT_OF_BOUNDS")

    def test_rejects_stream_count_and_record_count_bombs(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "bomb.dmp"
            target.write_bytes(struct.pack("<4sIIIIIQ", b"MDMP", 0, MAX_STREAMS + 1, 32, 0, 0, 0))
            self.assertEqual(parse_minidump(target)["error"], "STREAM_COUNT_LIMIT")
            target.write_bytes(
                struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 32, 0, 0, 0)
                + struct.pack("<III", 3, 4, 44) + struct.pack("<I", 50_000)
            )
            self.assertEqual(parse_minidump(target)["error"], "ITEM_COUNT_LIMIT")

    def test_rejects_nested_thread_descriptor_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "nested-rva.dmp"
            thread = bytearray(52)
            struct.pack_into("<I", thread, 0, 1)
            struct.pack_into("<IIIIQ", thread, 4, 7, 0, 0, 0, 0)
            struct.pack_into("<QII", thread, 28, 0x1000, 16, 0xFFFF)
            target.write_bytes(
                struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 32, 0, 0, 0)
                + struct.pack("<III", 3, len(thread), 44) + thread
            )
            report = parse_minidump(target)
        self.assertEqual(report["error"], "THREAD_STACK_OUT_OF_BOUNDS")

    def test_rejects_odd_utf16_string_length(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "odd-string.dmp"
            # Module list with name RVA pointing at odd-length UTF-16 descriptor.
            module = bytearray(4 + 108)
            struct.pack_into("<I", module, 0, 1)
            name_rva = 44 + len(module)
            struct.pack_into("<QIIII", module, 4, 0x1000, 0x100, 0, 0, name_rva)
            odd = struct.pack("<I", 3) + b"abc"
            target.write_bytes(
                struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 32, 0, 0, 0)
                + struct.pack("<III", 4, len(module), 44)
                + bytes(module)
                + odd
            )
            self.assertEqual(parse_minidump(target)["error"], "INVALID_STRING_LENGTH")

    def test_duplicate_stream_type_keeps_first_parsed_body(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "dup-stream.dmp"
            system_a = bytearray(56)
            struct.pack_into("<HHHBBIIIII", system_a, 0, 9, 6, 1, 2, 1, 10, 0, 1, 2, 0)
            system_b = bytearray(56)
            struct.pack_into("<HHHBBIIIII", system_b, 0, 0, 6, 1, 1, 1, 6, 1, 2, 2, 0)
            directory_rva = 32
            first_rva = directory_rva + 24
            second_rva = first_rva + len(system_a)
            target.write_bytes(
                struct.pack("<4sIIIIIQ", b"MDMP", 0, 2, directory_rva, 0, 0, 0)
                + struct.pack("<III", 7, len(system_a), first_rva)
                + struct.pack("<III", 7, len(system_b), second_rva)
                + bytes(system_a)
                + bytes(system_b)
            )
            report = parse_minidump(target)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["streams"]), 2)
        self.assertEqual(report["system_info"]["architecture"], "x86_64")
        self.assertEqual(report["system_info"]["os_version"], "10.0.1")

    def test_memory_list_and_thread_names_inventory_without_dumping_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "memory.dmp"
            directory_rva = 32
            stream_count = 3
            payload_rva = directory_rva + stream_count * 12

            mem_blob = b"ABCD1234"
            mem_list = bytearray(4 + 16)
            struct.pack_into("<I", mem_list, 0, 1)
            mem_data_rva = payload_rva + len(mem_list)
            struct.pack_into("<QII", mem_list, 4, 0x7FFE0000, len(mem_blob), mem_data_rva)

            name = _utf16("Worker")
            names = bytearray(4 + 16)
            struct.pack_into("<I", names, 0, 1)
            name_rva = payload_rva + len(mem_list) + len(mem_blob) + len(names)
            struct.pack_into("<I4xQ", names, 4, 99, name_rva)

            mem64_header_and_desc = bytearray(16 + 16)
            struct.pack_into("<QQ", mem64_header_and_desc, 0, 1, 0)  # base filled later
            struct.pack_into("<QQ", mem64_header_and_desc, 16, 0x10000, 4)
            mem64_blob = b"WXYZ"

            # Layout: mem_list | mem_blob | names | name | mem64_stream | mem64_blob
            parts = []
            rvas = {}
            cursor = payload_rva
            for key, blob in (
                ("mem_list", bytes(mem_list)),
                ("mem_blob", mem_blob),
                ("names", bytes(names)),
                ("name", name),
                ("mem64", bytes(mem64_header_and_desc)),
                ("mem64_blob", mem64_blob),
            ):
                rvas[key] = cursor
                parts.append(blob)
                cursor += len(blob)

            # Fix RVAs that depended on layout
            mem_list = bytearray(4 + 16)
            struct.pack_into("<I", mem_list, 0, 1)
            struct.pack_into("<QII", mem_list, 4, 0x7FFE0000, len(mem_blob), rvas["mem_blob"])
            names = bytearray(4 + 16)
            struct.pack_into("<I", names, 0, 1)
            struct.pack_into("<I4xQ", names, 4, 99, rvas["name"])
            mem64 = bytearray(16 + 16)
            struct.pack_into("<QQ", mem64, 0, 1, rvas["mem64_blob"])
            struct.pack_into("<QQ", mem64, 16, 0x10000, 4)

            directory = (
                struct.pack("<III", 5, len(mem_list), rvas["mem_list"])
                + struct.pack("<III", 24, len(names), rvas["names"])
                + struct.pack("<III", 9, len(mem64), rvas["mem64"])
            )
            header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, 3, directory_rva, 0, 1700000000, 0)
            # Rebuild body with corrected descriptors at known offsets
            body = bytearray(cursor - payload_rva)
            for key, blob in (
                ("mem_list", bytes(mem_list)),
                ("mem_blob", mem_blob),
                ("names", bytes(names)),
                ("name", name),
                ("mem64", bytes(mem64)),
                ("mem64_blob", mem64_blob),
            ):
                start = rvas[key] - payload_rva
                body[start:start + len(blob)] = blob
            target.write_bytes(header + directory + bytes(body))
            report = parse_minidump(target)

        self.assertTrue(report["ok"], report)
        self.assertEqual(report["memory_list"]["count"], 1)
        self.assertEqual(report["memory_list"]["items"][0]["start"], "0x7FFE0000")
        self.assertFalse(report["memory_list"]["contents_dumped"])
        self.assertFalse(report["memory_list"]["items"][0]["contents_dumped"])
        self.assertEqual(report["memory64_list"]["items"][0]["start"], "0x10000")
        self.assertFalse(report["memory64_list"]["contents_dumped"])
        self.assertEqual(report["thread_names"]["items"][0], {"thread_id": 99, "name": "Worker"})
        self.assertEqual(report["claims_ceiling"]["memory_contents"], "NOT_DUMPED")
        self.assertEqual(report["claims_ceiling"]["stack_unwind"], "UNKNOWN")

    def test_rejects_memory_range_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "bad-mem.dmp"
            mem = bytearray(4 + 16)
            struct.pack_into("<I", mem, 0, 1)
            struct.pack_into("<QII", mem, 4, 0x1000, 32, 0xFFFF)
            target.write_bytes(
                struct.pack("<4sIIIIIQ", b"MDMP", 0, 1, 32, 0, 0, 0)
                + struct.pack("<III", 5, len(mem), 44)
                + mem
            )
            self.assertEqual(parse_minidump(target)["error"], "MEMORY_RANGE_OUT_OF_BOUNDS")


if __name__ == "__main__":
    unittest.main()
