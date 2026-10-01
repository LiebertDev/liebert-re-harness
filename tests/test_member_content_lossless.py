"""Godot/Unreal `read` must not return binary member bytes as U+FFFD-mangled text.

The old code did ``content.decode('utf-8', errors='replace')`` on raw member
bytes: every invalid byte became U+FFFD and the caller could not tell a text
asset from a corrupted binary one. Now a member is text only if it is valid
UTF-8 (``content_kind: "text"``); otherwise ``content_kind: "binary"`` with its
size, sha256 and the first invalid offset, and no ``content`` key at all.
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import unittest
import zipfile
from pathlib import Path

from liebert_re.tools.formats import archive_inspect
from liebert_re.tools.godot import godot_asset_analyzer
from liebert_re.tools.unreal import unreal_asset_analyzer

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRATCH = REPO_ROOT / "dataset" / "runtime" / "_test_member_content_lossless_scratch"

TEXT = "hello é中 asset\n".encode("utf-8")
BINARY = b"ok prefix \xff\xfe\x00\x80binary"


def build_pck(members):
    """Minimal Godot pack v3, absolute offsets, no encryption."""
    header_len = 32 + 8 + 64
    body = b""
    rows = []
    for name, data in members:
        rows.append((name, header_len + len(body), len(data), hashlib.md5(data).digest()))
        body += data
    dir_offset = header_len + len(body)
    directory = struct.pack("<I", len(rows))
    for name, off, size, md5 in rows:
        raw = name.encode() + b"\0"
        raw += b"\0" * (-len(raw) % 4)
        directory += struct.pack("<I", len(raw)) + raw + struct.pack("<QQ", off, size) + md5 + struct.pack("<I", 0)
    head = b"GDPC" + struct.pack("<IIIII", 3, 4, 5, 1, 0) + struct.pack("<Q", 0) + struct.pack("<Q", dir_offset) + bytes(64)
    assert len(head) == header_len
    return head + body + directory


def _pak_string(s):
    raw = s.encode() + b"\0"
    return struct.pack("<i", len(raw)) + raw


def _pak_record(offset, size, sha1):
    return struct.pack("<QQQI20s", offset, 0, size, 0, sha1) + struct.pack("<BI", 0, 0)


def build_pak(members):
    """Minimal Unreal pak v3, uncompressed entries."""
    body = b""
    index = _pak_string("../../../")
    index += struct.pack("<I", len(members))
    for name, data in members:
        sha1 = hashlib.sha1(data).digest()
        offset = len(body)
        body += _pak_record(0, len(data), sha1) + data
        index += _pak_string(name) + _pak_record(offset, len(data), sha1)
    footer = struct.pack("<IIQQ20s", 0x5A6F12E1, 3, len(body), len(index), bytes(20))
    return body + index + footer


class _Scratch(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, SCRATCH, ignore_errors=True)


class GodotMembers(_Scratch):
    def test_text_member_is_text_and_binary_member_is_binary_and_lossless(self):
        p = SCRATCH / "t.pck"
        p.write_bytes(build_pck([("a.txt", TEXT), ("b.bin", BINARY)]))
        txt = json.loads(godot_asset_analyzer(str(p), "read", member="a.txt"))
        self.assertTrue(txt["ok"], txt)
        self.assertEqual((txt["content_kind"], txt["content"], txt["truncated"], txt["byte_size"]),
                         ("text", TEXT.decode(), False, len(TEXT)))
        binary = json.loads(godot_asset_analyzer(str(p), "read", member="b.bin"))
        self.assertTrue(binary["ok"], binary)
        self.assertEqual(binary["content_kind"], "binary")
        self.assertNotIn("content", binary)
        self.assertEqual(binary["byte_size"], len(BINARY))
        self.assertEqual(binary["sha256"], hashlib.sha256(BINARY).hexdigest())
        self.assertEqual(binary["first_invalid_utf8_offset"], BINARY.index(b"\xff"))
        self.assertNotIn("�", json.dumps(binary, ensure_ascii=False))

    def test_text_truncation_is_still_reported(self):
        p = SCRATCH / "t.pck"
        p.write_bytes(build_pck([("big.txt", b"x" * 5000)]))
        out = json.loads(godot_asset_analyzer(str(p), "read", member="big.txt", max_chars=1000))
        self.assertEqual((out["content_kind"], len(out["content"]), out["truncated"]), ("text", 1000, True))


class UnrealMembers(_Scratch):
    def test_text_member_is_text_and_binary_member_is_binary_and_lossless(self):
        p = SCRATCH / "t.pak"
        p.write_bytes(build_pak([("a.txt", TEXT), ("b.uasset", BINARY)]))
        txt = json.loads(unreal_asset_analyzer(str(p), "read", member="a.txt"))
        self.assertTrue(txt["ok"], txt)
        self.assertEqual((txt["content_kind"], txt["content"], txt["truncated"], txt["byte_size"]),
                         ("text", TEXT.decode(), False, len(TEXT)))
        binary = json.loads(unreal_asset_analyzer(str(p), "read", member="b.uasset"))
        self.assertTrue(binary["ok"], binary)
        self.assertEqual(binary["content_kind"], "binary")
        self.assertNotIn("content", binary)
        self.assertEqual(binary["byte_size"], len(BINARY))
        self.assertEqual(binary["sha256"], hashlib.sha256(BINARY).hexdigest())
        self.assertTrue(binary["sha1_matches_index"])
        self.assertNotIn("�", json.dumps(binary, ensure_ascii=False))


class ArchiveInspectMembers(_Scratch):
    def test_invalid_utf8_without_nul_is_refused_as_binary_not_mangled(self):
        p = SCRATCH / "t.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("ok.txt", TEXT)
            z.writestr("bad.txt", b"caf\xe9 no nul byte here")  # latin-1, invalid UTF-8
        p.write_bytes(buf.getvalue())
        ok = json.loads(archive_inspect(str(p), "read", member="ok.txt"))
        self.assertEqual(ok["content"], TEXT.decode())
        bad = json.loads(archive_inspect(str(p), "read", member="bad.txt"))
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["error"], "BINARY_MEMBER")
        self.assertEqual(bad["first_invalid_utf8_offset"], 3)


if __name__ == "__main__":
    unittest.main()
