"""Contract tests for archive_inspect's operation=extract (GAP: 'read'
already existed but explicitly refuses BINARY_MEMBER, so a sample living
inside a zip/tar could never be handed to any other tool). Pure, offline,
no guest/VM involvement -- built directly on zipfile/tarfile's own real
extraction support, per tools_formats.py's own module comments at the
extract branch.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import unittest
import unittest.mock
import zipfile
import zlib
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.tools.formats import archive_inspect

_SCRATCH = tools_workspace.WORKSPACE_ROOT / ".pytest_archive_extract_scratch"


def _symlinks_are_creatable() -> bool:
    """Best-effort capability probe, never a platform guess: some Windows
    hosts allow unprivileged symlink creation (Developer Mode / the right
    group policy), most don't without admin. Skip cleanly instead of
    silently skipping without saying why -- see the test below."""
    probe_dir = _SCRATCH.parent / ".pytest_symlink_probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    link = probe_dir / "link"
    target = probe_dir / "target"
    try:
        target.mkdir(exist_ok=True)
        if link.exists() or link.is_symlink():
            link.unlink()
        os.symlink(str(target), str(link), target_is_directory=True)
        return True
    except OSError:
        return False
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


_CAN_SYMLINK = _symlinks_are_creatable()


class _ScratchGuard(unittest.TestCase):
    def setUp(self):
        _SCRATCH.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(_SCRATCH, ignore_errors=True)

    def _dest(self, name):
        return str(_SCRATCH / name)


def _make_zip(path, members):
    with zipfile.ZipFile(str(path), "w") as z:
        for name, data in members.items():
            z.writestr(name, data)


# ZipCrypto's password check is a SINGLE byte (the last byte of the 12-byte
# encryption header must equal the CRC's top byte), so a WRONG password passes
# that check with probability 1/256 and only fails later as a CRC error. The
# header's 11 filler bytes therefore decide whether a wrong-password test hits
# the clean BAD_PASSWORD path or the collision path. Keep them seeded: an
# unseeded RNG makes the suite flaky at ~1/256 per run. Seed 0 was verified to
# give BAD_PASSWORD for "wrong-password"; seed 107 is the verified collision.
_FIXTURE_SEED = 0
_COLLIDING_SEED = 107


def _make_zip_traditional_encrypted(path, name, data, password, seed=_FIXTURE_SEED):
    """Hand-builds a minimal, spec-valid ZIP with ONE STORED, traditional-
    PKWARE-(ZipCrypto)-encrypted entry -- the scheme stdlib zipfile can
    actually DECRYPT (unlike AES, which it can only detect, never read).
    zipfile's own writer (ZipFile.writestr/_open_to_write) has no
    encrypt-on-write support and actively resets flag_bits/CRC/compress_size
    when a raw write handle is used (confirmed live: it zeroes
    zinfo.flag_bits unconditionally in _open_to_write), so producing a real
    encrypted fixture requires writing the local file header, encrypted
    data, central directory, and EOCD record directly per the PKZIP
    APPNOTE layout -- using the same ZipCrypto keystream algorithm
    CPython's own zipfile._ZipDecrypter implements, referenced (not
    imported) here so this fixture builder has no dependency on zipfile
    internals staying stable."""
    import random
    import struct
    import zlib

    def _gen_crc_table():
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
            table.append(crc)
        return table

    _CRC_TABLE = _gen_crc_table()

    class _Encrypter:
        def __init__(self, pwd):
            self.key0 = 305419896
            self.key1 = 591751049
            self.key2 = 878082192
            for c in pwd:
                self._update(c)

        def _crc32(self, ch, crc):
            # NOT the same as zlib.crc32's running-CRC continuation (that
            # was tried first and measurably does not match -- confirmed
            # live against zipfile's own decrypter here) -- PKZIP's stream
            # cipher uses this specific per-byte table update directly,
            # matching CPython zipfile._ZipDecrypter's own crc32() closure.
            return (crc >> 8) ^ _CRC_TABLE[(crc ^ ch) & 0xFF]

        def _update(self, c):
            self.key0 = self._crc32(c, self.key0)
            self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
            self.key1 = (self.key1 * 134775813 + 1) & 0xFFFFFFFF
            self.key2 = self._crc32((self.key1 >> 24) & 0xFF, self.key2)

        def _crypt_byte(self):
            temp = self.key2 | 2
            return ((temp * (temp ^ 1)) >> 8) & 0xFF

        def encrypt(self, c):
            k = self._crypt_byte()
            self._update(c)
            return k ^ c

    raw = data
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    rng = random.Random(seed)
    enc = _Encrypter(password.encode("utf-8"))
    header = bytes(rng.randint(0, 255) for _ in range(11)) + bytes([(crc >> 24) & 0xFF])
    encrypted = bytes(enc.encrypt(b) for b in header) + bytes(enc.encrypt(b) for b in raw)

    name_bytes = name.encode("utf-8")
    flag_bits = 0x1  # bit 0: traditional (ZipCrypto) encryption
    compress_type = 0  # stored
    dos_time, dos_date = 0, 0x21  # arbitrary, fixed, valid DOS date (1980-01-01-ish)
    compressed_size = len(encrypted)
    uncompressed_size = len(raw)

    local_header = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flag_bits, compress_type, dos_time, dos_date,
        crc, compressed_size, uncompressed_size, len(name_bytes), 0,
    )
    local_offset = 0
    central_header = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flag_bits, compress_type, dos_time, dos_date,
        crc, compressed_size, uncompressed_size, len(name_bytes), 0, 0, 0, 0, 0o600 << 16, local_offset,
    )
    cd_offset = len(local_header) + len(name_bytes) + len(encrypted)
    cd_bytes = central_header + name_bytes
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd_bytes), cd_offset, 0)

    with open(str(path), "wb") as f:
        f.write(local_header)
        f.write(name_bytes)
        f.write(encrypted)
        f.write(cd_bytes)
        f.write(eocd)


class TestZipSlipGuard(_ScratchGuard):
    def test_traversal_member_name_is_blocked(self):
        archive = _SCRATCH / "evil.zip"
        with zipfile.ZipFile(str(archive), "w") as z:
            zi = zipfile.ZipInfo("../../escaped.txt")
            z.writestr(zi, b"should never land outside the extraction root")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="../../escaped.txt", dest_path=self._dest("out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PATH_TRAVERSAL_BLOCKED")
        self.assertFalse((_SCRATCH / "out.txt").exists())
        self.assertFalse((tools_workspace.WORKSPACE_ROOT / "escaped.txt").exists())

    def test_absolute_member_name_is_blocked(self):
        archive = _SCRATCH / "evil_abs.zip"
        with zipfile.ZipFile(str(archive), "w") as z:
            zi = zipfile.ZipInfo("/etc/passwd")
            z.writestr(zi, b"nope")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="/etc/passwd", dest_path=self._dest("out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PATH_TRAVERSAL_BLOCKED")


class TestExtractOutcomes(_ScratchGuard):
    def test_dest_path_outside_workspace_is_path_refused(self):
        archive = _SCRATCH / "a.zip"
        _make_zip(archive, {"hello.txt": b"hi"})
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="hello.txt", dest_path="C:\\Windows\\evil.txt"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "PATH_REFUSED")

    @unittest.skipUnless(
        _CAN_SYMLINK,
        "unprivileged symlink creation is not available on this host (Windows "
        "without Developer Mode/admin) -- containment behavior for a "
        "workspace-internal symlink pointing outside the workspace cannot be "
        "exercised here; this is exactly the case tests/"
        "test_tools_workspace_safe_path.py's platform-independent tests cover "
        "for the underlying guard logic without needing a real symlink.",
    )
    def test_dest_path_through_workspace_internal_symlink_escaping_outside_is_refused(self):
        # A symlink that LIVES inside the workspace but points OUTSIDE it
        # (e.g. crafted by something that ran before this call, or a
        # decompression step that itself created one) must not let a
        # later dest_path through that symlink land outside the workspace.
        # safe_path() resolves the full path (Path.resolve() follows
        # symlinks) before the containment check, so this is expected to
        # already be refused by the SAME code path as the outside-path
        # regression above -- this test exists to make that a checked
        # guarantee, not an assumption.
        import tempfile

        # Deliberately OUTSIDE the workspace tree (system temp dir, e.g.
        # /tmp or %LOCALAPPDATA%\Temp) -- a directory under _SCRATCH's own
        # parent would still be inside WORKSPACE_ROOT and would not
        # exercise the escape this test is for.
        with tempfile.TemporaryDirectory() as outside_root_str:
            outside_root = Path(outside_root_str).resolve()
            self.assertRaises(ValueError, outside_root.relative_to, tools_workspace.WORKSPACE_ROOT)
            link_dir = _SCRATCH / "escape_link"
            if link_dir.exists() or link_dir.is_symlink():
                link_dir.unlink()
            os.symlink(str(outside_root), str(link_dir), target_is_directory=True)
            archive = _SCRATCH / "a.zip"
            _make_zip(archive, {"hello.txt": b"hi"})
            dest = str(link_dir / "escaped.txt")
            result = json.loads(archive_inspect(str(archive), operation="extract",
                                                 member="hello.txt", dest_path=dest))
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "PATH_REFUSED")
            self.assertFalse((outside_root / "escaped.txt").exists())

    def test_missing_member_is_member_not_found(self):
        archive = _SCRATCH / "a.zip"
        _make_zip(archive, {"hello.txt": b"hi"})
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="does_not_exist.txt", dest_path=self._dest("out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "MEMBER_NOT_FOUND")

    def test_oversized_member_is_capped_without_write(self):
        import liebert_re.tools.formats as tools_formats
        archive = _SCRATCH / "big.zip"
        _make_zip(archive, {"big.bin": b"x" * 1000})
        dest = self._dest("big.bin")
        original_cap = tools_formats.MAX_ARCHIVE_MEMBER
        tools_formats.MAX_ARCHIVE_MEMBER = 100  # lower the cap so a 1000-byte member trips it
        try:
            result = json.loads(archive_inspect(str(archive), operation="extract",
                                                 member="big.bin", dest_path=dest))
        finally:
            tools_formats.MAX_ARCHIVE_MEMBER = original_cap
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "MEMBER_TOO_LARGE")
        self.assertFalse(Path(dest).exists())

    def test_zip_hash_round_trip_and_real_write(self):
        data = b"a completely ordinary non-executable text sample"
        archive = _SCRATCH / "sample.zip"
        _make_zip(archive, {"sample.txt": data})
        dest = self._dest("sample_out.txt")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="sample.txt", dest_path=dest))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["size_bytes"], len(data))
        self.assertFalse(result["executable_content_detected"])
        self.assertTrue(Path(dest).is_file())
        self.assertEqual(Path(dest).read_bytes(), data)

    def test_tar_hash_round_trip_and_real_write(self):
        data = b"a tar member, also non-executable"
        archive = _SCRATCH / "sample.tar"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="sample.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        dest = self._dest("tar_out.txt")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="sample.txt", dest_path=dest))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(Path(dest).is_file())

    def test_tar_traversal_member_blocked(self):
        archive = _SCRATCH / "evil.tar"
        data = b"escape attempt"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="../outside.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="../outside.txt", dest_path=self._dest("out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PATH_TRAVERSAL_BLOCKED")

    def test_tar_password_is_rejected_not_supported(self):
        data = b"tar has no encryption concept"
        archive = _SCRATCH / "sample2.tar"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="sample.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="sample.txt", dest_path=self._dest("out.txt"),
                                             password="whatever"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PASSWORD_NOT_SUPPORTED_FOR_TAR")

    def test_encrypted_zip_member_without_password_is_password_required(self):
        archive = _SCRATCH / "enc.zip"
        _make_zip_traditional_encrypted(archive, "secret.txt", b"the real content", "s3cr3t")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="secret.txt", dest_path=self._dest("out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PASSWORD_REQUIRED")

    def test_encrypted_zip_member_with_wrong_password_is_bad_password(self):
        archive = _SCRATCH / "enc2.zip"
        _make_zip_traditional_encrypted(archive, "secret.txt", b"the real content", "s3cr3t")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="secret.txt", dest_path=self._dest("out.txt"),
                                             password="wrong-password"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "BAD_PASSWORD")

    def test_wrong_password_that_passes_zipcrypto_check_is_honest_not_a_crash(self):
        # Seed 107 builds an encryption header for which "wrong-password" slips
        # past ZipCrypto's 1-byte check, so zipfile raises BadZipFile (bad CRC)
        # instead of RuntimeError. That cannot be told apart from corrupt data,
        # so the status must not claim BAD_PASSWORD, and must not raise.
        archive = _SCRATCH / "enc_collision.zip"
        _make_zip_traditional_encrypted(archive, "secret.txt", b"the real content", "s3cr3t",
                                        seed=_COLLIDING_SEED)
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="secret.txt", dest_path=self._dest("out.txt"),
                                             password="wrong-password"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "BAD_PASSWORD_OR_CORRUPT_DATA")
        self.assertIn("CRC", result["detail"])
        self.assertFalse((_SCRATCH / "out.txt").exists())

    def test_corrupt_unencrypted_zip_member_is_corrupt_member(self):
        archive = _SCRATCH / "corrupt.zip"
        payload = b"payload that will be damaged on disk"
        _make_zip(archive, {"a.txt": payload})
        blob = bytearray(archive.read_bytes())
        offset = blob.index(payload)  # stored member data
        blob[offset] ^= 0xFF  # CRC no longer matches
        archive.write_bytes(bytes(blob))
        for operation, kwargs in (("extract", {"dest_path": self._dest("out.txt")}), ("read", {})):
            with self.subTest(operation=operation):
                result = json.loads(archive_inspect(str(archive), operation=operation,
                                                     member="a.txt", **kwargs))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "CORRUPT_MEMBER")
                self.assertIn("CRC", result["detail"])
        self.assertFalse((_SCRATCH / "out.txt").exists())

    def test_unreadable_archive_container_is_structured_not_raised(self):
        archive = _SCRATCH / "notarchive.zip"
        archive.write_bytes(b"this is not an archive at all")
        result = json.loads(archive_inspect(str(archive)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "UNSUPPORTED_ARCHIVE")

    def test_encrypted_zip_member_with_correct_password_extracts(self):
        data = b"the real content"
        archive = _SCRATCH / "enc3.zip"
        _make_zip_traditional_encrypted(archive, "secret.txt", data, "s3cr3t")
        dest = self._dest("secret_out.txt")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="secret.txt", dest_path=dest,
                                             password="s3cr3t"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(Path(dest).is_file())
        self.assertEqual(Path(dest).read_bytes(), data)

    def test_executable_member_refused_by_default(self):
        data = b"MZ" + b"\x90" * 62
        archive = _SCRATCH / "withexe.zip"
        _make_zip(archive, {"payload.exe": data})
        dest = self._dest("payload.exe")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="payload.exe", dest_path=dest))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "EXECUTABLE_CONTENT_REFUSED")
        self.assertEqual(result["executable_content_kind"], "PE")
        self.assertFalse(Path(dest).exists())

    def test_executable_member_extracted_when_explicitly_allowed(self):
        data = b"MZ" + b"\x90" * 62
        archive = _SCRATCH / "withexe2.zip"
        _make_zip(archive, {"payload.exe": data})
        dest = self._dest("payload_out.exe")
        result = json.loads(archive_inspect(str(archive), operation="extract",
                                             member="payload.exe", dest_path=dest,
                                             allow_executable_content=True))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["executable_content_detected"])
        self.assertTrue(Path(dest).is_file())
        self.assertEqual(Path(dest).read_bytes(), data)

class ReadOperationPasswordAndIoTests(_ScratchGuard):
    """`read` mirrors `extract`: the password reaches the library, and an
    operating-system error is its own status, never corruption."""

    def _enc(self, name="enc_read.zip", data=b"the real content", seed=_FIXTURE_SEED):
        archive = _SCRATCH / name
        _make_zip_traditional_encrypted(archive, "secret.txt", data, "s3cr3t", seed=seed)
        return archive

    def _read(self, archive, member="secret.txt", **kwargs):
        return json.loads(archive_inspect(str(archive), operation="read", member=member, **kwargs))

    def test_read_with_the_correct_password_returns_the_content(self):
        result = self._read(self._enc(), password="s3cr3t")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["content"], "the real content")

    def test_read_of_an_encrypted_member_without_a_password_is_password_required(self):
        result = self._read(self._enc())
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PASSWORD_REQUIRED")

    def test_read_with_a_wrong_password_is_bad_password(self):
        result = self._read(self._enc(), password="wrong-password")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "BAD_PASSWORD")

    def test_read_wrong_password_that_slips_past_the_check_is_not_claimed_as_bad_password(self):
        result = self._read(self._enc("enc_read_collide.zip", seed=_COLLIDING_SEED), password="wrong-password")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "BAD_PASSWORD_OR_CORRUPT_DATA")

    def test_read_tar_with_a_password_is_not_supported_like_extract(self):
        archive = _SCRATCH / "read.tar"
        data = b"plain text member"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="a.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        result = self._read(archive, member="a.txt", password="whatever")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "PASSWORD_NOT_SUPPORTED_FOR_TAR")
        self.assertTrue(self._read(archive, member="a.txt")["ok"])

    def test_an_os_error_while_reading_is_not_reported_as_corruption_or_a_password_problem(self):
        archive = _SCRATCH / "io.zip"
        _make_zip(archive, {"a.txt": b"fine data"})
        enc = self._enc("io_enc.zip")
        boom = OSError(5, "Input/output error")
        for operation, target, kwargs in (
            ("read", archive, {"member": "a.txt"}),
            ("extract", archive, {"member": "a.txt", "dest_path": self._dest("io_out.txt")}),
            ("read", enc, {"member": "secret.txt", "password": "s3cr3t"}),
            ("extract", enc, {"member": "secret.txt", "password": "s3cr3t", "dest_path": self._dest("io_out2.txt")}),
        ):
            with self.subTest(operation=operation, archive=target.name):
                with unittest.mock.patch.object(zipfile.ZipFile, "read", side_effect=boom):
                    result = json.loads(archive_inspect(str(target), operation=operation, **kwargs))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "MEMBER_READ_IO_ERROR")
                self.assertEqual(result["status"], "READ_FAILED")
                self.assertEqual(result["errno"], 5)
                self.assertEqual(result["error_type"], "OSError")
        self.assertFalse((_SCRATCH / "io_out.txt").exists())

    def test_an_os_error_on_a_tar_member_read_is_its_own_status(self):
        archive = _SCRATCH / "io.tar"
        data = b"plain text member"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="a.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        with unittest.mock.patch.object(tarfile.TarFile, "extractfile", side_effect=OSError(110, "Connection timed out")):
            result = self._read(archive, member="a.txt")
        self.assertEqual((result["error"], result["errno"]), ("MEMBER_READ_IO_ERROR", 110))

    def _plain_tar(self, name="plain.tar"):
        archive = _SCRATCH / name
        data = b"plain text member"
        with tarfile.open(str(archive), "w") as t:
            info = tarfile.TarInfo(name="a.txt")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        return archive

    def test_an_os_error_on_a_tar_member_extract_is_its_own_status(self):
        archive = self._plain_tar("io_extract.tar")
        with unittest.mock.patch.object(tarfile.TarFile, "extractfile", side_effect=OSError(110, "Connection timed out")):
            result = json.loads(archive_inspect(str(archive), operation="extract", member="a.txt",
                                                dest_path=self._dest("tar_io_out.txt")))
        self.assertEqual((result["error"], result["errno"], result["status"]),
                         ("MEMBER_READ_IO_ERROR", 110, "READ_FAILED"))
        self.assertFalse((_SCRATCH / "tar_io_out.txt").exists())

    def test_a_member_the_library_cannot_find_is_member_not_found_on_read_and_extract(self):
        archive = _SCRATCH / "keyerror.zip"
        _make_zip(archive, {"a.txt": b"fine data"})
        for operation, kwargs in (("read", {}), ("extract", {"dest_path": self._dest("keyerror_out.txt")})):
            with self.subTest(operation=operation):
                with unittest.mock.patch.object(zipfile.ZipFile, "read", side_effect=KeyError("a.txt")):
                    result = json.loads(archive_inspect(str(archive), operation=operation, member="a.txt", **kwargs))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "MEMBER_NOT_FOUND")
                self.assertIn("a.txt", result["detail"])
        self.assertFalse((_SCRATCH / "keyerror_out.txt").exists())

    def test_an_archive_that_cannot_be_opened_is_reported_as_unreadable_not_raised(self):
        archive = self._plain_tar("unreadable.tar")
        for exc in (zipfile.BadZipFile("File is not a zip file"), tarfile.ReadError("truncated header"),
                    EOFError("Compressed file ended"), zlib.error("bad data"), OSError(5, "Input/output error")):
            with self.subTest(exc=type(exc).__name__):
                with unittest.mock.patch("liebert_re.tools.formats._archive_members", side_effect=exc):
                    result = json.loads(archive_inspect(str(archive)))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "ARCHIVE_UNREADABLE")
                self.assertEqual(result["error_type"], type(exc).__name__)

    def test_a_destination_that_cannot_be_written_is_write_failed_not_raised(self):
        archive = _SCRATCH / "writefail.zip"
        _make_zip(archive, {"a.txt": b"fine data"})
        with unittest.mock.patch.object(Path, "write_bytes", side_effect=OSError(28, "No space left on device")):
            result = json.loads(archive_inspect(str(archive), operation="extract", member="a.txt",
                                                dest_path=self._dest("writefail_out.txt")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "WRITE_FAILED")
        self.assertEqual(result["member"], "a.txt")

    def test_genuine_corruption_signals_keep_their_corruption_status(self):
        archive = _SCRATCH / "still_corrupt.zip"
        _make_zip(archive, {"a.txt": b"fine data"})
        for exc in (zipfile.BadZipFile("Bad CRC-32 for file"), zlib.error("bad data"), EOFError("short")):
            with self.subTest(exc=type(exc).__name__):
                with unittest.mock.patch.object(zipfile.ZipFile, "read", side_effect=exc):
                    result = self._read(archive, member="a.txt")
                self.assertEqual(result["error"], "CORRUPT_MEMBER")


if __name__ == "__main__":
    unittest.main()
