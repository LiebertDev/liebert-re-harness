"""Focused public-port coverage for twelve small format-inspection modules
whose only private coverage is tests/test_offline_capabilities.py -- a file
that cannot be ported because it imports ~19 unpublished orchestration
modules (claim_verifier, coverage_engine, deterministic_planner,
file_router, hybrid_retrieval, obfuscation_analyzer, red_blue_pairing,
research_graph, research_state, tool_cache, tool_registry,
trajectory_compiler, tools_cfg_deobfuscate, tools_decompiler, tools_dotnet,
tools_ida, tools_native, tools_stackstring) and also references a
machine-local analysis-project cache directory plus real fixture corpora
that are out of scope for this port batch.

Per the port task's minimum obligation, this file proves for each of the
twelve modules: (i) it imports cleanly, and (ii) feeding it a file that is
not of its target format returns that module's own documented structured
"not this format" result -- never a raised exception and never a silent
false success. Each module's actual real-fixture round-trip parsing
already has full private coverage; this is deliberately narrower than
that, by design (see module docstring above).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tools_workspace
from tools_android import android_resource_analyzer
from tools_archive2 import rar_7z
from tools_dart import dart_aot_recovery
from tools_dex import dex_decompiler
from tools_godot import godot_asset_analyzer
from tools_il2cpp import il2cpp_mapper
from tools_jvm import jvm_decompiler
from tools_pcap import pcap_analyzer
from tools_plist import plist_inspect
from tools_unity import unity_asset_analyzer
from tools_unreal import unreal_asset_analyzer
from tools_upx import upx_unpack


def _j(raw):
    import json
    return json.loads(raw)


class FormatProbeNotThisFormatTests(unittest.TestCase):
    """Each module fed bytes that are plainly not its target format. Every
    one must come back ok:false with a named, format-specific error -- not
    raise, and not silently report success."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE, ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.garbage = self.root / "garbage.bin"
        self.garbage.write_bytes(b"not any recognised container format\x00\x01\x02" * 4)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dart_aot_recovery_reports_zero_plausible_headers(self):
        result = _j(dart_aot_recovery(str(self.garbage)))
        self.assertEqual(result["snapshot_magic_occurrences"], 0)
        self.assertEqual(result["plausible_snapshot_headers"], 0)

    def test_dart_aot_recovery_missing_file_is_a_structured_error(self):
        result = _j(dart_aot_recovery(str(self.root / "nope.so")))
        self.assertIn("error", result)

    def test_android_resource_analyzer_rejects_non_axml_non_apk(self):
        result = _j(android_resource_analyzer(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("ANDROID_MANIFEST_PARSE_ERROR", result["error"])

    def test_godot_asset_analyzer_rejects_non_pck(self):
        result = _j(godot_asset_analyzer(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("NOT_PCK_OR_PARSE_ERROR", result["error"])

    def test_godot_encrypted_directory_surfaces_its_named_error_directly(self):
        import struct
        pck = self.root / "enc.pck"
        # version 3 header with the directory-encrypted flag set
        hdr = b"GDPC" + struct.pack("<IIIII", 3, 4, 2, 0, 1) + struct.pack("<Q", 0) + struct.pack("<Q", 0) + bytes(64)
        pck.write_bytes(hdr)
        result = _j(godot_asset_analyzer(str(pck)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ENCRYPTED_DIRECTORY_NOT_SUPPORTED")

    def test_unreal_asset_analyzer_rejects_non_pak(self):
        result = _j(unreal_asset_analyzer(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("PAK_PARSE_ERROR", result["error"])

    def test_dex_decompiler_rejects_non_dex(self):
        result = _j(dex_decompiler(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("NOT_DEX_OR_PARSE_ERROR", result["error"])

    def test_jvm_decompiler_rejects_non_class_non_jar(self):
        result = _j(jvm_decompiler(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("NOT_JVM_TARGET", result["error"])

    def test_plist_inspect_rejects_non_plist(self):
        result = _j(plist_inspect(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("NOT_A_PLIST_OR_PARSE_ERROR", result["error"])

    def test_pcap_analyzer_rejects_non_pcap(self):
        result = _j(pcap_analyzer(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertIn("PCAP_PARSE_ERROR", result["error"])

    def test_rar_7z_reports_unrecognized_archive_format(self):
        result = _j(rar_7z(str(self.garbage)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "NOT_A_RECOGNIZED_ARCHIVE_FORMAT")

    def test_rar_7z_handles_real_stdlib_codecs_and_their_corruption(self):
        # gzip/bz2/xz are stdlib-only (no optional third-party library), so
        # this exercises a real decode success plus a real corrupted-body
        # structured failure without any external dependency at all.
        import bz2
        import gzip
        import lzma as lzma_mod

        gz = self.root / "note.txt.gz"
        gz.write_bytes(gzip.compress(b"hello from gzip"))
        ok = _j(rar_7z(str(gz), "read"))
        self.assertTrue(ok["ok"], ok)
        self.assertIn("hello from gzip", ok["content"])

        corrupt_gz = self.root / "corrupt.gz"
        corrupt_gz.write_bytes(gzip.compress(b"hello")[:5] + b"\xff\xff\xff\xff")
        bad = _j(rar_7z(str(corrupt_gz), "read"))
        self.assertFalse(bad["ok"])

        # bz2 and xz were imported here and never exercised, so the comment
        # above promised three codecs and the test covered one. The capability
        # table claims all three, which makes the gap worth closing rather than
        # deleting the imports to quiet the linter.
        for suffix, compress in (
            (".bz2", bz2.compress), (".xz", lzma_mod.compress),
        ):
            good = self.root / f"note.txt{suffix}"
            good.write_bytes(compress(b"hello from " + suffix.encode()))
            got = _j(rar_7z(str(good), "read"))
            self.assertTrue(got["ok"], got)
            self.assertIn("hello from", got["content"])

            broken = self.root / f"corrupt{suffix}"
            broken.write_bytes(compress(b"hello")[:6] + b"\xff\xff\xff\xff")
            refused = _j(rar_7z(str(broken), "read"))
            self.assertFalse(refused["ok"], refused)

    def test_rar_7z_reports_a_structured_error_for_a_corrupt_7z_body(self):
        # py7zr is an optional dependency (not in the published package's
        # required set). Forging the real 7Z magic with a junk body reaches
        # _7z_list's `import py7zr` either way: absent -> ModuleNotFoundError,
        # present -> a real py7zr parse failure on the bogus body -- both are
        # caught by rar_7z's own except Exception and reported as a
        # structured ok:false result, so this test proves the documented
        # "package absent" failure path for real rather than skipping it.
        sevenz = self.root / "fake.7z"
        sevenz.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
        result = _j(rar_7z(str(sevenz)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["format"], "7Z")

    def test_rar_7z_reports_a_structured_result_for_a_bare_rar_signature(self):
        # rarfile is an optional dependency. Forging just the RAR magic (no
        # real archive body) reaches _rar_list's `import rarfile` either
        # way. Two legitimate, both-structured outcomes, same shape as the
        # UnityPy absence test above:
        #   - rarfile installed (this repo's own dev environment): it does
        #     not raise on a signature-only body, it reports an empty
        #     member list -- ok:true, member_count 0.
        #   - rarfile NOT installed (a plain install of the published
        #     package): `import rarfile` raises ModuleNotFoundError, caught
        #     by rar_7z's own except Exception -- ok:false. This is the
        #     module's actual "package absent" path, exercised for real.
        rar = self.root / "fake.rar"
        rar.write_bytes(b"Rar!\x1a\x07\x01" + b"\x00" * 32)
        result = _j(rar_7z(str(rar)))
        self.assertEqual(result["format"], "RAR")
        if result["ok"]:
            self.assertEqual(result["member_count"], 0)
        else:
            self.assertIn("error", result)

    def test_rar_7z_reports_a_structured_error_for_a_corrupt_zstd_body(self):
        # Same reasoning again, for the backports.zstd dependency (stdlib's
        # own zstd support does not ship until a later Python than this
        # project targets, so the module falls back to the backport).
        zst = self.root / "fake.zst"
        zst.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 32)
        result = _j(rar_7z(str(zst)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["format"], "ZSTD")


class UnityAssetAnalyzerTests(unittest.TestCase):
    """Isolated in its own class: UnityPy.load() keeps a memory-mapped handle
    open on the file it loads, which on Windows can outlive a shared tmpdir's
    teardown from an unrelated test -- ignore_cleanup_errors keeps that a
    non-issue rather than a flaky failure."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE, ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_non_unity_asset_reports_a_structured_not_applicable_result(self):
        # Two legitimate outcomes for this exact input, both structured and
        # neither a raise or a fabricated success:
        #   - UnityPy installed (this repo's own dev environment): it does
        #     not raise on an unrecognised bundle, it reports an empty asset
        #     environment -- ok:true, object_count 0.
        #   - UnityPy NOT installed (a plain install of the published
        #     package, which does not list it as a dependency): the
        #     `import UnityPy` inside the module's own try/except is caught
        #     the same way a real load failure would be -- ok:false,
        #     NOT_UNITY_ASSET_OR_LOAD_ERROR. This is the module's actual
        #     "external tool absent" path, exercised for real rather than
        #     mocked.
        garbage = self.root / "garbage.bin"
        garbage.write_bytes(b"not any recognised container format\x00\x01\x02" * 4)
        result = _j(unity_asset_analyzer(str(garbage)))
        if result["ok"]:
            self.assertEqual(result["object_count"], 0)
            self.assertEqual(result["type_counts"], {})
        else:
            self.assertIn("NOT_UNITY_ASSET_OR_LOAD_ERROR", result["error"])

    def test_unity_list_surfaces_typetree_read_failure_instead_of_swallowing_it(self):
        try:
            import UnityPy  # noqa: F401
        except ImportError:
            self.skipTest("UnityPy not installed")

        class _FakeType:
            name = "GameObject"

        class _FakeObj:
            path_id = 1
            class_id = 1
            type = _FakeType()
            assets_file = None

            def read(self):
                raise RuntimeError("boom")

        class _FakeEnv:
            objects = [_FakeObj()]

        garbage = self.root / "garbage.bin"
        garbage.write_bytes(b"unity-ish\x00\x01" * 4)
        with mock.patch("UnityPy.load", return_value=_FakeEnv()):
            result = _j(unity_asset_analyzer(str(garbage), "list"))
        self.assertTrue(result["ok"], result)
        row = result["objects"][0]
        self.assertIsNone(row["name"])
        self.assertIn("TYPETREE_READ_FAILED", row["name_error"])


class Il2cppMapperToolMissingTests(unittest.TestCase):
    """il2cpp_mapper always shells out to a real external Il2CppDumper
    binary; forcing it absent (rather than relying on environment state)
    keeps this deterministic in both the private and public repos."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)
        self.binary = self.root / "GameAssembly.dll"
        self.binary.write_bytes(b"MZ\x90\x00fake")
        self.metadata = self.root / "global-metadata.dat"
        self.metadata.write_bytes(b"\xaf\x1b\xb1\xfa" + b"\x00" * 16)

    def tearDown(self):
        self.tmp.cleanup()

    def test_tool_missing_is_a_structured_result(self):
        with mock.patch("tools_il2cpp._il2cppdumper", return_value=None):
            result = _j(il2cpp_mapper(str(self.binary), str(self.metadata)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "IL2CPPDUMPER_TOOL_MISSING")


class UpxUnpackToolMissingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=tools_workspace.WORKSPACE)
        self.root = Path(self.tmp.name)
        self.target = self.root / "sample.exe"
        self.target.write_bytes(b"MZ\x90\x00not really packed")

    def tearDown(self):
        self.tmp.cleanup()

    def test_tool_missing_is_a_structured_result(self):
        with mock.patch("tools_upx._upx_binary", return_value=None):
            result = _j(upx_unpack(str(self.target)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "TOOL_MISSING")


if __name__ == "__main__":
    unittest.main()
