"""Regression for a missing general primitive found solving a real target:
listing and extracting a PE's embedded resources. A real solve attempt on a
.NET Reactor native stub needed to read an RT_RCDATA resource named "__"
holding the encrypted managed assembly payload, and had to call `pefile`
inline because no tool existed for it -- a repo-wide grep for resource
enumeration found only android_resource_analyzer, which is APK-only.

WHY THIS IS GENERAL, not target-specific: hiding a payload in a resource is
one of the most common packer/dropper/loader patterns there is (droppers,
self-extracting installers, embedded drivers, icon/overlay stuffing all use
the same PE resource directory shape). tools_binary.pe_resources is built
entirely on pefile's own already-vendored DIRECTORY_ENTRY_RESOURCE walker
-- no new resource parser -- and lives in tools_binary.py alongside this
module's other PE-level facts (pe_sections/pe_imports/pe_exports/
authenticode_signature).

FIXTURES. These tests used to read three real binaries that this repository
does not ship, so they skipped on every clean checkout. They now run against
PEs built by tests/_pe_fixtures.py (the recipe in docs/CORPUS.md), each the
smallest file that has the structure its tests assert on:

  PAYLOAD_PE  a .rsrc tree with two RT_RCDATA entries -- the NAME entry "__" holding 4096
              high-entropy bytes (the encrypted-payload shape, entropy above 7.9) and the NAME
              entry "~" holding 32 bytes -- plus four RT_ICON entries (IDs 1..4, all different
              sizes) and one RT_MANIFEST. One file serves every class below that needs resources.
  PLAIN_PE    the same PE header and one code section, with NO resource directory (data
              directory 2 is zero), for the no-resource-directory behaviour.
  CUT_PE      PAYLOAD_PE cut in the middle of its first resource's bytes: headers, section table
              and the whole directory tree survive, but the data entries and the section header
              declare bytes that are no longer in the file.

The expected sizes and hashes below are computed from the bytes the fixture put in, with hashlib, not
read back from the tool: the oracle stays independent of the code under test, as the original
real-binary hash check was.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.tools.binary import pe_resources
from tests._pe_fixtures import (
    LANG_EN_US, RT_ICON, RT_MANIFEST, RT_RCDATA, build_pe, pseudo_random_bytes,
)

# safe_path refuses paths outside the workspace, so the fixtures live in a temp dir under the repo root
# (the test conftest redirects such temp dirs into the ignored .pytest_evidence_scratch/).
REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)

# "__" is the Reactor-style encrypted payload; 4096 bytes keeps the file tiny while the entropy of a
# SHA-256 stream is about 7.95 bits/byte, above the 7.9 threshold the list test asserts.
PAYLOAD = pseudo_random_bytes(4096)
MARKER = b"~" * 32
# Four icons of different sizes, so selecting ID 2 can only return the right one.
ICONS = {1: pseudo_random_bytes(256, "icon1"), 2: pseudo_random_bytes(1064, "icon2"),
         3: pseudo_random_bytes(512, "icon3"), 4: pseudo_random_bytes(128, "icon4")}
MANIFEST = b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"></assembly>'
RESOURCES = [
    (RT_RCDATA, "__", LANG_EN_US, PAYLOAD),
    (RT_RCDATA, "~", LANG_EN_US, MARKER),
    *[(RT_ICON, icon_id, LANG_EN_US, data) for icon_id, data in ICONS.items()],
    (RT_MANIFEST, 1, LANG_EN_US, MANIFEST),
]
EXPECTED_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()

_TMP = None
PAYLOAD_PE = PLAIN_PE = CUT_PE = ""


def setUpModule():
    global _TMP, PAYLOAD_PE, PLAIN_PE, CUT_PE
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    root = Path(_TMP.name)
    files = {
        "payload.exe": build_pe(resources=RESOURCES),
        "plain.exe": build_pe(),
        "cut.exe": build_pe(resources=RESOURCES, truncate_in_resource_data=True),
    }
    for name, data in files.items():
        (root / name).write_bytes(data)
    PAYLOAD_PE, PLAIN_PE, CUT_PE = (str(root / n) for n in files)


def tearDownModule():
    _TMP.cleanup()


class FixtureShapeTests(unittest.TestCase):
    """The fixtures themselves, checked with pefile directly so a builder fault is not blamed on the tool."""

    def test_payload_pe_carries_the_declared_resource_tree(self):
        import pefile
        pe = pefile.PE(PAYLOAD_PE)
        try:
            found = {}
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for name in rtype.directory.entries:
                    lang = name.directory.entries[0]
                    key = (rtype.struct.Id, name.struct.Id if name.name is None else name.name.decode())
                    found[key] = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
        finally:
            pe.close()
        expected = {(t, n): d for t, n, _, d in RESOURCES}
        self.assertEqual(found, expected)

    def test_plain_and_cut_variants_differ_from_payload_pe_as_documented(self):
        full = Path(PAYLOAD_PE).read_bytes()
        cut = Path(CUT_PE).read_bytes()
        self.assertLess(len(cut), len(full))
        self.assertEqual(cut, full[: len(cut)])
        self.assertGreater(len(cut), len(Path(PLAIN_PE).read_bytes()))   # past the code section, into .rsrc
        import pefile
        plain = pefile.PE(PLAIN_PE)
        try:
            self.assertFalse(hasattr(plain, "DIRECTORY_ENTRY_RESOURCE"))
        finally:
            plain.close()


class PeResourcesListTests(unittest.TestCase):
    def test_list_finds_the_reactor_payload_and_the_second_rcdata(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="list"))
        self.assertTrue(result.get("ok"), result)
        self.assertTrue(result["has_resource_directory"])
        rcdata = [r for r in result["resources"] if r["type_well_known"] == "RT_RCDATA"]
        self.assertEqual(len(rcdata), 2)
        payload = next(r for r in rcdata if r["name"] == "__")
        self.assertEqual(payload["size"], len(PAYLOAD))
        self.assertGreater(payload["entropy"], 7.9)  # known encrypted-payload signature
        marker = next(r for r in rcdata if r["name"] == "~")
        self.assertEqual(marker["size"], 32)

    def test_list_is_paginated(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="list", max_results=1))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["has_more"])
        self.assertGreater(result["total"], 1)


class PeResourcesExtractHashTests(unittest.TestCase):
    def test_extract_matches_known_ground_truth_sha256(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="extract", resource_type="RT_RCDATA", resource_name="__"))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["size"], len(PAYLOAD))
        self.assertEqual(result["sha256"], EXPECTED_SHA256)

        evidence_path = Path(result["evidence_file"])
        self.assertTrue(evidence_path.exists())
        payload = evidence_path.read_bytes()
        self.assertEqual(len(payload), len(PAYLOAD))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), EXPECTED_SHA256)
        # Bytes never returned inline in full -- only a bounded preview.
        self.assertLess(result["preview_returned_bytes"], len(PAYLOAD))
        self.assertTrue(result["preview_truncated"])
        self.assertEqual(bytes.fromhex(result["preview_hex"]), payload[: result["preview_returned_bytes"]])

    def test_extract_by_numeric_type_id_matches_rt_constant(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="extract", resource_type=str(RT_RCDATA), resource_name="__"))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["sha256"], EXPECTED_SHA256)


class PeResourcesAmbiguousSelectorTests(unittest.TestCase):
    def test_selector_matching_multiple_resources_returns_all_not_one(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="extract", resource_type="RT_ICON"))
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "AMBIGUOUS_SELECTOR")
        self.assertEqual(len(result["matches"]), 4)
        self.assertEqual({m["name_id"] for m in result["matches"]}, {1, 2, 3, 4})

    def test_adding_name_disambiguates(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="extract", resource_type="RT_ICON", resource_name="2"))
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result["size"], len(ICONS[2]))
        self.assertEqual(result["sha256"], hashlib.sha256(ICONS[2]).hexdigest())

    def test_list_reports_ordinary_icon_and_version_style_resources(self):
        result = json.loads(pe_resources(PAYLOAD_PE, operation="list"))
        self.assertTrue(result.get("ok"), result)
        types = {r["type_well_known"] for r in result["resources"]}
        self.assertIn("RT_ICON", types)
        self.assertIn("RT_MANIFEST", types)


class PeResourcesNoResourceDirectoryTests(unittest.TestCase):
    def test_list_reports_cleanly_not_an_error(self):
        result = json.loads(pe_resources(PLAIN_PE, operation="list"))
        self.assertTrue(result.get("ok"), result)
        self.assertFalse(result["has_resource_directory"])
        self.assertEqual(result["resources"], [])
        self.assertEqual(result["total"], 0)

    def test_extract_refuses_with_a_named_reason(self):
        result = json.loads(pe_resources(PLAIN_PE, operation="extract", resource_type="RT_ICON"))
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "NO_RESOURCE_DIRECTORY")


class PeResourcesMalformedTests(unittest.TestCase):
    """A resource that pefile's own out-of-bounds clamp silently truncates
    (declares a Size larger than the bytes actually available) must be
    reported as a structured error, never presented as a complete
    resource. CUT_PE is PAYLOAD_PE cut halfway through its first resource's
    bytes. The cut point is deliberate: cutting earlier (inside the header
    or the directory tree) is a different failure, PE_PARSE_FAILED or
    RESOURCE_DIRECTORY_MALFORMED, and a cut past the data would leave the
    file whole. Cutting inside the data keeps the directory readable, so the
    corruption shape is the one under test: out-of-bounds resource data, not
    a bad header."""

    def test_truncated_resource_data_is_a_structured_error_not_a_partial_tree(self):
        result = json.loads(pe_resources(CUT_PE, operation="list"))
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "RESOURCE_DATA_MALFORMED")
        self.assertIn("truncated or corrupt", result.get("detail", ""))

    def test_truncated_resource_data_also_refuses_extract(self):
        result = json.loads(pe_resources(CUT_PE, operation="extract", resource_type="RT_MANIFEST"))
        self.assertFalse(result.get("ok"))
        self.assertIn(result.get("error"), {"RESOURCE_DATA_MALFORMED", "RESOURCE_NOT_FOUND"})


if __name__ == "__main__":
    unittest.main()
