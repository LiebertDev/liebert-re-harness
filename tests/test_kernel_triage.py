"""kernel_triage's contract (liebert_re/tools/binary.py), with no external tool involved.

The tool reads a PE and reports driver indicators one by one. These tests hold the line that matters: it
never states that a file IS a driver. `driver_likelihood` is LIKELY only when the native subsystem and a
kernel import are both observed with readable imports, and UNKNOWN otherwise, with the missing or
conflicting indicators named. Fixtures are built in code by
liebert_re.recover.owned_binary_fixtures.build_owned_pe_sections.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections, build_owned_rsds
from liebert_re.tools.binary import kernel_triage

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
_TMP = None
ROOT = Path()

TEXT = (".text", 0x60000020)
INIT = ("INIT", 0xE2000020)
PAGE = ("PAGE", 0x60000020)
KERNEL_IMPORTS = {"ntoskrnl.exe": ["IoCreateDevice", "IofCompleteRequest"], "HAL.dll": ["KeStallExecutionProcessor"]}
USER_IMPORTS = {"KERNEL32.dll": ["ExitProcess"]}


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def triage(name, **kwargs):
    path = build_owned_pe_sections(ROOT / name, **kwargs)
    return json.loads(kernel_triage(str(path)))


def indicator(result, name):
    return next(i for i in result["indicators"] if i["name"] == name)


class RefusalTests(unittest.TestCase):
    def test_non_pe_bytes_are_refused_as_invalid_pe(self):
        path = ROOT / "notape.bin"
        path.write_bytes(b"this is plainly not a portable executable" * 8)
        r = json.loads(kernel_triage(str(path)))
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "INVALID_PE")
        self.assertIs(r["fixable"], False)
        self.assertNotIn("driver_likelihood", r)

    def test_header_cut_short_is_invalid_pe_not_a_partial_result(self):
        full = build_owned_pe_sections(ROOT / "full.sys", subsystem=1, imports=KERNEL_IMPORTS).read_bytes()
        path = ROOT / "headercut.sys"
        path.write_bytes(full[:100])
        r = json.loads(kernel_triage(str(path)))
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "INVALID_PE")

    def test_missing_file_is_not_found_and_fixable(self):
        r = json.loads(kernel_triage(str(ROOT / "absent.sys")))
        self.assertEqual((r["ok"], r["status"], r["error"], r["fixable"]), (False, "NOT_FOUND", "FILE_NOT_FOUND", True))

    def test_path_outside_the_workspace_is_refused_and_fixable(self):
        r = json.loads(kernel_triage("../outside_the_workspace.sys"))
        self.assertEqual((r["ok"], r["status"], r["fixable"]), (False, "PATH_REFUSED", True))

    def test_unsupported_machine_is_refused_not_guessed(self):
        r = triage("arm32.sys", machine=0x1C0, subsystem=1, imports=KERNEL_IMPORTS)
        self.assertEqual((r["ok"], r["status"], r["error"], r["fixable"]), (False, "UNSUPPORTED", "UNSUPPORTED_MACHINE", False))
        self.assertEqual(r["machine"], "0x1c0")


class TruncationTests(unittest.TestCase):
    def test_truncated_pe_gives_a_limited_result_that_says_so(self):
        full = build_owned_pe_sections(ROOT / "whole.sys", sections=(TEXT, INIT, PAGE), subsystem=1,
                                       imports=KERNEL_IMPORTS, rsds=build_owned_rsds()).read_bytes()
        path = ROOT / "cut.sys"
        path.write_bytes(full[:len(full) - 0x180])
        r = json.loads(kernel_triage(str(path)))
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], "ANALYSIS_LIMITED")
        self.assertTrue(any("file ends before" in x for x in r["limitations"]), r["limitations"])
        self.assertEqual([s["name"] for s in r["pe"]["sections"]], [".text", "INIT", "PAGE", ".rdata"])


class PeBasicsTests(unittest.TestCase):
    def test_valid_x64_header_and_sections_are_read(self):
        r = triage("basic.sys", sections=(TEXT, INIT, PAGE), subsystem=1, imports=KERNEL_IMPORTS)
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], "OK")
        pe = r["pe"]
        self.assertTrue(pe["valid"])
        self.assertEqual((pe["machine"], pe["architecture"], pe["bits"]), ("0x8664", "x86_64", 64))
        self.assertEqual([s["name"] for s in pe["sections"]], [".text", "INIT", "PAGE", ".rdata"])
        init = pe["sections"][1]
        self.assertEqual((init["raw_size"], init["characteristics"]), (0x200, "0xe2000020"))
        self.assertEqual({d["dll"]: d["symbols"] for d in pe["imports"]["dlls"]},
                         {"ntoskrnl.exe": ["IoCreateDevice", "IofCompleteRequest"], "HAL.dll": ["KeStallExecutionProcessor"]})
        self.assertEqual(pe["imports"]["state"], "PRESENT")

    def test_subsystem_is_reported_but_is_not_driver_evidence(self):
        r = triage("native_only.sys", subsystem=1, imports=USER_IMPORTS)
        self.assertEqual((r["pe"]["subsystem"], r["pe"]["subsystem_name"]), (1, "NATIVE"))
        ind = indicator(r, "subsystem_native")
        self.assertTrue(ind["present"])
        self.assertIs(ind["proves_driver"], False)
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")

    def test_debug_and_pdb_indicators(self):
        with_pdb = triage("pdb.sys", subsystem=1, imports=KERNEL_IMPORTS, rsds=build_owned_rsds())["pe"]["debug"]
        self.assertTrue(with_pdb["directory_present"])
        self.assertEqual(with_pdb["entries"], [{"type": 2, "type_name": "CODEVIEW"}])
        self.assertEqual(with_pdb["pdb_paths"], ["owned_fixture.pdb"])
        self.assertTrue(with_pdb["pdb_indicator"])
        without = triage("nopdb.sys", subsystem=1, imports=KERNEL_IMPORTS)["pe"]["debug"]
        self.assertEqual((without["directory_present"], without["pdb_paths"], without["pdb_indicator"]), (False, [], False))


class IndicatorTests(unittest.TestCase):
    def test_kernel_import_alone_is_only_an_indicator(self):
        r = triage("kimport.exe", subsystem=3, imports={"ntoskrnl.exe": ["IoCreateDevice"]})
        ind = indicator(r, "kernel_import")
        self.assertEqual((ind["present"], ind["confidence"], ind["proves_driver"]), (True, "deterministic", False))
        self.assertEqual(ind["observed"], ["ntoskrnl.exe"])
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")

    def test_page_section_alone_is_only_a_heuristic_indicator(self):
        r = triage("pageonly.exe", sections=(TEXT, PAGE), subsystem=3, imports=USER_IMPORTS)
        ind = indicator(r, "page_section")
        self.assertEqual((ind["present"], ind["confidence"], ind["proves_driver"]), (True, "heuristic", False))
        self.assertEqual(indicator(r, "init_section")["present"], False)
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")

    def test_each_indicator_carries_its_own_confidence_label(self):
        r = triage("labels.sys", sections=(TEXT, INIT, PAGE), subsystem=1, imports=KERNEL_IMPORTS)
        labels = {i["name"]: i["confidence"] for i in r["indicators"]}
        self.assertEqual(labels, {"subsystem_native": "deterministic", "kernel_import": "deterministic",
                                  "init_section": "heuristic", "page_section": "heuristic"})

    def test_strong_indicators_give_likely_never_a_flat_verdict(self):
        r = triage("likely.sys", sections=(TEXT, INIT, PAGE), subsystem=1, imports=KERNEL_IMPORTS)
        self.assertEqual(r["driver_likelihood"], "LIKELY")
        self.assertIn("cannot be proven", r["statement"])
        self.assertTrue(all(i["proves_driver"] is False for i in r["indicators"]))

    def test_conflicting_signals_give_unknown_with_the_conflict_named(self):
        # kernel import and a PAGE section, but a console subsystem: the signals disagree.
        r = triage("conflict.exe", sections=(TEXT, PAGE), subsystem=3, imports=KERNEL_IMPORTS)
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")
        self.assertTrue(any("conflict" in x for x in r["rationale"]), r["rationale"])
        # the reverse conflict: native subsystem, no kernel import
        r = triage("conflict2.sys", subsystem=1, imports=USER_IMPORTS)
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")
        self.assertTrue(any("native subsystem without a kernel import" in x for x in r["rationale"]), r["rationale"])

    def test_ordinary_x64_pe_is_a_negative_with_unknown_not_not_a_driver(self):
        r = triage("plain.exe", subsystem=3, imports=USER_IMPORTS)
        self.assertEqual(r["driver_likelihood"], "UNKNOWN")
        self.assertFalse(indicator(r, "subsystem_native")["present"])
        self.assertFalse(indicator(r, "kernel_import")["present"])


class ImportStateTests(unittest.TestCase):
    def test_no_imports_and_broken_imports_are_different_states(self):
        absent = triage("noimp.sys", subsystem=1)
        broken = triage("badimp.sys", subsystem=1, bad_import_rva=True)
        self.assertEqual(absent["pe"]["imports"]["state"], "ABSENT")
        self.assertEqual(absent["pe"]["imports"]["dlls"], [])
        self.assertEqual(absent["status"], "OK")
        self.assertEqual(broken["pe"]["imports"]["state"], "UNREADABLE")
        self.assertIsNone(broken["pe"]["imports"]["dlls"])
        self.assertEqual(broken["status"], "ANALYSIS_LIMITED")
        self.assertTrue(any("import directory unreadable" in x for x in broken["limitations"]), broken["limitations"])

    def test_unreadable_imports_leave_kernel_import_unknown_and_block_likely(self):
        broken = triage("badimp2.sys", sections=(TEXT, INIT, PAGE), subsystem=1, bad_import_rva=True)
        self.assertIsNone(indicator(broken, "kernel_import")["present"])
        self.assertEqual(broken["driver_likelihood"], "UNKNOWN")
        # absent imports are a definite "no kernel import", unlike unreadable ones
        self.assertIs(indicator(triage("noimp2.sys", subsystem=1), "kernel_import")["present"], False)


class EnvelopeTests(unittest.TestCase):
    def test_success_envelope_has_the_documented_keys(self):
        r = triage("env.sys", subsystem=1, imports=KERNEL_IMPORTS)
        self.assertEqual(set(r), {"ok", "tool", "status", "path", "pe", "indicators", "driver_likelihood",
                                  "rationale", "statement", "limitations", "unknown_fields"})
        self.assertEqual(r["tool"], "kernel_triage")
        self.assertIn(r["driver_likelihood"], {"LIKELY", "UNKNOWN"})

    def test_refusal_envelope_has_fixable_and_fix(self):
        r = json.loads(kernel_triage(str(ROOT / "absent2.sys")))
        self.assertEqual({"ok", "tool", "status", "error", "fixable", "fix", "path"}, set(r))

    def test_undeterminable_fields_are_null_and_listed_as_unknown(self):
        r = triage("unk.sys", subsystem=0x55, imports=KERNEL_IMPORTS)
        self.assertEqual(r["pe"]["subsystem"], 0x55)
        self.assertIsNone(r["pe"]["subsystem_name"])
        self.assertIn("subsystem_name", r["unknown_fields"])
        for key in r["unknown_fields"]:
            if "." not in key:
                self.assertIsNone(r["pe"][key])
        broken = triage("unk2.sys", subsystem=1, bad_import_rva=True)
        self.assertIn("imports.dlls", broken["unknown_fields"])
        self.assertEqual(triage("unk3.sys", subsystem=1, imports=KERNEL_IMPORTS)["unknown_fields"], [])


if __name__ == "__main__":
    unittest.main()
