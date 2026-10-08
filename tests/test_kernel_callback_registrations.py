"""kernel_callback_registrations (liebert_re/tools/binary.py): a thin filter over rip_relative_iat_scan.

Names an import-table call to a callback-registration API. The API names were verified to be real exports
of the OS kernel image (ntoskrnl.exe) or of fltmgr.sys by reading their export tables; the family labels
are conceptual and NOT verified. A scan hit is never proof the call runs, the callback address is never
recovered, and "not found" never means "the driver does not register". A truncated scan is never NOT_FOUND.
Fixtures are built in code; no real driver is read.
"""
from __future__ import annotations

import json
import re
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import liebert_re.tools.binary as binary
import liebert_re.workspace as tools_workspace
from liebert_re.recover.owned_binary_fixtures import build_owned_pe_sections
from liebert_re.tools.binary import kernel_callback_registrations

REPO_ROOT = Path(tools_workspace.WORKSPACE_ROOT)
TEXT_RAW = 0x400
TEXT_RVA = 0x1000
_TMP = None
ROOT = Path()


def setUpModule():
    global _TMP, ROOT
    _TMP = tempfile.TemporaryDirectory(dir=REPO_ROOT)
    ROOT = Path(_TMP.name)


def tearDownModule():
    _TMP.cleanup()


def slots(path):
    import pefile
    pe = pefile.PE(str(path))
    base = pe.OPTIONAL_HEADER.ImageBase
    out = [int(m.address) - base for d in pe.DIRECTORY_ENTRY_IMPORT for m in d.imports]
    pe.close()
    return out


def call(at, target_rva, opcode=0x15):
    return at, bytes([0xFF, opcode]) + struct.pack("<i", target_rva - (TEXT_RVA + at + 6))


def make(name, patches=(), imports=None, **kw):
    path = build_owned_pe_sections(ROOT / name, subsystem=1, imports=imports, **kw)
    data = bytearray(path.read_bytes())
    for at, code in patches:
        data[TEXT_RAW + at:TEXT_RAW + at + len(code)] = code
    path.write_bytes(bytes(data))
    return path


def build(name, imports, calls):
    """Build ``imports`` and call, by index into the flattened import list, each slot in ``calls`` ([(at, index)])."""
    probe = slots(make("probe_" + name, imports=imports))
    return make(name, [call(at, probe[i]) for at, i in calls], imports=imports)


def run(path, **kw):
    return json.loads(kernel_callback_registrations(str(path), **kw))


class KernelCallbackRegistrationsTests(unittest.TestCase):
    def test_registration_call_is_found_with_its_family(self):
        p = build("proc.sys", {"ntoskrnl.exe": ["IoCreateDevice", "PsSetCreateProcessNotifyRoutineEx"]}, [(0x10, 1)])
        body = run(p)
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "FOUND")
        (r,) = body["registrations"]
        self.assertEqual(r["api"], "PsSetCreateProcessNotifyRoutineEx")
        self.assertEqual(r["dll"], "ntoskrnl")
        self.assertEqual(r["family"], "process")
        self.assertEqual(r["call_rva"], hex(TEXT_RVA + 0x10))
        self.assertEqual(r["encoding"], "FF15")
        self.assertEqual(r["kind"], "call")
        self.assertIs(r["proves_call"], False)
        self.assertEqual(r["confidence"], "heuristic")
        self.assertTrue(r["slot_rva"].startswith("0x"))

    def test_fltmgr_name_matches_its_own_module_and_dll_case_is_normalised(self):
        p = build("flt.sys", {"FLTMGR.SYS": ["FltRegisterFilter"]}, [(0x10, 0)])
        (r,) = run(p)["registrations"]
        self.assertEqual(r["api"], "FltRegisterFilter")
        self.assertEqual(r["dll"], "fltmgr")
        self.assertEqual(r["family"], "filesystem")

    def test_second_batch_of_names_is_found_with_its_family(self):
        # Name existence was re-verified from the ntoskrnl.exe export table; the family labels are inference.
        expected = {
            "KeRegisterBugCheckCallback": "bugcheck", "KeRegisterBugCheckReasonCallback": "bugcheck",
            "KeRegisterNmiCallback": "nmi", "IoRegisterPlugPlayNotification": "pnp",
            "ExRegisterCallback": "executive", "PoRegisterCoalescingCallback": "power",
            "FsRtlRegisterFileSystemFilterCallbacks": "filesystem",
            "IoRegisterBootDriverCallback": "boot", "SeRegisterImageVerificationCallback": "image_verification",
        }
        names = list(expected)
        p = build("batch2.sys", {"ntoskrnl.exe": names}, [(0x10 + 8 * i, i) for i in range(len(names))])
        body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual({r["api"]: r["family"] for r in body["registrations"]}, expected)
        for r in body["registrations"]:
            self.assertEqual(r["dll"], "ntoskrnl")
            self.assertIs(r["proves_call"], False)

    def test_second_batch_lookalikes_and_wrong_module_are_not_findings(self):
        names = ["KeRegisterNmiCallbackX", "xExRegisterCallback", "IoRegisterPlugPlayNotificationEx",
                 "keRegisterBugCheckCallback"]
        p = build("batch2trap.sys", {"ntoskrnl.exe": names}, [(0x10 + 8 * i, i) for i in range(len(names))])
        self.assertEqual(run(p)["registrations"], [])
        q = build("batch2wrong.sys", {"fltmgr.sys": ["KeRegisterNmiCallback"]}, [(0x10, 0)])
        self.assertEqual(run(q)["registrations"], [])

    def test_names_checked_is_reported_filled_in_every_outcome(self):
        found = run(build("scope_f.sys", {"ntoskrnl.exe": ["ObRegisterCallbacks"]}, [(0x10, 0)]))
        nf = run(build("scope_n.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, [(0x10, 0)]))
        self.assertEqual(found["outcome"], "FOUND")
        self.assertEqual(nf["outcome"], "NOT_FOUND")
        for body in (found, nf):
            nc = body["names_checked"]
            self.assertGreaterEqual(nc["count"], 25)
            self.assertEqual(nc["count"], len(nc["names"]))
            self.assertIs(nc["truncated"], False)
            self.assertIn("ntoskrnl!ObRegisterCallbacks", nc["names"])
            self.assertIn("fltmgr!FltRegisterFilter", nc["names"])
            self.assertIn("ntoskrnl!SeRegisterImageVerificationCallback", nc["names"])

    def test_not_found_rationale_cites_the_checked_scope_and_its_size(self):
        nf = run(build("scope_r.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, [(0x10, 0)]))
        text = " ".join(nf["rationale"])
        self.assertIn("names_checked", text)
        self.assertIn(str(nf["names_checked"]["count"]), text)
        self.assertIn("nothing about names outside that list", text)

    def test_name_from_the_wrong_module_is_not_a_finding(self):
        p = build("wrongdll.sys", {"ntoskrnl.exe": ["FltRegisterFilter"]}, [(0x10, 0)])
        body = run(p)
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["registrations"], [])

    def test_unrelated_import_is_not_found_and_does_not_say_the_driver_never_registers(self):
        p = build("plain.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, [(0x10, 0)])
        body = run(p)
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["registrations"], [])
        text = " ".join(body["rationale"])
        self.assertIn("no direct call through the import table", text)
        self.assertIn("not visible to this scan", text)
        self.assertNotRegex(text.lower(), r"does not register|doesn't register|no registration|not register")

    def test_imported_without_a_call_site_is_listed_apart_and_is_not_a_finding(self):
        p = build("noref.sys", {"ntoskrnl.exe": ["ObRegisterCallbacks", "IoCreateDevice"]}, [(0x10, 1)])
        body = run(p)
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["registrations"], [])
        (i,) = body["imported_without_reference"]
        self.assertEqual(i["api"], "ObRegisterCallbacks")
        self.assertEqual(i["family"], "object")

    def test_referenced_api_is_not_also_listed_as_imported_without_reference(self):
        p = build("both.sys", {"ntoskrnl.exe": ["CmRegisterCallbackEx", "ObRegisterCallbacks"]}, [(0x10, 0)])
        body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertEqual([i["api"] for i in body["imported_without_reference"]], ["ObRegisterCallbacks"])

    def test_substring_lookalikes_are_not_findings(self):
        names = ["PsSetCreateProcessNotifyRoutineExtra", "XCmRegisterCallback", "CmRegisterCallbackEx2",
                 "psSetCreateProcessNotifyRoutine"]
        p = build("trap.sys", {"ntoskrnl.exe": names}, [(0x10 + 8 * i, i) for i in range(len(names))])
        body = run(p)
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["registrations"], [])
        self.assertEqual(body["imported_without_reference"], [])

    def test_no_import_directory_inherits_the_scan_behaviour(self):
        body = run(make("noimp.sys", [(0x10, b"\xFF\x15\x00\x10\x00\x00")]))
        self.assertTrue(body["ok"])
        self.assertEqual(body["outcome"], "NOT_FOUND")
        self.assertEqual(body["reason"], "NO_IMPORT_DIRECTORY")

    def test_unreadable_reinventory_is_null_with_a_reason_not_an_empty_list(self):
        p = build("reinv.sys", {"ntoskrnl.exe": ["IoCreateDevice", "PsSetCreateProcessNotifyRoutineEx"]}, [(0x10, 1)])
        real = binary._pe
        state = {"calls": 0}

        def flaky(path):
            state["calls"] += 1
            if state["calls"] > 1:
                raise RuntimeError("second read failed")
            return real(path)

        with mock.patch.object(binary, "_pe", flaky):
            body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertIsNone(body["imported_without_reference"])
        self.assertEqual(body["imported_without_reference_error"], "RuntimeError")
        self.assertTrue(any("could not be re-read" in line for line in body["rationale"]))

    def test_readable_reinventory_has_a_list_and_no_error_field(self):
        p = build("reinv_ok.sys", {"ntoskrnl.exe": ["PsSetCreateProcessNotifyRoutineEx"]}, [(0x10, 0)])
        body = run(p)
        self.assertEqual(body["imported_without_reference"], [])
        self.assertNotIn("imported_without_reference_error", body)

    def test_unreadable_import_directory_is_not_looked_and_not_not_found(self):
        body = run(make("badimp.sys", bad_import_rva=True))
        self.assertFalse(body["ok"])
        self.assertEqual(body["outcome"], "NOT_LOOKED")
        self.assertEqual(body["error"], "IMPORT_DIRECTORY_UNREADABLE")
        miss = run(build("miss.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, []))
        self.assertEqual(miss["outcome"], "NOT_FOUND")
        self.assertNotEqual(miss["outcome"], body["outcome"])

    def test_invalid_pe_is_refused(self):
        p = ROOT / "junk.sys"
        p.write_bytes(b"not a pe at all")
        body = run(p)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "INVALID_PE")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_missing_file_is_refused(self):
        body = run(ROOT / "nonexistent.sys")
        self.assertEqual(body["error"], "FILE_NOT_FOUND")
        self.assertEqual(body["outcome"], "NOT_LOOKED")

    def test_truncated_scan_is_never_not_found(self):
        imports = {"ntoskrnl.exe": ["IoCreateDevice"]}
        p = build("trunc.sys", imports, [(6 * i, 0) for i in range(8)])
        # The scan now filters before it counts, so the limit that can stop it with no match is the examine limit.
        with mock.patch.object(binary, "_RIA_EXAMINE_LIMIT", 3):
            body = run(p)
        self.assertTrue(body["scan_truncation"]["truncated"])
        self.assertNotEqual(body["outcome"], "NOT_FOUND")
        self.assertIn(body["outcome"], ("UNKNOWN", "PARTIAL"))
        self.assertEqual(body["registrations"], [])

    def test_truncated_scan_that_still_saw_a_registration_is_found_and_says_truncated(self):
        imports = {"ntoskrnl.exe": ["PsSetLoadImageNotifyRoutine"]}
        p = build("trunc2.sys", imports, [(6 * i, 0) for i in range(8)])
        with mock.patch.object(binary, "_RIA_HARD_LIMIT", 3):
            body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertIs(body["scan_truncation"]["truncated"], True)

    def test_partial_import_directory_is_unknown_not_not_found(self):
        p = build("part.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, [(0x10, 0)])
        real = json.loads(binary.rip_relative_iat_scan(str(p)))
        real["entry"]["imports_state"] = "PARTIAL"
        with mock.patch.object(binary, "rip_relative_iat_scan", return_value=json.dumps(real)):
            body = run(p)
        self.assertEqual(body["outcome"], "UNKNOWN")
        self.assertEqual(body["reason"], "IMPORTS_PARTIAL")

    def test_callback_address_is_never_returned(self):
        p = build("addr.sys", {"ntoskrnl.exe": ["PsSetCreateThreadNotifyRoutine"]}, [(0x10, 0)])
        body = run(p)
        self.assertEqual(body["callback_address"], "NOT_RECOVERED")
        for r in body["registrations"]:
            self.assertFalse([k for k in r if re.search("callback|argument|handler", k)])

    def test_caveats_carry_the_scan_caveats_plus_two_more(self):
        p = build("cav.sys", {"ntoskrnl.exe": ["IoCreateDevice"]}, [])
        body = run(p)
        scan = json.loads(binary.rip_relative_iat_scan(str(p)))
        for c in scan["caveats"]:
            self.assertIn(c, body["caveats"])
        text = " ".join(body["caveats"]).lower()
        self.assertIn("callback address was not recovered", text)
        self.assertIn("name list is not exhaustive", text)
        self.assertEqual(len(body["caveats"]), len(scan["caveats"]) + 2)

class FilteredScanTests(unittest.TestCase):
    """A big driver has thousands of import references and a handful of registration calls: the scan must look at
    all of them but only keep the registration ones, so the output limit is not spent on unrelated references."""

    IMPORTS = {"ntoskrnl.exe": ["IoCreateDevice", "PsSetLoadImageNotifyRoutine"]}

    def _many_then_one(self, name):
        calls = [(6 * i, 0) for i in range(8)] + [(6 * 8, 1)]
        return build(name, self.IMPORTS, calls)

    def test_registration_after_many_unrelated_references_is_found_not_unknown(self):
        p = self._many_then_one("many_then_one.sys")
        with mock.patch.object(binary, "_RIA_HARD_LIMIT", 3):
            body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertNotIn("reason", body)
        self.assertEqual([r["api"] for r in body["registrations"]], ["PsSetLoadImageNotifyRoutine"])
        self.assertIs(body["scan_truncation"]["truncated"], False)

    def test_filtered_scan_keeps_only_matching_references_and_counts_the_rest(self):
        p = self._many_then_one("filter_unit.sys")
        body = json.loads(binary.rip_relative_iat_scan(str(p), 3, import_filter=lambda imp: imp.endswith("!PsSetLoadImageNotifyRoutine")))
        self.assertEqual(len(body["findings"]), 1)
        self.assertIs(body["truncation"]["truncated"], False)
        self.assertEqual(body["truncation"]["examined_total"], 9)
        self.assertEqual(body["truncation"]["not_matching_filter"], 8)

    def test_unfiltered_scan_output_is_unchanged(self):
        p = self._many_then_one("unfiltered.sys")
        body = json.loads(binary.rip_relative_iat_scan(str(p), 3))
        self.assertEqual(sorted(body["truncation"]),
                         ["found_total", "limit", "limit_name", "omitted", "returned", "truncated"])
        self.assertIs(body["truncation"]["truncated"], True)
        self.assertEqual(body["truncation"]["found_total"], 9)

    def test_matches_over_the_output_limit_are_still_reported_truncated(self):
        p = build("many_matches.sys", {"ntoskrnl.exe": ["PsSetLoadImageNotifyRoutine"]}, [(6 * i, 0) for i in range(8)])
        with mock.patch.object(binary, "_RIA_HARD_LIMIT", 3):
            body = run(p)
        self.assertEqual(body["outcome"], "FOUND")
        self.assertIs(body["scan_truncation"]["truncated"], True)
        self.assertEqual(len(body["registrations"]), 3)

    def test_scan_stopped_before_examining_everything_is_reported_truncated_and_never_not_found(self):
        p = self._many_then_one("examine_cap.sys")
        with mock.patch.object(binary, "_RIA_EXAMINE_LIMIT", 4):
            body = run(p)
        self.assertIs(body["scan_truncation"]["truncated"], True)
        self.assertEqual(body["scan_truncation"]["examine_omitted"], 5)
        self.assertEqual(body["outcome"], "UNKNOWN")
        self.assertEqual(body["reason"], "SCAN_TRUNCATED")
        self.assertEqual(body["registrations"], [])


if __name__ == "__main__":
    unittest.main()
