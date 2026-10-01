"""`liebert_re.tools.die`'s non-identify operations, and the scan-depth flags.

Fast tier on purpose: every fixture below is a verbatim capture of what DIE
3.21 actually printed on this machine, so the parsing contract is pinned
without needing diec.exe installed. `tests/test_tools_die.py` covers
`die_identify`'s own result shape and the failure vocabulary; this file
covers the operations added around it and the one thing most likely to
break silently -- the mapping from keyword argument to command-line flag.

Four distinct output shapes are exercised, because DIE really does emit
four: `{"detects": ...}`, `{"records": ...}`, `{"data": ...}`, and plain
text for `-w`/`-s` even when `-j` is passed.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import liebert_re.tools.die as td
from liebert_re.bounded_subprocess import BoundedProcessResult

# --- verbatim DIE 3.21 captures -------------------------------------------

# `diec -j -e <pe>`: per-section entropy, each with DIE's own verdict.
REAL_ENTROPY_JSON = json.dumps({
    "records": [
        {"entropy": 3.0695218851614285, "name": "Header", "offset": 0, "size": 1024, "status": "not packed"},
        {"entropy": 6.370292181370811, "name": "Section (1) [\".text\"]", "offset": 1024, "size": 19648000, "status": "not packed"},
        {"entropy": 6.812656911569499, "name": "Section (4) [\".pdata\"]", "offset": 24460800, "size": 672256, "status": "packed"},
        {"entropy": 0, "name": "Section (5) [\".fptable\"]", "offset": 25133056, "size": 512, "status": "not packed"},
    ]
})

# `diec -j -i <pe>`
REAL_INFO_JSON = json.dumps({
    "data": {
        "Info": {
            "Architecture": "AMD64", "Endianness": "LE", "Extension": "exe",
            "File type": "PE64", "MIME": "application/x-msdos-program",
            "Mode": "64-bit", "Operation system": "Windows(Vista)",
            "Size": "1265152", "String": "PE64", "Type": "Console",
        }
    }
})

# `diec -j -S "Check format" <pe>`: a string-keyed map, not a list.
REAL_FORMAT_CHECK_JSON = json.dumps({
    "data": {"0": "[Warning](0002) OptionalHeader.CheckSum: Corrupted data: 00000000"}
})
REAL_FORMAT_CHECK_CLEAN_JSON = json.dumps({"data": {}})

# `diec -j -S Hash <pe>`
REAL_HASH_JSON = json.dumps({
    "data": {
        "Hash": {
            "MD4": "83bc2d6d3d4f8e495a2b08005938e338",
            "MD5": "3af7965ae0f9a0700c17d964ae67d720",
            "SHA1": "3d0ff70ac2947369737743d968063e7816991109",
            "SHA256": "9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b",
        }
    }
})

# `diec -w <pe>` -- plain text, even with -j.
REAL_SHOWSTRUCTS_TEXT = "Structures:\n\tInfo\n\tHash\n\tEntropy\n\tCheck format\n"

# `diec -s <pe>` -- plain text, indented per-format signature counts.
REAL_SHOWDATABASE_TEXT = (
    "Main database: $data/db\n"
    "Extra database: $data/db_extra\n"
    "Custom database: $data/db_custom\n"
    "\tBinary: 287\n"
    "\tCOM: 245\n"
    "\tPE: 771\n"
)


def _ok(stdout):
    return BoundedProcessResult(0, stdout, "")


class _WithSample(unittest.TestCase):
    """Every operation calls safe_path() then .is_file(); give them a real
    file inside a temporary directory so neither gate is what fails."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.sample = Path(self._tmp.name) / "sample.exe"
        self.sample.write_bytes(b"MZ" + b"\0" * 64)
        self.addCleanup(self._tmp.cleanup)

    def run_op(self, fn, stdout, *args, **kwargs):
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch.object(td, "safe_path", return_value=self.sample), \
             mock.patch.object(td, "relative", return_value="sample.exe"), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=_ok(stdout)) as run:
            out = fn(str(self.sample), *args, **kwargs)
        self.last_command = run.call_args[0][0] if run.call_args else None
        return json.loads(out)


class FlagMappingTests(unittest.TestCase):
    """The keyword-to-flag map is the part a DIE upgrade or a careless edit
    can break without any test noticing, so it is asserted directly."""

    def test_no_options_produces_no_flags(self):
        self.assertEqual(td._build_args({}), [])
        self.assertEqual(td._scan_flags({}), {})

    def test_each_depth_keyword_maps_to_its_documented_switch(self):
        expected = {
            "deep": "-d", "heuristic": "-u", "aggressive": "-g",
            "all_types": "-a", "verbose": "-b", "hide_unknown": "-U",
            "profiling": "-l",
        }
        for keyword, flag in expected.items():
            self.assertEqual(td._build_args({keyword: True}), [flag], keyword)

    def test_false_is_the_same_as_absent(self):
        self.assertEqual(td._build_args({"deep": False, "heuristic": False}), [])
        self.assertEqual(td._scan_flags({"deep": False}), {})

    def test_database_overrides_pass_their_path_as_an_argument(self):
        args = td._build_args({"database": "D:/db", "extra_database": "D:/dbx", "custom_database": "D:/dbc"})
        self.assertEqual(args, ["-D", "D:/db", "-E", "D:/dbx", "-C", "D:/dbc"])

    def test_scan_flags_reports_paths_not_booleans_for_databases(self):
        flags = td._scan_flags({"deep": True, "custom_database": "D:/dbc"})
        self.assertEqual(flags, {"deep": True, "custom_database": "D:/dbc"})


class IdentifyDepthTests(_WithSample):
    def test_baseline_call_passes_only_minus_j_and_says_so(self):
        data = self.run_op(td.die_identify, json.dumps({"detects": []}))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["scan_depth"], "baseline")
        self.assertEqual(data["scan_flags"], {})
        self.assertIn("-j", self.last_command)
        for flag in ("-d", "-u", "-g", "-a"):
            self.assertNotIn(flag, self.last_command)

    def test_depth_flags_reach_the_command_line_and_are_echoed_back(self):
        data = self.run_op(
            td.die_identify, json.dumps({"detects": []}),
            deep=True, heuristic=True, aggressive=True,
        )
        self.assertEqual(data["scan_depth"], "extended")
        self.assertEqual(data["scan_flags"], {"deep": True, "heuristic": True, "aggressive": True})
        for flag in ("-d", "-u", "-g"):
            self.assertIn(flag, self.last_command)

    def test_custom_database_reaches_the_command_line(self):
        data = self.run_op(td.die_identify, json.dumps({"detects": []}), custom_database="D:/sigs")
        self.assertEqual(data["scan_flags"]["custom_database"], "D:/sigs")
        self.assertEqual(self.last_command[self.last_command.index("-C") + 1], "D:/sigs")


class EntropyTests(_WithSample):
    def test_records_shape_becomes_regions_with_dies_own_verdict(self):
        data = self.run_op(td.die_entropy, REAL_ENTROPY_JSON)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["region_count"], 4)
        self.assertEqual(data["regions_die_calls_packed"], ['Section (4) [".pdata"]'])
        self.assertTrue(data["any_region_packed"])
        self.assertEqual(data["regions"][0]["die_status"], "not packed")
        self.assertIn("-e", self.last_command)

    def test_highest_entropy_region_is_the_real_maximum(self):
        data = self.run_op(td.die_entropy, REAL_ENTROPY_JSON)
        self.assertEqual(data["highest_entropy_region"]["name"], 'Section (4) [".pdata"]')

    def test_no_records_is_an_empty_result_not_a_failure(self):
        data = self.run_op(td.die_entropy, json.dumps({"records": []}))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["region_count"], 0)
        self.assertFalse(data["any_region_packed"])
        self.assertIsNone(data["highest_entropy_region"])

    def test_a_non_numeric_entropy_never_crashes_the_maximum(self):
        data = self.run_op(td.die_entropy, json.dumps({"records": [{"name": "x", "entropy": None, "status": "?"}]}))
        self.assertTrue(data["ok"], data)
        self.assertIsNone(data["highest_entropy_region"])


class FileInfoTests(_WithSample):
    def test_info_block_is_surfaced_verbatim(self):
        data = self.run_op(td.die_file_info, REAL_INFO_JSON)
        self.assertTrue(data["ok"], data)
        self.assertTrue(data["info_present"])
        self.assertEqual(data["info"]["Architecture"], "AMD64")
        self.assertEqual(data["info"]["File type"], "PE64")
        self.assertIn("-i", self.last_command)

    def test_missing_info_block_is_reported_as_absent_not_invented(self):
        data = self.run_op(td.die_file_info, json.dumps({"data": {}}))
        self.assertTrue(data["ok"], data)
        self.assertFalse(data["info_present"])
        self.assertEqual(data["info"], {})


class FormatCheckTests(_WithSample):
    def test_string_keyed_warning_map_becomes_an_ordered_list(self):
        data = self.run_op(td.die_format_check, REAL_FORMAT_CHECK_JSON)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["anomaly_count"], 1)
        self.assertIn("OptionalHeader.CheckSum", data["anomalies"][0])
        self.assertFalse(data["clean"])
        self.assertIn("Check format", self.last_command)

    def test_empty_data_block_is_clean_not_an_error(self):
        data = self.run_op(td.die_format_check, REAL_FORMAT_CHECK_CLEAN_JSON)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["anomaly_count"], 0)
        self.assertTrue(data["clean"])

    def test_many_warnings_keep_numeric_not_lexicographic_order(self):
        raw = json.dumps({"data": {str(i): f"w{i}" for i in range(12)}})
        data = self.run_op(td.die_format_check, raw)
        self.assertEqual(data["anomalies"], [f"w{i}" for i in range(12)])


class HashTests(_WithSample):
    def test_all_algorithms_are_returned(self):
        data = self.run_op(td.die_hashes, REAL_HASH_JSON)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["requested_struct"], "Hash")
        self.assertEqual(data["hashes"]["SHA256"], "9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b")

    def test_single_algorithm_uses_dies_hash_hash_syntax(self):
        raw = json.dumps({"data": {"Hash": {"MD5": "3af7965ae0f9a0700c17d964ae67d720"}}})
        data = self.run_op(td.die_hashes, raw, algorithm="MD5")
        self.assertEqual(data["requested_struct"], "Hash#MD5")
        self.assertIn("Hash#MD5", self.last_command)

    def test_unknown_algorithm_is_analysis_limited_not_a_silent_empty_dict(self):
        data = self.run_op(td.die_hashes, json.dumps({"data": {}}), algorithm="NOTAHASH")
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "DIE_RETURNED_NO_HASH_BLOCK")


class StructureListingTests(_WithSample):
    def test_plain_text_is_parsed_and_the_header_line_dropped(self):
        data = self.run_op(td.die_structures, REAL_SHOWSTRUCTS_TEXT)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["structures"], ["Info", "Hash", "Entropy", "Check format"])
        self.assertEqual(data["structure_count"], 4)
        self.assertIn("-w", self.last_command)

    def test_empty_output_is_an_empty_list_not_a_parse_failure(self):
        data = self.run_op(td.die_structures, "")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["structures"], [])

    def test_raw_struct_requires_a_name_before_running_anything(self):
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.run_bounded_process") as run:
            data = json.loads(td.die_struct_raw(str(self.sample), "  "))
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "STRUCT_NAME_REQUIRED")
        run.assert_not_called()

    def test_raw_struct_returns_the_data_block_unparsed(self):
        data = self.run_op(td.die_struct_raw, REAL_INFO_JSON, "Info")
        self.assertTrue(data["ok"], data)
        self.assertTrue(data["data_present"])
        self.assertEqual(data["data"]["Info"]["Mode"], "64-bit")


class DatabaseInfoTests(_WithSample):
    def test_database_paths_and_per_format_counts_are_separated(self):
        data = self.run_op(td.die_database_info, REAL_SHOWDATABASE_TEXT)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["databases"]["Main database"], "$data/db")
        self.assertEqual(data["databases"]["Custom database"], "$data/db_custom")
        self.assertEqual(data["signature_counts"]["PE"], 771)
        self.assertEqual(data["total_signatures"], 287 + 245 + 771)
        self.assertIn("-s", self.last_command)

    def test_no_counts_reports_none_rather_than_a_misleading_zero(self):
        data = self.run_op(td.die_database_info, "Main database: $data/db\n")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["signature_counts"], {})
        self.assertIsNone(data["total_signatures"])


class ToolMissingTests(unittest.TestCase):
    """Every operation, not just die_identify, must return the standard
    TOOL_MISSING shape instead of raising when diec.exe is absent."""

    def test_every_operation_returns_tool_missing(self):
        operations = [
            ("die_identify", lambda: td.die_identify("x")),
            ("die_entropy", lambda: td.die_entropy("x")),
            ("die_file_info", lambda: td.die_file_info("x")),
            ("die_format_check", lambda: td.die_format_check("x")),
            ("die_hashes", lambda: td.die_hashes("x")),
            ("die_structures", lambda: td.die_structures("x")),
            ("die_struct_raw", lambda: td.die_struct_raw("x", "Hash")),
            ("die_database_info", lambda: td.die_database_info("x")),
            ("die_status", lambda: td.die_status()),
        ]
        with mock.patch.object(td, "_die_binary", return_value=None):
            for name, call in operations:
                data = json.loads(call())
                self.assertFalse(data["ok"], name)
                self.assertEqual(data["status"], "TOOL_MISSING", name)
                self.assertEqual(data["tool"], name, name)
                self.assertIn("DIE_HOME", data["detail"], name)

    def test_die_status_lists_every_operation_this_module_exposes(self):
        """A capability probe that under-reports is worse than none: the
        operation list is what a caller checks before claiming DIE cannot
        do something."""
        with mock.patch.object(td, "_die_binary", return_value="C:/fake/diec.exe"), \
             mock.patch("liebert_re.tools.die.run_bounded_process", return_value=_ok("die 3.21\n")):
            data = json.loads(td.die_status())
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["version"], "die 3.21")
        public = {n for n in dir(td) if n.startswith("die_") and n not in ("die_available", "die_status")}
        self.assertEqual(set(data["operations"]), public)


if __name__ == "__main__":
    unittest.main()
