"""`liebert_re.tools.capa`: argument handling, the rollups, and the failure
vocabulary.

Fast tier: the fixture below is a trimmed but structurally verbatim capture
of `capa -j -q` from capa 9.4.0 on this machine, so the parsing contract is
pinned without running capa (which takes minutes -- 3m48s measured on a
1.2 MB PE, which is exactly why no test here invokes it).

The cases that matter most are the ones that keep a weak result from reading
as a strong one: a failed backend must not silently become a result from
another engine, a timeout must not read as "no capabilities", and an empty
match set must stay an honest negative.
"""
from __future__ import annotations

import pytest
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import liebert_re.tools.capa as tc
from liebert_re.bounded_subprocess import BoundedProcessResult

# --- verbatim-shaped capa 9.4.0 capture (rules trimmed to five) -----------
REAL_CAPA_JSON = json.dumps({
    "meta": {
        "timestamp": "2026-10-02T00:00:00",
        "version": "9.4.0",
        "argv": ["-j", "-q", "sample.exe"],
        "sample": {
            "md5": "3af7965ae0f9a0700c17d964ae67d720",
            "sha1": "3d0ff70ac2947369737743d968063e7816991109",
            "sha256": "9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b",
            "path": "sample.exe",
        },
        "flavor": "static",
        "analysis": {
            "format": "pe", "arch": "amd64", "os": "windows",
            "extractor": "VivisectFeatureExtractor",
            "rules": ["(embedded rules)"],
            "base_address": {"type": "absolute", "value": 5368709120},
            "layout": {"functions": []},
            "feature_counts": {"file": 412, "functions": []},
            "library_functions": [{"address": 1}, {"address": 2}],
        },
    },
    "rules": {
        "create or open file": {
            "meta": {
                "name": "create or open file", "authors": ["x"], "scopes": {},
                "attack": [], "references": [], "examples": [], "lib": False,
                "is_subscope_rule": False, "maec": {}, "description": None,
                "mbc": [{"parts": ["File System", "Create File"], "objective": "File System",
                         "behavior": "Create File", "method": "", "id": "C0016"}],
            },
            "source": "", "matches": [[1, {}], [2, {}]],
        },
        "link function at runtime on Windows": {
            "meta": {
                "name": "link function at runtime on Windows", "authors": ["x"],
                "scopes": {}, "namespace": "linking/runtime-linking",
                "attack": [{"parts": ["Execution", "Shared Modules"], "tactic": "Execution",
                            "technique": "Shared Modules", "subtechnique": "", "id": "T1129"}],
                "mbc": [], "references": [], "examples": [], "lib": False,
                "is_subscope_rule": False, "maec": {}, "description": None,
            },
            "source": "", "matches": [[3, {}]],
        },
        "check for software breakpoints": {
            "meta": {
                "name": "check for software breakpoints", "authors": ["x"], "scopes": {},
                "namespace": "anti-analysis/anti-debugging/debugger-detection",
                "attack": [{"parts": ["Defense Evasion", "Debugger Evasion"],
                            "tactic": "Defense Evasion", "technique": "Debugger Evasion",
                            "subtechnique": "", "id": "T1622"}],
                "mbc": [{"parts": ["Anti-Behavioral Analysis", "Debugger Detection"],
                         "objective": "Anti-Behavioral Analysis", "behavior": "Debugger Detection",
                         "method": "", "id": "B0001"}],
                "references": [], "examples": [], "lib": False,
                "is_subscope_rule": False, "maec": {}, "description": "looks for 0xCC",
            },
            "source": "", "matches": [[4, {}]],
        },
        "reference anti-VM strings": {
            "meta": {
                "name": "reference anti-VM strings", "authors": ["x"], "scopes": {},
                "namespace": "anti-analysis/anti-vm/vm-detection",
                "attack": [], "mbc": [], "references": [], "examples": [],
                "lib": False, "is_subscope_rule": False, "maec": {}, "description": None,
            },
            "source": "", "matches": [[5, {}]],
        },
        "contain a resource (.rsrc) section": {
            "meta": {
                "name": "contain a resource (.rsrc) section", "authors": ["x"], "scopes": {},
                "namespace": "executable/pe/section/rsrc",
                "attack": [], "mbc": [], "references": [], "examples": [],
                "lib": True, "is_subscope_rule": False, "maec": {}, "description": None,
            },
            "source": "", "matches": [[6, {}]],
        },
    },
})

EMPTY_CAPA_JSON = json.dumps({
    "meta": {"version": "9.4.0", "flavor": "static", "sample": {}, "analysis": {}},
    "rules": {},
})


def _ok(stdout):
    return BoundedProcessResult(0, stdout, "")


class _WithSample(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.sample = Path(self._tmp.name) / "sample.exe"
        self.sample.write_bytes(b"MZ" + b"\0" * 64)
        self.addCleanup(self._tmp.cleanup)
        self.last_command = None

    def run_analyze(self, result, **kwargs):
        with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
             mock.patch.object(tc, "safe_path", return_value=self.sample), \
             mock.patch.object(tc, "relative", return_value="sample.exe"), \
             mock.patch("liebert_re.tools.capa.run_bounded_process", return_value=result) as run:
            out = tc.capa_analyze(str(self.sample), **kwargs)
        if run.call_args:
            self.last_command = run.call_args[0][0]
        return json.loads(out)


class RolloutTests(_WithSample):
    def test_capabilities_are_grouped_three_ways(self):
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["capability_count"], 5)
        self.assertEqual(
            data["namespace_roots"],
            ["(none)", "anti-analysis", "executable", "linking"],
        )
        self.assertEqual([a["id"] for a in data["attack_techniques"]], ["T1129", "T1622"])
        self.assertEqual([b["id"] for b in data["mbc_behaviors"]], ["B0001", "C0016"])

    def test_anti_analysis_is_surfaced_as_its_own_answer(self):
        """The reason this tool runs first on a hardened target."""
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        self.assertTrue(data["anti_analysis_present"])
        self.assertEqual(data["anti_analysis_capabilities"],
                         ["check for software breakpoints", "reference anti-VM strings"])

    def test_namespace_index_lists_rule_names_not_counts(self):
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        self.assertEqual(data["by_namespace"]["linking/runtime-linking"],
                         ["link function at runtime on Windows"])
        self.assertEqual(data["by_namespace"]["(none)"], ["create or open file"])

    def test_attack_and_mbc_entries_name_the_rules_that_produced_them(self):
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        t1622 = next(a for a in data["attack_techniques"] if a["id"] == "T1622")
        self.assertEqual(t1622["tactic"], "Defense Evasion")
        self.assertEqual(t1622["rules"], ["check for software breakpoints"])

    def test_library_rule_and_match_count_are_preserved(self):
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        by_name = {c["name"]: c for c in data["capabilities"]}
        self.assertTrue(by_name["contain a resource (.rsrc) section"]["is_library_rule"])
        self.assertEqual(by_name["create or open file"]["match_count"], 2)

    def test_analysis_metadata_is_carried_including_library_function_count(self):
        data = self.run_analyze(_ok(REAL_CAPA_JSON))
        self.assertEqual(data["analysis"]["extractor"], "VivisectFeatureExtractor")
        self.assertEqual(data["analysis"]["arch"], "amd64")
        self.assertEqual(data["analysis"]["library_function_count"], 2)
        self.assertEqual(data["sample_sha256"],
                         "9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b")

    def test_no_matches_is_an_honest_negative_not_an_error(self):
        data = self.run_analyze(_ok(EMPTY_CAPA_JSON))
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["capability_count"], 0)
        self.assertFalse(data["anti_analysis_present"])
        self.assertIn("packed", data["note"])


class InvocationTests(_WithSample):
    def test_default_call_passes_only_json_and_quiet(self):
        data = self.run_analyze(_ok(EMPTY_CAPA_JSON))
        self.assertEqual(data["invocation"], {})
        self.assertIn("-j", self.last_command)
        self.assertIn("-q", self.last_command)
        for flag in ("-b", "-f", "-r", "-s", "-t", "--os", "--restrict-to-functions"):
            self.assertNotIn(flag, self.last_command)

    def test_every_argument_reaches_the_command_line_and_is_echoed(self):
        data = self.run_analyze(
            _ok(EMPTY_CAPA_JSON), backend="vivisect", file_format="pe", os_name="windows",
            rules="D:/rules", signatures="D:/sigs", tag="namespace=anti-analysis",
            restrict_to_functions="0x401000,0x402000",
        )
        self.assertEqual(data["invocation"], {
            "backend": "vivisect", "format": "pe", "os": "windows",
            "rules": "D:/rules", "signatures": "D:/sigs",
            "tag": "namespace=anti-analysis",
            "restrict_to_functions": "0x401000,0x402000",
        })
        cmd = self.last_command
        self.assertEqual(cmd[cmd.index("-b") + 1], "vivisect")
        self.assertEqual(cmd[cmd.index("--restrict-to-functions") + 1], "0x401000,0x402000")

    def test_unknown_backend_is_refused_before_any_subprocess_runs(self):
        with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
             mock.patch.object(tc, "safe_path", return_value=self.sample), \
             mock.patch("liebert_re.tools.capa.run_bounded_process") as run:
            data = json.loads(tc.capa_analyze(str(self.sample), backend="notabackend"))
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "UNKNOWN_BACKEND")
        self.assertIn("vivisect", data["accepted"])
        run.assert_not_called()

    def test_unknown_format_and_os_are_refused_the_same_way(self):
        for kwargs, err in (({"file_format": "nope"}, "UNKNOWN_FORMAT"),
                            ({"os_name": "plan9"}, "UNKNOWN_OS")):
            with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
                 mock.patch.object(tc, "safe_path", return_value=self.sample), \
                 mock.patch("liebert_re.tools.capa.run_bounded_process"):
                data = json.loads(tc.capa_analyze(str(self.sample), **kwargs))
            self.assertEqual(data["error"], err, kwargs)


class FailureVocabularyTests(_WithSample):
    @pytest.mark.contract
    def test_nonzero_exit_is_reported_not_retried_with_another_backend(self):
        """The pefile-backend crash on capa 9.4.0 is the real case here: a
        result from a different engine would be a different claim."""
        result = BoundedProcessResult(1, "", "Unexpected exception raised: <class 'NotImplementedError'>.")
        data = self.run_analyze(result, backend="pefile")
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "CAPA_EXITED_NONZERO")
        self.assertEqual(data["invocation"]["backend"], "pefile")
        self.assertIn("NotImplementedError", data["stderr_tail"])
        self.assertIn("different claim", data["detail"])

    @pytest.mark.contract
    def test_timeout_says_not_to_read_it_as_no_capabilities(self):
        result = BoundedProcessResult(None, "", "", timed_out=True)
        data = self.run_analyze(result, timeout_seconds=60)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(data["timeout_seconds"], 60)
        self.assertIn("do not read a timeout as", data["detail"])

    @pytest.mark.contract
    def test_cancellation_is_its_own_status(self):
        result = BoundedProcessResult(None, "", "", cancelled=True)
        data = self.run_analyze(result)
        self.assertEqual(data["status"], "CANCELLED")

    @pytest.mark.contract
    def test_non_json_stdout_is_analysis_limited(self):
        data = self.run_analyze(_ok("capa: error: something went wrong"))
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "CAPA_NO_JSON_OUTPUT")

    @pytest.mark.contract
    def test_json_without_a_rules_object_is_a_parse_failure_not_an_empty_result(self):
        data = self.run_analyze(_ok(json.dumps({"meta": {}})))
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")
        self.assertEqual(data["error"], "CAPA_OUTPUT_MISSING_RULES_OBJECT")

    @pytest.mark.contract
    def test_unparseable_json_is_reported_as_version_drift(self):
        data = self.run_analyze(_ok("{not json at all}"))
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")

    def test_timeout_is_clamped_into_the_supported_range(self):
        self.run_analyze(_ok(EMPTY_CAPA_JSON), timeout_seconds=1)
        # the clamp is applied before the call; assert via the reported value
        result = BoundedProcessResult(None, "", "", timed_out=True)
        data = self.run_analyze(result, timeout_seconds=1)
        self.assertEqual(data["timeout_seconds"], tc._MIN_TIMEOUT_SECONDS)


class AvailabilityTests(unittest.TestCase):
    @pytest.mark.contract
    def test_missing_binary_returns_tool_missing_for_both_operations(self):
        with mock.patch.object(tc, "_capa_binary", return_value=None):
            for name, call in (("capa_analyze", lambda: tc.capa_analyze("x")),
                               ("capa_status", lambda: tc.capa_status())):
                data = json.loads(call())
                self.assertFalse(data["ok"], name)
                self.assertEqual(data["status"], "TOOL_MISSING", name)
                self.assertEqual(data["tool"], name, name)
                self.assertIn("CAPA_EXE", data["detail"], name)
            self.assertFalse(tc.capa_available())

    def test_status_reports_version_and_the_known_broken_backend(self):
        with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
             mock.patch("liebert_re.tools.capa.run_bounded_process", return_value=_ok("capa.exe 9.4.0\n")):
            data = json.loads(tc.capa_status())
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["version"], "capa.exe 9.4.0")
        self.assertIn("pefile", data["known_broken_backends"])
        self.assertIn("ida", data["backends_capa_accepts"])
        self.assertIn("needs a licensed IDA", data["note"])

    def test_nonexistent_path_returns_not_found_before_any_subprocess_call(self):
        with mock.patch.object(tc, "_capa_binary", return_value="C:/fake/capa.exe"), \
             mock.patch("liebert_re.tools.capa.run_bounded_process") as run:
            data = json.loads(tc.capa_analyze("does_not_exist_at_all.exe"))
        self.assertEqual(data["status"], "NOT_FOUND")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
