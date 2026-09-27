"""tools_yara_x.py's own contract: TOOL_MISSING when yr.exe is absent (never
raises), a nonexistent target path is rejected before any subprocess call,
neither rule source given is RULES_MISSING before any subprocess call, a
rule source that fails to compile is RULE_COMPILE_FAILED (not a crash), a
captured real yr.exe JSON string parses into the structured (not flattened)
finding list, content_offset pagination never silently drops content, and a
clean scan with zero matches is a real NEGATIVE result (matched: False), not
an error. Mirrors tests/test_tools_die.py's guard style for a real,
possibly-absent external toolchain: probe first, skipTest cleanly when
yr.exe genuinely isn't installed on this machine.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import tools_yara_x as ty
from evidence_index import EvidenceIndex, record_write as _evidence_index_record_write_real

REPO_ROOT = Path(__file__).resolve().parent.parent
TBM_EXE = REPO_ROOT / "benchmarks/real_corpora/trybypassme/TBM.exe"
TBMKD_SYS = REPO_ROOT / "benchmarks/real_corpora/trybypassme/TBMKD.sys"

# A real `yr scan -o json -m -g -e -s` capture (verbatim shape yr.exe 1.20.0
# emitted for a simple MZ-header rule against a real PE) used to test JSON
# parsing without requiring yr.exe to be installed.
REAL_YARA_X_JSON_MATCH = json.dumps({
    "version": "1.20.0",
    "matches": [
        {
            "rule": "test_mz_header",
            "namespace": "default",
            "file": "C:\\\\Windows\\\\System32\\\\notepad.exe",
            "meta": {"description": "detects MZ header", "author": "test"},
            "tags": [],
            "strings": [{"identifier": "$mz", "offset": 0, "match": "MZ"}],
        }
    ],
})

REAL_YARA_X_JSON_NO_MATCH = json.dumps({"version": "1.20.0", "matches": []})


class YaraXMissingTests(unittest.TestCase):
    def test_missing_binary_returns_tool_missing_not_an_exception(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value=None):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TOOL_MISSING")
        self.assertIn("required_capability", data)

    def test_yara_x_available_reports_false_when_binary_absent(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value=None):
            self.assertFalse(ty.yara_x_available())


class YaraXInputValidationTests(unittest.TestCase):
    """Every one of these must be rejected before any subprocess call."""

    def test_nonexistent_target_returns_not_found_before_any_subprocess_call(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.run_bounded_process") as mocked_run:
            out = ty.yara_x_scan(str(REPO_ROOT / "benchmarks" / "does_not_exist_at_all.bin"),
                                  rules_text="rule r{condition:true}")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "NOT_FOUND")
        mocked_run.assert_not_called()

    def test_neither_rule_source_given_is_rules_missing_before_any_subprocess_call(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process") as mocked_run:
            out = ty.yara_x_scan(str(TBM_EXE))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RULES_MISSING")
        mocked_run.assert_not_called()

    def test_nonexistent_rules_path_is_rules_missing(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"):
            out = ty.yara_x_scan(str(TBM_EXE), rules_path=str(REPO_ROOT / "no_such_rules_dir_xyz"))
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RULES_MISSING")


class YaraXRuleCompileFailedTests(unittest.TestCase):
    def test_nonzero_exit_with_empty_stdout_is_rule_compile_failed(self):
        # Verified live against the real installed yr.exe: a syntax error in
        # the rule source exits 1 with EMPTY stdout (all diagnostics on
        # stderr) -- this is the exact shape being simulated here.
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=1,
                                 stdout="", stderr="error[E001]: syntax error", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule broken { condition")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RULE_COMPILE_FAILED")
        self.assertIn("syntax error", data["stderr_tail"])


class YaraXTimeoutTests(unittest.TestCase):
    def test_timeout_result_from_run_bounded_process_becomes_timeout_status(self):
        fake_result = mock.Mock(cancelled=False, timed_out=True, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}", timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "TIMEOUT")

    def test_cancellation_result_becomes_cancelled_status(self):
        fake_result = mock.Mock(cancelled=True, timed_out=False, returncode=None,
                                 stdout="", stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}", timeout_seconds=10)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "CANCELLED")

    def test_output_truncated_is_analysis_limited_not_a_silent_crop(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_YARA_X_JSON_MATCH, stderr="", output_truncated=True)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")


class YaraXParsingTests(unittest.TestCase):
    """A captured real yr.exe JSON string parses into the structured finding
    list -- rule/namespace/meta/tags/matched_strings, never flattened -- and
    a clean zero-match scan is a real NEGATIVE, not an error."""

    def test_match_capture_parses_into_structured_finding_fields(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_YARA_X_JSON_MATCH, stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule test_mz_header{strings:$mz={4D 5A} condition:$mz at 0}")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertTrue(data["matched"])
        self.assertEqual(data["match_count"], 1)
        self.assertIn("internal_evidence_name", data)
        findings = json.loads(data["content"])
        self.assertEqual(findings[0]["rule"], "test_mz_header")
        self.assertEqual(findings[0]["matched_strings"][0]["match"], "MZ")

    def test_no_match_capture_is_a_real_negative_not_an_error(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_YARA_X_JSON_NO_MATCH, stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule never_matches{strings:$x=\"nope\" condition:$x}")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertFalse(data["matched"])
        self.assertEqual(data["match_count"], 0)

    def test_malformed_json_is_result_parse_failed_not_a_crash(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout="{not valid json,,,}", stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")


class YaraXPaginationTests(unittest.TestCase):
    """content_offset paging must never silently drop content -- same
    contract as ghidra_decompile/decompile_dotnet (tools_decompiler.py)."""

    def _many_matches_json(self, n):
        matches = [
            {
                "rule": f"rule_{i}", "namespace": None, "file": "x",
                "meta": {}, "tags": [],
                "strings": [{"identifier": "$x", "offset": i, "match": "A" * 40}],
            }
            for i in range(n)
        ]
        return json.dumps({"version": "1.20.0", "matches": matches})

    def test_small_max_chars_pages_without_losing_content(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=self._many_matches_json(30), stderr="", output_truncated=False)
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            first = json.loads(ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}", max_chars=1000))
        self.assertTrue(first["content_has_more"])
        self.assertEqual(first["content_returned_chars"], len(first["content"]))
        self.assertLessEqual(first["content_returned_chars"], 1000)

        collected = first["content"]
        offset = first["content_offset"] + first["content_returned_chars"]
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            while True:
                page = json.loads(ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}",
                                                   max_chars=1000, content_offset=offset))
                collected += page["content"]
                offset = page["content_offset"] + page["content_returned_chars"]
                if not page["content_has_more"]:
                    break

        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result):
            whole = json.loads(ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}", max_chars=120000))
        self.assertEqual(collected, whole["content"])

    def test_default_max_chars_matches_default_inline_chars_constant(self):
        import inspect
        self.assertEqual(inspect.signature(ty.yara_x_scan).parameters["max_chars"].default, ty._DEFAULT_INLINE_CHARS)
        self.assertEqual(inspect.signature(ty.yara_x_scan).parameters["content_offset"].default, 0)


class YaraXRulesTextIsThrowawayTests(unittest.TestCase):
    """rules_text must never be persisted into the repo -- written to a
    throwaway temp dir for exactly one scan and cleaned up afterward."""

    def test_inline_rules_text_temp_file_is_removed_after_the_call(self):
        captured_paths = []

        def _spy(cmd, **kwargs):
            captured_paths.append(cmd[-2])  # rules_arg is second-to-last positional
            return mock.Mock(cancelled=False, timed_out=False, returncode=0,
                              stdout=REAL_YARA_X_JSON_NO_MATCH, stderr="", output_truncated=False)

        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", side_effect=_spy):
            ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")
        self.assertEqual(len(captured_paths), 1)
        self.assertFalse(Path(captured_paths[0]).exists(), "inline rule temp file must be cleaned up after the call")


class YaraXRealBinaryTests(unittest.TestCase):
    """Exercised against the real yr.exe + a real corpus binary when
    YARA-X is actually installed; skips cleanly otherwise."""

    def setUp(self):
        if not ty.yara_x_available():
            raise unittest.SkipTest("YARA-X (yr.exe) not installed on this machine")
        if not TBMKD_SYS.is_file():
            raise unittest.SkipTest("corpus fixture missing: " + str(TBMKD_SYS))

    def test_real_driver_matches_its_own_known_process_notify_gate_strings(self):
        # PsSetCreateProcessNotifyRoutineEx/IoCreateDevice are real, already
        # statically-confirmed strings in this exact driver (see
        # docs/PROJECT_STATE.md's trybypassme analysis) -- a genuine
        # positive, not a synthetic fixture.
        rules = (
            "rule tbmkd_driver_indicators {"
            "  strings: $notify=\"PsSetCreateProcessNotifyRoutineEx\" $iocreate=\"IoCreateDevice\" $mz={4D 5A}"
            "  condition: $mz at 0 and $notify and $iocreate"
            "}"
        )
        out = ty.yara_x_scan(str(TBMKD_SYS), rules_text=rules, timeout_seconds=30)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertTrue(data["matched"])
        findings = json.loads(data["content"])
        self.assertEqual(findings[0]["rule"], "tbmkd_driver_indicators")

    def test_real_driver_negative_control_does_not_match(self):
        rules = (
            "rule never_matches_negative_control {"
            "  strings: $x=\"THIS_STRING_SHOULD_NOT_EXIST_IN_TBMKD_XYZ999\""
            "  condition: $x"
            "}"
        )
        out = ty.yara_x_scan(str(TBMKD_SYS), rules_text=rules, timeout_seconds=30)
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertFalse(data["matched"])


class YaraXRulesetSelectionTests(unittest.TestCase):
    """yara_x_scan(..., ruleset=<name>) -- named local rule-pack selection,
    the third mutually-exclusive rule-source shape alongside rules_path/
    rules_text. Precedence and error-shape contract, exercised without
    requiring yr.exe to actually be installed (a fake _yara_x_binary is
    enough for the validation-path tests; the real-binary tests below are
    the live proof)."""

    def test_unknown_ruleset_name_is_rules_missing_before_any_subprocess_call(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process") as mocked_run:
            out = ty.yara_x_scan(str(TBM_EXE), ruleset="not_a_real_ruleset_name")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RULES_MISSING")
        self.assertIn("unknown ruleset name", data["error"])
        mocked_run.assert_not_called()

    def test_known_but_uninstalled_ruleset_is_rules_missing_before_any_subprocess_call(self):
        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch.object(ty, "_resolve_ruleset", return_value=None), \
             mock.patch("tools_yara_x.run_bounded_process") as mocked_run:
            out = ty.yara_x_scan(str(TBM_EXE), ruleset="yara_forge_core")
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RULES_MISSING")
        self.assertIn("not provisioned", data["error"])
        mocked_run.assert_not_called()

    def test_rules_text_takes_precedence_over_ruleset_when_both_given(self):
        captured = {}

        def _spy(cmd, **kwargs):
            captured["rules_arg"] = cmd[-2]
            return mock.Mock(cancelled=False, timed_out=False, returncode=0,
                              stdout=REAL_YARA_X_JSON_NO_MATCH, stderr="", output_truncated=False)

        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch.object(ty, "_resolve_ruleset", return_value=Path("C:/fake/ruleset.yar")), \
             mock.patch("tools_yara_x.run_bounded_process", side_effect=_spy):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}", ruleset="yara_forge_core")
        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["rules_source"], "inline_rules_text")
        self.assertNotEqual(captured["rules_arg"], "C:/fake/ruleset.yar")

    def test_known_rulesets_reports_installed_state_without_a_subprocess(self):
        with mock.patch.object(ty, "_rulesets_home", return_value=Path("C:/definitely/not/installed")):
            rows = ty.known_rulesets()
        self.assertIn("yara_forge_core", rows)
        self.assertFalse(rows["yara_forge_core"]["installed"])


class YaraForgeCoreRulesetRealBinaryTests(unittest.TestCase):
    """Live proof the provisioned YARA-Forge Core ruleset (config/dependencies.
    manifest.json's 'YARA-Forge Core' entry, acquired via tool_provision_
    acquire's digest-verified path) is both reachable by name through
    yara_x_scan AND produces a real result against real corpus binaries --
    never a mocked yr.exe. Skips cleanly if the ruleset was not provisioned
    on this machine (same guard style as YaraXRealBinaryTests above)."""

    def setUp(self):
        if not ty.yara_x_available():
            raise unittest.SkipTest("YARA-X (yr.exe) not installed on this machine")
        if not ty.known_rulesets().get("yara_forge_core", {}).get("installed"):
            raise unittest.SkipTest("YARA-Forge Core ruleset not provisioned on this machine")

    def test_unprotected_trybypassme_binaries_are_a_false_positive_control(self):
        # TBM.exe / TBMKD.sys / WatchdogMain.exe are this repo's own compiled,
        # unprotected trybypassme corpus (docs/PROJECT_STATE.md) -- a public
        # packer/protector rule pack must NOT fire on them; a hit here would
        # mean the ruleset itself is too noisy for this product's use.
        for target in (TBM_EXE, TBMKD_SYS, REPO_ROOT / "benchmarks" / "real_corpora" / "trybypassme" / "WatchdogMain.exe"):
            with self.subTest(target=target.name):
                out = json.loads(ty.yara_x_scan(str(target), ruleset="yara_forge_core", timeout_seconds=120))
                self.assertEqual(out["status"], "OK", out)
                self.assertFalse(out["matched"], f"false positive on unprotected corpus binary {target.name}: {out.get('content')}")

    def test_ruleset_name_resolves_to_the_manifest_provisioned_file(self):
        resolved = ty._resolve_ruleset("yara_forge_core")
        self.assertIsNotNone(resolved)
        self.assertTrue(resolved.is_file())
        self.assertEqual(resolved.name, "yara-rules-core.yar")


class EvidenceIndexWriteTimeHookTests(unittest.TestCase):
    """Same freshness guarantee tests/test_tools_die.py already holds
    die_identify to must also hold for yara_x_scan's own raw yr.exe JSON
    evidence file."""

    def test_yara_x_json_indexed_without_refresh(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_YARA_X_JSON_MATCH, stderr="", output_truncated=False)
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "index.sqlite"

            def _redirected(path, **_kw):
                return _evidence_index_record_write_real(path, root=ty.EVIDENCE, db_path=db_path)

            with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
                 mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
                 mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result), \
                 mock.patch.object(ty, "_evidence_index_record_write", _redirected):
                out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")

            data = json.loads(out)
            self.assertTrue(data["ok"], data)
            index = EvidenceIndex(ty.EVIDENCE, db_path=db_path)
            self.assertEqual(
                1, index.status()["records"],
                "the raw yr.exe json evidence file must be queryable without a refresh() call",
            )

    def test_yara_x_write_survives_a_raising_index_hook(self):
        fake_result = mock.Mock(cancelled=False, timed_out=False, returncode=0,
                                 stdout=REAL_YARA_X_JSON_MATCH, stderr="", output_truncated=False)

        def _boom(path, **_kw):
            raise RuntimeError("index unavailable")

        with mock.patch.object(ty, "_yara_x_binary", return_value="C:/fake/yr.exe"), \
             mock.patch("tools_yara_x.safe_path", return_value=TBM_EXE), \
             mock.patch("tools_yara_x.run_bounded_process", return_value=fake_result), \
             mock.patch.object(ty, "_evidence_index_record_write", _boom):
            out = ty.yara_x_scan(str(TBM_EXE), rules_text="rule r{condition:true}")

        data = json.loads(out)
        self.assertTrue(data["ok"], data)
        self.assertTrue(
            (ty.EVIDENCE / data["internal_evidence_name"]).exists(),
            "the evidence write itself must succeed even when the index hook raises",
        )


if __name__ == "__main__":
    unittest.main()


# --- heavy marker (test-suite split: fast baseline vs external-tool integration) ---
# This test invokes (directly or via an imported tools_*/tools_emulation*/kernel_corpus/
# environment_contamination_check/isolated_artifact/phase81_live_control/runpod_acceptance
# module) a real external analysis tool (Ghidra analyzeHeadless, IDA idat.exe, angr, unicorn,
# frida, or a Hyper-V guest) or spawns a bounded subprocess -- these can be slow or hang,
# so they are excluded from the default run and must be run explicitly with `pytest -m heavy`.
import pytest as _pytest_heavy_marker
pytestmark = _pytest_heavy_marker.mark.heavy
