"""`liebert_re.tools.ghidra`: the headless status probe and the read-only program facts.

Fast tier (contract): nothing here starts Ghidra. `FakeHeadless` replaces `run_bounded_process` at the
process boundary and, like the real analyzeHeadless, writes the result file the post-script was told
about and a log. The case that matters most is `test_exit_zero_with_script_error_is_a_refusal`: Ghidra
exits 0 when a post-script fails (measured on 12.1.3), so the only thing standing between a failed run
and a reported success is the log scan plus the result-file check. Each of those has its own test.

Only `GhidraRealInstallTests` needs a Ghidra install and Java 21; it is marked heavy and skips when
the install is not found.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

import liebert_re.report.tool_families as tool_families
import liebert_re.tools.ghidra as tg
from liebert_re.bounded_subprocess import BoundedProcessResult

# Machine-path-looking text is assembled from parts so the repository's path scan never sees a literal.
_HOME_LIKE = "\\".join(("C:", "Users", "someone", "AppData", "x"))
_SAMPLE_USER = "zzaccountname"

GOOD_FACTS = {
    "schema": 1, "loader": "Portable Executable (PE)", "language_id": "x86:LE:64:default",
    "processor": "x86", "endian": "little", "variant": "default", "address_size_bits": 64,
    "compiler_spec": "windows", "image_base": "140000000", "entry_point_count": 1,
    "entry_points": ["140001000"], "memory_block_count": 2,
    "memory_blocks": [{"name": ".text", "start": "140001000", "size": 512, "read": True, "write": False,
                       "execute": True, "initialized": True}],
    "function_count": 3, "external_library_count": 1, "external_libraries": ["KERNEL32.DLL"],
    "errors": [], "script_completed": True,
}
CLEAN_LOG = "INFO  HEADLESS: execution starts\nINFO  ProgramFacts.java> done\nINFO  Import succeeded\n"
JAVA_21 = 'openjdk version "21.0.12" 2026-07-21 LTS\nOpenJDK Runtime Environment\n'


_EXEC_BITS: set[str] = set()
"""Launchers given an exec bit. Windows has no exec bit, so a chmod there changes nothing observable;
the Linux emulation below reads this record instead of the file system."""


def mark_executable(path: Path) -> None:
    os.chmod(path, 0o755)
    _EXEC_BITS.add(str(path))


def make_install(root: Path, version="12.1.3", java_min="21", with_properties=True) -> Path:
    (root / "support").mkdir(parents=True)
    (root / "Ghidra").mkdir()
    (root / "support" / "analyzeHeadless.bat").write_text("rem fake\n")
    (root / "support" / "analyzeHeadless").write_text("# fake\n")
    # On Linux the status probe (correctly) refuses a launcher with no exec bit, before it ever
    # reaches the Java check. The fake has to be launchable like the real one.
    mark_executable(root / "support" / "analyzeHeadless")
    if with_properties:
        (root / "Ghidra" / "application.properties").write_text(
            f"application.version={version}\napplication.java.min={java_min}\n")
    return root


class FakeHeadless:
    """analyzeHeadless and `java -version` at the process boundary."""

    def __init__(self):
        self.calls = []
        self.exit_code = 0
        self.log = CLEAN_LOG
        self.stderr = ""
        self.facts = dict(GOOD_FACTS)
        self.write_result = True
        self.raw_result = None
        self.timed_out = False
        self.cancelled = False
        self.java_text = JAVA_21
        self.mutate_source = None
        self.project_dirs = []
        self.tree_terminated = True
        self.launch_error = None

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append((argv, kw))
        if len(argv) > 1 and argv[1] == "-version":
            return BoundedProcessResult(0, "", self.java_text)
        if self.launch_error:
            raise self.launch_error
        if self.timed_out:
            return BoundedProcessResult(None, "", "", timed_out=True,
                                        process_tree_terminated=self.tree_terminated)
        if self.cancelled:
            return BoundedProcessResult(None, "", "", cancelled=True,
                                        process_tree_terminated=self.tree_terminated)
        self.project_dirs.append(argv[1])
        index = argv.index("-postScript")
        result_path = Path(argv[index + 2])
        if self.write_result:
            body = self.raw_result if self.raw_result is not None else json.dumps(self.facts)
            result_path.write_text(body, encoding="utf-8")
        if self.mutate_source:
            Path(argv[argv.index("-import") + 1]).write_bytes(self.mutate_source)
        return BoundedProcessResult(self.exit_code, self.log, self.stderr)


class GhidraBase(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.install = make_install(self.root / "ghidra_12.1.3_PUBLIC")
        self.evidence = self.root / "evidence"
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.target = self.root / "sample.bin"
        self.target.write_bytes(b"MZ" + b"\x00" * 64)
        self.fake = FakeHeadless()
        stack.enter_context(mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(self.install)}))
        stack.enter_context(mock.patch.object(tg, "_known_roots", return_value=[]))
        stack.enter_context(mock.patch.object(tg.shutil, "which", return_value=None))
        stack.enter_context(mock.patch.object(tg, "_java_executable", return_value=("java", "PATH")))
        stack.enter_context(mock.patch.object(tg, "run_bounded_process", self.fake))
        stack.enter_context(mock.patch.object(tg, "EVIDENCE", self.evidence))
        stack.enter_context(mock.patch.object(tg, "WORK_ROOT", self.scratch))
        stack.enter_context(mock.patch.object(tg, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(tg, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(tg, "_evidence_index_record_write", return_value={}))

    def facts(self, **kw):
        return json.loads(tg.ghidra_program_facts(str(self.target), **kw))

    def status(self):
        return json.loads(tg.ghidra_status())


class _PosixOs:
    """`tg.os` as it behaves on Linux: os.name is not "nt" and os.access(X_OK) reads an exec bit.
    Everything else is the real os module, so path handling is untouched."""

    name = "posix"

    def __getattr__(self, attr):
        return getattr(os, attr)

    @staticmethod
    def access(path, mode):
        if mode == os.X_OK:
            return str(path) in _EXEC_BITS
        return os.access(path, mode)


@pytest.mark.contract
class LinuxLauncherEmulationTests(GhidraBase):
    """The Linux-only failures, reproduced on any host. The code's LAUNCHER_NOT_EXECUTABLE check is
    correct and stays; these pin that it fires for a launcher with no exec bit and does not for one
    with it (so the Java checks behind it are reachable)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(tg, "os", _PosixOs())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.launcher = self.install / "support" / "analyzeHeadless"

    def test_launcher_without_exec_bit_is_refused(self):
        _EXEC_BITS.discard(str(self.launcher))
        data = self.status()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "INSTALL_INCOMPLETE")
        self.assertEqual(data["error"], "LAUNCHER_NOT_EXECUTABLE")

    def test_launcher_with_exec_bit_reaches_the_ok_status(self):
        data = self.status()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertIn("note", data)

    def test_java_below_minimum_is_reachable_on_linux(self):
        self.fake.java_text = 'openjdk version "17.0.9" 2023-10-17\n'
        self.assertEqual(self.status()["status"], "JAVA_TOO_OLD")

    def test_no_java_is_reachable_on_linux(self):
        with mock.patch.object(tg, "_java_executable", return_value=(None, None)):
            self.assertEqual(self.status()["status"], "JAVA_MISSING")


@pytest.mark.contract
class StatusContractTests(GhidraBase):
    def test_status_shape(self):
        data = self.status()
        for key in ("ok", "tool", "status", "binary", "version", "resolved_by", "operations", "note"):
            self.assertIn(key, data)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["version"], "12.1.3")
        self.assertEqual(data["resolved_by"], "GHIDRA_INSTALL_DIR")
        self.assertEqual(data["operations"], ["ghidra_status", "ghidra_program_facts"])
        self.assertEqual(data["java"]["required_minimum"], 21)
        self.assertEqual(data["java"]["found_major"], 21)
        self.assertIs(data["java"]["satisfies_minimum"], True)
        self.assertTrue(data["binary"].endswith(("analyzeHeadless.bat", "analyzeHeadless")))

    def test_status_does_not_launch_ghidra(self):
        self.status()
        self.assertTrue(all(argv[1] == "-version" for argv, _ in self.fake.calls), self.fake.calls)

    def test_missing_install_is_tool_missing_for_both_operations(self):
        with mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(self.root / "nowhere")}):
            for data in (json.loads(tg.ghidra_status()), self.facts()):
                self.assertFalse(data["ok"])
                self.assertEqual(data["status"], "TOOL_MISSING")
            self.assertEqual(json.loads(tg.ghidra_status())["unusable_settings"][0]["setting"],
                             "GHIDRA_INSTALL_DIR")

    def test_install_without_launcher_is_not_accepted(self):
        (self.install / "support" / "analyzeHeadless.bat").unlink()
        (self.install / "support" / "analyzeHeadless").unlink()
        self.assertEqual(self.status()["status"], "TOOL_MISSING")

    def test_java_below_minimum_is_reported(self):
        self.fake.java_text = 'openjdk version "17.0.9" 2023-10-17\n'
        data = self.status()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "JAVA_TOO_OLD")
        self.assertIs(data["java"]["satisfies_minimum"], False)
        self.assertEqual(self.facts()["status"], "JAVA_TOO_OLD")

    def test_unparseable_java_version_is_unknown_not_a_pass(self):
        self.fake.java_text = "something unexpected\n"
        data = self.status()
        self.assertIsNone(data["java"]["found_major"])
        self.assertIsNone(data["java"]["satisfies_minimum"])

    def test_old_style_java_version_numbering(self):
        self.assertEqual(tg._parse_java_major('java version "1.8.0_392"'), 8)
        self.assertEqual(tg._parse_java_major('openjdk version "21.0.12"'), 21)
        self.assertEqual(tg._parse_java_major('openjdk version "22"'), 22)
        self.assertIsNone(tg._parse_java_major(""))

    def test_unreadable_properties_is_incomplete_and_version_is_none(self):
        (self.install / "Ghidra" / "application.properties").unlink()
        data = self.status()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "INSTALL_INCOMPLETE")
        self.assertIsNone(data["version"])

    def test_no_java_is_reported(self):
        with mock.patch.object(tg, "_java_executable", return_value=(None, None)):
            self.assertEqual(self.status()["status"], "JAVA_MISSING")
            self.assertEqual(self.facts()["status"], "JAVA_MISSING")

    def test_home_directory_never_appears_in_status(self):
        home = str(Path.home())
        text = tg.ghidra_status()
        self.assertNotIn(home, text)
        self.assertNotIn(home.replace("\\", "\\\\"), text)


@pytest.mark.contract
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        stack.enter_context(mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": "", "GHIDRA_HOME": ""}))
        stack.enter_context(mock.patch.object(tg.shutil, "which", return_value=None))
        stack.enter_context(mock.patch.object(tg, "_known_roots", return_value=[self.root]))

    def test_newest_version_wins_among_discovered_installs(self):
        make_install(self.root / "ghidra_11.0_PUBLIC", version="11.0")
        make_install(self.root / "ghidra_12.1.3_PUBLIC", version="12.1.3")
        selection, candidates, _ = tg._select_install()
        self.assertEqual(len(candidates), 2)
        self.assertEqual(selection["version"], "12.1.3")
        self.assertIn("highest", selection["selected_by"])

    def test_equal_versions_keep_discovery_order_and_both_are_listed(self):
        make_install(self.root / "ghidra_a", version="12.1.3")
        make_install(self.root / "sub" / "ghidra", version="12.1.3")
        selection, candidates, _ = tg._select_install()
        self.assertEqual(len(candidates), 2)
        self.assertEqual(selection["install_dir"].name, "ghidra_a")

    def test_explicit_setting_beats_a_newer_discovered_install(self):
        make_install(self.root / "ghidra_99", version="99.0")
        old = make_install(self.root / "elsewhere", version="10.0")
        with mock.patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(old)}):
            selection, _, _ = tg._select_install()
        self.assertEqual(selection["version"], "10.0")
        self.assertEqual(selection["resolved_by"], "GHIDRA_INSTALL_DIR")
        self.assertIn("explicit", selection["selected_by"])

    def test_path_entry_resolves_to_its_install_directory(self):
        install = make_install(self.root / "onpath", version="12.0")
        with mock.patch.object(tg.shutil, "which",
                               side_effect=lambda n: str(install / "support" / n) if n == "analyzeHeadless" else None):
            selection, _, _ = tg._select_install()
        self.assertEqual(selection["resolved_by"], "PATH")

    def test_nothing_found_is_none(self):
        selection, candidates, skipped = tg._select_install()
        self.assertIsNone(selection)
        self.assertEqual(candidates, [])
        self.assertEqual(skipped, [])


@pytest.mark.contract
class ProgramFactsContractTests(GhidraBase):
    def test_success_shape_and_cleanup(self):
        data = self.facts()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["path"], "sample.bin")
        self.assertEqual(data["ghidra_version"], "12.1.3")
        self.assertEqual(data["facts"]["loader"], "Portable Executable (PE)")
        self.assertEqual(data["facts"]["function_count"], 3)
        self.assertEqual(data["facts"]["external_libraries"], ["KERNEL32.DLL"])
        self.assertNotIn("script_completed", data["facts"])
        self.assertIs(data["source_unchanged"], True)
        self.assertEqual(data["facts_unreadable"], [])
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertTrue(any(self.evidence.glob("*_facts.json")))

    def test_command_uses_a_java_script_a_private_project_and_deletes_it(self):
        self.facts()
        argv, kw = next((a, k) for a, k in self.fake.calls if a[1] != "-version")
        self.assertIn("-deleteProject", argv)
        self.assertIn("-postScript", argv)
        self.assertEqual(argv[argv.index("-postScript") + 1], "ProgramFacts.java")
        self.assertEqual(argv[argv.index("-import") + 1], str(self.target))
        self.assertNotIn("pyghidra", " ".join(argv).lower())
        self.assertIn("-analysisTimeoutPerFile", argv)
        self.assertEqual(kw["timeout_seconds"], 300)
        self.assertTrue(Path(argv[1]).parent.name.startswith("liebert-ghidra-"))

    def test_exit_zero_with_script_error_is_a_refusal(self):
        # The measured trap: the post-script failed, analyzeHeadless exited 0, and the result file the
        # script wrote earlier is complete and valid. Only the log says the run did not work.
        self.fake.exit_code = 0
        self.fake.log = CLEAN_LOG + "ERROR REPORT SCRIPT ERROR: ProgramFacts.java : boom\n"
        data = self.facts()
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "GHIDRA_FAILURE_MARKER_IN_LOG")
        self.assertEqual(data["exit_code"], 0)
        self.assertIn("SCRIPT_ERROR", data["failure_signals"])
        self.assertNotIn("facts", data)

    def test_other_failure_markers_in_an_exit_zero_run_are_refusals(self):
        cases = {
            "Ghidra was not started with PyGhidra. Python is not available": "SCRIPT_RUNTIME_UNAVAILABLE",
            "ghidra.app.script.GhidraScriptLoadException: x": "SCRIPT_LOAD_FAILED",
            "ProgramFacts.java: Unable to compile": "SCRIPT_COMPILE_FAILED",
            "ERROR Abort due to Headless analyzer error: x": "HEADLESS_ABORT",
            "ERROR Import failed for x": "IMPORT_FAILED",
        }
        for line, code in cases.items():
            with self.subTest(code=code):
                self.fake.log = CLEAN_LOG + line + "\n"
                data = self.facts()
                self.assertFalse(data["ok"], data)
                self.assertIn(code, data["failure_signals"])

    def test_clean_log_with_unrelated_error_lines_is_not_a_failure_but_is_counted(self):
        self.fake.log = CLEAN_LOG + "ERROR some analyzer noise\n"
        data = self.facts()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["log_error_lines"], 1)

    def test_exit_zero_without_a_result_file_is_a_refusal(self):
        self.fake.write_result = False
        data = self.facts()
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "GHIDRA_NO_RESULT_FILE")

    def test_result_file_problems_are_refusals(self):
        cases = {
            "{not json": "GHIDRA_RESULT_NOT_JSON",
            "[1]": "GHIDRA_RESULT_NOT_AN_OBJECT",
            json.dumps({k: v for k, v in GOOD_FACTS.items() if k != "script_completed"}): "GHIDRA_RESULT_INCOMPLETE",
            json.dumps(dict(GOOD_FACTS, schema=99)): "GHIDRA_RESULT_SCHEMA_MISMATCH",
        }
        for raw, code in cases.items():
            with self.subTest(code=code):
                self.fake.raw_result = raw
                data = self.facts()
                self.assertFalse(data["ok"], data)
                self.assertEqual(data["error"], code)

    def test_nonzero_exit_is_a_refusal(self):
        self.fake.exit_code = 1
        data = self.facts()
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "GHIDRA_EXITED_NONZERO")

    def test_timeout_is_a_timeout_with_the_modules_own_bound(self):
        self.fake.timed_out = True
        data = self.facts(timeout_seconds=40)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertFalse(data["ok"])
        self.assertNotIn("facts", data)
        argv, kw = next((a, k) for a, k in self.fake.calls if a[1] != "-version")
        self.assertEqual(kw["timeout_seconds"], 40)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_timeout_is_clamped_to_the_allowed_range(self):
        self.facts(timeout_seconds=1)
        self.facts(timeout_seconds=10 ** 9)
        seen = [kw["timeout_seconds"] for a, kw in self.fake.calls if a[1] != "-version"]
        self.assertEqual(seen, [tg._MIN_TIMEOUT_SECONDS, tg._MAX_TIMEOUT_SECONDS])

    def test_cancellation_is_reported(self):
        self.fake.cancelled = True
        self.assertEqual(self.facts()["status"], "CANCELLED")

    def test_lock_exception_is_its_own_refusal(self):
        self.fake.exit_code = 1
        self.fake.log = ("ERROR Abort due to Headless analyzer error: Unable to lock project! x "
                         "(HeadlessAnalyzer) ghidra.framework.store.LockException\n")
        data = self.facts()
        self.assertEqual(data["status"], "PROJECT_LOCKED")
        self.assertEqual(data["error"], "GHIDRA_PROJECT_LOCKED")
        self.assertFalse(data["ok"])

    def test_every_run_gets_its_own_project_directory(self):
        self.facts()
        self.facts()
        self.assertEqual(len(set(self.fake.project_dirs)), 2)

    def test_concurrent_runs_do_not_share_a_project_directory(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.facts())) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(r["ok"] for r in results), results)
        self.assertEqual(len(set(self.fake.project_dirs)), 4)

    def test_missing_input_and_refused_path(self):
        data = json.loads(tg.ghidra_program_facts(str(self.root / "absent.bin")))
        self.assertEqual(data["status"], "NOT_FOUND")
        with mock.patch.object(tg, "safe_path", side_effect=PermissionError("outside")):
            data = self.facts()
        self.assertEqual(data["status"], "PATH_REFUSED")
        self.assertEqual([a for a, _ in self.fake.calls if a[1] != "-version"], [])

    def test_unreadable_facts_stay_null_and_are_named(self):
        self.fake.facts = dict(GOOD_FACTS, function_count=None, external_libraries=None,
                               errors=["function_count: NullPointerException"])
        data = self.facts()
        self.assertTrue(data["ok"])
        self.assertIsNone(data["facts"]["function_count"])
        self.assertIsNone(data["facts"]["external_libraries"])
        self.assertEqual(data["facts_unreadable"], ["external_libraries", "function_count"])
        self.assertEqual(data["facts"]["errors"], ["function_count: NullPointerException"])

    def test_a_source_the_run_modified_is_a_refusal_not_a_success(self):
        original = self.target.read_bytes()
        self.fake.mutate_source = b"changed"
        data = self.facts()
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "SOURCE_MODIFIED")
        self.assertEqual(data["source_sha256_before"], hashlib.sha256(original).hexdigest())
        self.assertEqual(data["source_sha256_after"], hashlib.sha256(b"changed").hexdigest())
        self.assertNotIn("facts", data)
        self.assertNotIn(str(self.target), json.dumps(data))

    def test_an_unreadable_source_after_the_run_is_refused(self):
        real = tg._sha256_file
        calls = []

        def flaky(path):
            calls.append(path)
            if len(calls) > 1:
                raise PermissionError("denied")
            return real(path)

        with mock.patch.object(tg, "_sha256_file", flaky):
            data = self.facts()
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "SOURCE_UNVERIFIED")

    def test_unchanged_source_is_reported_as_such(self):
        self.assertIs(self.facts()["source_unchanged"], True)

    def test_timeout_reports_the_real_process_tree_state(self):
        self.fake.timed_out = True
        data = self.facts()
        self.assertIs(data["process_tree_terminated"], True)
        self.assertEqual(data["error"], "GHIDRA_TIMEOUT_PROCESS_TREE_TERMINATED")
        self.fake.tree_terminated = False
        data = self.facts()
        self.assertIs(data["process_tree_terminated"], False)
        self.assertEqual(data["error"], "GHIDRA_TIMEOUT_PROCESS_TREE_NOT_CONFIRMED_TERMINATED")
        self.assertIn("may still be running", data["detail"])
        self.fake.timed_out, self.fake.cancelled = False, True
        data = self.facts()
        self.assertEqual(data["error"], "GHIDRA_CANCELLED_PROCESS_TREE_NOT_CONFIRMED_TERMINATED")

    def test_a_scratch_directory_that_cannot_be_removed_is_reported(self):
        def refuse(path, *args, **kwargs):
            if kwargs.get("ignore_errors"):
                return None
            raise PermissionError("in use")

        with mock.patch.object(tg.shutil, "rmtree", refuse):
            data = self.facts()
        self.assertTrue(data["ok"], data)
        failure = data["cleanup_failures"][0]
        self.assertEqual(failure["error"], "PermissionError")
        self.assertTrue(failure["directory"].startswith("liebert-ghidra-"))
        self.assertIs(failure["may_remain_on_disk"], True)
        self.assertNotIn(str(self.scratch), json.dumps(data))

    def test_a_successful_cleanup_reports_nothing(self):
        self.assertNotIn("cleanup_failures", self.facts())

    def test_a_result_with_only_the_two_bookkeeping_fields_is_refused(self):
        self.fake.facts = {"schema": 1, "script_completed": True}
        data = self.facts()
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["error"], "GHIDRA_RESULT_CONTRACT_VIOLATION")

    def test_a_missing_fact_key_is_unreadable_and_distinct_from_null(self):
        partial = {k: v for k, v in GOOD_FACTS.items() if k not in ("function_count", "loader")}
        partial["external_libraries"] = None
        self.fake.facts = partial
        data = self.facts()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["facts_missing_from_result"], ["function_count", "loader"])
        self.assertEqual(data["facts_unreadable"], ["external_libraries", "function_count", "loader"])
        self.assertIsNone(data["facts"]["function_count"])
        self.assertIn("function_count", data["facts"])

    def test_a_measured_empty_value_is_not_unreadable(self):
        self.fake.facts = dict(GOOD_FACTS, external_libraries=[], external_library_count=0)
        data = self.facts()
        self.assertEqual(data["facts"]["external_libraries"], [])
        self.assertEqual(data["facts_unreadable"], [])

    def test_a_fact_of_the_wrong_type_is_malformed_not_trusted(self):
        self.fake.facts = dict(GOOD_FACTS, function_count="3", entry_points="140001000")
        data = self.facts()
        self.assertEqual(data["facts_malformed"], ["entry_points", "function_count"])
        self.assertIsNone(data["facts"]["function_count"])
        self.assertIn("function_count", data["facts_unreadable"])

    def test_the_contract_names_every_key_the_script_writes(self):
        text = Path(tg._SCRIPT_SOURCE).read_text(encoding="utf-8")
        for key in tg._FACT_SPEC:
            self.assertIn(key, text, key)

    def test_not_found_does_not_echo_an_absolute_path(self):
        absent = "\\".join(("D:", "Projects", "someone", "absent.bin"))
        data = json.loads(tg.ghidra_program_facts(absent))
        self.assertEqual(data["status"], "NOT_FOUND")
        self.assertNotIn("Projects", json.dumps(data))

    def test_a_generic_absolute_path_does_not_leak_from_status_or_logs(self):
        other = "\\".join(("D:", "Tools", "ghidra_x"))
        shown = tg._shown_path(other + "\\support\\analyzeHeadless.bat", 3)
        self.assertEqual(shown, "<ABS>/ghidra_x/support/analyzeHeadless.bat")
        self.assertNotIn("Tools", shown)
        self.assertEqual(tg._shown_path(other, 1), "<ABS>/ghidra_x")
        self.assertEqual(tg._shown_path("/opt/ghidra_x", 1), "<ABS>/ghidra_x")
        # the same function feeds the status response for an install outside the home directory
        selection, _, _ = tg._select_install()
        elsewhere = dict(selection, install_dir=Path(other), headless=Path(other) / "support" / "analyzeHeadless.bat")
        with mock.patch.object(tg, "_select_install", return_value=(elsewhere, [elsewhere], [])):
            text = tg.ghidra_status()
        self.assertNotIn("Tools", text)
        self.assertIn("<ABS>/ghidra_x", text)
        tools = "\\".join(("D:", "Tools", "Ghidra", "x.log"))
        cleaned = tg._redact(f"loading {tools} and /opt/a/b.c and ok.txt")
        self.assertNotIn("Tools", cleaned)
        self.assertNotIn("/opt/a", cleaned)
        self.assertIn("ok.txt", cleaned)

    def test_a_launcher_that_cannot_start_is_a_structured_refusal(self):
        self.fake.launch_error = OSError(193, "not a valid application")
        data = self.facts()
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ENVIRONMENT_ERROR")
        self.assertEqual(data["error"], "GHIDRA_LAUNCH_FAILED")
        self.assertIs(data["launcher_executed"], False)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_status_says_it_did_not_try_the_launcher(self):
        data = self.status()
        self.assertIs(data["launcher_verified"], False)
        self.assertIn("not executed", data["launcher_check"])
        self.assertIn("launcher_verified", data["note"])

    def test_scratch_with_a_dot_element_is_refused(self):
        dotted = self.root / ".hidden"
        dotted.mkdir()
        with mock.patch.object(tg, "WORK_ROOT", dotted):
            data = self.facts()
        self.assertEqual(data["status"], "ENVIRONMENT_ERROR")
        self.assertEqual(data["error"], "GHIDRA_SCRATCH_PATH_HAS_DOT_ELEMENT")
        self.assertEqual(list(dotted.iterdir()), [])

    def test_redaction_keeps_paths_and_account_out_of_the_answer(self):
        work_marker = []
        original = self.fake.__call__

        def leaking(argv, **kw):
            if argv[1] != "-version":
                work_marker.append(argv[1])
            self.fake.log = (f"ERROR Abort due to Headless analyzer error: {_HOME_LIKE}\n"
                             f"project {argv[1] if argv[1] != '-version' else ''} input {self.target}\n"
                             f"user {_SAMPLE_USER}\nhome {Path.home()}\n")
            return original(argv, **kw)

        with mock.patch.object(tg, "run_bounded_process", leaking), \
                mock.patch.object(tg.getpass, "getuser", return_value=_SAMPLE_USER):
            text = tg.ghidra_program_facts(str(self.target))
        data = json.loads(text)
        self.assertFalse(data["ok"])
        for forbidden in (_HOME_LIKE, _SAMPLE_USER, str(self.target), str(Path.home()), work_marker[0]):
            self.assertNotIn(forbidden, text)
            self.assertNotIn(forbidden.replace("\\", "\\\\"), text)
        self.assertIn("<HOME>", text)
        self.assertIn("<INPUT>", text)

    def test_redact_function_directly(self):
        out = tg._redact(f"a {_HOME_LIKE} b /work/x", work="/work/x", target=None)
        self.assertNotIn("someone", out)
        self.assertIn("<WORK>", out)


@pytest.mark.contract
class ScriptAndRegistrationTests(unittest.TestCase):
    def test_the_script_is_a_separate_java_data_file(self):
        source = Path(tg._SCRIPT_SOURCE)
        self.assertTrue(source.is_file())
        self.assertEqual(source.suffix, ".java")
        text = source.read_text(encoding="utf-8")
        self.assertIn("extends GhidraScript", text)
        self.assertIn("getScriptArgs", text)
        self.assertIn("script_completed", text)
        # read-only: no transaction, no write API on the program
        for write_api in ("startTransaction", "createFunction", "setName(", "removeFunction", "clearListing"):
            self.assertNotIn(write_api, text)

    def test_names_are_registered_in_a_family(self):
        self.assertIn("ghidra_status", tool_families.FAMILIES["native"])
        self.assertIn("ghidra_program_facts", tool_families.FAMILIES["native"])
        published = tool_families.published_tools("native")
        self.assertIn("ghidra_status", published)
        self.assertIn("ghidra_program_facts", published)


# ---------------------------------------------------------------------------
# the real tool
# ---------------------------------------------------------------------------
def _real_ghidra_usable():
    selection, _, _ = tg._select_install()
    if selection is None:
        return False
    java = tg._probe_java()
    minimum = tg._int_or_none(selection["java_min"])
    return bool(java["found"] and java["major"] is not None and (minimum is None or java["major"] >= minimum))


@pytest.mark.heavy
@unittest.skipUnless(_real_ghidra_usable(), "Ghidra with a suitable Java is not installed")
class GhidraRealInstallTests(unittest.TestCase):
    """Imports a tiny synthetic x86-64 PE built in code (nothing shipped, nothing third-party)."""

    @classmethod
    def setUpClass(cls):
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls._tmp = TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        # start: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret   then a caller: call start; ret
        code = bytes.fromhex("554889e531c05dc3") + b"\x90" * 8 + bytes.fromhex("e8ebffffffc3")
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", code)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.evidence = self.root / f"ev_{self.id().rsplit('.', 1)[-1]}"
        stack.enter_context(mock.patch.object(tg, "EVIDENCE", self.evidence))
        stack.enter_context(mock.patch.object(tg, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(tg, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(tg, "_evidence_index_record_write", return_value={}))

    def test_status_reports_the_install(self):
        data = json.loads(tg.ghidra_status())
        self.assertTrue(data["ok"], data)
        self.assertRegex(data["version"], r"^\d+\.\d+")
        self.assertIs(data["java"]["satisfies_minimum"], True)

    def test_import_reads_back_program_facts_without_touching_the_source(self):
        before = hashlib.sha256(self.pe.read_bytes()).hexdigest()
        data = json.loads(tg.ghidra_program_facts(str(self.pe), timeout_seconds=300))
        self.assertTrue(data["ok"], data)
        facts = data["facts"]
        self.assertEqual(facts["loader"], "Portable Executable (PE)")
        self.assertTrue(facts["language_id"].startswith("x86:LE:64"), facts["language_id"])
        self.assertEqual(facts["processor"], "x86")
        self.assertEqual(facts["address_size_bits"], 64)
        self.assertGreaterEqual(facts["entry_point_count"], 1)
        self.assertGreaterEqual(facts["memory_block_count"], 1)
        self.assertGreaterEqual(facts["function_count"], 1)
        self.assertIsInstance(facts["external_libraries"], list)
        self.assertEqual(facts["errors"], [])
        self.assertEqual(data["source_sha256"], before)
        self.assertIs(data["source_unchanged"], True)
        self.assertEqual(hashlib.sha256(self.pe.read_bytes()).hexdigest(), before)
        self.assertNotIn(str(self.root), json.dumps(data))

    def test_a_file_ghidra_cannot_load_is_a_refusal_not_empty_facts(self):
        junk = self.root / "junk.bin"
        junk.write_bytes(os.urandom(512))
        data = json.loads(tg.ghidra_program_facts(str(junk), timeout_seconds=300))
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertNotIn("facts", data)

    def test_two_concurrent_runs_do_not_lock_each_other(self):
        results = []
        threads = [threading.Thread(
            target=lambda: results.append(json.loads(tg.ghidra_program_facts(str(self.pe), timeout_seconds=300))))
            for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(r["ok"] for r in results), results)
