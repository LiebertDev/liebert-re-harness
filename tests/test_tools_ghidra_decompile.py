"""`liebert_re.tools.ghidra.ghidra_decompile`: the read-only decompile of selected functions.

Fast tier (contract): nothing here starts Ghidra. `DecompileHeadless` replaces
`run_bounded_process` at the process boundary; like the real analyzeHeadless it reads the request
file the post-script is told about and writes the result file. The Python side is checked for the
command line it builds, the request file, the parsing and normalisation of the script's JSON, the
refusals and the limits. The Java script is checked statically for read-only API use, because a
data file cannot be exercised without Ghidra. `GhidraDecompileRealInstallTests` is the one class that
runs a real install: it is marked heavy, does not run in CI, and skips without Ghidra and Java.
"""
from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from unittest import mock

import pytest

import liebert_re.report.tool_families as tool_families
import liebert_re.tools.ghidra as tg
from liebert_re.bounded_subprocess import BoundedProcessResult
from tests.test_tools_ghidra import CLEAN_LOG, FakeHeadless, GhidraBase, _real_ghidra_usable


def _entry(requested, address="140001000", name="FUN_140001000", **kw):
    base = {
        "requested": requested, "address": address, "name": name,
        "signature": "undefined8 FUN_140001000(void)", "decompiled_signature": "undefined8 FUN_140001000(void)",
        "c_code": "\nundefined8 FUN_140001000(void)\n\n{\n  return 0;\n}\n\n",
        "c_code_truncated": False, "decompile_completed": True, "warnings": [], "error": None,
    }
    base.update(kw)
    return base


def _failed(requested, error, **kw):
    return _entry(requested, c_code=None, decompile_completed=False, error=error,
                  decompiled_signature=None, **kw)


class DecompileHeadless(FakeHeadless):
    """analyzeHeadless running DecompileFunctions.java: reads the request file, writes the result."""

    def __init__(self):
        super().__init__()
        self.requests_seen = None
        self.script_args = None
        self.entries = None          # None: one completed entry per request
        self.result = None           # a whole result dict, replacing the generated one

    def __call__(self, argv, **kw):
        argv = list(argv)
        if len(argv) > 1 and argv[1] == "-version":
            return super().__call__(argv, **kw)
        if self.launch_error or self.timed_out or self.cancelled or "-postScript" not in argv:
            return super().__call__(argv, **kw)
        index = argv.index("-postScript")
        self.script_args = argv[index + 2:index + 6]
        result_path, request_path = Path(argv[index + 2]), Path(argv[index + 3])
        self.requests_seen = request_path.read_text(encoding="utf-8").splitlines()
        self.calls.append((argv, kw))
        self.project_dirs.append(argv[1])
        if self.write_result:
            if self.raw_result is not None:
                body = self.raw_result
            else:
                entries = self.entries
                if entries is None:
                    entries = [_entry(line.split("\t", 1)[1]) for line in self.requests_seen]
                result = self.result if self.result is not None else {
                    "schema": 1, "requested_count": len(self.requests_seen), "functions": entries,
                    "errors": [], "script_completed": True}
                body = json.dumps(result)
            result_path.write_text(body, encoding="utf-8")
        if self.mutate_source:
            Path(argv[argv.index("-import") + 1]).write_bytes(self.mutate_source)
        return BoundedProcessResult(self.exit_code, self.log, self.stderr)


class DecompileBase(GhidraBase):
    def setUp(self):
        super().setUp()
        self.fake = DecompileHeadless()
        patcher = mock.patch.object(tg, "run_bounded_process", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def decompile(self, functions=("0x140001000",), **kw):
        return json.loads(tg.ghidra_decompile(str(self.target), functions, **kw))

    def launched(self):
        return [a for a, _ in self.fake.calls if a[1] != "-version"]


@pytest.mark.contract
class DecompileContractTests(DecompileBase):
    def test_success_shape_and_cleanup(self):
        data = self.decompile(["0x140001000", "main"])
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["status"], data["tool"]), ("OK", "ghidra_decompile"))
        self.assertEqual(data["path"], "sample.bin")
        self.assertEqual((data["requested_count"], data["decompiled_count"], data["failed_count"]), (2, 2, 0))
        self.assertEqual([e["requested"] for e in data["functions"]], ["140001000", "main"])
        first = data["functions"][0]
        self.assertIs(first["decompile_completed"], True)
        self.assertIn("return 0;", first["c_code"])
        self.assertIsNone(first["error"])
        self.assertIs(data["source_unchanged"], True)
        self.assertEqual(data["ghidra_version"], "12.1.3")
        self.assertEqual(list(self.scratch.iterdir()), [])
        written = list((self.root / "ghidra_decompile").glob("*_decompile.json"))
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].name, data["internal_evidence_name"])
        stored = json.loads(written[0].read_text(encoding="utf-8"))
        self.assertEqual(stored["source_sha256"], data["source_sha256"])
        self.assertFalse((self.evidence / "ghidra_decompile").exists())

    def test_command_line_uses_the_decompile_script_and_a_request_file(self):
        self.decompile(["0x140001000", "my func with spaces", "FUN_00401000"])
        (argv,) = self.launched()
        self.assertIn("-deleteProject", argv)
        self.assertEqual(argv[argv.index("-postScript") + 1], "DecompileFunctions.java")
        self.assertEqual(argv[argv.index("-import") + 1], str(self.target))
        self.assertNotIn("pyghidra", " ".join(argv).lower())
        self.assertTrue(Path(argv[1]).parent.name.startswith("liebert-ghidra-"))
        args = self.fake.script_args
        self.assertEqual(Path(args[0]).name, "decompile.json")
        self.assertEqual(Path(args[1]).name, "requests.txt")
        self.assertEqual(args[2:4], ["30", "16"])
        # request data travels in a file, so a name with spaces never splits the command line
        self.assertEqual(self.fake.requests_seen, ["A\t140001000", "N\tmy func with spaces", "N\tFUN_00401000"])
        self.assertNotIn("my func with spaces", " ".join(argv))

    def test_requests_are_classified_without_guessing(self):
        cases = [
            (0x140001000, ("A", "140001000")),
            ("0x140001000", ("A", "140001000")),
            ("0X1400010AB", ("A", "1400010ab")),
            ("  0x10  ", ("A", "10")),
            ("deadbeef", ("N", "deadbeef")),       # looks like hex; without 0x it is a name
            ("140001000", ("N", "140001000")),
            ("main", ("N", "main")),
            ("ns::Class::method", ("N", "ns::Class::method")),
            ("0xzz", ("N", "0xzz")),
        ]
        for given, expected in cases:
            with self.subTest(given=given):
                requests, bad = tg._function_requests([given])
                self.assertIsNone(bad)
                self.assertEqual(requests, [expected])
        self.assertEqual(tg._function_requests("main")[0], [("N", "main")])
        self.assertEqual(tg._function_requests(4096)[0], [("A", "1000")])

    def test_unusable_requests_are_refused_before_anything_starts(self):
        cases = {
            "FUNCTIONS_REQUIRED": [None, [], ()],
            "TOO_MANY_FUNCTIONS": [["0x1"] * 17],
            "FUNCTION_SPEC_INVALID": [[1.5], [True], [None], [["0x1"]], [{"a": 1}], [""], ["   "],
                                      ["bad\nname"], ["bad\tname"], ["x" * 513], [-1], [1 << 64], 3.5, {"a": 1}],
        }
        for error, inputs in cases.items():
            for given in inputs:
                with self.subTest(error=error, given=repr(given)[:40]):
                    data = self.decompile(given)
                    self.assertFalse(data["ok"], data)
                    self.assertEqual((data["status"], data["error"]), ("TOOL_USAGE", error))
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_the_limit_is_sixteen_and_sixteen_is_accepted(self):
        data = self.decompile([f"0x{n:x}" for n in range(0x1000, 0x1010)])
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["requested_count"], 16)

    def test_missing_input_and_missing_install_are_the_facts_operations_refusals(self):
        data = json.loads(tg.ghidra_decompile(str(self.root / "absent.bin"), ["0x1"]))
        self.assertEqual((data["ok"], data["status"]), (False, "NOT_FOUND"))
        with mock.patch.object(tg, "_select_install", return_value=(None, [], [])):
            data = self.decompile()
        self.assertEqual((data["ok"], data["status"]), (False, "TOOL_MISSING"))
        self.assertEqual(self.fake.calls, [])

    def test_a_function_that_did_not_decompile_has_null_code_and_a_reason(self):
        self.fake.entries = [
            _entry("140001000"),
            _failed("nosuch", "FUNCTION_NOT_FOUND: no function has this name", address=None, name=None, signature=None),
            _failed("140002000", "DECOMPILE_TIMEOUT: no answer within 30 s", address="140002000"),
        ]
        data = self.decompile(["0x140001000", "nosuch", "0x140002000"])
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "PARTIAL")
        self.assertEqual((data["decompiled_count"], data["failed_count"]), (1, 2))
        ok, missing, timed_out = data["functions"]
        self.assertIsNotNone(ok["c_code"])
        for entry, prefix in ((missing, "FUNCTION_NOT_FOUND"), (timed_out, "DECOMPILE_TIMEOUT")):
            self.assertIsNone(entry["c_code"])
            self.assertIs(entry["decompile_completed"], False)
            self.assertTrue(entry["error"].startswith(prefix), entry)
        self.assertIsNone(missing["address"])

    def test_nothing_decompiled_is_a_refusal_that_still_shows_every_reason(self):
        self.fake.entries = [_failed("a", "AMBIGUOUS_FUNCTION_NAME: 2 functions have this name, use an address: 1,2"),
                             _failed("b", "DECOMPILE_FAILED: no message")]
        data = self.decompile(["a", "b"])
        self.assertFalse(data["ok"], data)
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "NO_FUNCTION_DECOMPILED"))
        self.assertEqual(len(data["functions"]), 2)
        self.assertTrue(all(e["c_code"] is None and e["error"] for e in data["functions"]))
        self.assertFalse((self.root / "ghidra_decompile").exists(), "a refusal writes no evidence")

    def test_a_decompiler_warning_is_carried_not_hidden(self):
        self.fake.entries = [_entry("140001000", c_code="halt_baddata();", warnings=["halt_baddata"])]
        data = self.decompile()
        self.assertEqual(data["functions"][0]["warnings"], ["halt_baddata"])
        self.assertIn("halt_baddata", data["note"])

    def test_entry_normalisation_never_turns_a_gap_into_a_success(self):
        entry, problems = tg._normalise_entry(
            {"requested": "x", "decompile_completed": True, "c_code": None}, None, None)
        self.assertIs(entry["decompile_completed"], False)
        self.assertIsNone(entry["c_code"])
        self.assertIn("completed without C code", entry["error"])
        self.assertEqual(problems, [])
        entry, _ = tg._normalise_entry({"requested": "x", "decompile_completed": False, "c_code": "int x;"}, None, None)
        self.assertIsNone(entry["c_code"], "code that was not completed is not returned as code")
        self.assertIn("no reason", entry["error"])
        entry, problems = tg._normalise_entry(
            {"requested": "x", "decompile_completed": "yes", "c_code": 5, "warnings": None, "address": 7}, None, None)
        self.assertIs(entry["decompile_completed"], False)
        self.assertEqual(sorted(problems), ["address", "c_code", "decompile_completed"])
        self.assertEqual(entry["warnings"], [])
        self.assertEqual(set(entry), set(tg._DECOMPILE_ENTRY_SPEC))
        entry, problems = tg._normalise_entry("not an object", None, None)
        self.assertIn("entry_not_an_object", problems)
        self.assertIs(entry["decompile_completed"], False)

    def test_malformed_entries_are_reported_by_index(self):
        self.fake.entries = [_entry("140001000"), _entry("140002000", c_code=12)]
        data = self.decompile(["0x140001000", "0x140002000"])
        self.assertEqual(data["entries_malformed"], {"1": ["c_code"]})
        self.assertEqual(data["status"], "PARTIAL")

    def test_error_text_is_redacted_of_scratch_and_input_paths(self):
        leak = f"DECOMPILE_FAILED: could not read {self.target} under {self.scratch}"
        self.fake.entries = [_entry("140001000"), _failed("140002000", leak)]
        data = self.decompile(["0x140001000", "0x140002000"])
        text = json.dumps(data)
        self.assertNotIn(str(self.target), text)
        self.assertNotIn(str(self.scratch), text)
        self.assertIn("<INPUT>", data["functions"][1]["error"])

    def test_result_that_does_not_match_the_request_is_refused(self):
        self.fake.entries = [_entry("140001000")]
        data = self.decompile(["0x140001000", "0x140002000"])
        self.assertEqual((data["ok"], data["status"], data["error"]),
                         (False, "ANALYSIS_LIMITED", "GHIDRA_RESULT_CONTRACT_VIOLATION"))
        self.assertNotIn("c_code", json.dumps(data))
        self.fake.entries = None
        self.fake.result = {"schema": 1, "functions": "nope", "script_completed": True}
        data = self.decompile()
        self.assertEqual(data["error"], "GHIDRA_RESULT_CONTRACT_VIOLATION")

    def test_result_file_problems_are_refusals(self):
        cases = {
            "GHIDRA_RESULT_NOT_JSON": "{not json",
            "GHIDRA_RESULT_NOT_AN_OBJECT": "[1]",
            "GHIDRA_RESULT_INCOMPLETE": json.dumps({"schema": 1, "functions": []}),
            "GHIDRA_RESULT_SCHEMA_MISMATCH": json.dumps({"schema": 2, "functions": [], "script_completed": True}),
            "GHIDRA_RESULT_CONTRACT_VIOLATION": json.dumps({"schema": 1, "script_completed": True}),
        }
        for error, body in cases.items():
            with self.subTest(error=error):
                self.fake.raw_result = body
                data = self.decompile()
                self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", error))
        self.fake.raw_result = None
        self.fake.write_result = False
        self.assertEqual(self.decompile()["error"], "GHIDRA_NO_RESULT_FILE")

    def test_exit_zero_with_script_error_is_a_refusal(self):
        self.fake.log = CLEAN_LOG + "ERROR REPORT SCRIPT ERROR: DecompileFunctions.java : boom\n"
        data = self.decompile()
        self.assertEqual((data["ok"], data["error"]), (False, "GHIDRA_FAILURE_MARKER_IN_LOG"))
        self.assertIn("SCRIPT_ERROR", data["failure_signals"])
        self.assertNotIn("functions", data)

    def test_compile_failure_and_nonzero_exit_are_refusals(self):
        self.fake.log = "DecompileFunctions.java: Unable to compile\n"
        self.assertEqual(self.decompile()["error"], "GHIDRA_FAILURE_MARKER_IN_LOG")
        self.fake.log = CLEAN_LOG
        self.fake.exit_code = 1
        self.assertEqual(self.decompile()["error"], "GHIDRA_EXITED_NONZERO")

    def test_timeout_cancellation_and_lock_are_reported_like_the_facts_operation(self):
        self.fake.timed_out = True
        data = self.decompile(timeout_seconds=40)
        self.assertEqual((data["status"], data["error"]), ("TIMEOUT", "GHIDRA_TIMEOUT_PROCESS_TREE_TERMINATED"))
        self.assertEqual(data["invocation"]["timeout_seconds"], 40)
        self.fake.timed_out, self.fake.cancelled = False, True
        self.assertEqual(self.decompile()["status"], "CANCELLED")
        self.fake.cancelled = False
        self.fake.log = CLEAN_LOG + "LockException: Unable to lock project\n"
        self.assertEqual(self.decompile()["status"], "PROJECT_LOCKED")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_a_launcher_that_cannot_start_is_a_structured_refusal(self):
        self.fake.launch_error = OSError("blocked")
        data = self.decompile()
        self.assertEqual((data["status"], data["error"]), ("ENVIRONMENT_ERROR", "GHIDRA_LAUNCH_FAILED"))

    def test_a_source_the_run_modified_is_a_refusal_not_a_success(self):
        self.fake.mutate_source = b"changed during the run"
        data = self.decompile()
        self.assertEqual((data["ok"], data["error"]), (False, "SOURCE_MODIFIED"))
        self.assertNotIn("functions", data)

    def test_the_source_is_reported_unchanged_with_its_hash(self):
        before = hashlib.sha256(self.target.read_bytes()).hexdigest()
        data = self.decompile()
        self.assertEqual(data["source_sha256"], before)
        self.assertIs(data["source_unchanged"], True)
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(), before)

    def test_timeouts_are_derived_and_clamped(self):
        data = self.decompile(["0x1", "0x2"])
        self.assertEqual(data["invocation"]["timeout_seconds"], 300 + 2 * 30)
        self.assertEqual(data["invocation"]["per_function_timeout_seconds"], 30)
        self.assertEqual(data["invocation"]["analysis_timeout_seconds"], int((360 - 60) * 0.6))
        data = self.decompile(["0x1"], per_function_timeout_seconds=1)
        self.assertEqual(data["invocation"]["per_function_timeout_seconds"], 5)
        self.assertEqual(self.fake.script_args[2], "5")
        data = self.decompile(["0x1"], per_function_timeout_seconds=9999)
        self.assertEqual(data["invocation"]["per_function_timeout_seconds"], 120)
        data = self.decompile(["0x1"], per_function_timeout_seconds="junk")
        self.assertEqual(data["invocation"]["per_function_timeout_seconds"], 30)
        data = self.decompile(["0x1"], timeout_seconds=99999)
        self.assertEqual(data["invocation"]["timeout_seconds"], 1800)
        data = self.decompile(["0x1"], timeout_seconds=1)
        self.assertEqual(data["invocation"]["timeout_seconds"], 10)
        data = self.decompile(["0x1"], timeout_seconds="junk")
        self.assertEqual(data["invocation"]["timeout_seconds"], 330)

    def test_concurrent_runs_get_their_own_project_directory(self):
        self.decompile()
        self.decompile()
        self.assertEqual(len(set(self.fake.project_dirs)), 2)

    def test_the_facts_operation_still_uses_the_shared_path(self):
        # the shared helper is the only run path: the facts call must keep its own script and contract
        facts = FakeHeadless()
        with mock.patch.object(tg, "run_bounded_process", facts):
            data = json.loads(tg.ghidra_program_facts(str(self.target)))
        self.assertTrue(data["ok"], data)
        argv = next(a for a, _ in facts.calls if a[1] != "-version")
        self.assertEqual(argv[argv.index("-postScript") + 1], "ProgramFacts.java")


@pytest.mark.contract
class DecompileScriptAndRegistrationTests(unittest.TestCase):
    SOURCE = Path(tg._DECOMPILE_SCRIPT_SOURCE)

    def text(self):
        return self.SOURCE.read_text(encoding="utf-8")

    def test_the_script_is_a_separate_java_data_file_with_the_contract_keys(self):
        self.assertTrue(self.SOURCE.is_file())
        self.assertEqual(self.SOURCE.suffix, ".java")
        self.assertEqual(self.SOURCE.name, tg._DECOMPILE_SCRIPT_NAME)
        text = self.text()
        for needle in ("extends GhidraScript", "getScriptArgs", "script_completed", "DecompInterface",
                       "decompileFunction(", "dispose()", "openProgram(", "getGlobalFunctions(",
                       "getFunctionContaining(", "AMBIGUOUS_FUNCTION_NAME", "FUNCTION_NOT_FOUND",
                       "DECOMPILE_TIMEOUT", "decompileCompleted()"):
            self.assertIn(needle, text)
        for key in tg._DECOMPILE_ENTRY_SPEC:
            self.assertIn(f'\\"{key}\\"', text, key)

    def test_the_script_only_uses_read_apis(self):
        text = self.text()
        code = re.sub(r"//[^\n]*", "", text)
        code = re.sub(r"'(?:[^'\\]|\\.)'", "' '", code)   # char literals first: '"' would open a string
        code = re.sub(r'"(?:[^"\\]|\\.)*"', '""', code)
        for forbidden in ("Transaction", "startTransaction", "endTransaction", "createFunction", "removeFunction",
                          "clearListing", "setName(", "setComment", "setReturnType", "setCustomVariableStorage",
                          "updateFunction", "commitParameters", "commitLocalNames", "createLabel", "createData",
                          "createBookmark", "deleteAddressRange", "analyzeAll", "setAnalysisOption", "importFile",
                          "saveProgram", "ProgramDB", "Runtime", "ProcessBuilder"):
            self.assertNotIn(forbidden, code)
        self.assertIsNone(re.search(r"\.save\w*\(|\.release\(|\.flush\(|\.lock\(", code))
        # every method called on the program, its managers or the decompiler is on this list
        allowed_program = {"getAddressFactory", "getFunctionManager"}
        self.assertLessEqual(set(re.findall(r"currentProgram\s*\.\s*(\w+)\(", code)), allowed_program)
        self.assertLessEqual(set(re.findall(r"\.getFunctionManager\(\)\s*\.\s*(\w+)\(", code)),
                             {"getFunctionContaining"})
        self.assertLessEqual(set(re.findall(r"\bifc\s*\.\s*(\w+)\(", code)),
                             {"setOptions", "openProgram", "getLastMessage", "decompileFunction", "dispose"})
        # no mutating verb on anything else, apart from the collections and the buffers the script builds
        mutators = set(re.findall(r"\.\s*((?:set|create|remove|delete|clear|save|commit|update|apply)\w*)\(", code))
        self.assertLessEqual(mutators, {"setOptions", "setLength"})
        # the only file it writes is the result file it was given
        self.assertEqual(len(re.findall(r"Files\.newBufferedWriter\(", code)), 1)
        self.assertIn("Paths.get(args[0])", code)

    def test_the_script_runs_no_command_and_opens_no_network_connection(self):
        code = self.text()
        for needle in ("java.net", "URL(", "Socket", "exec(", "System.exit", "loadLibrary"):
            self.assertNotIn(needle, code)

    def test_the_script_is_bundled_with_the_package(self):
        pyproject = (Path(tg.__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("ghidra_scripts/*.java", pyproject)

    def test_the_tool_is_registered_and_published(self):
        self.assertIn("ghidra_decompile", tool_families.FAMILIES["native"])
        self.assertIn("ghidra_decompile", tool_families.published_tools("native"))
        self.assertIn("ghidra_decompile", tg._OPERATIONS)
        # it needs more than a path, so it must not be offered as a bare-path call
        self.assertNotIn("ghidra_decompile", tool_families.NATIVE_PATH_ONLY_TOOLS)

    def test_the_cli_command_is_registered(self):
        from liebert_re import cli
        parser = cli._build_parser()
        args = parser.parse_args(["ghidradecompile", "x.exe", "--function", "0x1000", "main",
                                  "--function-timeout", "9", "--timeout", "77"])
        self.assertEqual((args.function, args.function_timeout, args.timeout, args.needs_file),
                         (["0x1000", "main"], 9, 77, True))
        self.assertIsNone(parser.parse_args(["ghidradecompile", "x.exe", "--function", "main"]).timeout)
        with self.assertRaises(SystemExit):
            parser.parse_args(["ghidradecompile", "x.exe"])


@pytest.mark.heavy
class GhidraDecompileRealInstallTests(unittest.TestCase):
    """Decompiles functions of a tiny synthetic x86-64 PE built in code (nothing shipped)."""

    @classmethod
    def setUpClass(cls):
        if not _real_ghidra_usable():
            raise unittest.SkipTest("Ghidra with a suitable Java is not installed")
        from tempfile import TemporaryDirectory
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls._tmp = TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        # start: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret   then a caller: call start; ret
        code = bytes.fromhex("554889e531c05dc3") + b"\x90" * 8 + bytes.fromhex("e8ebffffffc3")
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", code)

    @classmethod
    def tearDownClass(cls):
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()

    def setUp(self):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(tg, "EVIDENCE", self.root / "ev" / "ghidra_program_facts"))
        stack.enter_context(mock.patch.object(tg, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(tg, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(tg, "_evidence_index_record_write", return_value={}))

    def test_a_function_decompiles_and_the_source_is_untouched(self):
        before = hashlib.sha256(self.pe.read_bytes()).hexdigest()
        data = json.loads(tg.ghidra_decompile(str(self.pe), ["0x140001000"], timeout_seconds=600))
        self.assertTrue(data["ok"], data)
        entry = data["functions"][0]
        self.assertIs(entry["decompile_completed"], True, entry)
        self.assertIn("{", entry["c_code"])
        self.assertTrue(entry["address"])
        self.assertEqual(hashlib.sha256(self.pe.read_bytes()).hexdigest(), before)
        self.assertIs(data["source_unchanged"], True)
        self.assertNotIn(str(self.root), json.dumps(data))

    def test_an_unknown_name_and_an_address_outside_every_function_are_reported_not_guessed(self):
        data = json.loads(tg.ghidra_decompile(
            str(self.pe), ["0x140001000", "no_such_function_name", "0x140000010"], timeout_seconds=600))
        self.assertEqual(data["status"], "PARTIAL", data)
        self.assertEqual(len(data["functions"]), 3)
        for entry in data["functions"][1:]:
            self.assertIsNone(entry["c_code"])
            self.assertTrue(entry["error"].startswith("FUNCTION_NOT_FOUND"), entry)
