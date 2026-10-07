"""`liebert_re.tools.ida`: the argument handling, the database cache, the
four-signal success rule, the privacy of what is reported, and the packaged
IDAPython worker.

Fast tier: nothing here starts IDA. `FakeIdat` stands in for `idat.exe` at the
process boundary (`run_bounded_process` is mocked, the pattern of
`test_tools_capa.py`): it reads the job file the wrapper wrote, and writes
what the real tool writes -- `ida.log`, the packed `db.i64` on a first
analysis, and the worker's `result.json`, whose shapes are trimmed captures of
a real IDA 9.4 run. The mocked cases use stand-in input files (the idiom of
the `die` and `rizin` tests), so they run with no IDA, no corpus and no
network. Only `IdaRealInstallTests` needs a licensed IDA and is marked heavy.

The cases that matter most are the ones the wrapper exists to prevent:

* the cache must not grow per call (an analysed database cloned on every
  call would grow disk use without bound);
* success is never read from the exit code alone (a broken script exits 1
  with no database and loose unpacked files; a script that raised before
  writing can still exit 0);
* a query must not change the cached database;
* nothing from IDA's log that identifies the licence or the machine leaves
  the module;
* no symbol-server lookup is asked for.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import sys
import time
import unittest
from contextlib import ExitStack
from importlib.machinery import SourceFileLoader
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import pytest

import liebert_re.report.tool_families as tool_families
import liebert_re.tools.ida as ti
from liebert_re import cli
from liebert_re.bounded_subprocess import BoundedProcessResult

JOB_ENV = "LIEBERT_IDA_JOB"
WORKER_PATH = Path(ti._WORKER_SOURCE)


# --- trimmed captures of what the worker writes on IDA 9.4 -----------------
def _result(operation, sha256, md5, **fields):
    """A worker result file: bookkeeping first, `script_completed` last."""
    body = {"ok": True, "tool": "ida_query", "operation": operation, "items": []}
    body.update(fields)
    body["count"] = len(body["items"])
    body["engine_input_sha256"] = sha256
    body["engine_input_md5"] = md5
    body["script_completed"] = True
    return body


SUMMARY = dict(
    function_count=41, analysis_passes=2, analysis_unstable=False, segment_count=6,
    hexrays_available=True, hexrays_version="9.4.0.260714", processor="metapc", is_64bit=True,
    file_type="Portable executable for AMD64 (PE)", image_base="0x140000000", ida_kernel_version="9.4",
)
FUNCTIONS = [
    {"name": "sub_140001008", "address": "0x140001008", "signature": ""},
    {"name": "sub_140001020", "address": "0x140001020", "signature": "__int64 __fastcall(PVOID P)"},
    {"name": "start", "address": "0x1400024d0", "signature": ""},
]
XREFS = [
    {"from": "0x140001aa8", "from_function": "sub_140001108", "type": 17, "type_name": "Code_Near_Call", "is_call": True},
    {"from": "0x140001b10", "from_function": None, "type": 19, "type_name": "Code_Near_Jump", "is_call": False},
]
DECOMPILED = "__int64 __fastcall sub_140001008(__int64 a1)\n{\n  return 0;\n}\n"

# Log lines of a real run, with the identifying ones built at run time so this
# file carries no licence-shaped string or user path of its own.
_ID = "-".join(["AB12", "CD34", "EF56", "GH78"])
_HOME_NAME = "Someone"
_HOME = "C:" + "\\" + "Users" + "\\" + _HOME_NAME
CLEAN_LOG = (
    "Detected file format: Portable executable for AMD64 (PE)\n"
    "Autoanalysis subsystem has been initialized.\n"
    "  License: " + _ID + "  (1 user)\n"
    "The initial autoanalysis has been finished.\n"
)
DOWNLOAD_LOG = (
    "PDB: using PDBIDA provider\n"
    "PDB: downloading http://symbols.invalid/download/symbols/x.pdb => " + _HOME + "\\AppData\\Local\\Temp\\ida\\x.pdb\n"
)


_OMIT = object()


def _cp(returncode=0, stdout="", stderr="", **flags):
    return BoundedProcessResult(returncode, stdout, stderr, **flags)


class FakeIdat:
    """`idat.exe` at the process boundary.

    `behaviour` is a name, or a callable `(mode, job) -> name`:
      ok / no_output / broken / fatal_log / incomplete / no_db / garbage /
      timeout / cancel / mismatch / script_error / stderr_license
    """

    def __init__(self, sha256, md5, behaviour="ok", log=CLEAN_LOG):
        self.sha256, self.md5 = sha256, md5
        self.behaviour = behaviour
        self.log = log
        self.calls = []       # dicts: command, cwd, job, timeout, environment
        self.fields = {"summary": SUMMARY}
        # What a reopen-mode worker reports about discarding the session's
        # changes: True (the real worker's normal answer), False, or _OMIT.
        self.discard_flag = True
        self.result_operation = None   # override the `operation` the result claims
        self.log_unreadable = False    # make ida.log a directory, so reading it raises OSError

    def __call__(self, command, *, timeout_seconds, cancellation_token=None, cwd=None,
                 environment=None, max_output_chars=None):
        job = json.loads(Path(environment[JOB_ENV]).read_text(encoding="utf-8"))
        self.calls.append({"command": list(command), "cwd": Path(cwd), "job": job,
                           "timeout": timeout_seconds, "environment": dict(environment),
                           "script": (Path(cwd) / ti._JOB_SCRIPT).read_bytes()})
        mode = job["mode"]
        name = self.behaviour(mode, job) if callable(self.behaviour) else self.behaviour
        work = Path(cwd)
        if name == "timeout":
            return _cp(None, timed_out=True)
        if name == "cancel":
            return _cp(None, cancelled=True)
        if self.log_unreadable:
            (work / ti._LOG_NAME).mkdir()
        else:
            (work / ti._LOG_NAME).write_text(self.log, encoding="utf-8")
        if name == "broken":
            for suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
                (work / f"db{suffix}").write_bytes(b"x" * 8)
            return _cp(1, stderr="liebert_ida_job.py: name 'this' is not defined\n")
        if name == "empty_log":
            (work / ti._LOG_NAME).write_text("", encoding="utf-8")
        if name == "fatal_log":
            (work / ti._LOG_NAME).write_text(self.log + "FATAL ERROR: Oops! internal error 1228 occurred.\n", encoding="utf-8")
        if name == "stderr_license":
            return _cp(1, stderr="License: " + _ID + "\nopened " + _HOME + "\\x\n")
        if mode == "create" and name != "no_db":
            (work / ti._DB_NAME).write_bytes(b"IDA-DB" * 100)
        if name == "no_output":
            return _cp(0)
        if name == "garbage":
            (work / ti._RESULT_NAME).write_text("{not json", encoding="utf-8")
            return _cp(0)
        sha = "0" * 64 if name == "mismatch" else self.sha256
        body = self._body(job, sha)
        if name == "incomplete":
            body.pop("script_completed")
        if name == "script_error":
            body = {"ok": False, "tool": "ida_query", "operation": job["operation"], "items": [],
                    "error": "FUNCTION_NOT_FOUND", "engine_input_sha256": sha,
                    "engine_input_md5": self.md5, "script_completed": True}
        if mode == "reopen" and self.discard_flag is not _OMIT:
            body["database_changes_discarded"] = self.discard_flag
        if self.result_operation is not None:
            body["operation"] = self.result_operation
        (work / ti._RESULT_NAME).write_text(json.dumps(body), encoding="utf-8")
        return _cp(0)

    def _body(self, job, sha):
        op = job["operation"]
        extra = dict(self.fields.get(op, {}))
        if op == "list_functions":
            extra.update(items=FUNCTIONS, total_function_count=3, offset=job["offset"],
                         returned_count=3, next_offset=None)
        elif op == "decompile_function":
            extra.update(items=FUNCTIONS[:1], decompiled=DECOMPILED)
        elif op == "xrefs_to":
            extra.update(items=XREFS, resolved_address="0x1400024d0", total_xref_count=2,
                         offset=0, next_offset=None)
        elif op == "function_at_address":
            extra.update(items=FUNCTIONS[:1])
        return _result(op, sha, self.md5, **extra)

    @property
    def modes(self):
        return [c["job"]["mode"] for c in self.calls]


class IdaCase(unittest.TestCase):
    """A stand-in input, a private cache and evidence directory, and a fake idat."""

    behaviour = "ok"

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.sample = self.root / "sample.exe"
        self.sample.write_bytes(b"MZ" + bytes(range(64)))
        self.sha, self.md5 = ti._sha256_md5(self.sample)
        self.cache = self.root / "cache"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.fake = FakeIdat(self.sha, self.md5, self.behaviour)
        stack = ExitStack()
        self.addCleanup(stack.close)
        for target, kwargs in (
            (mock.patch.object(ti, "CACHE_ROOT", self.cache), {}),
            (mock.patch.object(ti, "EVIDENCE", self.evidence), {}),
            (mock.patch.object(ti, "_ida_binary", return_value="C:/fake/idat.exe"), {}),
            (mock.patch.object(ti, "safe_path", side_effect=lambda p: Path(p)), {}),
            (mock.patch.object(ti, "relative", side_effect=lambda p: Path(p).name), {}),
            (mock.patch.object(ti, "_evidence_index_record_write", return_value={"ok": True}), {}),
            (mock.patch.object(ti, "run_bounded_process", side_effect=self.fake), {}),
        ):
            stack.enter_context(target)

    def q(self, operation="summary", query="", path=None, **kwargs):
        return json.loads(ti.ida_query(str(path or self.sample), operation, query, **kwargs))

    def slots(self):
        if not self.cache.is_dir():
            return []
        return sorted(p for p in self.cache.iterdir() if p.is_dir() and ti._SLOT_NAME.match(p.name))

    def leftovers(self):
        return [p for p in self.cache.rglob("*") if p.name.startswith("work-")] if self.cache.is_dir() else []


# ---------------------------------------------------------------------------
# resolution, availability, argument checks
# ---------------------------------------------------------------------------
class AvailabilityTests(unittest.TestCase):
    @pytest.mark.contract
    def test_missing_binary_returns_tool_missing_for_both_operations(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=(None, None)):
            for name, call in (("ida_query", lambda: ti.ida_query("x")), ("ida_status", ti.ida_status)):
                data = json.loads(call())
                self.assertFalse(data["ok"], name)
                self.assertEqual(data["status"], "TOOL_MISSING", name)
                self.assertEqual(data["tool"], name, name)
                self.assertIn("required_capability", data)
                self.assertIn("IDAT_EXE", data["detail"], name)
                self.assertIn("IDA_HOME", data["detail"], name)
            self.assertFalse(ti.ida_available())

    def test_resolution_order_is_env_then_home_then_path_then_known_install(self):
        with TemporaryDirectory() as td:
            base = Path(td)
            explicit = base / "explicit" / "idat.exe"
            home = base / "home"
            for f in (explicit, home / "idat.exe"):
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(b"")
            env = {"IDAT_EXE": str(explicit), "IDA_HOME": str(home)}
            with mock.patch.dict(os.environ, env), mock.patch.object(ti.shutil, "which", return_value="/on/path/idat"):
                self.assertEqual(ti._resolved_by_and_binary(), ("IDAT_EXE", str(explicit)))
            with mock.patch.dict(os.environ, {"IDAT_EXE": str(explicit.parent), "IDA_HOME": ""}):
                self.assertEqual(ti._resolved_by_and_binary()[1], str(explicit))   # a folder is accepted
            with mock.patch.dict(os.environ, {"IDAT_EXE": "", "IDA_HOME": str(home)}), \
                 mock.patch.object(ti.shutil, "which", return_value="/on/path/idat"):
                self.assertEqual(ti._resolved_by_and_binary(), ("IDA_HOME", str(home / "idat.exe")))
            with mock.patch.dict(os.environ, {"IDAT_EXE": "", "IDA_HOME": ""}), \
                 mock.patch.object(ti.shutil, "which", return_value="/on/path/idat"):
                self.assertEqual(ti._resolved_by_and_binary(), ("PATH", "/on/path/idat"))
            install = base / "Program Files" / "IDA Professional 9.9"
            install.mkdir(parents=True)
            (install / "idat.exe").write_bytes(b"")
            with mock.patch.dict(os.environ, {"IDAT_EXE": "", "IDA_HOME": "", "ProgramFiles": str(base / "Program Files")}), \
                 mock.patch.object(ti.shutil, "which", return_value=None):
                self.assertEqual(ti._resolved_by_and_binary()[0], "known_install")

    @pytest.mark.contract
    def test_resolution_never_raises_when_nothing_is_there(self):
        with mock.patch.dict(os.environ, {"IDAT_EXE": "Z:/nowhere/idat.exe", "IDA_HOME": "Z:/nowhere", "ProgramFiles": "Z:/nowhere"}), \
             mock.patch.object(ti.shutil, "which", return_value=None):
            result = ti._resolved_by_and_binary()
        self.assertIn(result[0], (None, "known_install"))


class ArgumentTests(IdaCase):
    @pytest.mark.contract
    def test_nonexistent_path_returns_not_found_before_any_subprocess_call(self):
        data = json.loads(ti.ida_query(str(self.root / "no_such_file.exe")))
        self.assertEqual(data["status"], "NOT_FOUND")
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_path_outside_the_workspace_is_refused_before_any_subprocess_call(self):
        with mock.patch.object(ti, "safe_path", side_effect=PermissionError("outside the workspace")):
            data = json.loads(ti.ida_query(str(self.sample)))
        self.assertEqual(data["status"], "PATH_REFUSED")
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_unknown_operation_is_refused_and_lists_what_is_accepted(self):
        data = self.q("rename")      # a write operation is not part of this module
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "UNKNOWN_OPERATION")
        self.assertIn("decompile_function", data["accepted"])
        self.assertNotIn("rename", data["accepted"])
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_a_database_file_is_refused_as_input(self):
        """Cloning an already-analysed database into the cache on every call
        grows disk use without bound; IDA also rewrites a database on every open."""
        for name in ("old.i64", "old.idb", "old.id0"):
            db = self.root / name
            db.write_bytes(b"x")
            data = self.q(path=db)
            self.assertEqual(data["error"], "DATABASE_INPUT_NOT_SUPPORTED", name)
            self.assertEqual(data["status"], "ANALYSIS_LIMITED", name)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.slots(), [])

    def test_timeout_and_result_limits_are_clamped(self):
        self.q(timeout_seconds=1, max_results=10 ** 6, offset=-5)
        call = self.fake.calls[0]
        self.assertEqual(call["timeout"], ti._MIN_TIMEOUT_SECONDS)
        self.assertEqual(call["job"]["max_results"], 1000)
        self.assertEqual(call["job"]["offset"], 0)
        self.assertEqual(ti._MIN_TIMEOUT_SECONDS, 5)
        self.assertEqual(ti._MAX_QUERY_TIMEOUT_SECONDS, 300)
        self.assertEqual(ti._MAX_CREATE_TIMEOUT_SECONDS, 600)

    def test_first_analysis_may_use_600_but_the_question_session_never_exceeds_300(self):
        # first call: create session (summary) then the reopen session that answers.
        self.q("list_functions", timeout_seconds=10 ** 6)
        create, reopen = self.fake.calls[0], self.fake.calls[1]
        self.assertEqual(create["timeout"], 600)
        self.assertLessEqual(reopen["timeout"], 300)
        # a cache hit: only the question session runs, and it is capped at 300
        self.fake.calls.clear()
        self.q("list_functions", timeout_seconds=10 ** 6)
        self.assertEqual(len(self.fake.calls), 1)
        self.assertEqual(self.fake.calls[0]["timeout"], 300)

    def test_a_create_timeout_names_the_stage_and_its_ceiling(self):
        self.fake.behaviour = "timeout"
        data = self.q(timeout_seconds=10 ** 6)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(data["timed_out_stage"], "analysis")
        self.assertEqual(data["stage_ceiling_seconds"], 600)
        self.assertEqual(data["timeout_seconds"], 600)

    def test_signatures_match_the_routing_manifest(self):
        """tool_families treats ida_query as path-only (nothing else required)
        and ida_status as zero-argument."""
        required = [n for n, p in inspect.signature(ti.ida_query).parameters.items()
                    if p.default is inspect.Parameter.empty]
        self.assertEqual(required, ["path"])
        self.assertEqual(list(inspect.signature(ti.ida_status).parameters), [])


# ---------------------------------------------------------------------------
# the command line that reaches idat
# ---------------------------------------------------------------------------
class InvocationTests(IdaCase):
    def test_first_analysis_command_line(self):
        self.q("summary")
        call = self.fake.calls[0]
        command = call["command"]
        self.assertEqual(command[0], "C:/fake/idat.exe")
        for flag in ("-A", "-c", "-Opdb:off", f"-L{ti._LOG_NAME}", f"-o{ti._DB_NAME}", f"-S{ti._JOB_SCRIPT}"):
            self.assertIn(flag, command)
        self.assertEqual(command[-1], str(self.sample))
        self.assertTrue(call["cwd"].name.startswith("work-"))
        self.assertEqual(call["cwd"].parent, self.slots()[0])

    def test_reopen_command_line_has_no_new_database_switches(self):
        self.q("summary")
        self.q("list_functions")
        command = self.fake.calls[-1]["command"]
        self.assertEqual(self.fake.calls[-1]["job"]["mode"], "reopen")
        self.assertIn("-Opdb:off", command)
        self.assertNotIn("-c", command)    # `-o`/`-c` with an existing database is a hard error in idat
        self.assertFalse(any(a.startswith("-o") for a in command))
        self.assertEqual(command[-1], str(self.slots()[0] / ti._DB_NAME))

    def test_pdb_lookup_is_switched_off_on_every_launch(self):
        self.q("decompile_function", "0x140001008")      # first analysis and the question
        self.q("xrefs_to", "start")
        self.assertGreaterEqual(len(self.fake.calls), 3)
        for call in self.fake.calls:
            self.assertIn("-Opdb:off", call["command"])
        summary = self.q("summary")
        declared = summary["pdb_lookup_declared"]
        self.assertEqual(declared["declared"], "off")
        self.assertIn("declaration", declared["basis"])
        self.assertNotIn("pdb_lookup", summary)   # no bare status-looking field

    def test_query_travels_in_the_job_file_not_in_the_command_line(self):
        hostile = 'a "quoted" name with spaces & $(braces)'
        self.q("function_at_address", hostile)
        for call in self.fake.calls:
            self.assertFalse(any("quoted" in arg for arg in call["command"]), call["command"])
        self.assertEqual(self.fake.calls[-1]["job"]["query"], hostile)
        self.assertEqual(self.fake.calls[-1]["job"]["operation"], "function_at_address")

    def test_job_environment_keeps_the_callers_environment(self):
        with mock.patch.dict(os.environ, {"LIEBERT_TEST_MARKER": "kept"}):
            self.q("summary")
        env = self.fake.calls[0]["environment"]
        self.assertEqual(env["LIEBERT_TEST_MARKER"], "kept")
        self.assertIn(JOB_ENV, env)

    def test_first_call_is_two_sessions_for_a_question_and_one_for_summary(self):
        self.q("decompile_function", "start")
        self.assertEqual(self.fake.modes, ["create", "reopen"])
        self.assertEqual(self.fake.calls[0]["job"]["operation"], "summary")   # create only ever analyses
        self.assertEqual(self.fake.calls[1]["job"]["operation"], "decompile_function")
        self.fake.calls.clear()
        self.q("decompile_function", "start")
        self.assertEqual(self.fake.modes, ["reopen"])

    def test_summary_on_a_first_analysis_is_one_session(self):
        data = self.q("summary")
        self.assertEqual(self.fake.modes, ["create"])
        self.assertEqual(data["database_cache"], "CREATED")

    def test_second_session_gets_only_the_time_that_is_left(self):
        times = iter([100.0, 100.0, 140.0])       # lock wait, deadline, then 40 s later
        clock = SimpleNamespace(monotonic=lambda: next(times, 140.0), time=time.time, sleep=time.sleep)
        with mock.patch.object(ti, "time", clock):
            self.q("xrefs_to", "start", timeout_seconds=60)
        self.assertEqual(self.fake.calls[0]["timeout"], 60)
        self.assertLessEqual(self.fake.calls[1]["timeout"], 25)


# ---------------------------------------------------------------------------
# the cache
# ---------------------------------------------------------------------------
class CacheTests(IdaCase):
    def test_slot_is_named_by_the_inputs_sha256(self):
        self.q()
        (slot,) = self.slots()
        self.assertEqual(slot.name, ti._slot_dir(self.sha).name)
        self.assertEqual(sorted(p.name for p in slot.iterdir()), ["db.i64", "meta.json"])

    def test_first_call_creates_later_calls_hit(self):
        self.assertEqual(self.q()["database_cache"], "CREATED")
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")
        self.assertEqual(self.q("segments")["database_cache"], "HIT")
        self.assertEqual(self.fake.modes, ["create", "reopen", "reopen"])

    def test_the_same_bytes_under_another_name_share_one_slot(self):
        self.q()
        twin = self.root / "renamed_copy.bin"
        twin.write_bytes(self.sample.read_bytes())
        data = self.q("list_functions", path=twin)
        self.assertEqual(data["database_cache"], "HIT")
        self.assertEqual(len(self.slots()), 1)

    def test_different_bytes_get_their_own_slot(self):
        self.q()
        other = self.root / "other.exe"
        other.write_bytes(self.sample.read_bytes() + b"\0")
        self.fake.sha256, self.fake.md5 = ti._sha256_md5(other)
        self.assertEqual(self.q(path=other)["database_cache"], "CREATED")
        self.assertEqual(len(self.slots()), 2)

    def test_repeated_calls_never_grow_the_cache(self):
        """The regression itself: one input, many calls, one database."""
        def database_bytes():       # meta.json is a few bytes that vary with the timestamp text
            return sum(p.stat().st_size for p in self.cache.rglob("*.i64"))

        self.q("summary")
        db = self.slots()[0] / ti._DB_NAME
        size = database_bytes()
        for i in range(25):
            self.q(("list_functions", "segments", "xrefs_to", "strings")[i % 4], "start")
        self.assertEqual(len(self.slots()), 1)
        self.assertEqual(database_bytes(), size)
        self.assertEqual(sorted(p.name for p in self.cache.rglob("*") if p.is_file() and p.suffix == ".i64"), ["db.i64"])
        self.assertTrue(db.is_file())
        self.assertEqual(self.leftovers(), [])

    def test_a_query_never_modifies_the_cached_database(self):
        self.q("summary")
        db = self.slots()[0] / ti._DB_NAME
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        self.q("decompile_function", "start")
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_every_session_starts_from_a_clean_scratch_directory_that_is_removed(self):
        self.q("decompile_function", "start")
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(len({c["cwd"] for c in self.fake.calls}), 2)

    def _fake_slot(self, key, size, used):
        slot = self.cache / f"{key * 64}.{ti._ANALYSIS_PROFILE}"
        slot.mkdir(parents=True)
        (slot / ti._DB_NAME).write_bytes(b"x" * size)
        (slot / "meta.json").write_text("{}")
        os.utime(slot / "meta.json", (used, used))
        return slot

    def test_budget_evicts_least_recently_used_whole_slots(self):
        oldest, middle, newest = (self._fake_slot("a", 100, 1000), self._fake_slot("b", 100, 2000),
                                  self._fake_slot("c", 100, 3000))
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "250"}):
            evicted, freed, budget = ti._enforce_cache_budget(keep=newest)
        self.assertEqual(evicted, [oldest.name])
        self.assertEqual((freed, budget), (102, 250))
        self.assertFalse(oldest.exists())
        self.assertTrue(middle.is_dir() and newest.is_dir())

    def test_eviction_is_reported_in_the_response_that_caused_it(self):
        old = self._fake_slot("e", 5000, 1000)
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "3000"}):
            data = self.q()
        self.assertEqual(data["cache_evicted_slots"], [old.name])
        self.assertEqual(data["cache_budget_bytes"], 3000)
        self.assertEqual(len(self.slots()), 1)
        self.assertEqual(self.slots()[0].name, ti._slot_dir(self.sha).name)

    def test_the_slot_in_use_is_never_evicted_even_over_budget(self):
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "1"}):
            data = self.q()
        self.assertTrue(data["ok"])
        self.assertEqual(len(self.slots()), 1)

    def test_recently_used_and_locked_slots_survive_eviction(self):
        self._fake_slot("a", 100, 1000)
        locked = self._fake_slot("b", 100, 1000)
        ti._lock_path(locked).write_text("{}")                  # a live lock
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "10"}):
            evicted, freed, budget = ti._enforce_cache_budget(keep=self.cache / "keep")
        self.assertEqual([n.split(".")[0] for n in evicted], ["a" * 64])
        self.assertTrue(locked.is_dir())
        self.assertEqual((freed, budget), (100 + len("{}"), 10))
        # and a slot used a moment ago is not touched at all
        fresh = self.cache / f"{'c' * 64}.{ti._ANALYSIS_PROFILE}"
        fresh.mkdir()
        (fresh / ti._DB_NAME).write_bytes(b"x" * 100)
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "10"}):
            ti._enforce_cache_budget(keep=self.cache / "keep")
        self.assertTrue(fresh.is_dir())

    def test_files_that_are_not_slots_are_ignored_by_eviction(self):
        self.cache.mkdir()
        stray = self.cache / "notes.txt"
        stray.write_text("keep me")
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "1"}):
            ti._enforce_cache_budget(keep=self.cache / "x")
        self.assertTrue(stray.is_file())

    def test_a_slot_with_loose_components_is_rebuilt_not_reopened(self):
        """Reopening a database next to unpacked components was observed to crash idat."""
        self.q()
        slot = self.slots()[0]
        (slot / "db.id0").write_bytes(b"residue")
        data = self.q("list_functions")
        self.assertEqual(data["database_cache"], "REBUILT")
        self.assertEqual(self.fake.modes, ["create", "create", "reopen"])
        self.assertFalse((self.slots()[0] / "db.id0").exists())

    def test_abandoned_scratch_directories_are_swept_under_the_lock(self):
        self.q()
        stale = self.slots()[0] / "work-deadbeef"
        stale.mkdir()
        (stale / "junk").write_bytes(b"x")
        self.q("segments")
        self.assertFalse(stale.exists())

    def test_cache_budget_variable_is_parsed_defensively(self):
        for raw, expected in (("", ti._CACHE_BUDGET_DEFAULT), ("junk", ti._CACHE_BUDGET_DEFAULT),
                              ("0", 1), ("1000", 1000)):
            with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": raw}):
                self.assertEqual(ti._cache_budget_bytes(), expected, raw)
        self.assertEqual(ti._CACHE_BUDGET_DEFAULT, 5 * 1024 ** 3)


class EngineKeyTests(IdaCase):
    """The cache key carries the analysis engine: an updated idat must not reuse an old database."""

    def _engine(self, size):
        exe = self.root / "ida_home" / "idat.exe"
        exe.parent.mkdir(exist_ok=True)
        exe.write_bytes(b"\0" * size)
        return exe

    def test_tag_changes_when_the_engine_binary_changes_and_is_stable_otherwise(self):
        exe = self._engine(100)
        first = ti._engine_tag(str(exe))
        self.assertEqual(first, ti._engine_tag(str(exe)))
        self.assertRegex(first, r"^e[0-9a-f]{10}$")
        exe = self._engine(101)
        without_kernel = ti._engine_tag(str(exe))
        self.assertNotEqual(first, without_kernel)
        (exe.parent / "ida.dll").write_bytes(b"k")
        self.assertNotEqual(without_kernel, ti._engine_tag(str(exe)))

    @pytest.mark.contract
    def test_an_unreadable_engine_gives_a_fixed_tag_not_an_exception(self):
        self.assertEqual(ti._engine_tag(None), "unversioned")
        self.assertEqual(ti._engine_tag(str(self.root / "no" / "idat.exe")), "unversioned")

    def test_a_new_engine_builds_a_new_slot_instead_of_reusing_the_old_database(self):
        with mock.patch.object(ti, "_ida_binary", return_value=str(self._engine(100))):
            self.assertEqual(self.q()["database_cache"], "CREATED")
            self.assertEqual(self.q()["database_cache"], "HIT")
        with mock.patch.object(ti, "_ida_binary", return_value=str(self._engine(200))):
            self.assertEqual(self.q()["database_cache"], "CREATED")
        names = [p.name for p in self.slots()]
        self.assertEqual(len(names), 2)
        self.assertTrue(all(n.startswith(f"{self.sha}.{ti._ANALYSIS_PROFILE}.e") for n in names))


class SlotLockTests(IdaCase):
    def test_a_live_lock_held_by_another_process_reports_busy(self):
        slot = ti._slot_dir(self.sha)
        slot.parent.mkdir(parents=True)
        ti._lock_path(slot).write_text("{}")
        with mock.patch.object(ti, "_LOCK_WAIT_SECONDS", 0.3):
            data = self.q()
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "IDA_CACHE_SLOT_BUSY")
        self.assertEqual(self.fake.calls, [])

    def test_a_stale_lock_is_taken_over(self):
        slot = ti._slot_dir(self.sha)
        slot.parent.mkdir(parents=True)
        lock = ti._lock_path(slot)
        lock.write_text("{}")
        old = time.time() - ti._LOCK_STALE_SECONDS - 10
        os.utime(lock, (old, old))
        self.assertTrue(self.q()["ok"])
        self.assertFalse(lock.exists())          # released afterwards

    def test_the_lock_is_released_when_the_session_fails(self):
        self.fake.behaviour = "broken"
        self.q()
        self.assertFalse(ti._lock_path(ti._slot_dir(self.sha)).exists())


# ---------------------------------------------------------------------------
# success is read from four signals, never from the exit code
# ---------------------------------------------------------------------------
class FourSignalTests(IdaCase):
    def assertLimited(self, data, error):
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED", data)
        self.assertEqual(data["error"], error, data)
        self.assertIn("signals", data)
        self.assertEqual(self.slots(), [], "a failed first analysis must leave no slot")
        self.assertEqual(self.leftovers(), [], "and no scratch directory")

    @pytest.mark.contract
    def test_a_broken_script_exits_1_leaves_loose_components_and_is_discarded(self):
        self.fake.behaviour = "broken"
        data = self.q()
        self.assertLimited(data, "IDA_EXITED_NONZERO")
        self.assertEqual(data["signals"]["exit_code"], 1)
        self.assertFalse(data["signals"]["database_present"])
        self.assertIn("db.id0", data["signals"]["loose_components"])
        self.assertIn("not defined", data["stderr_tail"])
        self.assertEqual(list(self.cache.rglob("*.id0")), [])

    @pytest.mark.contract
    def test_exit_zero_without_a_result_file_is_not_success(self):
        self.fake.behaviour = "no_output"
        data = self.q()
        self.assertLimited(data, "IDA_NO_OUTPUT")
        self.assertEqual(data["signals"]["exit_code"], 0)
        self.assertFalse(data["signals"]["result_file_present"])

    @pytest.mark.contract
    def test_exit_zero_with_a_fatal_log_line_is_not_success(self):
        self.fake.behaviour = "fatal_log"
        data = self.q()
        self.assertLimited(data, "IDA_LOG_REPORTS_FAILURE")
        self.assertIn("fatal error", data["signals"]["log_fatal_markers"])

    @pytest.mark.contract
    def test_a_result_file_without_the_completion_marker_is_not_success(self):
        self.fake.behaviour = "incomplete"
        data = self.q()
        self.assertLimited(data, "IDA_OUTPUT_INCOMPLETE")
        self.assertFalse(data["signals"]["result_script_completed"])

    @pytest.mark.contract
    def test_a_first_analysis_that_produced_no_database_is_not_success(self):
        """Seen when a session marks a new database temporary: exit 0, a good
        result file, and no .i64 at all."""
        self.fake.behaviour = "no_db"
        self.assertLimited(self.q(), "IDA_NO_DATABASE")

    @pytest.mark.contract
    def test_unparseable_result_json_is_a_parse_failure(self):
        self.fake.behaviour = "garbage"
        data = self.q()
        self.assertEqual(data["status"], "RESULT_PARSE_FAILED")
        self.assertIn("parse_error", data["signals"])
        self.assertEqual(self.slots(), [])

    def test_every_signal_agreeing_is_the_only_success(self):
        data = self.q()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "OK")
        s = data["signals"]
        self.assertEqual((s["exit_code"], s["log_fatal_markers"], s["loose_components"]), (0, [], []))
        self.assertTrue(s["database_present"] and s["result_file_present"] and s["result_script_completed"])

    @pytest.mark.contract
    def test_a_failed_reopen_discards_the_slot_because_the_database_may_be_half_written(self):
        self.q()
        self.assertEqual(len(self.slots()), 1)
        self.fake.behaviour = "no_output"
        data = self.q("list_functions")
        self.assertEqual(data["error"], "IDA_NO_OUTPUT")
        self.assertEqual(self.slots(), [])
        self.fake.behaviour = "ok"
        self.assertEqual(self.q("list_functions")["database_cache"], "CREATED")

    @pytest.mark.contract
    def test_a_worker_that_answers_no_is_not_a_cache_failure(self):
        self.q()
        self.fake.behaviour = "script_error"
        data = self.q("function_at_address", "no_such_symbol")
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "FUNCTION_NOT_FOUND")
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(len(self.slots()), 1)       # the database is fine
        self.fake.behaviour = "ok"
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")

    @pytest.mark.contract
    def test_timeout_says_not_to_read_it_as_nothing_found_and_keeps_nothing(self):
        self.fake.behaviour = "timeout"
        data = self.q(timeout_seconds=60)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(data["timeout_seconds"], 60)
        self.assertIn("nothing found", data["detail"])
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])

    @pytest.mark.contract
    def test_cancellation_is_its_own_status(self):
        self.fake.behaviour = "cancel"
        data = self.q()
        self.assertEqual(data["status"], "CANCELLED")
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_a_timeout_on_reopen_discards_the_slot(self):
        self.q()
        self.fake.behaviour = "timeout"
        self.assertEqual(self.q("list_functions")["status"], "TIMEOUT")
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_input_identity_mismatch_is_refused_and_the_slot_dropped(self):
        self.fake.behaviour = "mismatch"
        data = self.q()
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "IDA_INPUT_HASH_MISMATCH")
        self.assertEqual(data["provenance"]["status"], "MISMATCH")
        self.assertEqual(self.slots(), [])

    def test_provenance_is_verified_or_honestly_unverifiable(self):
        self.assertEqual(self.q()["provenance"]["status"], "VERIFIED")
        prov = ti._provenance(self.sha, self.md5, {"engine_input_sha256": None, "engine_input_md5": None})
        self.assertEqual(prov["status"], "UNVERIFIABLE")
        self.assertEqual(ti._provenance(self.sha, self.md5, {"engine_input_md5": self.md5})["status"], "VERIFIED")

    @pytest.mark.contract
    def test_a_missing_packaged_worker_is_reported_not_raised(self):
        with mock.patch.object(ti, "_WORKER_SOURCE", self.root / "absent.idapy"):
            data = self.q()
        self.assertEqual(data["error"], "IDA_WORKER_MISSING")
        self.assertEqual(self.fake.calls, [])


# ---------------------------------------------------------------------------
# what is returned, and what is saved
# ---------------------------------------------------------------------------
class ResultTests(IdaCase):
    def test_summary_carries_the_worker_fields_and_the_envelope(self):
        data = self.q()
        self.assertEqual((data["tool"], data["operation"], data["target_sha256"]), ("ida_query", "summary", self.sha))
        self.assertEqual(data["function_count"], 41)
        self.assertTrue(data["hexrays_available"])
        self.assertEqual(data["path"], "sample.exe")
        self.assertEqual(data["invocation"]["operation"], "summary")
        for key in ("engine_input_sha256", "script_completed", "engine_input_md5"):
            self.assertNotIn(key, data)       # worker bookkeeping is not part of the answer

    def test_list_functions_keeps_paging_fields(self):
        data = self.q("list_functions", max_results=3, offset=0)
        self.assertEqual([f["name"] for f in data["items"]], ["sub_140001008", "sub_140001020", "start"])
        self.assertEqual(data["total_function_count"], 3)
        self.assertIsNone(data["next_offset"])

    def test_decompile_returns_pseudocode(self):
        data = self.q("decompile_function", "0x140001008")
        self.assertEqual(data["decompiled"], DECOMPILED)

    def test_xrefs_distinguish_calls_from_jumps(self):
        data = self.q("xrefs_to", "start")
        self.assertEqual([x["is_call"] for x in data["items"]], [True, False])

    def test_every_response_is_a_json_string(self):
        self.assertIsInstance(ti.ida_query(str(self.sample)), str)
        self.assertIsInstance(ti.ida_query(str(self.sample), "nope"), str)

    def test_evidence_is_the_raw_worker_output_with_a_conventional_name(self):
        data = self.q("list_functions")
        name = data["internal_evidence_name"]
        self.assertRegex(name, r"^sample_[0-9a-f]{8}_list_functions\.json$")
        saved = json.loads((self.evidence / name).read_text(encoding="utf-8"))
        self.assertEqual(saved["operation"], "list_functions")
        self.assertTrue(saved["script_completed"])                       # raw, not the normalised response
        self.assertEqual(saved["engine_input_sha256"], self.sha)
        self.assertIsNone(data["evidence_write_error"])

    @pytest.mark.contract
    def test_an_evidence_write_failure_is_reported_and_does_not_fail_the_query(self):
        blocker = self.root / "not_a_directory"
        blocker.write_text("x")
        with mock.patch.object(ti, "EVIDENCE", blocker):
            data = self.q("list_functions")
        self.assertTrue(data["ok"])
        self.assertIn("evidence_write_error", data)
        self.assertTrue(data["evidence_write_error"])

    @pytest.mark.contract
    def test_an_evidence_index_failure_never_propagates(self):
        with mock.patch.object(ti, "_evidence_index_record_write", side_effect=RuntimeError("index down")):
            self.assertTrue(self.q("list_functions")["ok"])

    def test_oversized_output_is_trimmed_to_valid_json_and_says_so(self):
        many = [{"name": f"sub_{i:08x}", "address": hex(i), "signature": ""} for i in range(2000)]
        self.q()   # the first call is a `summary` analysis; the patched answer below is a reopen session's
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: _result(
                "list_functions", sha, s.md5, items=many, total_function_count=2000, offset=0,
                returned_count=2000, next_offset=None)):
            raw = ti.ida_query(str(self.sample), "list_functions", max_chars=6000)
        self.assertLessEqual(len(raw), 6000 + 400)
        data = json.loads(raw)                               # still parseable
        self.assertEqual(data["status"], "PARTIAL")
        self.assertTrue(data["truncated"])
        self.assertLess(len(data["items"]), 2000)
        self.assertEqual(data["next_offset"], len(data["items"]))     # where to resume
        self.assertEqual(data["returned_count"], len(data["items"]))
        self.assertTrue(any("max_chars=6000" in item and "ceiling" in item for item in data["limitations"]))
        saved = json.loads((self.evidence / data["internal_evidence_name"]).read_text(encoding="utf-8"))
        self.assertEqual(len(saved["items"]), 2000)          # the evidence file is not trimmed

    def test_long_pseudocode_is_cut_not_corrupted(self):
        huge = "int f(void) {\n" + "  x += 1;\n" * 5000 + "}\n"
        self.q()   # the first call is a `summary` analysis; the patched answer below is a reopen session's
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: _result(
                "decompile_function", sha, s.md5, items=FUNCTIONS[:1], decompiled=huge)):
            data = json.loads(ti.ida_query(str(self.sample), "decompile_function", "f", max_chars=5000))
        self.assertEqual(data["status"], "PARTIAL")
        self.assertLess(len(data["decompiled"]), len(huge))

    def test_a_walk_limit_in_the_worker_is_a_partial_result(self):
        self.q()   # the first call is a `summary` analysis; the patched answer below is a reopen session's
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: _result(
                "strings", sha, s.md5, items=[], items_scanned=50000, items_matched=0,
                walk_limit={"walk": "strings", "reason": "MAX_ITEMS", "items_visited": 50000,
                            "max_items": 50000, "max_seconds": 120.0})):
            data = self.q("strings", "needle")
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "PARTIAL")
        text = " ".join(data["limitations"])
        self.assertIn("item ceiling of 50000", text)       # which ceiling, at what value
        self.assertIn("strings", text)

    def test_a_time_ceiling_is_named_with_its_value(self):
        self.q()   # the first call is a `summary` analysis; the patched answer below is a reopen session's
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: _result(
                "imports_exports", sha, s.md5, items=[], walk_limit={
                    "walk": "imports_exports", "reason": "MAX_SECONDS", "items_visited": 768,
                    "max_items": 50000, "max_seconds": 120.0})):
            data = self.q("imports_exports")
        self.assertEqual(data["status"], "PARTIAL")
        self.assertIn("time ceiling of 120.0 s", " ".join(data["limitations"]))

    def test_the_note_does_not_overclaim(self):
        note = self.q()["note"].lower()
        self.assertIn("not proof of absence", note)
        self.assertIn("symbol-server lookups disabled", note)


# ---------------------------------------------------------------------------
# privacy of what IDA printed
# ---------------------------------------------------------------------------
class RedactionTests(IdaCase):
    def test_licence_line_is_replaced_whatever_follows_it(self):
        out = ti._redact("a\n  License: " + _ID + "  (1 user)\nb\nlicence: " + _ID + "\n")
        self.assertNotIn(_ID, out)
        self.assertIn("License: <REDACTED>", out)
        self.assertEqual(out.count("<REDACTED>"), 2)
        self.assertTrue(out.startswith("a\n") and "\nb\n" in out)        # other lines untouched

    def test_home_directory_paths_and_the_account_name_are_removed(self):
        text = f"loaded {_HOME}\\AppData\\x and {_HOME.replace(chr(92), '/')}/y"
        out = ti._redact(text)
        self.assertNotIn(_HOME_NAME, out)
        self.assertIn("<HOME>", out)
        with mock.patch.object(ti.getpass, "getuser", return_value="zorbax"):
            self.assertNotIn("zorbax", ti._redact("owner zorbax opened it"))

    def test_scratch_and_input_paths_become_tokens(self):
        work, target = Path("/srv/scratch/work-1234abcd"), Path("/srv/samples/real name.exe")
        out = ti._redact(f"Loading file '{target}' in {work}\\ida.log", work=work, target=target)
        self.assertIn("'<INPUT>'", out)
        self.assertIn("<WORK>", out)
        self.assertNotIn("real name", out)

    def test_failure_responses_carry_no_licence_or_user_path(self):
        self.fake.behaviour = "stderr_license"
        self.fake.log = CLEAN_LOG + "opened " + _HOME + "\\AppData\\x\n"
        data = self.q()
        blob = json.dumps(data)
        self.assertNotIn(_ID, blob)
        self.assertNotIn(_HOME_NAME, blob)
        self.assertIn("<REDACTED>", data["log_tail"] + data["stderr_tail"])

    def test_a_pdb_download_in_the_log_is_flagged_without_failing_the_run(self):
        self.fake.log = CLEAN_LOG + DOWNLOAD_LOG
        data = self.q()
        self.assertTrue(data["ok"])
        self.assertTrue(data["signals"]["log_network_text_found"])

    @pytest.mark.contract
    def test_the_log_scan_states_its_markers_and_the_limit_of_its_evidence(self):
        signals = self.q()["signals"]
        self.assertEqual(signals["log_network_text_markers_scanned"], list(ti._NETWORK_MARKERS))
        self.assertIn("not a network observation", signals["log_network_text_evidence_limit"])
        self.assertIn("not detected", signals["log_network_text_evidence_limit"])
        self.assertNotIn("network_lookup_detected", signals)

    def test_a_clean_run_reports_no_network_lookup(self):
        self.assertFalse(self.q()["signals"]["log_network_text_found"])


# ---------------------------------------------------------------------------
# the worker file as shipped
# ---------------------------------------------------------------------------
class WorkerFileTests(IdaCase):
    def test_worker_is_a_data_file_not_a_module(self):
        """It imports IDA's own modules, so it must not be an importable
        `.py` in the package (the wheel smoke test imports every module)."""
        self.assertEqual(WORKER_PATH.suffix, ".idapy")
        self.assertEqual(list(WORKER_PATH.parent.glob("*.py")), [])

    def test_worker_has_no_bom_no_crlf_and_compiles(self):
        raw = WORKER_PATH.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "a BOM makes IDAPython fail on U+FEFF")
        self.assertNotIn(b"\r", raw)
        compile(raw.decode("utf-8"), str(WORKER_PATH), "exec")

    def test_the_copy_handed_to_idat_is_bom_free_even_if_the_source_gained_one(self):
        bom_source = self.root / "bom.idapy"
        bom_source.write_bytes(b"\xef\xbb\xbf" + WORKER_PATH.read_bytes().replace(b"\n", b"\r\n"))
        with mock.patch.object(ti, "_WORKER_SOURCE", bom_source):
            self.q()
        script = self.fake.calls[0]["script"]
        self.assertFalse(script.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", script)
        self.assertEqual(self.fake.calls[0]["command"].count(f"-S{ti._JOB_SCRIPT}"), 1)

    def test_worker_imports_only_the_standard_library_and_ida_modules(self):
        tree = ast.parse(WORKER_PATH.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        stdlib = {"json", "os", "sys", "time", "traceback"}
        ida = {n for n in names if n.startswith("ida") or n == "idc"}
        self.assertEqual(names - stdlib - ida, set())
        self.assertNotIn("liebert_re", names)

    def test_worker_contains_no_write_operation(self):
        """Renaming, commenting, patching and retyping are a separate, later change."""
        source = WORKER_PATH.read_text(encoding="utf-8")
        for api in ("set_name", "set_cmt", "set_func_cmt", "patch_bytes", "rename_lvar", "set_user_cmt",
                    "del_items", "create_insn", "apply_type", "set_type", "del_func", "add_func"):
            self.assertNotIn(api, source, api)


def _load_worker():
    """The worker executed against stub `ida_*` modules (it is only ever run
    inside idat, so this is the one way to test its logic without IDA)."""
    names = ["ida_auto", "ida_bytes", "ida_funcs", "ida_hexrays", "ida_ida", "ida_loader", "ida_name", "ida_nalt",
             "ida_pro", "ida_segment", "ida_xref", "idaapi", "idautils", "idc"]
    stubs = {n: mock.MagicMock(name=n) for n in names}
    stubs["ida_xref"].fl_CF, stubs["ida_xref"].fl_CN = 16, 17
    stubs["ida_xref"].fl_JF, stubs["ida_xref"].fl_JN = 18, 19
    stubs["idc"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["ida_hexrays"].DecompilationFailure = type("DecompilationFailure", (Exception,), {})
    stubs["ida_loader"].DBFL_TEMP = 4
    stubs["ida_hexrays"].get_hexrays_version.return_value = "9.4.0.260714"
    stubs["ida_ida"].inf_get_procname.return_value = "metapc"
    stubs["ida_ida"].inf_is_64bit.return_value = True
    stubs["ida_loader"].get_file_type_name.return_value = "Portable executable for AMD64 (PE)"
    stubs["ida_nalt"].get_imagebase.return_value = 0x140000000
    stubs["ida_nalt"].get_import_module_qty.return_value = 0
    stubs["idaapi"].get_kernel_version.return_value = "9.4"
    with mock.patch.dict(sys.modules, stubs):
        loader = SourceFileLoader("liebert_ida_worker_under_test", str(WORKER_PATH))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    return module, stubs


class WorkerLogicTests(unittest.TestCase):
    def setUp(self):
        self.w, self.ida = _load_worker()
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def run_job(self, **job):
        job.setdefault("operation", "list_functions")
        job.setdefault("mode", "reopen")
        job["output"] = str(self.tmp / "out.json")
        job_file = self.tmp / "job.json"
        job_file.write_text(json.dumps(job), encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job_file)}):
            code = self.w.main()
        out = self.tmp / "out.json"
        return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None

    def test_importing_the_worker_has_no_side_effects(self):
        self.ida["ida_pro"].qexit.assert_not_called()

    def test_budget_trips_on_items_and_reports_where(self):
        budget = self.w._Budget("strings", max_items=3)
        self.assertEqual([budget.tick() for _ in range(3)], [False, False, True])
        info = budget.as_limited()["walk_limit"]
        self.assertEqual((info["walk"], info["reason"], info["items_visited"]), ("strings", "MAX_ITEMS", 3))

    def test_perm_text(self):
        self.assertEqual(self.w._perm_text(5), "r-x")
        self.assertEqual(self.w._perm_text(6), "rw-")

    def test_calls_are_flagged_by_xref_type_and_jumps_are_not_calls(self):
        """fl_CF (16) and fl_CN (17) are calls; fl_JF (18) and fl_JN (19) are
        jumps. An earlier revision treated 18 -- a far jump -- as a call."""
        self.ida["idc"].get_name_ea_simple.return_value = 0x401000
        self.ida["ida_funcs"].get_func.return_value = None
        refs = [SimpleNamespace(frm=0x10 + t, type=t, iscode=True) for t in (16, 17, 18, 19)]
        self.ida["idautils"].XrefsTo.return_value = refs
        self.ida["idautils"].XrefTypeName.side_effect = lambda t: f"type{t}"
        result = {"ok": True, "items": []}
        self.w._op_xrefs_to(result, "target", 100, 0)
        self.assertEqual([x["is_call"] for x in result["items"]], [True, True, False, False])
        self.assertEqual(result["total_xref_count"], 4)
        self.assertIsNone(result["next_offset"])

    def test_xrefs_page_with_next_offset(self):
        self.ida["idc"].get_name_ea_simple.return_value = 0x401000
        self.ida["ida_funcs"].get_func.return_value = None
        self.ida["idautils"].XrefsTo.return_value = [SimpleNamespace(frm=i, type=17, iscode=True) for i in range(5)]
        self.ida["idautils"].XrefTypeName.side_effect = lambda t: "call"
        result = {"ok": True, "items": []}
        self.w._op_xrefs_to(result, "target", 2, 1)
        self.assertEqual([x["from"] for x in result["items"]], ["0x1", "0x2"])
        self.assertEqual(result["next_offset"], 3)

    @pytest.mark.contract
    def test_unresolvable_symbol_is_a_named_error_not_an_exception(self):
        self.ida["idc"].get_name_ea_simple.return_value = self.ida["idc"].BADADDR
        self.ida["idc"].get_segm_name.return_value = ""
        result = {"ok": True, "items": []}
        self.w._op_xrefs_to(result, "0x1", 10, 0)
        self.assertEqual((result["ok"], result["error"]), (False, "SYMBOL_NOT_FOUND"))

    def test_main_writes_an_atomic_result_whose_last_key_is_the_completion_marker(self):
        self.ida["idautils"].Functions.return_value = [0x1000]
        self.ida["ida_name"].get_name.return_value = "start"
        self.ida["idc"].get_type.return_value = None
        self.ida["ida_nalt"].retrieve_input_file_sha256.return_value = bytes.fromhex("ab" * 32)
        self.ida["ida_nalt"].retrieve_input_file_md5.return_value = bytes.fromhex("cd" * 16)
        code, data = self.run_job(operation="list_functions", max_results=10)
        self.assertEqual(code, 0)
        self.assertEqual(list(data)[-1], "script_completed")
        self.assertTrue(data["script_completed"])
        self.assertEqual(data["items"], [{"name": "start", "address": "0x1000", "signature": ""}])
        self.assertEqual(data["engine_input_sha256"], "ab" * 32)
        self.assertEqual(data["engine_input_md5"], "cd" * 16)
        self.assertEqual(list(self.tmp.glob("*.tmp")), [])

    def test_create_session_saves_and_never_marks_the_database_temporary(self):
        """A new database marked temporary is deleted on exit -- measured: no
        .i64 is produced."""
        self.ida["ida_loader"].save_database.return_value = True
        self.run_job(operation="summary", mode="create")
        self.ida["ida_loader"].save_database.assert_called_once()
        self.ida["ida_loader"].set_database_flag.assert_not_called()

    def test_reopen_session_marks_the_database_temporary_and_does_not_save(self):
        self.ida["idautils"].Functions.return_value = []
        _code, data = self.run_job(operation="list_functions", mode="reopen")
        self.ida["ida_loader"].set_database_flag.assert_called_once_with(4)
        self.ida["ida_loader"].save_database.assert_not_called()
        self.assertTrue(data["database_changes_discarded"])

    def test_reopen_reports_when_the_flag_is_unavailable(self):
        self.ida["ida_loader"].set_database_flag.side_effect = AttributeError("older build")
        self.ida["idautils"].Functions.return_value = []
        _code, data = self.run_job(operation="list_functions", mode="reopen")
        self.assertFalse(data["database_changes_discarded"])

    @pytest.mark.contract
    def test_unknown_operation_and_exceptions_still_write_a_completed_result(self):
        code, data = self.run_job(operation="rename")
        self.assertEqual((code, data["error"], data["ok"]), (0, "UNKNOWN_OPERATION", False))
        self.assertIn("segments", data["allowed"])
        self.ida["idautils"].Functions.side_effect = RuntimeError("kernel said no")
        code, data = self.run_job(operation="list_functions")
        self.assertEqual(data["error"], "IDAPYTHON_SCRIPT_EXCEPTION")
        self.assertIn("kernel said no", data["traceback"])
        self.assertTrue(data["script_completed"])

    def test_missing_or_malformed_job_exits_nonzero_without_a_result(self):
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: ""}):
            self.assertEqual(self.w.main(), 2)
        bad = self.tmp / "bad.json"
        bad.write_text("{}", encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(bad)}):
            self.assertEqual(self.w.main(), 2)

    def test_entry_always_quits_idat_even_when_the_job_blows_up(self):
        with mock.patch.object(self.w, "main", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.w._entry()
        self.ida["ida_pro"].qexit.assert_called_once_with(4)
        self.ida["ida_pro"].qexit.reset_mock()
        with mock.patch.object(self.w, "main", return_value=0):
            self.w._entry()
        self.ida["ida_pro"].qexit.assert_called_once_with(0)

    def test_search_filter_is_case_insensitive_and_pages_over_matches(self):
        class Entry:
            def __init__(self, ea, text):
                self.ea, self.length, self.strtype, self.text = ea, len(text), 0, text

            def __str__(self):
                return self.text

        texts = ["Alpha", "beta", "ALPHA two", "gamma", "alpha3"]
        self.ida["idautils"].Strings.return_value = [Entry(0x1000 + i, t) for i, t in enumerate(texts)]
        self.ida["idaapi"].get_fileregion_offset.return_value = 0x200
        self.ida["ida_nalt"].get_imagebase.return_value = 0x400000
        self.ida["idc"].get_segm_name.return_value = ".rdata"
        result = {"ok": True, "items": []}
        self.w._op_strings(result, "alpha", 2, 1)
        self.assertEqual([i["value"] for i in result["items"]], ["ALPHA two", "alpha3"])
        self.assertEqual((result["items_scanned"], result["items_matched"]), (5, 3))


# ---------------------------------------------------------------------------
# ida_status
# ---------------------------------------------------------------------------
class StatusTests(IdaCase):
    def status(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            return json.loads(ti.ida_status())

    def _lumina(self, behaviour):
        if isinstance(behaviour, Exception):
            def query(key, name):
                raise behaviour
        else:
            def query(key, name):
                return behaviour, 4
        fake = SimpleNamespace(
            HKEY_CURRENT_USER=object(),
            OpenKey=lambda root, sub: mock.MagicMock(),
            QueryValueEx=query,
        )
        with mock.patch.dict(sys.modules, {"winreg": fake}):
            return self.status()

    @pytest.mark.contract
    def test_lumina_zero_is_reported_as_off_without_a_warning(self):
        data = self._lumina(0)
        lum = data["lumina_config"]
        self.assertEqual((lum["measurement"], lum["value"], lum["auto_lumina"]), ("MEASURED", 0, "off"))
        self.assertIsNone(lum["warning"])
        self.assertEqual(data["warnings"], [])
        self.assertIn("not an observation", lum["kind"])

    @pytest.mark.contract
    def test_lumina_nonzero_is_a_visible_warning(self):
        data = self._lumina(1)
        self.assertEqual(data["lumina_config"]["auto_lumina"], "on")
        self.assertEqual(len(data["warnings"]), 1)
        self.assertIn("AutoUseLumina", data["warnings"][0])
        self.assertIn("MD5", data["warnings"][0])

    @pytest.mark.contract
    def test_lumina_unreadable_is_unknown_not_off_and_does_not_crash(self):
        for exc in (FileNotFoundError(2, "gone"), PermissionError(13, "denied"), OSError(5, "io")):
            with self.subTest(exc=type(exc).__name__):
                data = self._lumina(exc)
                self.assertTrue(data["ok"], data)
                lum = data["lumina_config"]
                self.assertEqual((lum["measurement"], lum["auto_lumina"]), ("UNKNOWN", "UNKNOWN"))
                self.assertIsNone(lum["value"])
        with mock.patch.dict(sys.modules, {"winreg": None}):      # import fails: non-Windows
            lum = self.status()["lumina_config"]
        self.assertEqual((lum["measurement"], lum["value"]), ("UNKNOWN", None))
        self.assertEqual(self._lumina("1")["lumina_config"]["measurement"], "UNKNOWN")

    def test_probe_runs_idat_on_an_empty_database_and_reports_what_it_read(self):
        data = self.status()
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["status"], data["tool"], data["resolved_by"]), ("OK", "ida_status", "PATH"))
        self.assertEqual(data["ida_kernel_version"], "9.4")
        self.assertTrue(data["decompiler_available"])
        self.assertEqual(data["decompiler_version"], "9.4.0.260714")
        command = self.fake.calls[0]["command"]
        for flag in ("-t", "-pmetapc", "-Opdb:off", "-A"):
            self.assertIn(flag, command)
        self.assertNotIn(str(self.sample), command)          # no input file
        self.assertIn("ida_query", data["operations"])
        self.assertIn("decompile_function", data["query_operations"])

    def test_probe_leaves_no_directory_behind(self):
        self.status()
        self.assertEqual([p for p in self.cache.iterdir()], [])

    def test_probe_reports_a_missing_decompiler_licence_as_a_fact_not_a_failure(self):
        self.fake.fields["summary"] = dict(SUMMARY, hexrays_available=False, hexrays_version=None)
        data = self.status()
        self.assertTrue(data["ok"])
        self.assertFalse(data["decompiler_available"])
        self.assertIn("decompile_function", data["note"])

    @pytest.mark.contract
    def test_probe_failure_is_analysis_limited_and_names_the_signals(self):
        self.fake.behaviour = "broken"
        data = self.status()
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "IDA_EXITED_NONZERO")
        self.assertEqual(data["binary"], "C:/fake/idat.exe")
        self.assertEqual([p for p in self.cache.iterdir()], [])

    @pytest.mark.contract
    def test_probe_timeout_is_reported(self):
        self.fake.behaviour = "timeout"
        self.assertEqual(self.status()["status"], "TIMEOUT")

    def test_a_probe_directory_left_by_a_killed_run_is_swept_later(self):
        stale = self.cache / "status-deadbeef"
        stale.mkdir(parents=True)
        old = time.time() - ti._LOCK_STALE_SECONDS - 60
        os.utime(stale, (old, old))
        fresh = self.cache / "status-cafe0001"
        fresh.mkdir()
        self.status()
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())      # a probe that may still be running is left alone

    def test_status_reports_the_cache_without_launching_for_it(self):
        self.q()
        self.fake.calls.clear()
        data = self.status()
        self.assertEqual(data["cache"]["slot_count"], 1)
        self.assertEqual(data["cache"]["budget_bytes"], ti._cache_budget_bytes())
        self.assertEqual(data["cache"]["root"], "<cache root>")        # no machine path in the report


# ---------------------------------------------------------------------------
# hardening: the discard guarantee, environment errors, the verdict, the lock,
# and the shared time budget
# ---------------------------------------------------------------------------
class DiscardGuaranteeTests(IdaCase):
    """A query must not change the cached database. The worker refuses to run
    the operation when it cannot set that up, AND the wrapper independently
    refuses any reopen result that does not carry `database_changes_discarded:
    true`, so neither layer is the only thing standing in the way."""

    def _prime(self):
        self.assertTrue(self.q()["ok"])
        self.assertEqual(len(self.slots()), 1)

    @pytest.mark.contract
    def test_a_reopen_result_with_the_flag_false_is_not_a_success_and_drops_the_slot(self):
        self._prime()
        evidence_before = sorted(self.evidence.iterdir())
        self.fake.discard_flag = False
        data = self.q("decompile_function", "start")
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDED")
        self.assertIs(data["signals"]["database_changes_discarded"], False)
        self.assertNotIn("decompiled", data)
        self.assertEqual(self.slots(), [], "a database that may have taken the decompiler's types is not kept")
        self.assertEqual(sorted(self.evidence.iterdir()), evidence_before, "no evidence is written for a refused answer")

    @pytest.mark.contract
    def test_a_reopen_result_without_the_flag_is_not_a_success_either(self):
        self._prime()
        self.fake.discard_flag = _OMIT
        data = self.q("list_functions")
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDED")
        self.assertIsNone(data["signals"]["database_changes_discarded"])
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_a_worker_that_declined_to_run_is_reported_with_its_own_error_named(self):
        self._prime()
        declined = {"ok": False, "tool": "ida_query", "operation": "list_functions", "items": [],
                    "error": "DATABASE_CHANGES_NOT_DISCARDABLE", "database_changes_discarded": False,
                    "engine_input_sha256": self.sha, "engine_input_md5": self.md5, "script_completed": True}
        self.fake.discard_flag = _OMIT   # leave the worker's own `False` in the body untouched
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: dict(declined)):
            data = self.q("list_functions")
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDED")
        self.assertEqual(data["worker_error"], "DATABASE_CHANGES_NOT_DISCARDABLE")
        self.assertEqual(self.slots(), [])

    def test_the_first_analysis_session_is_not_required_to_discard(self):
        """Create mode saves the pristine analysis; it must never be marked temporary."""
        self.fake.discard_flag = _OMIT
        self.assertTrue(self.q("summary")["ok"])

    def test_the_normal_case_is_untouched(self):
        self._prime()
        data = self.q("list_functions")
        self.assertTrue(data["ok"], data)
        self.assertIs(data["signals"]["database_changes_discarded"], True)
        self.assertEqual(data["database_cache"], "HIT")


class WorkerDiscardGuardTests(unittest.TestCase):
    """The worker side of the guarantee, against the stub ida_* modules."""

    def setUp(self):
        self.w, self.ida = _load_worker()
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def run_job(self, **job):
        job.setdefault("operation", "list_functions")
        job.setdefault("mode", "reopen")
        job["output"] = str(self.tmp / "out.json")
        job_file = self.tmp / "job.json"
        job_file.write_text(json.dumps(job), encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job_file)}):
            code = self.w.main()
        return code, json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))

    @pytest.mark.contract
    def test_when_the_temp_flag_cannot_be_set_the_operation_does_not_run(self):
        self.ida["ida_loader"].set_database_flag.side_effect = AttributeError("older build")
        self.ida["idautils"].Functions.return_value = [0x1000]
        for operation in ("list_functions", "decompile_function"):
            with self.subTest(operation=operation):
                code, data = self.run_job(operation=operation, query="start")
                self.assertEqual(code, 0)
                self.assertFalse(data["ok"])
                self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDABLE")
                self.assertIs(data["database_changes_discarded"], False)
                self.assertTrue(data["script_completed"])
                self.assertEqual(data["items"], [])
        self.ida["idautils"].Functions.assert_not_called()
        self.ida["ida_hexrays"].decompile.assert_not_called()
        self.ida["ida_auto"].auto_wait.assert_not_called()
        self.ida["ida_loader"].save_database.assert_not_called()

    @pytest.mark.contract
    def test_a_flag_that_reports_failure_by_returning_false_is_not_a_success_path(self):
        with mock.patch.object(self.w, "_discard_session_changes", return_value=False):
            _code, data = self.run_job(operation="list_functions")
        self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDABLE")
        self.ida["idautils"].Functions.assert_not_called()

    @pytest.mark.contract
    def test_the_flag_is_set_before_anything_else_runs(self):
        order = []
        self.ida["ida_loader"].set_database_flag.side_effect = lambda *_a: order.append("flag")
        self.ida["ida_auto"].auto_wait.side_effect = lambda *_a: order.append("auto_wait")
        self.ida["idautils"].Functions.side_effect = lambda *_a: order.append("op") or []
        self.run_job(operation="list_functions")
        self.assertEqual(order[:2], ["flag", "auto_wait"])
        self.assertIn("op", order)

    @pytest.mark.contract
    def test_an_exception_during_the_operation_keeps_the_discard_signal(self):
        self.ida["idautils"].Functions.side_effect = RuntimeError("kernel said no")
        _code, data = self.run_job(operation="list_functions")
        self.assertEqual(data["error"], "IDAPYTHON_SCRIPT_EXCEPTION")
        self.assertIs(data["database_changes_discarded"], True)


class EnvironmentErrorTests(IdaCase):
    """The wrapper's contract is never to raise: a local OS error becomes JSON
    that names itself as one and does not blame the input, the cache or IDA."""

    def assertEnvironmentError(self, data, error, errno=None):
        self.assertIsInstance(data, dict)
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["error"], error, data)
        self.assertEqual(data["status"], "ANALYSIS_LIMITED")
        self.assertIn("environment_error", data)
        if errno is not None:
            self.assertEqual(data["environment_error"]["errno"], errno)
        self.assertIn("environment", data["detail"])
        self.assertNotIn("corrupt", data["detail"].lower())

    @pytest.mark.contract
    def test_a_cache_root_that_is_a_file_is_reported_not_raised(self):
        self.cache.write_text("not a directory", encoding="utf-8")
        data = self.q()
        self.assertEnvironmentError(data, "IDA_CACHE_ROOT_UNUSABLE")
        self.assertEqual(data["target_sha256"], self.sha)
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_status_with_a_cache_root_that_is_a_file_is_reported_not_raised(self):
        self.cache.write_text("not a directory", encoding="utf-8")
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            data = json.loads(ti.ida_status())
        self.assertEnvironmentError(data, "IDA_CACHE_ROOT_UNUSABLE")
        self.assertEqual(data["tool"], "ida_status")
        self.assertEqual(self.fake.calls, [])

    def _unreadable_worker(self):
        def refuse():
            raise PermissionError(13, "Permission denied")
        return SimpleNamespace(is_file=lambda: True, read_bytes=refuse)

    @pytest.mark.contract
    def test_an_unreadable_packaged_worker_is_reported_not_raised(self):
        with mock.patch.object(ti, "_WORKER_SOURCE", self._unreadable_worker()):
            data = self.q()
        self.assertEnvironmentError(data, "IDA_WORKER_UNREADABLE", errno=13)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(ti._lock_path(ti._slot_dir(self.sha)).exists(), "the lock is released")

    @pytest.mark.contract
    def test_status_with_an_unreadable_worker_is_reported_not_raised(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")), \
                mock.patch.object(ti, "_WORKER_SOURCE", self._unreadable_worker()):
            data = json.loads(ti.ida_status())
        self.assertEnvironmentError(data, "IDA_WORKER_UNREADABLE", errno=13)

    @pytest.mark.contract
    def test_a_binary_that_exists_but_cannot_be_started_is_reported_not_raised(self):
        for exc, errno in ((FileNotFoundError(2, "The system cannot find the file specified"), 2),
                           (OSError(193, "%1 is not a valid Win32 application"), 193),
                           (PermissionError(13, "Permission denied"), 13)):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch.object(ti, "run_bounded_process", side_effect=exc):
                    data = self.q()
                self.assertEnvironmentError(data, "IDA_LAUNCH_FAILED", errno=errno)
                self.assertEqual(self.slots(), [])
                self.assertEqual(self.leftovers(), [])

    @pytest.mark.contract
    def test_a_job_file_that_cannot_be_written_is_reported_not_raised(self):
        real_write_text = Path.write_text

        def refuse_job(path, *args, **kwargs):
            if path.name == "job.json":
                raise OSError(28, "No space left on device")
            return real_write_text(path, *args, **kwargs)

        with mock.patch.object(Path, "write_text", refuse_job):
            data = self.q()
        self.assertEnvironmentError(data, "IDA_LAUNCH_FAILED", errno=28)
        self.assertEqual(self.fake.calls, [], "idat was never started")
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(ti._lock_path(ti._slot_dir(self.sha)).exists(), "the lock is released")

    @pytest.mark.contract
    def test_a_launch_failure_on_a_reopen_does_not_discard_a_healthy_slot(self):
        self.assertTrue(self.q()["ok"])
        with mock.patch.object(ti, "run_bounded_process", side_effect=PermissionError(13, "Permission denied")):
            data = self.q("list_functions")
        self.assertEnvironmentError(data, "IDA_LAUNCH_FAILED", errno=13)
        self.assertEqual(len(self.slots()), 1, "idat never started, so the database was not touched")

    @pytest.mark.contract
    def test_status_with_a_binary_that_cannot_be_started_is_reported_not_raised(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")), \
                mock.patch.object(ti, "run_bounded_process",
                                  side_effect=OSError(193, "%1 is not a valid Win32 application")):
            data = json.loads(ti.ida_status())
        self.assertEnvironmentError(data, "IDA_LAUNCH_FAILED", errno=193)
        self.assertEqual(data["binary"], "C:/fake/idat.exe")

    @pytest.mark.contract
    def test_an_unreadable_input_is_reported_not_raised(self):
        with mock.patch.object(ti, "_sha256_md5", side_effect=PermissionError(13, "Permission denied")):
            data = self.q()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "READ_FAILED")
        self.assertEqual(data["error"], "IDA_INPUT_UNREADABLE")
        self.assertEqual(data["environment_error"]["errno"], 13)

    @pytest.mark.contract
    def test_an_os_error_inside_the_locked_section_is_reported_and_the_lock_released(self):
        with mock.patch.object(ti, "_query_locked", side_effect=OSError(28, "No space left on device")):
            data = self.q()
        self.assertEnvironmentError(data, "IDA_CACHE_IO_ERROR", errno=28)
        self.assertFalse(ti._lock_path(ti._slot_dir(self.sha)).exists())

    @pytest.mark.contract
    def test_the_os_message_carries_no_machine_path(self):
        exc = PermissionError(13, "Permission denied")
        exc.filename = _HOME + "\\secret\\worker.idapy"
        with mock.patch.object(ti, "run_bounded_process", side_effect=exc):
            raw = ti.ida_query(str(self.sample))
        self.assertNotIn(_HOME_NAME, raw)

    @pytest.mark.contract
    def test_the_cases_that_already_answered_honestly_still_do(self):
        with mock.patch.object(ti, "_WORKER_SOURCE", self.root / "absent.idapy"):
            self.assertEqual(self.q()["error"], "IDA_WORKER_MISSING")
        db = self.root / "x.i64"
        db.write_bytes(b"x")
        self.assertEqual(self.q(path=db)["error"], "DATABASE_INPUT_NOT_SUPPORTED")
        with mock.patch.object(ti, "safe_path", side_effect=PermissionError("outside the workspace")):
            self.assertEqual(self.q()["status"], "PATH_REFUSED")
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            self.assertEqual(self.q()["status"], "TOOL_MISSING")


class StricterVerdictTests(IdaCase):
    @pytest.mark.contract
    def test_an_unreadable_log_does_not_count_as_the_log_signal(self):
        self.fake.log_unreadable = True
        data = self.q()
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["error"], "IDA_LOG_UNREADABLE")
        self.assertFalse(data["signals"]["log_readable"])
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_an_empty_log_does_not_count_either(self):
        self.fake.behaviour = "empty_log"
        data = self.q()
        self.assertEqual(data["error"], "IDA_LOG_UNREADABLE")
        self.assertTrue(data["signals"]["log_readable"])
        self.assertFalse(data["signals"]["log_present"])
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_a_fatal_marker_in_stdout_is_still_named_when_the_log_is_unreadable(self):
        self.fake.log_unreadable = True
        with mock.patch.object(FakeIdat, "__call__", autospec=True,
                               side_effect=lambda s, *a, **k: _cp(0, stdout="Fatal error: boom")):
            data = self.q()
        self.assertEqual(data["error"], "IDA_LOG_REPORTS_FAILURE")

    @pytest.mark.contract
    def test_a_result_for_another_operation_is_not_success(self):
        self.fake.result_operation = "list_functions"
        data = self.q("summary")
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["error"], "IDA_RESULT_OPERATION_MISMATCH")
        self.assertFalse(data["signals"]["result_operation_matches"])
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_a_reopen_result_for_another_operation_is_refused_and_the_slot_dropped(self):
        self.assertTrue(self.q()["ok"])
        evidence_before = sorted(self.evidence.iterdir())
        self.fake.result_operation = "segments"
        data = self.q("list_functions")
        self.assertEqual(data["error"], "IDA_RESULT_OPERATION_MISMATCH")
        self.assertEqual(self.slots(), [])
        self.assertEqual(sorted(self.evidence.iterdir()), evidence_before)

    @pytest.mark.contract
    def test_a_result_with_no_operation_at_all_is_not_success(self):
        self.assertTrue(self.q()["ok"])
        with mock.patch.object(FakeIdat, "_body", lambda s, job, sha: {
                "ok": True, "tool": "ida_query", "items": [], "database_changes_discarded": True,
                "engine_input_sha256": sha, "engine_input_md5": s.md5, "script_completed": True}):
            data = self.q("list_functions")
        self.assertEqual(data["error"], "IDA_RESULT_OPERATION_MISMATCH")

    @pytest.mark.contract
    def test_the_status_probe_demands_a_summary_answer_and_a_readable_log(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            self.fake.result_operation = "list_functions"
            data = json.loads(ti.ida_status())
            self.assertEqual(data["error"], "IDA_RESULT_OPERATION_MISMATCH")
            self.fake.result_operation = None
            self.fake.log_unreadable = True
            data = json.loads(ti.ida_status())
            self.assertEqual(data["error"], "IDA_LOG_UNREADABLE")

    def test_no_false_alarm_every_operation_succeeds_on_a_first_call_and_on_a_hit(self):
        """The hardening must not reject what already worked."""
        for operation in ti._ALLOWED_OPERATIONS:
            for state in ("CREATED", "HIT"):
                with self.subTest(operation=operation, state=state):
                    data = self.q(operation, "0x1000 8" if operation == "read_bytes" else "start")
                    self.assertTrue(data["ok"], data)
                    self.assertEqual(data["status"], "OK")
                    self.assertEqual(data["operation"], operation)
                    self.assertTrue(data["signals"]["log_readable"] and data["signals"]["log_present"])
                    self.assertTrue(data["signals"]["result_operation_matches"])
            self.fake.calls.clear()
            for slot in self.slots():
                import shutil
                shutil.rmtree(slot)

    def test_the_status_probe_still_succeeds(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            data = json.loads(ti.ida_status())
        self.assertTrue(data["ok"], data)


class SlotOwnershipTests(IdaCase):
    def _slot(self):
        slot = ti._slot_dir(self.sha)
        slot.parent.mkdir(parents=True, exist_ok=True)
        return slot

    def _plant(self, slot, record, age=0.0):
        lock = ti._lock_path(slot)
        lock.write_text(json.dumps(record), encoding="utf-8")
        if age:
            old = time.time() - age
            os.utime(lock, (old, old))
        return lock

    def _dead_pid(self):
        import subprocess
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        return proc.pid

    def test_the_lock_records_its_owner_atomically(self):
        slot = self._slot()
        lock = ti._acquire_slot_lock(slot, None)
        record = json.loads(ti._lock_path(slot).read_text(encoding="utf-8"))
        self.assertEqual(record["pid"], os.getpid())
        self.assertEqual(record["token"], lock.token)
        self.assertEqual(len(lock.token), 32)
        self.assertEqual([p.name for p in slot.parent.iterdir() if p.name.endswith(".tmp")], [],
                         "the staging file used to publish the record is removed")
        lock.release()

    def test_every_acquisition_gets_its_own_token(self):
        slot = self._slot()
        first = ti._acquire_slot_lock(slot, None)
        first.release()
        second = ti._acquire_slot_lock(slot, None)
        self.assertNotEqual(first.token, second.token)
        second.release()

    def test_a_taken_over_lock_owner_cannot_delete_its_successors_lock(self):
        """A is suspended past the stale age, B takes over; when A wakes up and
        releases, B's lock must survive."""
        slot = self._slot()
        a = ti._acquire_slot_lock(slot, None)
        old = time.time() - ti._LOCK_OWNER_ALIVE_CEILING_SECONDS - 10
        os.utime(a.path, (old, old))
        with mock.patch.object(ti._ProcessProbe, "alive", return_value=False):
            b = ti._acquire_slot_lock(slot, None)
        self.assertIsNotNone(b)
        self.assertNotEqual(a.token, b.token)
        self.assertFalse(a.release(), "A no longer owns the lock")
        ti._release_slot_lock(a)
        self.assertTrue(b.path.exists(), "A's release must not remove B's lock")
        self.assertEqual(json.loads(b.path.read_text(encoding="utf-8"))["token"], b.token)
        self.assertTrue(b.release())
        self.assertFalse(b.path.exists())

    def test_a_query_whose_lock_was_taken_over_mid_run_leaves_the_new_owners_lock(self):
        """The same through ida_query: another caller replaces the lock file
        while idat is running; this call's finally must not remove it."""
        slot = ti._slot_dir(self.sha)
        other = {"pid": os.getpid(), "token": "b" * 32, "started": time.time(), "create_time": None}

        def behaviour(mode, job):
            ti._lock_path(slot).write_text(json.dumps(other), encoding="utf-8")
            return "ok"

        self.fake.behaviour = behaviour
        self.assertTrue(self.q()["ok"])
        survivor = json.loads(ti._lock_path(slot).read_text(encoding="utf-8"))
        self.assertEqual(survivor["token"], "b" * 32)

    def test_releasing_a_lock_that_is_already_gone_is_harmless(self):
        slot = self._slot()
        lock = ti._acquire_slot_lock(slot, None)
        lock.path.unlink()
        self.assertFalse(lock.release())
        ti._release_slot_lock(lock)

    def test_a_running_owner_keeps_the_lock_past_the_stale_age(self):
        slot = self._slot()
        self._plant(slot, {"pid": os.getpid(), "token": "a" * 32, "started": 0, "create_time": None},
                    age=ti._LOCK_STALE_SECONDS + 60)
        self.assertTrue(ti._lock_is_live(ti._lock_path(slot)))
        with mock.patch.object(ti, "_LOCK_WAIT_SECONDS", 0.3):
            data = self.q()
        self.assertEqual(data["error"], "IDA_CACHE_SLOT_BUSY")
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(json.loads(ti._lock_path(slot).read_text(encoding="utf-8"))["token"], "a" * 32)

    def test_a_running_owner_is_not_trusted_forever(self):
        slot = self._slot()
        lock = self._plant(slot, {"pid": os.getpid(), "token": "a" * 32, "started": 0, "create_time": None},
                           age=ti._LOCK_OWNER_ALIVE_CEILING_SECONDS + 60)
        self.assertFalse(ti._lock_is_live(lock))
        self.assertTrue(self.q()["ok"])

    def test_a_dead_owner_makes_an_old_lock_stale_but_a_young_one_is_still_respected(self):
        slot = self._slot()
        pid = self._dead_pid()
        lock = self._plant(slot, {"pid": pid, "token": "a" * 32, "started": 0, "create_time": None},
                           age=ti._LOCK_STALE_SECONDS + 10)
        self.assertFalse(ti._lock_is_live(lock))
        self.assertTrue(self.q()["ok"])
        # young: the dead process's idat child could still be using the slot
        self._plant(slot, {"pid": pid, "token": "a" * 32, "started": 0, "create_time": None}, age=5)
        self.assertTrue(ti._lock_is_live(lock))

    def test_a_reused_pid_is_not_mistaken_for_the_owner(self):
        slot = self._slot()
        lock = self._plant(slot, {"pid": os.getpid(), "token": "a" * 32, "started": 0,
                                  "create_time": time.time() - 100000},
                           age=ti._LOCK_STALE_SECONDS + 10)
        self.assertFalse(ti._lock_is_live(lock))

    def test_a_lock_without_an_owner_record_is_judged_by_age_as_before(self):
        slot = self._slot()
        lock = ti._lock_path(slot)
        lock.write_text("{}")
        self.assertTrue(ti._lock_is_live(lock))
        lock.write_text("{half-written")
        self.assertTrue(ti._lock_is_live(lock))
        old = time.time() - ti._LOCK_STALE_SECONDS - 10
        os.utime(lock, (old, old))
        self.assertFalse(ti._lock_is_live(lock))

    def test_a_lock_that_changed_after_it_was_judged_stale_is_not_removed(self):
        slot = self._slot()
        lock = ti._lock_path(slot)
        lock.write_text("{}")
        replacement = json.dumps({"pid": os.getpid(), "token": "c" * 32})
        calls = []

        def judged(path):
            calls.append(path)
            path.write_text(replacement, encoding="utf-8")   # somebody else took over meanwhile
            return len(calls) > 1                             # first verdict: stale, then live

        with mock.patch.object(ti, "_lock_is_live", side_effect=judged), \
                mock.patch.object(ti, "_LOCK_WAIT_SECONDS", 0.3):
            self.assertIsNone(ti._acquire_slot_lock(slot, None))
        self.assertEqual(lock.read_text(encoding="utf-8"), replacement)

    def test_the_hard_link_fallback_still_excludes(self):
        slot = self._slot()
        with mock.patch.object(ti.os, "link", side_effect=OSError(1, "hard links unsupported")):
            first = ti._acquire_slot_lock(slot, None)
            self.assertIsNotNone(first)
            self.assertEqual(json.loads(first.path.read_text(encoding="utf-8"))["token"], first.token)
            with mock.patch.object(ti, "_LOCK_WAIT_SECONDS", 0.3):
                self.assertIsNone(ti._acquire_slot_lock(slot, None))
            first.release()


class ProcessProbeTests(unittest.TestCase):
    def _dead_pid(self):
        import subprocess
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        return proc.pid

    def test_this_process_is_alive_and_a_finished_one_is_not(self):
        self.assertIs(ti._ProcessProbe.alive(os.getpid()), True)
        self.assertIs(ti._ProcessProbe.alive(self._dead_pid()), False)

    def test_a_pid_that_is_not_a_pid_is_unknown(self):
        for bad in (None, "x", 0, -4):
            self.assertIsNone(ti._ProcessProbe.alive(bad))

    def test_a_different_creation_time_means_the_pid_was_reused(self):
        self.assertIs(ti._ProcessProbe.alive(os.getpid(), time.time() - 100000), False)

    @pytest.mark.skipif(os.name != "nt", reason="the Windows branch needs Windows")
    def test_the_windows_branch_on_its_own(self):
        self.assertIs(ti._ProcessProbe._windows(os.getpid()), True)
        self.assertIs(ti._ProcessProbe._windows(self._dead_pid()), False)

    def test_the_posix_branch_on_its_own_with_os_kill_stubbed(self):
        with mock.patch.object(ti.os, "kill", return_value=None) as kill:
            self.assertIs(ti._ProcessProbe._posix(4321), True)
            kill.assert_called_once_with(4321, 0)
        with mock.patch.object(ti.os, "kill", side_effect=ProcessLookupError()):
            self.assertIs(ti._ProcessProbe._posix(4321), False)
        with mock.patch.object(ti.os, "kill", side_effect=PermissionError()):
            self.assertIs(ti._ProcessProbe._posix(4321), True)
        with mock.patch.object(ti.os, "kill", side_effect=OSError(22, "invalid")):
            self.assertIsNone(ti._ProcessProbe._posix(4321))

    def test_without_psutil_the_platform_branch_answers(self):
        with mock.patch.dict(sys.modules, {"psutil": None}):
            self.assertIs(ti._ProcessProbe.alive(os.getpid()), True)
            self.assertIs(ti._ProcessProbe.alive(self._dead_pid()), False)

    def test_the_probe_never_signals_a_process_on_windows(self):
        with mock.patch.object(ti.os, "name", "nt"), mock.patch.dict(sys.modules, {"psutil": None}), \
                mock.patch.object(ti.os, "kill", side_effect=AssertionError("os.kill terminates on Windows")), \
                mock.patch.object(ti._ProcessProbe, "_windows", return_value=True) as win:
            self.assertIs(ti._ProcessProbe.alive(1234), True)
            win.assert_called_once_with(1234)


class BestEffortBranchTests(IdaCase):
    """Branches that swallow an OS or probe error on purpose. Each one answers
    with a defined fallback instead of raising; these pin the fallback and the
    exception class that triggers it."""

    def _slot(self):
        slot = ti._slot_dir(self.sha)
        slot.parent.mkdir(parents=True, exist_ok=True)
        return slot

    @pytest.mark.contract
    def test_a_search_for_the_binary_that_hits_an_os_error_finds_nothing(self):
        with mock.patch.dict(os.environ, {"IDAT_EXE": "", "IDA_HOME": ""}), \
                mock.patch.object(ti.shutil, "which", return_value=None), \
                mock.patch.object(ti.Path, "glob", side_effect=PermissionError(13, "Permission denied")):
            self.assertEqual(ti._resolved_by_and_binary(), (None, None))

    @pytest.mark.contract
    def test_a_clamp_of_an_unusable_value_falls_back_to_the_default(self):
        for bad in ("many", None, [1], object()):
            with self.subTest(bad=type(bad).__name__):
                self.assertEqual(ti._clamp(bad, 1, 10, 7), 7)
        self.assertEqual(ti._clamp("99", 1, 10, 7), 10)

    @pytest.mark.contract
    def test_redaction_still_works_when_the_account_name_is_unavailable(self):
        with mock.patch.object(ti.getpass, "getuser", side_effect=KeyError("LOGNAME")):
            text = ti._redact("License: ABC-123\nfine")
        self.assertIn("<REDACTED>", text)
        self.assertNotIn("ABC-123", text)

    @pytest.mark.contract
    def test_a_cache_file_that_vanishes_during_the_size_walk_is_skipped(self):
        (self.root / "kept.bin").write_bytes(b"12345")
        walked = [(str(self.root), [], ["kept.bin", "vanished.bin"])]
        with mock.patch.object(ti.os, "walk", return_value=iter(walked)):
            self.assertEqual(ti._dir_bytes(self.root), 5)

    @pytest.mark.contract
    def test_the_psutil_probe_maps_its_own_errors_to_dead_and_unknown(self):
        class Gone(Exception):
            pass

        class Broken(Exception):
            pass

        def fake_psutil(raises):
            def process(_pid):
                raise raises
            return SimpleNamespace(pid_exists=lambda _pid: True, Process=process, NoSuchProcess=Gone,
                                   Error=Broken, STATUS_ZOMBIE="zombie")

        self.assertIs(ti._ProcessProbe._psutil(fake_psutil(Gone()), 1, None), False)
        self.assertIsNone(ti._ProcessProbe._psutil(fake_psutil(Broken()), 1, None))
        self.assertIsNone(ti._ProcessProbe._psutil(fake_psutil(PermissionError(13, "denied")), 1, None))
        self.assertIsNone(ti._ProcessProbe._psutil(fake_psutil(ValueError("bad")), 1, None))

    @pytest.mark.contract
    def test_a_windows_probe_that_cannot_run_says_unknown(self):
        import ctypes
        broken = SimpleNamespace(kernel32=SimpleNamespace(
            OpenProcess=mock.Mock(side_effect=RuntimeError("no kernel32"))))
        with mock.patch.object(ctypes, "windll", broken, create=True):
            self.assertIsNone(ti._ProcessProbe._windows(os.getpid()))

    @pytest.mark.contract
    def test_a_lock_is_still_created_when_the_process_start_time_cannot_be_read(self):
        lock = self.root / "x.lock"
        broken = SimpleNamespace(Process=mock.Mock(side_effect=RuntimeError("no psutil")))
        with mock.patch.dict(sys.modules, {"psutil": broken}):
            ti._SlotLock.create(lock, "token-1234567890")
        record = json.loads(lock.read_text(encoding="utf-8"))
        self.assertEqual(record["token"], "token-1234567890")
        self.assertIsNone(record["create_time"])

    @pytest.mark.contract
    def test_an_existing_lock_is_reported_as_such_and_not_overwritten_by_the_fallback(self):
        lock = self.root / "y.lock"
        with mock.patch.object(ti.os, "link", side_effect=FileExistsError(17, "exists")), \
                mock.patch.object(ti.os, "open", side_effect=AssertionError("fallback must not run")):
            with self.assertRaises(FileExistsError):
                ti._SlotLock.create(lock, "token-1234567890")

    @pytest.mark.contract
    def test_a_staging_file_that_cannot_be_removed_does_not_fail_the_lock(self):
        lock = self.root / "z.lock"
        real_unlink = Path.unlink

        def refuse_staging(path, *args, **kwargs):
            if path.name.endswith(".tmp"):
                raise PermissionError(13, "Permission denied")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", refuse_staging):
            ti._SlotLock.create(lock, "token-1234567890")
        self.assertTrue(lock.is_file())

    @pytest.mark.contract
    def test_releasing_a_lock_that_cannot_be_deleted_reports_false(self):
        lock = self.root / "w.lock"
        ti._SlotLock.create(lock, "token-1234567890")
        held = ti._SlotLock(lock, "token-1234567890")
        with mock.patch.object(Path, "unlink", side_effect=PermissionError(13, "Permission denied")):
            self.assertIs(held.release(), False)

    @pytest.mark.contract
    def test_a_stale_lock_that_cannot_be_removed_is_retried_not_raised(self):
        slot = self._slot()
        lock = ti._lock_path(slot)
        lock.write_text("{}", encoding="utf-8")
        old = time.time() - ti._LOCK_STALE_SECONDS - 10
        os.utime(lock, (old, old))
        real_unlink = Path.unlink
        calls = []

        def refuse_once(path, *args, **kwargs):
            if path == lock and not calls:
                calls.append(path)
                raise PermissionError(13, "Permission denied")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", refuse_once):
            taken = ti._acquire_slot_lock(slot, None)
        self.assertIsNotNone(taken)
        self.assertEqual(len(calls), 1)
        ti._release_slot_lock(taken)

    @pytest.mark.contract
    def test_a_database_that_cannot_be_inspected_is_not_a_healthy_slot(self):
        slot = self._slot()
        slot.mkdir()
        (slot / ti._DB_NAME).write_bytes(b"x")
        with mock.patch.object(Path, "stat", side_effect=PermissionError(13, "Permission denied")):
            self.assertIs(ti._slot_is_healthy(slot), False)

    @pytest.mark.contract
    def test_metadata_that_cannot_be_written_does_not_fail_the_call(self):
        slot = self._slot()
        slot.mkdir()
        with mock.patch.object(Path, "write_text", side_effect=OSError(28, "No space left on device")):
            ti._touch_meta(slot, self.sha, created=True)
        self.assertFalse((slot / "meta.json").exists())

    @pytest.mark.contract
    def test_the_last_used_time_falls_back_to_the_slot_and_then_to_zero(self):
        slot = self._slot()
        slot.mkdir()
        self.assertGreater(ti._slot_last_used(slot), 0.0)
        with mock.patch.object(Path, "stat", side_effect=PermissionError(13, "Permission denied")):
            self.assertEqual(ti._slot_last_used(slot), 0.0)

    @pytest.mark.contract
    def test_a_database_size_that_cannot_be_read_counts_as_no_database(self):
        work = self.root / "work-v"
        work.mkdir()

        class Unreadable:
            def is_file(self):
                return True

            def stat(self):
                raise PermissionError(13, "Permission denied")

        cp = SimpleNamespace(returncode=0, stdout="", stderr="")
        _data, _error, signals = ti._verdict(cp, work, Unreadable(), expect_database=True)
        self.assertIs(signals["database_present"], False)
        self.assertEqual(signals["database_bytes"], 0)

    @pytest.mark.contract
    def test_a_stale_probe_directory_that_cannot_be_inspected_does_not_fail_status(self):
        old = self.cache / "status-old00000"
        old.mkdir(parents=True)
        real_stat = Path.stat

        def refuse_old(path, *args, **kwargs):
            if path.name == "status-old00000":
                raise PermissionError(13, "Permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")), \
                mock.patch.object(Path, "stat", refuse_old):
            data = json.loads(ti.ida_status())
        self.assertTrue(data["ok"], data)


class ErrorNameTests(IdaCase):
    """The exact status and error names a caller branches on."""

    @pytest.mark.contract
    def test_a_refused_operation_and_a_missing_worker_are_both_analysis_limited(self):
        data = self.q("rename")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "UNKNOWN_OPERATION"))
        with mock.patch.object(ti, "_WORKER_SOURCE", self.root / "absent.idapy"):
            data = self.q()
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "IDA_WORKER_MISSING"))

    @pytest.mark.contract
    def test_a_cancelled_and_a_timed_out_call_name_the_process_tree_termination(self):
        for behaviour, status, error in (
                ("cancel", "CANCELLED", "IDA_CANCELLED_PROCESS_TREE_TERMINATED"),
                ("timeout", "TIMEOUT", "IDA_TIMEOUT_PROCESS_TREE_TERMINATED")):
            with self.subTest(behaviour=behaviour):
                self.fake.behaviour = behaviour
                data = self.q()
                self.assertEqual((data["status"], data["error"]), (status, error))

    @pytest.mark.contract
    def test_a_probe_that_times_out_is_reported_with_its_own_error(self):
        self.fake.behaviour = "timeout"
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            data = json.loads(ti.ida_status())
        self.assertEqual((data["status"], data["error"]), ("TIMEOUT", "IDA_PROBE_TIMEOUT"))

    @pytest.mark.contract
    def test_a_worker_refusal_without_an_error_name_is_unknown_error_not_a_crash(self):
        self.fake.behaviour = "script_error"

        def nameless(command, **kwargs):
            cp = self.fake(command, **kwargs)
            result = Path(kwargs["cwd"]) / ti._RESULT_NAME
            body = json.loads(result.read_text(encoding="utf-8"))
            body.pop("error")
            result.write_text(json.dumps(body), encoding="utf-8")
            return cp

        with mock.patch.object(ti, "run_bounded_process", nameless):
            data = self.q()
        self.assertEqual((data["status"], data["error"], data["ok"]), ("ANALYSIS_LIMITED", "UNKNOWN_ERROR", False))

    @pytest.mark.contract
    def test_a_binary_found_through_a_folder_in_idat_exe_is_still_attributed_to_idat_exe(self):
        folder = self.root / "install"
        folder.mkdir()
        (folder / "idat.exe").write_bytes(b"")
        with mock.patch.dict(os.environ, {"IDAT_EXE": str(folder), "IDA_HOME": ""}):
            self.assertEqual(ti._resolved_by_and_binary(), ("IDAT_EXE", str(folder / "idat.exe")))


class SharedBudgetTests(IdaCase):
    def _clock(self, *values):
        times = iter(values)
        return SimpleNamespace(monotonic=lambda: next(times, values[-1]), time=time.time, sleep=time.sleep)

    @pytest.mark.contract
    def test_when_the_analysis_used_the_whole_budget_the_question_is_not_started(self):
        # lock wait, deadline, then 70 s later against a 60 s budget
        with mock.patch.object(ti, "time", self._clock(100.0, 100.0, 170.0)):
            data = self.q("list_functions", timeout_seconds=60)
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(data["error"], "IDA_TIMEOUT_BUDGET_EXHAUSTED")
        self.assertEqual(data["timed_out_stage"], "query")
        self.assertEqual(data["timeout_seconds"], 60)
        self.assertIn("nothing found", data["detail"])
        self.assertEqual(self.fake.modes, ["create"], "no extra seconds were granted to a second session")
        self.assertEqual(len(self.slots()), 1, "the analysed database was saved")
        self.fake.calls.clear()
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")

    @pytest.mark.contract
    def test_less_than_one_second_left_is_also_a_timeout(self):
        with mock.patch.object(ti, "time", self._clock(100.0, 100.0, 159.5)):
            data = self.q("list_functions", timeout_seconds=60)
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(self.fake.modes, ["create"])

    def test_the_second_session_is_never_given_more_than_what_is_left(self):
        with mock.patch.object(ti, "time", self._clock(100.0, 100.0, 157.0)):
            data = self.q("list_functions", timeout_seconds=60)
        self.assertTrue(data["ok"], data)
        self.assertEqual(self.fake.calls[1]["timeout"], 3, "3 s left means 3 s, not the old 5 s floor")

    def test_the_declared_budget_is_documented_as_a_hard_one(self):
        self.assertIn("never rounded up", inspect.getsource(ti._query_locked))


# ---------------------------------------------------------------------------
# routing manifest and command line
# ---------------------------------------------------------------------------
class RoutingTests(unittest.TestCase):
    def test_both_tools_are_published_and_routed_correctly(self):
        published = tool_families.published_tools("native")
        self.assertIn("ida_query", published)
        self.assertIn("ida_status", published)
        self.assertIn("ida_query", tool_families.NATIVE_PATH_ONLY_TOOLS)
        self.assertIn("ida_status", tool_families.NATIVE_NOT_FILE_ROUTABLE)

    def test_tools_that_are_not_implemented_yet_are_still_not_claimed(self):
        published = tool_families.published_tools("native")
        # ida_patch_plan, ida_type_member_offset and ida_annotations are implemented and left this list; so did
        # the rename pair (ida_rename became ida_rename_plan + ida_annotations_apply, two names, not a flag).
        for name in ("ida_rename", "ida_disasm_listing"):
            self.assertNotIn(name, published, name)


class CliTests(unittest.TestCase):
    def test_parser_has_the_ida_commands_with_the_operation_choices(self):
        parser = cli._build_parser()
        args = parser.parse_args(["ida", "x.exe", "--operation", "xrefs_to", "--query", "start", "--max-results", "5"])
        self.assertEqual((args.operation, args.query, args.max_results), ("xrefs_to", "start", 5))
        self.assertTrue(args.needs_file)
        self.assertFalse(parser.parse_args(["idastatus"]).needs_file)
        with self.assertRaises(SystemExit):
            parser.parse_args(["ida", "x.exe", "--operation", "rename"])

    def test_cli_operation_choices_match_the_module(self):
        """cli.py imports the module lazily, so it keeps its own copy of the list."""
        self.assertEqual(tuple(cli._IDA_OPERATIONS), tuple(ti._ALLOWED_OPERATIONS))

    @pytest.mark.contract
    def test_ida_without_idat_is_exit_3_tool_missing(self):
        with TemporaryDirectory() as td:
            sample = Path(td) / "s.exe"
            sample.write_bytes(b"MZ")
            with mock.patch.object(ti, "_resolved_by_and_binary", return_value=(None, None)), \
                 mock.patch("sys.stdout") as out:
                code = cli.main(["ida", str(sample)])
                body = json.loads("".join(c.args[0] for c in out.write.call_args_list))
        self.assertEqual(code, 3)
        self.assertEqual(body["status"], "TOOL_MISSING")
        self.assertEqual(body["command"], "ida")

    @pytest.mark.contract
    def test_idastatus_without_idat_is_exit_3_tool_missing(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=(None, None)), \
             mock.patch("sys.stdout") as out:
            code = cli.main(["idastatus"])
            body = json.loads("".join(c.args[0] for c in out.write.call_args_list))
        self.assertEqual(code, 3)
        self.assertEqual((body["command"], body["status"]), ("idastatus", "TOOL_MISSING"))


# ---------------------------------------------------------------------------
# the real tool
# ---------------------------------------------------------------------------
@pytest.mark.heavy
class IdaRealInstallTests(unittest.TestCase):
    """Needs a licensed IDA Pro 9.x; skips when idat is not found. Builds its
    own tiny synthetic x86-64 PE (nothing shipped, nothing third-party)."""

    @classmethod
    def setUpClass(cls):
        if not ti.ida_available():
            raise unittest.SkipTest("IDA Pro (idat) is not installed")
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
        self.cache = self.root / f"cache_{self.id().rsplit('.', 1)[-1]}"
        self.evidence = self.cache / "evidence"
        self.evidence.mkdir(parents=True)
        stack.enter_context(mock.patch.object(ti, "CACHE_ROOT", self.cache / "db"))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE", self.evidence))
        stack.enter_context(mock.patch.object(ti, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(ti, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))

    def q(self, operation="summary", query="", **kw):
        kw.setdefault("backend", "idat")      # these check the batch binary; the idalib backend has its own heavy tests
        return json.loads(ti.ida_query(str(self.pe), operation, query, **kw))

    def test_status_probe_launches_headless_and_reports_the_decompiler(self):
        data = json.loads(ti.ida_status())
        self.assertTrue(data["ok"], data)
        self.assertRegex(data["ida_kernel_version"], r"^9\.")
        self.assertFalse(data["log_network_text_found"])

    def test_analyse_then_reopen_keeps_exactly_one_database(self):
        first = self.q("summary")
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["database_cache"], "CREATED")
        self.assertEqual(first["provenance"]["status"], "VERIFIED")
        self.assertEqual(first["function_count"], 1)
        self.assertTrue(first["is_64bit"])
        second = self.q("list_functions")
        self.assertEqual(second["database_cache"], "HIT")
        self.assertEqual([f["name"] for f in second["items"]], ["start"])
        databases = [p for p in (self.cache / "db").rglob("*") if p.suffix == ".i64"]
        self.assertEqual(len(databases), 1)
        self.assertEqual([p for p in (self.cache / "db").rglob("*") if p.name.startswith("work-")], [])

    def test_xrefs_and_decompile_on_the_synthetic_function(self):
        refs = self.q("xrefs_to", "0x140001000")
        self.assertEqual([(x["from"], x["is_call"]) for x in refs["items"]], [("0x140001010", True)])
        code = self.q("decompile_function", "start")
        self.assertTrue(code["ok"], code)
        self.assertIn("return 0;", code["decompiled"])

    def test_the_four_queries_on_the_synthetic_function(self):
        """read_bytes, name-resolving xrefs_to, xrefs_from and callers_of_import against the real engine."""
        code = self.q("read_bytes", "0x140001000 8")
        self.assertTrue(code["ok"], code)
        self.assertEqual((code["bytes_hex"], code["fully_loaded"], code["segment"]["name"]), ("554889e531c05dc3", True, ".text"))
        self.assertFalse(self.q("read_bytes", "0x10 4")["ok"])
        self.assertEqual(self.q("read_bytes", "0x10 4")["error"], "ADDRESS_NOT_MAPPED")
        refs = self.q("xrefs_to", "start")
        self.assertEqual((refs["resolved_by"], refs["ambiguous"]), ("exact_name", False), refs)
        self.assertEqual([(x["from"], x["kind"], x["is_call"]) for x in refs["items"]], [("0x140001010", "code", True)])
        out = self.q("xrefs_from", "0x140001010")
        self.assertEqual(out["scope"], "address", out)
        self.assertEqual([(x["to"], x["kind"], x["is_call"]) for x in out["items"]], [("0x140001000", "code", True)])
        missing = self.q("callers_of_import", "CreateFileW")
        self.assertEqual(missing["error"], "IMPORT_NOT_FOUND", missing)

    def test_a_decompile_does_not_change_the_cached_database(self):
        self.q("summary")
        db = next((self.cache / "db").rglob("db.i64"))
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        self.q("decompile_function", "start")
        self.q("list_functions")
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertEqual(self.q("list_functions")["items"][0]["signature"], "")

    def test_an_unknown_symbol_is_a_named_answer_and_keeps_the_cache(self):
        data = self.q("function_at_address", "no_such_symbol_anywhere")
        self.assertEqual(data["error"], "FUNCTION_NOT_FOUND")
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")

    def test_a_file_with_a_debug_record_is_analysed_without_a_symbol_lookup(self):
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_rsds
        rsds = build_owned_pe_with_rsds(self.root / "with_rsds.exe")
        data = json.loads(ti.ida_query(str(rsds), "summary"))
        self.assertTrue(data["ok"], data)
        self.assertFalse(data["signals"]["log_network_text_found"])


if __name__ == "__main__":
    unittest.main()

