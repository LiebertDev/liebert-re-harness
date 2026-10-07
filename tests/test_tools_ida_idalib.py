"""`liebert_re.tools.ida` idalib backend: `ida_query(..., backend=)` and `ida_scripts/idalib_worker.idapy`.

Fast tier: nothing here starts IDA. Three stand-ins, each at a different boundary:

* `FakeIdalib` replaces the process boundary (`run_bounded_process`), like `FakeIdat` in
  `test_tools_ida.py`: it answers the probe and plays the worker's contract (job file in, result file
  out) with named misbehaviours. This is where the wrapper's rules are pinned: backend choice, the
  job and result contract, the four signals, the slot lifecycle, `CACHE_VIOLATION`, timeouts.
* The worker file itself is executed against stub `idapro` / `ida_*` modules in this process
  (`IdalibWorkerTests`): one open, a save before the first operation in a first analysis,
  `close_database(False)` in every ending, no `open_database` second call anywhere in the source.
* `IdalibSubprocessTests` runs the real worker in a real child interpreter (`sys.executable`) with
  stub modules on its path, to pin what only a real process shows: the timeout kill, stdout noise that
  must not be parsed, a path with a space, `-I`.

The real engine is `IdalibRealInstallTests` (heavy; needs LIEBERT_RE_IDALIB_PYTHON in the environment the
suite is started from and an idat): the idat and idalib answers to the same questions are equal.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import sys
import time
import unittest
from contextlib import ExitStack
from importlib.machinery import SourceFileLoader
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

import liebert_re.tools.ida as ti
from tests import conftest
from tests.test_tools_ida import (
    CLEAN_LOG, DECOMPILED, FUNCTIONS, SUMMARY, IdaCase, _cp, _result,
)

WORKER = Path(ti._IDALIB_WORKER_SOURCE)
QUERY_WORKER = Path(ti._WORKER_SOURCE)
IDALIB_ENV = ti.IDALIB_PYTHON_ENV
_PROBE_OK = {"import_ok": True, "idapro_version": "0.0.11", "library_version": [9, 4, 260714],
             "install_dir": "C:/fake/IDA"}


def _normalised(operation, answer):
    """An `ida_query` answer without the fields that legitimately differ between engines or between calls."""
    drop = {"command", "workspace", "internal_evidence_name", "evidence_write_error", "evidence_access", "signals",
            "database_cache", "backend", "invocation", "cache_evicted_slots", "cache_evicted_bytes",
            "cache_budget_bytes"}
    return {k: v for k, v in answer.items() if k not in drop}


class FakeIdalib:
    """The interpreter named by LIEBERT_RE_IDALIB_PYTHON, at the process boundary.

    A command with ``-c`` is the probe; a command whose first element is the fake interpreter is the
    worker; anything else (idat) goes to the wrapped `FakeIdat`. `behaviour` is a name or a callable
    ``(mode, job) -> name``: ok / timeout / cancel / garbage / no_output / incomplete / mismatch /
    fatal_log / stderr_traceback / nonzero / worker_failed / not_closed / op_mismatch / violation /
    no_db / refusal / unreadable_log / noisy
    """

    def __init__(self, python, idat, sha256, md5, behaviour="ok"):
        self.python, self.idat = str(python), idat
        self.sha256, self.md5 = sha256, md5
        self.behaviour = behaviour
        self.probe = dict(_PROBE_OK)
        self.probe_behaviour = "ok"        # ok / timeout / no_result / launch_failed
        self.probes = []
        self.calls = []                    # one dict per worker launch
        self.log = CLEAN_LOG

    def __call__(self, command, *, timeout_seconds, cancellation_token=None, cwd=None, environment=None,
                 max_output_chars=None):
        if str(command[0]) != self.python:
            return self.idat(command, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
                             cwd=cwd, environment=environment, max_output_chars=max_output_chars)
        if "-c" in command:
            self.probes.append(list(command))
            if self.probe_behaviour == "timeout":
                return _cp(None, timed_out=True)
            if self.probe_behaviour == "launch_failed":
                return _cp(None, launch_failed=True, launch_error="PermissionError: access denied")
            if self.probe_behaviour != "no_result":
                Path(command[-1]).write_text(json.dumps(self.probe), encoding="utf-8")
            return _cp(0, stderr="Z3 import failed\n")
        work = Path(cwd)
        job = json.loads((work / ti._IDALIB_JOB_NAME).read_text(encoding="utf-8"))
        slot = work.parent
        self.calls.append({
            "command": list(command), "cwd": work, "job": job, "timeout": timeout_seconds,
            "environment": dict(environment), "worker": (work / ti._IDALIB_JOB_SCRIPT).read_bytes(),
            "ops": (work / ti._IDALIB_OPS_NAME).read_bytes(),
            "copy": (work / ti._DB_NAME).read_bytes() if (work / ti._DB_NAME).exists() else None,
            "slot_db": (slot / ti._DB_NAME).read_bytes() if (slot / ti._DB_NAME).exists() else None,
        })
        mode = job["mode"]
        name = self.behaviour(mode, job) if callable(self.behaviour) else self.behaviour
        if name == "timeout":
            return _cp(None, timed_out=True)
        if name == "cancel":
            return _cp(None, cancelled=True)
        if name == "unreadable_log":
            (work / ti._LOG_NAME).mkdir()
        else:
            log = self.log + ("FATAL ERROR: Oops! internal error 1228 occurred.\n" if name == "fatal_log" else "")
            (work / ti._LOG_NAME).write_text(log, encoding="utf-8")
        if mode == "create" and name != "no_db":
            (work / ti._DB_NAME).write_bytes(b"IDA-DB" * 100)
        if name == "violation":
            (slot / ti._DB_NAME).write_bytes(b"CHANGED")
        if name == "no_output":
            return _cp(0)
        result_path = Path(job["output"])
        if name == "garbage":
            result_path.write_text("{not json", encoding="utf-8")
            return _cp(0)
        body = self._body(job, mode, "0" * 64 if name == "mismatch" else self.sha256)
        if name == "incomplete":
            body.pop("script_completed")
        if name == "not_closed":
            body["database_closed_without_save"] = False
        if name == "op_mismatch":
            body["results"][0]["operation"] = "segments"
        if name == "refusal":
            body["results"][0] = {"ok": False, "tool": "ida_query", "operation": job["operations"][0]["operation"],
                                  "items": [], "error": "FUNCTION_NOT_FOUND", "engine_input_sha256": self.sha256,
                                  "engine_input_md5": self.md5, "script_completed": True}
        if name == "worker_failed":
            body = {"ok": False, "schema": 1, "backend": "idalib", "mode": mode, "results": [],
                    "error": "IDALIB_OPEN_FAILED", "database_opened": False, "script_completed": True}
        result_path.write_text(json.dumps(body), encoding="utf-8")
        if name == "nonzero":
            return _cp(3, stderr="boom\n")
        if name == "stderr_traceback":
            return _cp(0, stderr="Traceback (most recent call last):\n  File \"<HOME>\"\n")
        if name == "noisy":
            # IDA plugins print banners and warnings to stdout; none of it is a result and none of it is a failure.
            return _cp(0, stdout="D810 initialized (version 0.6.6)\nTraceback (most recent call last): not an error\n",
                       stderr="Z3 import failed (No module named 'z3'). Z3 features disabled.\n")
        return _cp(0)

    def _body(self, job, mode, sha):
        operation = job["operations"][0]
        op = operation["operation"]
        fields = {}
        if op == "summary":
            fields = dict(SUMMARY)
        elif op == "list_functions":
            fields = dict(items=FUNCTIONS, total_function_count=3, offset=operation["offset"], returned_count=3,
                          next_offset=None)
        elif op == "decompile_function":
            fields = dict(items=FUNCTIONS[:1], decompiled=DECOMPILED)
        return {
            "ok": True, "schema": 1, "backend": "idalib", "mode": mode,
            "results": [_result(op, sha, self.md5, **fields)],
            "database_opened": True, "database_saved_before_queries": mode == "create",
            "database_closed_without_save": True, "close_error": None, "open_rc": 0,
            "idapro_version": "0.0.11", "library_version": [9, 4, 260714], "script_completed": True,
        }


class IdalibCase(IdaCase):
    """`IdaCase` plus an interpreter file, the variable pointing at it, and `FakeIdalib` at the boundary."""

    def setUp(self):
        super().setUp()
        self.python = self.root / "venv" / "python.exe"
        self.python.parent.mkdir()
        self.python.write_bytes(b"")
        self.idalib = FakeIdalib(self.python, self.fake, self.sha, self.md5, self.behaviour)
        patcher = mock.patch.object(ti, "run_bounded_process", side_effect=self.idalib)
        patcher.start()
        self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {IDALIB_ENV: str(self.python)})
        env.start()
        self.addCleanup(env.stop)

    def worker_calls(self):
        return self.idalib.calls

    def idat_calls(self):
        return self.fake.calls


# ---------------------------------------------------------------------------
# which engine answers
# ---------------------------------------------------------------------------
class BackendChoiceTests(IdalibCase):
    def test_without_the_variable_auto_is_idat_and_says_why(self):
        del os.environ[IDALIB_ENV]
        data = self.q("summary")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["backend"]["used"], "idat")
        self.assertEqual(data["backend"]["requested"], "auto")
        self.assertIn(IDALIB_ENV, data["backend"]["reason"])
        self.assertIn("not set", data["backend"]["reason"])
        self.assertEqual(self.idalib.probes, [])      # nothing was started to find out
        self.assertEqual(self.worker_calls(), [])

    def test_the_default_interpreter_is_never_guessed(self):
        """No variable means "not configured" even though the running interpreter could import nothing either."""
        del os.environ[IDALIB_ENV]
        public, private = ti._idalib_probe()
        self.assertEqual(public["status"], "NOT_CONFIGURED")
        self.assertFalse(public["configured"])
        self.assertEqual(private, {})
        self.assertEqual(self.idalib.probes, [])

    def test_a_variable_naming_a_missing_file_falls_back_to_idat_and_says_so(self):
        os.environ[IDALIB_ENV] = str(self.root / "nowhere" / "python.exe")
        data = self.q("summary")
        self.assertEqual(data["backend"]["used"], "idat")
        self.assertIn("INTERPRETER_NOT_FOUND", data["backend"]["reason"])
        self.assertIn("fell back to idat", data["backend"]["reason"])

    def test_a_failed_import_probe_falls_back_to_idat_and_says_why(self):
        self.idalib.probe = {"import_ok": False, "error": "ModuleNotFoundError: No module named 'idapro'"}
        data = self.q("summary")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["backend"]["used"], "idat")
        self.assertIn("IDAPRO_IMPORT_FAILED", data["backend"]["reason"])
        self.assertIn("No module named 'idapro'", data["backend"]["reason"])
        self.assertEqual(self.worker_calls(), [])

    def test_other_probe_failures_also_fall_back_and_name_themselves(self):
        for behaviour, status in (("timeout", "PROBE_TIMEOUT"), ("no_result", "PROBE_FAILED"),
                                  ("launch_failed", "INTERPRETER_NOT_LAUNCHABLE")):
            with self.subTest(behaviour):
                ti._IDALIB_PROBE_CACHE.clear()
                self.idalib.probe_behaviour = behaviour
                data = self.q("summary")
                self.assertEqual(data["backend"]["used"], "idat")
                self.assertIn(status, data["backend"]["reason"])

    def test_an_engine_that_cannot_be_identified_is_not_usable(self):
        """Slots are keyed by the engine that built them; without an install directory there is no key."""
        self.idalib.probe = dict(_PROBE_OK, install_dir=None)
        public, _private = ti._idalib_probe()
        self.assertEqual(public["status"], "ENGINE_UNIDENTIFIED")
        self.assertEqual(self.q("summary")["backend"]["used"], "idat")

    def test_a_configured_working_interpreter_makes_auto_idalib(self):
        data = self.q("list_functions")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["backend"]["used"], "idalib")
        self.assertIn("import idapro", data["backend"]["reason"])
        self.assertEqual(data["backend"]["idapro_version"], "0.0.11")
        self.assertEqual(data["backend"]["library_version"], [9, 4, 260714])
        self.assertEqual(len(self.worker_calls()), 1)
        self.assertEqual(self.idat_calls(), [])

    def test_idat_can_be_asked_for_explicitly_without_a_probe(self):
        data = self.q("summary", backend="idat")
        self.assertEqual(data["backend"], {"requested": "idat", "used": "idat", "reason": "requested explicitly"})
        self.assertEqual(self.idalib.probes, [])
        self.assertEqual(self.worker_calls(), [])

    def test_idalib_requested_but_not_configured_is_tool_missing_and_never_idat(self):
        del os.environ[IDALIB_ENV]
        data = self.q("summary", backend="idalib")
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "TOOL_MISSING", "IDALIB_NOT_CONFIGURED"))
        self.assertEqual(data["backend"]["used"], None)
        self.assertIn(IDALIB_ENV, data["detail"])
        self.assertEqual(self.idat_calls(), [])

    def test_idalib_requested_with_a_broken_probe_is_tool_missing_and_never_idat(self):
        self.idalib.probe = {"import_ok": False, "error": "ImportError: DLL load failed"}
        data = self.q("summary", backend="idalib")
        self.assertEqual((data["status"], data["error"]), ("TOOL_MISSING", "IDALIB_UNUSABLE"))
        self.assertEqual(data["idalib"]["status"], "IDAPRO_IMPORT_FAILED")
        self.assertEqual(self.idat_calls(), [])

    def test_an_unknown_backend_name_is_refused(self):
        data = self.q("summary", backend="ghidra")
        self.assertEqual((data["status"], data["error"], data["given"]), ("ANALYSIS_LIMITED", "UNKNOWN_BACKEND", "ghidra"))
        self.assertEqual(data["accepted"], ["auto", "idat", "idalib"])
        self.assertEqual(self.worker_calls() + self.idat_calls(), [])

    def test_every_answer_carries_the_backend_even_refusals_and_a_missing_tool(self):
        self.assertIn("backend", self.q("no_such_operation"))
        self.assertIn("backend", self.q("summary", path=self.root / "absent.exe"))
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            del os.environ[IDALIB_ENV]
            missing = self.q("summary")
        self.assertEqual(missing["status"], "TOOL_MISSING")
        self.assertEqual(missing["backend"]["used"], "idat")

    def test_the_probe_is_an_isolated_import_and_nothing_else(self):
        ti._idalib_probe()
        command = self.idalib.probes[0]
        self.assertEqual(command[:4], [str(self.python), "-I", "-X", "utf8"])
        self.assertIn("import idapro", command[command.index("-c") + 1])
        self.assertNotIn("open_database", ti._IDALIB_PROBE_CODE)

    def test_a_successful_probe_is_reused_but_a_failure_is_not(self):
        self.q("summary")
        self.q("summary")
        self.assertEqual(len(self.idalib.probes), 1)
        ti._IDALIB_PROBE_CACHE.clear()
        self.idalib.probe = {"import_ok": False, "error": "x"}
        self.q("summary")
        self.q("summary")
        self.assertEqual(len(self.idalib.probes), 3)

    def test_the_public_probe_redacts_the_interpreter_path(self):
        public, private = ti._idalib_probe()
        self.assertEqual(public["interpreter"], ti._redact(str(self.python)))
        self.assertEqual(private["python"], str(self.python))
        self.assertEqual(public["status"], "OK")
        home = ti._redact("C:" + "\\" + "Users" + "\\" + "Someone" + "\\venv\\python.exe")
        self.assertTrue(home.startswith("<HOME>"))

    def test_both_engines_share_the_slot_of_one_install(self):
        install = self.root / "IDA"
        install.mkdir()
        (install / "idat.exe").write_bytes(b"idat")
        self.idalib.probe = dict(_PROBE_OK, install_dir=str(install))
        with mock.patch.object(ti, "_ida_binary", return_value=str(install / "idat.exe")):
            self.q("summary")
        self.assertEqual([s.name for s in self.slots()], [ti._slot_dir(self.sha, str(install / "idat.exe")).name])
        self.assertEqual(ti._idalib_engine_exe(str(install)), str(install / "idat.exe"))


# ---------------------------------------------------------------------------
# the job and result contract, the slot lifecycle
# ---------------------------------------------------------------------------
class SessionContractTests(IdalibCase):
    def test_a_first_analysis_is_one_session_that_also_answers(self):
        data = self.q("list_functions")
        self.assertEqual(data["database_cache"], "CREATED")
        self.assertEqual([c["job"]["mode"] for c in self.worker_calls()], ["create"])
        self.assertEqual(data["items"], FUNCTIONS)
        self.assertEqual(len(self.slots()), 1)
        self.assertTrue((self.slots()[0] / ti._DB_NAME).is_file())

    def test_a_later_call_opens_a_copy_and_leaves_the_slot_bytes_alone(self):
        self.q("summary")
        slot_db = self.slots()[0] / ti._DB_NAME
        before = slot_db.read_bytes()
        data = self.q("list_functions")
        self.assertEqual(data["database_cache"], "HIT")
        call = self.worker_calls()[-1]
        self.assertEqual(call["job"]["mode"], "copy")
        self.assertNotIn("input", call["job"])
        self.assertEqual(call["copy"], before)                          # the worker was handed a copy of the slot
        self.assertNotEqual(call["cwd"], self.slots()[0])               # ... in the scratch directory
        self.assertEqual(call["cwd"].parent, self.slots()[0])
        self.assertEqual(slot_db.read_bytes(), before)
        self.assertEqual(data["signals"]["database_integrity"]["unchanged"], True)

    def test_the_job_names_one_operation_and_never_the_slot_database(self):
        self.q("xrefs_to", "start", max_results=7, offset=2)
        call = self.worker_calls()[0]
        job = call["job"]
        self.assertEqual(job["operations"], [{"operation": "xrefs_to", "query": "start", "max_results": 7, "offset": 2}])
        self.assertEqual(job["mode"], "create")
        self.assertEqual(job["input"], str(self.sample))
        self.assertEqual((job["database_name"], job["log_name"]), (ti._DB_NAME, ti._LOG_NAME))
        self.assertEqual(Path(job["output"]).parent, call["cwd"])
        self.assertEqual(Path(job["ops_path"]).parent, call["cwd"])
        self.assertEqual(job["max_result_bytes"], ti._IDALIB_MAX_RESULT_BYTES)
        self.assertNotIn(str(self.slots()[0] / ti._DB_NAME), json.dumps(job))

    def test_the_command_is_an_isolated_interpreter_running_the_copied_worker(self):
        self.q("summary")
        call = self.worker_calls()[0]
        self.assertEqual(call["command"], [str(self.python), "-I", "-X", "utf8", ti._IDALIB_JOB_SCRIPT, ti._IDALIB_JOB_NAME])

    def test_the_query_travels_in_the_job_file_not_in_the_command_line(self):
        self.q("function_at_address", "weird name 'with\" quotes")
        call = self.worker_calls()[0]
        self.assertNotIn("weird", " ".join(call["command"]))
        self.assertEqual(call["job"]["operations"][0]["query"], "weird name 'with\" quotes")

    def test_the_worker_and_the_shared_operations_are_copied_bom_free(self):
        bom = self.root / "bom.idapy"
        bom.write_bytes(b"\xef\xbb\xbf" + WORKER.read_bytes().replace(b"\n", b"\r\n"))
        with mock.patch.object(ti, "_IDALIB_WORKER_SOURCE", bom):
            self.q("summary")
        call = self.worker_calls()[0]
        self.assertFalse(call["worker"].startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", call["worker"])
        self.assertEqual(call["ops"], QUERY_WORKER.read_bytes().replace(b"\r\n", b"\n"))

    def test_the_cache_is_shared_with_idat(self):
        self.q("summary", backend="idat")
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")
        self.assertEqual([c["job"]["mode"] for c in self.worker_calls()], ["copy"])
        self.assertEqual(len(self.slots()), 1)

    def test_repeated_calls_never_grow_the_cache_and_leave_no_scratch(self):
        self.q("summary")
        names = sorted(f.name for f in self.slots()[0].iterdir())
        size = (self.slots()[0] / ti._DB_NAME).stat().st_size
        for _ in range(3):
            self.q("list_functions")
        self.assertEqual(len(self.slots()), 1)
        self.assertEqual(sorted(f.name for f in self.slots()[0].iterdir()), names)
        self.assertEqual((self.slots()[0] / ti._DB_NAME).stat().st_size, size)
        self.assertEqual(self.leftovers(), [])

    def test_the_answer_has_the_same_shape_as_the_idat_answer(self):
        via_idalib = self.q("list_functions")
        via_idat = self.q("list_functions", backend="idat")
        self.assertEqual(_normalised("list_functions", via_idalib), _normalised("list_functions", via_idat))
        self.assertTrue(via_idalib["database_changes_discarded"])
        signals = via_idalib["signals"]
        self.assertTrue(signals["database_closed_without_save"])
        self.assertEqual(signals["worker"]["open_rc"], 0)
        self.assertIn("elapsed_seconds", signals)
        self.assertEqual(via_idalib["provenance"]["status"], "VERIFIED")

    def test_a_worker_that_answers_no_is_a_named_refusal_and_keeps_the_slot(self):
        self.q("summary")
        self.idalib.behaviour = "refusal"
        data = self.q("function_at_address", "nope")
        self.assertEqual((data["ok"], data["error"]), (False, "FUNCTION_NOT_FOUND"))
        self.assertEqual(len(self.slots()), 1)
        self.assertEqual(data["backend"]["used"], "idalib")

    def test_timeouts_use_the_two_ceilings(self):
        self.q("summary", timeout_seconds=900)
        self.q("summary", timeout_seconds=900)
        self.assertEqual([c["timeout"] for c in self.worker_calls()], [ti._MAX_CREATE_TIMEOUT_SECONDS, ti._MAX_QUERY_TIMEOUT_SECONDS])

    def test_stdout_noise_is_neither_parsed_nor_a_failure(self):
        self.idalib.behaviour = "noisy"
        data = self.q("list_functions")
        self.assertTrue(data["ok"], data)
        self.assertNotIn("D810", json.dumps(data))

    def test_the_probe_cache_does_not_hide_a_changed_interpreter(self):
        self.q("summary")
        other = self.root / "venv2" / "python.exe"
        other.parent.mkdir()
        other.write_bytes(b"")
        os.environ[IDALIB_ENV] = str(other)
        self.idalib.python = str(other)
        self.q("summary")
        self.assertEqual(len(self.idalib.probes), 2)


class SessionFailureTests(IdalibCase):
    def assertLimited(self, data, error, status="ANALYSIS_LIMITED"):
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, status, error), data)
        self.assertEqual(data["backend"]["used"], "idalib")

    def test_a_garbled_result_file_is_a_parse_failure(self):
        self.idalib.behaviour = "garbage"
        data = self.q("summary")
        self.assertLimited(data, "RESULT_PARSE_FAILED", "RESULT_PARSE_FAILED")
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])

    def test_exit_zero_without_a_result_is_not_success(self):
        self.idalib.behaviour = "no_output"
        self.assertLimited(self.q("summary"), "IDA_NO_OUTPUT")
        self.assertEqual(self.slots(), [])

    def test_a_result_without_the_completion_marker_is_not_success(self):
        self.idalib.behaviour = "incomplete"
        self.assertLimited(self.q("summary"), "IDA_OUTPUT_INCOMPLETE")

    def test_a_nonzero_exit_after_a_complete_result_is_still_a_failure_and_says_so(self):
        self.idalib.behaviour = "nonzero"
        data = self.q("summary")
        self.assertLimited(data, "IDA_EXITED_NONZERO")
        self.assertEqual(data["signals"]["exit_diagnosis"]["class"], "NONZERO_EXIT_RESULT_COMPLETE")

    def test_a_fatal_log_line_is_a_failure_whatever_the_exit_code(self):
        self.idalib.behaviour = "fatal_log"
        self.assertLimited(self.q("summary"), "IDA_LOG_REPORTS_FAILURE")

    def test_a_traceback_on_stderr_is_a_failure_but_one_on_stdout_is_not(self):
        self.idalib.behaviour = "stderr_traceback"
        self.assertLimited(self.q("summary"), "IDA_LOG_REPORTS_FAILURE")

    def test_an_unreadable_log_does_not_count_as_a_clean_one(self):
        self.idalib.behaviour = "unreadable_log"
        self.assertLimited(self.q("summary"), "IDA_LOG_UNREADABLE")

    def test_a_result_that_answers_another_operation_is_refused(self):
        self.idalib.behaviour = "op_mismatch"
        self.assertLimited(self.q("summary"), "IDA_RESULT_OPERATION_MISMATCH")

    def test_a_worker_failure_is_reported_with_its_own_error(self):
        self.idalib.behaviour = "worker_failed"
        data = self.q("summary")
        self.assertLimited(data, "IDALIB_WORKER_FAILED")
        self.assertEqual(data["worker_error"], "IDALIB_OPEN_FAILED")

    def test_a_session_that_did_not_close_without_saving_is_not_success(self):
        self.idalib.behaviour = "not_closed"
        self.assertLimited(self.q("summary"), "DATABASE_CHANGES_NOT_DISCARDED")
        self.assertEqual(self.slots(), [])

    def test_a_first_analysis_that_left_no_database_is_not_success(self):
        self.idalib.behaviour = "no_db"
        self.assertLimited(self.q("summary"), "IDA_NO_DATABASE")
        self.assertEqual(self.slots(), [])

    def test_an_input_identity_mismatch_is_refused_and_a_cached_slot_dropped(self):
        self.q("summary")
        self.idalib.behaviour = "mismatch"
        data = self.q("list_functions")
        self.assertLimited(data, "IDA_INPUT_HASH_MISMATCH")
        self.assertEqual(self.slots(), [])

    def test_a_failed_first_analysis_promotes_nothing(self):
        self.idalib.behaviour = "mismatch"
        self.assertLimited(self.q("summary"), "IDA_INPUT_HASH_MISMATCH")
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])

    def test_an_oversized_result_file_is_refused_unread(self):
        with mock.patch.object(ti, "_IDALIB_MAX_RESULT_BYTES", 20):
            data = self.q("summary")
        self.assertLimited(data, "IDALIB_RESULT_TOO_LARGE")
        self.assertEqual(data["signals"]["result_limit_bytes"], 20)
        self.assertGreater(data["signals"]["result_file_bytes"], 20)

    def test_the_slot_moving_during_a_session_is_a_cache_violation_and_drops_it(self):
        self.q("summary")
        self.idalib.behaviour = "violation"
        data = self.q("list_functions")
        self.assertLimited(data, "CACHE_VIOLATION", "CACHE_VIOLATION")
        self.assertFalse(data["database_integrity"]["unchanged"])
        self.assertEqual(self.slots(), [])
        self.assertNotIn("items", data)
        self.assertEqual(self.q("list_functions", backend="idat")["database_cache"], "CREATED")

    def test_a_timeout_on_a_first_analysis_keeps_nothing(self):
        self.idalib.behaviour = "timeout"
        data = self.q("summary")
        self.assertLimited(data, "IDA_TIMEOUT_PROCESS_TREE_TERMINATED", "TIMEOUT")
        self.assertEqual(data["timed_out_stage"], "analysis")
        self.assertEqual(self.slots(), [])
        self.assertEqual(self.leftovers(), [])

    def test_a_timeout_on_a_cached_database_keeps_the_slot_because_a_copy_was_open(self):
        self.q("summary")
        before = (self.slots()[0] / ti._DB_NAME).read_bytes()
        self.idalib.behaviour = "timeout"
        data = self.q("list_functions")
        self.assertLimited(data, "IDA_TIMEOUT_PROCESS_TREE_TERMINATED", "TIMEOUT")
        self.assertEqual(data["timed_out_stage"], "query")
        self.assertEqual(len(self.slots()), 1)
        self.assertEqual((self.slots()[0] / ti._DB_NAME).read_bytes(), before)
        self.assertEqual(self.leftovers(), [])
        self.assertIn("nothing found", data["detail"])
        self.idalib.behaviour = "ok"
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")

    def test_cancellation_is_its_own_status_and_keeps_the_slot(self):
        self.q("summary")
        self.idalib.behaviour = "cancel"
        data = self.q("list_functions")
        self.assertLimited(data, "IDA_CANCELLED_PROCESS_TREE_TERMINATED", "CANCELLED")
        self.assertEqual(len(self.slots()), 1)

    def test_failure_tails_are_bounded_and_redacted(self):
        home = "C:" + "\\" + "Users" + "\\" + "Someone"
        self.idalib.log = CLEAN_LOG + f"opened {home}\\x\n"
        self.idalib.behaviour = "fatal_log"
        data = self.q("summary")
        text = json.dumps(data)
        self.assertNotIn("Someone", text)
        self.assertNotIn("AB12", text)
        self.assertLessEqual(len(data["stderr_tail"]), 2000)
        self.assertLessEqual(len(data["stdout_tail"]), 2000)

    def test_a_missing_packaged_worker_is_reported_not_raised(self):
        with mock.patch.object(ti, "_IDALIB_WORKER_SOURCE", self.root / "absent.idapy"):
            data = self.q("summary")
        self.assertLimited(data, "IDA_WORKER_MISSING")
        self.assertEqual(self.worker_calls(), [])

    def test_failed_scratch_is_kept_only_when_asked(self):
        self.idalib.behaviour = "garbage"
        with mock.patch.dict(os.environ, {ti.KEEP_FAILED_SCRATCH_ENV: "1"}):
            data = self.q("summary")
        self.assertTrue(data["scratch_retained"]["retained"])
        self.assertTrue(data["scratch_retained"]["contains_sensitive_content"])


class StatusTests(IdalibCase):
    def test_status_reports_the_idalib_probe_without_a_path_leak(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            data = json.loads(ti.ida_status())
        self.assertTrue(data["ok"], data)
        block = data["idalib"]
        self.assertEqual((block["status"], block["configured"], block["idapro_version"]), ("OK", True, "0.0.11"))
        self.assertEqual(block["library_version"], [9, 4, 260714])
        self.assertEqual(block["interpreter"], ti._redact(str(self.python)))
        self.assertEqual(data["auto_backend"]["selects"], "idalib")
        self.assertIn("not a database open", data["note"])

    def test_status_says_not_configured_and_auto_selects_idat(self):
        del os.environ[IDALIB_ENV]
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            data = json.loads(ti.ida_status())
        self.assertEqual(data["idalib"]["status"], "NOT_CONFIGURED")
        self.assertFalse(data["idalib"]["configured"])
        self.assertEqual(data["auto_backend"]["selects"], "idat")

    def test_status_always_probes_afresh(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=("PATH", "C:/fake/idat.exe")):
            ti.ida_status()
            ti.ida_status()
        self.assertEqual(len(self.idalib.probes), 2)

    def test_status_without_idat_still_reports_idalib(self):
        with mock.patch.object(ti, "_resolved_by_and_binary", return_value=(None, None)):
            data = json.loads(ti.ida_status())
        self.assertEqual(data["status"], "TOOL_MISSING")
        self.assertEqual(data["idalib"]["status"], "OK")


# ---------------------------------------------------------------------------
# the worker file as shipped
# ---------------------------------------------------------------------------
IDA_MODULES = ["ida_auto", "ida_bytes", "ida_funcs", "ida_hexrays", "ida_ida", "ida_loader", "ida_name", "ida_nalt",
               "ida_pro", "ida_segment", "ida_xref", "idaapi", "idautils", "idc"]


class WorkerFileTests(unittest.TestCase):
    def source(self):
        return WORKER.read_text(encoding="utf-8")

    def test_it_is_a_data_file_and_the_package_still_has_no_ida_py_module(self):
        self.assertEqual(WORKER.suffix, ".idapy")
        self.assertEqual(list(WORKER.parent.glob("*.py")), [])

    def test_no_bom_no_crlf_and_it_compiles(self):
        raw = WORKER.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        compile(raw.decode("utf-8"), str(WORKER), "exec")

    def test_idapro_is_the_first_import_after_the_standard_library(self):
        tree = ast.parse(self.source())
        order = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                order += [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                order.append((node.module or "").split(".")[0])
        stdlib = {"json", "os", "sys", "traceback"}
        self.assertEqual([n for n in order if n not in stdlib][:1], ["idapro"])
        self.assertNotIn("liebert_re", order)
        names = {n.split(".")[0] for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                 for n in ([a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""])}
        self.assertNotIn("liebert_re", names)

    def test_the_worker_has_exactly_one_open_and_only_ever_closes_without_saving(self):
        """The trap: a second `open_database` in a process silently SAVES and closes the first database."""
        tree = ast.parse(self.source())
        opens, closes = [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id == "idapro":
                (opens if node.func.attr == "open_database" else closes if node.func.attr == "close_database" else []).append(node)
        self.assertEqual(len(opens), 1)
        self.assertEqual(len(closes), 1)
        self.assertTrue(all(isinstance(c.args[0], ast.Constant) and c.args[0].value is False for c in closes))
        # the close is inside a `finally`
        finals = [n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.finalbody
                  for f in n.finalbody for c in ast.walk(f) if c in closes]
        self.assertTrue(finals)
        # and the open is not inside any loop
        for loop in (n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.While))):
            self.assertNotIn(opens[0], list(ast.walk(loop)))

    def test_the_query_logic_is_shared_not_copied(self):
        source = self.source()
        self.assertNotIn("def _op_", source)
        self.assertNotIn("_DISPATCH =", source)
        self.assertIn("liebert_query_ops", source)
        self.assertIn("_run(", source)

    def test_it_contains_no_write_operation(self):
        for api in ("set_name", "set_cmt", "set_func_cmt", "patch_bytes", "rename_lvar", "set_user_cmt", "del_items",
                    "create_insn", "apply_type", "set_type", "del_func", "add_func"):
            self.assertNotIn(api, self.source(), api)


def _load_worker_module():
    stubs = {n: mock.MagicMock(name=n) for n in IDA_MODULES + ["idapro"]}
    stubs["idc"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["ida_hexrays"].DecompilationFailure = type("DecompilationFailure", (Exception,), {})
    stubs["idc"].get_type.return_value = ""
    stubs["ida_name"].get_name.return_value = "f"
    stubs["idapro"].open_database.return_value = 0
    stubs["idapro"].get_library_version.return_value = (9, 4, 260714)
    stubs["ida_loader"].save_database.return_value = True
    stubs["ida_loader"].DBFL_TEMP = 4
    loader = SourceFileLoader("liebert_idalib_worker_under_test", str(WORKER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    patcher = mock.patch.dict(sys.modules, stubs)
    patcher.start()
    loader.exec_module(module)
    return module, stubs, patcher


class IdalibWorkerTests(unittest.TestCase):
    """The worker file run against stub `idapro` / `ida_*` modules, with the real shared operations file."""

    def setUp(self):
        self.module, self.ida, patcher = _load_worker_module()
        self.addCleanup(patcher.stop)
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.ops = self.tmp / "liebert_query_ops.py"
        self.ops.write_bytes(QUERY_WORKER.read_bytes())
        self.calls = []
        idapro, loader, utils = self.ida["idapro"], self.ida["ida_loader"], self.ida["idautils"]
        idapro.open_database.side_effect = lambda *a: (self.calls.append(("open", a)), 0)[1]
        idapro.close_database.side_effect = lambda *a: self.calls.append(("close", a))
        loader.save_database.side_effect = lambda *a: (self.calls.append(("save", a)), True)[1]
        utils.Functions.side_effect = lambda: iter([0x1000])
        self.ida["ida_name"].get_name.side_effect = lambda ea: (self.calls.append(("op", "get_name")), "f")[1]
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)

    def job(self, **fields):
        job = {"schema": 1, "mode": "copy", "output": str(self.tmp / "out.json"), "ops_path": str(self.ops),
               "database_name": "db.i64", "log_name": "ida.log", "max_result_bytes": 10 ** 7,
               "operations": [{"operation": "list_functions", "max_results": 5, "offset": 0}]}
        job.update(fields)
        return job

    def run_job(self, job):
        path = self.tmp / "job.json"
        path.write_text(json.dumps(job), encoding="utf-8")
        code = self.module.main(["worker", str(path)])
        out = Path(job["output"])
        return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None

    def kinds(self):
        return [c[0] for c in self.calls]

    def test_a_copy_session_opens_once_runs_the_operation_and_closes_without_saving(self):
        code, result = self.run_job(self.job())
        self.assertEqual(code, 0)
        self.assertEqual(self.kinds(), ["open", "op", "close"])
        _kind, (path, run_auto, arguments) = self.calls[0]
        self.assertEqual(Path(path).resolve(), (self.tmp / "db.i64").resolve())
        self.assertIs(run_auto, False)
        self.assertEqual(arguments, "-Opdb:off -Lida.log")
        self.assertEqual(self.calls[-1], ("close", (False,)))
        self.assertTrue(result["database_closed_without_save"])
        self.assertIsNone(result["database_saved_before_queries"])
        self.assertEqual([r["operation"] for r in result["results"]], ["list_functions"])
        self.assertEqual(result["results"][0]["items"][0]["address"], "0x1000")
        self.assertEqual(list(result)[-1], "script_completed")
        self.assertIs(result["script_completed"], True)
        self.assertEqual(result["library_version"], [9, 4, 260714])

    def test_a_create_session_analyses_the_input_and_saves_before_the_first_operation(self):
        job = self.job(mode="create", input=str(self.tmp / "in.bin"))
        code, result = self.run_job(job)
        self.assertEqual(code, 0)
        self.assertEqual(self.kinds(), ["open", "save", "op", "close"])
        _kind, (path, run_auto, arguments) = self.calls[0]
        self.assertEqual(path, str(self.tmp / "in.bin"))
        self.assertIs(run_auto, True)
        self.assertEqual(arguments, "-Opdb:off -Lida.log -odb.i64")
        self.assertEqual(Path(self.calls[1][1][0]).resolve(), (self.tmp / "db.i64").resolve())
        self.assertEqual(self.calls[1][1][1], 0)
        self.assertEqual(self.calls[-1], ("close", (False,)))       # the operations' own effects are not saved
        self.assertIs(result["database_saved_before_queries"], True)

    def test_several_operations_share_one_open(self):
        job = self.job(operations=[{"operation": "list_functions"}, {"operation": "segments"}, {"operation": "nope"}])
        _code, result = self.run_job(job)
        self.assertEqual(self.kinds().count("open"), 1)
        self.assertEqual(self.kinds().count("close"), 1)
        self.assertEqual([r["operation"] for r in result["results"]], ["list_functions", "segments", "nope"])
        self.assertEqual(result["results"][2]["error"], "UNKNOWN_OPERATION")

    def test_the_session_is_not_marked_temporary_and_claims_no_discard_itself(self):
        _code, result = self.run_job(self.job())
        self.ida["ida_loader"].set_database_flag.assert_not_called()
        self.assertNotIn("database_changes_discarded", result["results"][0])

    def test_a_failure_inside_the_session_still_closes_without_saving(self):
        code, result = self.run_job(self.job(ops_path=str(self.tmp / "missing_ops.py")))
        self.assertEqual(code, 3)
        self.assertEqual(result["error"], "IDALIB_WORKER_EXCEPTION")
        self.assertIn("Traceback", result["traceback"])
        self.assertEqual(self.kinds(), ["open", "close"])
        self.assertEqual(self.calls[-1], ("close", (False,)))
        self.assertTrue(result["database_closed_without_save"])

    def test_an_open_that_fails_closes_nothing_and_runs_nothing(self):
        self.ida["idapro"].open_database.side_effect = lambda *a: (self.calls.append(("open", a)), 1)[1]
        code, result = self.run_job(self.job())
        self.assertEqual(code, 0)
        self.assertEqual((result["ok"], result["error"], result["open_rc"]), (False, "IDALIB_OPEN_FAILED", 1))
        self.assertEqual(self.kinds(), ["open"])
        self.assertFalse(result["database_opened"])
        self.assertEqual(result["results"], [])

    def test_a_save_that_fails_stops_before_any_operation(self):
        self.ida["ida_loader"].save_database.side_effect = lambda *a: (self.calls.append(("save", a)), False)[1]
        _code, result = self.run_job(self.job(mode="create", input=str(self.tmp / "in.bin")))
        self.assertEqual(result["error"], "IDALIB_SAVE_FAILED")
        self.assertEqual(self.kinds(), ["open", "save", "close"])
        self.assertEqual(result["results"], [])

    def test_a_close_that_fails_is_recorded_and_the_exit_is_nonzero(self):
        def broken(*_args):
            raise RuntimeError("cannot close")
        self.ida["idapro"].close_database.side_effect = broken
        code, result = self.run_job(self.job())
        self.assertEqual(code, 3)
        self.assertFalse(result["database_closed_without_save"])
        self.assertIn("cannot close", result["close_error"])

    def test_an_oversized_result_is_replaced_by_a_small_error(self):
        code, result = self.run_job(self.job(max_result_bytes=50))
        self.assertEqual(code, 0)
        self.assertEqual(result["error"], "IDALIB_RESULT_TOO_LARGE")
        self.assertNotIn("results", result)
        self.assertGreater(result["result_bytes"], 50)
        self.assertEqual(list(result)[-1], "script_completed")

    def test_a_bad_job_exits_2_and_opens_nothing(self):
        for text in ("{not json", json.dumps({"mode": "copy"}), json.dumps(self.job(mode="weird"))):
            with self.subTest(text[:20]):
                (self.tmp / "bad.json").write_text(text, encoding="utf-8")
                self.assertEqual(self.module.main(["worker", str(self.tmp / "bad.json")]), 2)
        self.assertEqual(self.module.main(["worker"]), 2)
        self.assertEqual(self.module.main(["worker", str(self.tmp / "absent.json")]), 2)
        self.assertEqual(self.kinds(), [])

    def test_a_create_job_without_an_input_is_malformed(self):
        job = self.job(mode="create")
        (self.tmp / "bad.json").write_text(json.dumps(job), encoding="utf-8")
        self.assertEqual(self.module.main(["worker", str(self.tmp / "bad.json")]), 2)

    def test_importing_the_worker_has_no_side_effects(self):
        self.assertEqual(self.kinds(), [])
        self.assertFalse((self.tmp / "out.json").exists())


# ---------------------------------------------------------------------------
# a real child interpreter with stub modules on its path
# ---------------------------------------------------------------------------
_STUB_IDAPRO = '''
import json, os, time

def _log(**record):
    with open(os.environ["LIEBERT_STUB_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(record, pid=os.getpid())) + "\\n")

_state = {"open": False}

def open_database(path, run_auto, args=""):
    _log(call="open", path=path, run_auto=run_auto, args=args, cwd=os.getcwd())
    if _state["open"]:
        _log(call="SECOND_OPEN")
    _state["open"] = True
    if run_auto:
        for part in args.split():
            if part.startswith("-o"):
                open(part[2:], "wb").close()
    open("ida.log", "w", encoding="utf-8").write("Autoanalysis subsystem has been initialized.\\n")
    print("D810 initialized (version 0.0)")
    if os.environ.get("LIEBERT_STUB_BEHAVIOUR") == "hang":
        open(os.environ["LIEBERT_STUB_PIDFILE"], "w").write(str(os.getpid()))
        time.sleep(120)
    return 0

def close_database(save=True):
    _log(call="close", save=save)
    _state["open"] = False

def get_library_version():
    return (9, 4, 0)

def get_ida_install_dir():
    return os.environ["LIEBERT_STUB_INSTALL"]
'''

_STUB_MODULES = {
    "ida_auto": "def auto_wait():\n    return True\n",
    "idautils": "def Functions():\n    return iter([4096, 8192])\n\ndef Segments():\n    return iter([4096])\n",
    "idc": ("BADADDR = 0xFFFFFFFFFFFFFFFF\n\ndef get_type(ea):\n    return ''\n\n"
            "def get_name_ea_simple(name):\n    return BADADDR\n\ndef get_segm_name(ea):\n    return ''\n"),
    "ida_name": "def get_name(ea):\n    return 'sub_%x' % ea\n",
    "ida_nalt": ("import os\n\ndef retrieve_input_file_sha256():\n    return bytes.fromhex(os.environ['LIEBERT_STUB_SHA'])\n\n"
                 "def retrieve_input_file_md5():\n    return bytes.fromhex(os.environ['LIEBERT_STUB_MD5'])\n\n"
                 "def get_imagebase():\n    return 0x140000000\n"),
    "ida_loader": ("def save_database(path, flags):\n    open(path, 'wb').write(b'PACKED-DB' * 50)\n    return True\n\n"
                   "def get_file_type_name():\n    return 'Portable executable for AMD64 (PE)'\n"),
    "ida_ida": "def inf_get_procname():\n    return 'metapc'\n\ndef inf_is_64bit():\n    return True\n",
    "idaapi": "def get_kernel_version():\n    return '9.4'\n",
    "ida_hexrays": "class DecompilationFailure(Exception):\n    pass\n\ndef init_hexrays_plugin():\n    return False\n",
}


class IdalibSubprocessTests(IdaCase):
    """The real wrapper -> real child process -> real worker file, over stub `idapro` / `ida_*` modules."""

    def setUp(self):
        super().setUp()
        # IdaCase fakes the process boundary; this class wants the real one.
        patcher = mock.patch.object(ti, "run_bounded_process", _real_runner())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        (self.stubs / "idapro.py").write_text(_STUB_IDAPRO, encoding="utf-8")
        for name in IDA_MODULES:
            (self.stubs / f"{name}.py").write_text(_STUB_MODULES.get(name, ""), encoding="utf-8")
        self.install = self.root / "IDA"
        self.install.mkdir()
        self.log = self.root / "stub.jsonl"
        prefix = f"import sys\nsys.path.insert(0, {str(self.stubs)!r})\n"
        shim = self.root / "worker_with_stubs.idapy"
        shim.write_text(prefix + WORKER.read_text(encoding="utf-8"), encoding="utf-8")
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(ti, "_IDALIB_WORKER_SOURCE", shim))
        stack.enter_context(mock.patch.object(ti, "_IDALIB_PROBE_CODE", prefix + ti._IDALIB_PROBE_CODE))
        stack.enter_context(mock.patch.dict(os.environ, {
            IDALIB_ENV: sys.executable, "LIEBERT_STUB_LOG": str(self.log), "LIEBERT_STUB_INSTALL": str(self.install),
            "LIEBERT_STUB_SHA": self.sha, "LIEBERT_STUB_MD5": self.md5,
        }))

    def records(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_a_real_process_answers_creates_the_slot_then_hits_it_with_one_open_each(self):
        first = self.q("list_functions")
        self.assertTrue(first["ok"], first)
        self.assertEqual((first["backend"]["used"], first["database_cache"]), ("idalib", "CREATED"))
        self.assertEqual([i["address"] for i in first["items"]], ["0x1000", "0x2000"])
        second = self.q("list_functions")
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["database_cache"], "HIT")
        calls = self.records()
        self.assertEqual([c["call"] for c in calls], ["open", "close", "open", "close"])
        self.assertEqual([c["save"] for c in calls if c["call"] == "close"], [False, False])
        self.assertEqual(len({c["pid"] for c in calls}), 2)                  # one process per session
        self.assertNotIn("SECOND_OPEN", [c["call"] for c in calls])
        create, copy = calls[0], calls[2]
        self.assertEqual(create["path"], str(self.sample))
        self.assertTrue(create["run_auto"])
        self.assertIn("-Opdb:off", create["args"])
        self.assertFalse(copy["run_auto"])
        self.assertNotEqual(Path(copy["path"]).parent, self.slots()[0])      # the copy, never the slot itself
        self.assertEqual(self.leftovers(), [])

    def test_the_slot_database_is_the_saved_pristine_one_and_is_not_touched_by_later_questions(self):
        self.q("summary")
        db = self.slots()[0] / ti._DB_NAME
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        self.q("list_functions")
        self.q("decompile_function", "sub_1000")
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertEqual(db.read_bytes(), b"PACKED-DB" * 50)

    def test_the_probe_runs_in_the_child_and_reports_what_it_imported(self):
        public, private = ti._idalib_probe(use_cache=False)
        self.assertEqual((public["status"], public["idapro_version"]), ("OK", None))   # no dist-info for a stub: UNKNOWN stays None
        self.assertEqual(public["library_version"], [9, 4, 0])
        self.assertEqual(private["install_dir"], str(self.install))

    def test_banners_on_stdout_do_not_reach_the_answer_or_fail_it(self):
        data = self.q("summary")
        self.assertTrue(data["ok"], data)
        self.assertNotIn("D810", json.dumps(data))

    def test_a_path_with_a_space_works(self):
        spaced = self.root / "dir with space"
        spaced.mkdir()
        target = spaced / "my sample.exe"
        target.write_bytes(self.sample.read_bytes())
        with mock.patch.object(ti, "CACHE_ROOT", self.root / "cache with space"):
            data = json.loads(ti.ida_query(str(target), "list_functions"))
        self.assertTrue(data["ok"], data)

    def test_a_hung_session_is_killed_at_the_timeout_and_the_cached_slot_survives(self):
        self.q("summary")
        db = self.slots()[0] / ti._DB_NAME
        before = db.read_bytes()
        pidfile = self.root / "hang.pid"
        with mock.patch.object(ti, "_MIN_TIMEOUT_SECONDS", 1), \
                mock.patch.dict(os.environ, {"LIEBERT_STUB_BEHAVIOUR": "hang", "LIEBERT_STUB_PIDFILE": str(pidfile)}):
            started = time.monotonic()
            data = self.q("list_functions", timeout_seconds=1)
        self.assertEqual((data["status"], data["error"]), ("TIMEOUT", "IDA_TIMEOUT_PROCESS_TREE_TERMINATED"))
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(db.read_bytes(), before)
        self.assertEqual(self.leftovers(), [])
        pid = int(pidfile.read_text(encoding="utf-8"))
        for _ in range(50):
            if not conftest._pid_alive(pid):
                break
            time.sleep(0.1)
        self.assertFalse(conftest._pid_alive(pid), "the worker process outlived the timeout")
        self.assertEqual(self.q("list_functions")["database_cache"], "HIT")


def _real_runner():
    from liebert_re.bounded_subprocess import run_bounded_process
    return run_bounded_process


# ---------------------------------------------------------------------------
# the real engine
# ---------------------------------------------------------------------------
@pytest.mark.heavy
class IdalibRealInstallTests(unittest.TestCase):
    """idat and idalib answer the same questions the same way. Needs a licensed IDA, an idat, and
    LIEBERT_RE_IDALIB_PYTHON in the environment the suite is started from; skips otherwise."""

    @classmethod
    def setUpClass(cls):
        cls.python = conftest.IDALIB_PYTHON_AT_START
        if not cls.python:
            raise unittest.SkipTest(f"{IDALIB_ENV} is not set")
        if not ti.ida_available():
            raise unittest.SkipTest("IDA Pro (idat) is not installed")
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls._tmp = TemporaryDirectory(prefix="liebert-idalib-")
        cls.root = Path(cls._tmp.name)
        code = bytes.fromhex("554889e531c05dc3") + b"\x90" * 8 + bytes.fromhex("e8ebffffffc3")
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", code)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        # short on purpose: idat resolves its `-S` script by a relative name and failed ("could not locate file") on
        # scratch paths near the Windows path-length limit, which a long test name in the directory name reaches
        self.cache = self.root / f"c{hashlib.sha256(self.id().encode()).hexdigest()[:6]}"
        self.evidence = self.cache / "evidence"
        self.evidence.mkdir(parents=True)
        stack.enter_context(mock.patch.object(ti, "EVIDENCE", self.evidence))
        stack.enter_context(mock.patch.object(ti, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(ti, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))
        stack.enter_context(mock.patch.dict(os.environ, {IDALIB_ENV: self.python}))

    def ask(self, backend, root, operation, query="", spaced=False, **kw):
        if spaced and backend == "idalib":
            # A space in the cache path, on purpose: the idalib worker is handed its paths as data, not through a
            # command-line switch.
            root = root.parent / (root.name + " with space")
        with mock.patch.object(ti, "CACHE_ROOT", root):
            return json.loads(ti.ida_query(str(self.pe), operation, query, backend=backend, **kw))

    QUESTIONS = (("list_functions", ""), ("decompile_function", "start"), ("xrefs_to", "0x140001000"),
                 ("read_bytes", "0x140001000 8"))

    def test_idat_and_idalib_give_equal_answers_on_a_first_analysis_and_on_a_cache_hit(self):
        for backend in ("idat", "idalib"):
            for operation, query in self.QUESTIONS:
                answer = self.ask(backend, self.cache / backend, operation, query, spaced=True)
                self.assertTrue(answer["ok"], answer)
                self.assertEqual(answer["backend"]["used"], backend)
        for operation, query in self.QUESTIONS:
            with self.subTest(operation):
                by = {b: self.ask(b, self.cache / b, operation, query, spaced=True) for b in ("idat", "idalib")}
                self.assertEqual(by["idat"]["database_cache"], "HIT")
                self.assertEqual(by["idalib"]["database_cache"], "HIT")
                self.assertEqual(_normalised(operation, by["idat"]), _normalised(operation, by["idalib"]))

    def test_an_idalib_built_database_is_answered_identically_by_idat_and_is_never_modified(self):
        root = self.cache / "shared"
        built = self.ask("idalib", root, "summary")
        self.assertEqual(built["database_cache"], "CREATED")
        self.assertEqual(self.ask("idat", root, "list_functions")["database_cache"], "HIT")   # idat reads what idalib built
        db = next(root.rglob("db.i64"))
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        for operation, query in self.QUESTIONS:
            self.ask("idalib", root, operation, query)
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertEqual(self.ask("idat", root, "decompile_function", "start")["decompiled"],
                         self.ask("idalib", root, "decompile_function", "start")["decompiled"])
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
        self.assertEqual(self.ask("idalib", root, "list_functions")["items"][0]["signature"], "")

    def test_status_reports_the_working_interpreter(self):
        with mock.patch.object(ti, "CACHE_ROOT", self.cache / "status"):
            data = json.loads(ti.ida_status())
        self.assertEqual(data["idalib"]["status"], "OK", data)
        self.assertRegex(data["idalib"]["idapro_version"], r"^\d")
        self.assertNotIn(os.path.expanduser("~"), json.dumps(data["idalib"]))
