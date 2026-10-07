"""`liebert_re.tools.ida.ida_script`: caller-written IDAPython on a discarded copy of the cached database.

Fast tier: nothing here starts IDA. Four stand-ins, each at a different boundary:

* `GuardTests` / `PrecheckTests`: the gate, the idalib-only rule and the AST accident guard, which all answer
  BEFORE any process starts (the fake process boundary records that nothing was launched).
* `FakeScriptIdalib` replaces the process boundary (`run_bounded_process`), like `FakeIdalib` in
  `test_tools_ida_idalib.py`: it plays the worker's contract for a `script` job (job file in, result file out)
  with named misbehaviours. This is where the wrapper's rules are pinned: the copy-on-open session, the slot hash
  before and after, every status, the evidence record and the withheld result.
* The worker file itself is executed against stub `idapro` / `ida_*` modules in this process
  (`ScriptWorkerTests`): result capture, bounded stdout, exceptions, the one open and the discarding close.
* `ScriptSubprocessTests` runs the real wrapper against the real worker in a real child interpreter with stub
  modules: the timeout kill, stdout noise that must not be parsed, and a script that DOES get past the guard and
  overwrites the cache slot (the guard is not a sandbox; the slot hash is what catches it).

The real engine is `ScriptRealInstallTests` (heavy; needs LIEBERT_RE_IDALIB_PYTHON in the environment the suite
is started from): a function-count script equals `list_functions`, and a script that renames a function leaves
the cached database byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import pytest

import liebert_re.tools.ida as ti
from tests import conftest
from tests.test_tools_ida import _cp
from tests.test_tools_ida_idalib import (
    IDA_MODULES, IDALIB_ENV, WORKER, FakeIdalib, IdalibCase, _load_worker_module, _real_runner,
    _STUB_IDAPRO, _STUB_MODULES,
)

GATE = ti.SCRIPT_GATE_ENV
GOOD_SCRIPT = "import idautils\nresult = len(list(idautils.Functions()))\n"
HOME_TRACEBACK = (
    "Traceback (most recent call last):\n"
    "  File \"C:\\Users\\SomeOperator\\AppData\\Local\\Temp\\work\\script.py\", line 3, in <module>\n"
    "ValueError: bad input\n"
)


class FakeScriptIdalib(FakeIdalib):
    """`FakeIdalib` that also plays a `script` job.

    `script_behaviour` is a name or a callable ``job -> name``: ok / no_result / not_json / too_large / exception /
    syntax / hash_mismatch / unreadable / unknown / timeout / cancel / memory / resource / violation / not_closed /
    input_mismatch / no_output / fatal_log / nonzero / evidence_noise.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.script_behaviour = "ok"
        self.script_value = {"function_count": 3, "names": ["a", "b"]}
        self.script_calls = []

    def __call__(self, command, *, timeout_seconds, cancellation_token=None, cwd=None, environment=None,
                 max_output_chars=None, max_memory_bytes=None):
        job = None
        if str(command[0]) == self.python and "-c" not in command:
            job = json.loads((Path(cwd) / ti._IDALIB_JOB_NAME).read_text(encoding="utf-8"))
        if job is not None and job["mode"] == "script":
            return self._script(command, job, Path(cwd), timeout_seconds, environment, max_memory_bytes)
        return super().__call__(command, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
                                cwd=cwd, environment=environment, max_output_chars=max_output_chars)

    def _outcome(self, name, job):
        common = {"compiled_by": "ida_python", "auto_wait": True, "engine_input_sha256": self.sha256,
                  "engine_input_md5": self.md5, "stdout_tail": "printed line\n", "stdout_chars": 13,
                  "stdout_truncated": False, "script_sha256_seen": job["script_sha256"]}
        if name == "input_mismatch":
            common["engine_input_sha256"] = "0" * 64
        if name in ("ok", "input_mismatch", "fatal_log", "nonzero", "not_closed", "violation"):
            text = json.dumps(self.script_value)
            return dict(common, status="OK", result=self.script_value, result_chars=len(text),
                        result_type=type(self.script_value).__name__)
        if name == "no_result":
            return dict(common, status="NO_RESULT")
        if name == "not_json":
            return dict(common, status="NOT_JSON", result_type="set", error="TypeError: Object of type set is not JSON serializable")
        if name == "too_large":
            return dict(common, status="TOO_LARGE", result_chars=70000, max_result_chars=job["max_result_chars"],
                        result_type="str")
        if name == "exception":
            return dict(common, status="EXCEPTION", exception={
                "type": "ValueError", "message": "bad input at C:\\Users\\SomeOperator\\x", "traceback": HOME_TRACEBACK})
        if name == "syntax":
            return dict(common, status="SYNTAX_ERROR", error="SyntaxError: invalid syntax (<liebert_script>, line 2)", line=2)
        if name == "hash_mismatch":
            return dict(common, status="HASH_MISMATCH", expected_sha256=job["script_sha256"])
        if name == "unreadable":
            return dict(common, status="UNREADABLE", error="FileNotFoundError: gone")
        return dict(common, status="SOMETHING_NEW")

    def _script(self, command, job, work, timeout, environment, max_memory_bytes):
        slot = work.parent
        self.script_calls.append({
            "command": list(command), "cwd": work, "job": job, "timeout": timeout, "environment": dict(environment),
            "max_memory_bytes": max_memory_bytes, "script": (work / "script.py").read_bytes(),
            "copy": (work / ti._DB_NAME).read_bytes() if (work / ti._DB_NAME).exists() else None,
            "slot_db": (slot / ti._DB_NAME).read_bytes() if (slot / ti._DB_NAME).exists() else None,
            "files": sorted(q.name for q in work.iterdir()), "worker": (work / ti._IDALIB_JOB_SCRIPT).read_bytes(),
        })
        name = self.script_behaviour(job) if callable(self.script_behaviour) else self.script_behaviour
        if name == "timeout":
            return _cp(None, timed_out=True)
        if name == "cancel":
            return _cp(None, cancelled=True)
        if name == "memory":
            return _cp(None, memory_exceeded=True, process_tree_terminated=True)
        if name == "resource":
            return _cp(None, resource_limit_unavailable=True)
        log = self.log + ("FATAL ERROR: Oops! internal error 1228 occurred.\n" if name == "fatal_log" else "")
        (work / ti._LOG_NAME).write_text(log, encoding="utf-8")
        if name == "violation":
            (slot / ti._DB_NAME).write_bytes(b"OVERWRITTEN BY THE SCRIPT")
        if name == "no_output":
            return _cp(0)
        envelope = {
            "ok": True, "schema": 1, "backend": "idalib", "mode": "script", "results": [], "database_opened": True,
            "database_saved_before_queries": None, "database_closed_without_save": name != "not_closed",
            "close_error": None, "open_rc": 0, "idapro_version": "0.0.11", "library_version": [9, 4, 260714],
            "script": self._outcome(name, job), "script_completed": True,
        }
        Path(job["output"]).write_text(json.dumps(envelope), encoding="utf-8")
        return _cp(3, stderr="boom\n") if name == "nonzero" else _cp(0)


class ScriptCase(IdalibCase):
    """`IdalibCase` with the script gate open, a private evidence directory and the script-capable fake."""

    def setUp(self):
        super().setUp()
        self.idalib = FakeScriptIdalib(self.python, self.fake, self.sha, self.md5)
        patcher = mock.patch.object(ti, "run_bounded_process", side_effect=self.idalib)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.script_evidence = self.root / "script_evidence"
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(ti, "EVIDENCE_SCRIPT", self.script_evidence))
        stack.enter_context(mock.patch.dict(os.environ, {GATE: "authorized"}))
        stack.enter_context(mock.patch("liebert_re.bounded_subprocess._memory_monitor_usable", return_value=True))

    def s(self, script=GOOD_SCRIPT, path=None, **kwargs):
        return json.loads(ti.ida_script(str(path or self.sample), script, **kwargs))

    def started_nothing(self):
        return not (self.idalib.probes or self.idalib.calls or self.idalib.script_calls or self.fake.calls)

    def evidence_files(self):
        return sorted(self.script_evidence.glob("*_script.json")) if self.script_evidence.is_dir() else []

    def warm(self):
        """Create the cache slot (a first analysis) so the next script call is a HIT."""
        self.assertTrue(self.q("summary")["ok"])
        self.idalib.calls.clear()
        self.idalib.probes.clear()


# ---------------------------------------------------------------------------
# the gate, the backend rule, argument checks: nothing starts
# ---------------------------------------------------------------------------
class GateAndBackendTests(ScriptCase):
    def test_a_closed_gate_starts_nothing_and_reads_nothing(self):
        for value in (None, "", "1", "true", "yes", "AUTHORIZED ", "authorised"):
            with self.subTest(value=value):
                env = dict(os.environ)
                env.pop(GATE, None)
                if value is not None:
                    env[GATE] = value
                with mock.patch.dict(os.environ, env, clear=True):
                    data = self.s()
                if value == "AUTHORIZED ":      # exact value, case included; only surrounding blanks are ignored
                    self.assertEqual(data["status"], "AUTHORIZATION_REQUIRED")
                self.assertFalse(data["ok"])
                self.assertEqual(data["status"], "AUTHORIZATION_REQUIRED")
                self.assertEqual(data["error"], "SCRIPT_GATE_CLOSED")
                self.assertEqual(data["required_environment"], f"{GATE}=authorized")
                self.assertTrue(self.started_nothing())
                self.assertFalse(self.cache.exists())
                self.assertFalse(self.script_evidence.exists())

    def test_the_gate_is_checked_before_the_script_the_path_and_the_backend(self):
        with mock.patch.dict(os.environ, {GATE: ""}):
            for kwargs in ({"script": ""}, {"script": "import os"}, {"path": self.root / "nowhere.exe"},
                           {"backend": "idat"}, {"backend": "nonsense"}):
                with self.subTest(kwargs=kwargs):
                    self.assertEqual(self.s(**kwargs)["status"], "AUTHORIZATION_REQUIRED")

    def test_the_gate_is_open_with_the_exact_value(self):
        self.assertTrue(self.s()["ok"])
        with mock.patch.dict(os.environ, {GATE: "  authorized  "}):
            self.assertTrue(self.s()["ok"])

    def test_idat_is_unsupported_and_nothing_starts(self):
        data = self.s(backend="idat")
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "UNSUPPORTED")
        self.assertEqual(data["error"], "IDALIB_BACKEND_REQUIRED")
        self.assertIn("requires the idalib copy-on-open backend", data["reason"])
        self.assertIn("LIEBERT_RE_IDALIB_PYTHON", data["reason"])
        self.assertTrue(self.started_nothing())
        self.assertFalse(self.cache.exists())

    def test_an_unconfigured_idalib_is_unsupported_without_a_probe(self):
        del os.environ[IDALIB_ENV]
        for backend in ("auto", "idalib"):
            with self.subTest(backend):
                data = self.s(backend=backend)
                self.assertEqual(data["status"], "UNSUPPORTED")
                self.assertIn("requires the idalib copy-on-open backend (set LIEBERT_RE_IDALIB_PYTHON)", data["reason"])
                self.assertEqual(data["idalib"]["status"], "NOT_CONFIGURED")
                self.assertTrue(self.started_nothing())
        self.assertFalse(self.cache.exists())

    def test_a_configured_interpreter_that_cannot_import_idapro_is_unsupported_and_says_why(self):
        self.idalib.probe = {"import_ok": False, "error": "ModuleNotFoundError: No module named 'idapro'"}
        data = self.s()
        self.assertEqual(data["status"], "UNSUPPORTED")
        self.assertIn("IDAPRO_IMPORT_FAILED", data["reason"])
        self.assertEqual(self.idalib.calls, [])
        self.assertEqual(self.idalib.script_calls, [])
        self.assertFalse(self.cache.exists())

    def test_an_unknown_backend_is_refused_by_name(self):
        data = self.s(backend="quantum")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "UNKNOWN_BACKEND"))
        self.assertTrue(self.started_nothing())

    def test_a_host_that_cannot_measure_memory_fails_closed_before_anything_starts(self):
        with mock.patch("liebert_re.bounded_subprocess._memory_monitor_usable", return_value=False):
            data = self.s()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RESOURCE_LIMIT_UNAVAILABLE")
        self.assertEqual(self.idalib.calls, [])
        self.assertEqual(self.idalib.script_calls, [])
        self.assertFalse(self.cache.exists())

    def test_a_missing_input_and_a_database_input_are_refused_before_any_session(self):
        self.assertEqual(self.s(path=self.root / "nowhere.exe")["status"], "NOT_FOUND")
        database = self.root / "x.i64"
        database.write_bytes(b"IDA")
        data = self.s(path=database)
        self.assertEqual(data["error"], "DATABASE_INPUT_NOT_SUPPORTED")
        self.assertTrue(self.started_nothing())

    def test_a_refusal_before_the_session_does_not_name_the_target(self):
        data = self.s(path=self.root / "nowhere.exe")
        self.assertNotIn("nowhere", json.dumps(data))


class PrecheckTests(ScriptCase):
    def refused(self, script):
        data = self.s(script)
        self.assertFalse(data["ok"], data)
        self.assertTrue(self.started_nothing(), "a refused script must not start anything")
        self.assertFalse(self.cache.exists())
        return data

    def test_empty_and_non_string_scripts_are_invalid(self):
        for script in ("", "   \n\t ", None, 42, b"result = 1", ["result = 1"]):
            with self.subTest(script=script):
                data = self.refused(script)
                self.assertEqual((data["status"], data["error"], data["reason"]), ("ANALYSIS_LIMITED", "SCRIPT_INVALID", "SCRIPT_EMPTY"))

    def test_an_oversize_a_nul_and_a_non_utf8_script_are_invalid_with_a_reason(self):
        data = self.refused("x = 1\n" * 20000)
        self.assertEqual((data["error"], data["reason"]), ("SCRIPT_INVALID", "SCRIPT_TOO_LARGE"))
        self.assertEqual(data["limit_bytes"], ti._SCRIPT_MAX_BYTES)
        self.assertEqual(self.refused("result = 1\x00")["reason"], "SCRIPT_CONTAINS_NUL")
        self.assertEqual(self.refused("result = '\ud800'")["reason"], "SCRIPT_NOT_UTF8")

    def test_a_syntax_error_is_reported_with_its_line_and_who_compiled_it(self):
        data = self.refused("result = 1\nif True print(1)\n")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "SCRIPT_SYNTAX_ERROR"))
        self.assertEqual(data["compiled_by"], "harness_python")
        self.assertEqual(data["line"], 2)
        self.assertIn("Nothing was started", data["detail"])

    def test_a_valid_script_passes_every_precheck(self):
        script, refusal = ti._script_precheck(GOOD_SCRIPT)
        self.assertIsNone(refusal)
        self.assertEqual(script["raw"], GOOD_SCRIPT.encode("utf-8"))
        self.assertEqual(script["sha256"], hashlib.sha256(GOOD_SCRIPT.encode("utf-8")).hexdigest())
        self.assertEqual((script["bytes"], script["lines"]), (len(GOOD_SCRIPT), 2))
        for text in ("result = 1", "result = 1\n"):
            self.assertEqual(ti._script_precheck(text)[0]["lines"], 1)


# ---------------------------------------------------------------------------
# the accident guard: one example per forbidden category, and the documented gap
# ---------------------------------------------------------------------------
GUARD_REFUSALS = {
    "import os": "FORBIDDEN_IMPORT",
    "import subprocess": "FORBIDDEN_IMPORT",
    "import sys": "FORBIDDEN_IMPORT",
    "import socket": "FORBIDDEN_IMPORT",
    "import shutil": "FORBIDDEN_IMPORT",
    "import pathlib": "FORBIDDEN_IMPORT",
    "import ctypes": "FORBIDDEN_IMPORT",
    "import importlib": "FORBIDDEN_IMPORT",
    "import builtins": "FORBIDDEN_IMPORT",
    "import urllib.request": "FORBIDDEN_IMPORT",
    "import http.client": "FORBIDDEN_IMPORT",
    "import multiprocessing": "FORBIDDEN_IMPORT",
    "import threading": "FORBIDDEN_IMPORT",
    "import asyncio": "FORBIDDEN_IMPORT",
    "import ida_dbg": "FORBIDDEN_IMPORT",
    "import ida_idd": "FORBIDDEN_IMPORT",
    "import ida_fpro": "FORBIDDEN_IMPORT",
    "import ida_expr": "FORBIDDEN_IMPORT",
    "import ida_registry": "FORBIDDEN_IMPORT",
    "import idapro": "FORBIDDEN_IMPORT",
    "from os import path": "FORBIDDEN_IMPORT",
    "from os.path import join": "FORBIDDEN_IMPORT",
    "import tempfile": "IMPORT_NOT_ALLOWED",
    "import requests": "IMPORT_NOT_ALLOWED",
    "import pickle": "IMPORT_NOT_ALLOWED",
    "from . import sibling": "RELATIVE_IMPORT",
    "from idc import os": "FORBIDDEN_IMPORTED_NAME",
    "from ida_loader import save_database": "FORBIDDEN_IMPORTED_NAME",
    "x = open('f')": "FORBIDDEN_NAME",
    "exec('1')": "FORBIDDEN_NAME",
    "eval('1')": "FORBIDDEN_NAME",
    "compile('1', 'f', 'eval')": "FORBIDDEN_NAME",
    "__import__('os')": "FORBIDDEN_NAME",
    "getattr(1, 'real')": "FORBIDDEN_NAME",
    "setattr(object, 'x', 1)": "FORBIDDEN_NAME",
    "delattr(object, 'x')": "FORBIDDEN_NAME",
    "globals()": "FORBIDDEN_NAME",
    "vars()": "FORBIDDEN_NAME",
    "locals()": "FORBIDDEN_NAME",
    "breakpoint()": "FORBIDDEN_NAME",
    "x = __builtins__": "DUNDER_NAME",
    "x = __loader__": "DUNDER_NAME",
    "x = ().__class__": "PRIVATE_ATTRIBUTE",
    "x = (1).__class__.__subclasses__()": "PRIVATE_ATTRIBUTE",
    "import idc\nx = idc._get_hidden": "PRIVATE_ATTRIBUTE",
    "import ida_loader\nida_loader.save_database('x', 0)": "FORBIDDEN_ATTRIBUTE",
    "import ida_loader\nida_loader.gen_file(1, None, 0, 0, 0)": "FORBIDDEN_ATTRIBUTE",
    "import ida_loader\nida_loader.gen_exe_file(None)": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.eval_idc('Message(1)')": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.eval_idc_expr()": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.os.system('x')": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.sys.exit(1)": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.start_process('x', '', '')": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.attach_process(1, -1)": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.run_to(0)": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.fopen('f', 'w')": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.savefile(1, 0, 0, 0)": "FORBIDDEN_ATTRIBUTE",
    "import idc\nidc.loadfile('f', 0, 0, 1)": "FORBIDDEN_ATTRIBUTE",
    "import ida_loader\nida_loader.load_plugin('x')": "FORBIDDEN_ATTRIBUTE",
    "import ida_idaapi\nida_idaapi.IDAPython_ExecScript('x', {})": "FORBIDDEN_ATTRIBUTE",
    "import ida_dbg_free\nx = 1": None,                                  # ida_* but not a name on the list: allowed
    "idapro.open_database('x', True)": "FORBIDDEN_NAME",
    "open_database('x', True)": "FORBIDDEN_NAME",
    "close_database(False)": "FORBIDDEN_NAME",
    "save_database('x', 0)": "FORBIDDEN_NAME",
    "import ida_loader\nida_loader.open_database('x')": "FORBIDDEN_ATTRIBUTE",
    "import ida_loader\nida_loader.close_database(False)": "FORBIDDEN_ATTRIBUTE",
    "import ida_loader\nx = ida_loader.dbg_xyz": "FORBIDDEN_ATTRIBUTE",
}


class GuardTests(ScriptCase):
    def test_every_forbidden_category_is_refused_before_anything_starts(self):
        for script, rule in GUARD_REFUSALS.items():
            if rule is None:
                continue
            with self.subTest(script=script):
                data = self.s(script)
                self.assertFalse(data["ok"], data)
                self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "SCRIPT_GUARD_REFUSED"))
                self.assertIn(rule, {f["rule"] for f in data["findings"]}, data["findings"])
                self.assertEqual(data["guard"], {"kind": "ACCIDENT_GUARD_NOT_A_SANDBOX", "version": 1})
                self.assertIn("not a sandbox", data["detail"].lower())
                self.assertIn("Nothing was started", data["detail"])
                for finding in data["findings"]:
                    self.assertEqual(set(finding), {"rule", "name", "line", "column"})
                self.assertTrue(self.started_nothing())
        self.assertFalse(self.cache.exists())
        self.assertFalse(self.script_evidence.exists())

    def test_the_guard_names_the_line_and_the_name(self):
        data = self.s("import re\n\nimport ida_loader\nida_loader.save_database('x', 0)\n")
        (finding,) = data["findings"]
        self.assertEqual((finding["rule"], finding["name"], finding["line"]), ("FORBIDDEN_ATTRIBUTE", "save_database", 4))

    def test_findings_are_deduplicated_ordered_and_capped(self):
        data = self.s("import os\nimport sys\n" + "open('x')\n" * 100)
        lines = [f["line"] for f in data["findings"]]
        self.assertEqual(lines, sorted(lines))
        self.assertEqual(len(data["findings"]), ti._GUARD_MAX_FINDINGS)
        self.assertGreater(data["finding_count"], ti._GUARD_MAX_FINDINGS)

    def test_every_forbidden_example_is_syntactically_valid_python(self):
        """A guard example that fails to parse would be refused for the wrong reason and prove nothing."""
        for script in GUARD_REFUSALS:
            with self.subTest(script=script):
                compile(script, "<example>", "exec")

    def test_what_the_guard_allows_it_allows(self):
        allowed = (
            GOOD_SCRIPT,
            "import re, struct, math, collections, itertools, functools, hashlib, binascii, json, bisect, heapq, array\n"
            "result = re.compile('a').pattern\n",
            "import ida_hexrays, ida_funcs, ida_name, ida_bytes, ida_typeinf, idaapi, idc, idautils\n"
            "from ida_funcs import get_func\nresult = [hex(ea) for ea in idautils.Functions()][:3]\n",
            "import json\nresult = json.loads(json.dumps({'a': [1, 2.5, None, 'x']}))\n",
            "def helper(n):\n    return n * 2\nresult = sorted(helper(i) for i in range(3))\n",
            "if __name__ == '__liebert_script__':\n    result = LIEBERT_CONTEXT['input_sha256']\n",
        )
        for script in allowed:
            with self.subTest(script=script[:60]):
                self.assertIsNone(ti._script_precheck(script)[1])

    def test_a_known_bypass_passes_the_guard_and_the_answer_says_it_is_not_a_sandbox(self):
        """The guard is syntactic. `json` is allowed and itself imports `codecs`, which has `open`: reading or writing
        a host file needs no name on the lists. This is a documented gap, pinned so nobody mistakes the guard for a
        sandbox; closing it is a different mechanism (a guest, a job object), not a longer list."""
        import json as stdlib_json
        self.assertTrue(hasattr(stdlib_json, "codecs"), "the example relies on json importing codecs")
        bypass = "import json\nhandle = json.codecs.open('any_host_file', 'rb')\nresult = 1\n"
        self.assertIsNone(ti._script_precheck(bypass)[1], "the example must actually get past the guard")
        data = self.s(bypass)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["script"]["guard"], {"kind": "ACCIDENT_GUARD_NOT_A_SANDBOX", "version": 1})
        self.assertIn("not a sandbox", data["note"].lower())
        self.assertEqual(data["execution"]["filesystem"], "NOT_ENFORCED")
        self.assertEqual(data["execution"]["network"], "NOT_ENFORCED")
        self.assertEqual(data["execution"]["child_processes"], "NOT_ENFORCED")
        self.assertEqual(data["execution"]["environment"], "INHERITED")
        self.assertIn("not a sandbox", ti.ida_script.__doc__.lower())
        self.assertIn("NOT_ENFORCED", json.dumps(data))


# ---------------------------------------------------------------------------
# the session: copy on open, the slot measured, every outcome
# ---------------------------------------------------------------------------
class SessionTests(ScriptCase):
    def test_a_first_call_analyses_in_its_own_session_then_runs_the_script_on_a_copy(self):
        data = self.s()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["database_cache"], "CREATED")
        self.assertEqual([c["job"]["mode"] for c in self.idalib.calls], ["create"])
        self.assertEqual(len(self.idalib.script_calls), 1)
        self.assertEqual(self.idalib.calls[0]["job"]["operations"][0]["operation"], "summary")
        (slot,) = self.slots()
        self.assertEqual(self.idalib.script_calls[0]["cwd"].parent, slot)
        self.assertEqual(self.leftovers(), [])

    def test_a_cache_hit_runs_one_session_and_never_opens_the_slot_itself(self):
        self.warm()
        data = self.s()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["database_cache"], "HIT")
        self.assertEqual(self.idalib.calls, [])
        (call,) = self.idalib.script_calls
        (slot,) = self.slots()
        self.assertNotEqual(call["cwd"], slot)
        self.assertEqual(call["cwd"].parent, slot)
        self.assertEqual(call["copy"], call["slot_db"])               # the copy is the cached database, byte for byte
        self.assertEqual(call["job"]["database_name"], ti._DB_NAME)
        self.assertEqual(self.leftovers(), [])                        # the scratch copy is always removed

    def test_the_job_the_worker_receives(self):
        self.warm()
        self.s("result = LIEBERT_CONTEXT\n", timeout_seconds=77, max_result_chars=1234, max_stdout_chars=99,
               max_memory_bytes=3 * 1024 ** 3)
        (call,) = self.idalib.script_calls
        job = call["job"]
        self.assertEqual(job["mode"], "script")
        self.assertNotIn("operations", job)
        self.assertNotIn("ops_path", job)
        self.assertEqual((job["max_result_chars"], job["max_stdout_chars"]), (1234, 99))
        self.assertEqual(job["input_sha256"], self.sha)
        self.assertEqual(call["script"], b"result = LIEBERT_CONTEXT\n")
        self.assertEqual(job["script_sha256"], hashlib.sha256(call["script"]).hexdigest())
        self.assertEqual(call["timeout"], 77)
        self.assertEqual(call["max_memory_bytes"], 3 * 1024 ** 3)
        self.assertEqual(call["files"], sorted([ti._DB_NAME, "script.py", ti._IDALIB_JOB_NAME, ti._IDALIB_JOB_SCRIPT]))
        self.assertEqual(call["worker"], ti._IDALIB_WORKER_SOURCE.read_bytes().replace(b"\r\n", b"\n"))
        self.assertEqual(call["command"][1:4], ["-I", "-X", "utf8"])      # -I: no PYTHON* variables, no cwd modules
        self.assertEqual(call["command"][0], str(self.python))

    def test_the_success_answer_and_what_it_claims(self):
        self.warm()
        data = self.s()
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["tool"], "ida_script")
        self.assertEqual(data["target_sha256"], self.sha)
        self.assertEqual(data["result_kind"], "SCRIPT_REPORTED")
        self.assertEqual(data["script_result"], {"function_count": 3, "names": ["a", "b"]})
        self.assertFalse(data["script_result_redacted"])
        self.assertEqual(data["provenance"]["status"], "VERIFIED")
        self.assertEqual(data["backend"]["used"], "idalib")
        self.assertEqual(data["backend"]["requested"], "auto")
        self.assertEqual(data["script"], {"sha256": hashlib.sha256(GOOD_SCRIPT.encode()).hexdigest(),
                                          "bytes": len(GOOD_SCRIPT), "lines": 2,
                                          "guard": {"kind": "ACCIDENT_GUARD_NOT_A_SANDBOX", "version": 1}})
        execution = data["execution"]
        self.assertEqual(execution["session"], "open_of_scratch_copy")
        self.assertIs(execution["copy_discarded"], True)
        self.assertIs(execution["slot_database_integrity"]["unchanged"], True)
        self.assertEqual(execution["slot_database_integrity"]["database_sha256_before"],
                         execution["slot_database_integrity"]["database_sha256_after"])
        self.assertEqual((execution["child_processes"], execution["network"], execution["filesystem"]),
                         ("NOT_ENFORCED",) * 3)
        self.assertEqual(execution["environment"], "INHERITED")
        self.assertEqual(execution["timeout_seconds"], 120)
        self.assertEqual(execution["memory_limit_bytes"], 4 * 1024 ** 3)
        self.assertIn("script_result is the script's claim", data["claim_basis"])
        self.assertIn("the harness did not verify its content", data["claim_basis"])
        self.assertIn("completed inside IDA", data["claim_basis"])
        self.assertEqual(data["stdout_tail"], "printed line\n")
        self.assertNotIn("path", data)                         # the answer is keyed by the hash, never by the file name
        self.assertNotIn(self.sample.name, json.dumps(data))
        self.assertIsNone(data["evidence_write_error"])

    def test_the_environment_is_inherited_and_not_trimmed(self):
        self.warm()
        with mock.patch.dict(os.environ, {"LIEBERT_TEST_MARKER": "seen"}):
            self.s()
        self.assertEqual(self.idalib.script_calls[0]["environment"]["LIEBERT_TEST_MARKER"], "seen")

    def test_the_evidence_record_holds_the_script_and_what_happened(self):
        self.warm()
        data = self.s()
        (record,) = self.evidence_files()
        self.assertEqual(record.name, data["internal_evidence_name"])
        self.assertRegex(record.name, rf"^{self.sha[:16]}_[0-9a-f]{{8}}_script\.json$")
        saved = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(saved["script"]["text"], GOOD_SCRIPT)
        self.assertEqual(saved["script"]["sha256"], data["script"]["sha256"])
        self.assertEqual(saved["worker_result"]["script"]["status"], "OK")
        self.assertEqual(saved["response"]["script_result"], data["script_result"])
        self.assertNotIn("output", saved["job"])
        self.assertNotIn("script_path", saved["job"])
        self.assertNotIn(str(self.root), json.dumps(saved["job"]))

    def test_an_unwritable_evidence_directory_withholds_the_result(self):
        blocker = self.root / "blocker"
        blocker.write_text("a file where a directory is needed", encoding="utf-8")
        self.warm()
        with mock.patch.object(ti, "EVIDENCE_SCRIPT", blocker / "ida_script"):
            data = self.s()
        self.assertFalse(data["ok"], data)
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "EVIDENCE_WRITE_FAILED"))
        self.assertNotIn("script_result", data)
        self.assertNotIn("function_count", json.dumps(data))
        self.assertIs(data["result_withheld"], True)
        self.assertTrue(data["evidence_write_error"])
        self.assertIn("ran to completion", data["detail"])
        self.assertEqual(len(self.idalib.script_calls), 1)            # the script did run: the answer says so
        self.assertEqual(self.leftovers(), [])

    def test_a_result_with_a_home_path_is_redacted_and_says_so(self):
        self.idalib.script_value = {"where": "C:\\Users\\SomeOperator\\Desktop\\x.bin", "n": 1}
        data = self.s()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["script_result"], {"where": "<HOME>\\Desktop\\x.bin", "n": 1})
        self.assertIs(data["script_result_redacted"], True)
        self.assertNotIn("SomeOperator", json.dumps(data))

    def test_the_budget_ceiling_and_floor_are_clamped_not_trusted(self):
        self.warm()
        self.s(timeout_seconds=99999, max_memory_bytes=1, max_result_chars=1, max_stdout_chars=10 ** 9, max_chars=1)
        job = self.idalib.script_calls[-1]["job"]
        self.assertEqual(self.idalib.script_calls[-1]["timeout"], ti._MAX_SCRIPT_TIMEOUT_SECONDS)
        self.assertEqual(self.idalib.script_calls[-1]["max_memory_bytes"], ti._SCRIPT_MIN_MEMORY_BYTES)
        self.assertEqual(job["max_result_chars"], 100)
        self.assertEqual(job["max_stdout_chars"], 65536)
        self.s(timeout_seconds=0)
        self.assertEqual(self.idalib.script_calls[-1]["timeout"], ti._MIN_SCRIPT_TIMEOUT_SECONDS)
        self.s(timeout_seconds="soon")
        self.assertEqual(self.idalib.script_calls[-1]["timeout"], ti._DEFAULT_SCRIPT_TIMEOUT_SECONDS)


class OutcomeTests(ScriptCase):
    """Every way a script session ends, and what the answer refuses to say about it."""

    def failing(self, behaviour, **kwargs):
        self.warm()
        self.idalib.script_behaviour = behaviour
        data = self.s(**kwargs)
        self.assertFalse(data["ok"], data)
        self.assertNotIn("script_result", data)
        self.assertEqual(self.leftovers(), [])
        return data

    def test_no_result_is_an_error_and_stdout_never_substitutes(self):
        data = self.failing("no_result")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "SCRIPT_NO_RESULT"))
        self.assertIn("stdout never substitutes", data["detail"])
        self.assertEqual(data["stdout_tail"], "printed line\n")

    def test_a_result_that_is_not_json_names_its_type(self):
        data = self.failing("not_json")
        self.assertEqual((data["status"], data["error"], data["result_type"]), ("ANALYSIS_LIMITED", "SCRIPT_RESULT_NOT_JSON", "set"))

    def test_a_result_over_max_result_chars_is_withheld_never_truncated(self):
        self.warm()
        self.idalib.script_behaviour = "too_large"
        data = self.s(max_result_chars=500)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "PARTIAL")
        self.assertEqual(data["script_result_withheld"], "TOO_LARGE_FOR_MAX_RESULT_CHARS")
        self.assertEqual(data["script_result_chars"], 70000)
        self.assertEqual(data["max_result_chars"], 500)
        self.assertNotIn("script_result", data)
        self.assertTrue(data["limitations"])
        self.assertEqual(data["result_kind"], "SCRIPT_REPORTED")

    def test_a_result_that_fits_the_worker_but_not_the_response_is_withheld_never_cut(self):
        self.idalib.script_value = {"blob": "x" * 30000}
        self.warm()
        data = self.s(max_chars=8000)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["status"], "PARTIAL")
        self.assertEqual(data["script_result_withheld"], "TOO_LARGE_FOR_MAX_CHARS")
        self.assertNotIn("script_result", data)
        self.assertLessEqual(len(json.dumps(data, indent=2)), 8000)
        (record,) = self.evidence_files()
        saved = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(saved["response"]["script_result"], {"blob": "x" * 30000})      # the full value is kept
        again = self.s(max_chars=60000)
        self.assertEqual(again["status"], "OK")
        self.assertEqual(again["script_result"], {"blob": "x" * 30000})

    def test_an_exception_gives_a_redacted_traceback_and_the_stdout_tail(self):
        data = self.failing("exception")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "SCRIPT_EXCEPTION"))
        self.assertEqual(data["exception"]["type"], "ValueError")
        self.assertIn("ValueError: bad input", data["exception"]["traceback"])
        self.assertNotIn("SomeOperator", json.dumps(data))
        self.assertIn("<HOME>", data["exception"]["traceback"])
        self.assertEqual(data["stdout_tail"], "printed line\n")
        self.assertTrue(data["internal_evidence_name"])                  # a failed run is on record too

    def test_a_syntax_error_the_harness_did_not_see_is_reported_with_who_found_it(self):
        data = self.failing("syntax")
        self.assertEqual((data["error"], data["compiled_by"], data["line"]), ("SCRIPT_SYNTAX_ERROR", "ida_python", 2))

    def test_a_worker_that_read_other_script_text_is_refused(self):
        data = self.failing("hash_mismatch")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "SCRIPT_HASH_MISMATCH"))
        self.assertIn("was not run", data["detail"])

    def test_an_unreadable_script_file_and_an_unknown_outcome_are_errors_not_guesses(self):
        self.assertEqual(self.failing("unreadable")["error"], "SCRIPT_UNREADABLE")
        data = self.failing("unknown")
        self.assertEqual((data["error"], data["status_seen"]), ("SCRIPT_OUTCOME_UNRECOGNISED", "SOMETHING_NEW"))

    def test_a_timeout_kills_the_session_and_keeps_the_slot(self):
        self.warm()
        (slot,) = self.slots()
        before = (slot / ti._DB_NAME).read_bytes()
        self.idalib.script_behaviour = "timeout"
        data = self.s(timeout_seconds=30)
        self.assertEqual((data["status"], data["timed_out_stage"], data["timeout_seconds"]), ("TIMEOUT", "script", 30))
        self.assertIn("SCRIPT_TIMEOUT", data["error"])
        self.assertNotIn("script_result", data)
        self.assertEqual((slot / ti._DB_NAME).read_bytes(), before)
        self.assertEqual(self.slots(), [slot])
        self.assertEqual(self.leftovers(), [])
        self.idalib.script_behaviour = "ok"
        self.assertEqual(self.s()["database_cache"], "HIT")

    def test_a_cancelled_session_is_cancelled_and_keeps_the_slot(self):
        data = self.failing("cancel")
        self.assertEqual(data["status"], "CANCELLED")
        self.assertEqual(len(self.slots()), 1)

    def test_a_memory_overrun_is_its_own_status(self):
        data = self.failing("memory")
        self.assertEqual(data["status"], "MEMORY_LIMIT")
        self.assertEqual(data["memory_limit_bytes"], 4 * 1024 ** 3)

    def test_a_host_that_loses_the_memory_monitor_mid_run_fails_closed(self):
        data = self.failing("resource")
        self.assertEqual(data["status"], "RESOURCE_LIMIT_UNAVAILABLE")

    def test_a_changed_slot_is_a_cache_violation_the_slot_is_dropped_and_there_is_no_result(self):
        self.warm()
        self.idalib.script_behaviour = "violation"
        data = self.s()
        self.assertFalse(data["ok"], data)
        self.assertEqual((data["status"], data["error"]), ("CACHE_VIOLATION", "SCRIPT_CACHE_VIOLATION"))
        self.assertNotIn("script_result", data)
        self.assertNotIn("function_count", json.dumps(data))
        self.assertIs(data["execution"]["slot_database_integrity"]["unchanged"], False)
        self.assertEqual(self.slots(), [])
        self.idalib.script_behaviour = "ok"
        self.assertEqual(self.s()["database_cache"], "CREATED")      # the next call analyses again

    def test_a_database_that_was_not_discarded_is_refused(self):
        data = self.failing("not_closed")
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "DATABASE_CHANGES_NOT_DISCARDED"))
        self.assertIs(data["execution"]["copy_discarded"], False)

    def test_a_database_that_records_another_input_is_refused_and_dropped(self):
        data = self.failing("input_mismatch")
        self.assertEqual(data["error"], "IDA_INPUT_HASH_MISMATCH")
        self.assertEqual(self.slots(), [])

    def test_a_fatal_log_and_a_nonzero_exit_are_failures_even_with_a_result_file(self):
        self.assertEqual(self.failing("fatal_log")["error"], "IDA_LOG_REPORTS_FAILURE")
        data = self.failing("nonzero")
        self.assertEqual(data["error"], "IDA_EXITED_NONZERO")
        self.assertEqual(self.failing("no_output")["error"], "IDA_NO_OUTPUT")

    def test_a_failed_first_analysis_is_labelled_as_such_and_belongs_to_this_tool(self):
        self.idalib.behaviour = "timeout"
        data = self.s()
        self.assertEqual(data["tool"], "ida_script")
        self.assertEqual(data["status"], "TIMEOUT")
        self.assertEqual(data["failed_stage"], "first_analysis")
        self.assertEqual(data["script"]["bytes"], len(GOOD_SCRIPT))
        self.assertEqual(self.idalib.script_calls, [])           # the script never ran on a half-built database
        self.assertEqual(self.slots(), [])

    def test_a_scratch_directory_is_kept_for_diagnosis_only_when_asked(self):
        self.warm()
        self.idalib.script_behaviour = "exception"
        with mock.patch.dict(os.environ, {ti.KEEP_FAILED_SCRATCH_ENV: "1"}):
            data = self.s()
        self.assertTrue(data["scratch_retained"]["retained"])
        self.assertTrue(self.leftovers())

    def test_a_busy_slot_is_reported_not_waited_on_forever(self):
        with mock.patch.object(ti, "_acquire_slot_lock", return_value=None):
            data = self.s()
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "IDA_CACHE_SLOT_BUSY"))
        self.assertEqual(self.idalib.script_calls, [])


# ---------------------------------------------------------------------------
# reachable from the command line, behind the same key
# ---------------------------------------------------------------------------
class CommandLineTests(ScriptCase):
    def run_cli(self, *argv):
        from liebert_re import cli
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["--workspace", str(self.root), *argv])
        return code, json.loads(buffer.getvalue())

    def script_file(self, text=GOOD_SCRIPT):
        path = self.root / "probe.py"
        path.write_text(text, encoding="utf-8")
        return path.name

    def test_idascript_with_the_key_closed_is_a_refusal_and_starts_nothing(self):
        name = self.script_file()
        with mock.patch.dict(os.environ, {GATE: ""}):
            code, out = self.run_cli("idascript", str(self.sample), "--script-file", name)
        self.assertEqual(code, 3)
        self.assertEqual(out["status"], "AUTHORIZATION_REQUIRED")
        self.assertTrue(self.started_nothing())

    def test_tool_run_with_the_key_closed_is_the_same_refusal(self):
        args = json.dumps({"path": str(self.sample), "script": GOOD_SCRIPT})
        with mock.patch.dict(os.environ, {GATE: ""}):
            code, out = self.run_cli("tool", "run", "ida_script", "--args", args)
        self.assertEqual(code, 3)
        self.assertIn("AUTHORIZATION_REQUIRED", json.dumps(out))
        self.assertTrue(self.started_nothing())

    def test_idascript_refuses_idat_as_unsupported(self):
        name = self.script_file()
        code, out = self.run_cli("idascript", str(self.sample), "--script-file", name, "--backend", "idat")
        self.assertEqual(code, 3)
        self.assertEqual(out["status"], "UNSUPPORTED")
        self.assertTrue(self.started_nothing())

    def test_idascript_passes_the_options_and_prints_the_answer(self):
        name = self.script_file()
        with mock.patch.object(ti, "safe_path", side_effect=lambda p: Path(self.root) / Path(p).name):
            code, out = self.run_cli("idascript", str(self.sample), "--script-file", name, "--timeout", "33",
                                     "--max-result-chars", "4000")
        self.assertEqual(code, 0, out)
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["invocation"]["timeout_seconds"], 33)
        self.assertEqual(out["invocation"]["max_result_chars"], 4000)
        self.assertEqual(out["script_result"], {"function_count": 3, "names": ["a", "b"]})

    def test_a_missing_script_file_is_reported_before_anything_starts(self):
        code, out = self.run_cli("idascript", str(self.sample), "--script-file", "no_such_file.py")
        self.assertNotEqual(code, 0)
        self.assertEqual(out["error"], "SCRIPT_FILE_UNREADABLE")
        self.assertTrue(self.started_nothing())

    def test_a_script_file_outside_the_workspace_is_refused(self):
        code, out = self.run_cli("idascript", str(self.sample), "--script-file", "../outside.py")
        self.assertEqual(out["status"], "PATH_REFUSED")
        self.assertTrue(self.started_nothing())

    def test_the_tool_is_registered_and_described(self):
        from liebert_re.report import tool_families
        from tests.cli_literals import published_set
        self.assertIn("ida_script", published_set())
        self.assertEqual(tool_families.tool_modules()["ida_script"], "liebert_re.tools.ida")
        self.assertNotIn("ida_script", tool_families.python_only_declarations())
        code, out = self.run_cli("tool", "describe", "ida_script")
        self.assertEqual(code, 0)
        names = {p["name"] for p in out["parameters"]}
        self.assertEqual(names, {"path", "script", "timeout_seconds", "max_result_chars", "max_stdout_chars",
                                 "max_memory_bytes", "max_chars", "backend", "cancellation_token"})


# ---------------------------------------------------------------------------
# the worker file, run against stub modules in this process
# ---------------------------------------------------------------------------
class ScriptWorkerTests(unittest.TestCase):
    def setUp(self):
        self.module, self.ida, patcher = _load_worker_module()
        self.addCleanup(patcher.stop)
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.calls = []
        idapro = self.ida["idapro"]
        idapro.open_database.side_effect = lambda *a: (self.calls.append(("open", a)), 0)[1]
        idapro.close_database.side_effect = lambda *a: self.calls.append(("close", a))
        self.ida["ida_loader"].save_database.side_effect = lambda *a: (self.calls.append(("save", a)), True)[1]
        self.ida["ida_auto"].auto_wait.side_effect = lambda: (self.calls.append(("auto_wait", ())), True)[1]
        self.ida["ida_nalt"].retrieve_input_file_sha256.return_value = bytes.fromhex("ab" * 32)
        self.ida["ida_nalt"].retrieve_input_file_md5.return_value = bytes.fromhex("cd" * 16)
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)
        self.real_stdout = sys.stdout

    def run_script(self, text, *, raw=None, sha=None, **fields):
        raw = text.encode("utf-8") if raw is None else raw
        (self.tmp / "script.py").write_bytes(raw)
        job = {"schema": 1, "mode": "script", "output": str(self.tmp / "out.json"), "database_name": "db.i64",
               "log_name": "ida.log", "max_result_bytes": 10 ** 7, "script_path": str(self.tmp / "script.py"),
               "script_sha256": sha or hashlib.sha256(raw).hexdigest(), "input_sha256": "ee" * 32,
               "max_result_chars": 1000, "max_stdout_chars": 50}
        job.update(fields)
        path = self.tmp / "job.json"
        path.write_text(json.dumps(job), encoding="utf-8")
        code = self.module.main(["worker", str(path)])
        self.assertIs(sys.stdout, self.real_stdout, "the worker must put stdout back")
        result = json.loads(Path(job["output"]).read_text(encoding="utf-8"))
        return code, result, result["script"]

    def test_a_result_is_returned_as_json_and_the_session_is_opened_once_and_discarded(self):
        code, result, script = self.run_script("result = {'n': 3, 'xs': [1, 2], 's': 'é'}\n")
        self.assertEqual(code, 0)
        self.assertEqual((script["status"], script["result"]), ("OK", {"n": 3, "xs": [1, 2], "s": "é"}))
        self.assertEqual([c[0] for c in self.calls], ["open", "auto_wait", "close"])
        kind, (path, run_auto, arguments) = self.calls[0]
        self.assertEqual(Path(path).resolve(), (self.tmp / "db.i64").resolve())
        self.assertIs(run_auto, False)
        self.assertEqual(arguments, "-Opdb:off -Lida.log")
        self.assertEqual(self.calls[-1], ("close", (False,)))
        self.assertTrue(result["database_closed_without_save"])
        self.assertEqual(result["results"], [])
        self.assertIs(result["script_completed"], True)
        self.assertEqual(list(result)[-1], "script_completed")
        self.assertEqual(script["engine_input_sha256"], "ab" * 32)
        self.assertEqual(script["engine_input_md5"], "cd" * 16)
        self.assertIs(script["auto_wait"], True)
        self.assertEqual(script["result_chars"], len(json.dumps(script["result"], ensure_ascii=False)))

    def test_the_script_sees_its_context_and_a_plain_module_namespace(self):
        _code, _result, script = self.run_script(
            "result = [__name__, LIEBERT_CONTEXT['input_sha256'], LIEBERT_CONTEXT['max_result_chars']]\n")
        self.assertEqual(script["result"], ["__liebert_script__", "ee" * 32, 1000])

    def test_no_result_not_json_and_too_large_are_three_different_statuses(self):
        self.assertEqual(self.run_script("x = 1\n")[2]["status"], "NO_RESULT")
        for text in ("result = {1, 2}\n", "result = float('nan')\n", "result = object()\n",
                     "result = {}\nresult['me'] = result\n", "result = b'bytes'\n"):
            with self.subTest(text=text):
                script = self.run_script(text)[2]
                self.assertEqual(script["status"], "NOT_JSON")
                self.assertNotIn("result", script)
                self.assertTrue(script["result_type"])
        self.assertEqual(self.run_script("result = {1, 2}\n")[2]["result_type"], "set")
        big = self.run_script("result = 'x' * 5000\n")[2]
        self.assertEqual((big["status"], big["result_chars"], big["max_result_chars"]), ("TOO_LARGE", 5002, 1000))
        self.assertNotIn("result", big)                 # never truncated, never partly returned
        edge = self.run_script("result = 'x' * 998\n")[2]
        self.assertEqual((edge["status"], edge["result_chars"]), ("OK", 1000))

    def test_stdout_and_stderr_go_to_a_bounded_buffer_and_never_to_the_real_stdout(self):
        code, _result, script = self.run_script(
            "import sys\nprint('A' * 200)\nsys.stderr.write('E' * 30)\nprint('tail')\nresult = 1\n", max_stdout_chars=40)
        self.assertEqual(code, 0)
        self.assertEqual(script["status"], "OK")
        self.assertEqual(len(script["stdout_tail"]), 40)
        self.assertTrue(script["stdout_tail"].endswith("tail\n"))
        self.assertEqual(script["stdout_chars"], 200 + 1 + 30 + 4 + 1)
        self.assertIs(script["stdout_truncated"], True)

    def test_a_script_that_prints_a_lot_does_not_grow_the_buffer_without_bound(self):
        _code, _result, script = self.run_script("for _ in range(20000):\n    print('0123456789')\nresult = 1\n",
                                                 max_stdout_chars=100)
        self.assertEqual(script["stdout_chars"], 20000 * 11)
        self.assertEqual(len(script["stdout_tail"]), 100)

    def test_an_exception_is_a_status_with_a_traceback_and_the_session_still_closes(self):
        code, result, script = self.run_script("print('before')\nraise ValueError('boom')\n")
        self.assertEqual(code, 0)
        self.assertEqual(script["status"], "EXCEPTION")
        self.assertEqual((script["exception"]["type"], script["exception"]["message"]), ("ValueError", "boom"))
        self.assertIn("ValueError: boom", script["exception"]["traceback"])
        self.assertEqual(script["stdout_tail"], "before\n")
        self.assertEqual(self.calls[-1], ("close", (False,)))
        self.assertTrue(result["database_closed_without_save"])

    def test_systemexit_and_keyboardinterrupt_do_not_escape_the_session(self):
        for text, kind in (("raise SystemExit(3)\n", "SystemExit"), ("raise KeyboardInterrupt()\n", "KeyboardInterrupt")):
            with self.subTest(kind):
                self.calls.clear()
                _code, result, script = self.run_script(text)
                self.assertEqual((script["status"], script["exception"]["type"]), ("EXCEPTION", kind))
                self.assertEqual(self.calls[-1], ("close", (False,)))
                self.assertTrue(result["database_closed_without_save"])

    def test_a_script_whose_text_differs_from_the_submitted_hash_is_not_run(self):
        _code, _result, script = self.run_script("result = 1\nopen_marker = 1\n", sha="0" * 64)
        self.assertEqual(script["status"], "HASH_MISMATCH")
        self.assertNotIn("result", script)

    def test_a_syntax_error_in_the_ida_interpreter_is_reported_with_its_line(self):
        _code, _result, script = self.run_script("result = 1\nif True print(2)\n")
        self.assertEqual((script["status"], script["line"], script["compiled_by"]), ("SYNTAX_ERROR", 2, "ida_python"))

    def test_an_unreadable_script_and_a_non_utf8_script_are_statuses(self):
        self.assertEqual(self.run_script("x", raw=b"\xff\xfe\x00 not utf8")[2]["status"], "SYNTAX_ERROR")
        job_path = self.tmp / "job.json"
        path = self.tmp / "gone.py"
        job = {"schema": 1, "mode": "script", "output": str(self.tmp / "out2.json"), "script_path": str(path),
               "script_sha256": "0" * 64}
        job_path.write_text(json.dumps(job), encoding="utf-8")
        self.module.main(["worker", str(job_path)])
        self.assertEqual(json.loads((self.tmp / "out2.json").read_text(encoding="utf-8"))["script"]["status"], "UNREADABLE")

    def test_a_failed_open_runs_no_script(self):
        self.ida["idapro"].open_database.side_effect = lambda *a: 4
        (self.tmp / "script.py").write_text("result = 1\n", encoding="utf-8")
        raw = b"result = 1\n"
        job = {"schema": 1, "mode": "script", "output": str(self.tmp / "o.json"), "database_name": "db.i64",
               "script_path": str(self.tmp / "script.py"), "script_sha256": hashlib.sha256(raw).hexdigest()}
        (self.tmp / "j.json").write_text(json.dumps(job), encoding="utf-8")
        self.module.main(["worker", str(self.tmp / "j.json")])
        out = json.loads((self.tmp / "o.json").read_text(encoding="utf-8"))
        self.assertEqual(out["error"], "IDALIB_OPEN_FAILED")
        self.assertNotIn("script", out)

    def test_a_script_mode_job_needs_a_script_but_no_operations(self):
        job, problem = self.module._read_job(self._write_job({"schema": 1, "mode": "script", "output": "o.json",
                                                            "script_path": "s.py", "script_sha256": "0" * 64}))
        self.assertIsNone(problem)
        self.assertEqual(job["mode"], "script")
        for broken in ({"script_path": "s.py"}, {"script_sha256": "0" * 64}):
            base = {"schema": 1, "mode": "script", "output": "o.json"}
            _job, problem = self.module._read_job(self._write_job({**base, **broken}))
            self.assertEqual(problem, "JOB_MALFORMED")

    def _write_job(self, job):
        path = self.tmp / "read_job.json"
        path.write_text(json.dumps(job), encoding="utf-8")
        return str(path)

    def test_the_worker_still_has_exactly_one_open_and_one_discarding_close(self):
        import ast
        source = WORKER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "idapro"]
        self.assertEqual(sorted(c.func.attr for c in calls if c.func.attr.endswith("_database")),
                         ["close_database", "open_database"])
        for forbidden in ("save_database(", "def _op_"):
            self.assertEqual(source.count(forbidden), 1 if forbidden == "save_database(" else 0, forbidden)


# ---------------------------------------------------------------------------
# a real child interpreter with stub modules
# ---------------------------------------------------------------------------
class ScriptSubprocessTests(ScriptCase):
    """The real wrapper -> real child process -> real worker file, over stub `idapro` / `ida_*` modules."""

    def setUp(self):
        super().setUp()
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

    def test_a_real_process_runs_the_script_prints_are_captured_and_banners_are_ignored(self):
        data = self.s("import idautils\nprint('hello from the script')\nresult = sorted(idautils.Functions())\n")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["script_result"], [4096, 8192])
        self.assertEqual(data["stdout_tail"], "hello from the script\n")
        self.assertNotIn("D810", json.dumps(data))            # the plugin banner went to the real stdout: not a result
        self.assertEqual(data["provenance"]["status"], "VERIFIED")
        calls = self.records()
        self.assertEqual([c["call"] for c in calls], ["open", "close", "open", "close"])    # analysis, then the script
        self.assertEqual([c["save"] for c in calls if c["call"] == "close"], [False, False])
        script_open = calls[2]
        self.assertFalse(script_open["run_auto"])
        (slot,) = self.slots()
        self.assertNotEqual(Path(script_open["path"]).parent, slot)
        self.assertEqual(Path(script_open["path"]).parent.parent, slot)
        self.assertNotIn("SECOND_OPEN", [c["call"] for c in calls])
        self.assertEqual(self.leftovers(), [])
        self.assertEqual((slot / ti._DB_NAME).read_bytes(), b"PACKED-DB" * 50)

    def test_the_context_and_a_raised_exception_survive_a_real_process(self):
        data = self.s("result = LIEBERT_CONTEXT['input_sha256']\n")
        self.assertEqual(data["script_result"], self.sha)
        failed = self.s("import json\nprint('x')\nraise RuntimeError('real failure')\n")
        self.assertEqual((failed["error"], failed["exception"]["type"]), ("SCRIPT_EXCEPTION", "RuntimeError"))
        self.assertIn("real failure", failed["exception"]["traceback"])
        self.assertEqual(failed["stdout_tail"], "x\n")
        self.assertEqual(self.s()["database_cache"], "HIT")

    def test_a_script_that_gets_past_the_guard_and_overwrites_the_slot_is_caught_by_the_hash(self):
        self.assertTrue(self.s()["ok"])
        (slot,) = self.slots()
        db = slot / ti._DB_NAME
        hostile = (f"import json\nhandle = json.codecs.open({str(db)!r}, 'wb')\nhandle.write(b'overwritten')\n"
                   "handle.close()\nresult = 'done'\n")
        self.assertIsNone(ti._script_precheck(hostile)[1], "this is the documented gap: the guard does not see it")
        data = self.s(hostile)
        self.assertFalse(data["ok"], data)
        self.assertEqual(data["status"], "CACHE_VIOLATION")
        self.assertNotIn("script_result", data)
        self.assertNotIn("done", json.dumps(data))
        self.assertEqual(self.slots(), [])

    def test_a_script_that_never_ends_is_killed_with_its_process_tree_and_the_slot_survives(self):
        self.assertTrue(self.s()["ok"])
        (slot,) = self.slots()
        pidfile = self.root / "pid.txt"
        spin = f"import json\njson.codecs.open({str(pidfile)!r}, 'w').write('1')\nwhile True:\n    pass\n"
        started = time.monotonic()
        data = self.s(spin, timeout_seconds=5)
        self.assertEqual((data["status"], data["timed_out_stage"]), ("TIMEOUT", "script"))
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(self.slots(), [slot])
        self.assertEqual(self.s()["database_cache"], "HIT")
        self.assertEqual(self.leftovers(), [])


# ---------------------------------------------------------------------------
# the real engine
# ---------------------------------------------------------------------------
@pytest.mark.heavy
class ScriptRealInstallTests(unittest.TestCase):
    """A licensed IDA through idalib. Needs LIEBERT_RE_IDALIB_PYTHON in the environment the suite is started
    from; skips otherwise."""

    @classmethod
    def setUpClass(cls):
        cls.python = conftest.IDALIB_PYTHON_AT_START
        if not cls.python:
            raise unittest.SkipTest(f"{IDALIB_ENV} is not set")
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls._tmp = TemporaryDirectory(prefix="liebert-script-")
        cls.root = Path(cls._tmp.name)
        code = bytes.fromhex("554889e531c05dc3") + b"\x90" * 8 + bytes.fromhex("e8ebffffffc3")
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", code)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.cache = self.root / f"c{hashlib.sha256(self.id().encode()).hexdigest()[:6]}"
        self.evidence = self.cache / "evidence"
        self.evidence.mkdir(parents=True)
        stack.enter_context(mock.patch.object(ti, "CACHE_ROOT", self.cache / "cache"))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE", self.evidence))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE_SCRIPT", self.evidence / "script"))
        stack.enter_context(mock.patch.object(ti, "safe_path", side_effect=lambda p: Path(p)))
        stack.enter_context(mock.patch.object(ti, "relative", side_effect=lambda p: Path(p).name))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))
        stack.enter_context(mock.patch.dict(os.environ, {IDALIB_ENV: self.python, GATE: "authorized"}))

    def script(self, text, **kw):
        return json.loads(ti.ida_script(str(self.pe), text, **kw))

    def slot_hash(self):
        db = next((self.cache / "cache").rglob("db.i64"))
        return hashlib.sha256(db.read_bytes()).hexdigest()

    def test_a_function_count_script_equals_the_list_functions_total(self):
        answer = self.script("import idautils\nresult = len(list(idautils.Functions()))\n")
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["status"], "OK")
        self.assertIsInstance(answer["script_result"], int)
        listed = json.loads(ti.ida_query(str(self.pe), "list_functions", backend="idalib"))
        self.assertTrue(listed["ok"], listed)
        self.assertEqual(answer["script_result"], listed["total_function_count"])
        self.assertEqual(answer["provenance"]["status"], "VERIFIED")
        self.assertIs(answer["execution"]["copy_discarded"], True)

    def test_a_script_that_renames_a_function_leaves_the_cached_database_byte_identical(self):
        first = self.script("import idautils\nresult = sorted(idautils.Functions())[0]\n")
        self.assertTrue(first["ok"], first)
        before = self.slot_hash()
        rename = ("import idautils, ida_name\nea = sorted(idautils.Functions())[0]\n"
                  "ok = ida_name.set_name(ea, 'liebert_script_probe', ida_name.SN_FORCE)\n"
                  "result = [bool(ok), ida_name.get_name(ea)]\n")
        answer = self.script(rename)
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["script_result"], [True, "liebert_script_probe"])      # the script saw its own change
        self.assertIs(answer["execution"]["slot_database_integrity"]["unchanged"], True)
        self.assertEqual(self.slot_hash(), before)
        names = json.loads(ti.ida_query(str(self.pe), "list_functions", backend="idalib"))
        self.assertNotIn("liebert_script_probe", json.dumps(names))
        self.assertEqual(self.slot_hash(), before)

    def test_a_decompiler_script_counts_calls_in_a_function(self):
        text = (
            "import idautils, ida_hexrays, ida_funcs\n"
            "if not ida_hexrays.init_hexrays_plugin():\n    result = {'hexrays': False}\nelse:\n"
            "    ea = sorted(idautils.Functions())[0]\n    cfunc = ida_hexrays.decompile(ea)\n"
            "    class V(ida_hexrays.ctree_visitor_t):\n"
            "        def __init__(self):\n            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)\n"
            "            self.calls = 0\n"
            "        def visit_expr(self, e):\n            self.calls += (e.op == ida_hexrays.cot_call)\n            return 0\n"
            "    v = V()\n    v.apply_to(cfunc.body, None)\n    result = {'hexrays': True, 'calls': v.calls}\n"
        )
        answer = self.script(text)
        # The tiny owned image may not decompile; what must hold is that the guard let a visitor class through
        # (`ctree_visitor_t.__init__`) and that a failure is the script's own, reported as such.
        self.assertNotEqual(answer.get("error"), "SCRIPT_GUARD_REFUSED", answer)
        if answer["status"] == "OK":
            self.assertIn("hexrays", answer["script_result"])
        else:
            self.assertEqual(answer["error"], "SCRIPT_EXCEPTION", answer)
