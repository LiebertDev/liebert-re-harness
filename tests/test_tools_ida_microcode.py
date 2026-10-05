"""`liebert_re.tools.ida.ida_microcode_cfg`: microcode as a control-flow graph,
raw by default, with an opt-in d810 deobfuscation pass that says what it is.

Fast tier: nothing here starts IDA. Two stand-ins, the same idiom as
`test_tools_ida.py`:

* `MicrocodeFakeIdat` replaces `idat.exe` at the process boundary and writes the
  result file the microcode worker writes (trimmed shapes of a real IDA 9.4 run);
* the packaged worker `ida_scripts/microcode_cfg.idapy` is executed against stub
  `ida_*` modules and a stub `d810` package, which is the only way to test its
  logic without IDA (it only ever runs inside idat).

What the cases pin, in the order the design note puts them:

* (a) the d810 pass is off by default: a call that does not ask for it never
  imports d810, never creates a state directory and answers `microcode_kind: raw`;
* (b) when on, the answer says it is a d810 pass and names the rules that fired,
  the project, and whether the output differs from the raw microcode; an answer
  that does not carry that label is refused, in both directions;
* (c) d810's modules are all imported through its `Scanner` before it starts, and
  its `options.json` writes go to a private directory; if one leaks to the user's
  file anyway the bytes are put back and the result says so;
* (d) the loaded project is echoed;
* (e) d810 missing or not started is a status with NO microcode, never raw
  microcode under a deobfuscation request.

Only `IdaMicrocodeRealInstallTests` needs a licensed IDA (and, for its d810
cases, an installed d810); it is marked heavy and skips when either is absent.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
import sys
import types
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
from liebert_re.recover.pe_address import AddressForm
from tests._scratch import process_scratch
from tests.test_tools_ida import FakeIdat, IdaCase, _OMIT

MICROCODE_WORKER = Path(ti._MICROCODE_WORKER_SOURCE)
# The real evidence directories, read before any test patches them.
ORIGINAL_EVIDENCE_MICROCODE = Path(ti.EVIDENCE_MICROCODE)
ORIGINAL_EVIDENCE = Path(ti.EVIDENCE)
JOB_ENV = "LIEBERT_IDA_JOB"
ADDRESS = {"file_offset": "0x400", "rva": "0x1000", "va": "0x140001000",
           "image_base": "0x140000000", "section": ".text"}
ADDRESS_FIELDS = {f.name for f in dataclasses.fields(AddressForm)}


def _insn(index, text, opcode="mov"):
    return {"index": index, "address": dict(ADDRESS), "opcode": opcode, "text": text}


def _block(serial, kind, instructions, preds=(), succs=()):
    return {"serial": serial, "type": kind, "start": dict(ADDRESS), "end": dict(ADDRESS),
            "predecessors": list(preds), "successors": list(succs),
            "instruction_count": len(instructions), "instructions": instructions}


RAW_BLOCKS = [
    _block(0, "BLT_1WAY", [], succs=[1]),
    _block(1, "BLT_1WAY", [_insn(0, "mov ecx.4, eax.4"), _insn(1, "add eax.4, edx.4, eax.4", "add")],
           preds=[0], succs=[2]),
    _block(2, "BLT_STOP", [], preds=[1]),
]
RAW_FIELDS = dict(
    function={"name": "start", "address": dict(ADDRESS)}, microcode_kind="raw",
    maturity={"requested": "MMAT_LVARS", "reached": "MMAT_LVARS", "reached_as_requested": True},
    block_count=3, instruction_count=2, instructions_returned=2, instructions_truncated=False,
    microcode_sha256="a" * 64, deobfuscation={"requested": False, "pass": None}, items=RAW_BLOCKS,
)
D810_INFO = {
    "requested": True, "pass": "d810", "d810_version": "0.0-test",
    "project": {"requested": "default_instruction_only", "loaded": "default_instruction_only.json",
                "description": "x", "instruction_rules_known": 205, "instruction_rules_active": 180,
                "block_rules_known": 17, "block_rules_active": 2},
    "raw_baseline": {"blocks": 3, "instructions": 2, "microcode_sha256": "a" * 64},
    "output": {"blocks": 3, "instructions": 1, "microcode_sha256": "b" * 64},
    "transformed": True, "transform_equivalence": "NOT_CHECKED",
    "rules_fired": [{"name": "Add_HackersDelightRule_2", "kind": "instruction_rule", "fired": 1}],
    "optimizers_fired": {"PeepholeOptimizer": 1}, "rules_fired_count": 1,
    "config_isolation": {"mode": "isolated_state_directory", "user_options_unchanged": True},
}
D810_FIELDS = dict(
    RAW_FIELDS, microcode_kind="d810_pass", deobfuscation=D810_INFO, microcode_sha256="b" * 64,
    instruction_count=1, instructions_returned=1,
    items=[RAW_BLOCKS[0], dict(RAW_BLOCKS[1], instruction_count=1, instructions=[_insn(0, "add eax.4, edx.4, eax.4", "add")]),
           RAW_BLOCKS[2]],
)


class MicrocodeFakeIdat(FakeIdat):
    """`FakeIdat` that also answers the `microcode_cfg` operation.

    `microcode` selects what the worker reports: ok / d810_missing /
    d810_not_started / d810_project_missing / raw_for_d810 / d810_for_raw / empty.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.microcode = "ok"
        self.state_dirs = []       # (path, existed while the session ran)

    def _body(self, job, sha):
        if job["operation"] != "microcode_cfg":
            return super()._body(job, sha)
        wants = job.get("deobfuscate") is True
        if wants:
            state = Path(job["d810_state_dir"])
            self.state_dirs.append((state, state.is_dir()))
        failures = {
            "d810_missing": ("D810_NOT_INSTALLED", "The d810 package could not be imported inside IDA's Python."),
            "d810_not_started": ("D810_NOT_STARTED", "d810 loaded the project but its optimizer did not start."),
            "d810_project_missing": ("D810_PROJECT_NOT_FOUND", "No d810 project named 'x'."),
        }
        if self.microcode in failures and wants:
            error, detail = failures[self.microcode]
            body = {"ok": False, "tool": "ida_microcode_cfg", "operation": "microcode_cfg", "items": [],
                    "error": error, "detail": detail, "engine_input_sha256": sha,
                    "engine_input_md5": self.md5, "script_completed": True}
            return body
        fields = dict(D810_FIELDS if wants else RAW_FIELDS)
        if self.microcode == "raw_for_d810":
            fields = dict(RAW_FIELDS)
        elif self.microcode == "d810_for_raw":
            fields = dict(D810_FIELDS)
        elif self.microcode == "empty":
            fields = dict(fields, items=[], instruction_count=0, block_count=0)
        elif self.microcode == "d810_no_equivalence_field":
            info = {k: v for k, v in D810_INFO.items() if k != "transform_equivalence"}
            fields = dict(D810_FIELDS, deobfuscation=info)
        body = {"ok": True, "tool": "ida_microcode_cfg", "operation": "microcode_cfg",
                "engine_input_sha256": sha, "engine_input_md5": self.md5, "database_changes_discarded": True}
        body.update(fields)
        body["script_completed"] = True
        return body


class MicrocodeCase(IdaCase):
    """`IdaCase` with a microcode-aware fake idat and a private microcode evidence directory."""

    def setUp(self):
        super().setUp()
        self.fake = MicrocodeFakeIdat(self.sha, self.md5, self.behaviour)
        self.evidence_mc = self.root / "evidence_mc"
        self.evidence_mc.mkdir()
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(ti, "run_bounded_process", side_effect=self.fake))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE_MICROCODE", self.evidence_mc))

    def m(self, function="start", maturity="MMAT_LVARS", deobfuscate=False, path=None, **kwargs):
        return json.loads(ti.ida_microcode_cfg(str(path or self.sample), function, maturity, deobfuscate, **kwargs))

    def reopen_calls(self):
        return [c for c in self.fake.calls if c["job"]["mode"] == "reopen"]


# ---------------------------------------------------------------------------
# arguments and refusals: never raises, never guesses
# ---------------------------------------------------------------------------
class ArgumentTests(MicrocodeCase):
    @pytest.mark.contract
    def test_without_idat_it_is_tool_missing_and_does_not_raise(self):
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            data = self.m()
        self.assertEqual((data["ok"], data["status"], data["tool"]), (False, "TOOL_MISSING", "ida_microcode_cfg"))
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_a_missing_path_and_a_database_input_are_named_refusals(self):
        self.assertEqual(self.m(path=self.root / "absent.exe")["status"], "NOT_FOUND")
        database = self.root / "x.i64"
        database.write_bytes(b"IDA")
        data = self.m(path=database)
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "DATABASE_INPUT_NOT_SUPPORTED"))
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_a_bad_function_argument_is_refused_before_idat_starts(self):
        for bad in ("", "   ", None, 12, "x" * 513):
            with self.subTest(function=bad):
                data = ti.ida_microcode_cfg(str(self.sample), bad)
                body = json.loads(data)
                self.assertEqual((body["ok"], body["error"]), (False, "FUNCTION_REQUIRED"))
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_all_eight_maturities_are_accepted_and_unknown_ones_are_refused(self):
        self.assertEqual(len(ti._MICROCODE_MATURITIES), 8)
        for level in ti._MICROCODE_MATURITIES:
            with self.subTest(level=level):
                self.assertEqual(self.m(maturity=level)["invocation"]["maturity"], level)
        self.assertEqual(self.m(maturity="lvars")["invocation"]["maturity"], "MMAT_LVARS")
        for bad in ("MMAT_ZERO", "MMAT_9", "", None, 5, "GLBOPT0"):
            with self.subTest(bad=bad):
                body = json.loads(ti.ida_microcode_cfg(str(self.sample), "start", bad))
                self.assertEqual(body["error"], "UNKNOWN_MATURITY")
                self.assertEqual(body["accepted"], list(ti._MICROCODE_MATURITIES))

    @pytest.mark.contract
    def test_deobfuscate_is_never_inferred_from_truthiness(self):
        """A string "false" is truthy; accepting it would run a third-party pass nobody asked for."""
        before = len(self.fake.calls)
        for bad in ("false", "true", 1, 0, None, "yes", []):
            with self.subTest(value=bad):
                body = json.loads(ti.ida_microcode_cfg(str(self.sample), "start", "MMAT_LVARS", bad))
                self.assertEqual((body["ok"], body["error"]), (False, "INVALID_DEOBFUSCATE_ARGUMENT"))
        self.assertEqual(len(self.fake.calls), before)

    @pytest.mark.contract
    def test_the_d810_project_name_cannot_be_a_path(self):
        for bad in ("", "..\\x", "../x", "a b", "x" * 81, None, 3, "con:fig"):
            with self.subTest(project=bad):
                body = json.loads(ti.ida_microcode_cfg(str(self.sample), "start", "MMAT_LVARS", True, bad))
                self.assertEqual(body["error"], "INVALID_D810_PROJECT")
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_a_missing_packaged_worker_is_a_packaging_status(self):
        with mock.patch.object(ti, "_MICROCODE_WORKER_SOURCE", self.root / "nope.idapy"):
            body = self.m()
        self.assertEqual((body["status"], body["error"]), ("ANALYSIS_LIMITED", "IDA_WORKER_MISSING"))

    @pytest.mark.contract
    def test_max_results_and_timeout_are_clamped_not_rejected(self):
        body = self.m(max_results=10 ** 9, timeout_seconds=10 ** 9)
        self.assertEqual(body["invocation"]["max_results"], ti._MICROCODE_INSTRUCTION_CAP)
        self.assertEqual(body["invocation"]["timeout_seconds"], ti._MAX_CREATE_TIMEOUT_SECONDS)
        self.assertEqual(self.m(max_results=-4)["invocation"]["max_results"], 1)


# ---------------------------------------------------------------------------
# (a) raw is the default
# ---------------------------------------------------------------------------
class RawDefaultTests(MicrocodeCase):
    def test_the_default_call_is_raw_and_never_touches_d810(self):
        body = self.m()
        self.assertTrue(body["ok"], body)
        self.assertEqual((body["status"], body["microcode_kind"]), ("OK", "raw"))
        self.assertEqual(body["deobfuscation"], {"requested": False, "pass": None})
        self.assertEqual(body["invocation"]["deobfuscate"], False)
        self.assertIsNone(body["invocation"]["d810_project"])
        job = self.reopen_calls()[0]["job"]
        self.assertIs(job["deobfuscate"], False)
        self.assertNotIn("d810_state_dir", job)
        self.assertEqual(self.fake.state_dirs, [])
        self.assertEqual([p for p in self.cache.glob("d810-*")], [])
        self.assertIn("raw microcode", body["note"])
        self.assertNotIn("rules_fired", json.dumps(body))

    def test_it_returns_the_graph_with_the_shared_address_form_on_every_address(self):
        body = self.m()
        self.assertEqual([b["serial"] for b in body["items"]], [0, 1, 2])
        self.assertEqual(body["items"][1]["predecessors"], [0])
        self.assertEqual(body["items"][1]["successors"], [2])
        seen = 0
        for block in body["items"]:
            for form in (block["start"], block["end"], *[i["address"] for i in block["instructions"]]):
                self.assertEqual(set(form), ADDRESS_FIELDS)
                seen += 1
        self.assertGreater(seen, 4)

    def test_the_session_is_a_temporary_reopen_and_the_first_analysis_runs_the_query_worker(self):
        body = self.m()
        self.assertEqual(self.fake.modes, ["create", "reopen"])
        create, reopen = self.fake.calls
        self.assertEqual(create["job"]["operation"], "summary")
        self.assertEqual(reopen["job"]["operation"], "microcode_cfg")
        self.assertEqual(create["script"], Path(ti._WORKER_SOURCE).read_bytes().replace(b"\r\n", b"\n"))
        self.assertEqual(reopen["script"], MICROCODE_WORKER.read_bytes().replace(b"\r\n", b"\n"))
        self.assertIs(body["signals"]["database_changes_discarded"], True)
        self.assertEqual(self.m()["database_cache"], "HIT")

    @pytest.mark.contract
    def test_a_result_without_the_discard_guarantee_returns_no_microcode(self):
        self.fake.discard_flag = _OMIT
        self.m()  # first call creates; the reopen session already lacked the flag
        self.fake.discard_flag = False
        body = self.m()
        self.assertEqual((body["ok"], body["status"]), (False, "ANALYSIS_LIMITED"))
        self.assertEqual(body["error"], "DATABASE_CHANGES_NOT_DISCARDED")
        self.assertNotIn("microcode_kind", body)
        self.assertEqual(self.slots(), [])


# ---------------------------------------------------------------------------
# (b)(d) the d810 pass says what it is
# ---------------------------------------------------------------------------
class D810PassTests(MicrocodeCase):
    def d810(self, **kwargs):
        return self.m(deobfuscate=True, **kwargs)

    def test_the_answer_is_labelled_as_a_d810_pass_with_rules_project_and_difference(self):
        body = self.d810()
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["microcode_kind"], "d810_pass")
        info = body["deobfuscation"]
        self.assertIs(info["requested"], True)
        self.assertEqual(info["pass"], "d810")
        self.assertEqual(info["project"]["loaded"], "default_instruction_only.json")
        self.assertEqual(info["project"]["requested"], "default_instruction_only")
        self.assertEqual(info["rules_fired"][0]["name"], "Add_HackersDelightRule_2")
        self.assertIs(info["transformed"], True)
        self.assertNotEqual(info["raw_baseline"]["microcode_sha256"], info["output"]["microcode_sha256"])
        self.assertEqual(body["invocation"]["d810_project"], "default_instruction_only")
        self.assertIn("transformed output, not Hex-Rays' own", body["note"])
        self.assertIn("does not handle virtualised (VM-based) code", body["note"])      # the boundary is stated

    def test_the_requested_project_is_passed_to_the_worker_and_echoed(self):
        self.d810(d810_project="default_unflattening_ollvm")
        job = self.reopen_calls()[0]["job"]
        self.assertEqual((job["deobfuscate"], job["d810_project"]), (True, "default_unflattening_ollvm"))
        self.assertEqual(self.d810(d810_project="x.json")["invocation"]["d810_project"], "x.json")

    def test_d810_gets_a_private_state_directory_that_is_removed_afterwards(self):
        self.d810()
        (state, existed), = self.fake.state_dirs
        self.assertTrue(existed)
        self.assertFalse(state.exists())
        self.assertEqual(state.parent, self.cache)         # a short path next to the slots, not inside a slot
        self.assertEqual([p for p in self.cache.glob("d810-*")], [])

    def test_a_cache_root_too_deep_for_d810s_log_paths_falls_back_to_the_temp_directory(self):
        with mock.patch.object(ti, "_D810_STATE_PATH_LIMIT", 5):
            self.d810()
        (state, existed), = self.fake.state_dirs
        self.assertTrue(existed)
        self.assertNotEqual(state.parent, self.cache)
        self.assertTrue(state.name.startswith("liebert-d810-"))
        self.assertFalse(state.exists())

    @pytest.mark.contract
    def test_d810_missing_is_tool_missing_with_no_microcode(self):
        self.fake.microcode = "d810_missing"
        body = self.d810()
        self.assertEqual((body["ok"], body["status"], body["error"]), (False, "TOOL_MISSING", "D810_NOT_INSTALLED"))
        for key in ("items", "microcode_kind", "block_count", "microcode_sha256"):
            self.assertNotIn(key, body)
        self.assertEqual(list(self.evidence_mc.iterdir()), [])
        self.assertEqual([p for p in self.cache.glob("d810-*")], [])

    @pytest.mark.contract
    def test_d810_that_does_not_start_is_analysis_limited_with_no_microcode(self):
        for mode, error in (("d810_not_started", "D810_NOT_STARTED"), ("d810_project_missing", "D810_PROJECT_NOT_FOUND")):
            with self.subTest(mode=mode):
                self.fake.microcode = mode
                body = self.d810()
                self.assertEqual((body["ok"], body["status"], body["error"]), (False, "ANALYSIS_LIMITED", error))
                self.assertIn("detail", body)
                for key in ("items", "microcode_kind", "block_count"):
                    self.assertNotIn(key, body)

    @pytest.mark.contract
    def test_a_failed_d810_pass_is_never_answered_with_the_raw_microcode(self):
        """The raw microcode of the same function was readable (the default call proves it), and a
        deobfuscation request that fails must still not hand it back."""
        self.assertEqual(self.m()["microcode_kind"], "raw")
        self.fake.microcode = "d810_missing"
        body = self.d810()
        self.assertFalse(body["ok"])
        for key in ("items", "microcode_kind", "block_count", "instruction_count", "microcode_sha256"):
            self.assertNotIn(key, body)

    @pytest.mark.contract
    def test_an_unlabelled_result_is_refused_in_both_directions(self):
        self.fake.microcode = "raw_for_d810"          # asked for d810, the worker answered raw
        body = self.d810()
        self.assertEqual((body["ok"], body["error"]), (False, "DEOBFUSCATION_RESULT_UNLABELLED"))
        self.assertNotIn("items", body)
        self.fake.microcode = "d810_for_raw"          # asked for raw, the worker answered d810
        body = self.m()
        self.assertEqual((body["ok"], body["error"]), (False, "MICROCODE_KIND_MISMATCH"))
        self.assertNotIn("items", body)

    @pytest.mark.contract
    def test_a_d810_result_that_does_not_say_equivalence_was_not_checked_is_refused(self):
        """`transformed: true` is a claim that the listing changed, not that the meaning survived."""
        self.assertEqual(self.d810()["deobfuscation"]["transform_equivalence"], "NOT_CHECKED")
        self.fake.microcode = "d810_no_equivalence_field"
        body = self.d810()
        self.assertEqual((body["ok"], body["error"]), (False, "DEOBFUSCATION_RESULT_UNLABELLED"))
        self.assertNotIn("items", body)

    @pytest.mark.contract
    def test_an_empty_microcode_array_is_not_a_negative_finding(self):
        self.fake.microcode = "empty"
        for deobfuscate in (False, True):
            with self.subTest(deobfuscate=deobfuscate):
                body = self.m(deobfuscate=deobfuscate)
                self.assertEqual((body["ok"], body["error"]), (False, "MICROCODE_EMPTY"))


# ---------------------------------------------------------------------------
# evidence, size bounds, timeout ceiling
# ---------------------------------------------------------------------------
class EvidenceAndBoundsTests(MicrocodeCase):
    def test_the_raw_worker_json_is_saved_under_the_microcode_evidence_directory_only(self):
        body = self.m()
        saved = list(self.evidence_mc.iterdir())
        self.assertEqual([p.name for p in saved], [body["internal_evidence_name"]])
        self.assertTrue(saved[0].name.endswith("_microcode_cfg.json"))
        full = json.loads(saved[0].read_text(encoding="utf-8"))
        self.assertEqual(full["microcode_kind"], "raw")
        self.assertEqual(len(full["items"]), 3)
        self.assertEqual(list(self.evidence.iterdir()), [])     # ida_query's directory stays empty
        self.assertIsNone(body["evidence_write_error"])

    def test_the_real_evidence_directory_is_under_the_tools_own_name(self):
        self.assertEqual(ORIGINAL_EVIDENCE_MICROCODE.name, "ida_microcode_cfg")
        self.assertEqual(ORIGINAL_EVIDENCE_MICROCODE.parent, ORIGINAL_EVIDENCE.parent)

    def test_a_cut_listing_is_partial_and_says_how_much_was_cut(self):
        self.fake.microcode = "ok"
        original = dict(RAW_FIELDS)
        cut = dict(original, instructions_returned=1, instructions_truncated=True)
        with mock.patch.dict(RAW_FIELDS, cut):
            body = self.m(max_results=1)
        self.assertEqual(body["status"], "PARTIAL")
        self.assertTrue(any("cut at 1 of 2 instructions" in text for text in body["limitations"]), body["limitations"])

    def test_an_oversized_graph_is_trimmed_to_valid_json_and_marked_partial(self):
        big = [_block(i, "BLT_1WAY", [_insn(0, "mov " + "x" * 400)], succs=[i + 1]) for i in range(40)]
        with mock.patch.dict(RAW_FIELDS, {"items": big, "block_count": 40}):
            raw = ti.ida_microcode_cfg(str(self.sample), "start", "MMAT_LVARS", False, max_chars=8000)
        body = json.loads(raw)
        self.assertLessEqual(len(raw), 8000)
        self.assertEqual(body["status"], "PARTIAL")
        self.assertTrue(body["truncated"])
        self.assertLess(len(body["items"]), 40)

    @pytest.mark.contract
    def test_the_microcode_ceiling_is_its_own_constant_and_caps_the_reopen_session(self):
        self.assertEqual(ti._MAX_MICROCODE_TIMEOUT_SECONDS, 300)
        self.m(timeout_seconds=10 ** 6)
        create, reopen = self.fake.calls
        self.assertLessEqual(reopen["timeout"], ti._MAX_MICROCODE_TIMEOUT_SECONDS)
        self.assertLessEqual(create["timeout"], ti._MAX_CREATE_TIMEOUT_SECONDS)
        with mock.patch.object(ti, "_MAX_MICROCODE_TIMEOUT_SECONDS", 7):
            self.m(timeout_seconds=500)
        self.assertEqual(self.fake.calls[-1]["timeout"], 7)       # the new ceiling, not ida_query's 300

    @pytest.mark.contract
    def test_a_timed_out_microcode_session_is_timeout_with_the_stage_ceiling_and_no_microcode(self):
        self.m()
        self.fake.behaviour = lambda mode, job: "timeout" if mode == "reopen" else "ok"
        body = self.m()
        self.assertEqual((body["ok"], body["status"], body["error"]),
                         (False, "TIMEOUT", "IDA_TIMEOUT_PROCESS_TREE_TERMINATED"))
        self.assertEqual((body["timed_out_stage"], body["stage_ceiling_seconds"]), ("query", 300))
        self.assertNotIn("items", body)
        self.assertEqual(body["invocation"]["operation"], "microcode_cfg")

    @pytest.mark.contract
    def test_cancellation_and_a_broken_run_name_the_tool_that_was_called(self):
        self.fake.behaviour = lambda mode, job: "cancel"
        self.assertEqual(self.m()["tool"], "ida_microcode_cfg")
        self.fake.behaviour = lambda mode, job: "broken"
        body = self.m()
        self.assertEqual((body["tool"], body["status"]), ("ida_microcode_cfg", "ANALYSIS_LIMITED"))

    @pytest.mark.contract
    def test_a_worker_answer_that_is_not_for_this_operation_returns_no_microcode(self):
        self.fake.result_operation = "list_functions"
        body = self.m()
        self.assertEqual((body["ok"], body["error"]), (False, "IDA_RESULT_OPERATION_MISMATCH"))
        self.assertNotIn("items", body)


# ---------------------------------------------------------------------------
# routing and the command line
# ---------------------------------------------------------------------------
class RoutingTests(unittest.TestCase):
    def test_it_is_published_and_needs_a_coordinate(self):
        self.assertIn("ida_microcode_cfg", tool_families.published_tools("native"))
        self.assertIn("ida_microcode_cfg", tool_families.NATIVE_COORDINATE_TOOLS)
        self.assertNotIn("ida_microcode_cfg", tool_families.NATIVE_PATH_ONLY_TOOLS)

    def test_cli_maturity_choices_match_the_module(self):
        """cli.py imports the module lazily, so it keeps its own copy of the list."""
        self.assertEqual(tuple(cli._IDA_MATURITIES), tuple(ti._MICROCODE_MATURITIES))

    def test_parser_has_the_command_with_raw_as_the_default(self):
        parser = cli._build_parser()
        args = parser.parse_args(["idamicrocode", "x.exe", "--function", "start"])
        self.assertTrue(args.needs_file)
        self.assertEqual((args.function, args.maturity, args.deobfuscate, args.d810_project),
                         ("start", "MMAT_LVARS", False, "default_instruction_only"))
        args = parser.parse_args(["idamicrocode", "x.exe", "--function", "0x1000", "--maturity", "MMAT_CALLS",
                                  "--deobfuscate", "--d810-project", "default_unflattening_ollvm"])
        self.assertEqual((args.maturity, args.deobfuscate, args.d810_project),
                         ("MMAT_CALLS", True, "default_unflattening_ollvm"))
        with self.assertRaises(SystemExit):
            parser.parse_args(["idamicrocode", "x.exe", "--function", "start", "--maturity", "MMAT_ZERO"])

    @pytest.mark.contract
    def test_idamicrocode_without_idat_is_exit_3_tool_missing(self):
        with TemporaryDirectory() as td:
            sample = Path(td) / "s.exe"
            sample.write_bytes(b"MZ")
            with mock.patch.object(ti, "_ida_binary", return_value=None), mock.patch("sys.stdout") as out:
                code = cli.main(["idamicrocode", str(sample), "--function", "start"])
                body = json.loads("".join(c.args[0] for c in out.write.call_args_list))
        self.assertEqual(code, 3)
        self.assertEqual((body["command"], body["status"]), ("idamicrocode", "TOOL_MISSING"))


# ---------------------------------------------------------------------------
# the worker, against stub ida_* modules and a stub d810
# ---------------------------------------------------------------------------
class WorkerFileTests(unittest.TestCase):
    def test_worker_is_a_data_file_next_to_the_query_worker_and_is_packaged(self):
        self.assertEqual(MICROCODE_WORKER.suffix, ".idapy")
        self.assertEqual(list(MICROCODE_WORKER.parent.glob("*.py")), [])
        pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"ida_scripts/*.idapy"', pyproject)         # one glob covers both workers

    def test_worker_has_no_bom_no_crlf_and_compiles(self):
        raw = MICROCODE_WORKER.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        compile(raw.decode("utf-8"), str(MICROCODE_WORKER), "exec")

    def test_worker_imports_stdlib_ida_and_only_d810_inside_a_function(self):
        tree = ast.parse(MICROCODE_WORKER.read_text(encoding="utf-8"))
        top, nested = set(), set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                top |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                top.add((node.module or "").split(".")[0])
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef,)):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Import):
                        nested |= {a.name.split(".")[0] for a in inner.names}
                    elif isinstance(inner, ast.ImportFrom):
                        nested.add((inner.module or "").split(".")[0])
        stdlib = {"hashlib", "json", "os", "pathlib", "sys", "traceback", "pkgutil"}
        ida = {n for n in top if n.startswith("ida") or n == "idc"}
        self.assertEqual(top - stdlib - ida, set(), "module-level imports")
        self.assertEqual(nested - stdlib - ida - {"d810"}, set(), "function-level imports")
        self.assertIn("d810", nested)
        self.assertNotIn("liebert_re", top | nested)

    def test_worker_contains_no_write_operation_and_uses_the_decomp_ranges_form_only(self):
        source = MICROCODE_WORKER.read_text(encoding="utf-8")
        for api in ("set_name", "set_cmt", "set_func_cmt", "patch_bytes", "rename_lvar", "set_user_cmt",
                    "del_items", "create_insn", "apply_type", "set_type", "del_func", "add_func",
                    "save_database", "mba_ranges_t("):
            self.assertNotIn(api, source, api)
        self.assertIn("decomp_ranges_t(func_ea)", source)

    def test_worker_names_no_unflatten_entry_point_of_its_own(self):
        """d810's rule sets are chosen by project name; this worker contains no unflattening logic."""
        source = MICROCODE_WORKER.read_text(encoding="utf-8").lower()
        self.assertNotIn("def _unflat", source)
        self.assertNotIn("unflatten(", source)


class FakeInsn:
    def __init__(self, ea, opcode, text):
        self.ea, self.opcode, self._text, self.next = ea, opcode, text, None

    def dstr(self):
        return self._text


class FakeBlock:
    def __init__(self, serial, kind, start, end, texts, preds=(), succs=()):
        self.serial, self.type, self.start, self.end = serial, kind, start, end
        self._preds, self._succs = list(preds), list(succs)
        insns = [FakeInsn(start + i, 4, text) for i, text in enumerate(texts)]
        for left, right in zip(insns, insns[1:]):
            left.next = right
        self.head = insns[0] if insns else None

    def npred(self):
        return len(self._preds)

    def pred(self, index):
        return self._preds[index]

    def nsucc(self):
        return len(self._succs)

    def succ(self, index):
        return self._succs[index]


class FakeMba:
    def __init__(self, blocks, maturity=8):
        self._blocks, self.qty, self.maturity = blocks, len(blocks), maturity

    def get_mblock(self, index):
        return self._blocks[index]


def raw_mba():
    return FakeMba([
        FakeBlock(0, 3, 0x401000, 0x401000, [], succs=[1]),
        FakeBlock(1, 3, 0x401000, 0x401010, ["mov a", "xor b", "add c"], preds=[0], succs=[2]),
        FakeBlock(2, 1, 0x401010, 0x401010, [], preds=[1]),
    ])


def d810_mba():
    return FakeMba([
        FakeBlock(0, 3, 0x401000, 0x401000, [], succs=[1]),
        FakeBlock(1, 3, 0x401000, 0x401010, ["add a_b"], preds=[0], succs=[2]),
        FakeBlock(2, 1, 0x401010, 0x401010, [], preds=[1]),
    ])


WORKER_MODULES = ["ida_auto", "ida_funcs", "ida_hexrays", "ida_lines", "ida_loader", "ida_nalt", "ida_pro",
                  "idaapi", "idc"]


def load_microcode_worker():
    stubs = {n: mock.MagicMock(name=n) for n in WORKER_MODULES}
    hexrays = stubs["ida_hexrays"]
    for value, name in enumerate(("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", "MMAT_CALLS",
                                  "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3", "MMAT_LVARS"), start=1):
        setattr(hexrays, name, value)
    hexrays.DECOMP_NO_WAIT, hexrays.DECOMP_NO_CACHE = 1, 2
    hexrays.m_mov, hexrays.m_add = 4, 12
    hexrays.init_hexrays_plugin.return_value = True
    stubs["ida_lines"].tag_remove.side_effect = lambda text: text
    stubs["ida_loader"].DBFL_TEMP = 4
    stubs["idc"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["idc"].get_name_ea_simple.return_value = 0x401000
    stubs["idc"].get_segm_name.return_value = ".text"
    stubs["idc"].get_name.return_value = "start"
    stubs["ida_funcs"].get_func.return_value = SimpleNamespace(start_ea=0x401000)
    stubs["ida_nalt"].get_imagebase.return_value = 0x400000
    stubs["idaapi"].get_fileregion_offset.side_effect = lambda ea: ea - 0x400000 + 0x200
    with mock.patch.dict(sys.modules, stubs):
        loader = SourceFileLoader("liebert_microcode_worker_under_test", str(MICROCODE_WORKER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    return module, stubs


class StubD810:
    """A `d810` package in `sys.modules` that behaves like the real one where the worker depends on it:
    it must be fully imported before `start_d810`, its `load`/`start_d810` write an `options.json` into
    whatever `DEFAULT_IDA_USER_DIR` says, and the optimizer is a hook that changes what microcode
    generation returns."""

    def __init__(self, tmp, *, writes_to_real_dir=False, fail_start=False, projects=None, same_output=False):
        self.tmp = Path(tmp)
        self.pkg = self.tmp / "d810_pkg"
        for sub in ("ui", "rules"):
            (self.pkg / sub).mkdir(parents=True)
            (self.pkg / sub / "__init__.py").write_text("", encoding="utf-8")
        (self.pkg / "util.py").write_text("", encoding="utf-8")
        self.real_dir = self.tmp / "real_ida_user"
        (self.real_dir / "cfg" / "d810").mkdir(parents=True)
        self.options = self.real_dir / "cfg" / "d810" / "options.json"
        self.options.write_text('{"last_project_index": 3}', encoding="utf-8")
        self.calls, self.scans, self.imported = [], [], []
        self.writes_to_real_dir, self.fail_start, self.same_output = writes_to_real_dir, fail_start, same_output
        self.projects = projects or ["bogus_loops.json", "default_instruction_only.json", "default_unflattening_ollvm.json"]
        self.stats = SimpleNamespace(
            instruction_rule_usage={}, cfg_rule_usages={}, instruction_optimizer_usage={},
            reset=lambda: (self.stats.instruction_rule_usage.clear(), self.stats.cfg_rule_usages.clear(),
                           self.stats.instruction_optimizer_usage.clear()))
        self.config = types.ModuleType("d810.core.config")
        self.config.DEFAULT_IDA_USER_DIR = self.real_dir
        self.state = None

    def fire(self):
        """What d810's optimizer records while it rewrites during a generation."""
        self.stats.instruction_rule_usage["Add_HackersDelightRule_2"] = 1
        self.stats.instruction_optimizer_usage["PeepholeOptimizer"] = 1

    def user_dir(self):
        return Path(self.config.DEFAULT_IDA_USER_DIR)

    def modules(self):
        owner = self
        scanner = type("Scanner", (), {"scan": staticmethod(
            lambda paths, prefix, callback=None, skip_packages=False: owner.scans.append((list(paths), prefix)))})

        class D810State:
            def __init__(self_inner):
                self_inner.manager = SimpleNamespace(_started=False, stats=owner.stats)
                self_inner.known_ins_rules = list(range(205))
                self_inner.current_ins_rules = list(range(180))
                self_inner.known_blk_rules = list(range(17))
                self_inner.current_blk_rules = list(range(2))
                self_inner.project_manager = SimpleNamespace(
                    project_names=lambda: list(owner.projects), index=lambda name: owner.projects.index(name))
                self_inner.current_project = None
                self_inner._loaded = False
                owner.state = self_inner

            def _write_options(self_inner):
                target = (owner.real_dir if owner.writes_to_real_dir else owner.user_dir()) / "cfg" / "d810"
                target.mkdir(parents=True, exist_ok=True)
                (target / "options.json").write_text('{"last_project_index": 1, "configurations": []}',
                                                     encoding="utf-8")

            def load(self_inner, gui=True):
                owner.calls.append("load")
                self_inner._write_options()
                self_inner._loaded = True

            def is_loaded(self_inner):
                return self_inner._loaded

            def load_project(self_inner, index):
                owner.calls.append("load_project")
                self_inner.current_project = SimpleNamespace(
                    path=Path(owner.projects[index]), description="stub project")

            def start_d810(self_inner):
                owner.calls.append("start")
                self_inner._write_options()
                if not owner.fail_start:
                    self_inner.manager._started = True

            def stop_d810(self_inner):
                owner.calls.append("stop")
                self_inner.manager._started = False

            def unload(self_inner, gui=True):
                owner.calls.append("unload")

        package = types.ModuleType("d810")
        package.__path__ = [str(self.pkg)]
        package.__version__ = "0.0-test"
        core = types.ModuleType("d810.core")
        core.__path__ = []
        vendor = types.ModuleType("d810._vendor")
        vendor.__path__ = []
        reloader = types.ModuleType("d810._vendor.ida_reloader")
        reloader.Scanner = scanner
        manager = types.ModuleType("d810.manager")
        manager.D810State = D810State
        mods = {"d810": package, "d810.core": core, "d810.core.config": self.config, "d810._vendor": vendor,
                "d810._vendor.ida_reloader": reloader, "d810.manager": manager}
        for name in ("d810.rules", "d810.util"):
            mods[name] = types.ModuleType(name)
        return mods


class WorkerMicrocodeTests(unittest.TestCase):
    def setUp(self):
        self.w, self.ida = load_microcode_worker()
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.hexrays = self.ida["ida_hexrays"]
        self.hexrays.gen_microcode.side_effect = lambda *a, **k: raw_mba()

    def run_job(self, d810=None, **job):
        job.setdefault("operation", "microcode_cfg")
        job.setdefault("mode", "reopen")
        job.setdefault("query", "start")
        job.setdefault("maturity", "MMAT_LVARS")
        job["output"] = str(self.tmp / "out.json")
        job_file = self.tmp / "job.json"
        job_file.write_text(json.dumps(job), encoding="utf-8")
        modules = {} if d810 is None else d810.modules()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job_file)}))
            stack.enter_context(mock.patch.dict(sys.modules, modules))
            if d810 is None:
                stack.enter_context(mock.patch.dict(sys.modules, {"d810": None}))
            code = self.w.main()
        out = self.tmp / "out.json"
        return code, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None

    def d810_job(self, d810, **extra):
        # The optimizer is a hook: with it started, generation returns the changed listing.
        def generate(*_a, **_k):
            if d810.state is not None and d810.state.manager._started:
                d810.fire()
                if not d810.same_output:
                    return d810_mba()
            return raw_mba()
        self.hexrays.gen_microcode.side_effect = generate
        return self.run_job(d810=d810, deobfuscate=True, d810_project="default_instruction_only",
                            d810_state_dir=str(self.tmp / "state"), **extra)

    def test_importing_the_worker_has_no_side_effects(self):
        self.ida["ida_pro"].qexit.assert_not_called()

    # --- raw ----------------------------------------------------------------
    def test_raw_microcode_is_the_graph_and_never_imports_d810(self):
        code, data = self.run_job()               # sys.modules["d810"] is None: importing it would raise
        self.assertEqual(code, 0)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["microcode_kind"], "raw")
        self.assertEqual(data["deobfuscation"], {"requested": False, "pass": None})
        self.assertEqual((data["block_count"], data["instruction_count"]), (3, 3))
        self.assertEqual([b["serial"] for b in data["items"]], [0, 1, 2])
        self.assertEqual(data["items"][1]["predecessors"], [0])
        self.assertEqual(data["items"][1]["successors"], [2])
        self.assertEqual(data["items"][1]["type"], "BLT_1WAY")
        self.assertEqual(data["items"][1]["instructions"][0]["opcode"], "mov")
        self.assertEqual(data["maturity"], {"requested": "MMAT_LVARS", "reached": "MMAT_LVARS",
                                           "reached_as_requested": True})
        self.assertTrue(data["script_completed"])
        self.assertIs(data["database_changes_discarded"], True)
        self.ida["ida_hexrays"].decomp_ranges_t.assert_called_once_with(0x401000)

    def test_every_address_carries_the_shared_five_field_form_and_a_missing_one_is_marked(self):
        _code, data = self.run_job()
        block = data["items"][1]
        for form in (block["start"], block["end"], block["instructions"][0]["address"]):
            self.assertEqual(set(form), ADDRESS_FIELDS)
        self.assertEqual(block["start"], {"file_offset": "0x1200", "rva": "0x1000", "va": "0x401000",
                                          "image_base": "0x400000", "section": ".text"})
        self.assertEqual(self.w._address_form(self.ida["idc"].BADADDR), {"resolved": False, "error": "BADADDR"})
        self.ida["idaapi"].get_fileregion_offset.side_effect = lambda ea: -1
        self.assertEqual(self.w._address_form(0x401000)["error"], "NO_FILE_OFFSET")

    def test_the_listing_is_cut_at_max_results_and_the_edges_stay_complete(self):
        _code, data = self.run_job(max_results=2)
        self.assertEqual((data["instruction_count"], data["instructions_returned"]), (3, 2))
        self.assertTrue(data["instructions_truncated"])
        self.assertEqual([b["serial"] for b in data["items"]], [0, 1, 2])
        self.assertEqual(data["items"][1]["instruction_count"], 3)
        self.assertEqual(len(data["items"][1]["instructions"]), 2)
        self.assertEqual(data["items"][1]["successors"], [2])

    def test_the_same_listing_hashes_the_same_and_a_changed_one_differently(self):
        self.assertEqual(self.w._listing_digest(raw_mba()), self.w._listing_digest(raw_mba()))
        self.assertNotEqual(self.w._listing_digest(raw_mba()), self.w._listing_digest(d810_mba()))

    @pytest.mark.contract
    def test_a_maturity_that_was_not_reached_is_reported_not_hidden(self):
        self.hexrays.gen_microcode.side_effect = lambda *a, **k: FakeMba(raw_mba()._blocks, maturity=5)
        _code, data = self.run_job(maturity="MMAT_LVARS")
        self.assertEqual(data["maturity"], {"requested": "MMAT_LVARS", "reached": "MMAT_GLBOPT1",
                                           "reached_as_requested": False})

    @pytest.mark.contract
    def test_every_maturity_level_is_passed_to_the_generator(self):
        for value, name in enumerate(self.w.MATURITY_NAMES, start=1):
            with self.subTest(name=name):
                self.hexrays.gen_microcode.reset_mock()
                self.run_job(maturity=name)
                self.assertEqual(self.hexrays.gen_microcode.call_args.args[4], value)

    @pytest.mark.contract
    def test_named_failures_are_errors_not_exceptions(self):
        self.ida["idc"].get_name_ea_simple.return_value = self.ida["idc"].BADADDR
        self.ida["idc"].get_segm_name.return_value = ""
        _code, data = self.run_job(query="no_such_symbol")
        self.assertEqual((data["ok"], data["error"]), (False, "FUNCTION_NOT_FOUND"))
        self.ida["idc"].get_name_ea_simple.return_value = 0x401000
        _code, data = self.run_job(maturity="MMAT_ZERO")
        self.assertEqual(data["error"], "UNKNOWN_MATURITY")
        self.ida["ida_hexrays"].init_hexrays_plugin.return_value = False
        _code, data = self.run_job()
        self.assertEqual(data["error"], "HEXRAYS_NOT_AVAILABLE")
        self.ida["ida_hexrays"].init_hexrays_plugin.return_value = True
        self.hexrays.gen_microcode.side_effect = lambda *a, **k: None
        self.hexrays.hexrays_failure_t.return_value = SimpleNamespace(str="no decompiler for this", code=7)
        _code, data = self.run_job()
        self.assertEqual((data["error"], data["detail"], data["hexrays_error_code"]),
                         ("MICROCODE_GENERATION_FAILED", "no decompiler for this", 7))
        self.assertEqual(data["items"], [])

    @pytest.mark.contract
    def test_an_empty_array_is_microcode_empty(self):
        self.hexrays.gen_microcode.side_effect = lambda *a, **k: FakeMba([])
        _code, data = self.run_job()
        self.assertEqual((data["ok"], data["error"]), (False, "MICROCODE_EMPTY"))

    @pytest.mark.contract
    def test_an_unexpected_exception_keeps_the_discard_signal(self):
        self.hexrays.gen_microcode.side_effect = RuntimeError("kernel said no")
        _code, data = self.run_job()
        self.assertEqual(data["error"], "IDAPYTHON_SCRIPT_EXCEPTION")
        self.assertIs(data["database_changes_discarded"], True)

    @pytest.mark.contract
    def test_when_the_temp_flag_cannot_be_set_nothing_is_generated(self):
        self.ida["ida_loader"].set_database_flag.side_effect = AttributeError("older build")
        _code, data = self.run_job()
        self.assertEqual(data["error"], "DATABASE_CHANGES_NOT_DISCARDABLE")
        self.assertIs(data["database_changes_discarded"], False)
        self.hexrays.gen_microcode.assert_not_called()
        self.ida["ida_auto"].auto_wait.assert_not_called()

    @pytest.mark.contract
    def test_a_create_session_is_refused_so_microcode_never_runs_where_a_database_is_saved(self):
        _code, data = self.run_job(mode="create")
        self.assertEqual(data["error"], "MICROCODE_REQUIRES_REOPEN_SESSION")
        self.hexrays.gen_microcode.assert_not_called()
        self.ida["ida_loader"].save_database.assert_not_called()

    @pytest.mark.contract
    def test_a_wrong_operation_is_unknown_operation(self):
        _code, data = self.run_job(operation="decompile_function")
        self.assertEqual(data["error"], "UNKNOWN_OPERATION")

    def test_the_discard_flag_is_set_before_auto_wait_and_before_generation(self):
        order = []
        self.ida["ida_loader"].set_database_flag.side_effect = lambda *_a: order.append("flag")
        self.ida["ida_auto"].auto_wait.side_effect = lambda *_a: order.append("auto_wait")
        self.hexrays.gen_microcode.side_effect = lambda *a, **k: order.append("gen") or raw_mba()
        self.run_job()
        self.assertEqual(order, ["flag", "auto_wait", "gen"])

    def test_a_truthy_non_boolean_does_not_switch_the_pass_on_in_the_worker_either(self):
        _code, data = self.run_job(deobfuscate="true")          # no d810 stub: importing it would raise
        self.assertEqual(data["microcode_kind"], "raw")

    # --- (a)-(e) the d810 pass ---------------------------------------------
    def test_d810_pass_reports_rules_project_baseline_and_difference(self):
        d810 = StubD810(self.tmp)
        code, data = self.d810_job(d810)
        self.assertEqual(code, 0)
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["microcode_kind"], "d810_pass")
        info = data["deobfuscation"]
        self.assertEqual((info["requested"], info["pass"], info["d810_version"]), (True, "d810", "0.0-test"))
        self.assertEqual(info["project"]["requested"], "default_instruction_only")
        self.assertEqual(info["project"]["loaded"], "default_instruction_only.json")      # (d) echoed
        self.assertEqual((info["project"]["instruction_rules_known"], info["project"]["instruction_rules_active"],
                          info["project"]["block_rules_known"], info["project"]["block_rules_active"]),
                         (205, 180, 17, 2))
        self.assertEqual(info["rules_fired"], [{"name": "Add_HackersDelightRule_2", "kind": "instruction_rule",
                                                "fired": 1}])
        self.assertEqual(info["optimizers_fired"], {"PeepholeOptimizer": 1})
        self.assertIs(info["transformed"], True)
        self.assertEqual(info["transform_equivalence"], "NOT_CHECKED")
        self.assertIn("meaning", info["transform_equivalence_note"])
        self.assertEqual(info["raw_baseline"], {"blocks": 3, "instructions": 3,
                                                "microcode_sha256": self.w._listing_digest(raw_mba())})
        self.assertEqual(info["output"]["instructions"], 1)
        self.assertNotEqual(info["raw_baseline"]["microcode_sha256"], info["output"]["microcode_sha256"])
        self.assertEqual(data["microcode_sha256"], info["output"]["microcode_sha256"])
        self.assertEqual(data["instruction_count"], 1)
        self.assertIn("counters_note", info)

    def test_fired_rules_with_an_identical_listing_are_reported_as_not_transformed(self):
        """Counters and effect are different claims; the listing comparison is the one that decides."""
        d810 = StubD810(self.tmp, same_output=True)
        _code, data = self.d810_job(d810)
        info = data["deobfuscation"]
        self.assertEqual(info["rules_fired_count"], 1)
        self.assertIs(info["transformed"], False)
        self.assertEqual(info["transform_equivalence"], "NOT_CHECKED")
        self.assertEqual(info["raw_baseline"]["microcode_sha256"], info["output"]["microcode_sha256"])

    def test_scanner_runs_first_and_skips_the_gui_package_then_load_project_start_in_order(self):
        d810 = StubD810(self.tmp)
        self.d810_job(d810)
        self.assertEqual(d810.calls, ["load", "load_project", "start", "stop", "unload"])
        scanned = [prefix for _paths, prefix in d810.scans]
        self.assertEqual(scanned, ["d810.rules."])                 # `ui` is not scanned; plain modules are imported
        self.assertTrue(all(str(d810.pkg) in paths[0] for paths, _ in d810.scans))
        self.assertNotIn("d810.ui", sys.modules)

    def test_the_baseline_is_generated_before_d810_is_loaded_and_the_pass_after_it_started(self):
        d810 = StubD810(self.tmp)
        seen = []

        def generate(*_a, **_k):
            started = d810.state is not None and d810.state.manager._started
            seen.append(started)
            return d810_mba() if started else raw_mba()
        self.hexrays.gen_microcode.side_effect = generate
        self.run_job(d810=d810, deobfuscate=True, d810_project="default_instruction_only",
                     d810_state_dir=str(self.tmp / "state"))
        self.assertEqual(seen, [False, True])

    def test_d810_writes_options_json_into_the_private_directory_and_the_user_file_is_untouched(self):
        d810 = StubD810(self.tmp)
        before = hashlib.sha256(d810.options.read_bytes()).hexdigest()
        _code, data = self.d810_job(d810)
        iso = data["deobfuscation"]["config_isolation"]
        self.assertEqual(iso["mode"], "isolated_state_directory")
        self.assertIs(iso["user_options_unchanged"], True)
        self.assertEqual(iso["user_options_sha256_before"], before)
        self.assertEqual(iso["user_options_sha256_after"], before)
        self.assertEqual(hashlib.sha256(d810.options.read_bytes()).hexdigest(), before)
        self.assertTrue((self.tmp / "state" / "cfg" / "d810" / "options.json").is_file())
        self.assertEqual(d810.config.DEFAULT_IDA_USER_DIR, d810.real_dir)       # restored for the rest of the session

    def test_a_write_that_leaks_to_the_user_file_is_put_back_and_reported(self):
        d810 = StubD810(self.tmp, writes_to_real_dir=True)
        original = d810.options.read_bytes()
        _code, data = self.d810_job(d810)
        iso = data["deobfuscation"]["config_isolation"]
        self.assertIs(iso["user_options_unchanged"], False)
        self.assertIs(iso["user_options_restored"], True)
        self.assertEqual(d810.options.read_bytes(), original)

    @pytest.mark.contract
    def test_d810_not_importable_is_a_named_error_and_no_microcode_is_generated(self):
        code, data = self.run_job(deobfuscate=True, d810_project="default_instruction_only",
                                  d810_state_dir=str(self.tmp / "state"))        # sys.modules["d810"] is None
        self.assertEqual(code, 0)
        self.assertEqual((data["ok"], data["error"]), (False, "D810_NOT_INSTALLED"))
        self.assertEqual(data["items"], [])
        for key in ("microcode_kind", "block_count", "instruction_count", "microcode_sha256", "deobfuscation"):
            self.assertNotIn(key, data)
        self.hexrays.gen_microcode.assert_not_called()          # not even the raw baseline

    @pytest.mark.contract
    def test_a_missing_state_directory_refuses_to_let_d810_write_into_the_user_configuration(self):
        d810 = StubD810(self.tmp)
        _code, data = self.run_job(d810=d810, deobfuscate=True, d810_project="default_instruction_only")
        self.assertEqual(data["error"], "D810_STATE_DIR_MISSING")
        self.assertEqual(d810.calls, [])
        self.hexrays.gen_microcode.assert_not_called()

    @pytest.mark.contract
    def test_an_unknown_project_lists_the_available_ones_and_returns_no_microcode(self):
        d810 = StubD810(self.tmp)
        _code, data = self.run_job(d810=d810, deobfuscate=True, d810_project="no_such_project",
                                   d810_state_dir=str(self.tmp / "state"))
        self.assertEqual((data["ok"], data["error"]), (False, "D810_PROJECT_NOT_FOUND"))
        self.assertIn("default_instruction_only.json", data["available_projects"])
        self.assertEqual(data["items"], [])
        self.assertNotIn("microcode_kind", data)
        self.assertNotIn("start", d810.calls)

    @pytest.mark.contract
    def test_an_optimizer_that_did_not_start_is_an_error_even_though_start_returned_normally(self):
        """`start_d810()` logs and returns when the decompiler or the rules are unusable; it does not raise."""
        d810 = StubD810(self.tmp, fail_start=True)
        _code, data = self.d810_job(d810)
        self.assertEqual((data["ok"], data["error"]), (False, "D810_NOT_STARTED"))
        self.assertEqual(data["project"]["loaded"], "default_instruction_only.json")
        self.assertEqual(data["items"], [])
        self.assertNotIn("microcode_kind", data)
        self.assertEqual(d810.calls[-1], "unload")

    @pytest.mark.contract
    def test_d810_is_stopped_and_unloaded_even_when_generation_fails_after_it_started(self):
        d810 = StubD810(self.tmp)
        state = {"n": 0}

        def generate(*_a, **_k):
            state["n"] += 1
            if state["n"] == 2:
                raise RuntimeError("hook crashed")
            return raw_mba()
        self.hexrays.gen_microcode.side_effect = generate
        _code, data = self.run_job(d810=d810, deobfuscate=True, d810_project="default_instruction_only",
                                   d810_state_dir=str(self.tmp / "state"))
        self.assertEqual(data["error"], "IDAPYTHON_SCRIPT_EXCEPTION")
        self.assertEqual(d810.calls[-2:], ["stop", "unload"])
        self.assertEqual(d810.config.DEFAULT_IDA_USER_DIR, d810.real_dir)
        self.assertEqual(data["items"], [])

    @pytest.mark.contract
    def test_a_load_failure_is_a_named_error(self):
        d810 = StubD810(self.tmp)
        mods = d810.modules()

        def broken(self_inner, gui=True):
            raise ValueError("Unable to configure handler 'z3FileHandler'")
        mods["d810.manager"].D810State.load = broken
        job = {"operation": "microcode_cfg", "mode": "reopen", "query": "start", "maturity": "MMAT_LVARS",
               "deobfuscate": True, "d810_project": "default_instruction_only",
               "d810_state_dir": str(self.tmp / "state"), "output": str(self.tmp / "out.json")}
        (self.tmp / "job.json").write_text(json.dumps(job), encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(self.tmp / "job.json")}), \
                mock.patch.dict(sys.modules, mods):
            self.w.main()
        data = json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))
        self.assertEqual((data["ok"], data["error"]), (False, "D810_LOAD_FAILED"))
        self.assertIn("z3FileHandler", data["detail"])


# ---------------------------------------------------------------------------
# the real tool
# ---------------------------------------------------------------------------
# start: the (a ^ b) + 2 * (a & b) form of a + b, a pattern one of d810's instruction rules rewrites.
MBA_CODE = bytes.fromhex("89c831d0" "4189c8" "4121d0" "4501c0" "4401c0" "c3")


def _user_options_sha256():
    base = os.environ.get("APPDATA")
    if not base:
        return None
    path = Path(base) / "Hex-Rays" / "IDA Pro" / "cfg" / "d810" / "options.json"
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


@pytest.mark.heavy
class IdaMicrocodeRealInstallTests(unittest.TestCase):
    """Needs a licensed IDA Pro 9.x; skips when idat is not found. The d810 cases additionally need d810
    installed in IDA's Python and skip when it is not. Builds its own tiny synthetic x86-64 PE."""

    @classmethod
    def setUpClass(cls):
        if not ti.ida_available():
            raise unittest.SkipTest("IDA Pro (idat) is not installed")
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls.root = process_scratch("ida_microcode_real")
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.pe = build_owned_pe_with_code(cls.root / "owned_mba.exe", MBA_CODE + b"\x90" * 8)

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        # A short name on purpose: idat's working directory is a slot's scratch directory below it, and
        # Windows' 260-character path limit applies there (a long test name in this path broke the launch).
        self.cache = self.root / f"c{hashlib.sha256(self.id().encode()).hexdigest()[:6]}"
        (self.cache / "evidence").mkdir(parents=True)
        stack.enter_context(mock.patch.object(ti, "CACHE_ROOT", self.cache / "db"))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE", self.cache / "evidence"))
        stack.enter_context(mock.patch.object(ti, "EVIDENCE_MICROCODE", self.cache / "evidence"))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))

    def m(self, maturity="MMAT_LVARS", deobfuscate=False, **kwargs):
        return json.loads(ti.ida_microcode_cfg(str(self.pe), "start", maturity, deobfuscate, timeout_seconds=300, **kwargs))

    def test_raw_microcode_comes_back_as_a_graph_in_the_shared_address_form(self):
        data = self.m()
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["microcode_kind"], data["deobfuscation"]["requested"]), ("raw", False))
        self.assertEqual(data["maturity"]["reached"], "MMAT_LVARS")
        self.assertGreater(data["block_count"], 1)
        self.assertGreater(data["instruction_count"], 0)
        first = next(i for b in data["items"] for i in b["instructions"])
        self.assertEqual(set(first["address"]), ADDRESS_FIELDS)
        self.assertEqual((first["address"]["image_base"], first["address"]["section"]), ("0x140000000", ".text"))
        self.assertTrue(0x1000 <= int(first["address"]["rva"], 16) < 0x1000 + len(MBA_CODE))
        self.assertEqual(int(first["address"]["va"], 16), 0x140000000 + int(first["address"]["rva"], 16))
        self.assertEqual(data["function"]["address"]["rva"], "0x1000")
        edges = {b["serial"]: b for b in data["items"]}
        for block in data["items"]:
            for succ in block["successors"]:
                self.assertIn(block["serial"], edges[succ]["predecessors"])

    def test_all_eight_maturity_levels_are_reached(self):
        for level in ti._MICROCODE_MATURITIES:
            with self.subTest(level=level):
                data = self.m(level)
                self.assertTrue(data["ok"], data)
                self.assertEqual(data["maturity"]["requested"], level)
                self.assertTrue(data["maturity"]["reached_as_requested"], data["maturity"])

    def test_reading_microcode_does_not_change_the_cached_database(self):
        self.m()
        db = next((self.cache / "db").rglob("db.i64"))
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        self.m("MMAT_GENERATED")
        self.m("MMAT_LVARS")
        self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_an_unknown_function_is_a_named_answer_and_keeps_the_cache(self):
        body = json.loads(ti.ida_microcode_cfg(str(self.pe), "no_such_function_anywhere"))
        self.assertEqual((body["ok"], body["error"]), (False, "FUNCTION_NOT_FOUND"))
        self.assertEqual(self.m()["database_cache"], "HIT")

    def test_d810_pass_fires_a_rule_changes_the_output_and_leaves_the_user_options_alone(self):
        raw = self.m()
        before = _user_options_sha256()
        data = self.m(deobfuscate=True)
        if data.get("status") == "TOOL_MISSING":
            self.skipTest("d810 is not installed in IDA's Python")
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["microcode_kind"], "d810_pass")
        info = data["deobfuscation"]
        self.assertEqual(info["project"]["loaded"], "default_instruction_only.json")
        self.assertGreater(info["project"]["instruction_rules_active"], 0)
        self.assertTrue(info["rules_fired"], info)
        self.assertIs(info["transformed"], True)
        self.assertEqual(info["transform_equivalence"], "NOT_CHECKED")
        # the baseline is the raw microcode of the same function from the same session
        self.assertEqual(info["raw_baseline"]["microcode_sha256"], raw["microcode_sha256"])
        self.assertNotEqual(info["output"]["microcode_sha256"], raw["microcode_sha256"])
        self.assertIs(info["config_isolation"]["user_options_unchanged"], True)
        self.assertEqual(_user_options_sha256(), before)
        # the pass is gone afterwards: the next default call is raw again, byte for byte
        self.assertEqual(self.m()["microcode_sha256"], raw["microcode_sha256"])

    def test_a_project_that_does_not_exist_is_a_status_with_no_microcode(self):
        data = self.m(deobfuscate=True, d810_project="no_such_project_anywhere")
        if data.get("status") == "TOOL_MISSING":
            self.skipTest("d810 is not installed in IDA's Python")
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", "D810_PROJECT_NOT_FOUND"))
        self.assertNotIn("microcode_kind", data)
        self.assertNotIn("items", data)


if __name__ == "__main__":
    unittest.main()
