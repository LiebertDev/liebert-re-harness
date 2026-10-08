"""`liebert_re.tools.ida`: the three round-2a operations that do not persist anything --
`ida_annotations` (a file-system read of the write log), `ida_type_member_offset` (a read of a
struct member's offset from the type information) and `ida_patch_plan` (a patch PLAN computed by
really patching an in-memory copy of the database inside the discard guarantee).

Fast tier: nothing here starts IDA. The same two stand-ins as `test_tools_ida.py`: `FakeIdat`
replaces `idat.exe` at the process boundary, and the packaged workers are executed against stub
`ida_*` modules. Every case writes under the repository's own scratch helper
(`tests/_scratch.process_scratch`), never an OS temp directory, and leaves the real `safe_path`
in force, so the workspace boundary is part of what is tested.

What the cases pin:

* the annotation reader never starts the engine and works with no IDA installed; a cut list says it
  was cut, an unreadable log is never an empty list, and the target's name and path stay out of the
  answer and of the evidence file name;
* the reject paths teach: they name the field and say what is accepted;
* each operation has its own timeout ceiling constant and reports TIMEOUT in the shared shape;
* the patch plan keeps the reopen path's discard guarantee, hashes the cached database before and
  after, and reports a cache violation (slot dropped, no plan returned) when the two differ;
* every patch call in the patch worker is a method of one class that marks the database temporary
  first.

Only `IdaRound2aRealInstallTests` needs a licensed IDA; it is marked heavy at class level.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import unittest
from contextlib import ExitStack
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

import pytest

import liebert_re.report.tool_families as tool_families
import liebert_re.tools.ida as ti
from liebert_re.recover.pe_address import AddressForm
from tests._scratch import process_scratch
from tests.test_tools_ida import FakeIdat, _OMIT, _load_worker, _result

JOB_ENV = "LIEBERT_IDA_JOB"
PATCH_WORKER = Path(ti._PATCH_PLAN_WORKER_SOURCE)
QUERY_WORKER = Path(ti._WORKER_SOURCE)
ADDRESS_FIELDS = {f.name for f in dataclasses.fields(AddressForm)}
TARGET_NAME = "ZZ_secret_target_name"
ADDRESS = {"file_offset": "0x202", "rva": "0x1002", "va": "0x140001002",
           "image_base": "0x140000000", "section": ".text"}

TYPE_FOUND = dict(resolved_type_name="_LIST_ENTRY", tried_type_names=["_LIST_ENTRY", "LIST_ENTRY"], is_union=False,
                  member_name="Blink", member_index=1, offset_bits=64, offset_bytes=8, byte_aligned=True,
                  member_size_bits=64, member_size_bytes=8, member_type="struct _LIST_ENTRY *", is_bitfield=False,
                  struct_size_bytes=16, member_count=2)
PLAN_FOUND = dict(
    patch_operation="force_branch", plan_only=True, applied_to_file=False, address=dict(ADDRESS),
    original_length=2, patched_length=2, original_bytes="7403", patched_bytes="eb03",
    branch_target=dict(ADDRESS, rva="0x1007", va="0x140001007", file_offset="0x207"),
    disasm_before=["jz      short locret_140001007"], disasm_after=["jmp     short locret_140001007"], warnings=[],
)


class Round2aFakeIdat(FakeIdat):
    """`FakeIdat` that also answers `type_member_offset` and `patch_plan`.

    `type_result`: ok / member_missing / incomplete. `patch_result`: ok / refused / incomplete.
    `mutate_database` appends bytes to the cached database during a reopen session, the way a
    session that did NOT stay temporary would.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type_result = "ok"
        self.patch_result = "ok"
        self.mutate_database = False

    def __call__(self, command, *, timeout_seconds, cancellation_token=None, cwd=None,
                 environment=None, max_output_chars=None):
        job = json.loads(Path(environment[JOB_ENV]).read_text(encoding="utf-8"))
        if self.mutate_database and job["mode"] == "reopen":
            with open(command[-1], "ab") as handle:
                handle.write(b"changed")
        return super().__call__(command, timeout_seconds=timeout_seconds, cancellation_token=cancellation_token,
                                cwd=cwd, environment=environment, max_output_chars=max_output_chars)

    def _failure(self, job, sha, error, **extra):
        body = {"ok": False, "tool": "ida_query", "operation": job["operation"], "items": [], "error": error,
                "engine_input_sha256": sha, "engine_input_md5": self.md5, "script_completed": True}
        body.update(extra)
        return body

    def _body(self, job, sha):
        if job["operation"] == "type_member_offset":
            if self.type_result == "member_missing":
                return self._failure(job, sha, "MEMBER_NOT_FOUND", resolved_type_name="_LIST_ENTRY",
                                     member_count=2, member_names=["Flink", "Blink"], member_names_truncated=False)
            fields = {k: v for k, v in TYPE_FOUND.items() if self.type_result != "incomplete" or k != "offset_bits"}
            return _result("type_member_offset", sha, self.md5, **fields)
        if job["operation"] == "patch_plan":
            if self.patch_result == "refused":
                return self._failure(job, sha, "NOT_A_CONDITIONAL_BRANCH", instruction="mov     eax, ecx")
            fields = dict(PLAN_FOUND, plan_only=self.patch_result != "incomplete")
            body = _result("patch_plan", sha, self.md5, **fields)
            del body["items"], body["count"]
            return body
        return super()._body(job, sha)


class Round2aCase(unittest.TestCase):
    """A stand-in input and a private cache and evidence tree under the repository scratch directory."""

    def setUp(self):
        # A short name on purpose: idat's working directory sits below a slot, and Windows' 260-character
        # path limit applies there.
        self.root = process_scratch("r2a_" + hashlib.sha256(self.id().encode()).hexdigest()[:6])
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.sample = self.root / f"{TARGET_NAME}.exe"
        self.sample.write_bytes(b"MZ" + bytes(range(64)))
        self.sha, self.md5 = ti._sha256_md5(self.sample)
        self.cache = self.root / "cache"
        self.annotated = self.root / "annotated"      # the journal lives in the annotated root, not in the cache
        self.ev_type, self.ev_patch, self.ev_ann = (self.root / n for n in ("ev_type", "ev_patch", "ev_ann"))
        self.fake = Round2aFakeIdat(self.sha, self.md5, "ok")
        stack = ExitStack()
        self.addCleanup(stack.close)
        for target in (
            mock.patch.object(ti, "CACHE_ROOT", self.cache),
            mock.patch.object(ti, "ANNOTATED_ROOT", self.annotated),
            mock.patch.object(ti, "EVIDENCE_TYPE_MEMBER", self.ev_type),
            mock.patch.object(ti, "EVIDENCE_PATCH_PLAN", self.ev_patch),
            mock.patch.object(ti, "EVIDENCE_ANNOTATIONS", self.ev_ann),
            mock.patch.object(ti, "_ida_binary", return_value="C:/fake/idat.exe"),
            mock.patch.object(ti, "_evidence_index_record_write", return_value={"ok": True}),
            mock.patch.object(ti, "run_bounded_process", side_effect=self.fake),
        ):
            stack.enter_context(target)

    def slots(self):
        if not self.cache.is_dir():
            return []
        return sorted(p for p in self.cache.iterdir() if p.is_dir() and ti._SLOT_NAME.match(p.name))

    def reopens(self):
        return [c for c in self.fake.calls if c["job"]["mode"] == "reopen"]

    def write_log(self, lines, raw=None):
        self.annotated.mkdir(parents=True, exist_ok=True)
        log = self.annotated / f"{self.sha}{ti._ANNOTATION_LOG_SUFFIX}"
        log.write_bytes(raw if raw is not None else ("\n".join(json.dumps(x) if not isinstance(x, str) else x
                                                              for x in lines) + "\n").encode("utf-8"))
        return log

    def assertNoTargetLeak(self, text):
        self.assertNotIn(TARGET_NAME, text)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(str(self.root).replace("\\", "/"), text)


# ---------------------------------------------------------------------------
# ida_annotations: a file-system read, no engine
# ---------------------------------------------------------------------------
class AnnotationReaderTests(Round2aCase):
    def a(self, path=None, **kwargs):
        return json.loads(ti.ida_annotations(str(path or self.sample), **kwargs))

    @pytest.mark.contract
    def test_it_never_starts_the_engine_and_needs_no_ida(self):
        self.write_log([{"operation": "rename", "ok": True}])
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            data = self.a()
        self.assertTrue(data["ok"], data)
        self.assertIs(data["engine_started"], False)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual((data["status"], data["total_entries"], data["found"]), ("OK", 1, True))

    @pytest.mark.contract
    def test_no_log_is_found_false_and_says_it_is_not_a_statement_about_the_database(self):
        data = self.a()
        self.assertEqual((data["ok"], data["status"], data["found"], data["total_entries"], data["entries"]),
                         (True, "OK", False, 0, []))
        self.assertIn("does not exist until one has been applied", data["note"])
        self.assertIn("IDA's own names", data["note"])
        self.assertFalse(self.cache.exists())   # a read creates nothing

    def test_entries_come_back_in_written_order_with_the_sha_as_the_key(self):
        self.write_log([{"n": 1}, {"n": 2}, {"n": 3}])
        data = self.a()
        self.assertEqual([e["n"] for e in data["entries"]], [1, 2, 3])
        self.assertEqual(data["target_sha256"], self.sha)
        self.assertEqual(data["log_name"], f"{self.sha}.writes.jsonl")
        self.assertNotIn("truncated", data)
        self.assertEqual(data["omitted_older_entries"], 0)

    @pytest.mark.contract
    def test_a_cut_list_says_it_was_cut_and_keeps_the_newest(self):
        self.write_log([{"n": i} for i in range(10)])
        data = self.a(max_results=3)
        self.assertEqual([e["n"] for e in data["entries"]], [7, 8, 9])
        self.assertEqual((data["status"], data["truncated"], data["total_entries"], data["returned_entries"],
                          data["omitted_older_entries"]), ("PARTIAL", True, 10, 3, 7))
        self.assertTrue(any("7 older entries" in x for x in data["limitations"]), data["limitations"])

    @pytest.mark.contract
    def test_max_results_rejects_non_integers_with_the_accepted_range_and_clamps_integers(self):
        for bad in ("5", None, 2.5, True, [], "all"):
            with self.subTest(value=bad):
                data = json.loads(ti.ida_annotations(str(self.sample), bad))
                self.assertEqual((data["ok"], data["error"]), (False, "INVALID_MAX_RESULTS"))
                self.assertIn("1 to 5000", data["detail"])
        self.write_log([{"n": i} for i in range(3)])
        self.assertEqual(self.a(max_results=0)["invocation"]["max_results"], 1)
        self.assertEqual(self.a(max_results=10 ** 9)["invocation"]["max_results"], ti._ANNOTATION_MAX_ENTRIES)

    @pytest.mark.contract
    def test_unreadable_lines_are_counted_never_dropped_silently(self):
        self.write_log([{"n": 1}, "{not json", "[1, 2]", {"n": 2}, "", "\"a string\""])
        data = self.a()
        self.assertEqual([e["n"] for e in data["entries"]], [1, 2])
        self.assertEqual((data["status"], data["unreadable_lines"]), ("PARTIAL", 3))
        self.assertTrue(any("3 line(s)" in x for x in data["limitations"]), data["limitations"])

    @pytest.mark.contract
    def test_a_log_with_no_readable_line_is_not_an_empty_list(self):
        self.write_log(["{broken", "also broken"])
        data = self.a()
        self.assertEqual((data["ok"], data["status"], data["error"], data["unreadable_lines"]),
                         (False, "ANALYSIS_LIMITED", "ANNOTATION_LOG_UNREADABLE", 2))
        self.assertNotIn("entries", data)

    @pytest.mark.contract
    def test_non_utf8_bytes_and_deep_nesting_are_unreadable_lines_not_exceptions(self):
        raw = b'{"n": 1}\n\xff\xfe\x00 not utf8\n' + b"[" * 100000 + b"\n" + b'{"n": 2}\n'
        self.write_log(None, raw=raw)
        data = self.a()
        self.assertEqual([e["n"] for e in data["entries"]], [1, 2])
        self.assertEqual(data["unreadable_lines"], 2)

    @pytest.mark.contract
    def test_an_oversized_line_is_skipped_without_being_held_and_counted(self):
        big = b'{"pad": "' + b"x" * (ti._ANNOTATION_MAX_LINE_BYTES + 10) + b'"}\n'
        self.write_log(None, raw=b'{"n": 1}\n' + big + b'{"n": 2}\n')
        data = self.a()
        self.assertEqual([e["n"] for e in data["entries"]], [1, 2])
        self.assertEqual(data["unreadable_lines"], 1)
        self.assertTrue(any("longer than" in x for x in data["limitations"]), data["limitations"])

    @pytest.mark.contract
    def test_the_response_bound_cuts_the_oldest_and_says_so(self):
        self.write_log([{"n": i, "text": "y" * 400} for i in range(50)])
        data = self.a(max_results=50, max_chars=ti._MIN_RESPONSE_CHARS)
        self.assertLessEqual(len(ti._j(data)), ti._MIN_RESPONSE_CHARS)
        self.assertEqual((data["status"], data["truncated"]), ("PARTIAL", True))
        self.assertLess(data["returned_entries"], 50)
        self.assertEqual(data["entries"][-1]["n"], 49)          # the newest stay
        self.assertEqual(data["returned_entries"] + data["omitted_older_entries"], 50)
        self.assertTrue(any("response-size ceiling" in x for x in data["limitations"]), data["limitations"])
        evidence = json.loads((self.ev_ann / data["internal_evidence_name"]).read_text(encoding="utf-8"))
        self.assertEqual(len(evidence["entries"]), 50)             # the evidence file keeps what was read

    @pytest.mark.contract
    def test_the_target_name_and_path_stay_out_of_the_answer_and_the_evidence_name(self):
        self.write_log([{"operation": "rename", "ok": True}])
        text = ti.ida_annotations(str(self.sample))
        self.assertNoTargetLeak(text)
        data = json.loads(text)
        self.assertNoTargetLeak(data["internal_evidence_name"])
        self.assertTrue(data["internal_evidence_name"].startswith(self.sha[:16]))
        self.assertTrue((self.ev_ann / data["internal_evidence_name"]).is_file())
        self.assertIsNone(data["evidence_write_error"])
        for refused in (str(self.root / "nope.exe"), str(self.root / "x.i64")):
            (self.root / "x.i64").write_bytes(b"IDA")
            self.assertNoTargetLeak(ti.ida_annotations(refused))

    @pytest.mark.contract
    def test_strings_from_the_log_pass_the_same_scrubbing_as_ida_output(self):
        home = "C:" + "\\" + "Users" + "\\" + "SomeoneElse" + "\\" + "x.exe"
        self.write_log([{"old_name": home, "nested": [{"p": home}]}])
        text = ti.ida_annotations(str(self.sample))
        self.assertNotIn("SomeoneElse", text)
        self.assertIn("<HOME>", text)

    @pytest.mark.contract
    def test_refusals_never_raise_and_name_what_is_wrong(self):
        self.assertEqual(json.loads(ti.ida_annotations(str(self.root / "absent.exe")))["status"], "NOT_FOUND")
        (self.root / "x.i64").write_bytes(b"IDA")
        data = json.loads(ti.ida_annotations(str(self.root / "x.i64")))
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "DATABASE_INPUT_NOT_SUPPORTED"))
        outside = json.loads(ti.ida_annotations(str(Path(self.root.anchor) / "Windows" / "x.exe")))
        self.assertEqual(outside["status"], "PATH_REFUSED")
        for weird in (None, 123, "", "bad\x00name", self.root):
            with self.subTest(path=weird):
                self.assertIn(json.loads(ti.ida_annotations(weird))["status"], ("NOT_FOUND", "PATH_REFUSED"))

    @pytest.mark.contract
    def test_a_log_that_cannot_be_read_is_an_environment_status_not_an_empty_list(self):
        (self.annotated / f"{self.sha}{ti._ANNOTATION_LOG_SUFFIX}").mkdir(parents=True)   # opening a directory fails
        data = self.a()
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "READ_FAILED", "ANNOTATION_LOG_UNREADABLE_OS"))
        self.assertIn("errno", data["environment_error"])
        self.assertNotIn("entries", data)

    @pytest.mark.contract
    def test_an_input_that_cannot_be_read_is_read_failed(self):
        with mock.patch.object(ti, "_sha256_md5", side_effect=PermissionError(13, "denied")):
            data = self.a()
        self.assertEqual((data["status"], data["error"]), ("READ_FAILED", "IDA_INPUT_UNREADABLE"))

    def test_it_is_a_published_native_tool_and_left_the_unpublished_pin(self):
        self.assertIn("ida_annotations", tool_families.published_tools("native"))
        self.assertIn("ida_annotations", tool_families.FAMILIES["native"])


# ---------------------------------------------------------------------------
# ida_type_member_offset
# ---------------------------------------------------------------------------
class TypeMemberOffsetTests(Round2aCase):
    def t(self, struct="_LIST_ENTRY", member="Blink", **kwargs):
        return json.loads(ti.ida_type_member_offset(str(self.sample), struct, member, **kwargs))

    @pytest.mark.contract
    def test_rejections_name_the_field_and_say_what_is_accepted_and_start_nothing(self):
        for field, struct, member in (("struct_name", "", "Blink"), ("struct_name", None, "Blink"),
                                      ("struct_name", "1bad", "Blink"), ("struct_name", "a b", "Blink"),
                                      ("struct_name", "x" * 300, "Blink"), ("member_name", "_LIST_ENTRY", ""),
                                      ("member_name", "_LIST_ENTRY", None), ("member_name", "_LIST_ENTRY", "a.b"),
                                      ("member_name", "_LIST_ENTRY", 7)):
            with self.subTest(struct=struct, member=member):
                data = self.t(struct, member)
                self.assertEqual((data["ok"], data["status"], data["field"]), (False, "ANALYSIS_LIMITED", field))
                self.assertEqual(data["error"], field.upper() + "_REQUIRED")
                self.assertIn("C identifier", data["detail"])
                self.assertIn("for example", data["detail"])
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_missing_arguments_are_a_refusal_not_a_type_error(self):
        data = json.loads(ti.ida_type_member_offset(str(self.sample)))
        self.assertEqual(data["error"], "STRUCT_NAME_REQUIRED")
        data = json.loads(ti.ida_type_member_offset(str(self.sample), "_LIST_ENTRY"))
        self.assertEqual(data["error"], "MEMBER_NAME_REQUIRED")

    @pytest.mark.contract
    def test_a_bad_argument_is_reported_even_with_no_ida_installed(self):
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            self.assertEqual(self.t("", "Blink")["error"], "STRUCT_NAME_REQUIRED")
            data = self.t()
        self.assertEqual((data["ok"], data["status"], data["tool"]), (False, "TOOL_MISSING", "ida_type_member_offset"))

    @pytest.mark.contract
    def test_path_refusals_and_a_database_input_are_named_and_carry_no_path(self):
        self.assertEqual(json.loads(ti.ida_type_member_offset(str(self.root / "absent.exe"), "A", "b"))["status"], "NOT_FOUND")
        database = self.root / "x.i64"
        database.write_bytes(b"IDA")
        data = json.loads(ti.ida_type_member_offset(str(database), "A", "b"))
        self.assertEqual(data["error"], "DATABASE_INPUT_NOT_SUPPORTED")
        outside = ti.ida_type_member_offset(str(Path(self.root.anchor) / "Windows" / "x.exe"), "A", "b")
        self.assertEqual(json.loads(outside)["status"], "PATH_REFUSED")
        self.assertNoTargetLeak(ti.ida_type_member_offset(str(self.root / "absent.exe"), "A", "b"))
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_a_missing_packaged_worker_is_a_packaging_status(self):
        with mock.patch.object(ti, "_WORKER_SOURCE", self.root / "nope.idapy"):
            data = self.t()
        self.assertEqual((data["status"], data["error"]), ("ANALYSIS_LIMITED", "IDA_WORKER_MISSING"))

    def test_a_found_member_answers_in_integers_without_a_path_or_an_empty_items_list(self):
        data = self.t()
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["status"], data["offset_bits"], data["offset_bytes"], data["member_size_bits"],
                          data["byte_aligned"]), ("OK", 64, 8, 64, True))
        self.assertNotIn("items", data)
        self.assertNotIn("count", data)
        self.assertNotIn("path", data)
        self.assertEqual(data["target_sha256"], self.sha)
        self.assertNoTargetLeak(ti._j(data))
        job = self.reopens()[-1]["job"]
        self.assertEqual((job["operation"], job["mode"]), ("type_member_offset", "reopen"))
        self.assertEqual(json.loads(job["query"]), {"struct_name": "_LIST_ENTRY", "member_name": "Blink"})
        self.assertEqual(self.fake.modes, ["create", "reopen"])

    def test_the_raw_worker_result_is_evidence_named_by_hash_not_by_target(self):
        data = self.t()
        self.assertNoTargetLeak(data["internal_evidence_name"])
        self.assertTrue(data["internal_evidence_name"].startswith(self.sha[:16]))
        raw = json.loads((self.ev_type / data["internal_evidence_name"]).read_text(encoding="utf-8"))
        self.assertEqual(raw["offset_bits"], 64)
        self.assertIn("items", raw)   # the answer drops the empty envelope field; the evidence keeps the raw result

    @pytest.mark.contract
    def test_a_member_that_is_absent_is_an_answer_about_the_type_information(self):
        self.fake.type_result = "member_missing"
        data = self.t(member="Nope")
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", "MEMBER_NOT_FOUND"))
        self.assertEqual(data["member_names"], ["Flink", "Blink"])
        self.assertIs(data["member_names_truncated"], False)
        self.assertIn("not about the program", data["note"])
        self.assertNotIn("offset_bits", data)
        self.assertNoTargetLeak(ti._j(data))
        self.assertTrue((self.ev_type / data["internal_evidence_name"]).is_file())     # a refusal leaves evidence too
        self.assertEqual(self.t()["database_cache"], "HIT")                            # and the cache is intact

    def test_the_workers_lookup_status_is_carried_beside_the_run_status_not_over_it(self):
        self.fake.type_result = "member_missing"
        original = self.fake._body
        self.fake._body = lambda job, sha: {**original(job, sha), "status": "NOT_FOUND", "partial": False,
                                            "lookup_errors": []}
        data = self.t(member="Nope")
        self.assertEqual((data["ok"], data["status"]), (False, "ANALYSIS_LIMITED"))
        self.assertEqual(data["query_result"], {"status": "NOT_FOUND", "partial": False, "lookup_errors": []})
        self.assertNotIn("partial", data)

    @pytest.mark.contract
    def test_a_result_without_integer_offsets_is_not_an_answer(self):
        self.fake.type_result = "incomplete"
        data = self.t()
        self.assertEqual((data["ok"], data["error"]), (False, "TYPE_MEMBER_RESULT_INCOMPLETE"))
        self.assertNotIn("offset_bytes", data)

    @pytest.mark.contract
    def test_the_reopen_discard_guarantee_still_applies(self):
        self.fake.discard_flag = False
        data = self.t()
        self.assertEqual((data["ok"], data["error"]), (False, "DATABASE_CHANGES_NOT_DISCARDED"))
        self.assertEqual(self.slots(), [])
        self.fake.discard_flag = _OMIT
        self.assertEqual(self.t()["error"], "DATABASE_CHANGES_NOT_DISCARDED")

    @pytest.mark.contract
    def test_a_timeout_is_the_shared_shape_with_this_operations_own_ceiling(self):
        self.t()                                    # prime the cache so the timeout is in the question session
        self.fake.behaviour = "timeout"
        data = self.t(timeout_seconds=10 ** 9)
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "TIMEOUT", "IDA_TIMEOUT_PROCESS_TREE_TERMINATED"))
        self.assertEqual((data["timed_out_stage"], data["stage_ceiling_seconds"]), ("query", ti._MAX_TYPE_MEMBER_TIMEOUT_SECONDS))
        self.assertLessEqual(self.fake.calls[-1]["timeout"], ti._MAX_TYPE_MEMBER_TIMEOUT_SECONDS)
        self.assertIn("Do not read a timeout as", data["detail"])
        self.assertNoTargetLeak(ti._j(data))

    def test_the_ceiling_is_this_operations_own_constant_not_shared_infrastructure(self):
        self.assertEqual(ti._MAX_TYPE_MEMBER_TIMEOUT_SECONDS, 300)
        source = (Path(ti.__file__).parent.parent / "bounded_subprocess.py").read_text(encoding="utf-8")
        self.assertNotIn("TYPE_MEMBER", source)
        self.assertNotIn("PATCH_PLAN", source)

    def test_it_left_the_unpublished_pin_and_is_not_a_member_of_the_query_menu(self):
        self.assertIn("ida_type_member_offset", tool_families.published_tools("native"))
        self.assertNotIn("type_member_offset", ti._ALLOWED_OPERATIONS)
        data = json.loads(ti.ida_query(str(self.sample), "type_member_offset"))
        self.assertEqual(data["error"], "UNKNOWN_OPERATION")


# ---------------------------------------------------------------------------
# ida_patch_plan
# ---------------------------------------------------------------------------
class PatchPlanTests(Round2aCase):
    def p(self, address=0x140001002, operation="force_branch", **kwargs):
        return json.loads(ti.ida_patch_plan(str(self.sample), address, operation, **kwargs))

    @pytest.mark.contract
    def test_rejections_teach_and_start_nothing(self):
        data = self.p(operation="rename")
        self.assertEqual((data["status"], data["allowed"]), ("UNKNOWN_OPERATION", ["force_branch", "nop_out"]))
        self.assertEqual(self.p(operation=None)["status"], "UNKNOWN_OPERATION")
        for bad in (None, "", "zz", -1, True, 2 ** 64, 1.5, []):
            with self.subTest(address=bad):
                data = self.p(address=bad)
                self.assertEqual((data["ok"], data["status"]), (False, "INVALID_ADDRESS"))
                self.assertIn("0x140001002", data["detail"])
        data = self.p(address_kind="offset")
        self.assertEqual((data["status"], data["accepted"]), ("INVALID_ADDRESS_KIND", ["va", "rva", "file_offset"]))
        for bad in ("2", None, 2.0, True):
            with self.subTest(count=bad):
                data = self.p(operation="nop_out", instruction_count=bad)
                self.assertEqual(data["error"], "INVALID_INSTRUCTION_COUNT")
                self.assertIn("1 to 64", data["detail"])
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_missing_arguments_are_a_refusal_not_a_type_error(self):
        self.assertEqual(json.loads(ti.ida_patch_plan(str(self.sample)))["status"], "UNKNOWN_OPERATION")
        self.assertEqual(json.loads(ti.ida_patch_plan(str(self.sample), operation="nop_out"))["status"], "INVALID_ADDRESS")

    @pytest.mark.contract
    def test_tool_missing_database_input_path_and_worker_refusals(self):
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            self.assertEqual(self.p()["status"], "TOOL_MISSING")
        self.assertEqual(json.loads(ti.ida_patch_plan(str(self.root / "absent.exe"), 1, "nop_out"))["status"], "NOT_FOUND")
        (self.root / "x.i64").write_bytes(b"IDA")
        self.assertEqual(json.loads(ti.ida_patch_plan(str(self.root / "x.i64"), 1, "nop_out"))["error"],
                         "DATABASE_INPUT_NOT_SUPPORTED")
        with mock.patch.object(ti, "_PATCH_PLAN_WORKER_SOURCE", self.root / "nope.idapy"):
            self.assertEqual(self.p()["error"], "IDA_WORKER_MISSING")
        self.assertNoTargetLeak(ti.ida_patch_plan(str(self.root / "absent.exe"), 1, "nop_out"))

    def test_a_plan_has_the_shared_address_form_says_it_is_only_a_plan_and_carries_the_hash_proof(self):
        data = self.p(address="0x140001002")
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["status"], data["plan_only"], data["applied_to_file"]), ("OK", True, False))
        self.assertEqual(set(data["address"]), ADDRESS_FIELDS)
        self.assertEqual(set(data["branch_target"]), ADDRESS_FIELDS)
        self.assertEqual((data["original_bytes"], data["patched_bytes"]), ("7403", "eb03"))
        integrity = data["signals"]["database_integrity"]
        self.assertIs(integrity["unchanged"], True)
        self.assertEqual(integrity["database_sha256_before"], integrity["database_sha256_after"])
        self.assertEqual(len(integrity["database_sha256_before"]), 64)
        self.assertNoTargetLeak(ti._j(data))
        self.assertNotIn("path", data)
        job = self.reopens()[-1]["job"]
        self.assertEqual((job["operation"], job["patch_operation"], job["address"], job["address_kind"], job["mode"]),
                         ("patch_plan", "force_branch", "0x140001002", "va", "reopen"))
        self.assertIn(b"_TempSession", self.fake.calls[-1]["script"])     # the patch worker ran, not the query worker

    def test_the_address_is_accepted_as_an_integer_or_a_string_and_the_kind_is_forwarded(self):
        self.p(address=4198402, address_kind="RVA")
        self.assertEqual(self.reopens()[-1]["job"]["address"], hex(4198402))
        self.assertEqual(self.reopens()[-1]["job"]["address_kind"], "rva")
        data = self.p(address="  0x200 ", address_kind="file_offset", operation="nop_out", instruction_count=500)
        self.assertEqual(data["invocation"]["instruction_count"], 64)
        self.assertEqual(self.reopens()[-1]["job"]["instruction_count"], 64)
        self.assertIsNone(self.p(operation="force_branch")["invocation"]["instruction_count"])

    @pytest.mark.contract
    def test_a_database_that_differs_after_the_session_is_a_cache_violation_with_no_plan(self):
        self.p()                                    # the slot exists
        self.assertEqual(len(self.slots()), 1)
        self.fake.mutate_database = True
        data = self.p()
        self.assertEqual((data["ok"], data["status"], data["error"]),
                         (False, "PATCH_PLAN_CACHE_VIOLATION", "PATCH_PLAN_CACHE_VIOLATION"))
        integrity = data["database_integrity"]
        self.assertIs(integrity["unchanged"], False)
        self.assertNotEqual(integrity["database_sha256_before"], integrity["database_sha256_after"])
        for plan_field in ("original_bytes", "patched_bytes", "address", "disasm_after"):
            self.assertNotIn(plan_field, data)
        self.assertEqual(self.slots(), [])          # the slot is dropped
        self.fake.mutate_database = False
        again = self.p()
        self.assertEqual((again["ok"], again["database_cache"]), (True, "CREATED"))

    @pytest.mark.contract
    def test_a_database_that_cannot_be_hashed_beforehand_stops_the_session_from_starting(self):
        self.p()
        before = len(self.fake.calls)
        real = ti._sha256_md5

        def refuse_database(path):
            if Path(path).name == ti._DB_NAME:
                raise PermissionError(13, "denied")
            return real(path)

        with mock.patch.object(ti, "_sha256_md5", side_effect=refuse_database):
            data = self.p()
        self.assertEqual((data["ok"], data["status"], data["error"]), (False, "ANALYSIS_LIMITED", "IDA_DATABASE_UNREADABLE"))
        self.assertEqual(len(self.fake.calls), before)      # no patching session ran over a database nobody could vouch for
        self.assertNoTargetLeak(ti._j(data))

    @pytest.mark.contract
    def test_a_domain_refusal_carries_its_name_as_the_status_like_the_rizin_planner(self):
        self.fake.patch_result = "refused"
        data = self.p(address=0x140001000)
        self.assertEqual((data["ok"], data["status"], data["error"]),
                         (False, "NOT_A_CONDITIONAL_BRANCH", "NOT_A_CONDITIONAL_BRANCH"))
        self.assertEqual(data["instruction"], "mov     eax, ecx")
        self.assertIs(data["database_integrity"]["unchanged"], True)
        self.assertTrue((self.ev_patch / data["internal_evidence_name"]).is_file())
        self.assertNoTargetLeak(ti._j(data))
        self.assertEqual(self.p(operation="nop_out")["database_cache"], "HIT")     # the cache is intact

    @pytest.mark.contract
    def test_a_result_that_does_not_say_it_is_only_a_plan_is_refused(self):
        self.fake.patch_result = "incomplete"
        data = self.p()
        self.assertEqual((data["ok"], data["error"]), (False, "PATCH_PLAN_RESULT_INCOMPLETE"))
        self.assertNotIn("patched_bytes", data)

    @pytest.mark.contract
    def test_the_reopen_discard_guarantee_still_applies(self):
        self.fake.discard_flag = False
        data = self.p()
        self.assertEqual((data["ok"], data["error"]), (False, "DATABASE_CHANGES_NOT_DISCARDED"))
        self.assertEqual(self.slots(), [])

    @pytest.mark.contract
    def test_a_timeout_is_the_shared_shape_with_this_operations_own_ceiling(self):
        self.p()
        self.fake.behaviour = "timeout"
        data = self.p(timeout_seconds=10 ** 9)
        self.assertEqual((data["ok"], data["status"]), (False, "TIMEOUT"))
        self.assertEqual((data["timed_out_stage"], data["stage_ceiling_seconds"]), ("query", ti._MAX_PATCH_PLAN_TIMEOUT_SECONDS))
        self.assertLessEqual(self.fake.calls[-1]["timeout"], ti._MAX_PATCH_PLAN_TIMEOUT_SECONDS)
        self.assertNoTargetLeak(ti._j(data))

    def test_only_the_patch_plan_is_held_to_the_hash_check(self):
        """A question's session is not hashed (the flag and the four signals guard it); the patch plan's is."""
        self.assertTrue(json.loads(ti.ida_query(str(self.sample), "summary"))["ok"])
        self.fake.mutate_database = True
        data = json.loads(ti.ida_query(str(self.sample), "list_functions"))
        self.assertTrue(data["ok"], data)
        self.assertNotIn("database_integrity", data["signals"])

    def test_it_left_the_unpublished_pin_and_is_not_a_member_of_the_query_menu(self):
        self.assertIn("ida_patch_plan", tool_families.published_tools("native"))
        self.assertNotIn("patch_plan", ti._ALLOWED_OPERATIONS)
        self.assertEqual(json.loads(ti.ida_query(str(self.sample), "patch_plan"))["error"], "UNKNOWN_OPERATION")


# ---------------------------------------------------------------------------
# the patch worker, against stub ida_* modules
# ---------------------------------------------------------------------------
def _load_patch_worker():
    names = ["ida_auto", "ida_bytes", "ida_idp", "ida_ida", "ida_loader", "ida_name", "ida_nalt", "ida_pro",
             "idaapi", "idautils", "idc"]
    stubs = {n: mock.MagicMock(name=n) for n in names}
    stubs["idc"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["idc"].DELIT_SIMPLE = 0
    stubs["ida_loader"].DBFL_TEMP = 4
    stubs["ida_ida"].inf_get_procname.return_value = "metapc"
    stubs["ida_nalt"].get_imagebase.return_value = 0x140000000
    stubs["idaapi"].get_fileregion_offset.side_effect = lambda ea: ea - 0x140000000 + 0x200
    stubs["idaapi"].get_fileregion_ea.side_effect = lambda off: off - 0x200 + 0x140000000
    stubs["idc"].get_segm_name.return_value = ".text"
    stubs["idc"].is_code.return_value = True
    stubs["idc"].get_full_flags.return_value = 1
    stubs["idc"].create_insn.return_value = True
    with mock.patch.dict(sys.modules, stubs):
        loader = SourceFileLoader("liebert_ida_patch_worker_under_test", str(PATCH_WORKER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    return module, stubs


class PatchWorkerFileTests(unittest.TestCase):
    def test_it_is_a_data_file_without_bom_or_crlf_that_compiles(self):
        self.assertEqual(PATCH_WORKER.suffix, ".idapy")
        raw = PATCH_WORKER.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        compile(raw.decode("utf-8"), str(PATCH_WORKER), "exec")
        self.assertEqual(list(PATCH_WORKER.parent.glob("*.py")), [])

    def test_it_imports_only_the_standard_library_and_ida_modules(self):
        tree = ast.parse(PATCH_WORKER.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        self.assertEqual({n for n in names if not (n.startswith("ida") or n == "idc")}, {"json", "os", "sys", "traceback"})

    def test_every_patch_call_is_a_method_of_the_one_class_that_marks_the_database_temporary(self):
        tree = ast.parse(PATCH_WORKER.read_text(encoding="utf-8"))
        session = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_TempSession")
        inside = {id(n) for n in ast.walk(session)}
        mutators = {"patch_bytes", "del_items", "create_insn", "patch_byte", "set_database_flag"}
        outside, within = [], set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in mutators:
                (within.add(node.attr) if id(node) in inside else outside.append((node.attr, node.lineno)))
        self.assertEqual(outside, [])
        self.assertTrue({"patch_bytes", "del_items", "create_insn", "set_database_flag"} <= within, within)

    def test_the_query_worker_still_contains_no_write_api(self):
        source = QUERY_WORKER.read_text(encoding="utf-8")
        for api in ("set_name", "set_cmt", "patch_bytes", "rename_lvar", "del_items", "create_insn", "apply_type",
                    "set_type"):
            self.assertNotIn(api, source, api)

    def test_the_microcode_and_query_workers_do_not_gain_the_patch_worker_code(self):
        self.assertNotIn("_TempSession", QUERY_WORKER.read_text(encoding="utf-8"))
        self.assertTrue(PATCH_WORKER.is_file())


class PatchWorkerLogicTests(unittest.TestCase):
    def setUp(self):
        self.w, self.ida = _load_patch_worker()
        self.tmp = process_scratch("r2a_pw_" + hashlib.sha256(self.id().encode()).hexdigest()[:6])
        self.tmp.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = {"patched": False, "events": []}
        ida = self.ida

        def patch(ea, data):
            self.state["patched"] = not self.state["patched"]
            self.state["events"].append("patch")

        ida["ida_bytes"].patch_bytes.side_effect = patch
        ida["ida_loader"].set_database_flag.side_effect = lambda *_a: self.state["events"].append("flag")
        ida["ida_auto"].auto_wait.side_effect = lambda *_a: self.state["events"].append("auto_wait")
        ida["ida_nalt"].retrieve_input_file_sha256.return_value = bytes.fromhex("ab" * 32)
        ida["ida_nalt"].retrieve_input_file_md5.return_value = bytes.fromhex("cd" * 16)

    def run_job(self, **job):
        job.setdefault("operation", "patch_plan")
        job.setdefault("mode", "reopen")
        job["output"] = str(self.tmp / "out.json")
        job_file = self.tmp / "job.json"
        job_file.write_text(json.dumps(job), encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job_file)}):
            code = self.w.main()
        return code, json.loads((self.tmp / "out.json").read_text(encoding="utf-8"))

    def nop_stubs(self):
        ida, state = self.ida, self.state
        sizes = {0x140001000: 2, 0x140001002: 1}
        ida["idc"].get_item_size.side_effect = lambda ea: 1 if state["patched"] else sizes.get(ea, 1)
        ida["idc"].get_bytes.side_effect = lambda ea, n: bytes.fromhex("31c090")[:n]
        lines = {0x140001000: "xor     eax, eax", 0x140001002: "nop"}
        ida["idc"].generate_disasm_line.side_effect = lambda ea, _f: "nop" if state["patched"] else lines.get(ea, "?")

    def branch_stubs(self, mnemonic="jz", assembled=b"\xeb\x03"):
        ida, state = self.ida, self.state
        ida["idc"].get_item_size.return_value = 2
        ida["idc"].get_bytes.return_value = b"\x74\x03"
        ida["idc"].print_insn_mnem.return_value = mnemonic
        ida["idc"].print_operand.return_value = ""
        ida["idc"].generate_disasm_line.side_effect = lambda ea, _f: "jmp     short loc" if state["patched"] else "jz      short loc"
        ida["idc"].get_sreg.return_value = 0
        ida["idautils"].CodeRefsFrom.return_value = [0x140001007]
        ida["ida_name"].get_name.return_value = "locret_140001007"
        ida["ida_idp"].AssembleLine.return_value = assembled

    @pytest.mark.contract
    def test_the_database_is_marked_temporary_before_anything_else_including_auto_wait(self):
        self.nop_stubs()
        self.run_job(address="0x140001000", patch_operation="nop_out", instruction_count=2)
        events = self.state["events"]
        self.assertEqual(events[0], "flag")
        self.assertLess(events.index("flag"), events.index("auto_wait"))
        self.assertLess(events.index("auto_wait"), events.index("patch"))
        self.ida["ida_loader"].set_database_flag.assert_called_once_with(4)
        self.ida["ida_loader"].save_database.assert_not_called()

    @pytest.mark.contract
    def test_without_the_temp_flag_no_patch_call_is_made(self):
        self.ida["ida_loader"].set_database_flag.side_effect = AttributeError("older build")
        code, data = self.run_job(address="0x140001000", patch_operation="nop_out")
        self.assertEqual((code, data["ok"], data["error"]), (0, False, "DATABASE_CHANGES_NOT_DISCARDABLE"))
        self.assertNotIn("database_changes_discarded", data)       # so the wrapper refuses it as well
        self.ida["ida_bytes"].patch_bytes.assert_not_called()
        self.ida["idc"].del_items.assert_not_called()
        self.ida["idc"].create_insn.assert_not_called()
        self.ida["ida_auto"].auto_wait.assert_not_called()
        self.assertTrue(data["script_completed"])

    @pytest.mark.contract
    def test_a_create_session_is_refused_and_touches_nothing(self):
        _code, data = self.run_job(mode="create", address="0x140001000", patch_operation="nop_out")
        self.assertEqual((data["ok"], data["error"]), (False, "PATCH_PLAN_REQUIRES_REOPEN_SESSION"))
        self.ida["ida_loader"].set_database_flag.assert_not_called()
        self.ida["ida_bytes"].patch_bytes.assert_not_called()

    @pytest.mark.contract
    def test_bad_requests_are_named_refusals_after_the_flag_and_before_any_patch(self):
        self.nop_stubs()
        for job, error in (
            (dict(address="0x140001000", patch_operation="rename"), "UNKNOWN_PATCH_OPERATION"),
            (dict(address="zz", patch_operation="nop_out"), "INVALID_ADDRESS"),
            (dict(address="0x1", address_kind="offset", patch_operation="nop_out"), "INVALID_ADDRESS_KIND"),
        ):
            with self.subTest(error=error):
                _code, data = self.run_job(**job)
                self.assertEqual((data["ok"], data["error"]), (False, error))
        self.ida["idc"].get_segm_name.return_value = ""
        _code, data = self.run_job(address="0x1", patch_operation="nop_out")
        self.assertEqual(data["error"], "ADDRESS_OUTSIDE_SECTION")
        self.ida["ida_bytes"].patch_bytes.assert_not_called()

    @pytest.mark.contract
    def test_another_processor_is_refused_before_any_patch(self):
        self.ida["ida_ida"].inf_get_procname.return_value = "ARM"
        _code, data = self.run_job(address="0x140001000", patch_operation="nop_out")
        self.assertEqual((data["error"], data["processor"]), ("ARCHITECTURE_NOT_SUPPORTED", "ARM"))
        self.ida["ida_bytes"].patch_bytes.assert_not_called()

    def test_nop_out_patches_then_restores_the_original_bytes_and_reports_a_changed_boundary_count(self):
        self.nop_stubs()
        _code, data = self.run_job(address="0x140001000", patch_operation="nop_out", instruction_count=2)
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["original_bytes"], data["patched_bytes"]), ("31c090", "909090"))
        self.assertEqual(data["disasm_before"], ["xor     eax, eax", "nop"])
        self.assertEqual(data["disasm_after"], ["nop", "nop", "nop"])
        self.assertEqual((data["plan_only"], data["applied_to_file"], data["database_changes_discarded"]), (True, False, True))
        self.assertEqual(set(data["address"]), ADDRESS_FIELDS)
        self.assertEqual(data["address"]["rva"], "0x1000")
        self.assertEqual(len(data["warnings"]), 1)
        calls = self.ida["ida_bytes"].patch_bytes.call_args_list
        self.assertEqual([c.args for c in calls], [(0x140001000, b"\x90\x90\x90"), (0x140001000, bytes.fromhex("31c090"))])
        self.assertEqual(list(data)[-1], "script_completed")
        self.assertEqual(data["engine_input_sha256"], "ab" * 32)

    @pytest.mark.contract
    def test_data_bytes_are_never_counted_as_instructions(self):
        self.nop_stubs()
        self.ida["idc"].is_code.return_value = False
        _code, data = self.run_job(address="0x140001000", patch_operation="nop_out", instruction_count=2)
        self.assertEqual((data["error"], data["requested"], data["decoded"]), ("NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW", 2, 0))
        self.ida["ida_bytes"].patch_bytes.assert_not_called()
        _code, data = self.run_job(address="0x140001000", patch_operation="force_branch")
        self.assertEqual(data["error"], "DISASSEMBLY_FAILED")

    def test_force_branch_turns_a_conditional_jump_into_an_unconditional_one_of_the_same_length(self):
        self.branch_stubs()
        _code, data = self.run_job(address="0x140001002", patch_operation="force_branch")
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["original_bytes"], data["patched_bytes"], data["patched_length"]), ("7403", "eb03", 2))
        self.assertEqual(set(data["branch_target"]), ADDRESS_FIELDS)
        self.assertEqual(data["branch_target"]["va"], "0x140001007")
        self.assertEqual(data["warnings"], [])
        self.ida["ida_idp"].AssembleLine.assert_called_once()
        self.assertEqual(self.ida["ida_idp"].AssembleLine.call_args.args[-1], "jmp locret_140001007")

    def test_a_shorter_jump_is_padded_with_nops_to_the_original_length(self):
        self.branch_stubs(assembled=b"\xeb")
        self.ida["idc"].get_item_size.return_value = 2
        _code, data = self.run_job(address="0x140001002", patch_operation="force_branch")
        self.assertEqual(data["patched_bytes"], "eb90")

    @pytest.mark.contract
    def test_force_branch_refusals_are_named(self):
        self.branch_stubs(mnemonic="mov")
        _code, data = self.run_job(address="0x140001002", patch_operation="force_branch")
        self.assertEqual((data["error"], data["instruction"]), ("NOT_A_CONDITIONAL_BRANCH", "jz      short loc"))
        self.branch_stubs(assembled=b"\xe9\x00\x00\x00\x00")
        _code, data = self.run_job(address="0x140001002", patch_operation="force_branch")
        self.assertEqual((data["error"], data["unconditional_jump_length"]), ("TARGET_TOO_FAR_FOR_ORIGINAL_LENGTH", 5))
        self.branch_stubs(assembled=b"")
        self.assertEqual(self.run_job(address="0x140001002", patch_operation="force_branch")[1]["error"], "ASSEMBLY_FAILED")
        self.branch_stubs()
        self.ida["idautils"].CodeRefsFrom.return_value = []
        self.assertEqual(self.run_job(address="0x140001002", patch_operation="force_branch")[1]["error"], "NO_DIRECT_BRANCH_TARGET")
        self.branch_stubs()
        self.ida["ida_name"].get_name.return_value = ""
        self.assertEqual(self.run_job(address="0x140001002", patch_operation="force_branch")[1]["error"], "ASSEMBLY_FAILED")

    @pytest.mark.contract
    def test_an_exception_after_the_flag_keeps_the_discard_signal(self):
        self.nop_stubs()
        self.ida["idc"].get_bytes.side_effect = RuntimeError("kernel said no")
        _code, data = self.run_job(address="0x140001000", patch_operation="nop_out")
        self.assertEqual((data["error"], data["database_changes_discarded"]), ("IDAPYTHON_SCRIPT_EXCEPTION", True))
        self.assertIn("kernel said no", data["traceback"])

    @pytest.mark.contract
    def test_importing_has_no_side_effects_and_a_bad_job_exits_nonzero(self):
        self.ida["ida_pro"].qexit.assert_not_called()
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: ""}):
            self.assertEqual(self.w.main(), 2)
        with mock.patch.object(self.w, "main", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.w._entry()
        self.ida["ida_pro"].qexit.assert_called_once_with(4)


# ---------------------------------------------------------------------------
# the type-member operation of the query worker, against stub ida_* modules
# ---------------------------------------------------------------------------
class TypeMemberWorkerTests(unittest.TestCase):
    def setUp(self):
        self.w, self.ida = _load_worker()
        self.typeinf = mock.MagicMock(name="ida_typeinf")
        self.typeinf.BTF_TYPEDEF, self.typeinf.STRMEM_NAME = 1, 2
        patcher = mock.patch.dict(sys.modules, {"ida_typeinf": self.typeinf})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.known = {}

    def build(self, name, members, is_union=False, udt=True, size=16):
        """A tinfo_t stand-in for `name` (`members`: [(name, offset_bits, size_bits)])."""
        udms = []
        for member_name, offset, bits in members:
            udm = mock.MagicMock(name=member_name)
            udm.name, udm.offset, udm.size = member_name, offset, bits
            udm.type.__str__ = lambda _self: "void *"
            udm.is_bitfield.return_value = False
            udms.append(udm)
        self.known[name] = (udms, is_union, udt, size)

    def wire(self):
        known, typeinf = self.known, self.typeinf

        def new_tinfo():
            tif = mock.MagicMock(name="tinfo")
            state = {}

            def get_named_type(_til, name, _decl, _resolve):
                if name not in known:
                    return False
                state["entry"] = known[name]
                return True

            def find_udm(udm, _flags):
                for index, member in enumerate(state["entry"][0]):
                    if member.name == udm.name:
                        return index
                return -1

            tif.get_named_type.side_effect = get_named_type
            tif.is_udt.side_effect = lambda: state["entry"][2]
            tif.is_union.side_effect = lambda: state["entry"][1]
            tif.get_size.side_effect = lambda: state["entry"][3]
            tif.get_udt_nmembers.side_effect = lambda: len(state["entry"][0])
            tif.find_udm.side_effect = find_udm
            tif.get_udm.side_effect = lambda index: (index, state["entry"][0][index])
            return tif

        typeinf.tinfo_t.side_effect = new_tinfo
        typeinf.udm_t.side_effect = lambda: mock.MagicMock(name="udm_t")

    def ask(self, struct, member):
        self.wire()
        result = {"ok": True, "items": []}
        self.w._op_type_member_offset(result, json.dumps({"struct_name": struct, "member_name": member}), 1, 0)
        return result

    def test_a_direct_member_is_found_with_its_offset_in_bits_and_bytes(self):
        self.build("_LIST_ENTRY", [("Flink", 0, 64), ("Blink", 64, 64)])
        result = self.ask("_LIST_ENTRY", "Blink")
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["offset_bits"], result["offset_bytes"], result["member_size_bits"], result["byte_aligned"]),
                         (64, 8, 64, True))
        self.assertEqual((result["resolved_type_name"], result["struct_size_bytes"], result["member_index"]),
                         ("_LIST_ENTRY", 16, 1))

    def test_the_other_leading_underscore_spelling_is_tried(self):
        self.build("LIST_ENTRY", [("Flink", 0, 64)])
        result = self.ask("_LIST_ENTRY", "Flink")
        self.assertEqual((result["ok"], result["resolved_type_name"], result["tried_type_names"]),
                         (True, "LIST_ENTRY", ["_LIST_ENTRY", "LIST_ENTRY"]))

    def test_a_bit_field_is_not_reported_as_byte_aligned(self):
        self.build("_FLAGS", [("a", 3, 2)])
        result = self.ask("_FLAGS", "a")
        self.assertEqual((result["offset_bits"], result["offset_bytes"], result["byte_aligned"], result["member_size_bytes"]),
                         (3, 0, False, None))

    @pytest.mark.contract
    def test_the_three_negatives_are_kept_apart(self):
        self.build("_LIST_ENTRY", [("Flink", 0, 64), ("Blink", 64, 64)])
        self.build("DWORD", [], udt=False, size=4)
        self.assertEqual(self.ask("_NoSuch", "x")["error"], "TYPE_NOT_FOUND")
        self.assertEqual(self.ask("DWORD", "x")["error"], "TYPE_NOT_STRUCT_OR_UNION")
        result = self.ask("_LIST_ENTRY", "Nope")
        self.assertEqual((result["ok"], result["error"], result["member_names"], result["member_names_truncated"]),
                         (False, "MEMBER_NOT_FOUND", ["Flink", "Blink"], False))
        self.assertNotIn("offset_bits", result)

    @pytest.mark.contract
    def test_the_member_name_list_is_cut_at_a_stated_limit_and_says_so(self):
        count = self.w._MEMBER_NAME_LIST_LIMIT + 7
        self.build("_BIG", [(f"m{i}", i * 8, 8) for i in range(count)])
        result = self.ask("_BIG", "absent")
        self.assertEqual(len(result["member_names"]), self.w._MEMBER_NAME_LIST_LIMIT)
        self.assertEqual((result["member_count"], result["member_names_truncated"]), (count, True))

    @pytest.mark.contract
    def test_a_malformed_request_is_a_named_error_not_an_exception(self):
        result = {"ok": True, "items": []}
        self.w._op_type_member_offset(result, "not json", 1, 0)
        self.assertEqual((result["ok"], result["error"]), (False, "INVALID_TYPE_MEMBER_REQUEST"))
        result = {"ok": True, "items": []}
        self.w._op_type_member_offset(result, json.dumps({"struct_name": "A"}), 1, 0)
        self.assertEqual(result["error"], "INVALID_TYPE_MEMBER_REQUEST")

    def test_the_operation_is_dispatched_inside_the_discard_guarantee(self):
        self.build("_LIST_ENTRY", [("Flink", 0, 64)])
        self.wire()
        job_file = Path(process_scratch("r2a_tm_" + hashlib.sha256(self.id().encode()).hexdigest()[:6]))
        job_file.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, job_file, ignore_errors=True)
        job = {"operation": "type_member_offset", "mode": "reopen", "output": str(job_file / "out.json"),
               "query": json.dumps({"struct_name": "_LIST_ENTRY", "member_name": "Flink"}), "max_results": 1}
        (job_file / "job.json").write_text(json.dumps(job), encoding="utf-8")
        self.ida["ida_nalt"].retrieve_input_file_sha256.return_value = bytes.fromhex("ab" * 32)
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job_file / "job.json")}):
            self.assertEqual(self.w.main(), 0)
        data = json.loads((job_file / "out.json").read_text(encoding="utf-8"))
        self.assertEqual((data["ok"], data["offset_bytes"], data["database_changes_discarded"]), (True, 0, True))
        self.ida["ida_loader"].set_database_flag.assert_called_once_with(4)
        self.ida["ida_loader"].save_database.assert_not_called()


# ---------------------------------------------------------------------------
# the real tool
# ---------------------------------------------------------------------------
CODE = bytes.fromhex("85c9" "7403" "ffc0" "90" "c3") + b"\x90" * 8     # test ecx,ecx; jz +3; inc eax; nop; ret


@pytest.mark.heavy
class IdaRound2aRealInstallTests(unittest.TestCase):
    """Needs a licensed IDA Pro 9.x; skips when idat is not found. Builds its own tiny synthetic x86-64 PE."""

    @classmethod
    def setUpClass(cls):
        if not ti.ida_available():
            raise unittest.SkipTest("IDA Pro (idat) is not installed")
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        cls.root = process_scratch("r2a_real")
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", CODE)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        # A short name on purpose: Windows' 260-character path limit applies below a slot's scratch directory.
        self.cache = self.root / f"c{hashlib.sha256(self.id().encode()).hexdigest()[:6]}"
        self.cache.mkdir(parents=True)
        stack.enter_context(mock.patch.object(ti, "CACHE_ROOT", self.cache / "db"))
        stack.enter_context(mock.patch.object(ti, "ANNOTATED_ROOT", self.cache / "annotated"))
        for name in ("EVIDENCE", "EVIDENCE_TYPE_MEMBER", "EVIDENCE_PATCH_PLAN", "EVIDENCE_ANNOTATIONS"):
            stack.enter_context(mock.patch.object(ti, name, self.cache / "ev"))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))

    def database(self):
        return next((self.cache / "db").rglob("db.i64"))

    def database_digest(self):
        return hashlib.sha256(self.database().read_bytes()).hexdigest()

    def prime(self):
        self.assertTrue(json.loads(ti.ida_query(str(self.pe), "summary"))["ok"])

    def test_a_type_members_offset_is_read_from_the_type_information(self):
        self.prime()
        before = self.database_digest()
        data = json.loads(ti.ida_type_member_offset(str(self.pe), "_LIST_ENTRY", "Blink"))
        self.assertTrue(data["ok"], data)
        self.assertEqual((data["offset_bits"], data["offset_bytes"], data["member_size_bits"], data["struct_size_bytes"]),
                         (64, 8, 64, 16))
        self.assertEqual(data["database_cache"], "HIT")
        self.assertNotIn("path", data)
        other = json.loads(ti.ida_type_member_offset(str(self.pe), "UNICODE_STRING", "Buffer"))
        self.assertEqual((other["ok"], other["offset_bytes"]), (True, 8))
        self.assertEqual(self.database_digest(), before)       # a read did not change the cached database

    def test_the_three_negatives_are_separate_answers_and_keep_the_cache(self):
        self.prime()
        before = self.database_digest()
        member = json.loads(ti.ida_type_member_offset(str(self.pe), "_LIST_ENTRY", "NoSuchMember"))
        self.assertEqual((member["ok"], member["error"], member["member_names"]), (False, "MEMBER_NOT_FOUND", ["Flink", "Blink"]))
        self.assertEqual(json.loads(ti.ida_type_member_offset(str(self.pe), "NoSuchTypeAnywhere", "x"))["error"], "TYPE_NOT_FOUND")
        self.assertEqual(json.loads(ti.ida_type_member_offset(str(self.pe), "DWORD", "x"))["error"], "TYPE_NOT_STRUCT_OR_UNION")
        self.assertEqual(self.database_digest(), before)

    def test_a_plan_changes_nothing_in_the_database_and_names_the_bytes(self):
        self.prime()
        before = self.database_digest()
        branch = json.loads(ti.ida_patch_plan(str(self.pe), "0x140001002", "force_branch"))
        self.assertTrue(branch["ok"], branch)
        self.assertEqual((branch["original_bytes"], branch["patched_bytes"], branch["plan_only"]), ("7403", "eb03", True))
        self.assertEqual((branch["address"]["rva"], branch["address"]["image_base"], branch["address"]["section"]),
                         ("0x1002", "0x140000000", ".text"))
        self.assertEqual(set(branch["address"]), ADDRESS_FIELDS)
        nop = json.loads(ti.ida_patch_plan(str(self.pe), 0x1004, "nop_out", "rva", 2))
        self.assertEqual((nop["original_bytes"], nop["patched_bytes"]), ("ffc090", "909090"))
        for data in (branch, nop):
            integrity = data["signals"]["database_integrity"]
            self.assertIs(integrity["unchanged"], True)
            self.assertEqual(integrity["database_sha256_before"], before)
            self.assertEqual(integrity["database_sha256_after"], before)
        self.assertEqual(self.database_digest(), before)
        # the question after the plan sees the original bytes and the original function
        after = json.loads(ti.ida_patch_plan(str(self.pe), "0x140001002", "force_branch"))
        self.assertEqual(after["original_bytes"], "7403")
        self.assertEqual(json.loads(ti.ida_query(str(self.pe), "list_functions"))["items"][0]["name"], "start")
        self.assertEqual(self.database_digest(), before)

    def test_a_plan_over_the_wrong_thing_is_a_named_refusal_and_the_database_is_still_unchanged(self):
        self.prime()
        before = self.database_digest()
        not_branch = json.loads(ti.ida_patch_plan(str(self.pe), "0x140001000", "force_branch"))
        self.assertEqual((not_branch["ok"], not_branch["status"]), (False, "NOT_A_CONDITIONAL_BRANCH"))
        outside = json.loads(ti.ida_patch_plan(str(self.pe), "0x5000000", "nop_out"))
        self.assertEqual(outside["status"], "ADDRESS_OUTSIDE_SECTION")
        too_many = json.loads(ti.ida_patch_plan(str(self.pe), "0x140001000", "nop_out", "va", 60))
        self.assertEqual((too_many["status"], too_many["requested"]), ("NOT_ENOUGH_INSTRUCTIONS_IN_WINDOW", 60))
        self.assertEqual(self.database_digest(), before)

    def test_the_annotation_reader_reads_a_log_without_starting_idat(self):
        self.prime()
        before = self.database_digest()
        sha = ti._sha256_md5(self.pe)[0]
        log = ti._journal_path(sha)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps({"operation": "rename", "ok": True}) + "\n" + "{torn", encoding="utf-8")
        with mock.patch.object(ti, "run_bounded_process", side_effect=AssertionError("idat must not be started")):
            data = json.loads(ti.ida_annotations(str(self.pe)))
        self.assertEqual((data["ok"], data["status"], data["total_entries"], data["unreadable_lines"]), (True, "PARTIAL", 1, 1))
        self.assertEqual(self.database_digest(), before)
        slots = [p for p in ti._cache_root().iterdir() if p.is_dir() and ti._SLOT_NAME.match(p.name)]
        self.assertEqual(len(slots), 1)                         # the log file is not mistaken for a cache slot


if __name__ == "__main__":
    unittest.main()
