"""`liebert_re.tools.ida`: the annotation write path -- `ida_rename_plan` and `ida_annotations_apply`.

Fast tier: nothing here starts IDA. `AnnotateFakeIdat` stands in for `idat.exe` at the process boundary and
keeps a database as a small JSON document (names plus the annotation marker), so a write that did not
persist, a marker that did not travel and a read-back from another process are all things the tests can
make true or false. Every case writes under the repository's scratch helper (`tests/_scratch`), never an
OS temp directory, and leaves the real `safe_path` in force.

What the cases pin (the numbering is the design's):

* Z1 -- the annotated root is its own tree, beside the cache and never inside it, with its own locks. The
  cache's eviction, a whole-cache wipe and a tiny cache budget leave the annotated files byte-identical, and
  the source of the annotated section is read to prove it never calls the eviction helper or a recursive
  delete on a cache path.
* Z2 -- the candidate is held in its own recovery directory and survives a failed promotion; the file is
  synced before the move.
* Z3 -- a write is not published until a SEPARATE engine process has read the stored version back (names
  and the marker stored inside the database); the save call's return value is checked.
* Z4 -- the plan reads the annotated version (through a throwaway copy) and checks the marker against the
  manifest; the operation carries its own read path.
* Z5 -- versions are immutable files and one manifest pointer publishes them.
* Z6 -- concurrent writers are blocked, not merged, and every answer says so.
* Plan/apply are two names; apply cannot be called without a plan; the digest, the base version and every
  item's expectation are checked; atomic is the default.
* The audit journal is append-only JSON lines, written with a sync before the promotion; a crash between
  its records is recovered from the files; a journal that cannot be written is never hidden.

Only `AnnotateRealInstallTests` needs a licensed IDA; it is marked heavy at class level.
"""
from __future__ import annotations

import ast
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
from tests._scratch import process_scratch
from tests.test_tools_ida import CLEAN_LOG, SUMMARY, _cp, _result

JOB_ENV = "LIEBERT_IDA_JOB"
WORKER = Path(ti._ANNOTATE_WORKER_SOURCE)
TARGET_NAME = "ZZ_secret_target_name"
START = "0x140001000"
LATER = "0x140001004"


class AnnotateFakeIdat:
    """`idat.exe` at the process boundary, with a database that is a JSON document.

    `apply`: ok / save_false (the engine reports the save did not happen) / no_persist (it reports success
    but the names never reach the file). `verify`: ok / same_pid (the "other process" is the writer) /
    wrong_marker. `timeout_on` names an operation whose launch is cut off.
    """

    def __init__(self, sha256, md5):
        self.sha256, self.md5 = sha256, md5
        self.calls = []
        self.apply = "ok"
        self.verify = "ok"
        self.timeout_on = None
        self.pid = 4000
        self.pristine = {START: "start"}
        self.comments = {}      # (address, comment_kind) -> text the database holds

    def state(self, db):
        try:
            data = json.loads(Path(db).read_bytes().decode("utf-8").strip())
            return data if isinstance(data, dict) and "names" in data else None
        except (ValueError, OSError):
            return {"names": dict(self.pristine), "marker": None}

    def store(self, db, state):
        Path(db).write_bytes((json.dumps(state) + " " * 64).encode("utf-8"))

    def __call__(self, command, *, timeout_seconds, cancellation_token=None, cwd=None, environment=None,
                 max_output_chars=None):
        job = json.loads(Path(environment[JOB_ENV]).read_text(encoding="utf-8"))
        work = Path(cwd)
        self.calls.append({"job": job, "timeout": timeout_seconds, "cwd": work, "command": list(command)})
        operation = job["operation"]
        if self.timeout_on == operation:
            return _cp(None, timed_out=True)
        (work / ti._LOG_NAME).write_text(CLEAN_LOG, encoding="utf-8")
        db = work / ti._DB_NAME
        if job["mode"] == "create":
            db.write_bytes(b"IDA-DB" * 100)
            body = _result("summary", self.sha256, self.md5, **SUMMARY)
        else:
            body = self.rename(job, db) if operation.startswith("rename_") or operation == "comment_plan" else _result(
                operation, self.sha256, self.md5, **SUMMARY)
            body.setdefault("engine_input_sha256", self.sha256)
            body.setdefault("engine_input_md5", self.md5)
            body["script_completed"] = True
        (work / ti._RESULT_NAME).write_text(json.dumps(body), encoding="utf-8")
        return _cp(0)

    def rename(self, job, db):
        self.pid += 1
        body = {"ok": True, "tool": "ida_annotations", "operation": job["operation"], "engine_pid": self.pid,
                "engine_input_sha256": self.sha256, "engine_input_md5": self.md5}
        state = self.state(db) or {"names": {}, "marker": None}
        names = state["names"]
        items = job["items"]
        if job["operation"] == "comment_plan":
            body["database_changes_discarded"] = True
            body["plan_items"] = [{"index": i, "address": {"va": it["address"], "rva": "0x1000", "file_offset": "0x200",
                                                           "image_base": "0x140000000", "section": ".text"},
                                   "comment_kind": it["comment_kind"],
                                   "expect_comment": self.comments.get((it["address"], it["comment_kind"]))}
                                  for i, it in enumerate(items)]
            body["annotation_marker"] = state["marker"]
        elif job["operation"] == "rename_plan":
            body["database_changes_discarded"] = True
            body["plan_items"] = [{"index": i, "address": {"va": it["address"], "rva": "0x1000", "file_offset": "0x200",
                                                           "image_base": "0x140000000", "section": ".text"},
                                   "old_name": names.get(it["address"], ""), "new_name": it["new_name"]}
                                  for i, it in enumerate(items)]
            body["annotation_marker"] = state["marker"]
        elif job["operation"] == "rename_verify":
            body["database_changes_discarded"] = True
            if self.verify == "same_pid":
                body["engine_pid"] = self.pid - 1
            body["verified_items"] = [{"index": i, "address": it["address"], "actual_name": names.get(it["address"], "")}
                                      for i, it in enumerate(items)]
            marker = state["marker"]
            if self.verify == "wrong_marker" and marker:
                marker = dict(marker, version=marker["version"] + 7)
            body["annotation_marker"] = marker
        else:
            body["database_changes_discarded"] = False
            partial = job["allow_partial"]
            failed = [{"index": i, "error": "PRECONDITION_FAILED"} for i, it in enumerate(items)
                      if names.get(it["address"], "") != it["expect_name"]]
            if failed and not partial:
                body.update(ok=False, error="ABORTED_ATOMIC", applied=[], failed=failed, saved=False)
                return body
            applied = [{"index": i, "address": it["address"], "old_name": it["expect_name"], "new_name": it["new_name"]}
                       for i, it in enumerate(items) if i not in {f["index"] for f in failed}]
            body.update(applied=applied, failed=failed, atomic=not partial)
            if not applied:
                body.update(ok=False, error="ALL_FAILED", saved=False)
                return body
            if self.apply == "save_false":
                body.update(ok=False, error="SAVE_NOT_CONFIRMED", save_returned=False, marker_stored=True, saved=False)
                return body
            if self.apply != "no_persist":
                for item in applied:
                    names[item["address"]] = item["new_name"]
                state["marker"] = job["marker"]
                self.store(db, {"names": names, "marker": state["marker"]})
            else:
                self.store(db, {"names": names, "marker": None})
            body.update(save_returned=True, marker_stored=True, saved=True)
        return body


class AnnotateCase(unittest.TestCase):
    """A stand-in input, private cache / annotated / evidence trees under the repository scratch directory."""

    def setUp(self):
        # Short names on purpose: Windows' 260-character path limit applies below the annotated root.
        self.root = process_scratch("an_" + hashlib.sha256(self.id().encode()).hexdigest()[:5])
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.sample = self.root / f"{TARGET_NAME}.exe"
        self.sample.write_bytes(b"MZ" + bytes(range(64)))
        self.sha, self.md5 = ti._sha256_md5(self.sample)
        self.cache, self.annotated, self.ev = self.root / "c", self.root / "a", self.root / "e"
        self.fake = AnnotateFakeIdat(self.sha, self.md5)
        stack = ExitStack()
        self.addCleanup(stack.close)
        for target in (
            mock.patch.object(ti, "CACHE_ROOT", self.cache),
            mock.patch.object(ti, "ANNOTATED_ROOT", self.annotated),
            mock.patch.object(ti, "EVIDENCE", self.ev),
            mock.patch.object(ti, "EVIDENCE_RENAME_PLAN", self.ev),
            mock.patch.object(ti, "EVIDENCE_ANNOTATE_APPLY", self.ev),
            mock.patch.object(ti, "EVIDENCE_ANNOTATIONS", self.ev),
            mock.patch.object(ti, "_ida_binary", return_value="C:/fake/idat.exe"),
            mock.patch.object(ti, "_evidence_index_record_write", return_value={"ok": True}),
            mock.patch.object(ti, "run_bounded_process", side_effect=self.fake),
        ):
            stack.enter_context(target)

    # -- helpers ----------------------------------------------------------------------------------
    def plan(self, renames=None, label="first-pass", path=None, **kwargs):
        renames = renames if renames is not None else [{"address": START, "new_name": "liebert_start"}]
        return json.loads(ti.ida_rename_plan(str(path or self.sample), label, renames, **kwargs))

    @staticmethod
    def sealed(answer):
        return dict(answer["plan"], plan_sha256=answer["plan_sha256"])

    def apply(self, plan, path=None, **kwargs):
        return json.loads(ti.ida_annotations_apply(str(path or self.sample), plan, **kwargs))

    def write(self, renames=None, label="first-pass", **kwargs):
        answer = self.plan(renames, label)
        self.assertTrue(answer["ok"], answer)
        return self.apply(self.sealed(answer), **kwargs)

    def label_dir(self, label="first-pass"):
        return ti._label_dir(self.sha, label)

    def manifest(self, label="first-pass"):
        return ti._manifest_read(self.label_dir(label))[0]

    def events(self):
        return [r["event"] for r in ti._journal_records(self.sha)[0]]

    def snapshot(self, root=None):
        root = Path(root or self.annotated)
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.rglob("*")) if p.is_file() and not p.name.endswith(".lock")}

    def assertNoTargetLeak(self, text):
        self.assertNotIn(TARGET_NAME, text)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(str(self.root).replace("\\", "/"), text)


# ---------------------------------------------------------------------------
# the happy path, and what it leaves behind
# ---------------------------------------------------------------------------
class RoundTripTests(AnnotateCase):
    def test_plan_then_apply_publishes_a_version_that_a_separate_process_read_back(self):
        plan = self.plan([{"address": START, "new_name": "liebert_start"}, {"address": LATER, "new_name": "after_check"}])
        self.assertEqual((plan["ok"], plan["status"], plan["plan"]["base_version"]), (True, "OK", 0))
        self.assertEqual([i["expect_name"] for i in plan["plan"]["items"]], ["start", ""])
        out = self.apply(self.sealed(plan))
        self.assertEqual((out["ok"], out["status"], out["version"], out["applied_count"], out["failed_count"]),
                         (True, "OK", 1, 2, 0))
        verification = out["verification"]
        self.assertEqual((verification["separate_process"], verification["names_matched"], verification["marker_matched"]),
                         (True, 2, True))
        self.assertEqual(len({verification["write_session_pid"], verification["verify_session_pid"],
                              verification["harness_pid"]}), 3, "three different processes")
        manifest = self.manifest()
        self.assertEqual((manifest["version"], manifest["db_sha256"]), (1, out["db_sha256"]))
        self.assertEqual(manifest["db_sha256"], ti._file_sha256(ti._version_file(self.label_dir(), 1))[0])
        self.assertEqual(self.events(), ["batch_prepared", "batch_committed"])
        self.assertEqual(out["journal"], {"prepared": True, "committed": True})

    def test_the_next_plan_reads_the_annotated_version_and_binds_to_it(self):
        self.write()
        again = self.plan([{"address": START, "new_name": "second_name"}])
        self.assertEqual(again["plan"]["base_version"], 1)
        self.assertEqual(again["plan"]["items"][0]["expect_name"], "liebert_start")
        self.assertEqual(again["annotated_view"], {"state": "verified", "version": 1,
                                                   "read_from": "published annotation version", "marker_checked": True})
        self.assertEqual(again["plan"]["base_db_sha256"], self.manifest()["db_sha256"])

    def test_versions_are_immutable_and_the_pointer_moves(self):
        first = self.write()
        v1 = ti._version_file(self.label_dir(), 1)
        before = ti._file_sha256(v1)[0]
        second = self.write([{"address": START, "new_name": "second_name"}])
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(ti._file_sha256(v1)[0], before, "an earlier version is never rewritten")
        self.assertEqual(self.manifest()["version"], 2)
        self.assertEqual(self.events(), ["batch_prepared", "batch_committed"] * 2)

    def test_labels_are_separate_scopes_of_one_input(self):
        self.write(label="alpha")
        self.write([{"address": START, "new_name": "other_name"}], label="beta")
        self.assertEqual((self.manifest("alpha")["version"], self.manifest("beta")["version"]), (1, 1))
        self.assertNotEqual(self.label_dir("alpha"), self.label_dir("beta"))
        self.assertEqual(self.plan(label="beta")["plan"]["items"][0]["expect_name"], "other_name")

    def test_the_candidate_is_gone_after_a_good_write_and_no_scratch_is_left(self):
        self.write()
        self.assertEqual(list((self.label_dir() / "recovery").glob("*")), [])
        self.assertEqual(list(self.label_dir().glob("scratch-*")), [])

    def test_the_target_name_and_path_are_nowhere_in_answers_journal_or_evidence(self):
        plan = self.plan()
        out = self.apply(self.sealed(plan))
        for text in (json.dumps(plan), json.dumps(out), ti._journal_path(self.sha).read_text(encoding="utf-8")):
            self.assertNoTargetLeak(text)
        for evidence in self.ev.glob("*.json"):
            self.assertNoTargetLeak(evidence.read_text(encoding="utf-8"))
            self.assertNotIn(TARGET_NAME, evidence.name)
        self.assertNotIn("path", plan)

    def test_the_apply_session_is_not_temporary_and_the_read_sessions_are(self):
        self.write()
        modes = [(c["job"]["operation"], c["job"]["mode"]) for c in self.fake.calls if c["job"]["operation"].startswith("rename_")]
        self.assertEqual(modes, [("rename_plan", "reopen"), ("rename_apply", "write"), ("rename_verify", "reopen")])
        self.assertTrue(all(c["command"][-1].endswith("db.i64") for c in self.fake.calls
                            if c["job"]["operation"].startswith("rename_")),
                        "the write worker is only ever launched over a database copy")

    def test_the_first_apply_builds_the_pristine_analysis_and_never_writes_it(self):
        self.write()
        pristine = list(self.cache.glob("*.p0v1.*/db.i64"))
        self.assertEqual(len(pristine), 1)
        self.assertEqual(pristine[0].read_bytes(), b"IDA-DB" * 100, "the cached pristine database is untouched")

    def test_the_session_ceiling_is_its_own_constant_and_applies_to_each_session(self):
        self.write(timeout_seconds=600)
        sessions = [c["timeout"] for c in self.fake.calls if c["job"]["operation"].startswith("rename_")]
        self.assertTrue(all(t <= ti._MAX_ANNOTATE_TIMEOUT_SECONDS for t in sessions), sessions)

    def test_the_reader_reads_the_journal_the_writer_wrote(self):
        self.write()
        data = json.loads(ti.ida_annotations(str(self.sample)))
        self.assertEqual((data["ok"], data["status"], data["found"], data["total_entries"], data["unreadable_lines"]),
                         (True, "OK", True, 2, 0))
        self.assertEqual([e["event"] for e in data["entries"]], ["batch_prepared", "batch_committed"])
        prepared = data["entries"][0]
        for key in ("ts", "write_id", "label", "version", "candidate_db_sha256", "prior_db_sha256", "plan_sha256",
                    "record_sha256"):
            self.assertIn(key, prepared)
        self.assertEqual(data["entries"][1]["items"], [{"index": 0, "address": START, "old_name": "start",
                                                        "new_name": "liebert_start"}])
        self.assertNoTargetLeak(json.dumps(data))

    def test_every_journal_record_hashes_to_its_own_digest(self):
        self.write()
        for record in ti._journal_records(self.sha)[0]:
            body = {k: v for k, v in record.items() if k != "record_sha256"}
            self.assertEqual(ti._sha256_text(ti._canonical(body)), record["record_sha256"])


# ---------------------------------------------------------------------------
# plan / apply as two operations
# ---------------------------------------------------------------------------
class PlanApplyContractTests(AnnotateCase):
    @pytest.mark.contract
    def test_apply_cannot_be_called_without_a_plan(self):
        out = json.loads(ti.ida_annotations_apply(str(self.sample)))
        self.assertEqual((out["ok"], out["status"], out["error"], out["field"], out["fixable"]),
                         (False, "INVALID_PLAN", "PLAN_REQUIRED", "plan", True))
        self.assertIn("ida_rename_plan", out["fix"])
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_the_two_are_separate_names_and_there_is_no_dry_run_flag(self):
        import inspect
        self.assertIn("ida_rename_plan", tool_families.published_tools("native"))
        self.assertIn("ida_annotations_apply", tool_families.published_tools("native"))
        self.assertNotIn("ida_rename", tool_families.published_tools("native"))
        for fn in (ti.ida_rename_plan, ti.ida_annotations_apply):
            self.assertNotIn("dry_run", inspect.signature(fn).parameters)
        self.assertEqual(inspect.signature(ti.ida_annotations_apply).parameters["allow_partial"].default, False)

    @pytest.mark.contract
    def test_a_malformed_plan_is_a_named_refusal_with_the_field_and_fixability(self):
        good = self.sealed(self.plan())
        cases = [
            ("not an object", ["x"], "PLAN_NOT_AN_OBJECT"),
            ("missing digest", {k: v for k, v in good.items() if k != "plan_sha256"}, "PLAN_FIELD_MISSING_OR_WRONG_TYPE"),
            ("wrong schema", dict(good, schema=9), "PLAN_SCHEMA_UNSUPPORTED"),
            ("bad label", dict(good, label="no good"), "PLAN_FIELD_INVALID"),
            ("empty items", dict(good, items=[]), "PLAN_ITEMS_OUT_OF_RANGE"),
            ("item with extra key", dict(good, items=[dict(good["items"][0], extra=1)]), "PLAN_ITEM_MALFORMED"),
            ("item with bad name", dict(good, items=[dict(good["items"][0], new_name="bad name")]), "PLAN_ITEM_MALFORMED"),
        ]
        for label, plan, error in cases:
            with self.subTest(label):
                out = self.apply(plan)
                self.assertEqual((out["ok"], out["status"], out["error"], out["fixable"]), (False, "INVALID_PLAN", error, True))
        self.assertEqual(self.apply("{not json")["error"], "PLAN_NOT_JSON")
        self.assertEqual([c for c in self.fake.calls if c["job"]["operation"] == "rename_apply"], [])
        self.assertFalse(self.annotated.exists() and any(self.annotated.rglob("manifest.json")))

    @pytest.mark.contract
    def test_a_plan_whose_digest_does_not_match_is_refused(self):
        plan = self.sealed(self.plan())
        plan["items"][0]["new_name"] = "something_else"
        out = self.apply(plan)
        self.assertEqual((out["status"], out["error"], out["field"]), ("INVALID_PLAN", "PLAN_HASH_MISMATCH", "plan_sha256"))
        self.assertIn("not a signature", out["fix"])

    def test_the_whole_plan_answer_is_also_accepted_as_the_plan(self):
        self.assertEqual(self.apply(self.plan())["status"], "OK")

    @pytest.mark.contract
    def test_a_plan_for_other_input_content_is_refused(self):
        plan = self.sealed(self.plan())
        other = self.root / "other.exe"
        other.write_bytes(b"MZ" + b"\x01" * 40)
        out = self.apply(plan, path=other)
        self.assertEqual((out["status"], out["error"]), ("INVALID_PLAN", "PLAN_TARGET_MISMATCH"))

    @pytest.mark.contract
    def test_the_label_is_required_explicit_and_exact(self):
        for value in (None, "", "x" * 49, "has space", "a/b", "tail\n", 5):
            with self.subTest(value=value):
                out = self.plan(label=value)
                self.assertEqual((out["ok"], out["error"], out["field"], out["fixable"]), (False, "LABEL_REQUIRED", "label", True))
                self.assertIn("1 to 48", out["fix"])
        self.assertTrue(self.plan(label="a.b_c-1")["ok"])
        self.assertTrue(self.plan(label="x" * 48)["ok"])

    @pytest.mark.contract
    def test_a_bad_rename_list_names_the_item_and_what_is_accepted(self):
        cases = [
            ([], "RENAMES_REQUIRED"),
            ([{"address": START}], "RENAME_ITEM_NAME_INVALID"),
            ([{"new_name": "x"}], "RENAME_ITEM_ADDRESS_INVALID"),
            ([{"address": True, "new_name": "x"}], "RENAME_ITEM_ADDRESS_INVALID"),
            ([{"address": "zz", "new_name": "x"}], "RENAME_ITEM_ADDRESS_INVALID"),
            ([{"address": START, "new_name": "has space"}], "RENAME_ITEM_NAME_INVALID"),
            ([{"address": START, "new_name": "tail\n"}], "RENAME_ITEM_NAME_INVALID"),
            ([{"address": START, "new_name": "x", "address_kind": "ea"}], "INVALID_ADDRESS_KIND"),
            ([{"address": START, "new_name": "x", "comment": "no"}], "RENAME_ITEM_UNKNOWN_FIELD"),
            (["nope"], "RENAME_ITEM_NOT_AN_OBJECT"),
            ([{"address": START, "new_name": "a"}, {"address": START, "new_name": "b"}], "DUPLICATE_ADDRESS"),
            ([{"address": START, "new_name": "a"}, {"address": LATER, "new_name": "a"}], "DUPLICATE_NEW_NAME"),
        ]
        for renames, error in cases:
            with self.subTest(error=error, renames=str(renames)[:40]):
                out = self.plan(renames)
                self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, error, True))
                self.assertIn("accepted", out)
        none = json.loads(ti.ida_rename_plan(str(self.sample), "first-pass", None))
        self.assertEqual((none["error"], none["fixable"]), ("RENAMES_REQUIRED", True))
        self.assertEqual(self.fake.calls, [], "a refusal before the engine starts no session")

    @pytest.mark.contract
    def test_a_list_over_the_limit_is_refused_not_cut(self):
        many = [{"address": 0x140001000 + i, "new_name": f"n{i}"} for i in range(ti._RENAME_MAX_ITEMS + 1)]
        out = self.plan(many)
        self.assertEqual((out["error"], out["fixable"]), ("RENAMES_REQUIRED", True))
        self.assertIn("refused rather than cut", out["fix"])
        full = self.plan(many[:ti._RENAME_MAX_ITEMS])
        self.assertTrue(full["ok"])
        self.assertEqual((len(full["items_detail"]), full["items_listed_complete"]), (ti._RENAME_MAX_ITEMS, True))

    @pytest.mark.contract
    def test_allow_partial_is_exactly_a_boolean(self):
        plan = self.sealed(self.plan())
        for value in ("true", 1, None):
            with self.subTest(value=value):
                out = self.apply(plan, allow_partial=value)
                self.assertEqual((out["error"], out["field"], out["fixable"]), ("INVALID_ALLOW_PARTIAL", "allow_partial", True))
        self.assertEqual([c for c in self.fake.calls if c["job"]["operation"] == "rename_apply"], [])

    @pytest.mark.contract
    def test_a_database_as_input_is_refused_with_the_fix(self):
        db = self.root / "x.i64"
        db.write_bytes(b"x")
        out = self.plan(path=db)
        self.assertEqual((out["error"], out["fixable"]), ("DATABASE_INPUT_NOT_SUPPORTED", True))

    @pytest.mark.contract
    def test_without_idat_both_answer_tool_missing(self):
        sealed = self.sealed(self.plan())
        with mock.patch.object(ti, "_ida_binary", return_value=None):
            self.assertEqual(self.plan()["status"], "TOOL_MISSING")
            self.assertEqual(self.apply(sealed)["status"], "TOOL_MISSING")


# ---------------------------------------------------------------------------
# stale plans, atomic and partial, and the policy for concurrent writers (Z6)
# ---------------------------------------------------------------------------
class PreconditionAndConcurrencyTests(AnnotateCase):
    @pytest.mark.contract
    def test_a_plan_that_lost_the_race_is_blocked_not_merged(self):
        first = self.plan([{"address": START, "new_name": "writer_one"}])
        second = self.plan([{"address": START, "new_name": "writer_two"}])
        won = self.apply(self.sealed(first))
        self.assertEqual(won["status"], "OK")
        before = self.snapshot()
        lost = self.apply(self.sealed(second))
        self.assertEqual((lost["ok"], lost["status"], lost["error"], lost["written"]), (False, "PRECONDITION_FAILED", "STALE_BASE_VERSION", False))
        self.assertEqual((lost["plan_base_version"], lost["published_version"]), (0, 1))
        self.assertEqual(self.snapshot(), before, "nothing was changed by the refused apply")
        self.assertEqual(self.manifest()["version"], 1)

    def test_every_answer_states_the_concurrency_policy(self):
        plan = self.plan()
        out = self.apply(self.sealed(plan))
        for answer in (plan, out):
            policy = answer["concurrency_policy"]
            self.assertEqual((policy["policy"], policy["merges"], policy["lost_updates"]),
                             ("base_version_precondition", False, "blocked"))
            self.assertIn("never merge", policy["summary"])

    @pytest.mark.contract
    def test_an_item_whose_expectation_no_longer_holds_aborts_everything_by_default(self):
        plan = self.plan([{"address": START, "new_name": "liebert_start"}, {"address": LATER, "new_name": "after_check"}])
        sealed = self.sealed(plan)
        sealed["items"][1]["expect_name"] = "was_something_else"
        sealed.pop("plan_sha256")
        sealed["plan_sha256"] = ti._sha256_text(ti._canonical(sealed))
        out = self.apply(sealed)
        self.assertEqual((out["ok"], out["status"], out["error"], out["written"]), (False, "ABORTED_ATOMIC", "ABORTED_ATOMIC", False))
        self.assertEqual(out["failed"][0]["error"], "PRECONDITION_FAILED")
        self.assertIsNone(self.manifest())
        self.assertEqual(self.events(), [], "nothing was prepared: no promotion was ever near")

    def test_allow_partial_applies_what_holds_and_says_what_did_not(self):
        plan = self.plan([{"address": START, "new_name": "liebert_start"}, {"address": LATER, "new_name": "after_check"}])
        sealed = self.sealed(plan)
        sealed["items"][1]["expect_name"] = "was_something_else"
        sealed.pop("plan_sha256")
        sealed["plan_sha256"] = ti._sha256_text(ti._canonical(sealed))
        out = self.apply(sealed, allow_partial=True)
        self.assertEqual((out["ok"], out["status"], out["applied_count"], out["failed_count"], out["atomic"]),
                         (True, "PARTIAL_FAILURE", 1, 1, False))
        self.assertEqual(out["verification"]["names_expected"], 1, "only what was applied is verified")
        self.assertEqual(self.manifest()["version"], 1)

    def test_partial_with_nothing_applicable_is_all_failed_and_publishes_nothing(self):
        sealed = self.sealed(self.plan())
        sealed["items"][0]["expect_name"] = "was_something_else"
        sealed.pop("plan_sha256")
        sealed["plan_sha256"] = ti._sha256_text(ti._canonical(sealed))
        out = self.apply(sealed, allow_partial=True)
        self.assertEqual((out["ok"], out["status"], out["written"]), (False, "ALL_FAILED", False))
        self.assertIsNone(self.manifest())

    def test_the_wrapper_holds_one_lock_per_input_and_reports_busy_with_retry_later(self):
        lock_file = ti._lock_path(self.annotated / self.sha)
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        ti._SlotLock.create(lock_file, "someone-else")
        with mock.patch.object(ti, "_LOCK_WAIT_SECONDS", 0), mock.patch.object(ti, "_LOCK_OWNER_ALIVE_CEILING_SECONDS", 10 ** 9), \
                mock.patch.object(ti, "_LOCK_STALE_SECONDS", 10 ** 9):
            out = self.plan()
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "ANNOTATED_BUSY", "retry_later"))
        self.assertEqual(self.fake.calls, [])


# ---------------------------------------------------------------------------
# Z3: nothing is published until another process has read it back
# ---------------------------------------------------------------------------
class VerificationTests(AnnotateCase):
    @pytest.mark.contract
    def test_a_write_that_did_not_persist_is_not_published(self):
        self.fake.apply = "no_persist"
        out = self.write()
        self.assertEqual((out["ok"], out["status"], out["error"]), (False, "VERIFICATION_FAILED", "VERIFICATION_FAILED"))
        self.assertIsNone(self.manifest(), "no pointer was published")
        self.assertEqual(out["verification"]["names_matched"], 0)
        self.assertEqual(out["version_retained_unpublished"], "v000001")
        self.assertEqual(self.events(), ["batch_prepared", "batch_aborted"])
        self.assertEqual(ti._journal_records(self.sha)[0][-1]["reason"], "verification_failed")
        self.assertEqual(self.plan()["plan"]["base_version"], 0, "the published state is still the pristine analysis")

    @pytest.mark.contract
    def test_a_read_back_by_the_same_process_is_not_a_read_back(self):
        self.fake.verify = "same_pid"
        out = self.write()
        self.assertEqual(out["status"], "VERIFICATION_FAILED")
        self.assertIsNone(self.manifest())

    @pytest.mark.contract
    def test_a_marker_with_the_wrong_annotation_version_is_not_published(self):
        self.fake.verify = "wrong_marker"
        out = self.write()
        self.assertEqual((out["status"], out["verification"]["marker_matched"]), ("VERIFICATION_FAILED", False))
        self.assertIsNone(self.manifest())

    @pytest.mark.contract
    def test_a_save_the_engine_says_did_not_happen_promotes_nothing(self):
        self.fake.apply = "save_false"
        out = self.write()
        self.assertEqual((out["ok"], out["status"], out["error"], out["written"]), (False, "ANALYSIS_LIMITED", "SAVE_NOT_CONFIRMED", False))
        self.assertIsNone(self.manifest())
        self.assertEqual(self.events(), [], "prepared is only written for a candidate the engine confirmed")
        self.assertFalse(list(self.annotated.rglob("versions/*/db.i64")))

    @pytest.mark.contract
    def test_a_timeout_in_the_write_session_publishes_nothing_and_says_so(self):
        self.fake.timeout_on = "rename_apply"
        out = self.write()
        self.assertEqual((out["ok"], out["status"], out["written"]), (False, "TIMEOUT", False))
        self.assertIn("published nothing", out["detail"])
        self.assertIsNone(self.manifest())

    @pytest.mark.contract
    def test_a_timeout_in_the_read_back_leaves_the_version_unpublished(self):
        self.fake.timeout_on = "rename_verify"
        out = self.write()
        self.assertEqual(out["status"], "ANALYSIS_LIMITED")
        self.assertEqual(out["error"], "VERIFICATION_SESSION_FAILED")
        self.assertIsNone(self.manifest())
        self.assertEqual(self.events(), ["batch_prepared", "batch_aborted"])


# ---------------------------------------------------------------------------
# Z2 and the write-ahead journal
# ---------------------------------------------------------------------------
class PromotionAndJournalTests(AnnotateCase):
    @pytest.mark.contract
    def test_a_failed_promotion_keeps_the_candidate_and_the_cleanup_does_not_touch_it(self):
        real = ti._replace_file
        moves = []

        def refuse_the_candidate_move(source, destination):
            moves.append(Path(destination).name)
            return "PermissionError" if Path(source).name == ti._DB_NAME else real(source, destination)

        with mock.patch.object(ti, "_replace_file", side_effect=refuse_the_candidate_move):
            out = self.write()
        self.assertEqual((out["ok"], out["status"], out["error"], out["candidate_retained"], out["fixable"]),
                         (False, "ANNOTATED_PROMOTION_BLOCKED", "PROMOTION_FAILED", True, "retry_later"))
        candidate = self.label_dir() / "recovery" / out["write_id"] / ti._DB_NAME
        self.assertTrue(candidate.is_file())
        self.assertEqual(ti._file_sha256(candidate)[0], out["candidate_sha256"])
        prepared = ti._journal_records(self.sha)[0][0]
        self.assertEqual(prepared["candidate_db_sha256"], out["candidate_sha256"], "journalled before the move")
        self.assertEqual(self.events(), ["batch_prepared", "batch_aborted"])
        self.assertIsNone(self.manifest())
        self.assertFalse(list(self.annotated.rglob("versions/*/db.i64")), "no version file was created")
        # a later, healthy write goes ahead and still does not delete the retained candidate
        again = self.write()
        self.assertEqual(again["status"], "OK")
        self.assertTrue(candidate.is_file(), "a retained candidate is only removed by an explicit operation")

    @pytest.mark.contract
    def test_the_candidate_is_synced_to_disk_before_the_journal_and_the_move(self):
        order = []
        real_sync, real_journal, real_replace = ti._fsync_path, ti._journal_append, ti._replace_file
        with mock.patch.object(ti, "_fsync_path", side_effect=lambda p: (order.append(("sync", Path(p).name)), real_sync(p))[1]), \
                mock.patch.object(ti, "_journal_append",
                                  side_effect=lambda s, r: (order.append(("journal", r["event"])), real_journal(s, r))[1]), \
                mock.patch.object(ti, "_replace_file",
                                  side_effect=lambda a, b: (order.append(("move", Path(a).name)), real_replace(a, b))[1]):
            self.write()
        flat = [f"{kind}:{what}" for kind, what in order]
        self.assertLess(flat.index("sync:db.i64"), flat.index("journal:batch_prepared"))
        self.assertLess(flat.index("journal:batch_prepared"), flat.index("move:db.i64"))
        self.assertLess(flat.index("move:db.i64"), flat.index("journal:batch_committed"))
        self.assertLess(flat.index("sync:" + next(n for k, n in order if k == "sync" and n.endswith(".tmp"))),
                        flat.index("move:" + next(n for k, n in order if k == "move" and n.endswith(".tmp"))))

    @pytest.mark.contract
    def test_a_journal_that_cannot_be_written_blocks_the_write_before_the_promotion(self):
        with mock.patch.object(ti, "_journal_append", return_value=(False, "PermissionError")):
            out = self.write()
        self.assertEqual((out["ok"], out["status"], out["error"], out["fixable"]),
                         (False, "JOURNAL_UNWRITABLE", "PREPARED_RECORD_NOT_WRITTEN", "retry_later"))
        self.assertTrue(out["candidate_retained"])
        self.assertFalse(list(self.annotated.rglob("versions/*/db.i64")))
        self.assertIsNone(self.manifest())

    @pytest.mark.contract
    def test_a_commit_record_that_cannot_be_written_is_flagged_pending_and_recovered_later(self):
        real = ti._journal_append
        with mock.patch.object(ti, "_journal_append",
                               side_effect=lambda s, r: (False, "OSError") if r["event"] == "batch_committed" else real(s, r)):
            out = self.write()
        self.assertEqual((out["ok"], out["status"], out["commit_record_pending"]), (True, "OK", True))
        self.assertEqual(self.events(), ["batch_prepared"])
        self.assertEqual(self.manifest()["version"], 1, "the version is published; only its record is late")
        self.plan()                                    # any operation on the scope first runs the recovery
        records = ti._journal_records(self.sha)[0]
        self.assertEqual([r["event"] for r in records], ["batch_prepared", "batch_committed"])
        self.assertIs(records[-1]["recovered"], True)

    @pytest.mark.contract
    def test_a_crash_before_the_pointer_is_closed_as_an_abort_and_the_published_state_is_untouched(self):
        with mock.patch.object(ti, "_manifest_write", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                self.write()
        self.assertEqual(self.events(), ["batch_prepared"])
        again = self.plan()
        self.assertTrue(again["ok"], again)
        self.assertEqual(again["plan"]["base_version"], 0)
        records = ti._journal_records(self.sha)[0]
        self.assertEqual([r["event"] for r in records], ["batch_prepared", "batch_aborted"])
        self.assertEqual((records[-1]["reason"], records[-1]["retained"], records[-1]["recovered"]),
                         ("interrupted_before_publication", "versions", True))
        # the unpublished version is evidence, never reused: the next write is version 2
        self.assertTrue(ti._version_file(self.label_dir(), 1).is_file())
        self.assertEqual(self.apply(self.sealed(again))["version"], 2)

    @pytest.mark.contract
    def test_a_crash_before_the_promotion_is_closed_with_the_candidate_kept_in_recovery(self):
        with mock.patch.object(ti, "_replace_file", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                self.write()
        self.plan()
        record = ti._journal_records(self.sha)[0][-1]
        self.assertEqual((record["event"], record["reason"], record["retained"]), ("batch_aborted", "interrupted_before_publication", "recovery"))
        self.assertEqual(len(list((self.label_dir() / "recovery").glob("*/db.i64"))), 1)

    @pytest.mark.contract
    def test_a_manifest_that_is_neither_prior_nor_the_prepared_write_makes_the_scope_unverified(self):
        with mock.patch.object(ti, "_manifest_write", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                self.write()
        ti._manifest_write(self.label_dir(), {"schema": 1, "sha256": self.sha, "label": "first-pass", "version": 5,
                                             "write_id": "someone", "db_sha256": "0" * 64, "db_bytes": 1})
        out = self.plan()
        self.assertEqual((out["ok"], out["status"], out["error"], out["fixable"]),
                         (False, "ANALYSIS_LIMITED", "ANNOTATED_STATE_UNVERIFIED", False))
        self.assertIn("reason", out)
        self.assertIn("not repaired automatically", out["fix"])
        self.assertTrue(self.plan(label="elsewhere")["ok"], "another scope of the same input is not affected")

    @pytest.mark.contract
    def test_a_manifest_pointing_at_a_missing_or_altered_version_is_not_served(self):
        self.write()
        version = ti._version_file(self.label_dir(), 1)
        original = version.read_bytes()
        version.write_bytes(original + b"x")
        out = self.plan()
        self.assertEqual((out["error"], out["reason"]), ("ANNOTATED_STATE_UNVERIFIED", "VERSION_FILE_HASH_MISMATCH"))
        version.unlink()
        out = self.plan()
        self.assertEqual(out["error"], "ANNOTATED_STATE_UNVERIFIED")
        self.assertTrue(out["reason"].startswith("VERSION_FILE_UNREADABLE"))
        self.assertEqual([c for c in self.fake.calls if c["job"]["operation"] == "rename_plan"][1:], [],
                         "no session ran over an unconfirmed base")

    @pytest.mark.contract
    def test_a_manifest_that_is_not_a_well_formed_manifest_is_not_absent(self):
        self.write()
        (self.label_dir() / "manifest.json").write_text("{torn", encoding="utf-8")
        self.assertEqual(self.plan()["reason"], "MANIFEST_MALFORMED")
        (self.label_dir() / "manifest.json").write_text(json.dumps(dict(self.manifest() or {}, version=True)), encoding="utf-8")
        self.assertEqual(self.plan()["reason"], "MANIFEST_MALFORMED")

    @pytest.mark.contract
    def test_a_manifest_naming_another_scope_is_not_served(self):
        self.write()
        manifest = json.loads((self.label_dir() / "manifest.json").read_text(encoding="utf-8"))
        manifest["label"] = "First-Pass"     # a case variant: the directory is the same on a case-insensitive disk
        (self.label_dir() / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.plan()["reason"], "MANIFEST_NAMES_ANOTHER_SCOPE")

    @pytest.mark.contract
    def test_the_marker_inside_the_database_must_match_the_manifest(self):
        self.write()
        version = ti._version_file(self.label_dir(), 1)
        state = json.loads(version.read_bytes().decode("utf-8").strip())
        state["marker"]["version"] = 9
        version.write_bytes((json.dumps(state) + " " * 64).encode("utf-8"))
        manifest = self.manifest()
        manifest["db_sha256"] = ti._file_sha256(version)[0]       # the file and the manifest agree; the marker does not
        ti._manifest_write(self.label_dir(), manifest)
        out = self.plan()
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "ANNOTATION_VERSION_MISMATCH", False))
        self.assertEqual((out["manifest_version"], out["marker_version"]), (1, 9))

    @pytest.mark.contract
    def test_a_torn_last_journal_line_does_not_swallow_the_next_record(self):
        path = ti._journal_path(self.sha)
        path.parent.mkdir(parents=True)
        path.write_bytes(b'{"event": "torn"')
        self.assertEqual(ti._journal_append(self.sha, {"event": "x"}), (True, None))
        records, unreadable, error = ti._journal_records(self.sha)
        self.assertEqual((len(records), unreadable, error), (1, 1, None))

    @pytest.mark.contract
    def test_the_journal_is_append_only_and_an_unreadable_one_is_not_empty(self):
        self.write()
        before = ti._journal_path(self.sha).read_bytes()
        self.write([{"address": START, "new_name": "second_name"}])
        after = ti._journal_path(self.sha).read_bytes()
        self.assertTrue(after.startswith(before), "earlier records are never rewritten")
        ti._journal_path(self.sha).unlink()
        ti._journal_path(self.sha).mkdir()                 # a journal that cannot be read
        out = self.plan()
        self.assertEqual((out["ok"], out["error"]), (False, "ANNOTATED_STATE_UNVERIFIED"))
        self.assertTrue(out["reason"].startswith("JOURNAL_UNREADABLE"))


# ---------------------------------------------------------------------------
# the byte budget
# ---------------------------------------------------------------------------
class BudgetTests(AnnotateCase):
    @pytest.mark.contract
    def test_a_full_budget_refuses_the_write_and_says_it_is_not_fixable_by_the_caller(self):
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_ANNOTATED_BYTES": "1"}):
            out = self.write()
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "ANNOTATED_BUDGET_EXHAUSTED", False))
        self.assertIn("LIEBERT_IDA_ANNOTATED_BYTES", out["fix"])
        self.assertEqual(out["budget_bytes"], 1)
        self.assertIsNone(self.manifest())
        self.assertEqual([c for c in self.fake.calls if c["job"]["operation"] == "rename_apply"], [])

    @pytest.mark.contract
    def test_a_budget_that_cannot_be_measured_refuses_instead_of_guessing(self):
        with mock.patch.object(ti, "_annotated_total_bytes", return_value=None):
            out = self.write()
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "ANNOTATED_BUDGET_UNVERIFIABLE", False))
        self.assertIsNone(self.manifest())

    def test_the_total_is_not_a_partial_count_when_an_entry_cannot_be_read(self):
        self.annotated.mkdir(parents=True)
        (self.annotated / "f").write_bytes(b"x" * 10)
        self.assertEqual(ti._annotated_total_bytes(), 10)
        with mock.patch.object(ti.os, "stat", side_effect=OSError("denied")):
            self.assertIsNone(ti._annotated_total_bytes())

    def test_a_root_that_exists_but_cannot_be_looked_at_is_unknown_not_zero(self):
        # os.path.isdir() answers False on any OSError, so this used to read 0 (POSIX isdir goes
        # through os.stat); the mocked stat makes that visible on every platform.
        self.annotated.mkdir(parents=True)
        (self.annotated / "f").write_bytes(b"x" * 10)
        with mock.patch.object(ti.os, "stat", side_effect=PermissionError("denied")),                 mock.patch.object(ti.os.path, "isdir", side_effect=lambda p: False):
            self.assertIsNone(ti._annotated_total_bytes())

    def test_an_absent_root_is_zero(self):
        self.assertFalse(self.annotated.exists())
        self.assertEqual(ti._annotated_total_bytes(), 0)

    def test_the_budget_counts_what_is_held_and_has_its_own_default(self):
        self.assertEqual(ti._ANNOTATED_BUDGET_DEFAULT, 2 * 1024 ** 3)
        self.write()
        self.assertGreater(ti._annotated_total_bytes(), 0)


# ---------------------------------------------------------------------------
# Z1: the annotated data is out of the cache's reach
# ---------------------------------------------------------------------------
def _section_functions():
    """The functions of the annotated section of ida.py, found by the section's own banner comments."""
    source = Path(ti.__file__).read_text(encoding="utf-8")
    lines = source.splitlines()
    start = next(i for i, line in enumerate(lines) if "the annotation write path: ida_rename_plan" in line) + 1
    end = next(i for i, line in enumerate(lines) if i > start and line.strip() == "# ida_status") + 1
    tree = ast.parse(source)
    inside = [n for n in tree.body if isinstance(n, ast.FunctionDef) and start <= n.lineno <= end]
    cache_side = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name in ("_evict_slot", "_enforce_cache_budget", "_cache_summary", "_slot_is_healthy", "_touch_meta",
                                 "_dir_bytes", "_slot_last_used", "_slot_dir", "_run_stage", "_query_locked", "_locked_call",
                                 "ida_status", "_cache_root", "_cache_budget_bytes")]
    return inside, cache_side


def _called_names(node):
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = sub.func
            names.add(fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "")
    return names


def _referenced_names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class CacheSeparationTests(AnnotateCase):
    @pytest.mark.contract
    def test_the_annotated_root_is_a_sibling_of_the_cache_and_not_inside_it(self):
        self.assertTrue(ti._roots_apart())
        real_cache, real_annotated = Path(os.path.realpath(ti.__dict__["APP_DIR"] / "dataset" / "ida_cache")), \
            Path(os.path.realpath(ti.__dict__["APP_DIR"] / "dataset" / "ida_annotated"))
        self.assertNotIn(real_cache, real_annotated.parents)
        self.assertNotIn(real_annotated, real_cache.parents)
        self.assertNotEqual(real_cache, real_annotated)

    @pytest.mark.contract
    def test_an_overlapping_configuration_refuses_every_write_path_operation(self):
        for annotated in (self.cache / "inside", self.cache, self.root):       # inside, equal, containing
            with self.subTest(annotated=annotated.name), mock.patch.object(ti, "ANNOTATED_ROOT", annotated):
                self.assertFalse(ti._roots_apart())
                plan = self.plan()
                self.assertEqual((plan["ok"], plan["error"], plan["fixable"]), (False, "ANNOTATED_ROOT_OVERLAPS_CACHE", False))
                sealed = {"schema": 1, "kind": "rename", "target_sha256": self.sha, "label": "x", "base_version": 0,
                          "base_db_sha256": None, "plan_sha256": "",
                          "items": [{"index": 0, "address": START, "address_kind": "va", "new_name": "n", "expect_name": ""}]}
                sealed["plan_sha256"] = ti._sha256_text(ti._canonical({k: v for k, v in sealed.items() if k != "plan_sha256"}))
                self.assertEqual(self.apply(sealed)["error"], "ANNOTATED_ROOT_OVERLAPS_CACHE")
        self.assertEqual(self.fake.calls, [])

    def test_eviction_a_tiny_cache_budget_and_a_cache_wipe_leave_the_annotated_data_untouched(self):
        self.write()
        before = self.snapshot()
        self.assertTrue(before)
        # 1. a second input pushes the cache over a one-byte budget: the first pristine slot IS evicted
        other = self.root / "other.exe"
        other.write_bytes(b"MZ" + b"\x07" * 50)
        self.fake.sha256, self.fake.md5 = ti._sha256_md5(other)
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "1"}), mock.patch.object(ti, "_EVICT_SKIP_RECENT_SECONDS", 0):
            answer = json.loads(ti.ida_query(str(other), "summary"))
            self.assertTrue(answer["ok"], answer)
            self.assertTrue(answer["cache_evicted_slots"], "the test must really trigger an eviction")
            evicted, _bytes, _budget = ti._enforce_cache_budget(None)
        self.assertEqual(self.snapshot(), before)
        # 2. the whole cache is wiped, the way an operator or a recursive delete would
        shutil.rmtree(self.cache)
        self.assertEqual(self.snapshot(), before)
        # 3. the annotated version is still usable with no pristine analysis anywhere
        self.fake.sha256, self.fake.md5 = self.sha, self.md5
        again = self.plan([{"address": START, "new_name": "after_the_wipe"}])
        self.assertEqual((again["ok"], again["plan"]["base_version"], again["plan"]["items"][0]["expect_name"]),
                         (True, 1, "liebert_start"))
        self.assertFalse(self.cache.exists() and list(self.cache.glob("*.p0v1.*")), "no pristine analysis was needed")

    def test_the_cache_lifecycle_helpers_never_see_an_annotated_path(self):
        self.write()
        slot_like = [p.name for p in self.annotated.iterdir() if ti._SLOT_NAME.match(p.name) and p.is_dir()]
        self.assertEqual(slot_like, [], "nothing under the annotated root looks like a cache slot")
        summary = ti._cache_summary()
        self.assertEqual(summary["slot_count"], 1)
        self.assertLess(summary["total_bytes"], 2000, "the cache's own count does not include the annotated versions")

    def test_the_annotated_section_never_calls_the_eviction_helper_or_a_recursive_delete_on_a_cache_path(self):
        inside, cache_side = _section_functions()
        self.assertGreater(len(inside), 15)
        for fn in inside:
            names = _called_names(fn)
            self.assertNotIn("_evict_slot", names, fn.name)
            if fn.name != "_copy_pristine":
                self.assertNotIn("_enforce_cache_budget", names, fn.name)
                self.assertNotIn("_slot_dir", _referenced_names(fn), fn.name)
            if fn.name not in ("_remove_owned_work", "_purge_remove"):
                self.assertNotIn("rmtree", names, fn.name)
        copy_pristine = next(fn for fn in inside if fn.name == "_copy_pristine")
        self.assertNotIn("rmtree", _called_names(copy_pristine))
        roots = {fn.name for fn in inside if "_cache_root" in _referenced_names(fn)}
        self.assertEqual(roots, {"_roots_apart"}, "the only place the section reads the cache root is the overlap check")

    def test_the_only_recursive_delete_in_the_annotated_section_refuses_anything_it_does_not_own(self):
        self.annotated.mkdir(parents=True)
        victim = self.annotated / self.sha / "abcdef012345" / "versions" / "v000001"
        victim.mkdir(parents=True)
        (victim / "db.i64").write_bytes(b"x")
        for target in (victim, self.annotated, self.annotated / self.sha, victim.parent, self.root, self.cache):
            with self.subTest(target=target.name):
                self.assertFalse(ti._remove_owned_work(target))
        self.assertTrue((victim / "db.i64").exists())
        owned = self.annotated / self.sha / "abcdef012345" / "scratch-1234abcd"
        owned.mkdir(parents=True)
        self.assertTrue(ti._remove_owned_work(owned))
        recovery = self.annotated / self.sha / "abcdef012345" / "recovery" / "w1"
        recovery.mkdir(parents=True)
        self.assertTrue(ti._remove_owned_work(recovery))

    def test_the_cache_lifecycle_code_never_mentions_the_annotated_root(self):
        _inside, cache_side = _section_functions()
        for fn in cache_side:
            self.assertNotIn("ANNOTATED_ROOT", _referenced_names(fn), fn.name)
            self.assertNotIn("_annotated_root", _called_names(fn), fn.name)
            self.assertNotIn("_journal_path", _called_names(fn), fn.name)

    def test_the_locks_of_the_two_trees_are_different_files(self):
        seen = []
        real = ti._acquire_slot_lock
        with mock.patch.object(ti, "_acquire_slot_lock", side_effect=lambda slot, token: (seen.append(Path(slot)), real(slot, token))[1]):
            self.write()
        annotated_locks = [p for p in seen if self.annotated in p.parents]
        cache_locks = [p for p in seen if self.cache in p.parents]
        self.assertTrue(annotated_locks and cache_locks, seen)
        self.assertEqual(sorted({p.name for p in annotated_locks}), sorted({self.sha, "annotated-budget"}))
        for lock in annotated_locks:
            self.assertEqual(ti._lock_path(lock).parent, self.annotated)
        self.assertTrue(all(ti._lock_path(p).parent == self.cache for p in cache_locks))


# ---------------------------------------------------------------------------
# the comment plan: ida_set_comments_plan (plan only; apply is a later slice)
# ---------------------------------------------------------------------------
SECRET_TEXT = "ZZ_comment_text_must_not_reach_a_log"


class CommentPlanTests(AnnotateCase):
    def cplan(self, comments=None, label="first-pass", **kwargs):
        comments = comments if comments is not None else [
            {"address": START, "comment": SECRET_TEXT, "comment_kind": "regular"}]
        return json.loads(ti.ida_set_comments_plan(str(self.sample), label, comments, **kwargs))

    @pytest.mark.contract
    def test_the_answer_has_exactly_the_keys_of_the_rename_plan(self):
        out = self.cplan()
        rename = self.plan()
        self.assertTrue(out["ok"], out)
        self.assertEqual(set(out), set(rename))
        self.assertEqual(set(out["plan"]), set(rename["plan"]))
        self.assertEqual((out["plan"]["kind"], out["plan"]["schema"], out["plan"]["base_version"]), ("comments", 1, 0))
        self.assertEqual(out["plan"]["items"], [{"index": 0, "address": START, "address_kind": "va",
                                                 "comment": SECRET_TEXT, "comment_kind": "regular",
                                                 "expect_comment": None}])
        self.assertIs(out["items_listed_complete"], True)

    @pytest.mark.contract
    def test_signature_mirrors_the_rename_plan(self):
        import inspect
        mine = inspect.signature(ti.ida_set_comments_plan).parameters
        theirs = inspect.signature(ti.ida_rename_plan).parameters
        self.assertEqual(list(mine), ["path", "label", "comments", "timeout_seconds", "cancellation_token"])
        for name in ("label", "timeout_seconds", "cancellation_token"):
            self.assertEqual(mine[name].default, theirs[name].default)
        self.assertIn("ida_set_comments_plan", tool_families.published_tools("native"))
        self.assertNotIn("ida_set_comments", tool_families.published_tools("native"))

    @pytest.mark.contract
    def test_a_bad_item_names_the_item_and_what_is_accepted(self):
        cases = [
            ([], "COMMENTS_REQUIRED"),
            (["nope"], "COMMENT_ITEM_NOT_AN_OBJECT"),
            ([{"address": START, "comment": "x", "comment_kind": "regular", "new_name": "n"}], "COMMENT_ITEM_UNKNOWN_FIELD"),
            ([{"comment": "x", "comment_kind": "regular"}], "COMMENT_ITEM_ADDRESS_INVALID"),
            ([{"address": True, "comment": "x", "comment_kind": "regular"}], "COMMENT_ITEM_ADDRESS_INVALID"),
            ([{"address": "zz", "comment": "x", "comment_kind": "regular"}], "COMMENT_ITEM_ADDRESS_INVALID"),
            ([{"address": START, "comment": 5, "comment_kind": "regular"}], "COMMENT_ITEM_COMMENT_INVALID"),
            ([{"address": START, "comment": "a\x00b", "comment_kind": "regular"}], "COMMENT_ITEM_COMMENT_INVALID"),
            ([{"address": START, "comment": "x", "comment_kind": "regular", "address_kind": "ea"}], "INVALID_ADDRESS_KIND"),
        ]
        for comments, error in cases:
            with self.subTest(error=error, comments=str(comments)[:40]):
                out = self.cplan(comments)
                self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, error, True))
                self.assertIn("accepted", out)
        none = json.loads(ti.ida_set_comments_plan(str(self.sample), "first-pass", None))
        self.assertEqual((none["error"], none["fixable"]), ("COMMENTS_REQUIRED", True))
        self.assertEqual(self.fake.calls, [], "a refusal before the engine starts no session")

    @pytest.mark.contract
    def test_the_label_rule_is_the_rename_plans(self):
        for label in (None, "", "has space", "x" * 49):
            with self.subTest(label=label):
                out = self.cplan(label=label)
                self.assertEqual((out["ok"], out["error"], out["fixable"], out["field"]), (False, "LABEL_REQUIRED", True, "label"))
        self.assertEqual(self.fake.calls, [])

    @pytest.mark.contract
    def test_the_item_ceiling_is_refused_not_cut(self):
        many = [{"address": hex(0x140001000 + i), "comment": "c", "comment_kind": "regular"} for i in range(201)]
        out = self.cplan(many)
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "COMMENTS_REQUIRED", True))
        ok = self.cplan(many[:200])
        self.assertEqual((ok["ok"], ok["item_count"], len(ok["plan"]["items"])), (True, 200, 200))

    @pytest.mark.contract
    def test_an_empty_or_too_long_comment_is_refused(self):
        for text, error in (("", "COMMENT_ITEM_COMMENT_EMPTY"), ("   \n", "COMMENT_ITEM_COMMENT_EMPTY"),
                            ("x" * (ti._COMMENT_MAX_CHARS + 1), "COMMENT_ITEM_COMMENT_TOO_LONG")):
            with self.subTest(error=error, length=len(text)):
                out = self.cplan([{"address": START, "comment": text, "comment_kind": "regular"}])
                self.assertEqual((out["ok"], out["error"], out["item_index"]), (False, error, 0))
                self.assertNotIn("xxxxxxxx", json.dumps(out), "a refusal never echoes the text")
        edge = self.cplan([{"address": START, "comment": "x" * ti._COMMENT_MAX_CHARS, "comment_kind": "regular"}])
        self.assertTrue(edge["ok"], edge)

    @pytest.mark.contract
    def test_a_duplicate_address_is_refused(self):
        two = [{"address": START, "comment": "a", "comment_kind": "regular"},
               {"address": 0x140001000, "comment": "b", "comment_kind": "repeatable"}]
        out = self.cplan(two)
        self.assertEqual((out["ok"], out["error"], out["item_index"]), (False, "DUPLICATE_ADDRESS", 1))

    @pytest.mark.contract
    def test_only_regular_and_repeatable_are_accepted_and_nothing_is_defaulted(self):
        for kind in ("decompiler", "pseudocode", "anterior", "", None, 1, "Regular"):
            with self.subTest(kind=kind):
                out = self.cplan([{"address": START, "comment": "x", "comment_kind": kind}])
                self.assertEqual((out["ok"], out["error"], out["fixable"], out["accepted"]),
                                 (False, "UNSUPPORTED_COMMENT_KIND", True, ["regular", "repeatable"]))
        missing = self.cplan([{"address": START, "comment": "x"}])
        self.assertEqual(missing["error"], "UNSUPPORTED_COMMENT_KIND", "the kind is required, never defaulted")
        self.assertEqual(self.fake.calls, [], "an unsupported kind never reaches the engine")
        for kind in ("regular", "repeatable"):
            self.assertTrue(self.cplan([{"address": START, "comment": "x", "comment_kind": kind}])["ok"])

    @pytest.mark.contract
    def test_text_that_redaction_would_change_is_refused_not_altered(self):
        out = self.cplan([{"address": START, "comment": "see C:\\Users\\someone\\file", "comment_kind": "regular"}])
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "COMMENT_TEXT_NEEDS_REDACTION", True))
        self.assertNotIn("someone", json.dumps(out))

    @pytest.mark.contract
    def test_the_plan_digest_is_stable_and_binds_the_comment(self):
        a = self.cplan()
        b = self.cplan()
        self.assertEqual(a["plan_sha256"], b["plan_sha256"])
        self.assertEqual(a["plan_sha256"], ti._sha256_text(ti._canonical(a["plan"])))
        changed = self.cplan([{"address": START, "comment": SECRET_TEXT + "!", "comment_kind": "regular"}])
        self.assertNotEqual(a["plan_sha256"], changed["plan_sha256"])
        other_kind = self.cplan([{"address": START, "comment": SECRET_TEXT, "comment_kind": "repeatable"}])
        self.assertNotEqual(a["plan_sha256"], other_kind["plan_sha256"])
        self.assertNotEqual(a["plan_sha256"], self.plan()["plan_sha256"])

    @pytest.mark.contract
    def test_the_existing_comment_of_that_kind_is_read_as_the_expectation(self):
        self.fake.comments[(START, "regular")] = "old note"
        regular = self.cplan([{"address": START, "comment": "new note", "comment_kind": "regular"}])
        repeatable = self.cplan([{"address": START, "comment": "new note", "comment_kind": "repeatable"}])
        self.assertEqual(regular["plan"]["items"][0]["expect_comment"], "old note")
        self.assertIsNone(repeatable["plan"]["items"][0]["expect_comment"], "absent stays None, not an empty string")
        job = self.fake.calls[-1]["job"]
        self.assertEqual((job["operation"], job["mode"], job["write_mode"]), ("comment_plan", "reopen", "plan"))

    @pytest.mark.contract
    def test_the_plan_reads_the_published_version_like_the_rename_plan(self):
        self.write()
        again = self.cplan()
        self.assertEqual(again["plan"]["base_version"], 1)
        self.assertEqual(again["annotated_view"]["read_from"], "published annotation version")
        self.assertEqual(again["plan"]["base_db_sha256"], self.manifest()["db_sha256"])

    @pytest.mark.contract
    def test_comment_text_is_not_written_to_any_log_only_hash_and_length(self):
        out = self.cplan()
        self.assertTrue(out["ok"], out)
        text_hash = ti._sha256_text(SECRET_TEXT)
        detail = out["items_detail"][0]
        self.assertEqual((detail["comment_sha256"], detail["comment_length"]), (text_hash, len(SECRET_TEXT)))
        self.assertNotIn(SECRET_TEXT, json.dumps(out["items_detail"]))
        evidence = list(self.ev.glob("*_comment_plan.json"))
        self.assertEqual(len(evidence), 1)
        raw = evidence[0].read_text(encoding="utf-8")
        self.assertNotIn(SECRET_TEXT, raw)
        self.assertIn(text_hash, raw)
        self.assertIn(str(len(SECRET_TEXT)), raw)
        self.assertEqual(out["internal_evidence_name"], evidence[0].name)
        # the audit journal is not touched by a plan, and no log-like file under any root holds the text
        self.assertEqual(ti._journal_records(self.sha)[0], [])
        for root in (self.annotated, self.ev, self.cache):
            if not Path(root).exists():
                continue
            for f in Path(root).rglob("*"):
                if f.is_file() and f.suffix in (".json", ".jsonl", ".log"):
                    self.assertNotIn(SECRET_TEXT, f.read_text(encoding="utf-8", errors="ignore"), f.name)

    @pytest.mark.contract
    def test_nothing_is_published_by_a_plan(self):
        before = self.snapshot() if self.annotated.exists() else {}
        self.assertTrue(self.cplan()["ok"])
        self.assertEqual(self.snapshot() if self.annotated.exists() else {}, before)

    @pytest.mark.contract
    def test_the_comment_plan_is_not_accepted_by_apply_yet(self):
        plan = self.cplan()
        out = self.apply(self.sealed(plan))
        self.assertEqual((out["ok"], out["status"], out["error"]), (False, "INVALID_PLAN", "PLAN_SCHEMA_UNSUPPORTED"))

    @pytest.mark.contract
    def test_plan_problem_checks_each_kind_with_its_own_field_set(self):
        plan = self.cplan()["plan"]
        sealed = dict(plan, plan_sha256="0" * 64)
        self.assertEqual(ti._plan_problem(sealed, ("rename", "comments")), (None, None))
        self.assertEqual(ti._plan_problem(sealed)[0], "PLAN_SCHEMA_UNSUPPORTED")
        for mutate in (lambda i: i.pop("expect_comment"), lambda i: i.update(new_name="x"),
                       lambda i: i.update(comment_kind="decompiler"), lambda i: i.update(comment=""),
                       lambda i: i.update(expect_comment=5)):
            broken = json.loads(json.dumps(sealed))
            mutate(broken["items"][0])
            self.assertEqual(ti._plan_problem(broken, ("rename", "comments")), ("PLAN_ITEM_MALFORMED", "items"))
        rename = dict(self.plan()["plan"], plan_sha256="0" * 64)
        self.assertEqual(ti._plan_problem(rename), (None, None))
        self.assertEqual(ti._plan_problem(rename, ("rename", "comments")), (None, None))
        rename["items"][0]["comment"] = "x"
        self.assertEqual(ti._plan_problem(rename)[0], "PLAN_ITEM_MALFORMED")


# ---------------------------------------------------------------------------
# the write worker as a file
# ---------------------------------------------------------------------------
def _load_worker():
    names = ["ida_auto", "ida_loader", "ida_nalt", "ida_netnode", "ida_pro", "idaapi", "idc"]
    stubs = {n: mock.MagicMock(name=n) for n in names}
    stubs["idc"].BADADDR = 0xFFFFFFFFFFFFFFFF
    stubs["idc"].SN_NOWARN = 0x100
    stubs["ida_loader"].DBFL_TEMP = 4
    stubs["ida_loader"].PATH_TYPE_IDB = 1
    stubs["ida_loader"].get_path.return_value = "db.i64"
    stubs["ida_loader"].is_database_flag.return_value = False
    stubs["ida_nalt"].get_imagebase.return_value = 0x140000000
    stubs["idaapi"].get_fileregion_offset.side_effect = lambda ea: ea - 0x140000000 + 0x200
    stubs["idc"].get_segm_name.return_value = ".text"
    stubs["idc"].get_item_head.side_effect = lambda ea: ea
    with mock.patch.dict(sys.modules, stubs):
        loader = SourceFileLoader("liebert_ida_annotate_worker_under_test", str(WORKER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    return module, stubs


class WorkerFileTests(unittest.TestCase):
    def test_it_is_a_data_file_without_bom_or_crlf_that_compiles(self):
        self.assertEqual(WORKER.suffix, ".idapy")
        raw = WORKER.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        compile(raw.decode("utf-8"), str(WORKER), "exec")
        self.assertEqual(list(WORKER.parent.glob("*.py")), [])

    def test_it_imports_only_the_standard_library_and_ida_modules(self):
        tree = ast.parse(WORKER.read_text(encoding="utf-8"))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        self.assertEqual({n for n in names if not (n.startswith("ida") or n == "idc")}, {"json", "os", "sys", "traceback"})

    def test_the_write_api_exists_in_this_file_only_and_only_inside_the_scratch_writer(self):
        tree = ast.parse(WORKER.read_text(encoding="utf-8"))
        writer = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_ScratchWriter")
        inside = {id(n) for n in ast.walk(writer)}
        write_api = {"set_name", "setblob", "save_database", "set_cmt", "patch_bytes", "del_items"}
        outside = [(n.attr, n.lineno) for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in write_api
                   and id(n) not in inside]
        self.assertEqual(outside, [])
        found = {n.attr for n in ast.walk(writer) if isinstance(n, ast.Attribute)}
        self.assertTrue({"set_name", "setblob", "save_database"} <= found, found)
        for other in ("query_program.idapy", "microcode_cfg.idapy", "patch_plan.idapy"):
            text = (WORKER.parent / other).read_text(encoding="utf-8")
            for api in ("set_name", "setblob", "set_cmt"):
                self.assertNotIn(api, text, (other, api))
        # the one pre-existing save call lives in the query worker's create mode only
        self.assertEqual(text.count("save_database"), 0)

    def test_the_worker_is_in_the_wheel_checks_and_the_package_data(self):
        ci = (Path(ti.__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("ida_scripts/annotate_write.idapy", ci)
        self.assertIn("the IDAPython annotation write worker is missing from the wheel", ci)
        toml = (Path(ti.__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("ida_scripts/*.idapy", toml)       # the glob that ships this file
        self.assertTrue(WORKER.match("*/ida_scripts/*.idapy"))


class WorkerLogicTests(unittest.TestCase):
    def setUp(self):
        self.w, self.ida = _load_worker()
        self.names = {0x140001000: "start"}
        idc = self.ida["idc"]
        idc.get_name.side_effect = lambda ea: self.names.get(ea, "")
        idc.set_name.side_effect = lambda ea, name, flags: self.names.__setitem__(ea, name) or True

    def item(self, address="0x140001000", new="renamed", expect="start"):
        return {"address": address, "address_kind": "va", "new_name": new, "expect_name": expect}

    def run_op(self, operation, mode, items, **extra):
        job = {"operation": operation, "write_mode": mode, "items": items, **extra}
        return self.w._run(job)

    def test_the_apply_session_refuses_to_exist_when_the_session_is_temporary_or_unknown(self):
        for flag in (True, None):
            with self.subTest(flag=flag):
                self.ida["ida_loader"].is_database_flag.return_value = flag
                if flag is None:
                    self.ida["ida_loader"].is_database_flag.side_effect = AttributeError("no such call")
                result = self.run_op("rename_apply", "write", [self.item()], marker={"v": 1})
                self.assertEqual((result["ok"], result["error"]), (False, "APPLY_SESSION_IS_TEMPORARY"))
                self.ida["idc"].set_name.assert_not_called()
                self.ida["ida_loader"].save_database.assert_not_called()

    def test_plan_and_verify_mark_the_session_temporary_first_and_never_write(self):
        for operation, mode in (("rename_plan", "plan"), ("rename_verify", "verify")):
            with self.subTest(operation):
                self.ida["ida_loader"].set_database_flag.reset_mock()
                result = self.run_op(operation, mode, [self.item(new="other")])
                self.assertTrue(result["ok"], result)
                self.assertIs(result["database_changes_discarded"], True)
                self.ida["ida_loader"].set_database_flag.assert_called_once_with(4)
                self.ida["idc"].set_name.assert_not_called()
                self.ida["ida_loader"].save_database.assert_not_called()
        self.assertEqual(result["verified_items"][0]["actual_name"], "start")

    def test_a_read_session_that_cannot_be_marked_temporary_reads_nothing(self):
        self.ida["ida_loader"].set_database_flag.side_effect = RuntimeError("no flag")
        result = self.run_op("rename_plan", "plan", [self.item()])
        self.assertEqual((result["ok"], result["error"]), (False, "DATABASE_CHANGES_NOT_DISCARDABLE"))
        self.ida["idc"].get_name.assert_not_called()

    def test_an_operation_in_the_wrong_mode_is_refused(self):
        result = self.run_op("rename_apply", "plan", [self.item()], marker={})
        self.assertEqual((result["ok"], result["error"], result["expected_mode"]), (False, "OPERATION_MODE_MISMATCH", "write"))
        self.assertEqual(self.run_op("rename_nothing", "write", [])["error"], "UNKNOWN_OPERATION")

    def test_a_good_apply_sets_checks_the_read_back_stores_the_marker_and_checks_the_save(self):
        result = self.run_op("rename_apply", "write", [self.item()], marker={"version": 1})
        self.assertEqual((result["ok"], result["save_returned"], result["marker_stored"], result["saved"]), (True, True, True, True))
        self.assertEqual(result["applied"][0]["new_name"], "renamed")
        self.ida["ida_loader"].save_database.assert_called_once_with("db.i64", 0)
        self.assertEqual(self.names[0x140001000], "renamed")
        self.assertIs(result["database_changes_discarded"], False)

    def test_a_save_that_returns_false_is_not_a_success(self):
        self.ida["ida_loader"].save_database.return_value = False
        result = self.run_op("rename_apply", "write", [self.item()], marker={"version": 1})
        self.assertEqual((result["ok"], result["error"], result["save_returned"], result["saved"]),
                         (False, "SAVE_NOT_CONFIRMED", False, False))

    def test_an_atomic_apply_with_a_failed_precondition_writes_nothing(self):
        result = self.run_op("rename_apply", "write", [self.item(), self.item("0x140001004", "x", "was_other")], marker={})
        self.assertEqual((result["ok"], result["error"], result["applied"]), (False, "ABORTED_ATOMIC", []))
        self.assertEqual(result["failed"][0]["error"], "PRECONDITION_FAILED")
        self.ida["idc"].set_name.assert_not_called()
        self.ida["ida_loader"].save_database.assert_not_called()

    def test_an_engine_that_refuses_a_name_aborts_an_atomic_apply_before_saving(self):
        self.ida["idc"].set_name.side_effect = lambda ea, name, flags: False
        result = self.run_op("rename_apply", "write", [self.item()], marker={})
        self.assertEqual((result["ok"], result["error"]), (False, "ABORTED_ATOMIC"))
        self.assertEqual(result["failed"][0]["error"], "RENAME_REJECTED_BY_ENGINE")
        self.ida["ida_loader"].save_database.assert_not_called()

    def test_a_rename_whose_read_back_differs_is_a_failure_even_when_set_name_said_true(self):
        self.ida["idc"].set_name.side_effect = lambda ea, name, flags: True      # says yes, changes nothing
        result = self.run_op("rename_apply", "write", [self.item()], marker={})
        self.assertEqual((result["ok"], result["failed"][0]["read_back_matches"]), (False, False))

    def test_partial_applies_the_good_ones_and_all_failed_saves_nothing(self):
        partial = self.run_op("rename_apply", "write", [self.item(), self.item("0x140001004", "x", "was_other")],
                              marker={}, allow_partial=True)
        self.assertEqual((partial["ok"], len(partial["applied"]), len(partial["failed"]), partial["atomic"]), (True, 1, 1, False))
        self.ida["ida_loader"].save_database.reset_mock()
        none = self.run_op("rename_apply", "write", [self.item(expect="was_other")], marker={}, allow_partial=True)
        self.assertEqual((none["ok"], none["error"]), (False, "ALL_FAILED"))
        self.ida["ida_loader"].save_database.assert_not_called()

    def test_plan_refuses_by_item_and_says_which(self):
        cases = [(self.item(new="start"), "NAME_UNCHANGED"), (self.item(address="zz"), "INVALID_ADDRESS"),
                 (self.item(new=""), "INVALID_NAME")]
        for item, error in cases:
            with self.subTest(error):
                result = self.run_op("rename_plan", "plan", [item])
                self.assertEqual((result["ok"], result["error"], result["item_error"], result["item_index"]),
                                 (False, "PLAN_ITEM_REFUSED", error, 0))
        self.ida["idc"].get_item_head.side_effect = lambda ea: ea - 1
        result = self.run_op("rename_plan", "plan", [self.item(new="y")])
        self.assertEqual(result["item_error"], "ADDRESS_NOT_AN_ITEM_START")

    def comment_item(self, address="0x140001000", comment="note", kind="regular"):
        return {"address": address, "address_kind": "va", "comment_kind": kind, "comment": comment}

    def test_comment_plan_reads_the_existing_comment_of_the_kind_and_never_writes(self):
        idc = self.ida["idc"]
        idc.get_cmt.side_effect = lambda ea, rpt: {(0x140001000, 0): "old", (0x140001004, 1): ""}.get((ea, rpt))
        self.ida["ida_loader"].set_database_flag.reset_mock()
        result = self.run_op("comment_plan", "plan", [self.comment_item(), self.comment_item("0x140001004", "n", "repeatable"),
                                                      self.comment_item("0x140001008", "n", "regular")])
        self.assertTrue(result["ok"], result)
        self.assertEqual([(r["comment_kind"], r["expect_comment"]) for r in result["plan_items"]],
                         [("regular", "old"), ("repeatable", None), ("regular", None)])
        self.assertIs(result["database_changes_discarded"], True)
        self.ida["ida_loader"].set_database_flag.assert_called_once_with(4)
        idc.set_cmt.assert_not_called()
        idc.set_name.assert_not_called()
        self.ida["ida_loader"].save_database.assert_not_called()
        self.assertNotIn("note", json.dumps(result), "the job's comment text is not echoed")

    def test_comment_plan_refuses_by_item_and_says_which(self):
        self.ida["idc"].get_cmt.side_effect = lambda ea, rpt: "same"
        cases = [(self.comment_item(comment="same"), "COMMENT_UNCHANGED"), (self.comment_item(address="zz"), "INVALID_ADDRESS"),
                 (self.comment_item(kind="decompiler"), "UNSUPPORTED_COMMENT_KIND"), (self.comment_item(comment=""), "INVALID_COMMENT")]
        for item, error in cases:
            with self.subTest(error):
                result = self.run_op("comment_plan", "plan", [item])
                self.assertEqual((result["ok"], result["error"], result["item_error"], result["item_index"]),
                                 (False, "PLAN_ITEM_REFUSED", error, 0))
                self.assertNotIn("same", json.dumps(result))
        self.assertEqual(self.run_op("comment_plan", "write", [self.comment_item()])["error"], "OPERATION_MODE_MISMATCH")

    def test_comment_plan_in_a_session_that_cannot_be_marked_temporary_reads_nothing(self):
        self.ida["ida_loader"].set_database_flag.side_effect = RuntimeError("no flag")
        result = self.run_op("comment_plan", "plan", [self.comment_item()])
        self.assertEqual((result["ok"], result["error"]), (False, "DATABASE_CHANGES_NOT_DISCARDABLE"))
        self.ida["idc"].get_cmt.assert_not_called()

    def test_the_result_carries_the_engine_pid_and_the_completion_marker_last(self):
        out = Path(process_scratch("an_worker")) / "out.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, out.parent, ignore_errors=True)
        job = out.parent / "job.json"
        job.write_text(json.dumps({"output": str(out), "operation": "rename_plan", "write_mode": "plan",
                                   "items": [self.item(new="y")]}), encoding="utf-8")
        with mock.patch.dict(os.environ, {self.w.JOB_ENV: str(job)}):
            self.assertEqual(self.w.main(), 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(list(data)[-1], "script_completed")
        self.assertEqual(data["engine_pid"], os.getpid())


# ---------------------------------------------------------------------------
# the real engine
# ---------------------------------------------------------------------------
class PurgeCase(AnnotateCase):
    def purge(self, targets=None, token=None, label="first-pass", path=None):
        return json.loads(ti.ida_annotations_purge(str(path or self.sample), label, targets, token))

    def confirmed(self, targets, label="first-pass"):
        report = self.purge(targets, label=label)
        self.assertEqual(report["status"], "REPORT_ONLY", report)
        return self.purge(targets, report["confirm_token"], label=label)

    def keep_a_candidate(self):
        real = ti._replace_file
        with mock.patch.object(ti, "_replace_file",
                               side_effect=lambda s, d: "PermissionError" if Path(s).name == ti._DB_NAME else real(s, d)):
            return self.write()["write_id"]

    def two_versions(self):
        self.write()
        self.write([{"address": START, "new_name": "second_name"}])


class PurgeTests(PurgeCase):
    @pytest.mark.contract
    def test_a_call_without_confirmation_reports_and_deletes_nothing(self):
        self.two_versions()
        wid = self.keep_a_candidate()
        before = self.snapshot()
        report = self.purge(["version:1", f"candidate:{wid}"])
        self.assertEqual((report["ok"], report["status"], report["deleted"]), (True, "REPORT_ONLY", False))
        self.assertEqual({e["target"] for e in report["inventory"]}, {"version:1", "published:2", f"candidate:{wid}"})
        self.assertEqual([w["target"] for w in report["would_delete"]], ["version:1", f"candidate:{wid}"])
        self.assertGreater(report["would_free_bytes"], 0)
        self.assertEqual((report["published_version"], report["inventory_cut"]), (2, False))
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.purge()["confirm_token"])

    @pytest.mark.contract
    def test_the_confirmation_is_bound_to_the_named_targets(self):
        self.two_versions()
        wid = self.keep_a_candidate()
        report = self.purge(["version:1"])
        before = self.snapshot()
        for other in (["version:1", f"candidate:{wid}"], [f"candidate:{wid}"]):
            out = self.purge(other, report["confirm_token"])
            self.assertEqual((out["ok"], out["status"], out["deleted"], out["fixable"]), (False, "STALE_CONFIRMATION", False, True))
        self.assertEqual(self.snapshot(), before)
        done = self.purge(["version:1"], report["confirm_token"])
        self.assertEqual((done["ok"], done["status"], done["deleted"]), (True, "OK", True))
        self.assertFalse(ti._version_file(self.label_dir(), 1).exists())

    @pytest.mark.contract
    def test_a_confirmation_made_stale_by_a_later_change_deletes_nothing(self):
        self.write()
        report = self.purge(["published:1"])
        self.write([{"address": START, "new_name": "second_name"}])     # the scope changed after the report
        before = self.snapshot()
        out = self.purge(["published:1"], report["confirm_token"])
        self.assertEqual((out["status"], out["deleted"]), ("STALE_CONFIRMATION", False))
        self.assertEqual(self.snapshot(), before)

    @pytest.mark.contract
    def test_a_token_without_targets_or_for_another_scope_is_not_accepted(self):
        self.write()
        out = self.purge(None, "abc")
        self.assertEqual((out["error"], out["field"], out["fixable"]), ("CONFIRMATION_NEEDS_TARGETS", "confirm_token", True))
        self.write([{"address": START, "new_name": "other"}], label="second-scope")
        report = self.purge(["published:1"], label="second-scope")
        self.assertEqual(self.purge(["published:1"], report["confirm_token"], label="first-pass")["status"], "STALE_CONFIRMATION")

    @pytest.mark.contract
    def test_wildcards_and_everything_forms_are_refused_and_every_name_must_be_exact(self):
        self.write()
        for given in ("*", "all", "version:*", "version:1?", "candidate:*", "version:[1-2]", "ALL"):
            with self.subTest(given):
                out = self.purge([given])
                self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "WILDCARD_REFUSED", True))
                self.assertIn("accepted", out)
        for given in ("version:0", "version:01", "version:1 ", "candidate:xyz", "scratch:1", "version", "../x", "published:"):
            with self.subTest(given):
                self.assertEqual(self.purge([given])["error"], "TARGET_NAME_INVALID")
        self.assertEqual(self.purge(["version:1", "version:1"])["error"], "DUPLICATE_TARGET")
        self.assertEqual(self.purge("version:1")["error"], "TARGETS_INVALID")
        self.assertEqual(self.purge(["version:9"])["error"], "TARGET_NOT_FOUND")
        self.assertTrue(ti._version_file(self.label_dir(), 1).exists())

    @pytest.mark.contract
    def test_the_published_version_is_protected_unless_named_as_published(self):
        self.two_versions()
        out = self.purge(["version:2"])
        self.assertEqual((out["error"], out["fixable"]), ("PUBLISHED_VERSION_PROTECTED", True))
        self.assertIn("published:<N>", out["fix"])
        self.assertTrue(ti._version_file(self.label_dir(), 2).exists())
        done = self.confirmed(["published:2"])
        self.assertEqual((done["status"], done["published_version_after"]), ("OK", 0))
        self.assertIsNone(self.manifest(), "the pointer went first")
        self.assertFalse(ti._version_file(self.label_dir(), 2).exists())
        self.assertTrue(ti._version_file(self.label_dir(), 1).exists(), "an older version stays unless it is named")
        self.assertEqual(self.plan()["plan"]["base_version"], 0, "a new plan starts from the pristine analysis")

    @pytest.mark.contract
    def test_a_kept_candidate_is_deleted_by_name_and_frees_the_budget(self):
        wid = self.keep_a_candidate()
        held = ti._annotated_total_bytes() - ti._journal_path(self.sha).stat().st_size
        report = self.purge([f"candidate:{wid}"])
        self.assertEqual(report["would_delete"][0]["state"], "kept candidate (never promoted)")
        done = self.purge([f"candidate:{wid}"], report["confirm_token"])
        self.assertEqual((done["status"], done["deleted"]), ("OK", True))
        self.assertEqual(ti._annotated_total_bytes() - ti._journal_path(self.sha).stat().st_size, held - report["would_free_bytes"])
        self.assertFalse((self.label_dir() / "recovery" / wid).exists())

    @pytest.mark.contract
    def test_every_deletion_leaves_a_journal_trace_before_and_after(self):
        self.write()
        self.confirmed(["published:1"])
        records = ti._journal_records(self.sha)[0]
        self.assertEqual([r["event"] for r in records][-2:], ["purge_prepared", "purge_committed"])
        self.assertEqual(records[-2]["targets"], ["published:1"])
        self.assertEqual(records[-1]["results"][0]["deleted"], True)
        data = json.loads(ti.ida_annotations(str(self.sample)))
        self.assertEqual((data["status"], data["unreadable_lines"]), ("OK", 0))

    @pytest.mark.contract
    def test_a_journal_that_cannot_be_written_blocks_the_deletion(self):
        self.write()
        report = self.purge(["published:1"])
        with mock.patch.object(ti, "_journal_append", return_value=(False, "PermissionError")):
            out = self.purge(["published:1"], report["confirm_token"])
        self.assertEqual((out["ok"], out["status"], out["deleted"], out["fixable"]), (False, "JOURNAL_UNWRITABLE", False, "retry_later"))
        self.assertTrue(ti._version_file(self.label_dir(), 1).exists())
        real = ti._journal_append
        with mock.patch.object(ti, "_journal_append",
                               side_effect=lambda s, r: (False, "OSError") if r["event"] == "purge_committed" else real(s, r)):
            out = self.purge(["published:1"], report["confirm_token"])
        self.assertEqual((out["ok"], out["commit_record_pending"]), (True, True))

    @pytest.mark.contract
    def test_an_unverified_scope_is_cleared_only_by_name_and_the_answer_says_so(self):
        self.write()
        (self.label_dir() / "manifest.json").write_text("{torn", encoding="utf-8")
        self.assertEqual(self.plan()["error"], "ANNOTATED_STATE_UNVERIFIED")
        report = self.purge(["unverified-state"])
        self.assertEqual((report["scope_unverified"], report["unverified_reason"]), (True, "MANIFEST_MALFORMED"))
        self.assertEqual(self.plan()["error"], "ANNOTATED_STATE_UNVERIFIED", "a report changes nothing")
        done = self.purge(["unverified-state"], report["confirm_token"])
        self.assertEqual((done["ok"], done["status"], done["unverified_cleared"], done["unverified_reason_was"]),
                         (True, "OK", True, "MANIFEST_MALFORMED"))
        self.assertIn("cleared by this call", done["note"])
        self.assertTrue(done["results"][0]["removed_manifest_sha256"])
        self.assertTrue(self.plan()["ok"])
        self.assertTrue(ti._version_file(self.label_dir(), 1).exists(), "the version file stays until it is named")
        self.assertIn(done["results"][0]["target"], ti._journal_records(self.sha)[0][-2]["targets"])

    @pytest.mark.contract
    def test_an_open_write_record_that_blocks_a_scope_is_closed_by_the_clearing(self):
        with mock.patch.object(ti, "_manifest_write", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                self.write()
        ti._manifest_write(self.label_dir(), {"schema": 1, "sha256": self.sha, "label": "first-pass", "version": 5,
                                             "write_id": "x", "db_sha256": "0" * 64, "db_bytes": 1})
        self.assertEqual(self.plan()["error"], "ANNOTATED_STATE_UNVERIFIED")
        self.assertTrue(self.confirmed(["unverified-state"])["unverified_cleared"])
        self.assertTrue(self.plan()["ok"])

    @pytest.mark.contract
    def test_a_damaged_journal_is_not_clearable_by_purge(self):
        self.write()
        ti._journal_path(self.sha).unlink()
        ti._journal_path(self.sha).mkdir()
        out = self.purge(["unverified-state"])
        self.assertEqual((out["ok"], out["error"], out["fixable"]), (False, "JOURNAL_NOT_CLEARABLE", False))

    @pytest.mark.contract
    def test_a_scope_that_is_fine_has_no_unverified_state_to_clear(self):
        self.write()
        self.assertEqual(self.purge(["unverified-state"])["error"], "TARGET_NOT_FOUND")

    @pytest.mark.contract
    def test_a_long_inventory_says_it_was_cut(self):
        self.write()
        versions = self.label_dir() / "versions"
        for n in range(2, ti._PURGE_INVENTORY_LIMIT + 6):
            (versions / f"v{n:06d}").mkdir()
            (versions / f"v{n:06d}" / ti._DB_NAME).write_bytes(b"x")
        report = self.purge()
        self.assertEqual((report["inventory_cut"], len(report["inventory"])), (True, ti._PURGE_INVENTORY_LIMIT))
        self.assertIn("cut at", report["inventory_note"])
        self.assertGreater(report["inventory_total"], ti._PURGE_INVENTORY_LIMIT)

    @pytest.mark.contract
    def test_the_guard_refuses_a_delete_outside_one_scopes_named_artifacts(self):
        self.write()
        scope = self.label_dir()
        outside = [self.cache, self.root, self.annotated, scope, scope / "versions", scope / "manifest.json",
                   self.annotated / self.sha, scope.parent / "other"]
        victim = self.root / "ev_victim"
        victim.mkdir()
        (victim / "f").write_bytes(b"x")
        for target in outside + [victim]:
            with self.subTest(target=str(target)[-12:]):
                self.assertFalse(ti._purge_remove(target, scope))
        self.assertFalse(ti._purge_remove(scope / "versions" / "v000001", self.root), "a scope that is not under the root")
        self.assertTrue(ti._version_file(scope, 1).exists())
        self.assertTrue((victim / "f").exists())

    @pytest.mark.contract
    def test_purge_reaches_nothing_outside_the_annotated_root(self):
        """The mirror of the Z1 test: the pristine cache, a stand-in slot and the evidence directory are
        byte-identical after a purge that really deletes."""
        self.two_versions()
        wid = self.keep_a_candidate()
        self.ev.mkdir(exist_ok=True)
        (self.ev / "kept.json").write_text("{}", encoding="utf-8")
        outside = {"cache": self.snapshot(self.cache), "evidence": self.snapshot(self.ev)}
        self.assertTrue(outside["cache"] and outside["evidence"])
        done = self.confirmed(["version:1", f"candidate:{wid}", "published:2"])
        self.assertEqual((done["status"], done["deleted"]), ("OK", True))
        self.assertEqual({"cache": self.snapshot(self.cache), "evidence": self.snapshot(self.ev)}, outside)
        self.assertEqual(sorted(p.name for p in self.ev.glob("*")), sorted(outside["evidence"]))

    @pytest.mark.contract
    def test_an_overlapping_configuration_refuses_purge(self):
        with mock.patch.object(ti, "ANNOTATED_ROOT", self.cache / "inside"):
            out = self.purge()
        self.assertEqual(out["error"], "ANNOTATED_ROOT_OVERLAPS_CACHE")

    @pytest.mark.contract
    def test_the_label_and_the_input_are_checked_like_the_other_operations(self):
        self.assertEqual(self.purge(label="bad label")["error"], "LABEL_REQUIRED")
        self.assertEqual(self.purge(path=self.root / "missing.exe")["status"], "NOT_FOUND")

    @pytest.mark.contract
    def test_target_name_and_path_do_not_leak(self):
        self.write()
        report = self.purge(["published:1"])
        done = self.purge(["published:1"], report["confirm_token"])
        for text in (json.dumps(report), json.dumps(done), ti._journal_path(self.sha).read_text(encoding="utf-8")):
            self.assertNoTargetLeak(text)

    def test_the_purge_source_never_references_the_cache_slots_pristine_databases_or_evidence(self):
        inside, _cache_side = _section_functions()
        purge_functions = [fn for fn in inside if fn.name in ("ida_annotations_purge", "_purge_locked", "_purge_remove",
                                                              "_purge_inventory", "_purge_confirmation", "_tree_bytes")]
        self.assertEqual(len(purge_functions), 6)
        forbidden = {"_cache_root", "CACHE_ROOT", "_slot_dir", "_slot_is_healthy", "_evict_slot", "_enforce_cache_budget",
                     "_write_evidence", "EVIDENCE", "EVIDENCE_RENAME_PLAN", "EVIDENCE_ANNOTATE_APPLY", "EVIDENCE_ANNOTATIONS",
                     "_copy_pristine", "_query_locked"}
        for fn in purge_functions:
            self.assertEqual(forbidden & (_referenced_names(fn) | _called_names(fn)), set(), fn.name)

    def test_it_is_a_published_name_distinct_from_the_apply_and_the_plan(self):
        published = tool_families.published_tools("native")
        self.assertIn("ida_annotations_purge", published)
        self.assertEqual(len({"ida_rename_plan", "ida_annotations_apply", "ida_annotations_purge"} & set(published)), 3)




@pytest.mark.heavy
class AnnotateRealInstallTests(unittest.TestCase):
    """Needs a licensed IDA Pro 9.x; skips when idat is not found. Builds its own tiny synthetic x86-64 PE."""

    @classmethod
    def setUpClass(cls):
        if not ti.ida_available():
            raise unittest.SkipTest("IDA Pro (idat) is not installed")
        from liebert_re.recover.owned_binary_fixtures import build_owned_pe_with_code
        from tests.test_tools_ida_round2a import CODE
        cls.root = process_scratch("an_real")
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.pe = build_owned_pe_with_code(cls.root / "owned.exe", CODE)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        # Short names on purpose: Windows' 260-character path limit applies below the annotated root.
        self.base = self.root / f"t{hashlib.sha256(self.id().encode()).hexdigest()[:5]}"
        self.base.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.cache, self.annotated = self.base / "c", self.base / "a"
        stack.enter_context(mock.patch.object(ti, "CACHE_ROOT", self.cache))
        stack.enter_context(mock.patch.object(ti, "ANNOTATED_ROOT", self.annotated))
        for name in ("EVIDENCE", "EVIDENCE_RENAME_PLAN", "EVIDENCE_ANNOTATE_APPLY", "EVIDENCE_ANNOTATIONS"):
            stack.enter_context(mock.patch.object(ti, name, self.base / "e"))
        stack.enter_context(mock.patch.object(ti, "_evidence_index_record_write", return_value={}))
        self.sha = ti._sha256_md5(self.pe)[0]

    def plan(self, renames, label="first-pass"):
        return json.loads(ti.ida_rename_plan(str(self.pe), label, renames))

    def apply(self, plan_answer, **kwargs):
        return json.loads(ti.ida_annotations_apply(str(self.pe), dict(plan_answer["plan"], plan_sha256=plan_answer["plan_sha256"]), **kwargs))

    def pristine(self):
        return next(self.cache.glob("*.p0v1.*/db.i64"))

    def read_back_in_a_fresh_engine(self, version, items):
        """An independent read of the stored version: a copy of the file, opened in a new idat process."""
        work = self.annotated / self.sha / "scratch-test0001"
        work.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        shutil.copyfile(ti._version_file(ti._label_dir(self.sha, "first-pass"), version), work / ti._DB_NAME)
        data, _signals, _prov = ti._annotated_session(
            ti._ida_binary(), work, {"operation": "rename_verify", "write_mode": "verify", "items": items}, tool="t",
            sha256=self.sha, md5=ti._sha256_md5(self.pe)[1], invocation={}, temporary=True, seconds=120,
            cancellation_token=None)
        return data

    def test_a_rename_is_persisted_and_a_new_engine_process_reads_it_back(self):
        plan = self.plan([{"address": "0x140001000", "new_name": "liebert_start"}, {"address": 0x140001004, "new_name": "after_check"}])
        self.assertTrue(plan["ok"], plan)
        self.assertEqual([i["expect_name"] for i in plan["plan"]["items"]], ["start", ""])
        out = self.apply(plan)
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["status"], out["version"], out["applied_count"]), ("OK", 1, 2))
        v = out["verification"]
        self.assertEqual((v["names_matched"], v["marker_matched"], v["separate_process"]), (2, True, True))
        self.assertEqual(len({v["write_session_pid"], v["verify_session_pid"], v["harness_pid"]}), 3)
        fresh = self.read_back_in_a_fresh_engine(1, [{"address": "0x140001000"}, {"address": "0x140001004"}])
        self.assertEqual([r["actual_name"] for r in fresh["verified_items"]], ["liebert_start", "after_check"])
        self.assertEqual(fresh["annotation_marker"]["version"], 1)
        self.assertNotIn(fresh["engine_pid"], (os.getpid(), v["write_session_pid"], v["verify_session_pid"]))

    def test_the_database_digest_changes_and_the_pristine_one_does_not(self):
        plan = self.plan([{"address": "0x140001000", "new_name": "liebert_start"}])
        pristine_before = ti._file_sha256(self.pristine())[0]
        out = self.apply(plan)
        self.assertTrue(out["ok"], out)
        self.assertEqual(ti._file_sha256(self.pristine())[0], pristine_before, "the cached pristine database is byte-identical")
        self.assertNotEqual(out["db_sha256"], pristine_before)
        stored = ti._version_file(ti._label_dir(self.sha, "first-pass"), 1)
        self.assertEqual(ti._file_sha256(stored)[0], out["db_sha256"])
        # reading it again (a plan over the annotated version) does not change the stored file
        again = self.plan([{"address": "0x140001000", "new_name": "second_name"}])
        self.assertEqual(again["plan"]["items"][0]["expect_name"], "liebert_start")
        self.assertEqual(ti._file_sha256(stored)[0], out["db_sha256"])

    def test_the_second_version_replaces_the_pointer_atomically_and_leaves_the_first_file_alone(self):
        first = self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        v1 = ti._version_file(ti._label_dir(self.sha, "first-pass"), 1)
        v1_digest = ti._file_sha256(v1)[0]
        second = self.apply(self.plan([{"address": "0x140001000", "new_name": "second_name"}]))
        self.assertEqual((first["version"], second["version"]), (1, 2))
        self.assertEqual(ti._file_sha256(v1)[0], v1_digest)
        manifest = ti._manifest_read(ti._label_dir(self.sha, "first-pass"))[0]
        self.assertEqual((manifest["version"], manifest["db_sha256"], manifest["previous_version"]), (2, second["db_sha256"], 1))
        stale = self.plan([{"address": "0x140001000", "new_name": "third"}])
        self.assertEqual(stale["plan"]["base_version"], 2)

    def test_a_stale_plan_is_blocked_against_the_real_engine(self):
        one = self.plan([{"address": "0x140001000", "new_name": "writer_one"}])
        two = self.plan([{"address": "0x140001000", "new_name": "writer_two"}])
        self.assertTrue(self.apply(one)["ok"])
        lost = self.apply(two)
        self.assertEqual((lost["status"], lost["error"], lost["written"]), ("PRECONDITION_FAILED", "STALE_BASE_VERSION", False))
        names = self.read_back_in_a_fresh_engine(1, [{"address": "0x140001000"}])
        self.assertEqual(names["verified_items"][0]["actual_name"], "writer_one")

    def test_a_failed_promotion_keeps_the_real_candidate_and_a_later_write_goes_ahead(self):
        real = ti._replace_file

        def refuse_candidate(source, destination):
            return "PermissionError" if Path(source).name == ti._DB_NAME else real(source, destination)

        plan = self.plan([{"address": "0x140001000", "new_name": "liebert_start"}])
        with mock.patch.object(ti, "_replace_file", side_effect=refuse_candidate):
            out = self.apply(plan)
        self.assertEqual((out["status"], out["candidate_retained"]), ("ANNOTATED_PROMOTION_BLOCKED", True))
        candidate = ti._label_dir(self.sha, "first-pass") / "recovery" / out["write_id"] / ti._DB_NAME
        self.assertEqual(ti._file_sha256(candidate)[0], out["candidate_sha256"])
        self.assertIsNone(ti._manifest_read(ti._label_dir(self.sha, "first-pass"))[0])
        done = self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        self.assertTrue(done["ok"], done)
        self.assertTrue(candidate.is_file())

    def test_cache_eviction_and_a_cache_wipe_leave_the_real_annotated_data_alive(self):
        out = self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        self.assertTrue(out["ok"], out)
        stored = ti._version_file(ti._label_dir(self.sha, "first-pass"), 1)
        before = {p.relative_to(self.annotated).as_posix(): ti._file_sha256(p)[0] for p in self.annotated.rglob("*")
                  if p.is_file() and not p.name.endswith(".lock")}
        self.assertTrue(list(self.cache.glob("*.p0v1.*/db.i64")), "precondition: a pristine slot exists before the eviction")
        with mock.patch.dict(os.environ, {"LIEBERT_IDA_CACHE_BYTES": "1"}), mock.patch.object(ti, "_EVICT_SKIP_RECENT_SECONDS", 0):
            ti._enforce_cache_budget(None)                      # the cache evicts every slot it may
        self.assertEqual(list(self.cache.glob("*.p0v1.*")), [], "the pristine slot WAS evicted")
        shutil.rmtree(self.cache)
        after = {p.relative_to(self.annotated).as_posix(): ti._file_sha256(p)[0] for p in self.annotated.rglob("*")
                 if p.is_file() and not p.name.endswith(".lock")}
        self.assertEqual(after, before)
        self.assertTrue(stored.is_file())
        fresh = self.read_back_in_a_fresh_engine(1, [{"address": "0x140001000"}])
        self.assertEqual(fresh["verified_items"][0]["actual_name"], "liebert_start")
        plan = self.plan([{"address": "0x140001000", "new_name": "after_eviction"}])
        self.assertEqual((plan["ok"], plan["plan"]["base_version"], plan["plan"]["items"][0]["expect_name"]),
                         (True, 1, "liebert_start"))
        self.assertFalse(list(self.cache.glob("*.p0v1.*")) if self.cache.exists() else [], "no pristine analysis was rebuilt")

    def test_the_reader_sees_what_the_writer_journalled(self):
        self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        data = json.loads(ti.ida_annotations(str(self.pe)))
        self.assertEqual((data["status"], data["total_entries"], data["unreadable_lines"]), ("OK", 2, 0))
        self.assertEqual([e["event"] for e in data["entries"]], ["batch_prepared", "batch_committed"])

    def test_a_rename_the_engine_refuses_is_reported_and_publishes_nothing(self):
        plan = self.plan([{"address": "0x140001000", "new_name": "liebert_start"}])
        sealed = dict(plan["plan"], plan_sha256=plan["plan_sha256"])
        sealed["items"][0]["expect_name"] = "not_the_name"
        sealed.pop("plan_sha256")
        sealed["plan_sha256"] = ti._sha256_text(ti._canonical(sealed))
        out = json.loads(ti.ida_annotations_apply(str(self.pe), sealed))
        self.assertEqual((out["status"], out["written"]), ("ABORTED_ATOMIC", False))
        self.assertIsNone(ti._manifest_read(ti._label_dir(self.sha, "first-pass"))[0])


    # -- purge against the real engine -----------------------------------------------------------
    def purge(self, targets=None, token=None, label="first-pass"):
        return json.loads(ti.ida_annotations_purge(str(self.pe), label, targets, token))

    def test_purge_deletes_a_real_version_and_a_kept_candidate_and_the_next_plan_follows(self):
        first = self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        second = self.apply(self.plan([{"address": "0x140001000", "new_name": "second_name"}]))
        real = ti._replace_file
        with mock.patch.object(ti, "_replace_file",
                               side_effect=lambda s, d: "PermissionError" if Path(s).name == ti._DB_NAME else real(s, d)):
            kept = self.apply(self.plan([{"address": "0x140001000", "new_name": "third_name"}]))
        self.assertEqual((first["version"], second["version"], kept["status"]), (1, 2, "ANNOTATED_PROMOTION_BLOCKED"))
        journal = ti._journal_path(self.sha)
        held_before = ti._annotated_total_bytes() - journal.stat().st_size
        names = ["version:1", f"candidate:{kept['write_id']}"]
        report = self.purge(names)
        self.assertEqual(report["status"], "REPORT_ONLY")
        self.assertEqual(ti._annotated_total_bytes() - journal.stat().st_size, held_before, "the report deleted nothing")
        self.assertGreater(report["would_free_bytes"], 100000)         # two real databases
        done = self.purge(names, report["confirm_token"])
        self.assertEqual((done["status"], done["deleted"], done["freed_bytes"]), ("OK", True, report["would_free_bytes"]))
        self.assertEqual(ti._annotated_total_bytes() - journal.stat().st_size, held_before - report["would_free_bytes"])
        scope = ti._label_dir(self.sha, "first-pass")
        self.assertFalse(ti._version_file(scope, 1).exists())
        self.assertFalse((scope / "recovery" / kept["write_id"]).exists())
        self.assertTrue(ti._version_file(scope, 2).is_file())
        records = ti._journal_records(self.sha)[0]
        self.assertEqual([r["event"] for r in records][-2:], ["purge_prepared", "purge_committed"])
        # the next plan still reads the published version 2 (names of version 2, not of the deleted one)
        plan = self.plan([{"address": "0x140001000", "new_name": "fourth_name"}])
        self.assertEqual((plan["ok"], plan["plan"]["base_version"], plan["plan"]["items"][0]["expect_name"]), (True, 2, "second_name"))
        # deleting the published version removes the pointer; planning then starts from the pristine analysis again
        gone = self.purge(["published:2"])
        self.assertEqual(self.purge(["published:2"], gone["confirm_token"])["status"], "OK")
        again = self.plan([{"address": "0x140001000", "new_name": "fresh_start"}])
        self.assertEqual((again["plan"]["base_version"], again["plan"]["items"][0]["expect_name"]), (0, "start"))
        self.assertEqual(self.apply(again)["version"], 4, "version numbers are never reused (3 was prepared by the kept candidate)")

    def test_purge_touches_nothing_outside_the_annotated_root_in_a_real_run(self):
        self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        evidence = self.base / "e"
        evidence_before = {p.name: ti._file_sha256(p)[0] for p in evidence.glob("*") if p.is_file()}
        cache_before = {p.relative_to(self.cache).as_posix(): ti._file_sha256(p)[0] for p in self.cache.rglob("*") if p.is_file()}
        self.assertTrue(evidence_before and cache_before)
        report = self.purge(["published:1"])
        done = self.purge(["published:1"], report["confirm_token"])
        self.assertEqual(done["status"], "OK")
        self.assertEqual({p.name: ti._file_sha256(p)[0] for p in evidence.glob("*") if p.is_file()}, evidence_before)
        self.assertEqual({p.relative_to(self.cache).as_posix(): ti._file_sha256(p)[0] for p in self.cache.rglob("*") if p.is_file()},
                         cache_before, "the pristine cache, its meta and the slot are byte-identical")

    def test_purge_clears_a_real_unverified_scope_and_says_so(self):
        out = self.apply(self.plan([{"address": "0x140001000", "new_name": "liebert_start"}]))
        stored = ti._version_file(ti._label_dir(self.sha, "first-pass"), 1)
        stored.write_bytes(stored.read_bytes() + b"x")                 # the file no longer matches its pointer
        self.assertEqual(self.plan([{"address": "0x140001000", "new_name": "x_name"}])["error"], "ANNOTATED_STATE_UNVERIFIED")
        report = self.purge(["unverified-state"])
        done = self.purge(["unverified-state"], report["confirm_token"])
        self.assertEqual((done["status"], done["unverified_cleared"], done["unverified_reason_was"]),
                         ("OK", True, "VERSION_FILE_HASH_MISMATCH"))
        self.assertTrue(self.plan([{"address": "0x140001000", "new_name": "x_name"}])["ok"])
        self.assertNotEqual(out["db_sha256"], ti._file_sha256(stored)[0])


if __name__ == "__main__":
    unittest.main()
