"""Adapted from tests/test_native_xref.py: that file imports research_graph
and workspace_index (unpublished orchestration modules) for exactly one
test method (the ResearchGraph-ingestion adapter check); everything else in
it only exercises native_xref.py and analysis_ir.py, both published. This
file keeps that everything-else coverage verbatim and replaces the
ResearchGraph-dependent assertion with a check of
analysis_ir_graph_relationships()'s own return shape, which is all that
call actually proves before handing rows to a graph store. Also adds
native_xref_analyze() (the JSON-in/JSON-out wrapper), which the private
test never covered."""
from __future__ import annotations

import json
import unittest

from liebert_re.recover.analysis_ir import (
    UNKNOWN, AnalysisIR, Artifact, Call, Evidence, Function, Import, Module,
    StringLiteral, Symbol, artifact_id, function_id, module_id, stable_id,
)
from liebert_re.recover.native_xref import (
    analysis_ir_graph_relationships, native_xref_analyze, resolve_native_xrefs,
    resolve_rva_to_function, resolve_symbol_to_function,
)


class NativeXrefTests(unittest.TestCase):
    SHA = "41" * 32

    def setUp(self):
        aid = artifact_id(self.SHA)
        mid = module_id(self.SHA)
        self.mid = mid
        self.ir = AnalysisIR([
            Artifact(id=aid, sha256=self.SHA, format="PE"),
            Module(id=mid, artifact_id=aid, name="client.sys"),
        ])
        self.evidence = Evidence(
            id=stable_id("evidence", self.SHA, "decoder"), artifact_id=aid,
            source="CAPSTONE_X86_64", claim_status="METADATA_PROVEN",
        )
        self.f1 = Function(
            id=function_id(self.SHA, 0x1000), module_id=mid, start_rva=0x1000,
            end_rva=0x1080, confidence="METADATA_PROVEN", evidence_ids=(self.evidence.id,),
        )
        self.f2 = Function(
            id=function_id(self.SHA, 0x1100), module_id=mid, start_rva=0x1100,
            end_rva=0x1180, confidence="METADATA_PROVEN", evidence_ids=(self.evidence.id,),
        )
        self.imported = Import(
            id=stable_id("import", self.SHA, "kernel32", "Sleep"), module_id=mid,
            library="KERNEL32.dll", name="Sleep", iat_rva=0x3000,
            evidence_ids=(self.evidence.id,),
        )
        self.string = StringLiteral(
            id=stable_id("string_literal", self.SHA, 0x4000), module_id=mid,
            rva=0x4000, value="hello", evidence_ids=(self.evidence.id,),
        )
        self.symbol = Symbol(
            id=stable_id("symbol", self.SHA, 0x1100), module_id=mid,
            name="target", rva=0x1100, function_id=self.f2.id,
            confidence="SYMBOL_PROVEN", evidence_ids=(self.evidence.id,),
        )
        for node in (self.evidence, self.f1, self.f2, self.imported, self.string, self.symbol):
            self.ir.add(node)

    def test_rva_and_symbol_resolution_are_deterministic(self):
        self.assertEqual(resolve_rva_to_function(self.ir, 0x1100).target_id, self.f2.id)
        containing = resolve_rva_to_function(self.ir, 0x1110)
        self.assertEqual(containing.target_id, self.f2.id)
        self.assertEqual(containing.resolution, "UNIQUE_CONTAINING_RANGE")
        self.assertEqual(resolve_symbol_to_function(self.ir, self.symbol.id).target_id, self.f2.id)

    def test_calls_imports_strings_and_indirect_unknown(self):
        rows = [
            {"kind": "CALL", "source_function_id": self.f1.id, "callsite_rva": 0x1010,
             "target_rva": 0x1100, "evidence_id": self.evidence.id, "decoder": "capstone"},
            {"kind": "IMPORT_CALL", "source_function_id": self.f1.id, "callsite_rva": 0x1015,
             "iat_rva": 0x3000, "evidence_id": self.evidence.id},
            {"kind": "STRING_REFERENCE", "source_function_id": self.f1.id, "source_rva": 0x1020,
             "string_rva": 0x4000, "evidence_id": self.evidence.id},
            {"kind": "CALL", "source_function_id": self.f1.id, "callsite_rva": 0x1030,
             "indirect": True, "operand": "rax", "evidence_id": self.evidence.id},
        ]
        report = resolve_native_xrefs(self.ir, rows)
        direct = next(row for row in report["calls"] if row["callsite_rva"] == 0x1010)
        indirect = next(row for row in report["calls"] if row["callsite_rva"] == 0x1030)
        self.assertEqual(direct["target_function_id"], self.f2.id)
        self.assertEqual(indirect["target_function_id"], UNKNOWN)
        self.assertTrue(indirect["raw_provenance"]["indirect_target_not_inferred"])
        self.assertEqual(report["import_callers"][self.imported.id], [self.f1.id])
        self.assertEqual(report["string_referrers"][self.string.id], [self.f1.id])
        self.assertFalse(report["runtime_behavior_claimed"])

    def test_duplicate_and_self_cycle_are_stable(self):
        row = {"kind": "CALL", "source_function_id": self.f1.id, "callsite_rva": 0x1005,
               "target_rva": 0x1000, "evidence_id": self.evidence.id}
        report = resolve_native_xrefs(self.ir, [row, dict(row)])
        self.assertEqual(len(report["calls"]), 1)
        self.assertEqual(report["rejected"], [])
        self.assertTrue(report["calls"][0]["raw_provenance"]["cycle_candidate"])

    def test_observation_without_ir_evidence_is_rejected(self):
        report = resolve_native_xrefs(self.ir, [{
            "kind": "CALL", "source_function_id": self.f1.id,
            "callsite_rva": 0x1040, "target_rva": 0x1100,
        }])
        self.assertEqual(report["calls"], [])
        self.assertEqual(report["rejected"][0]["reason"], "MISSING_EVIDENCE")

    def test_existing_call_resolution_and_graph_adapter(self):
        self.ir.add(Call(
            id=stable_id("call", self.f1.id, 0x1040), source_function_id=self.f1.id,
            target_function_id=self.f2.id, callsite_rva=0x1040, target_rva=0x1100,
            resolution="DIRECT_EXACT_FUNCTION_START", confidence="METADATA_PROVEN",
            evidence_ids=(self.evidence.id,),
        ))
        rows = analysis_ir_graph_relationships(self.ir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["relation"], "CALLS")
        self.assertEqual(rows[0]["target"]["key"], self.f2.id)

    def test_graph_adapter_accepts_resolver_output_shaped_for_ingestion(self):
        # This is the part of the private test that does NOT need
        # ResearchGraph/WorkspaceIndex: the adapter's own output row shape is
        # everything a graph store's ingest_relationships() call actually
        # consumes, so proving that shape is complete proves this module's
        # own contract without needing the ingestion machinery itself.
        report = resolve_native_xrefs(self.ir, [{
            "kind": "IMPORT_CALL", "source_function_id": self.f1.id,
            "callsite_rva": 0x1050, "iat_rva": 0x3000,
            "evidence_id": self.evidence.id,
        }])
        rows = analysis_ir_graph_relationships(self.ir, report)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["metadata"]["reference_kind"], "IMPORT_CALL")
        self.assertEqual(row["relation"], "REFERENCES")
        self.assertIn("key", row["source"])
        self.assertIn("key", row["target"])

    def test_native_xref_analyze_json_wrapper_round_trips(self):
        rows = [{
            "kind": "CALL", "source_function_id": self.f1.id, "callsite_rva": 0x1010,
            "target_rva": 0x1100, "evidence_id": self.evidence.id,
        }]
        raw = native_xref_analyze(json.dumps(self.ir.to_dict()), json.dumps(rows))
        report = json.loads(raw)
        self.assertIn("calls", report)
        self.assertEqual(len(report["calls"]), 1)
        self.assertIn("ir", report)  # the wrapper echoes the (possibly-updated) IR back

    def test_native_xref_analyze_invalid_json_is_a_structured_failure(self):
        report = json.loads(native_xref_analyze("not json", "[]"))
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "INVALID_INPUT")

    def test_native_xref_analyze_non_list_observations_is_invalid_schema(self):
        report = json.loads(native_xref_analyze(json.dumps(self.ir.to_dict()), json.dumps({"not": "a list"})))
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "INVALID_SCHEMA")


if __name__ == "__main__":
    unittest.main()
