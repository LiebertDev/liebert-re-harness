import json
import unittest

from analysis_ir import (
    UNKNOWN,
    AnalysisIR,
    AnalysisIRValidationError,
    Artifact,
    Call,
    Evidence,
    Export,
    Function,
    Module,
    Reference,
    artifact_id,
    function_id,
    module_id,
    stable_id,
)


class AnalysisIRTests(unittest.TestCase):
    SHA = "ab" * 32

    def foundation(self):
        aid = artifact_id(self.SHA)
        mid = module_id(self.SHA)
        artifact = Artifact(id=aid, sha256=self.SHA, format="PE", size_bytes=42)
        module = Module(id=mid, artifact_id=aid, name="sample.sys", architecture="x86_64")
        return AnalysisIR([artifact, module]), aid, mid

    def test_ids_and_json_are_deterministic(self):
        ir, aid, mid = self.foundation()
        eid = stable_id("evidence", self.SHA, "pdata", 0x1000)
        fid = function_id(self.SHA, 0x1000)
        ir.add(Evidence(
            id=eid,
            artifact_id=aid,
            source="PE_EXCEPTION_PDATA",
            claim_status="METADATA_PROVEN",
            raw_provenance={"end": 0x1040, "begin": 0x1000},
        ))
        ir.add(Function(
            id=fid,
            module_id=mid,
            start_rva=0x1000,
            end_rva=0x1040,
            discovery_sources=("PE_EXCEPTION_PDATA",),
            confidence="METADATA_PROVEN",
            evidence_ids=(eid,),
        ))
        call = Call(
            id=stable_id("call", fid, 0x1008),
            source_function_id=fid,
            target_function_id=UNKNOWN,
            callsite_rva=0x1008,
            target_rva=UNKNOWN,
            resolution="INDIRECT_UNRESOLVED",
            confidence=UNKNOWN,
            evidence_ids=(eid,),
            raw_provenance={"operand": "rax", "indirect_target_not_inferred": True},
        )
        ir.add(call)
        first = ir.to_json(indent=None)
        second = ir.to_json(indent=None)
        self.assertEqual(first, second)
        decoded = json.loads(first)
        self.assertEqual(decoded["schema"], "analysis-ir/v1")
        self.assertEqual(decoded["entities"]["call"][0]["target_function_id"], UNKNOWN)
        self.assertTrue(decoded["entities"]["call"][0]["raw_provenance"]["indirect_target_not_inferred"])
        self.assertEqual(function_id(self.SHA.upper(), 0x1000), fid)

    def test_unknown_is_preserved_not_omitted(self):
        ir, _, mid = self.foundation()
        ir.add(Export(
            id=stable_id("export", self.SHA, 9),
            module_id=mid,
            ordinal=9,
        ))
        row = ir.to_dict()["entities"]["export"][0]
        self.assertIn("name", row)
        self.assertEqual(row["name"], UNKNOWN)
        self.assertEqual(row["function_id"], UNKNOWN)
        self.assertEqual(row["forwarder"], UNKNOWN)

    def test_resolved_endpoints_are_strict_but_unknown_target_is_valid(self):
        ir, _, mid = self.foundation()
        fid = function_id(self.SHA, 0x2000)
        ir.add(Function(id=fid, module_id=mid, start_rva=0x2000))
        ir.add(Reference(
            id=stable_id("reference", fid, "unknown"),
            source_id=fid,
            target_id=UNKNOWN,
            reference_kind="INDIRECT",
        ))
        self.assertEqual(ir.validate(), [])
        ir.add(Reference(
            id=stable_id("reference", fid, "missing"),
            source_id=fid,
            target_id="function:does-not-exist",
        ))
        with self.assertRaises(AnalysisIRValidationError) as caught:
            ir.validate()
        self.assertIn("missing endpoint", str(caught.exception))

    def test_same_id_with_different_content_is_rejected(self):
        ir, aid, _ = self.foundation()
        with self.assertRaises(AnalysisIRValidationError):
            ir.add(Artifact(id=aid, sha256="cd" * 32, format="ELF"))

    def test_round_trip_from_dict_preserves_valid_graph(self):
        ir, _, _ = self.foundation()
        rebuilt = AnalysisIR.from_dict(ir.to_dict())
        self.assertEqual(rebuilt.to_json(indent=None), ir.to_json(indent=None))


if __name__ == "__main__":
    unittest.main()
