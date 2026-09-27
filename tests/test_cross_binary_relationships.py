import unittest

from analysis_ir import (
    AnalysisIR, Artifact, Evidence, Export, Function, Import, Module, Reference,
    artifact_id, function_id, module_id, stable_id,
)
from cross_binary_relationships import build_cross_binary_relationships


def fixture(sha, name):
    aid = artifact_id(sha)
    mid = module_id(sha)
    ir = AnalysisIR([
        Artifact(id=aid, sha256=sha, format="PE"),
        Module(id=mid, artifact_id=aid, name=name),
    ])
    evidence = Evidence(
        id=stable_id("evidence", sha, "pe"), artifact_id=aid,
        source="PE_METADATA", claim_status="SYMBOL_PROVEN",
    )
    ir.add(evidence)
    return ir, aid, mid, evidence


class CrossBinaryRelationshipTests(unittest.TestCase):
    def setUp(self):
        self.client, _, client_mid, client_ev = fixture("51" * 32, "client.sys")
        self.server, _, server_mid, server_ev = fixture("52" * 32, "helper.dll")
        self.client_mid, self.server_mid = client_mid, server_mid
        self.client_ev, self.server_ev = client_ev, server_ev
        self.caller = Function(
            id=function_id("51" * 32, 0x1000), module_id=client_mid,
            start_rva=0x1000, end_rva=0x1080, confidence="METADATA_PROVEN",
            evidence_ids=(client_ev.id,),
        )
        self.target = Function(
            id=function_id("52" * 32, 0x2000), module_id=server_mid,
            start_rva=0x2000, end_rva=0x2080, confidence="SYMBOL_PROVEN",
            evidence_ids=(server_ev.id,),
        )
        self.imported = Import(
            id=stable_id("import", "51" * 32, "helper", "Verify"), module_id=client_mid,
            library="HELPER.DLL", name="Verify", iat_rva=0x3000,
            evidence_ids=(client_ev.id,),
        )
        self.exported = Export(
            id=stable_id("export", "52" * 32, "Verify"), module_id=server_mid,
            name="Verify", rva=0x2000, function_id=self.target.id,
            evidence_ids=(server_ev.id,),
        )
        for node in (self.caller, self.imported):
            self.client.add(node)
        for node in (self.target, self.exported):
            self.server.add(node)

    def test_module_match_without_call_does_not_invent_function_edge(self):
        report = build_cross_binary_relationships([self.client, self.server])
        self.assertEqual(len(report["relationships"]), 1)
        self.assertEqual(report["relationships"][0]["relation"], "IMPORTS")
        self.assertFalse(report["runtime_behavior_claimed"])

    def test_function_edge_requires_explicit_import_call_reference(self):
        self.client.add(Reference(
            id=stable_id("reference", self.caller.id, self.imported.id),
            source_id=self.caller.id, target_id=self.imported.id,
            reference_kind="IMPORT_CALL", source_rva=0x1010, target_rva=0x3000,
            confidence="METADATA_PROVEN", evidence_ids=(self.client_ev.id,),
        ))
        first = build_cross_binary_relationships([self.client, self.server])
        second = build_cross_binary_relationships([self.server, self.client])
        self.assertEqual(first, second)
        rows = first["relationships"]
        self.assertEqual([row["relation"] for row in rows], ["CALLS", "IMPORTS"])
        call = next(row for row in rows if row["relation"] == "CALLS")
        self.assertEqual(call["source"]["key"], self.caller.id)
        self.assertEqual(call["target"]["key"], self.target.id)
        self.assertFalse(call["metadata"]["runtime_behavior_claimed"])

    def test_ambiguous_export_fails_closed_and_deduplicates(self):
        duplicate = Export(
            id=stable_id("export", "52" * 32, "Verify", 2), module_id=self.server_mid,
            name="Verify", ordinal=2, rva=0x2010, evidence_ids=(self.server_ev.id,),
        )
        self.server.add(duplicate)
        report = build_cross_binary_relationships([self.client, self.server, self.server])
        self.assertEqual(report["relationships"], [])
        self.assertEqual(report["ambiguous"][0]["reason"], "AMBIGUOUS_EXPORT")

    def test_repeated_ir_input_does_not_duplicate_export_candidate(self):
        report = build_cross_binary_relationships([self.client, self.server, self.server])
        self.assertEqual(len(report["relationships"]), 1)
        self.assertEqual(report["ambiguous"], [])

    def test_auxiliary_observation_is_static_and_requires_evidence(self):
        report = build_cross_binary_relationships(
            [self.client, self.server],
            auxiliary_observations=[{
                "relationship_class": "CONFIG_REFERENCES_MODULE",
                "source_id": "config:settings.json", "target_module_id": self.server_mid,
                "evidence_ids": ["EV-CONFIG"], "locator": "plugins[0]",
                "observed_text": "helper.dll",
            }],
        )
        row = next(item for item in report["relationships"] if item["metadata"]["relationship_class"] == "CONFIG_REFERENCES_MODULE")
        self.assertEqual(row["relation"], "REFERENCES")
        self.assertFalse(row["metadata"]["runtime_behavior_claimed"])
        rejected = build_cross_binary_relationships(
            [self.client, self.server],
            auxiliary_observations=[{"relationship_class": "LOG_MENTIONS_MODULE", "source_id": "log:x", "target_module_id": self.server_mid}],
        )
        self.assertEqual(rejected["rejected"][0]["reason"], "UNPROVEN_AUXILIARY_ENDPOINT")

    def test_import_export_without_ir_evidence_is_not_promoted(self):
        client, _, client_mid, _ = fixture("61" * 32, "client2.sys")
        server, _, server_mid, _ = fixture("62" * 32, "bare.dll")
        imported = Import(
            id=stable_id("import", "61" * 32, "bare", "Open"), module_id=client_mid,
            library="bare.dll", name="Open", iat_rva=0x3000,
        )
        exported = Export(
            id=stable_id("export", "62" * 32, "Open"), module_id=server_mid,
            name="Open", rva=0x2000,
        )
        client.add(imported); server.add(exported)
        report = build_cross_binary_relationships([client, server])
        self.assertEqual(report["relationships"], [])
        self.assertEqual(report["ambiguous"][0]["reason"], "MISSING_IR_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
