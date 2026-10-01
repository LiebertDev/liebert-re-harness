import unittest

from liebert_re.recover.analysis_ir import (
    UNKNOWN,
    AnalysisIR,
    Artifact,
    BasicBlock,
    Call,
    Function,
    Import,
    Module,
    Reference,
    StringLiteral,
    artifact_id,
    function_id,
    module_id,
    stable_id,
)
from liebert_re.recover.binary_version_diff import diff_analysis_ir


class BinaryVersionDiffTests(unittest.TestCase):
    def make_ir(self, sha, *, changed=False):
        aid = artifact_id(sha)
        mid = module_id(sha, "agent.sys")
        main_id = function_id(sha, 0x3000 if changed else 0x1000)
        helper_id = function_id(sha, 0x4000 if changed else 0x2000)
        unmatched_id = function_id(sha, 0x6000 if changed else 0x5000)
        ir = AnalysisIR([
            Artifact(id=aid, sha256=sha, format="PE", size_bytes=9000),
            Module(id=mid, artifact_id=aid, name="agent.sys", architecture="x86_64"),
            Function(
                id=main_id, module_id=mid, start_rva=0x3000 if changed else 0x1000,
                end_rva=(0x3060 if changed else 0x1050), name="Analyze",
                confidence="SYMBOL_PROVEN",
                metadata={"sensitive_paths": ["device-control-to-write"] if changed else ["file-input-to-parse"]},
            ),
            Function(
                id=helper_id, module_id=mid, start_rva=0x4000 if changed else 0x2000,
                end_rva=(0x4030 if changed else 0x2030), name="Helper", confidence="SYMBOL_PROVEN",
            ),
            Function(
                id=unmatched_id, module_id=mid, start_rva=0x6000 if changed else 0x5000,
                name="AddedOnly" if changed else "RemovedOnly", confidence="SYMBOL_PROVEN",
            ),
        ])
        import_name = "DeviceIoControl" if changed else "ReadFile"
        import_id = stable_id("import", sha, import_name)
        string_value = "new behavior" if changed else "old behavior"
        string_id = stable_id("string", sha, string_value)
        ir.add(Import(id=import_id, module_id=mid, library="kernel32.dll", name=import_name))
        ir.add(StringLiteral(id=string_id, module_id=mid, rva=0x7000, value=string_value, encoding="utf-8"))
        ir.add(Reference(
            id=stable_id("reference", main_id, import_id), source_id=main_id,
            target_id=import_id, reference_kind="IMPORT_CALL", confidence="METADATA_PROVEN",
        ))
        ir.add(Reference(
            id=stable_id("reference", main_id, string_id), source_id=main_id,
            target_id=string_id, reference_kind="STRING", confidence="METADATA_PROVEN",
        ))
        ir.add(Call(
            id=stable_id("call", main_id, helper_id), source_function_id=main_id,
            target_function_id=helper_id, resolution="DIRECT", confidence="METADATA_PROVEN",
        ))
        block_id = stable_id("block", main_id)
        instructions = (
            ({"mnemonic": "cmp", "operand_kind": "reg"}, {"mnemonic": "jne", "operand_kind": "branch"})
            if changed else ({"mnemonic": "mov", "operand_kind": "reg"},)
        )
        ir.add(BasicBlock(
            id=block_id, function_id=main_id, start_rva=0x3000 if changed else 0x1000,
            instructions=instructions, confidence="METADATA_PROVEN",
            metadata={"successors": ["fallthrough", "branch"] if changed else ["fallthrough"]},
        ))
        return ir.to_dict(), main_id, unmatched_id

    def test_semantic_match_survives_rva_change_and_reports_dimensions(self):
        old_ir, old_main, old_removed = self.make_ir("11" * 32)
        new_ir, new_main, new_added = self.make_ir("22" * 32, changed=True)
        report = diff_analysis_ir(old_ir, new_ir)
        self.assertTrue(report["ok"])
        match = next(row for row in report["function_matches"] if row["old_function_id"] == old_main)
        self.assertEqual(match["new_function_id"], new_main)
        self.assertEqual(match["strategy"], "UNIQUE_SEMANTIC_NAME")
        self.assertEqual(match["confidence"], "SYMBOL_PROVEN")
        self.assertFalse(match["rva_equality_not_used"])

        change = next(row for row in report["function_changes"] if row["old_function_id"] == old_main)
        self.assertTrue(change["dimensions"]["imports"]["added"])
        self.assertTrue(change["dimensions"]["imports"]["removed"])
        self.assertTrue(change["dimensions"]["strings"]["added"])
        self.assertTrue(change["dimensions"]["sensitive_paths"]["added"])
        self.assertTrue(change["dimensions"]["cfg"]["changed"])
        self.assertFalse(change["provenance"]["raw_binary_execution"])
        self.assertEqual(report["added_functions"][0]["function_id"], new_added)
        self.assertEqual(report["removed_functions"][0]["function_id"], old_removed)

    def test_same_rva_alone_never_matches_unknown_functions(self):
        def minimal(sha):
            aid, mid = artifact_id(sha), module_id(sha)
            fid = function_id(sha, 0x1000)
            return AnalysisIR([
                Artifact(id=aid, sha256=sha), Module(id=mid, artifact_id=aid),
                Function(id=fid, module_id=mid, start_rva=0x1000, name=UNKNOWN),
            ]).to_dict(), fid

        old_ir, old_id = minimal("33" * 32)
        new_ir, new_id = minimal("44" * 32)
        report = diff_analysis_ir(old_ir, new_ir)
        self.assertEqual(report["function_matches"], [])
        self.assertEqual(report["removed_functions"][0]["function_id"], old_id)
        self.assertEqual(report["added_functions"][0]["function_id"], new_id)

    def test_string_reports_use_hashes_not_raw_values(self):
        old_ir, _, _ = self.make_ir("55" * 32)
        new_ir, _, _ = self.make_ir("66" * 32, changed=True)
        report = diff_analysis_ir(old_ir, new_ir)
        encoded = str(report)
        self.assertNotIn("old behavior", encoded)
        self.assertNotIn("new behavior", encoded)
        change = report["function_changes"][0]
        self.assertTrue(all(value.startswith("sha256:") for value in change["dimensions"]["strings"]["added"]))

    def test_output_is_deterministic(self):
        old_ir, _, _ = self.make_ir("77" * 32)
        new_ir, _, _ = self.make_ir("88" * 32, changed=True)
        self.assertEqual(diff_analysis_ir(old_ir, new_ir), diff_analysis_ir(old_ir, new_ir))

    def test_rejects_noncanonical_schema(self):
        report = diff_analysis_ir({"schema": "other"}, {"schema": "other"})
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "UNSUPPORTED_SCHEMA")


if __name__ == "__main__":
    unittest.main()
