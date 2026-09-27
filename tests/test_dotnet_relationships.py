import unittest

from analysis_ir import UNKNOWN
from dotnet_relationships import build_dotnet_relationships


class DotnetRelationshipTests(unittest.TestCase):
    def canonical(self):
        return {
            "artifact_sha256": "ab" * 32,
            "assembly": {"name": "Agent.Core", "version": "1.2.3.4"},
            "types": [
                {"name": "Agent.Base", "token": "0x02000001"},
                {"name": "Agent.Worker", "token": "0x02000002", "base_type_token": "0x02000001"},
            ],
            "methods": [
                {"type": "Agent.Worker", "name": "Run", "token": "0x06000001", "rva": 4096},
                {"type": "Agent.Worker", "name": "Local", "token": "0x06000002", "rva": 4200},
            ],
            "fields": [
                {"declaring_type": "Agent.Worker", "name": "state", "token": "0x04000001"},
            ],
            "strings": [{"token": "0x70000001", "value": "bounded literal"}],
            "member_refs": [{
                "token": "0x0A000001", "assembly": "System.Runtime",
                "declaring_type": "System.Console", "name": "WriteLine", "member_kind": "method",
            }],
            "references": [{"name": "System.Runtime", "version": "8.0.0.0"}],
            "il_methods": [{
                "type": "Agent.Worker", "name": "Run", "token": "0x06000001",
                "instructions": [
                    {"offset": 0, "mnemonic": "call", "operand": "02000006"},
                    {"offset": 5, "mnemonic": "callvirt", "operand": "0100000a"},
                    {"offset": 10, "mnemonic": "ldfld", "operand": "01000004"},
                    {"offset": 15, "mnemonic": "ldstr", "operand": "01000070"},
                    {"offset": 20, "mnemonic": "call", "operand": "9900000a"},
                ],
            }],
        }

    def test_inventory_hierarchy_and_il_relationships(self):
        report = build_dotnet_relationships(self.canonical())
        self.assertTrue(report["ok"])
        self.assertEqual(report["analysis_scope"], "STATIC_CANONICAL_DOTNET_INTERMEDIATE")
        self.assertFalse(report["execution_performed"])
        self.assertEqual(report["counts"]["method"], 2)
        kinds = [row["kind"] for row in report["relationships"]]
        self.assertIn("TYPE_INHERITS", kinds)
        self.assertIn("METHOD_CALL", kinds)
        self.assertIn("FIELD_ACCESS", kinds)
        self.assertIn("STRING_USE", kinds)
        self.assertIn("CROSS_ASSEMBLY_MEMBER_REFERENCE", kinds)
        self.assertIn("ASSEMBLY_REFERENCE", kinds)

        calls = [row for row in report["relationships"] if row["kind"] == "METHOD_CALL"]
        resolved = [row for row in calls if row["target_id"] != UNKNOWN]
        self.assertEqual(len(resolved), 2)
        self.assertTrue(all(row["confidence"] == "METADATA_PROVEN" for row in resolved))
        self.assertTrue(all(row["evidence"]["opcode"] in {"call", "callvirt"} for row in resolved))
        external = next(row for row in report["relationships"] if row["kind"] == "CROSS_ASSEMBLY_MEMBER_REFERENCE")
        self.assertEqual(external["provenance"]["target_assembly"], "System.Runtime")

    def test_unresolved_token_is_explicit_unknown_with_provenance(self):
        report = build_dotnet_relationships(self.canonical())
        unknown = [
            row for row in report["relationships"]
            if row["kind"] == "METHOD_CALL" and row["target_token"] == "0x0A000099"
        ]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["target_id"], UNKNOWN)
        self.assertEqual(unknown[0]["confidence"], UNKNOWN)
        self.assertEqual(unknown[0]["provenance"]["unresolved_reason"], "TOKEN_NOT_PRESENT_IN_CANONICAL_INPUT")
        self.assertEqual(unknown[0]["evidence"]["il_offset"], 20)
        self.assertEqual(report["status"], "PARTIAL")

    def test_output_is_deterministic_and_bounded(self):
        first = build_dotnet_relationships(self.canonical(), max_relationships=3)
        second = build_dotnet_relationships(self.canonical(), max_relationships=3)
        self.assertEqual(first, second)
        self.assertTrue(first["truncated"])
        self.assertEqual(len(first["relationships"]), 3)

    def test_current_metadata_shape_with_string_type_names_is_supported(self):
        report = build_dotnet_relationships({
            "assembly": {"name": "Minimal"},
            "types": ["Minimal.Program"],
            "methods": [{"type": "Minimal.Program", "name": "Main", "token": "0x06000001", "rva": 1}],
        })
        self.assertTrue(report["ok"])
        self.assertEqual(report["entities"]["type"][0]["name"], "Minimal.Program")
        self.assertEqual(report["entities"]["method"][0]["declaring_type"], "Minimal.Program")

    def test_invalid_input_fails_closed(self):
        report = build_dotnet_relationships([])
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
