"""vb6_pcode: opcode semantics read from the runtime's handler blocks.

Until now the tool reported an opcode's length and, when the handler called one,
the name of a runtime helper -- but never what the opcode itself does, which is why
its own `not_established` list carries `WHAT_ANY_OPCODE_MEANS`. These tests cover
the addition that names a subset of opcodes from the shape of their handler block.

The bar the tests hold it to is that a name is either right or absent. A wrong name
is worse than no name, because a reader would trust it, so the fixtures below are
opcodes whose meaning was read by hand out of `MSVBVM60.DLL` and cross-checked
against a real procedure's behaviour.
"""
from __future__ import annotations

import json
import os
import struct
import unittest

import liebert_re.tools.vb6_pcode as pcode

TARGET = os.path.join(
    "benchmarks", "windows_native_ladder", "corpus", "tier2", "son_console2_revised",
    "extracted", "inner", "SoN Console CrackMe 2.exe",
)
SUB_MAIN_DESCRIPTOR = "0x403a7c"

# (table index, expected name). Index is page * 256 + opcode.
KNOWN = (
    (0x04, "PUSH_LOCAL_ADDRESS"),
    (0x6C, "PUSH_LOCAL_VALUE"),
    (0x6B, "PUSH_LOCAL_WORD"),
    (0x0A, "CALL_THROUGH_LITERAL"),
    (0x1B, "PUSH_LITERAL"),
    (0xF5, "PUSH_IMMEDIATE_DWORD"),
    (0xF4, "PUSH_IMMEDIATE_BYTE"),
    (0xC0, "SIGNED_DIVIDE"),
    (0x60, "BSTR_OUT_OF_VARIANT"),
    (0x1C, "BRANCH_IF_WORD_ZERO"),
    (0x70, "STORE_LOCAL_WORD"),
    (0x31, "ASSIGN_LOCAL"),
    (0x46, "STORE_VARIANT_PUSH_ADDRESS"),
    (3 * 256 + 0x69, "STORE_VARIANT_PUSH_ADDRESS"),
    (3 * 256 + 0xC7, "POP_TO_LOCAL_PUSH_ADDRESS"),
    # The three store forms differ in where the Variant's type word comes from and
    # in the width of the value store, so one shape does not cover them.
    (0x4D, "STORE_VARIANT_TYPED_OPERAND"),
    (0x28, "STORE_INTEGER_IMMEDIATE"),
    (0x44, "STORE_VARIANT_WORD_PUSH_ADDRESS"),
    (0x3A, "STORE_LITERAL_BSTR"),
    (0x43, "POP_TO_LOCAL_GUARDED"),
    (3 * 256 + 0xFE, "BSTR_OUT_OF_VARIANT_INDEXED"),
    (0xE7, "WIDEN_WORD_TO_DWORD"),
    (0xE4, "NARROW_TO_WORD_CHECKED"),
    # Arithmetic against the stack, which is most of what remained unnamed.
    (0xA9, "ADD_INTO_STACK_TOP"),
    (0xAE, "SUBTRACT_FROM_STACK_TOP"),
    (0xB2, "MULTIPLY_STACK_TOP"),
    (0xC7, "SUBTRACT_STACK_TOP"),
    (0xDB, "COMPARE_STACK_TOP"),
    (0xBF, "DIVIDE_WORD"),
    (0x64, "INCREMENT_THROUGH_POINTER"),
    (0x71, "POP_INTO_LOCAL"),
    (0xF3, "PUSH_IMMEDIATE_WORD"),
    # Object, control-flow and indirect-access forms.
    (0x1A, "RELEASE_LOCAL_OBJECT_GUARDED"),
    (0x08, "SET_CURRENT_OBJECT_FROM_LOCAL_GUARDED"),
    (0x94, "PUSH_INDIRECT_LOCAL_OFFSET_GUARDED"),
    (0x05, "PUSH_LITERAL_INDIRECT"),
    (0x1E, "GOTO"),
    (0x5D, "SET_BYREF_FLAG_ON_STACK_TOP"),
    (0x65, "FOR_STEP_OVERFLOW_TRAP"),
)


def _runtime():
    path = pcode._runtime_path("")
    if path is None:
        return None
    return pcode._Runtime(path)


class SemanticsFromHandlerBlocks(unittest.TestCase):
    def setUp(self):
        self.runtime = _runtime()
        if self.runtime is None or self.runtime.engine is None:
            self.skipTest("MSVBVM60.DLL not installed on this machine")
        result = json.loads(pcode.vb6_pcode(operation="runtime_table", max_chars=20000))
        self.table_va = int(result["table_va"], 16)
        self.summary = result
        self.summary_entries = pcode._build_table(self.runtime)["entries"]

    def _handler(self, index):
        _name, va, _vsize, blob, _chars = self.runtime.engine
        offset = self.table_va - va + 4 * index
        return struct.unpack("<I", blob[offset:offset + 4])[0]

    def test_known_opcodes_are_named_exactly(self):
        """Every hand-verified opcode gets its name, and no other name."""
        for index, expected in KNOWN:
            name, description = pcode._handler_semantics(self.runtime, self._handler(index))
            self.assertEqual(name, expected,
                             "table index %d (page %d, opcode 0x%02x)"
                             % (index, index // 256, index % 256))
            self.assertTrue(description, "a named opcode must carry a description")

    def test_a_shared_body_is_followed_through_its_jump(self):
        """p3/0x69 is `mov bx, 3` then a jump into 0x46's body.

        Without following the jump it would be unnamed, so this pins the hop.
        """
        name, _ = pcode._handler_semantics(self.runtime, self._handler(3 * 256 + 0x69))
        self.assertEqual(name, "STORE_VARIANT_PUSH_ADDRESS")

    def test_the_error_stub_is_never_named(self):
        """Undefined opcodes point at the error stub and must stay unnamed."""
        stub = int(self.summary["undefined_handler_va"], 16)
        name, _ = pcode._handler_semantics(self.runtime, stub)
        self.assertIsNone(name)

    def test_unmatched_blocks_stay_unnamed_rather_than_guessed(self):
        """Most of the table is not named, and that is the intended behaviour."""
        named = self.summary["opcodes_with_semantics"]
        defined = self.summary["defined_opcodes"]
        self.assertGreater(named, 220, "the classifier should name a real subset")
        self.assertLess(named, defined // 2,
                        "naming half the table would mean the shapes are too loose")

    def test_a_handler_that_calls_a_helper_is_not_given_a_shape_name(self):
        """The helper name wins, because a wrong name is worse than none.

        `__vbaVarCat`'s handler opens with exactly the three instructions of the
        plain address-push shape and then continues into its call. Matching on that
        prefix labelled 277 instructions of one procedure `PUSH_LOCAL_ADDRESS` when
        they are concatenations -- a reader would have trusted it.
        """
        for entry in self.summary_entries:
            if entry.get("calls"):
                self.assertIsNone(entry.get("semantics"),
                                  "opcode %d calls %s but also carries a shape name"
                                  % (entry["index"], entry["calls"]))

    def test_the_summary_declares_what_the_names_are(self):
        self.assertIn("semantics_note", self.summary)
        self.assertIn("handler", self.summary["semantics_note"])


class SemanticsOnADecodedProcedure(unittest.TestCase):
    def setUp(self):
        if not os.path.exists(TARGET):
            self.skipTest("WNL-T2-077 corpus not present")
        if _runtime() is None:
            self.skipTest("MSVBVM60.DLL not installed on this machine")
        result = json.loads(pcode.vb6_pcode(
            path=TARGET, operation="procedure",
            descriptor_address=SUB_MAIN_DESCRIPTOR,
            max_instructions=6000, max_chars=4_000_000))
        self.instructions = [i for i in (result.get("instructions") or [])
                             if isinstance(i, dict)]
        self.result = result

    def test_the_procedure_still_decodes_as_before(self):
        """The addition must not disturb the decode it annotates."""
        self.assertEqual(self.result.get("stop_reason"), "END_OF_PROCEDURE")
        self.assertGreater(len(self.instructions), 1900)

    def test_most_instructions_now_carry_a_meaning(self):
        covered = [i for i in self.instructions
                   if i.get("semantics") or i.get("calls") or i.get("calls_runtime")]
        share = len(covered) / len(self.instructions)
        self.assertGreater(share, 0.85,
                           "semantics plus helper names should cover most of a real procedure")

    def test_a_specific_instruction_is_named_correctly(self):
        """0x403007 calls Hex$ through the literal table; 0x402fff stores 667."""
        by_address = {i["address"]: i for i in self.instructions}
        call = by_address.get("0x403007")
        self.assertIsNotNone(call)
        self.assertEqual(call.get("semantics"), "CALL_THROUGH_LITERAL")
        self.assertEqual(call.get("calls_runtime"), "rtcHexVarFromVar")

    def test_unnamed_instructions_omit_the_field_entirely(self):
        """Absence is expressed by omission, not by a null or a placeholder."""
        for insn in self.instructions:
            if "semantics" in insn:
                self.assertTrue(insn["semantics"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
