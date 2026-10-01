"""Canonical evidence-guard checks live in claim_guard, not teacher.py.

Ported from the upstream development repo: one test method,
``test_teacher_has_no_unreachable_evidence_guard_body``, was removed here
because it read ``teacher.py``'s source text directly off disk to assert a
structural property of that file -- ``teacher.py`` is an upstream,
project-specific orchestration file that is not part of this package, so the
assertion has no target here. Every other test in this file exercises
``claim_guard`` itself and is unaffected.
"""
from __future__ import annotations

import unittest

from liebert_re.evidence.claim_guard import claim_guard_issues


class ClaimGuardCanonicalTests(unittest.TestCase):
    def test_hex_and_line_references_require_evidence(self):
        evidence = "kernel32.dll!CreateFileW\n1500: mov eax, 0x401000\n"
        self.assertTrue(claim_guard_issues("PROVEN at 0x401000", ""))
        self.assertFalse(claim_guard_issues("PROVEN at 0x401000", evidence))
        self.assertTrue(claim_guard_issues("see lines 1500-1520", evidence))
        self.assertFalse(claim_guard_issues("see lines 1500", evidence))

    def test_import_absence_english_and_turkish_conflict(self):
        evidence = "kernel32.dll!CreateFileW"
        self.assertTrue(claim_guard_issues("does not import CreateFileW", evidence))
        self.assertTrue(claim_guard_issues("CreateFileW import edilmemis", evidence))
        self.assertFalse(claim_guard_issues("CreateFileW is imported", evidence))

    def test_negative_claim_requires_cautious_language(self):
        self.assertTrue(claim_guard_issues("PROVEN network yok", ""))
        self.assertFalse(claim_guard_issues("UNKNOWN: NO EVIDENCE OBSERVED for network", ""))


if __name__ == "__main__":
    unittest.main()
