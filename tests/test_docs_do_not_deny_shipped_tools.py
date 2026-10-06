"""A doc that says a capability does not exist must not do so once the tool is defined in code.

This catches one error class: the "missing capability" claim that outlived the code that
contradicted it. The harm is the user never trying a tool that works. It is the opposite of
overclaiming, and nothing else in the suite checks for it.

DENIALS is deliberately NARROW: tool name -> regular expressions that match a sentence in
``docs/CAPABILITIES_AND_LIMITS.md`` denying that tool's capability. It is not a natural-language
checker and it only knows what is listed. Extend it when a tool lands, adding the denial wording
the docs used before; a longer table is the intended direction. It is not a ``KNOWN_*``
allowlist, and growing it is good.

Both tables below are NARROW by design, and the narrowness is a known weakness, not a feature:
a sentence this checker does not know passes unseen. A table that grows is good; a table that
shrinks, or a pattern loosened until it no longer matches the wording it was written for, is bad.
Removing an entry needs a reason in the commit message.

A second shape of error is covered by ABSENCES: the denial is not about the tool but about a
gap IN ANOTHER tool, and the tool that closes the gap is the one that shipped. "ioctl_control_code_decode
has no feeder in this package" says nothing against ioctl_control_code_decode; it denies that
ioctl_candidate_scan exists. DENIALS, keyed by the tool a sentence is about, cannot see that.
ABSENCES is keyed by the tool that FILLS the gap, and its patterns match wording that states a
gap ("no feeder", "nothing in the package produces its input").

Scope: ``docs/CAPABILITIES_AND_LIMITS.md`` (DENIALS), ``README.md`` (README_DENIALS) and every
``.claude/agents/*.md`` agent prompt (AGENT_DENIALS). No other file is read. README_DENIALS patterns stay inside one table row ([^|]*) so a denial about one
tool cannot be matched against another tool's row.

A tool counts as shipped when ``tool_families._locally_defined_tool_names()`` contains it.
Patterns run on the document with whitespace collapsed, so line wrapping cannot hide a sentence.
"""
import re
import unittest
from pathlib import Path

from liebert_re.report import tool_families

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "CAPABILITIES_AND_LIMITS.md"
README = ROOT / "README.md"
AGENT_PROMPTS = sorted((ROOT / ".claude" / "agents").glob("*.md"))

_HEADLINE = r"nothing here analyses a kernel-mode binary's dispatch table"
_NO_MODULE = r"No module parses a driver's dispatch table"

DENIALS = {
    "driver_major_function_scan": (_HEADLINE, _NO_MODULE),
    "ioctl_control_code_decode": (r"nothing here analyses[^.]*IOCTLs", r"No module parses[^.]*control-code definitions"),
    "kernel_callback_registrations": (r"nothing here analyses[^.]*callbacks", r"No module parses[^.]*callback registrations"),
    "rip_relative_iat_scan": (r"No module parses[^.]*any other kernel-specific structure",),
}

# Wording that states an absence which a shipped tool closes. Key: the tool that closes it.
ABSENCES = {
    "ioctl_candidate_scan": (
        r"\bno feeder\b",
        r"Nothing in the package produces its input",
        r"which no operation does for this",
        r"\bhas no [^.|]{0,60}\bin this package",
    ),
}

README_DENIALS = {
    "kernel_triage": (r"`kernel_triage`:[^|]*not wired to the CLI",),
    "ghidra_program_facts": (r"`ghidra_status`:[^|]*not wired to the CLI",),
}

# Agent prompts. A prompt that tells a department a shipped tool is missing sends it down the
# wrong path, so the same denial shapes are checked per prompt.
AGENT_DENIALS = {
    "ida_query": (r"`ida_query`[^;]{0,200}no implementation",),
    "kernel_callback_registrations": (r"every `kernel_\*` name except `kernel_triage`(?! and `kernel_callback_registrations`)",),
    "driver_major_function_scan": (r"members are the generic `tool_missing` sentinel and `kernel_triage`",
                                   r"never a proof; it reads no dispatch table, IOCTL or callback"),
}


README_ABSENCES = ABSENCES


def _agent_offences():
    defined = tool_families._locally_defined_tool_names()
    found = []
    for doc in AGENT_PROMPTS:
        text = " ".join(doc.read_text(encoding="utf-8").split())
        found += [f"{doc.name} {tool}: {pat!r}" for tool, pats in AGENT_DENIALS.items() if tool in defined
                  for pat in pats if re.search(pat, text)]
    return found


def _offences(doc, table):
    text = " ".join(doc.read_text(encoding="utf-8").split())
    defined = tool_families._locally_defined_tool_names()
    return [f"{doc.name} {tool}: {pat!r}" for tool, pats in table.items() if tool in defined
            for pat in pats if re.search(pat, text)]


class DocsDoNotDenyShippedTools(unittest.TestCase):
    def test_denial_of_a_defined_tool_is_a_failure(self):
        text = " ".join(DOC.read_text(encoding="utf-8").split())
        defined = tool_families._locally_defined_tool_names()
        offences = []
        for tool, patterns in DENIALS.items():
            if tool not in defined:
                continue
            for pat in patterns:
                if re.search(pat, text):
                    offences.append(f"{tool}: {pat!r}")
        self.assertEqual(offences, [], "docs/CAPABILITIES_AND_LIMITS.md denies a tool that exists in code")

    def test_an_absence_closed_by_a_defined_tool_is_a_failure(self):
        self.assertEqual(_offences(DOC, ABSENCES), [], "docs state a gap that a tool in code closes")

    def test_readme_states_no_absence_closed_by_a_defined_tool(self):
        self.assertEqual(_offences(README, README_ABSENCES), [], "README.md states a gap that a tool in code closes")

    def test_absence_patterns_still_match_the_old_wording(self):
        # Guards the table itself: each pattern must match the sentence it was written against.
        old = ("`ioctl_control_code_decode` splits caller-supplied `CTL_CODE` integers into fields and has no feeder in this "
               "package. Nothing in the package produces its input; disassembly, which no operation does for this.")
        for pat in ABSENCES["ioctl_candidate_scan"]:
            self.assertRegex(old, pat)

    def test_absence_patterns_do_not_match_legitimate_sentences(self):
        # Narrowness check: ordinary negative statements that are not a gap closed by a tool must stay allowed.
        fine = ("This does not prove an IOCTL. No disassembler is used by the byte-pattern scan. "
                "The scan has no boolean field. There is no CLI wiring for this.")
        for pat in ABSENCES["ioctl_candidate_scan"]:
            self.assertIsNone(re.search(pat, fine), pat)

    def test_readme_does_not_deny_a_defined_tool(self):
        self.assertEqual(_offences(README, README_DENIALS), [], "README.md denies a tool that exists in code")

    def test_agent_prompts_do_not_deny_a_defined_tool(self):
        self.assertTrue(AGENT_PROMPTS, "no .claude/agents/*.md found; the scan would check nothing")
        self.assertEqual(_agent_offences(), [], ".claude/agents prompt denies a tool that exists in code")

    def test_agent_denial_patterns_still_match_the_old_wording(self):
        old = {
            "ida_query": "`ghidra_query`, `ida_query` and `ilspy` are names in `x.py`'s manifest with no implementation here",
            "kernel_callback_registrations": "and every `kernel_*` name except `kernel_triage`) have no implementation",
            "driver_major_function_scan": "members are the generic `tool_missing` sentinel and `kernel_triage` (static; never a proof; it reads no dispatch table, IOCTL or callback)",
        }
        for tool, pats in AGENT_DENIALS.items():
            for pat in pats:
                self.assertRegex(old[tool], pat)

    def test_every_listed_tool_is_defined(self):
        # A renamed or removed tool must not leave a dead row that silently checks nothing.
        defined = tool_families._locally_defined_tool_names()
        self.assertEqual([t for t in (*DENIALS, *README_DENIALS, *AGENT_DENIALS, *ABSENCES) if t not in defined], [])


if __name__ == "__main__":
    unittest.main()
