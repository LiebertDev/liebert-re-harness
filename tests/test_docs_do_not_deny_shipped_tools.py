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

Scope: ``docs/CAPABILITIES_AND_LIMITS.md`` (DENIALS) and ``README.md`` (README_DENIALS). No other
file is read. Agent prompts are not scanned on purpose: they are development scaffolding kept out
of the repository, so their drift risk left with them. README_DENIALS patterns stay inside one table row ([^|]*) so a denial about one
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

_HEADLINE = r"nothing here analyses a kernel-mode binary's dispatch table"
_NO_MODULE = r"No module parses a driver's dispatch table"

DENIALS = {
    "driver_major_function_scan": (_HEADLINE, _NO_MODULE),
    "ioctl_control_code_decode": (r"nothing here analyses[^.]*IOCTLs", r"No module parses[^.]*control-code definitions"),
    "kernel_callback_registrations": (r"nothing here analyses[^.]*callbacks", r"No module parses[^.]*callback registrations"),
    "rip_relative_iat_scan": (r"No module parses[^.]*any other kernel-specific structure",),
    "pe_runtime_functions": (r"No exception/unwind data parser", r"the PE surface does not cover[^.]*exception/unwind data"),
    "pe_function_extent": (r"no function-boundary recovery for stripped x64 images",),
    "pe_trailing_data": (r"does not (?:report|cover)[^.]*(?:overlay|data past the end of the last section)",
                         r"No module reports[^.]*(?:overlay|trailing data)"),
    "emulate_range": (r"No range emulation, tracing or slicing ships", r"No bounded code-range emulation, so nothing can",
                      r"Unicorn is imported only by `recover/vex\.py`"),
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
    "pe_function_extent": (r"Function-boundary recovery from exception-directory unwind data[^|]{0,80}Not here",),
    "emulate_range": (r"it cannot emulate a code range, and",),
}

README_ABSENCES = ABSENCES


# The claim test_documented_cli_surface_equals_the_live_one reads. Public so that
# test_docs_counts_match_code.py can prove its count markers never change what this regex matches.
CLI_CLAIM = re.compile(r"`liebert-re` CLI \((.*?)(\d+) subcommands")


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

    def test_denial_patterns_still_match_the_old_wording(self):
        # Guards DENIALS and README_DENIALS: each new entry must match the denial it replaced.
        old_doc = ("No exception/unwind data parser, so no function-boundary recovery for stripped x64 images. "
                   "Partial: the PE surface does not cover delay imports, base relocations, the rich header "
                   "or exception/unwind data.")
        for tool in ("pe_runtime_functions", "pe_function_extent"):
            self.assertTrue(any(re.search(p, old_doc) for p in DENIALS[tool]), tool)
        old_readme = ("Function-boundary recovery from exception-directory unwind data, prologue scanning, "
                      "and engine cross-check. Not here.")
        for pat in README_DENIALS["pe_function_extent"]:
            self.assertRegex(old_readme, pat)
        old_emulation = ("Unicorn is imported only by `recover/vex.py`, which corrects AVX instruction execution inside an "
                         "emulation session someone else sets up. No range emulation, tracing or slicing ships. "
                         "- No bounded code-range emulation, so nothing can exercise a routine in isolation.")
        for pat in DENIALS["emulate_range"]:
            self.assertRegex(old_emulation, pat)
        self.assertRegex("facts and decompile selected functions through Ghidra headless, it cannot emulate a code range, and when it guesses",
                         README_DENIALS["emulate_range"][0])
        old_trailing = ("No module reports the overlay. The PE surface does not report data past the end "
                        "of the last section.")
        for pat in DENIALS["pe_trailing_data"]:
            self.assertRegex(old_trailing, pat)

    def test_absence_patterns_do_not_match_legitimate_sentences(self):
        # Narrowness check: ordinary negative statements that are not a gap closed by a tool must stay allowed.
        fine = ("This does not prove an IOCTL. No disassembler is used by the byte-pattern scan. "
                "The scan has no boolean field. There is no CLI wiring for this.")
        for pat in ABSENCES["ioctl_candidate_scan"]:
            self.assertIsNone(re.search(pat, fine), pat)

    def test_readme_does_not_deny_a_defined_tool(self):
        self.assertEqual(_offences(README, README_DENIALS), [], "README.md denies a tool that exists in code")

    def test_documented_cli_surface_equals_the_live_one(self):
        # Exists because a hand-maintained list of a machine-knowable fact is a guarantee nobody is keeping.
        import argparse
        from liebert_re import cli
        parser = cli._build_parser()
        live = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)).choices
        text = " ".join(DOC.read_text(encoding="utf-8").split())
        m = CLI_CLAIM.search(text)
        self.assertIsNotNone(m, "the CLI list in CAPABILITIES_AND_LIMITS.md was not found")
        documented = re.findall(r"`([a-z0-9_-]+)`", m.group(1))
        self.assertEqual(sorted(set(documented)), sorted(live), "documented subcommands differ from the live CLI")
        self.assertEqual(len(documented), len(set(documented)), "a subcommand is listed twice")
        self.assertEqual(int(m.group(2)), len(live), "documented subcommand count differs from the live CLI")

    def test_every_listed_tool_is_defined(self):
        # A renamed or removed tool must not leave a dead row that silently checks nothing.
        defined = tool_families._locally_defined_tool_names()
        self.assertEqual([t for t in (*DENIALS, *README_DENIALS, *ABSENCES) if t not in defined], [])


if __name__ == "__main__":
    unittest.main()
