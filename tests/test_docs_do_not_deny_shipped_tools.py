"""A doc that says a capability does not exist must not do so once the tool is defined in code.

This catches one error class: the "missing capability" claim that outlived the code that
contradicted it. The harm is the user never trying a tool that works. It is the opposite of
overclaiming, and nothing else in the suite checks for it.

DENIALS is deliberately NARROW: tool name -> regular expressions that match a sentence in
``docs/CAPABILITIES_AND_LIMITS.md`` denying that tool's capability. It is not a natural-language
checker and it only knows what is listed. Extend it when a tool lands, adding the denial wording
the docs used before; a longer table is the intended direction. It is not a ``KNOWN_*``
allowlist, and growing it is good.

Scope: ``docs/CAPABILITIES_AND_LIMITS.md`` (DENIALS) and ``README.md`` (README_DENIALS). No other
file is read. README_DENIALS patterns stay inside one table row ([^|]*) so a denial about one
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
}

README_DENIALS = {
    "kernel_triage": (r"`kernel_triage`:[^|]*not wired to the CLI",),
    "ghidra_program_facts": (r"`ghidra_status`:[^|]*not wired to the CLI",),
}


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

    def test_readme_does_not_deny_a_defined_tool(self):
        self.assertEqual(_offences(README, README_DENIALS), [], "README.md denies a tool that exists in code")

    def test_every_listed_tool_is_defined(self):
        # A renamed or removed tool must not leave a dead row that silently checks nothing.
        defined = tool_families._locally_defined_tool_names()
        self.assertEqual([t for t in (*DENIALS, *README_DENIALS) if t not in defined], [])


if __name__ == "__main__":
    unittest.main()
