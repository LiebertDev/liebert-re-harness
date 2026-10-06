"""A number written by hand in a doc that the code can measure must equal the measurement.

Counts such as "81 test files" were typed once and went stale without any test noticing
(the real figure had reached 106). This test pins each such number to a measurement.

Marker convention: the number is followed IMMEDIATELY by an HTML comment naming what it counts,
``106<!-- count:test_files -->``. The comment is invisible when the Markdown is rendered, so the
prose stays plain; there is no template engine and no generated text. A comment on the number
itself (not a table of expected values kept in this file) means the doc and its check cannot be
edited apart: change the number or the claim and the marker moves with it.

Keys in MEASURE are measured live. The key ``historic`` marks a number that deliberately records
a past state ("68 test files at that check"); it is exempt from measurement, and the exemption is
visible at the number. A bare "<N> test files / Python modules" with no marker is
a failure, so a new hand-typed count cannot slip in unchecked.

The CLI subcommand count and list are already checked by
``test_documented_cli_surface_equals_the_live_one`` in test_docs_do_not_deny_shipped_tools.py, whose regex
needs the number unmarked, so they are deliberately left out here. ``MarkersDoNotChangeWhatOtherDocTestsRead``
proves that no marker alters what that test (or any denial pattern) reads, so the two cannot collide again.

Historic documents: a file that records a past state puts ``<!-- count-gate: historic -->`` anywhere in itself;
the bare-count check then skips that file (its numbers are the record of that day). Marked counts are still measured.

Ownership: each measured fact is marked in exactly ONE file (``test_a_fact_is_marked_in_exactly_one_file``);
elsewhere the prose points at the owner instead of repeating the number. Owners: modules and test files in
docs/INSTALL.md (the "what is in the package" page), the windows-kernel family counts in
docs/CAPABILITIES_AND_LIMITS.md (where those tools are described), the evidence-directory owner count in README.md
(where the capability table names each tool). CI types no module count: the wheel job measures it.

Scope: ``README.md``, ``CONTRIBUTING.md`` and every ``docs/*.md``. Not covered, because they are
not measurable without running the suite: the collected-test totals in CAPABILITIES_AND_LIMITS.md
("2082 of 2155"). The spelled-out "ten" / "Eight" / "Nine" figures were measured and replaced by marked
digits or by prose that points at the owner.
"""
import pkgutil
import re
import unittest
from pathlib import Path

import liebert_re
from liebert_re.report import tool_families
from tests import test_docs_do_not_deny_shipped_tools as other

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]

MARKED = re.compile(r"(\d+)<!--\s*count:([a-z_]+)\s*-->")
# A count noun right after a bare number, with no marker: "81 test files", "68 Python modules".
# Narrowed to the two facts this gate owns: how many test files the repo has and how many Python
# modules the package has. "N test files" and "N Python modules" always mean those; a bare
# "N modules" counts only when the same phrase names the package ("modules in the `liebert_re/`
# package"). A number used in another sense ("41 modules of some other system") is not ours to police.
UNMARKED = re.compile(
    r"(?<![\w.])(\d+)(?!<!--)\s+(?:\*\*\s*)?"
    r"(?:test\s+files\b|Python\s+modules\b|modules\b(?=[^.\n]{0,40}`?liebert_re))")


# A document that records a past state (a slice log, an archived narrative) says so in the file
# itself, with this comment anywhere in it. Its UNMARKED figures are the record of that day, not a
# claim about today, so the "no bare count" check skips it. No file name is hard-coded here, and
# the exemption is visible in the file it applies to. Marked counts in it are still measured.
HISTORIC_FILE = re.compile(r"<!--\s*count-gate:\s*historic\s*-->")


def _bare_counts(text):
    """Bare (unmarked) count claims in ``text``; empty for a file that declares itself historic."""
    if HISTORIC_FILE.search(text):
        return []
    return [m.group(0) for line in text.splitlines() for m in UNMARKED.finditer(line)]


def _modules():
    # Same definition as the `package` job in ci.yml: every non-package module, cli and __main__ included.
    return len([m for m in pkgutil.walk_packages(liebert_re.__path__, "liebert_re.") if not m.ispkg])


def _evidence_owner_modules():
    # Modules that bind a module-level ``EVIDENCE = ... "dataset" ... "evidence" ...`` directory.
    # Read from source, not by import: several modules have optional native dependencies.
    pat = re.compile(r"^EVIDENCE\s*=.*dataset.*evidence", re.MULTILINE)
    return len([p for p in (ROOT / "liebert_re").rglob("*.py") if pat.search(p.read_text(encoding="utf-8"))])


MEASURE = {
    "test_files": lambda: len(list((ROOT / "tests").glob("test_*.py"))),
    "modules": _modules,
    "kernel_family_named": lambda: len(tool_families.FAMILIES["windows-kernel"]),
    "kernel_family_defined": lambda: len(tool_families.published_tools("windows-kernel")),
    "evidence_modules": _evidence_owner_modules,
}


class DocCountsMatchCode(unittest.TestCase):
    def _marked(self):
        for path in DOCS:
            text = path.read_text(encoding="utf-8")
            for m in MARKED.finditer(text):
                yield path.name, int(m.group(1)), m.group(2)

    def test_every_marked_count_equals_its_measurement(self):
        wrong = []
        for name, claimed, key in self._marked():
            if key == "historic":
                continue
            self.assertIn(key, MEASURE, f"{name}: unknown count key {key!r}; known: {sorted(MEASURE)}")
            actual = MEASURE[key]()
            if claimed != actual:
                wrong.append(f"{name}: says {claimed} for {key}, measured {actual}")
        self.assertFalse(wrong, "stale hand-written counts:\n" + "\n".join(wrong))

    def test_every_measured_key_is_used_somewhere(self):
        # Deleting the marker would otherwise silence the check without failing anything.
        used = {key for _, _, key in self._marked()}
        self.assertFalse(set(MEASURE) - used, f"no doc carries a marker for: {sorted(set(MEASURE) - used)}")

    def test_no_unmarked_count_of_a_measurable_thing(self):
        bare = []
        for path in DOCS:
            for claim in _bare_counts(path.read_text(encoding="utf-8")):
                bare.append(f"{path.name}: {claim!r}")
        self.assertFalse(bare, "hand-written count without a <!-- count:KEY --> marker:\n" + "\n".join(bare))

    def test_a_fact_is_marked_in_exactly_one_file(self):
        # One owner per measurable fact: a second copy is a second place to go stale (three merges
        # broke this gate twice, 107 -> 108 -> 109, because the figure lived in several files).
        owners = {}
        for name, _, key in self._marked():
            if key != "historic":
                owners.setdefault(key, set()).add(name)
        many = {k: sorted(v) for k, v in owners.items() if len(v) > 1}
        self.assertFalse(many, f"a measured count is stated in more than one file: {many}")

    def test_historic_narrative_is_not_policed_but_a_live_wrong_marker_is(self):
        history = "<!-- count-gate: historic -->\nAt that check: 73 modules in the `liebert_re/` package, 41 test files.\n"
        self.assertEqual(_bare_counts(history), [])
        live = "At this check: 73 modules in the `liebert_re/` package, 41 test files.\n"
        self.assertEqual(len(_bare_counts(live)), 2)
        # A historic file's MARKED numbers are still measured (the marker check ignores the flag),
        # so only a wrong marked number in a live or historic doc fails test_every_marked_count_...

    def test_unmarked_pattern_only_claims_what_the_gate_owns(self):
        for text in ("73 modules in the `liebert_re/` package", "109 test files", "73 Python modules",
                     "81 **test files"):
            self.assertIsNotNone(UNMARKED.search(text), text)
        for text in ("41 modules of an unrelated system", "the 41 modules in that vendor's installer",
                     "73<!-- count:modules --> Python modules", "109<!-- count:test_files --> test files"):
            self.assertIsNone(UNMARKED.search(text), text)


class MarkersDoNotChangeWhatOtherDocTestsRead(unittest.TestCase):
    """A marker is invisible in rendered Markdown but not to a regex. It once sat between a number and
    "subcommands" and broke the CLI surface test. Every other test that reads these docs must see
    the same thing with the markers present as with them stripped."""

    @staticmethod
    def _collapsed(path):
        return " ".join(path.read_text(encoding="utf-8").split())

    def test_cli_claim_is_unchanged_by_markers(self):
        for path in DOCS:
            raw = self._collapsed(path)
            plain = MARKED.sub(r"\1", raw)
            a, b = other.CLI_CLAIM.search(raw), other.CLI_CLAIM.search(plain)
            self.assertEqual(a and a.groups(), b and b.groups(), path.name)

    def test_denial_patterns_hit_the_same_with_or_without_markers(self):
        tables = (other.DENIALS, other.ABSENCES, other.README_DENIALS, other.README_ABSENCES)
        for path in DOCS:
            raw = self._collapsed(path)
            plain = MARKED.sub(r"\1", raw)
            for table in tables:
                for tool, pats in table.items():
                    for pat in pats:
                        self.assertEqual(bool(re.search(pat, raw)), bool(re.search(pat, plain)),
                                         f"{path.name} {tool} {pat!r}")

    def test_the_guard_can_fail(self):
        # Reproduce the original breakage on a sample: a marker in front of "subcommands".
        sample = "`liebert-re` CLI (`a`, `b`, 2<!-- count:x --> subcommands"
        a, b = other.CLI_CLAIM.search(sample), other.CLI_CLAIM.search(MARKED.sub(r"\1", sample))
        self.assertNotEqual(a and a.groups(), b and b.groups())


if __name__ == "__main__":
    unittest.main()
