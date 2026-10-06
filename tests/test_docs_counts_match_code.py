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
needs the number unmarked, so they are deliberately left out here.

Scope: ``README.md``, ``CONTRIBUTING.md`` and every ``docs/*.md``. Not covered, because they are
not measurable without running the suite or are not digits: the collected-test totals in
CAPABILITIES_AND_LIMITS.md ("2082 of 2155"), and the spelled-out "ten" / "Eight" / "Nine" figures.
"""
import pkgutil
import re
import unittest
from pathlib import Path

import liebert_re
from liebert_re.report import tool_families

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]

MARKED = re.compile(r"(\d+)<!--\s*count:([a-z_]+)\s*-->")
# A count noun right after a bare number, with no marker: "81 test files", "68 Python modules".
UNMARKED = re.compile(
    r"(?<![\w.])(\d+)(?!<!--)\s+(?:\*\*\s*)?(?:Python\s+)?(?:test\s+files|modules)\b")


def _modules():
    # Same definition as the `package` job in ci.yml: every non-package module, cli and __main__ included.
    return len([m for m in pkgutil.walk_packages(liebert_re.__path__, "liebert_re.") if not m.ispkg])


MEASURE = {
    "test_files": lambda: len(list((ROOT / "tests").glob("test_*.py"))),
    "modules": _modules,
    "kernel_family_named": lambda: len(tool_families.FAMILIES["windows-kernel"]),
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
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for m in UNMARKED.finditer(line):
                    bare.append(f"{path.name}:{line_no}: {m.group(0)!r}")
        self.assertFalse(bare, "hand-written count without a <!-- count:KEY --> marker:\n" + "\n".join(bare))


if __name__ == "__main__":
    unittest.main()
