"""``capabilities`` names the routing-manifest entries this package does not implement.

``FAMILIES`` is a routing manifest; a name with no local definition is a roadmap
entry (``liebert_re/report/tool_families.py`` docstring). The command used to
report only ``[named, implemented]`` counts, so the missing names were hidden.
"""
import json
import subprocess
import sys
from pathlib import Path

from liebert_re.report.tool_families import FAMILIES, published_tools

ROOT = Path(__file__).resolve().parent.parent


def _capabilities():
    r = subprocess.run([sys.executable, "-m", "liebert_re", "capabilities"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_known_missing_names_appear_per_family():
    body = _capabilities()
    assert "ghidra_query" not in published_tools("windows-kernel")  # precondition: really missing
    assert "emulate_binary" not in published_tools("emulation")
    assert "ghidra_query" in body["unimplemented"]["windows-kernel"]
    assert "emulate_binary" in body["unimplemented"]["emulation"]
    assert "kernel_triage" not in body["unimplemented"]["windows-kernel"]  # implemented


def test_unimplemented_lists_are_exactly_named_minus_published():
    body = _capabilities()
    for family, names in FAMILIES.items():
        assert set(body["unimplemented"].get(family, [])) == set(names) - published_tools(family)
    assert set(body["unimplemented"]) <= set(FAMILIES)
    assert body["unimplemented_total"] == sum(len(v) for v in body["unimplemented"].values())
    assert body["unimplemented_truncated"] is False


def test_named_published_pair_is_unchanged():
    families = _capabilities()["families"]
    assert set(families) == set(FAMILIES)
    for family, names in FAMILIES.items():
        assert families[family] == [len(names), len(published_tools(family))]
