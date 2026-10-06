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
    assert body["unimplemented_truncated"] is False


def test_named_published_pair_is_unchanged():
    families = _capabilities()["families"]
    assert set(families) == set(FAMILIES)
    for family, names in FAMILIES.items():
        assert families[family] == [len(names), len(published_tools(family))]


def _expected_missing():
    return {f: sorted(set(n) - published_tools(f)) for f, n in FAMILIES.items()
            if set(n) - published_tools(f)}


def test_unimplemented_total_counts_distinct_names_not_family_entries():
    body = _capabilities()
    missing = _expected_missing()
    distinct = {n for v in missing.values() for n in v}
    # Precondition: some name really is declared in more than one family, else
    # this test could not tell a distinct count from a summed one.
    assert sum(len(v) for v in missing.values()) > len(distinct)
    assert body["unimplemented_total"] == len(distinct)


def test_unimplemented_family_entries_is_the_per_family_sum():
    body = _capabilities()
    assert body["unimplemented_family_entries"] == sum(len(v) for v in _expected_missing().values())


def test_repeated_name_is_listed_in_every_family_that_declares_it():
    body = _capabilities()
    for family, names in _expected_missing().items():
        assert body["unimplemented"][family] == names
    repeated = {n for n in {x for v in _expected_missing().values() for x in v}
                if sum(n in v for v in _expected_missing().values()) > 1}
    assert repeated
    for n in repeated:
        declaring = {f for f, v in _expected_missing().items() if n in v}
        assert {f for f, v in body["unimplemented"].items() if n in v} == declaring


def test_shipped_tools_are_registered_in_their_family():
    # An orphan (defined here, named in no family) can never be routed to.
    assert "disassemble_pe_structured" in published_tools("native")
    assert "ioctl_candidate_scan" in published_tools("windows-kernel")
    assert "ida_query" in published_tools("windows-kernel")
    assert "ida_query" in published_tools("native")


def test_kernel_route_reaches_ida_query_and_keeps_the_roadmap_name():
    from liebert_re.report import tool_families as tf
    assert "ida_query" in tf.WINDOWS_KERNEL_PATH_ONLY_TOOLS
    assert "ioctl_candidate_scan" in tf.WINDOWS_KERNEL_COORDINATE_TOOLS
    assert "disassemble_pe_structured" in tf.NATIVE_PATH_ONLY_TOOLS
    assert "ghidra_query" in tf.FAMILIES["windows-kernel"]  # roadmap name stays by design


def test_native_core_tools_are_all_in_the_native_family():
    # tool_families.py claimed this invariant was "enforced by
    # test_native_tier_family_parity.py", a file that does not exist. The claim is
    # now true: NATIVE_DEEP_TOOLS is derived from FAMILIES["native"], so a core
    # name missing from that family would silently stop being recommended.
    from liebert_re.report import tool_families as tf
    assert tf._NATIVE_CORE_TOOL_NAMES <= tf.FAMILIES["native"], sorted(
        tf._NATIVE_CORE_TOOL_NAMES - tf.FAMILIES["native"]
    )
