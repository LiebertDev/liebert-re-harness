"""Fingerprints that must hold unchanged across the package move.

Both exist because a layout change can break a guarantee while the suite stays
green: nothing fails loudly, the protection just quietly stops applying.
"""
import hashlib
import importlib
import subprocess
import sys
from pathlib import Path

from tests import conftest

import liebert_re.report.tool_families as tool_families

# Every module that owns an EVIDENCE directory. The set is the pin: adding a
# module here is the reviewed edit that says conftest is expected to redirect
# it during tests. The count is deliberately not in the test name -- the set
# below is what must be read and edited, and a number in the name only
# duplicates it.
EVIDENCE_OWNERS = {
    "liebert_re.dynamic.apimonitor", "liebert_re.dynamic.lab_gate", "liebert_re.tools.binary", "liebert_re.tools.capa",
    "liebert_re.tools.die", "liebert_re.tools.generic_static_probe", "liebert_re.tools.ghidra",
    "liebert_re.tools.ida",
    "liebert_re.tools.pe_sieve", "liebert_re.tools.rizin", "liebert_re.recover.emulate",
    "liebert_re.tools.upx", "liebert_re.tools.yara_x",
}


def test_exactly_the_declared_evidence_owners_resolve_under_the_real_ledger():
    # If a module's EVIDENCE stopped resolving under <repo>/dataset/evidence,
    # conftest would stop redirecting it per test and tests would write against
    # the real ledger with no failure. Uses conftest's own classifier.
    for name in EVIDENCE_OWNERS:
        importlib.import_module(name)
    owners = {m.__name__ for m, _ in conftest._evidence_owning_modules()}
    assert owners == EVIDENCE_OWNERS
    # conftest redirects each module's live EVIDENCE during a test, so read the
    # true import-time value in a fresh interpreter.
    code = (
        "import importlib, sys; "
        "[print(n, importlib.import_module(n).EVIDENCE.resolve()) for n in sys.argv[1:]]"
    )
    out = subprocess.run(
        [sys.executable, "-c", code, *sorted(EVIDENCE_OWNERS)],
        cwd=conftest.REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert len(out) == len(EVIDENCE_OWNERS)
    for line in out:
        name, _, path = line.partition(" ")
        assert conftest.REAL_EVIDENCE_ROOT in Path(path).parents, name


def test_published_tool_name_set_is_unchanged():
    """The public (non-underscore) top-level function names must stay as pinned.

    A change is legitimate only when public functions are deliberately added or
    removed; private ``_helpers`` do not move the digest. History of past moves:
    docs/PUBLISHED_SURFACE_HISTORY.md. Recompute with
    sha256(repr(sorted(public names)).encode()).
    """
    public = sorted(
        n for n in tool_families._locally_defined_tool_names() if not n.startswith("_")
    )
    digest = hashlib.sha256(repr(public).encode()).hexdigest()
    assert digest == "4a7f083f2be04f876e1f6d2af52b7a0e8783be191d7333617c64a6daf4c38d64"


def test_the_imported_package_is_this_checkout():
    # A stale editable install elsewhere on the machine can shadow the checkout
    # when the working directory is not the repo root; the suite would then
    # measure the wrong code without failing. Root comes from conftest.
    import liebert_re

    root = conftest.REPO_ROOT
    actual = Path(liebert_re.__file__).resolve()
    assert root in actual.parents, (
        f"liebert_re was imported from {actual}, expected a path under {root}. "
        "Another installation is probably shadowing this checkout."
    )
