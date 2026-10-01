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

EVIDENCE_OWNERS = {
    "liebert_re.dynamic.apimonitor", "liebert_re.tools.binary", "liebert_re.tools.die",
    "liebert_re.tools.rizin", "liebert_re.tools.upx", "liebert_re.tools.yara_x",
}


def test_exactly_the_six_evidence_owners_resolve_under_the_real_ledger():
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
    # Must stay identical across the package move. A change is only legitimate
    # when public functions are deliberately added or removed.
    #
    # Updated once since: liebert_re/tools/die.py gained the rest of what diec.exe
    # exposes (die_entropy, die_file_info, die_format_check, die_hashes,
    # die_structures, die_struct_raw, die_database_info, die_status) alongside the
    # existing die_identify, which previously used one flag (-j) of the tool's real
    # surface. All eight are registered in tool_families.FAMILIES["native"], and cli.py gained
    # the `die`/`diestatus` commands that reach them.
    digest = hashlib.sha256(
        repr(sorted(tool_families._locally_defined_tool_names())).encode()
    ).hexdigest()
    assert digest == "0707bac651d49fdaf111aadc43703cfbc2a66ad28984d58ab5fa4146f80ddf9e"
