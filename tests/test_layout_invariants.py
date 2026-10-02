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
    "liebert_re.dynamic.apimonitor", "liebert_re.tools.binary", "liebert_re.tools.capa",
    "liebert_re.tools.die", "liebert_re.tools.ida", "liebert_re.tools.pe_sieve", "liebert_re.tools.rizin",
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
    # Must stay identical across the package move. A change is only legitimate
    # when public functions are deliberately added or removed.
    #
    # Updated once since: liebert_re/tools/die.py gained the rest of what diec.exe
    # exposes (die_entropy, die_file_info, die_format_check, die_hashes,
    # die_structures, die_struct_raw, die_database_info, die_status) alongside the
    # existing die_identify, which previously used one flag (-j) of the tool's real
    # surface. All eight are registered in tool_families.FAMILIES["native"], and cli.py gained
    # the `die`/`diestatus` commands that reach them.
    #
    # Updated again: liebert_re/tools/capa.py wraps capa (capa_analyze was already
    # a FAMILIES name with no implementation here; capa_status is new), reached from
    # the CLI as `capa` and `capastatus`.
    #
    # Updated again: liebert_re/tools/ida.py wraps IDA Pro's headless batch mode. The public
    # functions added on purpose are ida_query (already a FAMILIES name with no implementation
    # here) and ida_status (new); the CLI reaches them as `ida` and `idastatus` through the
    # handlers _ida and _ida_status in cli.py. The set pinned below counts every top-level
    # function name, private helpers included, so the module's own underscore helpers moved
    # the digest too; only the two public names are a claim about the published surface.
    # The IDAPython worker it drives is a data file (ida_scripts/query_program.idapy), not a
    # module, so it adds no names here.
    #
    # Updated again: liebert_re/tools/rizin.py gained the rz-bin reads. The public functions
    # added on purpose are rz_bin_imports, rz_bin_sections, rz_bin_headers, rz_bin_relocations
    # and rz_bin_status, registered in tool_families.FAMILIES["native"]; the CLI reaches them as
    # `rzbin` and `rzbinstatus`. The shared runner is a private class (_RzBin) rather than
    # top-level functions, so no underscore helper joined the pinned set.
    #
    # Updated again: liebert_re/recover/vex.py gained one top-level helper on purpose,
    # _run_with_faulthandler_off. It is the single shared copy of the faulthandler-off-around-a-call
    # logic that self_check uses around Uc.mem_map and that tests/test_vex_layer.py reuses; it is
    # private and not a published tool, and it is a top-level def (not nested) so the pin counts it.
    #
    # Updated again: liebert_re/tools/rizin.py gained FLIRT signature matching done by rizin
    # itself. The public functions added on purpose are rizin_flirt_match (sigdb, `Fa`),
    # rizin_flirt_match_file (one .sig/.pat file, `Fs`) and rizin_flirt_inventory (`Fl`),
    # registered in tool_families.FAMILIES["native"]; the CLI reaches them as `flirt` and
    # `flirtinventory`. The shared runner is the private class _RzFlirt, so no underscore
    # helper joined the pinned set.
    #
    # Updated again: liebert_re/tools/pe_sieve.py wraps pe-sieve, the scan of ONE running process the
    # caller started, by PID. The public functions added on purpose are pe_sieve_scan (PID required,
    # scan only, no dump switch ever passed) and pe_sieve_status (zero arguments), registered in
    # tool_families.FAMILIES["dynamic"]; the CLI reaches them as `sieve` and `sievestatus`. The
    # scanner helpers live in the private class _PeSieve; the only other names that joined the
    # pinned set are the two CLI handlers in liebert_re/cli.py, _sieve and _sieve_status.
    digest = hashlib.sha256(
        repr(sorted(tool_families._locally_defined_tool_names())).encode()
    ).hexdigest()
    assert digest == "1d053b44353e97d9bcb51cf31390086519d8e65eafda93535354e4bb1f91d30b"
