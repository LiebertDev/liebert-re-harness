"""Repo-wide pytest configuration.

The single job of this file: make it structurally impossible for an
ordinary ``pytest`` run to deposit files into the real evidence ledger
(``dataset/evidence/``) that this product ships as proof of real analysis
runs.

Incident this closes: ``tests/test_tools_unpack.py`` monkeypatches only the
guest (Hyper-V) layer of ``tools_unpack.unpack_iat_rebuild`` -- never its
file-write side. That module's ``EVIDENCE`` directory, like every other
``tools_*.py`` adapter's, is a hardcoded path computed once at import time
with no test-time override, so every "fail-closed contract" test that
reaches the write calls (``EVIDENCE / f"{run_tag}_unlicense_stdout.txt"``,
``EVIDENCE / f"{run_tag}_{digest}_unpacked.exe"``) deposited a real file into
``dataset/evidence/unpack/`` -- roughly 250 of them, all built from the same
fabricated guest response and the same fixture file
(``.venv/Lib/site-packages/setuptools/cli-64.exe``), indistinguishable at a
glance from a genuine ``unlicense`` run recorded in the ledger.

Mechanism: every already-imported module that owns a module-level
``EVIDENCE`` ``Path`` pointing inside the real ledger gets that attribute
redirected, for the duration of each test, to a fresh per-test scratch
directory (deleted again immediately after). This generalises the ad hoc
pattern
``tests/test_evidence_registration_more_tools.py`` already uses in one place
(``patch.object(tools_decompiler, "EVIDENCE", root)``) so every test gets it
automatically instead of each test author having to remember it -- and
covers any future ``tools_*.py`` adapter that follows the same
``EVIDENCE = APP_DIR / "dataset" / "evidence" / ...`` convention, by
attribute discovery rather than a hardcoded module name list.

Production runs (anything not executed under pytest) are entirely
unaffected: this file only loads when pytest collects the ``tests/``
package, and every module's ``EVIDENCE`` attribute keeps its real,
hardcoded default outside of a test.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

import liebert_re.workspace as tools_workspace

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_EVIDENCE_ROOT = (REPO_ROOT / "dataset" / "evidence").resolve()


@pytest.fixture(autouse=True)
def _reset_shared_tool_bus_call_budget():
    """``teacher.TOOL_BUS`` (``teacher.py``, module scope) is constructed
    exactly once per process, at ``import teacher`` time, with a
    ``ToolBudget(max_calls=200)`` -- a deliberate per-real-session guard
    against runaway tool usage. Its call/output counters
    (``ToolBus._calls``/``_output_chars``/``_per_tool``/``_status_counts``)
    live on that one long-lived instance and are never reset by anything,
    by design: in production, one process is one session, so "since this
    process started" and "since this session started" are the same thing.

    A pytest run breaks that equivalence: ``sys.modules`` caches ``teacher``
    for the WHOLE process, so every test that ever routes a real call through
    the shared bus (``mcp_server.build_server(...).handle_message(...)``,
    ``teacher.ask(...)``, or a direct ``teacher.TOOL_BUS.execute(...)``) adds
    to the SAME counters as every other such test in the same pytest
    process, in file/method order. Once the cumulative count anywhere in the
    suite reaches 200 -- trivially reached across a 2000+-test run with many
    real-tool-call tests -- every later call from ANY test, anywhere, silently
    gets back ``{"status": "BUDGET_EXHAUSTED", ...}`` instead of its real
    result, for the rest of the process. Measured live regression this
    fixture closes (reproduced by directly setting
    ``teacher.TOOL_BUS._calls = 999`` and re-running in-process):
    ``tests/test_mcp_server.py::MCPServerTests::test_out_of_scope_path_is_refused``,
    ``::MCPServerProfileTests::test_route_file_names_locked_tools_and_the_profile_to_unlock_them``,
    ``::RizinAndFabricationAuditExposureTests::test_rizin_status_callable_through_the_bus_and_agrees_with_registry``,
    ``::RizinAndFabricationAuditExposureTests::test_rizin_functions_callable_through_the_bus_on_a_real_binary``,
    ``::ToolIndexToolBusConsistencyTests::test_dynamic_lab_gate_never_authorizes_by_default_fail_closed``, and
    ``tests/test_phase4_offline_teacher.py::Phase4OfflineTeacherTests::test_fake_brain_runs_full_teacher_toolbus_evidence_flow``
    (the last as a ``KeyError`` on a field only the real payload carries,
    since ``BUDGET_EXHAUSTED``'s structured output has no ``driver_loaded``
    key at all) -- all six reproduced instantly and deterministically this
    way, matching every measured full-suite baseline's exact failure set,
    and all six pass alone precisely because a solo run never accumulates
    200 real calls first.

    Fix: reset the counters on the ONE shared instance before (and after,
    for a test that inspects them via ``teacher.TOOL_BUS.stats()`` after a
    later test already ran) every test -- restoring "one call site, one
    budget" isolation without touching the 200-call limit itself, which is
    correct production behaviour for a real session and stays completely
    untouched here. Looked up via ``sys.modules`` rather than ``import
    teacher`` so a test file that never needs ``teacher`` is not forced to
    pay its import cost or trigger its own import-time side effects."""
    def _reset():
        teacher_module = sys.modules.get("teacher")
        if teacher_module is None:
            return
        bus = getattr(teacher_module, "TOOL_BUS", None)
        if bus is None:
            return
        with bus._lock:
            bus._calls = 0
            bus._output_chars = 0
            bus._per_tool.clear()
            bus._status_counts.clear()

    _reset()
    yield
    _reset()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "spawns_real_subprocess_evidence_writer(reason): this test deliberately launches a "
        "real, separate OS process (its own Python interpreter, e.g. via subprocess.run) "
        "whose own normal evidence-adjacent activity is independent of this process's "
        "in-test monkeypatch redirection -- see the 'Known, deliberate narrowing' note on "
        "the redirect fixture below for exactly what this opts out of and why. Requires "
        "reason=... explaining why that subprocess's activity is legitimate here, not an "
        "escape; an empty/missing reason fails the test at setup.",
    )

# NOTE: this is deliberately NOT pytest's own ``tmp_path`` (which lives under
# the OS temp dir, outside the repo). Several tool adapters route the paths
# they build from ``EVIDENCE`` through ``tools_workspace.safe_path()``, which
# refuses anything outside ``tools_workspace.WORKSPACE_ROOT`` (the repo root,
# by default) with ``PATH_REFUSED`` -- redirecting to a truly external tmp
# dir would trade "writes the real ledger" for "breaks safe_path() gating
# tests" instead of actually fixing anything. Anchoring the scratch root
# inside the workspace keeps those tests meaningful while still keeping test
# output completely out of the real ``dataset/evidence/`` ledger.
#
# Process-scoped, not just test-scoped (added 2026-09-26 after a measured
# ``FileNotFoundError`` in ``tools_emulate_range.py``'s ``_run_worker_once``
# under concurrent test execution): pytest's ``tmp_path`` names are a
# sanitized-nodeid-plus-counter scheme that restarts from 0 in every new
# session, so two SEPARATE ``pytest`` processes running concurrently against
# the same checkout (e.g. two agents each running their own suite) can and
# do land on the same ``tmp_path.name`` for unrelated tests. Worse, the
# session-scoped cleanup fixture below ``shutil.rmtree``s this ENTIRE root
# at its own session start and end -- with a bare, unqualified path shared
# by every pytest process on the box, one process starting or finishing
# deletes a sibling process's still-in-flight per-test scratch directories
# out from under it, and a subprocess mid-write (e.g. ``_run_worker_once``
# writing its trace file) hits ``FileNotFoundError`` on the now-missing
# parent directory. Folding this process's pid into the root means the
# whole-root rmtree, and every ``tmp_path.name`` collision, can only ever
# collide with this same process's own earlier runs, never a concurrent
# sibling's.
_TEST_EVIDENCE_SCRATCH_ROOT = (
    tools_workspace.WORKSPACE_ROOT / ".pytest_evidence_scratch" / f"pid_{os.getpid()}"
)


def _is_repo_owned_module(module) -> bool:
    """True only for modules that are actually part of this repo (the
    ``tools_*.py`` adapters, ``research_state.py``, etc.) -- never a
    third-party package.

    This exists so the probe below never has to touch anything outside the
    project in the first place, rather than merely tolerating what happens
    when it does. Third-party packages such as ``transformers`` implement
    module-level ``__getattr__`` that lazily imports submodules on first
    attribute access; probing an *arbitrary* attribute on them (``EVIDENCE``
    included) can trigger that machinery and raise something far removed
    from a plain ``AttributeError`` (e.g. ``ModuleNotFoundError`` when an
    optional dependency like ``torchvision`` isn't installed), which would
    otherwise blow up fixture setup and fail the rest of the session.
    """
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return False
    try:
        resolved = Path(module_file).resolve()
    except (OSError, ValueError):
        return False
    return resolved == REPO_ROOT or REPO_ROOT in resolved.parents


# Per-module-name classification cache, populated once per session instead
# of re-derived on every single test.
#
# Measured root cause (2026-09-26): this fixture runs autouse on every test,
# and BEFORE this cache existed it called ``_is_repo_owned_module`` --
# which resolves ``Path(module.__file__).resolve()``, a real filesystem
# syscall -- for every entry in ``sys.modules`` (~1200-1300 modules,
# overwhelmingly third-party, once the suite's heavier imports have loaded),
# every test. That is not a cost that grows noticeably with how many tests
# have already run (``sys.modules`` is already ~1226 entries by test #1 and
# only crept to ~1279 over the next ~800 tests) -- it is a large *fixed*
# per-test tax: instrumented timing showed ~0.23-0.29s spent inside this
# function alone on every single test, against a ~0.35-0.5s average total
# per-test time, i.e. this one fixture was consistently >50% of every
# test's wall time. Over the full ~2427-test fast tier that is roughly
# 10-12 minutes of pure sys.modules-walking, independent of anything the
# tests themselves do -- enough on its own to make a ``timeout -k 30 480``
# run land at the observed 28-33% every time.
#
# Fix: classify each module NAME (not object identity, so this survives an
# ``importlib.reload`` that replaces the module object but not its source
# file location) exactly once, the first time it is seen in ``sys.modules``,
# and cache the boolean "is this a repo-owned module whose EVIDENCE attribute
# resolves inside the real ledger". Every later test looks the name up in
# O(1) with zero filesystem I/O; only modules imported for the very first
# time (e.g. a lazy ``import teacher`` mid-test) ever pay the resolve() cost,
# and only once each, ever. The guard's protection is unchanged: this only
# memoizes WHICH modules to check, not the per-test coverage/content-diff
# checks in ``_evidence_guard_failures`` below, which still run in full on
# every test using the module objects' live, current ``EVIDENCE`` value.
_EVIDENCE_OWNER_CLASSIFICATION_CACHE: dict[str, bool] = {}


def _evidence_owning_modules():
    """Every currently-imported, repo-owned module with a module-level
    ``EVIDENCE`` attribute that resolves inside the real evidence ledger."""
    found = []
    for name, module in list(sys.modules.items()):
        is_owner = _EVIDENCE_OWNER_CLASSIFICATION_CACHE.get(name)
        if is_owner is None:
            is_owner = False
            if _is_repo_owned_module(module):
                try:
                    evidence = getattr(module, "EVIDENCE", None)
                except Exception:
                    # Any exception from attribute access -- not just
                    # AttributeError -- means "this module does not own an
                    # evidence path". A getattr(..., None) default only
                    # swallows AttributeError, which is not enough for
                    # modules with custom __getattr__ machinery.
                    evidence = None
                if isinstance(evidence, Path):
                    try:
                        resolved = evidence.resolve()
                    except OSError:
                        resolved = None
                    if resolved is not None and (
                        resolved == REAL_EVIDENCE_ROOT
                        or REAL_EVIDENCE_ROOT in resolved.parents
                    ):
                        is_owner = True
            _EVIDENCE_OWNER_CLASSIFICATION_CACHE[name] = is_owner
        if not is_owner:
            continue
        try:
            evidence = getattr(module, "EVIDENCE", None)
        except Exception:
            continue
        if isinstance(evidence, Path):
            found.append((module, evidence))
    return found


@pytest.fixture(scope="session", autouse=True)
def _clean_evidence_scratch_root_around_the_session():
    """Housekeeping only, not a guard: remove any scratch redirect leftovers
    (e.g. from a previous run that crashed before its own per-test cleanup
    ran) before the session starts, and once more after it ends. The actual
    isolation guarantee lives in ``_redirect_tool_evidence_dirs_away_from_the_real_ledger``
    below, per test -- this fixture only tidies its scratch directory."""
    shutil.rmtree(_TEST_EVIDENCE_SCRATCH_ROOT, ignore_errors=True)
    yield
    shutil.rmtree(_TEST_EVIDENCE_SCRATCH_ROOT, ignore_errors=True)


def _snapshot_real_subdir(relative: Path) -> tuple:
    """Fingerprint of ONE real-ledger subdirectory: ``None`` if it does not
    exist yet, else ``(st_mtime_ns, st_size, child_dir_names, child_file_stats)``
    for its DIRECT children only (single ``os.scandir``, deliberately not a
    recursive walk -- same cost discipline as before this fixed a real
    false-positive: see ``_evidence_guard_failures``'s use of this).

    Root cause fixed here (measured live, 2026-09-26, two concurrent `pytest`
    sessions both exercising the `teacher.ask()` path): ``research_state.py``'s
    module-level ``EVIDENCE`` is ``dataset/evidence/ledger`` -- NOT a
    single-owner subdirectory but a directory NTFS updates the mtime of
    every time ANY session creates its own ``ledger/<session_id>/``
    subdirectory (``ResearchState.evidence_dir`` defaults to
    ``EVIDENCE / self.session_id``). The single ``(mtime_ns, size)``
    fingerprint this function used to return could not tell "a concurrent,
    unrelated session legitimately created its own sibling directory" apart
    from "this test's own code escaped into the real ledger" -- both bump
    the parent directory's mtime identically. Returning the child DIRECTORY
    names (not just an aggregate stat) lets ``_evidence_guard_failures``
    apply a session-scoped rule instead of a raw-mtime one: a new/removed
    *directory* child is legitimate per-session churn (see
    ``ledger/<session_id>/`` above) and is not itself flagged; a new,
    changed, or removed *file* sitting directly in the tracked directory --
    which is never how a session writes (it always writes inside its own
    ``<session_id>/`` subdirectory) -- still is, since that shape exactly
    matches the original incident this whole fixture exists for (a flat
    file landing directly in ``dataset/evidence/unpack/``)."""
    path = REAL_EVIDENCE_ROOT / relative
    try:
        st = path.stat()
    except OSError:
        return None
    child_dirs = set()
    child_files = {}
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        child_dirs.add(entry.name)
                    else:
                        entry_stat = entry.stat(follow_symlinks=False)
                        child_files[entry.name] = (entry_stat.st_mtime_ns, entry_stat.st_size)
                except OSError:
                    # Vanished between scandir() yielding it and this stat --
                    # a live, concurrently-mutating directory fact, not a
                    # reason to crash the guard itself.
                    continue
    except OSError:
        pass
    return (st.st_mtime_ns, st.st_size, frozenset(child_dirs), tuple(sorted(child_files.items())))


def _evidence_guard_failures(redirected: dict, pre_subdir_snapshots: dict) -> list:
    """The actual guard logic, factored out of the fixture below so it can
    be exercised directly by ``tests/test_evidence_ledger_isolation_guard.py``
    without needing to spin up a nested pytest session.

    ``redirected`` maps each module that WAS redirected this test to the
    exact scratch ``Path`` its ``EVIDENCE`` attribute was pointed at.
    ``pre_subdir_snapshots`` maps each real-ledger-relative subdirectory
    those modules own to its ``_snapshot_real_subdir`` value taken before
    the test body ran.

    Two independent checks, both scoped to exactly what this test session
    could plausibly have produced:

    1. Coverage invariant (no directory I/O, so immune to any concurrent,
       unrelated process by construction): every module this test DID
       redirect must still have its ``EVIDENCE`` attribute pointed at its
       scratch path, not reset back to the real ledger (e.g. by an
       ``importlib.reload`` mid-test). This deliberately does NOT flag a
       module that is merely *discovered* late (first imported partway
       through the test body, e.g. a lazy ``import teacher`` inside a test
       -- which transitively imports most ``tools_*.py`` adapters for the
       first time, in whichever single test happens to run first) and
       still points at the real ledger: that reflects nothing more than
       "this module exists and was never called to write anything", which
       is the overwhelmingly common case and not itself evidence of a
       write. An earlier version of this check flagged exposure instead of
       writes and fired on essentially every test that lazily imports
       ``teacher`` -- exactly the "cries wolf" failure mode this guard
       exists to avoid.

    2. Narrow content diff: for exactly the real subdirectories this
       test's redirected modules own (never the whole ~80k-file ledger),
       the directory-level fingerprint must be unchanged from before this
       test's body ran to after. A genuine escape -- code that writes
       through a captured/hardcoded path instead of the live ``EVIDENCE``
       attribute -- still shows up here as a changed fingerprint in the
       one subdirectory it targets.

    Known, accepted gap from narrowing (1): a module imported for the
    first time during a test, whose EVIDENCE was therefore never
    redirected AND that genuinely gets written to in that same test, is
    caught by neither check here (it isn't in ``redirected`` for check 1,
    and its real subdirectory isn't in ``pre_subdir_snapshots`` for check
    2 either, since that dict is built from the same discovery pass run
    before the test body). This is a real, narrower guarantee than "any
    write to the real ledger, from any module, is caught" -- see the
    fixture docstring below for why the alternative (flagging on mere
    exposure) is worse in practice.

    Known, accepted gap from narrowing (5) (session-scoped directory diff,
    added 2026-09-26): for a tracked directory whose real, legitimate write
    shape is per-session subdirectories (currently only
    ``research_state.EVIDENCE`` == ``dataset/evidence/ledger``), a write
    that lands INSIDE an already-existing sibling session's directory
    (rather than directly in the tracked directory, or inside a brand-new
    session directory) is not caught -- indistinguishable, by a
    non-recursive top-level diff, from that sibling session's own
    legitimate activity. Accepted because the alternative (the old
    raw-mtime check) false-failed on the overwhelmingly common case
    instead: a concurrent, unrelated, entirely legitimate session simply
    creating its own ``ledger/<session_id>/`` while this suite happened to
    be running.
    """
    failures = []

    for module, expected in redirected.items():
        try:
            evidence = getattr(module, "EVIDENCE", None)
        except Exception:
            continue
        if evidence != expected:
            name = getattr(module, "__name__", module)
            failures.append(
                f"{name}.EVIDENCE was changed back to {evidence} during the test "
                f"(expected it to stay redirected to {expected})"
            )

    for relative, before in pre_subdir_snapshots.items():
        after = _snapshot_real_subdir(relative)
        if after == before:
            continue
        # Session-scoped diff, not a raw before!=after comparison: if the
        # tracked directory transitioned to/from not-existing at all, that
        # is unconditionally suspicious (matches the original incident's
        # shape -- a whole new subtree appearing where none was tracked
        # before) and is always flagged. Otherwise, a DIRECTORY child being
        # added or removed is legitimate concurrent per-session churn (see
        # `_snapshot_real_subdir`'s docstring: `ledger/<session_id>/`) and
        # is not itself a failure; only a changed/added/removed FILE sitting
        # directly in the tracked directory -- never how a session writes --
        # still is, since that is exactly the original incident's shape (a
        # flat file landing directly in `dataset/evidence/unpack/`).
        if before is None or after is None:
            failures.append(
                f"real evidence subdirectory {REAL_EVIDENCE_ROOT / relative} changed "
                f"during the test despite its owning module(s) being redirected: "
                f"before={before} after={after}"
            )
            continue
        _, _, before_dirs, before_files = before
        _, _, after_dirs, after_files = after
        if before_files != after_files or (before_dirs - after_dirs):
            failures.append(
                f"real evidence subdirectory {REAL_EVIDENCE_ROOT / relative} changed "
                f"during the test despite its owning module(s) being redirected "
                f"(file-level change, or an existing subdirectory disappeared -- not "
                f"just a new sibling session directory appearing): before={before} after={after}"
            )

    return failures


def _real_subprocess_evidence_writer_reason(request) -> str | None:
    """``None`` unless this test is marked
    ``spawns_real_subprocess_evidence_writer(reason=...)``; raises at setup
    if the marker is present without a non-empty ``reason`` -- this fixture
    requires the same justification-string discipline as every other
    exception list in this module (see the root-owning-modules carve-out
    below), not a silent, unexplained opt-out."""
    marker = request.node.get_closest_marker("spawns_real_subprocess_evidence_writer")
    if marker is None:
        return None
    reason = marker.kwargs.get("reason") or (marker.args[0] if marker.args else None)
    if not reason or not str(reason).strip():
        raise AssertionError(
            f"{request.node.nodeid}: spawns_real_subprocess_evidence_writer marker requires "
            "a non-empty reason=... explaining why this test's real subprocess activity is "
            "legitimate, not a silent opt-out from the evidence ledger isolation guard"
        )
    return str(reason)


@pytest.fixture(autouse=True)
def _redirect_tool_evidence_dirs_away_from_the_real_ledger(tmp_path, monkeypatch, request):
    """Point every evidence-owning module's ``EVIDENCE`` at a per-test
    scratch directory instead of the real ledger, for exactly the duration
    of one test, then delete that scratch directory. Subdirectory structure
    (e.g. ``.../unpack``, ``.../frida``) is preserved under the scratch root
    so relative-path assumptions in tool code keep working. ``tmp_path``
    (function-scoped, uniquely named per test by pytest) is used only for
    its guaranteed-unique name, not its location -- see the module-level
    comment on ``_TEST_EVIDENCE_SCRATCH_ROOT`` for why.

    This also guards the mechanism it just set up: see
    ``_evidence_guard_failures`` for what "the redirect was actually
    honoured this test" means and why it is scoped per-test and per-owned
    subdirectory rather than a single whole-ledger, whole-session
    fingerprint. That whole-session version used to fire on nothing more
    than a concurrent, unrelated agent writing real evidence elsewhere in
    ``dataset/evidence/`` while this suite happened to be running --
    catching that condition here instead, function-scoped and restricted
    to only the subdirectories this test's own modules own, is what closes
    that false-failure hole while still catching a genuine escape. What it
    can no longer catch: (1) a write into a real-ledger subdirectory that
    no currently-imported module claims via a module-level ``EVIDENCE``
    attribute at all (a totally new adapter that does not follow that
    convention) -- that was already outside the per-test redirect's own
    coverage, not a regression introduced here; and (2) a genuine escape
    specifically through one of the modules whose ``EVIDENCE`` is the
    ledger ROOT itself rather than a subdirectory (see the comment next to
    ``pre_subdir_snapshots`` below) -- for those, only the coverage
    invariant (the attribute stayed redirected) is checked, not file
    content, because the root is shared with concurrent unrelated
    activity and cannot be diffed without reintroducing false failures;
    and (3) a module imported for the first time during the test body
    itself (e.g. a lazy ``import teacher``, which transitively imports
    most ``tools_*.py`` adapters) is not covered by either check for that
    one test, by design -- see ``_evidence_guard_failures`` for why
    flagging it anyway turned out to be a worse, noisier failure mode than
    this gap; and (4) a test explicitly marked
    ``spawns_real_subprocess_evidence_writer(reason=...)`` skips the
    content-diff half entirely (coverage invariant still applies -- it is
    immune to any other process by construction, see check 1's docstring).
    Incident this narrows for:
    ``tests/test_workspace_root_isolation.py``'s
    ``test_external_workspace_cli_keeps_project_data_isolated`` launches a
    real, separate ``universal_file_acceptance.py --workspace`` subprocess
    (its own interpreter, not this test's monkeypatch scope) against
    workspace fixture files including a synthetic PE; that subprocess's own
    normal activity is invisible to and independent of this process's
    redirect, so when it happens to land inside a real-ledger subdirectory
    already owned (tracked) by a module some other already-collected test
    file imported (e.g. ``research_state.EVIDENCE`` ==
    ``dataset/evidence/ledger``, imported at this test file's own module
    level), the content diff cannot tell that apart from a genuine escape.
    Measured: the test always passes alone, and the guard's own
    ``_evidence_guard_failures``/coverage-invariant logic is unmodified and
    still exercised, unrelaxed, by every unmarked test and by
    ``tests/test_evidence_ledger_isolation_guard.py``."""
    real_subprocess_writer_reason = _real_subprocess_evidence_writer_reason(request)
    scratch_root = _TEST_EVIDENCE_SCRATCH_ROOT / tmp_path.name
    redirected = {}
    relatives = set()
    for module, evidence in _evidence_owning_modules():
        try:
            relative = evidence.resolve().relative_to(REAL_EVIDENCE_ROOT)
        except ValueError:
            relative = Path(".")
        relatives.add(relative)
        target = scratch_root / relative
        target.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(module, "EVIDENCE", target, raising=False)
        redirected[module] = target

    # Several adapters (``tools_decompiler``, ``tools_capability_extract``,
    # ``tools_emulation``, ``tools_emulate_range``, ``tools_isolated_dynamic``,
    # ``tools_memory_scan``) set ``EVIDENCE`` to the real ledger ROOT itself
    # (``relative == Path(".")``) and write flat files directly under it
    # (``EVIDENCE / f"{run_tag}_....json"``), not into a subdirectory. For
    # exactly those, "the real subdirectory this test's module owns" IS the
    # whole ~80k-file root, so a content diff on it is indistinguishable
    # from any other concurrent agent's activity anywhere at that top
    # level -- diffing it would reproduce the exact false-failure this
    # guard exists to remove. Deliberately excluded from the content-diff
    # half below; the coverage-invariant half (the attribute itself must
    # stay redirected) still applies to them.
    # A test carrying ``spawns_real_subprocess_evidence_writer(reason=...)``
    # opts out of this content diff entirely (see the fixture docstring's
    # narrowing (4) above): its own deliberately-launched real subprocess
    # can legitimately touch one of these subdirectories in a way this
    # process's redirect never sees, which the diff cannot distinguish from
    # a genuine in-process escape. The coverage invariant below is computed
    # from ``redirected`` regardless and still applies unconditionally.
    pre_subdir_snapshots = {} if real_subprocess_writer_reason else {
        relative: _snapshot_real_subdir(relative)
        for relative in relatives
        if relative != Path(".")
    }

    yield

    failures = _evidence_guard_failures(redirected, pre_subdir_snapshots)
    shutil.rmtree(scratch_root, ignore_errors=True)
    if failures:
        raise AssertionError(
            "evidence ledger isolation guard tripped:\n- " + "\n- ".join(failures)
        )


#  ``dataset/evidence/ledger/<session_id>/`` used to be a SEPARATE,
#  unguarded write path: ``research_state.ResearchState``/
#  ``register_runtime_evidence`` default their ``evidence_dir`` to
#  ``dataset/evidence/ledger/<session_id>`` whenever a caller (including
#  many tests' ``_IsolatedActiveStore``-style base classes, e.g.
#  ``tests/test_evidence_ledger_v2.py`` and
#  ``tests/test_evidence_registration_more_tools.py``) doesn't pass an
#  explicit ``evidence_dir=`` override. That's now covered by the same
#  redirect fixture above: ``research_state.py`` carries its own
#  module-level ``EVIDENCE`` Path (``dataset/evidence/ledger``), discovered
#  and redirected exactly like every ``tools_*.py`` adapter's ``EVIDENCE``,
#  so this snapshot no longer needs a carve-out.
