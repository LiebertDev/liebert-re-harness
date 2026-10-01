"""Anti-sprawl gate: the repository must stay a package, not a dump.

Reads the repo itself; needs no external tool. See docs/ROLLBACK.md.
"""
import codecs
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
SELF = "tests/test_repo_discipline.py"  # names the identifiers it hunts for; ONLY the marked block is blanked
_BEGIN = "# BEGIN-" + "PRIVATE-NAMES"  # concatenated so these two lines are not themselves markers
_END = "# END-" + "PRIVATE-NAMES"

# KNOWN LIMITS (documented, deliberately NOT covered; do not mistake them for coverage):
#  * KNOWN_PRIVATE_REFS pins identifiers per file, not occurrence counts. An allowlisted
#    file can turn a dead comment into a live import of a private module and still pass.
#  * The test-reference check accepts an existing tests/test_<m>.py even if it is empty
#    or fully skipped, and a quoted "m.x" match can be satisfied by prose in a string.

# ALLOWLIST RULE (applies to every KNOWN_* table below). An entry is a debt: it
# names a reason, and it exists only because fixing it was out of scope when the
# gate was added. Entries may be REMOVED, never added. The exact contents of each
# table are asserted in test_allowlists_have_not_grown, so growing one means
# editing that assertion on purpose and shows up in review. If a new offender
# appears, fix the offender.

# Modules with no test import today. New modules must ship with a test instead
# of being added here.
KNOWN_UNREFERENCED = {
    "asar_parser": "only reached indirectly via tools_formats.detect_asar; no direct test yet",
    "process_lock": "only reached indirectly via claim_index/evidence_index/workspace_index; no direct test yet",
}

# Tracked files that contain a machine-specific user path today. Empty = none.
# Both are generic placeholders surfaced when the scan widened to the home and root dirs (not real users).
KNOWN_USER_PATHS = {
    "tests/test_public_provenance_and_fixtures.py": "fake POSIX model path used as a test input, not a real user",
    "tools_workspace.py": "comment example path under a fake home dir, a placeholder, not a real user",
}

# BEGIN-PRIVATE-NAMES
_ENV = "reads or documents a TEACHER_* environment variable inherited from the private tree"
_DEAD = "comment/docstring naming a private-only module; harmless text, rename when next touched"
_DOC = "documentation naming a private-only module or env var"
# path -> (identifiers present today, reason). Frozen: a new leak fails the gate.
KNOWN_PRIVATE_REFS = {
    "README.md": ({"TEACHER_"}, _DOC),
    "docs/ARCHITECTURE_NOTES.md": ({"TEACHER_"}, _DOC),
    "docs/INSTALL.md": ({"TEACHER_"}, _DOC),
    "docs/ROADMAP.md": ({"tools_emulate_range"}, _DOC),
    "crackme_solutions/README.md": ({"tools_emulate_range"}, "says the solution script imports an unshipped module"),
    "crackme_solutions/scripts_mutated_crackme5_serial.py": ({"tools_emulate_range"}, "documentation-only script that imports an unshipped module"),
    "artifact_provenance.py": ({"TEACHER_"}, "teacher_* identifiers (e.g. prompts/teacher_system.md, teacher_model); surfaced by the case-insensitive scan"),
    "evidence_index.py": ({"research_state"}, _DEAD),
    "evidence_security.py": ({"TEACHER_", "research_state"}, _DEAD + "; lowercase teacher_runtime_tool_dispatch string"),
    "lll_exact.py": ({"teacher.py"}, _DEAD),
    "tool_families.py": ({"tools_emulation"}, _DEAD),
    "tools_rizin.py": ({"tools_decompiler"}, _DEAD),
    "tools_il2cpp.py": ({"TEACHER_"}, "temp-dir prefix teacher_il2cpp_; surfaced by the case-insensitive scan"),
    "tools_workspace.py": ({"TEACHER_", "teacher.py"}, _ENV + " (live code: TEACHER_WORKSPACE etc.)"),
    "tools_yara_x.py": ({"TEACHER_", "tools_capability_extract", "tools_decompiler"}, _DEAD + "; temp-dir prefix teacher_yarax_rule_"),
    "workspace_index.py": ({"TEACHER_", "tools_memory_scan"}, _ENV + "; plus a dead docstring reference"),
    "tests/conftest.py": ({"TEACHER_", "mcp_server", "research_state", "teacher.py", "tools_capability_extract", "tools_decompiler",
                           "tools_emulate_range", "tools_emulation", "tools_isolated_dynamic", "tools_memory_scan"}, _DEAD),
    "tests/test_artifact_provenance_absent_inputs.py": ({"TEACHER_"}, "names prompts/teacher_system.md; surfaced by the case-insensitive scan"),
    "tests/test_claim_guard.py": ({"TEACHER_", "teacher.py"}, _DEAD),
    "tests/test_claim_index.py": ({"tools_emulation"}, _DEAD),
    "tests/test_disassemble_pe_va_resolution.py": ({"tools_emulation"}, _DEAD),
    "tests/test_evidence_attestation_honesty.py": ({"TEACHER_"}, "fixture string teacher_runtime_tool_dispatch; surfaced by the case-insensitive scan"),
    "tests/test_frida_trace_client.py": ({"tools_emulation"}, _DEAD),
    "tests/test_pe_resources.py": ({"tools_emulation"}, _DEAD),
    "tests/test_public_format_probes.py": ({"research_state", "tools_decompiler"}, _DEAD),
    "tests/test_public_generic_static_probe.py": ({"research_state"}, _DEAD),
    "tests/test_structured_config_schema.py": ({"TEACHER_", "teacher.py"}, _DEAD),
    "tests/test_tools_apimonitor.py": ({"tools_emulation"}, _DEAD),
    "tests/test_tools_die.py": ({"tools_emulation"}, _DEAD),
    "tests/test_tools_lattice.py": ({"teacher.py"}, _DEAD),
    "tests/test_tools_rizin.py": ({"tools_emulation"}, _DEAD),
    "tests/test_tools_yara_x.py": ({"tools_decompiler", "tools_emulation"}, _DEAD),
    "tests/test_vex_layer.py": ({"tools_emulation"}, _DEAD),
}

# Identifiers that belong to the private tree and must not appear in the public one.
PRIVATE_IDS = (
    "TEACHER_", "teacher-agent", "teacher.py", "Liebert" + " Harness",
    "tools_emulate_range", "tools_emulation", "tools_isolated_dynamic", "tools_decompiler",
    "tools_capability_extract", "tools_memory_scan", "mcp_server", "research_state",
)
# END-PRIVATE-NAMES

# `dataset/` is banned anywhere in the tree: it is harness runtime output, not source.
ARTIFACT = re.compile(
    r"(^|/)(__pycache__|\.pytest_cache|\.ruff_cache|\.pytest_evidence_scratch|\.mypy_cache|\.hypothesis"
    r"|dataset|build|dist)(/|$)"
    r"|(^|/)[^/]*\.egg-info(/|$)"
    r"|(^|/)\.coverage(\.[^/]*)?$"
    r"|\.py[co]$"
)
# A real Windows user path: any drive letter, one or more backslashes (raw, source-escaped
# or JSON-escaped) or a forward slash, "Users", a separator, then a name. The name is
# anything that is not whitespace, a quote or a path separator, so non-ASCII names match.
_NAME = r"[^\s\"'\\/:*?<>|]+"
USER_PATH = re.compile(rf"[A-Za-z]:(?:\\+|/)Users(?:\\+|/){_NAME}", re.I)
# POSIX home-style path: /Users/x, /home/x, /root/x, also with JSON-escaped slashes.
# Case-sensitive. Shared/Public are system directories, exempt only as WHOLE names (a
# lookahead, not \b, which would also fire before the hyphen of "Public-foo").
_SEP = r"\\?/"
POSIX_USER_PATH = re.compile(
    rf"(?<![A-Za-z0-9_.-])(?:{_SEP}(?:Users|home){_SEP}(?!(?:Shared|Public)(?![\w.-])){_NAME}|{_SEP}root{_SEP}{_NAME})"
)


def _private_regexes():
    """Case-insensitive; two-word names also tolerate -, _ and space between the words."""
    out = []
    for ident in PRIVATE_IDS:
        words = re.fullmatch(r"([A-Za-z]+)[- ]([A-Za-z]+)", ident)
        pat = re.escape(words.group(1)) + r"[-_ ]?" + re.escape(words.group(2)) if words else re.escape(ident)
        out.append((ident, re.compile(pat, re.I)))
    return out


def _top_modules():
    return sorted(p.stem for p in ROOT.glob("*.py"))


def _pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _py_modules():
    mods = _pyproject().get("tool", {}).get("setuptools", {}).get("py-modules")
    assert mods, "pyproject.toml has no [tool.setuptools] py-modules list"
    return list(mods)


def _git_ls(root):
    """Tracked paths of the git repo at root. Skips locally if git is unusable, FAILS under CI
    (a skipped gate in CI is a silent pass; git's dubious-ownership error exits 128)."""
    def unusable(why):
        (pytest.fail if os.environ.get("CI") else pytest.skip)(why)
    if shutil.which("git") is None:
        unusable("git not available")
    r = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True)
    if r.returncode != 0:
        unusable(f"git ls-files failed ({r.returncode}): {r.stderr.decode('utf-8', 'replace').strip()}")
    return [f for f in r.stdout.decode("utf-8", "replace").split("\0") if f]


def _tracked():
    files = _git_ls(ROOT)
    assert len(files) > 50, f"implausibly small tracked corpus ({len(files)}); content scans would pass vacuously"
    return files


def _decode(data):
    """Text of a file, or None for a genuine binary. UTF-16/32 (BOM) is decoded, not skipped."""
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")):
        if data.startswith(bom):
            return data.decode(enc, "replace")
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def _blank_private_block(text):
    """Blank the one marked block of this file that names the private identifiers it hunts."""
    assert text.count(_BEGIN) == 1 and text.count(_END) == 1, "exactly one private-names block expected"
    i, j = text.index(_BEGIN), text.index(_END)
    assert i < j
    assert not re.search(r"(?m)^\s*(def|class|import)\b", text[i:j]), "the private-names block must be data only"
    return text[:i] + text[j:]


def scan_repo(root, files):
    """The one scan both the real test and the planted-file test run.
    Returns (files with a user path, {file: private identifiers found})."""
    user, private = [], {}
    regexes = _private_regexes()
    for f in files:
        try:
            data = (root / f).read_bytes()
        except OSError:
            continue
        text = _decode(data)
        if text is None:
            continue
        if USER_PATH.search(text) or POSIX_USER_PATH.search(text):
            user.append(f)
        scanned = _blank_private_block(text) if f == SELF else text
        hits = {ident for ident, rx in regexes if rx.search(scanned)}
        if hits:
            private[f] = hits
    return user, private


def _uses_module(m, corpus):
    """Real usage only: an import statement, import_module("m"), or a quoted
    dotted namespace such as patch("m.func"). A mention in prose does not count."""
    e = re.escape(m)
    return any(re.search(p, corpus) for p in (
        rf"(?m)^[ \t]*import[ \t]+[^\n#]*\b{e}\b",
        rf"(?m)^[ \t]*from[ \t]+{e}[ \t]+import\b",
        rf"import_module\(\s*[\"']{e}[\"']",
        rf"[\"']{e}\.\w",
    ))


def test_py_modules_matches_disk():
    listed_all = _py_modules()
    dupes = sorted({m for m in listed_all if listed_all.count(m) > 1})
    assert not dupes, f"duplicate py-modules entries: {dupes}"
    on_disk, listed = set(_top_modules()), set(listed_all)
    unlisted, missing = sorted(on_disk - listed), sorted(listed - on_disk)
    assert not unlisted, f"top-level modules missing from py-modules: {unlisted}"
    assert not missing, f"py-modules entries with no file on disk: {missing}"


def test_top_level_packages_are_declared():
    """A top-level package directory is invisible to _top_modules and would silently be left
    out of the wheel unless [tool.setuptools] packages names it. tests/ is not shipped."""
    cfg = _pyproject().get("tool", {}).get("setuptools", {})
    pk = cfg.get("packages", [])
    if isinstance(pk, dict):  # packages = {find = {...}}
        inc = pk.get("find", {}).get("include", ["*"])
        declared = lambda d: any(fnmatch.fnmatchcase(d, g) for g in inc)  # noqa: E731
    else:
        declared = lambda d: any(p == d or p.startswith(d + ".") for p in pk)  # noqa: E731
    found = sorted(d.name for d in ROOT.iterdir()
                   if d.is_dir() and (d / "__init__.py").is_file() and d.name != "tests")
    undeclared = [d for d in found if not declared(d)]
    assert not undeclared, f"top-level packages missing from [tool.setuptools] packages: {undeclared}"


def test_every_module_is_referenced_by_a_test():
    corpus = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in TESTS.glob("*.py") if p.name != Path(__file__).name
    )
    unreferenced = [
        m for m in _top_modules()
        if m not in KNOWN_UNREFERENCED
        and not (TESTS / f"test_{m}.py").exists()
        and not _uses_module(m, corpus)
    ]
    assert not unreferenced, f"modules with no test import: {unreferenced}"
    stale = sorted(m for m in KNOWN_UNREFERENCED if m not in _top_modules())
    assert not stale, f"KNOWN_UNREFERENCED lists modules that no longer exist: {stale}"
    # An allowlisted module that gained a real test must leave the list.
    healed = sorted(m for m in KNOWN_UNREFERENCED if (TESTS / f"test_{m}.py").exists() or _uses_module(m, corpus))
    assert not healed, f"remove from KNOWN_UNREFERENCED, now tested: {healed}"


def test_no_tracked_build_or_runtime_artifacts():
    bad = [f for f in _tracked() if ARTIFACT.search(f)]
    assert not bad, f"artifact paths are tracked: {bad}"


def test_user_path_pattern_is_not_vacuous():
    bs = "\\"
    # Samples are concatenated so this file does not itself contain a user path.
    pre = "C:" + "/Us" + "ers/"
    for sample in (f"C:{bs}Users{bs}Name", f"C:{bs}{bs}Users{bs}{bs}Name", pre + "Name",
                   f"C:{bs * 5}Users{bs * 5}Name", "D:" + "/Users/Name", pre + "\u00c7a\u011fr\u0131",
                   f'"C:{bs}{bs}Users{bs}{bs}Bob{bs}{bs}x"'):
        assert USER_PATH.search(sample), sample
    for sample in (f"C:{bs}Program Files{bs}x", "C:/Windows/System32", "C:/Use" + "rs", "C:/Users/",
                   "/usr/lib/x", "tools_binary.py"):
        assert not USER_PATH.search(sample), sample
    mac, lin, root = "/Us" + "ers/", "/ho" + "me/", "/ro" + "ot/"
    for sample in (mac + "name/x", lin + "berat/x", root + "x", "\\/Us" + "ers\\/bob", mac + "Public-foo/x"):
        assert POSIX_USER_PATH.search(sample), sample
    for sample in (mac + "Shared/x", mac + "Public/x", "src/Us" + "ers/x", "/usr/home", "/rooted/x"):
        assert not POSIX_USER_PATH.search(sample), sample


def test_artifact_pattern_is_not_vacuous():
    for bad in ("build/x", "a/dist/x.whl", "dataset/a", "a/dataset/b", "a/__pycache__/x.txt", ".mypy_cache/x",
                "a/.hypothesis/x", ".coverage", "a/.coverage.123", "pkg/mod.pyc", "x.egg-info/PKG-INFO"):
        assert ARTIFACT.search(bad), bad
    for ok in ("tests/test_x.py", "tools_binary.py", "docs/build_notes.md", "rebuild/x", "distance.py",
               "docs/coverage.md", "datasets.py"):
        assert not ARTIFACT.search(ok), ok


def test_no_machine_specific_user_paths():
    user, _ = scan_repo(ROOT, _tracked())
    offenders = [f for f in user if f not in KNOWN_USER_PATHS]
    assert not offenders, f"tracked files contain a user-specific path: {offenders}"


def test_scan_reaches_planted_files(tmp_path):
    """The only proof the scan reaches files at all: plant offenders in a throwaway git repo
    and run the SAME scan_repo the real tests run."""
    bs = "\\"
    private = PRIVATE_IDS[1]  # a two-word identifier, planted in a case/separator variant
    (tmp_path / "notes.txt").write_text("see C:" + "/Us" + "ers/Bob/x and " + private.upper().replace("-", "_") + "\n")
    (tmp_path / "utf16.txt").write_bytes(("home C:" + bs + "Us" + "ers" + bs + "Bob\n").encode("utf-16"))
    (tmp_path / "posix.txt").write_text("/ho" + "me/berat/x\n")
    (tmp_path / "clean.txt").write_text("nothing here\n")
    (tmp_path / "blob.bin").write_bytes(b"\0\0\0C:" + b"/Us" + b"ers/Bob\0" + private.encode())
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    if shutil.which("git") is None:
        (pytest.fail if os.environ.get("CI") else pytest.skip)("git not available")
    subprocess.run([*git, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([*git, "add", "-A"], cwd=tmp_path, check=True)
    files = _git_ls(tmp_path)
    assert sorted(files) == ["blob.bin", "clean.txt", "notes.txt", "posix.txt", "utf16.txt"]
    user, priv = scan_repo(tmp_path, files)
    assert sorted(user) == ["notes.txt", "posix.txt", "utf16.txt"]  # UTF-16 decoded; genuine binary still skipped
    assert priv == {"notes.txt": {private, PRIVATE_IDS[0]}}  # TEACHER_AGENT also contains the first id


def test_no_private_tree_identifiers_in_public_package():
    _, seen = scan_repo(ROOT, _tracked())
    new = {f: sorted(h) for f, h in seen.items() if f not in KNOWN_PRIVATE_REFS}
    assert not new, f"private-tree identifiers leaked into new files: {new}"
    grown = {f: sorted(h - KNOWN_PRIVATE_REFS[f][0]) for f, h in seen.items()
             if f in KNOWN_PRIVATE_REFS and h - KNOWN_PRIVATE_REFS[f][0]}
    assert not grown, f"new private identifiers in allowlisted files: {grown}"
    healed = sorted(f for f in KNOWN_PRIVATE_REFS if f not in seen)
    assert not healed, f"clean now; remove from KNOWN_PRIVATE_REFS: {healed}"
    shrunk = {f: sorted(KNOWN_PRIVATE_REFS[f][0] - seen[f]) for f in KNOWN_PRIVATE_REFS
              if KNOWN_PRIVATE_REFS[f][0] - seen[f]}
    assert not shrunk, f"identifiers gone; trim KNOWN_PRIVATE_REFS: {shrunk}"


def test_allowlists_have_not_grown():
    """Exact contents, so adding an entry means editing this test deliberately."""
    # The identifier tuple itself is pinned (by hash, so this file names none of them): deleting
    # an entry would otherwise blind the scan while every test stays green.
    assert len(PRIVATE_IDS) == 12
    assert hashlib.sha256(repr(PRIVATE_IDS).encode()).hexdigest().startswith("3694464b333b3ecd")
    assert set(KNOWN_UNREFERENCED) == {"asar_parser", "process_lock"}
    assert set(KNOWN_USER_PATHS) == {"tests/test_public_provenance_and_fixtures.py", "tools_workspace.py"}
    assert len(KNOWN_PRIVATE_REFS) == 33
    assert sum(len(ids) for ids, _ in KNOWN_PRIVATE_REFS.values()) == 51
    # Fingerprint of every (path, identifiers) pair: swapping an entry, not only
    # adding one, changes it. Update it only when REMOVING entries.
    digest = hashlib.sha256(repr(sorted((f, sorted(i)) for f, (i, _) in KNOWN_PRIVATE_REFS.items())).encode()).hexdigest()
    assert digest.startswith("f739265fb45951c7")
    assert all(reason for _, reason in KNOWN_PRIVATE_REFS.values())
