"""Anti-sprawl gate: the repository must stay a package, not a dump.

Reads the repo itself; needs no external tool. See docs/ROLLBACK.md.
"""
import codecs
import fnmatch
import getpass
import hashlib
import os
import platform
import re
import shutil
import socket
import subprocess
import uuid
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

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
    "liebert_re.tools.asar_parser": "only reached indirectly via tools_formats.detect_asar; no direct test yet",
}

# Tracked files that contain a machine-specific user path today. Empty = none.
# Both are generic placeholders surfaced when the scan widened to the home and root dirs (not real users).
KNOWN_USER_PATHS = {
    "tests/test_public_provenance_and_fixtures.py": "fake POSIX model path used as a test input, not a real user",
    "liebert_re/workspace.py": "comment example path under a fake home dir, a placeholder, not a real user",
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
    "liebert_re/evidence/artifact_provenance.py": ({"TEACHER_"}, "teacher_* identifiers (e.g. prompts/teacher_system.md, teacher_model); surfaced by the case-insensitive scan"),
    "liebert_re/evidence/index.py": ({"research_state"}, _DEAD),
    "liebert_re/evidence/security.py": ({"TEACHER_", "research_state"}, _DEAD + "; lowercase teacher_runtime_tool_dispatch string"),
    "liebert_re/recover/lll_exact.py": ({"teacher.py"}, _DEAD),
    "liebert_re/report/tool_families.py": ({"tools_emulation"}, _DEAD),
    "liebert_re/tools/rizin.py": ({"tools_decompiler"}, _DEAD),
    "liebert_re/tools/il2cpp.py": ({"TEACHER_"}, "temp-dir prefix teacher_il2cpp_; surfaced by the case-insensitive scan"),
    "liebert_re/workspace.py": ({"TEACHER_", "teacher.py"}, _ENV + " (live code: TEACHER_WORKSPACE etc.)"),
    "liebert_re/tools/yara_x.py": ({"TEACHER_", "tools_capability_extract", "tools_decompiler"}, _DEAD + "; temp-dir prefix teacher_yarax_rule_"),
    "liebert_re/evidence/workspace_index.py": ({"TEACHER_", "tools_memory_scan"}, _ENV + "; plus a dead docstring reference"),
    "tests/conftest.py": ({"TEACHER_", "mcp_server", "research_state", "teacher.py"}, _DEAD),
    "tests/test_artifact_provenance_absent_inputs.py": ({"TEACHER_"}, "names prompts/teacher_system.md; surfaced by the case-insensitive scan"),
    "tests/test_claim_guard.py": ({"TEACHER_", "teacher.py"}, _DEAD),
    "tests/test_disassemble_pe_va_resolution.py": ({"tools_emulation"}, _DEAD),
    "tests/test_evidence_attestation_honesty.py": ({"TEACHER_"}, "fixture string teacher_runtime_tool_dispatch; surfaced by the case-insensitive scan"),
    "tests/test_public_format_probes.py": ({"research_state", "tools_decompiler"}, _DEAD),
    "tests/test_public_generic_static_probe.py": ({"research_state"}, _DEAD),
    "tests/test_structured_config_schema.py": ({"TEACHER_", "teacher.py"}, _DEAD),
    "tests/test_tools_lattice.py": ({"teacher.py"}, _DEAD),
    "tests/test_tools_yara_x.py": ({"tools_decompiler"}, _DEAD),
}

# Identifiers that belong to the private tree and must not appear in the public one.
PRIVATE_IDS = (
    "TEACHER_", "teacher-agent", "teacher.py", "Liebert" + " Harness",
    "tools_emulate_range", "tools_emulation", "tools_isolated_dynamic", "tools_decompiler",
    "tools_capability_extract", "tools_memory_scan", "mcp_server", "research_state",
    "qwen", "llama", "mistral", "gemma", "phi-3",  # local model names
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
# POSIX home-style path (macOS /Users, Linux /home, root's home), also with JSON-escaped slashes.
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
    """Dotted name of every module in the liebert_re package (package markers excluded)."""
    pkg = ROOT / "liebert_re"
    return sorted(
        ".".join(p.relative_to(ROOT).with_suffix("").parts)
        for p in pkg.rglob("*.py") if p.name != "__init__.py"
    )


def _pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


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


def _texts(root, files):
    """(path, text) for every readable, non-binary file. The one file-walk and skip rule every
    content scan in this module shares (scan_repo, scan_privacy)."""
    for f in files:
        try:
            data = (root / f).read_bytes()
        except OSError:
            continue
        text = _decode(data)
        if text is not None:
            yield f, text


def scan_repo(root, files):
    """The one scan both the real test and the planted-file test run.
    Returns (files with a user path, {file: private identifiers found})."""
    user, private = [], {}
    regexes = _private_regexes()
    for f, text in _texts(root, files):
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


def test_layout_matches_packaging():
    """The flat layout must not come back, and the package must be a real package tree."""
    assert list(ROOT.glob("*.py")) == [], "modules at the repo root: they belong inside liebert_re/"
    pkg = ROOT / "liebert_re"
    assert (pkg / "__init__.py").is_file()
    missing = sorted(
        str(d.relative_to(ROOT)) for d in [pkg, *(x for x in pkg.rglob("*") if x.is_dir())]
        if d.name != "__pycache__" and any(d.glob("*.py")) and not (d / "__init__.py").is_file()
    )
    assert not missing, f"directories with modules but no __init__.py: {missing}"
    top_pkgs = sorted(d.name for d in ROOT.iterdir() if d.is_dir() and (d / "__init__.py").is_file() and d.name != "tests")
    assert top_pkgs == ["liebert_re"], f"liebert_re must be the only top-level package: {top_pkgs}"
    assert _pyproject().get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {}).get("include") == ["liebert_re*"]


def test_package_root_is_anchored_in_one_place():
    """No module may build a dataset/ or benchmarks/ path from its own __file__: the package-root
    anchor lives in liebert_re.workspace (PROJECT_ROOT) and nowhere else."""
    import ast
    offenders = []
    for p in sorted((ROOT / "liebert_re").rglob("*.py")):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8-sig"))):
            if not isinstance(node, ast.stmt) or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While, ast.With, ast.Try)):
                continue
            sub = list(ast.walk(node))
            uses_file = any(isinstance(n, ast.Name) and n.id == "__file__" for n in sub)
            names_dir = any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                            and n.value.split("/")[0] in ("dataset", "benchmarks") for n in sub)
            if uses_file and names_dir:
                offenders.append(f"{p.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, f"__file__-anchored dataset/benchmarks paths: {offenders}"


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
        and not _uses_module(m, corpus)
    ]
    assert not unreferenced, f"modules with no test import: {unreferenced}"
    stale = sorted(m for m in KNOWN_UNREFERENCED if m not in _top_modules())
    assert not stale, f"KNOWN_UNREFERENCED lists modules that no longer exist: {stale}"
    # An allowlisted module that gained a real test must leave the list.
    healed = sorted(m for m in KNOWN_UNREFERENCED if _uses_module(m, corpus))
    assert not healed, f"remove from KNOWN_UNREFERENCED, now tested: {healed}"


def test_no_tracked_build_or_runtime_artifacts():
    bad = [f for f in _tracked() if ARTIFACT.search(f)]
    assert not bad, f"artifact paths are tracked: {bad}"


def test_user_path_pattern_is_not_vacuous():
    bs = "\\"
    # Samples are concatenated so this file does not itself contain a user path.
    pre = "C:" + "/Us" + "ers/"
    for sample in (f"C:{bs}Users{bs}Name", f"C:{bs}{bs}Users{bs}{bs}Name", pre + "Name",
                   f"C:{bs * 5}Users{bs * 5}Name", "D:" + "/Us" + "ers/Name", pre + "\u00c7a\u011fr\u0131",
                   f'"C:{bs}{bs}Users{bs}{bs}Bob{bs}{bs}x"'):
        assert USER_PATH.search(sample), sample
    for sample in (f"C:{bs}Program Files{bs}x", "C:/Windows/System32", "C:/Use" + "rs", "C:/Users/",
                   "/usr/lib/x", "tools_binary.py"):
        assert not USER_PATH.search(sample), sample
    mac, lin, root = "/Us" + "ers/", "/ho" + "me/", "/ro" + "ot/"
    for sample in (mac + "name/x", lin + "bob/x", root + "x", "\\/Us" + "ers\\/bob", mac + "Public-foo/x"):
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
    (tmp_path / "posix.txt").write_text("/ho" + "me/bob/x\n")
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
    assert priv == {"notes.txt": {private, PRIVATE_IDS[0]}}  # the upper-case, underscore-joined form of that identifier also contains the first id


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
    assert len(PRIVATE_IDS) == 17
    assert hashlib.sha256(repr(PRIVATE_IDS).encode()).hexdigest().startswith("d51a752750a0f2a7")
    assert set(KNOWN_UNREFERENCED) == {"liebert_re.tools.asar_parser"}
    assert set(KNOWN_USER_PATHS) == {"tests/test_public_provenance_and_fixtures.py", "liebert_re/workspace.py"}
    # tests/conftest.py: six stale tools_* identifiers removed (40 -> 34); earlier, 24 -> 23 entries,
    # 41 -> 40 identifiers: tests/test_pe_resources.py now builds its fixtures
    # (docs/CORPUS.md) and no longer names a private-tree identifier, so its entry was removed.
    assert len(KNOWN_PRIVATE_REFS) == 23
    assert sum(len(ids) for ids, _ in KNOWN_PRIVATE_REFS.values()) == 34
    # Fingerprint of every (path, identifiers) pair: swapping an entry, not only
    # adding one, changes it. Update it only when REMOVING entries.
    digest = hashlib.sha256(repr(sorted((f, sorted(i)) for f, (i, _) in KNOWN_PRIVATE_REFS.items())).encode()).hexdigest()
    assert digest.startswith("63966aa9effe05b4")
    assert all(reason for _, reason in KNOWN_PRIVATE_REFS.values())


# ======================================================================================
# PRIVACY GATE. Two halves, one scan (scan_privacy), reusing _tracked/_texts/_decode above:
#   (a) real commercial / live application identities must never appear. A real target gets a
#       TARGET-NN codename plus a technical category tag; public crackmes and CTF binaries
#       may be named. Enforced by PRODUCT_DENYLIST below.
#   (b) nothing identifying the operator's machine or person: user/home paths (the scans
#       above plus the variants they miss), the username, hostname, machine GUID, volume
#       serial and MAC, credentials, tokens and licence-key-shaped strings.
#
# SUBSTITUTION CONVENTION. Replace the value, do not hide it. Angle-bracket tokens are the
# placeholder style the whole gate ignores: <USER>, <HOME>, <HOSTNAME>, <MACHINE-GUID>,
# <VOLUME-SERIAL>, <MAC>, <REDACTED>, <API_KEY>, <LICENSE-KEY>. Credential and licence rules
# also accept the usual dummy forms (xxxx, ****, EXAMPLE, your_..., changeme, a repeated char).
# A real application is written TARGET-NN plus a category tag, e.g. "TARGET-03 (kernel anti-cheat driver)".
#
# NEVER-LITERAL RULE. Operator-specific values (username, hostname, GUID, serial, MAC) are read
# from the running machine at test time, so this public file never contains them. Consequence:
# those exact-match probes protect whichever machine runs the test (the operator's, where it
# matters); the shape rules below protect everywhere, including CI.
#
# ONE-LINE WAIVER. A line may carry "privacy-ok: <rule-id>" to waive a SHAPE rule it
# legitimately trips (mac-address, licence-key, credential-*). Identity rules (denylisted
# product, operator/machine identity, user-path-variant) cannot be waived: fix the text.

PRIVACY_FIX = {
    "user-path-variant": "a user-profile path in a form the base scan misses; write <USER> in place of the account name (or <HOME>)",
    "operator-username": "the operator's account name; write <USER>",
    "operator-home": "the operator's home directory; write <HOME>",
    "machine-hostname": "this machine's hostname; write <HOSTNAME>",
    "machine-guid": "this machine's GUID; write <MACHINE-GUID>",
    "machine-volume-serial": "this machine's volume serial; write <VOLUME-SERIAL>",
    "machine-mac": "this machine's MAC address; write <MAC>",
    "mac-address": "a MAC-address-shaped string; write <MAC>, or append 'privacy-ok: mac-address' in a comment if it is a genuine fixture value",
    "credential-aws-key": "an AWS-style access key id; remove it (rotate it if it was ever real), read it from the environment, or write <API_KEY>",
    "credential-github-token": "a GitHub token; remove it (REVOKE it if it was ever real), or write <API_KEY>",
    "credential-llm-key": "an OpenAI/Anthropic-style API key; remove it (REVOKE it if it was ever real), or write <API_KEY>",
    "credential-assignment": "a credential-looking assignment with a non-placeholder value; read it from the environment or write <REDACTED>",
    "credential-private-key": "a PEM private-key block; remove it and rotate the key, or keep only the header with <REDACTED> as the body",
    "licence-key": "a licence-key-shaped string; write <LICENSE-KEY> or XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, or append 'privacy-ok: licence-key' in a comment for a public crackme's serial",
    "denylisted-product": "a real product/vendor identity from the private target registry; use TARGET-NN plus a technical category tag, e.g. 'TARGET-03 (kernel anti-cheat driver)'",
}
WAIVABLE = {"mac-address", "credential-aws-key", "credential-github-token", "credential-llm-key",
            "credential-assignment", "credential-private-key", "licence-key"}
_WAIVER = re.compile(r"privacy-ok:\s*([a-z0-9][a-z0-9_, -]*)", re.I)

# PRODUCT DENYLIST / PRIVATE CODENAME REGISTRY. The real names live OUTSIDE the repo, in a private
# registry read at test time (same never-literal rule as the operator identity probes above), so this
# public file names no commercial product or vendor. Default location: ~/.liebert-re/targets.txt;
# override with the LIEBERT_RE_TARGETS environment variable. Format, one target per line:
#     TARGET-NN | real name; other name; driver/service/process short name | category tag
# Blank lines and lines starting with # are ignored. Names match case-insensitively, as whole tokens
# (a name may be followed by a 32/64 bitness suffix), and a space inside a name also matches - _ . or
# nothing. File PATHS are scanned too. Failure output prints only the codename and a masked match,
# never the name. If the registry is absent or empty the product rule is INACTIVE (fresh clone, CI):
# test_product_rule_is_active_or_says_why then SKIPS with the reason, so it is visible in the report
# rather than a silent pass. A registry that exists but is malformed FAILS: a broken gate must not
# look like a missing one. Public crackmes and CTF binaries are NOT listed: those may be named.
# This file is scanned in full by every rule, including the product rule: it holds no names to blank.
TARGETS_ENV = "LIEBERT_RE_TARGETS"
_CODENAME = re.compile(r"TARGET-\d{2,}")


def _registry_path():
    env = os.environ.get(TARGETS_ENV)
    return Path(env).expanduser() if env else Path.home() / ".liebert-re" / "targets.txt"


def _parse_registry(text):
    """Registry text -> tuple of (codename, names, category tag). Raises ValueError on a bad line;
    the message carries the line number only, never the line (it may hold a real name)."""
    out, seen = [], set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) != 3 or not _CODENAME.fullmatch(parts[0]):
            raise ValueError(f"line {lineno}: expected 'TARGET-NN | name; name | category tag'")
        names = tuple(n for n in (x.strip() for x in parts[1].split(";")) if n)
        if not names or any(len(n) < 3 for n in names) or not parts[2]:
            raise ValueError(f"line {lineno}: need at least one name of 3+ characters and a category tag")
        if parts[0] in seen:
            raise ValueError(f"line {lineno}: codename {parts[0]} appears twice (codenames are never reused)")
        seen.add(parts[0])
        out.append((parts[0], names, parts[2]))
    return tuple(out)


def _load_denylist():
    """(entries, status). entries are (codename, names) pairs; status says why the rule is inactive,
    or '' when it is active. Never raises for an absent file; raises for a malformed one."""
    path = _registry_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (), f"no private target registry at {path} (set {TARGETS_ENV} or create it)"
    except OSError as e:
        return (), f"private target registry at {path} unreadable ({type(e).__name__})"
    entries = _parse_registry(text)
    if not entries:
        return (), f"private target registry at {path} has no entries"
    return tuple((code, names) for code, names, _ in entries), ""


_GENERIC_NAMES = {"admin", "administrator", "user", "users", "root", "runner", "runneradmin", "default", "public",
                  "guest", "test", "tester", "dev", "build", "ubuntu", "debian", "vagrant", "github", "docker",
                  "localhost", "windows", "buildkitsandbox", "ci", "jenkins", "system"}
_GENERIC_HOST_PREFIX = ("fv-az", "runnervm", "buildkit", "ci-", "localhost", "github-")
_PLACEHOLDER_WORDS = ("example", "placeholder", "redacted", "changeme", "change_me", "change-me", "your", "dummy",
                      "fake", "sample", "xxxx", "todo", "insert", "replace", "not-a-real", "notreal", "fixture",
                      "test", "1234", "abcd", "0000", "password", "secret_here", "<", ">", "${", "{{", "...")


def _is_placeholder(value):
    v = value.strip()
    low = v.lower()
    return (not v or any(w in low for w in _PLACEHOLDER_WORDS)
            or re.fullmatch(r"(.)\1+", v) is not None            # xxxxxxxx, ********, 00000000
            or re.fullmatch(r"[x*#.\-_ ]+", low) is not None
            or re.fullmatch(r"%[^%]+%", v) is not None            # %VAR%
            or v.startswith("$"))                                 # $VAR, ${VAR}


def _entropy(s):
    import math
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def _mask(s):
    return s[:2] + "***" + f"({len(s)} chars)"


# ---- (b) user-profile path variants the base USER_PATH / POSIX_USER_PATH miss -----------
# Verified against the base scan (see PATCH.md): it already catches the drive-letter forms with
# one backslash, doubled (JSON-escaped) backslashes or a forward slash, and the POSIX /Users,
# /home and /root forms. It misses the four forms below.
_PNAME = r"(?!(?:Public|Shared|Default|All)(?![\w.-]))[^\s\"'\\/%:*?<>|;,()\[\]]+"
_ENC = r"(?:%5[Cc]|%2[Ff])"
USER_PATH_VARIANTS = (
    re.compile(rf"(?:[A-Za-z](?:%3[Aa]|:))?{_ENC}+Users{_ENC}+{_PNAME}", re.I),                       # URL-encoded
    re.compile(rf"(?<![A-Za-z0-9_.:\\-])\\{{1,8}}Users\\{{1,8}}{_PNAME}", re.I),                     # drive-less, one or doubled backslashes
    re.compile(rf"(?<![A-Za-z0-9_.-]){_SEP}(?:mnt{_SEP})?[A-Za-z]{_SEP}Users{_SEP}{_PNAME}", re.I),  # WSL /mnt/c/Users, MSYS /c/Users
    re.compile(rf"[A-Za-z]:(?:\\+|/)Documents and Settings(?:\\+|/){_PNAME}", re.I),                 # pre-Vista profiles
)

# ---- (b) shape rules: credentials, MAC, licence key --------------------------------------
_NB = r"(?<![A-Za-z0-9+/_-])"          # not inside a longer base64/identifier run
_NA = r"(?![A-Za-z0-9+/_-])"
AWS_KEY = re.compile(_NB + r"(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA)[A-Z2-7]{16}" + _NA)
GITHUB_TOKEN = re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])")
LLM_KEY = re.compile(r"(?<![A-Za-z0-9_-])(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])")
_SENSITIVE = (r"(?:api[_-]?key|apikey|(?:access|auth|secret|private|client|bearer)[_-]?(?:key|token|secret)"
              r"|secret|passw(?:or)?d|passwd|token)")
# The identifier must END in a sensitive word (token_type, secret_len do not match), then = or :
# or :=, then a quoted value or (unquoted) a long bare word. _secret_value_ok decides the rest.
CRED_ASSIGN = re.compile(
    rf"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*{_SENSITIVE}[\"']?\s*(?::=|=|:)\s*"
    r"(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\s\"',;(){}\[\]]+))", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,200}?[A-Za-z0-9+/]{60,}")
MAC_SHAPE = re.compile(r"(?<![0-9A-Fa-f:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])(?!\1[0-9A-Fa-f]{2})")
LICENCE_SHAPE = re.compile(r"(?<![A-Za-z0-9-])[A-Z0-9]{4,6}(?:-[A-Z0-9]{4,6}){3,5}(?![A-Za-z0-9-])")
_MAC_KNOWN_DUMMY = {"aabbccddeeff", "001122334455", "112233445566", "0123456789ab", "123456789abc",
                    "deadbeefcafe", "deadbeef0000", "cafebabe0000", "feedfacecafe", "abcdef012345"}


def _mac_is_dummy(text):
    b = bytes.fromhex(re.sub(r"[:-]", "", text))
    diffs = {(b[i + 1] - b[i]) % 256 for i in range(5)}
    return bool(
        b[0] & 1                                                  # group/multicast bit: 01:00:5e.., 33:33.., ff:ff..
        or len(set(b)) == 1
        or (len(diffs) == 1 and diffs <= {1, 255})                # 01:02:03.. / 66:55:44..
        or b.hex() in _MAC_KNOWN_DUMMY
        or b.hex().startswith(("00005e0053", "00005e0001"))       # RFC 7042 documentation ranges
        or not re.search(r"[a-fA-F]", text))                      # digits only: a date or version, not a MAC


def _secret_value_ok(v, quoted):
    """True when an assigned value looks like a real secret rather than code, a type or a placeholder."""
    if len(v) < (8 if quoted else 16) or _is_placeholder(v):
        return False
    if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)) or _entropy(v) < 2.5:
        return False
    if re.fullmatch(r"[A-Z0-9]+(?:_[A-Z0-9]+)+", v) or re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)+", v):
        return False                                             # CONSTANT_NAME / snake_case identifier
    if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v) or v.startswith(("/", "./", "\\", "%")) or "://" in v:
        return False                                             # attribute access, path, URL, %s-format
    return True


def _licence_ok(text):
    alnum = text.replace("-", "")
    if _is_placeholder(text) or not (re.search(r"[A-Z]", alnum) and re.search(r"\d", alnum)) or len(set(alnum)) < 6:
        return False
    return not (len(alnum) <= 16 and re.fullmatch(r"[0-9A-F]+", alnum))   # DEAD-BEEF-style hex ids, not serials


def _identity_probes(hostnames=(), usernames=(), homes=(), guids=(), serials=(), macs=()):
    """(rule id, compiled regex) for each machine/operator value. Pure: tests feed synthetic values."""
    out = []
    for h in hostnames:
        for name in {h, h.split(".")[0]}:
            if len(name) >= 4 and name.lower() not in _GENERIC_NAMES and not name.lower().startswith(_GENERIC_HOST_PREFIX):
                out.append(("machine-hostname", re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.I)))
    for u in usernames:
        if len(u) >= 3 and u.lower() not in _GENERIC_NAMES:
            # also after a URL-encoded separator (%5CName), where a plain word boundary would not fire
            out.append(("operator-username", re.compile(rf"(?:(?<![A-Za-z0-9])|(?<=%5C)|(?<=%2F)){re.escape(u)}(?![A-Za-z0-9])", re.I)))
    for home in homes:
        parts = [p for p in re.split(r"[\\/]+", home) if p]
        if len(parts) >= 2 and parts[-1].lower() not in _GENERIC_NAMES:
            sep = r"(?:\\+|/|%5C|%2F)+"
            out.append(("operator-home", re.compile(r"(?<![A-Za-z0-9])" + sep.join(re.escape(p) for p in parts) + r"(?![A-Za-z0-9])", re.I)))
    for g in guids:
        raw = g.strip("{}").lower().replace("-", "")
        if re.fullmatch(r"[0-9a-f]{32}", raw):
            cut = ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32))
            out.append(("machine-guid", re.compile(r"(?<![0-9A-Fa-f])" + "-?".join(raw[i:j] for i, j in cut) + r"(?![0-9A-Fa-f])", re.I)))
    for s in serials:
        if re.fullmatch(r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}", s):
            out.append(("machine-volume-serial", re.compile(r"(?<![0-9A-Za-z-])" + re.escape(s) + r"(?![0-9A-Za-z-])", re.I)))
    for m in macs:
        h = re.sub(r"[^0-9a-f]", "", m.lower())
        if len(h) == 12:
            out.append(("machine-mac", re.compile(r"(?<![0-9A-Fa-f])" + r"[:.-]?".join(h[i:i + 2] for i in range(0, 12, 2)) + r"(?![0-9A-Fa-f])", re.I)))
    return out


@lru_cache(maxsize=1)
def _machine_identity():
    """Probes for THIS machine, discovered at run time (never written into the repo)."""
    hosts, users, homes, guids, serials, macs = set(), set(), set(), set(), set(), set()
    for fn in (socket.gethostname, socket.getfqdn, platform.node):
        try:
            hosts.add(fn())
        except Exception:
            pass
    hosts.add(os.environ.get("COMPUTERNAME", ""))
    for fn in (getpass.getuser, lambda: Path.home().name):
        try:
            users.add(fn())
        except Exception:
            pass
    users.update((os.environ.get("USERNAME", ""), os.environ.get("USER", ""), os.environ.get("LOGNAME", "")))
    try:
        homes.add(str(Path.home()))
    except Exception:
        pass
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            guids.add(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:
        pass
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            guids.add(Path(p).read_text().strip())
        except Exception:
            pass
    if os.name == "nt":
        import ctypes
        for drive in {os.environ.get("SystemDrive", "C:"), ROOT.drive}:
            try:
                ser = ctypes.c_uint32()
                if drive and ctypes.windll.kernel32.GetVolumeInformationW(drive + "\\", None, 0, ctypes.byref(ser), None, None, None, 0):
                    serials.add(f"{ser.value >> 16:04X}-{ser.value & 0xFFFF:04X}")
            except Exception:
                pass
    node = uuid.getnode()
    if not (node >> 40) & 1:  # uuid invents a multicast-bit value when it cannot read a real MAC
        macs.add(f"{node:012x}")
    return tuple(_identity_probes(hosts - {""}, users - {""}, homes, guids, serials, macs))


def _denylist_probes(denylist=None):
    """(codename, regex) per listed name. denylist: (codename, names) pairs; default: the private registry."""
    out = []
    for n, names in (_load_denylist()[0] if denylist is None else denylist):
        for name in names:
            words = [re.escape(w) for w in re.split(r"[\s_.-]+", name.strip()) if w]
            out.append((n, re.compile(rf"(?<![A-Za-z0-9]){r'[-_. ]?'.join(words)}(?:32|64)?(?![A-Za-z0-9])", re.I)))
    return out


class Finding(NamedTuple):
    path: str
    line: int       # 0 = the file name itself
    rule: str
    shown: str      # masked; never the full value

    def render(self):
        loc = f"{self.path}:{self.line}" if self.line else f"{self.path} (file name)"
        return f"{loc}: [{self.rule}] {self.shown}\n    fix: {PRIVACY_FIX[self.rule]}"


def _identity_findings(line, ident, deny):
    """Identity rules: operator/machine values and the product denylist."""
    for rule, rx in ident:
        m = rx.search(line)
        if m:
            yield rule, m.group(0)
    for n, rx in deny:
        m = rx.search(line)
        if m:
            yield "denylisted-product", f"private registry entry {n}: " + _mask(m.group(0))


def _shape_findings(line):
    """Shape rules: user-path variants, credentials, MAC, licence key."""
    for rx in USER_PATH_VARIANTS:
        m = rx.search(line)
        if m:
            yield "user-path-variant", m.group(0)
    for m in AWS_KEY.finditer(line):
        if not _is_placeholder(m.group(0)):
            yield "credential-aws-key", m.group(0)
    for m in GITHUB_TOKEN.finditer(line):
        if not _is_placeholder(m.group(0)):
            yield "credential-github-token", m.group(0)
    for m in LLM_KEY.finditer(line):
        body = m.group(0)
        if not _is_placeholder(body) and re.search(r"\d", body) and re.search(r"[A-Za-z]", body) and _entropy(body) >= 3.0:
            yield "credential-llm-key", body
    for m in CRED_ASSIGN.finditer(line):
        quoted = m.group(1) is not None or m.group(2) is not None
        val = next(g for g in m.groups() if g is not None)
        if _secret_value_ok(val, quoted):
            yield "credential-assignment", val
    for m in MAC_SHAPE.finditer(line):
        if not _mac_is_dummy(m.group(0)):
            yield "mac-address", m.group(0)
    for m in LICENCE_SHAPE.finditer(line):
        if _licence_ok(m.group(0)):
            yield "licence-key", m.group(0)


def _waived(line):
    ids = set()
    for w in _WAIVER.finditer(line):
        ids |= {r.lower() for r in re.split(r"[,\s]+", w.group(1)) if r}
    return ids


def scan_privacy(root, files, identity=None, denylist=None):
    """The one privacy scan the real test and the planted-file test both run. Same file walk and
    binary skipping as scan_repo (via _texts). identity: probes from _identity_probes (default:
    this machine). denylist: (codename, names) pairs (default: the private
    registry). Returns a list of Finding."""
    ident = tuple(_machine_identity() if identity is None else identity)
    deny = _denylist_probes(denylist)
    found = []
    for f in files:  # file names count too
        for rule, shown in _identity_findings(f, [p for p in ident if p[0] != "operator-home"], deny):
            found.append(Finding(f, 0, rule, shown if rule == "denylisted-product" else _mask(shown)))
    for f, text in _texts(root, files):
        lines = text.split("\n")
        for lineno, line in enumerate(lines, 1):
            waived = _waived(line)
            for rule, shown in (*_identity_findings(line, ident, deny), *_shape_findings(line)):
                if rule in WAIVABLE and rule in waived:
                    continue
                found.append(Finding(f, lineno, rule, shown if rule == "denylisted-product" else _mask(shown)))
        for m in PRIVATE_KEY.finditer(text):  # multi-line: header followed by a key-sized base64 body
            lineno = text.count("\n", 0, m.start()) + 1
            if "credential-private-key" not in _waived(lines[lineno - 1]):
                found.append(Finding(f, lineno, "credential-private-key", "PEM private key header + body"))
    return found


def _report(findings):
    return (f"privacy gate: {len(findings)} finding(s). Values are masked on purpose.\n"
            + "\n".join(x.render() for x in sorted(findings))
            + "\nConvention: replace the value with a <PLACEHOLDER> token (see the PRIVACY GATE comment in "
              "tests/test_repo_discipline.py); a real application becomes TARGET-NN plus a category tag.")


def test_privacy_patterns_are_not_vacuous():
    """Every shape rule fires on a positive sample and stays quiet on realistic clean RE content.
    Samples are assembled from pieces so this file does not itself contain a violation."""
    def hits(line):
        return {r for r, _ in _shape_findings(line)}
    colon = ":".join(("3c", "4d", "5e", "6f", "7a", "8b"))
    dash = "-".join(("3C", "4D", "5E", "6F", "7A", "8B"))
    bs, pct = "\\", "%"
    rnd = "q8Zk3Wm1Vb7Xc2Nd5Ls9Rt4Hy6Ge0Pf"  # 31 chars of mixed class
    AWS_BODY = "QWERTY234567MNPK"  # base32 alphabet, 16 chars, no placeholder word in it
    positives = {
        "mac-address": [f"nic {colon}", f"nic {dash}"],
        "credential-aws-key": ["key=" + "AKIA" + AWS_BODY, "ASIA" + AWS_BODY],
        "credential-github-token": ["tok " + "ghp" + "_" + rnd + "A1b2c3", "gho" + "_" + rnd + "A1b2c3", "github" + "_pat_" + rnd + "A1b2c3d4"],
        "credential-llm-key": ["OPENAI=" + "sk" + "-" + rnd + "9x", "sk" + "-ant-" + "api03-" + rnd],
        "credential-assignment": ['api_key = "{}"'.format(rnd), "password: {}".format(rnd), '"client_' + 'secret": "{}"'.format(rnd[:12]), "TOKEN={}".format(rnd)],
        "licence-key": ["serial " + "-".join(("K7QWE", "3R9TY", "UI2OP", "A5SDF", "G8HJK"))],
        "user-path-variant": [f"C{pct}3A{pct}5CUsers{pct}5CBob", f"file:///C{pct}3A{pct}2FUsers{pct}2FBob", bs + "Users" + bs + "Bob",
                              bs * 2 + "Users" + bs * 2 + "Bob", "/mnt/c/Us" + "ers/Bob/x", "/c/Us" + "ers/Bob", "C:" + bs + "Documents and Settings" + bs + "Bob"],
    }
    for rule, samples in positives.items():
        for s in samples:
            assert rule in hits(s), (rule, s)
    negatives = [
        "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "de:ad:be:ef:ca:fe",  # dummy / multicast MACs
        ":".join(("a1", "b2", "c3", "d4", "e5", "f6", "07", "18")),                                               # 8-byte id, not a MAC
        ":".join(f"{i * 17 % 256:02x}" for i in range(20)),                                                      # 20-byte fingerprint
        "00401000  8b ff 55 8b ec 83 e4 f8 6a ff 68 a0 12 40 00 64 a1 00 00 00 00",                              # hex dump
        "0x00401000: mov eax, dword ptr [ebp-0x8]  ; 8B 45 F8",                                                  # disassembly
        "8b ff 55 8b ec 83-e4 f8 6a ff 68 a0 12 40-00 64 a1 00 00 00 00 50",                                      # WinDbg-style dump
        "550e8400-e29b-41d4-a716-446655440000", "{8A3F5C21-9B7E-4D10-A2C6-1F0E3D5B7A94}",                          # UUIDs / GUIDs
        "UEsDBBQAAAAIAEGJ7FQ" + "AKIA" + AWS_BODY + "xYz+/9Qw==",                                # AWS shape inside base64
        "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",                # base64 PE header
        "ghp_" + "x" * 36, "AKIA" + "IOSFODNN7EXAMPLE", "sk-" + "x" * 40, "sk-ant-" + "your-key-here-0000000000",   # placeholders
        "task-queue-processing-pipeline-configuration-manager", "sk-learn", "risk-assessment-and-mitigation-plan-document",
        'password = "<REDACTED>"', "password = ''", 'api_key = os.environ["API_KEY"]', "token = self.token_value",
        'token_type = "TOKEN_ELEVATION_1"', 'secret = "${SECRET}"', 'password="%s"', 'token: str', "api_key=your_api_key_here",
        'password = "changeme123"', 'token = tokens.pop(0)', 'MAX_TOKEN = "ABC_123_XYZ_999"', "passwd = '/etc/passwd'",
        "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", "12345-67890-12345-67890-12345", "DEAD-BEEF-CAFE-F00D", "AES-256-GCM-SHA384",
        "<LICENSE-KEY>", "C:" + bs + "Users" + bs + "<USER>", f"C{pct}3A{pct}5CUsers{pct}5C{pct}3CUSER{pct}3E", "/mnt/c/Us" + "ers/Public/x",
        "-----BEGIN " + "RSA PRIVATE KEY----- header-only mention, no body",
    ]
    for s in negatives:
        assert not hits(s), (s, hits(s))
    # PEM: header + key-sized body fires, header alone does not (multi-line rule)
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2
    assert PRIVATE_KEY.search("-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n")
    assert PRIVATE_KEY.search("-----BEGIN " + "OPENSSH PRIVATE KEY-----\\n" + body)
    assert not PRIVATE_KEY.search("-----BEGIN " + "PRIVATE KEY-----\nthe header alone is just documentation\n")


_FAKE_NAME = "Zq" + "Fakeware"  # invented; a stand-in for a real product name
_FAKE_DENY = (("TARGET-99", (_FAKE_NAME, "zqfk")),)


def test_registry_parser_and_probes():
    good = "# comment\n\nTARGET-01 | Alpha Thing; alphasvc | tag one, tag two\nTARGET-02 | Beta | tag\n"
    assert _parse_registry(good) == (("TARGET-01", ("Alpha Thing", "alphasvc"), "tag one, tag two"),
                                     ("TARGET-02", ("Beta",), "tag"))
    for bad in ("TARGET-1 | Beta | t", "TARGET-01 | Beta", "TARGET-01 |  | t", "TARGET-01 | Be | t",
                "TARGET-01 | Beta | ", "name | Beta | t", "TARGET-01 | Beta | t\nTARGET-01 | Gamma | t"):
        with pytest.raises(ValueError):
            _parse_registry(bad)
    probes = _denylist_probes(_FAKE_DENY)
    for name in (_FAKE_NAME, "zqfk"):
        for ctx in (f"loaded {name}.sys", name.upper(), f"{name}64.exe", name.lower()):
            assert any(rx.search(ctx) for _, rx in probes), ctx
    assert not any(rx.search(f"xx{_FAKE_NAME}yy") for _, rx in probes), "names must match whole tokens"
    assert any(rx.search("zq-fakeware") for _, rx in _denylist_probes((("TARGET-98", ("zq fakeware",)),)))


def test_registry_loading_and_inactive_states(tmp_path, monkeypatch):
    absent = tmp_path / "nope.txt"
    monkeypatch.setenv(TARGETS_ENV, str(absent))
    entries, why = _load_denylist()
    assert entries == () and "no private target registry" in why and TARGETS_ENV in why
    assert _denylist_probes() == []  # inactive: no product probes; shape and identity rules still run
    empty = tmp_path / "empty.txt"
    empty.write_text("# only comments\n", encoding="utf-8")
    monkeypatch.setenv(TARGETS_ENV, str(empty))
    assert _load_denylist() == ((), f"private target registry at {empty} has no entries")
    live = tmp_path / "live.txt"
    live.write_text(f"TARGET-99 | {_FAKE_NAME}; zqfk | invented category\n", encoding="utf-8")
    monkeypatch.setenv(TARGETS_ENV, str(live))
    assert _load_denylist() == (_FAKE_DENY, "")
    bad = tmp_path / "bad.txt"
    bad.write_text("this is not a registry line\n", encoding="utf-8")
    monkeypatch.setenv(TARGETS_ENV, str(bad))
    with pytest.raises(ValueError, match="line 1"):
        _load_denylist()  # present but broken: loud, not silent


def test_product_rule_is_active_or_says_why():
    """Visible status of the product rule on THIS machine. Skips (never silently passes) when the
    private registry is missing, so a fresh clone or CI shows exactly why it is inactive."""
    entries, why = _load_denylist()
    if not entries:
        pytest.skip(f"PRODUCT RULE INACTIVE: {why}. Shape and operator-identity rules still ran.")
    assert _denylist_probes()


def _plant(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        (p.write_bytes if isinstance(content, bytes) else p.write_text)(content)
    if shutil.which("git") is None:
        (pytest.fail if os.environ.get("CI") else pytest.skip)("git not available")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run([*git, "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run([*git, "add", "-A"], cwd=tmp_path, check=True)
    return _git_ls(tmp_path)


def test_privacy_gate_reaches_planted_files(tmp_path):
    """Plant one offender per rule in a throwaway git repo and run the SAME scan_privacy the real
    test runs; also plant realistic clean files and require silence. Synthetic machine identity,
    so the proof is identical on every host (including CI)."""
    deny_name = _FAKE_NAME
    ident = _identity_probes(hostnames=["ZQHOST-" + "7K2"], usernames=["Zq" + "Operator"], homes=["D:\\work\\zqoperator"],
                             guids=["9f1c2d3e-4a5b-4c6d-8e7f-" + "0a1b2c3d4e5f"], serials=["7F3A-" + "91C2"],
                             macs=["3c4d5e6f7a8b"])
    rnd = "q8Zk3Wm1Vb7Xc2Nd5Ls9Rt4Hy6Ge0Pf"
    AWS_BODY = "QWERTY234567MNPK"
    planted = {
        "a_host.txt": "built on ZQHOST-" + "7K2 today\n",
        "a_user.md": "see C%3A%5CUs" + "ers%5Czq" + "operator\\x and ~Zq" + "Operator/x\n",
        "a_home.md": "cfg at D:\\\\work\\\\zq" + "operator\\\\cfg.json\n",
        "a_guid.txt": "id {9F1C2D3E-4A5B-4C6D-8E7F-" + "0A1B2C3D4E5F}\n",
        "a_serial.txt": "vol 7F3A-" + "91c2\n",
        "a_mac.txt": "nic " + "-".join(("3c", "4d", "5e", "6f", "7a", "8b")) + "\n",
        "b_mac.txt": "peer " + ":".join(("3c", "99", "5e", "6f", "7a", "8b")) + "\n",
        "b_aws.txt": "k=AKIA" + AWS_BODY + "\n",
        "b_gh.txt": "t=gh" + "p_" + rnd + "A1b2c3\n",
        "b_llm.txt": "k=sk" + "-ant-api03-" + rnd + "\n",
        "b_assign.py": 'api_key = "{}"\n'.format(rnd),
        "b_pem.txt": "-----BEGIN " + "PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2 + "\n",
        "b_lic.txt": "serial " + "-".join(("K7QWE", "3R9TY", "UI2OP", "A5SDF", "G8HJK")) + "\n",
        "c_deny.md": "line one\nthe " + deny_name + " driver loads early\n",
        f"notes_{deny_name}.md": "name only in the file name\n",
        "d_waived.txt": "peer " + ":".join(("3c", "99", "5e", "6f", "7a", "8b")) + "  # privacy-ok: mac-address\n",
        "d_unwaivable.txt": deny_name + "  # privacy-ok: denylisted-product\n",
        "utf16.txt": ("ZQHOST-" + "7K2\n").encode("utf-16"),
        "blob.bin": b"\0\0\0ZQHOST-7K2\0" + deny_name.encode(),  # genuine binary: skipped, as scan_repo skips it
        "clean_hexdump.txt": ("00401000  8b ff 55 8b ec 83 e4 f8 6a ff 68 a0 12 40 00 64\n" * 3
                              + "0x00401010: call dword ptr [0x00402000]  ; FF 15 00 20 40 00\n"),
        "clean_misc.txt": ("uuid 550e8400-e29b-41d4-a716-446655440000\nb64 TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAA=\n"
                           'password = "<REDACTED>"\nC:\\Users\\<USER>\\x\n' + "ghp_" + "x" * 36 + "\nTARGET-03 (kernel anti-cheat driver)\n"),
    }
    files = _plant(tmp_path, planted)
    found = scan_privacy(tmp_path, files, identity=ident, denylist=_FAKE_DENY)
    by_file = {}
    for x in found:
        by_file.setdefault(x.path, set()).add(x.rule)
    expect = {
        "a_host.txt": {"machine-hostname"}, "a_user.md": {"user-path-variant", "operator-username"},
        "a_home.md": {"operator-home", "operator-username"}, "a_guid.txt": {"machine-guid"}, "a_serial.txt": {"machine-volume-serial"},
        "a_mac.txt": {"machine-mac", "mac-address"}, "b_mac.txt": {"mac-address"}, "b_aws.txt": {"credential-aws-key"},
        "b_gh.txt": {"credential-github-token"}, "b_llm.txt": {"credential-llm-key"}, "b_assign.py": {"credential-assignment"},
        "b_pem.txt": {"credential-private-key"}, "b_lic.txt": {"licence-key"}, "c_deny.md": {"denylisted-product"},
        f"notes_{deny_name}.md": {"denylisted-product"}, "d_unwaivable.txt": {"denylisted-product"},
        "utf16.txt": {"machine-hostname"},
    }
    assert by_file == expect, {k: (by_file.get(k), expect.get(k)) for k in sorted(set(by_file) | set(expect)) if by_file.get(k) != expect.get(k)}
    # actionable: file, line, rule and the fix are all in the message; the secret and the name are not
    msg = _report(found)
    content_msg = _report([x for x in found if x.line])
    assert "c_deny.md:2: [denylisted-product]" in msg and "TARGET-NN" in msg
    assert "b_gh.txt:1: [credential-github-token]" in msg and "fix:" in msg
    assert rnd not in msg and deny_name not in content_msg and "ZQHOST" not in content_msg


def test_this_file_is_scanned_in_full_and_names_no_product(tmp_path):
    """Self-match defence, now structural: this file holds no names, so nothing is blanked. A planted
    copy at its own path that mentions a listed name anywhere is caught, as is a credential."""
    leaked = f"# header\n# mentions {_FAKE_NAME} here\n"
    secret = "# gh" + "p_" + "q8Zk3Wm1Vb7Xc2Nd5Ls9Rt4Hy6Ge0Pf" + "A1b2c3\n"
    for i, (content, want) in enumerate(((leaked, {("denylisted-product", 2)}),
                                         (secret, {("credential-github-token", 1)}), ("# clean\n", set()))):
        repo = tmp_path / f"case{i}"
        repo.mkdir(parents=True)
        files = _plant(repo, {SELF: content, "pad.txt": "x\n"})
        got = {(x.rule, x.line) for x in scan_privacy(repo, files, identity=[], denylist=_FAKE_DENY) if x.path == SELF}
        assert got == want, (got, want)
    assert not [x for x in scan_privacy(ROOT, [SELF]) if x.path == SELF], "this file trips its own rules"


def test_privacy_gate_waiver_and_marker_rules():
    assert _waived("x  # privacy-ok: mac-address, licence-key") == {"mac-address", "licence-key"}
    assert _waived("nothing here") == set()
    assert WAIVABLE <= set(PRIVACY_FIX) and "denylisted-product" not in WAIVABLE
    assert not {"machine-hostname", "operator-username", "operator-home", "machine-guid", "machine-mac",
                "machine-volume-serial", "user-path-variant"} & WAIVABLE


def test_machine_identity_probes_see_this_machine():
    """The probes are built from the live host, not from literals; a non-generic host name or
    account must therefore be found. (On a CI runner everything is generic and this proves nothing,
    which is why test_privacy_gate_reaches_planted_files uses synthetic values.)"""
    rules = {r for r, _ in _machine_identity()}
    host = socket.gethostname()
    if len(host) >= 4 and host.lower() not in _GENERIC_NAMES and not host.lower().startswith(_GENERIC_HOST_PREFIX):
        assert "machine-hostname" in rules
    user = getpass.getuser()
    if len(user) >= 3 and user.lower() not in _GENERIC_NAMES:
        assert "operator-username" in rules
    for rule, rx in _machine_identity():
        assert rule in PRIVACY_FIX and isinstance(rx.pattern, str)


def test_no_privacy_leaks_in_repo():
    findings = scan_privacy(ROOT, _tracked())
    assert not findings, _report(findings)


def test_tool_families_docstring_table_matches_live_report():
    # Exists because the hand-written declared/implemented table drifted twice before a human noticed.
    from liebert_re.report import tool_families as tf

    doc = tf.__doc__ or ""
    block = doc[doc.index("named / locally defined"):]
    block = block[:block.index("Re-measure")]
    parsed = {m.group(1): (int(m.group(2)), int(m.group(3)))
              for m in re.finditer(r"([a-z][a-z-]*) (\d+)/(\d+)", block)}
    assert parsed == tf.published_family_report()
