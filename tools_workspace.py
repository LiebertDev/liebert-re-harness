import fnmatch
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE_ACK_BROAD_ENV = "TEACHER_WORKSPACE_ACK_BROAD"
_WORKSPACE_FROM_ENV = "TEACHER_WORKSPACE" in os.environ
WORKSPACE_ROOT = Path(os.getenv("TEACHER_WORKSPACE", str(Path.cwd()))).expanduser().resolve()
# Backwards-compatible runtime name. Project-owned data must use PROJECT_ROOT;
# analysis tools intentionally remain sandboxed to WORKSPACE_ROOT.
WORKSPACE = WORKSPACE_ROOT
EXCLUDED_DIRS = {".git", ".venv", "__pycache__", "node_modules", ".vs", "dataset"}
TEXT_LOCAL_CODEPAGE_ENV = "TEACHER_TEXT_LOCAL_CODEPAGE"

_POSIX_LANDMARK_DIRS = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/var", "/opt", "/boot",
    "/dev", "/proc", "/sys", "/root", "/home", "/tmp", "/srv", "/mnt", "/media",
    "/Users", "/Library", "/System", "/Applications", "/Volumes",
)


def _host_is_posix() -> bool:
    return os.name != "nt"



def _broad_scope_landmarks() -> set:
    """Filesystem locations that are obviously system-wide, not a real analysis
    target. safe_path() only checks that a file is *inside* WORKSPACE_ROOT, so
    if WORKSPACE_ROOT itself is one of these, every file on the machine (or on
    the drive) becomes readable by static-analysis tools. Fail closed on these
    unless the operator explicitly acknowledges it."""
    landmarks = set()
    try:
        landmarks.add(Path.home().resolve())
    except Exception:
        pass
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = os.environ.get(env_name)
        if value:
            try:
                landmarks.add(Path(value).resolve())
            except Exception:
                pass
    windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot")
    if windir:
        try:
            node = Path(windir).resolve()
            while True:
                landmarks.add(node)
                if node.parent == node:
                    break
                node = node.parent
        except Exception:
            pass
    if _host_is_posix():
        # The Windows set above is built from Windows-only environment
        # variables, so on POSIX it would collapse to just the home
        # directory. These are the POSIX equivalents of the Windows dir /
        # Program Files / user-profile root: system config and binaries,
        # every user's home, and the shared scratch/mount points. Guarding
        # against the same thing -- a workspace ROOT set to a system-wide
        # directory turning "inside the workspace" into "anywhere on the
        # machine". Only the directory itself is refused; a project beneath
        # one (e.g. /home/me/target) is still a legitimate root.
        for name in _POSIX_LANDMARK_DIRS:
            try:
                landmarks.add(Path(name).resolve())
            except Exception:
                pass
    return landmarks


def _is_over_broad_root(root: Path) -> bool:
    """True for a drive/filesystem root (``C:\\``, ``/``) or a known
    system-wide directory (Windows dir, user profile root, Program Files)."""
    try:
        if root.parent == root:
            return True
        return root in _broad_scope_landmarks()
    except Exception:
        # Unresolvable/unknown roots are refused, not silently allowed.
        return True


def _acknowledged_broad() -> bool:
    return os.getenv(WORKSPACE_ACK_BROAD_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


_WORKSPACE_OVER_BROAD = _is_over_broad_root(WORKSPACE_ROOT)
_WORKSPACE_BROAD_ACK = _acknowledged_broad()

if _WORKSPACE_OVER_BROAD and not _WORKSPACE_BROAD_ACK:
    raise PermissionError(
        f"Workspace root '{WORKSPACE_ROOT}' is over-broad (a drive/filesystem root or a "
        "system-wide directory such as the Windows folder, user profile, or Program Files). "
        "Static-analysis tools gate solely on containment inside this root, so an over-broad "
        "root would let them read the entire drive. Narrow TEACHER_WORKSPACE (or teacher.py "
        "--target-root, upstream-only and not part of the published package) to the actual "
        "analysis "
        f"target, or set {WORKSPACE_ACK_BROAD_ENV}=1 to "
        "explicitly acknowledge broad access."
    )


def workspace_scope() -> dict:
    """Effective static-analysis scope for this process, for callers (CLI banners,
    environment_manifest.py -- upstream-only, not part of the published package) that
    need to record what a run was actually gated to."""
    return {
        "root": str(WORKSPACE_ROOT),
        "source": "env" if _WORKSPACE_FROM_ENV else "cwd_default",
        "over_broad": _WORKSPACE_OVER_BROAD,
        "broad_ack_used": _WORKSPACE_OVER_BROAD and _WORKSPACE_BROAD_ACK,
    }
MAX_FILE_BYTES = 8_000_000
MAX_READ_LINES = 500
MAX_SEARCH_RESULTS = 250
MAX_FIND_RESULTS = 400

def _looks_like_windows_absolute_path(raw: str) -> bool:
    """Pure string check for Windows absolute-path syntax: a drive letter
    (``C:\\x`` / ``C:/x``) or a UNC/bare-rooted path (``\\\\server\\share``
    / ``\\x``). Deliberately platform-independent (no filesystem access,
    no ``os.name`` check) so it is directly unit-testable on any host --
    see ``tests/test_tools_workspace_safe_path.py`` for the isolated proof
    this exists to make possible without waiting on a Linux CI run.
    """
    if raw[:1] == "\\":
        return True
    return len(raw) >= 3 and raw[0].isalpha() and raw[1] == ":" and raw[2] in "\\/"


def safe_path(path="."):
    raw = str(path or ".").strip()
    # POSIX-only guard, checked BEFORE any Path parsing. Root cause
    # (measured live -- see tests/test_tools_archive_extract.py::
    # TestExtractOutcomes::test_dest_path_outside_workspace_is_path_refused,
    # which failed only on Linux CI): backslash is not a path separator on
    # POSIX, so e.g. Path("C:\\Windows\\evil.txt") is neither absolute nor
    # traversal there -- pathlib treats the whole string as ONE ordinary,
    # oddly-named RELATIVE path component. That gets silently joined
    # *inside* WORKSPACE below (containment technically still holds -- the
    # write lands under WORKSPACE, not on the real /Windows -- but the
    # caller's plainly-foreign path is accepted instead of refused, which
    # is not the fail-closed contract this function promises). On native
    # Windows this exact same syntax is already absolute per
    # ``Path.is_absolute()`` (drive-letter case) or already resolves
    # outside WORKSPACE via the existing drive-substituting join (bare
    # ``\\...`` case -- see ``_looks_like_windows_absolute_path``'s
    # docstring), so this guard is a deliberate no-op there and must never
    # fire for an ordinary Windows path already inside WORKSPACE (whose
    # own root is itself a drive letter).
    if os.name != "nt" and _looks_like_windows_absolute_path(raw):
        raise PermissionError("Access outside the workspace root is denied.")
    p = Path(raw)
    target = p.resolve() if p.is_absolute() else (WORKSPACE / p).resolve()
    try:
        target.relative_to(WORKSPACE)
    except ValueError:
        raise PermissionError("Access outside the workspace root is denied.")
    return target

def relative(path):
    return "." if path == WORKSPACE else str(path.relative_to(WORKSPACE))

def skipped(path):
    try:
        parts = path.relative_to(WORKSPACE).parts
    except ValueError:
        return True
    return any(x in EXCLUDED_DIRS for x in parts)

def text_of(path):
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        raise UnicodeError("binary")
    # Order is deliberate. cp1252 is the general Western legacy default; a
    # machine-specific codepage (e.g. cp1254, Turkish) must NOT outrank it:
    # cp1254 accepts nearly every byte cp1252 does, so placed first it would
    # silently mis-decode other text (0xF0 is "ð" in cp1252 but "ğ" in
    # cp1254) and a second entry behind it is unreachable. An operator whose
    # files really use a local codepage opts in explicitly.
    local = os.environ.get(TEXT_LOCAL_CODEPAGE_ENV, "").strip()
    encodings = ["utf-8", "utf-8-sig"]
    if local:
        encodings.append(local)
    encodings.append("cp1252")
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return data.decode("utf-8", errors="replace")

def member_content(raw, max_chars):
    """Describe raw member bytes honestly: text only if they are valid UTF-8.

    Returns {'content_kind':'text','content','truncated'} for a member that
    decodes cleanly, else {'content_kind':'binary','sha256','first_invalid_utf8_offset'}
    with NO 'content' key. Never substitutes U+FFFD: a lossy string presented as
    content would be corrupted data reported as success."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return {"content_kind": "binary", "sha256": hashlib.sha256(raw).hexdigest(),
                "first_invalid_utf8_offset": exc.start}
    return {"content_kind": "text", "content": text[:max_chars], "truncated": len(text) > max_chars}

def list_directory(path=".", recursive=False, max_depth=2):
    target = safe_path(path)
    if not target.is_dir():
        return f"Directory not found: {path}"
    result = []
    if not recursive:
        items = sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        for item in items:
            if skipped(item):
                continue
            kind = "DIR" if item.is_dir() else "FILE"
            size = "" if item.is_dir() else f" ({item.stat().st_size} bytes)"
            result.append(f"{kind}: {relative(item)}{size}")
            if len(result) >= 500:
                break
        return "\n".join(result) or "Directory is empty."
    base_depth = len(target.parts)
    for root, dirs, fs in os.walk(target):
        root = Path(root)
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        depth = len(root.parts) - base_depth
        if depth >= int(max_depth):
            dirs[:] = []
        for d in sorted(dirs):
            result.append(f"DIR: {relative(root/d)}")
        for n in sorted(fs):
            p = root/n
            if skipped(p):
                continue
            try: size = p.stat().st_size
            except OSError: size = -1
            result.append(f"FILE: {relative(p)} ({size} bytes)")
        if len(result) >= 500:
            return "\n".join(result[:500]) + "\n[limit:500]"
    return "\n".join(result) or "Directory is empty."

def find_files(pattern="*", path="."):
    target = safe_path(path)
    if not target.is_dir():
        return f"Directory not found: {path}"
    out=[]
    pat=pattern.lower()
    for p in target.rglob("*"):
        if skipped(p) or not p.is_file():
            continue
        if fnmatch.fnmatch(p.name.lower(), pat) or fnmatch.fnmatch(relative(p).lower(), pat):
            out.append(relative(p))
            if len(out)>=MAX_FIND_RESULTS: break
    return "\n".join(out) if out else "File not found."

def read_file(path, start_line=1, end_line=None):
    p=safe_path(path)
    if not p.is_file(): return f"File not found: {path}"
    if p.stat().st_size>MAX_FILE_BYTES:
        return f"File too large ({p.stat().st_size} bytes). Use search_text instead."
    try: lines=text_of(p).splitlines()
    except UnicodeError: return "Binary dosya; binary/decompiler tool kullan."
    total=len(lines); start=max(1,int(start_line or 1))
    end=int(end_line) if end_line is not None else start+MAX_READ_LINES-1
    end=min(end,start+MAX_READ_LINES-1,total)
    if total and start>total: return f"{total} line(s) total."
    out=[f"[{relative(p)} | lines {start}-{end}/{total}]"]
    out += [f"{i}: {line}" for i,line in enumerate(lines[start-1:end],start)]
    if end<total: out.append(f"[more follows: start_line={end+1}]")
    return "\n".join(out)

def read_files(paths):
    if not isinstance(paths,list): return "paths must be a list."
    return "\n\n".join(read_file(str(p),1,250) for p in paths[:10])

def search_text(query,path=".",file_pattern="*",case_sensitive=False):
    target=safe_path(path)
    if not target.is_dir(): return f"Directory not found: {path}"
    needle=query if case_sensitive else query.lower()
    out=[]
    for p in target.rglob("*"):
        if skipped(p) or not p.is_file(): continue
        if not fnmatch.fnmatch(p.name.lower(),file_pattern.lower()): continue
        try:
            if p.stat().st_size>MAX_FILE_BYTES: continue
            text=text_of(p)
        except (OSError,UnicodeError): continue
        for i,line in enumerate(text.splitlines(),1):
            hay=line if case_sensitive else line.lower()
            if needle in hay:
                out.append(f"{relative(p)}:{i}: {line.strip()}")
                if len(out)>=MAX_SEARCH_RESULTS:
                    return "\n".join(out)+f"\n[limit:{MAX_SEARCH_RESULTS}]"
    return "\n".join(out) if out else "No results found."

def get_file_info(path):
    p=safe_path(path)
    if not p.exists(): return f"Not found: {path}"
    st=p.stat()
    d={"path":relative(p),"type":"directory" if p.is_dir() else "file",
       "size_bytes":st.st_size,"modified":datetime.fromtimestamp(st.st_mtime).isoformat()}
    return json.dumps(d,ensure_ascii=False,indent=2)

