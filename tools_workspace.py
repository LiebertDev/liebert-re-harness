import fnmatch
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
        f"--target-root) to the actual analysis target, or set {WORKSPACE_ACK_BROAD_ENV}=1 to "
        "explicitly acknowledge broad access."
    )


def workspace_scope() -> dict:
    """Effective static-analysis scope for this process, for callers (CLI banners,
    environment_manifest.py) that need to record what a run was actually gated to."""
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

def safe_path(path="."):
    p = Path(str(path or ".").strip())
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
    for enc in ("utf-8", "utf-8-sig", "cp1254", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")

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

