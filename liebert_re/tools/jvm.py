"""JVM bytecode decompilation (GAP-012) via JADX (already installed for
dex_decompiler; JADX also decompiles plain .class/.jar directly, not just
DEX/APK). Complements java_class_inspect's constant-pool-only structural
parse and archive_inspect's plain JAR listing with real decompiled Java
source. Does not disassemble raw JVM bytecode itself -- only via JADX's own
decompiled output, same split as dex_decompiler."""
from __future__ import annotations
import json,os,re,shutil,tempfile,zipfile
from pathlib import Path
from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.workspace import safe_path,relative

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

def _jadx():
    explicit=os.getenv("JADX_EXE","jadx")
    found=shutil.which(explicit)
    if found:return found
    bundled=Path.home()/"teacher-tools"/"jadx"/"bin"/"jadx.bat"
    return str(bundled) if bundled.exists() else None

def _descriptor_to_java_relpath(name):
    n=(name or '').strip().replace('.','/')
    return n+'.java'

def _list_classes(p,is_jar):
    if is_jar:
        with zipfile.ZipFile(p) as z:
            return [n[:-6].replace('/','.') for n in z.namelist() if n.endswith('.class') and '$' not in n]
    data=p.read_bytes()
    if data[:4]!=b'\xca\xfe\xba\xbe':raise ValueError('NOT_JVM_CLASS_OR_JAR')
    return [p.stem]

def jvm_decompiler(path,operation='classes',class_name='',max_items=300,max_chars=40000,cancellation_token=None):
    p=safe_path(path);max_items=max(1,min(int(max_items),2000));max_chars=max(1000,min(int(max_chars),120000))
    is_jar=zipfile.is_zipfile(p)
    try:classes=_list_classes(p,is_jar)
    except Exception as e:return _j({'ok':False,'tool':'jvm_decompiler','path':relative(p),'operation':operation,'error':f'NOT_JVM_TARGET: {e}'})
    base={'ok':True,'tool':'jvm_decompiler','format':'JAR' if is_jar else 'CLASS','path':relative(p),'operation':operation,'class_count':len(classes)}
    if operation in {'summary','headers','classes'}:
        return _j({**base,'classes':classes[:max_items],'truncated':len(classes)>max_items})
    if operation=='decompile_class':
        target=class_name or (classes[0] if len(classes)==1 else '')
        if not target:return _j({**base,'ok':False,'error':'CLASS_NAME_REQUIRED'})
        exe=_jadx()
        if not exe:return _j({**base,'ok':False,'error':'JADX_TOOL_MISSING'})
        with tempfile.TemporaryDirectory(prefix='jadx_jvm_out_') as tmp:
            cp=run_bounded_process([exe,'-d',tmp,str(p)],timeout_seconds=180,cancellation_token=cancellation_token,max_output_chars=2_000_000)
            if cp.cancelled:return _j({**base,'ok':False,'error':'JADX_CANCELLED_PROCESS_TREE_TERMINATED'})
            if cp.timed_out:return _j({**base,'ok':False,'error':'JADX_TIMEOUT_PROCESS_TREE_TERMINATED'})
            rel=_descriptor_to_java_relpath(target)
            candidates=[Path(tmp)/'sources'/rel,*Path(tmp).rglob(Path(rel).name)]
            hit=next((c for c in candidates if c.exists()),None)
            if not hit:return _j({**base,'ok':False,'error':'CLASS_NOT_FOUND_IN_DECOMPILED_OUTPUT','jadx_stderr':(cp.stderr or '')[-1500:]})
            text=hit.read_text(encoding='utf-8',errors='replace')
        return _j({**base,'class':target,'content':text[:max_chars],'truncated':len(text)>max_chars})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_JVM_OPERATION'})


def jvm_status():
    """Whether JADX (the decompiler behind `decompile_class`) is reachable, where from,
    whether it actually runs, and its version -- the capability probe to run before
    reporting JVM class/JAR decompilation as unavailable.

    Runs `jadx --version` once (starts a JVM, opens no input; seconds). Statuses: `OK`,
    `TOOL_MISSING` (`detail` names JADX_EXE and the other places it looked), `TIMEOUT`, and
    `ANALYSIS_LIMITED` (a launcher resolved but did not print a version, which on this tool
    usually means no usable Java runtime: JADX is a Java program, so a launcher can exist
    and still not work). `resolved_by` is JADX_EXE, PATH or bundled_fallback (the per-user
    tools folder). `operations_without_the_tool` are answered by pure-Python parsing and
    keep working when JADX is missing; only `decompile_class` needs it.
    """
    tool = "jvm_status"
    try:
        exe = _jadx()
        if not exe:
            return _j({
                "ok": False, "tool": tool, "status": "TOOL_MISSING", "resolved": False,
                "required_capability": "JADX launcher (jadx / jadx.bat) and a Java runtime",
                "detail": (
                    "jadx was not found. Set JADX_EXE to its full path (or to a name on PATH), or put "
                    "its bin folder on PATH; the last place this module looks is "
                    f"{Path.home() / 'teacher-tools' / 'jadx' / 'bin' / 'jadx.bat'}. JADX also needs Java "
                    "on PATH or JAVA_HOME. decompile_class cannot run until then."
                ),
                "env_set": {"JADX_EXE": bool(os.getenv("JADX_EXE", "").strip())},
                "operations_without_the_tool": ["summary", "headers", "classes"],
            })

        def _same(a, b):
            return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))

        explicit = os.getenv("JADX_EXE", "").strip()
        resolved_by = "bundled_fallback"
        if explicit and shutil.which(explicit) and _same(exe, shutil.which(explicit)):
            resolved_by = "JADX_EXE"
        else:
            on_path = shutil.which("jadx")
            if on_path and _same(exe, on_path):
                resolved_by = "PATH"
        cp = run_bounded_process([exe, "--version"], timeout_seconds=30, max_output_chars=8192)
        if cp.timed_out or cp.cancelled:
            return _j({"ok": False, "tool": tool, "status": "TIMEOUT", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "JADX_VERSION_TIMEOUT"})
        text = ((cp.stdout or "") + chr(10) + (cp.stderr or "")).strip()
        match = re.search(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\S*", text)
        if cp.returncode not in (0, None) or not match:
            return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "binary": exe,
                       "resolved_by": resolved_by, "runnable": False, "error": "JADX_VERSION_UNREADABLE",
                       "exit_code": cp.returncode, "output_tail": text[-500:],
                       "detail": "The launcher resolved but did not print a version when run. Check that a Java runtime is installed and on PATH or JAVA_HOME."})
        return _j({
            "ok": True, "tool": tool, "status": "OK",
            "binary": exe, "resolved_by": resolved_by, "runnable": True,
            "version": match.group(0),
            "operations": ["jvm_decompiler", "jvm_status"],
            "operations_without_the_tool": ["summary", "headers", "classes"],
            "note": (
                "OK means the launcher started a JVM and printed its version; no input file was opened. "
                "decompile_class decompiles the whole input before it reads one class, so it can take "
                "minutes on a large file."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "JADX_STATUS_UNEXPECTED_ERROR",
                   "detail": f"{type(exc).__name__}: {exc}"})
