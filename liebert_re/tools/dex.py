"""Structured DEX (Android Dalvik bytecode) inspection: pure-Python header/
class/string-pool structural parse (no external tool), plus bounded JADX
decompilation for a single named class. Does not disassemble Dalvik method
bytecode itself -- that depth comes only through JADX's own decompiled
Java source, mirroring dotnet_inspect's structural-metadata/ILSpy-decompile split."""
from __future__ import annotations
import json,os,re,shutil,struct,tempfile
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

_DEX_HDR_FMT='<8sI20s'+('I'*20)
_DEX_HDR_FIELDS=('magic','checksum','signature','file_size','header_size','endian_tag','link_size','link_off','map_off','string_ids_size','string_ids_off','type_ids_size','type_ids_off','proto_ids_size','proto_ids_off','field_ids_size','field_ids_off','method_ids_size','method_ids_off','class_defs_size','class_defs_off','data_size','data_off')

def _uleb128(data,pos):
    result=0;shift=0
    while True:
        b=data[pos];pos+=1;result|=(b&0x7f)<<shift
        if not (b&0x80):break
        shift+=7
    return result,pos

def _mutf8_decode(raw):
    # DEX strings are Modified UTF-8 (same encoding as JVM classfiles): a
    # supplementary character is encoded as a pair of 3-byte sequences over the
    # UTF-16 surrogate pair, never a real 4-byte UTF-8 sequence -- decoding as
    # plain UTF-8 would silently mis-handle those, so this implements the real
    # DEX string encoding rather than approximating it with a stdlib codec.
    units=[];i=0;n=len(raw)
    while i<n:
        b=raw[i]
        if b<0x80:units.append(b);i+=1
        elif b&0xE0==0xC0 and i+1<n:units.append(((b&0x1F)<<6)|(raw[i+1]&0x3F));i+=2
        elif b&0xF0==0xE0 and i+2<n:units.append(((b&0x0F)<<12)|((raw[i+1]&0x3F)<<6)|(raw[i+2]&0x3F));i+=3
        else:units.append(0xFFFD);i+=1
    chars=[];j=0
    while j<len(units):
        u=units[j]
        if 0xD800<=u<=0xDBFF and j+1<len(units) and 0xDC00<=units[j+1]<=0xDFFF:
            chars.append(0x10000+((u-0xD800)<<10)+(units[j+1]-0xDC00));j+=2
        else:chars.append(u);j+=1
    return ''.join(chr(c) for c in chars)

def _string_at(data,off):
    _,pos=_uleb128(data,off)
    end=data.find(b'\x00',pos)
    raw=data[pos:end] if end>=0 else data[pos:]
    return _mutf8_decode(raw)

def _header(data):
    if len(data)<112 or data[:4]!=b'dex\n':raise ValueError('NOT_DEX')
    vals=struct.unpack_from(_DEX_HDR_FMT,data,0)
    h=dict(zip(_DEX_HDR_FIELDS,vals))
    h['magic']=data[:8].rstrip(b'\x00').decode('ascii',errors='replace')
    h['signature']=data[8:28].hex()
    return h

def _type_name(data,h,type_idx):
    if type_idx is None or type_idx==0xFFFFFFFF or type_idx>=h['type_ids_size']:return None
    string_idx=struct.unpack_from('<I',data,h['type_ids_off']+type_idx*4)[0]
    if string_idx>=h['string_ids_size']:return None
    off=struct.unpack_from('<I',data,h['string_ids_off']+string_idx*4)[0]
    return _string_at(data,off)

def _classes(data,h,max_items):
    out=[]
    for i in range(min(h['class_defs_size'],max_items)):
        off=h['class_defs_off']+i*32
        class_idx,access_flags,superclass_idx,interfaces_off,source_file_idx,annotations_off,class_data_off,static_values_off=struct.unpack_from('<IIIIIIII',data,off)
        source_file=None
        if source_file_idx!=0xFFFFFFFF and source_file_idx<h['string_ids_size']:
            soff=struct.unpack_from('<I',data,h['string_ids_off']+source_file_idx*4)[0];source_file=_string_at(data,soff)
        out.append({'name':_type_name(data,h,class_idx),'superclass':_type_name(data,h,superclass_idx),'source_file':source_file,'access_flags':hex(access_flags),'has_class_data':class_data_off!=0})
    return out

def _strings(data,h,max_items):
    out=[]
    for i in range(min(h['string_ids_size'],max_items)):
        off=struct.unpack_from('<I',data,h['string_ids_off']+i*4)[0]
        out.append(_string_at(data,off))
    return out

def _descriptor_to_java_relpath(name):
    n=(name or '').strip()
    if n.startswith('L') and n.endswith(';'):n=n[1:-1]
    else:n=n.replace('.','/')
    return n+'.java'

def dex_decompiler(path,operation='summary',class_name='',max_items=300,max_chars=40000,cancellation_token=None):
    p=safe_path(path);max_items=max(1,min(int(max_items),2000));max_chars=max(1000,min(int(max_chars),120000))
    data=p.read_bytes()
    try:h=_header(data)
    except Exception as e:return _j({'ok':False,'tool':'dex_decompiler','path':relative(p),'operation':operation,'error':f'NOT_DEX_OR_PARSE_ERROR: {e}'})
    base={'ok':True,'tool':'dex_decompiler','format':'DEX','path':relative(p),'operation':operation,'dex_format_version':h['magic'].replace('dex','').strip(),'file_size':h['file_size'],'string_count':h['string_ids_size'],'type_count':h['type_ids_size'],'class_count':h['class_defs_size'],'method_count':h['method_ids_size'],'field_count':h['field_ids_size']}
    if operation in {'summary','headers'}:return _j({**base,'sha1_signature':h['signature'],'checksum':hex(h['checksum'])})
    if operation=='classes':
        classes=_classes(data,h,max_items);return _j({**base,'classes':classes,'truncated':h['class_defs_size']>max_items})
    if operation=='strings':
        strings=_strings(data,h,max_items);return _j({**base,'strings':strings,'truncated':h['string_ids_size']>max_items})
    if operation=='decompile_class':
        if not class_name:return _j({**base,'ok':False,'error':'CLASS_NAME_REQUIRED'})
        exe=_jadx()
        if not exe:return _j({**base,'ok':False,'error':'JADX_TOOL_MISSING'})
        with tempfile.TemporaryDirectory(prefix='jadx_out_') as tmp:
            cp=run_bounded_process([exe,'-d',tmp,str(p)],timeout_seconds=180,cancellation_token=cancellation_token,max_output_chars=2_000_000)
            if cp.cancelled:return _j({**base,'ok':False,'error':'JADX_CANCELLED_PROCESS_TREE_TERMINATED'})
            if cp.timed_out:return _j({**base,'ok':False,'error':'JADX_TIMEOUT_PROCESS_TREE_TERMINATED'})
            rel=_descriptor_to_java_relpath(class_name)
            candidates=[Path(tmp)/'sources'/rel,*Path(tmp).rglob(Path(rel).name)]
            hit=next((c for c in candidates if c.exists()),None)
            if not hit:return _j({**base,'ok':False,'error':'CLASS_NOT_FOUND_IN_DECOMPILED_OUTPUT','jadx_stderr':(cp.stderr or '')[-1500:]})
            text=hit.read_text(encoding='utf-8',errors='replace')
        return _j({**base,'class':class_name,'content':text[:max_chars],'truncated':len(text)>max_chars})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_DEX_OPERATION'})


def dex_status():
    """Whether JADX (the decompiler behind `decompile_class`) is reachable, where from,
    whether it actually runs, and its version -- the capability probe to run before
    reporting DEX/APK decompilation as unavailable.

    Runs `jadx --version` once (starts a JVM, opens no input; seconds). Statuses: `OK`,
    `TOOL_MISSING` (`detail` names JADX_EXE and the other places it looked), `TIMEOUT`, and
    `ANALYSIS_LIMITED` (a launcher resolved but did not print a version, which on this tool
    usually means no usable Java runtime: JADX is a Java program, so a launcher can exist
    and still not work). `resolved_by` is JADX_EXE, PATH or bundled_fallback (the per-user
    tools folder). `operations_without_the_tool` are answered by pure-Python parsing and
    keep working when JADX is missing; only `decompile_class` needs it.
    """
    tool = "dex_status"
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
                "operations_without_the_tool": ["summary", "headers", "classes", "strings"],
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
            "operations": ["dex_decompiler", "dex_status"],
            "operations_without_the_tool": ["summary", "headers", "classes", "strings"],
            "note": (
                "OK means the launcher started a JVM and printed its version; no input file was opened. "
                "decompile_class decompiles the whole input before it reads one class, so it can take "
                "minutes on a large file."
            ),
        })
    except Exception as exc:  # noqa: BLE001 - the contract is a JSON string, never an exception
        return _j({"ok": False, "tool": tool, "status": "ANALYSIS_LIMITED", "error": "JADX_STATUS_UNEXPECTED_ERROR",
                   "detail": f"{type(exc).__name__}: {exc}"})
