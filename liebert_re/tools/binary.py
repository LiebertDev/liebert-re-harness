import hashlib, json, math, os, re
from liebert_re.bounded_subprocess import run_bounded_process
from liebert_re.workspace import safe_path, relative, skipped

try:
    from liebert_re.evidence.index import record_write as _evidence_index_record_write
except Exception:  # pragma: no cover - an indexing dependency must never block evidence writing
    def _evidence_index_record_write(*_args, **_kwargs):
        return {"ok": False, "error": "EVIDENCE_INDEX_UNAVAILABLE"}

from liebert_re.workspace import PROJECT_ROOT as APP
# Module-level attribute deliberately named EVIDENCE (not e.g.
# _RESOURCE_EVIDENCE): tests/conftest.py's per-test isolation guard
# auto-discovers every imported module's EVIDENCE attribute by this exact
# name and redirects it to a scratch directory for the test's duration --
# see conftest.py's _evidence_owning_modules()/_redirect_tool_evidence_dirs_
# away_from_the_real_ledger. A differently-named attribute would silently
# write real files into the shipped evidence ledger during test runs.
EVIDENCE=APP/'dataset'/'evidence'/'pe_resources'
EVIDENCE.mkdir(parents=True,exist_ok=True)

BINARY_EXTS={".exe",".dll",".sys",".ocx",".cpl",".scr",".efi"}

def _entropy(data):
    if not data:return 0.0
    counts=[0]*256
    for b in data:counts[b]+=1
    n=len(data); e=0.0
    for c in counts:
        if c:
            p=c/n; e-=p*math.log2(p)
    return round(e,4)

def _pe(p):
    import pefile
    # Parse from owned bytes (not pefile.PE(str(p))) so pefile cannot retain a
    # Windows file handle after the caller is done with the returned object.
    return pefile.PE(data=p.read_bytes(),fast_load=False)

def find_binaries(path=".",max_results=300):
    root=safe_path(path); out=[]
    for p in root.rglob("*"):
        if skipped(p) or not p.is_file():continue
        if p.suffix.lower() in BINARY_EXTS:
            out.append(f"{relative(p)} ({p.stat().st_size} bytes)")
            if len(out)>=max_results:break
    return "\n".join(out) if out else "No binary found."

def hash_file(path):
    p=safe_path(path)
    hs={n:hashlib.new(n) for n in ("sha256","sha1","md5")}
    with p.open("rb") as f:
        for ch in iter(lambda:f.read(1024*1024),b""):
            for h in hs.values():h.update(ch)
    return json.dumps({"path":relative(p),**{k:v.hexdigest() for k,v in hs.items()}},indent=2)

def binary_summary(path):
    p=safe_path(path); data=p.read_bytes()
    out={"path":relative(p),"size_bytes":len(data),"entropy":_entropy(data),"is_pe":data[:2]==b"MZ"}
    if not out["is_pe"]:return json.dumps(out,indent=2)
    pe=_pe(p)
    out.update({
        "machine":hex(pe.FILE_HEADER.Machine),
        "timestamp":int(pe.FILE_HEADER.TimeDateStamp),
        "entry_point_rva":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base":hex(pe.OPTIONAL_HEADER.ImageBase),
        "subsystem":int(pe.OPTIONAL_HEADER.Subsystem),
        "dll_characteristics":hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "clr":len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress!=0,
        "sections":[{"name":s.Name.rstrip(b"\x00").decode(errors="replace"),
                     "rva":hex(s.VirtualAddress),"raw_size":int(s.SizeOfRawData),
                     "entropy":round(float(s.get_entropy()),4)} for s in pe.sections]
    })
    return json.dumps(out,ensure_ascii=False,indent=2)

def binary_strings(path,min_length=4,contains=None,max_results=300):
    p=safe_path(path); data=p.read_bytes(); min_length=max(3,min(int(min_length),64))
    ar=re.compile(rb"[\x20-\x7e]{"+str(min_length).encode()+rb",}")
    ur=re.compile(rb"(?:[\x20-\x7e]\x00){"+str(min_length).encode()+rb",}")
    vals=[]
    for m in ar.finditer(data):vals.append((m.start(),"ascii",m.group().decode("ascii",errors="replace")))
    for m in ur.finditer(data):vals.append((m.start(),"utf16",m.group().decode("utf-16le",errors="replace")))
    vals.sort()
    out=[]
    for off,k,s in vals:
        if contains and contains.lower() not in s.lower():continue
        out.append(f"0x{off:X} [{k}] {s}")
        if len(out)>=max_results:break
    return "\n".join(out) if out else "No strings found."

def pe_sections(path):
    p=safe_path(path); pe=_pe(p)
    return json.dumps([{"name":s.Name.rstrip(b"\x00").decode(errors="replace"),
                        "rva":hex(s.VirtualAddress),"virtual_size":int(s.Misc_VirtualSize),
                        "raw_offset":hex(s.PointerToRawData),"raw_size":int(s.SizeOfRawData),
                        "characteristics":hex(s.Characteristics),
                        "entropy":round(float(s.get_entropy()),4)} for s in pe.sections],indent=2)

# Structured status vocabulary for the two text-returning directory readers below,
# in the spirit of pe_resources' RESOURCE_NOT_FOUND / RESOURCE_DATA_MALFORMED codes:
# the return type stays text (callers compare against the "... tablosu yok." /
# "No matches." strings), but an unreadable directory now starts with a
# machine-matchable code and can never be mistaken for a genuine absence.
IMPORT_DIRECTORY_UNREADABLE="IMPORT_DIRECTORY_UNREADABLE"
IMPORT_DIRECTORY_PARTIAL="IMPORT_DIRECTORY_PARTIAL"
EXPORT_DIRECTORY_UNREADABLE="EXPORT_DIRECTORY_UNREADABLE"
EXPORT_DIRECTORY_PARTIAL="EXPORT_DIRECTORY_PARTIAL"

def _parse_directories(pe):
    """Run pefile's directory parse; return None on success, else a short error string.

    Only pefile's own format error and struct.error (a truncated header read) are
    caught -- anything else is a bug in this tool and must surface, not be
    reported as "no imports"."""
    import struct, pefile
    try:
        pe.parse_data_directories()
    except (pefile.PEFormatError,struct.error) as e:
        return f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
    return None

def _directory_problem(pe,parse_error,index,attr,keyword):
    """Explain why a directory that yielded nothing (or little) may not be genuinely absent.

    pefile does NOT normally raise on a corrupt directory: it swallows the error,
    records it in pe.get_warnings(), and leaves DIRECTORY_ENTRY_* unset -- which a
    getattr() default turns into the same answer a binary with no directory gets.
    So besides a raised error, look at (a) whether the data-directory slot is
    declared non-empty while no entries came out, and (b) pefile's own warnings."""
    notes=[]
    if parse_error:notes.append(f"parse error: {parse_error}")
    try:
        d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        if (d.VirtualAddress or d.Size) and not getattr(pe,attr,None):
            notes.append(f"directory declared (rva={hex(d.VirtualAddress)}, size={d.Size}) but no entries could be parsed")
    except (AttributeError,IndexError):pass
    gw=getattr(pe,"get_warnings",None)
    if gw:
        seen=[]
        for w in gw():
            if keyword in w.lower() and w not in seen:seen.append(w)
        if seen:notes.append("pefile warnings: "+" | ".join(seen[:3]))
    return "; ".join(notes)

def pe_imports(path,filter_text=None,max_results=500):
    pe=_pe(safe_path(path))
    problem=_directory_problem(pe,_parse_directories(pe),1,"DIRECTORY_ENTRY_IMPORT","import")
    entries=getattr(pe,"DIRECTORY_ENTRY_IMPORT",None)
    if not entries:
        if problem:return f"{IMPORT_DIRECTORY_UNREADABLE}: {problem}. This is NOT the same as a binary with no imports."
        return "Import tablosu yok."
    out=[]; flt=filter_text.lower() if filter_text else None
    tail=f"\n[{IMPORT_DIRECTORY_PARTIAL}: {problem}]" if problem else ""
    for d in entries:
        dn=d.dll.decode(errors="replace") if d.dll else "?"
        for x in d.imports:
            name=x.name.decode(errors="replace") if x.name else f"ordinal:{x.ordinal}"
            line=f"{dn}!{name} @IAT {hex(x.address)}"
            if flt and flt not in line.lower():continue
            out.append(line)
            if len(out)>=max_results:return "\n".join(out)+f"\n[limit:{max_results}]"+tail
    return "\n".join(out)+tail if out else "No matches."+tail

def pe_exports(path,max_results=500):
    pe=_pe(safe_path(path))
    problem=_directory_problem(pe,_parse_directories(pe),0,"DIRECTORY_ENTRY_EXPORT","export")
    ex=getattr(pe,"DIRECTORY_ENTRY_EXPORT",None)
    if not ex:
        if problem:return f"{EXPORT_DIRECTORY_UNREADABLE}: {problem}. This is NOT the same as a binary with no exports."
        return "Export tablosu yok."
    out=[]
    for s in ex.symbols[:max_results]:
        n=s.name.decode(errors="replace") if s.name else f"ordinal:{s.ordinal}"
        out.append(f"{n} RVA={hex(s.address)} ordinal={s.ordinal}")
    if problem:out.append(f"[{EXPORT_DIRECTORY_PARTIAL}: {problem}]")
    return "\n".join(out)

def dotnet_metadata(path,max_types=300):
    p=safe_path(path); pe=_pe(p)
    clr=len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress!=0
    if not clr:return "No CLR/.NET header present."
    import dnfile
    dn=dnfile.dnPE(str(p)); out=[]
    try:
        td=dn.net.mdtables.TypeDef
        for row in list(td.rows)[:max_types]:
            ns=str(row.TypeNamespace or ""); name=str(row.TypeName or "")
            out.append(f"{ns}.{name}".strip("."))
    except Exception as e:return f".NET metadata incomplete or failed: {e}"
    return "\n".join(out) if out else ".NET assembly parsed, but TypeDef table is empty."

# Bytes handed to a single capstone disasm() call (module-level so a test can
# shrink it to exercise chunk seams). Same default the sweep modules use.
_DISASM_CHUNK_BYTES=1_000_000

def disassemble_pe(path,section=None,start_offset=0,max_instructions=250,va=None):
    # `va` (Tier2 remediation roadmap Priority 3, Problem B; additive,
    # default None -- zero behavior change for every existing caller):
    # previously a caller who had a function's virtual address (e.g. from
    # ghidra_query's list_functions/decompile_function) had to manually
    # convert it to a section+start_offset pair via native_inspect's
    # per-section RVA/raw-offset table before calling this tool -- a real,
    # repeatedly-hand-done step (see WNL-T2-040/WNL-T2-073's manual
    # raw-disassembly fallbacks) this was never automated for. Passing
    # `va` directly (decimal or 0x-hex string, or int) now resolves the
    # containing section and correct in-section offset internally.
    from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_MODE_64,CS_ARCH_ARM64,CS_MODE_ARM
    p=safe_path(path)
    # Matches this function's own established contract (relied on verbatim by
    # ioctl_recovery.py's (upstream-only; not part of the published package) _parse_disassembly_lines docstring: "disassemble_pe
    # returns a plain human-readable error string ... on any failure ...
    # never raises") -- every other failure path in this function already
    # returns a plain string instead of raising, so a non-PE/corrupt input
    # (pefile.PEFormatError, or any other parse failure) must too, not an
    # uncaught exception. dotnet_inspect (tools_dotnet.py) handles the
    # identical bad-input case cleanly via its own JSON error vocabulary;
    # this function's vocabulary is plain text, so it stays plain text here
    # rather than switching shapes mid-function.
    try:
        pe=_pe(p)
    except Exception as e:
        return f"Gecersiz veya bozuk PE dosyasi ({type(e).__name__}): {e}"
    mach=pe.FILE_HEADER.Machine
    if mach==0x14c:md=Cs(CS_ARCH_X86,CS_MODE_32)
    elif mach==0x8664:md=Cs(CS_ARCH_X86,CS_MODE_64)
    elif mach==0xaa64:md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    else:return f"Desteklenmeyen machine {hex(mach)}"
    # x86/x64 sections routinely have data-in-code (jump tables, alignment
    # padding, literal pools) before max_instructions/section end. Without
    # skipdata, Cs.disasm() (one native cs_disasm() call) STOPS the moment it
    # hits such a byte instead of skipping and resynchronising -- the exact
    # under-reporting root cause fixed 2026-09-27 in tools_import_xrefs.py,
    # here manifesting as a listing that silently ends early with no error
    # and no indication real code continues past the gap. skipdata makes
    # capstone emit one ".byte 0xNN" pseudo-instruction per undecodable byte
    # instead (already a harmless, standard line shape for this function's
    # plain-text output -- ioctl_recovery._parse_disassembly_lines (upstream-only;
    # not part of the published package) simply
    # never matches it against any known mnemonic) and keeps decoding past
    # it, so a caller sees BOTH sides of the gap rather than a truncated,
    # falsely-complete-looking list. ARM64 is unaffected (not exercised by
    # this fix; left as-is).
    if mach in (0x14c,0x8664):md.skipdata=True
    chosen=None
    if va not in (None,""):
        try:va_int=int(str(va),0)
        except ValueError:return f"Gecersiz va: {va!r}"
        rva=va_int-pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
                chosen=s;start_offset=rva-s.VirtualAddress;break
        if chosen is None:return f"va {hex(va_int)} (RVA {hex(rva)}) herhangi bir section icinde bulunamadi."
    elif section:
        for s in pe.sections:
            if s.Name.rstrip(b"\x00").decode(errors="replace").lower()==section.lower():chosen=s;break
    else:
        ep=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for s in pe.sections:
            if s.VirtualAddress<=ep<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
                chosen=s;start_offset=max(int(start_offset),ep-s.VirtualAddress);break
    if chosen is None:return "Section not found."
    data=chosen.get_data(); start_offset=max(0,min(int(start_offset),len(data)))
    base=pe.OPTIONAL_HEADER.ImageBase+chosen.VirtualAddress+start_offset
    out=[]; more_at=None
    # md.disasm() is ONE native cs_disasm() call that allocates for its whole
    # input before yielding anything (~248 bytes of native heap per input
    # byte; see code_sweep_chunking's docstring), so a `break` after the
    # generator exists bounds the returned list, not the allocation. Feed it
    # one chunk at a time instead and stop as soon as the cap is reached.
    # CALLING CONVENTION (deliberate): pass the SECTION bytes with
    # file_offset=start_offset, not the whole file. Reason: the old code
    # handed capstone exactly data[start_offset:], so an instruction cut by
    # the end of the section came out as a truncated ".byte" line; reading the
    # tail overlap of the next section would decode it as a real instruction
    # and change that last line. The cost is that the final chunk has no tail
    # context past the section end, which is exactly the old behaviour.
    # `base` (va_base) is unchanged and chunk offsets are relative to it.
    from liebert_re.recover.code_sweep_chunking import chunk_boundaries,disasm_chunk
    size=len(data)-start_offset
    cap=max(1,int(max_instructions))  # old loop always emitted at least one
    for t0,t1 in chunk_boundaries(size,_DISASM_CHUNK_BYTES):
        for ins,credited in disasm_chunk(md,data,start_offset,base,t0,t1):
            if not credited:continue
            if len(out)>=cap:more_at=ins.address;break  # peek: more code exists
            out.append(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}".rstrip())
        if more_at is not None:break
    # Cap visibility: this function returns plain text that callers compare
    # and parse line by line, so the return type stays str. A capped listing
    # ends with one trailing marker line (same ANALYSIS_LIMITED vocabulary as
    # tools_rizin); it is emitted only when more decodable code really
    # follows, so a listing that ends exactly at the cap is left unmarked.
    if more_at is not None and out:
        out.append(f"[ANALYSIS_LIMITED: stopped after max_instructions={cap}; more code follows at 0x{more_at:X}]")
    return "\n".join(out) if out else "No instruction could be decoded."

def search_binary_bytes(path,pattern,max_results=100):
    p=safe_path(path); data=p.read_bytes()
    parts=pattern.strip().split(); pat=[]
    for x in parts:
        pat.append(None if x in {"?","??"} else int(x,16))
    out=[]; n=len(pat)
    for i in range(max(0,len(data)-n+1)):
        if all(v is None or data[i+j]==v for j,v in enumerate(pat)):
            out.append(f"file_offset=0x{i:X}")
            if len(out)>=max_results:break
    return "\n".join(out) if out else "No matches."

class _ResourceMalformed(Exception):
    """Raised when the resource directory (or one leaf's declared-vs-actual
    data) cannot be trusted -- caller turns this into a structured error
    naming what failed, never a partial tree silently presented as
    complete."""

def _resource_identity_list(pe):
    """Every leaf (type/name/language) entry in pe.DIRECTORY_ENTRY_RESOURCE,
    walked with pefile's OWN already-parsed tree (not a reimplemented
    parser) -- struct-field reads only, no data bytes fetched here, so this
    is cheap even on a binary carrying thousands of resources. Raises
    _ResourceMalformed (naming the entry index it failed at) if the walk
    itself breaks partway through, instead of returning a partial list that
    looks complete."""
    if not hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):return []
    import pefile
    items=[];idx=0
    try:
        for te in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id=te.struct.Id if te.name is None else None
            type_name=str(te.name) if te.name is not None else None
            type_well_known=pefile.RESOURCE_TYPE.get(type_id) if type_id is not None else None
            for ne in te.directory.entries:
                name_id=ne.struct.Id if ne.name is None else None
                name_str=str(ne.name) if ne.name is not None else None
                for le in ne.directory.entries:
                    lang_id=le.struct.Id if le.name is None else None
                    data=le.data
                    items.append({
                        'index':idx,'type_id':type_id,'type_name':type_name,'type_well_known':type_well_known,
                        'name_id':name_id,'name':name_str,'language_id':lang_id,
                        'codepage':int(data.struct.CodePage),'rva':int(data.struct.OffsetToData),'size':int(data.struct.Size),
                    })
                    idx+=1
    except _ResourceMalformed:
        raise
    except Exception as e:
        raise _ResourceMalformed(f'resource directory walk failed at leaf index {idx}: {type(e).__name__}: {e}')
    return items

def _resource_fetch(pe,item):
    """Resolve one leaf's RVA to a file offset and read its declared byte
    range. Raises _ResourceMalformed (naming the resource and the size
    mismatch) if pefile's own OOB clamp returns fewer bytes than the
    resource declares -- that clamp is silent by default in pefile, so
    presenting its output as the real resource without checking would be
    exactly the "partial tree presented as complete" defect this exists to
    refuse."""
    rva=item['rva'];size=item['size'];label=f"type={item['type_well_known'] or item['type_id']} name={item['name'] or item['name_id']} lang={item['language_id']}"
    try:
        file_off=pe.get_offset_from_rva(rva)
    except Exception:
        file_off=None
    try:
        raw=pe.get_data(rva,size)
    except Exception as e:
        raise _ResourceMalformed(f'resource {label}: failed to read {size} bytes at rva {hex(rva)}: {type(e).__name__}: {e}')
    if len(raw)!=size:
        raise _ResourceMalformed(f'resource {label} declares size {size} bytes at rva {hex(rva)} but only {len(raw)} bytes are available in the file -- the resource directory is truncated or corrupt')
    return file_off,raw

def _save_resource_bytes(p,item,data):
    label=f"t{item['type_id'] if item['type_id'] is not None else item['type_name']}_n{item['name_id'] if item['name_id'] is not None else item['name']}_l{item['language_id']}"
    key=hashlib.sha256((str(p)+label).encode()).hexdigest()[:12]
    out=EVIDENCE/f'{p.stem}_{key}_{re.sub(r"[^A-Za-z0-9_-]","_",str(label))[:60]}.bin'
    out.write_bytes(data)
    try:_evidence_index_record_write(out)
    except Exception:pass
    return out

def pe_resources(path,operation='list',resource_type='',resource_name='',language=None,offset=0,max_results=300,max_preview_bytes=2000):
    """List or extract a PE's embedded resources (RT_RCDATA/RT_ICON/RT_
    VERSION/... under IMAGE_DIRECTORY_ENTRY_RESOURCE), built entirely on
    pefile's own already-vendored DIRECTORY_ENTRY_RESOURCE walker -- no new
    resource parser. This is the general shape a huge class of packers/
    droppers/self-extracting installers uses to hide a payload (a resource
    entry with abnormally high entropy relative to the rest of the file)."""
    p=safe_path(path)
    try:
        pe=_pe(p)
    except Exception as e:
        return json.dumps({'ok':False,'path':relative(p),'error':'PE_PARSE_FAILED','detail':f'{type(e).__name__}: {e}'},indent=2)
    if not hasattr(pe,'DIRECTORY_ENTRY_RESOURCE'):
        if operation=='list':
            return json.dumps({'ok':True,'path':relative(p),'has_resource_directory':False,'resources':[],'offset':0,'returned':0,'total':0,'has_more':False,'detail':'No resource directory (IMAGE_DIRECTORY_ENTRY_RESOURCE) present in this PE.'},indent=2)
        if operation=='extract':
            return json.dumps({'ok':False,'path':relative(p),'has_resource_directory':False,'error':'NO_RESOURCE_DIRECTORY','detail':'This PE has no resource directory; there is nothing to extract.'},indent=2)
        return json.dumps({'ok':False,'path':relative(p),'error':'UNKNOWN_OPERATION'},indent=2)
    try:
        items=_resource_identity_list(pe)
    except _ResourceMalformed as e:
        return json.dumps({'ok':False,'path':relative(p),'error':'RESOURCE_DIRECTORY_MALFORMED','detail':str(e)},indent=2)

    if operation=='list':
        off=max(0,int(offset or 0));lim=max(1,min(int(max_results or 300),2000))
        page=items[off:off+lim];out=[]
        try:
            for it in page:
                file_off,raw=_resource_fetch(pe,it)
                out.append({
                    'index':it['index'],'type_id':it['type_id'],'type_name':it['type_name'],'type_well_known':it['type_well_known'],
                    'name_id':it['name_id'],'name':it['name'],'language_id':it['language_id'],'codepage':it['codepage'],
                    'rva':hex(it['rva']),'file_offset':(hex(file_off) if file_off is not None else None),
                    'size':it['size'],'entropy':_entropy(raw),
                })
        except _ResourceMalformed as e:
            return json.dumps({'ok':False,'path':relative(p),'error':'RESOURCE_DATA_MALFORMED','detail':str(e)},indent=2)
        total=len(items)
        return json.dumps({'ok':True,'path':relative(p),'has_resource_directory':True,'resources':out,'offset':off,'returned':len(out),'total':total,'has_more':(off+len(out))<total},ensure_ascii=False,indent=2)

    if operation=='extract':
        if not resource_type and not resource_name:
            return json.dumps({'ok':False,'path':relative(p),'error':'SELECTOR_REQUIRED','detail':'Pass resource_type and/or resource_name (from a prior operation=list call) to select which resource to extract.'},indent=2)
        def _int_or_none(v):
            try:return int(str(v).strip(),0)
            except (TypeError,ValueError):return None
        rt_int=_int_or_none(resource_type) if resource_type not in (None,'') else None
        rn_int=_int_or_none(resource_name) if resource_name not in (None,'') else None
        lang_int=_int_or_none(language) if language not in (None,'') else None
        def _matches(it):
            if resource_type:
                ok=(rt_int is not None and it['type_id']==rt_int) or \
                   (it['type_well_known'] and str(resource_type).strip().upper()==it['type_well_known'].upper()) or \
                   (it['type_name'] and str(resource_type).strip().lower()==it['type_name'].lower())
                if not ok:return False
            if resource_name:
                ok=(rn_int is not None and it['name_id']==rn_int) or \
                   (it['name'] and str(resource_name).strip().lower()==it['name'].lower())
                if not ok:return False
            if language not in (None,''):
                if lang_int is None or it['language_id']!=lang_int:return False
            return True
        matches=[it for it in items if _matches(it)]
        if not matches:
            return json.dumps({'ok':False,'path':relative(p),'error':'RESOURCE_NOT_FOUND','detail':f'No resource matches resource_type={resource_type!r} resource_name={resource_name!r} language={language!r}. Call operation=list first to get the exact identity.'},indent=2,ensure_ascii=False)
        if len(matches)>1:
            summary=[{'index':it['index'],'type_id':it['type_id'],'type_well_known':it['type_well_known'],'type_name':it['type_name'],'name_id':it['name_id'],'name':it['name'],'language_id':it['language_id'],'size':it['size']} for it in matches]
            return json.dumps({'ok':False,'path':relative(p),'error':'AMBIGUOUS_SELECTOR','detail':f'{len(matches)} resources match resource_type={resource_type!r} resource_name={resource_name!r} language={language!r} -- add language (or a more specific resource_type/resource_name) to disambiguate. Returning every match instead of silently picking one.','matches':summary},indent=2,ensure_ascii=False)
        it=matches[0]
        try:
            file_off,raw=_resource_fetch(pe,it)
        except _ResourceMalformed as e:
            return json.dumps({'ok':False,'path':relative(p),'error':'RESOURCE_DATA_MALFORMED','detail':str(e)},indent=2)
        digest=hashlib.sha256(raw).hexdigest()
        out_path=_save_resource_bytes(p,it,raw)
        prev_n=max(0,min(int(max_preview_bytes or 2000),4096))
        preview=raw[:prev_n]
        return json.dumps({
            'ok':True,'path':relative(p),
            'type_id':it['type_id'],'type_name':it['type_name'],'type_well_known':it['type_well_known'],
            'name_id':it['name_id'],'name':it['name'],'language_id':it['language_id'],'codepage':it['codepage'],
            'rva':hex(it['rva']),'file_offset':(hex(file_off) if file_off is not None else None),
            'size':it['size'],'sha256':digest,'evidence_file':str(out_path),
            'preview_hex':preview.hex(),'preview_returned_bytes':len(preview),'preview_truncated':it['size']>len(preview),
        },indent=2,ensure_ascii=False)

    return json.dumps({'ok':False,'path':relative(p),'error':'UNKNOWN_OPERATION'},indent=2)

def authenticode_signature(path,cancellation_token=None):
    p=safe_path(path)
    if os.name!="nt":return "Authenticode verification requires Windows."
    esc=str(p).replace("'","''")
    ps=f"$s=Get-AuthenticodeSignature -LiteralPath '{esc}'; [pscustomobject]@{{Status=[string]$s.Status;StatusMessage=$s.StatusMessage;SignerSubject=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}};Thumbprint=if($s.SignerCertificate){{$s.SignerCertificate.Thumbprint}}else{{$null}}}} | ConvertTo-Json -Compress"
    cp=run_bounded_process(
        ["powershell.exe","-NoProfile","-NonInteractive","-Command",ps],
        timeout_seconds=30,cancellation_token=cancellation_token,
    )
    if cp.cancelled:return json.dumps({"ok":False,"status":"CANCELLED","error":"TOOL_CALL_CANCELLED","process_tree_terminated":cp.process_tree_terminated})
    if cp.timed_out:return json.dumps({"ok":False,"status":"TIMEOUT","error":"PROCESS_TIMEOUT","process_tree_terminated":cp.process_tree_terminated})
    return cp.stdout.strip() if cp.returncode==0 else cp.stderr.strip()
