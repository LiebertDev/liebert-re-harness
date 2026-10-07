import hashlib, json, math, os, re
from liebert_re.bounded_subprocess import launch_failure, run_bounded_process
from liebert_re.workspace import safe_path, relative, skipped, _limit_marker

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

# Text tools state "nothing found" as a line that starts with this prefix, followed by the old
# sentence. It is NOT a failure: liebert_re.cli._decode reads it as ok=true plus empty=true, so an
# empty answer is distinguishable from a listing and from an error. A failure starts with one of the
# machine codes in cli._TEXT_LIMITED_PREFIXES / _TEXT_UNSUPPORTED_PREFIXES instead.
# tests/test_cli_tool_dispatch.py pins this equal to cli._TEXT_EMPTY_PREFIX.
EMPTY_RESULT_PREFIX="EMPTY_RESULT: "
DOTNET_METADATA_UNREADABLE="DOTNET_METADATA_UNREADABLE"
DISASSEMBLY_FAILED="DISASSEMBLY_FAILED"

def _empty(sentence):
    return EMPTY_RESULT_PREFIX+sentence

def find_binaries(path=".",max_results=300):
    root=safe_path(path); out=[]
    for p in root.rglob("*"):
        if skipped(p) or not p.is_file():continue
        if p.suffix.lower() in BINARY_EXTS:
            if len(out)>=max_results:
                return "\n".join(out)+"\n"+_limit_marker(len(out),max_results)
            out.append(f"{relative(p)} ({p.stat().st_size} bytes)")
    return "\n".join(out) if out else _empty("No binary found.")

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
    out=[]; matched=0
    for off,k,s in vals:
        if contains and contains.lower() not in s.lower():continue
        matched+=1
        if len(out)<max_results:out.append(f"0x{off:X} [{k}] {s}")
    if matched>len(out):out.append(_limit_marker(len(out),max_results,matched))
    return "\n".join(out) if out else _empty("No strings found.")

def pe_sections(path):
    p=safe_path(path); pe=_pe(p)
    return json.dumps([{"name":s.Name.rstrip(b"\x00").decode(errors="replace"),
                        "rva":hex(s.VirtualAddress),"virtual_size":int(s.Misc_VirtualSize),
                        "raw_offset":hex(s.PointerToRawData),"raw_size":int(s.SizeOfRawData),
                        "characteristics":hex(s.Characteristics),
                        "entropy":round(float(s.get_entropy()),4)} for s in pe.sections],indent=2)

# Structured status vocabulary for the two text-returning directory readers below,
# in the spirit of pe_resources' RESOURCE_NOT_FOUND / RESOURCE_DATA_MALFORMED codes:
# the return type stays text (callers compare against the "No import table." /
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
        return _empty("No import table.")
    out=[]; flt=filter_text.lower() if filter_text else None
    tail=f"\n[{IMPORT_DIRECTORY_PARTIAL}: {problem}]" if problem else ""
    for d in entries:
        dn=d.dll.decode(errors="replace") if d.dll else "?"
        for x in d.imports:
            name=x.name.decode(errors="replace") if x.name else f"ordinal:{x.ordinal}"
            line=f"{dn}!{name} @IAT {hex(x.address)}"
            if flt and flt not in line.lower():continue
            if len(out)>=max_results:return "\n".join(out)+"\n"+_limit_marker(len(out),max_results)+tail
            out.append(line)
    return "\n".join(out)+tail if out else _empty("No matches.")+tail

def pe_exports(path,max_results=500):
    pe=_pe(safe_path(path))
    problem=_directory_problem(pe,_parse_directories(pe),0,"DIRECTORY_ENTRY_EXPORT","export")
    ex=getattr(pe,"DIRECTORY_ENTRY_EXPORT",None)
    if not ex:
        if problem:return f"{EXPORT_DIRECTORY_UNREADABLE}: {problem}. This is NOT the same as a binary with no exports."
        return _empty("No export table.")
    out=[]
    all_symbols=list(ex.symbols)
    for s in all_symbols[:max_results]:
        n=s.name.decode(errors="replace") if s.name else f"ordinal:{s.ordinal}"
        out.append(f"{n} RVA={hex(s.address)} ordinal={s.ordinal}")
    if len(all_symbols)>max_results:out.append(_limit_marker(len(out),max_results,len(all_symbols)))
    if problem:out.append(f"[{EXPORT_DIRECTORY_PARTIAL}: {problem}]")
    return "\n".join(out)

def dotnet_metadata(path,max_types=300):
    p=safe_path(path); pe=_pe(p)
    clr=len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress!=0
    if not clr:return _empty("No CLR/.NET header present.")
    import dnfile
    dn=dnfile.dnPE(str(p)); out=[]
    try:
        td=dn.net.mdtables.TypeDef
        all_rows=list(td.rows)
        for row in all_rows[:max_types]:
            ns=str(row.TypeNamespace or ""); name=str(row.TypeName or "")
            out.append(f"{ns}.{name}".strip("."))
        if len(all_rows)>max_types:out.append(_limit_marker(len(out),max_types,len(all_rows)))
    except Exception as e:return f"{DOTNET_METADATA_UNREADABLE}: .NET metadata incomplete or failed: {e}"
    return "\n".join(out) if out else _empty(".NET assembly parsed, but TypeDef table is empty.")

# Bytes handed to a single capstone disasm() call (module-level so a test can
# shrink it to exercise chunk seams). Same default the sweep modules use.
_DISASM_CHUNK_BYTES=1_000_000

def _failure(error,status,message):
    """Structured failure result: ``status`` is from the package's status vocabulary
    (generic_static_probe.ALLOWED_STATUSES), ``error`` is a stable machine code."""
    return {"ok":False,"status":status,"error":error,"message":message}

def _dpe_open(path,section,start_offset,va,detail=False,structured=False):
    """Shared front half of disassemble_pe and disassemble_pe_structured: parse the PE,
    pick the machine, resolve the section/offset. Returns (ctx, None) or (None, _failure)."""
    from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_MODE_64,CS_ARCH_ARM64,CS_MODE_ARM
    p=safe_path(path)
    # Success is a plain-text listing; every FAILURE is a structured dict
    # (see _failure) so callers branch on `ok`/`error`, never on prose. A
    # non-PE or corrupt input returns INVALID_PE rather than raising.
    try:
        pe=_pe(p)
    except Exception as e:
        return None,_failure("INVALID_PE","ANALYSIS_LIMITED",f"Invalid or corrupt PE file ({type(e).__name__}): {e}")
    mach=pe.FILE_HEADER.Machine
    if mach==0x14c:md=Cs(CS_ARCH_X86,CS_MODE_32)
    elif mach==0x8664:md=Cs(CS_ARCH_X86,CS_MODE_64)
    elif mach==0xaa64:
        if structured:return None,_failure("STRUCTURED_UNSUPPORTED_MACHINE","UNSUPPORTED","Structured disassembly is x86/x64 only: ARM64 has no skipdata and a different operand model, so no x86-shaped fields are produced. The text listing (disassemble_pe) still works.")
        md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    else:return None,_failure("UNSUPPORTED_MACHINE","UNSUPPORTED",f"Unsupported machine type {hex(mach)}")
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
    if detail:md.detail=True  # structured path only; the text path never pays for operand detail
    chosen=None
    if va not in (None,""):
        try:va_int=int(str(va),0)
        except ValueError:return None,_failure("INVALID_VA","ANALYSIS_LIMITED",f"Invalid va: {va!r}")
        rva=va_int-pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            if s.VirtualAddress<=rva<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
                chosen=s;start_offset=rva-s.VirtualAddress;break
        if chosen is None:return None,_failure("VA_NOT_IN_SECTION","ANALYSIS_LIMITED",f"va {hex(va_int)} (RVA {hex(rva)}) was not found inside any section.")
    elif section:
        for s in pe.sections:
            if s.Name.rstrip(b"\x00").decode(errors="replace").lower()==section.lower():chosen=s;break
    else:
        ep=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for s in pe.sections:
            if s.VirtualAddress<=ep<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
                chosen=s;start_offset=max(int(start_offset),ep-s.VirtualAddress);break
    if chosen is None:return None,_failure("SECTION_NOT_FOUND","ANALYSIS_LIMITED","Section not found.")
    data=chosen.get_data(); start_offset=max(0,min(int(start_offset),len(data)))
    base=pe.OPTIONAL_HEADER.ImageBase+chosen.VirtualAddress+start_offset
    size=len(data)-start_offset
    return {"pe":pe,"md":md,"mach":mach,"data":data,"start_offset":start_offset,"base":base,"size":size},None

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
    ctx,err=_dpe_open(path,section,start_offset,va)
    if err is not None:return err
    md=ctx["md"];data=ctx["data"];start_offset=ctx["start_offset"];base=ctx["base"]
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
    return "\n".join(out) if out else f"{DISASSEMBLY_FAILED}: No instruction could be decoded."

def _dps_form(pe,va):
    """The shared AddressForm (pe_address.AddressForm, same hex-string spelling as
    pe_address.normalize_address) for one VA, from the PE already open. A VA that no section
    holds is {"resolved": False, "error": ...}, never a guessed form."""
    base=pe.OPTIONAL_HEADER.ImageBase
    if va<base:return {"resolved":False,"error":"VA_BELOW_IMAGE_BASE","va":hex(va)}
    rva=va-base
    s=pe.get_section_by_rva(rva)
    if s is None:return {"resolved":False,"error":"RVA_NOT_IN_ANY_SECTION","va":hex(va)}
    try:off=pe.get_offset_from_rva(rva)
    except Exception:return {"resolved":False,"error":"RVA_HAS_NO_FILE_OFFSET","va":hex(va)}
    return {"file_offset":hex(off),"rva":hex(rva),"va":hex(va),"image_base":hex(base),
            "section":s.Name.rstrip(b"\x00").decode(errors="replace")}

def _dps_entry(pe,ins):
    """One capstone instruction (detail on) as the flat per-instruction contract of
    rizin._instruction_entry, plus ``immediates`` and ``rip_relative`` (see disassemble_pe_structured)."""
    from capstone import CS_GRP_CALL,CS_GRP_JUMP
    from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
    # skipdata's pseudo-instruction is the only thing capstone emits with id 0 (X86_INS_INVALID);
    # its mnemonic is ".byte". Both must hold, so a real instruction is never mislabelled.
    undecodable=ins.id==0 and ins.mnemonic==".byte"
    entry={"address":_dps_form(pe,ins.address),"bytes":bytes(ins.bytes).hex(),"mnemonic":ins.mnemonic,
           "operands":ins.op_str,"length":ins.size,"decode_status":"UNDECODABLE" if undecodable else "DECODED"}
    if undecodable:return entry
    direct=None
    ops=list(ins.operands)
    if len(ops)==1 and ops[0].type==X86_OP_IMM and (ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP)):
        direct=ops[0]
        entry["branch_target"]=_dps_form(pe,direct.imm&0xFFFFFFFFFFFFFFFF)
    imms=[];rip=[]
    for i,op in enumerate(ops):
        if op.type==X86_OP_IMM and op is not direct:
            imms.append({"value":op.imm,"hex":hex(op.imm&((1<<(8*op.size))-1)),"size":op.size})
        elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
            rip.append({"operand_index":i,"disp":op.mem.disp,
                        "target":_dps_form(pe,(ins.address+ins.size+op.mem.disp)&0xFFFFFFFFFFFFFFFF)})
    if imms:entry["immediates"]=imms
    if rip:entry["rip_relative"]=rip
    return entry

def disassemble_pe_structured(path,section=None,start_offset=0,max_instructions=250,va=None):
    """Structured twin of disassemble_pe: the same section/va/entry-point selection, the same
    max_instructions cap, the same skipdata, returned as a dict instead of text.

    Per instruction: the rizin_disasm_listing contract (address form, bytes, mnemonic, operands,
    length, decode_status DECODED|UNDECODABLE, branch_target for a direct call/jmp/jcc) plus
    ``immediates`` ([{value, hex, size}], the IOCTL-recovery input) and ``rip_relative``
    ([{operand_index, disp, target}], target = address+length+disp, the import-slot input).
    A branch immediate is a target, not an immediate, so it appears only as branch_target.
    A cap that cut the listing is ``truncated`` true, status ANALYSIS_LIMITED and
    ``truncation`` {max_instructions, more_at}; it is never silent. x86/x64 only: ARM64 is
    refused with STRUCTURED_UNSUPPORTED_MACHINE. Failures keep disassemble_pe's codes."""
    ctx,err=_dpe_open(path,section,start_offset,va,detail=True,structured=True)
    if err is not None:return err
    pe=ctx["pe"];md=ctx["md"];data=ctx["data"];start_offset=ctx["start_offset"];base=ctx["base"]
    from liebert_re.recover.code_sweep_chunking import chunk_boundaries,disasm_chunk
    cap=max(1,int(max_instructions))
    out=[];more_at=None
    for t0,t1 in chunk_boundaries(ctx["size"],_DISASM_CHUNK_BYTES):
        for ins,credited in disasm_chunk(md,data,start_offset,base,t0,t1):
            if not credited:continue
            if len(out)>=cap:more_at=ins.address;break
            out.append(_dps_entry(pe,ins))
        if more_at is not None:break
    if not out:return _failure("DISASSEMBLY_FAILED","ANALYSIS_LIMITED","No instruction could be decoded.")
    undec=sum(1 for e in out if e["decode_status"]=="UNDECODABLE")
    dec=len(out)-undec
    cov="FULLY_DECODED" if undec==0 else "NOTHING_DECODED" if dec==0 else "PARTIALLY_DECODED"
    res={"ok":True,"tool":"disassemble_pe_structured","status":"OK","engine":"capstone",
         "architecture":"x86_64" if ctx["mach"]==0x8664 else "x86_32",
         "start":out[0]["address"],"count_requested":cap,"count_returned":len(out),
         "decode_coverage":{"status":cov,"instructions_decoded":dec,"instructions_undecodable":undec,
                            "bytes_covered":sum(e["length"] for e in out)},
         "truncated":more_at is not None,"instructions":out}
    if more_at is not None:
        res["status"]="ANALYSIS_LIMITED"
        res["truncation"]={"max_instructions":cap,"more_at":_dps_form(pe,more_at)}
    return res

def search_binary_bytes(path,pattern,max_results=100):
    p=safe_path(path); data=p.read_bytes()
    parts=pattern.strip().split(); pat=[]
    for x in parts:
        pat.append(None if x in {"?","??"} else int(x,16))
    out=[]; n=len(pat)
    for i in range(max(0,len(data)-n+1)):
        if all(v is None or data[i+j]==v for j,v in enumerate(pat)):
            if len(out)>=max_results:return "\n".join(out)+"\n"+_limit_marker(len(out),max_results)
            out.append(f"file_offset=0x{i:X}")
    return "\n".join(out) if out else _empty("No matches.")

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

def _authenticode_fields(stdout):
    """Parse the JSON Get-AuthenticodeSignature script's stdout into the result dict.

    Every field comes from that JSON object; one that is absent, null or not a string is None
    ("UNKNOWN"), never a guess. ``raw`` is the stdout text unchanged. Output that is not a JSON
    object is an ANALYSIS_LIMITED failure carrying the raw text, not a half-filled success."""
    try:
        data=json.loads(stdout)
    except ValueError:
        data=None
    if not isinstance(data,dict):
        return {"ok":False,"status":"ANALYSIS_LIMITED","error":"AUTHENTICODE_OUTPUT_UNPARSEABLE","raw":stdout}
    def field(key):
        v=data.get(key)
        return v if isinstance(v,str) and v else None
    return {"ok":True,"status":"OK","signature_status":field("Status"),"status_message":field("StatusMessage"),
            "signer":field("SignerSubject"),"issuer":field("Issuer"),"thumbprint":field("Thumbprint"),
            "timestamper":field("TimestamperSubject"),"raw":stdout}

def authenticode_signature(path,cancellation_token=None):
    """Authenticode status of a file, as JSON (Windows only; elsewhere the text line
    "Authenticode verification requires Windows." is returned and the CLI reads it as UNSUPPORTED).

    ``signature_status`` is PowerShell's own verdict string (Valid, NotSigned, HashMismatch, ...),
    kept apart from ``status``, which is the package vocabulary (OK on a parsed answer).
    ``signer``, ``issuer``, ``thumbprint`` and ``timestamper`` (the subject of the timestamp
    countersigner's certificate; Get-AuthenticodeSignature does not expose the signing time) are
    None when the file carries no such certificate or the field could not be read. ``raw`` is the
    script's stdout. A failed run is a JSON failure with ``ok`` false, never bare stderr."""
    p=safe_path(path)
    if os.name!="nt":return "Authenticode verification requires Windows."
    esc=str(p).replace("'","''")
    ps=f"$s=Get-AuthenticodeSignature -LiteralPath '{esc}'; [pscustomobject]@{{Status=[string]$s.Status;StatusMessage=$s.StatusMessage;SignerSubject=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}};Issuer=if($s.SignerCertificate){{$s.SignerCertificate.Issuer}}else{{$null}};Thumbprint=if($s.SignerCertificate){{$s.SignerCertificate.Thumbprint}}else{{$null}};TimestamperSubject=if($s.TimeStamperCertificate){{$s.TimeStamperCertificate.Subject}}else{{$null}}}} | ConvertTo-Json -Compress"
    cp=run_bounded_process(
        ["powershell.exe","-NoProfile","-NonInteractive","-Command",ps],
        timeout_seconds=30,cancellation_token=cancellation_token,
    )
    if cp.launch_failed is True:
        return json.dumps(launch_failure(cp, "authenticode_signature", "AUTHENTICODE_LAUNCH_FAILED"))
    if cp.cancelled:return json.dumps({"ok":False,"status":"CANCELLED","error":"TOOL_CALL_CANCELLED","process_tree_terminated":cp.process_tree_terminated})
    if cp.timed_out:return json.dumps({"ok":False,"status":"TIMEOUT","error":"PROCESS_TIMEOUT","process_tree_terminated":cp.process_tree_terminated})
    if cp.returncode!=0:
        return json.dumps({"ok":False,"status":"ANALYSIS_LIMITED","error":"AUTHENTICODE_COMMAND_FAILED","returncode":cp.returncode,"stderr":cp.stderr.strip()})
    return json.dumps(_authenticode_fields(cp.stdout.strip()),ensure_ascii=False)


# ---- kernel_triage ---------------------------------------------------------
# First static tool of the windows-kernel family. It reads the PE facts through the same _pe /
# _parse_directories / _directory_problem readers the tools above use and reports each driver
# indicator on its own. Whether a file is a driver is not provable statically, so the verdict is
# only ever "LIKELY" or "UNKNOWN", never a flat "driver".
_KT_MACHINES={0x14c:("x86",32),0x8664:("x86_64",64),0xaa64:("ARM64",64)}
_KT_SUBSYSTEMS={0:"UNKNOWN",1:"NATIVE",2:"WINDOWS_GUI",3:"WINDOWS_CUI",5:"OS2_CUI",7:"POSIX_CUI",9:"WINDOWS_CE_GUI",
                10:"EFI_APPLICATION",11:"EFI_BOOT_SERVICE_DRIVER",12:"EFI_RUNTIME_DRIVER",13:"EFI_ROM",14:"XBOX",
                16:"WINDOWS_BOOT_APPLICATION"}
_KT_DEBUG_TYPES={0:"UNKNOWN",1:"COFF",2:"CODEVIEW",3:"FPO",4:"MISC",9:"BORLAND",10:"RESERVED10",11:"CLSID",
                  12:"VC_FEATURE",13:"POGO",14:"ILTCG",16:"REPRO",20:"EX_DLLCHARACTERISTICS"}
_KT_KERNEL_DLLS=("ntoskrnl.exe","hal.dll")
KERNEL_TRIAGE_STATEMENT="Static indicators only: a PE file cannot be proven to be a kernel driver by reading it."

def _kt_refuse(status,error,fixable,fix,**extra):
    """Refusal envelope, same keys as the ida refusals: ok/tool/status/error/fixable/fix."""
    body={"ok":False,"tool":"kernel_triage","status":status,"error":error,"fixable":fixable,"fix":fix}
    body.update(extra)
    return json.dumps(body,ensure_ascii=False,indent=2)

def _kt_indicators(subsystem,imports,sections):
    """The driver indicators, each with its own confidence label.

    ``deterministic`` = the value is read exactly from a PE structure; ``heuristic`` = a naming
    convention that any PE may follow or ignore. Neither kind proves a driver (``proves_driver``)."""
    kernel_hits=sorted({d["dll"] for d in imports["dlls"] if d["dll"].lower() in _KT_KERNEL_DLLS}) if imports["dlls"] is not None else None
    init=[s["name"] for s in sections if s["name"].upper()=="INIT"]
    page=[s["name"] for s in sections if s["name"].upper().startswith("PAGE")]
    return [
        {"name":"subsystem_native","confidence":"deterministic","proves_driver":False,
         "present":subsystem==1,"observed":subsystem},
        {"name":"kernel_import","confidence":"deterministic","proves_driver":False,
         "present":(bool(kernel_hits) if imports["state"] in ("PRESENT","ABSENT") else None),"observed":kernel_hits},
        {"name":"init_section","confidence":"heuristic","proves_driver":False,"present":bool(init),"observed":init},
        {"name":"page_section","confidence":"heuristic","proves_driver":False,"present":bool(page),"observed":page},
    ]

def kernel_triage(path):
    """Read-only first look at a PE that might be a Windows kernel driver.

    Returns a JSON string. Refusals (``ok`` false, with ``fixable`` and ``fix``): PATH_REFUSED,
    NOT_FOUND, FILE_NOT_ACCESSIBLE, INVALID_PE (not a PE or the header is corrupt), UNSUPPORTED_MACHINE.
    Otherwise ``ok`` true with ``status`` OK, or ANALYSIS_LIMITED when the file is cut short or a
    directory could not be read; ``limitations`` says which. The ``pe.imports.state`` is one of PRESENT,
    ABSENT (no import directory) or UNREADABLE (declared but cannot be parsed -- not the same as absent);
    PARTIAL means some entries parsed and pefile reported problems with the rest.

    ``indicators`` lists each signal separately with ``confidence`` deterministic or heuristic and
    ``proves_driver`` always false. ``driver_likelihood`` is "LIKELY" only when the native subsystem and a
    kernel import (ntoskrnl.exe or hal.dll) are both observed, with fully readable imports; every other
    combination is "UNKNOWN" and ``rationale`` says which indicators are missing or conflicting. It is
    never a flat verdict. ``unknown_fields`` lists every ``pe`` field that could not be determined (also
    ``null`` in ``pe``)."""
    try:
        p=safe_path(path)
    except PermissionError as e:
        return _kt_refuse("PATH_REFUSED",str(e),True,"Pass a path inside the workspace root.",path=str(path))
    if not p.is_file():
        return _kt_refuse("NOT_FOUND","FILE_NOT_FOUND",True,"Pass the path of an existing file.",path=str(path))
    try:
        pe=_pe(p)
    except OSError as e:
        return _kt_refuse("ANALYSIS_LIMITED","FILE_NOT_ACCESSIBLE",False,"The file could not be read; check permissions or whether another process holds it.",path=relative(p),error_type=type(e).__name__)
    except Exception as e:
        return _kt_refuse("ANALYSIS_LIMITED","INVALID_PE",False,"The file is not a PE or its header is corrupt; nothing was read from it.",path=relative(p),detail=f"{type(e).__name__}: {e}")
    machine=int(pe.FILE_HEADER.Machine)
    if machine not in _KT_MACHINES:
        return _kt_refuse("UNSUPPORTED","UNSUPPORTED_MACHINE",False,"Only x86, x86_64 and ARM64 PEs are read.",path=relative(p),machine=hex(machine))
    arch,bits=_KT_MACHINES[machine]
    size=p.stat().st_size
    limitations=[]
    parse_error=_parse_directories(pe)
    if parse_error:limitations.append(f"data directories not fully parsed: {parse_error}")

    sections=[{"name":s.Name.rstrip(b"\x00").decode(errors="replace"),"virtual_size":int(s.Misc_VirtualSize),
               "raw_size":int(s.SizeOfRawData),"characteristics":hex(s.Characteristics)} for s in pe.sections]
    cut=[s.Name.rstrip(b"\x00").decode(errors="replace") for s in pe.sections if s.SizeOfRawData and s.PointerToRawData+s.SizeOfRawData>size]
    if cut:limitations.append("file ends before the raw data declared by section(s): "+", ".join(cut))

    problem=_directory_problem(pe,parse_error,1,"DIRECTORY_ENTRY_IMPORT","import")
    entries=getattr(pe,"DIRECTORY_ENTRY_IMPORT",None)
    if entries:
        dlls=[{"dll":(d.dll.decode(errors="replace") if d.dll else "?"),
               "symbols":[(x.name.decode(errors="replace") if x.name else f"ordinal:{x.ordinal}") for x in d.imports]} for d in entries]
        imports={"state":"PARTIAL" if problem else "PRESENT","dlls":dlls,"detail":problem or None}
    elif problem:
        imports={"state":"UNREADABLE","dlls":None,"detail":problem}
    else:
        imports={"state":"ABSENT","dlls":[],"detail":None}
    if imports["state"] in ("UNREADABLE","PARTIAL"):
        limitations.append(f"import directory {imports['state'].lower()}: {problem}")

    if parse_error:
        resources=None;debug=None
    else:
        top=getattr(pe,"DIRECTORY_ENTRY_RESOURCE",None)
        resources={"present":top is not None,"top_level_entries":len(top.entries) if top is not None else 0}
        dbg=getattr(pe,"DIRECTORY_ENTRY_DEBUG",None) or []
        cv=[]
        for d in dbg:
            name=getattr(getattr(d,"entry",None),"PdbFileName",None)
            if name:cv.append(name.rstrip(b"\x00").decode(errors="replace"))
        debug={"directory_present":bool(dbg),
               "entries":[{"type":int(d.struct.Type),"type_name":_KT_DEBUG_TYPES.get(int(d.struct.Type))} for d in dbg],
               "pdb_paths":cv,"pdb_indicator":bool(cv)}

    subsystem=int(pe.OPTIONAL_HEADER.Subsystem)
    info={
        "valid":True,"machine":hex(machine),"architecture":arch,"bits":bits,
        "subsystem":subsystem,"subsystem_name":_KT_SUBSYSTEMS.get(subsystem),
        "is_dll":bool(pe.FILE_HEADER.Characteristics&0x2000),
        "image_base":hex(pe.OPTIONAL_HEADER.ImageBase),"entry_point_rva":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "timestamp":int(pe.FILE_HEADER.TimeDateStamp),"size_bytes":size,
        "sections":sections,"imports":imports,"resources":resources,"debug":debug,
    }
    unknown=[k for k,v in info.items() if v is None]
    if imports["state"] in ("UNREADABLE","PARTIAL"):unknown.append("imports.dlls")

    ind=_kt_indicators(subsystem,imports,sections)
    by={i["name"]:i for i in ind}
    rationale=[]
    if imports["state"]!="PRESENT":
        rationale.append(f"imports are {imports['state']}: absence or presence of kernel imports cannot be relied on")
    if by["subsystem_native"]["present"] is False:
        rationale.append(f"subsystem is {info['subsystem_name'] or subsystem}, not NATIVE")
    if by["kernel_import"]["present"] is False:
        rationale.append("no ntoskrnl.exe or hal.dll import")
    if by["subsystem_native"]["present"] and by["kernel_import"]["present"] is False:
        rationale.append("conflict: native subsystem without a kernel import")
    if by["kernel_import"]["present"] and by["subsystem_native"]["present"] is False:
        rationale.append("conflict: kernel import with a non-native subsystem")
    strong=imports["state"]=="PRESENT" and by["subsystem_native"]["present"] and by["kernel_import"]["present"]
    likelihood="LIKELY" if strong else "UNKNOWN"
    if strong:
        rationale.append("native subsystem and a kernel import are both observed")
        rationale.append("INIT/PAGE section names "+("support this" if by["init_section"]["present"] or by["page_section"]["present"] else "are absent (they are not required)"))
    else:
        for name in ("init_section","page_section"):
            if by[name]["present"]:rationale.append(f"{name} observed, heuristic only")
    return json.dumps({
        "ok":True,"tool":"kernel_triage","status":"ANALYSIS_LIMITED" if limitations else "OK","path":relative(p),
        "pe":info,"indicators":ind,"driver_likelihood":likelihood,"rationale":rationale,
        "statement":KERNEL_TRIAGE_STATEMENT,"limitations":limitations,"unknown_fields":unknown,
    },ensure_ascii=False,indent=2)


# --- ioctl_control_code_decode: pure bit arithmetic, no file, no disassembly, no external tool ---------------
# CTL_CODE (winioctl.h) = (Device<<16)|(Access<<14)|(Function<<2)|Method, so: method 0-1, function 2-13, access 14-15,
# device_type 16-30, reserved 31. Convention: function = (code >> 2) & 0xFFF (12 bits); is_custom is derived as
# function >= 0x800 (Microsoft reserves < 0x800; 0x800 and above is the vendor range, valid, never rejected).
_IOCTL_METHODS={0:"METHOD_BUFFERED",1:"METHOD_IN_DIRECT",2:"METHOD_OUT_DIRECT",3:"METHOD_NEITHER"}
_IOCTL_ACCESS={0:"FILE_ANY_ACCESS",1:"FILE_READ_ACCESS",2:"FILE_WRITE_ACCESS",3:"FILE_READ_ACCESS|FILE_WRITE_ACCESS"}
_IOCTL_DEVICE_TYPES={
    0x01:"FILE_DEVICE_BEEP",0x02:"FILE_DEVICE_CD_ROM",0x03:"FILE_DEVICE_CD_ROM_FILE_SYSTEM",0x04:"FILE_DEVICE_CONTROLLER",
    0x05:"FILE_DEVICE_DATALINK",0x06:"FILE_DEVICE_DFS",0x07:"FILE_DEVICE_DISK",0x08:"FILE_DEVICE_DISK_FILE_SYSTEM",
    0x09:"FILE_DEVICE_FILE_SYSTEM",0x0A:"FILE_DEVICE_INPORT_PORT",0x0B:"FILE_DEVICE_KEYBOARD",0x0C:"FILE_DEVICE_MAILSLOT",
    0x0D:"FILE_DEVICE_MIDI_IN",0x0E:"FILE_DEVICE_MIDI_OUT",0x0F:"FILE_DEVICE_MOUSE",0x10:"FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x11:"FILE_DEVICE_NAMED_PIPE",0x12:"FILE_DEVICE_NETWORK",0x13:"FILE_DEVICE_NETWORK_BROWSER",
    0x14:"FILE_DEVICE_NETWORK_FILE_SYSTEM",0x15:"FILE_DEVICE_NULL",0x16:"FILE_DEVICE_PARALLEL_PORT",
    0x17:"FILE_DEVICE_PHYSICAL_NETCARD",0x18:"FILE_DEVICE_PRINTER",0x19:"FILE_DEVICE_SCANNER",0x1A:"FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x1B:"FILE_DEVICE_SERIAL_PORT",0x1C:"FILE_DEVICE_SCREEN",0x1D:"FILE_DEVICE_SOUND",0x1E:"FILE_DEVICE_STREAMS",
    0x1F:"FILE_DEVICE_TAPE",0x20:"FILE_DEVICE_TAPE_FILE_SYSTEM",0x21:"FILE_DEVICE_TRANSPORT",0x22:"FILE_DEVICE_UNKNOWN",
    0x23:"FILE_DEVICE_VIDEO",0x24:"FILE_DEVICE_VIRTUAL_DISK",0x25:"FILE_DEVICE_WAVE_IN",0x26:"FILE_DEVICE_WAVE_OUT",
    0x27:"FILE_DEVICE_8042_PORT",0x28:"FILE_DEVICE_NETWORK_REDIRECTOR",0x29:"FILE_DEVICE_BATTERY",0x2A:"FILE_DEVICE_BUS_EXTENDER",
    0x2B:"FILE_DEVICE_MODEM",0x2C:"FILE_DEVICE_VDM",0x2D:"FILE_DEVICE_MASS_STORAGE",0x2E:"FILE_DEVICE_SMB",
    0x2F:"FILE_DEVICE_KS",0x30:"FILE_DEVICE_CHANGER",0x31:"FILE_DEVICE_SMARTCARD",0x32:"FILE_DEVICE_ACPI",
    0x33:"FILE_DEVICE_DVD",0x34:"FILE_DEVICE_FULLSCREEN_VIDEO",0x35:"FILE_DEVICE_DFS_FILE_SYSTEM",
    0x36:"FILE_DEVICE_DFS_VOLUME",0x37:"FILE_DEVICE_SERENUM",0x38:"FILE_DEVICE_TERMSRV",0x39:"FILE_DEVICE_KSEC",
    0x3A:"FILE_DEVICE_FIPS",0x3B:"FILE_DEVICE_INFINIBAND",0x3E:"FILE_DEVICE_VMBUS",0x3F:"FILE_DEVICE_CRYPT_PROVIDER",
    0x40:"FILE_DEVICE_WPD",0x41:"FILE_DEVICE_BLUETOOTH",0x42:"FILE_DEVICE_MT_COMPOSITE",0x43:"FILE_DEVICE_MT_TRANSPORT",
    0x44:"FILE_DEVICE_BIOMETRIC",0x45:"FILE_DEVICE_PMI",
}

def _icd_one(code):
    if isinstance(code,bool) or not isinstance(code,int):
        return {"status":"INVALID_VALUE","error":"NOT_AN_INTEGER","value":repr(code)}
    if code<0:
        return {"status":"INVALID_VALUE","error":"NEGATIVE","value":code}
    if code>0xFFFFFFFF:
        return {"status":"INVALID_VALUE","error":"OUT_OF_RANGE_U32","value":code}
    device=(code>>16)&0x7FFF
    method=code&0x3
    access=(code>>14)&0x3
    function=(code>>2)&0xFFF
    name=_IOCTL_DEVICE_TYPES.get(device)
    return {"status":"DECODED","code":code,"code_hex":f"0x{code:08X}",
            "device_type":device,"device_type_name":name,"device_type_known":name is not None,
            "function":function,"is_custom":function>=0x800,
            "method":method,"method_name":_IOCTL_METHODS[method],
            "access":access,"access_name":_IOCTL_ACCESS[access],
            "reserved_bit_set":bool((code>>31)&1)}

def ioctl_control_code_decode(codes):
    """Split caller-supplied CTL_CODE integers into their declared bit fields. Reads nothing else.

    Per code: DECODED (a device_type missing from our table is still DECODED, with device_type_known false and
    the name None) or INVALID_VALUE (not an integer, negative, above 32 bits). Unknown is not invalid."""
    if not isinstance(codes,(list,tuple)) or not codes:
        return json.dumps({"ok":False,"tool":"ioctl_control_code_decode","status":"INVALID_INPUT","error":"CODES_NOT_A_NONEMPTY_LIST",
                           "fixable":True,"fix":"Pass a non-empty list of CTL_CODE integers."},ensure_ascii=False,indent=2)
    return json.dumps({"ok":True,"tool":"ioctl_control_code_decode","results":[_icd_one(c) for c in codes]},ensure_ascii=False,indent=2)


# --- ioctl_candidate_scan: the feeder for ioctl_control_code_decode -------------------------------------------
# Scans a code region from a start address and collects the immediates that are COMPARED (cmp reg/mem, imm and
# sub reg, imm chains), then hands them to ioctl_control_code_decode. It reports immediates compared in the
# scanned region. It never says "the driver's IOCTLs": a compared immediate may be a constant, a mask, a
# status code or an offset. proves_ioctl is always false and there is no boolean "is an IOCTL" field.
_ICS_MAX_INSTRUCTIONS=5000
_ICS_MIN_VALUE=0x10000
_ICS_LISTED_EXCLUSIONS=50
_ICS_STACK_REGS={"rsp","esp","sp","spl"}
_ICS_PATTERNS_SEARCHED=[
    "cmp reg, imm (32/64-bit operand; imm8/imm32 forms alike)",
    "cmp [mem], imm (32/64-bit operand)",
    "sub reg, imm (32/64-bit operand), chained across immediately following sub/cmp/test/conditional-jump "
    "instructions on the same register: the cumulative amount is the value the original register is compared with",
]
_ICS_PATTERNS_NOT_SEARCHED=[
    "mov reg, imm (a code loaded into a register and compared with another register)",
    "cmp reg, reg and cmp reg, [mem] (nothing immediate to read)",
    "lea reg, [reg-imm] and add reg, -imm (compilers also bias a switch this way)",
    "jump-table switches (cmp reg, N; ja; jmp [table+reg*8]): the table is not read",
    "sub [mem], imm, 8/16-bit operand widths, and any immediate outside the unsigned 32-bit range",
    "control flow: the scan is linear from the start address and never follows jumps or calls. It does not stop at ret: "
    "every ret passed is counted and listed in scope.rets_passed and each candidate and exclusion carries rets_before",
    "function-end signals other than ret: runs of int3 and alignment nop padding are NOT treated as a boundary "
    "(int3 can be a deliberate breakpoint and nop runs occur inside functions), so a boundary without a ret is not reported",
]
_ICS_RET_MNEMONICS=("ret","retn","retf")
_ICS_LISTED_RETS=50
_ICS_BOUNDARY_NOTE=("this site lies after a ret in a linear scan, so it may belong to another function than the one the scan "
                    "was started for; its value may be that function's, not this handler's")
_ICS_STATEMENT=("Immediates that are compared in the scanned region, each split by ioctl_control_code_decode. This is "
                "not a list of the driver's IOCTLs: a compared value may equally be a constant, a mask, a status code "
                "or an offset. proves_ioctl is false for every entry. Which criteria a value meets is listed, never "
                "summed into a verdict.")

def _ics_fail(error,status,message,**extra):
    out={"ok":False,"tool":"ioctl_candidate_scan","status":status,"error":error,"message":message}
    out.update(extra)
    return json.dumps(out,ensure_ascii=False,indent=2)

def _ics_walk(instrs):
    """Walk instructions linearly; return (matches, excluded). A match is a dict with pattern, value, raw, chain, entry."""
    chains={}
    matches=[];excluded=[];rets=[]
    for e in instrs:
        m=e["mnemonic"];ops=e["operands"];imms=e.get("immediates")
        if m in _ICS_RET_MNEMONICS:rets.append({"rva":e["address"].get("rva"),"va":e["address"].get("va")})
        parts=[x.strip() for x in ops.split(",")]
        if m in ("cmp","sub") and imms and len(parts)==2 and len(imms)==1:
            first=parts[0].lower()
            is_mem=first.endswith("]")
            if m=="sub" and is_mem:
                chains.clear();continue
            pattern="cmp_mem_imm" if is_mem else ("cmp_reg_imm" if m=="cmp" else "sub_reg_imm")
            imm=imms[0]
            where={"address":{"rva":e["address"].get("rva"),"va":e["address"].get("va")},"mnemonic":m,"operands":ops,"pattern":pattern,
                   "rets_before":len(rets),"after_ret_at":rets[-1] if rets else None}
            if not is_mem and first in _ICS_STACK_REGS:
                excluded.append(dict(where,compared_immediate=imm["hex"],reason="stack_pointer_register"));chains.clear();continue
            if imm["size"] not in (4,8):
                excluded.append(dict(where,compared_immediate=imm["hex"],reason="operand_width_not_32_or_64"));chains.pop(first,None);continue
            raw=int(imm["hex"],16) if imm["size"]==4 else imm["value"]
            if not 0<=raw<=0xFFFFFFFF:
                excluded.append(dict(where,compared_immediate=imm["hex"],reason="not_unsigned_32_range"));chains.pop(first,None);continue
            cum,chain=(0,[]) if is_mem else chains.get(first,(0,[]))
            value=(cum+raw)&0xFFFFFFFF
            if pattern=="sub_reg_imm":
                chain=chain+[{"address":where["address"]["rva"],"subtracted":hex(raw)}]
                chains[first]=(value,chain)
            if value==0xFFFFFFFF:
                excluded.append(dict(where,compared_immediate=hex(raw),value_hex=f"0x{value:08X}",reason="all_ones_sentinel"));continue
            if value<_ICS_MIN_VALUE:
                excluded.append(dict(where,compared_immediate=hex(raw),value_hex=f"0x{value:08X}",reason="below_0x10000_no_device_type"));continue
            matches.append({"where":where,"value":value,"raw":raw,"chain":chain,
                            "basis":"sub_chain_cumulative" if (len(chain)>1 if pattern=="sub_reg_imm" else bool(chain)) else "immediate"})
        elif m.startswith("j") and m!="jmp":continue
        elif m in ("nop","test","cmp"):continue
        else:chains.clear()
    return matches,excluded,rets

def ioctl_candidate_scan(path,start_rva=None,max_instructions=200,start_note=None):
    """Scan a code region from ``start_rva`` for compared immediates and decode each with ioctl_control_code_decode.

    ``start_rva`` is an RVA (int or "0x..." text). Left out, the scan starts at AddressOfEntryPoint; the origin is
    recorded in ``scope.start.source`` (caller_supplied or AddressOfEntryPoint) and ``start_note`` is kept verbatim,
    so an RVA taken from driver_major_function_scan is on the record as such. Nothing is chained automatically.

    Searched: cmp reg/mem, imm and sub reg, imm chains. Not searched: see ``scope.patterns_not_searched``.
    Immediates below 0x10000 (no room for a device type), stack-pointer operands and 0xFFFFFFFF are not candidates;
    they are counted and listed in ``excluded`` with a reason. Each candidate lists named criteria
    (device_type_in_known_table, reserved_bit_clear) and how many it meets; there is no boolean "is an IOCTL" field and
    ``proves_ioctl`` is false. outcome FOUND, NOT_FOUND (only for the searched patterns, scan not truncated, every
    byte decoded) or UNKNOWN (truncated or undecodable bytes and nothing found)."""
    try:
        p=safe_path(path)
        pe=_pe(p)
    except PermissionError as e:
        return _ics_fail("PATH_REFUSED","ANALYSIS_LIMITED",str(e))
    except Exception as e:
        return _ics_fail("INVALID_PE","ANALYSIS_LIMITED",f"Invalid or corrupt PE file ({type(e).__name__}): {e}")
    if start_rva is None:
        rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        source="AddressOfEntryPoint"
        if rva==0:return _ics_fail("ENTRY_POINT_ABSENT","ANALYSIS_LIMITED","The PE has no entry point; pass start_rva.")
    else:
        try:rva=int(str(start_rva),0)
        except ValueError:rva=-1
        if rva<0:return _ics_fail("INVALID_START_RVA","ANALYSIS_LIMITED",f"start_rva must be a non-negative integer RVA, got {start_rva!r}.")
        source="caller_supplied"
    try:cap=max(1,min(int(max_instructions),_ICS_MAX_INSTRUCTIONS))
    except (TypeError,ValueError):return _ics_fail("INVALID_MAX_INSTRUCTIONS","ANALYSIS_LIMITED",f"max_instructions must be an integer, got {max_instructions!r}.")
    d=disassemble_pe_structured(str(path),va=pe.OPTIONAL_HEADER.ImageBase+rva,max_instructions=cap)
    if not d.get("ok"):
        return _ics_fail(d["error"],d["status"],d["message"])
    instrs=d["instructions"]
    matches,excluded,rets=_ics_walk(instrs)
    decoded=json.loads(ioctl_control_code_decode([m["value"] for m in matches]))["results"] if matches else []
    cands=[]
    for m,dec in zip(matches,decoded):
        crit=[{"name":"device_type_in_known_table","met":bool(dec["device_type_known"]),
               "basis":"device_type is a key of the decoder's FILE_DEVICE_* table"},
              {"name":"reserved_bit_clear","met":not dec["reserved_bit_set"],
               "basis":"bit 31 of the code is 0 under the decoder's field layout"}]
        w=m["where"]
        cands.append({"address":w["address"],"mnemonic":w["mnemonic"],"operands":w["operands"],"pattern":w["pattern"],
                      "basis":m["basis"],"compared_immediate":hex(m["raw"]),"chain":m["chain"],
                      "value":m["value"],"value_hex":f"0x{m['value']:08X}","decoded":dec,
                      "criteria":crit,"criteria_met":sum(c["met"] for c in crit),"criteria_total":len(crit),"proves_ioctl":False,
                      "rets_before":w["rets_before"],"after_ret_at":w["after_ret_at"],
                      "may_be_in_another_function":w["rets_before"]>0,
                      "boundary_note":_ICS_BOUNDARY_NOTE if w["rets_before"]>0 else None})
    cands.sort(key=lambda c:(-c["criteria_met"],int(c["address"]["rva"],16)))
    reasons={}
    for x in excluded:reasons[x["reason"]]=reasons.get(x["reason"],0)+1
    truncated=bool(d["truncated"]);undec=d["decode_coverage"]["instructions_undecodable"]
    limited=truncated or undec>0
    outcome="FOUND" if cands else ("UNKNOWN" if limited else "NOT_FOUND")
    searched="cmp reg, imm; cmp [mem], imm; sub reg, imm"
    rationale=[]
    if cands:
        rationale.append(f"{len(cands)} immediate(s) were compared at the sites listed; none is shown to be a control code")
        rationale.append("criteria are listed per candidate for ordering only; a value that meets none is still listed, and a value that meets all is not thereby an IOCTL")
        rationale.append("custom device types (0x8000 and above) set bit 31 under this decoder's layout and so meet fewer criteria; they are not excluded for it")
    elif limited:
        why=[]
        if truncated:why.append(f"the scan stopped at max_instructions={cap} and more code follows at {d['truncation']['more_at']['rva']}")
        if undec:why.append(f"{undec} byte(s) did not decode")
        rationale.append("no candidate was seen, but "+" and ".join(why)+"; this is UNKNOWN, not NOT_FOUND")
    else:
        rationale.append(f"in the {len(instrs)} instruction(s) scanned from {hex(rva)}, no comparison with an immediate was seen under the searched patterns ({searched}) that survived the admission rule")
        rationale.append("this does not show that the region holds no IOCTL: the patterns not searched are listed in scope.patterns_not_searched")
    if any(c["rets_before"]>0 for c in cands):rationale.append("one or more candidates lie after a ret (rets_before > 0): they may belong to another function than the one scanned")
    if excluded:rationale.append(f"{len(excluded)} compared immediate(s) were set aside by the admission rule; see excluded")
    if source=="AddressOfEntryPoint":rationale.append("the start is the entry point: DriverEntry rarely compares control codes; the dispatch handler is a different address")
    res={"ok":True,"tool":"ioctl_candidate_scan","status":"ANALYSIS_LIMITED" if limited else "OK","path":relative(p),
         "outcome":outcome,"proves_ioctl":False,
         "scope":{"start":{"rva":hex(rva),"va":hex(pe.OPTIONAL_HEADER.ImageBase+rva),"source":source,"note":start_note},
                  "architecture":d["architecture"],"instructions_scanned":len(instrs),"max_instructions":cap,
                  "truncated":truncated,"ended_at":"instruction_budget" if truncated else "section_end",
                  "instructions_undecodable":undec,
                  "rets_passed":{"count":len(rets),"listed":rets[:_ICS_LISTED_RETS],"limit":_ICS_LISTED_RETS,
                                 "listed_truncated":len(rets)>_ICS_LISTED_RETS,
                                 "meaning":"the scan did not stop at these; a site after one may be in another function"},
                  "patterns_searched":list(_ICS_PATTERNS_SEARCHED),"patterns_not_searched":list(_ICS_PATTERNS_NOT_SEARCHED)},
         "admission":{"rule":"a compared immediate (or cumulative sub-chain value) becomes a candidate only if it is an unsigned 32-bit "
                             "value of at least 0x10000, so that the device_type field is not zero; the rest is listed in excluded",
                      "min_value":hex(_ICS_MIN_VALUE),"excluded_registers":sorted(_ICS_STACK_REGS),"excluded_values":["0xFFFFFFFF"],
                      "reason_for_min_value":"0, 1, 8, 0x20 and similar are loop counts, flags and stack or structure offsets far more often than control codes",
                      "limits":"a counter, mask or status code of 0x10000 or more passes this rule; it narrows noise, it proves nothing"},
         "candidates":cands,
         "excluded":{"count":len(excluded),"reasons":reasons,"listed":excluded[:_ICS_LISTED_EXCLUSIONS],
                     "listed_truncated":len(excluded)>_ICS_LISTED_EXCLUSIONS},
         "rationale":rationale,"statement":_ICS_STATEMENT}
    if truncated:res["scope"]["more_at"]=d["truncation"]["more_at"]
    return json.dumps(res,ensure_ascii=False,indent=2)


# --- driver_major_function_scan: a byte-pattern first pass over DriverEntry, NO disassembler -----------------
# DriverObject->MajorFunction[IRP_MJ_*] = handler usually compiles to a store at a constant offset:
#   x64:  lea reg,[rip+handler] ; mov [base+disp],reg      (MajorFunction at DRIVER_OBJECT+0x70, stride 8)
#   x86:  mov dword [base+disp],imm32 | mov reg,imm32 ; mov [base+disp],reg  (+0x38, stride 4)
# The scan walks every byte offset of a bounded window looking for the store shape, so it can hit bytes
# that are not an instruction boundary, and it cannot know the base register is the DriverObject. Every
# candidate is therefore heuristic and proves nothing. No capstone/IDA: it runs with no external tool.
_IRP_MJ_NAMES=("IRP_MJ_CREATE","IRP_MJ_CREATE_NAMED_PIPE","IRP_MJ_CLOSE","IRP_MJ_READ","IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION","IRP_MJ_SET_INFORMATION","IRP_MJ_QUERY_EA","IRP_MJ_SET_EA","IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION","IRP_MJ_SET_VOLUME_INFORMATION","IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL","IRP_MJ_DEVICE_CONTROL","IRP_MJ_INTERNAL_DEVICE_CONTROL","IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL","IRP_MJ_CLEANUP","IRP_MJ_CREATE_MAILSLOT","IRP_MJ_QUERY_SECURITY","IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER","IRP_MJ_SYSTEM_CONTROL","IRP_MJ_DEVICE_CHANGE","IRP_MJ_QUERY_QUOTA","IRP_MJ_SET_QUOTA","IRP_MJ_PNP")
_DMF_LAYOUT={0x8664:(0x70,8,True),0x14c:(0x38,4,False)}   # machine -> (MajorFunction offset, stride, is_x64)
_DMF_WINDOW=1024
_DMF_MAX_WINDOW=4096
_DMF_PAIR_DISTANCE=64
_DMF_JUMP_SEARCH=64   # a tail jump is looked for only in the first this-many bytes of a scanned window
_DMF_MAX_HOPS=3       # at most this many tail jumps are followed from the entry point
DISPATCH_SCAN_STATEMENT=("A first-pass byte-pattern heuristic, not a recovery: a candidate store is not proof of a "
                         "dispatch assignment, and the absence of one is not proof that none exists.")
_DMF_CAVEATS=("Only a bounded window from the DriverEntry address is read. When it holds no store pattern, a "
              "jmp rel8/rel32/[mem] in its first bytes is followed, and failing that an E8 call (the compiler's "
              "cookie-init + body trampoline), backward targets included (a few hops at most, see tail_jump); a tail call "
              "made any other way, or a jump further in, is not seen.",
              "A jump is recognised by bytes, not on an instruction boundary (an E8 call's 4 operand bytes are skipped), "
              "so a followed jump is a heuristic reading; tail_jump lists every hop so it can be checked. A jump-looking byte "
              "inside another instruction whose target happens to land in a code section cannot be told apart from a real "
              "jump without a disassembler; only implausible targets are rejected.",
              "Patterns are matched at every byte offset, not on instruction boundaries; the base register is not known to be the DriverObject.",
              "Stores through a computed index, a loop or a copied table are not matched.")

def _dmf_refuse(status,error,fixable,fix,**extra):
    """Refusal envelope (same keys as _kt_refuse, own tool name). outcome is always NOT_LOOKED: nothing was searched."""
    body={"ok":False,"tool":"driver_major_function_scan","status":status,"error":error,"fixable":fixable,"fix":fix,
          "outcome":"NOT_LOOKED"}
    body.update(extra)
    return json.dumps(body,ensure_ascii=False,indent=2)

def _dmf_index(disp,base,stride):
    rel=disp-base
    if rel<0 or rel%stride:return None
    idx=rel//stride
    return idx if idx<len(_IRP_MJ_NAMES) else None

def _dmf_find(buf,entry_rva,image_base,x64,base,stride,code_ranges):
    """Candidate MajorFunction stores in ``buf`` (bytes read from ``entry_rva``). Pure function of its inputs."""
    def code_rva(r):
        return r if r is not None and any(a<=r<b for a,b in code_ranges) else None
    loads=[]   # (offset, register, handler rva)
    for i in range(len(buf)):
        if x64:
            if i+7<=len(buf) and buf[i] in (0x48,0x4C) and buf[i+1]==0x8D and (buf[i+2]&0xC7)==0x05:
                rel=int.from_bytes(buf[i+3:i+7],"little",signed=True)
                loads.append((i,((buf[i]&4)<<1)|((buf[i+2]>>3)&7),entry_rva+i+7+rel))
        elif i+5<=len(buf) and 0xB8<=buf[i]<=0xBF:
            loads.append((i,buf[i]-0xB8,int.from_bytes(buf[i+1:i+5],"little")-image_base))
    out=[]
    for i in range(len(buf)-2):
        op=buf[i]
        if x64:
            if not (0x48<=op<=0x4F and buf[i+1]==0x89):continue
            m=buf[i+2];reg=((op&4)<<1)|((m>>3)&7);at=i+3;imm=False
        elif op==0x89:
            m=buf[i+1];reg=(m>>3)&7;at=i+2;imm=False
        elif op==0xC7:
            m=buf[i+1];reg=None;at=i+2;imm=True
            if (m>>3)&7:continue
        else:continue
        mod,rm=m>>6,m&7
        if mod not in (1,2) or rm==4:continue
        dlen=1 if mod==1 else 4
        if at+dlen+(4 if imm else 0)>len(buf):continue
        disp=int.from_bytes(buf[at:at+dlen],"little",signed=True)
        idx=_dmf_index(disp,base,stride)
        if idx is None:continue
        handler=None;basis="store_only"
        if imm:
            handler=code_rva(int.from_bytes(buf[at+dlen:at+dlen+4],"little")-image_base);basis="store_of_immediate"
        else:
            near=[l for l in loads if l[1]==reg and 0<i-l[0]<=_DMF_PAIR_DISTANCE]
            if near:
                handler=code_rva(near[-1][2])
                if handler is not None:basis="load_then_store"
        out.append({"index":idx,"name":_IRP_MJ_NAMES[idx],"store_rva":hex(entry_rva+i),
                    "handler_rva":hex(handler) if handler is not None else None,
                    "confidence":"heuristic" if handler is not None else "heuristic_weak",
                    "basis":basis,"proves_dispatch":False})
    return out

def _dmf_read(pe,rva,window):
    """Bytes at ``rva`` from the section holding it: ("OK",buf), ("NOT_IN_SECTION",None) or ("UNREADABLE",None)."""
    sec=next((s for s in pe.sections if s.VirtualAddress<=rva<s.VirtualAddress+max(int(s.Misc_VirtualSize),int(s.SizeOfRawData))),None)
    if sec is None:return "NOT_IN_SECTION",None
    delta=rva-int(sec.VirtualAddress)
    start=int(sec.PointerToRawData)+delta
    stop=min(start+window,int(sec.PointerToRawData)+int(sec.SizeOfRawData),len(pe.__data__))
    if delta>=int(sec.SizeOfRawData) or stop<=start:return "UNREADABLE",None
    return "OK",bytes(pe.__data__[start:stop])

def _dmf_tail_jump(pe,buf,at_rva,image_base,x64,code_ranges):
    """The first tail jump in the first _DMF_JUMP_SEARCH bytes of ``buf`` (read from ``at_rva``), or None.

    Recognised: EB cb (jmp rel8), E9 cd (jmp rel32), FF 25 cd (jmp [rip+disp32] on x64, jmp [abs32] on x86). A byte
    pattern past offset 0 counts only if it points somewhere plausible (a relative target inside a code section, an
    indirect slot inside the image) and an E8 call's operand bytes are skipped, because a prologue is not a jump.
    The result has ``jump_rva``, ``encoding`` and either ``to_rva`` or a ``reason`` the target cannot be followed;
    an indirect jump is resolved only when its slot is an import-table entry, and then ``import`` names it."""
    def in_image(r):return any(s.VirtualAddress<=r<s.VirtualAddress+max(int(s.Misc_VirtualSize),int(s.SizeOfRawData)) for s in pe.sections)
    def in_code(r):return any(a<=r<b for a,b in code_ranges)
    i=0;n=min(len(buf),_DMF_JUMP_SEARCH)
    while i<n:
        b=buf[i]
        if b==0xE8:i+=5;continue
        found=None
        if b==0xEB and i+2<=len(buf):
            found=("jmp_rel8",at_rva+i+2+int.from_bytes(buf[i+1:i+2],"little",signed=True),False)
        elif b==0xE9 and i+5<=len(buf):
            found=("jmp_rel32",at_rva+i+5+int.from_bytes(buf[i+1:i+5],"little",signed=True),False)
        elif b==0xFF and i+6<=len(buf) and buf[i+1]==0x25:
            d=int.from_bytes(buf[i+2:i+6],"little",signed=x64)
            found=("jmp_indirect_rip" if x64 else "jmp_indirect_abs",(at_rva+i+6+d) if x64 else d-image_base,True)
        if found:
            enc,target,indirect=found
            plausible=in_image(target) if indirect else in_code(target)
            if i==0 or plausible:
                out={"jump_rva":hex(at_rva+i),"jump_offset":i,"encoding":enc}
                if indirect:
                    out["slot_rva"]=hex(target)
                    imp=next((m for d in (getattr(pe,"DIRECTORY_ENTRY_IMPORT",None) or []) for m in d.imports
                              if m.address is not None and int(m.address)-image_base==target),None)
                    if imp is not None:
                        dll=next(d.dll for d in pe.DIRECTORY_ENTRY_IMPORT if imp in d.imports)
                        out["import"]=f"{dll.decode(errors='replace')}!{imp.name.decode(errors='replace') if imp.name else 'ordinal '+str(imp.ordinal)}"
                        out["reason"]="INDIRECT_TARGET_IS_IMPORT"
                    else:
                        out["reason"]="INDIRECT_TARGET_NOT_STATIC" if in_image(target) else "TARGET_OUTSIDE_IMAGE"
                elif not in_image(target):
                    out["to_rva"]=hex(target) if target>=0 else None;out["reason"]="TARGET_OUTSIDE_IMAGE"
                elif not in_code(target):
                    out["to_rva"]=hex(target);out["reason"]="TARGET_NOT_IN_CODE_SECTION"
                else:
                    out["to_rva"]=hex(target)
                return out
        i+=1
    return None

def _dmf_calls(buf,at_rva,code_ranges):
    """E8 rel32 calls in the first _DMF_JUMP_SEARCH bytes of ``buf`` (read from ``at_rva``) whose target is inside a code
    section, in order, as dicts with call_rva, call_offset and to_rva. Target = end of the instruction + signed rel32, so
    it may lie BEFORE ``at_rva``. rel32 == 0 (call-to-next, the get-PC idiom) is not a function call and is skipped. Byte pattern only, no instruction boundaries: an E8 inside another instruction can
    match, and only a target outside every code section rejects it."""
    out=[];i=0;n=min(len(buf),_DMF_JUMP_SEARCH)
    while i<n:
        if buf[i]==0xE8 and i+5<=len(buf):
            rel=int.from_bytes(buf[i+1:i+5],"little",signed=True)
            t=at_rva+i+5+rel
            if rel and any(a<=t<b for a,b in code_ranges):
                out.append({"call_rva":hex(at_rva+i),"call_offset":i,"to_rva":hex(t)});i+=5;continue
        i+=1
    return out

def driver_major_function_scan(path,max_bytes=_DMF_WINDOW):
    """First-pass byte-pattern search for DriverObject->MajorFunction[IRP_MJ_*] stores near DriverEntry. No disassembler.

    If the entry point's window holds no store, a tail jump in its first bytes (jmp rel8, jmp rel32, jmp [mem]) is
    followed (and, when there is no jump, the first E8 call, forward or backward, whose target window shows a store; hop encoding call_rel32, kind call), at most _DMF_MAX_HOPS deep and never revisiting an address, and the target is scanned instead;
    ``tail_jump`` lists every hop (from, jump and to RVA) and ``entry.scanned_rva`` says what was scanned. A jump
    that cannot be followed (target outside the image or unreadable, an indirect slot that is not statically known,
    a loop, too many hops) gives ``outcome`` TAIL_JUMP_UNRESOLVED -- never NOT_FOUND -- with ``tail_jump.reason``.
    Four outcomes that never share a code. ``outcome`` FOUND: ``candidates`` lists stores, each with
    ``confidence`` heuristic (paired with a load of an in-image code address) or heuristic_weak (store only),
    and ``proves_dispatch`` always false. NOT_FOUND: the window was read and no pattern matched; ``ok`` is true,
    ``candidates`` is empty and ``rationale`` says what was and was not covered. NOT_LOOKED: ``ok`` false with an
    ``error`` -- PATH_REFUSED, FILE_NOT_FOUND, FILE_NOT_ACCESSIBLE, INVALID_PE, UNSUPPORTED_MACHINE,
    EXPORT_DIRECTORY_UNREADABLE, ENTRY_POINT_ABSENT, ENTRY_POINT_NOT_IN_SECTION or ENTRY_POINT_UNREADABLE.
    ``dispatch_table`` is CANDIDATES_ONLY or UNKNOWN, never a recovered table. The DriverEntry address is the
    ``DriverEntry`` export when the export table is readable and has one, else AddressOfEntryPoint."""
    try:
        p=safe_path(path)
    except PermissionError as e:
        return _dmf_refuse("PATH_REFUSED",str(e),True,"Pass a path inside the workspace root.",path=str(path))
    if not p.is_file():
        return _dmf_refuse("FILE_MISSING","FILE_NOT_FOUND",True,"Pass the path of an existing file.",path=str(path))
    try:
        pe=_pe(p)
    except OSError as e:
        return _dmf_refuse("ANALYSIS_LIMITED","FILE_NOT_ACCESSIBLE",False,"The file could not be read; check permissions or whether another process holds it.",path=relative(p),error_type=type(e).__name__)
    except Exception as e:
        return _dmf_refuse("ANALYSIS_LIMITED","INVALID_PE",False,"The file is not a PE or its header is corrupt; nothing was read from it.",path=relative(p),detail=f"{type(e).__name__}: {e}")
    machine=int(pe.FILE_HEADER.Machine)
    layout=_DMF_LAYOUT.get(machine)
    if layout is None:
        return _dmf_refuse("UNSUPPORTED","UNSUPPORTED_MACHINE",False,"Only x86 and x86_64 byte patterns are searched.",path=relative(p),machine=hex(machine))
    base,stride,x64=layout
    window=max(16,min(int(max_bytes),_DMF_MAX_WINDOW))
    parse_error=_parse_directories(pe)
    problem=_directory_problem(pe,parse_error,0,"DIRECTORY_ENTRY_EXPORT","export")
    if problem:
        return _dmf_refuse("ANALYSIS_LIMITED","EXPORT_DIRECTORY_UNREADABLE",False,"The export table could not be read, so whether DriverEntry is exported is unknown; the entry point was not guessed.",path=relative(p),detail=problem)
    entry_rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint);source="AddressOfEntryPoint"
    ex=getattr(pe,"DIRECTORY_ENTRY_EXPORT",None)
    for s in (ex.symbols if ex else []):
        if s.name==b"DriverEntry" and s.address and not getattr(s,"forwarder",None):
            entry_rva=int(s.address);source="export:DriverEntry";break
    if not entry_rva:
        return _dmf_refuse("ANALYSIS_LIMITED","ENTRY_POINT_ABSENT",False,"The PE declares no entry point, so there is no DriverEntry address to read from.",path=relative(p))
    state,buf=_dmf_read(pe,entry_rva,window)
    if state=="NOT_IN_SECTION":
        return _dmf_refuse("ANALYSIS_LIMITED","ENTRY_POINT_NOT_IN_SECTION",False,"The entry point RVA lies outside every section, so there are no bytes to read.",path=relative(p),entry_rva=hex(entry_rva),source=source)
    if state=="UNREADABLE":
        return _dmf_refuse("ANALYSIS_LIMITED","ENTRY_POINT_UNREADABLE",False,"The section holding the entry point has no readable bytes at that address (file cut short, or the address is in zero-filled virtual space).",path=relative(p),entry_rva=hex(entry_rva),source=source)
    code=[(int(s.VirtualAddress),int(s.VirtualAddress)+max(int(s.Misc_VirtualSize),int(s.SizeOfRawData)))
          for s in pe.sections if s.Characteristics&0x20000020]
    image_base=int(pe.OPTIONAL_HEADER.ImageBase)
    # Scan the entry point; only if it shows no store, follow a tail jump (at most _DMF_MAX_HOPS, no revisits).
    scan_rva=entry_rva;hops=[];seen={entry_rva};blocked=None
    while True:
        cands=_dmf_find(buf,scan_rva,image_base,x64,base,stride,code)
        if cands:break
        jump=_dmf_tail_jump(pe,buf,scan_rva,image_base,x64,code)
        if jump is None:
            # No jump: the entry point may CALL the real body (compiler trampoline: cookie-init call, then body call).
            calls=_dmf_calls(buf,scan_rva,code)
            if not calls:break
            # Try every call in order and follow the first whose target window shows a store. In the measured
            # cookie-init + body trampoline the first call has none and the second is the body. A call whose target
            # shows no store is NOT followed: going on through an arbitrary call manufactures weak candidates.
            pick=None;nbuf=None
            for c in calls:
                st,nb=_dmf_read(pe,int(c["to_rva"],16),window)
                if st=="OK" and _dmf_find(nb,int(c["to_rva"],16),image_base,x64,base,stride,code):
                    pick=c;nbuf=nb;break
            if pick is None:break
            target=int(pick["to_rva"],16)
            if len(hops)>=_DMF_MAX_HOPS:
                blocked=dict(pick,jump_rva=pick["call_rva"],encoding="call_rel32",reason="CHAIN_LIMIT");break
            if target in seen:
                blocked=dict(pick,jump_rva=pick["call_rva"],encoding="call_rel32",reason="JUMP_LOOP");break
            hops.append({"from_rva":hex(scan_rva),"jump_rva":pick["call_rva"],"encoding":"call_rel32","kind":"call",
                         "to_rva":pick["to_rva"],"direction":"backward" if target<scan_rva else "forward",
                         "calls_seen":len(calls)})
            seen.add(target);scan_rva=target;buf=nbuf;continue
        if jump.get("reason"):blocked=jump;break
        target=int(jump["to_rva"],16)
        if len(hops)>=_DMF_MAX_HOPS:
            blocked=dict(jump,reason="CHAIN_LIMIT");break
        if target in seen:
            blocked=dict(jump,reason="JUMP_LOOP");break
        state,nbuf=_dmf_read(pe,target,window)
        if state!="OK":
            blocked=dict(jump,reason="TARGET_UNREADABLE");break
        hops.append({"from_rva":hex(scan_rva),"jump_rva":jump["jump_rva"],"encoding":jump["encoding"],"to_rva":jump["to_rva"]})
        seen.add(target);scan_rva=target;buf=nbuf
    tail={"state":"UNRESOLVED" if blocked else ("FOLLOWED" if hops else "NONE"),"hops":hops,
          "max_hops":_DMF_MAX_HOPS,"search_bytes":_DMF_JUMP_SEARCH}
    if blocked:
        tail["reason"]=blocked["reason"];tail["blocked_jump"]={k:v for k,v in blocked.items() if k not in ("reason","import")}
        if "import" in blocked:tail["import"]=blocked["import"]

    subsystem=int(pe.OPTIONAL_HEADER.Subsystem)
    entries=getattr(pe,"DIRECTORY_ENTRY_IMPORT",None)
    iprob=_directory_problem(pe,parse_error,1,"DIRECTORY_ENTRY_IMPORT","import")
    if entries:
        imports={"state":"PARTIAL" if iprob else "PRESENT","dlls":[{"dll":(d.dll.decode(errors="replace") if d.dll else "?")} for d in entries]}
    else:
        imports={"state":"UNREADABLE" if iprob else "ABSENT","dlls":None if iprob else []}
    secs=[{"name":s.Name.rstrip(b"\x00").decode(errors="replace")} for s in pe.sections]
    indicators=_kt_indicators(subsystem,imports,secs)
    rationale=[]
    if cands:
        rationale.append(f"{len(cands)} candidate store(s) matched the MajorFunction offset pattern; none is proof of a dispatch assignment")
        if all(c["handler_rva"] is None for c in cands):
            rationale.append("no candidate could be paired with a load of an in-image code address")
    elif blocked:
        rationale.append(f"the entry point ({hex(entry_rva)}) holds no store pattern and its tail jump could not be followed: {blocked['reason']}; this is not a NOT_FOUND")
    else:
        rationale.append(f"{len(buf)} byte(s) from {hex(scan_rva)} were read and no MajorFunction store pattern matched")
        rationale.append("this does not show the driver sets no dispatch routines: see caveats for what the pattern cannot see")
    if hops:rationale.append(f"scanned {hex(scan_rva)}, reached from the entry point {hex(entry_rva)} through {len(hops)} tail jump(s) listed in tail_jump.hops")
    if len(buf)<window:rationale.append("the window was cut short by the end of the section's raw data")
    if next(i for i in indicators if i["name"]=="subsystem_native")["present"] is False:
        rationale.append("subsystem is not NATIVE: this file may not be a driver; it was scanned anyway")
    return json.dumps({
        "ok":True,"tool":"driver_major_function_scan","status":"OK","path":relative(p),
        "outcome":"FOUND" if cands else ("TAIL_JUMP_UNRESOLVED" if blocked else "NOT_FOUND"),
        "dispatch_table":"CANDIDATES_ONLY" if cands else "UNKNOWN","proves_dispatch":False,
        "entry":{"source":source,"rva":hex(entry_rva),"scanned_rva":hex(scan_rva),"scanned_bytes":len(buf),"requested_window":window,
                 "architecture":"x86_64" if x64 else "x86"},
        "tail_jump":tail,
        "candidates":cands,"indicators":indicators,"rationale":rationale,"caveats":list(_DMF_CAVEATS),
        "statement":DISPATCH_SCAN_STATEMENT,
    },ensure_ascii=False,indent=2)


# ---- rip_relative_iat_scan -------------------------------------------------
# Which imported function a binary calls through its import address table, and from where. A byte-pattern
# first pass over the executable sections, no disassembler (deliberately: it needs no external tool and
# its limits are stated rather than hidden). Recognised: FF 15 (call [mem]) and FF 25 (jmp [mem]).
#   x86_64: the operand is RIP-relative, target = (RVA of the instruction's end) + signed disp32.
#   x86:    the same bytes are an ABSOLUTE address (call [abs32]); target = disp32 - ImageBase. No RIP maths.
# A reference is a finding only if its target is exactly an import-table slot; anything else (code, data,
# an address inside the table that is not a slot start) is ignored, not guessed at.
_RIA_MAX_FINDINGS=200
_RIA_HARD_LIMIT=5000
_RIA_EXAMINE_LIMIT=250000   # with an import_filter: most references the scan will look at before it says it stopped
_RIA_CODE_FLAGS=0x20000020   # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE (same test driver_major_function_scan uses)
IAT_SCAN_STATEMENT=("A first-pass byte-pattern heuristic, not a call graph: a finding is a byte sequence whose target is an "
                    "import slot, not proof that the code runs, and the absence of one is not proof the import is unused.")
_RIA_CAVEATS=("Patterns are matched at every byte offset of the executable sections, not on instruction boundaries, so FF 15 / FF 25 "
              "bytes inside another instruction's operand can be reported; the target landing on an import slot makes that "
              "unlikely, not impossible.",
              "Only direct FF 15 / FF 25 references are seen. Calls through a register loaded from a slot, delay-load stubs, "
              "GetProcAddress-style or MmGetSystemRoutineAddress lookups and imports by a copied table are not.",
              "Which function a slot holds is read from the import directory as written on disk; it is not what the loader "
              "will have bound at run time.")

def _ria_refuse(status,error,fixable,fix,**extra):
    """Refusal envelope (same keys as _dmf_refuse, own tool name). outcome is always NOT_LOOKED: nothing was searched."""
    body={"ok":False,"tool":"rip_relative_iat_scan","status":status,"error":error,"fixable":fixable,"fix":fix,
          "outcome":"NOT_LOOKED"}
    body.update(extra)
    return json.dumps(body,ensure_ascii=False,indent=2)

def _ria_slots(pe,image_base):
    """{slot rva: "dll!name"} for every import entry that has an address, plus the (start,end) rva span of each table."""
    names={};spans=[]
    for d in (getattr(pe,"DIRECTORY_ENTRY_IMPORT",None) or []):
        dn=d.dll.decode(errors="replace") if d.dll else "?"
        lo=hi=None
        for m in d.imports:
            if m.address is None:continue
            rva=int(m.address)-image_base
            names[rva]=f"{dn}!{m.name.decode(errors='replace') if m.name else 'ordinal '+str(m.ordinal)}"
            lo=rva if lo is None else min(lo,rva);hi=rva if hi is None else max(hi,rva)
        if lo is not None:spans.append((lo,hi))
    return names,spans

def _ria_find(buf,sec_rva,image_base,x64,names,spans):
    """Every FF 15 / FF 25 in ``buf`` (read from ``sec_rva``) whose target is an import slot. Pure function of its inputs.

    Returns (findings, ignored): ``ignored`` counts references whose target is not an import slot."""
    out=[];ignored=0
    step=8 if x64 else 4
    for i in range(len(buf)-5):
        if buf[i]!=0xFF or buf[i+1] not in (0x15,0x25):continue
        if x64:
            target=sec_rva+i+6+int.from_bytes(buf[i+2:i+6],"little",signed=True);basis="rip_relative"
        else:
            target=int.from_bytes(buf[i+2:i+6],"little")-image_base;basis="absolute_disp32"
        in_table=any(lo<=target<hi+step for lo,hi in spans)
        if not in_table or target not in names:
            ignored+=1;continue
        out.append({"call_rva":hex(sec_rva+i),"encoding":"FF15" if buf[i+1]==0x15 else "FF25",
                    "kind":"call" if buf[i+1]==0x15 else "jmp","slot_rva":hex(target),"import":names[target],
                    "target_basis":basis,"confidence":"heuristic","proves_call":False})
    return out,ignored

def rip_relative_iat_scan(path,max_findings=_RIA_MAX_FINDINGS,import_filter=None):
    """First-pass byte-pattern search for calls/jumps made through the import address table. No disassembler.

    Recognises FF 15 and FF 25. On x86_64 the target is RIP-relative (instruction end RVA + disp32); on x86 the same
    bytes are an absolute address and the target is disp32 - ImageBase (RIP arithmetic is never applied to x86).
    A reference counts only if its target is exactly an import slot, then ``import`` is ``dll!name`` (the format
    driver_major_function_scan's tail_jump.import uses). Three outcomes that never share a code. FOUND: ``findings``,
    each with ``proves_call`` false. NOT_FOUND: the code was read and no reference landed on an import slot (or the PE
    has no import directory at all, ``reason`` NO_IMPORT_DIRECTORY); ``ok`` true, ``findings`` empty. NOT_LOOKED:
    ``ok`` false with an ``error`` -- PATH_REFUSED, FILE_NOT_FOUND, FILE_NOT_ACCESSIBLE, INVALID_PE, UNSUPPORTED_MACHINE,
    IMPORT_DIRECTORY_UNREADABLE or CODE_SECTION_UNREADABLE. ``truncation`` always says how many findings were
    found, returned and omitted, and which limit (``max_findings``) applied.

    ``import_filter`` (a Python callable on the ``dll!name`` string, not exposed through the tool schema) keeps only
    the references it accepts, BEFORE ``max_findings`` is applied, so a caller interested in a few imports of a driver
    with thousands of references does not spend the output limit on the rest. Every reference is still examined; at
    most ``_RIA_EXAMINE_LIMIT`` of them, and ``truncation`` says so (``examine_omitted``) if the scan stops earlier.
    Without a filter nothing about the result changes."""
    try:
        p=safe_path(path)
    except PermissionError as e:
        return _ria_refuse("PATH_REFUSED",str(e),True,"Pass a path inside the workspace root.",path=str(path))
    if not p.is_file():
        return _ria_refuse("FILE_MISSING","FILE_NOT_FOUND",True,"Pass the path of an existing file.",path=str(path))
    try:
        pe=_pe(p)
    except OSError as e:
        return _ria_refuse("ANALYSIS_LIMITED","FILE_NOT_ACCESSIBLE",False,"The file could not be read; check permissions or whether another process holds it.",path=relative(p),error_type=type(e).__name__)
    except Exception as e:
        return _ria_refuse("ANALYSIS_LIMITED","INVALID_PE",False,"The file is not a PE or its header is corrupt; nothing was read from it.",path=relative(p),detail=f"{type(e).__name__}: {e}")
    machine=int(pe.FILE_HEADER.Machine)
    layout=_DMF_LAYOUT.get(machine)
    if layout is None:
        return _ria_refuse("UNSUPPORTED","UNSUPPORTED_MACHINE",False,"Only x86 and x86_64 byte patterns are searched.",path=relative(p),machine=hex(machine))
    x64=layout[2]
    limit=max(1,min(int(max_findings),_RIA_HARD_LIMIT))
    parse_error=_parse_directories(pe)
    iprob=_directory_problem(pe,parse_error,1,"DIRECTORY_ENTRY_IMPORT","import")
    entries=getattr(pe,"DIRECTORY_ENTRY_IMPORT",None)
    image_base=int(pe.OPTIONAL_HEADER.ImageBase)
    arch="x86_64" if x64 else "x86"
    if not entries and iprob:
        return _ria_refuse("ANALYSIS_LIMITED","IMPORT_DIRECTORY_UNREADABLE",False,"The import directory could not be read, so no slot can be named; this is NOT the same as a binary with no imports.",path=relative(p),detail=iprob)
    secs=[s for s in pe.sections if s.Characteristics&_RIA_CODE_FLAGS]
    bufs=[]
    for s in secs:
        state,buf=_dmf_read(pe,int(s.VirtualAddress),int(s.SizeOfRawData))
        if state=="OK" and buf:bufs.append((int(s.VirtualAddress),buf))
    if not bufs:
        return _ria_refuse("ANALYSIS_LIMITED","CODE_SECTION_UNREADABLE",False,"No executable section has readable bytes in the file (none declared, or the file is cut short); nothing was searched.",path=relative(p),executable_sections=len(secs))
    names,spans=_ria_slots(pe,image_base)
    found=[];ignored=0
    for rva,buf in bufs:
        f,ig=_ria_find(buf,rva,image_base,x64,names,spans)
        found+=f;ignored+=ig
    examined=len(found);examine_omitted=0;kept_out=0
    if import_filter is not None:
        examine_omitted=max(0,examined-_RIA_EXAMINE_LIMIT)
        looked=found[:_RIA_EXAMINE_LIMIT]
        found=[f for f in looked if import_filter(f["import"])]
        kept_out=len(looked)-len(found)
    total=len(found);returned=found[:limit]
    trunc={"truncated":total>limit,"limit_name":"max_findings","limit":limit,"found_total":total,"returned":len(returned),"omitted":total-len(returned)}
    if import_filter is not None:
        trunc.update(truncated=total>limit or examine_omitted>0,examined_total=examined,not_matching_filter=kept_out,
                     examine_limit=_RIA_EXAMINE_LIMIT,examine_omitted=examine_omitted)
    rationale=[];reason=None
    if returned:
        rationale.append(f"{total} reference(s) landed on an import slot; none is proof the code runs")
    elif import_filter is not None and examined:
        reason="NO_REFERENCE_MATCHED_THE_FILTER"
        rationale.append(f"{examined} reference(s) landed on an import slot and none matched the filter")
    elif not entries:
        reason="NO_IMPORT_DIRECTORY"
        rationale.append("the PE has no import directory, so there is no slot a call could resolve to; this is a read fact about the file, not a failure")
    else:
        reason="NO_REFERENCE_LANDED_ON_AN_IMPORT_SLOT"
        rationale.append(f"{sum(len(b) for _,b in bufs)} byte(s) of executable section were read and no FF 15 / FF 25 target was an import slot")
        rationale.append("this does not show no import is called: see caveats for what the pattern cannot see")
    if total>limit:rationale.append(f"truncated: {total-limit} finding(s) omitted, the max_findings limit of {limit} was reached")
    if examine_omitted:rationale.append(f"truncated: only the first {_RIA_EXAMINE_LIMIT} of {examined} reference(s) were examined against the filter")
    if import_filter is not None and kept_out:rationale.append(f"{kept_out} reference(s) were examined and did not match the filter")
    if ignored:rationale.append(f"{ignored} FF 15 / FF 25 reference(s) whose target is not an import slot were ignored")
    if iprob:rationale.append(f"the import directory is only partly readable ({iprob}); imports past the break cannot be named")
    body={"ok":True,"tool":"rip_relative_iat_scan","status":"OK","path":relative(p),
          "outcome":"FOUND" if returned else "NOT_FOUND","proves_call":False,
          "entry":{"architecture":arch,"target_basis":"rip_relative" if x64 else "absolute_disp32","image_base":hex(image_base),
                   "code_sections_read":len(bufs),"imports_state":"PARTIAL" if iprob else ("PRESENT" if entries else "ABSENT")},
          "findings":returned,"ignored_references":ignored,"truncation":trunc,"rationale":rationale,
          "caveats":list(_RIA_CAVEATS),"statement":IAT_SCAN_STATEMENT}
    if reason:body["reason"]=reason
    return json.dumps(body,ensure_ascii=False,indent=2)


# ---- kernel_callback_registrations -----------------------------------------
# A thin filter over rip_relative_iat_scan: which of its import-slot references name a callback-registration API.
# No scan logic of its own. Every API below was checked to be a real export, by reading the export table of the
# OS kernel image (ntoskrnl.exe) or of fltmgr.sys on the build the table was made on; the module is the one that
# exports it (FltRegisterFilter is in fltmgr.sys, not ntoskrnl.exe). The family labels are conceptual and were NOT
# verified: an export proves the name exists, not what the function does. The list is not exhaustive.
_KCR_APIS={
    ("ntoskrnl","PsSetCreateProcessNotifyRoutine"):"process",("ntoskrnl","PsSetCreateProcessNotifyRoutineEx"):"process",
    ("ntoskrnl","PsSetCreateProcessNotifyRoutineEx2"):"process",
    ("ntoskrnl","PsSetCreateThreadNotifyRoutine"):"thread",("ntoskrnl","PsSetCreateThreadNotifyRoutineEx"):"thread",
    ("ntoskrnl","PsSetLoadImageNotifyRoutine"):"image",("ntoskrnl","PsSetLoadImageNotifyRoutineEx"):"image",
    ("ntoskrnl","ObRegisterCallbacks"):"object",
    ("ntoskrnl","CmRegisterCallback"):"registry",("ntoskrnl","CmRegisterCallbackEx"):"registry",
    ("ntoskrnl","IoRegisterShutdownNotification"):"shutdown",("ntoskrnl","IoRegisterLastChanceShutdownNotification"):"shutdown",
    ("ntoskrnl","IoRegisterFsRegistrationChange"):"filesystem",("ntoskrnl","IoRegisterFsRegistrationChangeMountAware"):"filesystem",
    ("fltmgr","FltRegisterFilter"):"filesystem",
    ("ntoskrnl","PoRegisterPowerSettingCallback"):"power",
    # Second batch: name existence re-verified from the ntoskrnl.exe export table; the family labels are inference
    # from the name only, NOT verified. All nine candidates were added. For IoRegisterBootDriverCallback and
    # SeRegisterImageVerificationCallback the name alone does not settle WHAT is registered, but the table reports
    # that a registration-style API is called, not what it registers, so they are in with deliberately plain families.
    ("ntoskrnl","KeRegisterBugCheckCallback"):"bugcheck",("ntoskrnl","KeRegisterBugCheckReasonCallback"):"bugcheck",
    ("ntoskrnl","KeRegisterNmiCallback"):"nmi",
    ("ntoskrnl","IoRegisterPlugPlayNotification"):"pnp",
    ("ntoskrnl","ExRegisterCallback"):"executive",
    ("ntoskrnl","PoRegisterCoalescingCallback"):"power",
    ("ntoskrnl","FsRtlRegisterFileSystemFilterCallbacks"):"filesystem",
    ("ntoskrnl","IoRegisterBootDriverCallback"):"boot",("ntoskrnl","SeRegisterImageVerificationCallback"):"image_verification",
}
KCR_STATEMENT=("A filter over a byte-pattern first pass: a registration is an import-table call the scan saw, not proof the code runs. "
               "Not seeing one means no direct call through the import table was seen, which is not the same as the driver not registering.")
_KCR_EXTRA_CAVEATS=("The callback address was not recovered: argument set-up is interleaved with other code, for one API the argument "
                    "points to a structure, the address may be a trampoline, and a lea target cannot be told apart as function or data.",
                    "The API name list is not exhaustive and its family labels are conceptual, not verified; an export proves a name "
                    "exists, not what it does.")

def _kcr_norm_dll(dll):
    """Lower-case and drop a trailing .sys / .exe / .dll, so FLTMGR.SYS and fltmgr.sys both become ``fltmgr``."""
    d=str(dll).strip().lower()
    for ext in (".sys",".exe",".dll"):
        if d.endswith(ext):return d[:-len(ext)]
    return d

def _kcr_lookup(imp):
    """(dll, api, family) for an exact "dll!name" import that is in the table, else None. Exact name, never a substring."""
    dll,sep,name=str(imp).partition("!")
    if not sep:return None
    fam=_KCR_APIS.get((_kcr_norm_dll(dll),name))
    return None if fam is None else (_kcr_norm_dll(dll),name,fam)

def kernel_callback_registrations(path):
    """Which callback-registration APIs a driver calls through its import table, as seen by rip_relative_iat_scan.

    Outcomes: FOUND (``registrations``, each ``proves_call`` false, ``confidence`` heuristic); NOT_FOUND (the scan ran in
    full and saw no direct call through the import table to a listed API; this does NOT say the driver does not register);
    UNKNOWN (the scan was truncated, reason SCAN_TRUNCATED, or the import directory was only partly readable, reason
    IMPORTS_PARTIAL: a looked-at part is not the whole); NOT_LOOKED (every scan refusal passes through unchanged).
    ``imported_without_reference`` lists listed APIs that are imported but have no call site found: not a finding.
    The callback address is never recovered (``callback_address`` is "NOT_RECOVERED")."""
    scan=json.loads(rip_relative_iat_scan(path,_RIA_HARD_LIMIT,import_filter=lambda imp:_kcr_lookup(imp) is not None))
    if not scan.get("ok"):
        scan["tool"]="kernel_callback_registrations"
        return json.dumps(scan,ensure_ascii=False,indent=2)
    regs=[];called=set()
    for f in scan["findings"]:
        hit=_kcr_lookup(f["import"])
        if hit is None:continue
        dll,api,fam=hit;called.add((dll,api))
        regs.append({"api":api,"dll":dll,"family":fam,"call_rva":f["call_rva"],"encoding":f["encoding"],"kind":f["kind"],
                     "slot_rva":f["slot_rva"],"proves_call":False,"confidence":"heuristic"})
    unref=[]
    try:
        pe=_pe(safe_path(path))
        names,_=_ria_slots(pe,int(pe.OPTIONAL_HEADER.ImageBase))
        seen=set()
        for imp in names.values():
            hit=_kcr_lookup(imp)
            if hit and (hit[0],hit[1]) not in called and (hit[0],hit[1]) not in seen:
                seen.add((hit[0],hit[1]));unref.append({"api":hit[1],"dll":hit[0],"family":hit[2]})
    except Exception:
        pass
    unref.sort(key=lambda u:(u["dll"],u["api"]))
    trunc=scan["truncation"];state=scan["entry"]["imports_state"]
    rationale=[];reason=scan.get("reason")
    if reason=="NO_REFERENCE_MATCHED_THE_FILTER":reason=None
    if regs:
        outcome="FOUND";reason=None
        rationale.append(f"{len(regs)} import-table reference(s) name a listed registration API; none is proof the code runs")
        if trunc["truncated"]:rationale.append(f"the scan was truncated ({trunc['omitted']+trunc.get('examine_omitted',0)} reference(s) omitted), so more may exist")
    elif trunc["truncated"]:
        outcome="UNKNOWN";reason="SCAN_TRUNCATED"
        rationale.append("the scan stopped at its limit, so part of the code was not examined; no listed API was seen in the part that was")
    elif state=="PARTIAL":
        outcome="UNKNOWN";reason="IMPORTS_PARTIAL"
        rationale.append("the import directory was only partly readable, so imports past the break could not be named")
    else:
        outcome="NOT_FOUND"
        rationale.append(f"no direct call through the import table to any of the {len(_KCR_APIS)} API names this tool knows "
                         "(listed in names_checked) was seen; this says nothing about names outside that list")
        rationale.append("indirect calls and run-time name resolution (MmGetSystemRoutineAddress and the like) are not visible to this scan")
    if unref:rationale.append(f"{len(unref)} listed API(s) are imported but no call site was found for them; not a finding")
    body={"ok":True,"tool":"kernel_callback_registrations","status":"OK","path":scan["path"],"outcome":outcome,
          "proves_call":False,"registrations":regs,"imported_without_reference":unref,"names_checked":{"count":len(_KCR_APIS),"names":sorted(f"{d}!{n}" for d,n in _KCR_APIS),"truncated":False},"callback_address":"NOT_RECOVERED",
          "scan_truncation":trunc,"entry":scan["entry"],"rationale":rationale,
          "caveats":list(scan["caveats"])+list(_KCR_EXTRA_CAVEATS),"statement":KCR_STATEMENT}
    if reason:body["reason"]=reason
    return json.dumps(body,ensure_ascii=False,indent=2)
