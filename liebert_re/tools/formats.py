"""Bounded, read-only format/container/data inspection tools."""
from __future__ import annotations
import configparser,csv,hashlib,io,json,mimetypes,re,sqlite3,struct,tarfile,zipfile,zlib
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath
from urllib.parse import urlsplit
from liebert_re.workspace import safe_path,relative,skipped,text_of

MAX_IDENTITY_HASH_BYTES=512_000_000; MAX_STRUCTURED_BYTES=64_000_000; MAX_ARCHIVE_MEMBERS=500
MAX_ARCHIVE_TOTAL=512_000_000; MAX_ARCHIVE_MEMBER=8_000_000; MAX_RETURN_CHARS=60_000
MAX_WASM_BYTES=64_000_000
# file_identity's PE branch only needs pefile.PE(fast_load=True) header parsing
# (DOS/NT headers, section table, and the CLR data-directory slot) -- never the
# full image -- so this bounds the prefix read used for that instead of loading
# an entire, possibly huge, executable for every PE file_identity scans across a
# customer's directory.
MAX_PE_IDENTITY_PREFIX_BYTES=16_000_000
MAX_CONFIG_SCHEMA_LINES=10_000; MAX_CONFIG_SCHEMA_KEYS=1_000; MAX_CONFIG_SCHEMA_SECTIONS=256

def _json(obj): return json.dumps(obj,ensure_ascii=False,indent=2,default=str)
def _sha256(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
def _elf(head):
    if head[:4]!=b'\x7fELF': return None
    cls={1:'32-bit',2:'64-bit'}.get(head[4],'unknown'); endian={1:'little',2:'big'}.get(head[5],'unknown'); order='<' if head[5]==1 else '>'
    machine=struct.unpack(order+'H',head[18:20])[0] if len(head)>=20 else 0; et=struct.unpack(order+'H',head[16:18])[0] if len(head)>=18 else 0
    return {'type':'ELF','subtype':{1:'relocatable',2:'executable',3:'shared_library',4:'core'}.get(et,'unknown'),'architecture':{3:'x86',62:'x86_64',40:'ARM',183:'ARM64',243:'RISC-V'}.get(machine,f'machine_{machine}'),'bits':cls,'endianness':endian,'runtime':'native'}
def _macho(head):
    if len(head)<4:return None
    raw=head[:4]; thin={b'\xfe\xed\xfa\xce':('big',32),b'\xce\xfa\xed\xfe':('little',32),b'\xfe\xed\xfa\xcf':('big',64),b'\xcf\xfa\xed\xfe':('little',64)}; fat={b'\xca\xfe\xba\xbe':'fat32',b'\xbe\xba\xfe\xca':'fat32-swapped',b'\xca\xfe\xba\xbf':'fat64',b'\xbf\xba\xfe\xca':'fat64-swapped'}
    if raw in fat:return {'type':'MACHO','subtype':fat[raw],'architecture':'universal','runtime':'native'}
    if raw not in thin:return None
    endian,bits=thin[raw]; order='<' if endian=='little' else '>'; cpu=struct.unpack(order+'I',head[4:8])[0]
    return {'type':'MACHO','subtype':'thin','architecture':{7:'x86',12:'ARM',0x01000007:'x86_64',0x0100000c:'ARM64'}.get(cpu,f'cpu_{cpu}'),'bits':bits,'endianness':endian,'runtime':'native'}
def file_identity(path):
    p=safe_path(path)
    try:
        st=p.stat()
        with p.open('rb') as f:head=f.read(65536)
    except OSError as exc:
        # A real, reproduced failure mode: a directory (or any other
        # unreadable path -- permission-denied, a broken symlink, etc.)
        # previously raised a raw, uncaught PermissionError/OSError out of
        # this function and every caller built on it (kernel_triage,
        # route_file, and anything else that calls file_identity directly),
        # surfacing a Python traceback instead of a structured tool error.
        # Every OSError subclass (PermissionError, IsADirectoryError,
        # FileNotFoundError, NotADirectoryError, ...) is handled uniformly
        # here since the caller's real question -- "can this path be
        # identified as a file?" -- has the same honest answer (no) for
        # all of them.
        return _json({'ok':False,'error':'FILE_NOT_ACCESSIBLE','error_type':type(exc).__name__,'path':str(path),'type':'UNKNOWN'})
    ext=p.suffix.lower(); info={'ok':True,'path':relative(p),'extension':ext,'size_bytes':st.st_size,'mtime':datetime.fromtimestamp(st.st_mtime,timezone.utc).isoformat(),'sha256':_sha256(p) if st.st_size<=MAX_IDENTITY_HASH_BYTES else None,'text':b'\x00' not in head and (not head or sum(b in (9,10,13) or 32<=b<127 for b in head)/len(head)>.80),'container':None,'type':'UNKNOWN','subtype':None,'architecture':None,'endianness':None,'runtime':None,'framework_indicators':[],'confidence':.35,'recommended_capabilities':[],'limitations':[]}
    if head[:2]==b'MZ':
        info.update(type='PE',runtime='native',confidence=.98)
        try:
            import pefile
            # Parse from an owned, bounded byte prefix -- not pefile.PE(str(p)) --
            # so pefile never memory-maps the file by path and cannot retain a
            # Windows file handle past this call's return. file_identity runs over
            # every file in a customer's directory, so the read is bounded to what
            # fast_load=True actually needs (headers/section table), not the whole
            # image; a malformed/truncated read is handled by the except below.
            with p.open('rb') as f: pe_bytes=f.read(MAX_PE_IDENTITY_PREFIX_BYTES)
            pe=pefile.PE(data=pe_bytes,fast_load=True); m=pe.FILE_HEADER.Machine; info['architecture']={0x14c:'x86',0x8664:'x86_64',0xaa64:'ARM64'}.get(m,hex(m)); info['subtype']='dll' if pe.FILE_HEADER.Characteristics&0x2000 else 'executable'; clr=len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress!=0; info['runtime']='dotnet' if clr else 'native'; info['recommended_capabilities']=['dotnet_inspect','decompile_dotnet'] if clr else ['native_inspect','ghidra_query']
        except Exception as e: info['limitations'].append(f'PE parse failed: {type(e).__name__}')
    elif (e:=_elf(head)): info.update(e,confidence=.99,recommended_capabilities=['native_inspect','ghidra_query'])
    elif (m:=_macho(head)): info.update(m,confidence=.99,recommended_capabilities=['native_inspect','ghidra_query'])
    elif head[:4]==b'\x00asm': info.update(type='WASM',runtime='webassembly',confidence=.99,recommended_capabilities=['wasm_inspect']); info['limitations'].append('Structural WASM inspection only; compiler-grade semantics are unavailable')
    elif head[:4] in {b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'}: info.update(type='PCAP',container='packet_capture',confidence=.99,recommended_capabilities=['pcap_analyzer'])
    elif head[:4]==b'\x0a\x0d\x0d\x0a': info.update(type='PCAPNG',container='packet_capture',confidence=.99,recommended_capabilities=['pcap_analyzer'])
    elif head[:4]==b'MDMP': info.update(type='MINIDUMP',container='crash_dump',confidence=.99,recommended_capabilities=['minidump_structural_analyze','minidump_analyzer'])
    elif head.startswith(b'Microsoft C/C++ MSF'): info.update(type='PDB',container='debug_symbols',confidence=.99,recommended_capabilities=['msf_pdb_inspect','pdb_symbols'])
    elif head.startswith(b'BSJB'): info.update(type='PORTABLE_PDB',container='debug_symbols',confidence=.99,recommended_capabilities=['tool_missing']); info['limitations'].append('Portable PDB (BSJB) is not native MSF; msf_pdb_inspect will reject it')
    elif head[:6]==b'7z\xbc\xaf\x27\x1c': info.update(type='7Z',container='archive',confidence=.99,recommended_capabilities=['rar_7z'])
    elif head[:7] in {b'Rar!\x1a\x07\x00',b'Rar!\x1a\x07\x01'}: info.update(type='RAR',container='archive',confidence=.99,recommended_capabilities=['rar_7z']); info['limitations'].append('Listing only; extracting member content needs an external unrar-compatible tool, not installed')
    elif head[:2]==b'\x1f\x8b': info.update(type='GZIP',container='compressed_stream',confidence=.99,recommended_capabilities=['rar_7z'])
    elif head[:6]==b'\xfd7zXZ\x00': info.update(type='XZ',container='compressed_stream',confidence=.99,recommended_capabilities=['rar_7z'])
    elif head[:3]==b'BZh': info.update(type='BZIP2',container='compressed_stream',confidence=.99,recommended_capabilities=['rar_7z'])
    elif head[:4]==b'\x28\xb5\x2f\xfd': info.update(type='ZSTD',container='compressed_stream',confidence=.99,recommended_capabilities=['rar_7z'])
    elif head[:8]==b'\x89PNG\r\n\x1a\n':
        info.update(type='PNG',container='image',confidence=.99,recommended_capabilities=['file_identity'])
        if len(head)>=26:
            color_type=head[25];color_type_name={0:'grayscale',2:'truecolor',3:'indexed',4:'grayscale_alpha',6:'truecolor_alpha'}.get(color_type,f'unknown_{color_type}')
            info['media_metadata']={'width':struct.unpack('>I',head[16:20])[0],'height':struct.unpack('>I',head[20:24])[0],'bit_depth':head[24],'color_type':color_type_name}
        else:info['media_metadata']={}
    elif head[:2]==b'\xff\xd8': info.update(type='JPEG',container='image',confidence=.99,recommended_capabilities=['file_identity'])
    elif head[:4]==b'DDS ': info.update(type='DDS',container='image',confidence=.99,recommended_capabilities=['file_identity']); info['media_metadata']={'height':struct.unpack('<I',head[12:16])[0],'width':struct.unpack('<I',head[16:20])[0]} if len(head)>=20 else {}
    elif head[:12]==b'RIFF'+head[4:8]+b'WAVE':
        info.update(type='WAV',container='audio',confidence=.99,recommended_capabilities=['file_identity'])
        if len(head)>=36 and head[12:16]==b'fmt ':
            audio_format=struct.unpack('<H',head[20:22])[0];audio_format_name={1:'PCM',3:'IEEE_FLOAT',6:'A_LAW',7:'MU_LAW',0xFFFE:'EXTENSIBLE'}.get(audio_format,f'unknown_{audio_format}')
            info['media_metadata']={'audio_format':audio_format_name,'channels':struct.unpack('<H',head[22:24])[0],'sample_rate':struct.unpack('<I',head[24:28])[0],'byte_rate':struct.unpack('<I',head[28:32])[0],'block_align':struct.unpack('<H',head[32:34])[0],'bits_per_sample':struct.unpack('<H',head[34:36])[0]}
            info['limitations'].append('WAV metadata assumes the fmt chunk is the first chunk after the RIFF/WAVE header, which is the common case but not spec-guaranteed')
        elif len(head)>=28:info['media_metadata']={'channels':struct.unpack('<H',head[22:24])[0],'sample_rate':struct.unpack('<I',head[24:28])[0]};info['limitations'].append('fmt chunk not found at the expected fixed offset; only channels/sample_rate read on a best-effort basis')
        else:info['media_metadata']={}
    elif head[:4]==b'OggS': info.update(type='OGG',container='audio',confidence=.99,recommended_capabilities=['file_identity'])
    elif head[:4]==b'GDPC': info.update(type='GODOT_PCK',container='game_package',confidence=.95,recommended_capabilities=['godot_asset_analyzer'])
    elif head[:8]==b'UnityFS\x00': info.update(type='UNITY_ASSET',container='game_package',confidence=.95,recommended_capabilities=['unity_asset_analyzer'])
    elif head[:16]==b'UnityWebData1.0\x00': info.update(type='UNITY_ASSET',container='game_package',confidence=.95,recommended_capabilities=['unity_asset_analyzer']); info['limitations'].append('Brotli-compressed UnityWebData containers (.data.br) are not detected by magic -- only already-decompressed content is')
    elif head[:8]==b'bplist00': info.update(type='PLIST',subtype='binary',confidence=.99,recommended_capabilities=['plist_inspect'])
    elif head[:4]==b'dex\n' and len(head)>=8: info.update(type='DEX',runtime='android',confidence=.99,recommended_capabilities=['dex_decompiler'])
    elif head[:4]==b'\x03\x00\x08\x00': info.update(type='AXML',runtime='android',confidence=.9,recommended_capabilities=['android_resource_analyzer']); info['limitations'].append('Binary AndroidManifest.xml (AXML); resources.arsc string/style resolution is not performed')
    elif head[:4]==b'\xca\xfe\xba\xbe': info.update(type='JAVA_CLASS',runtime='jvm',confidence=.99,recommended_capabilities=['java_class_inspect'])
    elif head[:16]==b'SQLite format 3\x00': info.update(type='SQLITE',container='database',runtime='sqlite',confidence=.99,recommended_capabilities=['sqlite_inspect'])
    elif head[:4] in (b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08'):
        typ={'.apk':'APK','.aab':'AAB','.apks':'APKS','.jar':'JAR','.war':'WAR','.ear':'EAR','.ipa':'IPA','.whl':'PYTHON_WHEEL','.nupkg':'NUGET','.msix':'MSIX','.appx':'APPX'}.get(ext,'ZIP'); info.update(type=typ,container='zip',confidence=.98,recommended_capabilities=['archive_inspect'])
    elif tarfile.is_tarfile(p): info.update(type='TAR',container='tar',confidence=.95,recommended_capabilities=['archive_inspect'])
    else:
        try:
            from liebert_re.tools.asar_parser import detect_asar
            asar = detect_asar(head)
        except Exception:
            asar = {"ok": False}
        if asar.get("ok"):
            info.update(type='ASAR',container='electron_package',confidence=.95,recommended_capabilities=['asar_inspect','asar_parser'])
    if info['type']=='UNKNOWN' and info['text'] and (b'<!DOCTYPE plist' in head[:400] or b'<plist ' in head[:200] or head[:7]==b'<plist>'):
        info.update(type='PLIST',subtype='xml',confidence=.9,recommended_capabilities=['plist_inspect'])
    elif info['type']=='UNKNOWN' and info['text']:
        typ={'.py':'PYTHON','.pyc':'PYTHON_BYTECODE','.js':'JAVASCRIPT','.mjs':'JAVASCRIPT','.cjs':'JAVASCRIPT','.ts':'TYPESCRIPT','.tsx':'TYPESCRIPT','.jsx':'JAVASCRIPT','.cs':'CSHARP','.java':'JAVA','.c':'C','.h':'C_HEADER','.cpp':'CPP','.hpp':'CPP_HEADER','.go':'GO','.rs':'RUST','.lua':'LUA','.ps1':'POWERSHELL','.psm1':'POWERSHELL','.sh':'SHELL','.rb':'RUBY','.php':'PHP','.json':'JSON','.jsonl':'JSONL','.har':'HAR','.xml':'XML','.yaml':'YAML','.yml':'YAML','.toml':'TOML','.ini':'INI','.cfg':'CONFIG','.csv':'CSV','.log':'LOG','.wat':'WAT','.proto':'PROTO','.graphql':'GRAPHQL'}.get(ext,'TEXT'); info.update(type=typ,runtime='text',confidence=.85 if typ!='TEXT' else .6,recommended_capabilities=['har_inspect'] if typ=='HAR' else ['structured_inspect'] if typ in {'JSON','JSONL','XML','YAML','TOML','INI','CONFIG','CSV'} else ['log_inspect'] if typ=='LOG' else ['source_inspect','search_text','read_file'])
    name=p.name.lower()
    if info['type']=='UNKNOWN' and ext=='.pak' and st.st_size>=44:
        # PAK's real magic lives in the last 44 bytes (the footer), not the
        # head buffer everything else above matches against -- a .pak file
        # this small session's own real fixture already showed is larger
        # than the head-read window is common, so this is a genuine,
        # deliberate tail read, not a guess based on extension alone.
        with p.open('rb') as f:
            f.seek(-44,2);footer=f.read(44)
        if footer[:4]==b'\xe1\x12\x6f\x5a':info.update(type='UNREAL_PAK',container='game_package',confidence=.98,recommended_capabilities=['unreal_asset_analyzer'])
        else:info.update(type='UNREAL_ARTIFACT',container='game_package',confidence=.55,recommended_capabilities=['tool_missing']);info['limitations'].append('.pak extension but footer magic did not match; extension indicator only')
    if info['type']=='UNKNOWN' and ext in {'.ucas','.utoc','.uasset','.umap','.uexp','.ubulk'}:info.update(type='UNREAL_ARTIFACT',container='game_package',confidence=.55,recommended_capabilities=['tool_missing']);info['limitations'].append('Extension indicator only; content signature/parser unavailable')
    if info['type']=='UNKNOWN' and ext in {'.pck','.gdc'}:info.update(type='GODOT_ARTIFACT',container='game_package',confidence=.55,recommended_capabilities=['tool_missing']);info['limitations'].append('Extension indicator only')
    if info['type']=='UNKNOWN' and ext=='.asar':info.update(type='ASAR',container='electron_package',confidence=.55,recommended_capabilities=['asar_inspect']);info['limitations'].append('Extension indicator only; content header was not a valid ASAR pickle')
    for needle,framework in (('libflutter.so','Flutter'),('libapp.so','Flutter/Dart AOT candidate'),('gameassembly.dll','Unity IL2CPP'),('global-metadata.dat','Unity IL2CPP'),('assembly-csharp.dll','Unity Mono'),('unityplayer.dll','Unity'),('resources.pak','Electron/Chromium')):
        if name==needle: info['framework_indicators'].append(framework)
    source_types={'PYTHON','JAVASCRIPT','TYPESCRIPT','CSHARP','JAVA','C','C_HEADER','CPP','CPP_HEADER','GO','RUST','LUA','POWERSHELL','SHELL','RUBY','PHP','WAT','PROTO','GRAPHQL'}
    structured={'JSON','JSONL','XML','YAML','TOML','INI','CONFIG','CSV'}
    archives={'ZIP','TAR','APK','AAB','APKS','JAR','WAR','EAR','IPA','PYTHON_WHEEL','NUGET','MSIX','APPX','7Z','RAR','GZIP','XZ','BZIP2','ZSTD'}
    category=('SOURCE' if info['type'] in source_types else 'CONFIG' if info['type'] in {'INI','CONFIG','YAML','TOML'} else 'LOG' if info['type']=='LOG' else 'DATA' if info['type'] in structured else 'DATABASE' if info['type']=='SQLITE' else 'ARCHIVE' if info['type'] in archives else 'DOTNET' if info['type']=='PE' and info.get('runtime')=='dotnet' else 'PE' if info['type']=='PE' else 'ELF' if info['type']=='ELF' else 'MACHO' if info['type']=='MACHO' else 'DEX' if info['type']=='DEX' else 'AXML' if info['type']=='AXML' else 'WASM' if info['type']=='WASM' else 'PCAP' if info['type'] in {'PCAP','PCAPNG'} else 'MINIDUMP' if info['type']=='MINIDUMP' else 'PDB' if info['type']=='PDB' else 'MEDIA' if info.get('container') in {'image','audio'} else 'TEXT' if info['type']=='TEXT' else 'UNKNOWN_BINARY')
    if info['type'] in {'APK','AAB','APKS'}:category='APK'
    elif info['type'] in {'JAR','JAVA_CLASS'}:category='CLASS' if info['type']=='JAVA_CLASS' else 'JAR'
    elif info['type']=='ASAR':category='ASAR'
    info['category']=category
    expected={
      'PE':{'.exe','.dll','.sys','.scr','.cpl'},'ELF':{'.so','.elf',''},'MACHO':{'.dylib','.bundle',''},'WASM':{'.wasm'},
      'DEX':{'.dex'},'JAVA_CLASS':{'.class'},'SQLITE':{'.sqlite','.sqlite3','.db','.db3'},'PCAP':{'.pcap','.cap'},
      'PCAPNG':{'.pcapng','.ntar'},'MINIDUMP':{'.dmp','.mdmp'},'PDB':{'.pdb'},'PORTABLE_PDB':{'.pdb'},'ASAR':{'.asar',''},'PNG':{'.png'},'JPEG':{'.jpg','.jpeg'},
    }.get(info['type'])
    info['extension_mismatch']=bool(expected is not None and ext not in expected)
    if info['extension_mismatch']:info['limitations'].append(f"Extension {ext or '[none]'} does not match detected {info['type']} signature")
    info['mime_hint']=mimetypes.guess_type(p.name)[0]
    return _json(info)

def _archive_members(p):
    if zipfile.is_zipfile(p):
        z=zipfile.ZipFile(p); items=[{'name':x.filename,'size':x.file_size,'compressed_size':x.compress_size,'is_dir':x.is_dir(),'is_symlink':((x.external_attr >> 16) & 0o170000)==0o120000,'encrypted':bool(x.flag_bits&1)} for x in z.infolist()]; return 'zip',z,items
    if tarfile.is_tarfile(p):
        t=tarfile.open(p,'r:*'); items=[{'name':x.name,'size':x.size,'compressed_size':None,'is_dir':x.isdir(),'is_symlink':x.issym() or x.islnk(),'encrypted':False} for x in t.getmembers()]; return 'tar',t,items
    raise ValueError('Supported archive required: ZIP family or TAR family')
def _unsafe_member(name):
    q=PurePosixPath(name.replace('\\','/')); return q.is_absolute() or '..' in q.parts
# Same magic-byte set tools_guest_fetch.py's _detect_executable uses for the
# identical decision on the guest-fetch seam -- duplicated on purpose (never
# imported from there): that module pulls in the Hyper-V guest layer, which
# this pure, offline static-inspection module must never depend on just to
# make the same "is this executable content" call on bytes it already has.
_EXECUTABLE_MAGICS=(
    (b'MZ','PE'),(b'\x7fELF','ELF'),
    (b'\xfe\xed\xfa\xce','MACHO'),(b'\xce\xfa\xed\xfe','MACHO'),
    (b'\xfe\xed\xfa\xcf','MACHO'),(b'\xcf\xfa\xed\xfe','MACHO'),
    (b'\xca\xfe\xba\xbe','MACHO_FAT'),(b'\xbe\xba\xfe\xca','MACHO_FAT'),
    (b'\xca\xfe\xba\xbf','MACHO_FAT'),(b'\xbf\xba\xfe\xca','MACHO_FAT'),
)
def _looks_executable(data):
    head=data[:64]
    if head[:2]==b'#!':return 'SHEBANG_SCRIPT'
    for magic,label in _EXECUTABLE_MAGICS:
        if head[:len(magic)]==magic:return label
    return None

_MEMBER_READ_ERRORS=(RuntimeError,NotImplementedError,zipfile.BadZipFile,zlib.error,EOFError,tarfile.TarError,OSError)

def archive_inspect(path,operation='summary',query='',member='',max_results=200,max_chars=30000,dest_path='',password='',allow_executable_content=False):
    p=safe_path(path); max_results=max(1,min(int(max_results),MAX_ARCHIVE_MEMBERS)); max_chars=max(1000,min(int(max_chars),MAX_RETURN_CHARS))
    def _member_read_failure(base,member,exc,encrypted,has_pwd):
        """Map every exception zipfile/tarfile can raise while READING one member
        to a structured result (the wrapper contract: never raise, always JSON).
        ZipCrypto's password check is a single byte, so a wrong password passes it
        1 time in 256 and then fails later as a CRC error or a zlib error on
        garbage. For an ENCRYPTED member those failures cannot be told apart from
        genuinely corrupt data, so the status says so instead of claiming either."""
        detail=str(exc)
        if isinstance(exc,RuntimeError):
            return _json({**base,'ok':False,'error':'BAD_PASSWORD' if has_pwd else 'PASSWORD_REQUIRED','member':member,'detail':detail})
        if isinstance(exc,NotImplementedError):
            return _json({**base,'ok':False,'error':'ENCRYPTION_UNSUPPORTED','member':member,'detail':detail})
        if encrypted:
            return _json({**base,'ok':False,'error':'BAD_PASSWORD_OR_CORRUPT_DATA','member':member,'detail':detail})
        return _json({**base,'ok':False,'error':'CORRUPT_MEMBER','member':member,'detail':detail})
    try:kind,obj,items=_archive_members(p)
    except ValueError as exc:return _json({'ok':False,'tool':'archive_inspect','path':relative(p),'error':'UNSUPPORTED_ARCHIVE','detail':str(exc)})
    except (zipfile.BadZipFile,tarfile.TarError,EOFError,zlib.error,OSError) as exc:return _json({'ok':False,'tool':'archive_inspect','path':relative(p),'error':'ARCHIVE_UNREADABLE','error_type':type(exc).__name__,'detail':str(exc)})
    try:
        total=sum(max(0,x['size']) for x in items); warnings=[]
        if len(items)>MAX_ARCHIVE_MEMBERS:warnings.append('MEMBER_LIMIT_EXCEEDED')
        if total>MAX_ARCHIVE_TOTAL:warnings.append('DECOMPRESSED_SIZE_LIMIT_EXCEEDED')
        if any(_unsafe_member(x['name']) for x in items):warnings.append('PATH_TRAVERSAL_MEMBER')
        if any(x.get('is_symlink') for x in items):warnings.append('SYMLINK_MEMBER')
        if any(x['compressed_size'] and x['size']/max(1,x['compressed_size'])>200 for x in items):warnings.append('HIGH_COMPRESSION_RATIO')
        manifests=[x['name'] for x in items if Path(x['name']).name.lower() in {'androidmanifest.xml','manifest.mf','package.json','info.plist','appxmanifest.xml','metadata.json'}]
        nested=[x['name'] for x in items if Path(x['name']).suffix.lower() in {'.zip','.jar','.apk','.ipa','.whl','.nupkg','.tar','.gz','.7z','.rar'}]
        base={'ok':True,'tool':'archive_inspect','path':relative(p),'kind':kind,'member_count':len(items),'total_uncompressed_bytes':total,'manifest_candidates':manifests[:100],'nested_candidates':nested[:100],'warnings':warnings,'limits':{'max_members':MAX_ARCHIVE_MEMBERS,'max_total_bytes':MAX_ARCHIVE_TOTAL,'max_member_bytes':MAX_ARCHIVE_MEMBER},'truncated':len(items)>max_results}
        selected=items
        if query:selected=[x for x in items if query.lower() in x['name'].lower()]
        if operation in {'summary','list','find'}: base['members']=selected[:max_results]; return _json(base)
        if operation=='nested':
            found=[]
            for x in items:
                if len(found)>=20:break
                if Path(x['name']).suffix.lower() not in {'.zip','.jar','.apk','.ipa','.whl','.nupkg'} or x['size']>MAX_ARCHIVE_MEMBER:continue
                try:
                    raw=obj.read(x['name']) if kind=='zip' else obj.extractfile(next(y for y in obj.getmembers() if y.name==x['name'])).read()
                    with zipfile.ZipFile(io.BytesIO(raw)) as nz:
                        ni=nz.infolist();found.append({'member':x['name'],'kind':'zip','member_count':len(ni),'total_uncompressed_bytes':sum(y.file_size for y in ni),'manifest_candidates':[y.filename for y in ni if Path(y.filename).name.lower() in {'androidmanifest.xml','manifest.mf','package.json','info.plist'}][:30]})
                except Exception as e:found.append({'member':x['name'],'error':type(e).__name__})
            base.update(nested=found,nesting_depth=1,truncated=len(nested)>20);return _json(base)
        if operation=='read':
            hit=next((x for x in items if x['name']==member),None)
            if not hit:return _json({**base,'ok':False,'error':'MEMBER_NOT_FOUND'})
            if _unsafe_member(hit['name']):return _json({**base,'ok':False,'status':'ANALYSIS_LIMITED','error':'PATH_TRAVERSAL_BLOCKED','member':member})
            if hit.get('is_symlink'):return _json({**base,'ok':False,'status':'ANALYSIS_LIMITED','error':'SYMLINK_MEMBER_BLOCKED','member':member})
            if hit['size']>MAX_ARCHIVE_MEMBER:return _json({**base,'ok':False,'error':'MEMBER_TOO_LARGE','member':member})
            try:
                if kind=='zip':raw=obj.read(member)
                else:
                    fileobj=obj.extractfile(next(x for x in obj.getmembers() if x.name==member))
                    if fileobj is None:return _json({**base,'ok':False,'error':'MEMBER_NOT_A_REGULAR_FILE','member':member})
                    raw=fileobj.read()
            except _MEMBER_READ_ERRORS as exc:
                return _member_read_failure(base,member,exc,bool(hit.get('encrypted')),False)
            if b'\x00' in raw[:4096]:return _json({**base,'ok':False,'error':'BINARY_MEMBER','member':member,'size':len(raw)})
            try:text=raw.decode('utf-8')
            except UnicodeDecodeError as e:return _json({**base,'ok':False,'error':'BINARY_MEMBER','member':member,'size':len(raw),'first_invalid_utf8_offset':e.start})
            base.update(member=member,content=text[:max_chars],truncated=len(text)>max_chars); return _json(base)
        if operation=='extract':
            # First-class extraction (GAP: 'read' above refuses BINARY_MEMBER
            # outright, so a sample inside an archive could be listed but
            # never handed to any other tool). Built directly on the
            # underlying library's own extraction support -- zipfile.
            # ZipFile.read(name, pwd=...) and tarfile.TarFile.extractfile()
            # already do real decompression (optionally password-gated for
            # ZIP's traditional PKWARE encryption; tarfile has no encryption
            # concept at all, stdlib or otherwise); nothing here reimplements
            # decompression, this only adds the path-safety/size/hash
            # contract the raw library calls do not enforce on their own.
            #
            # HOST-SIDE ONLY, DELIBERATELY -- dest_path always resolves
            # through tools_workspace.safe_path, which only ever accepts a
            # HOST path under WORKSPACE; there is no guest-side extraction
            # mode here. For an archive that lives ONLY inside the isolated
            # guest (the operator's own AV-quarantine rule), this operation
            # cannot be used at all -- not just "not recommended", it never
            # even reaches the guest. Two real alternatives, deliberately
            # chosen over adding a guest-side extractor here: (1) for
            # inventory/text-member reading without ever writing anything to
            # host disk, use tools_guest_fetch.guest_analyze_static(guest_
            # path=..., analyzer='archive_inspect', operation='summary'|
            # 'list'|'find'|'nested'|'read') -- same zipfile/tarfile parse,
            # fed guest bytes via a throwaway non-executable quarantine file
            # instead of a host path the caller names; (2) if a member must
            # genuinely land on host disk (e.g. to hand a DLL to a
            # host-side decompiler), fetch the WHOLE archive out first via
            # tools_guest_fetch.guest_fetch_file, then call this operation
            # normally. A guest-side extractor was considered and rejected
            # here: ZIP could use System.IO.Compression.ZipFile from
            # PowerShell, but TAR/7z/RAR have no equivalent built into the
            # guest, so a "guest-side extract" mode would silently work for
            # one format and not the others -- worse than not offering it.
            if not member:return _json({**base,'ok':False,'error':'MEMBER_REQUIRED'})
            if not dest_path:return _json({**base,'ok':False,'error':'DEST_PATH_REQUIRED'})
            hit=next((x for x in items if x['name']==member),None)
            if not hit:return _json({**base,'ok':False,'error':'MEMBER_NOT_FOUND','member':member})
            # Zip-slip guard: refuses any member whose name is absolute or
            # contains a '..' path segment (after normalizing '\\' to '/'),
            # BEFORE the member is ever read or written anywhere -- see
            # _unsafe_member and tests/test_tools_archive_extract.py's
            # crafted-member-name regression test.
            if _unsafe_member(hit['name']):return _json({**base,'ok':False,'status':'ANALYSIS_LIMITED','error':'PATH_TRAVERSAL_BLOCKED','member':member})
            if hit.get('is_symlink'):return _json({**base,'ok':False,'status':'ANALYSIS_LIMITED','error':'SYMLINK_MEMBER_BLOCKED','member':member})
            if hit['size']>MAX_ARCHIVE_MEMBER:return _json({**base,'ok':False,'error':'MEMBER_TOO_LARGE','member':member,'size_bytes':hit['size'],'max_bytes':MAX_ARCHIVE_MEMBER})
            try:
                dest=safe_path(dest_path)
            except PermissionError as exc:
                return _json({**base,'ok':False,'status':'PATH_REFUSED','error':str(exc)})
            try:
                if kind=='zip':
                    pwd=password.encode('utf-8') if password else None
                    if hit.get('encrypted') and not pwd:
                        return _json({**base,'ok':False,'error':'PASSWORD_REQUIRED','member':member})
                    try:
                        raw=obj.read(member,pwd=pwd) if pwd else obj.read(member)
                    except _MEMBER_READ_ERRORS as exc:
                        return _member_read_failure(base,member,exc,bool(hit.get('encrypted')),bool(pwd))
                else:
                    if password:return _json({**base,'ok':False,'error':'PASSWORD_NOT_SUPPORTED_FOR_TAR','member':member})
                    member_info=next(x for x in obj.getmembers() if x.name==member)
                    fileobj=obj.extractfile(member_info)
                    if fileobj is None:return _json({**base,'ok':False,'error':'MEMBER_NOT_A_REGULAR_FILE','member':member})
                    try:raw=fileobj.read()
                    except _MEMBER_READ_ERRORS as exc:
                        return _member_read_failure(base,member,exc,False,False)
            except KeyError as exc:
                return _json({**base,'ok':False,'error':'MEMBER_NOT_FOUND','member':member,'detail':str(exc)})
            executable_kind=_looks_executable(raw)
            if executable_kind and not allow_executable_content:
                return _json({**base,'ok':False,'status':'EXECUTABLE_CONTENT_REFUSED','member':member,
                    'executable_content_kind':executable_kind,
                    'error':(f'extracted member sniffs as executable ({executable_kind}) -- refusing to '
                             'write it to the host by default, same decision guest_fetch_file makes for '
                             'the guest-to-host seam. Pass allow_executable_content=True if this extraction '
                             'is deliberate.'),
                    'remediation':'Re-call with allow_executable_content=True if this extraction is deliberate.'})
            digest=hashlib.sha256(raw).hexdigest()
            try:
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(raw)
            except OSError as exc:
                return _json({**base,'ok':False,'status':'WRITE_FAILED','error':str(exc),'member':member})
            base.update(member=member,dest_path=relative(dest),size_bytes=len(raw),sha256=digest,
                        executable_content_detected=bool(executable_kind),executable_content_kind=executable_kind)
            return _json(base)
        return _json({**base,'ok':False,'error':'UNKNOWN_OPERATION'})
    finally: obj.close()

def _shape(value,depth=0):
    if depth>=4:return type(value).__name__
    if isinstance(value,dict):return {'type':'object','keys':len(value),'sample':{str(k):_shape(v,depth+1) for k,v in list(value.items())[:30]}}
    if isinstance(value,list):return {'type':'array','length':len(value),'sample':[_shape(x,depth+1) for x in value[:5]]}
    return {'type':type(value).__name__,'preview':str(value)[:120]}
def _config_schema(p,max_results=100):
    """Return bounded INI/CFG structure without returning configuration values."""
    if p.stat().st_size>MAX_STRUCTURED_BYTES:raise ValueError('STRUCTURED_FILE_TOO_LARGE')
    max_keys=max(1,min(int(max_results),MAX_CONFIG_SCHEMA_KEYS)); text=text_of(p); lines=text.splitlines()
    section_order=[]; section_keys={}; section_entry_counts=Counter(); seen_sections=Counter(); seen_keys=Counter()
    current='<root>'; parsed_entries=duplicates=duplicate_sections=malformed=comments=blanks=0
    returned_keys=0

    def ensure_section(name):
        if name not in section_keys:
            section_order.append(name);section_keys[name]=[]

    ensure_section(current)
    for raw in lines[:MAX_CONFIG_SCHEMA_LINES]:
        stripped=raw.strip()
        if not stripped:blanks+=1;continue
        if stripped.startswith(('#',';')):comments+=1;continue
        if stripped.startswith('['):
            match=re.fullmatch(r'\[([^\]\r\n]+)\]\s*(?:[;#].*)?',stripped)
            if not match:malformed+=1;continue
            current=match.group(1).strip()
            if not current:malformed+=1;current='<root>';continue
            normalized=current.casefold();duplicate_sections+=int(seen_sections[normalized]>0);seen_sections[normalized]+=1
            ensure_section(current);continue
        key=''
        delimiter=re.match(r'^([^=:#]+?)\s*[=:]\s*(.*)$',stripped)
        if delimiter:
            key=delimiter.group(1).strip()
        else:
            fields=stripped.split(None,1)
            if len(fields)==2:key=fields[0].strip()
        if not key:malformed+=1;continue
        ensure_section(current);parsed_entries+=1;section_entry_counts[current]+=1
        identity=(current.casefold(),key.casefold());duplicates+=int(seen_keys[identity]>0);seen_keys[identity]+=1
        if key not in section_keys[current] and returned_keys<max_keys:
            section_keys[current].append(key);returned_keys+=1

    visible_sections=[]
    for name in section_order[:MAX_CONFIG_SCHEMA_SECTIONS]:
        if name=='<root>' and not section_entry_counts[name]:continue
        visible_sections.append({
            'name':name,'key_names':section_keys[name],
            'entry_count':section_entry_counts[name],
            'unique_key_count':sum(1 for section,key in seen_keys if section==name.casefold()),
        })
    unique_key_count=len(seen_keys);section_count=sum(1 for name in section_order if name!='<root>' or section_entry_counts[name])
    return {
        'ok':True,'tool':'structured_inspect','path':relative(p),'operation':'schema','format':p.suffix.lower(),
        'sections':visible_sections,'section_count':section_count,'unique_key_count':unique_key_count,
        'parsed_entry_count':parsed_entries,'duplicate_key_count':duplicates,'duplicate_section_count':duplicate_sections,
        'malformed_line_count':malformed,'comment_line_count':comments,'blank_line_count':blanks,
        'line_count':len(lines),'lines_scanned':min(len(lines),MAX_CONFIG_SCHEMA_LINES),
        'values_redacted':True,'value_fields_returned':0,
        'limits':{'max_file_bytes':MAX_STRUCTURED_BYTES,'max_lines_scanned':MAX_CONFIG_SCHEMA_LINES,
                  'max_key_names_returned':max_keys,'max_sections_returned':MAX_CONFIG_SCHEMA_SECTIONS},
        'truncated':len(lines)>MAX_CONFIG_SCHEMA_LINES or unique_key_count>returned_keys or section_count>len(visible_sections),
    }
def _load_structured(p):
    if p.stat().st_size>MAX_STRUCTURED_BYTES:raise ValueError('STRUCTURED_FILE_TOO_LARGE')
    ext=p.suffix.lower(); text=text_of(p)
    if ext=='.json':return json.loads(text)
    if ext=='.jsonl':return [json.loads(x) for x in text.splitlines()[:5000] if x.strip()]
    if ext in {'.yaml','.yml'}:
        import yaml; return yaml.safe_load(text)
    if ext=='.toml':
        try:import tomllib as _t
        except ImportError:import tomli as _t
        return _t.loads(text)
    if ext in {'.ini','.cfg'}:
        c=configparser.ConfigParser(); c.read_string(text); return {s:dict(c[s]) for s in c.sections()}
    if ext=='.csv':
        return list(csv.DictReader(io.StringIO(text)))[:5000]
    if ext=='.xml':
        root=ET.fromstring(text); return {'root':root.tag,'attributes':root.attrib,'element_counts':dict(Counter(x.tag for x in root.iter()))}
    raise ValueError('UNSUPPORTED_STRUCTURED_FORMAT')
def structured_inspect(path,operation='summary',query='',max_results=100):
    p=safe_path(path)
    if operation=='schema':
        if p.suffix.lower() not in {'.ini','.cfg'}:
            return _json({'ok':False,'tool':'structured_inspect','path':relative(p),'operation':'schema','error':'CONFIG_SCHEMA_REQUIRES_INI_OR_CFG'})
        try:return _json(_config_schema(p,max_results))
        except Exception as e:return _json({'ok':False,'tool':'structured_inspect','path':relative(p),'operation':'schema','error':str(e)})
    try:data=_load_structured(p)
    except Exception as e:return _json({'ok':False,'tool':'structured_inspect','path':relative(p),'error':str(e)})
    out={'ok':True,'tool':'structured_inspect','path':relative(p),'format':p.suffix.lower(),'shape':_shape(data),'truncated':False}
    if out['format']=='.toml':
        try:import tomllib as _t;out['toml_parser']=_t.__name__
        except ImportError:out['toml_parser']='tomli (fallback: tomllib unavailable)'
    if operation=='search':
        hits=[]
        def walk(v,loc='$'):
            if len(hits)>=max_results:return
            if isinstance(v,dict):
                for k,x in v.items():
                    if query.lower() in str(k).lower():hits.append({'location':loc+'.'+str(k),'preview':str(x)[:300]})
                    walk(x,loc+'.'+str(k))
            elif isinstance(v,list):
                for i,x in enumerate(v):walk(x,f'{loc}[{i}]')
            elif query.lower() in str(v).lower():hits.append({'location':loc,'preview':str(v)[:300]})
        walk(data); out['hits']=hits; out['truncated']=len(hits)>=max_results
    return _json(out)

MAX_HAR_STREAM_ENTRIES=2_000_000

def _har_entry_item(i,e):
    req=e.get('request',{}); resp=e.get('response',{}); u=urlsplit(req.get('url','')); return {'index':i,'started':e.get('startedDateTime'),'method':req.get('method'),'url':req.get('url'),'host':u.hostname,'status':resp.get('status'),'content_type':next((h.get('value') for h in resp.get('headers',[]) if h.get('name','').lower()=='content-type'),None),'time_ms':e.get('time'),'redirect_url':resp.get('redirectURL') or None,'request_header_names':[h.get('name') for h in req.get('headers',[])][:50],'cookie_names':[c.get('name') for c in req.get('cookies',[])][:50],'websocket_messages':len(e.get('_webSocketMessages',[]))}

def _har_stream(p,operation,query,index,max_results):
    # Bounded-memory pass for HAR files over MAX_STRUCTURED_BYTES via ijson
    # (BSD-3-Clause, real streaming JSON parser -- discovered as a real,
    # zero-build-tool-required pip dependency): entries are consumed one at
    # a time, never materialized as a single in-memory list, so entry_count
    # and the aggregate distributions stay accurate for files far larger
    # than would fit as one json.loads() call.
    import ijson
    hosts=Counter();statuses=Counter();methods=Counter();total_time=0.0;n=0;collected=[];detail_hit=None;truncated_scan=False
    want_query=(query or '').lower()
    try:
        with p.open('rb') as f:
            for e in ijson.items(f,'log.entries.item'):
                item=_har_entry_item(n,e)
                if item['host']:hosts[item['host']]+=1
                statuses[str(item['status'])]+=1;methods[item['method']]+=1;total_time+=float(item['time_ms'] or 0)
                if operation in {'requests','timeline'} and len(collected)<max_results:collected.append(item)
                elif operation=='search' and len(collected)<max_results and want_query in json.dumps(item,ensure_ascii=False).lower():collected.append(item)
                elif operation=='detail' and n==int(index):detail_hit=item
                n+=1
                if n>=MAX_HAR_STREAM_ENTRIES:truncated_scan=True;break
        with p.open('rb') as f:
            page_count=sum(1 for _ in ijson.items(f,'log.pages.item'))
    except Exception as e:return _json({'ok':False,'error':f'MALFORMED_HAR: {type(e).__name__}: {e}'})
    base={'ok':True,'tool':'har_inspect','path':relative(p),'entry_count':n,'page_count':page_count,'hosts':dict(hosts.most_common(100)),'status_distribution':dict(statuses),'method_distribution':dict(methods),'total_time_ms':round(total_time,2),'streaming':True,'scan_limited':truncated_scan}
    if operation=='hosts':return _json({**base,'hosts':dict(hosts.most_common(max_results))})
    if operation in {'requests','timeline'}:return _json({**base,'requests':collected,'truncated':n>len(collected) and len(collected)>=max_results})
    if operation=='search':return _json({**base,'hits':collected,'truncated':len(collected)>=max_results})
    if operation=='detail':return _json({**base,'request':detail_hit})
    return _json(base)

def har_inspect(path,operation='summary',query='',index=0,max_results=100):
    p=safe_path(path)
    if p.stat().st_size>MAX_STRUCTURED_BYTES:
        # Availability probe, not a use: _har_stream imports ijson itself. The
        # point is to fail with a named, actionable status instead of an
        # ImportError traceback from three frames deeper.
        try:import ijson  # noqa: F401
        except ImportError:return _json({'ok':False,'status':'ANALYSIS_LIMITED','error':'HAR_TOO_LARGE','limitations':['ijson (streaming JSON parser) is not installed; falling back to the bounded whole-file limit']})
        return _har_stream(p,operation,query,index,max(1,min(int(max_results),5000)))
    try:har=json.loads(text_of(p)); log=har.get('log',{}); entries=log.get('entries',[])
    except Exception as e:return _json({'ok':False,'error':f'MALFORMED_HAR: {e}'})
    items=[_har_entry_item(i,e) for i,e in enumerate(entries)]; hosts=Counter(x['host'] for x in items if x['host']); statuses=Counter(str(x['status']) for x in items); methods=Counter(x['method'] for x in items)
    base={'ok':True,'tool':'har_inspect','path':relative(p),'entry_count':len(entries),'page_count':len(log.get('pages',[])),'hosts':dict(hosts.most_common(100)),'status_distribution':dict(statuses),'method_distribution':dict(methods),'total_time_ms':round(sum(float(x['time_ms'] or 0) for x in items),2)}
    if operation=='hosts':return _json({**base,'hosts':dict(hosts.most_common(max_results))})
    if operation in {'requests','timeline'}:return _json({**base,'requests':items[:max_results],'truncated':len(items)>max_results})
    if operation=='search':
        hits=[x for x in items if query.lower() in json.dumps(x,ensure_ascii=False).lower()]; return _json({**base,'hits':hits[:max_results],'truncated':len(hits)>max_results})
    if operation=='detail':return _json({**base,'request':items[int(index)] if 0<=int(index)<len(items) else None})
    return _json(base)

def log_inspect(path,operation='summary',query='',max_results=200):
    p=safe_path(path);patterns={'error':re.compile(r'(?i)\b(error|exception|fatal|failed|traceback)\b'),'warning':re.compile(r'(?i)\bwarn(?:ing)?\b'),'info':re.compile(r'(?i)\binfo\b')};counts={k:0 for k in patterns};tsrx=re.compile(r'\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+');first_ts=last_ts=None;hits=[];target=patterns['error'] if operation=='errors' else re.compile(re.escape(query),re.I) if operation=='search' else None;line_count=0;scan_limited=False
    with p.open('r',encoding='utf-8',errors='replace') as f:
        for i,x in enumerate(f,1):
            line_count=i
            for k,rx in patterns.items():counts[k]+=int(bool(rx.search(x)))
            m=tsrx.search(x)
            if m:
                row={'line':i,'timestamp':m.group(0),'preview':x[:300]};first_ts=first_ts or row;last_ts=row
            if target and target.search(x) and len(hits)<max_results:hits.append({'line':i,'text':x[:500]})
            if i>=2_000_000:scan_limited=True;break
    out={'ok':True,'tool':'log_inspect','path':relative(p),'line_count':line_count,'severity_counts':counts,'first_timestamp':first_ts,'last_timestamp':last_ts,'scan_limited':scan_limited}
    if operation in {'errors','search'}:out.update(hits=hits,truncated=len(hits)>=max_results or scan_limited)
    return _json(out)

def sqlite_inspect(path,operation='summary',table='',query='',max_rows=100):
    p=safe_path(path); uri=p.as_uri()+'?mode=ro&immutable=1'; max_rows=max(1,min(int(max_rows),500)); con=sqlite3.connect(uri,uri=True); con.row_factory=sqlite3.Row
    try:
        tables=[dict(x) for x in con.execute("SELECT name,type,sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall()]
        out={'ok':True,'tool':'sqlite_inspect','path':relative(p),'tables':tables[:200],'table_count':len(tables),'read_only':True}
        if operation=='schema' and table:
            if table not in {x['name'] for x in tables}:return _json({**out,'ok':False,'error':'TABLE_NOT_FOUND'})
            out['columns']=[dict(x) for x in con.execute(f'PRAGMA table_info("{table.replace(chr(34),chr(34)*2)}")')]
        elif operation=='query':
            q=query.strip()
            if not re.match(r'(?is)^select\b',q) or ';' in q:return _json({**out,'ok':False,'error':'READ_ONLY_SELECT_REQUIRED'})
            if not re.search(r'(?is)\blimit\s+\d+',q):q+=f' LIMIT {max_rows}'
            rows=[dict(x) for x in con.execute(q).fetchmany(max_rows)]; out.update(rows=rows,row_count=len(rows),truncated=len(rows)>=max_rows)
        return _json(out)
    except sqlite3.Error as e:return _json({'ok':False,'tool':'sqlite_inspect','path':relative(p),'error':str(e),'read_only':True})
    finally:con.close()

def framework_detect(path='.',max_files=12000):
    root=safe_path(path); files=[]
    for p in root.rglob('*'):
        if p.is_file() and not skipped(p):
            files.append(relative(p).replace('\\','/').lower())
            if len(files)>=max_files:break
    names={Path(x).name for x in files}; joined='\n'.join(files); results=[]
    def add(name,signals,required=2):
        hits=[s for s in signals if (s in names or s in joined)]
        if hits:results.append({'framework':name,'confidence':round(min(.99,.45+.18*len(hits)),2),'evidence':hits,'strength':'STRONG' if len(hits)>=required else 'SUPPORTED'})
    add('Flutter',['libflutter.so','libapp.so','flutter_assets'],3); add('Unity IL2CPP',['gameassembly.dll','global-metadata.dat','unityplayer.dll'],2); add('Unity Mono',['assembly-csharp.dll','unityplayer.dll','managed/'],2); add('Unreal Engine',['.pak','.ucas','.utoc','.uasset'],2); add('Godot',['project.godot','.pck','.tscn'],2); add('Electron',['package.json','app.asar','electron.asar','resources.pak'],2); add('React Native',['react-native','index.android.js','index.ios.js'],2); add('.NET MAUI/Xamarin',['maui','xamarin','mono.android'],2); add('Cordova/Capacitor',['cordova','capacitor.config','www/'],2)
    return _json({'ok':True,'tool':'framework_detect','path':relative(root),'scanned_files':len(files),'truncated':len(files)>=max_files,'frameworks':sorted(results,key=lambda x:x['confidence'],reverse=True)})

def _leb(data,pos):
    value=0;shift=0
    while pos<len(data):
        b=data[pos];pos+=1;value|=(b&0x7f)<<shift
        if not b&0x80:return value,pos
        shift+=7
        if shift>63:raise ValueError('LEB128_TOO_LARGE')
    raise ValueError('TRUNCATED_LEB128')
def _wstr(data,pos):
    n,pos=_leb(data,pos);end=pos+n
    if end>len(data):raise ValueError('TRUNCATED_STRING')
    return data[pos:end].decode('utf-8',errors='replace'),end
def _skip_limits(data,pos):
    flags,pos=_leb(data,pos);_,pos=_leb(data,pos)
    if flags&1:_,pos=_leb(data,pos)
    return pos
def _sleb(data,pos):
    value=0;shift=0
    while pos<len(data):
        b=data[pos];pos+=1;value|=(b&0x7f)<<shift;shift+=7
        if not b&0x80:
            if shift<64 and b&0x40:value|=-(1<<shift)
            return value,pos
        if shift>63:raise ValueError('LEB128_TOO_LARGE')
    raise ValueError('TRUNCATED_LEB128')

# WASM MVP opcode table: byte -> (mnemonic, operand kind). operand kind
# controls how many immediate bytes are consumed (correctness-critical: an
# unsupported opcode must never be silently mis-sized, or every instruction
# after it decodes garbage) and which operands get surfaced as evidence.
# 'none' = no immediate. 'leb'/'sleb' = one (un)signed LEB128 varint,
# surfaced as the instruction's operand. 'blocktype' = one signed LEB128
# (block/loop/if result type, usually -0x40 "empty"). 'memarg' = two LEB128
# (align, offset). 'br_table' = a vector of label indices plus a default.
# 'raw4'/'raw8' = fixed-width f32/f64 constant bytes, surfaced as an operand.
_WASM_OPS = {
    0x00:('unreachable','none'),0x01:('nop','none'),
    0x02:('block','blocktype'),0x03:('loop','blocktype'),0x04:('if','blocktype'),
    0x05:('else','none'),0x0B:('end','none'),
    0x0C:('br','leb'),0x0D:('br_if','leb'),0x0E:('br_table','br_table'),
    0x0F:('return','none'),0x10:('call','leb'),0x11:('call_indirect','call_indirect'),
    0x1A:('drop','none'),0x1B:('select','none'),0x1C:('select_t','select_t'),
    0x20:('local.get','leb'),0x21:('local.set','leb'),0x22:('local.tee','leb'),
    0x23:('global.get','leb'),0x24:('global.set','leb'),
    0x25:('table.get','leb'),0x26:('table.set','leb'),
    0x28:('i32.load','memarg'),0x29:('i64.load','memarg'),0x2A:('f32.load','memarg'),0x2B:('f64.load','memarg'),
    0x2C:('i32.load8_s','memarg'),0x2D:('i32.load8_u','memarg'),0x2E:('i32.load16_s','memarg'),0x2F:('i32.load16_u','memarg'),
    0x30:('i64.load8_s','memarg'),0x31:('i64.load8_u','memarg'),0x32:('i64.load16_s','memarg'),0x33:('i64.load16_u','memarg'),
    0x34:('i64.load32_s','memarg'),0x35:('i64.load32_u','memarg'),
    0x36:('i32.store','memarg'),0x37:('i64.store','memarg'),0x38:('f32.store','memarg'),0x39:('f64.store','memarg'),
    0x3A:('i32.store8','memarg'),0x3B:('i32.store16','memarg'),0x3C:('i64.store8','memarg'),0x3D:('i64.store16','memarg'),0x3E:('i64.store32','memarg'),
    0x3F:('memory.size','reserved'),0x40:('memory.grow','reserved'),
    0x41:('i32.const','sleb'),0x42:('i64.const','sleb'),0x43:('f32.const','raw4'),0x44:('f64.const','raw8'),
    0x45:('i32.eqz','none'),0x46:('i32.eq','none'),0x47:('i32.ne','none'),0x48:('i32.lt_s','none'),0x49:('i32.lt_u','none'),
    0x4A:('i32.gt_s','none'),0x4B:('i32.gt_u','none'),0x4C:('i32.le_s','none'),0x4D:('i32.le_u','none'),0x4E:('i32.ge_s','none'),0x4F:('i32.ge_u','none'),
    0x50:('i64.eqz','none'),0x51:('i64.eq','none'),0x52:('i64.ne','none'),0x53:('i64.lt_s','none'),0x54:('i64.lt_u','none'),
    0x55:('i64.gt_s','none'),0x56:('i64.gt_u','none'),0x57:('i64.le_s','none'),0x58:('i64.le_u','none'),0x59:('i64.ge_s','none'),0x5A:('i64.ge_u','none'),
    0x5B:('f32.eq','none'),0x5C:('f32.ne','none'),0x5D:('f32.lt','none'),0x5E:('f32.gt','none'),0x5F:('f32.le','none'),0x60:('f32.ge','none'),
    0x61:('f64.eq','none'),0x62:('f64.ne','none'),0x63:('f64.lt','none'),0x64:('f64.gt','none'),0x65:('f64.le','none'),0x66:('f64.ge','none'),
    0x67:('i32.clz','none'),0x68:('i32.ctz','none'),0x69:('i32.popcnt','none'),
    0x6A:('i32.add','none'),0x6B:('i32.sub','none'),0x6C:('i32.mul','none'),0x6D:('i32.div_s','none'),0x6E:('i32.div_u','none'),
    0x6F:('i32.rem_s','none'),0x70:('i32.rem_u','none'),0x71:('i32.and','none'),0x72:('i32.or','none'),0x73:('i32.xor','none'),
    0x74:('i32.shl','none'),0x75:('i32.shr_s','none'),0x76:('i32.shr_u','none'),0x77:('i32.rotl','none'),0x78:('i32.rotr','none'),
    0x79:('i64.clz','none'),0x7A:('i64.ctz','none'),0x7B:('i64.popcnt','none'),
    0x7C:('i64.add','none'),0x7D:('i64.sub','none'),0x7E:('i64.mul','none'),0x7F:('i64.div_s','none'),0x80:('i64.div_u','none'),
    0x81:('i64.rem_s','none'),0x82:('i64.rem_u','none'),0x83:('i64.and','none'),0x84:('i64.or','none'),0x85:('i64.xor','none'),
    0x86:('i64.shl','none'),0x87:('i64.shr_s','none'),0x88:('i64.shr_u','none'),0x89:('i64.rotl','none'),0x8A:('i64.rotr','none'),
    0x8B:('f32.abs','none'),0x8C:('f32.neg','none'),0x8D:('f32.ceil','none'),0x8E:('f32.floor','none'),0x8F:('f32.trunc','none'),
    0x90:('f32.nearest','none'),0x91:('f32.sqrt','none'),0x92:('f32.add','none'),0x93:('f32.sub','none'),0x94:('f32.mul','none'),
    0x95:('f32.div','none'),0x96:('f32.min','none'),0x97:('f32.max','none'),0x98:('f32.copysign','none'),
    0x99:('f64.abs','none'),0x9A:('f64.neg','none'),0x9B:('f64.ceil','none'),0x9C:('f64.floor','none'),0x9D:('f64.trunc','none'),
    0x9E:('f64.nearest','none'),0x9F:('f64.sqrt','none'),0xA0:('f64.add','none'),0xA1:('f64.sub','none'),0xA2:('f64.mul','none'),
    0xA3:('f64.div','none'),0xA4:('f64.min','none'),0xA5:('f64.max','none'),0xA6:('f64.copysign','none'),
    0xA7:('i32.wrap_i64','none'),0xA8:('i32.trunc_f32_s','none'),0xA9:('i32.trunc_f32_u','none'),0xAA:('i32.trunc_f64_s','none'),0xAB:('i32.trunc_f64_u','none'),
    0xAC:('i64.extend_i32_s','none'),0xAD:('i64.extend_i32_u','none'),0xAE:('i64.trunc_f32_s','none'),0xAF:('i64.trunc_f32_u','none'),
    0xB0:('i64.trunc_f64_s','none'),0xB1:('i64.trunc_f64_u','none'),
    0xB2:('f32.convert_i32_s','none'),0xB3:('f32.convert_i32_u','none'),0xB4:('f32.convert_i64_s','none'),0xB5:('f32.convert_i64_u','none'),
    0xB6:('f32.demote_f64','none'),
    0xB7:('f64.convert_i32_s','none'),0xB8:('f64.convert_i32_u','none'),0xB9:('f64.convert_i64_s','none'),0xBA:('f64.convert_i64_u','none'),
    0xBB:('f64.promote_f32','none'),
    0xBC:('i32.reinterpret_f32','none'),0xBD:('i64.reinterpret_f64','none'),0xBE:('f32.reinterpret_i32','none'),0xBF:('f64.reinterpret_i64','none'),
    0xC0:('i32.extend8_s','none'),0xC1:('i32.extend16_s','none'),0xC2:('i64.extend8_s','none'),0xC3:('i64.extend16_s','none'),0xC4:('i64.extend32_s','none'),
}
_WASM_FC_OPS={8:('memory.init','memory_init'),9:('data.drop','leb'),10:('memory.copy','memory_copy'),11:('memory.fill','reserved'),
    12:('table.init','table_init'),13:('elem.drop','leb'),14:('table.copy','table_init'),15:('table.grow','leb'),16:('table.size','leb'),17:('table.fill','leb'),
    0:('i32.trunc_sat_f32_s','none'),1:('i32.trunc_sat_f32_u','none'),2:('i32.trunc_sat_f64_s','none'),3:('i32.trunc_sat_f64_u','none'),
    4:('i64.trunc_sat_f32_s','none'),5:('i64.trunc_sat_f32_u','none'),6:('i64.trunc_sat_f64_s','none'),7:('i64.trunc_sat_f64_u','none')}

def _decode_instructions(data,pos,end,max_instructions):
    """Decode one function body's instruction stream into a bounded list.
    Never guesses: any opcode this table doesn't recognize stops decoding
    for this function with an honest UNSUPPORTED_OPCODE marker rather than
    risk desyncing (and silently corrupting) every instruction after it."""
    out=[];truncated=False
    while pos<end:
        if len(out)>=max_instructions:truncated=True;break
        op_offset=pos;op=data[pos];pos+=1;insn={'offset':hex(op_offset)}
        if op==0xFC:
            sub,pos=_leb(data,pos)
            spec=_WASM_FC_OPS.get(sub)
            if spec is None:insn.update(mnemonic=f'UNSUPPORTED_FC_0x{sub:02x}',error='UNSUPPORTED_OPCODE');out.append(insn);truncated=True;break
            mnemonic,kind=spec
        elif op==0xFD:
            insn.update(mnemonic='UNSUPPORTED_SIMD',error='UNSUPPORTED_OPCODE');out.append(insn);truncated=True;break
        else:
            spec=_WASM_OPS.get(op)
            if spec is None:insn.update(mnemonic=f'UNSUPPORTED_0x{op:02x}',error='UNSUPPORTED_OPCODE');out.append(insn);truncated=True;break
            mnemonic,kind=spec
        insn['mnemonic']=mnemonic
        if kind=='none' or kind=='reserved':
            if kind=='reserved':pos+=1
        elif kind=='leb':
            insn['operand'],pos=_leb(data,pos)
        elif kind=='sleb':
            insn['operand'],pos=_sleb(data,pos)
        elif kind=='blocktype':
            insn['operand'],pos=_sleb(data,pos)
        elif kind=='memarg':
            align,pos=_leb(data,pos);offset,pos=_leb(data,pos);insn['align']=align;insn['mem_offset']=offset
        elif kind=='raw4':
            insn['operand_bytes']=data[pos:pos+4].hex();pos+=4
        elif kind=='raw8':
            insn['operand_bytes']=data[pos:pos+8].hex();pos+=8
        elif kind=='call_indirect':
            typeidx,pos=_leb(data,pos);_,pos=_leb(data,pos);insn['operand']=typeidx
        elif kind=='select_t':
            n,pos=_leb(data,pos)
            for _ in range(n):_,pos=_leb(data,pos)
        elif kind=='br_table':
            n,pos=_leb(data,pos);labels=[]
            for _ in range(n):lbl,pos=_leb(data,pos);labels.append(lbl)
            default,pos=_leb(data,pos);insn['labels']=labels;insn['default']=default
        elif kind=='memory_init':
            segidx,pos=_leb(data,pos);_,pos=_leb(data,pos);insn['operand']=segidx
        elif kind=='memory_copy':
            _,pos=_leb(data,pos);_,pos=_leb(data,pos)
        elif kind=='table_init':
            a,pos=_leb(data,pos);b,pos=_leb(data,pos);insn['operand']=a;insn['operand2']=b
        out.append(insn)
    return out,pos,truncated

def wasm_inspect(path,operation='summary',max_items=300):
    p=safe_path(path)
    if p.stat().st_size>MAX_WASM_BYTES:return _json({'ok':False,'tool':'wasm_inspect','path':relative(p),'status':'ANALYSIS_LIMITED','error':'WASM_TOO_LARGE','limit_bytes':MAX_WASM_BYTES})
    data=p.read_bytes()
    if data[:4]!=b'\x00asm':return _json({'ok':False,'error':'NOT_WASM'})
    pos=8;sections=[];imports=[];exports=[];funcs=0;code_range=None
    names={0:'custom',1:'type',2:'import',3:'function',4:'table',5:'memory',6:'global',7:'export',8:'start',9:'element',10:'code',11:'data',12:'data_count'}
    try:
        while pos<len(data):
            sid=data[pos];pos+=1;size,pos=_leb(data,pos);start=pos;end=pos+size
            if end>len(data):raise ValueError('TRUNCATED_SECTION')
            row={'id':sid,'name':names.get(sid,'unknown'),'offset':hex(start),'size':size}
            if sid==0:
                custom,_=_wstr(data,start);row['custom_name']=custom
            elif sid==2:
                count,q=_leb(data,start)
                for _ in range(count):
                    mod,q=_wstr(data,q);name,q=_wstr(data,q);kind=data[q];q+=1
                    if kind==0:desc,q=_leb(data,q)
                    elif kind==1:q+=1;q=_skip_limits(data,q);desc=None
                    elif kind==2:q=_skip_limits(data,q);desc=None
                    elif kind==3:q+=2;desc=None
                    elif kind==4:q+=1;desc,q=_leb(data,q)
                    imports.append({'module':mod,'name':name,'kind':kind,'type_index':desc})
            elif sid==3:funcs,_=_leb(data,start)
            elif sid==7:
                count,q=_leb(data,start)
                for _ in range(count):
                    name,q=_wstr(data,q);kind=data[q];q+=1;idx,q=_leb(data,q);exports.append({'name':name,'kind':kind,'index':idx})
            elif sid==10:
                code_range=(start,end)
            sections.append(row);pos=end
    except Exception as e:return _json({'ok':False,'tool':'wasm_inspect','path':relative(p),'error':f'MALFORMED_WASM: {e}','sections':sections})
    if operation=='instructions':
        return _wasm_instructions(data,p,code_range,imports,max_items)
    return _json({'ok':True,'tool':'wasm_inspect','path':relative(p),'version':int.from_bytes(data[4:8],'little'),'sections':sections[:max_items],'imports':imports[:max_items],'exports':exports[:max_items],'declared_functions':funcs,'truncated':any(len(x)>max_items for x in (sections,imports,exports))})

def _wasm_instructions(data,p,code_range,imports,max_items):
    """Real instruction-level decode of the code section's function bodies --
    the depth beyond imports/exports/section-listing that wasm_inspect's
    default operation never provided (GAP-013). Bounded per function and
    across functions; an unsupported opcode stops that one function's decode
    honestly rather than guessing and desyncing every instruction after it."""
    if code_range is None:return _json({'ok':True,'tool':'wasm_inspect','operation':'instructions','path':relative(p),'functions':[],'note':'NO_CODE_SECTION'})
    start,end=code_range;imported_func_count=sum(1 for x in imports if x['kind']==0)
    try:
        count,pos=_leb(data,start);functions=[];max_functions=max(1,min(int(max_items),2000))
        for func_idx in range(count):
            if len(functions)>=max_functions:break
            if pos>=end:raise ValueError('CODE_SECTION_DESYNC: declared function count exceeds section bounds')
            body_size,pos=_leb(data,pos);body_end=pos+body_size
            if body_end>end:raise ValueError('CODE_SECTION_DESYNC: function body extends past section end')
            local_count,q=_leb(data,pos);locals_decl=[]
            for _ in range(local_count):n,q=_leb(data,q);t=data[q];q+=1;locals_decl.append({'count':n,'type':hex(t)})
            insns,q,truncated=_decode_instructions(data,q,body_end,2000)
            calls=sorted({i['operand'] for i in insns if i['mnemonic']=='call' and 'operand' in i})
            globals_touched=sorted({i['operand'] for i in insns if i['mnemonic'] in ('global.get','global.set') and 'operand' in i})
            memory_ops=sum(1 for i in insns if i['mnemonic'].split('.')[-1].startswith(('load','store')))
            functions.append({
                'function_index':imported_func_count+func_idx,'locals':locals_decl,
                'instruction_count':len(insns),'instructions_truncated':truncated,
                'calls':calls,'globals_touched':globals_touched,'memory_op_count':memory_ops,
                'instructions':insns,
            })
            pos=body_end
        return _json({'ok':True,'tool':'wasm_inspect','operation':'instructions','path':relative(p),'function_count':count,'functions':functions,'truncated':count>len(functions)})
    except Exception as e:
        return _json({'ok':False,'tool':'wasm_inspect','operation':'instructions','path':relative(p),'error':f'MALFORMED_CODE_SECTION: {e}'})

_MISSING={'dex_decompiler':['JADX','androguard'],'android_resources':['apktool','aapt2'],'pcap_analyzer':['tshark','Wireshark'],'minidump_analyzer':['WinDbg','cdb'],'pdb_symbols':['LLVM PDB tools','DIA SDK'],'wasm_analyzer':['WABT','wasmparser'],'unreal_assets':['FModel-compatible tooling'],'unity_assets':['AssetRipper','UnityPy'],'asar_parser':['ASAR tooling'],'rar_7z':['7-Zip','libarchive']}
def tool_missing(target,required_capability,reason='Required specialist analyzer is not registered'):
    key=required_capability.lower().replace(' ','_'); return _json({'ok':True,'status':'TOOL_MISSING','target':target,'required_capability':required_capability,'reason':reason,'known_candidates':_MISSING.get(key,[]),'installation_performed':False})
