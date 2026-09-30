"""Godot .pck (GAP-011) structural inspection: pure-Python header/directory
parse, no external tool. Format confirmed against Godot's own open-source
engine (core/io/file_access_pack.h/.cpp, MIT), verified against a real
MIT-licensed .pck pulled from godotengine/godot-demo-projects' own automated
export. Supports pack format versions 2/3/4 (the versions the real engine
source actually documents); GDScript bytecode inside script resources is not
decoded -- only container-level file listing/extraction."""
from __future__ import annotations
import struct
from tools_workspace import safe_path,relative,member_content
import json

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

_PACK_DIR_ENCRYPTED=1<<0
_PACK_REL_FILEBASE=1<<1
_PACK_SPARSE_BUNDLE=1<<2

def _header(data):
    if data[:4]!=b'GDPC':raise ValueError('NOT_GODOT_PCK')
    version,vmaj,vmin,vpat,flags=struct.unpack_from('<IIIII',data,4)
    # Closed allowlist on purpose: versions 0/1 (Godot 2.x/3.x) have a different,
    # flag-less header this parser does not implement, and versions above 4 have
    # not been seen. Guessing a layout would yield a confident wrong file table,
    # so every version outside 2/3/4 is refused by name. Everything below is
    # therefore only ever reached with version in {2,3,4}.
    if version not in (2,3,4):raise ValueError(f'UNSUPPORTED_PCK_VERSION_{version}')
    file_base,=struct.unpack_from('<Q',data,24)
    pos=32
    dir_offset,=struct.unpack_from('<Q',data,pos);pos+=8
    pos+=16*4
    if version>=4 and (flags&_PACK_SPARSE_BUNDLE) and (flags&_PACK_DIR_ENCRYPTED):
        raise ValueError('ENCRYPTED_SPARSE_DIRECTORY_NOT_SUPPORTED')
    if flags&_PACK_DIR_ENCRYPTED:raise ValueError('ENCRYPTED_DIRECTORY_NOT_SUPPORTED')
    return {'version':version,'engine_version':f'{vmaj}.{vmin}.{vpat}','flags':flags,
            'rel_filebase':bool(flags&_PACK_REL_FILEBASE),'sparse_bundle':bool(flags&_PACK_SPARSE_BUNDLE),
            'file_base':file_base,'dir_offset':dir_offset}

_MAX_ENTRIES_PARSED=200_000  # safety cap against a pathological file_count; not a display limit

def _entries(data,h):
    pos=h['dir_offset'];file_count,=struct.unpack_from('<I',data,pos);pos+=4
    out=[]
    for _ in range(min(file_count,_MAX_ENTRIES_PARSED)):
        path_len,=struct.unpack_from('<I',data,pos);pos+=4
        path=data[pos:pos+path_len].split(b'\x00',1)[0].decode('utf-8',errors='replace');pos+=path_len
        offset,size=struct.unpack_from('<QQ',data,pos);pos+=16
        md5=data[pos:pos+16].hex();pos+=16
        # Verified against a real version-3 fixture: the per-entry flags field
        # is present for every version this parser accepts (2/3/4), not only
        # v4 -- an earlier version-gated assumption here was wrong and was
        # caught by exactly this real-fixture check before being trusted.
        entry_flags,=struct.unpack_from('<I',data,pos);pos+=4
        out.append({'path':path,'offset':offset,'size':size,'md5':md5,'flags':entry_flags})
    return out,file_count

def godot_asset_analyzer(path,operation='summary',member='',max_results=300,max_chars=30000):
    p=safe_path(path);max_results=max(1,min(int(max_results),5000));max_chars=max(1000,min(int(max_chars),120000))
    data=p.read_bytes()
    try:h=_header(data)
    except Exception as e:
        # Named refusals surface directly; only genuine non-PCK/parse failures get the generic wrapper.
        if str(e).startswith(('ENCRYPTED_','UNSUPPORTED_PCK_VERSION_')):
            return _j({'ok':False,'tool':'godot_asset_analyzer','path':relative(p),'operation':operation,'error':str(e)})
        return _j({'ok':False,'tool':'godot_asset_analyzer','path':relative(p),'operation':operation,'error':f'NOT_PCK_OR_PARSE_ERROR: {e}'})
    try:entries,file_count=_entries(data,h)
    except Exception as e:return _j({'ok':False,'tool':'godot_asset_analyzer','path':relative(p),'operation':operation,'error':f'DIRECTORY_PARSE_ERROR: {e}'})
    base={'ok':True,'tool':'godot_asset_analyzer','format':'GODOT_PCK','path':relative(p),'operation':operation,
          'pack_format_version':h['version'],'engine_version':h['engine_version'],'file_count':file_count}
    if operation in {'summary','headers'}:
        return _j({**base,'total_uncompressed_bytes':sum(e['size'] for e in entries)})
    if operation=='list':
        return _j({**base,'files':entries[:max_results],'truncated':len(entries)>max_results})
    if operation in {'read','extract'}:
        if not member:return _j({**base,'ok':False,'error':'MEMBER_REQUIRED'})
        hit=next((e for e in entries if e['path']==member),None)
        if hit is None:return _j({**base,'ok':False,'error':'MEMBER_NOT_FOUND'})
        start=h['file_base']+hit['offset'] if h['rel_filebase'] else hit['offset']
        content=data[start:start+hit['size']]
        # Lossless or refused: text only when the member is valid UTF-8, otherwise
        # content_kind='binary' with its hash, never U+FFFD-mangled "content".
        return _j({**base,'member':member,**member_content(content,max_chars),'byte_size':hit['size']})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_GODOT_OPERATION'})
