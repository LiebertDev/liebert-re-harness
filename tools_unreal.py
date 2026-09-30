"""Unreal Engine .pak inspection (GAP-009): pure-Python footer/index parse,
no external tool. Format confirmed against panzi/u4pak (BSD-licensed, a
mature community reference implementation -- Epic's own PakFile source is
gated behind a required Epic Games account login, unreachable from this
session) and independently verified against a real fixture before writing
this parser. Classic PAK only (versions 1/2/3/4/7, matching u4pak's own
supported set); IoStore (.utoc/.ucas, UE4.25+/UE5's newer container format)
is not covered -- its format is materially less documented (reverse-
engineering projects only, no one authoritative community spec) and often
carries its own AES encryption layer on top, a meaningfully different scope.
Listing only: `read` returns raw bytes for uncompressed entries; compressed
entries (zlib, in fixed-size blocks) are reported honestly as
COMPRESSION_NOT_SUPPORTED rather than guessed at."""
from __future__ import annotations
import hashlib,json,struct
from tools_workspace import safe_path,relative,member_content

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

_MAGIC=0x5A6F12E1
_COMPR_NAMES={0:'none',1:'zlib',0x10:'bias_memory',0x20:'bias_speed'}

def _read_path(data,pos):
    n,=struct.unpack_from('<i',data,pos);pos+=4
    if n<0:
        n=-2*n;s=data[pos:pos+n].decode('utf-16le',errors='replace').rstrip('\x00')
    else:
        s=data[pos:pos+n].decode('utf-8',errors='replace').rstrip('\x00')
    return s,pos+n

def _read_record(data,pos,version):
    offset,compressed_size,uncompressed_size,cmeth,sha1=struct.unpack_from('<QQQI20s',data,pos);pos+=48
    timestamp=None
    if version==1:
        timestamp,=struct.unpack_from('<Q',data,pos);pos+=8
    blocks=[]
    encrypted=False
    if version in (3,4,7) and cmeth!=0:
        block_count,=struct.unpack_from('<I',data,pos);pos+=4
        for _ in range(block_count):
            start,end=struct.unpack_from('<QQ',data,pos);pos+=16
            blocks.append({'start':start,'end':end})
    if version in (3,4,7):
        enc_byte,compression_block_size=struct.unpack_from('<BI',data,pos);pos+=5
        encrypted=bool(enc_byte)
    else:
        compression_block_size=None
    header_end=pos
    return {'offset':offset,'compressed_size':compressed_size,'uncompressed_size':uncompressed_size,
            'compression_method':_COMPR_NAMES.get(cmeth,f'unknown_{cmeth}'),'sha1':sha1.hex(),
            'timestamp':timestamp,'encrypted':encrypted,'compression_blocks':blocks or None,
            'compression_block_size':compression_block_size},header_end

def _parse(data):
    if len(data)<44:raise ValueError('FILE_TOO_SMALL_FOR_PAK_FOOTER')
    footer=data[-44:]
    magic,version,index_offset,index_size,index_sha1=struct.unpack('<IIQQ20s',footer)
    if magic!=_MAGIC:raise ValueError(f'NOT_A_PAK_FILE_BAD_MAGIC_{hex(magic)}')
    if version not in (1,2,3,4,7):raise ValueError(f'UNSUPPORTED_PAK_VERSION_{version}')
    footer_offset=len(data)-44
    if index_offset+index_size>footer_offset:raise ValueError('ILLEGAL_INDEX_OFFSET_OR_SIZE')
    pos=index_offset
    mount_point,pos=_read_path(data,pos)
    entry_count,=struct.unpack_from('<I',data,pos);pos+=4
    entries=[]
    for _ in range(entry_count):
        filename,pos=_read_path(data,pos)
        record,pos=_read_record(data,pos,version)
        entries.append({'filename':filename,**record})
    return {'version':version,'mount_point':mount_point,'index_offset':index_offset,'index_size':index_size,
            'index_sha1':index_sha1.hex(),'entries':entries}

def unreal_asset_analyzer(path,operation='summary',member='',max_results=300,max_chars=30000):
    p=safe_path(path);max_results=max(1,min(int(max_results),5000));max_chars=max(1000,min(int(max_chars),200000))
    data=p.read_bytes()
    try:parsed=_parse(data)
    except Exception as e:
        # Closed version allowlist (the set the parser's branches were written for): a named refusal, not a generic parse error.
        if str(e).startswith('UNSUPPORTED_PAK_VERSION_'):
            return _j({'ok':False,'tool':'unreal_asset_analyzer','path':relative(p),'operation':operation,'error':str(e)})
        return _j({'ok':False,'tool':'unreal_asset_analyzer','path':relative(p),'operation':operation,'error':f'PAK_PARSE_ERROR: {e}'})
    base={'ok':True,'tool':'unreal_asset_analyzer','format':'UNREAL_PAK','path':relative(p),'operation':operation,
          'pak_version':parsed['version'],'mount_point':parsed['mount_point'],'entry_count':len(parsed['entries'])}
    if operation in {'summary','headers'}:
        total=sum(e['uncompressed_size'] for e in parsed['entries'])
        compressed_count=sum(1 for e in parsed['entries'] if e['compression_method']!='none')
        return _j({**base,'total_uncompressed_bytes':total,'compressed_entry_count':compressed_count})
    if operation=='list':
        rows=[{'filename':e['filename'],'offset':e['offset'],'compressed_size':e['compressed_size'],
               'uncompressed_size':e['uncompressed_size'],'compression_method':e['compression_method'],
               'sha1':e['sha1'],'encrypted':e['encrypted']} for e in parsed['entries'][:max_results]]
        return _j({**base,'entries':rows,'truncated':len(parsed['entries'])>max_results})
    if operation in {'read','extract'}:
        if not member:return _j({**base,'ok':False,'error':'MEMBER_REQUIRED'})
        hit=next((e for e in parsed['entries'] if e['filename']==member),None)
        if hit is None:return _j({**base,'ok':False,'error':'MEMBER_NOT_FOUND'})
        if hit['encrypted']:return _j({**base,'ok':False,'error':'ENCRYPTED_ENTRY_NOT_SUPPORTED','filename':member})
        if hit['compression_method']!='none':
            return _j({**base,'ok':False,'error':'COMPRESSION_NOT_SUPPORTED','compression_method':hit['compression_method'],'filename':member})
        # header_size for this record's file-local copy is not tracked separately
        # here (it's re-derived from the same _read_record logic against the
        # data section, since Unreal writes an identical per-entry header
        # immediately before the raw bytes at `offset`).
        rec,data_start=_read_record(data,hit['offset'],parsed['version'])
        content=data[data_start:data_start+hit['uncompressed_size']]
        sha1_actual=hashlib.sha1(content).hexdigest()
        # Lossless or refused: text only when the member is valid UTF-8, otherwise
        # content_kind='binary' with its hash, never U+FFFD-mangled "content".
        return _j({**base,'filename':member,**member_content(content,max_chars),
                   'byte_size':len(content),'sha1_matches_index':sha1_actual==hit['sha1']})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_PAK_OPERATION'})
