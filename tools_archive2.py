"""7z/RAR/gzip/bz2/xz/zstd inspection (GAP-017), complementing archive_inspect's
ZIP/TAR coverage. 7z is full read (list + bounded extract) via py7zr; RAR is
listing-only via rarfile (pure Python, no external tool) -- RAR's proprietary
compression means real extraction needs an external unrar-compatible tool,
which isn't installed, so extraction is reported honestly rather than
attempted. gzip/bz2/xz/zstd are single-stream codecs (not multi-member
containers): decompress and report bounded content directly."""
from __future__ import annotations
import bz2,gzip,hashlib,json,lzma,tempfile
from pathlib import Path
from tools_workspace import safe_path,relative

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

_MAGIC={
    b'7z\xbc\xaf\x27\x1c':'7Z',
    b'Rar!\x1a\x07\x00':'RAR',b'Rar!\x1a\x07\x01':'RAR',
    b'\x1f\x8b':'GZIP',b'BZh':'BZIP2',b'\xfd7zXZ\x00':'XZ',b'\x28\xb5\x2f\xfd':'ZSTD',
}

def _detect(data):
    for magic,fmt in _MAGIC.items():
        if data[:len(magic)]==magic:return fmt
    return None

def _7z_list(p):
    import py7zr
    with py7zr.SevenZipFile(str(p)) as z:
        return [{'name':f.filename,'uncompressed':f.uncompressed,'compressed':f.compressed,'crc32':f.crc32,'is_directory':f.is_directory} for f in z.list()]

def _7z_read(p,member,max_chars):
    import py7zr
    with py7zr.SevenZipFile(str(p)) as z:
        names={f.filename for f in z.list()}
        if member not in names:return None
        with tempfile.TemporaryDirectory(prefix='sevenzip_out_') as tmp:
            z.extract(path=tmp,targets=[member])
            out=Path(tmp)/member
            if not out.exists():return None
            data=out.read_bytes()
    text=data.decode('utf-8',errors='replace')
    return {'content':text[:max_chars],'truncated':len(text)>max_chars,'byte_size':len(data)}

def _rar_list(p):
    import rarfile
    with rarfile.RarFile(str(p)) as rf:
        return [{'name':i.filename,'size':i.file_size,'compress_size':i.compress_size,'crc':i.CRC,'is_dir':i.is_dir()} for i in rf.infolist()]

def _decompress_stream(p,fmt):
    data=p.read_bytes()
    if fmt=='GZIP':return gzip.decompress(data)
    if fmt=='BZIP2':return bz2.decompress(data)
    if fmt=='XZ':return lzma.decompress(data)
    if fmt=='ZSTD':
        from backports import zstd
        return zstd.decompress(data)
    raise ValueError(f'UNSUPPORTED_STREAM_FORMAT_{fmt}')

def rar_7z(path,operation='summary',member='',max_results=200,max_chars=30000):
    p=safe_path(path);max_results=max(1,min(int(max_results),2000));max_chars=max(1000,min(int(max_chars),120000))
    head=p.read_bytes()[:8]
    fmt=_detect(head)
    if fmt is None:return _j({'ok':False,'tool':'rar_7z','path':relative(p),'operation':operation,'error':'NOT_A_RECOGNIZED_ARCHIVE_FORMAT'})
    base={'ok':True,'tool':'rar_7z','format':fmt,'path':relative(p),'operation':operation}
    try:
        if fmt=='7Z':
            members=_7z_list(p)
            if operation in {'summary','headers'}:
                return _j({**base,'member_count':len(members),'total_uncompressed_bytes':sum(m['uncompressed'] for m in members)})
            if operation=='list':
                return _j({**base,'members':members[:max_results],'truncated':len(members)>max_results})
            if operation in {'read','extract'}:
                if not member:return _j({**base,'ok':False,'error':'MEMBER_REQUIRED'})
                result=_7z_read(p,member,max_chars)
                if result is None:return _j({**base,'ok':False,'error':'MEMBER_NOT_FOUND'})
                return _j({**base,'member':member,**result})
            return _j({**base,'ok':False,'error':'UNSUPPORTED_RAR_7Z_OPERATION'})
        if fmt=='RAR':
            members=_rar_list(p)
            if operation in {'summary','headers'}:
                return _j({**base,'member_count':len(members),'total_uncompressed_bytes':sum(m['size'] for m in members)})
            if operation=='list':
                return _j({**base,'members':members[:max_results],'truncated':len(members)>max_results})
            if operation in {'read','extract'}:
                return _j({**base,'ok':False,'error':'RAR_EXTRACTION_REQUIRES_EXTERNAL_UNRAR_TOOL','limitations':['Listing (name/size/compress_size/crc) is real and available; RAR is a proprietary compression format and extracting member content needs an external unrar-compatible binary, which is not installed']})
            return _j({**base,'ok':False,'error':'UNSUPPORTED_RAR_7Z_OPERATION'})
        # Single-stream codecs: no member list, just decompressed content.
        decompressed=_decompress_stream(p,fmt)
        if operation in {'summary','headers'}:
            return _j({**base,'decompressed_bytes':len(decompressed),'decompressed_sha256':hashlib.sha256(decompressed).hexdigest()})
        if operation in {'read','extract'}:
            text=decompressed.decode('utf-8',errors='replace')
            return _j({**base,'content':text[:max_chars],'truncated':len(text)>max_chars,'byte_size':len(decompressed)})
        return _j({**base,'ok':False,'error':'UNSUPPORTED_RAR_7Z_OPERATION'})
    except Exception as e:
        return _j({**base,'ok':False,'error':f'{type(e).__name__}: {e}'})
