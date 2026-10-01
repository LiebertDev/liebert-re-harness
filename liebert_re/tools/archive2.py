"""7z/RAR/gzip/bz2/xz/zstd inspection (GAP-017), complementing archive_inspect's
ZIP/TAR coverage. 7z is full read (list + bounded extract) via py7zr; RAR is
listing-only via rarfile (pure Python, no external tool) -- RAR's proprietary
compression means real extraction needs an external unrar-compatible tool,
which isn't installed, so extraction is reported honestly rather than
attempted. gzip/bz2/xz/zstd are single-stream codecs (not multi-member
containers): decompress and report bounded content directly.

Decompression itself is bounded, not just the returned text: every read is
streamed and refused (DECOMPRESSED_SIZE_LIMIT_EXCEEDED) once it passes
_MAX_DECOMPRESSED_BYTES, so a compression bomb is never absorbed."""
from __future__ import annotations
import bz2,codecs,gzip,hashlib,json,lzma
from liebert_re.workspace import safe_path,relative

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

# Hard ceiling on how many decompressed bytes any single read/summary will
# produce before refusing. The returned text is separately capped by max_chars;
# this bounds the DECOMPRESSION so a highly compressible bomb (tens of GB from a
# few KB) is refused after at most this many bytes instead of being fully
# expanded first. Memory stays ~one chunk + the returned prefix regardless.
_MAX_DECOMPRESSED_BYTES=64*1024*1024
_STREAM_CHUNK=1024*1024

class DecompressionLimit(Exception):
    # seen is the byte count at refusal, or None when the backend (py7zr) aborted without reporting one.
    def __init__(self,seen):super().__init__(f'DECOMPRESSED_SIZE_LIMIT_EXCEEDED after {seen} bytes');self.seen=seen

class _Scan:
    """Constant-memory accumulator: total size, sha256, a bounded head, and
    whether the whole stream is valid UTF-8 (so text/binary is known exactly)."""
    def __init__(self,keep):
        self.keep=keep;self.total=0;self.head=bytearray();self.sha=hashlib.sha256()
        self._dec=codecs.getincrementaldecoder('utf-8')();self.utf8_ok=True;self.bad_offset=None
    def feed(self,chunk):
        if self.total+len(chunk)>_MAX_DECOMPRESSED_BYTES:raise DecompressionLimit(self.total+len(chunk))
        if len(self.head)<self.keep:self.head+=chunk[:self.keep-len(self.head)]
        self.sha.update(chunk)
        if self.utf8_ok:
            try:self._dec.decode(chunk)
            except UnicodeDecodeError as e:self.utf8_ok=False;self.bad_offset=self.total+e.start
        self.total+=len(chunk)
    def finish(self):
        if self.utf8_ok:
            try:self._dec.decode(b'',final=True)
            except UnicodeDecodeError:self.utf8_ok=False;self.bad_offset=self.total
        return self
    def result(self,max_chars):
        if not self.utf8_ok:
            return {'content_kind':'binary','byte_size':self.total,'sha256':self.sha.hexdigest(),'first_invalid_utf8_offset':self.bad_offset}
        head=bytes(self.head);cut=self.total>len(head)
        text=codecs.getincrementaldecoder('utf-8')().decode(head)  # non-final: drops a char cut at the head boundary
        return {'content_kind':'text','content':text[:max_chars],'truncated':cut or len(text)>max_chars,'byte_size':self.total}

def _head_bytes(max_chars):
    # >= 4 bytes per char plus slack: the first max_chars characters always lie inside the head.
    return max_chars*4+8

def _out(r):
    # content_kind is present on BOTH outcomes, deliberately. Emitting it only on
    # the binary path would keep the text result byte-identical to the previous
    # version, but it would leave a caller branching on "is this key here?" --
    # absence carrying meaning is the kind of contract an agent gets wrong, and
    # it is exactly the inconsistency this module was being fixed for. Adding a
    # key is additive: anything reading `content` is unaffected.
    return r

def _7z_read(p,member,max_chars):
    import py7zr
    from py7zr.io import Py7zIO,WriterFactory
    scan=_Scan(_head_bytes(max_chars))
    class _Sink(Py7zIO):
        # Receives the member as py7zr decompresses it; nothing is kept but the
        # bounded head, and the limit fires mid-stream, before the bomb expands.
        def write(self,s):scan.feed(bytes(s));return len(s)
        def read(self,size=None):return b''
        def seek(self,offset,whence=0):return 0
        def flush(self):return None
        def size(self):return scan.total
    class _Factory(WriterFactory):
        def __init__(self):self.hit=False
        def create(self,filename):self.hit=True;return _Sink()
    # Bounded read with py7zr, nothing is written to disk. Three layers:
    #  1. the member's header-declared size is refused above the cap BEFORE any decompression;
    #  2. py7zr's own max_extract_size (all bytes it decompresses, including the earlier
    #     members of a solid block that must be decoded to reach this one) aborts at the cap;
    #  3. the sink below refuses too, and keeps only a bounded head.
    # Residual: py7zr decodes in blocks of up to 128 MB (its get_memory_limit), so peak
    # memory is bounded by that block, not by our 1 MiB chunk as for the stdlib codecs.
    limit={'max_extract_size':_MAX_DECOMPRESSED_BYTES}
    try:
        z=py7zr.SevenZipFile(str(p),**limit)
    except TypeError:  # older py7zr without max_extract_size: layers 1 and 3 still apply
        z=py7zr.SevenZipFile(str(p))
    with z:
        infos={f.filename:f for f in z.list()}
        if member not in infos:return None
        declared=infos[member].uncompressed
        if declared and declared>_MAX_DECOMPRESSED_BYTES:raise DecompressionLimit(declared)
        fac=_Factory()
        try:z.extract(targets=[member],factory=fac)
        except getattr(py7zr.exceptions,'DecompressionBombError',DecompressionLimit):raise DecompressionLimit(None)
        if not fac.hit:return None
    return scan.finish().result(max_chars)

def _rar_list(p):
    import rarfile
    with rarfile.RarFile(str(p)) as rf:
        return [{'name':i.filename,'size':i.file_size,'compress_size':i.compress_size,'crc':i.CRC,'is_dir':i.is_dir()} for i in rf.infolist()]

def _open_stream(p,fmt):
    # File-object wrappers over the incremental decompressors (zlib/bz2/lzma
    # decompressobj, zstd): every read(n) decompresses at most ~n bytes, and
    # concatenated members/streams are handled as the one-shot helpers did.
    if fmt=='GZIP':return gzip.open(str(p),'rb')
    if fmt=='BZIP2':return bz2.open(str(p),'rb')
    if fmt=='XZ':return lzma.open(str(p),'rb')
    if fmt=='ZSTD':
        from backports import zstd
        return zstd.open(str(p),'rb')
    raise ValueError(f'UNSUPPORTED_STREAM_FORMAT_{fmt}')

def _scan_stream(p,fmt,keep):
    scan=_Scan(keep)
    with _open_stream(p,fmt) as f:
        while True:
            chunk=f.read(_STREAM_CHUNK)
            if not chunk:break
            scan.feed(chunk)
    return scan.finish()

def rar_7z(path,operation='summary',member='',max_results=200,max_chars=30000):
    p=safe_path(path);max_results=max(1,min(int(max_results),2000));max_chars=max(1000,min(int(max_chars),120000))
    with p.open('rb') as fh:head=fh.read(8)
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
                return _j({**base,'member':member,**_out(result)})
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
        if operation in {'summary','headers'}:
            scan=_scan_stream(p,fmt,0)
            return _j({**base,'decompressed_bytes':scan.total,'decompressed_sha256':scan.sha.hexdigest()})
        if operation in {'read','extract'}:
            scan=_scan_stream(p,fmt,_head_bytes(max_chars))
            return _j({**base,**_out(scan.result(max_chars))})
        return _j({**base,'ok':False,'error':'UNSUPPORTED_RAR_7Z_OPERATION'})
    except DecompressionLimit as e:
        return _j({**base,'ok':False,'error':'DECOMPRESSED_SIZE_LIMIT_EXCEEDED','limit_bytes':_MAX_DECOMPRESSED_BYTES,'bytes_seen_at_refusal':e.seen})
    except Exception as e:
        return _j({**base,'ok':False,'error':f'{type(e).__name__}: {e}'})
