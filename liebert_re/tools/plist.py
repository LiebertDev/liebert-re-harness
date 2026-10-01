"""Apple property list inspection (GAP-016 continued: bundle Info.plist and
any other standalone .plist file, binary or XML) via Python's own stdlib
`plistlib` -- no external tool, no hand-rolled bplist parser, since
plistlib already correctly implements both formats. Recursively converts
the parsed tree into JSON-safe values (datetime -> ISO 8601, bytes -> hex
with a length, anything else unexpected -> str()), bounded by item count
and string length so a large plist can't blow up the response."""
from __future__ import annotations
import datetime,json,plistlib
from liebert_re.workspace import safe_path,relative

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

def _json_safe(v,max_items,max_str_len,depth=0):
    if depth>16:return '...TRUNCATED_DEPTH...'
    if isinstance(v,dict):
        return {str(k):_json_safe(val,max_items,max_str_len,depth+1) for k,val in list(v.items())[:max_items]}
    if isinstance(v,list):
        return [_json_safe(x,max_items,max_str_len,depth+1) for x in v[:max_items]]
    if isinstance(v,(bytes,bytearray)):
        return {'bytes_hex':bytes(v[:max_str_len]).hex(),'byte_size':len(v),'truncated':len(v)>max_str_len}
    if isinstance(v,datetime.datetime):
        return v.isoformat()
    if isinstance(v,str):
        return v[:max_str_len]
    if isinstance(v,(int,float,bool)) or v is None:
        return v
    return str(v)  # e.g. plistlib.UID (rare, NSKeyedArchiver-style plists)

def plist_inspect(path,operation='summary',max_items=300):
    p=safe_path(path);max_items=max(1,min(int(max_items),2000))
    data=p.read_bytes()
    plist_format='binary' if data[:8]==b'bplist00' else 'xml' if b'<plist' in data[:512] else 'unknown'
    try:
        root=plistlib.loads(data)
    except Exception as e:
        return _j({'ok':False,'tool':'plist_inspect','path':relative(p),'operation':operation,'error':f'NOT_A_PLIST_OR_PARSE_ERROR: {type(e).__name__}: {e}'})
    base={'ok':True,'tool':'plist_inspect','format':'PLIST','plist_format':plist_format,'path':relative(p),'operation':operation,'root_type':type(root).__name__}
    if operation in {'summary','headers'}:
        if isinstance(root,dict):
            return _j({**base,'key_count':len(root),'top_level_keys':list(root.keys())[:max_items],'truncated':len(root)>max_items})
        if isinstance(root,list):
            return _j({**base,'item_count':len(root),'truncated':len(root)>max_items})
        return _j({**base,'value':_json_safe(root,max_items,2000)})
    if operation=='read':
        return _j({**base,'content':_json_safe(root,max_items,2000)})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_PLIST_OPERATION'})
