"""Unity serialized asset inspection (GAP-010) via UnityPy (MIT, pip,
prebuilt Windows wheels for every native codec dependency it pulls in).
Lists real objects (name/type/path_id/class_id) and reads bounded primitive
fields for one named object on request. `ObjectReader.name` is NOT a cheap
shortcut here -- verified directly against a real fixture that it comes
back None for essentially every object (GameObject, Texture2D, all of it)
under this load path, unlike some other UnityPy loading modes where a
bundle's own container manifest supplies names without a full read. Getting
real names means calling .read() per object, same as `read` does. Some
object types (observed directly: most MonoBehaviour instances in a real
"minsize" WebGL build, which strips full script TypeTree info) genuinely
fail to fully deserialize -- reported honestly as TYPETREE_READ_FAILED /
left unnamed rather than silently skipped or guessed at."""
from __future__ import annotations
import json
from collections import Counter
from liebert_re.workspace import safe_path,relative

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

_PRIMITIVE_TYPES=(str,int,float,bool,type(None))

def _extract_primitive_fields(data,max_fields=60,max_str_len=2000):
    fields={}
    try:
        items=list(vars(data).items())
    except TypeError:
        return fields
    for k,v in items:
        if k in ('object_reader','assets_file'):continue
        if isinstance(v,_PRIMITIVE_TYPES):
            if isinstance(v,str) and len(v)>max_str_len:v=v[:max_str_len]
            fields[k]=v
        if len(fields)>=max_fields:break
    return fields

def _container_name(o):
    af=getattr(o,'assets_file',None)
    return getattr(af,'name',None) or str(af)

def unity_asset_analyzer(path,operation='summary',path_id=None,container='',max_items=300):
    def _missing(package,extra,hint,exc,path,operation):
        # An environment fault, not a data fault: the file was never looked at.
        return _j({'ok':False,'tool':'unity_asset_analyzer','status':'TOOL_MISSING','error':'UNITYPY_UNAVAILABLE',
                   'missing_dependency':package,'required_capability':f'{package} ({hint})','path':path,'operation':operation,
                   'detail':f'the optional Python package {package} could not be imported ({type(exc).__name__}: {exc}); install it with {hint} (extra "{extra}"). The input was not examined.'})
    p=safe_path(path);max_items=max(1,min(int(max_items),5000))
    try:
        import UnityPy
    except ImportError as e:
        return _missing('UnityPy','unity','pip install -e ".[unity]"',e,relative(p),operation)
    try:
        env=UnityPy.load(str(p))
        objects=list(env.objects)
    except Exception as e:
        return _j({'ok':False,'tool':'unity_asset_analyzer','path':relative(p),'operation':operation,'error':f'NOT_UNITY_ASSET_OR_LOAD_ERROR: {type(e).__name__}: {e}'})
    base={'ok':True,'tool':'unity_asset_analyzer','format':'UNITY_ASSET','path':relative(p),'operation':operation,'object_count':len(objects)}
    if operation in {'summary','headers'}:
        type_counts=Counter(o.type.name for o in objects)
        containers=sorted({_container_name(o) for o in objects})
        return _j({**base,'type_counts':dict(type_counts),'containers':containers})
    if operation=='list':
        # path_id is only unique WITHIN one underlying container (e.g. a
        # WebGL build bundles sharedassets0.assets/level0/etc. together, each
        # with its own path_id numbering starting from 1) -- confirmed as a
        # real collision against this exact fixture (two distinct GameObjects
        # both carrying path_id=6 in different containers), so `container`
        # is included on every row rather than assuming path_id alone
        # identifies an object.
        rows=[]
        for o in objects[:max_items]:
            row={'path_id':o.path_id,'class_id':o.class_id,'type':o.type.name,'name':None,'container':_container_name(o)}
            try:
                row['name']=getattr(o.read(),'m_Name',None) or None
            except Exception as e:
                # Same failure `read` names explicitly -- do not swallow it here.
                row['name_error']=f'TYPETREE_READ_FAILED: {type(e).__name__}'
            rows.append(row)
        return _j({**base,'objects':rows,'truncated':len(objects)>max_items})
    if operation=='read':
        # 0 is a legal Unity path_id, so only None/'' mean "not specified".
        if path_id is None or path_id=='':return _j({**base,'ok':False,'error':'PATH_ID_REQUIRED'})
        candidates=[o for o in objects if o.path_id==int(path_id)]
        if container:
            candidates=[o for o in candidates if _container_name(o)==container]
        if not candidates:return _j({**base,'ok':False,'error':'OBJECT_NOT_FOUND'})
        if len(candidates)>1:
            return _j({**base,'ok':False,'error':'AMBIGUOUS_PATH_ID','candidates':[{'container':_container_name(o),'type':o.type.name} for o in candidates]})
        hit=candidates[0]
        try:
            data=hit.read()
        except Exception as e:
            return _j({**base,'ok':False,'error':f'TYPETREE_READ_FAILED: {type(e).__name__}','path_id':hit.path_id,'class_id':hit.class_id,'type':hit.type.name,'container':_container_name(hit)})
        fields=_extract_primitive_fields(data)
        return _j({**base,'path_id':hit.path_id,'class_id':hit.class_id,'type':hit.type.name,'container':_container_name(hit),'fields':fields})
    return _j({**base,'ok':False,'error':'UNSUPPORTED_UNITY_OPERATION'})
