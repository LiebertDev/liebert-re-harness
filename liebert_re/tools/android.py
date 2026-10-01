"""Android manifest/permission/component inspection (GAP-002) via androguard
(Apache-2.0, in-process, no external binary). Accepts either a whole `.apk`
(androguard's APK class handles the zip + manifest + real signing-presence
check) or a raw binary AndroidManifest.xml (AXML) extracted separately, e.g.
via archive_inspect. Resources.arsc string/style resolution and signature
verification depth are not implemented -- only presence/identity."""
from __future__ import annotations
import json
from liebert_re.workspace import safe_path,relative

_ANDROID_NS='{http://schemas.android.com/apk/res/android}'

def _quiet_loguru():
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)

def _axml_tree(data):
    from androguard.core.axml import AXMLPrinter
    return AXMLPrinter(data).get_xml_obj()

def _component_rows(root,tag):
    app=root.find('application')
    if app is None:return []
    rows=[]
    for el in app.findall(tag):
        rows.append({
            'name':el.get(_ANDROID_NS+'name'),
            'exported':el.get(_ANDROID_NS+'exported'),
            'actions':[a.get(_ANDROID_NS+'name') for f in el.findall('intent-filter') for a in f.findall('action')],
        })
    return rows

def _from_raw_axml(data,operation,max_items):
    root=_axml_tree(data)
    package=root.get('package')
    version_code=root.get(_ANDROID_NS+'versionCode')
    version_name=root.get(_ANDROID_NS+'versionName')
    sdk=root.find('uses-sdk')
    min_sdk=sdk.get(_ANDROID_NS+'minSdkVersion') if sdk is not None else None
    target_sdk=sdk.get(_ANDROID_NS+'targetSdkVersion') if sdk is not None else None
    permissions=[el.get(_ANDROID_NS+'name') for el in root.findall('uses-permission')]
    activities=_component_rows(root,'activity');services=_component_rows(root,'service')
    receivers=_component_rows(root,'receiver');providers=_component_rows(root,'provider')
    base={'package':package,'version_code':version_code,'version_name':version_name,'min_sdk':min_sdk,'target_sdk':target_sdk,
          'permission_count':len(permissions),'activity_count':len(activities),'service_count':len(services),
          'receiver_count':len(receivers),'provider_count':len(providers)}
    if operation in {'summary','headers'}:return base
    if operation=='permissions':return {**base,'permissions':permissions[:max_items],'truncated':len(permissions)>max_items}
    if operation=='components':
        comps=[{'type':'activity',**c} for c in activities]+[{'type':'service',**c} for c in services]+[{'type':'receiver',**c} for c in receivers]+[{'type':'provider',**c} for c in providers]
        return {**base,'components':comps[:max_items],'truncated':len(comps)>max_items}
    return None

def _from_apk(p,operation,max_items):
    from androguard.core.apk import APK
    a=APK(str(p))
    permissions=a.get_permissions() or []
    activities=a.get_activities() or [];services=a.get_services() or []
    receivers=a.get_receivers() or [];providers=a.get_providers() or []
    base={'package':a.get_package(),'version_code':a.get_androidversion_code(),'version_name':a.get_androidversion_name(),
          'min_sdk':a.get_min_sdk_version(),'target_sdk':a.get_target_sdk_version(),'app_name':a.get_app_name(),
          'main_activity':a.get_main_activity(),'is_signed':a.is_signed(),
          'permission_count':len(permissions),'activity_count':len(activities),'service_count':len(services),
          'receiver_count':len(receivers),'provider_count':len(providers)}
    if operation in {'summary','headers'}:return base
    if operation=='permissions':return {**base,'permissions':permissions[:max_items],'truncated':len(permissions)>max_items}
    if operation=='components':
        comps=([{'type':'activity','name':x} for x in activities]+[{'type':'service','name':x} for x in services]
               +[{'type':'receiver','name':x} for x in receivers]+[{'type':'provider','name':x} for x in providers])
        return {**base,'components':comps[:max_items],'truncated':len(comps)>max_items}
    return None

def android_resource_analyzer(path,operation='summary',max_items=300):
    _quiet_loguru()
    p=safe_path(path);max_items=max(1,min(int(max_items),2000))
    head=p.read_bytes()[:4]
    is_zip=head[:2]==b'PK'
    try:
        result=_from_apk(p,operation,max_items) if is_zip else _from_raw_axml(p.read_bytes(),operation,max_items)
    except Exception as e:
        return _j({'ok':False,'tool':'android_resource_analyzer','path':relative(p),'operation':operation,'error':f'ANDROID_MANIFEST_PARSE_ERROR: {e}'})
    if result is None:
        return _j({'ok':False,'tool':'android_resource_analyzer','path':relative(p),'operation':operation,'error':'UNSUPPORTED_ANDROID_OPERATION'})
    return _j({'ok':True,'tool':'android_resource_analyzer','format':'APK' if is_zip else 'AXML','path':relative(p),'operation':operation,**result})
