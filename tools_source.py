"""Bounded source/project intelligence with parser-to-regex fallbacks."""
from __future__ import annotations
import ast,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from tools_workspace import safe_path,relative,skipped,text_of

MAX_SOURCE_BYTES=16_000_000; MAX_RESULTS=500; MAX_SCAN_FILES=12000
LANG={'.py':'Python','.cs':'C#','.c':'C','.h':'C/C++ header','.cpp':'C++','.hpp':'C++ header','.java':'Java','.js':'JavaScript','.mjs':'JavaScript','.cjs':'JavaScript','.jsx':'JavaScript JSX','.ts':'TypeScript','.tsx':'TypeScript TSX','.go':'Go','.rs':'Rust','.lua':'Lua','.ps1':'PowerShell','.psm1':'PowerShell','.sh':'Shell','.rb':'Ruby','.php':'PHP'}
MANIFESTS={'pyproject.toml','requirements.txt','setup.py','package.json','package-lock.json','pnpm-lock.yaml','yarn.lock','cargo.toml','go.mod','pom.xml','build.gradle','build.gradle.kts','settings.gradle','composer.json','gemfile','cmakelists.txt','makefile','.sln','.csproj','global.json'}
ENTRY_NAMES={'main.py','app.py','__main__.py','program.cs','main.cs','main.c','main.cpp','main.go','main.rs','index.js','index.ts','server.js','server.ts','app.js','app.ts'}
CONFIG_EXT={'.json','.yaml','.yml','.toml','.ini','.cfg','.xml','.env'}

def _j(x):return json.dumps(x,ensure_ascii=False,indent=2,default=str)
def _read(p):
    if p.stat().st_size>MAX_SOURCE_BYTES:raise ValueError('SOURCE_TOO_LARGE_FOR_FULL_PARSE')
    return text_of(p)
def _c_symbols(lines,cpp=False):
    """Conservative multiline C/C++ definition scan; never treat control flow as a symbol."""
    out=[]; pending=[]; controls={'if','for','while','switch','catch','sizeof','return','do'}
    for i,line in enumerate(lines,1):
        stripped=line.strip()
        if not stripped or stripped.startswith(('#','//')):
            continue
        pending.append((i,stripped))
        if len(pending)>24:
            pending=pending[-24:]
        if '{' not in stripped:
            if ';' in stripped or '}' in stripped:
                pending=[]
            continue
        before=' '.join(part for _,part in pending).split('{',1)[0].strip()
        normalized=re.sub(r'/\*.*?\*/',' ',before)
        normalized=re.sub(r'\s+',' ',normalized).strip()
        if re.match(r'^(?:if|for|while|switch|catch|else|do)\b',normalized,re.I):
            pending=[]
            continue
        # A definition needs a return/type prefix and a final identifier before its parameters.
        match=re.match(r'^(?P<prefix>.+?)\b(?P<name>[A-Za-z_]\w*(?:::\w+)?)\s*\((?P<args>.*)\)\s*(?:const\s*)?$',normalized)
        if match:
            name=match.group('name'); prefix=match.group('prefix').strip()
            if name.casefold() not in controls and prefix and '=' not in prefix:
                out.append({'name':name,'kind':'function','line':pending[0][0],'signature':normalized[:300]})
        pending=[]
    return out
def _regex_symbols(lines,ext):
    rules={
      '.py':[(r'^\s*(?:async\s+)?def\s+(\w+)','function'),(r'^\s*class\s+(\w+)','class')],
      '.cs':[(r'^\s*(?:public|private|protected|internal|static|async|sealed|abstract|partial|virtual|override|\s)+\s*(?:class|record|struct|interface|enum)\s+(\w+)','type'),(r'^\s*(?:public|private|protected|internal|static|async|virtual|override|sealed|extern|unsafe|new|\s)+[\w<>,\[\]?\.]+\s+(\w+)\s*\(','method')],
      '.java':[(r'^\s*(?:public|private|protected|abstract|final|static|\s)*(?:class|interface|enum|record)\s+(\w+)','type'),(r'^\s*(?:public|private|protected|static|final|abstract|synchronized|native|\s)+[\w<>,\[\]?\.]+\s+(\w+)\s*\(','method')],
      '.js':[(r'^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)','function'),(r'^\s*(?:export\s+)?class\s+(\w+)','class'),(r'^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(','function')],
      '.ts':[(r'^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)','function'),(r'^\s*(?:export\s+)?(?:class|interface|type|enum)\s+(\w+)','type')],
      '.c':[],'.cpp':[],
      '.go':[(r'^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(','function'),(r'^\s*type\s+(\w+)\s+(?:struct|interface)','type')],
      '.rs':[(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)','function'),(r'^\s*(?:pub\s+)?(?:struct|enum|trait)\s+(\w+)','type')],
      '.lua':[(r'^\s*(?:local\s+)?function\s+([\w.:]+)','function')],
      '.ps1':[(r'^\s*function\s+([\w-]+)','function')],
    }
    if ext in {'.c','.cpp','.h','.hpp'}:return _c_symbols(lines,cpp=ext in {'.cpp','.hpp'})
    chosen=rules.get(ext,rules.get('.js') if ext in {'.mjs','.cjs','.jsx'} else rules.get('.ts') if ext=='.tsx' else [])
    out=[]
    for i,line in enumerate(lines,1):
        for pat,kind in chosen:
            m=re.search(pat,line,re.I)
            if m:out.append({'name':m.group(1),'kind':kind,'line':i,'signature':line.strip()[:300]});break
    return out
def _python_symbols(text):
    tree=ast.parse(text);out=[]
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            out.append({'name':node.name,'kind':'class' if isinstance(node,ast.ClassDef) else 'function','line':node.lineno,'end_line':getattr(node,'end_lineno',None),'decorators':[ast.unparse(x) for x in node.decorator_list][:10]})
    return sorted(out,key=lambda x:x['line'])
def _call_graph(text,ext):
    if ext=='.py':
        tree=ast.parse(text);edges=[]
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for x in ast.walk(node):
                    if isinstance(x,ast.Call):
                        if isinstance(x.func,ast.Name):callee=x.func.id
                        elif isinstance(x.func,ast.Attribute):callee=x.func.attr
                        else:continue
                        edges.append({'caller':node.name,'callee':callee,'line':getattr(x,'lineno',None)})
        return edges,'python_ast'
    lines=text.splitlines();symbols=_regex_symbols(lines,ext);known={x['name'].split('::')[-1] for x in symbols};edges=[]
    for idx,s in enumerate(symbols):
        start=s['line'];end=(symbols[idx+1]['line']-1) if idx+1<len(symbols) else min(len(lines),start+500)
        for n in range(start-1,end):
            for callee in re.findall(r'\b([A-Za-z_]\w*)\s*\(',lines[n]):
                if callee in known and callee!=s['name']:edges.append({'caller':s['name'],'callee':callee,'line':n+1})
    return edges,'syntax_scan'
def _imports(text,ext):
    out=[]
    for i,line in enumerate(text.splitlines(),1):
        pats=[r'^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))',r'^\s*(?:const|let|var)?\s*.*?require\(["\']([^"\']+)',r'^\s*import\s+.*?from\s+["\']([^"\']+)',r'^\s*using\s+([\w.]+)',r'^\s*#include\s*[<"]([^>"]+)',r'^\s*use\s+([\w:]+)',r'^\s*package\s+([\w./]+)']
        for pat in pats:
            m=re.search(pat,line)
            if m:out.append({'line':i,'value':next(x for x in m.groups() if x),'text':line.strip()[:300]});break
    return out
def source_inspect(path,operation='outline',query='',patterns=None,max_results=200):
    p=safe_path(path); max_results=max(1,min(int(max_results),MAX_RESULTS)); ext=p.suffix.lower(); lang=LANG.get(ext,'Unknown/Text')
    try:text=_read(p)
    except Exception as e:
        if operation not in {'outline','symbols'}:return _j({'ok':False,'status':'ANALYSIS_LIMITED','error':str(e),'path':relative(p)})
        lines=[]
        with p.open('r',encoding='utf-8',errors='replace') as f:
            for i,line in enumerate(f,1):
                lines.append(line.rstrip('\n'))
                if i>=250000:break
        symbols=_regex_symbols(lines,ext); return _j({'ok':True,'tool':'source_inspect','path':relative(p),'language':lang,'operation':operation,'symbols':symbols[:max_results],'parser':'streaming_regex','truncated':len(symbols)>max_results or len(lines)>=250000,'limitations':['Full AST parse skipped for large file']})
    lines=text.splitlines(); base={'ok':True,'tool':'source_inspect','path':relative(p),'language':lang,'operation':operation,'line_count':len(lines),'size_bytes':p.stat().st_size,'truncated':False}
    if operation in {'outline','symbols','definitions'}:
        try:symbols=_python_symbols(text) if ext=='.py' else _regex_symbols(lines,ext); parser='python_ast' if ext=='.py' else 'syntax_scan'
        except Exception:symbols=_regex_symbols(lines,ext);parser='fallback_scan'
        if query:symbols=[x for x in symbols if query.lower() in x['name'].lower()]
        base.update(symbols=symbols[:max_results],parser=parser,truncated=len(symbols)>max_results);return _j(base)
    if operation=='call_graph_light':
        try:edges,parser=_call_graph(text,ext)
        except Exception as e:return _j({**base,'ok':False,'error':f'CALL_GRAPH_PARSE_FAILED: {e}'})
        base.update(edges=edges[:max_results],parser=parser,truncated=len(edges)>max_results,limitations=['Lightweight static calls only; dynamic dispatch/reflection are not resolved']);return _j(base)
    if operation=='imports':
        vals=_imports(text,ext);base.update(imports=vals[:max_results],truncated=len(vals)>max_results);return _j(base)
    if operation in {'references','search','regex','multi_search'}:
        pats=patterns if isinstance(patterns,list) and patterns else [query]; compiled=[]
        for pat in pats:
            try:compiled.append((pat,re.compile(pat if operation in {'regex','multi_search'} else re.escape(pat),re.I)))
            except re.error as e:return _j({**base,'ok':False,'error':f'INVALID_REGEX: {e}'})
        hits=[]
        for i,line in enumerate(lines,1):
            for label,rx in compiled:
                if rx.search(line):hits.append({'pattern':label,'line':i,'text':line.strip()[:500]});break
            if len(hits)>=max_results:break
        base.update(hits=hits,truncated=len(hits)>=max_results);return _j(base)
    return _j({**base,'ok':False,'error':'UNKNOWN_OPERATION'})

def project_inspect(path='.',operation='summary',query='',max_files=12000,max_results=300):
    root=safe_path(path);items=[]
    for p in root.rglob('*'):
        if p.is_file() and not skipped(p):
            items.append(p)
            if len(items)>=min(int(max_files),MAX_SCAN_FILES):break
    langs=Counter(LANG.get(p.suffix.lower(),'Other') for p in items); manifests=[relative(p) for p in items if p.name.lower() in MANIFESTS or p.suffix.lower() in {'.sln','.csproj','.fsproj','.vcxproj'}]; configs=[relative(p) for p in items if p.suffix.lower() in CONFIG_EXT or p.name.lower() in {'.env.example','dockerfile'}];tests=[relative(p) for p in items if 'test' in p.name.lower() or any(x.lower() in {'tests','test','spec','specs'} for x in p.parts)]; entries=[relative(p) for p in items if p.name.lower() in ENTRY_NAMES]
    out={'ok':True,'tool':'project_inspect','path':relative(root),'operation':operation,'file_count':len(items),'truncated':len(items)>=max_files,'languages':dict(langs),'manifests':manifests[:max_results],'entrypoints':entries[:max_results],'configs':configs[:max_results],'tests':tests[:max_results]}
    if operation=='structure':
        tree=defaultdict(lambda:{'files':0,'bytes':0})
        for p in items:
            rel=Path(relative(p)); top=rel.parts[0] if len(rel.parts)>1 else '.';tree[top]['files']+=1
            try:tree[top]['bytes']+=p.stat().st_size
            except OSError:pass
        out['top_level']=dict(tree)
    return _j(out)

def cross_file_graph(path='.',query='',max_files=3000,max_edges=500):
    root=safe_path(path); files=[]; skipped_oversize=0
    for p in root.rglob('*'):
        if p.is_file() and not skipped(p):
            if p.stat().st_size<=2_000_000:files.append(p)
            else:skipped_oversize+=1
        if len(files)>=max_files:break
    by_name=defaultdict(list)
    for p in files:by_name[p.name.lower()].append(p)
    edges=[]; skipped_decode_error=0
    ref_rx=re.compile(r'(?i)\b[A-Za-z0-9_.-]{2,200}\.(?:dll|exe|sys|so|dylib|json|xml|ini|cfg|yaml|yml|toml|js|ts|py|cs|jar|apk|db|sqlite|log)\b')
    for src in files:
        try:text=text_of(src).lower()
        except Exception:skipped_decode_error+=1;continue
        mentioned=set(ref_rx.findall(text))
        for name in mentioned:
            targets=by_name.get(name,[])
            if len(name)<5 or src in targets:continue
            if targets and (not query or query.lower() in name or query.lower() in text):
                for target in targets:edges.append({'from':relative(src),'to':relative(target),'relation':'filename_reference','evidence':name})
                if len(edges)>=max_edges:break
        if len(edges)>=max_edges:break
    # Files dropped from the graph (oversize at the initial scan, or
    # unreadable/undecodable at the per-file text pass) were previously
    # silently absent: `nodes` is only the length of the already-filtered
    # list and `truncated` only reflects the edges cap, so a caller could not
    # tell "this file has no cross-references" from "this file was never
    # scanned". Surface both counts explicitly instead of folding them into
    # `truncated`, whose existing meaning (edges cap hit) must not change.
    skipped_total=skipped_oversize+skipped_decode_error
    return _j({'ok':True,'tool':'cross_file_graph','path':relative(root),'nodes':len(files),'edges':edges,'truncated':len(edges)>=max_edges,'skipped_files':skipped_total,'skipped_files_breakdown':{'oversize_gt_2MB':skipped_oversize,'decode_error':skipped_decode_error},'limitations':['Filename-reference correlation only; semantic linkage requires verification']})

def java_class_inspect(path,max_items=300):
    p=safe_path(path);data=p.read_bytes()
    if data[:4]!=b'\xca\xfe\xba\xbe':return _j({'ok':False,'error':'NOT_JAVA_CLASS'})
    pos=8;count=struct.unpack('>H',data[pos:pos+2])[0];pos+=2;cp=[None];utf=[]
    try:
        i=1
        while i<count:
            tag=data[pos];pos+=1
            if tag==1:
                n=struct.unpack('>H',data[pos:pos+2])[0];pos+=2;s=data[pos:pos+n].decode('utf-8',errors='replace');pos+=n;cp.append(s);utf.append(s)
            elif tag in {3,4}:pos+=4;cp.append(None)
            elif tag in {5,6}:pos+=8;cp.extend([None,None]);i+=1
            elif tag in {7,8,16,19,20}:pos+=2;cp.append(None)
            elif tag in {9,10,11,12,17,18}:pos+=4;cp.append(None)
            elif tag==15:pos+=3;cp.append(None)
            else:raise ValueError(f'unknown constant pool tag {tag}')
            i+=1
    except Exception as e:return _j({'ok':False,'error':f'MALFORMED_CLASS: {e}'})
    likely=[x for x in utf if re.match(r'^[A-Za-z_$][\w$<>/;().\[\]-]{1,200}$',x)]
    return _j({'ok':True,'tool':'java_class_inspect','path':relative(p),'major_version':struct.unpack('>H',data[6:8])[0],'constant_pool_count':count-1,'utf8_constants':likely[:max_items],'truncated':len(likely)>max_items,'limitations':['Constant-pool inventory only; bytecode decompiler is TOOL_MISSING']})
