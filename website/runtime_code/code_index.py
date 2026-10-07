"""Static references and URL search through the same saved-Run/artifact services."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time
import zipfile
from .config import get_config

MAX_INPUT=128*1024**2

def references(data,metadata):
    from .analysis import structure
    validity=structure(data,{})
    if validity.get('format')!='dex' or validity.get('validity')!='structurally_inspected':
        return {'format':'code-references/v1','validity':'unsupported','diagnostic':'Requires a structurally inspected standalone DEX','structure':validity.get('validity')}
    bundled=Path(__file__).resolve().parents[1]/'.venvs/analysis/bin/python'
    configured=os.environ.get('RUNTIME_CODE_ANALYSIS_PYTHON') or get_config()['paths']['analysis_python']
    python=Path(configured).expanduser() if configured else bundled if bundled.is_file() else Path.home()/'tools/venv/bin/python'
    with tempfile.TemporaryDirectory(prefix='runtime-code-index-') as directory:
        root=Path(directory);source=root/'input.dex';source.write_bytes(data)
        with (root/'result.json').open('wb') as output, (root/'errors.log').open('wb') as errors:
            timeout=min(60,max(.01,float(metadata.get('index_timeout_seconds',60))))
            subprocess.run([str(python),str(Path(__file__).with_name('code_index_worker.py')),str(source)],stdout=output,stderr=errors,timeout=timeout,check=True)
        result=root/'result.json'
        if result.stat().st_size>32*1024**2:raise ValueError('Code index output budget exceeded')
        if not result.stat().st_size:raise ValueError('Static worker unavailable, failed, or resource-limited; run bundle setup or set RUNTIME_CODE_ANALYSIS_PYTHON to a Python with Androguard')
        return json.loads(result.read_text())


def dex_inputs(path):
    """Read bounded archive entries in memory; never extract app-supplied paths."""
    path=Path(path)
    with path.open('rb') as stream:raw=stream.read(MAX_INPUT+1)
    if len(raw)>MAX_INPUT:raise ValueError('Static input exceeds 128 MiB')
    parent_hash=hashlib.sha256(raw).hexdigest();budget=[0,0]
    def walk(data,label,depth=0):
        if data.startswith(b'dex\n'):
            budget[1]+=len(data)
            if len(data)>64*1024**2 or budget[1]>MAX_INPUT:raise ValueError('DEX expansion limit')
            yield label,data;return
        if depth>2 or not data.startswith(b'PK'):raise ValueError('Expected DEX, APK or APK split ZIP')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            items=archive.infolist()
            if len(items)>10000:raise ValueError('Archive entry limit')
            names=set()
            for member in items:
                if member.filename in names:raise ValueError('Duplicate archive member')
                names.add(member.filename)
                parts=PurePosixPath(member.filename)
                if parts.is_absolute() or '..' in parts.parts or '\\' in member.filename:raise ValueError('Unsafe archive member path')
                if member.is_dir():continue
                if not (re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',member.filename) or member.filename.endswith('.apk')):continue
                budget[0]+=1
                if budget[0]>256 or member.file_size>64*1024**2 or member.file_size>max(1,member.compress_size)*250:raise ValueError('Archive expansion/entry budget')
                with archive.open(member) as stream:child=stream.read(64*1024**2+1)
                if len(child)>64*1024**2:raise ValueError('Archive expanded size limit')
                if member.filename.endswith('.apk'):
                    budget[1]+=len(child)
                    if budget[1]>MAX_INPUT:raise ValueError('Aggregate archive expansion limit')
                yield from walk(child,label+'!'+member.filename,depth+1)
    # Materialize before publishing so a hostile later member cannot hide a partial import.
    return parent_hash,list(walk(raw,str(path.resolve())))


def import_code(service,run,path,source=None,deadline=None):
    digest,entries=dex_inputs(path)
    if not entries:raise ValueError('No standalone DEX entries in input')
    result=[]
    for origin,data in entries:
        remaining=deadline-time.monotonic() if deadline is not None else 60
        if remaining<=0:raise TimeoutError('Pre-launch static analysis time budget exhausted')
        if source and source.get('device_path'):
            origin=source['device_path']+('!'+origin.split('!',1)[1] if '!' in origin else '')
        snapshot=service.store.import_static(run,data,{'origin':origin,'container_sha256':digest,
            'input_kind':'analyst_supplied_code','execution':'not_established','limitations':['Supplied code has not been verified against the running process'],**(source or {}),'index_timeout_seconds':min(60,remaining)})
        job=service.analyze(snapshot,'code.references')
        result.append({'snapshot':snapshot,'analysis':job['id'],'state':job['state'],'validity':job['result'].get('validity')})
    return {'input_sha256':digest,'artifacts':result,'execution':'not_established'}


def search(service,run,query='',limit=100,since_ns=0,include='',exclude=''):
    from .search_filters import query_filters,matches,classes
    query,include,exclude=query_filters(query,include,exclude)
    if type(since_ns) is not int or since_ns<0:raise ValueError('Invalid search time boundary')
    if not isinstance(query,str) or len(query)>2048:raise ValueError('Search text must be at most 2048 characters')
    if type(limit) is not int or not 1<=limit<=200:raise ValueError('Search result limit must be 1..200')
    service.store.one('SELECT id FROM runs WHERE id=?',(run,))
    analyses=service.store.rows("SELECT a.id,a.snapshot_id,length(a.result) AS result_size,s.hash,s.metadata FROM analyses a JOIN snapshots s ON s.id=a.snapshot_id WHERE s.run_id=? AND a.handler='code.references' AND a.state='complete' ORDER BY a.started_ns DESC LIMIT 64",(run,))
    query_fold=query.casefold();hits=[];edges=[];methods={};class_rows=[];seen=set();diagnostics=[];index_bytes=0;index_limited=False
    literals={}
    for analysis in analyses:
        if analysis['snapshot_id'] in seen:continue
        seen.add(analysis['snapshot_id'])
        if index_bytes+analysis['result_size']>32*1024**2:
            index_limited=True;diagnostics.append({'snapshot':analysis['snapshot_id'],'diagnostic':'search_index_byte_budget'});continue
        index_bytes+=analysis['result_size']
        result=json.loads(service.store.one('SELECT result FROM analyses WHERE id=?',(analysis['id'],))['result']);origin=json.loads(analysis['metadata']).get('origin')
        if result.get('validity')!='indexed':diagnostics.append({'snapshot':analysis['snapshot_id'],'diagnostic':result.get('diagnostic',result.get('validity'))});continue
        prefix=analysis['snapshot_id']+':'
        defined=set(result.get('defined_methods',[]))
        for cls in result.get('classes',[]):
            if matches(cls,include,exclude):class_rows.append((analysis,cls))
        for edge in result.get('edges',[]):
            if not all(matches({'method':edge[end]},include,exclude) for end in ('from','to')):continue
            source=prefix+edge['from'];target=prefix+edge['to']
            edges.append({**edge,'from':source,'to':target,'label':edge.get('basis'),'snapshot':analysis['snapshot_id']})
            for node,method in [(source,edge['from']),(target,edge['to'])]:methods[node]={'id':node,'label':method,'kind':'static_method' if method in defined else 'static_external_reference','snapshot':analysis['snapshot_id'],'origin':origin,'executed':'not_established','definition':'present_in_snapshot' if method in defined else 'reference_only'}
        for site in result.get('sites',[]):
            if not matches(site,include,exclude):continue
            if site['kind'] in ('string_literal','field_literal') and isinstance(site.get('value'),str):
                literals.setdefault(site['value'],[]).append({**site,'snapshot':analysis['snapshot_id'],'origin':origin,'sha256':analysis['hash']})
            if query_fold and query_fold not in json.dumps(site,ensure_ascii=False).casefold():continue
            if not query_fold and site['kind'] not in ('decoded_string','stringfog_candidate','reflective_call','reflective_instantiation','xor_candidate','webview_navigation','webview_client','custom_tab'):continue
            value={**site,'snapshot':analysis['snapshot_id'],'sha256':analysis['hash'],'origin':origin,'analysis':analysis['id']}
            value['id']=prefix+site['method']+'@'+str(site['offset'])+':'+site['kind']
            value['node']=prefix+site['method'];hits.append(value)
            methods.setdefault(value['node'],{'id':value['node'],'label':site['method'],'kind':'static_method','snapshot':analysis['snapshot_id'],'origin':origin,'executed':'not_established'})
    # Preserve class declaration evidence even when construction is only reflective.
    for analysis,cls in class_rows:
        if cls.get('webview_base'):
            if query_fold and query_fold not in json.dumps(cls).casefold():continue
            hits.append({**cls,'id':analysis['snapshot_id']+':'+cls['descriptor'],'kind':'custom_webview_class','snapshot':analysis['snapshot_id'],'sha256':analysis['hash']})
    total=len(hits);hits=hits[:limit]
    roots={h['node'] for h in hits if 'node' in h};nodes=set(sorted(roots)[:96]);selected_edges=[]
    adjacent={}
    for edge in edges:
        adjacent.setdefault(edge['from'],[]).append(edge);adjacent.setdefault(edge['to'],[]).append(edge)
    frontier=list(nodes)
    for _ in range(5):
        next_nodes=[]
        for node in frontier:
            for edge in adjacent.get(node,[]):
                other=edge['to'] if edge['from']==node else edge['from']
                if other in nodes:continue
                if len(nodes)>=96:break
                nodes.add(other);next_nodes.append(other)
        frontier=next_nodes
    selected_edges=[e for e in edges if e['from'] in nodes and e['to'] in nodes][:256]
    runtime=[]
    observed_flow=None
    if query:
        matching_events=set();scanned_bytes=0
        for snap in service.store.rows("SELECT id,process_id,received,metadata FROM snapshots WHERE run_id=? AND time_ns>? AND kind='trace_payload' AND status='captured' ORDER BY time_ns DESC LIMIT 256",(run,since_ns)):
            if scanned_bytes+snap['received']>8*1024**2:continue
            _,content=service.store.read(snap['id']);scanned_bytes+=len(content)
            if query_fold in content.decode('utf-8','replace').casefold():
                correlation=json.loads(snap['metadata']).get('correlation')
                if correlation:matching_events.add((snap['process_id'],correlation))
        rows=service.store.rows('SELECT * FROM observations WHERE run_id=? AND time_ns>? ORDER BY sequence DESC LIMIT 10000',(run,since_ns))
        for row in rows:
            if not matches(row,include,exclude):continue
            data=json.loads(row['data'])
            retained_match=(row['process_id'],data.get('id')) in matching_events
            if not retained_match and query_fold not in json.dumps(data,ensure_ascii=False).casefold():continue
            runtime.append({'id':row['id'],'kind':row['kind'],'process':row['process_id'],'package_classes':classes(row),'data':data,'basis':'retained_payload_text_match' if retained_match else 'observed_event_text_match'})
            if row['kind'] in ('crypto.doFinal','crypto.custom','crypto.update','crypto.base64'):
                from .evidence import retained_value,callers
                values={name:retained_value(service.store,run,row['process_id'],data.get(name),8192) for name in ('input','output','key')}
                definitions=[]
                for role in ('input','key'):
                    for value in {values[role].get('utf8'),values[role].get('base64')} - {None}:
                        definitions.extend({**site,'role':role} for site in literals.get(value,[])[:32])
                runtime[-1]['string_mapping']={**values,'algorithm':data.get('algorithm'),'mode':data.get('mode'),
                    'caller':callers(data)['primary_app_caller'],'definition_sites':definitions[:64],
                    'definition_basis':'Literal equality is an inferred association, not proof of data flow' if definitions else 'No matching literal definition established; value may be constructed or loaded at runtime',
                    'decoder_classification':'observed_transformation; StringFog identity not established'}
            if len(runtime)>=100:break
        if runtime:
            selected=next((r for r in runtime if r['kind'] in ('webview.loadUrl','webview.custom_tab','webview.custom_tab_intent') or str(r['data'].get('navigation_kind','')).startswith('custom_tab')),runtime[0])
            observed_flow=service.evidence(run,selected['id'],include=include,exclude=exclude)['flow']
            observed_flow['steps']=[step for step in observed_flow['steps'] if matches(step,include,exclude)]
            retained={step['event'] for step in observed_flow['steps']}
            observed_flow['edges']=[edge for edge in observed_flow['edges'] if edge['from'] in retained and edge['to'] in retained]
            observed_flow['package_filters']={'include':include,'exclude':exclude}
    graph_nodes=[methods[n] for n in sorted(nodes) if n in methods]
    # Runtime matches are linked by explicit text association, not asserted data flow.
    for row in runtime[:24]:
        node='event:'+row['id'];graph_nodes.append({'id':node,'label':row['kind'],'kind':'runtime_event','observation':row['id']})
        for root in sorted(roots)[:4]:selected_edges.append({'from':root,'to':node,'basis':'search_text_association_only','label':'matching search text; not causality'})
    return {'query':query,'static_hits':hits,'runtime_hits':runtime,'static_hit_count':total,'indexed_snapshots':len(seen),'diagnostics':diagnostics,
        'graph':{'nodes':graph_nodes,'edges':selected_edges,'limits':{'nodes':96,'edges':256,'hops':5,'runtime_nodes':24}},'observed_flow':observed_flow,
        'limitations':['Static graph edges are code references, not runtime/data-flow proof','Supplied DEX identity is not automatically associated with the installed APK',
         'Runtime search examines the latest 10000 observations; exact defining class may be unavailable for constructed/server/native strings',
         'Retained text search examines up to 256 recent payload snapshots and 8 MiB; binary/encrypted text requires an observed or statically recovered decoder output',
         'Substring matches are search associations, not proof of a request-response relationship'],
        'truncated':total>limit or len(nodes)>=96 or len(analyses)>=64 or index_limited}


def scope_pack(service,run,snapshot,method,decoder=False):
    from .model import Pack
    row=service.store.one('SELECT run_id FROM snapshots WHERE id=?',(snapshot,))
    if row['run_id']!=run:raise ValueError('Artifact belongs to another Run')
    results=service.store.rows("SELECT result FROM analyses WHERE snapshot_id=? AND handler='code.references' AND state='complete' ORDER BY started_ns DESC LIMIT 1",(snapshot,))
    if not results:raise ValueError('Index this snapshot first')
    result=json.loads(results[0]['result']);sites=result.get('sites',[])
    allowed={s['method'] for s in sites}
    if decoder:allowed={s['method'] for s in sites if s['kind']=='xor_candidate'}|{s.get('decoder') for s in sites if s['kind']=='decoded_string'}
    if method not in allowed:raise ValueError('Method is not an indexed '+('decoder candidate' if decoder else 'reference site'))
    match=re.fullmatch(r'L([^;]+);->([^()]+)\(.*\).*',method)
    if not match:raise ValueError('Select a method, not a field or class declaration')
    selector={'class':match[1].replace('/','.'),'method':'$init' if match[2]=='<init>' else match[2]}
    raw=json.loads(service.store.one('SELECT pack FROM runs WHERE id=?',(run,))['pack'])
    capability='crypto.custom' if decoder else 'flow.java'
    token=next((t for t in raw['tokens'] if t['capability']==capability),None)
    if token is None:
        names={t['name'] for t in raw['tokens']};name='selected-decoder' if decoder else 'selected-code-flow'
        while name in names:name+='x'
        token={'name':name,'capability':capability,'mode':'observe','trigger':'call','handlers':[],'selection':{}};raw['tokens'].append(token)
    methods=token.setdefault('selection',{}).setdefault('methods',[])
    if selector not in methods:methods.append(selector)
    raw['id']=raw['id'][:80]+'.code-scope'
    return Pack.parse(raw).json()
