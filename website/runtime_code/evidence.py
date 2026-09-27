"""Bounded, backend-neutral presentation of observed provenance and crypto bytes."""
import base64
import json
import ipaddress
import re

SYSTEM_PREFIXES=('android.','androidx.','java.','javax.','sun.','dalvik.','libcore.','com.android.','org.json.','kotlin.','kotlinx.')


def retained_value(store,run,process,reference,limit=8192):
    value=dict(reference) if isinstance(reference,dict) else {'status':'unavailable'}
    digest=value.get('sha256')
    if not digest:return value
    rows=store.rows("SELECT id FROM snapshots WHERE run_id=? AND process_id IS ? AND hash=? AND status='captured' ORDER BY time_ns LIMIT 1",(run,process,digest))
    if not rows:return {**value,'status':'unavailable','reason':'Matching bytes not retained or transfer not published yet'}
    try:
        snapshot=rows[0]['id'];_,raw=store.read(snapshot);prefix=raw[:limit]
        try:text=prefix.decode('utf-8')
        except UnicodeDecodeError:text=None
        value.update(snapshot=snapshot,hex=prefix.hex(),base64=base64.b64encode(prefix).decode(),utf8=text,
                     display_truncated=len(raw)>limit,display_bytes=len(prefix))
    except (ValueError,OSError) as error:value.update(status='unavailable',reason=str(error))
    return value


def crypto_values(store,row,limit=8192):
    data=json.loads(row['data']) if isinstance(row['data'],str) else row['data']
    return {name:retained_value(store,row['run_id'],row['process_id'],data.get(name),limit) for name in ('input','output')}


def navigation(data):
    """Normalize both saved legacy callbacks and current structured callbacks."""
    result=dict(data);api=data.get('api','');args=data.get('arguments',[])
    failed=any('.'+name+'(' in api for name in ('onReceivedError','onReceivedHttpError','onReceivedSslError'))
    if '.onReceivedError(' in api and len(args)>=4:
        result.update(url=data.get('url') or args[3],error_code=data.get('error_code',args[1]),
                      error_description=data.get('error_description',args[2]))
    elif any('.'+name+'(' in api for name in ('onPageStarted','onPageFinished')) and len(args)>1:
        result['url']=data.get('url') or args[1]
    if failed:result.update(navigation_outcome='failed',failure_basis='observed_webview_error_callback')
    if failed:result['network_category']='failed_webview_request'
    elif any('.'+name+'(' in api for name in ('loadUrl','postUrl','launchUrl')):
        result['url']=result.get('url') or (args[0] if args else None)
        if isinstance(result['url'],str) and result['url'].startswith(('https://','http://')):
            result['network_category']='navigation_intent'
            result['network_status']='Observed navigation request; transport success is not established'
    elif result.get('url') and any('.'+name+'(' in api for name in ('onPageStarted','onPageFinished','shouldInterceptRequest','shouldOverrideUrlLoading')):
        result['network_category']='webview_callback'
    return result


def network_summary(data,raw=None):
    endpoint=data.get('endpoint');peer=endpoint if isinstance(endpoint,str) else None
    address=endpoint if isinstance(endpoint,dict) else {}
    ip=address.get('ip');port=address.get('port')
    if not ip and address.get('address_hex'):
        try:
            value=bytes.fromhex(address['address_hex']);port=int.from_bytes(value[2:4],'big')
            ip=str(ipaddress.ip_address(value[4:8] if address.get('family')==2 else value[8:24]))
        except (ValueError,TypeError):pass
    if ip:peer=('['+ip+']' if ':' in ip else ip)+(':'+str(port) if port is not None else '')
    result={'peer':peer,'ip':ip,'port':port,'url':data.get('url'),'direction':data.get('direction'),
            'url_status':'observed' if data.get('url') else 'not_observed'}
    if raw:
        header=raw[:16384].split(b'\r\n\r\n',1)[0].decode('latin1')
        first=header.split('\r\n',1)[0]
        request=re.fullmatch(r'(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) ([^\s]{1,4096}) HTTP/1\.[01]',first)
        if request:
            result.update(method=request[1],request_target=request[2],protocol='HTTP/1')
            host=re.search(r'^Host:\s*([^\r\n]{1,512})',header,re.M|re.I)
            if host:result['host']=host[1].strip()
            if request[2].startswith(('http://','https://')):result.update(url=request[2],url_status='observed_absolute_request_target')
            elif host:result.update(destination=host[1].strip()+request[2],url_status='host_and_target_observed_scheme_unknown')
        elif re.match(r'^HTTP/1\.[01] [0-9]{3}',first):result.update(status_line=first,protocol='HTTP/1')
    return result


def decoded(record):
    result=dict(record)
    for key in ('data','metadata','result','coverage','pack'):
        if isinstance(result.get(key),str):
            try:result[key]=json.loads(result[key])
            except (ValueError,RecursionError):pass
    return result


def callers(data):
    frames=data.get('caller',[])
    if not isinstance(frames,list):frames=[]
    app=[];platform=[]
    for frame in frames:
        if not isinstance(frame,dict):continue
        origin=frame.get('origin') or '';name=frame.get('class') or ''
        system=origin.startswith(('/system/','/apex/','/vendor/')) or name.startswith(SYSTEM_PREFIXES)
        item={**frame,'jadx_search':name+'.'+(frame.get('method') or ''),'classification':'platform_or_support_library' if system else 'app_or_bundled_library'}
        (platform if system else app).append(item)
    first=next((i for i,f in enumerate(frames) if isinstance(f,dict) and app and f.get('class')==app[0].get('class') and f.get('method')==app[0].get('method')),None)
    immediate=frames[first+1] if first is not None and first+1<len(frames) else None
    outer=None
    if first is not None:
        primary=frames[first]
        outer=next((f for f in frames[first+1:] if isinstance(f,dict) and (f.get('class'),f.get('method'),f.get('signature'))!=(primary.get('class'),primary.get('method'),primary.get('signature'))),None)
    chain=[]
    for index,frame in enumerate(reversed([f for f in frames if isinstance(f,dict)])):
        chain.append({**frame,'label':(frame.get('class') or '?')+'.'+(frame.get('method') or '?')})
    return {'app_callers':app,'call_chain':chain,'primary_app_caller':app[0] if app else None,
            'primary_app_caller_called_by':immediate,'primary_app_caller_next_distinct':outer,
            'call_chain_basis':'Observed synchronous stack at this boundary; folded app frames are not necessarily adjacent calls','platform_callers':platform,'classification_basis':'Origin path and visible namespace heuristic; bundled libraries can appear as app code',
            'attribution': 'observed_stack' if frames else 'unattributed',
            'native_caller':data.get('native_caller')}


def links(data):
    for field in ('parent','init_event','previous_cipher_event','parse'):
        if isinstance(data.get(field),str):yield data[field],field,'observed_nested_invocation' if field=='parent' else 'observed_reference'
    for field in ('input','output','payload','key','iv','url_origin','launch_source','context_source','client_source','client_origin','chrome_client_source','connection_source','navigation_source'):
        value=data.get(field)
        if not isinstance(value,dict):continue
        source=value.get('source',value)
        if isinstance(source,dict) and isinstance(source.get('event'),str):
            yield source['event'],field,source.get('association','inferred_equal_bytes')

    for source in data.get('intent_sources',[]):
        if isinstance(source,dict) and isinstance(source.get('event'),str):
            yield source['event'],'intent_extra',source.get('association','inferred_equal_bytes')

    for link in data.get('data_links',[]):
        if isinstance(link,dict) and isinstance(link.get('event'),str):
            yield link['event'],link.get('path','object'),link.get('association','unattributed')
    for index,value in enumerate(data.get('parameters',[])):
        source=value.get('source',{}) if isinstance(value,dict) else {}
        if isinstance(source.get('event'),str):yield source['event'],'argument['+str(index)+']',source.get('association','inferred_equal_bytes')


def object_paths(data):
    found=[]
    def walk(value,phase):
        if len(found)>=96 or not isinstance(value,dict):return
        item={k:value[k] for k in ('path','object_id','class','type','preview','sha256','status','identity_basis') if k in value}
        item['phase']=phase;found.append(item)
        for field in value.get('fields',[]):walk(field.get('value',field),phase)
    for phase in ('objects_before','objects_after'):
        for item in data.get(phase,[]):walk(item,phase)
    return found


def detail(service,run,observation):
    store=service.store
    row=store.one('SELECT * FROM observations WHERE run_id=? AND id=?',(run,observation));data=navigation(json.loads(row['data']))
    row={**row,'data':json.dumps(data)}
    presentation={'record':decoded(row),**callers(data)}
    if row['kind'].startswith('network.'):
        presentation['network']=service.present_event(row)['summary']['network']
    # Scope identities to a process instance; agent counters can repeat after restart.
    rows=store.rows('SELECT * FROM observations WHERE run_id=? AND process_id IS ? ORDER BY sequence DESC LIMIT 10000',(run,row['process_id']))
    nodes={}
    for item in rows:
        payload=json.loads(item['data'])
        if isinstance(payload.get('id'),str):nodes[payload['id']]=(item,payload)
    enclosing=[];cursor=data.get('parent');visited=set()
    while cursor and cursor not in visited and len(enclosing)<48:
        visited.add(cursor);entry=nodes.get(cursor)
        if not entry:break
        item,value=entry;enclosing.append({'event':cursor,'api':value.get('api'),'kind':item['kind'],'observation':item['id']});cursor=value.get('parent')
    presentation['enclosing_invocations']=enclosing
    root=data.get('id')
    if root and root not in nodes:nodes[root]=(row,data)
    ancestors={root} if root else set();front=list(ancestors);edges=[]
    while front and len(ancestors)<128:
        current=front.pop();entry=nodes.get(current)
        if not entry:continue
        for source,via,basis in links(entry[1]):
            if source==current:continue
            edges.append({'from':source,'to':current,'via':via,'basis':basis})
            if source not in ancestors and len(ancestors)<128:ancestors.add(source);front.append(source)
    ancestor_limited=bool(front) or len(ancestors)>=128
    # Follow downstream handoffs as well as upstream sources, with bounded traversal.
    outgoing={}
    for key,(_,value) in nodes.items():
        for source,via,basis in links(value):
            if key!=source:outgoing.setdefault(source,[]).append((key,via,basis))
    # Include observed children of upstream producers: a request and a parser may
    # be sibling calls inside the same producer. Root-only traversal hid them.
    consumers=set();front=sorted(ancestors)
    while front and len(consumers)<128:
        source=front.pop()
        for key,via,basis in outgoing.get(source,[]):
            edges.append({'from':source,'to':key,'via':via,'basis':basis})
            if key not in consumers and key!=root:
                consumers.add(key);front.append(key)
                if len(consumers)>=128:break
    descendant_limited=bool(front) or len(consumers)>=128
    unique={tuple(e.values()):e for e in edges};edges=list(unique.values())
    steps=[]
    for key in ancestors|consumers:
        if key not in nodes:continue
        item,payload=nodes[key];payload=navigation(payload);frames=callers(payload)['app_callers']
        steps.append({'event':key,'observation':item['id'],'kind':item['kind'],'sequence':item['sequence'],
                      'started_ms':payload.get('started_ms',payload.get('agent_time_ms',0)),
                      'api':payload.get('api'),'url':payload.get('url'),'app_caller':frames[0] if frames else None,
                      'navigation_outcome':payload.get('navigation_outcome'),
                      'method_kind':payload.get('method_kind'),'objects':object_paths(payload)})
        from .search_filters import classes
        steps[-1]['package_classes']=classes({'data':payload})
    presentation['object_observations']=object_paths(data)
    presentation['flow']={'steps':sorted(steps,key=lambda s:(s['started_ms'],s['sequence'])),'edges':edges,
       'missing_references':sorted({e['from'] for e in edges if e['from'] not in nodes}),
       'coverage':{'event_window_limited':len(rows)>=10000,'ancestor_limit_reached':ancestor_limited,'descendant_limit_reached':descendant_limited},
       'limits':'Most recent 10000 process events; at most 128 ancestors and 128 downstream events. Stack, call nesting, same-object references and equal-byte inference are distinct. Field snapshots do not establish bytecode field reads.'}
    if row['kind'].startswith('crypto.'):
        values={}
        references={label:data.get(label) for label in ('input','output','key','iv')}
        references.update({'argument['+str(i)+']':value for i,value in enumerate(data.get('parameters',[])[:8])})
        for label,reference in references.items():
            value=retained_value(store,run,row['process_id'],reference)
            values[label]=value
        presentation['crypto']={'operation':row['kind'],'algorithm':data.get('algorithm'),'mode':data.get('mode'),'direction':data.get('direction'),
                                'init_event':data.get('init_event'),'values':values}
    return presentation
