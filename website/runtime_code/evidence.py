"""Bounded, backend-neutral presentation of observed provenance and crypto bytes."""
import base64
import hashlib
import json
import ipaddress
import re

SYSTEM_PREFIXES=('android.','androidx.','java.','javax.','sun.','dalvik.','libcore.','com.android.','org.json.','kotlin.','kotlinx.')


def retained_value(store,run,process,reference,limit=8192):
    value=dict(reference) if isinstance(reference,dict) else {'status':'unavailable','reason':'Not observed at this boundary'}
    digest=value.get('sha256')
    if not digest:return value
    rows=store.rows("SELECT id FROM snapshots WHERE run_id=? AND process_id IS ? AND hash=? AND status='captured' ORDER BY time_ns LIMIT 1",(run,process,digest))
    if not rows:return {**value,'status':'unavailable','reason':'Matching bytes not retained or transfer not published yet'}
    try:
        snapshot=rows[0]['id'];_,raw=store.read(snapshot);prefix=raw[:limit]
        try:text=prefix.decode('utf-8')
        except UnicodeDecodeError:text=None
        value.update(status='captured',snapshot=snapshot,hex=prefix.hex(),base64=base64.b64encode(prefix).decode(),utf8=text,
                     display_truncated=len(raw)>limit,display_bytes=len(prefix))
    except (ValueError,OSError) as error:value.update(status='unavailable',reason=str(error))
    return value


def crypto_values(store,row,limit=8192,nodes=None):
    data=json.loads(row['data']) if isinstance(row['data'],str) else row['data']
    needs_init=data.get('init_event') and any(name not in data for name in ('key','iv'))
    if nodes is None and (needs_init or row['kind']=='crypto.doFinal' and data.get('previous_cipher_event')):
        rows=store.rows("SELECT * FROM observations WHERE run_id=? AND process_id IS ? AND sequence<=? AND kind LIKE 'crypto.%' ORDER BY sequence DESC LIMIT 1000",(row['run_id'],row['process_id'],row['sequence']))
        nodes={json.loads(r['data']).get('id'):(r,json.loads(r['data'])) for r in rows}
    nodes=nodes or {}
    init=nodes.get(data.get('init_event'),({},{}))[1]
    values={name:retained_value(store,row['run_id'],row['process_id'],data.get(name,init.get(name)),limit) for name in ('input','output','key','iv')}
    if row['kind']=='crypto.init':
        for name in ('input','output'):values[name]={'status':'not_applicable','reason':'Initialization configures the cipher; data is observed at update/doFinal'}
    if row['kind']=='crypto.base64':
        for name in ('key','iv'):values[name]={'status':'not_applicable','reason':'Base64 decoding does not use a cryptographic '+name}
    # Assemble only a verified same-Cipher chain, stopping at its previous final.
    if row['kind']=='crypto.doFinal' and data.get('previous_cipher_event'):
        values['call_input']=values['input'];values['call_output']=values['output']
        parts=[];output_parts=[];cursor=data;seen=set();complete=True;output_complete=True
        while len(seen)<64:
            if cursor.get('id') in seen:complete=False;break
            seen.add(cursor.get('id'))
            if cursor.get('kind',row['kind'])!='crypto.updateAAD':
                ref=cursor.get('input',{})
                if ref.get('sha256'):parts.append(retained_value(store,row['run_id'],row['process_id'],ref,limit))
                elif not ref.get('status') in ('absent','no_input') and not ref.get('reason','').startswith('Input from previous update'):complete=False
                ref=cursor.get('output',{})
                if ref.get('sha256'):output_parts.append(retained_value(store,row['run_id'],row['process_id'],ref,limit))
                elif ref.get('status')!='absent':output_complete=False
            previous=cursor.get('previous_cipher_event')
            if not previous:break
            entry=nodes.get(previous)
            if not entry:complete=False;break
            prior_row,prior=entry
            if prior_row['kind']=='crypto.doFinal':break
            if prior.get('cipher')!=data.get('cipher') or prior.get('init_event')!=data.get('init_event'):complete=False;break
            cursor={**prior,'kind':prior_row['kind']}
        else:complete=False
        if parts and complete and all(p.get('snapshot') and not p.get('truncated') for p in parts):
            raw=b''.join(store.read(p['snapshot'])[1] for p in reversed(parts))
            if len(raw)<=4*1024**2:
                prefix=raw[:limit]
                try:text=prefix.decode('utf-8')
                except UnicodeDecodeError:text=None
                values['input']={'status':'captured','basis':'ordered_same_cipher_input_fragments','snapshots':[p['snapshot'] for p in reversed(parts)],'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hex':prefix.hex(),'base64':base64.b64encode(prefix).decode(),'utf8':text,'display_truncated':len(raw)>limit,'display_bytes':len(prefix)}
        elif parts:
            values['input']={**values['input'],'status':'partial','reason':'Streamed input chain has missing, truncated or unretained fragments','fragments':[p.get('snapshot') for p in reversed(parts)]}
        if output_parts and complete and output_complete and all(p.get('snapshot') and not p.get('truncated') for p in output_parts):
            raw=b''.join(store.read(p['snapshot'])[1] for p in reversed(output_parts));prefix=raw[:limit]
            try:text=prefix.decode('utf-8')
            except UnicodeDecodeError:text=None
            if len(raw)<=4*1024**2:values['output']={'status':'captured','basis':'ordered_same_cipher_output_fragments','snapshots':[p['snapshot'] for p in reversed(output_parts)],'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hex':prefix.hex(),'base64':base64.b64encode(prefix).decode(),'utf8':text,'display_truncated':len(raw)>limit,'display_bytes':len(prefix)}
        elif output_parts:values['output']={**values['output'],'status':'partial','reason':'Streamed output chain has missing, truncated or unretained fragments'}
    return values


def navigation(data):
    """Normalize both saved legacy callbacks and current structured callbacks."""
    result=dict(data);api=data.get('api') or '';args=data.get('arguments',[])
    tab=str(data.get('navigation_kind','')).startswith('custom_tab') or '.customtabs.' in api or str(data.get('kind','')).startswith('webview.custom_tab')
    if tab:
        category=data.get('navigation_kind','custom_tab_launch' if '.launchUrl(' in api else 'custom_tab_context')
        result['navigation_kind']=category
        if category in ('custom_tab_launch','custom_tab_intent'):
            result['network_category']='navigation_intent'
            result['network_status']='Observed Custom Tab launch request; browser transport success is not established'
            if data.get('outcome')=='threw':result.update(navigation_outcome='failed',failure_basis='observed_custom_tab_launch_exception')
        elif category=='custom_tab_callback':
            result['network_category']='custom_tab_callback'
            event=data.get('navigation_event')
            if event in (1,2,3,4,5,6):result['navigation_outcome']={1:'started',2:'finished',3:'failed',4:'aborted',5:'shown',6:'hidden'}[event]
            if event==3:result['failure_basis']='observed_custom_tabs_navigation_failed_callback'
        else:result['network_category']=category
        return result
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
    for field in ('input','output','payload','key','iv','url_origin','launch_source','context_source','client_source','client_origin','chrome_client_source','connection_source','navigation_source','session_source','callback_source','builder_source','intent_source'):
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


def detail(service,run,observation,depth=8,include='',exclude=''):
    from .search_filters import patterns,matches,classes
    if type(depth) is not int or not 1<=depth<=8:raise ValueError('Flow depth must be 1..8')
    include=patterns(include);exclude=patterns(exclude,exclusion=True)
    store=service.store
    row=store.one('SELECT * FROM observations WHERE run_id=? AND id=?',(run,observation));data=navigation(json.loads(row['data']))
    row={**row,'data':json.dumps(data)}
    presentation={'record':decoded(row),**callers(data)}
    def allowed(payload):return matches({'data':payload},(),exclude)
    def visible_frames(payload):return [f for f in callers(payload)['app_callers'] if matches(f,(),exclude)]
    if exclude:
        frames=data.get('caller',[]);frames=frames if isinstance(frames,list) else []
        filtered={**data,'caller':[f for f in frames if isinstance(f,dict) and matches(f,(),exclude)]}
        presentation.update(callers(filtered))
    presentation['app_callers']=visible_frames(data)
    presentation['call_chain']=[f for f in presentation['call_chain'] if matches(f,(),exclude)]
    if row['kind'].startswith('network.'):
        presentation['network']=service.present_event(row)['summary']['network']
    # Scope identities to a process instance; agent counters can repeat after restart.
    rows=store.rows('SELECT * FROM observations WHERE run_id=? AND process_id IS ? ORDER BY sequence DESC LIMIT 10000',(run,row['process_id']))
    nodes={}
    for item in rows:
        payload=json.loads(item['data'])
        if isinstance(payload.get('id'),str):nodes[payload['id']]=(item,payload)
    enclosing=[];cursor=data.get('parent');visited=set()
    while cursor and cursor not in visited and len(enclosing)<depth:
        visited.add(cursor);entry=nodes.get(cursor)
        if not entry:break
        item,value=entry
        if not allowed(value):break
        enclosing.append({'event':cursor,'api':value.get('api'),'kind':item['kind'],'observation':item['id']});cursor=value.get('parent')
    presentation['enclosing_invocations']=enclosing
    root=data.get('id')
    if root and root not in nodes:nodes[root]=(row,data)
    adjacent={};all_edges=[]
    for key,(_,value) in nodes.items():
        if not allowed(value):continue
        for source,via,basis in links(value):
            if key==source or (source in nodes and not allowed(nodes[source][1])):continue
            edge={'from':source,'to':key,'via':via,'basis':basis};all_edges.append(edge)
            adjacent.setdefault(source,[]).append(key);adjacent.setdefault(key,[]).append(source)
    reached={root} if root and allowed(data) else set();front=list(reached)
    for _ in range(depth):
        following=[]
        for current in front:
            for neighbor in adjacent.get(current,[]):
                if neighbor in reached or len(reached)>=256:continue
                reached.add(neighbor);following.append(neighbor)
        front=following
        if not front:break
    depth_limited=any(n not in reached for key in front for n in adjacent.get(key,[]))
    edges=list({tuple(e.values()):e for e in all_edges if e['from'] in reached and e['to'] in reached}.values())
    steps=[]
    for key in reached:
        if key not in nodes:continue
        item,payload=nodes[key];payload=navigation(payload);frames=visible_frames(payload)
        if include and not matches({'data':payload},include,()):continue
        steps.append({'event':key,'observation':item['id'],'kind':item['kind'],'sequence':item['sequence'],
                      'started_ms':payload.get('started_ms',payload.get('agent_time_ms',0)),
                      'api':payload.get('api'),'url':payload.get('url'),'app_caller':frames[0] if frames else None,
                      'navigation_outcome':payload.get('navigation_outcome'),
                      'navigation_kind':payload.get('navigation_kind'),'navigation_event':payload.get('navigation_event'),'url_basis':payload.get('url_basis'),
                      'method_kind':payload.get('method_kind'),'objects':object_paths(payload)})
        steps[-1]['package_classes']=classes({'data':payload})
    retained={s['event'] for s in steps}
    edges=[e for e in edges if e['to'] in retained and (e['from'] in retained or e['from'] not in nodes)]
    presentation['object_observations']=object_paths(data)
    presentation['flow']={'steps':sorted(steps,key=lambda s:(s['started_ms'],s['sequence'])),'edges':edges,
       'missing_references':sorted({e['from'] for e in edges if e['from'] not in nodes}),
       'coverage':{'event_window_limited':len(rows)>=10000,'depth_limit_reached':depth_limited,'node_limit_reached':len(reached)>=256},
       'depth':depth,'package_filters':{'include':include,'exclude':exclude},
       'limits':'Most recent 10000 process events; up to 256 nodes. Calls, same-object references and equal-byte inference are distinct.'}
    if row['kind'].startswith('crypto.'):
        values=crypto_values(store,row,nodes=nodes)
        values.update({'argument['+str(i)+']':retained_value(store,run,row['process_id'],value) for i,value in enumerate(data.get('parameters',[])[:8])})
        init=nodes.get(data.get('init_event'),({},{}))[1];mode=data.get('mode',init.get('mode'))
        for name in ('key','iv'):
            if row['kind'] in ('crypto.custom','crypto.string') and values[name].get('reason')=='Not observed at this boundary':values[name]['reason']='Argument roles are unverified; inspect the captured arguments' if row['kind']=='crypto.custom' else 'String conversion has no observed cryptographic '+name+' role'
        if row['kind']=='crypto.init':
            for name in ('input','output'):values[name]={'status':'not_applicable','reason':'Initialization configures the cipher; data is observed at update/doFinal'}
        presentation['crypto']={'operation':row['kind'],'algorithm':data.get('algorithm',init.get('algorithm')),'mode':mode,'direction':data.get('direction') or ('decrypt' if mode==2 else 'encrypt' if mode==1 else None),
                                'init_event':data.get('init_event'),'values':values}
    # Same app frames/classes offer investigative leads, not request/response proof.
    roots=visible_frames(data)[:depth];methods={(f.get('class'),f.get('method')) for f in roots};root_classes={f.get('class') for f in roots}
    candidates=[];navigation_candidates=[];schema={}
    for field_row,field in nodes.values():
        if field_row['kind']=='parser.field' and allowed(field):
            bucket=schema.setdefault(field.get('parse'),[])
            if len(bucket)<32:bucket.append({k:field[k] for k in ('path','expected_type','access_state','reaction') if k in field})
    for item,payload in nodes.values():
        payload=navigation(payload)
        nav_event=item['kind'] in ('webview.loadUrl','webview.postUrl','webview.loadData','webview.loadDataWithBaseURL') or payload.get('network_category') in ('navigation_intent','webview_callback','failed_webview_request','custom_tab_callback')
        if not (item['kind'].startswith(('network.','parser.')) or nav_event) or item['id']==observation or not allowed(payload):continue
        if include and not matches({'data':payload},include,()):continue
        frames=visible_frames(payload)[:depth];shared=[f for f in frames if (f.get('class'),f.get('method')) in methods]
        class_shared=sorted({f.get('class') for f in frames}&root_classes)
        if not shared and not class_shared:continue
        parse=payload.get('parse',payload.get('id'));fields=schema.get(parse,[])
        candidate={'observation':item['id'],'kind':item['kind'],'api':payload.get('api'),'url':payload.get('url'),
            'basis':'shared_app_stack_method' if shared else 'shared_app_class','shared':list(dict.fromkeys(f['jadx_search'] for f in shared)) or class_shared,
            'fields':fields,'distance_ns':abs(item['time_ns']-row['time_ns'])}
        if nav_event:candidate.update({k:payload[k] for k in ('navigation_kind','navigation_outcome','url_basis') if k in payload})
        (navigation_candidates if nav_event else candidates).append(candidate)
    presentation['network_context']=sorted(candidates,key=lambda c:(c['basis']!='shared_app_stack_method',c['distance_ns']))[:16]
    if row['kind'].startswith('network.'):
        from .discovery import static_connections
        static=static_connections(service,run,roots,depth,include,exclude)
        linked=[s for s in presentation['flow']['steps'] if s['kind'] in ('webview.loadUrl','webview.postUrl','webview.loadData','webview.loadDataWithBaseURL') or s.get('navigation_kind') in ('custom_tab_launch','custom_tab_intent','custom_tab_callback') or s.get('navigation_outcome')=='failed']
        related=sorted(navigation_candidates,key=lambda c:(c['basis']!='shared_app_stack_method',c['distance_ns']))[:8]
        presentation['request_backtracking']={'depth':depth,'callers':[f['jadx_search'] for f in roots],
            'status':'linked_navigation_observed' if linked else 'shared_navigation_candidate' if related else 'static_navigation_candidate' if static['navigation_paths'] else 'no_navigation_link_observed',
            'linked_navigation':[{k:v for k,v in {'observation':s['observation'],'kind':s['kind'],'url':s.get('url'),'url_basis':s.get('url_basis')}.items() if v is not None} for s in linked],
            'navigation_candidates':related,
            'static_connections':static,
            'note':'Checks retained links, app stack frames and bounded static call neighborhoods. Shared callers and static paths are investigative leads; a static path may contain a gate that prevented navigation.'}
    presentation['compact']=compact(presentation)
    return presentation


def compact(presentation):
    """Small graph contract for copy/paste; raw evidence remains separately available."""
    row=presentation['record'];data=row['data'];flow=presentation['flow']
    result={'selected':data.get('id',row['id']),'kind':row['kind'],
        'chain':[f.get('label',f.get('jadx_search')) for f in presentation['call_chain'][-16:]],
        'nodes':[{k:v for k,v in {'id':s['event'],'kind':s['kind'],'method':s.get('api'),'caller':(s.get('app_caller') or {}).get('jadx_search'),'url':s.get('url'),'outcome':s.get('navigation_outcome'),'navigation':s.get('navigation_kind'),'event':s.get('navigation_event'),'url_basis':s.get('url_basis')}.items() if v is not None} for s in flow['steps']],
        'edges':flow['edges'],'depth':flow['depth']}
    gaps={k:v for k,v in flow['coverage'].items() if v}
    if gaps:result['gaps']=gaps
    if flow['missing_references']:result['missing']=flow['missing_references']
    if presentation.get('network_context'):result['network_context']=[{k:v for k,v in c.items() if k!='distance_ns' and v} for c in presentation['network_context']]
    if presentation.get('request_backtracking'):
        backtrack=presentation['request_backtracking']
        result['request_backtracking']={'status':backtrack['status'],'depth':backtrack['depth'],
            'linked_navigation':[n['observation'] for n in backtrack['linked_navigation']],
            'navigation_candidates':[{k:v for k,v in n.items() if k in ('observation','kind','basis','shared','url','url_basis','navigation_kind','navigation_outcome') and v} for n in backtrack['navigation_candidates']]}
        static=backtrack.get('static_connections',{})
        if static.get('navigation_paths'):
            def method_label(method):
                return method.split('(',1)[0].removeprefix('L').replace(';->','.').replace('/','.')
            result['request_backtracking']['static_paths']=[{
                'methods':[method_label(m) for m in p['methods']],
                'links':p['links'],'target':method_label(p['target']),
                'gates':[{'method_index':p['methods'].index(g['method']),'offset':g['offset'],'opcode':g['opcode']} for g in p['gates']],
                'basis':p['basis']} for p in static['navigation_paths']]
    if presentation.get('crypto'):
        result['crypto']={k:presentation['crypto'][k] for k in ('algorithm','direction','mode') if presentation['crypto'].get(k) is not None}
        result['crypto']['values']={name:{k:v[k] for k in ('status','reason','sha256','length','basis') if k in v} for name,v in presentation['crypto']['values'].items() if not name.startswith('argument')}
    return result
