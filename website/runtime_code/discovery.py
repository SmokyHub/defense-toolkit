"""Bounded semantic method selection from the pre-launch DEX index, without mapping files."""
from collections import deque
import heapq
import json
import re

from .model import Pack
from .search_filters import matches, patterns

LIBRARIES=('android.','androidx.','java.','javax.','kotlin.','kotlinx.','dalvik.','libcore.','sun.','org.json.',
           'com.google.','com.facebook.','okhttp3.','okio.','retrofit2.','org.apache.')
METHOD=re.compile(r'^L([^;]+);->([^()]+)(\([^)]*\).+)$')
BOUNDARIES={'webview_navigation':0,'custom_tab':0,'network_boundary':1,'parser_boundary':1,
            'crypto_boundary':1,'xor_candidate':2,'decoded_string':2,'stringfog_candidate':2,'byte_string_conversion':2}


def selector(method,exclude=()):
    match=METHOD.fullmatch(method)
    if not match:return None
    owner,name,descriptor=match.groups();owner=owner.replace('/','.')
    if owner.startswith(LIBRARIES) or name in ('<clinit>','toString','hashCode','equals','finalize'):
        return None
    item={'class':owner,'method':'$init' if name=='<init>' else name}
    return item if matches(item,(),exclude) else None


def indexes(service,run):
    total=0;seen=set()
    rows=service.store.rows("SELECT a.id,a.snapshot_id,length(a.result) AS bytes,s.metadata FROM analyses a JOIN snapshots s ON s.id=a.snapshot_id WHERE s.run_id=? AND a.handler='code.references' AND a.state='complete' ORDER BY a.started_ns DESC LIMIT 64",(run,))
    for row in rows:
        if row['snapshot_id'] in seen:continue
        seen.add(row['snapshot_id']);total+=row['bytes']
        if total>32*1024**2:break
        result=json.loads(service.store.one('SELECT result FROM analyses WHERE id=?',(row['id'],))['result'])
        if result.get('validity')=='indexed':yield row['snapshot_id'],json.loads(row['metadata']),result


def automatic_pack(service,run,pack,heavy=False,exclude='',depth=8):
    excluded=patterns(exclude,exclusion=True);raw=pack.json();token=next(t for t in raw['tokens'] if t['capability']=='flow.java')
    definitions=set();edges=[];seeds={};base_hash=None;indexed=0;hierarchy={}
    for _,meta,index in indexes(service,run):
        indexed+=1;definitions.update(index.get('defined_methods',[]));edges.extend(index.get('edges',[]))
        hierarchy.update({c['descriptor']:c.get('superclass') for c in index.get('classes',[])})
        if meta.get('source_kind')=='installed_apk_copy' and meta.get('device_path','').endswith('/base.apk'):
            base_hash=meta.get('container_sha256')
        for site in index.get('sites',[]):
            rank=BOUNDARIES.get(site['kind'])
            if site['kind']=='xor_candidate':
                match=METHOD.fullmatch(site['method'])
                if not match or not match.group(3).endswith(('Ljava/lang/String;','[B')):continue
            if rank is not None:seeds[site['method']]=min(seeds.get(site['method'],rank),rank)
    callers={}
    for edge in edges:
        if edge.get('basis')=='static_invoke_reference':callers.setdefault(edge['to'],set()).add(edge['from'])
    # R8 may rename Kotlin/Compose helpers into the root package. Their names no
    # longer identify library ownership. Avoid ubiquitous hubs unless there is a
    # direct network/parser/navigation/decoder boundary in the method itself.
    hubs={m for m,cs in callers.items() if len(cs)>32 and seeds.get(m,3)>2}
    void_helpers={m for m in definitions if (match:=METHOD.fullmatch(m)) and match.group(3).endswith(')V') and seeds.get(m,3)!=0}
    generic_helpers=set()
    for method in definitions:
        match=METHOD.fullmatch(method)
        if not match or seeds.get(method,3)<=2:continue
        descriptor=match.group(3);args,result=descriptor.split(')',1)
        if result in ('Z','B','S','C','I','J','F','D') or (result=='Ljava/lang/Object;' and '[B' not in args and 'Ljava/lang/String;' not in args):
            generic_helpers.add(method)
    framework_classes=set()
    for owner in hierarchy:
        parent=hierarchy.get(owner);seen_parents=set()
        while parent and parent not in seen_parents and len(seen_parents)<32:
            seen_parents.add(parent)
            if parent.startswith(('Landroid/view/','Landroid/widget/')) or parent in ('Landroid/app/Activity;','Landroid/app/Fragment;'):
                framework_classes.add(owner);break
            parent=hierarchy.get(parent)
    ui_helpers={m for m in definitions if m.split('->',1)[0] in framework_classes and seeds.get(m,3)!=0}
    eligible={m:selector(m,excluded) for m in definitions if m not in hubs and m not in void_helpers and m not in ui_helpers and m not in generic_helpers};eligible={m:s for m,s in eligible.items() if s}
    for method in eligible:
        descriptor=METHOD.fullmatch(method).group(3)
        if descriptor.endswith(('Ljava/lang/String;','[B')) and ('[B' in descriptor.split(')')[0] or 'Ljava/lang/String;' in descriptor.split(')')[0]):
            seeds.setdefault(method,3)
    adjacent={}
    for edge in edges:
        if edge.get('basis') not in ('static_invoke_reference','static_callback_candidate'):continue
        source,target=edge['from'],edge['to']
        if source in eligible and target in eligible:
            adjacent.setdefault(source,set()).add(target);adjacent.setdefault(target,set()).add(source)
    scored={};queue=[((int(rank>=3),0,rank),m) for m,rank in seeds.items() if m in eligible];heapq.heapify(queue)
    while queue and len(scored)<2048:
        score,method=heapq.heappop(queue);tier,distance,rank=score
        if method in scored and scored[method]<=score:continue
        scored[method]=score
        if distance<depth:
            for neighbor in adjacent.get(method,()):
                following=(tier,distance+1,rank)
                if neighbor not in scored or following<scored[neighbor]:heapq.heappush(queue,(following,neighbor))
    limit=32 if heavy else 64;selected=[];seen=set()
    for method in sorted(scored,key=lambda m:(int(eligible[m]["method"]=="$init"),scored[m],m)):
        item=eligible[method];key=(item['class'],item['method'])
        if key in seen:continue
        seen.add(key)
        if len(selected)<limit:selected.append(item)
    # Capture nearby application methods even when obfuscation changes every name.
    token['selection'].update(methods=selected,max_methods=48 if heavy else 96,
        object_depth=1 if heavy else 2,object_fields=4 if heavy else 8,
        object_nodes=3 if heavy else 6,object_time_ms=3 if heavy else 5,
        call_rate=30 if heavy else 100)
    token['selection']['trace_byte_strings']=False
    if base_hash:token['selection']['apk_sha256']=base_hash
    for scoped in raw['tokens']:
        if scoped['capability']!='native.inventory':
            scoped.setdefault('selection',{})['exclude_prefixes']=list(dict.fromkeys(scoped.get('selection',{}).get('exclude_prefixes',[])+excluded))
    # Broad libc callbacks can contend with ART/Frida transport locks while Java
    # stacks are inspected. Automatic Java capture uses managed boundaries;
    # native socket bytes require an explicitly selected pack.
    raw['tokens']=[t for t in raw['tokens'] if t['capability']!='network.native']
    # A short decoder burst includes metadata plus separate owned transfers.
    # Bound the queue generously enough for these bursts without blocking hooks.
    raw['limits']['queue_depth']=512
    if heavy:
        raw['limits'].update(capture_bytes=262144,pending_bytes=4194304)
    raw['id']='lab.automatic.companion' if heavy else 'lab.automatic'
    result=Pack.parse(raw)
    report={'mode':'automatic','indexed_dex':indexed,'selected_methods':selected,'selected_count':len(selected),
        'candidate_count':len(seen),'selection_limited':len(seen)>len(selected),'depth':depth,
        'profile':'companion' if heavy else 'standard','calls_per_second':token['selection']['call_rate'],
        'exclude_prefixes':excluded,'base_apk_sha256':base_hash,
        'ubiquitous_helpers_omitted':len(hubs),
        'void_helpers_omitted':len(void_helpers),
        'framework_class_methods_omitted':len(ui_helpers),
        'generic_helpers_omitted':len(generic_helpers),
        'byte_string_capture':'scoped_app_conversion_methods; global String constructors excluded',
        'native_network':'excluded: broad libc callbacks can contend with Java/transport locks; managed request boundaries remain active',
        'basis':'Static boundary references, call neighborhoods and String/byte[] transform signatures; names are not semantic evidence',
        'limitations':['Bounded selection, not all app methods','Obfuscated third-party ownership cannot always be inferred','Unobserved calls and rate-limited events are not recoverable']}
    return result,report


def static_connections(service,run,frames,depth=5,include=(),exclude=()):
    """Potential paths only: code references never prove response flow or execution."""
    definitions=set();edges=[];sites={};origins={}
    for snapshot,_,index in indexes(service,run):
        for method in index.get('defined_methods',[]):origins.setdefault(method,snapshot)
        definitions.update(index.get('defined_methods',[]));edges.extend(index.get('edges',[]))
        for site in index.get('sites',[]):
            if site['kind'] in ('webview_navigation','custom_tab','parser_boundary','conditional_gate'):
                sites.setdefault(site['method'],[]).append(site)
    frame_names={(f.get('class'),f.get('method')) for f in frames}
    callers={}
    for edge in edges:
        if edge.get('basis')=='static_invoke_reference':callers.setdefault(edge['to'],set()).add(edge['from'])
    hubs={m for m,cs in callers.items() if len(cs)>32 and not any(s['kind'] in ('webview_navigation','custom_tab','parser_boundary') for s in sites.get(m,[]))}
    eligible={m:selector(m,exclude) for m in definitions if m not in hubs};eligible={m:s for m,s in eligible.items() if s and matches(s,include,exclude)}
    roots=sorted(m for m,s in eligible.items() if (s['class'],s['method'].replace('$init','<init>')) in frame_names)
    parents={}
    for edge in edges:
        if edge.get('basis') in ('static_invoke_reference','static_callback_candidate') and edge['from'] in eligible and edge['to'] in eligible:
            parents.setdefault(edge['to'],[]).append((edge['from'],
                'possible_callback' if edge['basis']=='static_callback_candidate' else 'calls',edge.get('offset')))
    navigation_goals=sorted(m for m in eligible if any(s['kind'] in ('webview_navigation','custom_tab') for s in sites.get(m,[])))
    parser_goals=sorted(m for m in eligible if any(s['kind']=='parser_boundary' for s in sites.get(m,[])))
    # Work backward from each navigation/parser boundary to an observed app caller.
    # This preserves long forward paths without exploring thousands of unrelated
    # callees near UI/framework entry points. Callback edges remain only possible.
    paths=[];parsers=[];total=0;limited=len(roots)>16 or len(navigation_goals)>32 or len(parser_goals)>32
    root_set=set(roots[:16])
    for goal in navigation_goals[:32]+parser_goals[:32]:
        if not root_set:break
        if total>=2048:limited=True;break
        queue=deque([(goal,[goal],[])]);visited=set();found=None
        while queue and len(visited)<128 and total<2048:
            method,reverse_path,reverse_links=queue.popleft()
            if method in visited:continue
            visited.add(method);total+=1
            if method in root_set:
                found=(list(reversed(reverse_path)),list(reversed(reverse_links)));break
            if len(reverse_path)-1>=depth:continue
            for parent,direction,offset in sorted(set(parents.get(method,[]))):
                if parent not in visited:queue.append((parent,reverse_path+[parent],reverse_links+[{'direction':direction,'offset':offset}]))
        if not found:
            if queue:limited=True
            continue
        path,links=found
        gates=[{'method':m,'offset':s['offset'],'opcode':s['opcode']} for m in path for s in sites.get(m,[]) if s['kind']=='conditional_gate'][:16]
        for site in sites.get(goal,[]):
            if site['kind'] not in ('webview_navigation','custom_tab','parser_boundary'):continue
            bucket=parsers if site['kind']=='parser_boundary' else paths
            if any(p['target']==site.get('target') and p['methods'][-1]==goal for p in bucket):continue
            bucket.append({'target':site.get('target'),'kind':site['kind'],'snapshot':origins[goal],
                'methods':path,'links':links,'gates':gates,'hops':len(path)-1,
                'basis':'static_call_references_only','execution':'not_established'})
    def rank(path):
        # Prefer response-parsing gates over broad UI dispatch switch statements.
        gated_parsers=sum(any(s['kind']=='parser_boundary' for s in sites.get(g['method'],[])) for g in path['gates'])
        return (-gated_parsers,-path['hops'],path['target'] or '')
    return {'navigation_paths':sorted(paths,key=rank)[:4],'parser_paths':sorted(parsers,key=rank)[:4],
        'roots':roots[:16],'hops':depth,'visited_methods':total,'limited':limited or len(paths)>4 or len(parsers)>4,
        'limits':{'goals_per_kind':32,'methods_per_goal':128,'visited':2048,'paths_per_kind':4},
        'note':'Boundary-to-caller static references show possible connections and conditional branches. They do not prove data provenance, branch outcomes, or execution.'}
