'use strict';
const suppliedToken=new URLSearchParams(location.hash.slice(1)).get('token');
if(suppliedToken)sessionStorage.setItem('runtime-code-token',suppliedToken);
const token=suppliedToken||sessionStorage.getItem('runtime-code-token');
history.replaceState(null,'',location.pathname);
const $=id=>document.getElementById(id);
let state=null,view='inventory',selected=null,detailMode='record',after=0,refreshing=null;
let timeline=[],filters={},positions={},actionGeneration=0,actionBusy=false;
let notice='Connecting…';
let page=0,pageSize=40,showEarlier=false,graphZoom=1,graphExpanded=false,lastFlow=null,rootRecord=null,inspectorTab='summary';
let pendingCommand=null,actionHost=null,focusedFlowRecord=null;
let packageInclude='',packageExclude='',selectedFromGraph=false;
let codeSearchTimer=null;
function scheduleCodeSearch(){clearTimeout(codeSearchTimer);codeSearchTimer=setTimeout(()=>{if(view==='code')searchCode().catch(e=>{notice=e.message;render();});},250);}
function packagePrefixes(value,exclusion=false){return value.split(/[,\s]+/).filter(Boolean).map(x=>(exclusion?x.replace(/^-/, ''):x).replace(/\.\*$/, '').replace(/\.+$/,''));}
function packageMatches(record){const names=record.package_classes||[record.app_caller?.class,record.summary?.caller?.class,recordData(record).class,appFrame(record)?.class].filter(Boolean);const under=p=>names.some(n=>n===p||n.startsWith(p+'.'));return !packagePrefixes(packageExclude,true).some(under)&&(!packageInclude.trim()||packagePrefixes(packageInclude).some(under));}
function matchingRecords(){const query=$('filter').value.toLowerCase();const rows=recordsForView().filter(packageMatches).filter(r=>!query||JSON.stringify(r).toLowerCase().includes(query));if(selectedFromGraph&&focusedFlowRecord&&packageMatches(focusedFlowRecord)&&!rows.some(r=>r.id===focusedFlowRecord.id))rows.unshift({...focusedFlowRecord,flow_selection:true});return rows;}
function syncFlowSelection(record){selectedFromGraph=true;focusedFlowRecord=record;const matches=matchingRecords(),index=matches.findIndex(r=>r.id===record.id);if(index>=0)page=Math.floor(index/pageSize);render();$('record-'+record.id)?.scrollIntoView({block:'nearest'});if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);}
function setText(id,value){if($(id).textContent!==value)$(id).textContent=value;}
async function api(path,body){
 const r=await fetch(path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 const d=await r.json();if(!r.ok)throw Error(d.error||r.statusText);return d;
}
function parsed(record){
 const copy={...record};for(const key of ['data','metadata','result','coverage','pack'])if(typeof copy[key]==='string'){try{copy[key]=JSON.parse(copy[key]);}catch(e){}}return copy;
}
function show(x){const value=parsed(x);const text=JSON.stringify(lastFlow?.visible?{record:value,flow:lastFlow.visible}:value,null,2);if($('details').textContent!==text)$('details').textContent=text;}
function textNode(tag,text,parent){const node=document.createElement(tag);node.textContent=text;parent.append(node);return node;}
function recordData(record){try{return typeof record.data==='string'?JSON.parse(record.data):record.data||{};}catch(e){return {};}}
function appFrame(record){const data=recordData(record);if(record.kind==='flow.candidate')return data.request;return (data.caller||[]).find(f=>!(/^(android\.|androidx\.|java\.|javax\.|sun\.|dalvik\.|libcore\.|com\.android\.|org\.json\.|kotlin\.|kotlinx\.)/.test(f.class||'')||/^\/(system|apex|vendor)\//.test(f.origin||'')));}
async function downloadScope(observation,scopeClass){
 try{
  const pack=await api('/api/action',{action:'flow-scope',observation,scope_class:scopeClass});
  const url=URL.createObjectURL(new Blob([JSON.stringify(pack,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');
  link.href=url;link.download='runtime-flow-scope.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
  notice='Scope pack downloaded. Restart capture with --pack /path/to/runtime-flow-scope.json, then repeat the flow.';render();
 }catch(e){notice='Scope pack: '+e.message;render();}
}
function frameLabel(frame){return frame?(frame.class||'?')+'.'+(frame.method||'?'):'Unattributed';}
function inspector(tab){inspectorTab=tab;$('details').hidden=tab!=='raw';$('evidence').hidden=tab==='raw';document.querySelectorAll('[data-inspector]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.inspector===tab)));}
function drawFlow(flow,box,navigate,staticMode=false){
 lastFlow={flow,box,navigate,staticMode};box.replaceChildren();
 const all=flow.steps.slice(0,256).filter(s=>staticMode||packageMatches(s)),byId=new Map(all.map(n=>[n.event,n]));
 let steps=all;
 if(!staticMode&&!graphExpanded){
  steps=all.filter(s=>s.kind.startsWith('network.')||s.navigation_outcome==='failed'||s.kind==='crypto.doFinal'||s.kind==='crypto.custom'||s.kind==='parser.custom'||s.kind==='parser.parse'||['webview.loadUrl','webview.custom_tab','webview.loadDataWithBaseURL'].includes(s.kind));
  if(!steps.length)steps=all.slice(0,30);
 }
 const controls=textNode('div','',box);controls.style.cssText='padding:8px;position:sticky;top:0;background:#17212eee;z-index:1';
 const expand=textNode('button',graphExpanded?'Key stages':'Show app hops ('+all.length+')',controls);
 expand.hidden=staticMode;expand.onclick=()=>{graphExpanded=!graphExpanded;drawFlow(flow,box,navigate,staticMode);};
 textNode('span',' '+steps.length+' stages · '+(staticMode?'Static references; execution not established':'Only linked observations'),controls);
 if(!steps.length){lastFlow.visible={...flow,steps:[],edges:[],view:graphExpanded?'app_hops':'key_stages'};show(focusedFlowRecord||rootRecord||{});textNode('p','No linked stages match the package filters.',box);return;}
 const retained=new Set(steps.map(n=>n.event)),adj=new Map();
 for(const e of flow.edges) {if(!adj.has(e.from))adj.set(e.from,[]);adj.get(e.from).push(e);}
 const edges=[];
 for(const step of steps){const queue=[{id:step.event,via:[],basis:[]}],visited=new Set([step.event]);
  while(queue.length&&visited.size<=256){const at=queue.shift();for(const e of adj.get(at.id)||[]){
   if(visited.has(e.to))continue;visited.add(e.to);const via=[...at.via,e.via],basis=[...at.basis,e.basis];
   if(retained.has(e.to)){edges.push({from:step.event,to:e.to,via:via.join(' → '),basis:basis.length===1?basis[0]:'collapsed_observed_path',parts:basis});}
   else if(byId.has(e.to))queue.push({id:e.to,via,basis});
  }}
 }
 lastFlow.visible={...flow,steps,edges,view:graphExpanded?'app_hops':'key_stages',package_filters:{include:packageInclude,exclude:packageExclude}};
 show(focusedFlowRecord||rootRecord||{});
 const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg'),width=1260;
 const lane=s=>staticMode?0:s.kind.startsWith('network.')?0:s.kind.startsWith('parser.')?1:s.kind.startsWith('crypto.')?2:s.kind.startsWith('webview.')?4:3;
 // Chronological positions inside each lane; connected producers influence row placement.
 const positions=new Map(),laneRows=[0,0,0,0,0];
 for(const step of steps){const col=lane(step);let row=laneRows[col];
  for(const e of edges.filter(e=>e.to===step.event)){const prior=positions.get(e.from);if(prior)row=Math.max(row,prior.row+(prior.col===col?1:0));}
  laneRows[col]=row+1;positions.set(step.event,{x:12+col*250,y:48+row*88,row,col,step});
 }
 const height=Math.max(260,Math.max(...laneRows)*88+65);
 svg.setAttribute('viewBox','0 0 '+width+' '+height);svg.style.cssText='width:'+Math.round(width*graphZoom)+'px;height:'+Math.round(height*graphZoom)+'px';svg.setAttribute('aria-label',staticMode?'Static code graph':'Observed flow graph');
 const defs=document.createElementNS(ns,'defs'),marker=document.createElementNS(ns,'marker'),arrow=document.createElementNS(ns,'path');
 for(const [k,v] of Object.entries({id:'flow-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto'}))marker.setAttribute(k,v);
 arrow.setAttribute('d','M 0 0 L 10 5 L 0 10 z');arrow.setAttribute('fill','#8aa8c2');marker.append(arrow);defs.append(marker);svg.append(defs);
 for(const [i,name] of ['Network','Parsing','Crypto','App handoffs','Navigation'].entries()){const t=document.createElementNS(ns,'text');t.setAttribute('x',14+i*250);t.setAttribute('y',24);t.setAttribute('fill','#9bacc1');t.setAttribute('font-size',12);t.textContent=staticMode?'Code references':name;svg.append(t);if(staticMode)break;}
 for(const e of edges){const f=positions.get(e.from),t=positions.get(e.to);if(!f||!t)continue;const path=document.createElementNS(ns,'path');
  const x1=f.x+115,y1=f.y+64,x2=t.x+115,y2=t.y;
  path.setAttribute('d',`M ${x1} ${y1} C ${x1} ${y1+32}, ${x2} ${y2-24}, ${x2} ${y2}`);path.setAttribute('stroke','#7d9bae');path.setAttribute('fill','none');path.setAttribute('marker-end','url(#flow-arrow)');path.setAttribute('stroke-dasharray',e.basis==='observed_nested_invocation'?'none':'5 4');
  const title=document.createElementNS(ns,'title');title.textContent=e.basis+' · '+e.via;path.append(title);path.onclick=()=>{inspector('summary');$('evidence').replaceChildren();textNode('h4','Relationship', $('evidence'));textNode('p',e.basis,$('evidence'));textNode('pre',e.via,$('evidence'));show(e);};svg.append(path);
 }
 for(const {x,y,step} of positions.values()){
  const group=document.createElementNS(ns,'g');group.setAttribute('role','button');group.setAttribute('tabindex','0');group.setAttribute('aria-label',step.kind+' '+(step.api||step.event));
  const rect=document.createElementNS(ns,'rect');for(const [key,value] of Object.entries({x,y,width:230,height:64,rx:8,fill:step.observation===selected?'#294951':'#1d2c3c',stroke:step.observation===selected?'#7fcac1':'#45627b'}))rect.setAttribute(key,value);group.append(rect);
  const labels=[step.kind,step.app_caller?.jadx_search||step.api||step.event,step.url||step.network?.peer||''];
  labels.forEach((label,i)=>{const t=document.createElementNS(ns,'text');t.setAttribute('x',x+9);t.setAttribute('y',y+17+i*18);t.setAttribute('fill',i?'#e5edf7':'#7fcac1');t.setAttribute('font-size',i?11:10);t.textContent=label.length>34?label.slice(0,31)+'…':label;group.append(t);});
  const title=document.createElementNS(ns,'title');title.textContent=labels.join(' · ');group.append(title);
  group.onclick=()=>navigate(step);group.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();navigate(step);}};svg.append(group);
 }
 box.append(svg);
}
async function inspectRecord(record,keepGraph=false){
 if(!keepGraph)selectedFromGraph=false;
 const generation=++actionGeneration;selected=record.id;focusedFlowRecord=record;detailMode='evidence';notice='Selected '+(record.kind||'artifact');
 const box=$('evidence');box.replaceChildren();show(record);inspector('summary');render();
 if(!record.kind||!record.data||record.kind==='decoded_string'){
  lastFlow=null;rootRecord=null;show(record);
  if(record.finding){textNode('h4','Decoded string mapping',box);textNode('pre',JSON.stringify(record.finding.mapping,null,2),box);}
  textNode('h4',record.kind||'Artifact',box);textNode('p',record.status||record.state||'',box);
  textNode('pre',record.hash||'No published hash',box);
  if(record.dynamic_load)textNode('p',record.dynamic_load.dynamically_loaded?'Dynamically loaded · loader returned':'Loading: '+record.dynamic_load.state,box);
  if(record.hash){const b=textNode('button','Download raw artifact',box);b.onclick=()=>download(record.id,true).catch(e=>{notice=e.message;render();});}
  $('graph').replaceChildren();return;
 }
 try{
  const evidence=await api('/api/evidence?observation='+encodeURIComponent(record.id));if(generation!==actionGeneration)return;
  focusedFlowRecord={...record,...evidence.record};show(focusedFlowRecord);const data=evidence.record.data,primary=evidence.primary_app_caller,higher=evidence.primary_app_caller_next_distinct||evidence.primary_app_caller_called_by;
  textNode('h4',data.api||record.kind,box);
  const chain=textNode('p',frameLabel(higher)+' → '+frameLabel(primary)+' → '+(data.api||record.kind),box);chain.className='caller-chain';
  chain.title='Next distinct outer stack frame → nearest app method → operation. Frame adjacency can include instrumentation.';
  textNode('p','Next distinct outer method: '+frameLabel(higher),box);
  const search=textNode('button','Copy JADX search',box);search.onclick=()=>navigator.clipboard.writeText(frameLabel(primary)).catch(()=>{notice='Copy manually: '+frameLabel(primary);render();});
  const scope=textNode('button','Download scope pack for these app methods',box);scope.onclick=()=>downloadScope(record.id);
  if(evidence.network){const n=evidence.network;textNode('h4',n.url||n.destination||n.peer||'Destination unattributed',box);textNode('p',[n.direction,n.method,n.status_line,n.peer,n.url_status].filter(Boolean).join(' · '),box);}
  if(evidence.crypto){
   const crypto=evidence.crypto;textNode('h4',(crypto.direction||'Crypto')+' · '+(crypto.algorithm||'Algorithm unavailable'),box);
   const grid=document.createElement('div');grid.className='value-grid';box.append(grid);
   for(const [name,value] of Object.entries(crypto.values)){
    const card=document.createElement('div');card.className='value-card';grid.append(card);
    textNode('label',({input:crypto.mode===2?'Encrypted input':crypto.mode===1?'Plaintext input':'Input',output:crypto.mode===2?'Decrypted result':crypto.mode===1?'Encrypted result':'Output',key:'Key',iv:'Nonce / IV'})[name]||name,card);
    textNode('pre',value.utf8??value.base64??value.reason??value.status??'Unavailable',card);
    if(value.snapshot){const b=textNode('button','Download '+name+' bytes',card);b.onclick=()=>download(value.snapshot,true).catch(e=>{notice=e.message;render();});}
    if(value.source?.event){const b=textNode('button','Follow source',card);b.onclick=()=>{const source=evidence.flow.steps.find(s=>s.event===value.source.event);if(source)navigate(source);};}
   }
  }
  const context=document.createElement('details');textNode('summary','App code — search these methods in JADX',context);
  for(const frame of evidence.app_callers||[])textNode('pre',frame.jadx_search+' '+(frame.signature||'')+'\n'+(frame.origin||''),context);box.append(context);
  if(evidence.enclosing_invocations?.length){const calls=document.createElement('details');textNode('summary','Observed enclosing calls:',calls);textNode('pre',evidence.enclosing_invocations.slice().reverse().map(x=>x.api||x.kind).join(' → '),calls);box.append(calls);}
  if(evidence.object_observations?.length){const objects=document.createElement('details');textNode('summary','Objects & fields ('+evidence.object_observations.length+')',objects);
   for(const n of evidence.object_observations)textNode('pre',[n.phase,n.path,n.class,n.preview??n.status??n.object_id].filter(Boolean).join(' · '),objects);box.append(objects);}
  if(evidence.native_caller){const native=document.createElement('details');textNode('summary','Native attribution',native);textNode('pre',JSON.stringify(evidence.native_caller,null,2),native);box.append(native);}
  const navigate=async step=>{try{const known=timeline.find(r=>r.id===step.observation);const target=known||(await api('/api/evidence?observation='+step.observation)).record;await inspectRecord({...target,summary:known?.summary,package_classes:known?.package_classes},true);syncFlowSelection(target);}catch(e){notice=e.message;render();}};
  if(!keepGraph){rootRecord=record;drawFlow(evidence.flow,$('graph'),navigate);}else if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);
  if(evidence.flow.missing_references.length||Object.values(evidence.flow.coverage||{}).some(Boolean))textNode('p','Partial flow: some events were outside the retained graph window.',box);
  if(!evidence.flow.edges.length)textNode('p','No preceding data handoff established. Unobserved hops remain unattributed.',box);
 }catch(e){if(generation===actionGeneration){notice='Evidence: '+e.message;render();}}
}
// Keep existing DOM nodes for unchanged records: native browser Find and text selection survive polling.
function reconcileRows(table){
 const old=$('rows').firstElementChild;if(!old||old.tagName!=='TABLE'){$('rows').replaceChildren(table);return;}
 const existing=new Map(Array.from(old.children).map(n=>[n.dataset.key,n]));
 let index=0;
 for(const row of Array.from(table.children)){
  const prior=existing.get(row.dataset.key);existing.delete(row.dataset.key);
  let node=prior||row;
  if(prior&&prior.outerHTML!==row.outerHTML){prior.replaceWith(row);node=row;}
  if(old.children[index]!==node)old.insertBefore(node,old.children[index]||null);
  index++;
 }
 for(const row of existing.values())row.remove();
}
async function download(id,raw=false){
 const r=await fetch('/api/download?snapshot='+encodeURIComponent(id)+'&format='+(raw?'raw':'bundle'),{headers:{Authorization:'Bearer '+token}});
 if(!r.ok)throw Error((await r.json()).error);
 const url=URL.createObjectURL(await r.blob()),link=document.createElement('a');
 link.href=url;link.download=(r.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)[1];document.body.append(link);link.click();link.remove();
 setTimeout(()=>URL.revokeObjectURL(url),30000);
 return {download:link.download,note:raw?'Raw bytes saved by your browser to its Downloads location; use the bundle for provenance.':'Saved by your browser to its Downloads location; includes raw bytes and provenance manifest.'};
}
function button(label,fn,reason){
 const b=document.createElement('button');b.textContent=label;b.disabled=!!reason||actionBusy;
 if(reason)b.title=reason;
 b.onclick=async()=>{
  const generation=++actionGeneration;actionBusy=true;notice=label+'…';render();
  try{const result=await fn();if(generation===actionGeneration){detailMode='action';show(result);pendingCommand=result.command?{id:result.command,generation}:null;notice=label+(result.command?' queued':' completed');}}
  catch(e){if(generation===actionGeneration)notice=label+': '+e.message;}
  finally{actionBusy=false;await refresh();render();}
 };
 actionHost.append(b);
 if(reason){const span=document.createElement('span');span.textContent=reason;span.className='muted';actionHost.append(span);}
}
function currentInventory(){const floor=showEarlier?0:state.checkpoint?.time_ns||0;return state.inventory.filter(r=>r.time_ns>floor);}
function withFlowSelection(records){if(focusedFlowRecord?.data&&lastFlow?.flow.steps.some(s=>s.observation===focusedFlowRecord.id)&&!records.some(r=>r.id===focusedFlowRecord.id))return [focusedFlowRecord,...records];return records;}
function recordsForView(){
 const floor=showEarlier?0:state.checkpoint?.sequence||0,events=timeline.filter(r=>r.sequence>floor);
 if(view==='inventory')return currentInventory().filter(r=>r.kind!=='trace_payload');
 if(view==='payloads')return currentInventory().filter(r=>r.kind==='trace_payload');
 if(view==='findings'){const floor=showEarlier?0:state.checkpoint?.time_ns||0;return state.findings.filter(r=>r.time_ns>floor);}
 if(['jni','network','crypto','parser','flow'].includes(view))return withFlowSelection(events.filter(r=>r.kind.startsWith(view+'.')||(view==='network'&&recordData(r).network_category)));
 if(view==='webview')return withFlowSelection(events.filter(r=>['webview.loadUrl','webview.postUrl','webview.loadData','webview.loadDataWithBaseURL','webview.custom_tab'].includes(r.kind)||recordData(r).navigation_kind==='custom_tab_intent'||recordData(r).navigation_outcome==='failed'));
 return events;
}
function rowLabels(record){
 const data=recordData(record),nearest=record.summary?.caller||appFrame(record),outer=record.summary?.called_by;
 const caller=frameLabel(nearest),chain=outer?frameLabel(outer)+' → '+caller:caller;
 if(record.kind==='trace_payload'){let meta={};try{meta=JSON.parse(record.metadata);}catch(e){}return {title:meta.source||'Captured bytes',sub:(record.received||0)+' bytes · '+record.status,badge:'Payload',extra:meta.correlation||''};}
 if(record.dynamic_load)return {title:record.kind,sub:(record.received||0)+' bytes · '+record.status,badge:record.dynamic_load.dynamically_loaded?'Dynamic load':'Code artifact',extra:(record.hash||'Pending').slice(0,20)};
 if(record.finding)return {title:Object.values(record.finding.mapping).map(v=>v.utf8??v.base64??v.status??'').join(' → '),sub:chain,badge:'Observed string',extra:record.finding.semantic_basis||record.finding.execution};
 if(data.navigation_outcome==='failed')return {title:data.url||'Failed WebView request',sub:data.error_description||'WebView reported a load error',badge:'Failed request',extra:data.error_code||data.api};
 if(data.network_category)return {title:data.url||data.arguments?.[0]||'WebView navigation',sub:chain,badge:data.network_category==='navigation_intent'?'WebView request intent':'WebView callback',extra:data.api};
 if(record.kind?.startsWith('crypto.'))return {title:chain,sub:(data.algorithm||'')+' · '+(data.direction||record.kind.split('.')[1]),badge:'Crypto',extra:(record.summary?.values?.input?.utf8??record.summary?.values?.input?.base64??'Input unavailable').slice(0,72)+' → '+(record.summary?.values?.output?.utf8??record.summary?.values?.output?.base64??'Output unavailable').slice(0,100)};
 if(record.kind?.startsWith('network.')){const n=record.summary?.network||{};return {title:n.url||n.destination||n.peer||data.url||'Destination unattributed',sub:[n.method,n.direction,n.status_line].filter(Boolean).join(' · '),badge:'Network',extra:n.peer||data.api||''};}
 return {title:data.url||data.path||data.api||caller,sub:chain,badge:record.kind||record.handler||'Finding',extra:data.access_state||data.outcome||record.state||''};
}
function render(){
 if(!state)return;
 setText('title',({inventory:'Loaded code',payloads:'Captured bytes',jni:'JNI trace',webview:'Navigation flows',parser:'Parsers',flow:'App calls',code:'Code & URL search'})[view]||view[0].toUpperCase()+view.slice(1));
 document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-current',b.dataset.view===view?'page':'false'));
 const cov=state.coverage;
 setText('context',`${cov.run.app} · ${cov.run.device} · Run ${cov.run.id.slice(0,8)} · ${cov.run.state} · ${cov.processes.map(p=>p.pid+' '+p.state).join(', ')||'no process'}`);
 $('context').title='Run '+cov.run.id;$('earlier').hidden=!state.checkpoint?.sequence;
 $('earlier').textContent=showEarlier?'Hide earlier results':'Show earlier results';
 setText('status',notice);
 actionHost=document.createElement('div');
 if(view==='code'){button('Search code & flow',searchCode);if($('actions').innerHTML!==actionHost.innerHTML)$('actions').replaceChildren(...actionHost.childNodes);return;}
 if(view==='coverage'){
  $('rows').replaceChildren();$('actions').replaceChildren();$('graph').replaceChildren();
  if(detailMode!=='coverage'){detailMode='coverage';$('evidence').replaceChildren();textNode('h4','Capture coverage',$('evidence'));textNode('p',cov.run.state+' · '+cov.processes.length+' process instances',$('evidence'));textNode('p','Open Raw JSON for exact profiles, exclusions and loss counters.',$('evidence'));show(cov);}return;
 }
 {
  const records=recordsForView(),current=state.inventory.find(x=>x.id===selected);
  if(['inventory','payloads'].includes(view)&&current){
   const id=current.id;
   if(current.kind!=='trace_payload'){
    button('Analyze artifact',()=>api('/api/action',{action:'analyze',snapshot:id}));
    button('Index code references',()=>api('/api/action',{action:'analyze',snapshot:id,handler:'code.references'}));
    if(current.kind==='dex_runtime_snapshot')button('Snapshot now',()=>api('/api/action',{action:'snapshot',process:current.process_id,target:current.logical_id}),cov.run.state==='running'?null:'Run ended');
   }
   button('Download raw artifact',()=>download(id,true),current.hash?null:'No bytes');
   button('Download artifact + manifest',()=>download(id),current.hash?null:'No bytes');
  }else if(!['inventory','payloads','findings'].includes(view))button('Export trace',()=>api('/api/action',{action:'export-trace',kinds:view==='timeline'?[]:[view+'.']}));
  const matching=matchingRecords();
  page=Math.min(page,Math.max(0,Math.ceil(matching.length/pageSize)-1));
  const shown=matching.slice(page*pageSize,(page+1)*pageSize),table=document.createElement('table');
  for(const record of shown){const tr=document.createElement('tr'),td=document.createElement('td'),b=document.createElement('button');
   tr.dataset.key=record.id;b.id='record-'+record.id;b.className='record';const labels=rowLabels(record);
   const badge=textNode('span',(record.flow_selection?'Selected flow stage · ':'')+labels.badge,b);badge.className='badge';textNode('b',labels.title,b);textNode('small',labels.sub,b);if(labels.extra)textNode('small',labels.extra,b);
   b.title=record.id;b.setAttribute('aria-pressed',String(selected===record.id));b.onclick=()=>inspectRecord(recordsForView().find(r=>r.id===record.id)||record);td.append(b);tr.append(td);table.append(tr);
  }
  if(shown.length)reconcileRows(table);else if(!$('rows').querySelector('.empty')){const empty=document.createElement('p');empty.className='empty';empty.textContent=state.checkpoint?.sequence&&!showEarlier?'No matches in the current display window. Use “Show earlier results” to search saved evidence.':view==='inventory'?'No code artifacts yet. Crypto and network fragments appear in Captured bytes.':'No matching observations yet.';$('rows').replaceChildren(empty);}
  setText('page-info',matching.length?`${page*pageSize+1}–${page*pageSize+shown.length} / ${matching.length}`:'0 results');$('previous').disabled=page===0;$('next').disabled=(page+1)*pageSize>=matching.length;
 }
 if($('actions').innerHTML!==actionHost.innerHTML)$('actions').replaceChildren(...actionHost.childNodes);
}
function refresh(){
 if(refreshing)return refreshing;
 refreshing=(async()=>{
  try{
   let pages=0;
   do{
    const next=await api('/api/state?after='+after);
    const incoming=next.timeline.filter(x=>x.sequence>after);
    if(incoming.length){after=incoming.at(-1).sequence;timeline.push(...incoming);timeline=timeline.slice(-5000);}
    state=next;
    const refreshed=new Map((next.updates||[]).map(r=>[r.id,r]));timeline=timeline.map(r=>refreshed.get(r.id)||r);
    if(pendingCommand&&pendingCommand.generation===actionGeneration){
     const command=(state.commands||[]).find(x=>x.id===pendingCommand.id);
     if(command&&command.state!=='pending'){
      show({...command,result:JSON.parse(command.result)});notice='Snapshot request '+command.state;pendingCommand=null;
     }
    }
    if(next.timeline.length<500)break;
   }while(++pages<5);
   if(notice==='Connecting…'||notice.startsWith('Refresh failed:'))notice='Connected';
   render();
  }catch(e){notice='Refresh failed: '+e.message;$('status').textContent=notice;}
 })().finally(()=>refreshing=null);
 return refreshing;
}
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>{
 filters[view]=$('filter').value;positions[view]=$('rows').scrollTop;
 view=b.dataset.view;page=0;++actionGeneration;detailMode='record';selected=null;rootRecord=null;lastFlow=null;focusedFlowRecord=null;selectedFromGraph=false;$('graph').replaceChildren();$('filter').value=filters[view]||'';
 $('evidence').replaceChildren();$('rows').replaceChildren();$('details').textContent='Select a record to inspect its observed evidence.';render();
 $('rows').scrollTop=positions[view]||0;
 if(view==='code')scheduleCodeSearch();
});
for(const [id,key] of [['include-packages','include'],['exclude-packages','exclude']])$(id).oninput=()=>{if(key==='include')packageInclude=$(id).value;else packageExclude=$(id).value;page=0;++actionGeneration;render();if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);if(view==='code')searchCode().catch(e=>{notice=e.message;render();});};
$('filter').oninput=()=>{page=0;if(view==='code'){++actionGeneration;scheduleCodeSearch();}render();};$('filter').onkeydown=e=>{if(e.key==='Enter'&&view==='code'){clearTimeout(codeSearchTimer);searchCode().catch(e=>{notice=e.message;render();});}};$('refresh').onclick=()=>{refresh();if(view==='code')scheduleCodeSearch();};
$('previous').onclick=()=>{page=Math.max(0,page-1);render();$('rows').scrollTop=0;};$('next').onclick=()=>{page++;render();$('rows').scrollTop=0;};
document.querySelectorAll('[data-inspector]').forEach(b=>b.onclick=()=>inspector(b.dataset.inspector));
$('zoom-in').onclick=()=>{graphZoom=Math.min(1.8,graphZoom+.15);if(lastFlow)drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);};
$('zoom-out').onclick=()=>{graphZoom=Math.max(.35,graphZoom-.15);if(lastFlow)drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);};
$('clear-results').onclick=()=>$('clear-dialog').showModal();$('cancel-clear').onclick=()=>$('clear-dialog').close();
$('confirm-clear').onclick=async()=>{try{await api('/api/action',{action:'clear-workspace'});showEarlier=false;page=0;selected=null;++actionGeneration;$('graph').replaceChildren();$('evidence').replaceChildren();$('details').textContent='';$('rows').replaceChildren();$('clear-dialog').close();notice='Results cleared · Capture continues · Saved evidence preserved';await refresh();}catch(e){notice=e.message;render();}};
$('earlier').onclick=()=>{showEarlier=!showEarlier;page=0;render();if(view==='code'){++actionGeneration;scheduleCodeSearch();}};
refresh();setInterval(refresh,1000);

async function searchCode(){
 const generation=actionGeneration,query=$('filter').value,result=await api('/api/code?q='+encodeURIComponent(query)+'&include='+encodeURIComponent(packageInclude)+'&exclude='+encodeURIComponent(packagePrefixes(packageExclude,true).join(','))+'&since_ns='+(showEarlier?0:state.checkpoint?.time_ns||0));
 if(view!=='code'||generation!==actionGeneration||query!==$('filter').value)return result;
 const box=$('evidence');box.replaceChildren();$('rows').replaceChildren();inspector('summary');
 textNode('h3','Static definitions and potential navigation paths',box);
 textNode('p','Static references can include code that never ran. They do not prove that a URL flowed through every connected method. Click a node or match for the exact method, bytecode offset and snapshot.',box);
 if(!result.indexed_snapshots)textNode('p','No static code indexed. Start watch with --code /path/app.apk, run index-code for this Run, or select a DEX in Inventory and click Index code references.',box);
 textNode('p',result.static_hit_count+' static matches; '+result.runtime_hits.length+' observed text/payload matches'+(result.truncated?' · Results/graph limited':''),box);
 for(const hit of result.static_hits){
  const row=document.createElement('p');const b=textNode('button',(hit.class||'')+' · '+(hit.method||hit.kind)+' @ '+(hit.offset??'declaration'),row);
  b.onclick=()=>show(hit);textNode('span',' '+hit.kind+' · '+(hit.value||hit.target||'')+' · execution not established',row);box.append(row);
  if(hit.string_obfuscation){const s=hit.string_obfuscation;textNode('pre','Original input: '+(s.input.text??s.input.base64??s.input.status)+'\nKey candidate: '+(s.key_candidate.text??s.key_candidate.base64??s.key_candidate.status)+'\nDecoder: '+hit.decoder+'\n'+s.key_role,row);}
  if(hit.method&&hit.method.includes('(')){
   const decoder=hit.kind==='xor_candidate'||hit.kind==='decoded_string',method=decoder&&hit.decoder?hit.decoder:hit.method;
   const scope=textNode('button',decoder?'Download decoder scope':'Download method scope',row);
   scope.onclick=async()=>{try{const pack=await api('/api/action',{action:'code-scope',snapshot:hit.snapshot,method,decoder});
    const url=URL.createObjectURL(new Blob([JSON.stringify(pack,null,2)],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='runtime-code-scope.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),30000);
    notice='Scope downloaded. Restart capture with --pack /path/to/runtime-code-scope.json and repeat the flow.';render();
   }catch(e){notice=e.message;render();}};
  }
 }
 const graph={steps:result.graph.nodes.map(n=>({event:n.id,kind:n.kind,api:n.label,record:n,observation:n.observation})),edges:result.graph.edges};
 if(result.static_hits.length){const staticGraph=textNode('div','',box);drawFlow(graph,staticGraph,step=>show(step.record),true);}
 const links=document.createElement('details');textNode('summary','Static/reference edges and search associations',links);textNode('pre',JSON.stringify(result.graph.edges,null,2),links);box.append(links);
 textNode('h3','Observed URL / payload matches',box);
 for(const hit of [...result.runtime_hits].sort((a,b)=>Number(!!b.string_mapping)-Number(!!a.string_mapping))){const b=textNode('button',hit.kind+' · '+(hit.string_mapping?.caller?.jadx_search||hit.basis),box);b.onclick=async()=>{const e=await api('/api/evidence?observation='+encodeURIComponent(hit.id));inspectRecord(e.record);};
  if(hit.string_mapping){const m=hit.string_mapping,card=textNode('div','',box);
   textNode('h4','Decoded string · '+(m.algorithm||'Observed transformation'),card);
   textNode('pre','Output: '+(m.output.utf8??m.output.reason??'Unavailable')+'\nOriginal input: '+(m.input.utf8??m.input.base64??m.input.reason??'Unavailable')+'\nKey: '+(m.key.utf8??m.key.base64??m.key.reason??m.key.status??'Not captured'),card);
   textNode('p','Produced in '+(m.caller?.jadx_search||'unattributed')+' · '+(m.caller?.origin||'origin unavailable'),card);
   for(const site of m.definition_sites){const b=textNode('button',site.role+' literal · '+site.method+' @ '+site.offset,card);b.onclick=()=>show(site);}
   textNode('p',m.definition_basis,card);
  }
 }
 if(result.observed_flow){
  textNode('p','Observed flow for the matching navigation (or first matching event). Solid edges are recorded call nesting; object/value associations retain their separate evidence labels.',box);
  const runtimeGraph=textNode('div','',box);drawFlow(result.observed_flow,runtimeGraph,async step=>{const e=await api('/api/evidence?observation='+encodeURIComponent(step.observation));inspectRecord(e.record);});
 }
 textNode('pre',result.limitations.join('\n'),box);
 return result;
}
