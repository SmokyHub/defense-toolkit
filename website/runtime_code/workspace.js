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
let codeSearchTimer=null,evidenceTimer=null,lastPackageQuery='';
let lastEvidence=null,fullJson=false,stringResults=null,stringBusy=false;
let stringSelectedMethod='',stringRenderSignature='';
let logRows=[],logCursor=0,logState=null,logBusy=false;
function scheduleCodeSearch(){clearTimeout(codeSearchTimer);codeSearchTimer=setTimeout(()=>{if(view==='code')searchCode().catch(e=>{notice=e.message;render();});},250);}
function packagePrefixes(value,exclusion=false){return value.split(/[,\s]+/).filter(Boolean).map(x=>x.replace(exclusion?/^-pkg:|^-/:/^pkg:/,'').replace(/\.\*$/, '').replace(/\.+$/,''));}
function searchOptions(){const words=$('filter').value.split(/\s+/),include=words.filter(x=>x.startsWith('pkg:')),exclude=words.filter(x=>x.startsWith('-pkg:'));return {query:words.filter(x=>!x.startsWith('pkg:')&&!x.startsWith('-pkg:')).join(' ').toLowerCase(),include:packagePrefixes([packageInclude,...include].join(' ')),exclude:packagePrefixes([packageExclude,...exclude].join(' '),true)};}
function packageMatches(record){const names=record.package_classes||[record.app_caller?.class,record.summary?.caller?.class,recordData(record).class,appFrame(record)?.class].filter(Boolean),opts=searchOptions();const under=p=>names.some(n=>n===p||n.startsWith(p+'.'));return !opts.exclude.some(under)&&(!opts.include.length||opts.include.some(under));}
function matchingRecords(){const query=searchOptions().query;const rows=recordsForView().filter(packageMatches).filter(r=>!query||JSON.stringify(r).toLowerCase().includes(query));if(selectedFromGraph&&focusedFlowRecord&&packageMatches(focusedFlowRecord)&&!rows.some(r=>r.id===focusedFlowRecord.id))rows.unshift({...focusedFlowRecord,flow_selection:true});return rows;}
function syncFlowSelection(record){selectedFromGraph=true;focusedFlowRecord=record;const matches=matchingRecords(),index=matches.findIndex(r=>r.id===record.id);if(index>=0)page=Math.floor(index/pageSize);render();$('record-'+record.id)?.scrollIntoView({block:'nearest'});if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);}
function setText(id,value){if($(id).textContent!==value)$(id).textContent=value;}
async function api(path,body){
 const r=await fetch(path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 const d=await r.json();if(!r.ok)throw Error(d.error||r.statusText);return d;
}
function parsed(record){
 const copy={...record};for(const key of ['data','metadata','result','coverage','pack'])if(typeof copy[key]==='string'){try{copy[key]=JSON.parse(copy[key]);}catch(e){}}return copy;
}
function show(x){
 let value=parsed(x);
 if(lastEvidence&&lastEvidence.record.id===x.id){
  value=fullJson?lastEvidence:{...lastEvidence.compact};
  if(!fullJson)value.chain=(value.chain||[]).filter(label=>!searchOptions().exclude.some(p=>label===p||label.startsWith(p+'.')));
  if(!fullJson&&lastFlow?.visible){const f=lastFlow.visible;value.nodes=f.steps.map(s=>({id:s.event,kind:s.kind,method:s.api,caller:s.app_caller?.jadx_search,url:s.url,outcome:s.navigation_outcome,navigation:s.navigation_kind,event:s.navigation_event,url_basis:s.url_basis}));value.edges=f.edges.map(({from,to,via,basis,parts})=>({from,to,via,basis,...(parts?.length>1?{basis_path:parts}:{})}));}
 }else if(fullJson&&lastFlow?.visible)value={record:value,flow:lastFlow.visible};
 const text=JSON.stringify(value,null,fullJson?2:0);if($('details').textContent!==text)$('details').textContent=text;
}
async function copyText(text){
 try{await navigator.clipboard.writeText(text);}catch(e){const field=document.createElement('textarea');field.value=text;field.style.cssText='position:fixed;opacity:0';document.body.append(field);field.select();const copied=document.execCommand('copy');field.remove();if(!copied)throw Error('Clipboard unavailable; select the displayed text manually.');}
 notice='Copied';setText('status',notice);
}
function copyIcon(parent,label,read){const b=textNode('button','⧉',parent);b.className='copy-icon';b.title='Copy '+label;b.setAttribute('aria-label','Copy '+label);b.onclick=async()=>{try{notice='Copying '+label+'…';setText('status',notice);await copyText(await read());}catch(e){notice=e.message;setText('status',notice);}};return b;}
function evidenceURL(id){const o=searchOptions();return '/api/evidence?'+new URLSearchParams({observation:id,depth:$('flow-depth').value,include:o.include.join(','),exclude:o.exclude.join(',')});}
function exportOptions(){const o=searchOptions();return new URLSearchParams({q:o.query,include:o.include.join(','),exclude:o.exclude.join(','),depth:$('flow-depth').value,since_ns:showEarlier?0:state?.checkpoint?.time_ns||0});}
function textNode(tag,text,parent){const node=document.createElement(tag);node.textContent=text;parent.append(node);return node;}
function recordData(record){try{return typeof record.data==='string'?JSON.parse(record.data):record.data||{};}catch(e){return {};}}
function appFrame(record){const data=recordData(record);if(record.kind==='flow.candidate')return data.request;return (data.caller||[]).find(f=>!(/^(android\.|androidx\.|java\.|javax\.|sun\.|dalvik\.|libcore\.|com\.android\.|org\.json\.|kotlin\.|kotlinx\.)/.test(f.class||'')||/^\/(system|apex|vendor)\//.test(f.origin||'')));}
async function downloadScope(observation,scopeClass,decoder=false){
 try{
  const pack=await api('/api/action',{action:'flow-scope',observation,scope_class:scopeClass,depth:Number($('flow-depth').value),exclude:searchOptions().exclude.join(','),decoder});
  const url=URL.createObjectURL(new Blob([JSON.stringify(pack,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');
  link.href=url;link.download='runtime-flow-scope.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
  notice='Scope pack downloaded. Restart capture with --pack /path/to/runtime-flow-scope.json, then repeat the flow.';render();
 }catch(e){notice='Scope pack: '+e.message;render();}
}
function frameLabel(frame){return frame?(frame.class||'?')+'.'+(frame.method||'?'):'Unattributed';}
async function openObservation(id,destination){
 const generation=actionGeneration;
 try{const evidence=await api(evidenceURL(id));if(generation!==actionGeneration)return;const record=evidence.record;
  openView(destination||(record.kind.startsWith('network.')?'backtrack':record.kind.startsWith('webview.')?'webview':record.kind.startsWith('flow.')?'flow':record.kind.startsWith('parser.')?'parser':'crypto'));
  await inspectRecord(record);syncFlowSelection(record);
 }catch(e){if(generation===actionGeneration){notice=e.message;setText('status',notice);}}
}
function inspector(tab){inspectorTab=tab;$('details').hidden=tab!=='raw';$('evidence').hidden=tab==='raw';document.querySelectorAll('[data-inspector]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.inspector===tab)));}
function drawFlow(flow,box,navigate,staticMode=false){
 lastFlow={flow,box,navigate,staticMode};box.replaceChildren();
 const all=flow.steps.slice(0,256).filter(s=>staticMode||packageMatches(s)),byId=new Map(all.map(n=>[n.event,n]));
 let steps=all;
 if(!staticMode&&!graphExpanded){
  steps=all.filter(s=>s.kind.startsWith('network.')||s.kind.startsWith('webview.custom_tab')||s.navigation_outcome==='failed'||s.kind==='crypto.doFinal'||s.kind==='crypto.custom'||s.kind==='parser.custom'||s.kind==='parser.parse'||['webview.loadUrl','webview.loadDataWithBaseURL'].includes(s.kind));
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
 $('copy-flow-json').disabled=true;
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
  $('graph').replaceChildren();$('copy-flow-json').disabled=false;return;
 }
 try{
  const evidence=await api(evidenceURL(record.id));if(generation!==actionGeneration)return;lastEvidence=evidence;
  focusedFlowRecord={...record,...evidence.record};show(focusedFlowRecord);const data=evidence.record.data,primary=evidence.primary_app_caller,higher=evidence.primary_app_caller_next_distinct||evidence.primary_app_caller_called_by;
  textNode('h4',data.api||record.kind,box);
  if(evidence.request_backtracking){
   const backtrack=evidence.request_backtracking,section=textNode('div','',box);section.className='backtrack-context';
   textNode('h4','Request backtracking · '+backtrack.depth+' hops',section);
   textNode('p',({linked_navigation_observed:'Navigation appears in the linked event graph. Inspect edge labels for the relationship basis.',shared_navigation_candidate:'Related WebView / Custom Tab candidates found by shared callers; no response handoff is established.',static_navigation_candidate:'No linked navigation observed. Indexed code contains a possible path to WebView / Custom Tabs; check the conditional gates below.',no_navigation_link_observed:'No linked WebView / Custom Tab observed within '+backtrack.depth+' hops.'})[backtrack.status],section);
   textNode('pre',[data.api||record.kind,...backtrack.callers].join(' ← '),section);
   textNode('p',backtrack.note,section);
   if(!backtrack.callers.length)textNode('p','No app stack was retained for this event. Select a Java network request or capture scoped app methods.',section);
   const fields=[],seen=new Set();for(const candidate of evidence.network_context||[])for(const field of candidate.fields){const key=JSON.stringify([candidate.shared,field]);if(!seen.has(key)){seen.add(key);fields.push({candidate,field});}}
   if(fields.length){textNode('h4','Related JSON fields · shared caller matches',section);for(const {candidate,field} of fields.slice(0,24)){const line=textNode('div','',section);textNode('pre',[field.path,field.expected_type,field.access_state,field.reaction].filter(Boolean).join(' · '),line);const b=textNode('button','Inspect parser',line);b.onclick=()=>openObservation(candidate.observation,'parser');}}
   for(const candidate of backtrack.navigation_candidates){const card=textNode('div','',section);card.className='value-card';textNode('b',candidate.url||candidate.api||candidate.kind,card);textNode('p',candidate.basis+' · '+candidate.shared.join(', '),card);if(candidate.url_basis)textNode('p','URL basis: '+candidate.url_basis,card);const b=textNode('button','Open navigation candidate',card);b.onclick=()=>openObservation(candidate.observation,'webview');}
   const staticLinks=backtrack.static_connections;
   for(const path of staticLinks?.navigation_paths||[]){
    const card=textNode('div','',section);card.className='value-card';textNode('b','Possible static path · '+path.hops+' calls',card);
    textNode('pre',path.methods.join('\n → ')+'\n → '+path.target,card);
    textNode('p',path.gates.length?'Conditional branches: '+path.gates.map(g=>g.method+' @'+g.offset+' '+g.opcode).join(', '):'No conditional branch indexed on this path.',card);
    textNode('p','Code references only; execution and response provenance are not established.',card);
    const b=textNode('button','Find navigation method in code',card);b.onclick=()=>{openView('code');$('filter').value=path.methods.at(-1);scheduleCodeSearch();};
   }
   if(staticLinks?.limited)textNode('p','Static lookup reached its depth or method budget. Increase Backtrack hops or search the remaining methods in Code & URL search.',section);
   const frame=evidence.app_callers?.[0];
   if(frame){const b=textNode('button','Search '+frame.class+' in code',section);b.onclick=()=>{openView('code');$('filter').value=frame.class;scheduleCodeSearch();};}
  }
  const chain=textNode('p',frameLabel(higher)+' → '+frameLabel(primary)+' → '+(data.api||record.kind),box);chain.className='caller-chain';
  chain.title='Next distinct outer stack frame → nearest app method → operation. Frame adjacency can include instrumentation.';
  textNode('p','Next distinct outer method: '+frameLabel(higher),box);
  const search=textNode('button','Copy JADX search',box);search.onclick=()=>navigator.clipboard.writeText(frameLabel(primary)).catch(()=>{notice='Copy manually: '+frameLabel(primary);render();});
  const scope=textNode('button','Download scope pack for these app methods',box);scope.onclick=()=>downloadScope(record.id);
  if(data.navigation_kind?.startsWith('custom_tab')){
   textNode('h4','Custom Tab · '+(data.navigation_outcome||data.navigation_kind.replace('custom_tab_','').replaceAll('_',' ')),box);
   if(data.url){textNode('pre',data.url,box);copyIcon(box,'Custom Tab URL',()=>data.url);}
   if(data.url_basis)textNode('p','URL is the session’s launch context; the callback does not report a final browser URL.',box);
   if(data.browser_package)textNode('p','Browser: '+data.browser_package,box);
   if(data.session_attribution)textNode('p',data.session_attribution,box);
   if(data.error_description||data.error)textNode('p',data.error_description||data.error,box);
  }
  if(evidence.network){const n=evidence.network;textNode('h4',n.url||n.destination||n.peer||'Destination unattributed',box);textNode('p',[n.direction,n.method,n.status_line,n.peer,n.url_status].filter(Boolean).join(' · '),box);}
  if(evidence.crypto){
   const crypto=evidence.crypto;textNode('h4',(crypto.direction||'Crypto')+' · '+(crypto.algorithm||'Algorithm unavailable'),box);
   const grid=document.createElement('div');grid.className='value-grid';box.append(grid);
   for(const [name,value] of Object.entries(crypto.values)){
    const card=document.createElement('div');card.className='value-card';grid.append(card);
    textNode('label',({input:crypto.operation==='crypto.updateAAD'?'Authenticated additional data':crypto.mode===2?'Encrypted input':crypto.mode===1?'Plaintext input':'Input',output:crypto.mode===2?'Decrypted result':crypto.mode===1?'Encrypted result':'Output',key:'Key',iv:'Nonce / IV'})[name]||name,card);
    const selector=textNode('select','',card);selector.setAttribute('aria-label',name+' encoding');
    for(const encoding of ['utf8','hex','base64'])if(value[encoding]!=null){const option=textNode('option',encoding==='utf8'?'Text':encoding==='hex'?'Hex':'Base64',selector);option.value=encoding;}
    selector.hidden=!selector.options.length;selector.value=(name==='key'||name==='iv'||value.utf8==null||/[\x00-\x08\x0e-\x1f]/.test(value.utf8))?'hex':'utf8';
    const preview=textNode('pre',value[selector.value]??value.reason??value.status??'Not observed',card);
    selector.onchange=()=>preview.textContent=value[selector.value];
    if(selector.options.length)copyIcon(card,name,()=>copyValue(value,selector.value));
    if(value.reason)textNode('p',value.reason,card);
    if(value.basis)textNode('p',value.basis.replaceAll('_',' '),card);
    if(value.truncated||value.display_truncated)textNode('p',value.truncated?'Capture limited: some bytes were not retained.':'Preview limited; copy retrieves the retained bytes.',card);
    if(value.snapshot){const b=textNode('button','Download '+name+' bytes',card);b.onclick=()=>download(value.snapshot,true).catch(e=>{notice=e.message;render();});}
    if(value.source?.event){const b=textNode('button','Follow source',card);b.onclick=()=>{const source=evidence.flow.steps.find(s=>s.event===value.source.event);if(source)navigate(source);};}
   }
  }
  if(evidence.network_context?.length){const related=textNode('details','',box);related.open=!!evidence.request_backtracking;textNode('summary','Possible request / JSON parser context ('+evidence.network_context.length+')',related);
   textNode('p','Shared app methods or classes within '+$('flow-depth').value+' stack levels are leads; they do not establish a response handoff.',related);
   for(const candidate of evidence.network_context){const card=textNode('div','',related);textNode('b',candidate.api||candidate.kind,card);textNode('p',candidate.basis+' · '+candidate.shared.join(', '),card);for(const field of candidate.fields)textNode('pre',[field.path,field.expected_type,field.access_state,field.reaction].filter(Boolean).join(' · '),card);const follow=textNode('button','Inspect',card);follow.onclick=async()=>{const e=await api(evidenceURL(candidate.observation));inspectRecord(e.record);};}
  }else if(evidence.request_backtracking){textNode('p','No shared request/parser context was found in retained events. Inspect static connections below, or search Code & URL search.',box);
  }
  const context=document.createElement('details');textNode('summary','App code — search these methods in JADX',context);
  for(const frame of evidence.app_callers||[])textNode('pre',frame.jadx_search+' '+(frame.signature||'')+'\n'+(frame.origin||''),context);box.append(context);
  if(evidence.enclosing_invocations?.length){const calls=document.createElement('details');textNode('summary','Observed enclosing calls:',calls);textNode('pre',evidence.enclosing_invocations.slice().reverse().map(x=>x.api||x.kind).join(' → '),calls);box.append(calls);}
  if(evidence.object_observations?.length){const objects=document.createElement('details');textNode('summary','Objects & fields ('+evidence.object_observations.length+')',objects);
   for(const n of evidence.object_observations)textNode('pre',[n.phase,n.path,n.class,n.preview??n.status??n.object_id].filter(Boolean).join(' · '),objects);box.append(objects);}
  if(evidence.native_caller){const native=document.createElement('details');textNode('summary','Native attribution',native);textNode('pre',JSON.stringify(evidence.native_caller,null,2),native);box.append(native);}
  const navigate=async step=>{try{const known=timeline.find(r=>r.id===step.observation);const target=known||(await api(evidenceURL(step.observation))).record;await inspectRecord({...target,summary:known?.summary,package_classes:known?.package_classes},true);syncFlowSelection(target);}catch(e){notice=e.message;render();}};
  if(!keepGraph){rootRecord=record;drawFlow(evidence.flow,$('graph'),navigate);}else if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);
  if(evidence.flow.missing_references.length||Object.values(evidence.flow.coverage||{}).some(Boolean))textNode('p','Partial flow: some events were outside the retained graph window.',box);
  if(!evidence.flow.edges.length)textNode('p','No preceding data handoff established. Unobserved hops remain unattributed.',box);
 }catch(e){if(generation===actionGeneration){notice='Evidence: '+e.message;render();}}
 finally{if(generation===actionGeneration)$('copy-flow-json').disabled=false;}
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
async function downloadRoute(path){
 const r=await fetch(path,{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw Error((await r.json()).error);
 const blob=await r.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');
 link.href=url;link.download=(r.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'export.txt';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);return {download:link.download,bytes:blob.size};
}
async function copyValue(value,encoding){
 const ids=value.snapshots||(value.snapshot?[value.snapshot]:[]);if(!ids.length)return value[encoding]??value.reason;
 const parts=[];let size=0;
 for(const id of ids){const r=await fetch('/api/download?snapshot='+encodeURIComponent(id)+'&format=raw',{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw Error((await r.json()).error);const bytes=new Uint8Array(await r.arrayBuffer());size+=bytes.length;if(size>4*1024*1024)throw Error('Use artifact download for values larger than 4 MiB.');parts.push(bytes);}
 const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
 if(encoding==='utf8')return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(encoding==='hex')return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
 let text='';for(let i=0;i<bytes.length;i+=32768)text+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(text);
}
async function refreshStrings(){
 if(stringBusy)return;stringBusy=true;const options=exportOptions().toString(),method=stringSelectedMethod;
 try{const result=await api('/api/strings?'+options+'&method='+encodeURIComponent(method));if(view==='strings'&&options===exportOptions().toString()&&method===stringSelectedMethod)stringResults=result;}catch(e){notice='Strings: '+e.message;setText('strings-status',notice);}finally{stringBusy=false;}
}
function renderStrings(){
 if(!stringResults){setText('strings-status','Loading observed transformations…');$('strings-pairs').replaceChildren();return;}
 const candidates=stringResults.candidates.filter(packageMatches).sort((a,b)=>b.calls-a.calls||b.pairs-a.pairs||a.method.localeCompare(b.method));
 const signature=JSON.stringify([stringSelectedMethod,candidates.map(c=>[c.method,c.calls,c.string_results,c.pairs]),stringResults.pairs.map(p=>[p.observation,p.input_sha256,p.output_sha256,p.occurrences])]);
 if(signature===stringRenderSignature)return;stringRenderSignature=signature;
 const methods=$('strings-methods');methods.replaceChildren();$('all-string-mappings').setAttribute('aria-pressed',String(!stringSelectedMethod));
 for(const candidate of candidates){const b=textNode('button','',methods);b.className='record';b.setAttribute('aria-pressed',String(stringSelectedMethod===candidate.method));
  textNode('span',candidate.classification==='cipher_decrypt'?'Cipher decrypt':'Decoder candidate',b).className='badge';textNode('b',candidate.method,b);textNode('small',candidate.calls+' calls · '+candidate.string_results+' string results · '+candidate.pairs+' unique pairs',b);
  b.onclick=()=>{++actionGeneration;stringSelectedMethod=candidate.method;stringResults=null;stringRenderSignature='';renderStrings();refreshStrings().then(()=>{if(view==='strings')renderStrings();});};
 }
 setText('strings-title','CIPHER → PLAINTEXT'+(stringSelectedMethod?' · '+stringSelectedMethod:''));
 setText('strings-status',stringResults.pairs.length+' displayed / '+stringResults.pair_count+' matching pairs · '+candidates.length+' methods · Export includes all matching retained methods.');
 const box=$('strings-pairs');box.replaceChildren();
 if(!candidates.length){textNode('p',state?.checkpoint?.sequence&&!showEarlier?'No transformations in the current display window. Click Show earlier results to search the saved evidence.':'No retained string transformations match. Known Cipher decrypts appear after they run. For unknown decoders, select app methods in App calls or Code & URL search, download a scope pack and repeat capture.',box);return;}
 if(!stringResults.pairs.length){textNode('p','No mappings for this method match the current search. Choose All mappings or adjust the filters.',box);return;}
 const table=textNode('table','',box),head=textNode('tr','',textNode('thead','',table));for(const label of ['CIPHER / input','PLAINTEXT / output','Method / evidence'])textNode('th',label,head);
 const body=textNode('tbody','',table);
 for(const pair of stringResults.pairs){const tr=textNode('tr','',body);
  for(const [role,label] of [['cipher','cipher'],['plaintext','plaintext']]){const td=textNode('td','',tr);textNode('pre',pair[role].slice(0,1000)+(pair[role].length>1000?'\n… preview limited; copy retains the saved value':''),td);copyIcon(td,label,()=>pair[role]);}
  const td=textNode('td','',tr);textNode('b',pair.method,td);textNode('small',(pair.classification==='cipher_decrypt'?'Observed Cipher decrypt':'Decoder candidate; semantics unverified')+' · '+pair.occurrences+' occurrences',td);
  if(pair.conversion==='later_byte_array_to_string')textNode('small','byte[] return → later String conversion · '+(pair.source_basis||'association unverified'),td);
  if(pair.input_truncated)textNode('small','Input capture is partial',td);
  const inspect=textNode('button','Inspect call / flow',td);inspect.onclick=()=>openObservation(pair.observation);
  if(pair.classification==='decoder_candidate'){const scope=textNode('button','Trace decoder next run',td);scope.onclick=()=>downloadScope(pair.observation,undefined,true);}
 }
 setText('status',stringResults.truncated?'Latest 10,000 transformation events; export coverage is recorded.':stringResults.note);
}
async function refreshLogcat(){
 if(logBusy)return;logBusy=true;
 try{const result=await api('/api/logcat?after='+logCursor);logRows.push(...result.rows);logRows=logRows.slice(-5000);logCursor=result.last;logState=result;}catch(e){logState={status:{state:'failed',reason:e.message}};}finally{logBusy=false;}
}
function visibleLogs(){const text=$('logcat-search').value.toLowerCase(),levels='VDIWEFA',minimum=levels.indexOf($('logcat-level').value);return logRows.filter(row=>(!$('logcat-app').checked||row.app)&&levels.indexOf(row.level)>=minimum&&packageMatches(row)&&(!text||logText(row).toLowerCase().includes(text))).slice(-2000);}
function logText(row){return [row.time,row.pid,row.tid,row.level,row.tag+':',row.message].filter(v=>v!=null).join(' ');}
function renderLogcat(){
 const box=$('logcat-output'),rows=visibleLogs(),query=$('logcat-search').value.toLowerCase(),signature=JSON.stringify([rows.map(r=>r.sequence),query]);
 setText('logcat-status',(logState?.status.state||'Loading')+' · '+rows.length+' matching lines'+(logState?.status.reason?' · '+logState.status.reason:'')+(logState?.gap?' · older lines exceeded the retention window':''));
 if(box.dataset.signature===signature)return;box.dataset.signature=signature;const previous=box.scrollTop;box.replaceChildren();
 for(const row of rows){const line=textNode('div','',box);line.className='log-line log-'+row.level;const text=logText(row);let offset=0,at=query?text.toLowerCase().indexOf(query):-1;
  while(at>=0){line.append(document.createTextNode(text.slice(offset,at)));textNode('mark',text.slice(at,at+query.length),line);offset=at+query.length;at=text.toLowerCase().indexOf(query,offset);}line.append(document.createTextNode(text.slice(offset)));}
 box.scrollTop=$('logcat-follow').checked?box.scrollHeight:previous;
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
 if(view==='backtrack')return withFlowSelection(events.filter(r=>r.kind.startsWith('network.')));
 if(['jni','network','crypto','parser','flow'].includes(view))return withFlowSelection(events.filter(r=>r.kind.startsWith(view+'.')||(view==='network'&&recordData(r).network_category)));
 if(view==='webview')return withFlowSelection(events.filter(r=>['webview.loadUrl','webview.postUrl','webview.loadData','webview.loadDataWithBaseURL'].includes(r.kind)||r.kind.startsWith('webview.custom_tab')||recordData(r).navigation_kind?.startsWith('custom_tab')||recordData(r).navigation_outcome==='failed'));
 return events;
}
function rowLabels(record){
 const data=recordData(record),nearest=record.summary?.caller||appFrame(record),outer=record.summary?.called_by;
 const caller=frameLabel(nearest),chain=outer?frameLabel(outer)+' → '+caller:caller;
 if(record.kind==='trace_payload'){let meta={};try{meta=JSON.parse(record.metadata);}catch(e){}return {title:meta.source||'Captured bytes',sub:(record.received||0)+' bytes · '+record.status,badge:'Payload',extra:meta.correlation||''};}
 if(record.dynamic_load)return {title:record.kind,sub:(record.received||0)+' bytes · '+record.status,badge:record.dynamic_load.dynamically_loaded?'Dynamic load':'Code artifact',extra:(record.hash||'Pending').slice(0,20)};
 if(record.finding)return {title:Object.values(record.finding.mapping).map(v=>v.utf8??v.base64??v.status??'').join(' → '),sub:chain,badge:'Observed string',extra:record.finding.semantic_basis||record.finding.execution};
 if(data.navigation_kind?.startsWith('custom_tab'))return {title:data.url||data.api||'Custom Tab',sub:[data.navigation_outcome,data.browser_package,data.error_description||data.session_attribution,chain].filter(Boolean).join(' · '),badge:data.navigation_outcome==='failed'?'Custom Tab failed':data.navigation_outcome==='aborted'?'Custom Tab aborted':data.network_category==='navigation_intent'?'Custom Tab request intent':data.navigation_kind==='custom_tab_callback'?'Custom Tab callback':data.navigation_kind==='custom_tab_prefetch'?'Custom Tab prefetch':'Custom Tab',extra:data.api};
 if(data.navigation_outcome==='failed')return {title:data.url||'Failed WebView request',sub:data.error_description||'WebView reported a load error',badge:'Failed request',extra:data.error_code||data.api};
 if(data.network_category)return {title:data.url||data.arguments?.[0]||'WebView navigation',sub:chain,badge:data.network_category==='navigation_intent'?'WebView request intent':'WebView callback',extra:data.api};
 if(record.kind?.startsWith('crypto.')){const value=role=>{const v=record.summary?.values?.[role]||{};return v.utf8??(v.hex!=null?'hex:'+v.hex:null)??v.base64??v.reason??v.status??'Not observed at this boundary';};return {title:chain,sub:(data.algorithm||'')+' · '+(data.direction||record.kind.split('.')[1]),badge:'Crypto',extra:value('input').slice(0,72)+' → '+value('output').slice(0,100)};}
 if(record.kind?.startsWith('network.')){const n=record.summary?.network||{};return {title:n.url||n.destination||n.peer||data.url||'Destination unattributed',sub:[n.method,n.direction,n.status_line].filter(Boolean).join(' · '),badge:'Network',extra:n.peer||data.api||''};}
 return {title:data.url||data.path||data.api||caller,sub:chain,badge:record.kind||record.handler||'Finding',extra:data.access_state||data.outcome||record.state||''};
}
function render(){
 if(!state)return;
 setText('title',({inventory:'Loaded code',payloads:'Captured bytes',jni:'JNI trace',webview:'Navigation flows',backtrack:'Request backtracking',parser:'Parsers',flow:'App calls',code:'Code & URL search',strings:'Decrypted strings',logcat:'ADB logcat'})[view]||view[0].toUpperCase()+view.slice(1));
 $('logcat-panel').hidden=view!=='logcat';$('strings-panel').hidden=view!=='strings';document.querySelector('.workbench').style.display=['logcat','strings'].includes(view)?'none':'';
 document.querySelector('.inspection').classList.toggle('request-inspection',view==='backtrack');
 const help={backtrack:'Select a network request or response. The lookup checks linked events and shared app callers within 8 hops by default, including JSON parser fields and possible WebView / Custom Tab connections. Adjust Backtrack hops above the graph. Filter SDKs with -pkg:com.appsflyer.',strings:'CIPHER → PLAINTEXT mappings appear below. Methods are ranked by retained call frequency. Select a method to filter its mappings, copy either value, inspect the source call, or export all pairs. Automatic pre-analysis selects bounded decoder candidates; readable output alone does not prove decryption.'}[view];
 $('view-help').hidden=!help;if(help)setText('view-help',help);
 setText('graph-title',view==='backtrack'?'Request flow':'Flow');
 document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-current',b.dataset.view===view?'page':'false'));
 const cov=state.coverage;
 setText('context',`${cov.run.app} · ${cov.run.device} · Run ${cov.run.id.slice(0,8)} · ${cov.run.state} · ${cov.processes.map(p=>p.pid+' '+p.state).join(', ')||'no process'}`);
 $('context').title='Run '+cov.run.id;$('earlier').hidden=!state.checkpoint?.sequence;
 $('earlier').textContent=showEarlier?'Hide earlier results':'Show earlier results';
 setText('status',notice);
 actionHost=document.createElement('div');
 if(view==='logcat'){$('actions').replaceChildren();renderLogcat();return;}
 if(view==='strings'){button('Export CIPHER - PLAINTEXT',()=>downloadRoute('/api/strings/export?'+exportOptions()+'&format=txt'));button('Export JSONL with provenance',()=>downloadRoute('/api/strings/export?'+exportOptions()+'&format=jsonl'));$('actions').replaceChildren(...actionHost.childNodes);renderStrings();return;}
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
  }else if(!['inventory','payloads','findings'].includes(view))button('Export trace',()=>api('/api/action',{action:'export-trace',kinds:view==='timeline'?[]:view==='backtrack'?['network.','parser.','webview.','flow.']:[view+'.']}));
  if(view==='network'){const b=textNode('button','Backtrack selected request',actionHost);b.disabled=!focusedFlowRecord?.kind?.startsWith('network.');b.onclick=()=>openObservation(focusedFlowRecord.id,'backtrack');}
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
    // Show the connected Run after the first page, even when a saved capture
    // needs several timeline pages before the initial refresh finishes.
    if(pages===0)render();
    if(next.timeline.length<500)break;
   }while(++pages<5);
   if(view==='strings')await refreshStrings();if(view==='logcat')await refreshLogcat();
   if(notice==='Connecting…'||notice.startsWith('Refresh failed:'))notice='Connected';
   render();
  }catch(e){notice='Refresh failed: '+e.message;$('status').textContent=notice;}
 })().finally(()=>refreshing=null);
 return refreshing;
}
function openView(nextView){
 filters[view]=$('filter').value;positions[view]=$('rows').scrollTop;
 view=nextView;page=0;++actionGeneration;detailMode='record';selected=null;rootRecord=null;lastFlow=null;lastEvidence=null;focusedFlowRecord=null;selectedFromGraph=false;graphExpanded=view==='backtrack';$('graph').replaceChildren();$('filter').value=filters[view]||'';
 if(view==='strings'){stringSelectedMethod='';stringResults=null;stringRenderSignature='';}
 $('evidence').replaceChildren();$('rows').replaceChildren();$('details').textContent='Select a record to inspect its observed evidence.';render();
 $('rows').scrollTop=positions[view]||0;
 if(view==='code')scheduleCodeSearch();
 if(view==='strings'||view==='logcat')refresh();
}
document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>openView(b.dataset.view));
$('open-logcat').onclick=()=>openView('logcat');
$('all-string-mappings').onclick=()=>{++actionGeneration;stringSelectedMethod='';stringResults=null;stringRenderSignature='';renderStrings();refreshStrings().then(()=>{if(view==='strings')renderStrings();});};
for(const [id,key] of [['include-packages','include'],['exclude-packages','exclude']])$(id).oninput=()=>{if(key==='include')packageInclude=$(id).value;else packageExclude=$(id).value;page=0;++actionGeneration;render();if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);if(focusedFlowRecord?.data&&view!=='strings')inspectRecord(focusedFlowRecord);if(view==='strings')refreshStrings().then(render);if(view==='code')searchCode().catch(e=>{notice=e.message;render();});};
$('filter').oninput=()=>{page=0;if(view==='code'){++actionGeneration;scheduleCodeSearch();}if(view==='strings')refreshStrings().then(render);if(lastFlow?.box===$('graph'))drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);const options=searchOptions(),packageQuery=JSON.stringify([options.include,options.exclude]);if(packageQuery!==lastPackageQuery){lastPackageQuery=packageQuery;clearTimeout(evidenceTimer);evidenceTimer=setTimeout(()=>{if(focusedFlowRecord?.data&&view!=='strings')inspectRecord(focusedFlowRecord);},250);}render();};$('filter').onkeydown=e=>{if(e.key==='Enter'&&view==='code'){clearTimeout(codeSearchTimer);searchCode().catch(e=>{notice=e.message;render();});}};$('refresh').onclick=()=>{refresh();if(view==='code')scheduleCodeSearch();};
$('previous').onclick=()=>{page=Math.max(0,page-1);render();$('rows').scrollTop=0;};$('next').onclick=()=>{page++;render();$('rows').scrollTop=0;};
document.querySelectorAll('[data-inspector]').forEach(b=>b.onclick=()=>inspector(b.dataset.inspector));
$('copy-flow-json').onclick=()=>copyText($('details').textContent).catch(e=>setText('status',e.message));
$('full-json').onclick=()=>{fullJson=!fullJson;$('full-json').textContent=fullJson?'Compact JSON':'Full JSON';show(focusedFlowRecord||{});};
$('flow-depth').onchange=()=>{const value=Number($('flow-depth').value);if(!Number.isInteger(value)||value<1||value>8){$('flow-depth').value='8';return;}if(focusedFlowRecord)inspectRecord(focusedFlowRecord);if(view==='strings')refreshStrings().then(render);};
for(const id of ['logcat-search','logcat-level','logcat-app'])$(id).oninput=renderLogcat;
$('copy-logcat').onclick=()=>copyText(visibleLogs().map(logText).join('\n')).catch(e=>setText('status',e.message));
$('zoom-in').onclick=()=>{graphZoom=Math.min(1.8,graphZoom+.15);if(lastFlow)drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);};
$('zoom-out').onclick=()=>{graphZoom=Math.max(.35,graphZoom-.15);if(lastFlow)drawFlow(lastFlow.flow,lastFlow.box,lastFlow.navigate,lastFlow.staticMode);};
$('clear-results').onclick=()=>$('clear-dialog').showModal();$('cancel-clear').onclick=()=>$('clear-dialog').close();
$('confirm-clear').onclick=async()=>{try{await api('/api/action',{action:'clear-workspace'});showEarlier=false;page=0;selected=null;++actionGeneration;$('graph').replaceChildren();$('evidence').replaceChildren();$('details').textContent='';$('rows').replaceChildren();$('clear-dialog').close();notice='Results cleared · Capture continues · Saved evidence preserved';await refresh();}catch(e){notice=e.message;render();}};
$('earlier').onclick=()=>{showEarlier=!showEarlier;page=0;render();if(view==='code'){++actionGeneration;scheduleCodeSearch();}if(view==='strings'){stringResults=null;stringRenderSignature='';refreshStrings().then(()=>{if(view==='strings')renderStrings();});}};
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
