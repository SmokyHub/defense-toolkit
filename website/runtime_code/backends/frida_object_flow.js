// Scoped object-flow observations. No arbitrary getters, equals(), hashCode() or toString().
const objectRecords=new Map(),objectBuckets=new Map(),objectClasses=new Set(),objectMethodKeys=new Set();
const objectDiscoveredMethods=new Set();let objectHelpers=null,objectHookLimitReported=false;
const objectDefaults={object_depth:4,object_fields:24,object_nodes:12,tracked_objects:512,object_time_ms:20,max_methods:96};
function objectOptions(token){return Object.assign({},objectDefaults,token.selection);}
function reserveObjectHook(token,key){
 const limit=objectOptions(token).max_methods;
 if(objectMethodKeys.size>=limit){
  if(!objectHookLimitReported){objectHookLimitReported=true;event('coverage',{token:token.name,state:'partial',reason:'app_method_hook_limit',limit});}
  return false;
 }
 objectMethodKeys.add(key);return true;
}
function objectIdentity(value,options){
 const hash=String(objectHelpers.System.identityHashCode(value));
 const bucket=objectBuckets.get(hash)||[];
 for(const record of bucket){
  const previous=record.weak.get();
  if(previous!==null&&Java.vm.getEnv().isSameObject(previous.$h,value.$h))return record;
 }
 if(objectRecords.size>=options.tracked_objects){
  const old=objectRecords.values().next().value;objectRecords.delete(old.id);
  objectBuckets.set(old.hash,(objectBuckets.get(old.hash)||[]).filter(r=>r!==old));
  if(!objectBuckets.get(old.hash).length)objectBuckets.delete(old.hash);
  old.weak.$dispose();losses.object_identities_evicted=(losses.object_identities_evicted||0)+1;
 }
 const record={id:'object-'+(++serial),hash,weak:Java.retain(objectHelpers.Weak.$new(value)),last_event:null};
 objectRecords.set(record.id,record);const current=objectBuckets.get(hash)||[];current.push(record);objectBuckets.set(hash,current);
 return record;
}
function objectPlatform(name){return /^(android\.|androidx\.|java\.|javax\.|sun\.|dalvik\.|libcore\.|com\.android\.|kotlin\.|kotlinx\.)/.test(name);}
function objectLink(context,source,path,relation,extra={}){
 if(!source||source===context.id||context.data_links.length>=48)return;
 context.data_links.push(Object.assign({event:source,path,association:relation},extra));
}
function observeObjectValue(token,value,path,depth,context,budget){
 const options=budget.options;
 if(Date.now()>budget.deadline||budget.nodes--<=0){losses.object_snapshot_limits=(losses.object_snapshot_limits||0)+1;return {path,status:'budget_exhausted'};}
 if(value===null||value===undefined)return {path,value:null};
 if(typeof value==='string'||value.$className==='java.lang.String'){
  let text;
  if(typeof value==='string')text=value;else {const string=Java.cast(value,objectHelpers.String),length=string.length();if(length>65536)return {path,type:'string',preview:String(string.substring(0,512)),length,status:'size_limit'};text=String(string);}
  const bytes=text.length<=65536?textBytes(text):null;
  const hash=bytes?Checksum.compute('sha256',bytes):null,source=hash?flowSources.get(hash):null;
  if(source)objectLink(context,source.event,path,'inferred_equal_bytes',{sha256:hash,source_path:source.path||null});
  return {path,type:'string',preview:text.slice(0,512),length:text.length,sha256:hash,hash_status:hash?'observed_utf8':'size_limit'};
 }
 if(typeof value==='number'||typeof value==='boolean')return {path,value};
 if(!value.$h)return {path,status:'not_an_instance',type:value.$className||typeof value};
 let record;
 try{record=objectIdentity(value,options);}catch(e){return {path,status:'identity_unavailable',reason:flowText(e)};}
 const node={path,object_id:record.id,class:value.$className,identity_basis:'JNI_IsSameObject_with_weak_reference'};
 objectLink(context,record.last_event,path,'observed_same_object',{object_id:record.id});
 budget.identities.add(record.id);
 if(node.class==='[B'){
  const bytes=javaBytes(value,0,value.length),hash=Checksum.compute('sha256',bytes),source=flowSources.get(hash);
  node.length=value.length;node.sha256=hash;node.hash_scope=bytes.byteLength===value.length?'full_array':'captured_prefix';
  if(source)objectLink(context,source.event,path,'inferred_equal_bytes',{sha256:hash});
  return node;
 }
 if(budget.seen.has(record.id)){node.status='repeated_reference';return node;}
 budget.seen.add(record.id);
 if(depth>=options.object_depth){node.status='depth_limit';return node;}
 if(objectPlatform(node.class||'')){node.status='platform_fields_excluded';return node;}
 node.fields=[];
 try{
  let cls=value.getClass();let supers=0;
  while(cls!==null&&supers++<4&&!objectPlatform(String(cls.getName()))){
   const fields=cls.getDeclaredFields();
   for(let i=0;i<fields.length;i++){
    if(budget.fields<=0||budget.nodes<=0||Date.now()>budget.deadline){node.status='budget_exhausted';losses.object_snapshot_limits=(losses.object_snapshot_limits||0)+1;return node;}
    const field=fields[i];if((field.getModifiers()&8)!==0)continue; // No static field reads/class initialization.
    budget.fields--;
    const fieldName=String(field.getName()),fieldPath=path+'.'+fieldName;
    try{field.setAccessible(true);node.fields.push({declaring_class:String(cls.getName()),name:fieldName,
      value:observeObjectValue(token,field.get(value),fieldPath,depth+1,context,budget)});}
    catch(e){node.fields.push({name:fieldName,status:'unreadable',reason:flowText(e)});}
   }
   cls=cls.getSuperclass();
  }
  node.status='observed_fields';
 }catch(e){node.status='unreadable';node.reason=flowText(e);}
 return node;
}
function objectBoundary(token,values,context,phase){
 const options=objectOptions(token),budget={options,nodes:options.object_nodes,fields:options.object_fields,
  deadline:Date.now()+options.object_time_ms,seen:new Set(),identities:new Set()};
 const observations=[];
 for(const [path,value] of values)observations.push(observeObjectValue(token,value,path,0,context,budget));
 context[phase]=observations;
 return budget.identities;
}
function commitObjectBoundary(context,identities){
 for(const id of identities){const record=objectRecords.get(id);if(record)record.last_event=context.id;}
 // A returned string is a value observed at this boundary, not proof of where it was allocated.
 for(const value of context.objects_after||[])if(value.path==='return'&&value.sha256)remember(flowSources,value.sha256,{event:context.id,path:'return'});
}
function instrumentObjectMethod(token,name,method){
 flowHook(token,name,method,{kind:'flow.call',
  before(args,ctx){
   ctx.data_links=[];ctx.method_kind=method==='$init'?'constructor':'method';
   const values=args.map((arg,i)=>['argument['+i+']',arg]);
   if(method!=='$init'&&this.$h)values.unshift(['receiver',this]);
   objectBoundary(token,values,ctx,'objects_before');
   ctx.field_observation='Snapshots at method boundaries; no claim of individual field reads/writes';ctx.field_consistency='sequential_field_reads_not_atomic';
  },
  after(args,result,ctx){
   const values=[['return',result]];if(this.$h)values.push(['receiver',this]);
   const identities=objectBoundary(token,values,ctx,'objects_after');commitObjectBoundary(ctx,identities);ctx.outcome='returned';
  },
  error(args,error,ctx){ctx.outcome='threw';ctx.objects_after=[];}});
}
function instrumentObjectClass(token,name,reason){
 if(objectClasses.has(name)||objectClasses.size>=32||!selected(token,name))return;
 objectClasses.add(name);
 try{
  const Class=Java.use(name),methods=Class.class.getDeclaredMethods(),names=new Set(['$init']);
  for(let i=0;i<Math.min(methods.length,128);i++)if(!(methods[i].getModifiers()&(256|1024)))names.add(String(methods[i].getName()));
  for(const method of names)instrumentObjectMethod(token,name,method);
  event('coverage.flow_scope',{token:token.name,class:name,reason,installed_methods:objectMethodKeys.size,
   started_ms:Date.now(),earlier_calls:'not_recoverable',field_reads:'not_instrumented'});
 }catch(e){event('coverage',{token:token.name,state:'partial',class:name,reason:'app_class_unavailable: '+flowText(e)});}
}
function discoverObjectFlow(frames){
 const token=tokens.get('flow.java');if(!token||!token.selection.discover_from_stacks||!objectHelpers)return;
 for(const frame of frames){
  const name=frame.class||'',origin=frame.origin||'',method=frame.method==='<init>'?'$init':frame.method,key=name+'.'+method;
  if(!method||!origin.startsWith('/data/')||objectPlatform(name)||objectDiscoveredMethods.has(key)||objectDiscoveredMethods.size>=64)continue;
  objectDiscoveredMethods.add(key);
  event('flow.candidate',{id:'candidate-'+(++serial),token:token.name,class:name,method,origin,
   reason:'observed_stack_candidate_only',trace_enabled:false,
   request:{class:name,method},limitation:'Select a bounded scope and restart capture; no runtime hook expansion'});
 }
}
function installObjectFlow(){
 const token=tokens.get('flow.java');if(!token)return;
 objectHelpers={System:Java.use('java.lang.System'),Weak:Java.use('java.lang.ref.WeakReference'),String:Java.use('java.lang.String')};
 for(const name of token.selection.classes||[])instrumentObjectClass(token,name,'pack_selected');
 for(const method of token.selection.methods||[])instrumentObjectMethod(token,method.class,method.method);
 event('coverage',{token:token.name,state:(token.selection.classes||[]).length||(token.selection.methods||[]).length?'active':'candidates_only',limits:objectOptions(token),
  object_identity:'JNI IsSameObject verification; bounded weak references; identity expires on eviction or collection',
  limitations:['Selected Java methods only; no universal taint tracking','Field snapshots do not prove which bytecode read or wrote a field','Automatic stack discovery emits candidates only; selected hooks install on the next run','Native/Dart/JS execution and unobserved asynchronous handoffs remain gaps','Default Java class loader only; unreadable fields and budgets are explicit']});
}

function stopObjectFlow(){for(const record of objectRecords.values()){try{record.weak.$dispose();}catch(e){}}objectRecords.clear();objectBuckets.clear();}
