// Bounded platform observations; application names never determine eligibility.
const flowHooks=new Set(),flowObjects=new Map(),flowSources=new Map(),flowThreads=new Map(),flowMissing=new Map();
const socketIds=new Map(),networkSymbols=new Set(),flowIntents=new Map(),flowLaunchRoots=new Map(),flowNetworkContexts=new Map(),networkLast=new Map();
const webviewClients=new Map(),clientOrigins=new Map();
const webviewNavigations=new Map();
function navigationIdentity(value){
 if(typeof objectHelpers!=='undefined'&&objectHelpers){try{return {id:objectIdentity(value,objectDefaults).id,association:'observed_same_object'};}catch(e){}}
 return {id:flowId(value),association:'inferred_identity_hash_only'};
}
function remember(map,key,value){if(map.size>=1024&&!map.has(key))map.delete(map.keys().next().value);map.set(key,value);}
function flowText(value){
 if(value===null||value===undefined)return null;
 try{
  if(typeof value==='string')return value.slice(0,2048);
  if(typeof value==='number'||typeof value==='boolean')return String(value);
  if(value instanceof Error)return String(value.message).slice(0,2048);
  if(value.$className==='java.lang.String'){const string=Java.cast(value,Java.use('java.lang.String'));return String(string.substring(0,Math.min(2048,string.length())));}
  if(/^java.lang.(Integer|Long|Double|Float|Boolean|Short|Byte|Character)$/.test(value.$className||''))return String(value);
  if(typeof value.length==='number')return '<array length='+value.length+'>';
  return '<'+(value.$className||typeof value)+'>';
 }catch(e){return '<unreadable>';}
}
function flowId(value){try{return value.$className+':'+Java.use('java.lang.System').identityHashCode(value);}catch(e){return 'unknown';}}
function javaBytes(value,offset,length){
 const size=Math.min(length,65536,config.limits.capture_bytes);
 if(size<=0)return new ArrayBuffer(0);
 const memory=Memory.alloc(size);Java.vm.getEnv().getByteArrayRegion(value.$h,offset,size,memory);
 return memory.readByteArray(size);
}
function textBytes(value){
 const text=String(value);if(text.length>65536)return null;
 return byteArray(Java.use('java.lang.String').$new(text).getBytes('UTF-8'));
}
function payload(token,bytes,context,total,retain=true){
 if(!bytes)return {status:'not_captured',reason:'input_size_limit'};
 const hash=Checksum.compute('sha256',bytes),previous=flowSources.get(hash);
 const result={length:total===undefined?bytes.byteLength:total,captured_length:bytes.byteLength,sha256:hash,
   truncated:total!==undefined&&total>bytes.byteLength,hash_scope:total>bytes.byteLength?'captured_prefix':'observed_fragment',
   source:previous?Object.assign({association:'inferred_equal_bytes'},previous):{association:'unattributed'}};
 remember(flowSources,hash,{event:context.id});
 // HTTP/1 plaintext fragments may contain headers and body together. A body match
 // remains explicitly inferred, never presented as general data-flow tracking.
 const raw=new Uint8Array(bytes);
 if(raw.length>8&&raw[0]===72&&raw[1]===84&&raw[2]===84&&raw[3]===80){
  for(let i=4;i<Math.min(raw.length-3,16384);i++)if(raw[i]===13&&raw[i+1]===10&&raw[i+2]===13&&raw[i+3]===10){
   remember(flowSources,Checksum.compute('sha256',bytes.slice(i+4)),{event:context.id,slice_offset:i+4});break;
  }
 }
 if(retain)capture(token,bytes,{kind:'trace_payload',source:context.kind,correlation:context.id,
   caller:context.caller||[],api:context.api,
   logical_id:context.id+'-'+(++serial),payload:result,input_original:true,
   limitations:['Observed fragment; not necessarily a whole request/response or complete source']},Date.now());
 if(result.truncated){losses.truncated_bytes=(losses.truncated_bytes||0)+total-bytes.byteLength;}
 return result;
}
function flowHook(token,name,method,handlers){
 runtimeDebug.mark('java.hook.resolve:'+name+'.'+method);
 let Class;
 try{Class=Java.use(name);if(!Class[method]){remember(flowMissing,token.name+':'+name+'.'+method,'method unavailable');return;}}
 catch(e){remember(flowMissing,token.name+':'+name+'.'+method,flowText(e));return;}
 // The bridge may expose inherited members (including Object's constructor for
 // an interface). Never install those under a selected app class's identity.
 let declared=null;
 if(method==='$init'||token.capability==='flow.java'){
  try{
   declared=new Set();
   const members=method==='$init'?Class.class.getDeclaredConstructors():Class.class.getDeclaredMethods();
   for(let i=0;i<members.length;i++){
    const member=members[i];
    if(method!=='$init'&&String(member.getName())!==method)continue;
    const parameters=member.getParameterTypes(),names=[];
    for(let j=0;j<parameters.length;j++)names.push(String(parameters[j].getName()));
    declared.add(names.join(','));
   }
  }catch(e){remember(flowMissing,token.name+':'+name+'.'+method,'declaring member validation failed: '+flowText(e));return;}
 }
 for(const overload of Class[method].overloads){
  const signature=overload.argumentTypes.map(t=>t.className),key=name+'.'+method+'('+signature.join(',')+')';
  if(declared!==null&&(!declared.has(signature.join(','))||overload.holder.$className!==name)){
   remember(flowMissing,token.name+':'+key,'inherited or undeclared member excluded');continue;
  }
  if(flowHooks.has(key))continue;
  if(token.capability==='flow.java'&&!reserveObjectHook(token,key))continue;
  flowHooks.add(key);
  runtimeDebug.mark('java.hook.install:'+key);
  overload.implementation=function(){
   const args=Array.from(arguments),tid=Process.getCurrentThreadId();
   if(guards.has(tid)||!selected(token,name))return overload.apply(this,args);
   const debugCall=runtimeDebug.enter(key);
   try {
   if(handlers.accept){let accepted=false;withGuard(()=>{accepted=handlers.accept.call(this,args);});if(!accepted)return overload.apply(this,args);}
   const previous=flowThreads.get(tid),ctx={id:'flow-'+(++serial),kind:handlers.kind,token:token.name,
     api:key,started_ms:Date.now(),caller:[],parent:previous||null,signature,return_type:overload.returnType.className};
   withGuard(()=>{if(handlers.stack===false)ctx.caller_attribution='unattributed: stack walk excluded at concurrent socket boundary';else ctx.caller=stack();if(ctx.caller.some(f=>f.class==='java.lang.reflect.Method'||f.class==='java.lang.reflect.Constructor'))ctx.invocation_mechanism='reflection_frame_observed';if(typeof discoverObjectFlow==='function')discoverObjectFlow(ctx.caller);if(handlers.before)handlers.before.call(this,args,ctx);});
   flowThreads.set(tid,ctx.id);
   try{
    const result=overload.apply(this,args);
    withGuard(()=>{if(handlers.after)handlers.after.call(this,args,result,ctx);ctx.ended_ms=Date.now();if(!ctx.skip)event(ctx.kind,ctx);});
    return result;
   }catch(e){
    withGuard(()=>{ctx.outcome='threw';ctx.error=flowText(e);if(handlers.error)handlers.error.call(this,args,e,ctx);ctx.ended_ms=Date.now();if(!ctx.skip)event(ctx.kind,ctx);});
    throw e;
   }finally{if(previous)flowThreads.set(tid,previous);else flowThreads.delete(tid);}
   } finally { runtimeDebug.leave(debugCall); }
  };
  hooks.push(overload);
  runtimeDebug.mark('java.hook.installed:'+key);
 }
}
function hookStream(token,stream,exchange,direction,context){
 if(!stream)return;
 remember(flowObjects,flowId(stream),{exchange,direction});
 context.stream=flowId(stream);context.direction=direction;
 remember(flowNetworkContexts,Process.getCurrentThreadId(),{event:context.id,time:Date.now(),exchange,direction});
 // Blocking Java read/write replacement callbacks can deadlock with concurrent ART
 // stack walks. Only record the returned stream; bytes are captured by native hooks.
}
function hookConnection(token,connection,url){
 if(!connection)return;const name=String(connection.$className);
 remember(flowObjects,flowId(connection),{exchange:'exchange-'+(++serial),url});
 for(const method of ['connect','setRequestMethod','setRequestProperty','getResponseCode','getInputStream','getErrorStream','getOutputStream']){
  flowHook(token,name,method,{kind:method==='getResponseCode'?'network.response':'network.request',
   before(args,ctx){Object.assign(ctx,flowObjects.get(flowId(this))||{association:'unattributed'});ctx.arguments=args.map(flowText);},
   after(args,result,ctx){
    if(method==='getResponseCode')ctx.status_code=result;
    if(['getInputStream','getErrorStream','getOutputStream'].includes(method))hookStream(token,result,ctx.exchange,method==='getOutputStream'?'out':'in',ctx);
   }
  });
 }
}
function installFlows(){
 installReflectionAndDecoders();
 const web=tokens.get('webview.platform'),net=tokens.get('network.platform'),parser=tokens.get('parser.json'),custom=tokens.get('parser.custom'),crypto=tokens.get('crypto.cipher');
 if(net)try{
  flowHook(net,'java.net.URL','openConnection',{kind:'network.open',
    before(args,ctx){ctx.url=flowText(this.toExternalForm());},after(args,result,ctx){hookConnection(net,result,ctx.url);}});
  for(const method of ['getInputStream','getOutputStream'])flowHook(net,'java.net.Socket',method,{kind:'network.socket',stack:false,
   before(args,ctx){ctx.endpoint=flowText(this.getRemoteSocketAddress());ctx.exchange=flowId(this);},
   after(args,result,ctx){hookStream(net,result,ctx.exchange,method==='getInputStream'?'in':'out',ctx);}});
  event('coverage',{token:net.name,scope:'URL connections and returned socket/connection stream metadata; no blocking Java I/O replacements',limitations:['Other Java transports may bypass these boundaries','Payload bytes require network.native; no Java read/write byte capture','Native WebView renderer traffic is in another process']});
 }catch(e){event('coverage',{token:net.name,state:'partial',reason:'Optional hook installation failed: '+flowText(e)});}
 if(web)try{
  for(const name of ['android.app.Activity','android.app.Fragment','androidx.fragment.app.Fragment'])
   for(const method of ['onCreate','onResume','onStart','startActivity','startActivityForResult','startService'])
    flowHook(web,name,method,{kind:'webview.lifecycle',before(args,ctx){ctx.component=this.$className;ctx.arguments=args.map(flowText);try{
     const intent=args[0]&&args[0].$className==='android.content.Intent'?args[0]:this.getIntent();
     ctx.intent={action:flowText(intent.getAction()),component:intent.getComponent()?flowText(intent.getComponent().flattenToString()):null,data:flowText(intent.getDataString())};ctx.extras={};const extras=intent.getExtras();
     if(extras){const keys=extras.keySet().iterator();for(let n=0;n<32&&keys.hasNext();n++){const key=String(keys.next());ctx.extras[key]=flowText(extras.get(key));}}
     const fingerprint=JSON.stringify({intent:ctx.intent,extras:ctx.extras});
     const readable=Object.values(ctx.extras).every(x=>typeof x==='string'&&!x.startsWith('<')&&x.length<2048||x===null);
     if(ctx.intent.action==='android.intent.action.VIEW'&&Object.prototype.hasOwnProperty.call(ctx.extras,'android.support.customtabs.extra.SESSION')){
      ctx.navigation_kind='custom_tab_intent';ctx.navigation_basis='observed_VIEW_intent_with_custom_tabs_session_extra';ctx.url=ctx.intent.data;
     }
     ctx.intent_sources=[];
     for(const value of Object.values(ctx.extras))if(typeof value==='string'){
      const bytes=textBytes(value),source=bytes?flowSources.get(Checksum.compute('sha256',bytes)):null;
      if(source)ctx.intent_sources.push(Object.assign({association:'inferred_equal_bytes'},source));
     }
     if(method.startsWith('startActivity')||method==='startService'){
      const root=flowLaunchRoots.get(ctx.parent);
      remember(flowLaunchRoots,ctx.id,root||ctx.id);
      if(!root){const candidates=flowIntents.get(fingerprint)||[];candidates.push({event:ctx.id,time:Date.now()});remember(flowIntents,fingerprint,candidates.slice(-4));}
     }else{
      const candidates=(flowIntents.get(fingerprint)||[]).filter(x=>Date.now()-x.time<30000);
      if(readable&&candidates.length===1)ctx.launch_source={event:candidates[0].event,association:'inferred_equal_intent_fields'};
      else ctx.launch_attribution=!readable?'intent_extras_incomplete':candidates.length?'ambiguous_matching_launches':'launch_not_observed';
     }
    }catch(e){}}});
  for(const method of ['loadUrl','postUrl','loadData','loadDataWithBaseURL','evaluateJavascript','addJavascriptInterface','removeJavascriptInterface']){
   flowHook(web,'android.webkit.WebView',method,{kind:'webview.'+method,
    before(args,ctx){ctx.webview=flowId(this);ctx.arguments=args.map(flowText);
     const viewIdentity=navigationIdentity(this);ctx.client_source=webviewClients.get(viewIdentity.id+'.setWebViewClient')||null;ctx.chrome_client_source=webviewClients.get(viewIdentity.id+'.setWebChromeClient')||null;
     if(['loadUrl','postUrl','loadData','loadDataWithBaseURL'].includes(method))remember(webviewNavigations,viewIdentity.id,{event:ctx.id,association:viewIdentity.association});
     if(method==='loadUrl'){const bytes=textBytes(args[0]);ctx.url=flowText(args[0]);ctx.url_origin=bytes?flowSources.get(Checksum.compute('sha256',bytes))||{association:'unattributed'}:{association:'unattributed'};if(ctx.url_origin.event)ctx.url_origin=Object.assign({association:'inferred_equal_bytes'},ctx.url_origin);}
     if(['loadData','loadDataWithBaseURL','evaluateJavascript'].includes(method)){
      const i=method==='loadDataWithBaseURL'?1:0;ctx.payload=payload(web,textBytes(args[i]),ctx);}
     if(method==='addJavascriptInterface'&&args[0]){
      const object=args[0],name=String(object.$className);ctx.bridge_name=flowText(args[1]);ctx.bridge_class=name;
      const methods=object.getClass().getMethods();ctx.exposed_methods=[];
      for(let i=0;i<Math.min(methods.length,256);i++){
       if(methods[i].isAnnotationPresent(Java.use('android.webkit.JavascriptInterface').class)){
        const methodName=String(methods[i].getName());ctx.exposed_methods.push(String(methods[i]));
        flowHook(web,name,methodName,{kind:'webview.bridge',before(a,c){c.arguments=a.map(flowText);c.bridge_class=name;c.js_callsite={status:'unattributed',reason:'Java callback does not expose JavaScript source location'};}});
       }
      }
     }
    }});
  }
  for(const method of ['setWebViewClient','setWebChromeClient'])flowHook(web,'android.webkit.WebView',method,{kind:'webview.client',
   before(args,ctx){ctx.view_identity=navigationIdentity(this);ctx.client=null;if(!args[0])return;const name=String(args[0].$className);ctx.client=name;
    ctx.client_origin=clientOrigins.get(navigationIdentity(args[0]).id)||null;
    for(const callback of ['onPageStarted','onPageFinished','shouldOverrideUrlLoading','shouldInterceptRequest','onReceivedError','onReceivedHttpError','onReceivedSslError','onConsoleMessage'])
     flowHook(web,name,callback,{kind:'webview.callback',before(a,c){
      c.arguments=a.map(flowText);c.client_class=name;
      try{c.navigation_source=webviewNavigations.get(navigationIdentity(a[0]).id)||null;}catch(e){}
      try{c.url=c.signature[1]==='java.lang.String'?flowText(a[1]):flowText(a[1].getUrl().toString());}catch(e){}
      if(['onReceivedError','onReceivedHttpError','onReceivedSslError'].includes(callback)){
       c.navigation_outcome='failed';c.failure_basis='observed_webview_error_callback';
       try{
        if(callback==='onReceivedError'&&c.signature[1]==='int'){c.error_code=a[1];c.error_description=flowText(a[2]);c.url=flowText(a[3]);}
        else if(callback==='onReceivedError'){c.error_code=a[2].getErrorCode();c.error_description=String(a[2].getDescription()).slice(0,2048);c.main_frame=a[1].isForMainFrame();}
        else if(callback==='onReceivedHttpError'){c.status_code=a[2].getStatusCode();c.error_description=flowText(a[2].getReasonPhrase());}
        else{c.url=flowText(a[2].getUrl());c.error_code=a[2].getPrimaryError();}
       }catch(e){c.error_detail='unavailable';}
      }
     },after(a,r,c){c.return_value=flowText(r);}});
   },after(args,result,ctx){if(ctx.view_identity)remember(webviewClients,ctx.view_identity.id+'.'+method,{event:ctx.id,association:ctx.view_identity.association,client:ctx.client});}});
  flowHook(web,'android.webkit.WebResourceResponse','$init',{kind:'webview.resource_response',before(args,ctx){ctx.arguments=args.map(flowText);}});
  event('coverage',{token:web.name,scope:'Platform WebView APIs, installed client overrides and annotated Java bridges',limitations:['Flow parents reflect observed synchronous nesting; asynchronous hops may be unattributed','Custom Tabs and renderer JS callsites not fully covered','Compose app code is attributed at platform boundaries']});
 }catch(e){event('coverage',{token:web.name,state:'partial',reason:'Optional hook installation failed: '+flowText(e)});}
 if(parser)try{
  const nullClass=String(Java.use('org.json.JSONObject').NULL.value.getClass().getName());
  for(const name of ['org.json.JSONObject','org.json.JSONArray']){
   flowHook(parser,name,'$init',{kind:'parser.parse',before(args,ctx){if(ctx.signature[0]==='java.lang.String'){ctx.preview=flowText(args[0]);ctx.payload=payload(parser,textBytes(args[0]),ctx);}},after(args,result,ctx){remember(flowObjects,flowId(this),{path:'$',parse:ctx.id});ctx.object=flowId(this);}});
   for(const method of ['get','opt','getString','optString','getInt','optInt','getLong','optLong','getBoolean','optBoolean','getDouble','optDouble','getJSONObject','optJSONObject','getJSONArray','optJSONArray']){
    flowHook(parser,name,method,{kind:'parser.field',before(args,ctx){
     const parent=flowObjects.get(flowId(this))||{path:'$',parse:null};ctx.parse=parent.parse;
     const key=args[0];ctx.path=parent.path+(typeof key==='number'?'['+key+']':'.'+String(key));ctx.expected_type=method.replace(/^(get|opt)/,'')||'any';
     const value=this.opt(key);ctx.observed_value=flowText(value);
     const present=name==='org.json.JSONObject'?this.has(key):key>=0&&key<this.length();
     const isNull=value===null||value.$className===nullClass;
     if(isNull)ctx.observed_value=null;
     ctx.access_state=!present?'absent':isNull?'null':'present';
     if(value!==null)ctx.observed_type=value.$className||typeof value;
    },after(args,result,ctx){
     if(result&&result.$className&&['org.json.JSONObject','org.json.JSONArray'].includes(result.$className))remember(flowObjects,flowId(result),{path:ctx.path,parse:ctx.parse});
     if(['getString','optString'].includes(method)&&result!==null)ctx.output=payload(parser,textBytes(result),ctx);
     ctx.result=flowText(result);if(ctx.access_state!=='present')ctx.reaction=method.startsWith('opt')?'default_or_null_returned':'returned';
     if(ctx.access_state==='present'&&ctx.expected_type!=='any'){
      const expected={String:'java.lang.String',JSONObject:'org.json.JSONObject',JSONArray:'org.json.JSONArray',Boolean:'java.lang.Boolean'}[ctx.expected_type];
      if(expected&&ctx.observed_type!==expected)ctx.access_state='type_mismatch';
      if(['Int','Long','Double'].includes(ctx.expected_type)&&ctx.observed_type&&!/Integer|Long|Double|Float|Short|Byte/.test(ctx.observed_type))ctx.access_state='type_mismatch';
     }
    },error(args,error,ctx){ctx.reaction='exception';if(ctx.access_state==='present')ctx.access_state='type_mismatch';}});
   }
  }
  event('coverage',{token:parser.name,scope:'org.json constructor and field access',limitations:['Custom parser semantics require declared methods','Byte-equality source links are inference, not taint tracking']});
 }catch(e){event('coverage',{token:parser.name,state:'partial',reason:'Optional hook installation failed: '+flowText(e)});}
 if(custom)try{
  for(const selector of custom.selection.methods||[])flowHook(custom,selector.class,selector.method,{kind:'parser.custom',
   before(args,ctx){ctx.arguments=args.map(flowText);ctx.schema='unknown_custom_parser';for(let i=0;i<args.length;i++)if(ctx.signature[i]==='java.lang.String'){ctx.input=payload(custom,textBytes(args[i]),ctx);break;}},
   after(args,result,ctx){ctx.result=flowText(result);if(result!==null&&ctx.return_type==='java.lang.String')ctx.output=payload(custom,textBytes(result),ctx);}});
  event('coverage',{token:custom.name,selectors:custom.selection.methods||[],limitations:['Declared parser calls observed; no inferred expected-field schema for arbitrary bytecode','Classes in alternate class loaders may need a dedicated adapter']});
 }catch(e){event('coverage',{token:custom.name,state:'partial',reason:'Optional hook installation failed: '+flowText(e)});}
 if(crypto)try{
  flowHook(crypto,'javax.crypto.Cipher','init',{kind:'crypto.init',
   before(args,ctx){ctx.mode=args[0];ctx.algorithm=String(this.getAlgorithm());},
   after(args,result,ctx){
    ctx.key={status:'not_requested',reason:'capture_keys selection disabled'};
    if(crypto.selection.capture_keys===true){
     try{
      const key=args[1],encoded=key.getEncoded();
      ctx.key_algorithm=String(key.getAlgorithm());ctx.key_format=key.getFormat()?String(key.getFormat()):null;
      ctx.key=encoded?payload(crypto,javaBytes(encoded,0,encoded.length),ctx,encoded.length):{status:'unavailable',reason:'Key is not exportable (for example Android Keystore)'};
     }catch(e){ctx.key={status:'unavailable',reason:'Key encoding unavailable: '+flowText(e)};}
    }
    const iv=this.getIV();ctx.iv=iv?payload(crypto,javaBytes(iv,0,iv.length),ctx,iv.length):{status:'absent',reason:'Algorithm has no IV'};
    remember(flowObjects,flowId(this),{mode:ctx.mode,algorithm:ctx.algorithm,key:ctx.key,key_algorithm:ctx.key_algorithm,key_format:ctx.key_format,iv:ctx.iv,init_event:ctx.id});
   }});
  for(const method of ['update','doFinal','updateAAD'])flowHook(crypto,'javax.crypto.Cipher',method,{kind:'crypto.'+method,
   before(args,ctx){
    Object.assign(ctx,flowObjects.get(flowId(this))||{key:{status:'unavailable',reason:'Initialization occurred before observation or metadata was evicted'}});
    ctx.cipher=flowId(this);ctx.algorithm=String(this.getAlgorithm());
    ctx.direction=ctx.mode===1?'encrypt':ctx.mode===2?'decrypt':'other_or_unknown';
    ctx.previous_cipher_event=ctx.previous_event||null;delete ctx.previous_event;
    // doFinal(byte[], int) supplies an OUTPUT buffer; it is not ciphertext input.
    const outputOnly=method==='doFinal'&&ctx.signature.length===2&&ctx.signature[0]==='[B';
    if(ctx.signature[0]==='[B'&&!outputOnly){
     const offset=ctx.signature.length>=3?args[1]:0,length=ctx.signature.length>=3?args[2]:args[0].length;
     ctx.input=payload(crypto,javaBytes(args[0],offset,length),ctx,length);
    }else ctx.input={status:'not_captured',reason:outputOnly||!args.length?'Input from previous update calls; follow previous_cipher_event':'Unsupported input representation'};
   },
   after(args,result,ctx){
    if(result&&ctx.return_type==='[B')ctx.output=payload(crypto,javaBytes(result,0,result.length),ctx,result.length);
    else if(ctx.return_type==='int'&&result>=0){
     const index=ctx.signature.lastIndexOf('[B');
     if(index>=0){const offset=ctx.signature[index+1]==='int'?args[index+1]:0;ctx.output=payload(crypto,javaBytes(args[index],offset,result),ctx,result);}
     else ctx.output={status:'not_captured',reason:'Unsupported output representation'};
    }else ctx.output={status:'absent',reason:'No output returned by this call'};
    const remembered=flowObjects.get(ctx.cipher);if(remembered)remembered.previous_event=ctx.id;
   }});
  flowHook(crypto,'android.util.Base64','decode',{kind:'crypto.base64',
   before(args,ctx){if(ctx.signature[0]==='java.lang.String')ctx.input=payload(crypto,textBytes(args[0]),ctx,undefined,crypto.selection.capture_keys===true);},
   after(args,result,ctx){if(result)ctx.output=payload(crypto,javaBytes(result,0,result.length),ctx,result.length,crypto.selection.capture_keys===true);ctx.raw_retention=crypto.selection.capture_keys===true?'enabled_by_scoped_crypto_token':'disabled: decoded material may be a key';}});
  event('coverage',{token:crypto.name,scope:'Cipher byte-array operations and Android Base64 decode',key_material:crypto.selection.capture_keys===true?'exportable_encoding_requested':'not_requested',limitations:['Nonexportable keystore keys remain unavailable','Native and hand-rolled algorithms are not identified automatically','ByteBuffer overloads remain unsupported','Incremental operations retain fragments linked by previous_cipher_event; no fabricated combined message']});
 }catch(e){event('coverage',{token:crypto.name,state:'partial',reason:'Optional hook installation failed: '+flowText(e)});}
 event('coverage.flow_hooks',{installed:Array.from(flowHooks),unavailable:Array.from(flowMissing,([target,reason])=>({target,reason})),object_correlation:'bounded identity-hash cache; collisions/evictions can reduce attribution'});
}
function installNativeNetwork(){
 const token=tokens.get('network.native');if(!token)return;
 const libc=Process.getModuleByName('libc.so'),getpeer=new NativeFunction(libc.getExportByName('getpeername'),'int',['int','pointer','pointer']);
 function peer(fd){const address=Memory.alloc(128),length=Memory.alloc(4);length.writeU32(128);if(getpeer(fd,address,length)!==0)return null;const family=address.readU16();if(family!==2&&family!==10)return null;const bytes=new Uint8Array(address.readByteArray(Math.min(28,length.readU32())));const port=bytes[2]*256+bytes[3];let ip;
  if(family===2)ip=Array.from(bytes.slice(4,8)).join('.');else {const parts=[];for(let i=8;i<24;i+=2)parts.push((bytes[i]*256+bytes[i+1]).toString(16));ip=parts.join(':');}
  return {family,ip,port,address_hex:Array.from(bytes).map(x=>x.toString(16).padStart(2,'0')).join('')};}
 function install(image,name,tls){
  const address=image.findExportByName(name);if(!address||networkSymbols.has(address.toString()))return;
  networkSymbols.add(address.toString());
  const outgoing=['write','send','sendto','SSL_write'].includes(name);
  nativeHooks.push(Interceptor.attach(address,{
   onEnter(args){
    this.active=false;const tid=Process.getCurrentThreadId();if(guards.has(tid))return;
    guards.add(tid);
    try{
     const endpoint=tls?{tls_object:args[0].toString()}:peer(args[0].toInt32());if(!endpoint)return;
     const callerImage=Process.findModuleByAddress(this.returnAddress);
     if(callerImage&&(/frida|rc-test-fsd|gum-js/.test(callerImage.path)||!selected(token,callerImage.path)))return;
     this.ctx={id:'net-'+(++serial),kind:'network.native',token:token.name,api:name,direction:outgoing?'out':'in',endpoint,parent:flowThreads.get(Process.getCurrentThreadId())||null,
       representation:tls?'TLS_API_plaintext':'socket_bytes_may_be_encrypted',
       native_caller:{return_address:this.returnAddress.toString(),module:callerImage?callerImage.path:null,status:'return_address_only',static_callsite:'unattributed'}};
     const context=flowNetworkContexts.get(tid);if(context&&Date.now()-context.time<30000&&context.direction===(outgoing?'out':'in'))this.ctx.context_source={event:context.event,association:'inferred_same_thread_recent_stream',exchange:context.exchange};
     if(!tls){const fd=args[0].toInt32();let connection=socketIds.get(fd);if(!connection){connection='socket-'+(++serial);remember(socketIds,fd,connection);}this.ctx.fd=fd;this.ctx.connection=connection;}
     this.pointer=args[1];this.length=args[2].toUInt32();this.active=true;
     if(outgoing&&this.length)this.bytes=this.pointer.readByteArray(Math.min(this.length,65536,config.limits.capture_bytes));
    }catch(e){event('coverage.gap',{token:token.name,reason:'native_network_copy',error:String(e)});}finally{guards.delete(tid);}
   },
   onLeave(result){if(!this.active)return;withGuard(()=>{
    const count=result.toInt32();this.ctx.result=count;
    if(count>0){const bytes=outgoing?this.bytes:this.pointer.readByteArray(Math.min(count,this.length,65536,config.limits.capture_bytes));
     if(bytes)this.ctx.payload=payload(token,outgoing?bytes.slice(0,Math.min(count,bytes.byteLength)):bytes,this.ctx,count);}
    if(this.ctx.connection){this.ctx.connection_source=networkLast.get(this.ctx.connection)||null;remember(networkLast,this.ctx.connection,{event:this.ctx.id,association:'observed_same_connection_not_causality'});}
    event('network.native',this.ctx);
   });}
  }));
 }
 for(const name of ['read','write','send','recv','sendto','recvfrom'])install(libc,name,false);
 nativeHooks.push(Interceptor.attach(libc.getExportByName('close'),{onEnter(args){socketIds.delete(args[0].toInt32());}}));
 const inspect=image=>{for(const name of ['SSL_read','SSL_write'])install(image,name,true);};
 for(const image of Process.enumerateModules())inspect(image);
 // Inventory callbacks schedule export lookup outside the linker callback.
 const moduleObserver=Process.attachModuleObserver({onAdded(image){setImmediate(()=>{if(!stopped){try{inspect(image);}catch(e){}}});}});
 nativeHooks.push({detach(){moduleObserver.detach();}});
 event('coverage',{token:token.name,scope:'libc connected-socket I/O and exported SSL_read/SSL_write',limitations:['No sendmsg/recvmsg or io_uring coverage','Hidden/inlined TLS, QUIC and custom crypto plaintext are unsupported','Socket data is not automatically decoded into HTTP','Native caller is an observed return address, not a claimed static callsite']});
}

function frameworkCoverage(){
 let names=[];try{names=Process.enumerateModules().map(image=>image.name.toLowerCase());}catch(e){}
 const markers={Unity:['libunity.so','libil2cpp.so'],Flutter:['libflutter.so','libapp.so'],Hermes:['libhermes.so'],Cocos:['libcocos2dcpp.so','libcocos2djs.so','libcocos.so']};
 for(const [framework,files] of Object.entries(markers)){
  const observed=files.filter(name=>names.includes(name));
  if(observed.length)event('coverage.framework',{framework,basis:'module_name_indicator',observed,
   support:'Platform/native boundaries only; no engine heap or bytecode traversal',
   limitations:['Engine-specific crypto and script frames may remain unattributed','Java absence or missing optional classes must not disable independent native observation']});
 }
 if(typeof Java!=='undefined'&&Java.available)try{Java.use('org.apache.cordova.CordovaWebView');event('coverage.framework',{framework:'Cordova',basis:'class_available',support:'WebView platform boundaries; JavaScript source frames may remain unattributed'});}catch(e){}
}

function installReflectionAndDecoders(){
 const reflection=tokens.get('reflection.java'),decoder=tokens.get('crypto.custom'),web=tokens.get('webview.platform');
 if(web){
  for(const name of ['androidx.browser.customtabs.CustomTabsIntent','android.support.customtabs.CustomTabsIntent'])
   flowHook(web,name,'launchUrl',{kind:'webview.custom_tab',before(args,ctx){ctx.url=args[1]?String(args[1].toString()):null;const bytes=ctx.url?textBytes(ctx.url):null;ctx.url_origin=bytes?flowSources.get(Checksum.compute('sha256',bytes))||{association:'unattributed'}:{association:'unattributed'};}});
 }
 if(reflection)try{
  // Replacing caller-sensitive reflection APIs changes Java access checks. Observe
  // constructor targets and target stacks instead; never force accessibility.
  for(const name of ['android.webkit.WebViewClient','android.webkit.WebChromeClient'])
   flowHook(reflection,name,'$init',{kind:'reflection.client_constructor',
    before(args,ctx){ctx.resolved_class=this.$className;ctx.resolved_method='$init';ctx.target=ctx.resolved_class+'.$init';
     ctx.client_identity=navigationIdentity(this);
     ctx.reflection_frames=ctx.caller.filter(f=>f.class==='java.lang.reflect.Constructor'||f.class==='java.lang.reflect.Method');
     ctx.invocation_mechanism=ctx.reflection_frames.length?'reflection_frame_observed':'not_established';},
    after(args,result,ctx){ctx.outcome='returned';if(ctx.client_identity)remember(clientOrigins,ctx.client_identity.id,{event:ctx.id,association:ctx.client_identity.association});}});
  event('coverage',{token:reflection.name,scope:'WebView client base constructors and reflection frames at observed targets',limitations:['Caller-sensitive Method.invoke and Constructor.newInstance are deliberately not replaced','Unexecuted code requires static indexing','A reflection frame proves stack context, not every reflective lookup or dispatch argument','Alternate/inlined/custom navigation paths may remain unattributed']});
 }catch(e){event('coverage',{token:reflection.name,state:'partial',reason:flowText(e)});}
 if(decoder)try{
  function encodedArgument(value,type,ctx){
   if(type==='java.lang.String'&&value!==null)return payload(decoder,textBytes(value),ctx);
   if(type==='[B'&&value!==null)return payload(decoder,javaBytes(value,0,value.length),ctx,value.length);
   return {status:'unsupported',reason:'Only bounded String and byte[] values are retained',type};
  }
  for(const selector of decoder.selection.methods||[])flowHook(decoder,selector.class,selector.method,{kind:'crypto.custom',
   before(args,ctx){ctx.algorithm='app_defined_unverified';ctx.direction='Observed app transformation';ctx.parameters=[];
    for(let i=0;i<Math.min(args.length,8);i++)ctx.parameters.push(encodedArgument(args[i],ctx.signature[i],ctx));
    ctx.input=ctx.parameters[0]||{status:'absent'};ctx.semantic_basis='Pack-selected method; algorithm and argument roles are not inferred from names';},
   after(args,result,ctx){ctx.output=encodedArgument(result,ctx.return_type,ctx);ctx.outcome='returned';}});
  event('coverage',{token:decoder.name,selectors:decoder.selection.methods||[],limitations:['Scoped executed methods only; unknown/inlined decoders require static analysis or another scope','All selected String/byte[] parameters are retained, including key bytes when passed as such; their semantic roles are unverified','No native decoder or unsupported buffer/char[] overload coverage']});
 }catch(e){event('coverage',{token:decoder.name,state:'partial',reason:flowText(e)});}
}
