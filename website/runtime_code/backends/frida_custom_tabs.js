// App-side Custom Tabs boundaries. Browser internals remain outside this process.
const tabClients=new Map(),tabSessions=new Map(),tabCallbacks=new Map(),tabBuilders=new Map(),tabIntents=new Map(),tabConnections=new Map(),tabLaunches=new Map();
const tabCallbackClasses=new Set();
const tabNavigationEvents={1:'started',2:'finished',3:'failed',4:'aborted',5:'shown',6:'hidden'};
function tabSource(event,association){return {event,association};}
function tabURL(ctx,uri){
 if(uri===null||uri===undefined){ctx.url=null;ctx.url_origin={association:'unattributed'};return;}
 const text=String(uri.toString());ctx.url=text.slice(0,2048);
 const bytes=textBytes(text),source=bytes?flowSources.get(Checksum.compute('sha256',bytes)):null;
 ctx.url_origin=source?Object.assign({association:'inferred_equal_bytes'},source):{association:'unattributed'};
}
function tabSessionContext(value,ctx){
 if(!value)return null;
 const identity=navigationIdentity(value);ctx.session_identity=identity;
 const state=tabSessions.get(identity.id);
 if(state){ctx.session_source=tabSource(state.event,identity.association);ctx.browser_package=state.browser_package;}
 else ctx.session_attribution='Session creation was not observed or its metadata was evicted';
 return state;
}
function tabLaunch(ctx,state){
 const root=tabLaunches.get(ctx.parent)||ctx.id;remember(tabLaunches,ctx.id,root);
 if(root!==ctx.id)ctx.navigation_source=tabSource(root,'observed_nested_custom_tab_launch');
 if(state&&root===ctx.id)state.navigation={event:root,url:ctx.url,association:'observed_same_session_last_launch_not_causality'};
}
function isCustomTabsIntent(intent){
 try{return intent&&String(intent.getAction())==='android.intent.action.VIEW'&&intent.hasExtra('android.support.customtabs.extra.SESSION');}catch(e){return false;}
}
function customTabsIntentObservation(intent,ctx,isLaunch){
 if(!isCustomTabsIntent(intent))return false;
 ctx.navigation_kind='custom_tab_intent';ctx.navigation_basis='observed_VIEW_intent_with_custom_tabs_session_extra';
 tabURL(ctx,intent.getData());ctx.browser_package=intent.getPackage()?String(intent.getPackage()):null;
 const identity=navigationIdentity(intent),known=tabIntents.get(identity.id);
 if(known){ctx.intent_source=tabSource(known.event,identity.association);ctx.session_identity=known.session_identity;
  const state=known.session_identity?tabSessions.get(known.session_identity.id):null;
  if(state)ctx.session_source=tabSource(state.event,known.session_identity.association);
  if(isLaunch)tabLaunch(ctx,state);
 }else {ctx.session_attribution='No observed Builder/session association; raw intent remains a navigation boundary';if(isLaunch)tabLaunch(ctx,null);}
 if(isLaunch)ctx.kind='webview.custom_tab_intent';
 return true;
}
function tabFailure(args,error,ctx){ctx.navigation_outcome='failed';ctx.failure_basis='observed_custom_tab_launch_exception';ctx.error_description=flowText(error);}
function tabInstallCallbacks(token,value,methods,handlers){
 if(!value)return;
 let cls=value.getClass();
 for(let depth=0;cls&&depth<8;depth++,cls=cls.getSuperclass()){
  const name=String(cls.getName()),key=name+':'+methods.join(',');
  if(tabCallbackClasses.has(key))continue;
  if(tabCallbackClasses.size>=64)return;
  tabCallbackClasses.add(key);
  const declared=cls.getDeclaredMethods(),names=new Set();
  for(let i=0;i<Math.min(declared.length,256);i++)names.add(String(declared[i].getName()));
  for(const method of methods)if(names.has(method))flowHook(token,name,method,handlers(method));
  if(name==='java.lang.Object')break;
 }
}
function tabCallbackHandlers(token,method){return {kind:'webview.custom_tab_callback',before(args,ctx){
 ctx.navigation_kind='custom_tab_callback';ctx.callback_class=this.$className;ctx.callback_identity=navigationIdentity(this);ctx.arguments=args.map(flowText);
 const callback=tabCallbacks.get(ctx.callback_identity.id),sessions=callback?callback.sessions:[];
 if(callback)ctx.callback_source=tabSource(callback.event,ctx.callback_identity.association);
 if(sessions.length===1){const state=tabSessions.get(sessions[0]);
  if(state){ctx.session_source=tabSource(state.event,'observed_registered_callback');ctx.browser_package=state.browser_package;
   if(state.navigation){ctx.navigation_source=state.navigation;ctx.url=state.navigation.url;ctx.url_basis='session_last_launch_context_not_callback_url';}}
  else ctx.session_attribution='Session metadata was evicted; callback navigation is unattributed';
 }else ctx.session_attribution=sessions.length?'Callback reused across sessions; navigation association is ambiguous':'No observed session for callback';
 if(method==='onNavigationEvent'){
  ctx.navigation_event=Number(args[0]);ctx.navigation_outcome=tabNavigationEvents[ctx.navigation_event]||'unknown';
  if(ctx.navigation_outcome==='failed')ctx.failure_basis='observed_custom_tabs_navigation_failed_callback';
 }else if(method==='onPostMessage'){
  ctx.message_direction='browser_to_app';ctx.payload=payload(token,textBytes(args[0]),ctx);
 }else if(method==='onRelationshipValidationResult'){
  ctx.relationship=Number(args[0]);ctx.origin=args[1]?String(args[1].toString()).slice(0,2048):null;ctx.validated=Boolean(args[2]);
 }
},after(args,result,ctx){ctx.return_value=flowText(result);}};}
function installCustomTabs(token){
 for(const base of ['androidx.browser.customtabs.','android.support.customtabs.']){
  const Client=base+'CustomTabsClient',Builder=base+'CustomTabsIntent$Builder',Intent=base+'CustomTabsIntent',Session=base+'CustomTabsSession';
  for(const method of ['bindCustomTabsService','bindCustomTabsServicePreservePriority'])flowHook(token,Client,method,{kind:'webview.custom_tab_connection',before(args,ctx){
   ctx.navigation_kind='custom_tab_connection';ctx.browser_package=args[1]?String(args[1]):null;
   if(!args[2])return;const identity=navigationIdentity(args[2]);remember(tabConnections,identity.id,{event:ctx.id,browser_package:ctx.browser_package});
   tabInstallCallbacks(token,args[2],['onCustomTabsServiceConnected','onServiceDisconnected','onBindingDied','onNullBinding'],callback=>({kind:'webview.custom_tab_connection',before(a,c){
    c.navigation_kind='custom_tab_connection';c.arguments=a.map(flowText);const id=navigationIdentity(this),bound=tabConnections.get(id.id);
    if(bound){c.connection_source=tabSource(bound.event,id.association);c.browser_package=bound.browser_package;}
    c.connection_state=callback==='onCustomTabsServiceConnected'?'connected':callback==='onServiceDisconnected'?'disconnected':callback==='onNullBinding'?'rejected':'binding_died';
    if(callback==='onCustomTabsServiceConnected'&&a[1])remember(tabClients,navigationIdentity(a[1]).id,{event:c.id,browser_package:c.browser_package});
   }}));
  },after(args,result,ctx){ctx.bind_accepted=Boolean(result);}});
  flowHook(token,Client,'warmup',{kind:'webview.custom_tab_connection',before(args,ctx){ctx.navigation_kind='custom_tab_warmup';const state=tabClients.get(navigationIdentity(this).id);if(state)ctx.client_source=tabSource(state.event,'observed_same_client');},after(args,result,ctx){ctx.warmup_accepted=Boolean(result);}});
  flowHook(token,Client,'newSession',{kind:'webview.custom_tab_session',before(args,ctx){
   ctx.navigation_kind='custom_tab_session';const client=tabClients.get(navigationIdentity(this).id);
   if(client){ctx.client_source=tabSource(client.event,'observed_same_client');ctx.browser_package=client.browser_package;}
   if(args[0]){ctx.callback_identity=navigationIdentity(args[0]);ctx.callback_class=args[0].$className;
    const prior=tabCallbacks.get(ctx.callback_identity.id);remember(tabCallbacks,ctx.callback_identity.id,{event:ctx.id,sessions:prior?prior.sessions:[]});
    tabInstallCallbacks(token,args[0],['onNavigationEvent','extraCallback','extraCallbackWithResult','onMessageChannelReady','onPostMessage','onRelationshipValidationResult'],method=>tabCallbackHandlers(token,method));
   }
  },after(args,result,ctx){
   ctx.session_creation=result?'accepted':'rejected';if(!result)return;
   ctx.session_identity=navigationIdentity(result);remember(tabSessions,ctx.session_identity.id,{event:ctx.id,browser_package:ctx.browser_package});
   if(ctx.callback_identity){const callback=tabCallbacks.get(ctx.callback_identity.id);if(callback&&!callback.sessions.includes(ctx.session_identity.id))callback.sessions=[...callback.sessions,ctx.session_identity.id].slice(-4);}
  }});
  for(const method of ['$init','setSession'])flowHook(token,Builder,method,{kind:'webview.custom_tab_builder',after(args,result,ctx){
   ctx.navigation_kind='custom_tab_builder';const session=args[0]&&ctx.signature[0]===Session?args[0]:null;
   if(session)tabSessionContext(session,ctx);
   remember(tabBuilders,navigationIdentity(this).id,{event:ctx.id,session_identity:ctx.session_identity||null});
  }});
  flowHook(token,Builder,'build',{kind:'webview.custom_tab_builder',before(args,ctx){
   ctx.navigation_kind='custom_tab_builder';const id=navigationIdentity(this),state=tabBuilders.get(id.id);
   if(state){ctx.builder_source=tabSource(state.event,id.association);ctx.session_identity=state.session_identity;}
  },after(args,result,ctx){if(!result)return;const intent=result.intent.value;if(intent)remember(tabIntents,navigationIdentity(intent).id,{event:ctx.id,session_identity:ctx.session_identity||null});}});
  flowHook(token,Intent,'launchUrl',{kind:'webview.custom_tab',before(args,ctx){
   ctx.navigation_kind='custom_tab_launch';const intent=this.intent.value;
   customTabsIntentObservation(intent,ctx,false);ctx.navigation_kind='custom_tab_launch';ctx.kind='webview.custom_tab';tabURL(ctx,args[1]);
   const known=intent?tabIntents.get(navigationIdentity(intent).id):null;
   tabLaunch(ctx,known&&known.session_identity?tabSessions.get(known.session_identity.id):null);
  },error:tabFailure});
  for(const method of ['mayLaunchUrl','requestPostMessageChannel','postMessage'])flowHook(token,Session,method,{kind:method==='mayLaunchUrl'?'webview.custom_tab_prefetch':'webview.custom_tab_message',before(args,ctx){
   ctx.navigation_kind=method==='mayLaunchUrl'?'custom_tab_prefetch':'custom_tab_message';tabSessionContext(this,ctx);
   if(method==='postMessage'){ctx.message_direction='app_to_browser';ctx.payload=payload(token,textBytes(args[0]),ctx);}
   else if(method==='mayLaunchUrl')tabURL(ctx,args[0]);else ctx.origin=args[0]?String(args[0].toString()).slice(0,2048):null;
  },after(args,result,ctx){ctx.return_value=flowText(result);}});
 }
 for(const name of ['android.content.ContextWrapper','android.app.ContextImpl'])flowHook(token,name,'startActivity',{kind:'webview.custom_tab_intent',accept(args){return isCustomTabsIntent(args[0]);},before(args,ctx){customTabsIntentObservation(args[0],ctx,true);},error:tabFailure});
 event('coverage',{token:token.name,scope:'Custom Tabs app-side launches, raw VIEW/session intents, service connections, sessions, callbacks and postMessage',limitations:['Callback URL is session launch context, not an observed redirect or final browser URL','Callback reuse across sessions is ambiguous','Prefetch/warmup acceptance is not navigation or transport success','External browser network/renderer/JavaScript internals are outside the app process','Obfuscated library boundaries may require an app-method scope; raw intents remain detectable']});
}
