// Installed only in the companion's isolated context; original source follows.
(function(){
 const namespace='Mod'+'ule',legacy=globalThis[namespace]||{},limit=__HOOK_LIMIT__;
 function module(name,required){
  const result=Process.findModuleByName(name);
  if(!result&&required)throw new Error('Module not found: '+name);
  return result;
 }
 function find(name,symbol,type){
  if(name!==null){const m=module(name,false);return m?m[type](symbol):null;}
  for(const m of Process.enumerateModules()){const result=m[type](symbol);if(result)return result;}
  return null;
 }
 function required(value,label){if(!value)throw new Error('Export/symbol not found: '+label);return value;}
 const shim={
  findBaseAddress(name){const m=module(name,false);return m?m.base:null;},
  getBaseAddress(name){return module(name,true).base;},
  ensureInitialized(name){module(name,true).ensureInitialized();},
  findExportByName(name,symbol){return find(name,symbol,'findExportByName');},
  getExportByName(name,symbol){return required(find(name,symbol,'findExportByName'),symbol);},
  findSymbolByName(name,symbol){return find(name,symbol,'findSymbolByName');},
  getSymbolByName(name,symbol){return required(find(name,symbol,'findSymbolByName'),symbol);},
  findGlobalExportByName(symbol){return find(null,symbol,'findExportByName');},
  getGlobalExportByName(symbol){return required(find(null,symbol,'findExportByName'),symbol);}
 };
 for(const type of ['Exports','Imports','Symbols','Ranges']){
  shim['enumerate'+type+'Sync']=function(name,protection){return module(name,true)['enumerate'+type](...(type==='Ranges'?[protection]:[]));};
  shim['enumerate'+type]=function(name,...args){
   const callback=args.find(a=>a&&typeof a==='object'&&typeof a.onMatch==='function');
   const result=shim['enumerate'+type+'Sync'](name,args[0]);
   if(!callback)return result;
   for(const item of result){if(callback.onMatch(item)==='stop')break;}
   if(callback.onComplete)callback.onComplete();
  };
 }
 // Keep modern APIs provided by the runtime. All legacy lookups above use Process.
 // Native Frida namespace methods may be read-only. Shadow them on an adapter
 // object instead of mutating the runtime's original namespace.
 const adapter=Object.create(legacy);
 for(const [name,value] of Object.entries(shim))Object.defineProperty(adapter,name,{value,writable:true,configurable:true,enumerable:true});
 globalThis[namespace]=adapter;
 const runtimeInterceptor=globalThis.Interceptor,scopedInterceptor=Object.create(runtimeInterceptor);
 for(const name of ['attach','replace','replaceFast','revert','detachAll']){
  if(typeof runtimeInterceptor[name]==='function')Object.defineProperty(scopedInterceptor,name,{value:runtimeInterceptor[name].bind(runtimeInterceptor),writable:true,configurable:true,enumerable:true});
 }
 globalThis.Interceptor=scopedInterceptor;
 const attach=Interceptor.attach.bind(Interceptor),replace=Interceptor.replace.bind(Interceptor);
 let active=0,skipped=0;const listeners=new Set();
 function denied(){
  skipped++;
  if(skipped===1||skipped%100===0)send({runtime_companion_budget:{limit,active,skipped,scope:'native Interceptor hooks; Java hooks remain analyst-controlled'}});
 }
 Interceptor.attach=function(...args){
  if(active>=limit){denied();return {detach(){}};}
  const listener=attach(...args),wrapped=Object.create(listener);active++;listeners.add(wrapped);const detach=listener.detach.bind(listener);
  Object.defineProperty(wrapped,'detach',{value:function(){if(listeners.delete(wrapped)){active--;detach();}}});return wrapped;
 };
 if(Interceptor.detachAll){const detachAll=Interceptor.detachAll.bind(Interceptor);
  Interceptor.detachAll=function(){const result=detachAll();active-=listeners.size;listeners.clear();return result;};}
 const replacements=new Set(),revert=Interceptor.revert.bind(Interceptor);
 for(const name of ['replace','replaceFast']){
  const original=name==='replace'?replace:Interceptor.replaceFast&&Interceptor.replaceFast.bind(Interceptor);
  if(!original)continue;
  Interceptor[name]=function(target,...args){
   const key=target.toString();
   if(!replacements.has(key)&&active>=limit){denied();throw new Error('Companion native hook quota exceeded ('+limit+')');}
   const result=original(target,...args);if(!replacements.has(key)){replacements.add(key);active++;}return result;
  };
 }
 Interceptor.revert=function(target){const result=revert(target);if(replacements.delete(target.toString()))active--;return result;};
 send({runtime_companion_policy:{limit,compatibility:'legacy module lookups through Process',java_hooks:'not automatically bounded'}});
 setImmediate(()=>send({runtime_companion_budget:{limit,active,skipped,checkpoint:'initial_source_evaluated'}}));
})();
