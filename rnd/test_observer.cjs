// Host-side behavior test, not Android/Frida runtime validation.
const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const messages = [], hooks = [];
const reference = 'com.crimavon.barrage.RootCheck';
function method(original, types=[], returnType='boolean') {
  return {argumentTypes:types.map(className=>({className})), returnType:{className:returnType},
    call:(self,...args)=>original(...args)};
}
const error = new Error('original failure');
const yes=method(()=>true), throws=method(()=>{throw error;});
const root = {isDeviceRooted:{overloads:[yes]},checkRootMethod1:{overloads:[throws]}};
const clazz = {getName:()=>reference,getClassLoader:()=>({})};
const load = method(()=>clazz,['java.lang.String'],'java.lang.Class');
const api = {
  'java.lang.Class': {}, 'java.lang.System': {identityHashCode:()=>42},
  'java.lang.ClassLoader': {loadClass:{overloads:[load]}}
};
const context = {
  send:x=>messages.push(x), setImmediate:fn=>fn(), setInterval:()=>0,
  Process:{arch:'arm64',getCurrentThreadId:()=>1,attachModuleObserver:o=>{hooks.push(o);return o;}},
  Java:{available:true,perform:fn=>fn(),use:n=>api[n],cast:x=>x,
    ClassFactory:{get:()=>({use:()=>root})},
    enumerateLoadedClasses:o=>{o.onMatch(reference,clazz);o.onComplete();}}
};
vm.runInNewContext(fs.readFileSync(__dirname+'/observe_signals.js','utf8'), context);
assert.equal(yes.implementation.call({}),true,'original result preserved');
assert.throws(()=>throws.implementation.call({}),e=>e===error,'original exception preserved');
const before=messages.filter(x=>x.kind==='java.hooked').length;
assert.equal(load.implementation.call({},reference),clazz);
assert.equal(messages.filter(x=>x.kind==='java.hooked').length,before,'same loader not hooked twice');
assert(messages.some(x=>x.kind==='java.method_absent'),'absent methods explicit');
assert(messages.some(x=>x.kind==='java.leave'&&x.result==='true'));
assert(messages.every((x,i)=>x.sequence===i+1),'ordered event sequence');
const checked=messages.find(x=>x.kind==='java.hooked');
assert.equal(checked.ghidra_va,null,'no invented Java Ghidra address');
assert(checked.dex_candidates.some(x=>x.origin==='payload'&&x.code_item_offset));
console.log('PASS: return/exception preservation, loader deduplication, explicit absence, event order, DEX references');
