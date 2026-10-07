'use strict';
// This adapter only uses the process runtime namespace. Third-party bridge loading
// is isolated and checked by the host before this source is installed.
const config = __CONFIG__;
runtimeDebug.mark('collector.source.enter');
let sequence = 0, serial = 0, stopped = false, queuedBytes = 0;
const owned = new Map(), guards = new Set(), hooks = [], tokens = new Map(), loads = new Map();
const regions = new Map(), nativeHooks = [];
const nativeLoads = new Map();
const jniCalls = new Map();
const triggerHooks = new Map();
const eventRing=[];let flushScheduled=false;
const transferQueue=[];let transferFlushScheduled=false;
const losses = {skipped_captures: 0, dropped_bytes: 0, queue_overflow: 0, emitted_events: 0, capture_time_ms: 0};
const traceRetained=new Set(),tracePending=new Map();
for (const token of config.tokens) tokens.set(token.capability, token);
function acknowledgeOwned(transfer,verified=false){
  const entry=owned.get(transfer);
  if(entry){
    queuedBytes-=entry.size;owned.delete(transfer);
    if(entry.trace_key){
      tracePending.delete(entry.trace_key);
      if(verified){traceRetained.add(entry.trace_key);if(traceRetained.size>1024)traceRetained.delete(traceRetained.values().next().value);}
    }
  }
}
function receiveAcknowledgement(){
  recv('runtime.acknowledge',message=>{
    const value=message.payload;
    if(value&&typeof value.transfer==='string')acknowledgeOwned(value.transfer,value.verified===true);
    if(!stopped)receiveAcknowledgement();
  });
}
receiveAcknowledgement();

function event(kind, data, binary) {
  if (stopped) return false;
  if (++sequence > config.limits.events && !['capture.begin','capture.end','transfer.chunk','loss','coverage','instrumentation.ready'].includes(kind)) {
    losses.observations_throttled = (losses.observations_throttled || 0) + 1;
    return false;
  }
  if(eventRing.length>=config.limits.queue_depth){
    losses.queue_overflow++;
    if(binary)losses.dropped_bytes+=binary.byteLength;
    else losses.observations_throttled=(losses.observations_throttled||0)+1;
    return false;
  }
  eventRing.push([{kind, sequence, data: Object.assign({agent_time_ms: Date.now(), thread_id: Process.getCurrentThreadId()}, data)},binary]);
  if(!flushScheduled){flushScheduled=true;setImmediate(flushEvents);}
  return true;
}
function flushEvents(){
  flushScheduled=false;
  for(let n=0;n<32&&eventRing.length;n++){const entry=eventRing.shift();send(entry[0],entry[1]);losses.emitted_events++;
    if(entry[0].kind==='jni.call')losses.jni_emitted_calls=(losses.jni_emitted_calls||0)+1;}
  if(eventRing.length&&!flushScheduled){flushScheduled=true;setImmediate(flushEvents);}
  scheduleTransfers();
}
function scheduleTransfers(){
  if(transferQueue.length&&!transferFlushScheduled&&!stopped){transferFlushScheduled=true;setImmediate(flushTransfers);}
}
function flushTransfers(){
  transferFlushScheduled=false;
  for(let n=0;n<8&&transferQueue.length;n++){
    const transfer=transferQueue[0],entry=owned.get(transfer);
    if(!entry){transferQueue.shift();continue;}
    const needed=2+Math.ceil(entry.size/262144);
    if(eventRing.length+needed>config.limits.queue_depth)break;
    transferQueue.shift();
    event('capture.begin',entry.begin);
    for(let offset=0;offset<entry.size;offset+=262144){
      event('transfer.chunk',{transfer,offset},entry.bytes.slice(offset,Math.min(entry.size,offset+262144)));
    }
    event('capture.end',{transfer});
  }
  // A full ring waits for flushEvents to make room, without discarding owned bytes.
  if(transferQueue.length&&eventRing.length===0)scheduleTransfers();
}
function gap(token, reason, size) {
  losses.skipped_captures++;
  losses.dropped_bytes += size || 0;
  event('coverage.gap', {token: token.name, reason, bytes: size || 0});
}
function selected(token, label) {
  return !(token.selection.exclude_prefixes || []).some(p => label.startsWith(p));
}
function stack() {
  try { return Java.backtrace({limit: 48}).frames.map(f => ({class: f.className, method: f.methodName,
    signature: f.signature, file: f.fileName, line: f.lineNumber, origin: f.origin, artifact: null, attribution: 'origin_path_only'})); }
  catch (e) { return [{attribution: 'unattributed', reason: String(e)}]; }
}
function capture(token, bytes, metadata, start) {
  const captureThread=Process.getCurrentThreadId(),observedTime=Date.now();
  const length = bytes.byteLength;
  const sha256 = Checksum.compute('sha256', bytes);
  const traceKey=metadata.kind==='trace_payload'?token.name+':'+sha256:null;
  if(traceKey&&(traceRetained.has(traceKey)||tracePending.has(traceKey))){losses.trace_values_reused=(losses.trace_values_reused||0)+1;return;}
  if (length > config.limits.capture_bytes) { gap(token, 'capture_size_limit', length); return; }
  if (owned.size >= config.limits.queue_depth || queuedBytes + length > config.limits.pending_bytes) {
    losses.queue_overflow++; gap(token, 'owned_byte_queue_full', length); return;
  }
  const elapsed = Date.now() - start;
  losses.capture_time_ms += elapsed;
  losses.max_capture_time_ms=Math.max(losses.max_capture_time_ms||0,elapsed);
  if (elapsed > config.limits.capture_ms) { gap(token, 'copy_time_budget_exceeded', length); return; }
  const transfer = 'transfer-' + (++serial);
  if(2+Math.ceil(length/262144)>config.limits.queue_depth){gap(token,'transfer_exceeds_event_ring_capacity',length);return;}
  const entry = {bytes, time: Date.now(), size: length,trace_key:traceKey,
    begin:Object.assign({transfer, token: token.name, pack: config.id,
      size:length,sha256,logical_id:transfer,consistency:'single_copy_not_atomic',
      thread_id:captureThread,agent_time_ms:observedTime,capture_processing_ms:elapsed,
      profile:'public-java-buffer-v1',limitations:['No ART backing-memory association established']},metadata)};
  owned.set(transfer, entry); queuedBytes += length;
  if(traceKey)tracePending.set(traceKey,transfer);
  // The owned ArrayBuffer is populated before returning from the hook. No target
  // pointer or application ByteBuffer is deferred into the transfer queue.
  transferQueue.push(transfer);scheduleTransfers();
}
function withGuard(fn) {
  const tid = Process.getCurrentThreadId();
  if (guards.has(tid)) return;
  guards.add(tid);
  try { return fn(); } catch (e) { event('coverage.gap', {reason: 'instrumentation_error', error: String(e)}); }
  finally { guards.delete(tid); }
}
function byteArray(value) {
  const length=value.length;
  if(!length)return new ArrayBuffer(0);
  const result=Memory.alloc(length);
  Java.vm.getEnv().getByteArrayRegion(value.$h,0,length,result);
  return result.readByteArray(length);
}
function boundedPath(address) {
  const range=Process.findRangeByAddress(address);
  if(!range || !range.protection.includes('r'))throw Error('String is unreadable');
  const length=Math.min(4096,range.base.add(range.size).sub(address).toUInt32());
  const bytes=new Uint8Array(address.readByteArray(length));
  const end=bytes.indexOf(0);if(end<0)throw Error('Unterminated path within limit');
  return String.fromCharCode.apply(null,bytes.slice(0,end));
}
function readable(base, size) {
  const range = Process.findRangeByAddress(base);
  return range !== null && range.protection.includes('r') && base.add(size).compare(range.base.add(range.size)) <= 0;
}
function snapshotRegion(id, trigger) {
  const token = tokens.get('dex.snapshot.runtime');
  if (!token) throw new Error('Snapshot token not enabled');
  const item = regions.get(id);
  if (!item) throw new Error('Region is unavailable, expired, or was never tracked');
  if (!readable(item.object, 24) || !item.object.add(config.art_profile.begin_offset).readPointer().equals(item.base) ||
      item.object.add(config.art_profile.size_offset).readU64().toNumber() !== item.size || !readable(item.base, item.size)) {
    regions.delete(id);
    event('region.expired', {logical_id: id, reason: 'ownership_or_mapping_changed'});
    throw new Error('Region ownership or mapping changed; no stale snapshot returned');
  }
  const started = Date.now();
  const data = item.base.readByteArray(item.size);
  capture(token, data, {kind: 'dex_runtime_snapshot', logical_id: id, source: 'validated_dexfile_object',
    profile: config.art_profile.id, correlation: item.correlation, input_original: false, trigger,
    base: item.base.toString(), size: item.size, limitations: ['Concurrent mutation can produce an inconsistent single copy',
      'Polling can miss short-lived method bodies', 'Object lifetime does not prove all writers are observed']}, started);
  return {logical_id: id, outcome: 'snapshot_queued'};
}
function installArt() {
  const token = tokens.get('dex.input.art');
  if (!token) return;
  const profile = config.art_profile;
  if (!profile) throw new Error('ART capture requested without a validated profile');
  const module = Process.getModuleByName(profile.module);
  const ctor = module.getExportByName(profile.constructor), dtor = module.getExportByName(profile.destructor);
  const prefix = Array.from(new Uint8Array(ctor.readByteArray(profile.constructor_prefix.length / 2)), x => x.toString(16).padStart(2, '0')).join('');
  if (prefix !== profile.constructor_prefix) throw new Error('Installed constructor instructions differ from profile');
  nativeHooks.push(Interceptor.attach(dtor, {onEnter(args) {
    for (const [id,item] of regions) if (item.object.equals(args[0])) {
      regions.delete(id);event('region.expired', {logical_id:id, reason:'DexFile destructor entered'});
    }
  }}));
  nativeHooks.push(Interceptor.attach(ctor, {
    onEnter(args) {
      if (guards.has(Process.getCurrentThreadId())) return;
      try {
        const start = Date.now(), base = args[1], size = parseInt(args[profile.size_argument].toString(), 16);
        const map = Process.findRangeByAddress(base), path = map && map.file ? map.file.path : '';
        if (!selected(token,path)) return;
        if (!Number.isSafeInteger(size) || size < 112 || size > config.limits.capture_bytes) { gap(token,'ART input size outside capture limits',size);return; }
        if (!readable(base,size)) { gap(token,'ART input mapping unreadable',size);return; }
        const magic = Array.from(new Uint8Array(base.readByteArray(4)));
        const ordinary=magic.join(',') === '100,101,120,10';
        const headerMatches=ordinary && base.add(32).readU32()===size;
        this.id = 'art-object-' + (++serial);
        for(const [id,item] of regions)if(item.object.equals(args[0])){
          regions.delete(id);event('region.expired',{logical_id:id,reason:'DexFile address reused by a new construction'});
        }
        this.region = {object:args[0],base,size,correlation:loads.get(Process.getCurrentThreadId()) || jniCalls.get(Process.getCurrentThreadId()) || 'art-load-'+serial};
        event('art.construct.attempt',{token:token.name,correlation:this.region.correlation,logical_id:this.id,base:base.toString(),size,
          profile:profile.id,source_path:path,source_offset:map && map.file ? map.file.offset + base.sub(map.base).toUInt32() : null});
        capture(token,base.readByteArray(size),{kind:'dex_art_input',logical_id:this.id,correlation:this.region.correlation,
          source:'DexFile_constructor_input',input_original:true,profile:profile.id,base:base.toString(),size,
          source_path:path,source_offset:map && map.file ? map.file.offset + base.sub(map.base).toUInt32() : null,
          header_matches_range:headerMatches,representation:ordinary?'standard_dex_candidate':'unsupported_representation',
          limitations:['Captured before DexFile constructor; runtime acceptance and execution not established']},start);
      } catch(e) { gap(token,'ART input copy failed: '+e,0); }
    },
    onLeave() {
      if (!this.region) return;
      const item=this.region;
      try {
        if (!readable(item.object,24) || !item.object.add(profile.begin_offset).readPointer().equals(item.base) ||
            item.object.add(profile.size_offset).readU64().toNumber() !== item.size) {
          event('coverage.gap',{token:token.name,reason:'DexFile object layout validation failed',logical_id:this.id});return;
        }
        event('art.construct.outcome',{correlation:item.correlation,logical_id:this.id,outcome:'constructor_returned',runtime_acceptance:'not_established'});
        if (tokens.has('dex.snapshot.runtime')) {
          if(regions.size>=config.limits.tracked_regions) {gap(token,'tracked_region_budget',item.size);return;}
          regions.set(this.id,item);
          event('region.tracked',{logical_id:this.id,profile:profile.id,base:item.base.toString(),size:item.size,correlation:item.correlation});
        }
      } catch(e) {event('coverage.gap',{token:token.name,reason:'DexFile ownership validation failed: '+e});}
    }
  }));
  event('coverage',{token:token.name,profile:profile.id,boundary:'DexFile constructor',destructor_tracking:true,
    limitations:['Pre-existing DexFile objects are not enumerated','Open paths that bypass this constructor are unsupported'],
    exclusions:token.selection.exclude_prefixes || []});
}
function installLinker() {
  const token=tokens.get('native.input.linker');if(!token)return;
  const profile=config.linker_profile;if(!profile)throw new Error('Missing validated linker profile');
  const linker=Process.getModuleByName(profile.module),libc=Process.getModuleByName('libc.so');
  const symbol=linker.enumerateSymbols().find(s=>s.name===profile.reader);
  if(!symbol)throw new Error('Profile reader symbol is absent');
  const prefix=Array.from(new Uint8Array(symbol.address.readByteArray(profile.reader_prefix.length/2)),x=>x.toString(16).padStart(2,'0')).join('');
  if(prefix!==profile.reader_prefix)throw new Error('Linker reader instruction guard failed');
  const pread=new NativeFunction(libc.getExportByName('pread64'),'long',['int','pointer','ulong','int64']);
  const fstat=new NativeFunction(libc.getExportByName('fstat'),'int',['int','pointer']);
  for(const name of ['dlopen','android_dlopen_ext']) {
    const address=linker.findExportByName('__loader_'+name);
    if(!address)continue;
    nativeHooks.push(Interceptor.attach(address,{
      onEnter(args){this.tid=Process.getCurrentThreadId();if(nativeLoads.has(this.tid))return;
        this.id='native-load-'+(++serial);nativeLoads.set(this.tid,this.id);
        let path=null;try{path=boundedPath(args[0]);}catch(e){}
        event('native.load.attempt',{token:token.name,correlation:this.id,api:name,path,triggering_jni_call:jniCalls.get(this.tid)||null});},
      onLeave(result){if(!this.id)return;nativeLoads.delete(this.tid);event('native.load.outcome',{
        token:token.name,correlation:this.id,outcome:result.isNull()?'failed':'returned_handle',execution:'not_established'});}
    }));
  }
  nativeHooks.push(Interceptor.attach(symbol.address,{
    onEnter(args){
      if(guards.has(Process.getCurrentThreadId()))return;
      withGuard(()=>{
        const started=Date.now(),fd=args[profile.fd_argument].toInt32();
        const offset=parseInt(args[profile.offset_argument].toString(),16),declared=parseInt(args[profile.size_argument].toString(),16);
        let name='';try{name=boundedPath(args[1]);}catch(e){}
        if(!selected(token,name))return;
        this.id=nativeLoads.get(Process.getCurrentThreadId()) || 'linker-read-'+(++serial);
        if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(declared)||offset<0||declared<64){gap(token,'Invalid descriptor offset/extent',0);return;}
        const before=Memory.alloc(profile.stat_size),after=Memory.alloc(profile.stat_size);
        if(fstat(fd,before)!==0 || (before.add(profile.stat_mode_offset).readU32() & 0xf000)!==0x8000){gap(token,'Non-regular or inaccessible source descriptor',0);return;}
        const fileSize=before.add(profile.stat_file_size_offset).readU64().toNumber();
        function read(relative,length){
          if(!Number.isSafeInteger(relative)||!Number.isSafeInteger(length)||relative<0||length<0||length>config.limits.capture_bytes||offset+relative+length>fileSize)throw Error('ELF read outside bounded file');
          const memory=Memory.alloc(Math.max(1,length));
          const got=Number(pread(fd,memory,length,new Int64(offset+relative)));
          if(got!==length)throw Error('Partial descriptor read');
          if(Date.now()-started>config.limits.capture_ms)throw Error('Descriptor copy time budget');
          return memory;
        }
        try{
          const header=read(0,64);
          if(header.readU32()!==0x464c457f || header.add(4).readU8()!==2 || header.add(5).readU8()!==1)throw Error('Unsupported ELF representation');
          const phoff=header.add(32).readU64().toNumber(),shoff=header.add(40).readU64().toNumber();
          const phsize=header.add(54).readU16(),phnum=header.add(56).readU16(),shsize=header.add(58).readU16(),shnum=header.add(60).readU16();
          if(phsize!==56||phnum>1024||!phnum||shnum>8192||(shnum&&shsize!==64))throw Error('ELF table bounds');
          let extent=Math.max(64,phoff+phsize*phnum,shnum?shoff+shsize*shnum:0);
          const ph=read(phoff,phsize*phnum);
          for(let i=0;i<phnum;i++){const p=ph.add(i*phsize);extent=Math.max(extent,p.add(8).readU64().toNumber()+p.add(32).readU64().toNumber());}
          if(shnum){const sh=read(shoff,shsize*shnum);for(let i=0;i<shnum;i++){const s=sh.add(i*shsize);if(s.add(4).readU32()!==8)extent=Math.max(extent,s.add(24).readU64().toNumber()+s.add(32).readU64().toNumber());}}
          if(queuedBytes+extent>config.limits.pending_bytes){gap(token,'Pending byte budget',extent);return;}
          const bytes=read(0,extent).readByteArray(extent);
          if(fstat(fd,after)!==0)throw Error('Source descriptor lost');
          // Ignore atime (our read may update it); compare identity, size, mtime and ctime.
          for(const off of [0,8,24,48,88,96,104,112])if(before.add(off).readU64().compare(after.add(off).readU64())!==0)throw Error('Source changed during descriptor capture');
          capture(token,bytes,{kind:'elf_input',source:'validated_linker_descriptor',profile:profile.id,
            correlation:this.id,descriptor:fd,source_offset:offset,source_label:name,source_size:fileSize,
            inode:before.add(8).readU64().toString(),device:before.readU64().toString(),input_original:true,
            pre_constructor_capture:true,extent_basis:'ELF program and section file ranges',
            limitations:['Concurrent writes preserving stat fields cannot be excluded','Trailing bytes outside ELF sections are not included']},started);
        }catch(e){gap(token,'Linker descriptor capture failed: '+e,0);}
      });
    },
    onLeave(result){if(this.id)event('native.reader.outcome',{token:token.name,correlation:this.id,outcome:result.toInt32()?'reader_returned_true':'reader_returned_false',runtime_acceptance:'not_established'});}
  }));
  event('coverage',{token:token.name,profile:profile.id,boundary:'ElfReader::Read descriptor/offset before segment load',
    limitations:['Custom loaders bypassing the validated linker are unsupported','Only ELF64 little-endian regular descriptors are supported'],
    exclusions:token.selection.exclude_prefixes||[]});
}
function nativeCaller(returnAddress,target) {
  const answer={return_address:returnAddress.toString(),resolved_target:target.toString(),call_site:null,
    static_address:null,load_bias:null,module_path:null,build_id:null,artifact_snapshot:null,status:'unattributed'};
  try{
    let call=null;
    if(Process.arch==='arm64'){
      const candidate=returnAddress.sub(4),instruction=Instruction.parse(candidate);
      if(['bl','blr','blraa','blrab'].includes(instruction.mnemonic)&&instruction.next.equals(returnAddress))call=candidate;
    }else if(Process.arch==='x64'){
      const candidates=[];
      for(let back=2;back<=15;back++)try{
        const p=returnAddress.sub(back),instruction=Instruction.parse(p);
        if(instruction.mnemonic==='call'&&instruction.next.equals(returnAddress))candidates.push(p);
      }catch(e){}
      if(candidates.length===1)call=candidates[0];
    }
    if(!call)throw Error('Call instruction cannot be uniquely decoded');
    answer.call_site=call.toString();
    const module=Process.findModuleByAddress(call);
    if(!module)throw Error('Caller is in JIT, anonymous, or otherwise unrecognized memory');
    answer.module_path=module.path;
    const header=module.base;
    if(!readable(header,64)||header.readU32()!==0x464c457f||header.add(4).readU8()!==2||header.add(5).readU8()!==1)throw Error('Mapped ELF64 header unavailable');
    const phoff=header.add(32).readU64().toNumber(),count=header.add(56).readU16(),size=header.add(54).readU16();
    if(count>128||size!==56||phoff>65536||!readable(header.add(phoff),count*size))throw Error('Mapped ELF program headers unsupported');
    let bias=null;const segments=[],notes=[];
    for(let i=0;i<count;i++){
      const p=header.add(phoff+i*size),kind=p.readU32(),offset=p.add(8).readU64().toNumber(),va=p.add(16).readU64().toNumber(),bytes=p.add(40).readU64().toNumber();
      if(![offset,va,bytes].every(Number.isSafeInteger))throw Error('ELF address exceeds safe range');
      if(kind===1){segments.push({virtual_address:va,memory_size:bytes,flags:p.add(4).readU32()});if(offset===0)bias=header.sub(va);}
      if(kind===4)notes.push({va,size:p.add(32).readU64().toNumber()});
    }
    if(bias===null)throw Error('ELF load bias cannot be established');
    const staticAddress=call.sub(bias),number=parseInt(staticAddress.toString(),16);
    const segment=segments.find(s=>number>=s.virtual_address&&number<s.virtual_address+s.memory_size&&(s.flags&1));
    if(!segment)throw Error('Call site is outside executable ELF segments');
    for(const note of notes){
      if(note.size>65536||!readable(bias.add(note.va),note.size))continue;
      let at=0;const p=bias.add(note.va);
      while(at+12<=note.size){const namesz=p.add(at).readU32(),descsz=p.add(at+4).readU32(),type=p.add(at+8).readU32();at+=12;
        const desc=at+((namesz+3)&~3),end=desc+((descsz+3)&~3);if(namesz>4096||descsz>4096||end>note.size)break;
        if(namesz===4&&type===3&&descsz<=128&&p.add(at).readU32()===0x00554e47)answer.build_id=Array.from(new Uint8Array(p.add(desc).readByteArray(descsz)),b=>b.toString(16).padStart(2,'0')).join('');
        at=end;
      }
    }
    Object.assign(answer,{status:'attributed',static_address:staticAddress.toString(),load_bias:bias.toString(),
      segment,ghidra_image_base:'0x0',artifact_link_status:'unresolved'});
  }catch(e){answer.reason=String(e);}
  return answer;
}
function installJni() {
  const token=tokens.get('jni.trace.selected'),env=Java.vm.getEnv(),table=env.handle.readPointer();
  const functions=config.jni_table.filter(f=>!token.selection.functions||token.selection.functions.includes(f.name));
  const addresses=new Set();let installed=0;
  for(const f of functions){
    const target=table.add(f.index*Process.pointerSize).readPointer(),range=Process.findRangeByAddress(target),module=Process.findModuleByAddress(target);
    if(!range||!range.protection.includes('x')||!module||module.name!=='libart.so')throw Error('JNI table validation failed for '+f.name);
    if(addresses.has(target.toString())){event('coverage.gap',{token:token.name,reason:'JNI table aliases share an implementation',function:f.name});continue;}
    addresses.add(target.toString());
    nativeHooks.push(Interceptor.attach(target,{
      onEnter(args){
        const tid=Process.getCurrentThreadId();if(guards.has(tid))return;
        const callerImage=Process.findModuleByAddress(this.returnAddress);
        if(callerImage&&!selected(token,callerImage.path))return;
        const started=Date.now();this.active=true;this.tid=tid;this.id='jni-'+(++serial);this.previous=jniCalls.get(tid);jniCalls.set(tid,this.id);
        withGuard(()=>{
          const data={token:token.name,correlation:this.id,parent_jni_call:this.previous||null,function:f.name,
            signature:f.signature,direction:'native_to_jni',native_caller:nativeCaller(this.returnAddress,target),java_caller:stack()};
          try{
            if(f.name==='FindClass')data.requested_class=boundedPath(args[1]);
            if(['GetMethodID','GetStaticMethodID','GetFieldID','GetStaticFieldID'].includes(f.name)){
              data.member_name=boundedPath(args[2]);data.member_signature=boundedPath(args[3]);
            }
            if(f.name==='RegisterNatives')data.registration_count=args[3].toInt32();
          }catch(e){data.argument_attribution='unattributed: '+e;}
          data.processing_ms=Date.now()-started;
          losses.jni_processing_ms=(losses.jni_processing_ms||0)+data.processing_ms;
          losses.jni_observed_calls=(losses.jni_observed_calls||0)+1;
          event('jni.call',data);
        });
      },
      onLeave(){if(!this.active)return;if(this.previous)jniCalls.set(this.tid,this.previous);else jniCalls.delete(this.tid);}
    }));installed++;
  }
  event('coverage',{token:token.name,installed_functions:installed,selection:token.selection,
    limitations:['Selected standard native-to-JNI calls only','Java-to-native entry tracing is not implemented',
      'Java stack origins may lack artifact references','Processing time uses millisecond clock resolution']});
}
function installJava() {
  runtimeDebug.mark('java.availability.check');
  if(typeof Java==='undefined'||!Java.available){
    try { frameworkCoverage(); } catch(e) {}
    for(const token of config.tokens)if(token.capability!=='network.native'&&token.capability!=='native.inventory')event('coverage',{token:token.name,state:'unsupported',reason:'Java VM unavailable; no managed runtime traversal attempted'});
    event('instrumentation.ready',{java:false,coverage:'native_only_java_unavailable'});runtimeDebug.ready(false);return;
  }
  runtimeDebug.mark('java.perform.waiting');
  Java.perform(() => {
    runtimeDebug.mark('java.perform.entered');
    runtimeDebug.mark('java.framework.discovery');
    try { frameworkCoverage(); } catch(e) {}
    runtimeDebug.mark('java.object_flow.install');
    try { if(tokens.has('flow.java'))installObjectFlow(); } catch(e) { event('coverage.gap',{reason:'object_flow_installation',error:String(e)}); }
    runtimeDebug.mark('java.platform_hooks.install');
    try { installFlows(); } catch(e) { event('coverage.gap', {reason:'flow_installation',error:String(e)}); }
    runtimeDebug.mark('java.jni_hooks.install');
    if(tokens.has('jni.trace.selected')) installJni();
    const bufferToken = tokens.get('dex.input.java');
    if (bufferToken) {
      runtimeDebug.mark('java.dex_loader.resolve');
      const Loader = Java.use('dalvik.system.InMemoryDexClassLoader');
      const Buffer = Java.use('java.nio.ByteBuffer');
      const BaseBuffer = Java.use('java.nio.Buffer');
      let installed = 0;
      for (const overload of Loader.$init.overloads) {
        const sig = overload.argumentTypes.map(t => t.className);
        if (!['java.nio.ByteBuffer', '[Ljava.nio.ByteBuffer;'].includes(sig[0])) continue;
        runtimeDebug.mark('java.dex_loader.hook:'+sig.join(','));
        overload.implementation = function () {
          const args = Array.from(arguments), tid = Process.getCurrentThreadId();
          if (loads.has(tid)) return overload.apply(this, args);
          const debugCall=runtimeDebug.enter('InMemoryDexClassLoader('+sig.join(',')+')');
          try {
          const attempt = 'load-' + (++serial);
          loads.set(tid, attempt);
          withGuard(() => {
            const buffers = sig[0] === 'java.nio.ByteBuffer' ? [args[0]] : args[0];
            event('load.attempt', {token: bufferToken.name, correlation: attempt, api: 'InMemoryDexClassLoader', signature: sig, caller: stack()});
            if (!selected(bufferToken, 'dalvik.system.InMemoryDexClassLoader')) return;
            const totalStart=Date.now(),bufferCount=buffers.length;
            const maximum=Math.min(bufferCount,config.limits.queue_depth);
            if(maximum<bufferCount)gap(bufferToken,'input_buffer_count_limit',0);
            for (let index = 0; index < maximum; index++) {
              if(Date.now()-totalStart>config.limits.capture_ms){gap(bufferToken,'input_batch_time_budget',0);break;}
              const start = Date.now();
              try {
                const original = buffers[index];
                const state = Java.cast(original, BaseBuffer);
                const count = original.remaining();
                if (count > config.limits.capture_bytes || queuedBytes + count > config.limits.pending_bytes) {
                  gap(bufferToken, 'input_or_pending_size_limit', count); continue;
                }
                const position = state.position(), limit = state.limit();
                let bytes;
                if(!count)bytes=new ArrayBuffer(0);
                else if(original.isDirect()){
                  const pointer=Java.vm.getEnv().getDirectBufferAddress(original.$h);
                  if(pointer.isNull())throw Error('Direct buffer address unavailable');
                  bytes=pointer.add(position).readByteArray(count);
                }else if(original.hasArray()){
                  const array=original.array(),copy=Memory.alloc(count);
                  Java.vm.getEnv().getByteArrayRegion(array.$h,original.arrayOffset()+position,count,copy);
                  bytes=copy.readByteArray(count);
                }else{
                  const duplicate = Java.cast(original.duplicate(), Buffer);
                  const array = Java.array('byte', new Array(count).fill(0));
                  Buffer.get.overload('[B').call(duplicate, array);
                  bytes = byteArray(array);
                }
                capture(bufferToken, bytes, {kind: 'dex_input', correlation: attempt, source: 'caller_byte_buffer',
                  buffer_index: index, position, limit, direct: original.isDirect(), input_original: true,
                  buffer_state_preserved: state.position() === position && state.limit() === limit}, start);
              } catch (e) { gap(bufferToken, 'buffer_copy_failed: ' + e, 0); }
            }
          });
          try {
            const result = overload.apply(this, args);
            event('load.outcome', {correlation: attempt, outcome: 'returned', token: bufferToken.name,
              execution: 'not_established'});
            return result;
          } catch (e) {
            event('load.outcome', {correlation: attempt, outcome: 'threw', error: String(e), token: bufferToken.name});
            throw e;
          } finally { loads.delete(tid); }
          } finally { runtimeDebug.leave(debugCall); }
        };
        hooks.push(overload); installed++;
      }
      event('coverage', {token: bufferToken.name, installed_overloads: installed, api: 'InMemoryDexClassLoader',
        level: 'java_input_only', art_boundaries: 'unsupported', runtime_owned_regions: 'unsupported',
        excludes: bufferToken.selection.exclude_prefixes || []});
      if (!installed) throw new Error('No supported ByteBuffer loader overload installed');
    }
    event('instrumentation.ready', {java: true, tokens: config.tokens.map(t => t.name),
      startup_coverage: 'Java hooks active at this event; earlier events may be missed'});
    runtimeDebug.mark('java.hooks.ready');
    runtimeDebug.ready(true);
  });
}
let observer = null;
let triggerObserver = null;
const nativeToken = tokens.get('native.inventory');
if (nativeToken) {
  runtimeDebug.mark('native.module_observer.install');
  let initial = true;
  observer = Process.attachModuleObserver({
    onAdded(module) {
      if (!selected(nativeToken, module.path)) return;
      event('native.inventory', {token: nativeToken.name, path: module.path, name: module.name,
        base: module.base.toString(), size: module.size, state: initial ? 'discovered_after_loading' : 'module_added',
        original_input: false, pre_constructor_capture: false, build_id: null,
        load_bias: null, limitations: ['Module base is not asserted to be ELF load bias', 'No original bytes captured']});
    },
    onRemoved(module) { event('native.removed', {token: nativeToken.name, path: module.path, base: module.base.toString()}); }
  });
  initial = false;
  runtimeDebug.mark('native.module_observer.installed');
}
rpc.exports = {
  acknowledge(transfer) { acknowledgeOwned(transfer); },
  stats() { return Object.assign({pending_transfers: owned.size, pending_bytes: queuedBytes}, losses); },
  snapshot(id) { return snapshotRegion(id,'manual'); },
  regions() { return Array.from(regions, ([id,r]) => ({id,base:r.base.toString(),size:r.size})); },
  stop() {
    runtimeDebug.mark('agent.stop.enter');
    event('loss', Object.assign({pending_transfers: owned.size, pending_bytes: queuedBytes}, losses));
    for (const hook of hooks) hook.implementation = null;
    if(typeof stopObjectFlow==='function')stopObjectFlow();
    for (const hook of nativeHooks) hook.detach();
    for (const hook of triggerHooks.values()) hook.detach();
    if (observer) observer.detach();
    if (triggerObserver) triggerObserver.detach();
    while(eventRing.length||transferQueue.length){flushEvents();flushTransfers();}
    stopped = true;
    owned.clear();transferQueue.length=0;tracePending.clear();traceRetained.clear();queuedBytes = 0;
    runtimeDebug.stop();
    return losses;
  }
};
setInterval(() => {
  for (const [id, entry] of owned) {
    if (Date.now() - entry.time > config.limits.transfer_seconds * 1000) {
      acknowledgeOwned(id);
      losses.dropped_bytes += entry.size;
      event('coverage.gap', {reason: 'transfer_ack_timeout', transfer: id, bytes: entry.size});
    }
  }
}, 1000);
runtimeDebug.mark('native.art.install');
installArt();
runtimeDebug.mark('native.linker.install');
installLinker();
if(tokens.has('dex.snapshot.runtime') && tokens.get('dex.snapshot.runtime').trigger==='native_function') {
  const token=tokens.get('dex.snapshot.runtime');
  event('coverage',{token:token.name,trigger:'native_function',state:'pending_module',selection:token.selection});
  triggerObserver=Process.attachModuleObserver({onAdded(module){
    if(module.name!==token.selection.module)return;
    // Symbol-table enumeration avoids a dlsym/dlopen round trip inside the linker
    // notification callback, where re-entering the loader is unsafe.
    const symbol=module.enumerateSymbols().find(s=>s.name===token.selection.symbol&&s.type==='function');
    const target=symbol ? symbol.address : null;
    if(!target){event('coverage.gap',{token:token.name,reason:'Requested trigger symbol not found',module:module.path});return;}
    triggerHooks.set(module.base.toString(),Interceptor.attach(target,{onEnter(){
      const start=Date.now();
      for(const id of regions.keys()){
        if(Date.now()-start>config.limits.capture_ms){gap(token,'trigger_total_time_budget',0);break;}
        try{snapshotRegion(id,'native_function:'+token.selection.symbol);}catch(e){event('coverage.gap',{token:token.name,reason:String(e),logical_id:id});}
      }
    }}));
    event('coverage',{token:token.name,state:'trigger_installed',module:module.path,symbol:token.selection.symbol,address:target.toString()});
  },onRemoved(module){
    const key=module.base.toString(),hook=triggerHooks.get(key);if(!hook)return;
    try{hook.detach();}catch(e){}triggerHooks.delete(key);
    event('coverage',{token:token.name,state:'trigger_unloaded',module:module.path});
  }});
}
if (tokens.has('dex.snapshot.runtime') && tokens.get('dex.snapshot.runtime').trigger === 'poll') {
  setInterval(() => {for(const id of regions.keys()) {try{snapshotRegion(id,'poll');}catch(e){event('coverage.gap',{reason:String(e),logical_id:id});}}},config.limits.snapshot_interval_ms);
}
// TRACE_EXTENSION
runtimeDebug.mark('native.network.install');
try { installNativeNetwork(); } catch(e) { event('coverage.gap',{reason:'native_network_installation',error:String(e)}); }
if (['dex.input.java','jni.trace.selected','webview.platform','network.platform','parser.json','parser.custom','crypto.cipher','crypto.custom','reflection.java','flow.java'].some(x=>tokens.has(x))) installJava();
else {event('instrumentation.ready', {java: false, tokens: config.tokens.map(t => t.name)});runtimeDebug.ready(false);}
runtimeDebug.mark('collector.source.loaded');
