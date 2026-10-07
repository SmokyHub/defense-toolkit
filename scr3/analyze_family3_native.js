#!/usr/bin/env node
"use strict";
// Findings: reports/family3/ANALYSIS.md FAMILY3-NATIVE-001..004.
// Local offline analysis. No profiles, client uploads or live-backend probes.
function parseELF64(bytes){
 const b=bytes;
 const cut=(o,n)=>{if(!Number.isSafeInteger(o)||!Number.isSafeInteger(n)||o<0||n<0||o+n>b.length)throw Error("truncated ELF");return b.slice(o,o+n);};
 const u16=o=>{const x=cut(o,2);return x[0]+x[1]*256;},u32=o=>{const x=cut(o,4);return(x[0]+x[1]*256+x[2]*65536+x[3]*16777216)>>>0;};
 const u64=o=>{let v=0n;const x=cut(o,8);for(let i=7;i>=0;i--)v=v*256n+BigInt(x[i]);if(v>BigInt(Number.MAX_SAFE_INTEGER))throw Error("ELF integer overflow");return Number(v);};
 if(b.length<64||String.fromCharCode(...b.slice(0,4))!=="\x7fELF"||b[4]!==2||b[5]!==1||u16(18)!==183)throw Error("unsupported ELF");
 const shoff=u64(40),shent=u16(58),shnum=u16(60),stridx=u16(62),phoff=u64(32),phent=u16(54),phnum=u16(56);
 if(shent!==64||phent!==56||shnum>4096||phnum>4096||stridx>=shnum)throw Error("unsupported ELF tables");
 cut(shoff,shent*shnum);cut(phoff,phent*phnum);
 const sh=[];
 for(let i=0;i<shnum;i++){let p=shoff+i*shent;sh.push({nameOffset:u32(p),type:u32(p+4),flags:u64(p+8),va:u64(p+16),offset:u64(p+24),size:u64(p+32),entsize:u64(p+56)});}
 const st=sh[stridx],str=cut(st.offset,st.size);
 for(const s of sh){let p=s.nameOffset;if(p>=str.length)throw Error("bad section name");let e=p;while(e<str.length&&str[e]!==0)e++;if(e===str.length)throw Error("unterminated section name");s.name=String.fromCharCode(...str.slice(p,e));if(s.type!==8)s.bytes=cut(s.offset,s.size);}
 const loads=[];for(let i=0;i<phnum;i++){let p=phoff+i*phent;if(u32(p)===1)loads.push({offset:u64(p+8),va:u64(p+16),filesz:u64(p+32),memsz:u64(p+40)});}
 return {sections:sh,loads};
}

function decodeRecords(sections,onlyVAs=null){
 const raw=(va,n)=>{if(!Number.isSafeInteger(va)||n<0)throw Error("range");for(const s of sections)if(va>=s.va&&va+n<=s.va+s.size)return s.bytes.slice(va-s.va,va-s.va+n);throw Error("unmapped");};
 const u64raw=va=>{let v=0n;const b=raw(va,8);for(let i=7;i>=0;i--)v=(v<<8n)|BigInt(b[i]);return v;};
 const u32=va=>{const b=raw(va,4);return(b[0]+b[1]*256+b[2]*65536+b[3]*16777216)>>>0;};
 const rela=sections.find(s=>s.name===".rela.dyn"),rels=new Map();
 for(let o=0;o<rela.size;o+=24){const va=rela.va+o,info=u64raw(va+8);if((info&0xffffffffn)===1027n&&info>>32n===0n)rels.set(Number(u64raw(va)),u64raw(va+16));}
 const u64=va=>rels.has(va)?rels.get(va):u64raw(va);
 const mask=(1n<<64n)-1n;
 const rol64=(v,r)=>{r=BigInt(r&63);return ((v<<r)|(v>>((64n-r)&63n)))&mask;};
 const rol8=(v,r)=>{v&=255;r&=7;return((v<<r)|(v>>((8-r)&7)))&255;};
 const ror8=(v,r)=>rol8(v,(8-(r&7))&7);
 const decode=va=>{
  const ptr=Number(u64(va)),count=Number(u64(va+8)),length=Number(u64(va+16));
  if(count<1||count>64||length<1||length>8192||!rels.has(va))throw Error("shape");
  raw(ptr,count*24);
  const a=u64(va+24),b=u64(va+32),c=u64(va+40),f=raw(va+48,4),r=f[1]&7,mode=(f[2]^f[3])&255;
  const combined=b^c^rol64(a,f[0]);const output=new Array(length),used=new Uint8Array(length);let total=0;
  for(let s=0;s<count;s++){
   const seg=ptr+s*24,cp=Number(u64(seg)),ip=Number(u64(seg+8)),n=Number(u64(seg+16));
   if(n<1||n>length||total+n>length)throw Error("count");
   const cipher=raw(cp,n);raw(ip,n*4);
   for(let j=0;j<n;j++){
    const p=u32(ip+j*4);if(p>=length||used[p])throw Error("indices");used[p]=1;total++;
    let z=(c*BigInt(p+1)+combined)&mask;
    z=((z^(z>>30n))*0xbf58476d1ce4e5b9n)&mask;
    z=((z^(z>>27n))*0x94d049bb133111ebn)&mask;
    z^=z>>31n;
    const shift=BigInt((p&7)*8),k1=Number((z>>shift)&0xffffffffn),k0=(Number((c>>shift)&0xffffffffn)+17*p)>>>0,x=cipher[j];
    let plain;
    if(mode===0)plain=(x^k0^k1)&255;
    else if(mode===1)plain=(ror8(x^k0,r)-k1)&255;
    else if(mode===2)plain=(rol8(x-k1,r)^k0)&255;
    else plain=(ror8((k1+k0)^x,r)+k1)&255;
    output[p]=plain;
   }
  }
  if(total!==length)throw Error("coverage");
  return {va,length,count,mode,bytes:output,text:String.fromCharCode(...output)};
 };
 const records=[],rejections={}; const data=sections.find(s=>s.name===".data.rel.ro");
 const candidates=onlyVAs||Array.from({length:Math.floor((data.size-56)/8)+1},(_,i)=>data.va+i*8);
 for(const va of candidates){try{const rec=decode(va);records.push(rec);}catch(e){rejections[e.message]=(rejections[e.message]||0)+1;}}
 return {records,rejections,candidates:candidates.length,relocations:rels.size};
}

function extractSelectorClusters(section){
 const b=section.bytes,word=o=>(b[o]+b[o+1]*256+b[o+2]*65536+b[o+3]*16777216)>>>0;
 const imm1=w=>{
  if(w===0xaa1f03e1||w===0x2a1f03e1)return 0;
  if(((w&0x7f80001f)>>>0)===0x52800001){const shift=((w>>>21)&3)*16;const imm=(w>>>5)&65535;return imm*2**shift;}
  return null;
 };
 const calls=[];
 for(let o=4;o+4<=b.length;o+=4){
  const w=word(o);if(((w&0xfc000000)>>>0)!==0x94000000)continue;
  const selector=imm1(word(o-4));if(selector===null||selector>0xffffffff)continue;
  const imm=w&0x03ffffff,delta=(imm>=0x02000000?imm-0x04000000:imm)*4;
  calls.push({pc:section.va+o,selector,target:section.va+o+delta});
 }
 const by=new Map();for(const c of calls){if(!by.has(c.target))by.set(c.target,[]);by.get(c.target).push(c);}
 const clusters=[];
 for(const [target,cc]of by){let run=[];for(const c of cc){if(run.length&&c.pc-run[run.length-1].pc!==24){if(run.length>=12)clusters.push({target,calls:run});run=[];}run.push(c);}if(run.length>=12)clusters.push({target,calls:run});}
 for(const cluster of clusters){const earlier=calls.filter(c=>c.target===cluster.target&&c.pc<cluster.calls[0].pc&&cluster.calls[0].pc-c.pc<=512);cluster.outerCandidates=earlier.slice(-1);}return {clusters,candidateCalls:calls.length};
}

function resolvePLT(elf){
 const get=n=>elf.sections.find(s=>s.name===n),plt=get(".plt"),rela=get(".rela.plt"),dyn=get(".dynsym"),str=get(".dynstr");
 if(!plt||!rela||!dyn||!str)return[];
 const u32=(s,o)=>{const b=s.bytes;return(b[o]+b[o+1]*256+b[o+2]*65536+b[o+3]*16777216)>>>0;};
 const u64=(s,o)=>{let v=0n;for(let i=7;i>=0;i--)v=v*256n+BigInt(s.bytes[o+i]);return v;};
 const table=new Map();
 for(let o=0;o+24<=rela.size;o+=24){const info=u64(rela,o+8),sym=Number(info>>32n);if(sym*24+24>dyn.size)continue;
  const off=u32(dyn,sym*24);let end=off;while(end<str.size&&str.bytes[end])end++;
  table.set(Number(u64(rela,o)),String.fromCharCode(...str.bytes.slice(off,end)));
 }
 const out=[];
 for(let o=0;o+16<=plt.size;o+=4){const w=u32(plt,o),load=u32(plt,o+4);if(((w&0x9f000000)>>>0)!==0x90000000||((load&0xffc00000)>>>0)!==0xf9400000)continue;
  const reg=w&31;if(((load>>>5)&31)!==reg)continue;
  let imm=(((w>>>5)&0x7ffff)*4)+((w>>>29)&3);if(imm>=1<<20)imm-=1<<21;
  const page=Math.floor((plt.va+o)/4096)*4096+imm*4096,got=page+((load>>>10)&4095)*8;
  if(table.has(got))out.push({va:plt.va+o,got,symbol:table.get(got)});
 }
 return out;
}

function extractJNIMethods(elf){
 const ss=elf.sections.filter(s=>s.bytes&&s.flags&2),rela=elf.sections.find(s=>s.name===".rela.dyn"),tx=elf.sections.find(s=>s.name===".text");
 if(!rela||!tx)return[];
 const raw=(va,n)=>{for(const s of ss)if(va>=s.va&&va+n<=s.va+s.size)return s.bytes.slice(va-s.va,va-s.va+n);throw Error("unmapped");};
 const u64=va=>{const b=raw(va,8);let v=0n;for(let i=7;i>=0;i--)v=v*256n+BigInt(b[i]);return v;},rels=new Map();
 for(let o=0;o+24<=rela.size;o+=24){const p=rela.va+o,info=u64(p+8);if((info&0xffffffffn)===1027n&&(info>>32n)===0n)rels.set(Number(u64(p)),Number(u64(p+16)));}
 function stringAt(va,max=1024){for(const s of ss)if(va>=s.va&&va<s.va+s.size){let a=va-s.va,e=a;while(e<s.size&&e-a<max&&s.bytes[e])e++;if(e===s.size||e-a===max)throw Error("unterminated");const b=s.bytes.slice(a,e);if(b.some(x=>x<32||x>126))throw Error("non-ASCII");return String.fromCharCode(...b);}throw Error("unmapped string");}
 function descriptor(s){let i=0;
  function type(voidOK=false){if(i>=s.length)return false;let x=s[i++];if("ZBCSIJFD".includes(x))return true;if(x==="V")return voidOK;if(x==="[")return type(false);if(x==="L"){let e=s.indexOf(";",i);if(e<=i||!/^[-\w/$]+$/.test(s.slice(i,e)))return false;i=e+1;return true;}return false;}
  if(s[i++]!=="(")return false;while(i<s.length&&s[i]!==")")if(!type(false))return false;if(s[i++]!==")"||!type(true))return false;return i===s.length;
 }
 const out=[];
 for(const slot of [...rels.keys()].sort((a,b)=>a-b)){if(!rels.has(slot+8)||!rels.has(slot+16))continue;const fn=rels.get(slot+16);if(fn<tx.va||fn>=tx.va+tx.size)continue;
  try{const name=stringAt(rels.get(slot),128),sig=stringAt(rels.get(slot+8));if(!/^[A-Za-z_$][\w$]*$/.test(name)||!descriptor(sig))continue;out.push({name,descriptor:sig,functionVA:fn,tableVA:slot});}catch{}
 }
 return out;
}

function bindNativeResponseRoles(text, meta, cluster) {
 const fail=(why)=>({status:"needs_review",reason:why});
 const B=text.bytes,VA=text.va??text.base,END=VA+B.length,H=x=>"0x"+x.toString(16),sx=(n,k)=>n>=2**(k-1)?n-2**k:n;
 const W=p=>{if(p<VA||p+4>END||p%4)throw Error("instruction outside text");let i=p-VA;return(B[i]|B[i+1]<<8|B[i+2]<<16|B[i+3]<<24)>>>0;};
 const BL=(p)=>{let w=W(p);return w>>>26===0x25?p+sx(w&0x3ffffff,26)*4:null;};
 const mov=(w)=>((w&0xffe0ffe0)>>>0===0xaa0003e0||(w&0xffe0ffe0)>>>0===0x2a0003e0)?{d:w&31,s:w>>>16&31}:null;
 const lit=(w,r)=>{if((w&31)!==r)return null;if((w&0x7f800000)>>>0===0x52800000)return(w>>>5&65535)*2**((w>>>21&3)*16);const m=mov(w);return m&&m.s===31?0:null;};
 const add=(w)=>((w&0x7f000000)>>>0===0x11000000)?{d:w&31,s:w>>>5&31,n:(w>>>10&4095)*((w>>>22&1)?4096:1)}:null;
 const ldr=(w)=>((w&0xffc00000)>>>0===0xf9400000)?{d:w&31,s:w>>>5&31,n:(w>>>10&4095)*8}:null;
 const blr=w=>(w&0xfffffc1f)>>>0===0xd63f0000?(w>>>5&31):null;
 try {
  const all=[];for(let p=VA;p<END;p+=4){const t=BL(p);if(t!==null&&p>=VA+4){const k=lit(W(p-4),1);if(k!==null)all.push({pc:p,target:t,key:k});}}
  let g=cluster;
  if(!g){const groups=[];for(const c of all){let seq=[c];for(let q=c.pc+24;;q+=24){const v=all.find(v=>v.pc===q&&v.target===c.target);if(!v)break;seq.push(v);}if(seq.length===15&&!all.some(v=>v.pc===c.pc-24&&v.target===c.target))groups.push(seq);}
   if(groups.length!==1)return fail("unique 15-selector cluster absent");const calls=groups[0],prior=all.filter(x=>x.target===calls[0].target&&x.pc<calls[0].pc&&calls[0].pc-x.pc<=512).sort((a,b)=>b.pc-a.pc);
   if(!prior.length)return fail("outer selector absent");g={calls,outer:prior[0],getter:calls[0].target};
  }
  if(g.calls.length!==15)return fail("unsupported getter count");
  const fields=[];let destReg=null,converter=null;
  for(const call of g.calls.slice(0,14)){
   let dst=null,conv=null;
   for(let q=call.pc+4;q<=call.pc+16;q+=4){let w=W(q),a=add(w),m=mov(w);if(a&&a.d===1&&a.s!==31)dst={reg:a.s,off:a.n};else if(m&&m.d===1&&m.s!==31)dst={reg:m.s,off:0};let t=BL(q);if(t!==null){if(!dst)return fail("string destination unresolved");conv={pc:q,target:t};break;}}
   if(!conv||!(W(conv.pc+4)&0x7e000000)||((W(conv.pc+4)&0x7e000000)>>>0!==0x36000000))return fail("conversion result guard absent");
   if(destReg===null)destReg=dst.reg;else if(destReg!==dst.reg)return fail("payload carrier changed");
   if(converter===null)converter=conv.target;else if(converter!==conv.target)return fail("string converters disagree");
   if(fields.some(f=>f.off===dst.off))return fail("duplicate string destination");
   fields.push({key:call.key,off:dst.off,getterPC:call.pc,copyPC:conv.pc});
  }
  const fMap=new Map(fields.map(f=>[f.off,f]));if(fMap.size!==14)return fail("field count");
  const table=(meta.jni??[]).filter(x=>["encodeString","encodeString_2","decodeString"].includes(x.name));
  if(table.length!==3)return fail("three MMKV string JNI registrations required");
  const starts=(meta.jni??[]).map(x=>Number(x.functionVA)).sort((a,b)=>a-b),pairs=[];
  for(const j of table){const start=Number(j.functionVA),stop=starts.find(x=>x>start)??Math.min(start+4096,END),found=[];
   for(let p=start;p+12<stop;p+=4){const gate=BL(p),consumer=BL(p+12);if(gate!==null&&consumer!==null&&consumer<=g.outer.pc&&g.outer.pc-consumer<=512&&((W(p+4)&0x7e000000)>>>0===0x36000000)&&((W(p+4)>>>19)&31)===0)found.push({gate,consumer,pc:p});}
   if(found.length!==1)return fail("string JNI interception pair unresolved");pairs.push(found[0]);
  }
  if(pairs.some(x=>x.gate!==pairs[0].gate||x.consumer!==pairs[0].consumer))return fail("JNI interception targets disagree");
  const gate=pairs[0].gate, consumer=pairs[0].consumer;
  const plt=new Map((meta.plt??[]).map(x=>[Number(x.pltVA),x.symbol]));
  const toString=[...plt].filter(x=>/^_ZNSt6__ndk19to_stringEm$/.test(x[1])).map(x=>x[0]);
  if(toString.length!==1)return fail("verified unsigned-long to_string binding absent");
  const todo=[gate],seen=new Set(),storage=[];
  while(todo.length){let p=todo.pop();for(let n=0;n<2048;n++,p+=4){if(p<gate||p>=Math.min(gate+8192,END))return fail("gate control flow escapes bound");if(seen.has(p))break;seen.add(p);let w=W(p),t=BL(p);if(t===toString[0]){const k=lit(W(p-4),0);if(k===null)return fail("storage constant unresolved");storage.push({key:k,pc:p});}
    if(w===0xd65f03c0)break;if(w>>>26===5){todo.push(p+sx(w&0x3ffffff,26)*4);break;}
    if((w&0xff000010)>>>0===0x54000000)todo.push(p+sx(w>>>5&0x7ffff,19)*4);
    if((w&0x7e000000)>>>0===0x34000000)todo.push(p+sx(w>>>5&0x7ffff,19)*4);
    if((w&0x7e000000)>>>0===0x36000000)todo.push(p+sx(w>>>5&16383,14)*4);
   }}
  if(storage.length!==1||storage[0].key!==g.outer.key)return fail("storage/outer selectors disagree");
  const slots=new Set([0x30,0xf8,0x108,0x388,0x398,0x118,0xe8,0x1f0,0xc8,0x728]);
  function helperSlot(target){if(target<VA||target>=END)return null;const found=[];
   for(let p=target;p+16<Math.min(target+512,END);p+=4){if(p>target&&W(p)===0xd65f03c0)break;const a=ldr(W(p));if(!a||a.s!==0||a.n!==0)continue;
    for(let q=p+4;q<=p+12;q+=4){const b=ldr(W(q));if(!b||b.s!==a.d||!slots.has(b.n))continue;for(let r=q+4;r<=q+20;r+=4)if(blr(W(r))===b.d)found.push(b.n);}}
   return found.length===1?found[0]:null;
  }
  const end=Math.min(consumer+8192,END), localRefs=[];
  for(let p=g.calls.at(-1).pc;p+32<end;p+=4){const a=ldr(W(p));if(!a||a.n!==0)continue;const b=ldr(W(p+4));if(!b||b.s!==a.d||b.n!==0xc8)continue;for(let q=p+8;q<=p+24;q+=4)if(blr(W(q))===b.d)localRefs.push({pc:p,envReg:a.s,callPC:q});}
  if(localRefs.length!==1)return fail("retained Context local-reference boundary unresolved");
  const R=Array(32).fill(null), events=[], bindings=new Map;R[destReg]={kind:"payload",off:0};R[localRefs[0].envReg]={kind:"env"};
  const clone=x=>x?{...x}:null, same=(a,b)=>a&&b&&JSON.stringify(a)===JSON.stringify(b);
  const stringAt=off=>fMap.has(off)?{kind:"string",off}:null;
  function plus(v,n){if(!v)return null;if(v.kind==="payload"){let off=v.off+n;return stringAt(off-1)??{kind:"payload",off};}if(v.kind==="string"&&n===0)return clone(v);return null;}
  const set=(d,v)=>{if(d!==31)R[d]=v;}, get=d=>d===31?{kind:"zero"}:R[d];
  function field(v,role,pc){if(!v||v.kind!=="string"||!fMap.has(v.off))throw Error("role "+role+" has no string producer at "+H(pc));const old=bindings.get(role);if(old!==undefined&&old!==v.off)throw Error("ambiguous role "+role);bindings.set(role,v.off);}
  function invoke(slot,pc){const a=R.map(clone);let result=null;
   if(slot===0x720||slot===0x98)result={kind:"constant",value:0};
   else if(slot===0xc8)result={kind:"context"};
   else if(slot===0x30){field(a[1],"resolver_class",pc);result={kind:"resolverClass"};}
   else if(slot===0x388&&a[1]?.kind==="resolverClass"){field(a[2],"resolver_method",pc);field(a[3],"resolver_descriptor",pc);result={kind:"resolverMethod"};}
   else if(slot===0x538&&a[1]?.kind==="string")result={kind:"jstring",off:a[1].off};
   else if(slot===0x398&&a[1]?.kind==="resolverClass"&&a[2]?.kind==="resolverMethod"&&a[3]?.kind==="jstring"){field({kind:"string",off:a[3].off},"loader_class",pc);result={kind:"loaderClass"};}
   else if(slot===0x728&&a[1]?.kind==="vectorBegin"&&a[2]?.kind==="vectorLength"&&a[1].off===a[2].off)result={kind:"byteBuffer",off:a[1].off};
   else if(slot===0xf8&&a[1]?.kind==="context")result={kind:"contextClass"};
   else if(slot===0x108){const k=a[1]?.kind;if(!["contextClass","loaderClass","payloadClass"].includes(k)||a[2]?.kind!=="string"||a[3]?.kind!=="string")throw Error("method producer unresolved at "+H(pc));result={kind:"method",owner:k,nameOff:a[2].off,descOff:a[3].off};}
   else if(slot===0x118&&a[1]?.kind==="context"&&a[2]?.kind==="method"&&a[2].owner==="contextClass"){field({kind:"string",off:a[2].nameOff},"parent_getter_name",pc);field({kind:"string",off:a[2].descOff},"parent_getter_descriptor",pc);result={kind:"parentObject"};}
   else if(slot===0xe8&&a[1]?.kind==="loaderClass"&&a[2]?.kind==="method"&&a[2].owner==="loaderClass"&&a[3]?.kind==="byteBuffer"&&a[4]?.kind==="parentObject"){field({kind:"string",off:a[2].nameOff},"constructor_name",pc);field({kind:"string",off:a[2].descOff},"loader_constructor_descriptor",pc);result={kind:"loaderObject"};}
   else if(slot===0x118&&a[1]?.kind==="loaderObject"&&a[2]?.kind==="method"&&a[2].owner==="loaderClass"&&a[3]?.kind==="jstring"){field({kind:"string",off:a[2].nameOff},"load_class_method",pc);field({kind:"string",off:a[2].descOff},"load_class_descriptor",pc);field({kind:"string",off:a[3].off},"payload_class",pc);result={kind:"payloadClass"};}
   else if(slot===0xe8&&a[1]?.kind==="payloadClass"&&a[2]?.kind==="method"&&a[2].owner==="payloadClass"){field({kind:"string",off:a[2].nameOff},"constructor_name",pc);field({kind:"string",off:a[2].descOff},"payload_constructor_descriptor",pc);result={kind:"payloadObject"};}
   else if(slot===0x1f0&&a[1]?.kind==="payloadObject"&&a[2]?.kind==="method"&&a[2].owner==="payloadClass"&&a[3]?.kind==="context"){field({kind:"string",off:a[2].nameOff},"entry_method",pc);field({kind:"string",off:a[2].descOff},"entry_descriptor",pc);result={kind:"invoked"};}
   events.push({pc:H(pc),slot:H(slot),result:result?.kind??null});for(let i=0;i<19;i++)R[i]=null;R[0]=result;
  }
  let zflag=null;const guards=[];
  for(let p=localRefs[0].pc,steps=0;p<end&&steps++<2048;p+=4){const w=W(p),a=add(w),m=mov(w),l=ldr(w),br=blr(w),t=BL(p),rd=w&31,rn=w>>>5&31;
   if((w&0xff000010)>>>0===0x54000000){const cond=w&15;if((cond===0||cond===1)&&zflag!==null){if(cond===0?zflag:!zflag){const dst=p+sx(w>>>5&0x7ffff,19)*4;if(dst<localRefs[0].pc||dst>=end)return fail("selected branch exits trace");p=dst-4;}}else guards.push({pc:H(p),kind:"conditional"});continue;}
   if((w&0x7e000000)>>>0===0x34000000){const v=get(rd),nz=v?.kind==="constant"?v.value!==0:v&&v.kind!=="zero"?true:v?.kind==="zero"?false:null;const take=(w&0x1000000)?nz:!nz;if(nz!==null&&take){const dst=p+sx(w>>>5&0x7ffff,19)*4;if(dst<localRefs[0].pc||dst>=end)return fail("selected CB branch exits trace");p=dst-4;}else if(nz===null)guards.push({pc:H(p),kind:"nonnull"});continue;}
   if((w&0x7e000000)>>>0===0x36000000){const v=get(rd);if(v?.kind==="constant"){const bit=(w>>>19&31)+(w>>>31)*32,nz=Boolean(Math.floor(v.value/2**bit)%2),take=(w&0x1000000)?nz:!nz;if(take){const dst=p+sx(w>>>5&16383,14)*4;if(dst<localRefs[0].pc||dst>=end)return fail("selected TB branch exits trace");p=dst-4;}}else guards.push({pc:H(p),kind:"helper succeeds"});continue;}
   if(w>>>26===5){const dst=p+sx(w&0x3ffffff,26)*4;if(dst<localRefs[0].pc||dst>=end)return fail("unconditional branch exits trace");p=dst-4;continue;}
   if((w&0x1f800000)>>>0===0x12000000&&(w>>>29&3)===3&&rd===31){const v=get(rn);zflag=v?.kind==="constant"&&v.value===0?true:null;continue;}
   if(m){set(m.d,clone(get(m.s)));continue;}if(a){set(a.d,plus(get(a.s),a.n));continue;}
   if(l){let v=get(l.s),out=null;if(v?.kind==="env"&&l.n===0)out={kind:"vtable"};else if(v?.kind==="vtable")out={kind:"jni",slot:l.n};else if(v?.kind==="payload")out=stringAt(v.off+l.n-16);set(l.d,out);continue;}
   if((w&0xffc00000)>>>0===0x39400000){const v=get(rn);set(rd,v?.kind==="payload"&&fMap.has(v.off+(w>>>10&4095))?{kind:"stringTag",off:v.off+(w>>>10&4095)}:null);continue;}
   if((w&0xffc00000)>>>0===0xa9400000){const v=get(rn),off=sx(w>>>15&127,7)*8;if(v?.kind==="payload"){set(rd,{kind:"vectorBegin",off:v.off+off});set(w>>>10&31,{kind:"vectorEnd",off:v.off+off});}else{set(rd,null);set(w>>>10&31,null);}continue;}
   if((w&0xffe0fc00)>>>0===0xcb000000){let x=get(rn),y=get(w>>>16&31);set(rd,x?.kind==="vectorEnd"&&y?.kind==="vectorBegin"&&x.off===y.off?{kind:"vectorLength",off:x.off}:null);continue;}
   if((w&0x1fe00000)>>>0===0x1a800000){let x=get(rn),y=get(w>>>16&31);if(w&0x400)y=plus(y,1);set(rd,same(x,y)?clone(x):null);continue;}
   if(br!==null){const v=get(br);if(v?.kind==="jni")invoke(v.slot,p);else{for(let i=0;i<19;i++)R[i]=null;}if(R[0]?.kind==="invoked")break;continue;}
   if(t!==null){const slot=helperSlot(t);if(slot!==null)invoke(slot,p);else for(let i=0;i<19;i++)R[i]=null; if(R[0]?.kind==="invoked")break;continue;}
   if((w&0x7f800000)>>>0===0x52800000){set(rd,{kind:"constant",value:(w>>>5&65535)*2**((w>>>21&3)*16)});continue;}
   if((w&0x9f000000)>>>0===0x90000000||(w&0x9f000000)>>>0===0x10000000){set(rd,null);continue;}
   if((w&0x7f000000)>>>0===0x51000000){set(rd,null);continue;}
   if((w&0x3a000000)>>>0===0x28000000||(w&0x3b000000)>>>0===0x39000000||(w&0x3b200c00)>>>0===0x38000000)continue;
   if((w&0xff000010)>>>0===0x54000000||(w&0x7e000000)>>>0===0x34000000||(w&0x7e000000)>>>0===0x36000000||w>>>26===5||w===0xd503201f)continue;
   set(rd,null);
  }
  const roles=["resolver_class","resolver_method","resolver_descriptor","loader_class","parent_getter_name","parent_getter_descriptor","constructor_name","loader_constructor_descriptor","load_class_method","load_class_descriptor","payload_class","payload_constructor_descriptor","entry_method","entry_descriptor"];
  if(!events.some(e=>e.result==="invoked"))return fail("buffer-to-Context-entry topology unresolved");
  if(roles.some(r=>!bindings.has(r)))return fail("missing role");
  const used=new Set(roles.map(r=>bindings.get(r)));if(used.size!==14)return fail("roles do not cover 14 distinct fields");
  return{status:"supported_static_topology",outer:g.outer.key,storage:storage[0].key,carrierRegister:destReg,converter:H(converter),gate:H(gate),consumer:H(consumer),bindings:roles.map(role=>{const off=bindings.get(role),f=fMap.get(off);return{role,key:f.key,fieldOffset:H(off),getterPC:H(f.getterPC),copyPC:H(f.copyPC)};}),arrayKey:g.calls[14].key,events,guards};
 }catch(e){return fail(String(e.message??e));}
}

function analyzeNative(bytes,name="<memory>"){
 let elf;try{elf=parseELF64(bytes);}catch(e){return{name,status:"needs_review",error:e.message};}
 const modifiedSignature="(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IZZJ)V";
 // Search raw bytes without spread limits for the longer MMKV file.
 const contains=(str)=>{const needle=Array.from(str,c=>c.charCodeAt(0));outer:for(let i=0;i+needle.length<=bytes.length;i++){if(bytes[i]!==needle[0])continue;for(let j=1;j<needle.length;j++)if(bytes[i+j]!==needle[j])continue outer;return true;}return false;};
 const registered=extractJNIMethods(elf);
 const mmkv=contains("com/tencent/mmkv/MMKV")&&contains("jniInitialize"),changed=mmkv&&registered.some(x=>x.name==="jniInitialize"&&x.descriptor===modifiedSignature);
 const text=elf.sections.find(s=>s.name===".text");
 const clusters=text?extractSelectorClusters(text).clusters:[];
 const slotCalls=[];
 if(text){const b=text.bytes,w=o=>(b[o]+b[o+1]*256+b[o+2]*65536+b[o+3]*16777216)>>>0;
  for(let o=0;o+4<=b.length;o+=4){
   const x=w(o);if(((x&0xffc00000)>>>0)!==0xf9400000)continue;
   const slot=((x>>>10)&4095)*8;if(![0x728,0xc8,0x30,0x388].includes(slot))continue;
   const rt=x&31;
   for(let j=1;j<=4&&o+j*4+4<=b.length;j++){if(w(o+j*4)===(0xd63f0000|(rt<<5))>>>0){slotCalls.push({va:text.va+o,call:text.va+o+j*4,slot});break;}}
  }
 }
 const matched=clusters.filter(c=>c.calls.length===15&&c.outerCandidates.length===1&&new Set(c.calls.map(x=>x.selector)).size===15&&slotCalls.some(x=>x.slot===0x728&&x.va>c.calls[14].pc&&x.va-c.calls[14].pc<4096)&&slotCalls.some(x=>x.slot===0xc8&&x.va>c.calls[14].pc&&x.va-c.calls[14].pc<4096));
 let decoded={records:[],rejections:{},candidates:0};
 const required=[".rela.dyn",".rodata",".data.rel.ro"];
 if(required.every(n=>elf.sections.some(s=>s.name===n)))decoded=decodeRecords(elf.sections.filter(s=>required.includes(s.name)));
 const records=decoded.records.filter(r=>/^[\x20-\x7e]+$/.test(r.text)),strings=records.map(r=>r.text);
 const jniSig="(Landroid/app/Activity;Lorg/json/JSONObject;)Lorg/json/JSONObject;";
 const coherent=contains("JNI_OnLoad")&&strings.includes("nativeEntry")&&strings.includes(jniSig)&&["java/net/HttpURLConnection","POST","application/json; charset=utf-8","org/json/JSONObject","com/tencent/mmkv/MMKV","initialize","encode","decodeString"].every(x=>strings.includes(x));
 const urls=strings.filter(x=>/^https?:\/\/[^ \t]+$/.test(x));
 const bound=text&&changed&&matched.length===1?bindNativeResponseRoles(text,{jni:registered,plt:resolvePLT(elf).map(x=>({pltVA:x.va,symbol:x.symbol}))}):null;
 let status=changed&&matched.length===1&&bound?.status==="supported_static_topology"?"family3_loader_pattern":coherent?"family3_companion_pattern":changed||records.length||matched.length||clusters.length?"needs_review":"no_family3_pattern";
 let contract=null,contract_candidate=null;
 if(status==="family3_loader_pattern"){
  const chosen={resolver_class:"java/lang/Class",resolver_method:"forName",resolver_descriptor:"(Ljava/lang/String;)Ljava/lang/Class;",loader_class:"dalvik.system.InMemoryDexClassLoader",parent_getter_name:"getClassLoader",parent_getter_descriptor:"()Ljava/lang/ClassLoader;",constructor_name:"<init>",loader_constructor_descriptor:"(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",load_class_method:"loadClass",load_class_descriptor:"(Ljava/lang/String;)Ljava/lang/Class;",payload_class:"PAYLOAD_CLASS_NAME",payload_constructor_descriptor:"()V",entry_method:"ENTRY_METHOD_NAME",entry_descriptor:"(Landroid/content/Context;)V"};
  const fields=Object.fromEntries(bound.bindings.map(x=>[String(x.key),chosen[x.role]]));
  fields[String(bound.arrayKey)]="DEX ARRAY";
  contract_candidate={status:"needs_review",evidence:"conditional static JNI-compatible choices, not remote values or execution",outer:String(bound.outer),storage:String(bound.storage),roles:Object.fromEntries(bound.bindings.map(x=>[x.role,String(x.key)])),array_key_candidate:String(bound.arrayKey),template:{[String(bound.outer)]:fields},validation:{string_roles:"bound through destinations and JNI arguments on a conditional success path",array_source:"independent getter-to-vector parser binding still required",context_source:"initializer-to-retained-Context binding still required",runtime:"unobserved"}};
 }
 return{name,status,modified_mmkv_context_signature:changed,role_binding:bound,contract,contract_candidate,decoded_record_count:records.length,decoded_records:records.map(r=>({va:r.va,text:r.text})),config_urls:urls,limits:["ARM64 ELF64 LE with section headers and RELA only","Observed compiler layout requires fifteen selector getters at 24-byte call spacing","Automatic array parser and initializer Context provenance are incomplete; complete response contracts remain needs_review","Capability pattern does not prove execution, maliciousness or attribution"]};
}

const fs = require("node:fs");
const path = require("node:path");
const inputs = process.argv.slice(2);
if (!inputs.length || inputs.includes("--help") || inputs.includes("-h")) {
  process.stderr.write("Usage: node scripts/analyze_family3_native.js <ELF.so | unpacked-library-directory> [...]\n");
  process.exit(inputs.length ? 0 : 2);
}
const files = [];
function visit(input, depth=0) {
  if (depth > 12 || files.length >= 512) throw Error("Input exceeds directory/file bounds");
  const st = fs.lstatSync(input);
  if (st.isSymbolicLink()) return;
  if (st.isDirectory()) for (const entry of fs.readdirSync(input).sort()) visit(path.join(input, entry), depth + 1);
  else if (st.isFile() && input.endsWith(".so")) files.push(input);
}
for (const input of inputs) visit(input);
if (!files.length) throw Error("No .so files; unpack the complete APK/split set first");
const results = files.map(file => {
  const size = fs.statSync(file).size;
  if (size > 32*1024*1024) return {name:file, status:"needs_review", error:"ELF exceeds 32 MiB bound"};
  const bytes = Array.from(fs.readFileSync(file));
  // Unsupported ABIs are explicit; use the original arm64-v8a directory when available.
  try { return analyzeNative(bytes, file); }
  catch (error) { return {name:file,status:"needs_review",error:String(error.message ?? error)}; }
});
const loaders = results.filter(r => r.status === "family3_loader_pattern");
const companions = results.filter(r => r.status === "family3_companion_pattern");
const output = {
  status: loaders.length && companions.length ? "family3_loader_and_companion_patterns" :
          loaders.length ? "family3_loader_pattern" :
          results.some(r => r.status !== "no_family3_pattern") ? "needs_review" : "no_family3_pattern",
  evidence: "static capability/patterns; remote values, execution and RMG are unconfirmed",
  validated_scope: "four homologous ARM64 builds; changed def-use/layout requires review",
  results
};
process.stdout.write(JSON.stringify(output, null, 2) + "\n");
