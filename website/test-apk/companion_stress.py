#!/usr/bin/env python3
"""Generate 3,072 distinct native hooks for isolated companion stress tests."""
from pathlib import Path
import argparse


def source(hooks=3072, namespace='legacy'):
    if type(hooks) is not int or not 1 <= hooks <= 4096:
        raise ValueError('hooks must be 1..4096')
    if namespace not in ('legacy', 'process'):
        raise ValueError('namespace must be legacy or process')
    lines=['// Benign companion: distinct private code stubs, never broad libc hooks.']
    if namespace == 'legacy':
        lines += ["Module.ensureInitialized('libc.so');",
                  "const base=Module.getBaseAddress('libc.so');",
                  "const pidAddress=Module.getExportByName('libc.so','getpid');"]
    else:
        # A lexical analyst-owned namespace must not collide with either bridge.
        lines += ["const Module=Object.freeze({sentinel:'analyst-script-local'});",
                  "const libc=Process.getModuleByName('libc.so');libc.ensureInitialized();",
                  "const base=libc.base,pidAddress=libc.getExportByName('getpid');"]
    lines += [f"const stressCount={hooks},namespace={namespace!r},stride=32;",
              "const slab=Memory.alloc(stressCount*stride),raw=new Uint8Array(stressCount*stride),words=new DataView(raw.buffer);",
              "for(let i=0;i<stressCount;i++){const offset=i*stride;if(Process.arch==='arm64'){",
              " words.setUint32(offset,0x52800000|(i<<5),true);words.setUint32(offset+4,0xd65f03c0,true);for(let j=8;j<stride;j+=4)words.setUint32(offset+j,0xd503201f,true);",
              "}else if(Process.arch==='x64'){raw.fill(0x90,offset,offset+stride);raw[offset]=0xb8;words.setUint32(offset+1,i,true);raw[offset+5]=0xc3;}",
              "else throw Error('Unsupported stress ABI: '+Process.arch);}",
              "slab.writeByteArray(raw.buffer);if(!Memory.protect(slab,raw.byteLength,'r-x'))throw Error('Private stub executable protection failed');",
              "let attempts=0;const hits=new Uint32Array(stressCount),functions=[],listeners=[];",
              "function register(index){const address=slab.add(index*stride);functions.push(new NativeFunction(address,'int',[]));listeners.push(Interceptor.attach(address,{onEnter(){hits[index]++;}}));attempts++;}"]
    lines += [f'register({index});' for index in range(hooks)]
    lines += [
        "const pid=new NativeFunction(pidAddress,'int',[])();let sweeps=0;",
        "function sweep(){for(let i=0;i<stressCount;i++){const actual=functions[i]();if(actual!==i)throw Error('Hook changed original return at '+i);}sweeps++;}",
        "sweep();",
        "function metrics(){let observed=0,calls=0;for(const hit of hits){if(hit)observed++;calls+=hit;}return {attempts,unique_addresses:stressCount,observed_native_hooks:observed,native_callbacks:calls,sweeps,namespace,pid};}",
        "Java.perform(()=>{const MathClass=Java.use('java.lang.Math');let java_calls=0;for(const overload of MathClass.abs.overloads){overload.implementation=function(){java_calls++;return overload.apply(this,arguments);};}const Integer=Java.use('java.lang.Integer');const method=MathClass.class.getDeclaredMethod('abs',Java.array('java.lang.Class',[Integer.TYPE.value]));const result=method.invoke(null,Java.array('java.lang.Object',[Integer.valueOf(-73)]));if(String(result)!=='73')throw Error('Companion Java hook changed original result');send({fixture_companion:'ready',...metrics(),java_hooks:MathClass.abs.overloads.length,java_calls,base:String(base)});});",
        "rpc.exports={fixtureidentity(){return 'isolated companion';},fixturemetrics:metrics};",
        "const stressTimer=setInterval(()=>{sweep();if(sweeps%5===0)send({fixture_companion:'alive',...metrics()});},1000);",
    ]
    return '\n'.join(lines)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('out')
    parser.add_argument('--hooks',type=int,default=3072)
    parser.add_argument('--namespace',choices=('legacy','process'),default='legacy')
    args=parser.parse_args();Path(args.out).write_text(source(args.hooks,args.namespace));print(args.out)
