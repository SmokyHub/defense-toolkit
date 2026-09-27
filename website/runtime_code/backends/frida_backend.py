"""Frida transport adapter. Core services consume only standard events and owned bytes."""
from dataclasses import asdict
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from ..model import Capability
from . import register


def host_compatibility(version):
    if version not in ('17.18.0','17.19.0'):
        raise RuntimeError('Supported Frida host versions: 17.18.0, 17.19.0; use an exactly matching server')
    return {'host_version':version,'required_server_version':version,
            'server_flavor':'unverified',
            'validation':'host_api_only' if version=='17.18.0' else 'see_device_validation_matrix',
            'limitations':['Host version does not establish server flavor or device/build coverage',
                            'Florida 17.18.0 has not been validated with the capture fixtures']}


def adb(serial,*args):
    result=subprocess.run(['adb','-s',serial,*args],capture_output=True,text=True,timeout=15,check=True)
    return result.stdout.strip()


@contextmanager
def frida_deadline(stage,seconds=10):
    """Cancel transport waits and identify the stalled startup operation."""
    import frida
    with frida.Cancellable() as cancel:
        expired=threading.Event()
        def expire():
            expired.set();cancel.cancel()
        timer=threading.Timer(seconds,expire);timer.daemon=True;timer.start()
        try:
            yield
        except Exception as error:
            if expired.is_set():
                raise TimeoutError(f'{stage} exceeded {seconds}s; check the Frida server and foreground app on the selected device') from error
            raise
        finally:timer.cancel()


def launch_app(serial,app):
    # A PID may belong to a cached/frozen process. Always foreground the launcher
    # before attachment; PID existence alone does not establish runnable state.
    component=adb(serial,'shell','cmd','package','resolve-activity','--brief',app).splitlines()
    if not component or not re.fullmatch(r'[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+',component[-1]):
        raise ValueError('No launchable Activity for '+app)
    launch=adb(serial,'shell','am','start','-W','-n',component[-1])
    if 'Error:' in launch or 'Status: timeout' in launch:raise ValueError('Activity launch failed: '+launch)
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=subprocess.run(['adb','-s',serial,'shell','pidof',app],capture_output=True,text=True,timeout=2)
        if result.returncode==0 and len(result.stdout.split())==1 and result.stdout.strip().isdigit():return int(result.stdout.strip())
        time.sleep(.1)
    raise RuntimeError('Android launched no stable app process; inspect launch/crash logs')


def preflight(serial,require_root=True):
    allowed={'33011FDH20018E':'Pixel 7','emulator-5554':'sdk_gphone64','127.0.0.1:6520':'Cuttlefish'}
    if re.fullmatch(r'emulator-\d+',serial):
        name=adb(serial,'emu','avd','name').splitlines()[0]
        if name not in ('anzol_lab_api34_x86_64','anzol_lab_api36_x86_64'):
            raise ValueError('Emulator AVD is not a designated lab image')
        allowed[serial]='sdk_gphone64'
    if serial not in allowed:
        raise ValueError('Device is not in the designated lab device policy')
    model=adb(serial,'shell','getprop','ro.product.model')
    if allowed[serial] not in model:
        raise ValueError('Device model does not match the designated serial')
    result={'serial':serial,'model':model}
    for name,prop in [('fingerprint','ro.build.fingerprint'),('api','ro.build.version.sdk'),('abi','ro.product.cpu.abi')]:
        result[name]=adb(serial,'shell','getprop',prop)
    result['root']=adb(serial,'shell','id','-u')=='0'
    result['selinux']=adb(serial,'shell','getenforce')
    if require_root and not result['root']:
        raise ValueError('Root adbd access unavailable; no policy, rooting, or APK changes attempted')
    result['binaries']={}
    for name,path in [('art','/apex/com.android.art/lib64/libart.so'),('dexfile','/apex/com.android.art/lib64/libdexfile.so'),('linker','/apex/com.android.runtime/bin/linker64')]:
        try:result['binaries'][name]={'path':path,'sha256':adb(serial,'shell','sha256sum',path).split()[0]}
        except Exception as error:result['binaries'][name]={'path':path,'status':'unreadable','reason':str(error)}
    result['internal_profiles']={'art':'unsupported: no validated profile','linker':'unsupported: no validated profile'}
    return result


def select_profile(candidates,device_info,binary,tokens):
    matches=[p for p in candidates if p['api']==device_info.get('api') and p['abi']==device_info.get('abi') and
             p['sha256']==device_info.get('binaries',{}).get(binary,{}).get('sha256')]
    if len(matches)!=1:
        raise ValueError(json.dumps({'rejected_tokens':[{'token':t.name,'reason':f'No unique validated {binary} profile for installed API/ABI/SHA-256'} for t in tokens]}))
    return matches[0]


class FridaBackend:
    def __init__(self):
        self.sessions={}
        self.service=None
        self.device=None
        self.poll_stop=threading.Event()
        self.poller=None
        self.lock=threading.RLock()
        self.rpc_slots=threading.BoundedSemaphore(4)
        port=os.environ.get('RUNTIME_CODE_FRIDA_SERVER_PORT')
        if port is not None and (not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535):
            raise ValueError('RUNTIME_CODE_FRIDA_SERVER_PORT must be a device TCP port from 1 to 65535')
        self.server_port=int(port) if port is not None else None
        self.forward_port=None
        self.remote_endpoint=None
        self.companions=[]

    def configure_scripts(self,paths):
        if len(paths)>8:raise ValueError('--script accepts at most 8 files')
        scripts=[];total=0
        for path in paths:
            path=Path(path).expanduser().resolve()
            with path.open('rb') as stream:raw=stream.read(4*1024**2+1)
            total+=len(raw)
            if len(raw)>4*1024**2 or total>8*1024**2:raise ValueError('--script exceeds the 4 MiB/file or 8 MiB total source limit')
            scripts.append({'path':str(path),'name':path.name,'sha256':hashlib.sha256(raw).hexdigest(),'source':raw.decode('utf-8-sig')})
        self.companions=scripts

    def load_companions(self,session,item,process):
        item['companions']=[]
        item['companion_stats']=[]
        for index,spec in enumerate(self.companions):
            metadata={k:v for k,v in spec.items() if k!='source'}
            with frida_deadline('Loading companion '+spec['name'],15):
                # Each create_script has separate globals and RPC exports. Do not
                # concatenate analyst source with the collector or rewrite it.
                script=session.create_script(self.java_bridge_source(isolated=True)+'\n'+spec['source'],name='companion-'+str(index)+'-'+spec['name'])
                item['companions'].append(script)
                stats={**metadata,'emitted':0,'dropped':0,'binary_bytes_not_retained':0}
                item['companion_stats'].append(stats)
                def on_message(message,data,meta=metadata,counters=stats):
                    counters['binary_bytes_not_retained']+=len(data or b'')
                    if counters['emitted']>=min(self.pack.limits.events,1024):
                        counters['dropped']+=1
                        if counters['dropped']==1:self.service.submit(process,{'kind':'coverage.gap','data':{**meta,'reason':'companion_message_budget','limit':min(self.pack.limits.events,1024)}})
                        return
                    counters['emitted']+=1
                    budget=[8192,128]
                    def bounded(value,depth=0):
                        budget[1]-=1
                        if budget[0]<=0 or budget[1]<=0:return '<preview limit>'
                        if isinstance(value,str):
                            text=value[:min(2048,budget[0])];budget[0]-=len(text);return text
                        if value is None or type(value) in (int,float,bool):return value
                        if depth>=3:return '<depth limit>'
                        if isinstance(value,list):return [bounded(v,depth+1) for v in value[:16]]
                        if isinstance(value,dict):return {str(k)[:128]:bounded(value[k],depth+1) for k in list(value)[:16]}
                        return '<unsupported value>'
                    self.service.submit(process,{'kind':'companion.error' if message.get('type')=='error' else 'companion.message',
                        'data':{**meta,'message':bounded(message),'binary_bytes_not_retained':len(data or b''),'presentation':'bounded preview; companion output is not a collector protocol event'}})
                script.on('message',on_message)
                script.load()
            self.service.submit(process,{'kind':'coverage.companion','data':{**metadata,'state':'loaded','globals':'isolated_script_context',
                'order':'after_collector_script_load','startup_events_may_be_missed':True,
                'limitations':['Hooking the same target method may still conflict','Script load does not establish asynchronous hook readiness','Messages are bounded previews; binary output is not retained']}})

    def report_companions(self,item,process):
        if item.get('companion_stats_reported'):return
        item['companion_stats_reported']=True
        for stats in item.get('companion_stats',[]):
            self.service.submit(process,{'kind':'coverage.companion_final','data':dict(stats)})

    def connect_device(self,serial):
        import frida
        if self.server_port is None:return frida.get_device(serial,timeout=5)
        # Allocate an owned host port through the already verified device serial.
        # Never connect an arbitrary endpoint while attributing it to another device.
        forwarded=adb(serial,'forward','tcp:0',f'tcp:{self.server_port}')
        if not forwarded.isdigit() or not 1<=int(forwarded)<=65535:
            raise RuntimeError('ADB did not return a valid allocated forwarding port')
        self.forward_port=int(forwarded)
        self.remote_endpoint=f'127.0.0.1:{self.forward_port}'
        return frida.get_device_manager().add_remote_device(self.remote_endpoint)

    def available_devices(self):
        result=subprocess.run(['adb','devices'],capture_output=True,text=True,timeout=10,check=True)
        return [line.split()[0] for line in result.stdout.splitlines()[1:] if len(line.split())==2 and line.split()[1]=='device'
                and (line.split()[0] in ('33011FDH20018E','127.0.0.1:6520') or re.fullmatch(r'emulator-\d+',line.split()[0]))]

    def prepare_watch(self,serial,app):
        """One explicit lab workflow: verified stock server, Android launch, late attach."""
        import frida
        if frida.__version__!='17.18.0':
            raise RuntimeError('The live workflow is pinned to Frida 17.18.0. Run scripts/runtime-code instead.')
        if not re.fullmatch(r'[A-Za-z0-9_.]+',app):raise ValueError('Invalid package identifier')
        info=preflight(serial,require_root=False)
        if not info['root'] and serial.startswith('emulator-'):
            adb(serial,'root')
            subprocess.run(['adb','-s',serial,'wait-for-device'],timeout=10,check=True,capture_output=True)
            info=preflight(serial)
        if not info['root']:raise ValueError('Root adbd is required on the selected lab device')
        abi={'arm64-v8a':'arm64','x86_64':'x86_64'}.get(info['abi'])
        if not abi:raise ValueError('Live server binary unavailable for '+info['abi'])
        bundled=Path(__file__).resolve().parents[2]/'vendor/frida-server'
        server_dir=Path(os.environ['RUNTIME_CODE_SERVER_DIR']) if os.environ.get('RUNTIME_CODE_SERVER_DIR') else bundled if bundled.is_dir() else Path.home()/'tools/frida-server'
        local=server_dir/f'frida-server-17.18.0-android-{abi}'
        if not local.is_file():raise ValueError('Missing verified matching server binary: '+str(local))
        self.server_port=27043
        remote='/data/local/tmp/runtime-code-fsd-17.18.0'
        expected=hashlib.sha256(local.read_bytes()).hexdigest()
        try:actual=adb(serial,'shell','sha256sum',remote).split()[0]
        except subprocess.CalledProcessError:actual=None
        if actual!=expected:
            adb(serial,'push',str(local),remote);adb(serial,'shell','chmod','755',remote)
        # Reuse a matching live endpoint; report conflicts rather than kill another server.
        probe_port=adb(serial,'forward','tcp:0','tcp:27043')
        endpoint='127.0.0.1:'+probe_port;manager=frida.get_device_manager()
        ready=False
        try:
            with frida_deadline('Probing Frida server',3):
                device=manager.add_remote_device(endpoint)
                device.query_system_parameters();ready=True
        except Exception:ready=False
        finally:
            try:
                with frida_deadline('Closing Frida probe',2):manager.remove_remote_device(endpoint)
            except Exception:pass
            adb(serial,'forward','--remove','tcp:'+probe_port)
        if not ready:
            listeners=adb(serial,'shell','ss','-lntp')
            if re.search(r':27043\s',listeners):
                raise RuntimeError('Device port 27043 is occupied but does not answer as the expected Frida server; existing listener was left untouched')
            adb(serial,'shell',f'nohup {remote} -D -l 127.0.0.1:27043 >{remote}.log 2>&1 </dev/null &')
            time.sleep(.3)
        listeners=adb(serial,'shell','ss','-lntp')
        owners=[int(pid) for line in listeners.splitlines() if re.search(r':27043\s',line) for pid in re.findall(r'pid=(\d+)',line)]
        if len(set(owners))!=1 or adb(serial,'shell','sha256sum',f'/proc/{owners[0]}/exe').split()[0]!=expected:
            raise RuntimeError('Cannot verify that device port 27043 belongs to the matching 17.18.0 server binary')
        # Launching through Android avoids unsupported zygote spawn profiles and is
        # explicitly recorded as late attachment by start().
        return launch_app(serial,app)

    def capabilities(self):
        supported=[Capability('dex.input.java',('extract',),('load',),True,
                              'Explicit narrow capture of caller ByteBuffer inputs; no ART coverage'),
                   Capability('native.inventory',('observe',),('attach_and_module_change',),True,
                              'Inventory only; no extraction or pre-constructor claim'),
                   Capability('dex.input.art',('extract',),('load',),True,'Requires exact libdexfile hash, ABI, constructor guard and object validation'),
                   Capability('dex.snapshot.runtime',('snapshot',),('manual','poll','native_function'),True,'Requires dex.input.art token and a validated object-lifetime profile'),
                   Capability('native.input.linker',('extract',),('load',),True,'Requires exact linker hash and validated descriptor/offset boundary'),
                   Capability('jni.trace.selected',('observe',),('call',),True,'Selected standard JNI table calls; caller attribution when instruction and ELF header are verified')]
        for name,reason in (
            ('webview.platform','Android WebView, Activity/Fragment lifecycle and observed JavaScript bridge calls; no universal JS source attribution'),
            ('network.platform','Java URLConnection intents and returned stream metadata; bytes require network.native; no blocking read/write hooks'),
            ('network.native','Exported libc socket I/O and standard SSL_read/SSL_write; encrypted traffic remains encrypted'),
            ('parser.json','org.json field access and constructor inputs; other parsers require explicit method selectors'),
            ('parser.custom','Pack-selected Java methods, including root-package and one-letter names; no automatic arbitrary schema inference'),
            ('flow.java','Bounded app method/constructor calls and weak object identities; field snapshots are not field-read instrumentation'),
            ('crypto.cipher','javax.crypto.Cipher inputs/outputs; exportable key bytes only with capture_keys selection')):
            supported.append(Capability(name,('observe',),('call',),True,reason))
        supported.extend([Capability('reflection.java',('observe',),('call',),True,'Target-side WebView client constructors and reflection frames; no caller-sensitive reflection API replacement'),
                          Capability('crypto.custom',('observe',),('call',),True,'Pack-selected app decoders; bounded string/byte inputs and results; algorithm not guessed')])
        for name in ('dex.input.file','native.snapshot',
                     'mapping.snapshot','change_tracking','jni.trace','webview.flow','crypto.trace','parser.trace'):
            supported.append(Capability(name,(),(),False,'No validated implementation/profile in this release; no automatic fallback'))
        return supported

    def source(self,pack,profile=None,linker_profile=None):
        scoped=[t for t in pack.tokens if t.capability in ('flow.java','parser.custom','crypto.custom')]
        for i,left in enumerate(scoped):
            for right in scoped[i+1:]:
                left_methods={(m['class'],m['method']) for m in left.selection.get('methods',[])}
                right_methods={(m['class'],m['method']) for m in right.selection.get('methods',[])}
                overlap=left_methods&right_methods
                overlap|={(c,m) for c,m in left_methods if c in right.selection.get('classes',[])}
                overlap|={(c,m) for c,m in right_methods if c in left.selection.get('classes',[])}
                if overlap:raise ValueError(f'{left.name}, {right.name}: overlapping method hooks {sorted(overlap)}; select each method in one scoped token')
        jni=json.loads(Path(__file__).with_name('jni_table.json').read_text())['functions']
        source=(Path(__file__).with_name('frida_agent.js')).read_text().replace('__CONFIG__',json.dumps({**pack.json(),'art_profile':profile,'linker_profile':linker_profile,'jni_table':jni}))
        source=source.replace('// TRACE_EXTENSION',Path(__file__).with_name('frida_flows.js').read_text()+'\n'+Path(__file__).with_name('frida_object_flow.js').read_text())
        if any(t.capability in ('dex.input.java','jni.trace.selected','webview.platform','network.platform','parser.json','parser.custom','crypto.cipher','crypto.custom','reflection.java','flow.java') for t in pack.tokens):
            source=self.java_bridge_source()+source
        if ('Mod'+'ule.') in source:
            raise RuntimeError('Forbidden runtime namespace in assembled agent')
        return source

    def java_bridge_source(self,isolated=False):
        import frida_tools
        bridge=(Path(frida_tools.__file__).parent/'bridges/java.js').read_text()
        # The bundled bridge has two legacy global-export resolver calls. Redirect
        # only these reviewed APIs to process-scoped enumeration; refuse other uses.
        namespace='Mod'+'ule.'
        supported={'findGlobalExportByName','getGlobalExportByName'}
        if set(re.findall(re.escape(namespace)+r'(\w+)',bridge))-supported:
            raise RuntimeError('Java bridge contains an unreviewed global resolver API')
        bridge=bridge.replace(namespace,'runtimeExports.')
        shim='''const runtimeExports={
          findGlobalExportByName(name){for(const m of Process.enumerateModules()){const a=m.findExportByName(name);if(a)return a;}return null;},
          getGlobalExportByName(name){const a=this.findGlobalExportByName(name);if(a===null)throw new Error('Missing export: '+name);return a;}
        };'''
        return '(function(){'+shim+bridge+'\nglobalThis.Java=bridge;})();\n' if isolated else shim+bridge+'\nconst Java=bridge;\n'

    def validate_pack_apk(self,pack,app,serial):
        import shlex
        for token in pack.tokens:
            expected=token.selection.get('apk_sha256')
            if not expected:continue
            paths=[line[8:] for line in adb(serial,'shell','pm','path',app).splitlines() if line.startswith('package:')]
            base=[path for path in paths if path.endswith('/base.apk')]
            if len(base)!=1:raise ValueError(f'{token.name}: cannot establish base APK for apk_sha256 validation')
            actual=adb(serial,'shell','sha256sum '+shlex.quote(base[0])).split()[0]
            if actual!=expected:
                raise ValueError(f'{token.name}: APK/pack mismatch: installed {actual}, pack expects {expected}. Install the APK built with this pack, or regenerate the pack from the installed build; no scoped hooks installed.')

    def start(self,service,pack,app,serial,pid=None):
        import frida
        compatibility=host_compatibility(frida.__version__)
        if not re.fullmatch(r'[A-Za-z0-9_.]+',app):
            raise ValueError('Invalid package identifier')
        self.service,self.pack,self.app=service,pack,app
        self.serial=serial
        for token in pack.tokens:
            if token.trigger=='native_function' and not all(token.selection.get(key) for key in ('module','symbol')):
                raise ValueError(f'{token.name}: native_function requires module and symbol selectors')
        device_info=preflight(serial)
        self.validate_pack_apk(pack,app,serial)
        packages=adb(serial,'shell','pm','list','packages','-U',app)
        match=re.search(r'^package:'+re.escape(app)+r' uid:(\d+)$',packages,re.M)
        if not match:raise ValueError('Requested app package/UID is not installed or cannot be established')
        self.uid=int(match.group(1))
        requested=[t for t in pack.tokens if t.capability in ('dex.input.art','dex.snapshot.runtime','jni.trace.selected')]
        profile=None
        if requested:
            candidates=json.loads(Path(__file__).with_name('art_profiles.json').read_text())['profiles']
            profile=select_profile(candidates,device_info,'dexfile',requested)
            if any(t.capability=='dex.snapshot.runtime' for t in requested) and not any(t.capability=='dex.input.art' for t in requested):
                raise ValueError('dex.snapshot.runtime requires an explicit dex.input.art capture token')
            device_info['internal_profiles']['art']=profile['id']
        jni_tokens=[t for t in pack.tokens if t.capability=='jni.trace.selected']
        jni_names={f['name'] for f in json.loads(Path(__file__).with_name('jni_table.json').read_text())['functions']}
        for token in jni_tokens:
            unknown=set(token.selection.get('functions',[]))-jni_names
            if unknown:raise ValueError(f'{token.name}: unknown JNI functions: {sorted(unknown)}')
        linker_tokens=[t for t in pack.tokens if t.capability=='native.input.linker']
        linker_profile=None
        if linker_tokens:
            candidates=json.loads(Path(__file__).with_name('linker_profiles.json').read_text())['profiles']
            linker_profile=select_profile(candidates,device_info,'linker',linker_tokens)
            device_info['internal_profiles']['linker']=linker_profile['id']
        with frida_deadline('Connecting to Frida'):
            self.device=self.connect_device(serial)
            system=self.device.query_system_parameters()
        if system.get('access')=='jailed':
            raise RuntimeError('Full Frida server access unavailable. Start the matching rooted frida-server; APK/Gadget modification is not used.')
        device_info['frida']=frida.__version__
        device_info['frida_compatibility']=compatibility
        device_info['frida_transport']={'kind':'adb_forward' if self.server_port else 'device_default',
                                        'device_server_port':self.server_port}
        device_info['system']=system
        self.code=self.source(pack,profile,linker_profile)
        service.store.observe(service.run,None,'coverage.device',device_info)
        service.store.observe(service.run,None,'coverage.policy',{'secondary_processes':'late_attach_polling_1s',
            'startup_gap':'Secondary process startup is not gated in this release',
            'source_sha256':hashlib.sha256(self.code.encode()).hexdigest(),
            'exclusions':{t.name:t.selection for t in pack.tokens},'limits':asdict(pack.limits)})
        spawned=False
        if pid is None:
            pid=self.device.spawn([app]);spawned=True
        try:
            self.attach(pid,app,'spawned_suspended' if spawned else 'late_attached')
        finally:
            if spawned:self.device.resume(pid)
        self.poller=threading.Thread(target=self.poll,daemon=True);self.poller.start()

    def attach(self,pid,name,mode):
        with self.lock:
            if any(item['pid']==pid for item in self.sessions.values()):return
            status=adb(self.serial,'shell','cat',f'/proc/{int(pid)}/status')
            uid=re.search(r'^Uid:\s+(\d+)',status,re.M)
            if not uid or int(uid.group(1))!=self.uid:
                raise ValueError('Process UID does not match requested app; isolated/shared-process ownership needs separate support')
            process=self.service.process(pid,name,{'mode':mode,'startup_events_may_be_missed':True,
                'app_uid':self.uid,'scope':'explicitly negotiated tokens','process_identity':'host UUID per attachment'})
            with frida_deadline(f'Attaching to {name} (PID {pid})'):
                session=self.device.attach(pid)
            self.sessions[process]={'pid':pid,'session':session,'script':None}
            with frida_deadline('Creating instrumentation script'):
                script=session.create_script(self.code)
            self.sessions[process]={'pid':pid,'session':session,'script':script}
            def message(message,data):
                if message.get('type')=='send':self.service.submit(process,message['payload'],data)
                elif message.get('type')=='error':self.service.submit(process,{'kind':'instrumentation.failure','data':message})
            script.on('message',message)
            def detached(reason,*args):
                self.service.submit(process,{'kind':'lifecycle.detached','data':{'reason':reason}})
                with self.lock:
                    item=self.sessions.pop(process,None)
                    if item:self.report_companions(item,process)
            session.on('detached',detached)
            with frida_deadline('Loading instrumentation script',15):script.load()
            self.load_companions(session,self.sessions[process],process)

    def poll(self):
        while not self.poll_stop.wait(1):
            try:
                for process in self.device.enumerate_processes():
                    if process.name==self.app or process.name.startswith(self.app+':'):
                        self.attach(process.pid,process.name,'late_attached_secondary_or_restart')
            except Exception as error:
                self.service.submit(None,{'kind':'coverage.gap','data':{'reason':'process_inventory_failed','error':str(error)}})
                self.poll_stop.wait(3)

    def acknowledge(self,process,transfer):
        with self.lock:item=self.sessions.get(process)
        if item:
            self.bounded_rpc(item,'acknowledge',transfer)

    def static_input_files(self,directory):
        """Copy package-manager code paths for core static indexing; never patch APKs."""
        import shlex
        paths=[line[8:] for line in adb(self.serial,'shell','pm','path',self.app).splitlines() if line.startswith('package:')]
        included=[p for p in paths if not Path(p).name.startswith('split_config.')]
        self.service.store.observe(self.service.run,None,'coverage.static_input',{'source':'package_manager_paths',
            'included':included,'excluded_configuration_splits':[p for p in paths if p not in included],
            'limits':{'files':16,'bytes':128*1024**2},'limitations':['Configuration split filenames excluded; supply a split ZIP with --code to inspect them','Installed-file copy is not proof of memory identity or runtime execution']})
        if len(included)>16:raise ValueError('Installed code file count exceeds 16; supply selected files with --code')
        total=0
        for index,path in enumerate(included):
            if not path.startswith('/') or '\x00' in path:raise ValueError('Invalid package code path')
            size=int(adb(self.serial,'shell','stat','-c','%s',shlex.quote(path)));total+=size
            if size<0 or total>128*1024**2:raise ValueError('Installed APK copy exceeds 128 MiB static budget; use selected DEX files')
            target=Path(directory)/(str(index)+'.apk')
            subprocess.run(['adb','-s',self.serial,'pull',path,str(target)],capture_output=True,text=True,check=True,timeout=30)
            if target.stat().st_size!=size:raise ValueError('APK changed size during copy')
            yield target,{'source_kind':'installed_apk_copy','device':self.serial,'package':self.app,'device_path':path}

    def bounded_rpc(self,item,method,*args,timeout=2):
        # The 17.18 Python RPC condition wait ignores Cancellable. Keep waiting
        # threads bounded even if the target cannot answer or tear down normally.
        if not self.rpc_slots.acquire(blocking=False):raise TimeoutError('Frida RPC pending-call budget exhausted')
        done=threading.Event();outcome=[]
        def invoke():
            try:outcome.append((True,getattr(item['script'].exports_sync,method)(*args)))
            except Exception as error:outcome.append((False,error))
            finally:self.rpc_slots.release();done.set()
        threading.Thread(target=invoke,daemon=True,name='runtime-rpc-'+method).start()
        if not done.wait(timeout):raise TimeoutError(f'Frida RPC {method} exceeded {timeout}s; target completion is unknown')
        success,result=outcome[0]
        if not success:raise result
        return result

    def snapshot(self,process,target):
        with self.lock:item=self.sessions.get(process)
        if not item:raise ValueError('Snapshot unavailable: process is disconnected')
        return self.bounded_rpc(item,'snapshot',target)

    def stop(self):
        import frida
        self.poll_stop.set()
        if self.poller:self.poller.join(timeout=3)
        with self.lock:items=list(self.sessions.items())
        for process,item in items:
            self.report_companions(item,process)
            try:
                if item['script'] is not None:
                    stats=self.bounded_rpc(item,'stop')
                    self.service.store.observe(self.service.run,process,'coverage.agent_final',stats)
            except Exception as error:
                self.service.submit(process,{'kind':'coverage.gap','data':{'reason':'bounded_detach','error':str(error)}})
            try:
                with frida.Cancellable() as cancel:
                    timer=threading.Timer(2,cancel.cancel);timer.start()
                    try:item['session'].detach()
                    finally:timer.cancel()
            except Exception:pass
        if self.remote_endpoint:
            try:
                with frida_deadline('Closing Frida connection',2):frida.get_device_manager().remove_remote_device(self.remote_endpoint)
            except Exception:pass
            self.remote_endpoint=None
        if self.forward_port is not None:
            try:adb(self.serial,'forward','--remove',f'tcp:{self.forward_port}')
            except Exception as error:
                self.service.submit(None,{'kind':'coverage.gap','data':{'reason':'forward_cleanup_failed','error':str(error)}})
            self.forward_port=None


register('frida',FridaBackend)
