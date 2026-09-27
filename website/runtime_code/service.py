"""Shared lifecycle, observations, artifact transport, and analysis command surface."""
from dataclasses import asdict
import json
import queue
import threading
import time

from .analysis import HANDLERS, analyze, export_variants, analysis_copy
from .model import negotiate
from .store import identity,encoded


class Service:
    def __init__(self, store):
        self.store = store
        self.backend = None
        self.run = None
        self.queue = None
        self.worker = None
        self.controller = None
        self.lease = None
        self.stopping = threading.Event()
        self.loss_lock = threading.Lock()
        self.loss = {'observations_dropped':0,'binary_bytes_dropped':0,'messages_dropped':0}
        self.count = 0
        self.target_lease = None

    def reserve(self,app,device):
        if self.target_lease is None:
            from .target_lease import TargetLease
            self.target_lease=TargetLease(app,device)

    def release_target(self):
        if self.target_lease is not None:
            self.target_lease.close();self.target_lease=None

    def start(self, backend, pack, app, device, pid=None):
        coverage = negotiate(pack, backend.capabilities(), HANDLERS)
        self.reserve(app,device)
        self.pack, self.backend = pack, backend
        self.run = self.store.create_run(app, device, pack, {'requested':coverage,'backend_capabilities':[asdict(c) for c in backend.capabilities()]})
        self.lease = self.store.lease(self.run)
        self.queue = queue.Queue(maxsize=pack.limits.queue_depth)
        self.worker = threading.Thread(target=self._consume, daemon=True)
        self.worker.start()
        try:
            backend.start(self, pack, app, device, pid)
            self.store.state('runs', self.run, 'running')
            self.controller=threading.Thread(target=self._commands,daemon=True);self.controller.start()
        except (Exception,KeyboardInterrupt) as error:
            self.store.observe(self.run, None, 'lifecycle.failure', {'error':str(error)})
            self.stop('failed')
            raise
        return self.run

    def request_snapshot(self,run,process,target):
        row=self.store.one('SELECT state FROM runs WHERE id=?',(run,))
        if row['state']!='running':raise ValueError('Snapshot unavailable: Run is not active')
        if self.store.one('SELECT run_id FROM processes WHERE id=?',(process,))['run_id']!=run:
            raise ValueError('Process belongs to a different Run')
        command=identity()
        with self.store.lock,self.store.db:
            count=self.store.db.execute("SELECT COUNT(*) FROM commands WHERE run_id=? AND state='pending'",(run,)).fetchone()[0]
            if count>=16:raise ValueError('Snapshot request queue is full')
            self.store.db.execute('INSERT INTO commands VALUES(?,?,?,?,?,?)',
                (command,run,time.time_ns(),'pending',encoded({'process':process,'target':target}),'{}'))
        return {'command':command,'state':'pending','capture':'not_yet_observed'}

    def _commands(self):
        while not self.stopping.wait(.2):
            for row in self.store.rows("SELECT * FROM commands WHERE run_id=? AND state='pending'",(self.run,)):
                try:
                    if time.time_ns()-row['created_ns']>10*10**9:raise ValueError('Snapshot request expired')
                    args=json.loads(row['request']);result=self.snapshot(args['process'],args['target']);state='complete'
                except Exception as error:result={'error':str(error)};state='failed'
                with self.store.lock,self.store.db:
                    self.store.db.execute('UPDATE commands SET state=?,result=? WHERE id=?',(state,encoded(result),row['id']))
                self.store.observe(self.run,None,'command.result',{'command':row['id'],'state':state,'result':result})

    def process(self,pid,name,coverage):
        return self.store.add_process(self.run,pid,name,coverage)

    def submit(self,process,event,data=None):
        """Adapter callbacks never wait for handlers, UI, or persistence."""
        try:
            self.queue.put_nowait((process,event,data))
        except queue.Full:
            with self.loss_lock:
                self.loss['messages_dropped']+=1
                self.loss['binary_bytes_dropped']+=len(data or b'')
                self.loss['observations_dropped']+=int(data is None)

    def _consume(self):
        while not self.stopping.is_set() or not self.queue.empty():
            try:
                process,event,data=self.queue.get(timeout=.2)
            except queue.Empty:
                self.store.expire(self.run)
                continue
            try:
                kind=event.get('kind')
                payload=event.get('data',{})
                sequence=event.get('sequence')
                if kind=='transfer.chunk':
                    self.store.chunk(process,payload['transfer'],payload['offset'],data)
                elif kind=='capture.begin':
                    self.store.begin(self.run,process,payload,sequence)
                elif kind=='capture.end':
                    snapshot=self.store.finish(process,payload['transfer'])
                    try:self.backend.acknowledge(process,payload['transfer'])
                    except Exception as error:
                        self.store.observe(self.run,process,'transfer.ack_unavailable',{'snapshot':snapshot,'reason':str(error),
                                           'integrity':'host publication already verified'})
                    # Analysis is outside the hook; exact snapshot ID is immutable.
                    row=self.store.one('SELECT * FROM snapshots WHERE id=?',(snapshot,))
                    if row['status']=='captured':
                        self._relate_input(row)
                        token=next(t for t in self.pack.tokens if t.name==row['token'])
                        for handler in token.handlers:
                            analyze(self.store,snapshot,handler)
                else:
                    if kind=='jni.call':self._associate_caller(process,payload)
                    if 'java_caller' in payload:self._associate_java(process,payload['java_caller'])
                    if 'caller' in payload and isinstance(payload['caller'],list):self._associate_java(process,payload['caller'])
                    if self.count >= self.pack.limits.events and kind not in ('coverage','loss','lifecycle.detached'):
                        with self.loss_lock:self.loss['observations_dropped']+=1
                    else:
                        self.store.observe(self.run,process,str(kind),payload,sequence)
                        self.count+=1
                        if kind=='instrumentation.ready':
                            self.store.state('processes',process,'active')
                        elif kind=='instrumentation.failure':
                            self.store.state('processes',process,'failed')
                        elif kind=='lifecycle.detached':
                            self.store.state('processes',process,'disconnected',True)
            except Exception as error:
                self.store.observe(self.run,process,'capture.failure',{'error':str(error),'event_kind':event.get('kind'),
                                       'transfer':event.get('data',{}).get('transfer')})
            finally:
                self.queue.task_done()

    def _associate_caller(self,process,payload):
        caller=payload.get('native_caller',{})
        if not caller.get('build_id') or not caller.get('module_path'):return
        candidates=self.store.rows("SELECT snapshots.id,snapshots.metadata,analyses.result FROM snapshots JOIN analyses ON analyses.snapshot_id=snapshots.id WHERE snapshots.process_id=? AND snapshots.kind='elf_input' AND snapshots.status='captured' AND analyses.handler='structure' AND analyses.state='complete'",(process,))
        matches=[]
        for row in candidates:
            metadata,result=json.loads(row['metadata']),json.loads(row['result'])
            if metadata.get('source_label')==caller['module_path'] and result.get('build_id')==caller['build_id']:
                matches.append(row['id'])
        if len(matches)==1:
            caller['artifact_snapshot']=matches[0]
            caller['artifact_link_status']='inferred_matching_path_and_build_id'

    def _relate_input(self,row):
        if row['kind'] not in ('dex_input','dex_art_input'):return
        correlation=json.loads(row['metadata']).get('correlation')
        if not correlation:return
        candidates=self.store.rows("SELECT * FROM snapshots WHERE process_id=? AND hash=? AND status='captured' AND kind IN ('dex_input','dex_art_input')",
                                    (row['process_id'],row['hash']))
        candidates=[s for s in candidates if json.loads(s['metadata']).get('correlation')==correlation]
        inputs=[s for s in candidates if s['kind']=='dex_input'];backings=[s for s in candidates if s['kind']=='dex_art_input']
        if len(inputs)!=1 or len(backings)!=1:return
        with self.store.lock,self.store.db:
            self.store.db.execute('INSERT OR IGNORE INTO relationships VALUES(?,?,?,?,?,?,?)',
                (identity(),row['run_id'],inputs[0]['id'],backings[0]['id'],'candidate_input_to_art_backing',
                 'Inferred from identical captured bytes and the same nested load correlation',row['observation_id']))

    def _associate_java(self,process,frames):
        candidates=self.store.rows("SELECT snapshots.id,snapshots.metadata,analyses.result FROM snapshots JOIN analyses ON analyses.snapshot_id=snapshots.id WHERE snapshots.process_id=? AND snapshots.kind='dex_art_input' AND snapshots.status='captured' AND analyses.handler='structure' AND analyses.state='complete'",(process,))
        for frame in frames:
            signature=frame.get('signature','').split(',')
            if len(signature)!=3:continue
            method=signature[0]+'->'+signature[1]+signature[2]
            matches=[]
            for row in candidates:
                metadata,result=json.loads(row['metadata']),json.loads(row['result'])
                if metadata.get('source_path')==frame.get('origin') and method in {m['identity'] for m in result.get('methods',[])}:
                    matches.append(row['id'])
            if len(matches)==1:
                frame.update(artifact=matches[0],method_identity=method,attribution='inferred_origin_path_and_method_identity')

    def stop(self,state='ended'):
        if not self.run:return
        if self.backend:
            try:self.backend.stop()
            except Exception as error:self.store.observe(self.run,None,'shutdown.failure',{'error':str(error)})
        self.stopping.set()
        if self.controller:self.controller.join(timeout=3)
        if self.worker:self.worker.join(timeout=20)
        if self.worker and self.worker.is_alive():
            self.store.observe(self.run,None,'coverage.gap',{'reason':'host_shutdown_deadline_exceeded'})
            self.store.state('runs',self.run,'disconnected',True)
            self.release_target()
            return
        self.store.expire(self.run,'run_ended_before_transfer_completed')
        with self.store.lock,self.store.db:
            self.store.db.execute("UPDATE commands SET state='failed',result=? WHERE run_id=? AND state='pending'",
                                  (encoded({'error':'Run ended before request execution'}),self.run))
        with self.loss_lock:
            self.store.observe(self.run,None,'coverage.loss',self.loss)
        for p in self.store.rows("SELECT id FROM processes WHERE run_id=? AND ended_ns IS NULL",(self.run,)):
            self.store.state('processes',p['id'],'detached',True)
        self.store.state('runs',self.run,state,True)
        if self.lease:self.lease.close();self.lease=None
        self.release_target()

    def snapshot(self,process,target):
        if not self.backend or self.stopping.is_set():
            raise ValueError('Snapshot unavailable: no live instrumentation for this service')
        return self.backend.snapshot(process,target)

    def inventory(self,run):
        from .search_filters import classes
        rows=self.store.rows('SELECT * FROM snapshots WHERE run_id=? ORDER BY time_ns',(run,))
        outcomes={}
        analyses={}
        source_classes={}
        for event in self.store.rows("SELECT process_id,data FROM observations WHERE run_id=? AND json_extract(data,'$.id') IS NOT NULL ORDER BY sequence DESC LIMIT 10000",(run,)):
            data=json.loads(event['data'])
            source_classes.setdefault((event['process_id'],data.get('id')),classes({'data':data}))
        for analysis in self.store.rows('SELECT id,snapshot_id,handler,state FROM analyses WHERE snapshot_id IN (SELECT id FROM snapshots WHERE run_id=?)',(run,)):
            analyses.setdefault(analysis['snapshot_id'],[]).append(analysis)
        for event in self.store.rows("SELECT process_id,data FROM observations WHERE run_id=? AND kind='load.outcome' ORDER BY sequence",(run,)):
            data=json.loads(event['data']);outcomes[(event['process_id'],data.get('correlation'))]=data.get('outcome')
        for row in rows:
            metadata=json.loads(row['metadata'])
            outcome=outcomes.get((row['process_id'],metadata.get('correlation')))
            row['dynamic_load']={'dynamically_loaded':True if outcome=='returned' else None,
                                 'state':'observed_loader_return' if outcome=='returned' else 'load_failed' if outcome=='threw' else 'not_established',
                                 'execution':'not_established'}
            if row['kind']=='static_dex':row['dynamic_load']['state']='static_code_input'
            row['analyses']=analyses.get(row['id'],[])
            row['package_classes']=classes(row) or source_classes.get((row['process_id'],metadata.get('correlation')),[])
        return rows

    def download(self,run,snapshot,bundle=True):
        """Integrity-checked bytes plus provenance, shared by every frontend."""
        import io,zipfile
        row=self.store.one('SELECT run_id FROM snapshots WHERE id=?',(snapshot,))
        if row['run_id']!=run:raise ValueError('Artifact belongs to another Run')
        row,data=self.store.read(snapshot)
        inventory=next(r for r in self.inventory(run) if r['id']==snapshot)
        extension='.bin'
        if row['status']=='captured':
            from .analysis import structure
            validity=structure(data,{})
            if validity.get('format')=='dex' and validity.get('validity')=='structurally_inspected':extension='.dex'
            elif validity.get('format')=='elf' and validity.get('validity')=='structurally_inspected' and row['kind']=='elf_input':extension='.elf'
        if not bundle:return 'capture-'+snapshot+extension,data
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_STORED) as archive:
            archive.writestr('artifact'+extension,data)
            archive.writestr('manifest.json',json.dumps(inventory,indent=2))
        return 'capture-'+snapshot+'.zip',stream.getvalue()

    def timeline(self,run,after=0,limit=500):
        if not 1<=limit<=1000:raise ValueError('Timeline page limit is 1..1000')
        return [self.present_event(row) for row in self.store.rows('SELECT * FROM observations WHERE run_id=? AND sequence>? ORDER BY sequence LIMIT ?',
                               (run,after,limit))]

    def present_event(self,row):
        from .evidence import callers,network_summary,navigation,crypto_values
        from .search_filters import classes
        data=navigation(json.loads(row['data']));result={**row,'data':json.dumps(data)}
        result['package_classes']=classes(result)
        frames=callers(data)
        result['summary']={'caller':frames['primary_app_caller'],'called_by':frames['primary_app_caller_next_distinct']}
        if row['kind'].startswith('crypto.'):
            result['summary']['values']=crypto_values(self.store,row,512)
        if row['kind'].startswith('network.') or data.get('network_category'):
            raw=None;digest=data.get('payload',{}).get('sha256')
            if digest:
                candidates=self.store.rows("SELECT id FROM snapshots WHERE run_id=? AND process_id IS ? AND hash=? AND status='captured' LIMIT 1",(row['run_id'],row['process_id'],digest))
                if candidates:
                    try:_,raw=self.store.read(candidates[0]['id'])
                    except (OSError,ValueError):pass
            result['summary']['network']=network_summary(data,raw)
        return result

    def findings(self,run):
        """Analyst findings plus observational string mappings; no automatic severity."""
        from .evidence import crypto_values
        from .search_filters import classes
        rows=self.store.rows('SELECT findings.*,snapshots.time_ns,snapshots.process_id,snapshots.metadata FROM findings JOIN snapshots ON findings.snapshot_id=snapshots.id WHERE snapshots.run_id=?',(run,))
        for row in rows:row['package_classes']=classes(row)
        observations=self.store.rows("SELECT * FROM observations WHERE run_id=? AND kind IN ('crypto.doFinal','crypto.update','crypto.custom','crypto.base64') ORDER BY sequence DESC LIMIT 1000",(run,))
        for observation in observations:
            data=json.loads(observation['data'])
            if data.get('outcome')=='threw':continue
            values=crypto_values(self.store,observation,8192)
            output=values['output']
            if not output.get('utf8') or not output.get('snapshot'):continue
            # A custom transformation's semantic roles remain unverified.
            decrypt=data.get('mode')==2
            mapping={'encrypted' if decrypt else 'input':values['input'],
                     'decrypted' if decrypt else 'output':output}
            row=self.present_event(observation)
            row.update(finding={'type':'observed_string_transformation','assessment':'observed',
                'mapping':mapping,'semantic_basis':'Cipher decrypt mode' if decrypt else data.get('semantic_basis','Observed transformation; encryption semantics unverified')},
                snapshot_id=output['snapshot'])
            rows.append(row)
        # Statically recovered strings remain explicitly distinct from execution.
        analyses=self.store.rows("SELECT a.id,a.snapshot_id,a.result,s.time_ns,s.process_id FROM analyses a JOIN snapshots s ON a.snapshot_id=s.id WHERE s.run_id=? AND a.handler='code.references' AND a.state='complete' ORDER BY a.started_ns DESC LIMIT 64",(run,))
        budget=0
        for analysis in analyses:
            budget+=len(analysis['result'])
            if budget>32*1024**2:break
            for index,site in enumerate(json.loads(analysis['result']).get('sites',[])):
                if site.get('kind')!='decoded_string':continue
                row={'id':analysis['id']+':'+str(index),'kind':'decoded_string','snapshot_id':analysis['snapshot_id'],
                     'time_ns':analysis['time_ns'],'process_id':analysis['process_id'],'data':site,
                     'finding':{'type':'statically_decoded_string','assessment':'observed_static_analysis',
                                'mapping':{'encrypted':{'status':'not_retained_by_static_handler'},'decrypted':{'utf8':site.get('value')}},
                                'execution':'not_established'}}
                row['package_classes']=classes(row);rows.append(row)
                if len(rows)>=2000:return rows
        return rows

    def workspace_checkpoint(self,run):
        self.store.one('SELECT id FROM runs WHERE id=?',(run,))
        rows=self.store.rows('SELECT sequence,time_ns FROM workspace_checkpoints WHERE run_id=?',(run,))
        return rows[0] if rows else {'sequence':0,'time_ns':0}

    def clear_workspace(self,run):
        """Start a new display window without corrupting live transfers or provenance."""
        with self.store.lock,self.store.db:
            self.store.one('SELECT id FROM runs WHERE id=?',(run,))
            sequence=self.store.one('SELECT COALESCE(MAX(sequence),0) AS sequence FROM observations WHERE run_id=?',(run,))['sequence']
            self.store.db.execute('INSERT OR REPLACE INTO workspace_checkpoints VALUES(?,?,?)',(run,sequence,time.time_ns()))
        return {**self.workspace_checkpoint(run),'saved_evidence':'preserved','capture':'continues'}

    def evidence(self,run,observation):
        from .evidence import detail
        return detail(self,run,observation)

    def index_code(self,run,path,source=None):
        from .code_index import import_code
        return import_code(self,run,path,source)

    def search_code(self,run,query='',include='',exclude=''):
        from .code_index import search
        return search(self,run,query,include=include,exclude=exclude)

    def code_scope(self,run,snapshot,method,decoder=False):
        from .code_index import scope_pack
        return scope_pack(self,run,snapshot,method,decoder)

    def flow_scope(self,run,observation,scope_class=None):
        """Create reviewable pack data for the next Run; never mutate active hooks."""
        from .model import Pack
        from .evidence import callers,object_paths
        row=self.store.one('SELECT data FROM observations WHERE run_id=? AND id=?',(run,observation))
        data=json.loads(row['data']);frames=callers(data)['app_callers']
        if data.get('request') and data.get('trace_enabled') is False:frames=[data['request']]
        raw=json.loads(self.store.one('SELECT pack FROM runs WHERE id=?',(run,))['pack'])
        token=next((t for t in raw['tokens'] if t['capability']=='flow.java'),None)
        if token is None:
            names={t['name'] for t in raw['tokens']};name='selected-app-flow'
            while name in names:name+='x'
            token={'name':name,'capability':'flow.java','mode':'observe','trigger':'call','selection':{},'handlers':[]};raw['tokens'].append(token)
        selection=token.setdefault('selection',{});selection['discover_from_stacks']=True
        if scope_class:
            observed={f.get('class') for f in frames}|{v.get('class') for v in object_paths(data)}
            if scope_class not in observed:raise ValueError('Class was not observed in this record')
            classes=selection.setdefault('classes',[])
            if scope_class not in classes:classes.append(scope_class)
        else:
            methods=selection.setdefault('methods',[]);added=[]
            for frame in frames:
                method={'class':frame.get('class'),'method':'$init' if frame.get('method')=='<init>' else frame.get('method')}
                if method not in methods:methods.append(method)
                if method not in added:added.append(method)
                if len(added)==2:break
            if not added:raise ValueError('No app method was observed; select an attributed event or candidate')
        raw['id']=raw['id'][:82]+'.selected-flow'
        return Pack.parse(raw).json()

    def coverage(self,run):
        return {'run':self.store.one('SELECT * FROM runs WHERE id=?',(run,)),
                'processes':self.store.rows('SELECT * FROM processes WHERE run_id=?',(run,)),
                'events':self.store.rows("SELECT * FROM observations WHERE run_id=? AND (kind LIKE 'coverage%' OR kind IN ('loss','instrumentation.ready','instrumentation.failure','lifecycle.failure')) ORDER BY sequence",(run,))}

    def relationships(self,run):return self.store.rows('SELECT * FROM relationships WHERE run_id=?',(run,))

    def analyze(self,snapshot,handler='structure'):return analyze(self.store,snapshot,handler)
    def export(self,snapshot,directory):return self.store.export(snapshot,directory)
    def variants(self,snapshots,directory):return export_variants(self.store,snapshots,directory)
    def analysis_copy(self,snapshot,directory):return analysis_copy(self.store,snapshot,directory)

    def export_trace(self,run,kinds,directory):
        from pathlib import Path
        from .store import export_directory
        # A generic observation export serves all trace views; no frontend-only state.
        with export_directory(directory) as dest:
            with (dest/'observations.jsonl').open('w') as stream:
                after=0
                while True:
                    page=self.timeline(run,after,1000)
                    if not page:break
                    for event in page:
                        if not kinds or any(event['kind'].startswith(k) for k in kinds):
                            stream.write(json.dumps(event)+'\n')
                    after=page[-1]['sequence']
            (dest/'coverage.json').write_text(json.dumps(self.coverage(run),indent=2)+'\n')
        return str(Path(directory).absolute())
