"""Bounded, saved ADB logcat independent of Frida's event loop."""
from collections import deque
import json
from pathlib import Path
import re
import subprocess
import threading

LINE=re.compile(r'^(\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEFA])\s+([^:]+):\s?(.*)$')
MAX_BYTES=8*1024**2


def parse_line(text,sequence,pids=(),app=''):
    text=text.rstrip('\r\n')[:8192];match=LINE.match(text)
    if not match:return {'sequence':sequence,'level':'I','tag':'logcat','message':text,'app':False,'package_classes':[]}
    stamp,pid,tid,level,tag,message=match.groups();owned=int(pid) in pids
    return {'sequence':sequence,'time':stamp,'pid':int(pid),'tid':int(tid),'level':level,
            'tag':tag.strip(),'message':message,'app':owned,'package_classes':[app] if owned else []}


class LogcatCapture:
    def __init__(self,adb,serial,root,run,app,pids):
        self.command=[adb,'-s',serial,'logcat','-v','threadtime','-T','1']
        self.path=Path(root)/'logcat'/(run+'.jsonl');self.path.parent.mkdir(parents=True,exist_ok=True)
        self.status=self.path.with_suffix('.status.json');self.app=app;self.pids=pids
        self.process=None;self.thread=None;self.stop_event=threading.Event();self.sequence=0

    def state(self,state,**data):
        temp=self.status.with_suffix('.tmp');temp.write_text(json.dumps({'state':state,**data}));temp.replace(self.status)

    def start(self):
        self.process=subprocess.Popen(self.command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',bufsize=1)
        self.state('running');self.thread=threading.Thread(target=self._read,name='runtime-logcat',daemon=True);self.thread.start();return self

    def _read(self):
        recent=deque();recent_bytes=0;size=0
        try:
            with self.path.open('w',encoding='utf-8') as stream:
                for line in self.process.stdout:
                    if self.stop_event.is_set():break
                    self.sequence+=1
                    row=parse_line(line,self.sequence,self.pids(),self.app)
                    raw=json.dumps(row,ensure_ascii=False)+'\n';recent.append(raw);recent_bytes+=len(raw.encode())
                    while len(recent)>2000 or recent_bytes>1024**2:recent_bytes-=len(recent.popleft().encode())
                    stream.write(raw);stream.flush();size+=len(raw.encode())
                    if size>=MAX_BYTES:
                        stream.seek(0);stream.truncate();stream.writelines(recent);stream.flush()
                        size=sum(len(x.encode()) for x in recent)
            self.state('stopped' if self.stop_event.is_set() else 'disconnected',exit_code=self.process.poll())
        except Exception as error:self.state('failed',reason=str(error))

    def close(self):
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=2)
        if self.thread:self.thread.join(timeout=2)


def read_logcat(service,run,after=0):
    service.store.one('SELECT id FROM runs WHERE id=?',(run,))
    if type(after) is not int or after<0:raise ValueError('Invalid logcat cursor')
    path=service.store.root/'logcat'/(run+'.jsonl');rows=[]
    status={'state':'unavailable','reason':'No logcat was collected for this Run'}
    failures=service.store.rows("SELECT data FROM observations WHERE run_id=? AND kind='coverage.logcat' ORDER BY sequence DESC LIMIT 1",(run,))
    if failures:status=json.loads(failures[0]['data'])
    if path.with_suffix('.status.json').exists():
        try:status=json.loads(path.with_suffix('.status.json').read_text())
        except (ValueError,OSError):pass
    if path.exists():
        with path.open('rb') as stream:
            stream.seek(0,2);length=stream.tell();stream.seek(max(0,length-2*1024**2))
            if length>2*1024**2:stream.readline()
            for raw in stream:
                try:row=json.loads(raw)
                except (ValueError,UnicodeDecodeError):continue  # A live writer may have an incomplete last line.
                if row['sequence']>after:rows.append(row)
    rows=rows[-2000:]
    return {'rows':rows,'status':status,'last':rows[-1]['sequence'] if rows else after,
            'limits':{'retained_bytes':MAX_BYTES,'page_rows':2000},
            'gap':bool(rows and rows[0]['sequence']>after+1)}
