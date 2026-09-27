"""One collector per app/device across stores; independent of instrumentation backend."""
import fcntl
import hashlib
import json
import os
from pathlib import Path


def legacy_collectors(app,device,proc=Path('/proc')):
    matches=[]
    def option(args,name):
        for i,value in enumerate(args):
            if value==name and i+1<len(args):return args[i+1]
            if value.startswith(name+'='):return value.split('=',1)[1]
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name)==os.getpid():continue
        try:
            if entry.stat().st_uid!=os.getuid():continue
            args=(entry/'cmdline').read_bytes().decode(errors='replace').split('\0')
            if not any(args[i:i+2]==['-m','runtime_code'] for i in range(len(args)-1)):continue
            if not any(c in args for c in ('watch','capture')):continue
            if option(args,'--app')==app and option(args,'--device')==device:matches.append(int(entry.name))
        except (OSError,ValueError):continue
    return matches


class TargetLease:
    def __init__(self,app,device,root=None):
        root=Path(root) if root else Path.home()/'.cache/apk-defense/collectors'
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        digest=hashlib.sha256(json.dumps([app,device]).encode()).hexdigest()
        self.file=(root/(digest+'.lock')).open('a+')
        try:
            try:fcntl.flock(self.file,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError(f'A collector already owns {app} on {device}; stop that collector before starting another')
            older=legacy_collectors(app,device)
            if older:raise ValueError(f'Existing collector PID(s) {older} already watch {app} on {device}; stop that collector before starting another')
            self.file.seek(0);self.file.truncate();self.file.write(str(os.getpid()));self.file.flush()
        except Exception:
            self.close();raise
    def close(self):
        if not self.file.closed:self.file.close()
