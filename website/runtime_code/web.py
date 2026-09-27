"""Local desktop browser workspace using exactly the same service as the terminal."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit,parse_qs


def open_workspace(server):
    """Browser launch must not hold up capture or require a desktop session."""
    def open_browser():
        import webbrowser
        try:
            if not webbrowser.open(server.workspace_url):
                print(json.dumps({'browser':'unavailable','hint':'Open the printed workspace URL manually'}),flush=True)
        except Exception as error:
            print(json.dumps({'browser':'unavailable','error':str(error)}),flush=True)
    threading.Thread(target=open_browser,daemon=True,name='workspace-browser').start()


def serve(service,run,port=8765,background=False):
    service.store.one('SELECT id FROM runs WHERE id=?',(run,))
    token=secrets.token_urlsafe(24)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,status,data,kind='application/json',filename=None):
            raw=json.dumps(data).encode() if kind=='application/json' else data
            self.send_response(status);self.send_header('Content-Type',kind)
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            if filename:self.send_header('Content-Disposition',f'attachment; filename="{filename}"')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            path=urlsplit(self.path)
            if path.path=='/':
                self.reply(200,Path(__file__).with_name('workspace.html').read_bytes(),'text/html; charset=utf-8');return
            if path.path=='/workspace.js':
                self.reply(200,Path(__file__).with_name('workspace.js').read_bytes(),'text/javascript; charset=utf-8');return
            if self.headers.get('Authorization')!='Bearer '+token:
                self.reply(403,{'error':'Local workspace token required'});return
            try:
                if path.path=='/api/evidence':
                    self.reply(200,service.evidence(run,parse_qs(path.query).get('observation',[''])[0]));return
                if path.path=='/api/code':
                    from .code_index import search
                    query=parse_qs(path.query)
                    self.reply(200,search(service,run,query.get('q',[''])[0],since_ns=int(query.get('since_ns',['0'])[0]),include=query.get('include',[''])[0],exclude=query.get('exclude',[''])[0]));return
                if path.path=='/api/download':
                    query=parse_qs(path.query);format=query.get('format',['bundle'])[0]
                    if format not in ('bundle','raw'):raise ValueError('Unknown download format')
                    name,raw=service.download(run,query.get('snapshot',[''])[0],bundle=format=='bundle')
                    self.reply(200,raw,'application/zip' if format=='bundle' else 'application/octet-stream',name);return
                if path.path=='/api/state':
                    result={'coverage':service.coverage(run),'inventory':service.inventory(run),
                            'checkpoint':service.workspace_checkpoint(run),
                            'relationships':service.relationships(run),
                            'timeline':service.timeline(run,int(parse_qs(path.query).get('after',['0'])[0])),
                            'findings':service.findings(run),
                            'updates':[service.present_event(row) for row in service.store.rows("SELECT * FROM observations WHERE run_id=? AND kind LIKE 'crypto.%' ORDER BY sequence DESC LIMIT 200",(run,))]}
                    result['commands']=service.store.rows('SELECT * FROM commands WHERE run_id=? ORDER BY created_ns DESC LIMIT 30',(run,))
                else:raise ValueError('Unknown route')
                self.reply(200,result)
            except Exception as error:self.reply(400,{'error':str(error)})
        def do_POST(self):
            if self.headers.get('Authorization')!='Bearer '+token:
                self.reply(403,{'error':'Local workspace token required'});return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=8192:raise ValueError('Request size limit')
                data=json.loads(self.rfile.read(size))
                action=data['action']
                for name in ('snapshot',):
                    if name in data and action!='snapshot':
                        row=service.store.one('SELECT run_id FROM snapshots WHERE id=?',(data[name],))
                        if row['run_id']!=run:raise ValueError('Artifact belongs to another Run')
                if action=='clear-workspace':result=service.clear_workspace(run)
                elif action=='flow-scope':result=service.flow_scope(run,data['observation'],data.get('scope_class'))
                elif action=='code-scope':result=service.code_scope(run,data['snapshot'],data['method'],data.get('decoder') is True)
                elif action=='analyze':result=service.analyze(data['snapshot'],data.get('handler','structure'))
                elif action=='snapshot':result=service.request_snapshot(run,data['process'],data['target'])
                elif action=='export':result=service.export(data['snapshot'],service.store.root/'exports'/secrets.token_hex(16))
                elif action=='analysis-copy':result=service.analysis_copy(data['snapshot'],service.store.root/'exports'/secrets.token_hex(16))
                elif action=='export-trace':result=service.export_trace(run,data.get('kinds',[]),service.store.root/'exports'/secrets.token_hex(16))
                elif action=='export-variants':
                    snapshots=data['snapshots']
                    if not isinstance(snapshots,list) or not 1<=len(snapshots)<=100:raise ValueError('Snapshot count limit')
                    for item in snapshots:
                        if service.store.one('SELECT run_id FROM snapshots WHERE id=?',(item,))['run_id']!=run:raise ValueError('Wrong Run')
                    result=service.variants(snapshots,service.store.root/'exports'/secrets.token_hex(16))
                else:raise ValueError('Unsupported action')
                self.reply(200,result)
            except Exception as error:self.reply(400,{'error':str(error)})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    server.workspace_url=f'http://127.0.0.1:{server.server_port}/#token={token}'
    print(json.dumps({'workspace':server.workspace_url,'run':run}),flush=True)
    if background:
        threading.Thread(target=server.serve_forever,daemon=True).start();return server
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
