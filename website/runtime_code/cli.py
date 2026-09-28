import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time

from .backends import discover
from .model import Pack, negotiate
from .analysis import HANDLERS,discover_handlers
from .service import Service
from .store import Store
from .config import load_config, config_source, write_example


def main():
    parser=argparse.ArgumentParser(prog='python -m runtime_code')
    parser.add_argument('--config',help='Machine-local JSON settings file')
    parser.add_argument('--store',help='Managed SQLite/artifact directory')
    sub=parser.add_subparsers(dest='command',required=True)
    c=sub.add_parser('config',help='Create or inspect machine-local settings');c.add_argument('action',choices=('init','show'));c.add_argument('--out',default='runtime-code.local.json')
    c=sub.add_parser('capabilities');c.add_argument('--backend',required=True)
    c=sub.add_parser('capture');c.add_argument('--backend',required=True);c.add_argument('--pack',required=True)
    c.add_argument('--app',required=True);c.add_argument('--device');c.add_argument('--pid',type=int)
    c.add_argument('--seconds',type=float,default=30);c.add_argument('--ui-port',type=int)
    c.add_argument('--script',action='append',default=[],help='Additional script file, in an isolated backend context; repeat for multiple files')
    c=sub.add_parser('watch',help='Live capture, portal and JSONL log until Ctrl+C')
    c.add_argument('--backend',default='frida');c.add_argument('--device');c.add_argument('--app',required=True)
    c.add_argument('--pack',default=str(Path(__file__).parent/'packs/live.json'))
    c.add_argument('--port',type=int,default=8765);c.add_argument('--seconds',type=float,default=0)
    c.add_argument('--no-web',action='store_true')
    c.add_argument('--no-open',action='store_true',help='Serve the workspace without opening a browser')
    c.add_argument('--code',action='append',default=[],help='APK/DEX/split ZIP to index for unexecuted code references')
    c.add_argument('--no-static',action='store_true',help='Explicitly skip automatic installed-APK static indexing')
    c.add_argument('--script',action='append',default=[],help='Additional script file, in an isolated backend context; repeat for multiple files')
    sub.add_parser('runs')
    c=sub.add_parser('evidence',help='Inspect an observation, its callers, linked flow and retained crypto bytes')
    c.add_argument('--run',required=True);c.add_argument('--observation',required=True)
    c=sub.add_parser('scope-pack',help='Print a next-run pack tracing app methods or an observed class')
    c.add_argument('--run',required=True);c.add_argument('--observation',required=True)
    c.add_argument('--class',dest='scope_class')
    c=sub.add_parser('index-code',help='Import APK/DEX/split ZIP and index static code for a Run')
    c.add_argument('--run',required=True);c.add_argument('path')
    c=sub.add_parser('search-code',help='Search URL/string/method definitions and potential/observed flow')
    c.add_argument('--run',required=True);c.add_argument('query',nargs='?',default='')
    c.add_argument('--include-packages',default='');c.add_argument('--exclude-packages',default='')
    c=sub.add_parser('code-scope',help='Print next-run method/decoder tracing pack from indexed evidence')
    c.add_argument('--run',required=True);c.add_argument('--snapshot',required=True);c.add_argument('--method',required=True);c.add_argument('--decoder',action='store_true')
    for name in ('inventory','timeline','findings','coverage','relationships','tui','serve'):
        c=sub.add_parser(name);c.add_argument('--run',required=True)
        if name in ('inventory','timeline','findings'):
            c.add_argument('--query',default='');c.add_argument('--include-packages',default='');c.add_argument('--exclude-packages',default='')
        if name=='serve':c.add_argument('--port',type=int,default=8765)
        if name=='timeline':c.add_argument('--after',type=int,default=0)
    c=sub.add_parser('analyze');c.add_argument('snapshot');c.add_argument('--handler',default='structure')
    c=sub.add_parser('export');c.add_argument('snapshot');c.add_argument('directory')
    c=sub.add_parser('analysis-copy');c.add_argument('snapshot');c.add_argument('directory')
    c=sub.add_parser('export-variants');c.add_argument('directory');c.add_argument('snapshots',nargs='+')
    c=sub.add_parser('export-trace');c.add_argument('--run',required=True);c.add_argument('--kind',action='append',default=[]);c.add_argument('directory')
    c=sub.add_parser('recover');c.add_argument('--run',required=True)
    c=sub.add_parser('snapshot');c.add_argument('--run',required=True);c.add_argument('--process',required=True);c.add_argument('--target',required=True)
    c=sub.add_parser('command');c.add_argument('id')
    for command_parser in sub.choices.values():
        command_parser.add_argument('--config',default=argparse.SUPPRESS,help='Machine-local JSON settings file')
    args=parser.parse_args()
    store=None
    try:
        if args.command=='config' and args.action=='init':
            write_example(args.out);print(json.dumps({'created':args.out}));return
        settings=load_config(args.config)
        if args.command=='config':
            print(json.dumps({'source':config_source(),'settings':settings},indent=2));return
        args.store=args.store or settings['paths']['store']
        if args.command in ('capture','watch'):
            args.device=args.device or settings['device']['serial'] or None
            if args.command=='capture' and not args.device:raise ValueError('Select --device or configure device.serial')
        registry=discover()
        discover_handlers()
        if args.command=='capabilities':
            if args.backend not in registry:raise ValueError('Unknown backend')
            print(json.dumps([asdict(c) for c in registry[args.backend]().capabilities()],indent=2));return
        store=Store(args.store);service=Service(store)
        if args.command in ('capture','watch'):
            if args.backend not in registry:raise ValueError('Unknown backend')
            watching=args.command=='watch'
            if not 0<=args.seconds<=86400 or (not watching and not args.seconds):raise ValueError('seconds must be in (0, 86400], or 0 for continuous watch')
            pack=Pack.parse(json.loads(Path(args.pack).read_text()))
            backend=registry[args.backend]()
            negotiate(pack,backend.capabilities(),HANDLERS)
            if args.script:
                if not hasattr(backend,'configure_scripts'):raise ValueError('Selected backend does not support --script; no scripts or capture started')
                backend.configure_scripts(args.script)
            if watching:
                print(json.dumps({'startup':'Checking device, server and launcher','app':args.app,'device':args.device}),file=sys.stderr,flush=True)
                if not hasattr(backend,'prepare_watch'):raise ValueError('Selected backend does not implement live launch preparation')
                devices=backend.available_devices()
                if not args.device:
                    if len(devices)!=1:raise ValueError('Select --device; available Android devices: '+', '.join(devices))
                    args.device=devices[0]
                service.reserve(args.app,args.device)
                args.pid=backend.prepare_watch(args.device,args.app)
                print(json.dumps({'startup':'Attaching instrumentation','pid':args.pid}),file=sys.stderr,flush=True)
                args.ui_port=None if args.no_web else args.port
            run=service.start(backend,pack,args.app,args.device,args.pid)
            print(json.dumps({'run':run,'state':'running'}),flush=True)
            log_path=store.root/(run+'.jsonl');cursor=0
            server=None
            try:
                if args.ui_port is not None:
                    from .web import serve
                    try:server=serve(service,run,args.ui_port,background=True)
                    except OSError as error:
                        import errno
                        if not watching or error.errno!=errno.EADDRINUSE:raise
                        server=serve(service,run,0,background=True)
                    if watching and not args.no_open:
                        from .web import open_workspace
                        open_workspace(server)
                try:
                    for path in getattr(args,'code',[]):
                        print(json.dumps({'static_index':service.index_code(run,path)}),flush=True)
                    if watching and not args.no_static and not args.code:
                        import tempfile
                        if not hasattr(backend,'static_input_files'):raise ValueError('Selected backend cannot copy installed code; supply --code')
                        with tempfile.TemporaryDirectory(prefix='runtime-installed-code-') as directory:
                            for path,source in backend.static_input_files(directory):
                                print(json.dumps({'static_index':service.index_code(run,path,source)}),flush=True)
                except Exception as error:
                    service.store.observe(run,None,'coverage.static_index',{'state':'partial_or_failed','reason':str(error)})
                    print(json.dumps({'static_index_error':str(error)}),flush=True)
                deadline=time.monotonic()+args.seconds if args.seconds else float('inf')
                log=None;cursor=0
                if watching:
                    log_path=store.root/(run+'.jsonl');log=log_path.open('a',encoding='utf-8')
                    print(json.dumps({'live_log':str(log_path),'attachment':'late_attach','stop':'Ctrl+C'}),flush=True)
                try:
                    while time.monotonic()<deadline:
                        if log:
                            page=service.timeline(run,cursor,1000)
                            for event in page:log.write(json.dumps(event)+'\n');cursor=event['sequence']
                            log.flush()
                        time.sleep(.2)
                finally:
                    if log:log.close()
            except KeyboardInterrupt:pass
            finally:
                service.stop()
                if server:server.shutdown();server.server_close()
                if watching:
                    with log_path.open('a',encoding='utf-8') as output:
                        while True:
                            page=service.timeline(run,cursor,1000)
                            if not page:break
                            for event in page:output.write(json.dumps(event)+'\n');cursor=event['sequence']
            result=service.coverage(run)
        elif args.command=='runs':result=store.rows('SELECT * FROM runs ORDER BY started_ns DESC')
        elif args.command=='evidence':result=service.evidence(args.run,args.observation)
        elif args.command=='scope-pack':result=service.flow_scope(args.run,args.observation,args.scope_class)
        elif args.command=='index-code':result=service.index_code(args.run,args.path)
        elif args.command=='search-code':result=service.search_code(args.run,args.query,args.include_packages,args.exclude_packages)
        elif args.command=='code-scope':result=service.code_scope(args.run,args.snapshot,args.method,args.decoder)
        elif args.command=='inventory':result=service.inventory(args.run)
        elif args.command=='findings':result=service.findings(args.run)
        elif args.command=='timeline':result=service.timeline(args.run,args.after)
        elif args.command=='coverage':result=service.coverage(args.run)
        elif args.command=='relationships':result=service.relationships(args.run)
        elif args.command=='analyze':result=service.analyze(args.snapshot,args.handler)
        elif args.command=='export':result=service.export(args.snapshot,args.directory)
        elif args.command=='analysis-copy':result=service.analysis_copy(args.snapshot,args.directory)
        elif args.command=='export-variants':result=service.variants(args.snapshots,args.directory)
        elif args.command=='export-trace':result=service.export_trace(args.run,args.kind,args.directory)
        elif args.command=='snapshot':result=service.request_snapshot(args.run,args.process,args.target)
        elif args.command=='command':result=store.one('SELECT * FROM commands WHERE id=?',(args.id,))
        elif args.command=='recover':
            row=store.one('SELECT * FROM runs WHERE id=?',(args.run,))
            with store.lease(args.run):
                store.expire(args.run,'explicit_recovery_after_collector_loss')
                store.state('runs',args.run,'disconnected',True)
                for process in store.rows('SELECT id FROM processes WHERE run_id=? AND ended_ns IS NULL',(args.run,)):
                    store.state('processes',process['id'],'disconnected',True)
            result={'run':args.run,'state':'disconnected','warning':'Only recover after the original collector has stopped'}
        elif args.command=='serve':
            from .web import serve
            serve(service,args.run,args.port);return
        elif args.command=='tui':
            from .tui import show
            show(service,args.run);return
        if args.command in ('inventory','timeline','findings'):
            from .search_filters import matches,patterns
            include,exclude=patterns(args.include_packages),patterns(args.exclude_packages,exclusion=True)
            result=[r for r in result if matches(r,include,exclude) and args.query.casefold() in json.dumps(r).casefold()]
        print(json.dumps(result,indent=2))
    except KeyboardInterrupt:
        print(json.dumps({'state':'interrupted'}),file=sys.stderr,flush=True)
    except Exception as error:
        print(json.dumps({'error':str(error)}),file=sys.stderr);sys.exit(2)
    finally:
        if store:
            service.release_target()
            store.close()
