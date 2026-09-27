"""Keyboard interface over the shared service; usable after capture termination."""
import curses
import json


def show(service,run):
    def main(screen):
        index=0;message='';view='inventory';marked=[]
        while True:
            screen.erase();h,w=screen.getmaxyx()
            coverage=service.coverage(run);r=coverage['run']
            rows=service.inventory(run) if view=='inventory' else service.timeline(run)
            index=max(0,min(index,len(rows)-1))
            def line(y,text):
                if y<h-1:screen.addnstr(y,0,str(text),max(1,w-1))
            line(0,f"{r['app']} | {r['device']} | Run {run} | {r['state']}")
            line(1,'↑/↓ · Enter details · i inventory · t timeline · c coverage · a analyze · d index DEX · / code search · e export · s snapshot · space mark · m variants · q quit')
            for n,row in enumerate(rows[max(0,index-h+8):][:max(1,h-6)]):
                absolute=max(0,index-h+8)+n
                line(n+3,('> ' if absolute==index else '  ')+row['id']+' '+str(row.get('status',row.get('kind')))+' '+str(row.get('process_id')))
            line(h-2,message)
            key=screen.getch()
            if key==ord('q'):return
            if key==curses.KEY_DOWN:index+=1
            elif key==curses.KEY_UP:index-=1
            elif key==ord('i'):view='inventory';index=0
            elif key==ord('t'):view='timeline';index=0
            else:
                try:
                    item=rows[index] if rows else None
                    if key==ord('c'):result=coverage
                    elif key in (10,13) and item:result=item
                    elif key==ord('a') and item and view=='inventory':result=service.analyze(item['id'])
                    elif key==ord('d') and item and view=='inventory':result=service.analyze(item['id'],'code.references')
                    elif key==ord('/'):
                        screen.move(h-2,0);screen.clrtoeol();screen.addstr(h-2,0,'URL/string/method: ');curses.echo()
                        try:query=screen.getstr(h-2,19,min(1024,max(1,w-20))).decode('utf-8','replace')
                        finally:curses.noecho()
                        result=service.search_code(run,query)
                    elif key==ord('e') and item and view=='inventory':
                        from .store import identity
                        result=service.export(item['id'],service.store.root/'exports'/identity())
                    elif key==ord('s') and item and view=='inventory':
                        result=service.request_snapshot(run,item['process_id'],item['logical_id'])
                    elif key==ord(' ') and item and view=='inventory':
                        if item['id'] in marked:marked.remove(item['id'])
                        elif len(marked)<64:marked.append(item['id'])
                        message=f'{len(marked)} snapshots marked';continue
                    elif key==ord('m'):
                        from .store import identity
                        if not marked:raise ValueError('Mark snapshots first')
                        result=service.variants(marked,service.store.root/'exports'/identity())
                    else:continue
                    text=json.dumps(result,indent=2).splitlines();offset=0
                    while True:
                        screen.erase()
                        for n,textline in enumerate(text[offset:offset+h-2]):line(n,textline)
                        line(h-2,'↑/↓ scroll · q return');k=screen.getch()
                        if k==ord('q'):break
                        offset=max(0,min(max(0,len(text)-h+2),offset+(1 if k==curses.KEY_DOWN else -1 if k==curses.KEY_UP else 0)))
                except Exception as error:message=str(error)
    curses.wrapper(main)
