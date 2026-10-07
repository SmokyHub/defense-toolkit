"""Observed string transformations and frequency-ranked decoder candidates."""
from collections import Counter
import json

from .evidence import crypto_values,links,retained_value,callers
from .search_filters import query_filters,matches,classes


def readable(value):
    text=value.get('utf8')
    return isinstance(text,str) and bool(text) and sum(c.isprintable() or c in '\n\r\t' for c in text)/len(text)>.9


def value_text(value):
    if value.get('representation') in ('byte_array','byte_buffer') and value.get('hex') is not None:return 'hex:'+value['hex']
    if readable(value):return value['utf8']
    if value.get('hex') is not None:return 'hex:'+value['hex']
    return '['+value.get('reason',value.get('status','unavailable'))+']'


def collect(service,run,query='',include='',exclude='',since_ns=0,depth=5):
    query,include,exclude=query_filters(query,include,exclude)
    if type(depth) is not int or not 1<=depth<=8:raise ValueError('Decoder link depth must be 1..8')
    if type(since_ns) is not int or since_ns<0:raise ValueError('Invalid time boundary')
    service.store.one('SELECT id FROM runs WHERE id=?',(run,))
    rows=service.store.rows("SELECT * FROM observations WHERE run_id=? AND time_ns>? AND (kind LIKE 'crypto.%' OR kind='flow.call') ORDER BY sequence DESC LIMIT 10000",(run,since_ns))
    nodes={};counts=Counter();groups={};pairs={};cached={};observed_pairs=set()
    for row in rows:
        data=json.loads(row['data']);nodes[(row['process_id'],data.get('id'))]=(row,data)
        if matches(row,include,exclude) and row['kind'] in ('flow.call','crypto.custom','crypto.doFinal','crypto.update'):
            counts[data.get('api',row['kind'])]+=1
    def retained(row,ref):
        key=(row['process_id'],json.dumps(ref,sort_keys=True))
        if key not in cached:cached[key]=retained_value(service.store,run,row['process_id'],ref,65536)
        return cached[key]
    process_nodes={}
    for (process,event),entry in nodes.items():process_nodes.setdefault(process,{})[event]=entry
    for row in rows:
        if not matches(row,include,exclude):continue
        data=json.loads(row['data'])
        if data.get('outcome')=='threw' or row['kind'] not in ('crypto.doFinal','crypto.update','crypto.custom','crypto.string','flow.call'):continue
        values=crypto_values(service.store,row,65536,nodes=process_nodes.get(row['process_id'],{})) if row['kind'].startswith('crypto.') and row['kind']!='crypto.string' else None
        output=values['output'] if values else retained(row,data.get('output'))
        if not readable(output) or output.get('truncated') or output.get('display_truncated') or output.get('status')=='partial':continue
        producer=row;producer_data=data;via='returned_string_or_utf8_bytes';source_basis=None
        app_conversion=row['kind']=='flow.call' and data.get('input',{}).get('representation') in ('byte_array','byte_buffer') and data.get('output',{}).get('representation')=='string'
        if row['kind']=='crypto.string' or app_conversion:
            # A byte[] return followed by String construction retains its original
            # transformation input. Equal bytes are an association, not taint proof.
            frontier=[data];seen=set();found=None
            for _ in range(depth):
                following=[]
                for current in frontier:
                    for source,_,basis in links(current):
                        if source in seen:continue
                        seen.add(source);entry=nodes.get((row['process_id'],source))
                        if not entry or not matches(entry[0],include,exclude):continue
                        if entry[0]['kind'] in ('flow.call','crypto.custom','crypto.doFinal','crypto.update') and entry[1].get('output',{}).get('sha256')==data.get('input',{}).get('sha256'):
                            found=entry;source_basis=basis;break
                        following.append(entry[1])
                    if found:break
                if found:break
                frontier=following[:128]
            if not found and row['kind']=='crypto.string':continue
            if found:producer,producer_data=found;via='later_byte_array_to_string'
        method=producer_data.get('api',producer['kind'])
        if producer['kind'].startswith('crypto.'):
            values=crypto_values(service.store,producer,65536,nodes=process_nodes.get(producer['process_id'],{}))
            incoming=values['input']
        else:incoming=retained(producer,producer_data.get('input'))
        decrypt=producer_data.get('mode')==2
        basis='Cipher decrypt mode observed' if decrypt else 'Candidate transformation; decryption semantics unverified'
        package_classes=classes(producer)
        pair={'observation':producer['id'],'method':method,'process':producer['process_id'],
              'cipher':value_text(incoming),'plaintext':output['utf8'],'classification':'cipher_decrypt' if decrypt else 'decoder_candidate',
              'basis':basis,'output_observation':row['id'],'conversion':via,'source_basis':source_basis,
              'input_status':incoming.get('status'),'input_representation':incoming.get('representation'),'input_sha256':incoming.get('sha256'),'output_sha256':output.get('sha256'),
              'input_truncated':bool(incoming.get('truncated') or incoming.get('display_truncated') or incoming.get('status')=='partial'),
              'message_scope':'update_fragment' if producer['kind']=='crypto.update' else 'transformation_result',
              'package_classes':package_classes}
        if query and query.casefold() not in json.dumps(pair,ensure_ascii=False).casefold():continue
        key=(method,pair['cipher'],pair['plaintext'],pair['classification'])
        occurrence=(producer['id'],key)
        if occurrence in observed_pairs:continue
        observed_pairs.add(occurrence)
        if key in pairs:pairs[key]['occurrences']+=1
        else:pairs[key]={**pair,'occurrences':1}
        group=groups.setdefault(method,{'method':method,'calls':counts[method],'string_results':0,'pairs':0,'classification':pair['classification'],
            'observation':producer['id'],'package_classes':package_classes,'basis':basis,'conversions':set()})
        group['string_results']+=1;group['conversions'].add(via)
    for group in groups.values():
        group['pairs']=sum(p['method']==group['method'] for p in pairs.values());group['conversions']=sorted(group['conversions'])
    ranked=sorted(groups.values(),key=lambda g:(g['classification']!='cipher_decrypt',-g['calls'],-g['pairs'],g['method']))
    return {'candidates':ranked,'pairs':list(pairs.values()),'scanned_events':len(rows),'truncated':len(rows)>=10000,
            'limits':{'events':10000,'value_bytes':65536,'link_depth':depth},
            'note':'Frequency counts retained observed calls, not every invocation. String returns and later byte[] conversions identify candidates; only observed Cipher decrypt mode establishes that role.'}


def export(service,run,format='txt',**filters):
    if format not in ('txt','jsonl'):raise ValueError('String export format must be txt or jsonl')
    result=collect(service,run,**filters);lines=[];size=0;export_limited=False
    for pair in result['pairs']:
        line=json.dumps(pair,ensure_ascii=False) if format=='jsonl' else json.dumps(pair['cipher'],ensure_ascii=False)+' - '+json.dumps(pair['plaintext'],ensure_ascii=False)
        size+=len(line.encode('utf-8'))
        if size>24*1024**2:export_limited=True;break
        lines.append(line)
    metadata={k:v for k,v in result.items() if k not in ('pairs','candidates')}
    metadata.update(type='export_metadata',exported_pairs=len(lines),export_truncated=export_limited)
    if format=='jsonl':lines.insert(0,json.dumps(metadata))
    else:lines.insert(0,'# CIPHER - PLAINTEXT; hex: denotes binary input. Cipher decrypts and unverified decoder candidates are included; use JSONL for roles/provenance.\n# '+json.dumps(metadata))
    return 'decrypted-strings.'+format,('\n'.join(lines)+'\n').encode('utf-8')
