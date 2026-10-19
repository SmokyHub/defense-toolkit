"""Reviewed encrypted selectors and indirect field roles for a Family4 core.

Instruction graphs bind every parser/loader helper; selector ciphertext and
constant-ID string calls are recovered from the input. No package/hash lookup.
"""
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct

from family4_native import (Unsupported, Code, ARM64_OP_MEM, _local_argument,
                            _jni_slot, _validator_model)
from family4_indexed import verify_graph, shape
from family4_decoder import Decoder

MODEL = 'family4_encoded_models.json'
MODELS = (MODEL, 'family4_encoded_split_models.json', 'family4_encoded_records_models.json')
DEFAULT_TRIGGER = {'before':24, 'after':72, 'calls':{'6':'selector_value','12':'formatter'},
                   'failures':[7,18], 'formatter_instruction':12}


def trigger_shape(img, call, bound, layout=None):
    """Check the reviewed successful path from selector(0) to NewStringUTF.

    Failure exits leave this slice; the result is conditional path evidence,
    not a claim that startup or any of these branches ran.
    """
    layout=DEFAULT_TRIGGER if layout is None else layout
    start, end = call.address-layout['before'], call.address+layout['after']
    if not 0<=layout['before']<=128 or not 0<=layout['after']<=128:
        raise Unsupported('encoded trigger slice exceeds bounds')
    code = Code(img.byaddr[a] for a in range(start,end+4,4) if a in img.byaddr)
    if len(code)!=(end-start)//4+1:raise Unsupported('incomplete encoded outer-trigger slice')
    replacements={}
    for k,ins in enumerate(code):
        if ins.mnemonic=='bl':
            name=layout['calls'].get(str(k))
            if name is None or ins.operands[0].imm!=bound[name]:
                raise Unsupported('changed encoded trigger helper')
            replacements[k]='bl function:'+name
        elif ins.mnemonic=='tbz':
            if k not in layout['failures'] or start<=ins.operands[-1].imm<=end:
                raise Unsupported('changed encoded trigger failure exit')
            replacements[k]=ins.mnemonic+' '+ins.op_str.rsplit(', ',1)[0]+', <failure>'
    return shape(code,replacements),code


def selector_parameters(codes, model):
    """Read reviewed scalar sites after graph verification; never skip guards."""
    if 'selector_parameters' not in model:
        return {'mapping_mask':0xd4, 'low_rotation':14, 'high_rotation':26}
    result={}
    for name,site in model['selector_parameters'].items():
        op=codes[site['function']][site['instruction']].operands[site['operand']]
        result[name]=op.shift.value if site.get('shift') else op.imm
    if model.get('selector_kind')=='rotating_u64_records':
        chunks={f'rotation_mask_{k}' for k in range(4)}
        if (set(result)!=chunks|{'mapping_mask'} or not 0<=result['mapping_mask']<=0xff
                or not all(0<=result[k]<=0xffff for k in chunks)):
            raise Unsupported('unmodeled record selector parameters')
        return {'kind':'rotating_u64_records', 'mapping_mask':result['mapping_mask'],
                'rotation_mask':sum(result[f'rotation_mask_{k}']<<(16*k) for k in range(4))}
    if (set(result)!={'mapping_mask','low_rotation','high_rotation'}
            or not 0<=result['mapping_mask']<=0xffffffff
            or not all(1<=result[k]<=31 for k in ('low_rotation','high_rotation'))):
        raise Unsupported('unmodeled encrypted selector parameters')
    return result


def selectors(img, refs, spec, parameters=None):
    parameters=selector_parameters({}, {}) if parameters is None else parameters
    if parameters.get('kind')=='rotating_u64_records':
        return record_selectors(img,refs,spec,parameters)
    addresses={name:refs[tuple(site)] for name,site in spec.items()}
    sizes={'mapping':64,'xor':128,'add':128,'cipher':128}
    for name,address in addresses.items():
        if not any(not s['p_flags']&2 and s['p_vaddr']<=address and
                   address+sizes[name]<=s['p_vaddr']+s['p_filesz'] for s in img.loads):
            raise Unsupported('encoded selector table is not read-only')
    mapping=[x^parameters['mapping_mask'] for x in struct.unpack('<16I',img.read(addresses['mapping'],64))]
    if sorted(mapping)!=list(range(16)):
        raise Unsupported('encoded selector mapping is not a permutation')
    tables={name:struct.unpack('<32I',img.read(addresses[name],128)) for name in ('xor','add','cipher')}
    ror=lambda x,n:((x>>n)|(x<<(32-n)))&0xffffffff
    keys=[]
    for index in mapping:
        low,high=2*index,2*index+1
        lo=((tables['xor'][low]^ror(tables['cipher'][low],parameters['low_rotation']))-tables['add'][low])&0xffffffff
        hi=((ror(tables['cipher'][high],parameters['high_rotation'])-tables['add'][high])&0xffffffff)^tables['xor'][high]
        keys.append(lo|(hi<<32))
    # Same nonnegative decimal domain as the proof generator and prior readers.
    if len(set(keys[1:]))!=15 or not all(0<=k<10**12 for k in keys):
        raise Unsupported('invalid recovered encrypted selectors')
    return keys,addresses


def record_selectors(img, refs, spec, parameters):
    """Decode the verified uint16 index map and five-word uint64 records.

    The instruction model fixes the low-byte mask, record stride, arithmetic,
    MOVK shifts and both rotation guards. Only the cipher scalars and tables
    are input-derived. These reads never execute the loader.
    """
    addresses={name:refs[tuple(site)] for name,site in spec.items()}
    sizes={'mapping':32, 'records':640}
    if set(addresses)!=set(sizes):raise Unsupported('incomplete record selector tables')
    for name,address in addresses.items():
        if not any(not s['p_flags']&2 and s['p_vaddr']<=address and
                   address+sizes[name]<=s['p_vaddr']+s['p_filesz'] for s in img.loads):
            raise Unsupported('record selector table is not read-only')
    mapping=[(x&0xff)^parameters['mapping_mask']
             for x in struct.unpack('<16H',img.read(addresses['mapping'],32))]
    if sorted(mapping)!=list(range(16)):
        raise Unsupported('record selector mapping is not a permutation')
    records=list(struct.iter_unpack('<5Q',img.read(addresses['records'],640)))
    keys=[];mask=(1<<64)-1
    for index in mapping:
        a,encoded_rotation,cipher,add,b=records[index]
        rotation=encoded_rotation^parameters['rotation_mask']
        if not 1<=rotation<=63:raise Unsupported('invalid record selector rotation')
        rotated=((cipher>>rotation)|(cipher<<(64-rotation)))&mask
        keys.append(((rotated-add)&mask)^a^b)
    if len(set(keys[1:]))!=15 or not all(0<=k<10**12 for k in keys):
        raise Unsupported('invalid recovered record selectors')
    return keys,addresses


def recover_strings(img, model, bound, codes, constants, imported):
    entries={name:bound[name] for name in model['isolated_decoders'] if name in bound}
    # These two additional pools supply network constants. Match their complete
    # decoder graphs before isolated execution; do not run arbitrary app helpers.
    for name,aux in model['auxiliary_decoders'].items():
        matches=[]
        for start in img.starts:
            try:verify_graph(img,start,aux,core=True)
            except (Unsupported,KeyError,IndexError):continue
            matches.append(start)
        if len(matches)!=1:raise Unsupported('missing or ambiguous auxiliary decoder: '+name)
        entries[name]=matches[0]
    decoders={name:Decoder(img,va,imported) for name,va in entries.items()}
    def decode(name,identifier):
        decoder=decoders[name]
        if identifier not in decoder.cache and sum(d.total_time for d in decoders.values())>=Decoder.MAX_TOTAL_SECONDS:
            raise Unsupported('encoded decoder aggregate time budget')
        return decoder.decode(identifier)
    required=[]
    for name,spec in model['functions'].items():
        for k,binding in spec.get('string_calls',{}).items():
            identifier=(constants[(name,binding['argument_instruction'])] if 'argument_instruction' in binding
                        else binding['identifier'])
            row=decode(binding['decoder'],identifier)
            if row is None or row['text']!=binding['text']:
                raise Unsupported('encoded core string does not match its JNI use')
            required.append((binding['decoder'],identifier,codes[name][int(k)].address))
    calls={};byentry={va:name for name,va in entries.items()}
    for k,ins in enumerate(img.ins):
        if ins.mnemonic!='bl' or ins.operands[0].imm not in byentry:continue
        identifier=_local_argument(img.ins,k,'x0')
        if identifier is not None and 0<=identifier<=0xffffffff:
            calls.setdefault((byentry[ins.operands[0].imm],identifier),[]).append(ins.address)
    if len(calls)>Decoder.MAX_CALLS:raise Unsupported('encoded decoder aggregate call budget')
    rows=[]
    for (name,identifier),addresses in calls.items():
        row=decode(name,identifier)
        if row is None:raise Unsupported('encoded decoder rejected a referenced ID')
        row['decode_calls']=[{'call_va':hex(a),'string_id':identifier} for a in addresses]
        rows.append(row)
    if not all(va in calls.get((name,identifier),[]) for name,identifier,va in required):
        raise Unsupported('incomplete encoded decoder call provenance')
    return rows


def analyze_encoded(img):
    candidates=set()
    for ins in img.ins:
        if (ins.mnemonic=='ldr' and len(ins.operands)==2 and ins.operands[1].type==ARM64_OP_MEM
                and ins.operands[1].mem.disp==0x730):
            at=bisect_right(img.starts,ins.address)-1
            if at>=0:candidates.add(img.starts[at])
    if not candidates:return None
    if len(candidates)>16:return None
    results=[]
    for filename in MODELS:
        model=json.loads(Path(__file__).with_name(filename).read_text())
        result=_analyze_model(img,candidates,model,filename)
        if result is not None:results.append(result)
    supported=[r for r in results if r['status']=='supported']
    if len(supported)==1:return supported[0]
    if len(supported)>1:
        return {'family':'family4','status':'needs_review','contracts':[],'strings':[],
                'diagnostics':['ambiguous encrypted core models'],'runtime_execution_observed':False}
    return results[0] if results else None


def _analyze_model(img,candidates,model,filename):
    results=[];failures=[]
    for start in sorted(candidates):
        try:bound,codes,refs,constants,imported=verify_graph(img,start,model,core=True)
        except (Unsupported,KeyError,IndexError):continue
        try:
            parameters=selector_parameters(codes,model)
            keys,addresses=selectors(img,refs,model['selector_arrays'],parameters)
            triggers=[]
            layout=model.get('trigger_layout',DEFAULT_TRIGGER)
            for ins in img.ins:
                if ins.mnemonic!='bl' or ins.operands[0].imm!=bound['selector_value']:continue
                try:
                    trigger_bound=dict(bound)
                    if 'trigger_formatter_model' in model:
                        site=ins.address-layout['before']+layout['formatter_instruction']*4
                        call=img.byaddr[site]
                        if call.mnemonic!='bl':continue
                        target=call.operands[0].imm
                        verify_graph(img,target,model['trigger_formatter_model'],core=True)
                        trigger_bound['formatter']=target
                    observed,code=trigger_shape(img,ins,trigger_bound,layout)
                except (Unsupported,KeyError,IndexError):continue
                if hashlib.sha256(observed.encode()).hexdigest()==model['trigger_sha256']:
                    triggers.append({'value':str(keys[0]),'selector_source':'verified_encrypted_selector_zero',
                                     'selector_call_va':hex(ins.address),'format_call_va':hex(code[layout['formatter_instruction']].address),
                                     'jni_call_va':hex(code[-1].address),
                                     'scope':'Conditional successful instruction path; startup reachability is not established.'})
            if len(triggers)!=1:raise Unsupported('missing or ambiguous encrypted selector trigger')
            guard,helpers=_validator_model(img,img.function(bound['validator']))
            if guard is None:raise Unsupported('unmodeled encrypted-core DEX validator')
            evidence=[]
            for item in model['jni_roles']:
                ins=codes['loader'][item['instruction']]
                if _jni_slot(codes['loader'],item['instruction'])!=item['slot']:
                    raise Unsupported('changed encoded-core JNI role call')
                evidence.append({'jni_slot':hex(item['slot']),'name_key':str(keys[item['name_index']]),
                                 'signature_key':str(keys[item['signature_index']]),'call_va':hex(ins.address),
                                 'binding':'Reviewed loader graph and checked role-map table.'})
            rows=recover_strings(img,model,bound,codes,constants,imported)
            endpoints={r['text'] for r in rows if re.fullmatch(r'https?://[^\s]+',r['text'])}
            values={r['text'] for r in rows}
            if len(endpoints)!=1 or not {'java/nio/ByteBuffer','allocateDirect','java/lang/ClassLoader',
                                        'org/json/JSONObject','getResponseCode','POST','<init>'}<=values:
                raise Unsupported('incomplete encrypted-core strings/endpoint')
            contract={'outer_key':str(keys[0]),'array_key':str(keys[2]),
                'roles':{role:str(keys[index+1]) for role,index in model['role_indices'].items()},
                'complete':True,'selector_storage':{k:hex(v) for k,v in addresses.items()},
                'selector_decoder_va':hex(bound['selector_value']),'parser_va':hex(bound['parser']),
                'loader_va':hex(start),'dex_validator_va':hex(bound['validator']),
                'validator_model':guard,'validator_helpers':helpers,'role_evidence':evidence,
                'outer_trigger_evidence':triggers,'diagnostics':[],
                'guards':{'dex_min_bytes':112,'dex_max_bytes':33554432,
                          'dex_versions':['035','037','038','039','040','041'],'exact_file_size':True,
                          'header_and_table_bounds':True,'dex_checksum_checked_by_native':False},
                'additional_checks':'Verified JSON preflight, indirect field roles, descriptor syntax, allocation budgets and JNI types.'}
            results.append({'family':'family4','variant':'encrypted_selector_core','contract_model':filename,
                'status':'supported','sha256':hashlib.sha256(img.data).hexdigest(),'endpoint':next(iter(endpoints)),
                'http_method':'POST','strings':rows,'contracts':[contract],'diagnostics':[],
                'evidence_level':'verified_native_contract_and_isolated_decoder_calls','runtime_execution_observed':False,
                'endpoint_evidence':'Decoded constant-ID call; surrounding network path is not verified.',
                'selector_transform':parameters,
                'limitations':['Conditional verified loader and outer-selector path; startup and network reachability are not established.',
                               'Role-map changes and unknown parser/loader layouts require review.',
                               'Bounded isolated decoder execution is not app or DEX runtime execution.']})
        except (Unsupported,ValueError,struct.error) as error:failures.append(str(error))
    if len(results)==1:return results[0]
    if results or failures:
        return {'family':'family4','variant':'encrypted_selector_core','status':'needs_review','contracts':[],
                'strings':[],'diagnostics':['ambiguous encrypted cores'] if results else failures,
                'runtime_execution_observed':False}
    return None
