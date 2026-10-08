"""Bounded discovery of an async Pigeon preferences boundary in Flutter AOT.

The result is a conditional structural candidate, not a network provenance proof.
Selectors derive from standard channel strings and instructions in the input ELF;
there are no application names, hashes, offsets, or reviewed key lists here.
"""
from collections import defaultdict, deque
import json
import re


def integer(v):
    return int(v.lstrip('#'), 0)


def register(v):
    return 'x' + v[1:] if v.startswith('w') else v


def calls(p, f):
    return [(a, integer(p.code[a][1])) for a in p.functions[f] if p.code[a][0] == 'bl']


def frame(v):
    return isinstance(v, tuple) and len(v) == 2 and v[0] == 'frame'


def snapshot(p, start, end, initial=None):
    """Local copy/dataflow only. Unknown calls kill registers, never frame facts.

    Branches are intentionally not interpreted. Callers only compare local ABI
    setup spans, or record the result as a conditional structural candidate.
    """
    regs = {'x22': ('null',), **(initial or {})}; slots = {}; stack = {}; writes = []
    for a in range(start, end, 4):
        op, args = p.code.get(a, ('', '')); parts = args.split(', ')
        dst = register(parts[0]); value = None
        if a in p.refs:
            ref = p.refs[a]
            value = ('pool', p.ref_offsets[a])
            if ref.startswith('String: '):
                value = ('string', json.loads(ref[8:]))
            regs[dst] = value
        elif op == 'mov' and len(parts) == 2:
            regs[dst] = integer(parts[1]) if parts[1].startswith('#') else regs.get(register(parts[1]))
        elif op in ('ldr', 'ldur', 'str', 'stur'):
            m = re.fullmatch(r'[xw]\d+, \[(x\d+)(?:, (#[^\]]+|x\d+))?\]', args)
            if not m:
                if op in ('ldr', 'ldur'): regs.pop(dst, None)
                continue
            base, off = m[1], m[2] or '#0'
            off = integer(off) if off.startswith('#') else regs.get(off)
            if not isinstance(off, int):
                if op in ('ldr', 'ldur'): regs.pop(dst, None)
                continue
            memory = slots if base == 'x29' else stack if base == 'x15' else None
            if op in ('ldr', 'ldur'):
                regs[dst] = (memory.get(off, ('frame', off)) if base == 'x29' else
                             memory.get(off, ('stack', off)) if base == 'x15' else
                             ('member', regs[base], off) if regs.get(base) is not None else None)
            elif memory is not None:
                memory[off] = regs.get(dst)
            else:
                writes.append((a, regs.get(base), off, regs.get(dst)))
        elif op == 'stp':
            m = re.fullmatch(r'(x\d+), (x\d+), \[(x15|x29)(?:, #(0x[0-9a-f]+|-?\d+))?\]', args)
            if m:
                mem = stack if m[3] == 'x15' else slots; off = integer(m[4] or '0')
                mem[off] = regs.get(m[1]); mem[off + 8] = regs.get(m[2])
        elif op == 'add' and len(parts) == 4 and parts[2:] == ['x28', 'lsl #32']:
            regs[dst] = regs.get(register(parts[1]))
        elif op in ('bl', 'blr'):
            result = ('call', a, integer(args)) if op == 'bl' else ('indirect', a)
            regs = {'x22': ('null',), 'x0': result}
        elif dst.startswith('x') and op not in ('str', 'stur', 'stp', 'cmp', 'tst', 'b', 'ret', 'tbz', 'tbnz', 'cbz', 'cbnz') and not op.startswith('b.'):
            regs.pop(dst, None)
    return regs, slots, stack, writes


def local_args(p, pc, span=64):
    return snapshot(p, max(p.owner(pc), pc - span * 4), pc)[0]


def await_after(p, pc):
    for a in range(pc + 4, pc + 36, 4):
        op, args = p.code.get(a, ('', ''))
        if op == 'bl':
            if p.metadata.get('stubs', {}).get(integer(args)) == 'AwaitStub':
                r = snapshot(p, pc + 4, a, {'x0': ('future',)})[0]
                if r.get('x1') == ('future',): return a
            return None
        if op in ('b', 'ret', 'blr') or op.startswith('b.'): return None
    return None


def keyed_calls(p, keys, function):
    result = []
    for key in keys:
        if int(key['function'], 16) != function: continue
        start = int(key['address'], 16) + 12
        for a in range(start, start + 80, 4):
            if p.owner(a) != function: break
            op, args = p.code.get(a, ('', ''))
            if op == 'bl':
                r, _, s, _ = snapshot(p, start, a, {'x0': ('key', key['key'])})
                result.append({'key': key['key'], 'key_va': key['address'], 'decimal_helper': key['helper'],
                               'pc': a, 'target': integer(args), 'registers': r, 'stack': s})
                break
            if op in ('b', 'ret', 'blr') or op.startswith('b.'): break
    return result


def possible_path(p, function, start, end):
    """Bounded CFG existence check; branch feasibility remains conditional."""
    todo=[start];seen=set()
    while todo and len(seen)<8192:
        pc=todo.pop()
        if pc==end:return True
        if pc in seen or p.owner(pc)!=function or pc not in p.code:continue
        seen.add(pc);op,args=p.code[pc]
        if op in ('ret','br','brk'):continue
        if op=='b':todo.append(integer(args));continue
        if op.startswith('b.') or op in ('tbz','tbnz','cbz','cbnz'):
            todo.append(integer(args.split(', ')[-1]))
        todo.append(pc+4)
    return False


def channel_functions(p, suffix):
    channel = 'dev.flutter.pigeon.shared_preferences_android.SharedPreferencesAsyncApi.' + suffix
    return {f for f, literals in p.literals.items() if any(v == channel for _, v in literals)}


def reaches(p, source, targets, depth=2):
    todo = deque([(source, 0)]); seen = set()
    while todo and len(seen) < 64:
        f, d = todo.popleft()
        if f in targets: return True
        if f in seen: continue
        seen.add(f)
        if d < depth: todo.extend((t, d + 1) for t in p.edges[f])
    return False


def channel_argument_packing(p, f, argument, array_offset):
    # Generated Pigeon messages must actually pack the key/value input, not just
    # contain the channel name as unrelated dead data.
    end = min(max(p.functions[f]) + 4, f + 1024)
    _, _, _, writes = snapshot(p, f, end, {f'x{i}': ('argument', i) for i in range(1, 8)})
    return [hex(pc) for pc, base, offset, value in writes
            if offset == array_offset and value == ('argument', argument) and base is not None]


def literals_reachable(p, f, depth=4):
    todo = deque([(f, 0)]); seen = set(); found = set()
    while todo and len(seen) < 256:
        current, d = todo.popleft()
        if current in seen: continue
        seen.add(current); found.update(v for _, v in p.literals[current])
        if d < depth: todo.extend((t, d + 1) for t in sorted(p.edges[current]))
    return found


def prior_calls(p, function, pc, count):
    return [(a, t) for a, t in calls(p, function) if a < pc][-count:]


def utf8_encoder_evidence(p, encoder):
    """Recognize bounded UTF-16-to-UTF-8 emission structure, not a function name.

    Constants are Unicode/UTF-8 format constants. Register relationships connect
    the two/three-byte lead-byte shifts to OR-prefix and byte output instructions.
    This is a compiler-shape recognizer under standard-library semantics, not a
    complete proof of arbitrary encoder equivalence.
    """
    candidates=[]
    for call_pc,target in calls(p,encoder):
        body=[(a,*p.code[a])for a in p.functions[target]]
        pairs=[(op,args)for a,op,args in body]
        if not any(op=='cmp' and args.endswith(', #0x7f')for op,args in pairs):continue
        if not any(op=='cmp' and args.endswith(', #0x7ff')for op,args in pairs):continue
        if not any(op=='and' and args.endswith(', #0xfc00')for op,args in pairs):continue
        if not all(any(op=='mov' and args.endswith(', #'+hex(value))for op,args in pairs)for value in (0xd800,0xdc00)):continue
        emissions=[]
        for i,(pc,op,args)in enumerate(body):
            if op!='asr':continue
            m=re.fullmatch(r'(x\d+), (x\d+), #(6|0xc)',args)
            if not m or i+1>=len(body):continue
            nxt_pc,nxt_op,nxt_args=body[i+1]
            prefix=0xc0 if m[3]=='6'else 0xe0
            prefix_match=re.fullmatch(r'(x\d+), '+m[1]+r', #'+hex(prefix),nxt_args)if nxt_op=='orr'else None
            if not prefix_match:continue
            out=register(prefix_match[1]);store=None
            for store_pc,store_op,store_args in body[i+2:i+14]:
                if store_op=='strb' and register(store_args.split(', ')[0])==out:
                    store=store_pc;break
                if store_args.split(', ')[0]==out and store_op not in ('cmp','tst','str','stur','stp'):break
            if store:emissions.append({'shift':pc,'prefix':nxt_pc,'store':store,'prefix_value':prefix,'source':m[2]})
        if {v['prefix_value']for v in emissions}!={0xc0,0xe0}:continue
        if len({v['source']for v in emissions})!=1:continue
        if not any(op=='and' and args.endswith(', #0x3f')for op,args in pairs):continue
        if not any(op=='orr' and args.endswith(', #0x80')for op,args in pairs):continue
        # Input string must pass through the outer encoder to its byte emitter.
        initial={'x2':('input_string',)}
        input_regs=snapshot(p,encoder,call_pc,initial)[0]
        if input_regs.get('x2')!=('input_string',):continue
        candidates.append({'emitter':hex(target),'call':hex(call_pc),
                           'lead_byte_emissions':[{'shift':hex(v['shift']),'prefix':hex(v['prefix']),
                                                   'store':hex(v['store']),'value':v['prefix_value']}for v in emissions]})
    if len(candidates)!=1:raise ValueError('UTF-8 encoder byte-emission semantics unrecognized.')
    return candidates[0]


def codec_chain(p, loader, guard, decode, decoder, network, writes):
    before = [(a,t) for a,t in calls(p,loader) if guard < a < decode]
    if len(before) != 2: raise ValueError('Unrecognized byte decoding chain.')
    (base_pc, base), (utf_pc, utf) = before
    if local_args(p,utf_pc,8).get('x2') != ('call',base_pc,base):
        raise ValueError('Base64 result does not feed UTF-8 decoding.')
    if local_args(p,decode,8).get('x1') != ('call',utf_pc,utf):
        raise ValueError('UTF-8 result does not feed JSON decoding.')
    if not {'Missing padding character', 'Invalid length, must be multiple of four'} <= literals_reachable(p,base):
        raise ValueError('Base64 decoder semantics unrecognized.')
    if not {'Invalid UTF-8 byte', 'Unfinished UTF-8 octet sequence'} <= literals_reachable(p,utf):
        raise ValueError('UTF-8 decoder semantics unrecognized.')
    if not {'Unterminated string', 'Unexpected end of input', 'true', 'false', 'null'} <= literals_reachable(p,decoder):
        raise ValueError('JSON decoder semantics unrecognized.')
    second = writes[1]; chain = prior_calls(p,network,second['pc'],3)
    if len(chain) != 3: raise ValueError('Unrecognized preferences serialization chain.')
    first_args = local_args(p,chain[0][0],12)
    if first_args.get('x2') != writes[0]['args']['x3']:
        raise ValueError('Serialized branch is not sourced from the same map value.')
    for (prev_pc,prev_target),(pc,target) in zip(chain,chain[1:]):
        if local_args(p,pc,8).get('x2') != ('call',prev_pc,prev_target):
            raise ValueError('Serialization stages are not connected by argument provenance.')
    if second['args']['x3'] != ('call',*chain[-1]):
        raise ValueError('Serialized bytes do not reach the preferences writer.')
    if not {'true','false','null'} <= literals_reachable(p,chain[0][1]):
        raise ValueError('JSON encoder semantics unrecognized.')
    utf8_encoder=utf8_encoder_evidence(p,chain[1][1])
    if 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' not in literals_reachable(p,chain[-1][1]):
        raise ValueError('Base64 encoder semantics unrecognized.')
    return {'decode_calls':[hex(base_pc),hex(utf_pc),hex(decode)],
            'encode_calls':[hex(a) for a,t in chain], 'utf8_encoder':utf8_encoder,
            'wire_value':'JSON array', 'stored_value':'Base64(UTF8(JSON(value)))',
            'library_semantics_assumption':'Standard JSON, UTF-8 and Base64 codec implementations; symbol/diagnostic and argument-flow evidence, not equivalence proof.'}


def byte_closure_evidence(p, loader, getter, guard, first_read, receiver, options, codecs):
    closures = []
    for pc in p.functions[loader]:
        for match in re.finditer(r'(?:Anonymous)?Closure:.*?\(0x([0-9a-f]+)\)',p.refs.get(pc,'')):
            target = int(match[1],16)
            if getter in p.edges[target]: closures.append((pc,target))
    if len(closures) != 1: raise ValueError('No unique byte-read preferences closure.')
    closure_ref, closure = closures[0]
    getcalls = [(pc,t) for pc,t in calls(p,closure) if t == getter]
    if len(getcalls) != 1: raise ValueError('Byte closure has ambiguous getter calls.')
    getter_pc = getcalls[0][0]; args = local_args(p,getter_pc,7)
    fields = [args.get('x'+str(i)) for i in (1,2,3)]
    if any(not isinstance(v,tuple) or len(v)!=3 or v[0]!='member' or not frame(v[1]) for v in fields):
        raise ValueError('Byte getter arguments are not captured context fields.')
    if len({v[1] for v in fields})!=1: raise ValueError('Byte getter context mismatch.')
    _,saved,_,writes = snapshot(p,loader,closure_ref,{f'x{i}':('argument',i)for i in range(1,8)})
    captured={}
    for label,field,source in [('receiver',fields[0],receiver),('options',fields[2],options)]:
        expected=saved.get(source[1])
        matches=[(pc,base,off,val)for pc,base,off,val in writes if off==field[2]]
        if expected is None or len(matches)!=1 or matches[0][3]!=expected:
            raise ValueError('Byte closure '+label+' differs from the role-read preferences source.')
        captured[label]={'store':hex(matches[0][0]),'source_frame':source,'origin':expected}
    key_stores = [(pc,base,off,val) for pc,base,off,val in writes if off==fields[1][2] and val==('argument',2)]
    if len(key_stores)!=1: raise ValueError('Caller key is not captured for the byte getter.')
    # Match the later equality guard's frame source back to the captured field.
    guard_start = int(guard['key_va'],16)-24
    guard_regs,_,guard_stack,_ = snapshot(p,guard_start,guard['pc'])
    guarded = guard_stack.get(8)
    if not isinstance(guarded,tuple) or len(guarded)!=3 or guarded[0]!='member' or guarded[2]!=fields[1][2]:
        raise ValueError('Equality guard is not over the captured byte key.')
    # Closure is allocated into an async wrapper whose awaited result is saved
    # for the first decoder. Retain the wrapper as evidence, never identity-map
    # arbitrary direct calls to values.
    between = [(pc,t)for pc,t in calls(p,loader) if closure_ref < pc < guard['pc']]
    wrappers = [(pc,t)for pc,t in between if await_after(p,pc)]
    if len(wrappers)!=1: raise ValueError('Byte closure wrapper has no unique await.')
    wrapper_pc, wrapper = wrappers[0]
    allocations=[(pc,t) for pc,t in between if p.metadata.get('stubs',{}).get(t)=='AllocateClosureStub']
    if len(allocations)!=1 or allocations[0][0]!=closure_ref+4:
        raise ValueError('Referenced getter closure is not constructed by AllocateClosureStub.')
    closure_pc,closure_allocator=allocations[0]
    stack=snapshot(p,closure_pc+4,wrapper_pc,{'x0':('closure_result',)})[2]
    if stack.get(0)!=('closure_result',):raise ValueError('Getter closure does not reach wrapper callback argument.')
    await_pc=await_after(p,wrapper_pc)
    base_pc=int(codecs['decode_calls'][0],16)
    decoder_regs=snapshot(p,await_pc+4,base_pc,{'x0':('awaited_preferences_bytes',)})[0]
    if decoder_regs.get('x1')!=('awaited_preferences_bytes',):
        raise ValueError('Base64 decoder input is not the awaited byte-getter result.')
    wb=[p.code[a]for a in p.functions[wrapper]]
    if not any(op=='blr'for op,args in wb) or not any(p.metadata.get('stubs',{}).get(t)=='AwaitStub'for _,t in calls(p,wrapper)):
        raise ValueError('Byte wrapper does not invoke and await its supplied closure.')
    return {'closure':hex(closure),'closure_reference':hex(closure_ref),'getter_call':hex(getter_pc),
            'captured_key_store':hex(key_stores[0][0]),'captured_sources':captured,
            'base64_input_from_await':hex(base_pc),'wrapper':hex(wrapper),
            'wrapper_call':hex(wrapper_pc),'closure_allocation':hex(closure_pc),'await_va':hex(await_after(p,wrapper_pc)),
            'captured_argument_offsets':{'receiver':fields[0][2],'key':fields[1][2],'options':fields[2][2]}}


def network_evidence(p, n, loader, setters):
    initial={'x1':('argument',1),'x2':('argument',2),'x3':('argument',3)}
    wrapper = n['trigger']['target']
    loader_calls = [(a,t) for a,t in calls(p,wrapper) if t==loader]
    if len(loader_calls)!=1: raise ValueError('Loader wrapper has ambiguous invocation.')
    args = snapshot(p,wrapper,loader_calls[0][0],initial)[0]
    if args.get('x1')!=('member',('argument',1),11) or args.get('x2')!=('argument',2):
        raise ValueError('Loader wrapper does not preserve preferences receiver and key.')
    writer=n['writes'][0]['function']
    setter_calls=[(a,t)for a,t in calls(p,writer)if t in setters]
    if len(setter_calls)!=1: raise ValueError('Preferences writer does not invoke one setString channel.')
    setter_pc,setter=setter_calls[0]
    if not channel_argument_packing(p,setter,2,15) or not channel_argument_packing(p,setter,3,19):
        raise ValueError('Pigeon writer key/value message packing unresolved.')
    args = snapshot(p,writer,setter_pc,initial)[0]
    if args.get('x2')!=('argument',2) or args.get('x3')!=('argument',3):
        raise ValueError('Preferences writer alters its key/value before setString.')
    outer_pc=n['outer']['pc']; first=n['writes'][0]
    for w in n['writes']:
        if not possible_path(p,n['function'],outer_pc,w['pc']) or not possible_path(p,n['function'],w['pc'],n['trigger']['pc']):
            raise ValueError('Preferences producer/write/loader blocks lack a connected possible CFG path.')
    status_checks=[]
    for pc in range(n['body_decode']-96,n['body_decode'],4):
        op,args=p.code.get(pc,('',''))
        if op=='cmp' and args.endswith(', #0xc8') and p.code.get(pc+4,('',))[0]=='b.ne':
            status_checks.append(pc)
    if len(status_checks)!=1:raise ValueError('No unique HTTP 200 gate before body decoding.')
    body_slots=snapshot(p,n['body_decode']+4,outer_pc,{'x0':('decoded_body',)})[1]
    if body_slots.get(n['outer']['registers']['x1'][1])!=('decoded_body',):
        raise ValueError('Outer lookup receiver is not the decoded response object.')
    outslots=snapshot(p,outer_pc+4,outer_pc+24,{'x0':('outer_map',)})[1]
    maps=[('frame',slot)for slot,value in outslots.items()if value==('outer_map',)]
    if len(maps)!=1: raise ValueError('Outer object is not preserved in one map slot.')
    map_source=maps[0]; key_source=first['args']['x2']; value_source=first['args']['x3']
    if not frame(value_source): raise ValueError('Direct string writer has no saved map value.')
    matches=[]
    for pc in range(outer_pc+4,first['pc'],4):
        if p.code.get(pc,('',))[0]!='blr':continue
        r,slots,_,_=snapshot(p,max(outer_pc,pc-64),pc)
        if r.get('x1')!=map_source or r.get('x2') is None or r.get('x2')!=slots.get(key_source[1]):continue
        after=snapshot(p,pc+4,pc+20,{'x0':('map_value',)})[1]
        if after.get(value_source[1])==('map_value',):matches.append((pc,r['x2']))
    if len(matches)!=1: raise ValueError('Writer key/value do not originate in one outer-map element read.')
    element_pc,key=matches[0]
    if not isinstance(key,tuple) or key[0]!='indirect':raise ValueError('Map key iterator source unresolved.')
    key_pc=key[1]; iterator_source=local_args(p,key_pc,12).get('x1')
    if not frame(iterator_source):raise ValueError('Map key is not read from a saved iterator.')
    iterator_matches=[]
    for pc in range(outer_pc+4,key_pc,4):
        if p.code.get(pc,('',))[0]!='blr':continue
        r=local_args(p,pc,12); input_=r.get('x1')
        if not isinstance(input_,tuple)or input_[0]!='indirect':continue
        if local_args(p,input_[1],12).get('x1')!=map_source:continue
        slots=snapshot(p,pc+4,pc+20,{'x0':('iterator',)})[1]
        if slots.get(iterator_source[1])==('iterator',):iterator_matches.append(pc)
    if len(iterator_matches)!=1:raise ValueError('Iterator is not derived from the selected outer map.')
    return {'wrapper_loader_call':hex(loader_calls[0][0]),'setter_function':hex(setter),
            'setter_call':hex(setter_pc),'status_200_compare':hex(status_checks[0]),'map_receiver':map_source,'map_element_call':hex(element_pc),
            'iterator_call':hex(iterator_matches[0]),'iterator_current_call':hex(key_pc),
            'key_slot':key_source,'value_slot':value_source,
            'assumption':'Standard Map keys/iterator/indexing and SharedPreferences Pigeon library semantics on successful branches.'}


def discover_preferences(program):
    p = program; diagnostics = []; flows = []; keys = p.numeric_keys()
    getters = channel_functions(p, 'getString'); setters = channel_functions(p, 'setString')
    if not getters: return {'flows': [], 'diagnostics': ['No supported async preferences getString channel.']}
    good_getters = {g for g in getters if channel_argument_packing(p, g, 2, 15)}
    if not good_getters: return {'flows': [], 'diagnostics': ['Preferences getter key packing is unresolved.']}
    groups = defaultdict(list)
    for f in {int(k['function'], 16) for k in keys}:
        for access in keyed_calls(p, keys, f):
            r = access['registers']; aw = await_after(p, access['pc'])
            if access['target'] in good_getters and r.get('x2') == ('key', access['key']) and frame(r.get('x1')) and frame(r.get('x3')) and aw:
                groups[f].append({**access, 'await': aw})
    for loader, reads in groups.items():
        reads.sort(key=lambda r:r['pc'])
        try:
            if len(reads) < 4: continue
            receivers = {(r['registers']['x1'], r['registers']['x3'], r['target']) for r in reads}
            if len(receivers) != 1: raise ValueError('Role reads do not share one preferences receiver/options source.')
            receiver, options, getter = next(iter(receivers))
            # A decimal equality guard over a caller-supplied key precedes reads.
            guard_candidates = []
            for k in keyed_calls(p, keys, loader):
                if k['pc'] >= reads[0]['pc'] or k['target'] == getter: continue
                body = [p.code[a] for a in p.functions[k['target']]]
                if body[:3] != [('ldr', 'x0, [x15, #8]'), ('ldr', 'x1, [x15]'), ('cmp', 'x0, x1')]: continue
                if k['stack'].get(0) != ('key', k['key']) or k['stack'].get(8) is None: continue
                if p.code.get(k['pc'] + 4, ('',))[0] != 'tbnz': continue
                guard_candidates.append(k)
            if len(guard_candidates) != 1: raise ValueError('No unique preferences loader key equality guard.')
            guard = guard_candidates[0]; outer = guard['key']
            # The byte-result decoder is the last direct call before a List check
            # after the guarded preferences read. It stays an explicit transform.
            decode = []
            for pc, target in calls(p, loader):
                if not guard['pc'] < pc < reads[0]['pc']: continue
                refs = [p.refs.get(a, '') for a in range(pc + 4, min(pc + 100, reads[0]['pc']), 4)]
                intervening = [a for a in range(pc + 4, pc + 28, 4) if p.code.get(a, ('',))[0] == 'bl']
                if 'Type: List' in refs and not intervening: decode.append((pc, target))
            if len(decode) != 1: raise ValueError('No unique byte decoder/List boundary.')
            decode_pc, decoder = decode[0]
            if not possible_path(p,loader,guard['pc'],decode_pc) or not all(possible_path(p,loader,decode_pc,r['pc'])for r in reads):
                raise ValueError('Preferences read/decoder blocks lack a connected possible CFG path.')
            wrappers = {f for f in p.functions if len(p.functions[f]) < 96 and loader in p.edges[f]}
            networks = []
            for f in {int(k['function'], 16) for k in keys}:
                direct = keyed_calls(p, keys, f)
                trigger = [k for k in direct if k['target'] in wrappers and k['key'] == outer and k['registers'].get('x2') == ('key', outer) and frame(k['registers'].get('x1'))]
                if not trigger: continue
                trigger = max(trigger, key=lambda k: k['pc']); prefs = trigger['registers']['x1']
                outer_reads = [k for k in direct if k['key'] == outer and k['pc'] < trigger['pc'] and k['target'] not in wrappers and k['registers'].get('x2') == ('key', outer) and frame(k['registers'].get('x1'))]
                if len(outer_reads) != 1: continue
                outer_read = outer_reads[0]
                map_refs = [(a, p.refs.get(a)) for a in range(outer_read['pc'], outer_read['pc'] + 256, 4) if p.refs.get(a) == 'Type: Map']
                body_decodes = [(a,t) for a,t in calls(p,f) if t == decoder and a < outer_read['pc'] and outer_read['pc'] - a < 160]
                if not map_refs or len(body_decodes) != 1: continue
                writes = []
                for pc, target in calls(p, f):
                    if not outer_read['pc'] < pc < trigger['pc'] or not reaches(p,target,setters,2): continue
                    args = local_args(p, pc, 12)
                    if args.get('x1') != ('member', prefs, 11) or not frame(args.get('x2')) or args.get('x3') is None or not await_after(p,pc): continue
                    writes.append({'pc': pc, 'function': target, 'args': args, 'await': await_after(p,pc)})
                if len(writes) != 2 or writes[0]['function'] != writes[1]['function'] or writes[0]['args']['x2'] != writes[1]['args']['x2']: continue
                networks.append({'function':f, 'outer':outer_read, 'trigger':trigger, 'writes':writes,'prefs':prefs, 'body_decode':body_decodes[0][0]})
            if len(networks) != 1: raise ValueError('No unique matching map-to-preferences writer and loader handoff.')
            n = networks[0]
            codecs = codec_chain(p,loader,guard['pc'],decode_pc,decoder,n['function'],n['writes'])
            closure = byte_closure_evidence(p,loader,getter,guard,reads[0]['pc'],receiver,options,codecs)
            provenance = network_evidence(p,n,loader,setters)
            flows.append({'status':'conditional_preferences_boundary', 'loader_function':hex(loader),
                          'getter_function':hex(getter),'writer_function':hex(n['writes'][0]['function']),
                          'outer_key':outer,'array_key':outer,'byte_decode_va':hex(decode_pc),
                          'decoder_function':hex(decoder), 'guard_va':hex(guard['pc']),
                          'codecs':codecs, 'byte_closure':closure, 'preferences_provenance':provenance,
                          'receiver':['frame',hex(receiver[1])], 'options_receiver':['frame',hex(options[1])],
                          'accesses':[{'key':r['key'],'key_va':r['key_va'],'decimal_helper':r['decimal_helper'],
                                       'access_va':hex(r['await']),'get_call_va':hex(r['pc']),
                                       'receiver':['frame', '#'+hex(receiver[1])], 'expected_type':'string',
                                       'status':'conditional_preferences_read'} for r in reads],
                          'byte_access':{'key':outer,'access_va':hex(decode_pc), 'receiver':['frame','#'+hex(receiver[1])],
                                         'expected_type':'list','status':'conditional_preferences_bytes'},
                          'network_function':hex(n['function']),'outer_access_va':hex(n['outer']['pc']),
                          'body_decode_va':hex(n['body_decode']),
                          'loader_wrapper':hex(n['trigger']['target']),'handoff_va':hex(n['trigger']['pc']),
                          'network_preferences_receiver':list(n['prefs']),
                          'write_calls':[{'call_va':hex(w['pc']),'await_va':hex(w['await']),
                                          'receiver':w['args']['x1'],'key':w['args']['x2'],'value':w['args']['x3']} for w in n['writes']],
                          'assumptions':['Conditional ABI/copy slices; successful type checks and async completion required.',
                                         'Pigeon preferences and decoder library semantics need independent verification.',
                                         'Exact network-body provenance and runtime execution are not established; codec identities are conditional on the recorded standard library semantics.']})
        except ValueError as e:
            diagnostics.append({'loader_function':hex(loader),'reason':str(e)})
    return {'flows':flows,'diagnostics':diagnostics}
