"""Conservative compiled-flow model for a packed Flutter response envelope.

Checks input instruction graphs and snapshot references; never selects by package,
ELF hash, endpoint, or saved response. Unknown compilations remain review items.
"""
import hashlib
import json
from pathlib import Path
import re

MODEL = 'flutter_packed_models.json'
MODELS = (MODEL, 'flutter_packed_callers_models.json')
MAX_FUNCTIONS = 2048
MAX_INSTRUCTIONS = 150000


class Unmodeled(ValueError):
    pass


def node(program, function, skip=0, parameters=(), *, stop=None):
    """Canonicalize addresses as graph edges, preserving instructions and data."""
    addresses = program.functions.get(function, [])
    if not 0 <= skip < len(addresses) or len(addresses) > 12000:
        raise Unmodeled('packed helper bounds')
    fragment = stop is not None
    if fragment:
        if not skip < stop <= len(addresses) or stop-skip > 128:
            raise Unmodeled('packed caller slice bounds')
        addresses = addresses[skip:stop]
        skip = 0
    positions = {a: k for k, a in enumerate(addresses)}
    rows = []; edges = {}; values = {}
    for k, a in enumerate(addresses):
        if k < skip: continue
        op, args = program.code[a]
        if k in parameters:
            if op != 'mov' or not re.fullmatch(r'x16, #(?:0x[0-9a-f]+|\d+)', args):
                raise Unmodeled('changed decimal selector instruction')
            value = int(args.split('#')[1], 0)
            if value & 1 or not 0 <= value < 2**32:
                raise Unmodeled('invalid tagged decimal selector')
            values[k] = str(value // 2); args = 'x16, <selector>'
        if op == 'bl':
            target = int(args[1:], 0)
            stub = program.metadata['stubs'].get(target)
            if stub: args = 'stub:' + stub
            else: edges[f'call:{k}'] = target; args = '<function>'
        elif op == 'b' or op.startswith('b.') or op in ('tbz', 'tbnz', 'cbz', 'cbnz'):
            target = int(args.rsplit('#', 1)[1], 0)
            if target in positions:
                args = args.rsplit('#', 1)[0] + '@' + str(positions[target])
            elif (fragment and op != 'b' and target > addresses[-1]
                  and program.owner(target) == function):
                # This is a conditional successful caller slice. Failure exits
                # must leave it forwards; never treat a back edge as a failure.
                args = args.rsplit('#', 1)[0] + '<failure>'
            elif fragment:
                raise Unmodeled('unmodeled packed caller exit')
            elif target in program.metadata['stubs']:
                args = args.rsplit('#', 1)[0] + 'stub:' + program.metadata['stubs'][target]
            elif target in program.functions:
                edges[f'branch:{k}'] = target; args = args.rsplit('#', 1)[0] + '<function>'
            elif target in program.code and program.owner(target) in program.functions:
                owner = program.owner(target)
                edges[f'branch:{k}'] = owner
                args = args.rsplit('#', 1)[0] + '<function>:@' + str(program.functions[owner].index(target))
            else:
                raise Unmodeled('external packed helper branch')
        elif op in ('adr', 'adrp'):
            target = int(args.rsplit('#', 1)[1], 0)
            if op != 'adr' or target not in program.code:
                raise Unmodeled('unmodeled packed helper address')
            if target in positions:
                args = args.rsplit('#', 1)[0] + '@' + str(positions[target])
            else:
                owner = program.owner(target)
                edges[f'address:{k}'] = owner
                args = args.rsplit('#', 1)[0] + '<function>:@' + str(program.functions[owner].index(target))
        ref = program.refs.get(a)
        if ref is not None:
            off = program.ref_offsets[a]
            field = program.metadata['fields'].get(off)
            if field:
                target = field['initializer']
                if target:
                    if target not in program.functions: raise Unmodeled('missing lazy initializer')
                    edges[f'field:{k}'] = target
                ref = 'field:' + json.dumps({**field, 'initializer': bool(target)}, sort_keys=True)
            def closure(match):
                target = int(match[1], 16)
                edges[f'closure:{k}'] = target
                return 'Closure:<function>'
            ref = re.sub(r'Closure:.*?\(0x([0-9a-f]+)\)', closure, ref)
            # Class identity is supplied by snapshot metadata, not an obfuscated name.
            if ref.startswith('Obj!'): ref = 'Object'
            if ref == 'CachedArray':
                identity = program.metadata.get('cached_arrays', {}).get(off)
                if identity is None or not 21 <= identity < 60:
                    raise Unmodeled('unresolved cached descriptor identity')
                ref += ':' + str(identity)
            cid = program.metadata['objects'].get(off)
            args += ' pool:' + hashlib.sha256((ref + '|cid:' + str(cid)).encode()).hexdigest()
        rows.append(op + ' ' + args)
    last = addresses[-1]
    if not fragment and program.code[last][0] not in ('b', 'br', 'ret', 'brk'):
        if last + 4 not in program.functions: raise Unmodeled('unresolved helper fallthrough')
        edges['fallthrough'] = last + 4
    return {'instructions': len(rows), 'sha256': hashlib.sha256('\n'.join(rows).encode()).hexdigest()}, edges, values


def verify(program, root, model):
    bound = {'loader': root}; reverse = {root: 'loader'}; pending = ['loader']; done = set()
    keys = {}; total = 0
    def bind(name, target):
        if name in bound and bound[name] != target: raise Unmodeled('changed packed helper identity')
        if target in reverse and reverse[target] != name: raise Unmodeled('aliased packed helpers')
        bound[name] = target; reverse[target] = name; pending.append(name)
    for index, name in model['dispatch'].items():
        target = program.metadata['dispatch'].get(int(index))
        if target is None: raise Unmodeled('missing packed dispatch target')
        bind(name, target)
    if program.metadata['builtins'] != model['builtins']: raise Unmodeled('changed packed builtin classes')
    while pending:
        name = pending.pop()
        if name in done: continue
        done.add(name)
        if len(done) > MAX_FUNCTIONS: raise Unmodeled('packed helper count budget')
        spec = model['functions'][name]
        actual, edges, values = node(program, bound[name], spec.get('skip', 0), spec.get('parameters', []))
        total += actual['instructions']
        if total > MAX_INSTRUCTIONS: raise Unmodeled('packed instruction budget')
        if actual != spec['shape'] or set(edges) != set(spec['edges']): raise Unmodeled('changed packed instruction graph')
        for site, target in edges.items(): bind(spec['edges'][site], target)
        if name == 'loader': keys = values
    if done != set(model['functions']): raise Unmodeled('incomplete packed graph')
    return bound, keys


def caller_envelopes(program, bound, model):
    """Bind outer-map reads to a separately verified fragment-consuming loader.

    Every direct caller must match a reviewed successful slice. No outer key is
    borrowed from an unrelated numeric conversion or inferred from inner keys.
    """
    calls = [a for a, (op, args) in program.code.items()
             if op == 'bl' and int(args[1:], 0) == bound['loader']]
    if not 1 <= len(calls) <= 16:
        raise Unmodeled('missing or excessive packed envelope callers')
    if len(calls) != model['caller_count']:
        raise Unmodeled('changed packed envelope caller count')
    results = []
    for call in calls:
        function = program.owner(call)
        addresses = program.functions[function]
        end = addresses.index(call) + 1
        matches = []
        for spec in model['caller_envelopes']:
            start = end - spec['instructions']
            if start < 0: continue
            try:
                actual, edges, keys = node(program, function, start, [spec['selector']], stop=end)
            except (Unmodeled, KeyError, IndexError, ValueError):
                continue
            if (actual != spec['shape'] or set(edges) != set(spec['edges'])
                    or any(target != bound[spec['edges'][site]] for site, target in edges.items())):
                continue
            matches.append({'outer_key': keys[spec['selector']], 'caller_function': hex(function),
                            'selector_va': hex(addresses[start+spec['selector']]),
                            'loader_call_va': hex(call),
                            'scope': 'Conditional successful caller slice; failure paths and network/cache origin are not established.'})
        if len(matches) != 1:
            raise Unmodeled('unmodeled or ambiguous packed envelope caller')
        results.extend(matches)
    if len({item['outer_key'] for item in results}) != 1:
        raise Unmodeled('inconsistent packed outer selectors across callers')
    return results


def discover(program, candidates, bridge_table, origin):
    if not origin: return [], []
    findings = []; diagnostics = []
    for filename in MODELS:
        model = json.loads(Path(__file__).with_name(filename).read_text())
        matches, failures = _discover_model(program, candidates, bridge_table, origin, model, filename)
        findings.extend(matches); diagnostics.extend(failures)
    if len(findings) > 1: return [], [{'diagnostic': 'ambiguous packed consumer graphs'}]
    return findings, diagnostics


def _discover_model(program, candidates, bridge_table, origin, model, filename):
    findings = []; diagnostics = []
    for function in sorted(set(candidates))[:32]:
        try:
            bound, keys = verify(program, function, model)
            for slot, symbol in model['bridge_slots'].items():
                if bridge_table.get(int(slot), {}).get('symbol') != symbol:
                    raise Unmodeled('changed packed JNI bridge slot')
            callers = caller_envelopes(program, bound, model) if 'caller_envelopes' in model else []
            outer = callers[0]['outer_key'] if callers else keys[model['outer_selector']]
            selected = [keys[b['selector']] for b in model['bindings']]
            if len(set(selected)) != len(selected): raise Unmodeled('colliding packed response keys')
            bindings = []
            for b in model['bindings']:
                bindings.append({'role': b['role'], 'path': [outer, keys[b['selector']]], 'value': b['value'],
                                 'provenance': 'reviewed_compiled_consumer_graph',
                                 'evidence': {'selector_va': hex(program.functions[function][b['selector']]),
                                              'consumer_function': hex(function)}})
            transform = {'path': [outer], 'encoding': 'base64_utf8_json_fragments'}
            findings.append({'bindings': bindings, 'fixed_calls': model['fixed_calls'],
                             'response_transforms': [transform],
                             'evidence': {'kind': 'reviewed_compiled_consumer_graph', 'function': hex(function),
                                          'model': filename, 'review_report': model['review_report'],
                                          'functions_checked': len(bound), 'bridge_origin': origin,
                                          'response_transforms': [transform],
                                          'assumptions': ['Conditional successful path with initialized Context/Activity and JNI bridge.',
                                                          'Standard Dart VM stubs, collection, JSON, UTF-8 and Base64 library semantics.',
                                                          'Exact network/cache provenance and runtime execution are not established.']}})
            if callers:
                findings[-1]['evidence']['outer_callers'] = callers
        except (Unmodeled, KeyError, IndexError, ValueError) as error:
            diagnostics.append({'function': hex(function), 'diagnostic': str(error)})
    if len(findings) > 1: return [], [{'diagnostic': 'ambiguous packed consumer graphs'}]
    return findings, diagnostics
