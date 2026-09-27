#!/usr/bin/env python3
"""Bounded, offline Dalvik data-flow analysis. No app code is executed.

Androguard decodes instructions; the interpreter below models only explicitly supported
operations. Schema roles come from consumers and object provenance, never string proximity.
Unknown calls/operations do not acquire modeled semantics from an app's chosen name.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from collections import defaultdict, deque

UNKNOWN = ('unknown',)
ACTIVITY = ('activity',)
PARENT = ('parent',)


def const(value):
    return ('const', value)


def literal(value):
    return value[1] if isinstance(value, tuple) and value[0] == 'const' else None


def types(descriptor):
    return re.findall(r'\[*L[^;]+;|\[*[ZBCSIJFDV]', descriptor.replace(' ', ''))


def ref(owner, name, descriptor):
    return owner + '->' + name + descriptor.replace(' ', '')


def field(parent, key):
    if isinstance(parent, tuple) and parent[0] == 'field' and isinstance(key, (str, int)):
        return ('field', parent[1] + (key,), parent[2])
    if isinstance(parent, tuple) and parent[0] == 'split' and type(key) is int and 0 <= key < 32:
        return ('piece', parent[1], parent[2], key)
    return UNKNOWN


def sequence(value):
    # Dalvik uses const/4 0 for a null varargs array; reflection treats it as no args.
    if value == const(0) or value == const(None):
        return []
    if isinstance(value, dict) and value.get('kind') == 'array':
        size = literal(value.get('size', UNKNOWN))
        if type(size) is int and 0 <= size <= 32 and set(value['items']) == set(range(size)):
            return [value['items'][index] for index in range(size)]
    return None


class Unsupported(Exception):
    pass


class Analyzer:
    def __init__(self, dex_blobs, max_roots=100, max_steps=40000, contract=None):
        from androguard.core.dex import DEX
        from loguru import logger
        logger.disable('androguard')
        self.methods, self.edges, self.callers = {}, defaultdict(set), defaultdict(set)
        self.findings, self.diagnostics = [], []
        self.steps, self.max_steps, self.max_roots = 0, max_steps, max_roots
        self.declared = set()
        self.final_classes = set()
        self.contract = contract or {'payload_class': 'com.apkdefense.fixture.webview.ResponseEntry', 'entry_method': 'run'}
        for blob in dex_blobs:
            dex = DEX(blob)
            for cls in dex.get_classes():
                self.declared.add(cls.get_name())
                if cls.get_access_flags() & 16:
                    self.final_classes.add(cls.get_name())
            for method in dex.get_encoded_methods():
                code = method.get_code()
                if code is None:
                    continue
                key = ref(method.get_class_name(), method.get_name(), method.get_descriptor())
                if key in self.methods:
                    raise ValueError('Conflicting method definitions across DEX members')
                instructions = {}
                for pc, ins in method.get_instructions_idx():
                    operands = ins.get_operands(pc)
                    instructions[pc] = (ins.get_name(), operands, ins.get_length())
                    if ins.get_name().startswith('invoke'):
                        target = str(operands[-1][-1]).replace(' ', '')
                        self.edges[key].add(target)
                        self.callers[target].add(key)
                self.methods[key] = (code.get_registers_size(), code.get_ins_size(), method.get_access_flags(), instructions)

    def roots(self):
        sinks = {key for key in self.methods if any('DexClassLoader;-><init>' in target or
                 'Ljava/lang/reflect/Constructor;->newInstance' in target for target in self.edges[key])}
        roots, frontier = set(sinks), set(sinks)
        for _ in range(6):
            frontier = {parent for node in frontier for parent in self.callers[node]} - roots
            roots.update(frontier)
        return sorted(roots, key=lambda key: (not any(self.network_call(t) for t in self.edges[key]), key))[:self.max_roots]

    @staticmethod
    def network_call(target):
        return any(target.startswith(prefix) for prefix in (
            'Ljava/net/URL;->open', 'Ljava/net/URLConnection;->getInputStream',
            'Ljava/net/HttpURLConnection;->getInputStream', 'Lokhttp3/ResponseBody;->string',
            'Lokhttp3/ResponseBody;->bytes', 'Lokhttp3/Response;->body'))

    def analyze(self):
        for root in self.roots():
            if self.steps >= self.max_steps:
                self.diagnostics.append('instruction_budget_exhausted')
                break
            descriptor = root[root.index('('):]
            parameters = types(descriptor.split(')')[0])
            args = [ACTIVITY if t == 'Landroid/app/Activity;' else UNKNOWN for t in parameters]
            if not self.methods[root][2] & 8:
                args.insert(0, UNKNOWN)
            try:
                self.execute(root, args, {'constraints': [], 'trace': [], 'root': root}, (), 0)
            except Unsupported as error:
                self.diagnostics.append(str(error))
        distinct = {}
        for finding in self.findings:
            key = json.dumps(finding['bindings'], sort_keys=True)
            distinct[key] = finding
        return {'findings': list(distinct.values()), 'diagnostics': sorted(set(self.diagnostics))[:50],
                'methods_analyzed': len(self.methods), 'instruction_steps': self.steps}

    def require(self, state, value, chosen, role, site):
        if isinstance(value, tuple) and value[0] in ('field', 'piece'):
            state['constraints'].append((value, chosen, role, site))
        elif literal(value) == chosen:
            state['constraints'].append((value, chosen, role, site))
        else:
            raise Unsupported('unresolved_or_incompatible_' + role)

    def execute(self, key, args, state, stack, depth):
        if depth > 8 or key in stack:
            raise Unsupported('recursive_or_deep_app_helper')
        count, incoming, flags, code = self.methods[key]
        registers = {i: UNKNOWN for i in range(count)}
        for i, value in enumerate(args):
            registers[count - incoming + i] = value
        # Each branch owns its registers, object heap (through shared dict references), and
        # constraints. Aliasing survives deepcopy; incompatible paths are never merged.
        queue = deque([(0, registers, UNKNOWN, state, {})])
        returns, states = [], 0
        while queue:
            pc, regs, pending, context, visits = queue.popleft()
            states += 1
            if states > 128:
                raise Unsupported('control_flow_state_budget_exhausted')
            try:
                while pc in code:
                    self.steps += 1
                    if self.steps > self.max_steps:
                        raise Unsupported('instruction_budget_exhausted')
                    visits[pc] = visits.get(pc, 0) + 1
                    if visits[pc] > 2:
                        raise Unsupported('unsummarized_loop')
                    name, operands, length = code[pc]
                    rr = [int(item[1]) for item in operands if int(item[0]) == 0]
                    values = [regs.get(r, UNKNOWN) for r in rr]
                    literals = [item[1] for item in operands if int(item[0]) == 1]
                    site = key + '+' + hex(pc)
                    next_pc = pc + length
                    if name.startswith('move-result'):
                        regs[rr[0]] = pending
                    elif name.startswith('move') and len(rr) >= 2:
                        regs[rr[0]] = values[1]
                    elif name.startswith('const-string'):
                        regs[rr[0]] = const(str(operands[-1][-1]))
                    elif name == 'const-class':
                        regs[rr[0]] = ('type', str(operands[-1][-1]))
                    elif name.startswith('const'):
                        regs[rr[0]] = const(literals[0])
                    elif name == 'new-instance':
                        regs[rr[0]] = {'kind': 'new', 'type': str(operands[-1][-1])}
                    elif name == 'new-array':
                        regs[rr[0]] = {'kind': 'array', 'type': str(operands[-1][-1]), 'size': values[1], 'items': {}}
                    elif name.startswith('filled-new-array'):
                        pending = {'kind': 'array', 'size': const(len(values)), 'items': dict(enumerate(values))}
                    elif name.startswith('aput'):
                        index = literal(values[2])
                        if not isinstance(values[1], dict) or values[1].get('kind') != 'array' or type(index) is not int:
                            raise Unsupported('unknown_array_write')
                        if not 0 <= index < 256:
                            raise Unsupported('array_index_limit')
                        values[1].pop('payload', None)
                        values[1]['items'][index] = values[0]
                    elif name.startswith('aget'):
                        index = literal(values[2])
                        if isinstance(values[1], dict) and values[1].get('kind') == 'array':
                            regs[rr[0]] = values[1]['items'].get(index, UNKNOWN)
                        else:
                            regs[rr[0]] = field(values[1], index)
                    elif name == 'array-length':
                        regs[rr[0]] = values[1].get('size', UNKNOWN) if isinstance(values[1], dict) else (
                            ('payload_length', values[1]) if isinstance(values[1], tuple) and values[1][0] == 'payload' else UNKNOWN)
                    elif name == 'check-cast' or name in ('nop', 'monitor-enter', 'monitor-exit'):
                        pass
                    elif name.startswith('invoke'):
                        target = str(operands[-1][-1]).replace(' ', '')
                        pending = self.call(target, values, context, site, stack + (key,), depth,
                                            static=name.startswith('invoke-static'), dispatch=name)
                    elif name.startswith('return'):
                        returns.append((values[0] if values else const(None), context))
                        break
                    elif name == 'throw':
                        break
                    elif name.startswith('goto'):
                        next_pc = pc + int(operands[-1][1]) * 2
                    elif name.startswith('if-'):
                        loop_exit = self.byte_loop(code, pc, regs)
                        if loop_exit is not None:
                            pc = loop_exit
                            continue
                        target = pc + int(operands[-1][1]) * 2
                        a = literal(values[0])
                        b = literal(values[1]) if len(values) == 2 else 0
                        known = values[0][0] == 'const' if isinstance(values[0], tuple) else False
                        known = known and (len(values) == 1 or isinstance(values[1], tuple) and values[1][0] == 'const')
                        if known:
                            relation = name.split('-')[1].rstrip('z')
                            conditions = {'eq': lambda: a == b, 'ne': lambda: a != b,
                                          'lt': lambda: a < b, 'le': lambda: a <= b,
                                          'gt': lambda: a > b, 'ge': lambda: a >= b}
                            try:
                                if conditions[relation]():
                                    next_pc = target
                            except TypeError:
                                raise Unsupported('incomparable_branch_operands')
                        else:
                            context['unresolved_branch'] = site
                            queue.append(copy.deepcopy((target, regs, pending, context, visits)))
                    elif name.startswith(('add-int', 'sub-int', 'xor-int', 'and-int', 'or-int', 'mul-int')):
                        if '/2addr' in name:
                            a, b = literal(values[0]), literal(values[1])
                        else:
                            a = literal(values[1])
                            b = literals[0] if literals else literal(values[2])
                        functions = {'add': lambda: a + b, 'sub': lambda: a - b, 'xor': lambda: a ^ b,
                                     'and': lambda: a & b, 'or': lambda: a | b, 'mul': lambda: a * b}
                        regs[rr[0]] = const(functions[name.split('-')[0]]()) if type(a) is int and type(b) is int else UNKNOWN
                    elif name.startswith('sget') and str(operands[-1][-1]).endswith('->TYPE Ljava/lang/Class;'):
                        wrapper = str(operands[-1][-1]).split(';')[0] + ';'
                        primitive = {'Ljava/lang/Void;': 'V', 'Ljava/lang/Integer;': 'I', 'Ljava/lang/Boolean;': 'Z'}
                        regs[rr[0]] = ('type', primitive[wrapper]) if wrapper in primitive else UNKNOWN
                    elif name.startswith(('iget', 'sget', 'instance-of')):
                        regs[rr[0]] = UNKNOWN
                    elif name.startswith(('iput', 'sput')):
                        raise Unsupported('unmodeled_field_mutation')
                    else:
                        raise Unsupported('unsupported_instruction:' + name)
                    pc = next_pc
            except Unsupported as error:
                self.diagnostics.append(str(error))
        if not returns:
            raise Unsupported('no_modeled_helper_return:' + key)
        # Caller continuation is only sound when helper paths return the same symbolic
        # value and constraints. Separate entry analyses can still yield independent findings.
        first_value, first_context = returns[0]
        if any(value != first_value or ctx['constraints'] != first_context['constraints'] for value, ctx in returns[1:]):
            raise Unsupported('ambiguous_helper_return')
        state.update(first_context)
        return first_value

    @staticmethod
    def byte_loop(code, pc, regs):
        """Prove the canonical full-array copy loop; do not infer a transform from one store."""
        name, operands, length = code[pc]
        if name != 'if-ge':
            return None
        index, count = operands[0][1], operands[1][1]
        size = regs.get(count, UNKNOWN)
        if regs.get(index) != const(0) or not isinstance(size, tuple) or size[0] != 'json_length':
            return None
        exit_pc = pc + operands[-1][1] * 2
        cursor, body = pc + length, []
        while cursor < exit_pc and len(body) < 8 and cursor in code:
            instruction = code[cursor]
            body.append((cursor, *instruction))
            cursor += instruction[2]
        if cursor != exit_pc or [item[1] for item in body] != [
                'invoke-virtual', 'move-result', 'int-to-byte', 'aput-byte', 'add-int/lit8', 'goto']:
            return None
        source_args = body[0][2]
        if str(source_args[-1][-1]).replace(' ', '') != 'Lorg/json/JSONArray;->getInt(I)I':
            return None
        source_reg, input_index = source_args[0][1], source_args[1][1]
        converted = body[1][2][0][1]
        if input_index != index or regs.get(source_reg) != size[1] or [v[1] for v in body[2][2]] != [converted, converted]:
            return None
        source, dest, output_index = [v[1] for v in body[3][2]]
        if source != converted or output_index != index or [v[1] for v in body[4][2]] != [index, index, 1]:
            return None
        if body[5][0] + body[5][2][-1][1] * 2 != pc:
            return None
        array = regs.get(dest)
        if not isinstance(array, dict) or array.get('type') != '[B' or array.get('size') != size or array.get('items'):
            return None
        array['payload'] = ('payload', size[1], 'integer_array')
        regs[index] = size
        regs[converted] = UNKNOWN
        return exit_pc

    def call(self, target, args, state, site, stack, depth, static=False, dispatch=''):
        owner, rest = target.split('->', 1)
        name = rest.split('(', 1)[0]
        obj = args[0] if args and not static else UNKNOWN
        params = args if static else args[1:]
        # Never assign framework semantics to app-defined lookalikes.
        if target in self.methods:
            if dispatch.startswith(('invoke-virtual', 'invoke-interface')) and owner not in self.final_classes and not self.methods[target][2] & 16:
                raise Unsupported('unresolved_app_virtual_dispatch:' + target)
            return self.execute(target, args, state, stack, depth + 1)
        if owner in self.declared:
            if state.get('files') or any(self.tracked(value) for value in args):
                raise Unsupported('unmodeled_app_method_with_tracked_argument:' + target)
            return UNKNOWN
        if owner == 'Ljava/net/URL;' and name == '<init>' and isinstance(obj, dict):
            url = literal(params[0]) if len(params) == 1 else None
            if isinstance(url, str) and re.match(r'^https?://[^/]+', url):
                obj.update(kind='url', url=url)
            return const(None)
        if owner == 'Ljava/net/URL;' and name in ('openStream', 'openConnection'):
            if isinstance(obj, dict) and obj.get('kind') == 'url':
                return ('network' if name == 'openStream' else 'connection', site, obj['url'])
            return UNKNOWN
        if owner in ('Ljava/net/URLConnection;', 'Ljava/net/HttpURLConnection;') and name == 'getInputStream':
            if isinstance(obj, tuple) and obj[0] == 'connection':
                return ('network', site, obj[2])
            return UNKNOWN
        if owner == 'Ljava/io/InputStream;' and name == 'readAllBytes' and isinstance(obj, tuple) and obj[0] == 'network':
            return obj
        if owner == 'Ljava/lang/String;' and name == '<init>' and isinstance(obj, dict):
            value = params[0] if len(params) in (1, 2) else UNKNOWN
            obj.update(kind='string', value=value)
            return const(None)
        if owner in ('Lorg/json/JSONObject;', 'Lorg/json/JSONArray;'):
            if name == '<init>' and isinstance(obj, dict) and params:
                value = params[0]
                if isinstance(value, dict) and value.get('kind') == 'string':
                    value = value['value']
                if isinstance(value, tuple) and value[0] == 'network':
                    obj.update(kind='json', value=('field', (), value[1]))
                return const(None)
            if name.startswith(('get', 'opt')) and params:
                source = obj['value'] if isinstance(obj, dict) and obj.get('kind') == 'json' else obj
                return field(source, literal(params[0]))
            if owner == 'Lorg/json/JSONArray;' and name == 'length' and isinstance(obj, tuple) and obj[0] == 'field':
                return ('json_length', obj)
        if owner == 'Ljava/lang/String;' and name == 'split' and params:
            pattern = literal(params[0])
            if isinstance(pattern, str) and (re.fullmatch(r'[,:;#/@_-]+', pattern) or pattern in (r'\|', r'\.', r'\$')):
                delimiter = pattern.replace('\\', '')
                return ('split', obj, delimiter)
            raise Unsupported('nonliteral_or_complex_split_regex')
        if owner in ('Ljava/lang/Integer;', 'Ljava/lang/String;') and name in ('toString', 'valueOf'):
            if static and len(params) != 1:
                return UNKNOWN
            source = params[0] if static and params else obj
            value = literal(source)
            return const(str(value)) if value is not None else source
        if owner == 'Landroid/util/Base64;' and name == 'decode' and params:
            if isinstance(params[0], tuple) and params[0][0] == 'field':
                flags = literal(params[1]) if len(params) == 2 else None
                if type(flags) is not int:
                    raise Unsupported('unresolved_base64_flags')
                return ('payload', params[0], 'base64url' if flags & 8 else 'base64')
            return UNKNOWN
        if owner == 'Ljava/nio/ByteBuffer;' and name == 'wrap' and params:
            if len(params) != 1:
                return UNKNOWN
            payload = params[0].get('payload', UNKNOWN) if isinstance(params[0], dict) else params[0]
            return ('buffer', payload)
        if owner == 'Ljava/nio/ByteBuffer;' and name == 'allocateDirect' and len(params) == 1:
            return {'kind': 'byte_buffer', 'payload': UNKNOWN, 'size': params[0]}
        if owner == 'Ljava/nio/ByteBuffer;' and name == 'put' and isinstance(obj, dict) and obj.get('kind') == 'byte_buffer':
            payload, size = UNKNOWN, UNKNOWN
            if len(params) == 1 and isinstance(params[0], dict):
                payload, size = params[0].get('payload', UNKNOWN), params[0].get('size', UNKNOWN)
            elif len(params) == 1 and isinstance(params[0], tuple) and params[0][0] == 'payload':
                payload, size = params[0], ('payload_length', params[0])
            obj['payload'] = payload if size != UNKNOWN and obj['size'] == size and not obj.get('written') else UNKNOWN
            obj.update(written=True, ready=False)
            return obj
        if owner in ('Landroid/app/Activity;', 'Landroid/content/Context;', 'Landroid/content/ContextWrapper;') and name == 'getClassLoader':
            return PARENT if obj == ACTIVITY else UNKNOWN
        if owner == 'Ljava/lang/Object;' and name == 'getClass':
            if obj == ACTIVITY:
                return ('class', const('android.app.Activity'))
            if isinstance(obj, dict) and obj.get('kind') == 'loader':
                return ('runtime_class', obj)
        if owner == 'Ljava/lang/Class;' and name == 'forName' and params:
            return ('class', params[0])
        if owner == 'Ldalvik/system/InMemoryDexClassLoader;' and name == '<init>' and isinstance(obj, dict):
            if len(params) == 2 and params[1] == PARENT:
                if isinstance(params[0], tuple) and params[0][0] == 'buffer':
                    obj.update(kind='loader', payload=params[0][1])
                elif isinstance(params[0], dict) and params[0].get('kind') == 'byte_buffer':
                    # Require explicit rewind/flip before the whole buffer can be treated as input.
                    obj.update(kind='loader', payload=params[0]['payload'] if params[0].get('ready') else UNKNOWN)
            return const(None)
        if owner in ('Ljava/nio/ByteBuffer;', 'Ljava/nio/Buffer;') and name in ('flip', 'rewind') and isinstance(obj, dict) and obj.get('kind') == 'byte_buffer':
            obj['ready'] = True
            return obj
        if owner == 'Ljava/io/FileOutputStream;' and name == '<init>' and isinstance(obj, dict) and params:
            path = literal(params[0])
            if isinstance(path, str):
                empty = len(params) == 1 or len(params) == 2 and literal(params[1]) == 0
                obj.update(kind='file_stream', path=path, empty=empty, written=False)
                state.setdefault('files', {})[path] = UNKNOWN
            return const(None)
        if owner in ('Ljava/io/FileOutputStream;', 'Ljava/io/OutputStream;') and name == 'write' and isinstance(obj, dict) and obj.get('kind') == 'file_stream':
            if len(params) == 1 and obj['empty'] and not obj['written']:
                payload = params[0].get('payload', UNKNOWN) if isinstance(params[0], dict) else params[0]
                state.setdefault('files', {})[obj['path']] = payload
            else:
                state.setdefault('files', {})[obj['path']] = UNKNOWN
            obj['written'] = True
            return const(None)
        if owner in ('Ljava/io/FileOutputStream;', 'Ljava/io/OutputStream;') and name in ('close', 'flush'):
            return const(None)
        if owner == 'Ldalvik/system/DexClassLoader;' and name == '<init>' and isinstance(obj, dict) and len(params) == 4:
            if params[3] == PARENT:
                obj.update(kind='loader', payload=state.get('files', {}).get(literal(params[0]), UNKNOWN))
            return const(None)
        if owner in ('Ljava/lang/ClassLoader;', 'Ldalvik/system/InMemoryDexClassLoader;', 'Ldalvik/system/DexClassLoader;') and name == 'loadClass':
            if isinstance(obj, dict) and obj.get('kind') == 'loader':
                return {'kind': 'payload_class', 'name': params[0], 'payload': obj['payload']}
        if owner == 'Ljava/lang/Class;' and name in ('getMethod', 'getDeclaredMethod'):
            return {'kind': 'method', 'class': obj, 'name': params[0], 'parameters': sequence(params[1])} if len(params) == 2 else UNKNOWN
        if owner == 'Ljava/lang/Class;' and name in ('getConstructor', 'getDeclaredConstructor'):
            return {'kind': 'constructor', 'class': obj, 'parameters': sequence(params[0])} if len(params) == 1 else UNKNOWN
        if owner == 'Ljava/lang/Class;' and name == 'newInstance' and isinstance(obj, dict) and obj.get('kind') == 'payload_class':
            return {'kind': 'payload_object', 'class': obj}
        if owner == 'Ljava/lang/reflect/Constructor;' and name == 'newInstance' and isinstance(obj, dict) and obj.get('kind') == 'constructor':
            values = sequence(params[0]) if params else None
            cls = obj['class']
            if isinstance(cls, dict) and cls.get('kind') == 'payload_class' and values == []:
                return {'kind': 'payload_object', 'class': cls}
            if isinstance(cls, tuple) and cls[0] == 'class' and values and len(values) == 2:
                if obj['parameters'] == [('type', 'Ljava/nio/ByteBuffer;'), ('type', 'Ljava/lang/ClassLoader;')] and values[1] == PARENT:
                    self.require(state, cls[1], 'dalvik.system.InMemoryDexClassLoader', 'loader_class', site)
                    if isinstance(values[0], tuple) and values[0][0] == 'buffer':
                        return {'kind': 'loader', 'payload': values[0][1], 'class': cls}
            return UNKNOWN
        if owner == 'Ljava/lang/reflect/Method;' and name == 'invoke' and isinstance(obj, dict) and obj.get('kind') == 'method':
            return self.invoke(obj, params, state, site)
        if owner == 'Ljava/lang/reflect/AccessibleObject;' and name == 'setAccessible':
            return const(None)
        if owner == 'Ljava/lang/Object;' and name == '<init>':
            return const(None)
        # Calls that can mutate modeled objects invalidate the current path rather than
        # retaining a stale array/JSON/loader value through an unknown helper.
        if any(self.tracked(value) for value in args):
            raise Unsupported('unknown_call_with_tracked_object:' + target)
        if state.get('files'):
            raise Unsupported('unmodeled_call_after_file_write:' + target)
        return UNKNOWN

    @staticmethod
    def tracked(value):
        return (isinstance(value, dict) and value.get('kind') in ('array', 'json', 'loader', 'payload_class', 'payload_object', 'byte_buffer') or
                isinstance(value, tuple) and value[0] in ('field', 'payload', 'buffer', 'piece', 'split'))

    def invoke(self, method, params, state, site):
        if len(params) != 2:
            return UNKNOWN
        receiver, values = params[0], sequence(params[1])
        cls = method['class']
        if receiver == ACTIVITY and cls == ('class', const('android.app.Activity')) and values == [] and method['parameters'] == []:
            self.require(state, method['name'], 'getClassLoader', 'parent_method', site)
            return PARENT
        if isinstance(receiver, dict) and receiver.get('kind') == 'loader' and values and len(values) == 1:
            if cls in (('runtime_class', receiver), receiver.get('class'), ('class', const('java.lang.ClassLoader'))) and method['parameters'] == [('type', 'Ljava/lang/String;')]:
                self.require(state, method['name'], 'loadClass', 'load_class_method', site)
                return {'kind': 'payload_class', 'name': values[0], 'payload': receiver['payload']}
        if not isinstance(cls, dict) or cls.get('kind') != 'payload_class':
            return UNKNOWN
        if not (isinstance(receiver, dict) and receiver.get('kind') == 'payload_object' and receiver['class'] == cls):
            raise Unsupported('unsupported_static_or_unbound_payload_entry')
        if method['parameters'] != [('type', 'Landroid/app/Activity;')] or values != [ACTIVITY]:
            raise Unsupported('entry_arguments_do_not_match_activity_contract')
        payload = cls['payload']
        if state.get('unresolved_branch'):
            raise Unsupported('unresolved_branch_gate:' + state['unresolved_branch'])
        if not isinstance(payload, tuple) or payload[0] != 'payload' or payload[1][0] != 'field' or not payload[1][1]:
            raise Unsupported('payload_bytes_not_traced_to_json_response')
        selected_class = literal(cls['name']) or self.contract['payload_class']
        selected_entry = literal(method['name']) or self.contract['entry_method']
        if not isinstance(selected_class, str) or selected_class.startswith(('java.', 'javax.', 'android.', 'dalvik.')) or 'L' + selected_class.replace('.', '/') + ';' in self.declared:
            raise Unsupported('payload_class_resolves_to_platform_or_existing_app_class')
        self.require(state, cls['name'], selected_class, 'payload_class', site)
        self.require(state, method['name'], selected_entry, 'entry_method', site)
        state['constraints'].append((payload[1], 'DEX ARRAY', 'dex_bytes', site))
        finding = self.solve(state, payload[1][2], payload[2], selected_class, selected_entry)
        self.findings.append(finding)
        return UNKNOWN

    def solve(self, state, origin, encoding, payload_class, entry_method):
        bindings, fixed, packed = {}, [], {}
        for source, chosen, role, site in state['constraints']:
            if source[0] == 'const':
                fixed.append({'role': role, 'value': chosen, 'evidence': site, 'owner': 'app'})
                continue
            if source[0] == 'piece':
                base, delimiter, index = source[1:]
                if base[0] != 'field' or base[2] != origin:
                    raise Unsupported('packed_field_has_unresolved_origin')
                key = base[1]
                if key not in packed:
                    packed[key] = {'delimiter': delimiter, 'items': {}, 'evidence': []}
                entry = packed[key]
                if entry['delimiter'] != delimiter or index in entry['items'] and entry['items'][index] != chosen:
                    raise Unsupported('conflicting_packed_field_constraints')
                entry['items'][index] = chosen
                entry['evidence'].append(site)
                continue
            if source[0] != 'field' or source[2] != origin:
                raise Unsupported('mixed_or_unresolved_response_origins')
            path = source[1]
            binding = {'path': list(path), 'value': chosen, 'role': role, 'evidence': site,
                       'provenance': 'consumer_dataflow_with_compatible_test_value'}
            if role == 'dex_bytes':
                binding['wire_encoding'] = encoding
            if path in bindings and bindings[path]['value'] != chosen:
                raise Unsupported('conflicting_response_constraints')
            bindings[path] = binding
        for path, info in packed.items():
            indexes = sorted(info['items'])
            if indexes != list(range(len(indexes))) or path in bindings:
                raise Unsupported('incomplete_or_overlapping_packed_field')
            bindings[path] = {'path': list(path), 'encoding': 'join', 'delimiter': info['delimiter'],
                              'values': [info['items'][i] for i in indexes], 'role': 'packed_methods',
                              'evidence': info['evidence'], 'provenance': 'consumer_dataflow'}
        return {'bindings': list(bindings.values()), 'fixed_calls': fixed,
                'contract': {'payload_class': payload_class, 'entry_method': entry_method,
                             'entry_descriptor': '(Landroid/app/Activity;)V'},
                'evidence': {'root_method': state['root'], 'network_source': origin,
                             'engine': 'bounded_dalvik_consumer_dataflow',
                             'claim': 'Network response JSON -> decoded bytes -> DEX class loader -> reflected instance entry(Activity)'}}


def main():
    # Files are private, bounded copies made by the parent archive reader. Never import
    # Python or profile files from an APK, and never launch the decoded bytecode.
    try:
        paths, contract = sys.argv[1:], None
        if paths[:1] == ['--contract']:
            contract = json.loads(paths[1])
            paths = paths[2:]
        blobs = [open(path, 'rb').read() for path in paths]
        print(json.dumps(Analyzer(blobs, contract=contract).analyze()))
    except Exception as error:
        print(json.dumps({'findings': [], 'diagnostics': [type(error).__name__ + ': ' + str(error)]}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
