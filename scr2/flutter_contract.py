"""Symbolic values and bounded ARM64 consumer slices for Flutter response contracts.

No application hashes, addresses, key positions or obfuscated names are selectors.
Unknown transformations remain explicit symbolic calls, rather than identities.
"""
from dataclasses import dataclass, field
import json
import re


@dataclass(eq=False)
class Value:
    kind: str
    args: tuple = ()
    fields: dict = field(default_factory=dict)
    cid: int | None = None

    def brief(self, depth=0):
        if depth > 5:
            return self.kind
        return [self.kind, *[a.brief(depth + 1) if isinstance(a, Value) else a for a in self.args]]


def reg(name):
    return 'x' + name[1:] if name.startswith('w') else name


def imm(value):
    return int(value.lstrip('#'), 0)


class Slice:
    def __init__(self, program, bindings, boundary=None):
        self.p = program
        self.bindings = bindings
        self.boundary = boundary
        self.classifications = {}
        self.events = []
        self.unknown = []
        self.allocations = {}
        self.guards = []
        self.transfers = []
        self.builtins = program.metadata.get('builtins', {})
        self.decimal = program.decimal_helpers()
        self.string_cid = next((program.metadata['objects'].get(offset) for offset, value in program.pool.items()
                                if value.startswith('String: "') and value.endswith('"') and value.isascii()
                                and offset in program.metadata['objects']), None)

    def closure_targets(self, f):
        return [int(m, 16) for a in self.p.functions[f]
                for m in re.findall(r'Closure:.*?\(0x([0-9a-f]+)\)', self.p.refs.get(a, ''))]

    def dispatch_selector(self, f):
        constants = {}; selectors = []
        for a in self.p.functions[f]:
            op, args = self.p.code[a]; parts = args.split(', ')
            if op == 'mov' and len(parts) == 2 and parts[1].startswith('#'):
                constants[parts[0]] = imm(parts[1])
            if op in ('add', 'sub') and parts[:2] == ['x30', 'x0']:
                value = imm(parts[2]) if parts[2].startswith('#') else constants.get(parts[2])
                if value is not None:
                    if len(parts) == 4 and parts[3].startswith('lsl #'):
                        value <<= imm(parts[3][4:])
                    if self.p.code.get(a + 4) == ('ldr', 'x30, [x21, x30, lsl #3]'):
                        selectors.append(value if op == 'add' else -value)
        return selectors

    def classify(self, f):
        if f in self.classifications:
            return self.classifications[f]
        literals = {v['literal'] for v in self.p.context(f, 6)[0]}
        native = {b['symbol'] for b in self.p.reachable_bindings(f, self.bindings)}
        kind = None
        body = [self.p.code[a] for a in self.p.functions[f]]
        if {'allocateDirect', 'java/nio/ByteBuffer'} <= literals and 'globalEnv_GetDirectBufferAddress' in native:
            kind = 'buffer'
        elif 'getActivity' in literals and 'globalEnv_CallStaticObjectMethod' in literals:
            kind = 'activity'
        elif 'globalEnv_GetObjectClass' in native:
            kind = 'get_class'
        elif 'globalEnv_NewObjectA' in native:
            kind = 'construct'
        elif 'globalEnv_GetMethodID' in native:
            kind = 'constructor_id' if '<init>' in literals else 'method_id'
        elif 'FindClass' in literals:
            kind = 'class_name'
        elif 'globalEnv_NewString' in native:
            kind = 'java_string'
        elif ('mov', 'x0, x2') in body[:16] and ('stur', 'w0, [x1, #7]') in body[:16]:
            kind = 'reference_store'
        elif ('stur', 'wzr, [x3, #0xb]') in body and ('mov', 'x0, x3') in body:
            kind = 'list_create'
        else:
            closures = self.closure_targets(f)
            selectors = [(c, self.dispatch_selector(c)) for c in closures]
            selectors = [(c, s[0]) for c, s in selectors if len(s) == 1]
            if len(selectors) == 1:
                # This remains a candidate until the supplied constant adapter's
                # actual dispatch entry resolves to the required JNI operation.
                kind = ('adapter_call', *selectors[0])
        self.classifications[f] = kind
        return kind

    def allocation(self, f):
        if f in self.allocations:
            return self.allocations[f]
        instructions = [self.p.code.get(f + i * 4) for i in range(3)]
        result = None
        if instructions[0] and instructions[1] and instructions[2]:
            a, b, c = instructions
            if (a[0] == 'mov' and a[1].startswith('x2, #') and b[0] == 'movk' and b[1].startswith('x2, #') and
                    c[0] == 'b' and self.p.metadata['stubs'].get(imm(c[1])) in ('AllocateObjectStub', 'AllocateObjectParameterizedStub')):
                base = imm(a[1].split(', ')[1]); parts = b[1].split(', ')
                tag = base | (imm(parts[1]) << imm(parts[2][4:]))
                result = (tag >> 12) & 0xfffff
        self.allocations[f] = result
        return result

    def literal(self, address):
        text = self.p.refs[address]
        offset = self.p.ref_offsets[address]
        if text.startswith('String: '):
            return Value('string', (json.loads(text[8:]),), cid=self.p.metadata['objects'].get(offset))
        m = re.search(r'Closure:.*?\(0x([0-9a-f]+)\)', text)
        if m:
            return Value('function', (int(m[1], 16),))
        if text == 'Null':
            return None
        return Value('pool', (offset, text), cid=self.p.metadata['objects'].get(offset))

    def load(self, base, offset):
        if isinstance(base, Value):
            if offset in base.fields:
                return base.fields[offset]
            if offset == -1 and base.cid is not None:
                return base.cid << 12
            return Value('member', (base, offset))
        return None

    def expected_type(self, pc):
        for address in range(pc + 4, pc + 180, 4):
            value = self.p.refs.get(address, '')
            if value in ('Type: String', 'Type: List', 'Type: Map'):
                return value[6:].lower()
            if self.p.code.get(address, ('',))[0] == 'bl':
                break
        return None

    def run(self, f, accesses):
        access_by_pc = {int(a['access_va'], 16): a for a in accesses}
        registers = {'x22': None}; frame = {}; stack = {}; constants = {}
        addresses = self.p.functions[f]
        first = min(access_by_pc) if access_by_pc else f
        # Values before the first selected access are explicitly unbound. They
        # cannot establish a network origin merely by being named "response".
        for a in accesses:
            if a['receiver'][0] == 'frame' and a['receiver'][1].startswith('#'):
                slot = imm(a['receiver'][1]); frame[slot] = Value('input_frame', (slot,))
        preference_root = None
        if self.boundary:
            # This wire-object identity is supplied only by the independently
            # checked map/write/read boundary, never by a getter's name alone.
            preference_root = Value('field', (Value('input_frame', ('preferences_wire',)),
                                             self.boundary['outer_key'],
                                             int(self.boundary['outer_access_va'], 16)))
            preference_root.fields['expected_type'] = 'map'
        pc = first; seen = set(); steps = 0; comparison = None
        while pc in self.p.code and self.p.owner(pc) == f and pc not in seen and steps < 12000:
            seen.add(pc); steps += 1
            op, args = self.p.code[pc]; parts = args.split(', '); dst = reg(parts[0]); next_pc = pc + 4
            if pc in self.p.refs:
                registers[dst] = self.literal(pc)
            elif pc in access_by_pc:
                access = access_by_pc[pc]
                receiver = registers.get('x1')
                if receiver is None and access['receiver'][0] == 'frame':
                    receiver = frame.get(imm(access['receiver'][1]))
                if preference_root is not None:
                    receiver = preference_root
                expected = access.get('expected_type') if self.boundary else self.expected_type(pc)
                result = Value('field', (receiver, access['key'], pc), cid=self.builtins.get(expected))
                result.fields['expected_type'] = expected
                registers = {'x22': None, 'x0': result}
                self.events.append({'pc': pc, 'kind': 'field', 'value': result})
            elif op == 'mov':
                registers[dst] = imm(parts[1]) if parts[1].startswith('#') else registers.get(reg(parts[1]))
            elif op == 'movk':
                shift = imm(parts[2][4:]) if len(parts) > 2 else 0
                old = registers.get(dst)
                registers[dst] = ((old & ~(0xffff << shift)) | (imm(parts[1]) << shift)) if isinstance(old, int) else None
            elif op in ('ldr', 'ldur', 'str', 'stur'):
                if op == 'ldr' and args == 'x30, [x21, x30, lsl #3]':
                    registers['x30'] = self.p.metadata['dispatch'].get(registers.get('x30'))
                    pc = next_pc
                    continue
                m = re.fullmatch(r'[xw]\d+, \[(x\d+)(?:, (#[^\]]+|x\d+))?\]', args)
                if m:
                    base_reg, displacement = m[1], m[2] or '#0'
                    offset = imm(displacement) if displacement.startswith('#') else registers.get(displacement)
                    if isinstance(offset, int):
                        memory = frame if base_reg == 'x29' else stack if base_reg == 'x15' else None
                        base = registers.get(base_reg)
                        if op in ('str', 'stur'):
                            if memory is not None: memory[offset] = registers.get(dst)
                            elif isinstance(base, Value): base.fields[offset] = registers.get(dst)
                        else:
                            registers[dst] = memory.get(offset) if memory is not None else self.load(base, offset)
                    elif op in ('ldr', 'ldur'):
                        registers[dst] = None
                elif op in ('ldr', 'ldur') and dst != 'x30':
                    registers[dst] = None
            elif op == 'stp':
                m = re.fullmatch(r'(x\d+), (x\d+), \[(x15|x29)(?:, #(0x[0-9a-f]+|-?\d+))?\]', args)
                if m:
                    memory = stack if m[3] == 'x15' else frame; offset = imm(m[4] or '0')
                    memory[offset] = registers.get(m[1]); memory[offset + 8] = registers.get(m[2])
            elif op in ('add', 'sub'):
                # Compressed-pointer decompression preserves symbolic identity.
                if len(parts) == 4 and parts[2] == 'x28' and parts[3] == 'lsl #32':
                    registers[dst] = registers.get(reg(parts[1]))
                elif dst not in ('x15', 'x29'):
                    left = registers.get(reg(parts[1])); right = imm(parts[2]) if parts[2].startswith('#') else registers.get(reg(parts[2]))
                    if isinstance(right, int) and len(parts) > 3 and parts[3].startswith('lsl #'): right <<= imm(parts[3][4:])
                    registers[dst] = (left + right if op == 'add' else left - right) if isinstance(left, int) and isinstance(right, int) else None
            elif op in ('ubfx', 'sbfx', 'sbfiz'):
                value = registers.get(reg(parts[1])); shift = imm(parts[2]); width = imm(parts[3])
                if isinstance(value, int):
                    registers[dst] = (value >> shift) & ((1 << width) - 1) if op != 'sbfiz' else value << shift
                else: registers[dst] = None
            elif op == 'bl':
                target = imm(args)
                result = self.call(pc, target, dict(registers), dict(stack))
                # The Dart allocation fast stubs explicitly preserve other values.
                if self.allocation(target) is None and not self.is_allocator(target):
                    registers = {'x22': None}
                registers['x0'] = result
            elif op == 'blr':
                result = self.indirect(pc, dict(registers), dict(stack))
                registers = {'x22': None, 'x0': result}
            elif op == 'b':
                target = imm(args)
                if target > pc: next_pc = target
                else: break
            elif op == 'ret':
                break
            elif op == 'ldp' and args.startswith('x29, x30, [x15]'):
                # Cold throw blocks follow the function's epilogue.
                break
            elif op == 'cmp':
                left = registers.get(reg(parts[0])); right = imm(parts[1]) if parts[1].startswith('#') else registers.get(reg(parts[1]))
                comparison = None
                if len(parts) == 2 and isinstance(left, int) and isinstance(right, int):
                    comparison = (left, right)
                elif len(parts) == 2 and isinstance(left, Value) and isinstance(right, Value) and left is right:
                    comparison = (1, 1)
                elif len(parts) == 2 and isinstance(left, Value) and reg(parts[1]) == 'x22':
                    comparison = (1, 0)
            elif op in ('tst', 'tbz', 'tbnz', 'cbz', 'cbnz') or op.startswith('b.'):
                # This is a conditional success-path abstraction, not a runtime
                # execution proof. Retain every branch assumption in the output.
                if op != 'tst':
                    taken = None; conditional = False
                    if op.startswith('b.') and comparison is not None:
                        left, right = comparison
                        tests = {'eq': left == right, 'ne': left != right, 'ls': left <= right, 'hi': left > right,
                                 'lt': left < right, 'ge': left >= right, 'le': left <= right, 'gt': left > right,
                                 'hs': left >= right, 'lo': left < right}
                        taken = tests.get(op[2:])
                    elif op in ('tbz', 'tbnz'):
                        value = registers.get(reg(parts[0])); bit = imm(parts[1])
                        if isinstance(value, Value) and value.kind == 'list_empty_test' and bit == 4:
                            # Select a nonempty input list. Keep this a condition,
                            # not a claim about the bytes received at runtime.
                            taken = op == 'tbnz'; conditional = True
                        if isinstance(value, Value) and bit == 0: value = 1
                        if isinstance(value, int): taken = bool(value & (1 << bit)) == (op == 'tbnz')
                    elif op in ('cbz', 'cbnz') and isinstance(registers.get(reg(parts[0])), int):
                        taken = (registers[reg(parts[0])] == 0) == (op == 'cbz')
                    if taken:
                        target = imm(parts[-1])
                        if target <= pc: break
                        next_pc = target
                    self.guards.append({'address': hex(pc), 'instruction': op + ' ' + args,
                                        'selected_edge': 'branch' if taken else 'fallthrough',
                                        'status': 'resolved_for_test_input' if taken is not None and not conditional else 'path_condition'})
                else:
                    comparison = None
            elif dst.startswith('x'):
                registers[dst] = None
            pc = next_pc
        return self.events

    def is_allocator(self, target):
        return self.p.metadata['stubs'].get(target, '').startswith('Allocate')

    def call(self, pc, target, registers, stack):
        r = lambda n: registers.get('x' + str(n))
        if target in self.decimal:
            value = stack.get(0)
            return Value('string', (str(value // 2),), cid=self.string_cid) if isinstance(value, int) and value % 2 == 0 else None
        cid = self.allocation(target)
        if cid is not None or self.is_allocator(target):
            if isinstance(r(1), Value) and r(1).kind == 'function':
                return Value('closure', (r(1).args[0], r(2)))
            stub = self.p.metadata['stubs'].get(target, '')
            if stub == 'AllocateUint8ArrayStub': cid = self.builtins.get('uint8')
            return Value('allocation', (pc, target), cid=cid)
        kind = self.classify(target)
        if kind == 'class_name' and isinstance(r(1), Value):
            r(1).fields['class'] = r(2)
            result = r(1)
        elif kind in ('constructor_id', 'method_id'):
            result = Value('method', (r(1), '<init>' if kind == 'constructor_id' else r(2), r(2) if kind == 'constructor_id' else r(3)))
        elif kind == 'get_class': result = Value('class_of', (r(1),))
        elif kind == 'activity': result = Value('activity', (pc,))
        elif kind == 'buffer': result = Value('buffer', (r(1),))
        elif kind == 'java_string': result = Value('java_string', (r(1),))
        elif kind == 'reference_store' and isinstance(r(1), Value):
            r(1).fields[7] = r(2)
            result = None
        elif kind == 'list_create' and r(2) == 0:
            result = Value('empty_list')
        elif kind == 'construct': result = Value('construct', (stack.get(8), stack.get(16), stack.get(0)))
        elif isinstance(kind, tuple) and kind[0] == 'adapter_call':
            adapter = stack.get(8)
            address = self.p.metadata['dispatch'].get(adapter.cid + kind[2]) if isinstance(adapter, Value) and adapter.cid is not None else None
            result = Value('invoke', (stack.get(24), stack.get(16), stack.get(0), address))
        else:
            result = Value('call', (pc, target, tuple(registers.get('x' + str(i)) for i in range(1, 7))))
            # Recognize a bounded byte-range copy by its byte stores and explicit
            # source/destination arguments. Preserve the converter as evidence.
            body = [self.p.code[a] for a in self.p.functions[target]]
            if (isinstance(r(1), Value) and r(1).cid == self.builtins.get('uint8') and
                    r(2) == 0 and r(6) == 0 and isinstance(r(5), Value) and r(5).kind == 'materialized' and
                    any(op == 'strb' for op, _ in body) and any(op == 'sbfx' for op, _ in body)):
                r(1).fields['byte_source'] = r(5)
                r(1).fields['copy_function'] = target
                self.transfers.append({'call': hex(pc), 'function': hex(target), 'operation': 'uint8_range_copy'})
        self.events.append({'pc': pc, 'target': target, 'kind': kind, 'registers': registers, 'stack': stack, 'value': result})
        return result

    def indirect(self, pc, registers, stack):
        # Resolve the actual dispatch target when the receiver's CID is known.
        table = registers.get('x30')
        original = stack.get(0)
        if table is None and isinstance(original, Value) and original.kind == 'field' and original.cid is None:
            # A field used through toString may legitimately be a String. Resolve
            # that concrete compatible input type, rather than assuming every
            # unknown virtual call is an identity.
            constants = {}
            for a in range(pc - 24, pc, 4):
                op, args = self.p.code.get(a, ('', '')); parts = args.split(', ')
                if op == 'mov' and len(parts) == 2 and parts[1].startswith('#'):
                    constants[parts[0]] = imm(parts[1])
                if op in ('add', 'sub') and parts[:2] == ['x30', 'x0']:
                    delta = imm(parts[2]) if parts[2].startswith('#') else constants.get(parts[2])
                    if delta is not None:
                        table = self.p.metadata['dispatch'].get(self.string_cid + (delta if op == 'add' else -delta))
        if table in self.p.code:
            if self.p.code.get(table) == ('ldr', 'x0, [x15]') and self.p.code.get(table + 4) == ('ret', ''):
                self.transfers.append({'call': hex(pc), 'function': hex(table), 'operation': 'identity_toString'})
                return original
            body = [self.p.code[a] for a in self.p.functions[table]]
            receiver = registers.get('x1')
            if (isinstance(receiver, Value) and receiver.fields.get('expected_type') == 'list' and
                    body[:1] == [('ldur', 'w2, [x1, #0xb]')] and len(body) >= 6 and
                    body[1] == ('cbz', 'w2, #' + hex(table + 16)) and
                    body[2] == ('add', 'x0, x22, #0x30') and
                    body[3] == ('b', '#' + hex(table + 20)) and
                    body[4:6] == [('add', 'x0, x22, #0x20'), ('ret', '')]):
                self.transfers.append({'call': hex(pc), 'function': hex(table),
                                       'operation': 'list_empty_test', 'condition': 'input list is nonempty'})
                return Value('list_empty_test', (receiver,))
            # List.map stores the receiver and closure in a fresh iterable.
            if (isinstance(original, Value) and original.kind == 'closure' and
                    isinstance(stack.get(8), Value) and
                    ('ldr', 'x1, [x29, #0x18]') in body and ('stur', 'w1, [x0, #0xb]') in body and
                    ('ldr', 'x1, [x29, #0x10]') in body and ('stur', 'w1, [x0, #0xf]') in body):
                allocations = [self.allocation(imm(args)) for op, args in body if op == 'bl']
                allocations = [c for c in allocations if c is not None]
                if len(allocations) == 1:
                    return Value('mapped', (stack[8], original, table), cid=allocations[0])
            receiver = registers.get('x1')
            if isinstance(receiver, Value) and receiver.kind == 'mapped':
                # Materialization must allocate a growable list; unknown methods
                # retain their identity rather than silently passing data through.
                targets = set(self.p.edges[table])
                for _ in range(2):
                    targets.update(t for f in list(targets) for t in self.p.edges[f])
                if any(self.p.metadata['stubs'].get(t) == 'AllocateGrowableArrayStub' for t in targets):
                    return Value('materialized', (receiver, table), cid=self.builtins.get('list'))
        return Value('indirect', (pc, registers.get('x1'), original))


class Unresolved(ValueError):
    pass


def require(test, reason):
    if not test:
        raise Unresolved(reason)


def node(value, kind):
    require(isinstance(value, Value) and value.kind == kind, 'expected ' + kind)
    return value.args


def arguments(value):
    require(isinstance(value, Value), 'unresolved argument list')
    if value.kind == 'empty_list':
        return []
    require(value.kind == 'allocation', 'unrecognized argument container')
    size = value.fields.get(11)
    require(type(size) is int and size % 2 == 0 and 0 <= size <= 32, 'unresolved argument count')
    storage = value.fields.get(15)
    require(isinstance(storage, Value) and storage.kind == 'allocation', 'unresolved argument storage')
    result = [storage.fields.get(15 + i * 4) for i in range(size // 2)]
    require(all(isinstance(v, Value) for v in result), 'unresolved argument value')
    return result


def field_path(value):
    result = []; root = value
    for _ in range(32):
        if isinstance(root, Value) and root.kind == 'field':
            parent, key, _ = root.args
            result.insert(0, key); root = parent
        else:
            break
    require(result and isinstance(root, Value) and root.kind == 'input_frame', 'unresolved field root')
    return result, root


def reachable(program, root, depth=5):
    pending = [(root, 0)]; seen = set()
    while pending and len(seen) < 256:
        f, d = pending.pop(0)
        if f in seen: continue
        seen.add(f)
        if d < depth: pending.extend((t, d + 1) for t in sorted(program.edges[f]) if t not in seen)
    require(not pending, 'helper graph budget exhausted')
    return seen


def check_mapper(slice_, mapped):
    source, closure, map_target = node(mapped, 'mapped')
    require(isinstance(source, Value) and source.fields.get('expected_type') == 'list', 'byte input is not a List')
    mapper, _ = node(closure, 'closure')
    functions = reachable(slice_.p, mapper, 3)
    literals = {v for f in functions for _, v in slice_.p.literals[f]}
    require({'Invalid number', 'Invalid radix-'} <= literals, 'unresolved decimal element conversion')
    selectors = slice_.dispatch_selector(mapper)
    require(len(selectors) == 1, 'unresolved element toString dispatch')
    target = slice_.p.metadata['dispatch'].get(slice_.string_cid + selectors[0])
    require(slice_.p.code.get(target) == ('ldr', 'x0, [x15]') and
            slice_.p.code.get(target + 4 if target else 0) == ('ret', ''), 'unsupported string element conversion')
    body = [slice_.p.code[a] for a in slice_.p.functions[mapper]]
    require(('mov', 'x1, x0') in body and any(op == 'sbfiz' for op, _ in body), 'unrecognized integer mapper result')
    return source, {'mapper': hex(mapper), 'map_dispatch': hex(map_target), 'element_conversion': 'decimal_parse_of_toString'}


def match_contract(slice_, invocation, function):
    """Bind roles by receiver/argument identities, never key order or addresses.

    The result is a conditional static test contract. Success-path branch
    conditions and standard JNI/library semantics are explicit assumptions.
    """
    program = slice_.p
    method, instance, argv, adapter = node(invocation, 'invoke')
    require(adapter in program.code, 'missing entry adapter dispatch')
    symbols = {b['symbol'] for b in program.reachable_bindings(adapter, slice_.bindings)}
    require('globalEnv_CallVoidMethodA' in symbols, 'entry is not a void JNI invocation')
    klass, entry_name, entry_desc = node(method, 'method')
    payload_class, payload_ctor, payload_args = node(instance, 'construct')
    require(klass is payload_class and arguments(payload_args) == [], 'payload instance/class mismatch')
    ctor_class, ctor_name, ctor_desc = node(payload_ctor, 'method')
    require(ctor_class is klass and ctor_name == '<init>', 'payload constructor mismatch')
    entry_args = arguments(argv)
    require(len(entry_args) == 1, 'entry must receive one Activity')
    activity = entry_args[0]; node(activity, 'activity')
    reference = klass.fields.get(7)
    class_result, ref_offset = node(reference, 'member')
    require(ref_offset == 7, 'unsupported JNI reference wrapper')
    load_method, loader, load_args, load_adapter = node(class_result, 'invoke')
    require('globalEnv_CallObjectMethodA' in {b['symbol'] for b in program.reachable_bindings(load_adapter, slice_.bindings)},
            'class loading adapter is unresolved')
    load_class, load_name, load_desc = node(load_method, 'method')
    loader_class, loader_ctor, loader_args = node(loader, 'construct')
    require(load_class is loader_class, 'loadClass receiver/class mismatch')
    lc, init, loader_desc = node(loader_ctor, 'method')
    require(lc is loader_class and init == '<init>', 'loader constructor mismatch')
    ca = arguments(load_args)
    require(len(ca) == 1, 'loadClass needs one class-name argument')
    payload_name, = node(ca[0], 'java_string')
    la = arguments(loader_args)
    require(len(la) == 2, 'loader needs buffer and parent arguments')
    byte_array, = node(la[0], 'buffer')
    require(byte_array.cid == slice_.builtins.get('uint8'), 'unsupported DEX backing type')
    materialized, = (byte_array.fields.get('byte_source'),)
    mapped, materializer = node(materialized, 'materialized')
    dex, byte_evidence = check_mapper(slice_, mapped)
    parent_method, parent_receiver, parent_args, parent_adapter = node(la[1], 'invoke')
    require(parent_receiver is activity and arguments(parent_args) == [], 'parent receiver or arguments mismatch')
    require('globalEnv_CallObjectMethodA' in {b['symbol'] for b in program.reachable_bindings(parent_adapter, slice_.bindings)},
            'parent adapter is unresolved')
    pc, parent_name, parent_desc = node(parent_method, 'method')
    require(node(pc, 'class_of')[0] is activity, 'parent class differs from Activity class')
    roles = [
        ('loader_class', loader_class.fields.get('class'), 'dalvik/system/InMemoryDexClassLoader'),
        ('dex_bytes', dex, 'DEX ARRAY'),
        ('loader_constructor', loader_desc, '(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V'),
        ('parent_method', parent_name, 'getClassLoader'),
        ('parent_descriptor', parent_desc, '()Ljava/lang/ClassLoader;'),
        ('load_method', load_name, 'loadClass'),
        ('load_descriptor', load_desc, '(Ljava/lang/String;)Ljava/lang/Class;'),
        ('payload_class', payload_name, {'contract': 'payload_class'}),
        ('payload_constructor', ctor_desc, '()V'),
        ('entry_method', entry_name, {'contract': 'entry_method'}),
        ('entry_descriptor', entry_desc, {'contract': 'entry_descriptor'}),
    ]
    bindings = []; paths = set(); roots = set(); parents = set()
    for role, value, chosen in roles:
        path, root = field_path(value)
        require(tuple(path) not in paths, 'conflicting semantic roles share a response field')
        paths.add(tuple(path)); roots.add(id(root)); parents.add(id(value.args[0]))
        bindings.append({'role': role, 'path': path, 'value': chosen,
                         'provenance': 'conditional_static_consumer_inference',
                         'evidence': {'access_va': hex(value.args[2]), 'consumer_function': hex(function)}})
    require(len(roots) == 1 and len(parents) == 1, 'fields come from different response objects')
    root_object = roles[0][1].args[0]
    require(root_object.fields.get('expected_type') == 'map', 'unresolved response map guard')
    # Ensure JNI provider context exists in the actual helper graph. This is
    # recorded as a library-semantic assumption, not arbitrary receiver proof.
    helper_roots = {e['target'] for e in slice_.events if e.get('kind') in
                    ('class_name', 'constructor_id', 'method_id', 'construct', 'get_class', 'buffer')}
    require(any('GetGlobalEnv' == h['literal'] for f in helper_roots for h in program.context(f, 8)[0]),
            'unresolved JNI table provider context')
    # Identify JSON parsing and request-building context independently of field
    # roles. Do not label call-graph proximity as verified network byte provenance.
    parser_function = int(slice_.boundary['network_function'], 16) if slice_.boundary else function
    prior_calls = [imm(program.code[a][1]) for a in program.functions[parser_function]
                   if a < root_object.args[2] and program.code[a][0] == 'bl']
    parser_context = []
    for target in dict.fromkeys(prior_calls):
        fs = reachable(program, target, 4)
        literals = {v for f in fs for _, v in program.literals[f]}
        if {'Unterminated string', 'Unexpected character'} <= literals:
            parser_context.append(hex(target))
    require(parser_context, 'JSON parser context not established')
    result = {'bindings': bindings, 'fixed_calls': [],
            'evidence': {'kind': 'conditional_static_consumer_contract', 'function': hex(function),
                         'parser_candidates': parser_context, 'byte_conversion': byte_evidence,
                         'materializer': hex(materializer), 'copy_function': hex(byte_array.fields['copy_function']),
                         'object_adapter': hex(load_adapter), 'void_adapter': hex(adapter),
                         'path_conditions': slice_.guards, 'transfers': slice_.transfers,
                         'assumptions': ['Successful type checks, initialized Activity/JNI bridge, and no exception on the selected path.',
                                         'Standard Dart collection/decimal conversion and exported dartjni bridge semantics.',
                                         'JSON/request call context is available; exact network-body provenance is not proven.',
                                         'Offline inference does not establish runtime acceptance or execution.']}}
    if slice_.boundary:
        result['evidence']['preferences_boundary'] = slice_.boundary
        result['evidence']['assumptions'].extend(slice_.boundary['assumptions'])
    return result


def recover_contract(program, function, accesses, bindings, boundary=None):
    require(program.metadata.get('builtins') and program.metadata.get('stubs') and program.metadata.get('dispatch'),
            'metadata-exporting Blutter required (builtins, stubs and dispatch table)')
    slice_ = Slice(program, bindings, boundary)
    slice_.run(function, accesses)
    findings = []; failures = []
    for event in slice_.events:
        value = event['value']
        if isinstance(value, Value) and value.kind == 'invoke':
            try:
                finding = match_contract(slice_, value, function)
                finding['evidence']['entry_call'] = hex(event['pc'])
                finding['evidence']['path_conditions'] = [g for g in slice_.guards if int(g['address'], 16) < event['pc']]
                findings.append(finding)
            except Unresolved as error:
                failures.append(str(error))
    require(len(findings) == 1, 'no unique supported consumer contract: ' + '; '.join(dict.fromkeys(failures)))
    return findings[0]
