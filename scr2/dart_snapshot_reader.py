"""Bounded, offline Python reader for a supported Dart full-AOT snapshot format.

No Dart VM, SDK source, compiler, native Blutter or sample-specific metadata is
used. Only structural metadata needed by the existing consumer analysis is
exported; this is not a Dart source decompiler. Unknown layouts fail closed.
"""
from __future__ import annotations
import json
import struct
from flutter_semantic import Unsupported, elf_image, read_va, snapshot_identity
from dart_snapshot_schema import CLASS_NAMES as names, STORE_STUB_NAMES, SNAPSHOT_HASH, SCHEMAS

MAX_OBJECTS = 500_000
MAX_ELEMENTS = 2_000_000
MAX_CLUSTERS = 65_536
MAX_RENDER = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise Unsupported('Python snapshot reader: ' + message)


def symbol(data, name):
    elf, segments = elf_image(data)
    symbols = elf.get_section_by_name('.dynsym')
    hits = symbols.get_symbol_by_name(name) if symbols else None
    require(hits and len(hits) == 1, 'missing or ambiguous ' + name)
    sym = hits[0]
    require(0 < sym['st_size'] <= len(data), 'invalid snapshot symbol size')
    return sym, read_va(data, segments, sym['st_value'], sym['st_size'])


class Reader:

    def __init__(self, data, start=0, schema=None):
        self.data = data
        self.pos = start
        self.ref_limit = MAX_OBJECTS
        self.instructions = 0
        self.instoffset = 0
        self.schema = schema or SCHEMAS[SNAPSHOT_HASH]

    def take(self, size):
        require(0 <= size <= len(self.data) - self.pos, 'truncated snapshot record')
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def byte(self):
        return self.take(1)[0]

    def count(self, limit=MAX_ELEMENTS):
        value = self.read()
        require(value <= limit, 'count exceeds allocation budget')
        return value

    def read(self, marker=128):
        v = 0
        for shift in range(0, 70, 7):
            b = self.byte()
            if b > 127:
                value = v | ((b - marker) << shift)
                require((-2**63 <= value < 2**63) if marker == 192 else (0 <= value < 2**64), 'varint overflow')
                return value
            v |= b << shift
        raise Unsupported('Python snapshot reader: unterminated varint')

    def signed(self):
        return self.read(192)

    def ref(self):
        v = 0
        for i in range(4):
            b = self.byte()
            v = (v << 7) + (b & 127)
            if b > 127:
                require(0 < v <= self.ref_limit, 'reference outside object table')
                return v
        raise Unsupported('Python snapshot reader: unterminated reference')

def cluster_tag(tag, schema):
    """Decode only the tag bits serialized by this reviewed SDK format."""
    tag &= 0xffffffff
    require(tag & 0xfff & ~(2 | schema.immutable_tag) == 0,
            'unsupported cluster tag bits')
    canonical = bool(tag & 2)
    immutable = bool(tag & schema.immutable_tag)
    require(not schema.canonical_requires_immutable or not canonical or immutable,
            'canonical cluster is not deeply immutable')
    return tag >> 12, canonical


def alloc(data, name, base_refs=None, schema=None):
    sym, raw = symbol(data, name)
    require(len(raw) >= 128 and raw[:4] == bytes.fromhex('f5f5dcdc'), 'invalid snapshot magic')
    length, kind = struct.unpack_from('<QQ', raw, 4)
    length += 4
    require(52 < length <= len(raw) and kind == 3, 'requires bounded full-AOT snapshot')
    actual_schema = SCHEMAS.get(raw[20:52].decode('ascii', errors='replace'))
    require(actual_schema is not None, 'unsupported snapshot format')
    require(schema is None or schema == actual_schema, 'VM/isolate snapshot format mismatch')
    schema = actual_schema
    end = raw.find(b'\0', 52, min(length, 1024))
    require(end >= 0, 'unterminated snapshot features')
    flags = raw[52:end].decode('ascii').split()
    require({'product', 'no-code_comments', 'dwarf_stack_traces_mode', 'dedup_instructions', 'no-asan', 'no-msan', 'no-tsan', 'no-shared_data', 'arm64', 'android', 'compressed-pointers'} == set(flags), 'unsupported snapshot features')
    require('no-compressed-pointers' not in flags and 'debug' not in flags, 'unsupported VM layout')
    r = Reader(raw[:length], end + 1, schema)
    base, objects = r.count(MAX_OBJECTS), r.count(MAX_OBJECTS)
    clusters = r.count(MAX_CLUSTERS)
    r.instructions, r.instoffset = r.count(), r.count(len(raw))
    require(0 < clusters <= objects and base < objects, 'invalid object/cluster counts')
    require(base == (len(base_refs) - 1 if base_refs is not None else 99), 'base object table mismatch')
    r.ref_limit = objects
    items = []
    nextref = base + 1
    variable = {'ObjectPool', 'PcDescriptors', 'CodeSourceMap', 'CompressedStackMaps', 'ExceptionHandlers', 'Context', 'ContextScope', 'Array', 'ImmutableArray', 'WeakArray', 'String', 'TypeArguments', 'Record'}
    canonicalsets = {'String', 'TypeArguments', 'Type', 'FunctionType', 'RecordType', 'TypeParameter'}
    for i in range(clusters):
        pos = r.pos
        cid, canonical = cluster_tag(r.signed(), schema)
        name = names[cid] if cid < len(names) else 'Instance'
        c = {'cid': cid, 'name': name, 'canonical': canonical, 'start': nextref, 'offset': pos}
        count = r.count(MAX_OBJECTS)
        c['count'] = count
        require(count <= objects - nextref + 1, 'cluster object count overflow')
        if name == 'Class':
            c['predefined'] = [r.signed() for _ in range(count)]
            c['count'] = count + r.count(MAX_OBJECTS)
        elif name == 'Code':
            c['states'] = [r.signed() for _ in range(count)]
            c['deferred'] = r.count(MAX_OBJECTS)
            require(c['deferred'] == 0, 'deferred loading units are unsupported')
            c['states'] += [r.signed() for _ in range(c['deferred'])]
            c['count'] += c['deferred']
        elif name == 'Instance':
            c['next_field'] = r.signed()
            c['size'] = r.signed()
            require(2 <= c['next_field'] <= c['size'] <= 16384, 'invalid instance layout')
        elif name == 'Mint':
            c['values'] = [r.signed() for _ in range(count)]
        elif name in variable or (name.startswith(('TypedData', 'ExternalTypedData')) and (not name.endswith('View'))) or name == 'NativePointer':
            c['lengths'] = [r.count() for _ in range(count)]
        if name in canonicalsets and canonical and (name != 'String' or base_refs is not None):
            c['table_size'] = r.count()
            c['first'] = r.count(count)
            c['gaps'] = [r.count(c['table_size']) for _ in range(count - c['first'])]
            require(sum(c['gaps']) + len(c['gaps']) <= c['table_size'], 'invalid canonical table layout')
        require(cid >= 4, 'invalid cluster class ID')
        require(c['count'] <= objects - nextref + 1, 'cluster total overflow')
        c['end_offset'] = r.pos
        nextref += c['count']
        items.append(c)
    require(nextref == objects + 1, 'object table count mismatch')
    return (raw, r, items)

def fill(raw, r, items, base=None):
    refs = list(base) if base else [None] + [{'name': 'base', 'cid': -1} for _ in range(items[0]['start'] - 1)]
    for c in items:
        refs += [{'name': c['name'], 'cid': c['cid'], 'cluster': c} for _ in range(c['count'])]

    def rr(n):
        return [r.ref() for _ in range(n)]

    def vals(n):
        return [r.signed() for _ in range(n)]

    def byte():
        return r.byte()
    for c in items:
        name = c['name']
        start = r.pos
        if name == 'Instance':
            bitmap = r.read()
        for j in range(c['count']):
            o = refs[c['start'] + j]
            if name == 'String':
                enc = r.read()
                if not enc == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                n = (enc >> 1) * (2 if enc & 1 else 1)
                o['value'] = r.take(n).decode('utf-16-le' if enc & 1 else 'latin1', errors='surrogatepass')
                o['cid'] = 95 if enc & 1 else 94
            elif name == 'Mint':
                o['value'] = c['values'][j]
                o['cid'] = 60 if -2 ** 30 <= o['value'] < 2 ** 30 else 61
            elif name == 'Double':
                o['bits'] = r.signed()
            elif name == 'Code':
                o['payload'] = r.read()
                o['refs'] = rr(6)
            elif name == 'Function':
                o['refs'] = rr(4)
                o['code_index'] = r.read()
                o['flags'] = r.signed()
            elif name == 'WeakArray':
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['refs'] = rr(n)
            elif name == 'FunctionType':
                o['refs'] = rr(6)
                o['flags'] = byte()
                o['counts'] = vals(2)
            elif name == 'TypeParameter':
                o['refs'] = rr(3)
                o['params'] = vals(2)
                o['flags'] = byte()
            elif name == 'Type':
                o['refs'] = rr(3)
                o['flags'] = r.read()
            elif name == 'TypeArguments':
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['hash'] = r.signed()
                o['nullability'] = r.read()
                o['refs'] = rr(n + 1)
            elif name == 'Closure':
                o['refs'] = rr(6)
            elif name == 'RecordType':
                o['refs'] = rr(4)
                o['flags'] = byte()
            elif name == 'Record':
                o['shape'] = r.read()
                o['refs'] = rr(c['lengths'][j])
            elif name in ('ConstMap', 'ConstSet'):
                o['refs'] = rr(5)
            elif name in ('Array', 'ImmutableArray'):
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['refs'] = rr(n + 1)
            elif name == 'Instance':
                o['refs'] = []
                o['fields'] = {}
                off = 2
                while off < c['next_field']:
                    if bitmap & 1 << off:
                        o['fields'][off * 4] = ('raw', vals(2))
                        off += 1
                    else:
                        ref = r.ref()
                        o['refs'].append(ref)
                        o['fields'][off * 4] = ref
                        off += 1
            elif name == 'Class':
                o['refs'] = rr(13)
                o['class_id'] = r.signed()
                o['layout'] = vals(5)
                o['flags'] = r.signed()
                if o['class_id'] < 1 << 20:
                    o['bitmap'] = r.read()
            elif name == 'PatchClass':
                o['refs'] = rr(2)
            elif name == 'TypeParameters':
                o['refs'] = rr(4)
            elif name == 'ClosureData':
                o['refs'] = rr(2)
                o['flags'] = r.read()
            elif name == 'FfiTrampolineData':
                o['refs'] = rr(4)
                o['callback_id'] = r.signed()
                o['ffi_kind'] = byte()
            elif name == 'Field':
                o['refs'] = rr(4)
                o['flags'] = r.signed()
                o['slot'] = r.ref()
            elif name == 'Script':
                o['refs'] = rr(1)
                o['flags'] = vals(1)
            elif name == 'Library':
                o['refs'] = rr(10)
                o['flags'] = vals(2) + [byte(), byte()]
            elif name == 'ObjectPool':
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['entries'] = []
                for k in range(n):
                    tag = byte()
                    typ = tag & 15
                    require(tag >> 5 in (0, 2, 3, 4), 'unsupported object-pool reset tag')
                    if tag >> 5:
                        o['entries'].append(('reset', tag >> 5))
                        continue
                    if typ == 1:
                        v = r.ref()
                    elif typ == 0:
                        v = r.signed()
                    elif typ == 2:
                        v = None
                    else:
                        raise ValueError(('pooltag', tag, k))
                    o['entries'].append((typ, v))
            elif name == 'PcDescriptors':
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['data'] = r.take(n)
            elif name == 'ExceptionHandlers':
                v = r.read()
                n = v >> 1
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                o['refs'] = rr(1)
                for _ in range(n):
                    vals(2)
                    byte()
                    byte()
                    byte()
            elif name == 'UnlinkedCall':
                o['refs'] = rr(2)
                o['flag'] = byte()
            elif name == 'SubtypeTestCache':
                o['refs'] = rr(1)
                o['flags'] = vals(2)
            elif name == 'LoadingUnit':
                o['refs'] = rr(1)
                o['id'] = r.signed()
            elif name == 'GrowableObjectArray':
                o['refs'] = rr(3)
            elif name.startswith('TypedData'):
                n = r.count()
                if not n == c['lengths'][j]:
                    raise Unsupported('Invalid Dart snapshot record or root boundary')
                size = next((size for suffix, size in [('Int8Array',1),('Uint8Array',1),('Uint8ClampedArray',1),('Int16Array',2),('Uint16Array',2),('Int32Array',4),('Uint32Array',4),('Int64Array',8),('Uint64Array',8),('Float32Array',4),('Float64Array',8),('Float32x4Array',16),('Float64x2Array',16),('Int32x4Array',16)] if name == 'TypedData' + suffix), None)
                require(size is not None, 'unsupported typed-data layout')
                n *= size
                o['data'] = r.take(n)
            else:
                raise ValueError(('missing fill', name))
            if any((not 0 < v < len(refs) for v in o.get('refs', []))):
                raise ValueError(('badref', name, j, o.get('refs'), r.pos))
    return refs

def tables(data, raw, items, refs, reader, vm=False):
    """Resolve Code/Function references via the serialized instructions table."""
    elf, segs = elf_image(data)
    prefix = '_kDartVm' if vm else '_kDartIsolate'
    instruction_symbol, instruction_bytes = symbol(data, prefix + 'SnapshotInstructions')
    instr = instruction_symbol['st_value']
    length = struct.unpack_from('<Q', raw, 4)[0] + 4
    image = length + 63 & ~63
    start = image + reader.instoffset + 16
    require(start + 16 <= len(raw), 'instructions table header outside image')
    header = struct.unpack_from('<IIII', raw, start)
    n = header[1]
    first = header[2]
    require(0 <= first <= n <= MAX_ELEMENTS and start + 16 + n * 8 <= len(raw), 'instructions table outside image')
    pcs = [instr + struct.unpack_from('<I', raw, start + 16 + i * 8)[0] for i in range(n)]
    codes = [c for c in items if c['name'] == 'Code']
    require(len(codes) == 1, 'ambiguous Code cluster')
    code = codes[0]
    require(n - first == code['count'] == reader.instructions, 'instruction/code counts disagree')
    require(all(instr <= pc < instr + len(instruction_bytes) and pc % 4 == 0 for pc in pcs), 'code entry outside instructions')
    require(all(a < b for a, b in zip(pcs, pcs[1:])), 'unordered instruction entries')
    for i in range(code['count']):
        o = refs[code['start'] + i]
        o['entry'] = pcs[first + i] + (24 if o['payload'] & 1 else 0)
        require(o['entry'] < instr + len(instruction_bytes), 'entry-point offset outside instructions')
        if first + i + 1 < len(pcs):
            o['body'] = read_va(data, segs, o['entry'], pcs[first + i + 1] - o['entry'])

    def entry(index):
        require(0 <= index <= n, 'function code index outside table')
        if index == 0:
            return 0
        if index - 1 < first:
            return pcs[index - 1]
        return refs[code['start'] + index - 1 - first]['entry']
    for c in items:
        if c['name'] == 'Function':
            for i in range(c['count']):
                o = refs[c['start'] + i]
                o['entry'] = entry(o['code_index'])
    return entry

def roots_parse(raw, r, refs, entry, vm=False):
    if vm:
        stubnames = r.schema.vm_stub_names
        rootrefs = []
        length = struct.unpack_from('<Q', raw, 4)[0] + 4
        while r.pos < length:
            rootrefs.append(r.ref())
        symbols = r.schema.vm_symbol_count
        require(len(rootrefs) == symbols + 1 + len(stubnames), 'VM root schema mismatch')
        require(all(refs[v]['name'] == 'String' for v in rootrefs[:symbols]), 'invalid predefined symbols')
        codes = rootrefs[-len(stubnames):]
        if not all((refs[v]['name'] == 'Code' for v in codes)):
            raise Unsupported('Invalid Dart snapshot record or root boundary')
        stubs = {refs[v]['entry']: name + 'Stub' for name, v in zip(stubnames, codes)}
        return stubs
    fields = r.schema.root_fields
    roots = {f: r.ref() for f in fields}
    fieldtable = [r.ref() for _ in range(r.count())]
    shared = [r.ref() for _ in range(r.count())]
    length = r.count()
    first = r.read() if length else 0
    if length:
        code_clusters = {o['cluster']['start'] for o in refs[1:] if o['name'] == 'Code'}
        require(first == max(code_clusters), 'dispatch first Code reference mismatch')
    out = []
    recent = [0] * 64
    ri = 0
    value = 0
    null = refs[roots['dispatch_table_null_error_stub']]['entry']
    while len(out) < length:
        v = r.signed()
        if v == 0:
            value = null
        elif v < 0:
            require(-64 <= v < 0 and recent[~v] != 0, 'invalid recent dispatch reference')
            value = recent[~v]
        elif v <= 63:
            require(value != 0 and len(out) + v <= length, 'invalid dispatch repeat')
            out.extend([value] * v)
            continue
        else:
            value = entry(v - 64)
            recent[ri] = value
            ri = ri + 1 & 63
        out.append(value)
    if not len(out) == length:
        raise Unsupported('Invalid Dart snapshot record or root boundary')
    if not r.pos == struct.unpack_from('<Q', raw, 4)[0] + 4:
        raise Unsupported('Invalid Dart snapshot record or root boundary')
    return (roots, {i - 4096: v for i, v in enumerate(out)})

def copied_stubs(refs, roots, stubs):
    """Label object-store roots, then exact copies of known stub bodies."""
    for field, name in STORE_STUB_NAMES.items():
        if field in roots:
            o = refs[roots[field]]
            if o['name'] == 'Code':
                stubs[o['entry']] = name + 'Stub'
    # Require exact bytes AND an unambiguous VM/store identity, never nearest match.
    bodies = {}
    for o in refs[1:]:
        if o['name'] == 'Code' and o.get('entry') in stubs and o.get('body'):
            bodies.setdefault(o['body'], set()).add(stubs[o['entry']])
    known = {body: next(iter(labels)) for body, labels in bodies.items() if len(labels) == 1}
    for o in refs[1:]:
        if o['name'] == 'Code' and o['refs'][0] == 1 and (o.get('body') in known):
            stubs[o['entry']] = known[o['body']]
    return stubs

def export(refs, roots, dispatch, stubs):
    refs[1].update(name='Null', cid=names.index('Null'), value=None)
    for i in (2, 3):
        refs[i].update(name='Sentinel', cid=names.index('Sentinel'))
    # 35 cached argument descriptors and four cached ICData arrays.
    for i in range(21, 60):
        refs[i].update(name='CachedArray', cid=91)
    # Base objects are defined by VMDeserializationRoots, not by a sample.
    refs[7].update(name='Type', cid=49, flags=173 << 3 | 1, refs=[1, 1, 1])
    refs[8].update(name='Type', cid=49, flags=174 << 3 | 1, refs=[1, 1, 1])
    refs[4].update(name='Array', cid=names.index('Array'), refs=[1])
    refs[10].update(name='Bool', cid=63, value=True)
    refs[11].update(name='Bool', cid=63, value=False)
    classes = {o['class_id']: o for o in refs[1:] if o['name'] == 'Class'}

    def clsname(cid):
        return refs[classes[cid]['refs'][0]]['value'] if cid in classes else names[cid] if cid < len(names) else 'Unknown'

    def funname(o):
        return refs[o['refs'][0]]['value']

    def owner_name(o):
        owner = refs[o['refs'][1]]
        if owner['name'] == 'PatchClass':
            owner = refs[owner['refs'][0]]
        return refs[owner['refs'][0]]['value'] if owner['name'] == 'Class' else 'Unknown'
    for o in refs[1:]:
        if o['name'] == 'Code' and o.get('entry') and (refs[o['refs'][0]]['name'] == 'Class'):
            name = refs[refs[o['refs'][0]]['refs'][0]]['value']
            stubs[o['entry']] = 'Allocate' + name.split('@')[0] + 'Stub'

    render_budget = [MAX_ELEMENTS]

    def render(i, depth=0):
        render_budget[0] -= 1
        require(render_budget[0] >= 0, 'recursive rendering budget exceeded')
        o = refs[i]
        n = o['name']
        if depth > 3:
            return '...'
        if n == 'String':
            return 'String: ' + json.dumps(o['value'], ensure_ascii=False)
        if n == 'Null':
            return 'Null'
        if n == 'Bool':
            return 'true' if o['value'] else 'false'
        if n == 'Mint':
            return ('Smi: ' if o['cid'] == 60 else 'Mint: ') + str(o['value'])
        if n == 'Field':
            return 'Field <' + owner_name(o) + '.' + funname(o) + '>: ' + str(refs[o['slot']].get('value'))
        if n == 'Function':
            return 'Closure: ' + funname(o) + ' (' + hex(o['entry']) + ')'
        if n == 'Closure':
            f = refs[o['refs'][3]]
            return 'Closure: ' + funname(f) + ' (' + hex(f['entry']) + ')'
        if n == 'Code':
            owner = refs[o['refs'][0]]
            if owner['name'] == 'Function':
                return 'Closure: ' + funname(owner) + ' (' + hex(o['entry']) + ')'
            return 'Stub: ' + stubs.get(o['entry'], 'Unknown') + ' (' + hex(o['entry']) + ')'
        if n == 'Type':
            args = refs[o['refs'][2]]
            suffix = '<' + ', '.join((render(v, depth + 1).removeprefix('Type: ') for v in args['refs'][1:])) + '>' if args['name'] == 'TypeArguments' and len(args['refs']) > 1 else ''
            return 'Type: ' + clsname(o['flags'] >> 3).split('@')[0] + suffix + ('?' if not o['flags'] & 1 else '')
        if n in ('Array', 'ImmutableArray'):
            vals = o['refs'][1:]
            strs = all((refs[v]['name'] == 'String' for v in vals))
            return ('List<String>' if strs else 'List') + '(' + str(len(vals)) + ') [' + ', '.join((json.dumps(refs[v]['value']) if refs[v]['name'] == 'String' else render(v, depth + 1) for v in vals[:512])) + ']'
        return 'Obj!' + clsname(o['cid']) if o['cid'] >= len(names) else n
    poolobj = refs[roots['global_object_pool']]
    pool = {}
    meta = {'fields': {}, 'objects': {}, 'dispatch': dispatch, 'stubs': stubs, 'builtins': {'string': 94, 'list': 92, 'uint8': 116}}
    sum_length = [0]
    for i, (kind, value) in enumerate(poolobj['entries']):
        off = 16 + i * 8
        if kind == 1:
            o = refs[value]
            require(o['cid'] >= 0, 'unmodeled base object in global pool')
            pool[off] = render(value)
            meta['objects'][off] = o['cid']
            if o['name'] == 'Field':
                f = refs[o['refs'][3]]
                meta['fields'][off] = {'slot': refs[o['slot']]['value'] * 4, 'static': bool(o['flags'] & 2), 'initializer': f.get('entry', 0)}
        elif kind == 'reset' and value == 2:
            target = next((k for k, v in stubs.items() if v == 'CallBootstrapNativeStub'))
            pool[off] = 'Stub: CallBootstrapNative (' + hex(target) + ')'
            meta['objects'][off] = 18
        elif kind == 0:
            pool[off] = 'IMM: ' + hex(value & ((1 << 64) - 1))
        else:
            pool[off] = 'IMM: unresolved'
        require(sum_length[0] + len(pool[off]) <= MAX_RENDER, 'pool rendering budget exceeded')
        sum_length[0] += len(pool[off])
    return (pool, meta)


def supports(identity):
    return identity.get('snapshot_hash') in SCHEMAS


def recover(data):
    """Return pool and semantic metadata derived exclusively from this ELF."""
    identity = snapshot_identity(data)
    require(supports(identity), 'unsupported snapshot format; use a matching Blutter analyzer')
    schema = SCHEMAS[identity['snapshot_hash']]
    try:
        vm = alloc(data, '_kDartVmSnapshotData', schema=schema)
        vmrefs = fill(*vm)
        iso = alloc(data, '_kDartIsolateSnapshotData', vmrefs, schema)
        refs = fill(*iso, vmrefs)
        ve = tables(data, vm[0], vm[2], vmrefs, vm[1], True)
        ie = tables(data, iso[0], iso[2], refs, iso[1])
        stubs = roots_parse(vm[0], vm[1], vmrefs, ve, True)
        roots, dispatch = roots_parse(iso[0], iso[1], refs, ie)
        stubs = copied_stubs(refs, roots, stubs)
        pool, metadata = export(refs, roots, dispatch, stubs)
        metadata['reader'] = {'name': 'python_snapshot', 'schema': schema.snapshot_hash,
                              'dart_version': schema.dart_version,
                              'objects': len(refs) - 1, 'clusters': len(iso[2]),
                              'unresolved_code_stubs': sum(o['name'] == 'Code' and o.get('entry') not in stubs and o['refs'][0] == 1 for o in refs[1:])}
        return pool, metadata
    except (IndexError, KeyError, TypeError, StopIteration, struct.error) as error:
        raise Unsupported('Python snapshot reader: inconsistent or unsupported snapshot structure') from error
