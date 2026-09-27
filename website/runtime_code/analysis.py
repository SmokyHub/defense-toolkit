"""Bounded format inspection and method-body comparison, not a decompiler."""
import hashlib
import json
from pathlib import Path
import struct
import time
import zlib
from .plugins import group_entry_points

from .store import identity, encoded, export_directory


class Invalid(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
    def region(self, offset, size):
        if type(offset) is not int or type(size) is not int or offset < 0 or size < 0 or offset > len(self.data) - size:
            raise Invalid('Range outside artifact')
        return self.data[offset:offset + size]
    def u16(self, offset):
        return struct.unpack('<H', self.region(offset, 2))[0]
    def u32(self, offset):
        return struct.unpack('<I', self.region(offset, 4))[0]
    def leb(self, offset, signed=False):
        value = 0
        for i in range(5):
            b = self.region(offset + i, 1)[0]
            value |= (b & 127) << (i * 7)
            if not b & 128:
                if i == 4 and (b > 15 if not signed else b not in (*range(8), *range(120,128))):
                    raise Invalid('LEB128 overflow')
                if signed and b & 64:
                    value -= 1 << ((i + 1) * 7)
                return value, offset + i + 1
        raise Invalid('Unterminated LEB128')


def dex(data):
    r = Reader(data)
    if data.startswith((b'cdex', b'dey\n')):
        return {'format': 'compact_or_optimized_dex', 'validity': 'unsupported', 'methods': []}
    if r.region(0, 8) not in [b'dex\n' + v + b'\0' for v in (b'035', b'037', b'038', b'039', b'040')]:
        return {'format': 'dex', 'validity': 'unsupported', 'diagnostic': 'Only standalone DEX 035,037,038,039,040 supported', 'methods': []}
    if r.u32(32) != len(data) or r.u32(36) != 112 or r.u32(40) != 0x12345678:
        raise Invalid('DEX size/header/endianness mismatch')
    if len(data) > 64 * 1024 * 1024:
        raise Invalid('DEX size budget')
    counts, offsets = {}, {}
    for name, header, width in [('strings',56,4), ('types',64,4), ('protos',72,12), ('fields',80,8), ('methods',88,8), ('classes',96,32)]:
        count, offset = r.u32(header), r.u32(header+4)
        if count > 100000 or (count and (offset < 112 or offset % 4)):
            raise Invalid('Identifier table bounds/alignment')
        r.region(offset, count * width)
        counts[name], offsets[name] = count, offset
    strings = []
    decoded_bytes=0
    for i in range(counts['strings']):
        at = r.u32(offsets['strings'] + 4*i)
        length, at = r.leb(at)
        if length > 65536:
            raise Invalid('String length budget')
        end = data.find(b'\0', at, min(len(data), at + 196609))
        if end < 0:
            raise Invalid('Unterminated DEX string')
        decoded_bytes+=end-at
        if decoded_bytes>16*1024*1024:raise Invalid('Decoded string budget')
        # Preserve unusual modified-UTF8 identifiers deterministically; never filter on length.
        strings.append(data[at:end].replace(b'\xc0\x80', b'\0').decode('utf-8', 'surrogateescape'))
    def get(items, index):
        if not 0 <= index < len(items):
            raise Invalid('Identifier index outside table')
        return items[index]
    types = [get(strings, r.u32(offsets['types'] + 4*i)) for i in range(counts['types'])]
    protos = []
    for i in range(counts['protos']):
        at = offsets['protos'] + 12*i
        ret, args = get(types, r.u32(at+4)), r.u32(at+8)
        params = []
        if args:
            count = r.u32(args)
            if count > 255:
                raise Invalid('Prototype parameter budget')
            params = [get(types, r.u16(args+4+2*j)) for j in range(count)]
        protos.append('(' + ''.join(params) + ')' + ret)
    identifiers = []
    for i in range(counts['methods']):
        at = offsets['methods'] + 8*i
        identifiers.append(get(types, r.u16(at)) + '->' + get(strings, r.u32(at+4)) + get(protos, r.u16(at+2)))
    methods, seen = [], set()
    encoded_items=0;body_bytes=0
    for i in range(counts['classes']):
        at = r.u32(offsets['classes'] + 32*i + 24)
        if not at:
            continue
        sizes = []
        for _ in range(4):
            number, at = r.leb(at)
            if number > 100000:
                raise Invalid('Class data budget')
            sizes.append(number)
        encoded_items+=sum(sizes)
        if encoded_items>1000000:raise Invalid('Encoded class data budget')
        for size in sizes[:2]:
            index = 0
            for _ in range(size):
                delta, at = r.leb(at)
                _, at = r.leb(at)
                index += delta
                if index >= counts['fields']:
                    raise Invalid('Field index outside table')
        for size in sizes[2:]:
            index = 0
            for _ in range(size):
                delta, at = r.leb(at)
                flags, at = r.leb(at)
                code, at = r.leb(at)
                index += delta
                name = get(identifiers, index)
                if name in seen:
                    raise Invalid('Duplicate encoded method')
                seen.add(name)
                item = {'identity': name, 'index': index, 'access_flags': flags, 'code_offset': code}
                if flags & (0x100 | 0x400):
                    if code:
                        raise Invalid('Native/abstract method has a code body')
                    item['state'] = 'native' if flags & 0x100 else 'abstract'
                elif not code:
                    item['state'] = 'absent'
                else:
                    if code % 4:
                        raise Invalid('Unaligned code item')
                    registers, ins, outs, tries = struct.unpack('<4H', r.region(code, 8))
                    debug, units = r.u32(code+8), r.u32(code+12)
                    if units > 4*1024*1024 or tries > 65535 or ins > registers:
                        raise Invalid('Code-item resource bounds')
                    end = code + 16 + 2*units
                    r.region(code, end-code)
                    try_items = []
                    if tries:
                        end += 2 if units % 2 else 0
                        for j in range(tries):
                            start, count, handler = struct.unpack('<IHH', r.region(end+8*j,8))
                            if start + count > units:
                                raise Invalid('Try range outside instructions')
                            try_items.append((start,count,handler))
                        end += tries*8
                        handlers_start = end
                        count, end = r.leb(end)
                        if count > 65535:
                            raise Invalid('Handler budget')
                        handler_offsets = set()
                        for _ in range(count):
                            handler_offsets.add(end-handlers_start)
                            size, end = r.leb(end, True)
                            if abs(size) > 65535:
                                raise Invalid('Handler length budget')
                            for _ in range(abs(size)):
                                type_idx, end = r.leb(end)
                                address, end = r.leb(end)
                                get(types,type_idx)
                                if address >= units:
                                    raise Invalid('Handler outside instructions')
                            if size <= 0:
                                address, end = r.leb(end)
                                if address >= units:
                                    raise Invalid('Catch-all outside instructions')
                        if any(h not in handler_offsets for _,_,h in try_items):
                            raise Invalid('Invalid handler offset')
                    body = r.region(code, end-code)
                    body_bytes+=len(body)
                    if body_bytes>64*1024*1024:raise Invalid('Aggregate code-item budget')
                    item.update(state='observed', code_size=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
                                registers=registers, incoming=ins, outgoing=outs, tries=try_items,
                                debug_info_offset=debug, instruction_units=units,
                                suspected_stub=(units == 1 and body[16:18] == b'\x0e\x00' or
                                                body[16:] in (b'\x12\x00\x11\x00',b'\x12\x00\x00\x00\x11\x00')),
                                stub_evidence='Heuristic short void/null return; legitimate methods can have this shape')
                methods.append(item)
    table_bytes = b''.join(r.region(offsets[n], counts[n]*w) for n,w in [('strings',4),('types',4),('protos',12),('methods',8)])
    return {'format':'dex', 'version':data[4:7].decode(), 'validity':'structurally_inspected',
            'limitations':['Bounded table/code-item inspection; not a verifier or proof of loadability',
                           'Debug data remains in the raw snapshot; body exports link to that snapshot'],
            'checksum_matches':r.u32(8) == zlib.adler32(data[12:]) & 0xffffffff,
            'signature_matches':data[12:32] == hashlib.sha1(data[32:]).digest(),
            'tables_sha256':hashlib.sha256(table_bytes + json.dumps([strings,types,protos,identifiers]).encode()).hexdigest(),
            'methods':methods, 'method_count':len(methods)}


def elf(data):
    r=Reader(data)
    if r.region(0,4) != b'\x7fELF' or r.region(5,1) != b'\x01':
        raise Invalid('Unsupported ELF magic/byte order')
    bits = r.region(4,1)[0]
    if bits == 2:
        phoff = struct.unpack('<Q',r.region(32,8))[0]
        entry_size, count = r.u16(54),r.u16(56)
        fmt, expected = '<IIQQQQQQ',56
    elif bits == 1:
        phoff,entry_size,count = r.u32(28),r.u16(42),r.u16(44)
        fmt,expected = '<IIIIIIII',32
    else:
        raise Invalid('Unsupported ELF class')
    if entry_size != expected or not 0 < count <= 1024:
        raise Invalid('ELF program-header bounds')
    segments,build_id=[],None
    for i in range(count):
        p=struct.unpack(fmt,r.region(phoff+i*entry_size,entry_size))
        kind,flags,offset,va,_,filesz,memsz,alignment = p if bits==2 else (p[0],p[6],p[1],p[2],p[3],p[4],p[5],p[7])
        r.region(offset,filesz)
        if kind==1:
            if memsz < filesz:
                raise Invalid('ELF memory segment shorter than file segment')
            segments.append(dict(offset=offset,virtual_address=va,file_size=filesz,memory_size=memsz,flags=flags,alignment=alignment))
        if kind==4:
            at=offset
            while at+12<=offset+filesz:
                namesz,descsz,tag=struct.unpack('<III',r.region(at,12));at+=12
                if namesz > 4096 or descsz > 65536:
                    raise Invalid('ELF note budget')
                name=r.region(at,namesz);at+=(namesz+3)&~3
                value=r.region(at,descsz);at+=(descsz+3)&~3
                if at>offset+filesz:
                    raise Invalid('ELF note exceeds segment')
                if name==b'GNU\0' and tag==3:
                    build_id=value.hex()
    return {'format':'elf','validity':'structurally_inspected','bits':32 if bits==1 else 64,
            'machine':r.u16(18),'segments':segments,'build_id':build_id,
            'limitations':['Program-header inspection does not establish original-input provenance or loadability']}


def structure(data, metadata):
    try:
        if data.startswith((b'dex\n',b'cdex',b'dey\n')):
            return dex(data)
        if data.startswith(b'\x7fELF'):
            return elf(data)
        return {'format':'unknown','validity':'unsupported','bytes':len(data)}
    except (Invalid, struct.error, IndexError, UnicodeError) as error:
        return {'format':'dex' if data.startswith(b'dex') else 'unknown','validity':'resource_limited' if 'budget' in str(error) else 'structurally_invalid',
                'diagnostic':str(error),'methods':[]}


from .code_index import references
HANDLERS = {'structure': structure, 'code.references': references}


def discover_handlers():
    for plugin in group_entry_points('runtime_code.analysis_handlers'):
        if plugin.name not in HANDLERS:register_handler(plugin.name,plugin.load())
    return HANDLERS


def register_handler(name, handler):
    if name in HANDLERS:
        raise ValueError('Handler already registered')
    HANDLERS[name] = handler


def analyze(store, snapshot, handler='structure'):
    if handler not in HANDLERS:
        raise ValueError('Unknown analysis handler')
    row,data=store.read(snapshot)
    job=identity()
    with store.lock,store.db:
        store.db.execute('INSERT INTO analyses VALUES(?,?,?,?,?,?,?)',(job,snapshot,handler,time.time_ns(),None,'pending','{}'))
    try:
        result=HANDLERS[handler](data,json.loads(row['metadata']))
        findings=result.get('findings',[])
        if not isinstance(findings,list) or len(findings)>1000 or any(not isinstance(f,dict) for f in findings):
            raise ValueError('Handler returned invalid Findings')
        finding_rows=[(identity(),job,snapshot,encoded(f)) for f in findings]
        state='complete'
    except Exception as error:
        result,state,finding_rows={'error':str(error)},'failed',[]
    # Large bounded method inventories are analysis results, not Observation payloads.
    with store.lock,store.db:
        store.db.execute('UPDATE analyses SET ended_ns=?,state=?,result=? WHERE id=?',
                         (time.time_ns(),state,json.dumps(result),job))
        store.db.executemany('INSERT INTO findings VALUES(?,?,?,?)',finding_rows)
    store.observe(row['run_id'],row['process_id'],'analysis.completed',{'analysis':job,'snapshot':snapshot,'handler':handler,'state':state})
    return {'id':job,'snapshot':snapshot,'state':state,'result':result}


def export_variants(store,snapshots,directory):
    with export_directory(directory) as target:
        return _write_variants(store,snapshots,target)


def _write_variants(store,snapshots,target):
    manifest={'format':'runtime-code.method-variants/v1','snapshots':[],'variants':{},
              'limitations':['No synthetic merged DEX is produced','Full original snapshots retain debug data and identifier tables']}
    logical=None
    for snapshot in snapshots:
        row,data=store.read(snapshot)
        key=(row['process_id'],row['logical_id'])
        if logical and key!=logical:raise ValueError('Variant exports require the same process and logical DEX')
        logical=key
        result=structure(data,{})
        if result.get('format')!='dex' or result['validity']!='structurally_inspected':
            raise ValueError('Method variants unavailable for this artifact representation')
        (target/(snapshot+'.bin')).write_bytes(data)
        manifest['snapshots'].append(row)
        for method in result['methods']:
            if 'body_sha256' not in method:continue
            digest=method['body_sha256']
            (target/(digest+'.code_item')).write_bytes(data[method['code_offset']:method['code_offset']+method['code_size']])
            manifest['variants'].setdefault(method['identity'],[]).append({'snapshot':snapshot,**method})
    manifest['methods_with_retained_body_variants']=sum(len({v['body_sha256'] for v in variants})>1 for variants in manifest['variants'].values())
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


def analysis_copy(store,snapshot,directory):
    """Explicit checksum-only transformation, never replacement of observed bytes."""
    row,data=store.read(snapshot)
    result=structure(data,{})
    if row['status']!='captured' or result.get('format')!='dex' or result['validity']!='structurally_inspected':
        raise ValueError('Checksum normalization requires a captured, structurally inspected standalone DEX')
    copy=bytearray(data)
    copy[12:32]=hashlib.sha1(copy[32:]).digest()
    struct.pack_into('<I',copy,8,zlib.adler32(copy[12:])&0xffffffff)
    manifest={'source_snapshot':snapshot,'source_sha256':row['hash'],'analysis_sha256':hashlib.sha256(copy).hexdigest(),
              'transformation':'Recomputed DEX SHA-1 signature and Adler32 checksum only',
              'limitations':['Does not validate instructions or assemble method variants','Analysis copy was not observed in the target']}
    with export_directory(directory) as target:
        (target/'observed.bin').write_bytes(data);(target/'analysis.dex').write_bytes(copy)
        (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest
