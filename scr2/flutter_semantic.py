#!/usr/bin/env python3
"""Bounded offline AArch64 Flutter discovery. Never executes submitted code.

Native Blutter is selected by snapshot format and host compatibility. A bounded
Python reader supports the reviewed snapshot formats without compiling a VM. Neither
path selects application hashes or downloads per-application profiles.
Incomplete consumer contracts remain evidence for review. Supported contracts
retain conditional-path and library-semantic assumptions explicitly.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import defaultdict, deque
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFError

MAX_ELF = 256 * 1024 * 1024
MAX_POOL = 64 * 1024 * 1024
MAX_INSTRUCTIONS = 4_000_000
MAX_FUNCTIONS = 200_000
MAX_GRAPH_NODES = 512
MAX_CANDIDATES = 128


class Unsupported(ValueError):
    pass


def read_bounded(path, limit):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Unsupported(f'{Path(path).name}: size exceeds {limit} bytes')
    return data


def elf_image(data):
    if len(data) > MAX_ELF:
        raise Unsupported('ELF size limit exceeded')
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64':
        raise Unsupported('Flutter discovery requires ELF64 little-endian AArch64')
    if elf.num_segments() > 128 or elf.num_sections() > 65536:
        raise Unsupported('ELF table limits exceeded')
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    for s in segments:
        if s['p_filesz'] > s['p_memsz'] or s['p_offset'] + s['p_filesz'] > len(data):
            raise Unsupported('ELF segment outside file bounds')
    return elf, segments


def read_va(data, segments, address, length):
    hits = [s for s in segments if s['p_vaddr'] <= address and
            address + length <= s['p_vaddr'] + s['p_filesz']]
    if length < 0 or len(hits) != 1:
        raise Unsupported('Ambiguous or unavailable file-backed ELF address')
    offset = hits[0]['p_offset'] + address - hits[0]['p_vaddr']
    return data[offset:offset + length]


def snapshot_identity(data):
    elf, segments = elf_image(data)
    symbols = elf.get_section_by_name('.dynsym')
    found = symbols.get_symbol_by_name('_kDartVmSnapshotData') if symbols else None
    if not found or len(found) != 1 or found[0]['st_size'] < 128:
        raise Unsupported('Dart VM snapshot symbol unavailable or ambiguous')
    symbol = found[0]
    raw = read_va(data, segments, symbol['st_value'] + 20, min(symbol['st_size'] - 20, 308))
    digest, flags = raw[:32], raw[32:].split(b'\0', 1)[0]
    if not re.fullmatch(b'[0-9a-f]{32}', digest):
        raise Unsupported('Unsupported Dart snapshot header')
    flags = flags.decode('ascii', errors='strict').strip().split()
    if 'arm64' not in flags or 'compressed-pointers' not in flags:
        raise Unsupported('Requires an arm64 compressed-pointer Dart snapshot')
    return {'snapshot_hash': digest.decode(), 'flags': flags}


def choose_analyzer(identity, directory=None, executable=None):
    """Require a compatible snapshot and host binary; never fetch during discovery."""
    from flutter_toolchain import select
    try:
        return select(identity, directory, executable)
    except ValueError as error:
        raise Unsupported(str(error)) from error


def recover_pool(libapp, identity, directory=None, executable=None, timeout=120):
    analyzer, digest = choose_analyzer(identity, directory, executable)
    with tempfile.TemporaryDirectory(prefix='flutter-pool-') as temp:
        output = Path(temp) / 'out'
        # Blutter loads data, not the target ELF as executable code. Log output is
        # bounded by the worker's process limits, and is not part of the JSON protocol.
        with (Path(temp) / 'blutter.log').open('w+b') as log:
            env = os.environ.copy()
            lab_libraries = Path.home() / 'tools/blutter-deps/root/usr/lib/x86_64-linux-gnu'
            if lab_libraries.is_dir():
                env['LD_LIBRARY_PATH'] = str(lab_libraries) + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
            process = subprocess.run([str(analyzer), '-i', str(libapp), '-o', str(output)],
                                     stdout=log, stderr=log, timeout=timeout, check=False, env=env)
            if process.returncode:
                log.seek(0)
                detail = log.read(2048).decode(errors='replace')
                raise Unsupported(f'Blutter failed ({process.returncode}): {detail}')
        text = read_bounded(output / 'pp.txt', MAX_POOL).decode('utf-8')
        metadata_path = output / 'semantic.tsv'
        if analyzer.name.endswith('_semantic') and not metadata_path.is_file():
            log_path = Path(temp) / 'blutter.log'
            with log_path.open('rb') as diagnostic:
                diagnostic.seek(max(0, log_path.stat().st_size - 2048))
                detail = diagnostic.read(2048).decode(errors='replace')
            raise Unsupported('Semantic Blutter produced no semantic.tsv; rebuild with --prepare-blutter. ' + detail)
        metadata = parse_metadata(read_bounded(metadata_path, MAX_POOL).decode('ascii')) if metadata_path.is_file() else None
        if metadata is not None:
            metadata['stubs'] = parse_stubs(read_bounded(output / 'ida_script/addNames.py', MAX_POOL).decode('utf-8'))
    return text, {'analyzer': analyzer.name, 'analyzer_sha256': digest, **identity}, metadata


def parse_metadata(text):
    lines = text.splitlines()
    if not lines or lines[0] != 'format\tapk-defense.flutter-metadata/v1':
        raise Unsupported('Unsupported semantic snapshot metadata')
    result = {'fields': {}, 'objects': {}, 'dispatch': {}, 'stubs': {}, 'builtins': {}}
    for line in lines[1:]:
        cells = line.split('\t'); kind = cells[0]
        if kind == 'builtin' and len(cells) == 3 and cells[1] in ('string', 'list', 'uint8'):
            value = int(cells[2])
            if cells[1] in result['builtins'] or not 0 < value < 2**20:
                raise Unsupported('Invalid or duplicate builtin class ID')
            result['builtins'][cells[1]] = value
            continue
        values = list(map(int, cells[1:]))
        if kind == 'field' and len(values) == 4:
            offset, slot, static, address = values
            if offset in result['fields'] or min(offset, slot, address) < 0 or max(offset, slot, address) >= 2**63 or static not in (0, 1):
                raise Unsupported('Invalid or duplicate field metadata')
            result['fields'][offset] = {'slot': slot, 'static': bool(static), 'initializer': address}
        elif kind in ('object', 'dispatch') and len(values) == 2:
            target = result['objects' if kind == 'object' else 'dispatch']
            if values[0] in target or not -2**31 <= values[0] < 2**63 or not 0 <= values[1] < 2**63:
                raise Unsupported('Invalid or duplicate object/dispatch metadata')
            target[values[0]] = values[1]
        else:
            raise Unsupported('Invalid semantic snapshot metadata row')
    return result


def parse_stubs(text):
    """Read generated name records as data; never execute the IDA script."""
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'idaapi\.set_name\(0x([0-9a-f]+), "([A-Za-z0-9_]+Stub)_([0-9a-f]+)"\)', line)
        if match and match[1] == match[3]:
            result[int(match[1], 16)] = match[2]
    return result


def parse_pool(text):
    pool = {}
    for line in text.splitlines():
        m = re.match(r'^\[pp\+0x([0-9a-f]+)\] (.*)$', line)
        if m:
            offset = int(m[1], 16)
            if offset in pool:
                raise Unsupported('Duplicate object pool offset')
            pool[offset] = m[2]
    return pool


def jni_table(data):
    """Derive exported bridge-table slots from this ELF's symbol relocations."""
    elf, segments = elf_image(data)
    symbols = elf.get_section_by_name('.dynsym')
    found = symbols.get_symbol_by_name('globalJniEnv') if symbols else None
    if not found or len(found) != 1 or found[0]['st_size'] > 65536:
        return {}
    base, size = found[0]['st_value'], found[0]['st_size']
    table = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if section.num_relocations() > 1_000_000:
            raise Unsupported('ELF relocation budget exceeded')
        linked = elf.get_section(section['sh_link'])
        for relocation in section.iter_relocations():
            address = relocation['r_offset']
            if base <= address < base + size and relocation['r_info_sym']:
                symbol = linked.get_symbol(relocation['r_info_sym'])
                if (symbol.name.startswith('globalEnv_') and relocation['r_info_type'] == 257 and
                        relocation.entry.get('r_addend', 0) == 0 and symbol['st_info']['type'] == 'STT_FUNC' and
                        symbol['st_shndx'] != 'SHN_UNDEF' and
                        any(s['p_flags'] & 1 and s['p_vaddr'] <= symbol['st_value'] < s['p_vaddr'] + s['p_filesz'] for s in segments)):
                    # R_AARCH64_ABS64 entries point to exported bridge functions.
                    table[address - base] = {'symbol': symbol.name, 'symbol_va': hex(symbol['st_value']),
                                            'relocation_va': hex(address)}
    return table


def bridge_origin(data):
    """Validate the exported table provider using this ELF's relocations.

    This verifies table identity, not arbitrary replacement implementations of
    the JNI functions. ELF symbol resolution and the JNI ABI remain assumptions.
    """
    elf, segments = elf_image(data)
    symbols = elf.get_section_by_name('.dynsym')
    found = symbols.get_symbol_by_name('GetGlobalEnv') if symbols else None
    if not found or len(found) != 1 or not 0 < found[0]['st_size'] <= 512:
        return None
    relocs = {}
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            if section.num_relocations() > 1_000_000:
                raise Unsupported('ELF relocation budget exceeded')
            linked = elf.get_section(section['sh_link'])
            for r in section.iter_relocations():
                if r['r_info_type'] == 1025 and r['r_info_sym'] and r.entry.get('r_addend', 0) == 0:
                    relocs[r['r_offset']] = ('symbol', linked.get_symbol(r['r_info_sym']).name)
    symbol = found[0]; regs = {'xzr': 0}; condition = None
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for address, _, op, args in dis.disasm_lite(read_va(data, segments, symbol['st_value'], symbol['st_size']), symbol['st_value']):
        parts = args.split(', ')
        if op == 'adrp': regs[parts[0]] = number(parts[1])
        elif op == 'ldr':
            m = re.fullmatch(r'(x\d+), \[(x\d+)(?:, (#[^\]]+))?\]', args)
            if not m: return None
            base = regs.get(m[2]); offset = number(m[3] or '0')
            regs[m[1]] = relocs.get(base + offset) if isinstance(base, int) else ('load', base, offset)
        elif op == 'cmp' and parts[1] == '#0': condition = regs.get(parts[0])
        elif op == 'csel' and parts[-1] == 'eq':
            if condition != ('load', ('load', ('symbol', 'jni'), 0), 0): return None
            regs[parts[0]] = ('conditional', regs.get(parts[1]), regs.get(parts[2]))
        elif op == 'ret':
            if regs.get('x0') == ('conditional', 0, ('symbol', 'globalJniEnv')):
                return {'provider': 'GetGlobalEnv', 'provider_va': hex(symbol['st_value']),
                        'table': 'globalJniEnv', 'status': 'validated_table_identity',
                        'condition': 'JavaVM initialized; standard ELF/JNI ABI'}
            return None
        else: return None
    return None


def number(text):
    return int(text.lstrip('#'), 0)


class Program:
    """Instruction and reference index. Function boundaries remain explicitly heuristic."""
    def __init__(self, data, pool, metadata=None):
        self.pool = pool
        self.metadata = metadata or {'fields': {}, 'objects': {}, 'dispatch': {}, 'stubs': {}}
        self._contexts = {}
        _, segments = elf_image(data)
        dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        dis.skipdata = True
        self.code = {}
        self.refs = {}
        self.ref_offsets = {}
        starts = {f['initializer'] for f in self.metadata['fields'].values() if f['initializer']}
        prior = None
        for s in segments:
            if not s['p_flags'] & 1:
                continue
            prior = None
            for a, size, op, args in dis.disasm_lite(s.data(), s['p_vaddr']):
                if len(self.code) >= MAX_INSTRUCTIONS:
                    raise Unsupported('Instruction budget exceeded')
                if a in self.code or size != 4:
                    raise Unsupported('Overlapping or unaligned executable segments')
                self.code[a] = (op, args)
                if op == 'stp' and args == 'x29, x30, [x15, #-0x10]!':
                    starts.add(a)
                if op == 'bl' and args.startswith('#'):
                    starts.add(number(args))
                load = re.fullmatch(r'[xw]\d+, \[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', args) if op == 'ldr' else None
                if load:
                    off = number(load[2] or '0')
                    if load[1] == 'x27':
                        ref = off
                    elif prior and prior[0] == load[1]:
                        ref = prior[1] + off
                    else:
                        ref = None
                    if ref in pool:
                        self.ref_offsets[a] = ref
                        self.refs[a] = pool[ref]
                        for target in re.findall(r'\(0x([0-9a-f]+)\)', pool[ref]):
                            starts.add(int(target, 16))
                add = re.fullmatch(r'(x\d+), x27, #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?', args) if op == 'add' else None
                prior = (add[1], number(add[2]) << int(add[3] or '0')) if add else None
        self.starts = sorted(starts & self.code.keys())
        if len(self.starts) > MAX_FUNCTIONS:
            raise Unsupported('Function budget exceeded')
        self.functions = defaultdict(list)
        self.edges = defaultdict(set)
        self.literals = defaultdict(list)
        for a, (op, args) in self.code.items():
            function = self.owner(a)
            if function is None:
                continue
            self.functions[function].append(a)
            if op == 'bl':
                self.edges[function].add(number(args))
            ref = self.refs.get(a, '')
            if ref.startswith('String: '):
                try:
                    value = json.loads(ref[8:])
                except ValueError:
                    continue
                self.literals[function].append((a, value))
            if 'Closure:' in ref:
                for target in re.findall(r'\(0x([0-9a-f]+)\)', ref):
                    self.edges[function].add(int(target, 16))
        # Instance lazy-field references carry names recovered from this snapshot.
        # Match those names to their initializer's closure metadata, not a list of
        # previously observed obfuscated names. Static fields without metadata
        # stay unresolved.
        initializers = defaultdict(set)
        for ref in pool.values():
            match = re.search(r'in \[[^\]]*\] ([^: ]+)::([^ (]+) \(0x([0-9a-f]+)\)', ref)
            if match:
                initializers[(match[1], match[2])].add(int(match[3], 16))
        for address, ref in self.refs.items():
            match = re.match(r'Field <([^.]*)\.([^@>]+)(?:@\d+)?>:', ref)
            if match and self.owner(address) is not None:
                self.edges[self.owner(address)].update(initializers[(match[1], match[2])])
            field = self.metadata['fields'].get(self.ref_offsets[address])
            if field and field['initializer'] in self.code:
                self.edges[self.owner(address)].add(field['initializer'])

    def owner(self, address):
        i = bisect_right(self.starts, address) - 1
        return self.starts[i] if i >= 0 else None

    def context(self, root, depth=4):
        if (root, depth) in self._contexts:
            return self._contexts[root, depth]
        pending = deque([(root, [])])
        visited, hits = set(), []
        while pending and len(visited) < MAX_GRAPH_NODES:
            f, path = pending.popleft()
            if f in visited:
                continue
            visited.add(f)
            for address, value in self.literals[f]:
                if (re.search(r'https?://|(?:globalEnv_|FindClass|GetGlobalEnv|ByteBuffer|<init>|getActivity|loadClass)', value)
                        or value in ('GET', 'POST', 'https', 'http', 'allocateDirect', 'application/json')):
                    hits.append({'literal': value[:1024], 'address': hex(address),
                                 'call_path': [hex(v) for v in [*path, f]]})
            if len(path) < depth:
                pending.extend((target, [*path, f]) for target in sorted(self.edges[f]) if target not in visited)
        result = hits[:128], bool(pending) or len(hits) > 128
        self._contexts[root, depth] = result
        return result

    def decimal_helpers(self):
        result = set()
        for f, addresses in self.functions.items():
            # Dart's small-integer toString fast path indexes a decimal string
            # table after arithmetic untagging. Both facts are required.
            entries = [self.refs.get(a, '') for a in addresses]
            decimal_table = any('List<String>' in e and all('"' + s + '"' in e for s in ('-99', '-98', '0', '98', '99')) for e in entries)
            untag = any(self.code[a][0] in ('sbfx', 'asr') and re.search(r', #1(?:, #0x1f)?$', self.code[a][1]) for a in addresses)
            if decimal_table and untag:
                result.add(f)
        return result

    def numeric_keys(self):
        helpers = self.decimal_helpers()
        result = []
        self.numeric_limit_reached = False
        for a, (op, args) in self.code.items():
            if op != 'mov' or not args.startswith('x16, #'):
                continue
            value = number(args.split(', ')[1])
            if value < 0 or value & 1 or value > 2**32:
                continue
            if self.code.get(a + 4) != ('str', 'x16, [x15]'):
                continue
            call = self.code.get(a + 8)
            if not call or call[0] != 'bl' or number(call[1]) not in helpers:
                continue
            result.append({'address': hex(a), 'key': str(value >> 1),
                           'helper': hex(number(call[1])), 'function': hex(self.owner(a))})
            if len(result) >= MAX_CANDIDATES:
                self.numeric_limit_reached = True
                break
        return result

    def bridge_candidates(self, table):
        bindings = {}
        # A Dart Pointer<struct> dereference followed by a fixed slot load is a
        # candidate FFI table binding. The table receiver is not established by
        # the slot alone; keep that limitation attached to every match.
        for f, addresses in self.functions.items():
            for i, a in enumerate(addresses):
                op, args = self.code[a]
                m = re.fullmatch(r'x\d+, \[x0, #(0x[0-9a-f]+|\d+)\]', args) if op == 'ldr' else None
                if m and number(m[1]) in table and i and self.code[addresses[i - 1]] == ('ldur', 'x0, [x1, #7]'):
                    bindings[f] = {'slot': hex(number(m[1])), 'load_va': hex(a), **table[number(m[1])],
                                   'status': 'candidate_table_binding', 'receiver_proven': False}
        return bindings

    def reachable_bindings(self, root, bindings, depth=5):
        todo = deque([(root, [])]); seen = set(); result = []
        while todo and len(seen) < MAX_GRAPH_NODES:
            f, path = todo.popleft()
            if f in seen:
                continue
            seen.add(f)
            if f in bindings:
                result.append({**bindings[f], 'call_path': [hex(v) for v in [*path, f]]})
            if len(path) < depth:
                todo.extend((target, [*path, f]) for target in sorted(self.edges[f]))
        return result[:32]

    def field_accesses(self, function, keys):
        """Resolve short key-to-dispatch slices without assigning semantic roles."""
        result = []
        seeds = [(int(k['address'], 16) + 12, 'x0', k['key'], k['address'], k['helper']) for k in keys]
        for address in self.functions[function]:
            ref = self.refs.get(address, '')
            if ref.startswith('String: '):
                try:
                    value = json.loads(ref[8:])
                except ValueError:
                    continue
                if isinstance(value, str) and len(value) <= 1024:
                    seeds.append((address + 4, self.code[address][1].split(',')[0], value, hex(address), None))
        for start, register, key, key_va, helper in seeds:
            regs = {register: ('key', key)}
            dispatch_table = False
            for address in range(start, start + 128, 4):
                if self.owner(address) != function or address not in self.code:
                    break
                op, args = self.code[address]
                parts = args.split(', ')
                dst = parts[0].replace('w', 'x', 1)
                if op == 'mov' and len(parts) == 2:
                    regs[dst] = regs.get(parts[1])
                elif op in ('ldr', 'ldur'):
                    m = re.fullmatch(r'[xw]\d+, \[x29, (#[^\]]+|x\d+)\]', args)
                    if m:
                        offset = m[1] if m[1].startswith('#') else regs.get(m[1])
                        regs[dst] = ('frame', str(offset))
                    elif '[x21,' in args and dst == 'x30':
                        dispatch_table = True
                    else:
                        regs.pop(dst, None)
                elif op == 'blr':
                    if dispatch_table and regs.get('x2') == ('key', key) and regs.get('x1'):
                        result.append({'key': key, 'key_va': key_va, 'decimal_helper': helper,
                                       'access_va': hex(address), 'receiver': regs['x1'],
                                       'status': 'candidate_dynamic_key_access'})
                    break
                elif op in ('bl', 'b', 'ret') or op.startswith('b.'):
                    break
                elif dst.startswith('x') and op not in ('str', 'stur', 'stp', 'cmp', 'tst', 'tbz', 'tbnz', 'cbz', 'cbnz'):
                    regs.pop(dst, None)
                # Frame offsets beyond signed LDUR range are materialized in x17.
                if op == 'mov' and len(parts) == 2 and parts[1].startswith('#'):
                    regs[dst] = parts[1]
        return sorted(result, key=lambda v: int(v['access_va'], 16))

    def direct_consumers(self, function, access, bindings):
        """Bounded possible-path register/frame copy slices into direct calls.

        Branches remain alternatives. Unknown call results kill register facts;
        saved frame copies can survive. This does not establish which argument
        registers a callee uses, or promote a possible branch to a verified path.
        """
        first = int(access['access_va'], 16) + 4
        todo = deque([(first, frozenset({'x0'}), frozenset(), ())])
        seen = set(); results = {}; steps = 0
        while todo and steps < 512:
            address, registers, slots, const = todo.popleft()
            state = (address, registers, slots, const)
            if state in seen or self.owner(address) != function or address not in self.code:
                continue
            seen.add(state); steps += 1
            regs, frame, constants = set(registers), set(slots), dict(const)
            op, args = self.code[address]; parts = args.split(', ')
            dst = parts[0].replace('w', 'x', 1)
            successors = [address + 4]
            if op == 'mov' and len(parts) == 2:
                if parts[1] in regs: regs.add(dst)
                else: regs.discard(dst)
                if parts[1].startswith('#'): constants[dst] = parts[1]
                elif parts[1] in constants: constants[dst] = constants[parts[1]]
                else: constants.pop(dst, None)
            elif op in ('str', 'stur', 'ldr', 'ldur'):
                m = re.fullmatch(r'[xw]\d+, \[x29, (#[^\]]+|x\d+)\]', args)
                if m:
                    slot = m[1] if m[1].startswith('#') else constants.get(m[1])
                    if op in ('str', 'stur') and slot:
                        if dst in regs: frame.add(slot)
                        else: frame.discard(slot)
                    else:
                        if slot in frame: regs.add(dst)
                        else: regs.discard(dst)
                elif op in ('ldr', 'ldur'):
                    regs.discard(dst)
                if op in ('ldr', 'ldur'): constants.pop(dst, None)
            elif op == 'bl':
                target = number(args)
                arguments = sorted(regs & {'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'})
                if arguments:
                    context, limited = self.context(target, depth=3)
                    results[(address, tuple(arguments))] = {
                        'call_va': hex(address), 'target': hex(target), 'arguments': arguments,
                        'reachable_context': context, 'context_budget_exhausted': limited,
                        'jni_candidates': self.reachable_bindings(target, bindings)}
                regs.clear()
                constants.clear()
            elif op == 'blr':
                regs.clear(); constants.clear()
            elif op == 'ret':
                successors = []
            elif op == 'b':
                successors = [number(args)]
            elif op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                successors.append(number(parts[-1]))
            elif dst.startswith('x') and op not in ('str', 'stur', 'stp', 'cmp', 'tst'):
                regs.discard(dst); constants.pop(dst, None)
            if regs or frame:
                todo.extend((next_address, frozenset(regs), frozenset(frame), tuple(sorted(constants.items())))
                            for next_address in successors)
        access['slice_budget_exhausted'] = bool(todo)
        return list(results.values())
def discover(data, pool, bridge=None, metadata=None):
    from flutter_contract import recover_contract, Unresolved
    from flutter_preferences import discover_preferences
    program = Program(data, pool, metadata)
    keys = program.numeric_keys()
    groups = defaultdict(list)
    for key in keys:
        groups[key['function']].append(key)
    candidates = []; findings = []
    bindings = program.bridge_candidates(jni_table(bridge)) if bridge else {}
    origin = bridge_origin(bridge) if bridge else None
    # Literal-key layouts are eligible too. Limit this additional search to
    # functions that contain literals and key-access-shaped dispatches.
    literal_groups = 0
    large_functions = 0
    for function in sorted(program.literals):
        if hex(function) in groups:
            continue
        if len(program.functions[function]) > 4096:
            large_functions += 1
            continue
        accesses = program.field_accesses(function, [])
        if len(accesses) >= 2 and program.reachable_bindings(function, bindings):
            groups[hex(function)] = []
            literal_groups += 1
            if literal_groups >= MAX_CANDIDATES:
                break
    for function, fields in groups.items():
        context, limited = program.context(int(function, 16))
        accesses = program.field_accesses(int(function, 16), fields)
        for access in accesses:
            access['direct_consumers'] = program.direct_consumers(int(function, 16), access, bindings)
        callers = sorted(f for f, targets in program.edges.items() if int(function, 16) in targets)[:32]
        request_context = []
        for caller in callers:
            literals, exhausted = program.context(caller, depth=2)
            if any(v['literal'] in ('GET', 'POST', 'https', 'http') or v['literal'].startswith(('https://', 'http://')) for v in literals):
                request_context.append({'caller_function': hex(caller), 'context': literals,
                                        'budget_exhausted': exhausted,
                                        'local_literals': [{'address': hex(a), 'value': s[:1024]}
                                                           for a, s in program.literals[caller]][:128],
                                        'status': 'request_context_candidate_not_verified_network_origin'})
        candidates.append({'function': function, 'numeric_strings': fields, 'reachable_context': context,
                           'request_context_candidates': request_context,
                           'field_access_candidates': accesses,
                           'jni_candidates': program.reachable_bindings(int(function, 16), bindings),
                           'context_budget_exhausted': limited,
                           'status': 'unresolved',
                           'limitations': ['Numeric strings may be keys or unrelated values.',
                                           'Call-graph proximity does not establish response-to-loader data flow.',
                                           'Indirect calls and lazy initializers may be unresolved.']})
        if accesses and origin:
            try:
                finding = recover_contract(program, int(function, 16), accesses, bindings)
                finding['evidence']['bridge_origin'] = origin
                finding['evidence']['libapp_sha256'] = hashlib.sha256(data).hexdigest()
                finding['evidence']['bridge_sha256'] = hashlib.sha256(bridge).hexdigest()
                finding['evidence']['request_context_candidates'] = request_context
                findings.append(finding)
                candidates[-1]['status'] = 'conditional_contract_recovered'
                candidates[-1]['limitations'] = finding['evidence']['assumptions']
            except Unresolved as error:
                candidates[-1]['contract_diagnostic'] = str(error)
        elif accesses:
            candidates[-1]['contract_diagnostic'] = 'JNI bridge table provider not validated'
    preferences = discover_preferences(program) if origin and metadata else {'flows': [], 'diagnostics': []}
    for boundary in preferences['flows']:
        function = int(boundary['loader_function'], 16)
        candidate = {'function': hex(function), 'status': 'unresolved',
                     'boundary': 'async_preferences', 'preferences_evidence': boundary}
        candidates.append(candidate)
        try:
            finding = recover_contract(program, function,
                                       [boundary['byte_access'], *boundary['accesses']], bindings, boundary)
            finding['evidence'].update(bridge_origin=origin,
                                       libapp_sha256=hashlib.sha256(data).hexdigest(),
                                       bridge_sha256=hashlib.sha256(bridge).hexdigest())
            findings.append(finding)
            candidate['status'] = 'conditional_contract_recovered'
            candidate['limitations'] = finding['evidence']['assumptions']
        except Unresolved as error:
            candidate['contract_diagnostic'] = str(error)
    # A separately reviewed compiled graph covers packed Base64/JSON envelopes.
    # It does not reinterpret unresolved generic calls as collection identities.
    from flutter_packed import discover as discover_packed
    packed, packed_diagnostics = discover_packed(program, [int(f, 16) for f in groups],
                                                 jni_table(bridge) if bridge else {}, origin)
    findings.extend(packed)
    for finding in packed:
        candidates.append({'function': finding['evidence']['function'],
                           'boundary': 'base64_utf8_json_fragments',
                           'status': 'conditional_contract_recovered',
                           'limitations': finding['evidence']['assumptions']})
    return {'findings': findings, 'candidates': candidates,
            'packed_diagnostics': packed_diagnostics,
            'preferences_diagnostics': preferences['diagnostics'],
            'coverage_limits': {'numeric_candidate_limit_reached': program.numeric_limit_reached,
                                'literal_group_limit_reached': literal_groups >= MAX_CANDIDATES,
                                'literal_function_size_exclusions': large_functions,
                                'context_max_call_depth': 4, 'jni_context_max_call_depth': 5,
                                'field_slice_max_states': 512},
            'statistics': {'instructions': len(program.code), 'function_hints': len(program.starts),
                           'numeric_strings': len(keys)},
            'diagnostics': ([] if findings else ['flutter_consumer_bindings_not_proven'] if candidates else ['no_supported_flutter_candidates'])}


def load_snapshot(libapp, data, identity, directory=None, executable=None, reader='auto'):
    """Select a compatible reader without executing an incompatible native VM."""
    from dart_snapshot_reader import recover, supports
    fallback = None
    if reader == 'auto':
        try:
            choose_analyzer(identity, directory, executable)
        except Unsupported as error:
            if not supports(identity):
                raise
            fallback = str(error)
            reader = 'python'
    if reader == 'python':
        pool, metadata = recover(data)
        toolchain = {'reader': 'python_snapshot', 'analyzer': None, **identity,
                     'schema': metadata['reader'], 'compilation_required': False}
        if fallback:
            toolchain['native_selection_diagnostic'] = fallback
        return pool, toolchain, metadata
    if reader not in ('auto', 'blutter'):
        raise Unsupported('Unknown Flutter snapshot reader')
    try:
        pool, analyzer, metadata = recover_pool(libapp, identity, directory, executable)
        if metadata is None and reader == 'auto' and supports(identity):
            raise Unsupported('Native reader produced no semantic metadata')
        pool = parse_pool(pool)
    except (OSError, ValueError, ELFError, subprocess.TimeoutExpired) as error:
        # A matching installed VM can still fail to start or lack semantic
        # metadata. Auto mode may use the independently checked Python schema;
        # explicit native mode and unknown formats retain the original failure.
        if reader != 'auto' or not supports(identity):
            raise
        try:
            pool, analyzer, metadata = load_snapshot(libapp, data, identity, reader='python')
        except (OSError, ValueError, ELFError) as python_error:
            raise Unsupported(f'Native snapshot reader failed: {error}; Python snapshot reader failed: {python_error}') from python_error
        analyzer['native_reader_diagnostic'] = str(error)
        return pool, analyzer, metadata
    analyzer['reader'] = 'blutter'
    return pool, analyzer, metadata


def analyze_input(libapp, bridge=None, directory=None, executable=None, reader='auto', after_metadata=None):
    """Preserve the failed stage and snapshot identity for unsupported inputs."""
    from dart_snapshot_schema import SCHEMAS
    stages = []
    identity = None
    analyzer = None
    def begin(name):
        stages.append({'stage': name, 'status': 'unresolved'})
    def complete():
        stages[-1]['status'] = 'complete'
    try:
        begin('input_read')
        data = read_bounded(libapp, MAX_ELF)
        complete()
        begin('snapshot_identity')
        identity = snapshot_identity(data)
        complete()
        begin('snapshot_metadata')
        pool, analyzer, metadata = load_snapshot(libapp, data, identity, directory, executable, reader)
        complete()
        if after_metadata is not None:
            begin('analysis_resource_limits')
            after_metadata()
            complete()
        begin('bridge_read')
        bridge_data = read_bounded(bridge, MAX_ELF) if bridge else None
        complete()
        if bridge is None:
            stages[-1]['status'] = 'not_supplied'
        begin('consumer_contract')
        result = discover(data, pool, bridge_data, metadata)
        # Native metadata can omit cached descriptors needed by a conservative
        # graph model even when snapshot loading succeeds. Auto mode may retry
        # the independently checked Python snapshot schema, without relaxing
        # consumer checks or changing explicit native-only behavior.
        if reader == 'auto' and analyzer.get('reader') == 'blutter' and not result['findings']:
            from dart_snapshot_reader import supports
            if supports(identity):
                native_diagnostics = result.get('diagnostics', [])
                try:
                    pp, alternate, mm = load_snapshot(libapp, data, identity, reader='python')
                    recovered = discover(data, pp, bridge_data, mm)
                    if recovered['findings']:
                        result = recovered
                        analyzer = alternate
                        analyzer['native_consumer_diagnostic'] = native_diagnostics
                    else:
                        result['python_consumer_diagnostics'] = recovered.get('diagnostics', [])
                except (OSError, ValueError, ELFError) as error:
                    result['python_consumer_diagnostics'] = [str(error)]
        stages[-1]['status'] = 'conditional_contract_recovered' if result['findings'] else 'needs_review'
    except (OSError, ValueError, ELFError, subprocess.TimeoutExpired) as error:
        stages[-1].update(status='failed', diagnostic=str(error))
        result = {'findings': [], 'candidates': [], 'diagnostics': [f'flutter_analysis_unavailable: {error}']}
    result['analysis_stages'] = stages
    if identity is not None:
        result['snapshot_compatibility'] = {
            **identity, 'python_format_registered': identity['snapshot_hash'] in SCHEMAS,
            'supported_python_formats': [{'snapshot_hash': s.snapshot_hash, 'dart_version': s.dart_version}
                                         for s in SCHEMAS.values()],
            'limitation': 'A registered format still requires valid feature flags, structure and a supported consumer flow.'}
    if analyzer is not None:
        result['toolchain'] = analyzer
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libapp', type=Path)
    parser.add_argument('--blutter-dir', action='append')
    parser.add_argument('--blutter-bin')
    parser.add_argument('--flutter-reader', choices=('auto', 'blutter', 'python'), default='auto')
    parser.add_argument('--bridge', type=Path)
    args = parser.parse_args()
    try:
        # Unix worker resource limits complement the parent wall-clock timeout.
        # A failed limit is reported, not silently mistaken for successful parsing.
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
        if os.uname().sysname == 'Linux':
            # Dart 3.12 reserves 32 GiB guards on each side of a 4 GiB heap,
            # plus alignment. This limits virtual addresses, not resident RAM.
            resource.setrlimit(resource.RLIMIT_AS, (96 * 1024**3, 96 * 1024**3))
        def limit_analysis_memory():
            if os.uname().sysname == 'Linux':
                resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 96 * 1024**3))
        result = analyze_input(args.libapp, args.bridge, args.blutter_dir, args.blutter_bin,
                               args.flutter_reader, after_metadata=limit_analysis_memory)
    except (OSError, ValueError, ELFError, subprocess.TimeoutExpired) as error:
        result = {'findings': [], 'candidates': [], 'diagnostics': [f'flutter_analysis_unavailable: {error}']}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
