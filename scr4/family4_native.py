#!/usr/bin/env python3
"""Bounded, offline ARM64 Family4 structural native reader.

No execution, network, application hashes, known response keys or file offsets.
Descriptor transforms are reconstructed from the analyzed loader implementation.
The supported JNI topology and strict DEX validator must be recognized before a
response contract is marked complete. Unsupported changes require review.
"""
from __future__ import annotations
import hashlib
import io
import re
import struct
from bisect import bisect_right
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

MASK = (1 << 64) - 1

class Unsupported(ValueError):
    pass

class Code(tuple):
    """Immutable instruction sequence with reusable control-flow boundaries."""
    def __new__(cls, instructions):
        value = super().__new__(cls, instructions)
        value.slice_leaders = None
        return value

class Image:
    def __init__(self, data):
        if not isinstance(data, bytes) or not 64 <= len(data) <= 32 * 1024 * 1024:
            raise Unsupported('native input size outside reader bounds')
        if data[:6] != b'\x7fELF\x02\x01':
            raise Unsupported('unsupported ELF header')
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
        if not (1 <= phnum <= 128 and phsize == 56 and 1 <= shnum <= 1024 and shsize == 64):
            raise Unsupported('ELF table counts or sizes exceed reader model')
        if phoff+phsize*phnum > len(data) or shoff+shsize*shnum > len(data):
            raise Unsupported('truncated ELF tables')
        self.data = data
        self.elf = ELFFile(io.BytesIO(data))
        if self.elf['e_machine'] != 'EM_AARCH64' or self.elf.elfclass != 64 or not self.elf.little_endian:
            raise Unsupported('only little-endian AArch64 ELF64 is supported')
        self.loads = [s for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.reloc = {}
        for segment in self.loads:
            if segment['p_offset']+segment['p_filesz'] > len(data) or segment['p_vaddr']+segment['p_memsz'] > (1 << 48):
                raise Unsupported('invalid load-segment extent')
        relocation_count = 0
        for sec in self.elf.iter_sections():
            if sec['sh_type'] != 'SHT_NOBITS' and sec['sh_offset']+sec['sh_size'] > len(data):
                raise Unsupported('truncated section')
            if sec['sh_type'] == 'SHT_RELA':
                if sec['sh_entsize'] != 24 or sec['sh_size'] % 24:
                    raise Unsupported('unsupported relocation table')
                relocation_count += sec['sh_size']//24
                if relocation_count > 131072:
                    raise Unsupported('relocation budget exceeded')
                for r in sec.iter_relocations():
                    if r['r_info_type'] == 1027:
                        self.reloc[r['r_offset']] = r['r_addend']
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True
        self.ins = []
        code_bytes = 0
        for s in self.elf.iter_sections():
            if s['sh_flags'] & 4 and s['sh_type'] == 'SHT_PROGBITS':
                code_bytes += s['sh_size']
                if code_bytes > 2*1024*1024 or s['sh_addr']+s['sh_size'] > (1 << 48):
                    raise Unsupported('executable code budget exceeded')
                self.ins.extend(md.disasm(s.data(), s['sh_addr']))
        self.ins.sort(key=lambda i:i.address)
        self.ins = Code(self.ins)
        valid_addresses = {i.address for i in self.ins}
        if len(valid_addresses) != len(self.ins):
            raise Unsupported('overlapping executable sections')
        self.starts = sorted({i.address for k,i in enumerate(self.ins) if i.mnemonic=='bti' and i.op_str=='c' or i.mnemonic in ('paciasp','pacibsp') and not any(x.mnemonic=='bti' for x in self.ins[max(0,k-8):k])} | {i.operands[0].imm for i in self.ins if i.mnemonic=='bl' and i.operands[0].imm in valid_addresses})
        # Exported or retained function symbols also identify leaf functions
        # without BTI/PAC prologues or in-image direct callers.
        symbols = set()
        for sec in self.elf.iter_sections():
            if sec['sh_type'] in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                if sec.num_symbols() > 131072:
                    raise Unsupported('function symbol budget exceeded')
                symbols.update(s['st_value'] for s in sec.iter_symbols()
                               if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] != 'SHN_UNDEF'
                               and s['st_value'] in valid_addresses)
        self.starts = sorted(set(self.starts) | symbols)
        self.byaddr = {i.address:i for i in self.ins}
        self._functions = {}
        if not self.starts:
            raise Unsupported('unrecognized function-boundary convention')

    def read(self, va, n):
        if not 0 <= n <= len(self.data):
            raise Unsupported('invalid read length')
        for s in self.loads:
            if s['p_vaddr'] <= va and va+n <= s['p_vaddr']+s['p_filesz']:
                off = va-s['p_vaddr']+s['p_offset']
                if 0 <= off <= len(self.data)-n:
                    return self.data[off:off+n]
        raise Unsupported('read outside file-backed ELF mapping')

    def q(self, va):
        return self.reloc.get(va, struct.unpack('<Q', self.read(va, 8))[0])

    def function(self, va):
        if va not in self.byaddr:
            raise Unsupported('function target outside decoded code')
        k = bisect_right(self.starts, va)-1
        if k < 0:
            raise Unsupported('no bounded function')
        end = self.starts[k+1] if k+1 < len(self.starts) else va+16384
        if end-self.starts[k] > 65536:
            raise Unsupported('function span exceeds analysis budget')
        if self.starts[k] not in self._functions:
            self._functions[self.starts[k]] = Code(self.byaddr[a] for a in range(self.starts[k], end, 4) if a in self.byaddr)
        return self._functions[self.starts[k]]


def _ror(v, shift, bits):
    shift %= bits
    mask = (1 << bits)-1
    return ((v >> shift) | (v << ((-shift) % bits))) & mask


def decode_descriptors(img):
    """Discover pointer-relocated descriptors, verify complete position coverage."""
    found = []
    total = 0
    for a in sorted(img.reloc):
        if total > 1024*1024 or len(found)>4096:
            raise Unsupported('decoded pool exceeds reader bounds')
        try:
            seg, count, size, k1, k2, k3 = (img.q(a+i*8) for i in range(6))
            if not 1 <= count <= 32 or not 1 <= size <= 16384:
                continue
            r, rotation, m1, m2 = img.read(a+48, 4)
            mode = m1 ^ m2
            if mode > 3:
                continue
            decoded = bytearray(size)
            visited = set()
            for j in range(count):
                src, indices, n = (img.q(seg+j*24+i*8) for i in range(3))
                if not 1 <= n <= size:
                    raise Unsupported('fragment count')
                enc = img.read(src, n)
                positions = struct.unpack('<'+'I'*n, img.read(indices, n*4))
                for b, pos in zip(enc, positions):
                    if pos >= size or pos in visited:
                        raise Unsupported('overlapping or out-of-range string position')
                    visited.add(pos)
                    shift = (pos & 7)*8
                    v = (k3+k3*pos+(k2 ^ k3 ^ _ror(k1, -r, 64))) & MASK
                    v = ((v ^ (v >> 30))*0xbf58476d1ce4e5b9) & MASK
                    v = ((v ^ (v >> 27))*0x94d049bb133111eb) & MASK
                    v = ((v ^ (v >> 31)) >> shift) & 255
                    w = ((k3 >> shift)+pos*17) & 255
                    if mode == 0:
                        z = b ^ w ^ v
                    elif mode == 1:
                        z = (_ror(b ^ w, rotation, 8)-v) & 255
                    elif mode == 2:
                        z = _ror((b-v)&255, -rotation, 8) ^ w
                    else:
                        z = (_ror(((v+w)&255)^b, rotation, 8)+v) & 255
                    decoded[pos] = z
            if len(visited) != size:
                continue
            text = decoded.decode('utf-8')
            if any(ord(c)<32 or ord(c)==127 for c in text):
                continue
            total += size
            found.append({'descriptor_va':hex(a), 'text':text, 'length':size, 'mode':mode})
        except (Unsupported, UnicodeError, struct.error):
            continue
    if total > 1024*1024 or len(found)>4096:
        raise Unsupported('decoded pool exceeds reader bounds')
    return found


def _reg(ins, op):
    return ins.reg_name(op.reg).replace('w', 'x', 1) if op.type == ARM64_OP_REG else None


class ArgumentSlice:
    """Bounded basic-block values; no execution or assumed identity for calls.

    Preserve widths, track frame aliases and exact stack spills, and stop at
    control transfers, unknown writes or possible memory aliases. A stack load
    denotes its input cell, not a claim about the cell's runtime contents.
    """
    def __init__(self, insns, limit=128):
        self.insns = insns
        self.limit = limit
        self.steps = 0
        self.memo = {}
        cached = getattr(insns, 'slice_leaders', None)
        if cached is not None:
            self.leaders = cached
            return
        indices = {i.address: k for k, i in enumerate(insns)}
        leaders = {0}
        for k, i in enumerate(insns):
            if i.mnemonic in ('b', 'br', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz') or i.mnemonic.startswith('b.'):
                leaders.add(k + 1)
                if i.operands and i.operands[-1].type == ARM64_OP_IMM:
                    target = indices.get(i.operands[-1].imm)
                    if target is not None:
                        leaders.add(target)
        self.leaders = sorted(leaders)
        if isinstance(insns, Code):
            insns.slice_leaders = self.leaders

    def lower_bound(self, at):
        floor = self.leaders[bisect_right(self.leaders, at) - 1]
        return max(-1, floor - 1, at - self.limit)

    @staticmethod
    def width(name):
        return 4 if name.startswith('w') else 8

    def address(self, at, mem, depth):
        i = self.insns[at]
        if mem.index:
            return None
        base = i.reg_name(mem.base)
        value = ('pointer', base, 0) if base in ('sp', 'fp', 'x29') else self.value(at, base, depth + 1)
        if value and value[0] == 'pointer':
            return ('pointer', value[1], value[2] + mem.disp)
        return None

    def memory(self, at, address, width, depth):
        if address is None:
            return None
        # Calls delimit memory knowledge, but the resulting frame-cell identity
        # is still useful for the separately validated parser context layout.
        for k in range(at - 1, self.lower_bound(at), -1):
            self.steps += 1
            if self.steps > 2048:
                return None
            i = self.insns[k]
            if i.mnemonic in ('bl', 'blr', 'b', 'br', 'ret') or i.mnemonic.startswith('b.') or i.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                break
            _, writes = i.regs_access()
            if any(i.reg_name(r) in ('sp', 'fp', 'x29') for r in writes):
                break
            if i.mnemonic in ('str', 'stur', 'stp', 'strb', 'strh', 'sturb', 'sturh'):
                ops = i.operands
                count = 2 if i.mnemonic == 'stp' else 1
                dest = self.address(k, ops[count].mem, depth + 1)
                if dest is None or i.writeback:
                    return None  # An unlocated write may alias this spill.
                if not re.fullmatch(r'[xw](?:\d+|zr)', i.reg_name(ops[0].reg)):
                    return None  # SIMD stores have a different size/alias model.
                size = 1 if i.mnemonic.endswith('b') else 2 if i.mnemonic.endswith('h') else self.width(i.reg_name(ops[0].reg))
                for n in range(count):
                    offset = dest[2] + n * size
                    if dest[1] != address[1]:
                        return None  # FP and SP can refer to overlapping storage.
                    if offset < address[2] + width and address[2] < offset + size:
                        if offset != address[2] or size != width:
                            return None
                        return self.value(k, i.reg_name(ops[n].reg), depth + 1)
            elif i.mnemonic.startswith(('st', 'cas', 'swp')):
                return None
        return ('load', address, width, at)

    def value(self, at, register, depth=0):
        if depth > 16 or self.steps > 2048:
            return None
        width = self.width(register)
        register = 'x' + register[1:] if register.startswith('w') else register
        if register in ('xzr', 'wzr'):
            return ('constant', 0)
        if register in ('sp', 'fp', 'x29'):
            return ('pointer', register, 0)
        key = (at, register, width)
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = None
        for k in range(at - 1, self.lower_bound(at), -1):
            self.steps += 1
            if self.steps > 2048:
                return None
            i = self.insns[k]; ops = i.operands; op = i.mnemonic
            if op in ('b', 'br', 'ret') or op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                return None
            if op in ('bl', 'blr'):
                if register not in {f'x{n}' for n in range(19, 30)}:
                    return None
                continue
            _, written = i.regs_access()
            if not any(i.reg_name(r).replace('w', 'x', 1) == register for r in written):
                continue
            result = None
            dest_width = self.width(i.reg_name(ops[0].reg)) if ops and ops[0].type == ARM64_OP_REG else 8
            if op == 'mov' and len(ops) == 2:
                result = ('constant', ops[1].imm) if ops[1].type == ARM64_OP_IMM else self.value(k, i.reg_name(ops[1].reg), depth + 1)
            elif op in ('movz', 'movn') and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:
                v = ops[1].imm << ops[1].shift.value
                result = ('constant', ~v if op == 'movn' else v)
            elif op == 'movk' and ops[1].type == ARM64_OP_IMM:
                old = self.value(k, i.reg_name(ops[0].reg), depth + 1)
                if old and old[0] == 'constant':
                    shift = ops[1].shift.value
                    result = ('constant', (old[1] & ~(0xffff << shift)) | (ops[1].imm << shift))
            elif op in ('add', 'sub') and len(ops) == 3 and ops[2].type == ARM64_OP_IMM:
                base = self.value(k, i.reg_name(ops[1].reg), depth + 1)
                amount = (ops[2].imm << ops[2].shift.value) * (1 if op == 'add' else -1)
                if base and base[0] == 'constant':
                    result = ('constant', base[1] + amount)
                elif base and base[0] == 'pointer' and dest_width == 8:
                    result = ('pointer', base[1], base[2] + amount)
            elif op in ('ldr', 'ldur', 'ldp') and not i.writeback:
                count = 2 if op == 'ldp' else 1
                address = self.address(k, ops[count].mem, depth + 1)
                n = next((n for n in range(count) if _reg(i, ops[n]) == register), None)
                if address and n is not None:
                    dest_width = self.width(i.reg_name(ops[n].reg))
                    address = ('pointer', address[1], address[2] + n * dest_width)
                    result = self.memory(k, address, dest_width, depth + 1)
            if result and result[0] == 'constant':
                result = ('constant', result[1] & ((1 << (8 * min(width, dest_width))) - 1))
            elif result and min(width, dest_width) != 8:
                result = None  # Truncating a pointer destroys its provenance.
            if result and result[0] in ('pointer', 'load'):
                base = result[1] if result[0] == 'pointer' else result[1][1]
                aliases = {'fp', 'x29'} if base in ('fp', 'x29') else {base}
                if any(aliases.intersection(j.reg_name(r) for r in j.regs_access()[1])
                       for j in self.insns[k + 1:at]):
                    result = None  # The coordinate frame moved after definition.
            self.memo[key] = result
            return result
        return None


def _stack_source(insns, at, register, *, since=0):
    value = ArgumentSlice(insns).value(at, register)
    if value and value[0] == 'load' and value[1][1] == 'sp' and value[2] == 8 and value[3] >= since:
        return value[1][2]
    return None


def _jni_slot(insns, k):
    """Require [JNIEnv*]->vtable->slot provenance for indirect calls."""
    call=insns[k]
    if call.mnemonic!='blr':
        return None
    reg=_reg(call,call.operands[0])
    for pos in range(k-1,max(-1,k-11),-1):
        i=insns[pos]
        if i.operands and _reg(i,i.operands[0])==reg:
            if i.mnemonic!='ldr' or i.operands[1].type!=ARM64_OP_MEM:
                return None
            slot=i.operands[1].mem.disp
            base=i.reg_name(i.operands[1].mem.base)
            for q in range(pos-1,max(-1,pos-21),-1):
                origin=insns[q]
                if not origin.operands or _reg(origin,origin.operands[0])!=base:
                    continue
                if origin.mnemonic in ('cmp','tst','str','stur','stp'):
                    continue
                if origin.mnemonic!='ldr' or origin.operands[1].type!=ARM64_OP_MEM:
                    return None
                mem=origin.operands[1].mem
                if mem.disp or mem.index:
                    return None
                env=origin.reg_name(mem.base)
                # Environment is incoming x0 or a callee-saved copy made in the
                # entry block, before the first call can clobber arguments.
                envs={'x0'}
                for entry in insns[:32]:
                    if entry.mnemonic in ('bl','blr'):
                        break
                    if entry.mnemonic=='mov' and len(entry.operands)==2 and _reg(entry,entry.operands[1]) in envs:
                        envs.add(_reg(entry,entry.operands[0]))
                return slot if env in envs else None
            return None
    return None


def _address_refs(insns):
    for k,i in enumerate(insns):
        if i.mnemonic=='adr':
            yield k,i.operands[1].imm
        elif i.mnemonic=='adrp' and k+1<len(insns):
            n=insns[k+1]
            if n.mnemonic=='add' and _reg(n,n.operands[1])==_reg(i,i.operands[0]) and n.operands[2].type==ARM64_OP_IMM:
                yield k,i.operands[1].imm+n.operands[2].imm


def _shape(insns):
    """Relocation-independent instruction template, retaining guard constants."""
    rows=[]
    for i in insns:
        s=i.op_str
        if i.mnemonic.startswith('b') or i.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            # Branch targets relative to function start preserve control topology.
            if i.operands and i.operands[-1].type==ARM64_OP_IMM:
                target=i.operands[-1].imm
                s=re.sub(r'#[^, ]+$', '@'+str(target-insns[0].address), s)
        rows.append(i.mnemonic+' '+s)
    return '\n'.join(rows)


def _canonical_shape(shape, offsets=None):
    """Normalize padding and bijective scratch-register allocation only.

    Preserve ABI inputs/outputs (including x8), callee-saved registers, widths,
    constants, memory accesses and every branch predicate. Branch targets are
    remapped after removing NOP/BTI padding, never deleted with their guards.
    """
    if shape is None:
        return None
    rows = shape.splitlines()
    offsets = list(offsets) if offsets is not None else list(range(0, 4 * len(rows), 4))
    if not rows or len(rows) > 1024 or len(offsets) != len(rows) or len(set(offsets)) != len(rows):
        return None
    kept = [k for k, row in enumerate(rows) if row.split(' ', 1)[0] not in ('nop', 'bti')]
    if not kept:
        return None
    positions = {}; next_position = len(kept) * 4
    positions[offsets[-1] + 4] = next_position
    for k in range(len(rows) - 1, -1, -1):
        if k in kept:
            next_position -= 4
        positions[offsets[k]] = next_position
    registers = {}
    def register(match):
        width, number = match[1], int(match[2])
        if 9 <= number <= 17:
            registers.setdefault(number, 9 + len(registers))
            return width + str(registers[number])
        return match[0]
    result = []
    for k in kept:
        row = re.sub(r'\b([xw])(\d+)\b', register, rows[k])
        branch = re.search(r'@(-?\d+)$', row)
        if branch:
            target = positions.get(int(branch[1]))
            if target is None:
                return None
            row = row[:branch.start()] + '@' + str(target)
        result.append(row)
    return '\n'.join(result)


def _equivalent_shape(insns, template, shape=None):
    raw = _shape(insns) if shape is None else shape
    normalized = _canonical_shape(raw, [i.address - insns[0].address for i in insns])
    return normalized is not None and normalized == _canonical_shape(template)



def _validator_graph(shape):
    """Compare acyclic validator control flow, independent of shared return layout.

    Preserve every nonterminal instruction and branch predicate. Only fold direct
    jumps and the two equivalent zero-return sequences, and normalize condition
    inverses. This is not a byte hash or a relaxed search for a few guard constants.
    """
    rows=shape.splitlines()
    if not 1 <= len(rows) <= 512:
        return None
    memo={}; active=set()
    inverses={'b.lo':'b.hs','b.hi':'b.ls','b.ne':'b.eq','b.lt':'b.ge',
              'b.gt':'b.le','cbnz':'cbz','tbnz':'tbz'}
    def visit(k):
        if k in memo:return memo[k]
        if k in active or not 0<=k<len(rows):raise Unsupported('cyclic or external validator branch')
        active.add(k)
        if rows[k:k+2]==['mov w0, wzr','ret ']:
            node=('return_zero',)
        elif rows[k:k+3]==['mov w8, wzr','mov w0, w8','ret ']:
            node=('return_zero',)
        elif rows[k:k+2]==['mov w0, w8','ret ']:
            node=('return_w8',)
        else:
            op,_,args=rows[k].partition(' ')
            branch=re.fullmatch(r'(.*)@(-?\d+)',args)
            if branch:
                address=int(branch[2])
                if address%4:raise Unsupported('unaligned validator branch')
                yes=visit(address//4)
                if op=='b':
                    active.remove(k);memo[k]=yes;return yes
                if not (op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz')):
                    raise Unsupported('unmodeled validator branch')
                no=visit(k+1)
                if op in inverses:op=inverses[op];yes,no=no,yes
                node=(op,branch[1],yes,no)
            else:
                if op in ('ret','br','blr','bl'):raise Unsupported('unmodeled validator terminal')
                node=(rows[k],visit(k+1))
        # Hash-cons the instruction graph, not the sample; bounded shared tails
        # avoid exponentially expanding the many converging validation branches.
        result=hashlib.sha256(repr(node).encode()).hexdigest()
        memo[k]=result;active.remove(k);return result
    try:return visit(0)
    except (Unsupported,RecursionError):return None


def _local_argument(insns, at, register, pointer=False):
    """Recover constants and frame pointers through bounded aliases/spills."""
    value = ArgumentSlice(insns).value(at, register)
    if value and pointer and value[0] == 'pointer':
        return (value[1], value[2])
    if value and not pointer and value[0] == 'constant':
        return value[1]
    return None


def _reachable_code(img, start, budget=512):
    """Follow bounded intraprocedural flow across shrink-wrapped prologues.

    PAC instructions can occur after early returns, so they are not necessarily
    function boundaries. Calls remain explicit and their callees are checked
    separately. Never execute the library or follow indirect branches.
    """
    pending=[start];seen={}
    while pending:
        address=pending.pop()
        if address in seen:continue
        if len(seen)>=budget or not start<=address<start+32768:
            raise Unsupported('bounded function flow exceeded')
        i=img.byaddr.get(address)
        if i is None:raise Unsupported('function flow reaches undecoded code')
        seen[address]=i
        if i.mnemonic=='ret':continue
        if i.mnemonic in ('br','blr'):raise Unsupported('indirect helper flow')
        if i.mnemonic=='b' or i.mnemonic.startswith('b.') or i.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            if not i.operands or i.operands[-1].type!=ARM64_OP_IMM:
                raise Unsupported('unmodeled helper branch')
            pending.append(i.operands[-1].imm)
            if i.mnemonic=='b':continue
        pending.append(address+4)
    return Code(seen[a] for a in sorted(seen))


def _typed_call_shape(img, insns, helper_templates):
    """Replace call addresses only after checking each complete callee body."""
    rows=_shape(insns).splitlines();evidence=[]
    for k,i in enumerate(insns):
        if i.mnemonic!='bl':continue
        target=i.operands[0].imm
        try:body=_reachable_code(img,target,128)
        except Unsupported:return None,[]
        matches=[name for name,shape in helper_templates.items() if _equivalent_shape(body,shape)]
        if len(matches)!=1:return None,[]
        rows[k]='bl '+matches[0]
        evidence.append({'call_va':hex(i.address),'helper_va':hex(target),'role':matches[0]})
    return '\n'.join(rows),evidence


def _decimal_model(img, helper):
    if not helper or helper[-1].mnemonic!='bl':return None
    body=helper[:-1] # final stack-canary failure path, as in the existing model
    if _equivalent_shape(body,DECIMAL_FORMAT_TEMPLATE):return 'multiply_decimal'
    shape,_=_typed_call_shape(img,body,{'zero_buffer':ZERO_BUFFER_TEMPLATE})
    if shape is not None and _equivalent_shape(body,DIVIDE_DECIMAL_TEMPLATE,shape):return 'divide_decimal'
    return None


def _validator_model(img, guard):
    graph=_validator_graph(_shape(guard))
    if graph is not None and graph==_validator_graph(DEX_VALIDATOR_TEMPLATE):
        return 'inline_section_checks',[]
    normalized = _canonical_shape(_shape(guard), [i.address-guard[0].address for i in guard])
    graph = _validator_graph(normalized) if normalized else None
    if graph is not None and graph == _validator_graph(_canonical_shape(DEX_VALIDATOR_TEMPLATE)):
        return 'inline_section_checks',[]
    try:body=_reachable_code(img,guard[0].address)
    except Unsupported:return None,[]
    shape,evidence=_typed_call_shape(img,body,{
        'load_frame_arguments':DEX_FRAME_ARGUMENTS_TEMPLATE,
        'check_dex_section':DEX_SECTION_TEMPLATE})
    if shape is not None and _equivalent_shape(body,OUTLINED_DEX_VALIDATOR_TEMPLATE,shape):
        return 'outlined_section_checks',evidence
    return None,[]


def _decimal_calls(img, insns):
    """Recognize the complete bounded signed-decimal formatter, then its inputs."""
    for k,i in enumerate(insns):
        if i.mnemonic!='bl':continue
        target=i.operands[0].imm
        value=_local_argument(insns,k,'x0')
        size=_local_argument(insns,k,'x2')
        buffer=_local_argument(insns,k,'x1',True)
        if value is None or not 0<=value<10**12 or size!=32 or buffer is None:continue
        helper=img.function(target)
        # The final call is the stack-canary failure path. Other calls must
        # resolve to fully verified helpers; no arbitrary callees are ignored.
        model=_decimal_model(img,helper)
        if model is None:continue
        yield {'value':str(value),'selector_source':'constant_decimal_argument','formatter_model':model,
               'format_call_va':hex(i.address),'helper_va':hex(target),'buffer':buffer,'index':k}


def _formatted_numeric_selectors(img):
    found=[]
    for start in img.starts:
        f=img.function(start)
        for item in _decimal_calls(img,f):
            for j in range(item['index']+1,min(item['index']+16,len(f))):
                if _jni_slot(f,j)==0x538 and _local_argument(f,j,'x1',True)==item['buffer']:
                    found.append({k:v for k,v in item.items() if k not in ('index','buffer') } | {'jni_call_va':hex(f[j].address)})
                    break
                if f[j].mnemonic in ('bl','blr'):break
    return found


def _array_skip(parser,index):
    # Older code compares a field index; newer code iterates 16-byte records.
    for k,i in enumerate(parser[:-1]):
        if i.mnemonic!='cmp' or i.operands[-1].type!=ARM64_OP_IMM or parser[k+1].mnemonic!='b.eq':continue
        value=i.operands[-1].imm
        if value==index:return True
        if value!=index*16:continue
        reg=_reg(i,i.operands[0]);target=parser[k+1].operands[0].imm
        tail=next((j for j,x in enumerate(parser) if x.address==target),None)
        if tail is None:continue
        x=parser[tail]
        if x.mnemonic!='add' or x.op_str!=f'{reg}, {reg}, #0x10':continue
        if not any(y.mnemonic=='cmp' and _reg(y,y.operands[0])==reg and y.operands[-1].type==ARM64_OP_IMM and y.operands[-1].imm==15*16 for y in parser[tail+1:tail+5]):continue
        # The skipped record must be stored as pointer+length at context+index+40.
        body=parser[k+2:tail]
        if any(y.mnemonic=='add' and len(y.operands)==3 and _reg(y,y.operands[2])==reg and any(z.mnemonic=='stp' and z.operands[-1].type==ARM64_OP_MEM and z.reg_name(z.operands[-1].mem.base)==_reg(y,y.operands[0]) and z.operands[-1].mem.disp==40 for z in body[j+1:j+5]) for j,y in enumerate(body)):
            return True
    return False


def _inline_numeric_selectors(img):
    selectors=[]
    for start in img.starts:
        f=img.function(start)
        for k,i in enumerate(f):
            if _jni_slot(f,k)!=0x538:
                continue
            prefix=f[max(0,k-64):k]
            for j,m in enumerate(prefix):
                if m.mnemonic!='mov' or m.operands[-1].type!=ARM64_OP_IMM:
                    continue
                value=m.operands[-1].imm
                if not 0<=value<65536 or not re.fullmatch(rb'[0-9]{2}',struct.pack('<H',value)):
                    continue
                reg=_reg(m,m.operands[0])
                for store in prefix[j+1:j+12]:
                    if store.mnemonic not in ('sturh','strh') or _reg(store,store.operands[0])!=reg:
                        continue
                    mem=store.operands[1].mem
                    for addr in prefix[j+1:]:
                        if addr.mnemonic in ('add','sub') and len(addr.operands)==3 and _reg(addr,addr.operands[0])=='x1' and addr.operands[2].type==ARM64_OP_IMM:
                            off=addr.operands[2].imm*(1 if addr.mnemonic=='add' else -1)
                            if off==mem.disp and addr.operands[1].reg==mem.base:
                                selectors.append({'value':struct.pack('<H',value).decode(),'literal_va':hex(m.address),'jni_call_va':hex(i.address)})
    return selectors

def extract_contract(img, progress=None):
    candidates=[]
    progress = progress if progress is not None else {}
    def observed(stage):
        progress[stage] = progress.get(stage, 0) + 1
    inline_selectors=_inline_numeric_selectors(img)+_formatted_numeric_selectors(img)
    for k,va in _address_refs(img.ins):
        try:
            keys=struct.unpack('<15Q',img.read(va,120))
        except (Unsupported, struct.error):
            continue
        if len(set(keys))!=15 or not all(0<x<10**12 for x in keys):
            continue
        parser=img.function(img.ins[k].address)
        if not any(i.mnemonic=='cmp' and i.operands[-1].type==ARM64_OP_IMM and i.operands[-1].imm==15 for i in parser):
            continue
        observed('selector_table')
        formatted=list(_decimal_calls(img,parser))
        outer=[x['value'] for x in formatted]
        for j,i in enumerate(parser[:-1]):
            if i.mnemonic=='mov' and i.operands[-1].type==ARM64_OP_IMM:
                val=i.operands[-1].imm
                if 0<=val<65536 and re.fullmatch(rb'[0-9]{2}',struct.pack('<H',val)):
                    n=parser[j+1]
                    if n.mnemonic in ('sturh','strh') and _reg(n,n.operands[0])==_reg(i,i.operands[0]):
                        outer.append(struct.pack('<H',val).decode())
        if len(set(outer))!=1:
            continue
        observed('outer_selector')
        start=parser[0].address
        callers=[i for i in img.ins if i.mnemonic=='bl' and i.operands[0].imm==start]
        for call in callers:
            loader=img.function(call.address)
            pos=next(j for j,i in enumerate(loader) if i.address==call.address)
            context = _local_argument(loader, pos, 'x0', True)
            if context is None or context[0] != 'sp':
                continue
            anchor = context[1]
            observed('parser_context')
            def context_source(at, register):
                return _stack_source(loader, at, register, since=pos + 1)
            def field(off):
                if off is not None and off>=anchor+40 and (off-anchor-40)%16==0 and (off-anchor-40)//16<15:
                    return (off-anchor-40)//16
            events=[]; class_fields=[]; strings=[]
            for j,i in enumerate(loader):
                slot=_jni_slot(loader,j)
                if slot in (0x108,0x388):
                    a,b=field(context_source(j,'x2')),field(context_source(j,'x3'))
                    if a is not None or b is not None:
                        events.append((slot,a,b,i.address))
                elif slot==0x30:
                    a=field(context_source(j,'x1'))
                    if a is not None:class_fields.append((a,i.address))
                if i.mnemonic=='bl':
                    a=field(context_source(j,'x1'))
                    off2=context_source(j,'x2')
                    if a is not None and off2==anchor+40+a*16+8:
                        # The same helper must create both Java class-name strings.
                        helper=img.function(i.operands[0].imm)
                        if any(_jni_slot(helper,z)==0x518 for z in range(len(helper))):
                            strings.append((a,i.address,i.operands[0].imm))
            if [v[0] for v in events] != [0x388,0x108,0x108,0x108,0x108,0x108] or len(class_fields)!=1 or len(strings)!=2:
                continue
            if any(a is None or b is None for _,a,b,_ in events):continue
            static,getter,ctor,load,entryctor,entry=events
            if ctor[1]!=entryctor[1] or strings[0][2]!=strings[1][2]:continue
            bindings={
                'loader_class':strings[0][0], 'loader_constructor_signature':ctor[2],
                'activity_loader_method':getter[1], 'activity_loader_signature':getter[2],
                'load_class_method':load[1], 'load_class_signature':load[2],
                'entry_class':strings[1][0], 'entry_constructor_signature':entryctor[2],
                'entry_method':entry[1], 'entry_signature':entry[2],
                'class_class':class_fields[0][0], 'class_lookup_method':static[1],
                'class_lookup_signature':static[2], 'constructor_name':ctor[1],
            }
            remaining=set(range(15))-set(bindings.values())
            if len(set(bindings.values()))!=14 or len(remaining)!=1:continue
            observed('jni_role_bindings')
            arrayindex=remaining.pop()
            if not _array_skip(parser,arrayindex):continue
            observed('array_binding')
            guard=None
            for j in range(pos+1,min(pos+35,len(loader))):
                i=loader[j]
                if i.mnemonic=='bl' and context_source(j,'x0')==anchor+0x128 and context_source(j,'x1')==anchor+0x130:
                    guard=img.function(i.operands[0].imm)
                    break
            if guard is None:continue
            # This is a semantic code-template match, not an APK/ELF identity test.
            # Constants and branch topology are deliberately retained: changed
            # validation behavior must require review, not inherit assumed bounds.
            guard_model,guard_helpers=_validator_model(img,guard)
            known_guard = guard_model is not None
            trigger_consistent=len(inline_selectors)==1 and inline_selectors[0]['value']==outer[0]
            if known_guard:observed('dex_validator')
            if trigger_consistent:observed('trigger_agreement')
            candidates.append({'outer_key':outer[0], 'array_key':str(keys[arrayindex]),
                'roles':{name:str(keys[index]) for name,index in bindings.items()},
                'complete':known_guard and trigger_consistent, 'outer_trigger_evidence':inline_selectors, 'table_va':hex(va), 'parser_va':hex(start),
                'loader_va':hex(loader[0].address), 'dex_validator_va':hex(guard[0].address),
                'validator_model':guard_model,'validator_helpers':guard_helpers,
                'role_evidence':[{'jni_slot':hex(s),'name_key':str(keys[a]),'signature_key':str(keys[b]),'call_va':hex(c)} for s,a,b,c in events],
                'diagnostics':([] if known_guard else ['unmodeled_dex_validator'])+([] if trigger_consistent else ['outer_trigger_mismatch_or_ambiguous']),
                'guards':{'dex_min_bytes':112,'dex_max_bytes':33554432,'dex_versions':['035','037','038','039','040','041'],'exact_file_size':True,'header_and_table_bounds':True,'dex_checksum_checked_by_native':False} if known_guard else None})
    unique={ (c['table_va'],c['loader_va']):c for c in candidates }
    return list(unique.values())


def _analyze_native(data):
    """Return findings; only one complete, recognized contract enables proof."""
    img=Image(data)
    strings=decode_descriptors(img)
    values={s['text'] for s in strings}
    progress = {}
    contracts=extract_contract(img, progress)
    required={'java/nio/ByteBuffer','allocateDirect','java/lang/ClassLoader','org/json/JSONObject','getResponseCode','POST'}
    endpoints=[s for s in strings if re.fullmatch(r'https?://[^\s]+',s['text'])]
    complete=len(contracts)==1 and contracts[0]['complete'] and required<=values and len(endpoints)==1
    diagnostics=[]
    if not required<=values:diagnostics.append('incomplete_native_anchors')
    if len(endpoints)!=1:diagnostics.append('ambiguous_endpoint')
    if len(contracts)!=1:diagnostics.append('ambiguous_or_unmodeled_loader_topology')
    diagnostics.extend(d for c in contracts for d in c['diagnostics'])
    return {'family':'family4','status':'supported' if complete else 'needs_review',
        'sha256':hashlib.sha256(data).hexdigest(), 'endpoint':endpoints[0]['text'] if len(endpoints)==1 else None,
        'http_method':'POST' if 'POST' in values else None, 'contracts':contracts,
        'strings':strings,'diagnostics':diagnostics,
        'analysis_stages': [{'stage': name, 'status': 'observed' if progress.get(name) else 'unresolved',
                             'candidate_count': progress.get(name, 0)}
                            for name in ('selector_table', 'outer_selector', 'parser_context',
                                         'jni_role_bindings', 'array_binding', 'dex_validator', 'trigger_agreement')],
        'stage_limitation': 'Counts describe candidate paths, not coverage or a complete contract; final status retains all checks.',
        'evidence_level':'static_reconstruction_and_JNI_argument_binding',
        'runtime_execution_observed':False}



def analyze_native(data):
    """Normalize malformed-ELF failures for offline CLI callers."""
    try:
        return _analyze_native(data)
    except Unsupported:
        raise
    except (ELFError, struct.error, KeyError, IndexError, OverflowError, TypeError) as exc:
        raise Unsupported('malformed or unsupported ELF: '+str(exc)) from exc


def analyze_bytes(data):
    """CLI-facing compatibility API with the same role names as Family3."""
    result = analyze_native(data)
    names = {
        'class_class':'resolver_class', 'class_lookup_method':'resolver_method',
        'class_lookup_signature':'resolver_descriptor', 'loader_class':'loader_class',
        'activity_loader_method':'parent_getter_name', 'activity_loader_signature':'parent_getter_descriptor',
        'constructor_name':'constructor_name', 'loader_constructor_signature':'loader_constructor_descriptor',
        'load_class_method':'load_class_method', 'load_class_signature':'load_class_descriptor',
        'entry_class':'payload_class', 'entry_constructor_signature':'payload_constructor_descriptor',
        'entry_method':'entry_method', 'entry_signature':'entry_descriptor',
    }
    if len(result['contracts']) == 1:
        c = result['contracts'][0]
        result.update(outer=c['outer_key'], array_key=c['array_key'],
                      roles={names[k]:v for k,v in c['roles'].items()}, size_guard=c['guards'])
    else:
        result.update(outer=None, array_key=None, roles={}, size_guard=None)
    return result

# Populated below with an instruction-level validator template, independent of
# app identity, addresses, keys, endpoint, split name, and descriptor secrets.
DEX_VALIDATOR_TEMPLATE = 'bti c\nmov w8, wzr\ncbz x0, @780\nmov x9, #-0x2000001\nmov x10, #-0xff91\nadd x9, x1, x9\nmovk x10, #0xfe00, lsl #16\ncmp x9, x10\nb.lo @780\nldrb w8, [x0]\ncmp w8, #0x64\nb.ne @136\nldrb w8, [x0, #1]\ncmp w8, #0x65\nb.ne @136\nldrb w8, [x0, #2]\ncmp w8, #0x78\nb.ne @136\nldrb w8, [x0, #3]\ncmp w8, #0xa\nb.ne @136\nldrb w8, [x0, #4]\ncmp w8, #0x30\nb.ne @136\nldrb w8, [x0, #5]\nsub w9, w8, #0x3a\ncmn w9, #0xa\nb.lo @136\nldrb w9, [x0, #6]\nsub w10, w9, #0x3a\ncmn w10, #0xa\nb.lo @136\nldrb w10, [x0, #7]\ncbz w10, @144\nmov w0, wzr\nret \nmov w10, #0xa\nmadd w9, w8, w10, w9\nsub w8, w9, #0x23a\ncmn w8, #7\nmov w8, wzr\nb.lo @780\nsub w10, w9, #0x210\ncmp w10, #0x24\nb.eq @780\ncmp w10, #0x29\nmov w8, #0x70\nmov w9, #0x78\ncsel x9, x9, x8, eq\ncmp x1, x9\nb.lo @136\nldr w8, [x0, #0x24]\ncmp x9, x8\nb.ne @136\nldr w11, [x0, #0x20]\nmov w8, wzr\ncmp x1, x11\nb.lo @780\nldr w12, [x0, #0x28]\nmov w13, #0x5678\nmovk w13, #0x1234, lsl #16\ncmp w12, w13\nb.ne @780\ncmp x9, x11\nb.hi @780\ncmp w10, #0x29\nb.ne @292\nldr w8, [x0, #0x70]\ncmp x1, x8\nb.ne @136\nldr w8, [x0, #0x74]\ncbnz w8, @136\nb @300\ncmp x1, x11\nb.ne @136\nldp w12, w11, [x0, #0x2c]\ncbz w12, @344\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w11, w1, w11\ncmp w11, w12\nb.hs @348\nb @780\ncbnz w11, @136\nldp w12, w11, [x0, #0x38]\ncbz w12, @392\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w8, w1, w11\ncmp w12, w8, lsr #2\nb.hi @136\nb @396\ncbnz w11, @136\nldp w12, w11, [x0, #0x40]\ncbz w12, @440\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w8, w1, w11\ncmp w12, w8, lsr #2\nb.hi @136\nb @444\ncbnz w11, @136\nldp w11, w12, [x0, #0x48]\ncbz w11, @504\ncmp x9, x12\nmov w8, wzr\nb.hi @780\ncmp x1, x12\nb.lo @780\nsub w8, w1, w12\nmov w12, #0xaaab\nmovk w12, #0xaaaa, lsl #16\numull x8, w8, w12\nlsr x8, x8, #0x23\ncmp w8, w11\nb.lo @136\nb @508\ncbnz w12, @136\nldp w12, w11, [x0, #0x50]\ncbz w12, @552\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w8, w1, w11\ncmp w12, w8, lsr #3\nb.hi @136\nb @556\ncbnz w11, @136\nldp w12, w11, [x0, #0x58]\ncbz w12, @600\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w8, w1, w11\ncmp w12, w8, lsr #3\nb.hi @136\nb @604\ncbnz w11, @136\nldp w12, w11, [x0, #0x60]\ncbz w12, @648\ncmp x9, x11\nmov w8, wzr\nb.hi @780\ncmp x1, x11\nb.lo @780\nsub w8, w1, w11\ncmp w12, w8, lsr #5\nb.hi @136\nb @652\ncbnz w11, @136\ncmp w10, #0x29\nb.eq @708\nldp w11, w10, [x0, #0x68]\ncbz w11, @704\ncmp w10, #0x70\nmov w8, wzr\nb.lo @780\ncmp x1, x10\nb.lo @780\nsub w10, w1, w10\ncmp w10, w11\nb.hs @708\nb @780\ncbnz w10, @136\nldr w10, [x0, #0x34]\ncbz w10, @776\ncmp x9, x10\nmov w8, wzr\nb.hi @780\nsubs x9, x1, x10\nb.lo @780\ncmp x9, #4\nb.lo @136\nsub w8, w9, #4\nmov w9, #0xaaab\nmovk w9, #0xaaaa, lsl #16\numull x8, w8, w9\nldr w9, [x0, x10]\nlsr x8, x8, #0x23\ncmp w8, w9\nb.lo @136\nmov w8, #1\nmov w0, w8\nret '

# Complete bounded decimal conversion helper; only the trailing canary-failure
# call is excluded. The input value and buffer are recovered at each call site.
DECIMAL_FORMAT_TEMPLATE = 'paciasp \nsub sp, sp, #0x30\nstp x29, x30, [sp, #0x20]\nmrs x9, tpidr_el0\nadd x29, sp, #0x20\nldr x10, [x9, #0x28]\nmov x8, x0\nmov w0, wzr\nstur x10, [x29, #-8]\ncbz x1, @232\ncbz x2, @232\ncmp x8, #0\nmov x12, #-0x3333333333333334\nmov x11, xzr\nmovk x12, #0xcccd\ncneg x15, x8, mi\nmov w13, #0xa\nmov x14, sp\nstp xzr, xzr, [sp]\nstr wzr, [sp, #0x10]\numulh x10, x15, x12\ncmp x15, #0xa\nlsr x16, x10, #3\nmsub w10, w16, w13, w15\norr w15, w10, #0x30\nadd x10, x11, #1\nstrb w15, [x14, x11]\nb.lo @128\ncmp x11, #0x13\nmov x15, x16\nmov x11, x10\nb.lo @80\nadd x11, x10, x8, lsr #63\ncmp x11, x2\ncset w0, lo\nb.hs @208\ntbnz x8, #0x3f, @156\nmov x8, xzr\nb @168\nmov w8, #0x2d\nstrb w8, [x1]\nmov w8, #1\nmov x11, sp\nsub x11, x11, #1\nldrb w12, [x11, x10]\nsubs x10, x10, #1\nstrb w12, [x1, x8]\nadd x8, x8, #1\nb.ne @176\nstrb wzr, [x1, x8]\ncbz x3, @208\nstr x8, [x3]\nmov x8, xzr\nmov x10, sp\nstrb wzr, [x10, x8]\nadd x8, x8, #1\ncmp x8, #0x14\nb.ne @216\nldr x8, [x9, #0x28]\nldur x9, [x29, #-8]\ncmp x8, x9\nb.ne @264\nldp x29, x30, [sp, #0x20]\nadd sp, sp, #0x30\nautiasp \nret '

# Reviewed compact-code templates: see the Reasonglow Family4 variant report.
# Call targets are replaced by roles only after their full bodies match.
ZERO_BUFFER_TEMPLATE = 'bti c\ncbz x1, @20\nsub x1, x1, #1\nstrb wzr, [x0], #1\ncbnz x1, @8\nret '

DEX_FRAME_ARGUMENTS_TEMPLATE = 'ldr x0, [sp]\nldur x3, [x29, #-8]\nret '

DEX_SECTION_TEMPLATE = 'bti c\nadd x9, x0, x1\nldp w8, w9, [x9]\ncbz w8, @36\ncmp x4, x9\nccmp x3, x9, #0, ls\nb.hs @48\nmov w0, wzr\nret \ncmp w9, #0\ncset w0, eq\nret \nsub w9, w3, w9\nudiv w9, w9, w2\ncmp w9, w8\ncset w0, hs\nret '

OUTLINED_DEX_VALIDATOR_TEMPLATE = 'bti c\nmov w8, wzr\ncbz x0, @140\nmov x9, #-0x2000001\nmov x10, #-0xff91\nadd x9, x1, x9\nmovk x10, #0xfe00, lsl #16\ncmp x9, x10\nb.lo @140\nldrb w8, [x0]\ncmp w8, #0x64\nb.ne @136\nldrb w8, [x0, #1]\ncmp w8, #0x65\nb.ne @136\nldrb w8, [x0, #2]\ncmp w8, #0x78\nb.ne @136\nldrb w8, [x0, #3]\ncmp w8, #0xa\nb.ne @136\nldrb w8, [x0, #4]\ncmp w8, #0x30\nb.ne @136\nldrb w8, [x0, #5]\nsub w9, w8, #0x3a\ncmn w9, #0xa\nb.lo @136\nldrb w9, [x0, #6]\nsub w10, w9, #0x3a\ncmn w10, #0xa\nb.lo @136\nldrb w10, [x0, #7]\ncbz w10, @148\nmov w8, wzr\nmov w0, w8\nret \nmov w10, #0xa\nmadd w9, w8, w10, w9\nsub w8, w9, #0x23a\ncmn w8, #7\nmov w8, wzr\nb.lo @140\nsub w9, w9, #0x210\ncmp w9, #0x24\nb.eq @140\ncmp w9, #0x29\nmov w8, #0x70\nmov w10, #0x78\ncsel x8, x10, x8, eq\ncmp x1, x8\nb.lo @136\nldr w10, [x0, #0x24]\ncmp x8, x10\nb.ne @136\nldr w10, [x0, #0x20]\nldr w11, [x0, #0x28]\nmov w12, #0x5678\nmovk w12, #0x1234, lsl #16\ncmp x1, x10\nccmp w11, w12, #0, hs\nccmp x8, x10, #2, eq\nb.hi @136\npaciasp \nsub sp, sp, #0x30\nstp x29, x30, [sp, #0x20]\nadd x29, sp, #0x20\ncmp w9, #0x29\nstr x8, [sp, #0x10]\nstr w9, [sp, #0xc]\nstur x1, [x29, #-8]\nb.ne @316\nldr w9, [x0, #0x70]\ncmp x1, x9\nb.ne @652\nldr w9, [x0, #0x74]\nmov x8, x0\ncbz w9, @328\nb @652\nmov x8, x0\ncmp x1, x10\nb.ne @652\nstr x8, [sp]\nldp w9, w8, [x8, #0x2c]\ncbz w9, @372\nldr x10, [sp, #0x10]\ncmp x10, x8\nldur x10, [x29, #-8]\nsub w11, w10, w8\nccmp x10, x8, #0, ls\nccmp w11, w9, #0, hs\nb.hs @376\nb @652\ncbnz w8, @652\nbl load_frame_arguments\nmov w1, #0x38\nldr x4, [sp, #0x10]\nmov w2, #4\nbl check_dex_section\ntbz w0, #0, @652\nbl load_frame_arguments\nmov w1, #0x40\nldr x4, [sp, #0x10]\nmov w2, #4\nbl check_dex_section\ntbz w0, #0, @652\nbl load_frame_arguments\nmov w1, #0x48\nldr x4, [sp, #0x10]\nmov w2, #0xc\nbl check_dex_section\ntbz w0, #0, @652\nbl load_frame_arguments\nmov w1, #0x50\nldr x4, [sp, #0x10]\nmov w2, #8\nbl check_dex_section\ntbz w0, #0, @652\nbl load_frame_arguments\nmov w1, #0x58\nldr x4, [sp, #0x10]\nmov w2, #8\nbl check_dex_section\ntbz w0, #0, @652\nbl load_frame_arguments\nmov w1, #0x60\nldr x4, [sp, #0x10]\nmov w2, #0x20\nbl check_dex_section\ntbz w0, #0, @652\nldr w8, [sp, #0xc]\ncmp w8, #0x29\nb.eq @576\nldr x8, [sp]\nldp w9, w8, [x8, #0x68]\ncbz w9, @572\nldur x10, [x29, #-8]\ncmp w8, #0x70\nsub w11, w10, w8\nccmp x10, x8, #0, hs\nccmp w11, w9, #0, hs\nb.hs @576\nb @652\ncbnz w8, @652\nldr x8, [sp]\nldr w8, [x8, #0x34]\ncbz w8, @672\nldr x9, [sp, #0x10]\ncmp x9, x8\nldur x9, [x29, #-8]\nccmp x9, x8, #0, ls\nb.lo @652\nldur x9, [x29, #-8]\nsub x9, x9, x8\ncmp x9, #4\nb.lo @652\nsub w9, w9, #4\nmov w10, #0xc\nudiv w10, w9, w10\nldr x9, [sp]\nldr w8, [x9, x8]\ncmp w10, w8\nb.hs @672\nmov w8, wzr\nldp x29, x30, [sp, #0x20]\nadd sp, sp, #0x30\nautiasp \nb @140\nmov w8, #1\nb @656'

DIVIDE_DECIMAL_TEMPLATE = 'paciasp \nsub sp, sp, #0x40\nstp x29, x30, [sp, #0x20]\nadd x29, sp, #0x20\nstp x20, x19, [sp, #0x30]\nmrs x20, tpidr_el0\nmov w19, wzr\nldr x8, [x20, #0x28]\nstur x8, [x29, #-8]\ncbz x1, @208\ncbz x2, @208\ncmp x0, #0\nmov x8, xzr\nmov w9, #0xa\ncneg x11, x0, mi\nmov x10, sp\nstp xzr, xzr, [sp]\nstr wzr, [sp, #0x10]\nudiv x12, x11, x9\ncmp x11, #0xa\nccmp x8, #0x13, #2, hs\nmsub w13, w12, w9, w11\norr w11, w13, #0x30\nstrb w11, [x10, x8]\nadd x8, x8, #1\nmov x11, x12\nb.lo @72\nadd x9, x8, x0, lsr #63\ncmp x9, x2\ncset w19, lo\nb.hs @196\ntbnz x0, #0x3f, @136\nmov x9, xzr\nb @148\nmov w9, #0x2d\nstrb w9, [x1]\nmov w9, #1\nmov x10, sp\nsub x10, x10, #1\ncbz x8, @184\nldrb w11, [x10, x8]\nadd x12, x9, #1\nsub x8, x8, #1\nstrb w11, [x1, x9]\nmov x9, x12\ncbnz x8, @160\nstrb wzr, [x1, x9]\ncbz x3, @196\nstr x9, [x3]\nmov x0, sp\nmov w1, #0x14\nbl zero_buffer\nldr x8, [x20, #0x28]\nldur x9, [x29, #-8]\ncmp x8, x9\nb.ne @248\nmov w0, w19\nldp x20, x19, [sp, #0x30]\nldp x29, x30, [sp, #0x20]\nadd sp, sp, #0x40\nautiasp \nret '
