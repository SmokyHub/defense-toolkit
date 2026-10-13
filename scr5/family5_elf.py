"""Bounded ARM64 ELF reader for the independent Family5 analyzer.

Adapted from the lab native reader; importing Family4 is not required.
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
        # Constructors can be indirect-only and have neither symbols nor BTI.
        # Resolve their pointers before using them as function boundaries.
        self.constructors = set()
        for sec in self.elf.iter_sections():
            if sec['sh_type'] == 'SHT_INIT_ARRAY':
                if sec['sh_size'] % 8 or sec['sh_size'] > 8192:
                    raise Unsupported('constructor table exceeds reader model')
                for offset in range(0, sec['sh_size'], 8):
                    target = self.q(sec['sh_addr'] + offset)
                    if target in valid_addresses:
                        self.constructors.add(target)
        self.starts = sorted(set(self.starts) | symbols | self.constructors)
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


def _reg(ins, op):
    return ins.reg_name(op.reg).replace('w', 'x', 1) if op.type == ARM64_OP_REG else None

def _address_refs(insns):
    for k,i in enumerate(insns):
        if i.mnemonic=='adr':
            yield k,i.operands[1].imm
        elif i.mnemonic=='adrp' and k+1<len(insns):
            n=insns[k+1]
            if n.mnemonic=='add' and _reg(n,n.operands[1])==_reg(i,i.operands[0]) and n.operands[2].type==ARM64_OP_IMM:
                yield k,i.operands[1].imm+n.operands[2].imm


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
