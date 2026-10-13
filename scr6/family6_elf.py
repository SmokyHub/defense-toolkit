"""Bounded ARM64 ELF reader for the independent Family6 analyzer.

Adapted from the lab native reader; importing Family4 is not required.
"""
from __future__ import annotations
import io
import struct
from bisect import bisect_right
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

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
                    elif r['r_info_type'] in (257, 1025):  # ABS64 / GLOB_DAT
                        symbols = self.elf.get_section(sec['sh_link'])
                        symbol = symbols.get_symbol(r['r_info_sym'])
                        if symbol['st_shndx'] != 'SHN_UNDEF':
                            self.reloc[r['r_offset']] = symbol['st_value'] + r['r_addend']
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
        self.starts = sorted(set(self.starts) | symbols | self.constructors | {v for v in self.reloc.values() if v in valid_addresses})
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



class ArgumentSlice:
    """Cached basic-block boundaries for bounded backward constant slicing."""
    def __init__(self, insns, limit=128):
        self.insns = insns
        self.limit = limit
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
