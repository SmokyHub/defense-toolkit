"""Bounded ELF metadata and corroborated XOR discovery, independent of Qiling.

Program headers/dynamic tags are authoritative. Section headers are optional;
an invalid section table must not prevent analysis of a loadable image.
"""
from __future__ import annotations

import dataclasses
import struct


@dataclasses.dataclass(frozen=True)
class ProgramHeader:
    index: int
    header_offset: int
    type: int
    offset: int
    va: int
    filesz: int
    memsz: int
    flags: int
    align: int


class ElfImage:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 16 or data[:4] != b'\x7fELF':
            raise ValueError('Not an ELF file')
        if data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ValueError('Unsupported ELF class or byte order')
        self.bits = 32 if data[4] == 1 else 64
        self.endian = '<' if data[5] == 1 else '>'
        self.word = self.bits // 8
        h = self.unpack('HHIIIIIHHHHHH' if self.bits == 32 else 'HHIQQQIHHHHHH', 16)
        (_, self.machine, _, self.entry, phoff, self.shoff, _, _, phent,
         phnum, self.shent, self.shnum, self.shstr) = h
        if phnum == 0xffff:
            raise ValueError('Extended program-header counts are not supported')
        fmt = 'IIIIIIII' if self.bits == 32 else 'IIQQQQQQ'
        if phent < struct.calcsize(self.endian + fmt):
            raise ValueError('Invalid program-header entry size')
        self.range(phoff, phent * phnum)
        self.programs = []
        for i in range(phnum):
            offset = phoff + i * phent
            p = self.unpack(fmt, offset)
            if self.bits == 32:
                typ, off, va, _, filesz, memsz, flags, align = p
            else:
                typ, flags, off, va, _, filesz, memsz, align = p
            if typ in (1, 2):
                self.range(off, filesz)
            if typ == 1 and (filesz > memsz or memsz > 512 * 1024 * 1024):
                raise ValueError(f'Invalid/oversized PT_LOAD {i}')
            self.programs.append(ProgramHeader(i, offset, typ, off, va, filesz, memsz, flags, align))
        if not any(p.type == 1 for p in self.programs):
            raise ValueError('ELF has no PT_LOAD segments')
        self.section_error = None
        try:
            self.sections = self._sections()
        except (ValueError, struct.error) as exc:
            self.sections = []
            self.section_error = str(exc)
        self.dynamic = {}
        for p in self.programs:
            if p.type == 2:
                for off in range(p.offset, p.offset + p.filesz - 2 * self.word + 1, 2 * self.word):
                    tag, value = self.unpack('II' if self.bits == 32 else 'QQ', off)
                    if tag == 0:
                        break
                    self.dynamic.setdefault(tag, value)

    def range(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise ValueError(f'ELF range outside file: {offset:#x}+{size:#x}')

    def unpack(self, fmt, offset):
        self.range(offset, struct.calcsize(self.endian + fmt))
        return struct.unpack_from(self.endian + fmt, self.data, offset)

    def file_offset(self, va, size=1):
        for p in self.programs:
            if p.type == 1 and p.va <= va and va + size <= p.va + p.filesz:
                return p.offset + va - p.va
        raise ValueError(f'Virtual range is not file-backed: {va:#x}+{size:#x}')

    def _sections(self):
        if not self.shoff and not self.shnum:
            return []
        fmt = 'IIIIIIIIII' if self.bits == 32 else 'IIQQQQIIQQ'
        if not self.shoff or self.shent < struct.calcsize(self.endian + fmt):
            raise ValueError('Invalid section-header table')
        count = self.shnum or self.unpack(fmt, self.shoff)[5]
        self.range(self.shoff, count * self.shent)
        sections = [self.unpack(fmt, self.shoff + i * self.shent) for i in range(count)]
        string_index = sections[0][6] if self.shstr == 0xffff else self.shstr
        if string_index >= count:
            raise ValueError('Invalid section-name table index')
        for s in sections:
            if s[1] not in (0, 8):  # SHT_NULL / SHT_NOBITS occupy no file bytes
                self.range(s[4], s[5])
            if s[6] >= count and s[6] != 0:
                raise ValueError('Invalid section link')
        if string_index:
            strings = sections[string_index]
            if strings[1] != 3:
                raise ValueError('Invalid section-name string table')
            for s in sections:
                if s[0] >= strings[5]:
                    raise ValueError('Section name outside string table')
        return sections

    def without_sections(self):
        data = bytearray(self.data)
        struct.pack_into(self.endian + ('I' if self.bits == 32 else 'Q'), data,
                         32 if self.bits == 32 else 40, 0)
        struct.pack_into(self.endian + 'HHH', data, 46 if self.bits == 32 else 58, 0, 0, 0)
        return bytes(data)

    def symbol(self, index):
        if not index:
            return '', 0, False
        d = self.dynamic
        stride = d.get(11, 16 if self.bits == 32 else 24)
        expected = 16 if self.bits == 32 else 24
        if stride != expected or 6 not in d or 5 not in d:
            raise ValueError('Missing/invalid dynamic symbol table')
        off = self.file_offset(d[6] + index * stride, stride)
        if self.bits == 32:
            name, value, _, _, _, shndx = self.unpack('IIIBBH', off)
        else:
            name, _, _, shndx, value, _ = self.unpack('IBBHQQ', off)
        size = d.get(10, 0)
        if name >= size:
            raise ValueError('Symbol name outside DT_STRTAB')
        start = self.file_offset(d[5] + name, size - name)
        end = self.data.find(b'\0', start, start + size - name)
        if end < 0:
            raise ValueError('Unterminated dynamic symbol name')
        return self.data[start:end].decode('utf-8', errors='replace'), value, shndx != 0

    def relocations(self):
        """Yield (slot, type, symbol_index, addend); REL addends are read at runtime."""
        d = self.dynamic
        tables = [(d.get(7), d.get(8, 0), True, d.get(9)),
                  (d.get(17), d.get(18, 0), False, d.get(19))]
        if d.get(23):
            if d.get(20) not in (7, 17):
                raise ValueError('Invalid DT_PLTREL')
            tables.append((d[23], d.get(2, 0), d[20] == 7, None))
        seen = set()
        for va, size, rela, stride in tables:
            if not va or not size:
                continue
            fmt = ('IIi' if rela else 'II') if self.bits == 32 else ('QQq' if rela else 'QQ')
            expected = struct.calcsize(self.endian + fmt)
            if stride not in (None, expected) or size % expected:
                raise ValueError('Invalid dynamic relocation entry size')
            start = self.file_offset(va, size)
            for off in range(start, start + size, expected):
                if off in seen:
                    continue
                seen.add(off)
                row = self.unpack(fmt, off)
                shift = 8 if self.bits == 32 else 32
                yield row[0], row[1] & ((1 << shift) - 1), row[1] >> shift, row[2] if rela else None

    def relr_data(self):
        d = self.dynamic
        # Standard tags, then the older Android aliases.
        for addr, size, entry in ((36, 35, 37), (0x6fffe000, 0x6fffe001, 0x6fffe003)):
            if addr in d and size in d:
                if d.get(entry, self.word) != self.word or d[size] % self.word:
                    raise ValueError('Invalid DT_RELR entry size')
                start = self.file_offset(d[addr], d[size])
                return self.data[start:start + d[size]]
        return b''


XOR_ANCHORS = (
    b'dalvik/system/InMemoryDexClassLoader', b'android/content/res/AssetManager',
    b'dalvik/system/PathClassLoader', b'dalvik/system/DexClassLoader',
    b'java/net/HttpURLConnection', b'java/lang/ClassLoader', b'java/nio/ByteBuffer',
    b'()Landroid/content/res/AssetManager;', b'getAssets',
)

XOR_TABLES = tuple(bytes(i ^ key for i in range(256)) for key in range(256))


def xor_bytes(raw: bytes, key: bytes, phase: int = 0) -> bytes:
    if not key:
        raise ValueError('XOR key cannot be empty')
    result = bytearray(len(raw))
    for i in range(len(key)):
        result[i::len(key)] = raw[i::len(key)].translate(XOR_TABLES[key[(i + phase) % len(key)]])
    return bytes(result)


def canonical_key(key: bytes) -> bytes:
    for size in range(1, len(key) + 1):
        if len(key) % size == 0 and key == key[:size] * (len(key) // size):
            key = key[:size]
            break
    return min(key[i:] + key[:i] for i in range(len(key)))


def discover_xor_keys(raw, lengths=(1, 2, 4, 8, 16, 32), anchors=XOR_ANCHORS,
                      max_keys=16, max_matches=256):
    """Recover periodic keys; never accept a plaintext-derived key alone.

Require two distinct full anchor matches plus either a stored multi-byte key
or at least eight repeated-key constraints. Search is bounded per anchor/length.
The returned evidence describes static decoding, not observed execution.
"""
    results, seen = [], set()
    for length in sorted(set(lengths)):
        if not 1 <= length <= 256:
            raise ValueError('XOR key lengths must be between 1 and 256')
        eligible = [a for a in anchors if len(a) >= length + 4]
        if not eligible:
            continue
        diff = bytes(a ^ b for a, b in zip(raw, raw[length:]))
        for anchor in eligible:
            signature = bytes(a ^ b for a, b in zip(anchor, anchor[length:]))
            pos = -1
            for _ in range(max_matches):
                pos = diff.find(signature, pos + 1)
                if pos < 0:
                    break
                key = canonical_key(bytes(a ^ b for a, b in zip(raw[pos:pos + length], anchor)))
                if not any(key) or key in seen:
                    continue
                key_offset = None
                if len(key) >= 8:
                    for phase in range(len(key)):
                        found = raw.find(key[phase:] + key[:phase])
                        if found >= 0:
                            key_offset = found
                            break
                if key_offset is None and len(anchor) - length < 8:
                    continue
                evidence = []
                evidence_ranges = []
                for other in dict.fromkeys(anchors):
                    for phase in range(len(key)):
                        found = raw.find(xor_bytes(other, key, phase))
                        if found >= 0 and all(found + len(other) <= start or found >= end
                                              for start, end in evidence_ranges):
                            evidence.append({'anchor': other.decode('utf-8'), 'file_offset': found, 'phase': phase})
                            evidence_ranges.append((found, found + len(other)))
                            break
                if len(evidence) < 2:
                    continue
                results.append((key, {'stored_key_file_offset': key_offset, 'anchor_matches': evidence}))
                seen.add(key)
                if len(results) >= max_keys:
                    return results
    return results
