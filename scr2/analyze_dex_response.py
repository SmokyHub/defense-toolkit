#!/usr/bin/env python3
"""Offline APK/ZIP DEX-response analyzer. Python 3.10+; semantic worker uses Androguard.

Automatic offline Dalvik consumer analysis and bounded Flutter discovery.
Reviewed AOT profiles are optional and must be explicitly selected on the CLI.
Unresolved flows remain inconclusive. No sample code, device, backend or external
service is used for analysis. Explicit --prepare-blutter may download toolchain
sources through an installed Blutter checkout. See docs/dex-response-analyzer.md.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import signal
import stat
import struct
import sys
import tempfile
import subprocess
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from dex_response_proof import build_proof, ProofUnavailable, encode_envelopes

FORMAT = 'apk-defense.dex-response/v1'
PLACEHOLDER = 'DEX ARRAY'
DEFAULT_CONTRACT = {
    'payload_class': 'com.apkdefense.fixture.webview.ResponseEntry',
    'entry_method': 'run',
    'entry_descriptor': '(Landroid/app/Activity;)V',
}
SCHEMA_URI = 'https://json-schema.org/draft/2020-12/schema'
MAX_PROFILE = 2 * 1024 * 1024


class AnalysisError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_load(text):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise AnalysisError(f'Duplicate JSON key: {key}')
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(AnalysisError(f'Invalid JSON: {value}')))


def integer(value, label='integer', minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise AnalysisError(f'Invalid {label}')
    return value


def bounded(data, start, length):
    if start < 0 or length < 0 or start + length > len(data):
        raise AnalysisError('Truncated or out-of-bounds binary structure')
    return data[start:start + length]


def load_segments(data):
    """ELF64 little-endian AArch64 PT_LOAD mapping; no section-name dependency."""
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise AnalysisError('Expected little-endian ELF64')
    if struct.unpack_from('<H', data, 18)[0] != 183:
        raise AnalysisError('Expected AArch64 ELF')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    if entsize != 56 or not 1 <= count <= 1024:
        raise AnalysisError('Unsupported ELF program-header table')
    bounded(data, phoff, entsize * count)
    segments = []
    for index in range(count):
        kind, flags, offset, va, _, filesz, memsz, align = struct.unpack_from('<II6Q', data, phoff + index * entsize)
        if kind != 1:
            continue
        bounded(data, offset, filesz)
        if memsz < filesz:
            raise AnalysisError('ELF file size exceeds memory size')
        segments.append(dict(offset=offset, va=va, filesz=filesz, memsz=memsz, flags=flags, align=align))
    if not segments or len({s['va'] for s in segments}) != len(segments):
        raise AnalysisError('Missing or ambiguous PT_LOAD mappings')
    return segments


def va_offset(segments, va, length=4):
    found = [s['offset'] + va - s['va'] for s in segments
             if s['va'] <= va and va + length <= s['va'] + s['filesz']]
    if len(found) != 1:
        raise AnalysisError('Address does not have one file-backed PT_LOAD mapping')
    return found[0]


def fingerprint(data, sites, normalization=None):
    """Mask ONLY imm16 bits of audited MOVZ X16 sites, preserving every other loaded byte.

    The mask admits numeric-key rotations, not arbitrary opcode, branch or callee changes.
    It deliberately rejects recompilations/unknown layouts instead of reusing stale offsets.
    """
    segments = load_segments(data)
    normalized = bytearray(data)
    if normalization == 'runtime_notes_v1':
        # ELF section-table coordinates and GNU build IDs are not load semantics.
        # Preserve the program headers, dynamic tables, code, data and relocations.
        normalized[40:48] = bytes(8)
        normalized[58:64] = bytes(6)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        count = struct.unpack_from('<H', data, 56)[0]
        for index in range(count):
            kind, _, offset, _, _, size, _, _ = struct.unpack_from('<II6Q', data, phoff + 56 * index)
            if kind != 4:  # PT_NOTE
                continue
            bounded(data, offset, size)
            cursor, end = offset, offset + size
            while cursor + 12 <= end:
                namesz, descsz, note_type = struct.unpack_from('<III', data, cursor)
                name_at = cursor + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                next_note = desc_at + ((descsz + 3) & ~3)
                if next_note > end:
                    raise AnalysisError('Invalid ELF note bounds')
                if note_type == 3 and bounded(data, name_at, namesz) == bytes((71, 78, 85, 0)):
                    normalized[desc_at:desc_at + descsz] = bytes(descsz)
                cursor = next_note
    elif normalization is not None:
        raise AnalysisError('Unknown ELF normalization mode')
    keys = {}
    offsets = set()
    for name, site in sites.items():
        va = integer(site['va'], 'site VA')
        offset = va_offset(segments, va, 12)
        if offset in offsets or va % 4:
            raise AnalysisError('Duplicate or unaligned key site')
        offsets.add(offset)
        word, store, branch = struct.unpack_from('<III', data, offset)
        # MOVZ X16, #imm16, LSL #0; STR X16,[X15]; BL decimal-conversion helper.
        if word & ~0x1FFFE0 != 0xD2800010 or store != 0xF90001F0 or branch & 0xFC000000 != 0x94000000:
            raise AnalysisError('Audited Smi key instruction pattern changed')
        immediate = (word >> 5) & 0xFFFF
        if immediate & 1:
            raise AnalysisError('Key is not an even tagged nonnegative Smi')
        keys[name] = str(immediate >> 1)
        struct.pack_into('<I', normalized, offset, word & ~0x1FFFE0)
    result = []
    for segment in segments:
        start, size = segment['offset'], segment['filesz']
        result.append({**segment, 'sha256': sha(normalized[start:start + size])})
    return result, keys


def manifest_identity(data):
    """Read package/version/split from text XML or bounded Android binary XML."""
    if data.lstrip().startswith(b'<'):
        import xml.etree.ElementTree as ET
        if b'<!DOCTYPE' in data or b'<!ENTITY' in data:
            raise AnalysisError('DTD/entities are not accepted in manifests')
        try:
            root = ET.fromstring(data)
        except ET.ParseError as error:
            raise AnalysisError(f'Malformed XML manifest: {error}') from error
        if root.tag.rsplit('}', 1)[-1] != 'manifest':
            raise AnalysisError('Expected manifest root element')
        attrs = {key.rsplit('}', 1)[-1]: value for key, value in root.attrib.items()}
        return {key: str(attrs[key]) for key in ('package', 'versionCode', 'versionCodeMajor', 'split') if key in attrs}
    if len(data) < 8 or struct.unpack_from('<H', data)[0] != 3:
        raise AnalysisError('Not an Android binary XML manifest')
    header, total = struct.unpack_from('<HI', data, 2)
    bounded(data, 0, total)
    if header < 8:
        raise AnalysisError('Invalid XML header')
    strings = []
    position = header
    while position < total:
        kind, hsize, size = struct.unpack('<HHI', bounded(data, position, 8))
        if hsize < 8 or size < hsize or position + size > total:
            raise AnalysisError('Invalid XML chunk')
        chunk = bounded(data, position, size)
        if kind == 1:
            if hsize < 28:
                raise AnalysisError('Invalid string pool header')
            count, _, flags, start, _ = struct.unpack_from('<5I', chunk, 8)
            bounded(chunk, hsize, count * 4)

            def length_at(pos, utf8):
                width = 1 if utf8 else 2
                first = int.from_bytes(bounded(chunk, pos, width), 'little')
                high = 0x80 if utf8 else 0x8000
                if first & high:
                    second = int.from_bytes(bounded(chunk, pos + width, width), 'little')
                    return ((first & (high - 1)) << (8 if utf8 else 16)) | second, pos + width * 2
                return first, pos + width

            for index in range(count):
                pos = start + struct.unpack_from('<I', chunk, hsize + 4 * index)[0]
                if flags & 0x100:
                    _, pos = length_at(pos, True)
                    length, pos = length_at(pos, True)
                    strings.append(bounded(chunk, pos, length).decode('utf-8'))
                else:
                    length, pos = length_at(pos, False)
                    strings.append(bounded(chunk, pos, length * 2).decode('utf-16le'))
        elif kind == 0x102:
            if hsize < 16:
                raise AnalysisError('Invalid XML element header')
            _, name, attr_start, attr_size, attr_count = struct.unpack('<IIHHH', bounded(chunk, hsize, 14))
            if name >= len(strings):
                raise AnalysisError('Invalid XML string index')
            if strings[name] == 'manifest':
                if attr_size < 20:
                    raise AnalysisError('Invalid XML attribute size')
                attrs = {}
                for index in range(attr_count):
                    attribute = bounded(chunk, hsize + attr_start + index * attr_size, attr_size)
                    _, key, raw, _, _, dtype, value = struct.unpack_from('<IIIHBBI', attribute)
                    if key >= len(strings):
                        raise AnalysisError('Invalid attribute key')
                    if raw != 0xFFFFFFFF or dtype == 3:
                        string_index = raw if raw != 0xFFFFFFFF else value
                        if string_index >= len(strings):
                            raise AnalysisError('Invalid attribute value')
                        value = strings[string_index]
                    attrs[strings[key]] = str(value)
                return {key: attrs[key] for key in ('package', 'versionCode', 'versionCodeMajor', 'split') if key in attrs}
        position += size
    raise AnalysisError('Manifest element not found')


class ArchiveReader:
    """Bounded in-memory traversal: no extractall, filesystem paths or sample execution."""
    def __init__(self, max_bytes=1024**3, max_member=256 * 1024**2, max_entries=30000, max_depth=4):
        self.max_bytes, self.max_member = max_bytes, max_member
        self.max_entries, self.max_depth = max_entries, max_depth
        self.bytes = self.entries = 0
        self.apks = []

    def read(self, source, label, depth=0):
        if depth > self.max_depth:
            raise AnalysisError('Nested archive depth limit exceeded')
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            self.entries += len(infos)
            if self.entries > self.max_entries:
                raise AnalysisError('Archive entry limit exceeded')
            names = set()
            for info in infos:
                path = PurePosixPath(info.filename)
                if (info.filename in names or path.is_absolute() or '..' in path.parts or
                        '\\' in info.filename or '\x00' in info.filename or re.match(r'^[A-Za-z]:', info.filename)):
                    raise AnalysisError('Unsafe or duplicate archive member name')
                names.add(info.filename)
                if stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK or info.flag_bits & 1:
                    raise AnalysisError('Symlink/encrypted ZIP entries are unsupported')
                if info.file_size > self.max_member:
                    raise AnalysisError('Archive member exceeds size limit')
                self.bytes += info.file_size
                if self.bytes > self.max_bytes:
                    raise AnalysisError('Aggregate expanded archive size limit exceeded')
            manifest = next((i for i in infos if i.filename == 'AndroidManifest.xml'), None)
            if manifest:
                manifest_data = archive.read(manifest)
                if len(manifest_data) > 8 * 1024**2:
                    raise AnalysisError('Manifest exceeds size limit')
                identity = manifest_identity(manifest_data)
                package = identity.get('package', '')
                if not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*', package, re.ASCII):
                    raise AnalysisError('Missing/invalid manifest package identity')
                artifacts = []
                for info in infos:
                    if info.is_dir() or info.filename == 'AndroidManifest.xml':
                        continue
                    with archive.open(info) as stream:
                        magic = stream.read(4)
                    if magic == b'\x7fELF' or magic == b'dex\n':
                        data = archive.read(info)
                        artifacts.append({'path': info.filename, 'origin': label, 'sha256': sha(data),
                                          'kind': 'ELF' if magic == b'\x7fELF' else 'DEX', 'data': data})
                self.apks.append({'origin': label, 'identity': identity, 'artifacts': artifacts})
                return
            children = [i for i in infos if not i.is_dir() and
                        PurePosixPath(i.filename).suffix.lower() in ('.apk', '.zip', '.apks', '.xapk', '.apkm')]
            if not children:
                raise AnalysisError('Archive contains neither a root AndroidManifest.xml nor APK/archive members')
            for info in children:
                self.read(io.BytesIO(archive.read(info)), label + '!/' + info.filename, depth + 1)


def validate_profile(profile):
    if not isinstance(profile, dict) or profile.get('format') != 'apk-defense.loader-profile/v1':
        raise AnalysisError('Unsupported loader profile format')
    if not re.fullmatch(r'[a-z0-9_-]{1,100}', profile.get('id', '')):
        raise AnalysisError('Invalid profile id')
    if not profile.get('evidence') or not profile.get('segments'):
        raise AnalysisError('Profile must cite a review and guard the full loaded ELF')
    if profile.get('elf_normalization') not in (None, 'runtime_notes_v1'):
        raise AnalysisError('Unknown ELF normalization mode')
    sites = profile.get('key_sites', {})
    if not isinstance(sites, dict) or len(sites) > 256:
        raise AnalysisError('Invalid key sites')
    for name, site in sites.items():
        if not isinstance(name, str) or not isinstance(site, dict):
            raise AnalysisError('Invalid site')
        integer(site.get('va'), 'site VA')
    for segment in profile['segments']:
        for field in ('va', 'offset', 'filesz', 'memsz', 'flags', 'align'):
            integer(segment.get(field), 'segment ' + field)
        if not re.fullmatch(r'[0-9a-f]{64}', segment.get('sha256', '')):
            raise AnalysisError('Invalid segment digest')
    bindings = profile.get('bindings')
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 256:
        raise AnalysisError('Invalid bindings')
    for binding in bindings:
        if not isinstance(binding, dict) or not isinstance(binding.get('role'), str):
            raise AnalysisError('Each binding requires a semantic role')
        path = binding.get('path')
        if not isinstance(path, list) or not 1 <= len(path) <= 32:
            raise AnalysisError('Invalid binding path')
        for part in path:
            if isinstance(part, dict):
                if set(part) != {'key'} or part['key'] not in sites:
                    raise AnalysisError('Unknown key reference')
            elif not (isinstance(part, str) or type(part) is int and 0 <= part <= 128):
                raise AnalysisError('Invalid path component')
        if binding.get('encoding', 'scalar') not in ('scalar', 'join'):
            raise AnalysisError('Unsupported binding encoding')
        if binding.get('encoding') == 'join':
            if not isinstance(binding.get('delimiter'), str) or not binding['delimiter']:
                raise AnalysisError('Joined values require a nonempty delimiter')
            if not isinstance(binding.get('values'), list) or not 2 <= len(binding['values']) <= 16:
                raise AnalysisError('Invalid joined value list')
        elif 'value' not in binding:
            raise AnalysisError('Missing binding value')
    # All dependencies must be hash-bound. Custom profiles are local reviewed configuration,
    # never trusted if found in a submitted app ZIP.
    for dependency in profile.get('dependencies', []):
        if not re.fullmatch(r'[0-9a-f]{64}', dependency.get('sha256', '')) or not dependency.get('path'):
            raise AnalysisError('Invalid profile dependency')
    for group in profile.get('equal_keys', []):
        if not isinstance(group, list) or len(group) < 2 or any(name not in sites for name in group):
            raise AnalysisError('Invalid key equality constraint')
    if not isinstance(profile.get('artifact_path'), str):
        raise AnalysisError('Profile must name its APK artifact path')
    for call in profile.get('fixed_calls', []):
        if not isinstance(call, dict) or not call.get('evidence'):
            raise AnalysisError('App-owned call must include static evidence')
        if 'contract' in call and ('value' not in call or call['contract'] not in DEFAULT_CONTRACT):
            raise AnalysisError('Invalid fixed contract constraint')
    return profile


def value_of(spec, contract):
    if isinstance(spec, dict):
        if set(spec) != {'contract'} or spec['contract'] not in contract:
            raise AnalysisError('Unknown value expression')
        return contract[spec['contract']]
    if not isinstance(spec, (str, int, float, bool, type(None))):
        raise AnalysisError('Binding values must be scalar or a contract reference')
    return spec


def assign(root, path, value):
    node = root
    for index, key in enumerate(path):
        last = index == len(path) - 1
        if isinstance(node, dict) and isinstance(key, str):
            if last:
                if key in node:
                    raise AnalysisError('Response field collision')
                node[key] = value
            else:
                expected = list if type(path[index + 1]) is int else dict
                if key not in node:
                    node[key] = expected()
                if not isinstance(node[key], expected):
                    raise AnalysisError('Conflicting response field shapes')
                node = node[key]
        elif isinstance(node, list) and type(key) is int:
            while len(node) <= key:
                node.append(_MISSING)
            if last:
                if node[key] is not _MISSING:
                    raise AnalysisError('Response array slot collision')
                node[key] = value
            else:
                expected = list if type(path[index + 1]) is int else dict
                if node[key] is _MISSING:
                    node[key] = expected()
                if not isinstance(node[key], expected):
                    raise AnalysisError('Conflicting response array shapes')
                node = node[key]
        else:
            raise AnalysisError('Path container type mismatch')


_MISSING = object()


def render(profile, keys, contract):
    template, fields, dex_paths, dex_encodings = {}, [], [], {}
    for call in profile.get('fixed_calls', []):
        if 'contract' in call and contract[call['contract']] != call['value']:
            raise AnalysisError('Selected payload contract conflicts with an app-owned constant')
    for binding in profile['bindings']:
        path = [keys[p['key']] if isinstance(p, dict) else p for p in binding['path']]
        if binding.get('encoding') == 'join':
            values = [str(value_of(item, contract)) for item in binding['values']]
            if any(binding['delimiter'] in item for item in values):
                raise AnalysisError('Packed-field delimiter collides with a supplied value')
            value = binding['delimiter'].join(values)
        else:
            value = value_of(binding['value'], contract)
        if binding.get('role') == 'dex_bytes':
            if value != PLACEHOLDER or binding.get('encoding', 'scalar') != 'scalar':
                raise AnalysisError('DEX binding must be the literal placeholder')
            dex_paths.append(path)
            dex_encodings[tuple(path)] = binding.get('wire_encoding', 'integer_array')
            if dex_encodings[tuple(path)] not in ('integer_array', 'base64', 'base64url'):
                raise AnalysisError('Unsupported DEX wire encoding')
        assign(template, path, value)
        fields.append({'path': path, 'role': binding['role'], 'value': value,
                       'provenance': binding.get('provenance', 'reviewed_compatible_test_value'),
                       'evidence': binding.get('evidence', profile['evidence'])})
    if not dex_paths:
        raise AnalysisError('Complete loader template requires a DEX byte binding')

    def schema(value, path, wire):
        if value is _MISSING:
            raise AnalysisError('Sparse response arrays need explicit reviewed values')
        if path in dex_paths and wire:
            if dex_encodings[tuple(path)] in ('base64', 'base64url'):
                alphabet = 'A-Za-z0-9_-' if dex_encodings[tuple(path)] == 'base64url' else 'A-Za-z0-9+/'
                return {'type': 'string', 'minLength': 4, 'contentEncoding': dex_encodings[tuple(path)],
                        'pattern': f'^(?:[{alphabet}]{{4}})*(?:[{alphabet}]{{2}}==|[{alphabet}]{{3}}=)?$',
                        'description': 'Base64-encoded DEX; semantic validity and entry contract require separate validation.'}
            # The reviewed NN555 parser accepts integer values and decimal strings, then
            # stores unsigned bytes. The contract restricts values to valid byte ranges.
            return {'type': 'array', 'minItems': 1, 'items': {'anyOf': [
                {'type': 'integer', 'minimum': 0, 'maximum': 255},
                {'type': 'string', 'pattern': '^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'}]},
                'description': 'DEX bytes. Schema validation does not verify DEX format or its entry contract.'}
        if isinstance(value, dict):
            return {'type': 'object', 'properties': {key: schema(item, path + [key], wire) for key, item in value.items()},
                    'required': list(value), 'additionalProperties': True}
        if isinstance(value, list):
            return {'type': 'array', 'prefixItems': [schema(item, path + [i], wire) for i, item in enumerate(value)],
                    'minItems': len(value), 'maxItems': len(value)}
        return {'const': value}

    template_schema = {'$schema': SCHEMA_URI, 'title': 'Analysis placeholder template', **schema(template, [], False)}
    response_schema = {'$schema': SCHEMA_URI, 'title': 'Compatible test response after DEX substitution', **schema(template, [], True)}
    result = {'template': template, 'template_schema': template_schema, 'response_schema': response_schema,
            'fields': fields, 'dex_paths': dex_paths, 'fixed_calls': profile.get('fixed_calls', []),
            'dex_encodings': [{'path': list(path), 'encoding': encoding} for path, encoding in dex_encodings.items()]}
    transforms = profile.get('response_transforms', [])
    if transforms:
        try:
            result['template'] = encode_envelopes(template, transforms)
        except ProofUnavailable as error:
            raise AnalysisError(str(error)) from error
        result['decoded_template'] = template
        result['response_transforms'] = transforms
        result['decoded_response_schema'] = response_schema
        result['template_schema'] = {'$schema': SCHEMA_URI, 'title': 'Encoded analysis placeholder template',
                                     **schema(result['template'], [], False)}
        # Chunk concatenation and decoded object validation need a second pass;
        # JSON Schema alone cannot express that cross-element transformation.
        key = transforms[0]['path'][0]
        result['response_schema'] = {'$schema': SCHEMA_URI, 'type': 'object', 'required': [key],
            'properties': {key: {'type': 'array', 'minItems': 1,
                'items': {'type': 'string', 'pattern': '^[A-Za-z0-9+/=]*$'},
                'description': 'Join fragments, Base64 decode, UTF-8 decode, then parse JSON. Decoded schema is separate.'}},
            'x-decoded-response-schema': response_schema}
    return result


SIGNALS = {
    'dex_loader_api': [b'InMemoryDexClassLoader', b'DexClassLoader'],
    'reflection_api': [b'getDeclaredMethod', b'loadClass'],
    'http_api': [b'HttpURLConnection', b'okhttp3', b'Cronet', b'package:http/'],
    'jni_bridge': [b'globalEnv_NewObject', b'FindClass'],
}


def candidate_sites(data, limit=128):
    """Untrusted hints only: identify numeric-string construction without naming consumers."""
    try:
        segments = load_segments(data)
    except AnalysisError:
        return []
    out = []
    for segment in segments:
        if not segment['flags'] & 1:
            continue
        start, end = segment['offset'], segment['offset'] + segment['filesz'] - 12
        for offset in range(start, end + 1, 4):
            word = struct.unpack_from('<I', data, offset)[0]
            if word & ~0x1FFFE0 != 0xD2800010:
                continue
            store, branch = struct.unpack_from('<II', data, offset + 4)
            immediate = (word >> 5) & 0xFFFF
            if store == 0xF90001F0 and branch & 0xFC000000 == 0x94000000 and not immediate & 1:
                va = segment['va'] + offset - start
                displacement = branch & 0x3FFFFFF
                if displacement & 0x2000000:
                    displacement -= 0x4000000
                out.append({'va': hex(va), 'possible_decimal': str(immediate >> 1),
                            'helper_va': hex(va + 8 + displacement * 4)})
                if len(out) >= limit:
                    return out
    return out


def match_profile(profile, artifact, artifacts):
    if artifact['path'] != profile['artifact_path']:
        return None
    try:
        actual, keys = fingerprint(artifact['data'], profile['key_sites'], profile.get('elf_normalization'))
    except AnalysisError:
        return None
    if actual != profile['segments']:
        return None
    for names in profile.get('equal_keys', []):
        if len({keys[name] for name in names}) != 1:
            return None
    for dependency in profile.get('dependencies', []):
        candidates = [a for a in artifacts if a['path'] == dependency['path']]
        matched = any(a['sha256'] == dependency['sha256'] for a in candidates)
        if not matched and dependency.get('runtime_segments'):
            for candidate in candidates:
                try:
                    digest, _ = fingerprint(candidate['data'], {}, 'runtime_notes_v1')
                    matched = matched or digest == dependency['runtime_segments']
                except AnalysisError:
                    pass
        if not matched:
            return None
    return keys


def semantic_discovery(artifacts, options):
    if options.get('disabled'):
        return {'findings': [], 'diagnostics': ['semantic_analysis_disabled']}
    blobs = [artifact for artifact in artifacts if artifact['kind'] == 'DEX' and
             re.fullmatch(r'classes\d*\.dex', artifact['path'])]
    if not blobs:
        return {'findings': [], 'diagnostics': ['no_dalvik_code_to_analyze']}
    python = options.get('python')
    if not python:
        local = Path(__file__).resolve().parents[1] / '.venvs/analysis/bin/python'
        if not local.is_file():local = Path.home() / 'tools/venv/bin/python'
        python = str(local) if local.is_file() else sys.executable
    worker = Path(__file__).resolve().with_name('dex_semantic.py')
    with tempfile.TemporaryDirectory(prefix='dex-semantic-') as temp:
        paths = []
        for index, artifact in enumerate(blobs):
            path = Path(temp) / f'classes-{index}.dex'
            path.write_bytes(artifact['data'])
            paths.append(str(path))
        try:
            process = subprocess.run([python, str(worker), '--contract', json.dumps(options.get('contract', DEFAULT_CONTRACT)), *paths], capture_output=True, text=True,
                                     timeout=options.get('timeout', 60), check=False)
            result = json_load(process.stdout)
            if not isinstance(result, dict) or not isinstance(result.get('findings'), list):
                raise AnalysisError('Invalid semantic-worker result')
            return result
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            return {'findings': [], 'diagnostics': ['semantic_worker_unavailable_or_failed: ' + str(error)]}


def flutter_discovery(artifacts, options):
    if options.get('disabled') or options.get('no_flutter'):
        return {'findings': [], 'diagnostics': ['flutter_analysis_disabled']}
    apps = [a for a in artifacts if a['path'] == 'lib/arm64-v8a/libapp.so']
    if not apps:
        return {'findings': [], 'diagnostics': ['no_arm64_flutter_image']}
    python = options.get('python')
    if not python:
        local = Path(__file__).resolve().parents[1] / '.venvs/analysis/bin/python'
        if not local.is_file():
            local = Path.home() / 'tools/venv/bin/python'
        python = str(local) if local.is_file() else sys.executable
    worker = Path(__file__).resolve().with_name('flutter_semantic.py')
    bridge = next((a for a in artifacts if a['path'] == 'lib/arm64-v8a/libdartjni.so'), None)
    with tempfile.TemporaryDirectory(prefix='flutter-semantic-') as temp:
        libapp = Path(temp) / 'libapp.so'
        libapp.write_bytes(apps[0]['data'])
        command = [python, str(worker), str(libapp)]
        command.extend(['--flutter-reader', options.get('flutter_reader', 'auto')])
        for key, flag in [('blutter_dir', '--blutter-dir'), ('blutter_bin', '--blutter-bin')]:
            value = options.get(key)
            for item in value if isinstance(value, (list, tuple)) else [value] if value else []:
                command.extend([flag, str(item)])
        if bridge:
            path = Path(temp) / 'libdartjni.so'
            path.write_bytes(bridge['data'])
            command.extend(['--bridge', str(path)])
        try:
            preparation = None
            if options.get('prepare_blutter'):
                if options.get('flutter_reader') == 'python':
                    raise ValueError('--flutter-reader python cannot be combined with --prepare-blutter')
                from flutter_toolchain import prepare_external
                engine = next((a for a in artifacts if a['path'] == 'lib/arm64-v8a/libflutter.so'), None)
                if engine:
                    (Path(temp) / 'libflutter.so').write_bytes(engine['data'])
                preparation = prepare_external(python, Path(temp), options.get('blutter_dir'),
                                               options.get('blutter_bin'), options.get('blutter_build_timeout', 1800))
                # Bind analysis to the exact prepared build, across multiple roots.
                command = [python, str(worker), str(libapp), '--blutter-bin', preparation['analyzer'],
                           '--flutter-reader', 'blutter']
                if bridge: command.extend(['--bridge', str(Path(temp) / 'libdartjni.so')])
            # File-backed stdout prevents an unbounded host-memory allocation.
            with (Path(temp) / 'result.json').open('w+b') as output, (Path(temp) / 'stderr').open('w+b') as errors:
                process = subprocess.Popen(command, stdout=output, stderr=errors,
                                           start_new_session=(os.name == 'posix'))
                try:
                    process.wait(timeout=options.get('flutter_timeout', 180))
                except subprocess.TimeoutExpired:
                    if os.name == 'posix':
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        process.kill()
                    process.wait()
                    raise
                output.seek(0); raw = output.read(16 * 1024**2 + 1)
                if len(raw) > 16 * 1024**2:
                    raise AnalysisError('Flutter worker result exceeds size limit')
                if process.returncode:
                    errors.seek(0)
                    raise AnalysisError('Flutter worker failed: ' + errors.read(2048).decode(errors='replace'))
                result = json_load(raw)
                if not isinstance(result, dict) or not isinstance(result.get('findings'), list):
                    raise AnalysisError('Invalid Flutter-worker result')
                if preparation: result['toolchain_preparation'] = preparation
                result['artifact'] = {'path': apps[0]['path'], 'sha256': apps[0]['sha256']}
                if bridge:
                    result['bridge_artifact'] = {'path': bridge['path'], 'sha256': bridge['sha256']}
                return result
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            return {'findings': [], 'diagnostics': ['flutter_worker_unavailable_or_failed: ' + str(error)]}


def analyze_app(apks, profiles, contract, semantic_options=None):
    package = apks[0]['identity']['package']
    versions = {(a['identity'].get('versionCode'), a['identity'].get('versionCodeMajor', '0')) for a in apks}
    if len(versions) > 1:
        raise AnalysisError(f'Mixed version codes in split set for {package}')
    identities = [a['identity'].get('split', '') for a in apks]
    if len(identities) != len(set(identities)):
        raise AnalysisError(f'Duplicate base/split identities for {package}')
    artifacts = [artifact for apk in apks for artifact in apk['artifacts']]
    paths = defaultdict(set)
    for artifact in artifacts:
        paths[artifact['path']].add(artifact['sha256'])
    if any(len(hashes) > 1 for hashes in paths.values()):
        raise AnalysisError(f'Conflicting executable members across splits for {package}')
    unique = {(a['path'], a['sha256']): a for a in artifacts}.values()
    inventory, matches = [], []
    for artifact in unique:
        signals = {name: [value.decode('ascii') for value in values if value in artifact['data']]
                   for name, values in SIGNALS.items()}
        signals = {name: values for name, values in signals.items() if values}
        facts = {key: artifact[key] for key in ('path', 'origin', 'sha256', 'kind')}
        facts['signals'] = signals
        for profile in profiles:
            keys = match_profile(profile, artifact, artifacts)
            if keys is not None:
                try:
                    rendered = render(profile, keys, contract)
                except AnalysisError as error:
                    facts.setdefault('rejected_templates', []).append(str(error))
                    continue
                matches.append({'profile_id': profile['id'], 'profile_source': profile['_source'],
                                'artifact': facts['path'], 'artifact_sha256': facts['sha256'],
                                'extracted_keys': keys, 'evidence': profile['evidence'],
                                'request': profile.get('request'), 'rendered': rendered})
        inventory.append(facts)
    semantic = {'findings': [], 'diagnostics': []}
    flutter = {'findings': [], 'diagnostics': ['explicit_profile_matched_flutter_discovery_skipped']}
    if not matches:
        flutter = flutter_discovery(list(unique), semantic_options or {})
        semantic = semantic_discovery(list(unique), {**(semantic_options or {}), 'contract': contract})
        for index, finding in enumerate(semantic['findings']):
            discovered = {'bindings': finding['bindings'], 'fixed_calls': finding['fixed_calls'],
                          'evidence': finding['evidence']}
            try:
                rendered = render(discovered, {}, finding['contract'])
            except AnalysisError as error:
                semantic['diagnostics'].append('schema_constraint_failure: ' + str(error))
                continue
            matches.append({'profile_id': f'dalvik_dataflow_{index + 1}', 'profile_source': 'automatic_consumer_dataflow',
                            'artifacts': [{'path': a['path'], 'sha256': a['sha256']} for a in unique if a['kind'] == 'DEX'],
                            'extracted_keys': {}, 'evidence': finding['evidence'], 'request': None,
                            'resolved_contract': finding['contract'], 'rendered': rendered})
        for index, finding in enumerate(flutter['findings']):
            try:
                rendered = render(finding, {}, contract)
            except AnalysisError as error:
                flutter['diagnostics'].append('schema_constraint_failure: ' + str(error))
                continue
            matches.append({'profile_id': f'flutter_dataflow_{index + 1}',
                            'profile_source': 'automatic_flutter_consumer_inference',
                            'artifacts': [{'path': a['path'], 'sha256': a['sha256']} for a in unique
                                          if a['path'].endswith(('/libapp.so', '/libdartjni.so'))],
                            'extracted_keys': {}, 'evidence': finding['evidence'], 'request': None,
                            'resolved_contract': contract, 'rendered': rendered})
    complete_input = '' in identities
    multiple_verified_paths = bool(matches) and all(m['profile_source'] == 'automatic_consumer_dataflow' for m in matches)
    complete = complete_input and (len(matches) == 1 or multiple_verified_paths)
    # Unknown patterns are still searched for candidates, but these are never promoted
    # to keys/roles or a claim of network-to-loader data flow.
    if not complete:
        for artifact, facts in zip(unique, inventory):
            if artifact['path'].endswith('/libapp.so'):
                facts['numeric_string_candidates'] = candidate_sites(artifact['data'])
    signals_present = any(item['signals'].get('dex_loader_api') for item in inventory)
    reason = ('conditional_flutter_consumer_contract' if complete and any(m['profile_source'] == 'automatic_flutter_consumer_inference' for m in matches) else
              'network_to_loader_consumer_dataflow' if complete and multiple_verified_paths else
              'reviewed_loaded_code_and_dependencies_match' if complete else
              'base_apk_missing' if not complete_input else
              'ambiguous_multiple_loader_profiles' if len(matches) > 1 else
              'automatic_discovery_incomplete')
    return {
        'package': package, 'version': dict(zip(('versionCode', 'versionCodeMajor'), next(iter(versions)))),
        'apks': [{'origin': a['origin'], 'identity': a['identity']} for a in apks],
        'capability': {'status': 'supported_by_static_evidence' if complete else 'possible' if signals_present else 'unknown',
                       'runtime_validated_this_run': False, 'reason': reason},
        'schema_status': 'complete_for_test_contract' if complete else 'needs_review',
        'automation': {'template_ready': complete, 'action': 'validate_template' if complete else 'manual_review'},
        'inventory': inventory, 'matches': matches if complete else [],
        'semantic_analysis': {key: value for key, value in semantic.items() if key != 'findings'},
        'flutter_analysis': {key: value for key, value in flutter.items() if key != 'findings'},
        'limitations': [
            'Offline static analysis; no sample, DEX, device or backend was executed/contacted.',
            'Filled method/class values implement the selected benign test contract, not recovered production server values.',
            'Unknown code, encrypted remote values and unreviewed call topologies require further analysis.',
            'Loader response branch only; unrelated UI/config response fields are outside this schema.',
            'A schema-valid integer array is not necessarily a valid DEX or a compatible payload.',
        ],
    }


def load_profiles(extra, include_builtin=False):
    locations = [(path, 'builtin') for path in sorted((Path(__file__).resolve().parent / 'dex_response_profiles').glob('*.json'))] if include_builtin else []
    locations += [(Path(path), 'custom_local_review_required') for path in extra]
    profiles, ids = [], set()
    for path, source in locations:
        if path.stat().st_size > MAX_PROFILE:
            raise AnalysisError('Profile exceeds size limit')
        profile = validate_profile(json_load(path.read_text()))
        if profile['id'] in ids:
            raise AnalysisError('Duplicate profile ID')
        ids.add(profile['id'])
        profile['_source'] = source
        profiles.append(profile)
    return profiles


def run(input_path, out_dir, profiles, contract, limits, semantic_options=None):
    if out_dir.exists():
        raise AnalysisError('Output path already exists; choose a fresh --out directory to avoid stale results')
    with input_path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else None
        if digest is None:
            stream.seek(0)
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(chunk)
            digest = hasher.hexdigest()
    reader = ArchiveReader(**limits)
    reader.read(input_path, input_path.name)
    groups = defaultdict(list)
    for apk in reader.apks:
        groups[apk['identity']['package']].append(apk)
    if not groups:
        raise AnalysisError('No APKs found')
    apps = [analyze_app(groups[key], profiles, contract, semantic_options) for key in sorted(groups)]
    result = {'format': FORMAT, 'input_sha256': digest, 'input_name': input_path.name,
              'analysis_mode': 'offline_explicit_profiles_and_discovery' if profiles else 'offline_automatic_discovery',
              'contract': contract, 'placeholder': PLACEHOLDER,
              'status': 'complete' if all(a['automation']['template_ready'] for a in apps) else 'needs_review',
              'apps': apps}
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.dex-response-', dir=out_dir.parent) as temp:
        staging = Path(temp) / 'result'
        staging.mkdir()
        for app in apps:
            for match in app['matches']:
                relative = Path(app['package']) / match['profile_id']
                target = staging / relative
                target.mkdir(parents=True)
                rendered = match.pop('rendered')
                match.update({'fields': rendered['fields'], 'dex_paths': rendered['dex_paths'],
                              'fixed_calls': rendered['fixed_calls'], 'dex_encodings': rendered['dex_encodings'], 'files': {}})
                for key, filename in [('template', 'response.template.json'), ('template_schema', 'template.schema.json'),
                                      ('response_schema', 'response.schema.json')]:
                    (target / filename).write_text(json.dumps(rendered[key], indent=2, ensure_ascii=False) + '\n')
                    match['files'][key] = (relative / filename).as_posix()
                try:
                    proof, metadata = build_proof(rendered, match.get('resolved_contract', contract))
                    filename = 'response.proof.json'
                    (target / filename).write_text(json.dumps(proof, indent=2, ensure_ascii=False) + '\n')
                    match['files']['proof_response'] = (relative / filename).as_posix()
                    match['proof_response'] = metadata
                except ProofUnavailable as error:
                    match['proof_response'] = {'status': 'unavailable', 'runtime_validated_this_run': False,
                                               'reason': str(error)}
        (staging / 'analysis.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
        staging.rename(out_dir)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='APK, ZIP of APK splits, APKS, XAPK or APKM; never uploaded')
    parser.add_argument('--out', required=True, type=Path, help='Fresh output directory')
    parser.add_argument('--proof-response', type=Path,
                        help='Also export the generated benign DEX response to a fresh file; requires one compatible complete loader')
    parser.add_argument('--print-template', action='store_true',
                        help='Print only the filled response JSON for one complete app; diagnostics go to stderr')
    parser.add_argument('--profile', action='append', default=[], help='Additional locally reviewed JSON loader profile')
    parser.add_argument('--reviewed-profiles', action='store_true', help='Opt in to bundled reviewed Flutter profiles (legacy path)')
    parser.add_argument('--no-semantic', action='store_true', help='Disable all automatic code analysis')
    parser.add_argument('--no-flutter', action='store_true', help='Disable automatic Flutter discovery only')
    parser.add_argument('--blutter-dir', action='append', help='Installed Blutter root or bin directory; repeat for multiple installations')
    parser.add_argument('--prepare-blutter', action='store_true', help='Explicitly build a matching semantic analyzer; may download toolchain sources, never uploads the app')
    parser.add_argument('--blutter-build-timeout', type=int, default=1800, help='Preparation timeout in seconds (default 1800); cached builds are reused')
    parser.add_argument('--blutter-bin', help='Installed snapshot-compatible native Blutter analyzer; never a download wrapper')
    parser.add_argument('--flutter-reader', choices=('auto', 'blutter', 'python'), default='auto',
                        help='auto: native if compatible, otherwise supported Python snapshot reader; python: no Blutter or compilation')
    parser.add_argument('--semantic-python', help='Python with Androguard, Capstone and pyelftools (lab venv is auto-detected)')
    parser.add_argument('--payload-class', default=DEFAULT_CONTRACT['payload_class'])
    parser.add_argument('--entry-method', default=DEFAULT_CONTRACT['entry_method'])
    parser.add_argument('--max-total-mib', type=int, default=1024)
    parser.add_argument('--max-member-mib', type=int, default=256)
    args = parser.parse_args(argv)
    try:
        if args.flutter_reader == 'python' and args.prepare_blutter:
            raise AnalysisError('--flutter-reader python cannot be combined with --prepare-blutter')
        if args.proof_response is not None and (args.proof_response.exists() or args.proof_response.is_symlink()):
            raise AnalysisError('--proof-response path already exists; refusing to overwrite it')
        if not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+', args.payload_class, re.ASCII):
            raise AnalysisError('Invalid Java payload class name')
        if not re.fullmatch(r'[A-Za-z_$][\w$]*', args.entry_method, re.ASCII):
            raise AnalysisError('Invalid Java entry method name')
        integer(args.blutter_build_timeout, 'Blutter build timeout', 1, 14400)
        integer(args.max_total_mib, 'total size limit', 1, 16384)
        integer(args.max_member_mib, 'member size limit', 1, 2048)
        contract = {**DEFAULT_CONTRACT, 'payload_class': args.payload_class, 'entry_method': args.entry_method}
        result = run(args.input, args.out, load_profiles(args.profile, include_builtin=args.reviewed_profiles), contract,
                     {'max_bytes': args.max_total_mib * 1024**2, 'max_member': args.max_member_mib * 1024**2},
                     {'disabled': args.no_semantic, 'python': args.semantic_python, 'no_flutter': args.no_flutter,
                      'blutter_dir': args.blutter_dir, 'blutter_bin': args.blutter_bin, 'flutter_reader': args.flutter_reader,
                      'prepare_blutter': args.prepare_blutter, 'blutter_build_timeout': args.blutter_build_timeout})
        outputs = [{'package': application['package'], 'profile_id': match['profile_id'],
                    **{name: str(args.out / path) for name, path in match['files'].items()}}
                   for application in result['apps'] for match in application['matches']]
        summary = {'format': FORMAT, 'status': result['status'], 'report': str(args.out / 'analysis.json'),
                   'apps': len(result['apps']), 'outputs': outputs}
        if args.proof_response is not None:
            if result['status'] != 'complete' or len(result['apps']) != 1 or len(outputs) != 1:
                raise AnalysisError('--proof-response requires exactly one complete app and loader path')
            if 'proof_response' not in outputs[0]:
                reason = result['apps'][0]['matches'][0]['proof_response']['reason']
                raise AnalysisError('Benign proof response unavailable: ' + reason)
            args.proof_response.parent.mkdir(parents=True, exist_ok=True)
            with args.proof_response.open('x', encoding='utf-8') as exported:
                exported.write(Path(outputs[0]['proof_response']).read_text())
            summary['proof_response_export'] = str(args.proof_response)
        if args.print_template:
            if result['status'] != 'complete':
                print(json.dumps(summary), file=sys.stderr)
                return 2
            if len(result['apps']) != 1 or len(outputs) != 1:
                raise AnalysisError('--print-template requires exactly one complete app and loader path; use the per-loader files in the report')
            sys.stdout.write(Path(outputs[0]['template']).read_text())
        else:
            print(json.dumps(summary))
        return 0 if result['status'] == 'complete' else 2
    except (AnalysisError, OSError, zipfile.BadZipFile, RuntimeError, struct.error, UnicodeError,
            json.JSONDecodeError, KeyError, TypeError) as error:
        print(json.dumps({'format': FORMAT, 'status': 'error', 'message': str(error)}),
              file=sys.stderr if args.print_template else sys.stdout)
        return 1


if __name__ == '__main__':
    sys.exit(main())
