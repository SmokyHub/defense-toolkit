"""Reviewed RSPAK01 resource loader: HKDF-SHA256, AES-GCM and DEX validation.

No sample code is executed. Instruction models are compiler scoped; keys and APK
identity come from the supplied inputs, never a package or native-hash whitelist.
"""
import base64
import hashlib
import hmac
import json
import re
import struct
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from family5_elf import Unsupported
from classloader_report import location

MAX_CONTAINER = 32 * 1024 * 1024
MAX_META = 1024 * 1024
MAX_CHUNKS = 4096


def instruction_shape(code, root, imports):
    rows = []
    for ins in code:
        operands = ins.op_str
        if ins.mnemonic == 'bl':
            target = ins.operands[0].imm
            operands = '@' + imports.get(target, str(target - root))
        elif ins.mnemonic in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
            operands = operands.rsplit('#', 1)[0] + '@' + str(ins.operands[-1].imm - root)
        elif ins.mnemonic in ('adr', 'adrp'):
            operands = operands.split(',')[0] + ', @' + str(ins.operands[1].imm - root)
        rows.append(ins.mnemonic + ' ' + operands)
    return hashlib.sha256('\n'.join(rows).encode()).hexdigest()


def recover_model(img):
    from family5_native import import_targets, constant
    starts = set()
    for section in img.elf.iter_sections():
        if section['sh_type'] in ('SHT_DYNSYM', 'SHT_SYMTAB'):
            starts.update(s['st_value'] for s in section.iter_symbols()
                          if s.name == 'JNI_OnLoad' and s['st_shndx'] != 'SHN_UNDEF')
    if len(starts) != 1:
        return None
    root = starts.pop()
    model = json.loads(Path(__file__).with_name('family5_resource_models.json').read_text())
    imports = import_targets(img)
    for block in model['blocks']:
        start = root + block['offset']
        try:
            code = [img.byaddr[start + 4 * k] for k in range(block['instructions'])]
        except KeyError:
            return None
        if instruction_shape(code, root, imports) != block['shape_sha256']:
            return None
    switch = model['switch']
    if hashlib.sha256(img.read(root + switch['offset'], switch['bytes'])).hexdigest() != switch['sha256']:
        return None
    strings = []
    for item in model['strings']:
        va = root + item['offset']
        raw = bytes(b ^ 0x5a for b in img.read(va, item['bytes'])[::4])
        # Preserve the exact length and bytes consumed by the native loop.
        if raw != item['text'].encode():
            return None
        strings.append({'va': hex(va), 'text': item['text'].rstrip('\0'), 'encoding': 'stride4_xor_5a'})
    key = b''
    key_locations = []
    for source in model['master_key_loads']:
        page, load = img.byaddr[root + source['page']], img.byaddr[root + source['load']]
        # Instruction fingerprint binds the load, width and destination to the
        # reviewed HKDF input. Resolve the source address from this input ELF.
        va = page.operands[1].imm + load.operands[1].mem.disp
        key += img.read(va, 16)
        key_locations.append(location(img, va))

    def constructed_string(offset):
        code = img.function(root + offset)
        values = [constant(code, k, 'w1') for k, ins in enumerate(code)
                  if ins.mnemonic == 'bl' and ins.operands[0].imm == root + model['append_byte']]
        if not values or any(v is None or not 32 <= v < 127 for v in values):
            raise Unsupported('resource_string_construction_unresolved')
        return bytes(values).decode('ascii')

    ref = model['class_reference']
    reference = {k: location(img, root + off) for k, off in ref.items()}
    reference.update(text='dalvik/system/InMemoryDexClassLoader', resolution='decoded_static_reference',
                     encoding='stride4_xor_5a', jni_api='FindClass',
                     binding='reviewed_complete_resource_instruction_layout_and_string_constants')
    loader = {'status': 'named_classloader_reference_recovered',
              'mechanism': 'in_memory_dex_loader_and_existing_loader_dex_elements_injection',
              'referenced_class': reference['text'], 'concrete_runtime_class': None,
              'function': location(img, root + model['driver']), 'references': [reference],
              'operations': [{'api': api, 'location': location(img, root + off)}
                             for api, off in model['operations'].items()],
              'reason': 'Reviewed native flow supplies reconstructed DEX via NewDirectByteBuffer to InMemoryDexClassLoader, then copies dexElements into the application loader. Static references only; runtime gates and execution are not evaluated.'}
    return {'master_key': key, 'key_locations': key_locations,
            'asset_name': 'assets/' + constructed_string(model['asset_name_function']),
            'item_ids': [constructed_string(off) for off in model['item_name_functions']],
            'strings': strings, 'classloader': loader}


def hkdf(ikm, salt, info):
    """Reviewed HKDF extract and single-block expand to 32 bytes."""
    return hmac.digest(hmac.digest(salt, ikm, 'sha256'), info + b'\x01', 'sha256')


def strict_json(raw):
    # Bound depth before parsing: callers may have raised Python's recursion
    # limit, and authenticated metadata remains an untrusted input.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                raise ValueError('resource_metadata_depth_exceeded')
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_resource_metadata_key')
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError('invalid_JSON_constant')

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid_resource_metadata_JSON') from error


def decode_container(data, master_key, package, version, item_ids):
    from family5_native import validate_dex

    def require(value, diagnostic):
        if not value:
            raise ValueError(diagnostic)

    def integer(obj, name, maximum=MAX_CONTAINER):
        value = obj.get(name)
        require(type(value) is int and 0 <= value <= maximum, 'invalid_resource_' + name)
        return value

    def digest(raw, expected):
        require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
                and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected), 'resource_SHA256_mismatch')

    require(64 <= len(data) <= MAX_CONTAINER and data[:8] == b'RSPAK01\0', 'invalid_resource_container_header')
    container_version, count, meta_size = struct.unpack_from('<III', data, 8)
    require(container_version == 2, 'unsupported_resource_container_version')
    require(1 <= count <= MAX_CHUNKS and 16 <= meta_size <= MAX_META and 64 + meta_size < len(data),
            'invalid_resource_container_sizes')
    require(isinstance(package, str) and 0 < len(package) <= 255 and '\0' not in package
            and type(version) is int and 0 <= version < 2**31, 'invalid_resource_APK_identity')
    salt = data[32:48]
    info = b'pak' + package.encode('utf-8') + b'\0' + struct.pack('<Q', version) + data[48:64]
    pak_key = hkdf(master_key, salt, info)
    try:
        raw = AESGCM(hkdf(pak_key, salt, b'meta')).decrypt(data[20:32], data[64:64 + meta_size], None)
    except InvalidTag as error:
        raise ValueError('resource_metadata_GCM_authentication_failed') from error
    meta = strict_json(raw)
    require(isinstance(meta, dict) and type(meta.get('version')) is int and meta['version'] == container_version
            and meta.get('algorithm') == 'AES-256-GCM', 'unsupported_resource_metadata')
    items = meta.get('items')
    require(isinstance(items, list) and len(items) == len(item_ids) and len(set(item_ids)) == len(item_ids),
            'unexpected_resource_item_count')
    require(all(isinstance(item, dict) and isinstance(item.get('id'), str) for item in items), 'invalid_resource_items')
    require(len({item['id'] for item in items}) == len(items)
            and {item['id'] for item in items} == set(item_ids), 'resource_item_selection_mismatch')
    payloads, reports, ranges = [], [], []
    chunks_seen = 0
    start = 64 + meta_size
    for item_id in item_ids:
        item = next(i for i in items if i['id'] == item_id)
        total = integer(item, 'totalPlainSize')
        chunks = item.get('chunks')
        require(0 < total and isinstance(chunks, list) and 1 <= len(chunks) <= count, 'invalid_resource_chunks')
        chunks_seen += len(chunks)
        require(chunks_seen <= count, 'resource_chunk_count_mismatch')
        plain = bytearray()
        ids = set()
        for index, chunk in enumerate(chunks):
            require(isinstance(chunk, dict), 'invalid_resource_chunk')
            require(integer(chunk, 'index', MAX_CHUNKS) == index and integer(chunk, 'offset') == len(plain),
                    'resource_plaintext_gap_or_overlap')
            length = integer(chunk, 'plainSize')
            off, size = integer(chunk, 'cipherOffset'), integer(chunk, 'cipherSize')
            require(0 < length <= total - len(plain) and size == length + 16
                    and off + size <= len(data) - start, 'resource_chunk_out_of_bounds')
            chunk_id = chunk.get('id')
            require(isinstance(chunk_id, str) and 0 < len(chunk_id) <= 255 and '\0' not in chunk_id
                    and chunk_id not in ids, 'invalid_resource_chunk_id')
            ids.add(chunk_id)
            iv_text = chunk.get('iv')
            require(isinstance(iv_text, str) and len(iv_text) == 16, 'invalid_resource_chunk_IV')
            try:
                iv = base64.b64decode(iv_text, validate=True)
                chunk_info = b'chunk' + struct.pack('<IQ', index, len(plain)) + chunk_id.encode('utf-8')
                decoded = AESGCM(hkdf(pak_key, salt, chunk_info)).decrypt(iv, data[start + off:start + off + size], None)
            except (InvalidTag, UnicodeError, ValueError) as error:
                raise ValueError('resource_chunk_GCM_authentication_or_IV_failed') from error
            digest(decoded, chunk.get('plainSha256'))
            plain.extend(decoded)
            ranges.append((off, off + size))
        require(len(plain) == total, 'resource_plaintext_size_mismatch')
        digest(plain, item.get('overallSha256'))
        dex = bytes(plain)
        reports.append({'item_id': item_id, 'chunks': len(chunks), 'dex': validate_dex(dex),
                        'all_GCM_tags_match': True, 'all_chunk_SHA256_match': True, 'overall_SHA256_matches': True})
        payloads.append(dex)
    require(chunks_seen == count, 'resource_chunk_count_mismatch')
    end = 0
    for low, high in sorted(ranges):
        require(low == end, 'resource_ciphertext_gap_or_overlap')
        end = high
    require(start + end == len(data), 'resource_unaccounted_container_bytes')
    return reports, payloads


def analyze_resource(img, assets, identities):
    model = recover_model(img)
    if model is None:
        return None
    result = {'family': 'family5', 'variant': 'resource_pak_v2', 'status': 'needs_review',
              'native_sha256': hashlib.sha256(img.data).hexdigest(), 'constructor_pool': None,
              'asset_models': [{'container': 'RSPAK01_v2', 'asset': model['asset_name'],
                                'key_derivation': 'HKDF_SHA256_package_version_bound',
                                'cipher': 'AES_256_GCM', 'master_key_sources': model['key_locations'],
                                'validation': 'reviewed_complete_resource_instruction_layout_and_string_constants'}],
              'jni_string_recovery': [{'strings': model['strings']}],
              'classloader': model['classloader'], 'payloads': [], 'class_loading': [],
              'diagnostics': [], 'runtime_execution_observed': False}
    try:
        valid = {(i['package'], i['version_code']) for i in identities if 'diagnostic' not in i}
        if len(valid) != 1 or any('diagnostic' in i for i in identities):
            raise ValueError('resource_requires_one_unambiguous_APK_package_and_version')
        package, version = valid.pop()
        selected = [a for a in assets if a['name'] == model['asset_name']]
        if not selected or len({hashlib.sha256(a['data']).hexdigest() for a in selected}) != 1:
            raise ValueError('resource_asset_missing_or_conflicting')
        asset = selected[0]
        reports, payloads = decode_container(asset['data'], model['master_key'], package, version, model['item_ids'])
        result.update(status='static_asset_dex_recovered', payloads=reports,
                      apk_identity={'package': package, 'version_code': version},
                      asset={'name': asset['name'], 'source': asset['source'], 'bytes': len(asset['data']),
                             'sha256': hashlib.sha256(asset['data']).hexdigest()})
        return result, payloads
    except ValueError as error:
        result['diagnostics'].append(str(error))
        return result, []
