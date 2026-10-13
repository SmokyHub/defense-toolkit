"""Independent offline Family5 asset and native evidence recovery."""
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path
from family5_elf import Image, Unsupported, ArgumentSlice, _address_refs, _jni_slot
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM

def import_targets(img):
    slots = {}
    for sec in img.elf.iter_sections():
        if sec['sh_type'] == 'SHT_RELA':
            symbols = img.elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                if rel['r_info_type'] == 1026:  # AArch64 JUMP_SLOT
                    slots[rel['r_offset']] = symbols.get_symbol(rel['r_info_sym']).name
    targets = {}
    for k, ins in enumerate(img.ins[:-3]):
        if ins.mnemonic != 'adrp':
            continue
        load, add, branch = img.ins[k + 1:k + 4]
        if (load.mnemonic == 'ldr' and load.operands[1].type == ARM64_OP_MEM
                and load.operands[1].mem.base == ins.operands[0].reg
                and add.mnemonic == 'add' and branch.mnemonic == 'br'
                and branch.operands[0].reg == load.operands[0].reg):
            name = slots.get(ins.operands[1].imm + load.operands[1].mem.disp)
            if name:
                targets[ins.address] = name
    return targets


def code_shape(img, code, imports):
    """Full instruction template, retaining conditions, widths and constants.

    Local branch targets retain relative offsets; direct calls retain imported
    symbol names or a stable local-callee index. PC-relative data addresses are
    labels. This is deliberately compiler-scoped, not semantic equivalence.
    """
    rows, callees = [], []
    for ins in code:
        operands = ins.op_str
        if ins.mnemonic == 'bl':
            target = ins.operands[0].imm
            name = imports.get(target)
            if name is None:
                if target not in callees:
                    callees.append(target)
                name = 'local_' + str(callees.index(target))
            operands = '@' + name
        elif (ins.mnemonic == 'b' or ins.mnemonic.startswith('b.')
              or ins.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz')):
            operands = re.sub(r'#[^, ]+$', '@' + str(ins.operands[-1].imm - code[0].address), operands)
        elif ins.mnemonic in ('adr', 'adrp'):
            operands = operands.split(',')[0] + ', @data'
        rows.append(ins.mnemonic + ' ' + operands)
    return '\n'.join(rows), callees


def constant(code, index, register):
    result = ArgumentSlice(code).value(index, register)
    return result[1] if result and result[0] == 'constant' else None


def recover_asset_model(img):
    models = json.loads(Path(__file__).with_name('family5_models.json').read_text())
    imports = import_targets(img)
    # Seed only functions that actually call the Android asset API.
    targets = {va for va, name in imports.items() if name == 'AAsset_read'}
    candidates = set()
    for ins in img.ins:
        if ins.mnemonic == 'bl' and ins.operands[0].imm in targets:
            candidates.add(img.function(ins.address)[0].address)
    found = []
    for start in sorted(candidates):
        shape, helpers = code_shape(img, img.function(start), imports)
        if helpers or shape != models['asset_decode']:
            continue
        for call in img.ins:
            if call.mnemonic != 'bl' or call.operands[0].imm != start:
                continue
            driver = img.function(call.address)
            index = next(k for k, i in enumerate(driver) if i.address == call.address)
            key, prefix, suffix = (constant(driver, index, r) for r in ('w3', 'w4', 'w5'))
            if key is None or not 0 <= key <= 255 or prefix is None or suffix is None:
                continue
            if not 0 <= prefix <= 1048576 or not 0 <= suffix <= 1048576:
                continue
            for k in range(index + 1, len(driver)):
                ins = driver[k]
                if ins.mnemonic != 'bl' or ins.operands[0].imm in imports:
                    continue
                size = constant(driver, k, 'w1')
                if size is None or not 1 <= size <= 1048576:
                    continue
                swap = img.function(ins.operands[0].imm)
                shape, helpers = code_shape(img, swap, imports)
                if shape != models['edge_swap'] or len(helpers) != len(models['edge_swap_helpers']):
                    continue
                if any(code_shape(img, img.function(h), imports)[0] != expected
                       for h, expected in zip(helpers, models['edge_swap_helpers'])):
                    continue
                found.append({'decoder_va': hex(start), 'driver_va': hex(driver[0].address),
                              'call_va': hex(call.address), 'xor_byte': key,
                              'prefix_bytes': prefix, 'suffix_bytes': suffix,
                              'edge_swap_va': hex(swap[0].address), 'edge_bytes': size,
                              'validation': 'complete_reviewed_instruction_templates_and_call_arguments'})
    return found


def decode_asset(data, model):
    prefix, suffix, edge = (model[k] for k in ('prefix_bytes', 'suffix_bytes', 'edge_bytes'))
    if len(data) < prefix + suffix:
        raise ValueError('Asset shorter than recovered trim lengths.')
    body = data[prefix:len(data) - suffix if suffix else len(data)]
    key = model['xor_byte']
    decoded = bytes(((b ^ key) ^ 255) if index & 1 else
                    (((b ^ key) >> 3) | ((b ^ key) << 5)) & 255
                    for index, b in enumerate(body))
    if len(decoded) >= 2 * edge:
        decoded = decoded[-edge:][::-1] + decoded[edge:-edge] + decoded[:edge][::-1]
    return decoded


def validate_dex(data):
    """Integrity and bounded tables, not an ART acceptance claim."""
    if len(data) < 112 or data[:8] not in (b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0', b'dex\n040\0'):
        raise ValueError('Reassembled bytes have no supported DEX header.')
    size, header, endian = struct.unpack_from('<III', data, 32)
    if size != len(data) or header != 112 or endian != 0x12345678:
        raise ValueError('DEX size/header/endian mismatch.')
    if hashlib.sha1(data[32:]).digest() != data[12:32]:
        raise ValueError('DEX SHA-1 signature mismatch.')
    if zlib.adler32(data[12:]) & 0xffffffff != struct.unpack_from('<I', data, 8)[0]:
        raise ValueError('DEX Adler-32 mismatch.')
    for offset, width in ((56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)):
        count, start = struct.unpack_from('<II', data, offset)
        if count and (start < 112 or start + count * width > len(data)):
            raise ValueError('DEX table outside recovered file.')
    strings_count, strings_off, types_count, types_off = struct.unpack_from('<IIII', data, 56)
    classes_count, classes_off = struct.unpack_from('<II', data, 96)
    classes = []
    for index in range(classes_count):
        type_index = struct.unpack_from('<I', data, classes_off + index * 32)[0]
        if type_index >= types_count:
            raise ValueError('Invalid DEX class type index.')
        string_index = struct.unpack_from('<I', data, types_off + type_index * 4)[0]
        if string_index >= strings_count:
            raise ValueError('Invalid DEX descriptor string index.')
        offset = struct.unpack_from('<I', data, strings_off + string_index * 4)[0]
        for _ in range(5):
            if offset >= len(data):
                raise ValueError('Truncated DEX string.')
            value = data[offset]
            offset += 1
            if value < 128:
                break
        else:
            raise ValueError('Invalid DEX string length.')
        end = data.find(b'\0', offset, min(len(data), offset + 16384))
        if end < 0:
            raise ValueError('Unterminated DEX descriptor.')
        classes.append(data[offset:end].decode('utf-8', errors='replace'))
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'dex_version': data[4:7].decode(), 'sha1_matches': True, 'adler32_matches': True,
            'file_size_matches': True, 'header_and_id_tables_bounded': True,
            'class_count': classes_count, 'class_descriptors': classes}


def recover_payload(pool, assets, model):
    """Match a constructor-referenced concatenation of 8-byte asset names.

    The reviewed driver slices this string in 8-byte pieces. No names, package
    identity, binary hash, known payload or guessed permutation is used.
    """
    by_name = {}
    for asset in assets:
        name = asset['name'].rsplit('/', 1)[-1]
        if len(name) == 8:
            by_name.setdefault(name, {})[hashlib.sha256(asset['data']).hexdigest()] = asset
    candidates = []
    for item in pool['strings']:
        text = item['text']
        if not 16 <= len(text) <= 512 or len(text) % 8:
            continue
        names = [text[k:k + 8] for k in range(0, len(text), 8)]
        if len(set(names)) != len(names) or any(len(by_name.get(name, {})) != 1 for name in names):
            continue
        selected = [next(iter(by_name[name].values())) for name in names]
        if sum(len(a['data']) for a in selected) > 32 * 1024 * 1024:
            continue
        data = b''.join(decode_asset(a['data'], model) for a in selected)
        evidence = {'name_table_va': item['va'], 'assets': [
            {'name': a['name'], 'source': a['source'], 'bytes': len(a['data']),
             'sha256': hashlib.sha256(a['data']).hexdigest()} for a in selected]}
        try:
            evidence['dex'] = validate_dex(data)
            evidence['status'] = 'validated_dex'
        except ValueError as error:
            evidence.update(status='needs_review', diagnostic=str(error))
            data = None
        candidates.append((evidence, data))
    return candidates


def loader_evidence(img, model):
    """Find JNI array-field injection called by the asset driver's caller.

    Encrypted class/method names remain unresolved. Do not turn JNI slot
    observations into a claim that a specific Java method executed.
    """
    names = {0x30: 'FindClass', 0x108: 'GetMethodID', 0x2f0: 'GetFieldID',
             0x2f8: 'GetObjectField', 0x340: 'SetObjectField', 0x538: 'NewStringUTF',
             0x558: 'GetArrayLength', 0x560: 'NewObjectArray',
             0x568: 'GetObjectArrayElement', 0x570: 'SetObjectArrayElement'}
    required = {0x2f0, 0x2f8, 0x340, 0x560, 0x568, 0x570}
    driver = int(model['driver_va'], 16)
    found, visited = [], set()
    for call in img.ins:
        if call.mnemonic != 'bl' or call.operands[0].imm != driver:
            continue
        parent = img.function(call.address)
        for sibling in parent:
            if sibling.mnemonic != 'bl':
                continue
            target = sibling.operands[0].imm
            if target in visited or target not in img.byaddr:
                continue
            visited.add(target)
            try:
                function = img.function(target)
            except Unsupported:
                continue
            events = [(i.address, _jni_slot(function, k)) for k, i in enumerate(function)
                      if i.mnemonic == 'blr']
            if not required <= {slot for _, slot in events}:
                continue
            found.append({'status': 'static_jni_array_field_injection',
                          'function_va': hex(function[0].address), 'shared_caller_va': hex(parent[0].address),
                          'asset_driver_call_va': hex(call.address), 'jni_loader_call_va': hex(sibling.address),
                          'calls': [{'va': hex(va), 'jni_slot': hex(slot), 'api': names[slot]}
                                    for va, slot in events if slot in names],
                          'limitation': 'Class and field names are encrypted; this is a classpath-injection structure, not resolved Java names or runtime execution.'})
    return found


def analyze_native(data, assets):
    img = Image(data)
    pool = recover_constructor_pool(img)
    result = {'family': 'family5', 'status': 'needs_review',
              'native_sha256': hashlib.sha256(data).hexdigest(), 'constructor_pool': pool,
              'asset_models': [], 'payloads': [], 'class_loading': [],
              'runtime_execution_observed': False, 'diagnostics': []}
    if pool is None:
        result['diagnostics'].append('constructor_bootstrap_pattern_not_recovered')
        return result, []
    models = recover_asset_model(img)
    result['asset_models'] = models
    if len(models) != 1:
        result['diagnostics'].append('asset_transform_unmodeled_or_ambiguous')
        return result, []
    result['class_loading'] = loader_evidence(img, models[0])
    candidates = recover_payload(pool, assets, models[0])
    result['payloads'] = [evidence for evidence, _ in candidates]
    recovered = [payload for _, payload in candidates if payload is not None]
    if len(candidates) == 1 and len(recovered) == 1 and len(result['class_loading']) == 1:
        result['status'] = 'static_asset_dex_recovered'
    else:
        result['diagnostics'].append('missing_or_ambiguous_assets_dex_integrity_or_jni_structure')
    return result, recovered if result['status'] == 'static_asset_dex_recovered' else []

def recover_constructor_pool(img):
    """Diagnostic-only recognition of a constructor-XOR bootstrap layout.

    These are code-referenced candidates, not an emulation of the constructor.
    This pool alone never enables a recovered-DEX result.
    """
    markers = {'v3uuid', 'v3k1', 'v3k2'}
    for start in sorted(img.constructors):
        try:
            code = img.function(start)
        except Unsupported:
            continue
        # Require both scalar and vector XOR code and a repeated-byte vector
        # constant. This bounds candidate keys without brute-forcing data.
        if not any(i.mnemonic == 'eor' and i.op_str.startswith('v') for i in code):
            continue
        scalar = {i.operands[1].imm for i in code
                  if i.mnemonic == 'mov' and len(i.operands) == 2
                  and i.operands[1].type == ARM64_OP_IMM
                  and 0 < i.operands[1].imm < 256}
        vector = {i.operands[1].imm for i in code
                  if i.mnemonic == 'movi' and len(i.operands) == 2
                  and re.match(r'v\d+\.(8|16)b,', i.op_str)
                  and i.operands[1].type == ARM64_OP_IMM}
        keys = scalar & vector
        if len(keys) != 1:
            continue
        key = keys.pop()
        references = set(va for _, va in _address_refs(code))
        if len(references) > 2048:
            continue
        decoded = {}
        for va in sorted(references):
            # Only writable file-backed globals, at most 512 bytes per ref.
            segment = next((s for s in img.loads if s['p_flags'] & 2
                            and s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']), None)
            if segment is None:
                continue
            raw = img.read(va, min(512, segment['p_vaddr'] + segment['p_filesz'] - va))
            end = raw.find(bytes([key]))  # XOR-encoded terminating NUL
            if not 0 < end < 512:
                continue
            plain = bytes(b ^ key for b in raw[:end])
            if all(32 <= b < 127 for b in plain):
                decoded[va] = plain.decode('ascii')
        values = set(decoded.values())
        ciphertext = [va for va, value in decoded.items()
                      if len(value) % 32 == 0 and re.fullmatch(r'[0-9a-f]{32,}', value)]
        if not markers <= values or len(ciphertext) < 8:
            continue
        return {
            'status': 'candidate_only',
            'pattern': 'constructor_xor_v3_preferences_bootstrap',
            'constructor_va': hex(start),
            'xor_byte': key,
            'markers': [{'text': value, 'va': hex(va)} for va, value in decoded.items()
                        if value in markers],
            'hex_ciphertext_candidates': len(ciphertext),
            'strings': [{'va': hex(va), 'text': text} for va, text in decoded.items()],
            'limitation': 'Static marker and code-reference evidence only; does not establish runtime decryption, family attribution, cipher semantics or response-field roles.',
        }
    return None
