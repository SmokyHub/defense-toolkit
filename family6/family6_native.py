"""Offline Family6 native models, string recovery and relocated JNI call evidence."""
import hashlib
import json
import re
from collections import deque
from pathlib import Path
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from family6_elf import Image, Unsupported, ArgumentSlice
from classloader_report import location, unresolved

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


def register(name):
    return name.replace('w', 'x', 1)


def constant(img, code, at, name, depth=0):
    """Local constants and relocated pointers; no execution or guessed call results."""
    if depth > 8:
        return None
    name = register(name)
    if name == 'xzr':
        return 0
    reader = ArgumentSlice(code, limit=2048)
    for k in range(at - 1, reader.lower_bound(at), -1):
        i = code[k]; ops = i.operands
        if i.mnemonic in ('bl', 'blr'):
            if name not in {f'x{n}' for n in range(19, 30)}:
                return None
            continue
        if name not in {register(i.reg_name(r)) for r in i.regs_access()[1]}:
            continue
        value = None
        if i.mnemonic in ('adr', 'adrp'):
            value = ops[1].imm
        elif i.mnemonic == 'mov':
            value = ops[1].imm if ops[1].type == ARM64_OP_IMM else constant(img, code, k, i.reg_name(ops[1].reg), depth + 1)
        elif i.mnemonic == 'add' and ops[2].type == ARM64_OP_IMM:
            base = constant(img, code, k, i.reg_name(ops[1].reg), depth + 1)
            if base is not None:
                value = base + (ops[2].imm << ops[2].shift.value)
        elif i.mnemonic == 'ldr' and not i.writeback and ops[1].type == ARM64_OP_MEM and not ops[1].mem.index:
            base = constant(img, code, k, i.reg_name(ops[1].mem.base), depth + 1)
            if base is not None:
                try:
                    value = img.q(base + ops[1].mem.disp)
                except Unsupported:
                    return None
        if value is not None and i.reg_name(ops[0].reg).startswith('w'):
            value &= 0xffffffff
        return value
    return None


def function_models(img):
    models = json.loads(Path(__file__).with_name('family6_models.json').read_text())
    imports = import_targets(img)
    expected = {name: value for name, value in models['functions'].items()}
    matches = {name: [] for name in expected}
    lengths = {len(value.splitlines()) for value in expected.values()}
    for start in img.starts:
        try:
            code = img.function(start)
        except Unsupported:
            continue
        if len(code) not in lengths:
            continue
        shape, _ = code_shape(img, code, imports)
        for name, value in expected.items():
            if shape == value:
                matches[name].append(start)
    return matches, imports


def string_pool(img, xor_helper, imports):
    symbols = {s.name: s['st_value'] for sec in img.elf.iter_sections()
               if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()
               if s['st_shndx'] != 'SHN_UNDEF'}
    targets = {xor_helper} | {va for va, name in imports.items() if symbols.get(name) == xor_helper}
    groups = {}
    for i in img.ins:
        if i.mnemonic == 'bl' and i.operands[0].imm in targets:
            code = img.function(i.address)
            groups[code[0].address] = code
    pools = []
    for start, code in groups.items():
        # The reviewed initializer is straight-line; conditionally decoded pools
        # would require a separate state/guard model.
        if any(i.mnemonic in ('b', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz') or i.mnemonic.startswith('b.') for i in code):
            continue
        rows = []; total = 0
        for k, i in enumerate(code):
            if i.mnemonic != 'bl' or i.operands[0].imm not in targets:
                continue
            va, length, key = (constant(img, code, k, r) for r in ('x0', 'w1', 'w2'))
            if None in (va, length, key) or not 1 <= length <= 4096 or not 0 <= key <= 255:
                continue
            total += length
            if total > 65536:
                raise Unsupported('decoded string pool budget exceeded')
            plain = bytes(b ^ key for b in img.read(va, length))
            if plain[-1:] == b'\0' and all(32 <= b < 127 for b in plain[:-1]):
                rows.append({'va': hex(va), 'call_va': hex(i.address), 'text': plain[:-1].decode()})
        if len(rows) >= 16:
            pools.append({'initializer_va': hex(start), 'xor_helper_va': hex(xor_helper), 'strings': rows})
    return pools


JNI_ANCHORS = (
    '(Ljava/lang/String;Ljava/lang/String;I)Ldalvik/system/DexFile;',
    '(Ljava/io/File;ZLjava/io/File;Ldalvik/system/DexFile;)V',
    '[Ldalvik/system/DexPathList$Element;',
    'dalvik/system/BaseDexClassLoader',
)


def jni_names(pool):
    """Known-plaintext candidates need two complete, independent long anchors.

    The native nibble/XOR decoder must separately match. This infers the key;
    it does not claim the key was recovered from a native constant or a server.
    """
    encoded = []
    for item in pool['strings']:
        text = item['text']
        if len(text) % 2 == 0 and re.fullmatch('[a-p]{2,4096}', text):
            encoded.append((item, bytes((ord(text[k]) - 97) * 16 + ord(text[k + 1]) - 97 for k in range(0, len(text), 2))))
    candidates = {}
    for _, raw in encoded:
        for anchor in JNI_ANCHORS[:2]:
            if len(raw) != len(anchor):
                continue
            stream = bytes(a ^ b for a, b in zip(raw, anchor.encode()))
            for period in range(1, 33):
                if len(raw) < period + 8 or any(stream[k] != stream[k % period] for k in range(len(stream))):
                    continue
                key = stream[:period]
                decoded = [(item, bytes(b ^ key[k % period] for k, b in enumerate(data))) for item, data in encoded]
                hits = [(item, raw) for item, raw in decoded if raw in [a.encode() for a in JNI_ANCHORS[:2]]]
                if len({raw for _, raw in hits}) != 2:
                    continue
                names = [{'va': item['va'], 'text': raw.decode()} for item, raw in decoded if all(32 <= b < 127 for b in raw)]
                candidates[key] = {'method': 'inferred_repeating_xor_with_two_independent_complete_JNI_anchors',
                                   'key_bytes': period, 'key_sha256': hashlib.sha256(key).hexdigest(),
                                   'anchors': [{'va': item['va'], 'text': raw.decode()} for item, raw in hits], 'strings': names}
    return list(candidates.values())


JNI_SLOTS = {0x30: 'FindClass', 0xf0: 'NewObjectA', 0xf8: 'GetObjectClass', 0x108: 'GetMethodID',
             0x120: 'CallObjectMethodA', 0x138: 'CallBooleanMethodA', 0x2f0: 'GetFieldID',
             0x2f8: 'GetObjectField', 0x340: 'SetObjectField', 0x388: 'GetStaticMethodID',
             0x398: 'CallStaticObjectMethodV', 0x3a0: 'CallStaticObjectMethodA',
             0x538: 'NewStringUTF', 0x558: 'GetArrayLength', 0x560: 'NewObjectArray',
             0x568: 'GetObjectArrayElement', 0x570: 'SetObjectArrayElement'}


def pointer_states(img, code):
    """Conservative CFG constants: a value survives a join only on agreement.

    Both conditional edges are followed, including flattened dispatch loops.
    Unknown loads and caller-clobbered registers are discarded.
    """
    positions = {i.address: k for k, i in enumerate(code)}
    states = [None] * len(code); states[0] = {}
    pending = deque([0]); steps = 0
    while pending:
        k = pending.popleft(); steps += 1
        if steps > 200000:
            raise Unsupported('JNI pointer dataflow budget exceeded')
        ins = code[k]; ops = ins.operands; before = states[k]; after = dict(before)
        def reg(r):
            name = register(ins.reg_name(r))
            return 0 if name == 'xzr' else before.get(name)
        value = None
        if ins.mnemonic in ('adr', 'adrp'):
            value = ops[1].imm
        elif ins.mnemonic == 'mov':
            value = ops[1].imm if ops[1].type == ARM64_OP_IMM else reg(ops[1].reg)
        elif ins.mnemonic == 'add' and ops[2].type == ARM64_OP_IMM and reg(ops[1].reg) is not None:
            value = reg(ops[1].reg) + (ops[2].imm << ops[2].shift.value)
        elif (ins.mnemonic == 'ldr' and not ins.writeback and ops[1].type == ARM64_OP_MEM
              and not ops[1].mem.index and reg(ops[1].mem.base) is not None):
            try:
                value = img.q(reg(ops[1].mem.base) + ops[1].mem.disp)
            except Unsupported:
                pass
        for r in ins.regs_access()[1]:
            after.pop(register(ins.reg_name(r)), None)
        if value is not None:
            name = ins.reg_name(ops[0].reg)
            after[register(name)] = value & 0xffffffff if name.startswith('w') else value
        if ins.mnemonic in ('bl', 'blr'):
            after = {r: v for r, v in after.items() if r in {f'x{n}' for n in range(19, 30)}}
        successors = []
        if ins.mnemonic not in ('b', 'br', 'ret') and k + 1 < len(code):
            successors.append(k + 1)
        if ins.mnemonic == 'b' or ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            target = positions.get(ops[-1].imm)
            if target is not None:
                successors.append(target)
        for target in successors:
            old = states[target]
            joined = dict(after) if old is None else {r: v for r, v in old.items() if after.get(r) == v}
            if old != joined:
                states[target] = joined; pending.append(target)
    return states


def jni_calls(img, start, find_class):
    wrappers = {find_class: (0x30, 'FindClass')}
    for target in set(img.reloc.values()):
        code = [img.byaddr.get(target + i * 4) for i in range(3)]
        if any(i is None for i in code):
            continue
        a, b, c = code
        if (a.mnemonic != 'ldr' or b.mnemonic != 'ldr' or c.mnemonic != 'br'
                or a.op_str.split(', ', 1)[-1] != '[x0]' or b.operands[1].type != ARM64_OP_MEM
                or b.operands[1].mem.index or b.operands[1].mem.base != a.operands[0].reg
                or c.operands[0].reg != b.operands[0].reg):
            continue
        slot = b.operands[1].mem.disp
        if slot in JNI_SLOTS:
            wrappers[target] = (slot, JNI_SLOTS[slot])
    code = img.function(start); calls = []; states = pointer_states(img, code)
    for k, i in enumerate(code):
        if i.mnemonic != 'blr':
            continue
        target = (states[k] or {}).get(register(i.reg_name(i.operands[0].reg)))
        if target in wrappers:
            slot, api = wrappers[target]
            calls.append({'call_va': hex(i.address), 'wrapper_va': hex(target), 'jni_slot': hex(slot), 'api': api})
    return calls


def analyze_native(data):
    img = Image(data)
    matches, imports = function_models(img)
    result = {'family': 'family6', 'status': 'needs_review', 'diagnostics': [],
              'native_sha256': hashlib.sha256(data).hexdigest(),
              'model_matches': {name: [hex(v) for v in values] for name, values in matches.items()},
              'runtime_execution_observed': False}
    result['classloader'] = unresolved('Reviewed native models and decoded JNI references have not all been validated.')
    if any(len(values) != 1 for values in matches.values()):
        result['diagnostics'].append('missing_or_ambiguous_reviewed_native_models')
        return result
    addresses = {name: values[0] for name, values in matches.items()}
    pools = string_pool(img, addresses['xor_string'], imports)
    result['string_pools'] = pools
    if len(pools) != 1:
        result['diagnostics'].append('missing_or_ambiguous_string_initializer')
        return result
    names = jni_names(pools[0]); result['jni_string_recovery'] = names
    calls = jni_calls(img, addresses['jni_loader'], addresses['find_class'])
    result['class_loading'] = {'function_va': hex(addresses['jni_loader']), 'calls': calls,
                               'evidence': 'reviewed_loader_instructions_and_relocated_JNI_wrappers'}
    required = {'FindClass', 'CallStaticObjectMethodA', 'GetFieldID', 'GetObjectField', 'SetObjectField', 'GetStaticMethodID',
                'NewObjectArray', 'GetObjectArrayElement', 'SetObjectArrayElement', 'NewObjectA'}
    if len(names) != 1 or not required <= {c['api'] for c in calls}:
        result['diagnostics'].append('JNI_names_or_relocated_call_structure_incomplete')
        return result
    # Bind normalized PC-relative data references back to the decoded pool.
    # Matching code with changed string pointers is insufficient evidence.
    loader = img.function(addresses['jni_loader']); states = pointer_states(img, loader)
    pool_by_va = {int(s['va'], 16): s['text'] for s in pools[0]['strings']}
    names_by_va = {int(s['va'], 16): s['text'] for s in names[0]['strings']}
    refs = []
    for k, ins in enumerate(loader):
        if ins.mnemonic != 'bl' or ins.operands[0].imm != addresses['nibble_xor']:
            continue
        state = states[k] or {}; va = state.get('x0'); size = state.get('x1')
        if va in names_by_va and size == len(pool_by_va[va]) + 1:
            refs.append({'call_va': hex(ins.address), 'string_va': hex(va), 'text': names_by_va[va]})
    result['class_loading']['decoded_string_calls'] = refs
    expected = ['android/content/Context', 'getClassLoader', '()Ljava/lang/ClassLoader;',
                'dalvik/system/BaseDexClassLoader', 'pathList', 'Ldalvik/system/DexPathList;',
                'dalvik/system/DexPathList', 'dexElements', '[Ldalvik/system/DexPathList$Element;',
                'dalvik/system/DexFile', 'loadDex', JNI_ANCHORS[0],
                'dalvik/system/DexPathList$Element', '<init>', JNI_ANCHORS[1]]
    if [r['text'] for r in refs] != expected:
        result['diagnostics'].append('JNI_loader_string_reference_binding_incomplete')
        return result
    # Bind the asset driver to the reviewed JNI loader and nibble decoder calls.
    driver = img.function(addresses['asset_driver'])
    sites = {name: [hex(i.address) for i in driver if i.mnemonic == 'bl' and i.operands[0].imm == addresses[name]]
             for name in ('jni_loader', 'nibble_xor')}
    if any(not values for values in sites.values()):
        result['diagnostics'].append('asset_driver_to_loader_or_string_decoder_link_missing')
        return result
    result['asset_decoder'] = {'function_va': hex(addresses['asset_driver']),
                               'transform': 'output[i] = input[i] XOR key[i % len(key)]',
                               'phase': 'reset for each asset, continuous across reads',
                               'read_call_vas': [hex(i.address) for i in driver if i.mnemonic == 'bl' and imports.get(i.operands[0].imm) == 'AAsset_read'],
                               'linked_calls': sites,
                               'key_origin': 'native configuration argument; recovered asset key is inferred offline, not extracted from a native constant'}
    references = []
    # Within the complete matched loader, each decoded class name precedes its
    # FindClass lookup; method/field names precede the corresponding ID lookup.
    classes = {'android/content/Context', 'dalvik/system/BaseDexClassLoader',
               'dalvik/system/DexPathList', 'dalvik/system/DexFile', 'dalvik/system/DexPathList$Element'}
    methods = {'getClassLoader': 'GetMethodID', 'loadDex': 'GetStaticMethodID', '<init>': 'GetMethodID',
               'pathList': 'GetFieldID', 'dexElements': 'GetFieldID'}
    for ref in refs:
        api = 'FindClass' if ref['text'] in classes else methods.get(ref['text'])
        if not api:
            continue
        call = next((c for c in calls if c['api'] == api and int(c['call_va'], 16) > int(ref['call_va'], 16)), None)
        if call is None:
            result['diagnostics'].append('named_JNI_lookup_binding_missing')
            return result
        references.append({'text': ref['text'], 'resolution': 'statically_decoded_and_code_referenced',
                           'encoding': 'constant_XOR_then_nibble_repeating_XOR',
                           'storage': location(img, int(ref['string_va'], 16)),
                           'decode_call': location(img, int(ref['call_va'], 16)),
                           'jni_lookup': location(img, int(call['call_va'], 16)), 'jni_api': api,
                           'jni_wrapper': location(img, int(call['wrapper_va'], 16)),
                           'binding': 'complete_reviewed_loader_model_and_decoded_argument_addresses'})
    result['classloader'] = {'status': 'resolved_static_reference',
                            'mechanism': 'existing_loader_dex_path_injection',
                            'referenced_class': 'dalvik.system.BaseDexClassLoader',
                            'concrete_runtime_class': None,
                            'function': location(img, addresses['jni_loader']), 'references': references,
                            'operations': [{'api': c['api'], 'location': location(img, int(c['call_va'], 16))}
                                           for c in calls if c['api'] in ('CallObjectMethodA', 'CallStaticObjectMethodA', 'NewObjectA', 'NewObjectArray', 'SetObjectField')],
                            'reason': 'Resolves BaseDexClassLoader and modifies pathList.dexElements of an existing loader using DexFile.loadDex. The reference identifies a base type; the concrete runtime subtype is unobserved.'}
    result['status'] = 'native_asset_loader_identified'
    return result
