"""Conservative indexed-pool Family4 reader; no execution or sample identities.

A reviewed instruction graph binds the decoder, parser, JNI loader and trigger.
Code/data relocations and response selectors are read from the input. Unknown
instructions, changed guards or ambiguous bindings fail closed.
"""
import hashlib
import json
import re
import struct
from pathlib import Path


def imports(img):
    slots = {}
    for sec in img.elf.iter_sections():
        if sec['sh_type'] == 'SHT_RELA':
            symbols = img.elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                if r['r_info_type'] == 1026:
                    slots[r['r_offset']] = symbols.get_symbol(r['r_info_sym']).name
    result = {}
    for k, ins in enumerate(img.ins[:-2]):
        body = img.ins[k:k+4]
        if ins.mnemonic == 'bti':
            body = body[1:]
        if len(body) >= 2 and body[0].mnemonic == 'adrp' and body[1].mnemonic == 'ldr':
            if body[0].op_str.startswith('x16,') and body[1].op_str.startswith('x17, [x16,'):
                address = body[0].operands[1].imm + body[1].operands[1].mem.disp
                if address in slots:
                    result[ins.address] = slots[address]
    return result


def body(img, start, imported):
    from family4_native import Code, Unsupported, ARM64_OP_IMM
    pending = [start]; seen = {}
    while pending:
        va = pending.pop()
        if va in seen:
            continue
        if len(seen) >= 4096 or not start <= va < start + 65536:
            raise Unsupported('indexed helper flow exceeds bounds')
        ins = img.byaddr.get(va)
        if ins is None:
            raise Unsupported('indexed helper reaches undecoded code')
        seen[va] = ins
        if ins.mnemonic in ('ret', 'br'):
            continue
        if ins.mnemonic == 'bl' and imported.get(ins.operands[0].imm) in ('__stack_chk_fail', 'abort'):
            continue
        if ins.mnemonic == 'b' or ins.mnemonic.startswith('b.') or ins.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            if ins.operands[-1].type != ARM64_OP_IMM:
                raise Unsupported('indexed helper branch is not direct')
            pending.append(ins.operands[-1].imm)
            if ins.mnemonic == 'b':
                continue
        pending.append(va + 4)
    return Code(seen[a] for a in sorted(seen))


def shape(code, overrides):
    """Retain registers, predicates and constants; normalize only explicit sites."""
    positions = {i.address: k for k, i in enumerate(code)}
    rows = []
    for k, i in enumerate(code):
        if k in overrides:
            rows.append(overrides[k]); continue
        text = i.op_str
        if i.mnemonic == 'b' or i.mnemonic.startswith('b.') or i.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            text = re.sub(r'#[^, ]+$', '@' + str(positions[i.operands[-1].imm]), text)
        rows.append(i.mnemonic + ' ' + text)
    return '\n'.join(rows)


def parameter_shape(ins, count):
    """Mask reviewed scalar operands only; retain opcodes, widths and shifts' kinds."""
    return ins.mnemonic + ' ' + re.sub(r'#-?(?:0x[0-9a-f]+|\d+)', '<parameter>', ins.op_str, count=count)


def map_id(img, start, value, imported):
    """Interpret a bounded, pure integer decision tree. No memory or guest calls."""
    from family4_native import Unsupported, ARM64_OP_IMM, ARM64_OP_REG
    code = {i.address: i for i in body(img, start, imported)}
    allowed = {'bti', 'nop', 'mov', 'and', 'cmp', 'b.eq', 'b.ne', 'b.gt', 'b.le', 'ret'}
    if any(i.mnemonic not in allowed for i in code.values()):
        raise Unsupported('unmodeled string-ID mapper instruction')
    for ins in code.values():
        if ins.mnemonic == 'ret' and ins.op_str not in ('', 'x30'):
            raise Unsupported('unmodeled string-ID mapper return')
        if ins.mnemonic in ('mov', 'and', 'cmp'):
            count = 3 if ins.mnemonic == 'and' else 2
            if len(ins.operands) != count or any(op.shift.value or op.ext for op in ins.operands):
                raise Unsupported('unmodeled string-ID mapper operands')
            if any(op.type not in (ARM64_OP_IMM, ARM64_OP_REG) or
                   (op.type == ARM64_OP_REG and not re.fullmatch(r'w(?:\d+|zr)', ins.reg_name(op.reg)))
                   for op in ins.operands):
                raise Unsupported('unmodeled string-ID mapper width')
    regs = {'w0': value & 0xffffffff}; flags = None; pc = start
    def read(ins, op):
        if op.type == ARM64_OP_IMM: return op.imm
        name = ins.reg_name(op.reg)
        if name == 'wzr': return 0
        if name not in regs: raise Unsupported('unknown string-ID mapper register')
        return regs[name]
    for _ in range(4096):
        i = code.get(pc)
        if i is None: raise Unsupported('string-ID mapper exits modeled flow')
        m, ops = i.mnemonic, i.operands; pc += 4
        if m in ('nop','bti'): continue
        if m == 'ret': return regs['w0']
        if m in ('mov','and'):
            dst = i.reg_name(ops[0].reg)
            if not re.fullmatch(r'w\d+', dst): raise Unsupported('unsupported mapper width')
            value = read(i,ops[1]) if m == 'mov' else read(i,ops[1]) & read(i,ops[2])
            regs[dst] = value & 0xffffffff
        elif m == 'cmp':
            a,b = read(i,ops[0]) & 0xffffffff, read(i,ops[1]) & 0xffffffff
            signed = lambda x: x if x < 0x80000000 else x - 0x100000000
            flags = (a == b, signed(a) > signed(b))
        else:
            if flags is None: raise Unsupported('unknown mapper branch flags')
            take = {'b.eq':flags[0], 'b.ne':not flags[0], 'b.gt':flags[1], 'b.le':not flags[1]}[m]
            if take: pc = ops[0].imm
    raise Unsupported('string-ID mapper budget exceeded')


def verify_graph(img, root, model):
    from family4_native import Unsupported, ARM64_OP_IMM
    imported = imports(img); bound = {}; codes = {}; references = {}; constants = {}
    pending = [('entry', root)]
    while pending:
        name, start = pending.pop()
        if name in bound:
            if bound[name] != start: raise Unsupported('inconsistent indexed helper binding: ' + name)
            continue
        if start in bound.values(): raise Unsupported('aliased indexed helpers')
        bound[name] = start
        if name == 'mapper':
            map_id(img,start,0,imported)
            continue
        spec = model['functions'][name]; code = body(img,start,imported); codes[name] = code
        if len(code) != spec['instructions']: raise Unsupported('changed indexed helper length: ' + name)
        replacements = {}
        for key, edge in spec['edges'].items():
            k = int(key); i = code[k]
            if i.mnemonic != edge['mnemonic']: raise Unsupported('changed indexed call/reference')
            if not i.operands or i.operands[-1].type != ARM64_OP_IMM:
                raise Unsupported('changed indexed reference operand')
            if i.mnemonic in ('adr', 'adrp'):
                actual = i.mnemonic + ' ' + i.reg_name(i.operands[0].reg) + ', <address>'
                if actual != edge['shape']:
                    raise Unsupported('changed indexed address destination')
            target = i.operands[-1].imm
            replacements[k] = edge['shape']
            if 'import' in edge:
                if imported.get(target) != edge['import']: raise Unsupported('changed indexed import')
            elif 'function' in edge:
                pending.append((edge['function'], target))
            else:
                references[(name,k)] = target
                if 'literal' in edge and img.read(target,len(bytes.fromhex(edge['literal']))) != bytes.fromhex(edge['literal']):
                    raise Unsupported('changed indexed read-only literal')
        for key in spec.get('constants', []):
            k = int(key); i = code[k]
            if i.mnemonic != 'mov' or i.op_str.split(',')[0] != 'w0' or i.operands[1].type != ARM64_OP_IMM:
                raise Unsupported('changed indexed selector argument')
            replacements[k] = 'mov w0, <input-selector>'
            constants[(name,k)] = i.operands[1].imm
        for key, count in spec.get('parameters', {}).items():
            k = int(key)
            replacements[k] = parameter_shape(code[k], count)
        if hashlib.sha256(shape(code,replacements).encode()).hexdigest() != spec['shape_sha256']:
            raise Unsupported('changed indexed instruction graph: ' + name)
    # Check immutable SIMD/scalar parser limits referenced through ADRP pages.
    for item in model['literals']:
        target = references[(item['function'],item['instruction'])] + item['offset']
        literal = bytes.fromhex(item['hex'])
        if img.read(target,len(literal)) != literal: raise Unsupported('changed indexed parser limit/literal')
    return bound, codes, references, constants, imported


def decoder_parameters(model, code=None):
    """Derive scalar transform parameters after the complete body was checked."""
    from family4_native import Unsupported
    params = dict(model['decoder'])
    sites = params.get('parameter_sites')
    if code is None or not sites:
        raise Unsupported('indexed decoder requires verified instruction parameters')
    def word(pair):
        lo,hi = (code[k].operands[1].imm for k in pair)
        if not 0 <= lo <= 65535 or not 0 <= hi <= 65535:
            raise Unsupported('indexed decoder mask outside 32-bit model')
        return lo | (hi << 16)
    for key in ('offset_mask','length_mask','seed_mask'):
        params[key] = word(sites[key])
    params['index_mask'] = code[sites['index_mask']].operands[1].imm
    params['xorshift'] = [code[k].operands[2].shift.value for k in sites['xorshift']]
    params['subtract_state_shift'] = code[sites['subtract_state_shift']].operands[2].shift.value
    params['xor_state_shift'] = code[sites['xor_state_shift']].operands[2].shift.value
    rotate, width = (op.imm for op in code[sites['rotate_right']].operands[2:])
    complement = code[sites['rotate_complement']].operands[2].shift.value
    if not 1 <= rotate <= 7 or width != 8-rotate or complement != 8-rotate:
        raise Unsupported('inconsistent indexed byte rotation')
    params['rotate_right'] = rotate
    if (not all(1 <= s <= 31 for s in params['xorshift']) or
        not 0 <= params['subtract_state_shift'] <= 24 or not 0 <= params['xor_state_shift'] <= 24 or
        not 0 <= params['index_mask'] <= 65535):
        raise Unsupported('indexed decoder parameter outside supported range')
    return params


def decode_pool(img, addresses, model, imported, decoder_code=None):
    from family4_native import Unsupported
    decoder = decoder_parameters(model, decoder_code); refs = addresses
    tables = [refs[('decoder', k)] for k in decoder['table_instructions']]
    offsets,seeds,addends,lengths,cipher = tables
    rows = []
    for index in range(decoder['count']):
        word = lambda base: struct.unpack('<I',img.read(base+4*index,4))[0]
        start = word(offsets) ^ decoder['offset_mask']; size = word(lengths) ^ decoder['length_mask']
        if not 0 < size <= 16384 or start + size > decoder['pool_size']:
            raise Unsupported('indexed string table bounds')
        state = ((word(seeds)^decoder['seed_mask'])+word(addends)) & 0xffffffff
        plain = bytearray()
        for j,byte in enumerate(img.read(cipher+start,size)[::-1]):
            left,right,last = decoder['xorshift']
            state ^= (state << left) & 0xffffffff; state ^= state >> right; state ^= (state << last) & 0xffffffff
            v = (byte-j-(state>>decoder['subtract_state_shift'])) & 255
            rotation = decoder['rotate_right']
            plain.append(((v>>rotation)|((v<<(8-rotation))&255))^((state>>decoder['xor_state_shift'])&255))
        try: text = plain.decode('utf-8')
        except UnicodeError as error: raise Unsupported('indexed plaintext is not UTF-8') from error
        if any(ord(c)<32 or ord(c)==127 for c in text): raise Unsupported('indexed plaintext has control bytes')
        file_offset = next(s['p_offset']+cipher+start-s['p_vaddr'] for s in img.loads
                           if s['p_vaddr'] <= cipher+start < s['p_vaddr']+s['p_filesz'])
        rows.append({'index':index,'text':text,'length':size,'storage_va':hex(cipher+start),
                     'file_offset':hex(file_offset),'decoder_va':None,'decode_calls':[]})
    return rows


def analyze_indexed(img):
    results = []
    for filename in ('family4_indexed_models.json', 'family4_indexed_rotated_models.json'):
        model = json.loads(Path(__file__).with_name(filename).read_text())
        result = _analyze_model(img, model)
        if result is not None:
            results.append(result)
    supported = [r for r in results if r['status'] == 'supported']
    if len(supported) == 1:
        return supported[0]
    if len(supported) > 1:
        return {'family':'family4', 'status':'needs_review', 'contracts':[], 'strings':[],
                'diagnostics':['ambiguous indexed instruction models']}
    return results[0] if results else None


def _analyze_model(img, model):
    from family4_native import Unsupported, _validator_model, _jni_slot, _stack_source
    roots = []
    for sec in img.elf.iter_sections():
        if sec['sh_type'] in ('SHT_DYNSYM','SHT_SYMTAB'):
            roots.extend(s['st_value'] for s in sec.iter_symbols() if s.name == 'JNI_OnLoad' and s['st_shndx'] != 'SHN_UNDEF')
    if len(set(roots)) != 1: return None
    root = roots[0]
    try: bound,codes,refs,constants,imported = verify_graph(img,root,model)
    except Unsupported: return None
    try:
        params = decoder_parameters(model, codes['decoder'])
        rows = decode_pool(img,refs,model,imported,codes['decoder'])
        for row in rows: row['decoder_va'] = hex(bound['decoder'])
        for name,spec in model['functions'].items():
            for k in spec.get('string_calls', []):
                call = codes[name][int(k)]
                binding = spec['string_calls'][str(k)]
                argument = constants[(name,binding['argument_instruction'])]
                index = map_id(img,bound['mapper'],argument,imported)^params['index_mask']
                if not 0 <= index < len(rows): raise Unsupported('unresolved indexed string call')
                text = rows[index]['text']
                patterns = {'endpoint':r'https?://[^\s]+','bridge_class':r'[A-Za-z_$][A-Za-z0-9_$/]*',
                            'bridge_method':r'[A-Za-z_$][A-Za-z0-9_$]*','application_label':r'[A-Za-z0-9_.-]{1,128}'}
                if binding['kind'] == 'literal':
                    valid = text == binding['text']
                else:
                    valid = re.fullmatch(patterns[binding['kind']],text) is not None
                if not valid: raise Unsupported('changed indexed string use: ' + hex(call.address))
                rows[index]['decode_calls'].append({'call_va':hex(call.address),'string_id':argument})
        table = refs[('selectors',model['selector_table_instruction'])]
        keys = struct.unpack('<16Q',img.read(table,128))
        if len(set(keys[1:])) != 15 or not all(0 < x < 10**12 for x in keys): raise Unsupported('invalid indexed selectors')
        outer = constants[tuple(model['outer_selector_site'])]
        if outer != keys[0]: raise Unsupported('indexed trigger/parser selector mismatch')
        guard_model, helpers = _validator_model(img,img.function(bound['validator']))
        if not guard_model: raise Unsupported('unmodeled indexed DEX validator')
        roles = {role:str(keys[index+1]) for role,index in model['role_indices'].items()}
        # Emit fresh call addresses from the checked loader body and its frame arguments.
        evidence = []
        for k, i in enumerate(codes['loader']):
            slot = _jni_slot(codes['loader'],k)
            if slot in (0x108,0x388):
                a,b = _stack_source(codes['loader'],k,'x2'),_stack_source(codes['loader'],k,'x3')
                anchor = model['context_fields_offset']
                def key(off):
                    if off is not None and 0 <= off-anchor < 240 and (off-anchor)%16==0:
                        return str(keys[1+(off-anchor)//16])
                if key(a) and key(b): evidence.append({'jni_slot':hex(slot),'name_key':key(a),'signature_key':key(b),'call_va':hex(i.address)})
        if len(evidence) != 6: raise Unsupported('incomplete indexed JNI argument binding')
        values = {r['text'] for r in rows}; endpoints = [r['text'] for r in rows if re.fullmatch(r'https?://[^\s]+',r['text'])]
        required = {'java/nio/ByteBuffer','allocateDirect','java/lang/ClassLoader','org/json/JSONObject','getResponseCode','POST','<init>'}
        if not required <= values or len(endpoints) != 1: raise Unsupported('incomplete indexed strings/endpoint')
        contract = {'outer_key':str(outer),'array_key':str(keys[2]),'roles':roles,'complete':True,
                    'table_va':hex(table),'parser_va':hex(bound['parser']),'loader_va':hex(bound['loader']),
                    'dex_validator_va':hex(bound['validator']),'validator_model':guard_model,'validator_helpers':helpers,
                    'role_evidence':evidence,'outer_trigger_evidence':[{'value':str(outer),'literal_va':hex(codes[model['outer_selector_site'][0]][model['outer_selector_site'][1]].address)}],
                    'diagnostics':[], 'guards':{'dex_min_bytes':112,'dex_max_bytes':33554432,
                    'dex_versions':['035','037','038','039','040','041'],'exact_file_size':True,
                    'header_and_table_bounds':True,'dex_checksum_checked_by_native':False},
                    'additional_checks':'Reviewed JSON preflight, allocation budgets, descriptor syntax and JNI type/assignability checks; conditional static contract.'}
        return {'family':'family4','variant':'indexed_string_pool','status':'supported',
                'decoder_transform': {k:params[k] for k in ('xorshift','subtract_state_shift','xor_state_shift','rotate_right')},
                'sha256':hashlib.sha256(img.data).hexdigest(),'endpoint':endpoints[0],'http_method':'POST',
                'strings':rows,'contracts':[contract],'diagnostics':[],
                'analysis_stages':[{'stage':'indexed_instruction_graph','status':'observed','candidate_count':len(bound)}],
                'evidence_level':'static_reconstruction_and_JNI_argument_binding','runtime_execution_observed':False,
                'limitations':['Compiler-scoped instruction graph; changed layouts or decoder instructions require review. No runtime execution observed.']}
    except (Unsupported,ValueError,struct.error,KeyError) as error:
        return {'family':'family4','variant':'indexed_string_pool','status':'needs_review',
                'strings':[], 'contracts':[], 'diagnostics':[str(error)],'runtime_execution_observed':False}
