"""Shared output formatting; bundled independently with each native analyzer."""


def location(img, va):
    """Use the ELF's file-backed PT_LOAD mapping, never a fixed VA delta."""
    result = {'elf_va': hex(va), 'file_offset': None, 'section': None}
    for segment in img.loads:
        if segment['p_vaddr'] <= va < segment['p_vaddr'] + segment['p_filesz']:
            result['file_offset'] = hex(segment['p_offset'] + va - segment['p_vaddr'])
            break
    for section in img.elf.iter_sections():
        if section['sh_flags'] & 2 and section['sh_addr'] <= va < section['sh_addr'] + section['sh_size']:
            result['section'] = section.name
            break
    instruction = img.byaddr.get(va)
    if instruction is not None:
        result['instruction'] = instruction.mnemonic + ' ' + instruction.op_str
    return result


def unresolved(reason):
    return {'status': 'unresolved', 'mechanism': 'unresolved', 'referenced_class': None,
            'concrete_runtime_class': None, 'references': [], 'reason': reason}


def summaries(report):
    return [{'source': r.get('source'), **{key: r['classloader'].get(key) for key in
             ('status', 'mechanism', 'referenced_class', 'concrete_runtime_class')}}
            for r in report['results'] if relevant(r)]


def relevant(result):
    return 'classloader' in result and (result['classloader']['status'] != 'unresolved'
            or bool(result.get('asset_models')) or bool(result.get('class_loading')))


def render(report):
    lines = ['Class-loader evidence — ' + report['family'],
             'DEX origin for recovered payloads: bundled APK assets (offline reconstruction).',
             'Addresses are ELF virtual addresses and original .so file offsets.',
             'For a rebased Ghidra import, add its relocation delta to the ELF VA.',
             'Concrete runtime class is not observed by these static analyzers.', '']
    def where(value):
        return ('ELF ' + value['elf_va'] + ', file ' + str(value['file_offset'])
                + ', section ' + str(value['section']))
    for result in report['results']:
        evidence = result.get('classloader')
        if not relevant(result):
            continue
        lines += ['Library: ' + result.get('source', '<native input>'),
                  'SHA-256: ' + result.get('native_sha256', result.get('sha256', 'unknown')),
                  'Status: ' + evidence['status'], 'Mechanism: ' + evidence['mechanism'],
                  'Referenced class: ' + (evidence['referenced_class'] or 'unresolved'),
                  'Concrete runtime class: ' + (evidence['concrete_runtime_class'] or 'unobserved'),
                  'Evidence: ' + evidence.get('reason', '')]
        if evidence.get('function'):
            lines.append('Loader function: ' + where(evidence['function']))
        if evidence.get('reference_diagnostic'):
            lines.append('Reference diagnostic: ' + evidence['reference_diagnostic'])
        for reference in evidence['references']:
            lines.append('  Reference: ' + (reference.get('text') or '<encrypted class name; unresolved>'))
            for key, label in (('storage', 'Encrypted string'), ('address_reference', 'Address reference'),
                               ('decode_call', 'String decoder call'), ('jni_lookup', 'JNI lookup')):
                if reference.get(key):
                    lines.append('    ' + label + ': ' + where(reference[key]))
            if reference.get('jni_api'):
                lines.append('    JNI API: ' + reference['jni_api'])
        for operation in evidence.get('operations', []):
            lines.append('  ' + operation['api'] + ': ' + where(operation['location']))
        lines.append('')
    if not any(relevant(r) for r in report['results']):
        lines.append('No supported native class-loader evidence was recovered. See analysis.json diagnostics.')
    return '\n'.join(lines) + '\n'
