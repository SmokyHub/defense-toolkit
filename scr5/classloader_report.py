"""Shared output formatting; bundled independently with each native analyzer."""
import io
import json
import re
from pathlib import PurePosixPath
from elftools.elf.elffile import ELFFile


def string_groups(result):
    pool = result.get('constructor_pool') or {}
    yield 'constructor_xor_decoded', pool.get('strings', [])
    for pool in result.get('string_pools', []):
        yield 'first_xor_layer_decoded', pool.get('strings', [])
    for pool in result.get('jni_string_recovery', []):
        yield 'jni_xor_decoded', pool.get('strings', [])


def annotate_library(result, data):
    """Keep provenance on individual rows, even when copied out of the report."""
    source = result['source']; library = PurePosixPath(source.rsplit('!', 1)[-1]).name
    digest = result.get('native_sha256', result.get('sha256'))
    result['library'] = library
    groups = list(string_groups(result))
    if any(rows for _, rows in groups):
        elf = ELFFile(io.BytesIO(data))
        loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        referenced = {r['storage']['elf_va'] for r in result.get('classloader', {}).get('references', [])}
        by_address = {}
        for stage, rows in groups:
            for row in rows:
                va = int(row['va'], 16)
                offset = next((s['p_offset'] + va - s['p_vaddr'] for s in loads
                               if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']), None)
                remaining = ('hex_AES_ciphertext' if stage == 'constructor_xor_decoded'
                             and re.fullmatch('[0-9a-f]{32,}', row['text']) and len(row['text']) % 32 == 0
                             else 'nibble_XOR_ciphertext' if stage == 'first_xor_layer_decoded'
                             and re.fullmatch('[a-p]{2,}', row['text']) and len(row['text']) % 2 == 0 else None)
                row.update(origin={'library': library, 'source': source, 'sha256': digest,
                                   'elf_va': hex(va), 'file_offset': hex(offset) if offset is not None else None},
                           decoding_stage=stage, remaining_encoding=remaining,
                           referenced_by_loader=hex(va) in referenced)
                by_address[row['va']] = row['origin']
        aliases = list((result.get('constructor_pool') or {}).get('markers', []))
        for pool in result.get('jni_string_recovery', []):
            aliases.extend(pool.get('anchors', []))
        loading = result.get('class_loading', {})
        if isinstance(loading, dict):
            aliases.extend(loading.get('decoded_string_calls', []))
        for row in aliases:
            origin = by_address.get(row.get('va', row.get('string_va')))
            if origin:
                row['origin'] = dict(origin)
        for row in result.get('classloader', {}).get('references', []):
            origin = by_address.get(row['storage']['elf_va'])
            if origin:
                row['origin'] = dict(origin)
    evidence = result.get('classloader')
    if evidence:
        evidence['named_classloader_found'] = bool(evidence['referenced_class'])
        evidence['conclusion'] = (
            'Named class-loader reference recovered: ' + evidence['referenced_class']
            + '. Its concrete runtime subtype is not observed.' if evidence['referenced_class'] else
            'No class-loader name recovered. Native operations suggest classpath injection; the relevant class names remain encrypted.'
            if evidence['status'] == 'structural_evidence_only' else
            'No class-loader identity established for this library.')


def overview(report):
    evidence = [r for r in report['results'] if relevant(r)]
    return {'dex_recovered': report['status'] == 'static_asset_dex_recovered',
            'named_classloader_found': any(r['classloader'].get('referenced_class') for r in evidence),
            'concrete_runtime_class_observed': False,
            'classloaders': summaries(report),
            'other_libraries': [{'library': r.get('library'), 'source': r.get('source'),
                                 'analysis_status': r['status'],
                                 'explanation': 'No supported loader evidence established in this library; this status is separate from DEX recovery.'}
                                for r in report['results'] if not relevant(r)]}


def recovered_strings(report):
    return [row for r in report['results'] for _, rows in string_groups(r) for row in rows]


def render_strings(report):
    lines = ['Recovered native strings',
             'First-layer recovery may still contain ciphertext; see the encoding labels.', '']
    for result in report['results']:
        lines += ['Library: ' + result.get('library', '<unknown>'),
                  'Source: ' + result.get('source', '<unknown>'),
                  'SHA-256: ' + result.get('sha256', '<unknown>')]
        count = 0
        for stage, rows in string_groups(result):
            for row in rows:
                origin = row['origin']; count += 1
                lines.append('  ELF ' + origin['elf_va'] + ', file ' + str(origin['file_offset'])
                             + ' | ' + stage + ' | ' + (row['remaining_encoding'] or 'recovered text')
                             + ' | ' + json.dumps(row['text'], ensure_ascii=True))
        if not count:
            lines.append('  No strings recovered by this analyzer from this library.')
        lines.append('')
    return '\n'.join(lines) + '\n'


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
             ('status', 'mechanism', 'referenced_class', 'concrete_runtime_class', 'named_classloader_found', 'conclusion')}}
            for r in report['results'] if relevant(r)]


def relevant(result):
    return 'classloader' in result and (result['classloader']['status'] != 'unresolved'
            or bool(result.get('asset_models')) or bool(result.get('class_loading')))


def render(report):
    lines = ['Class-loader evidence — ' + report['family'],
             'DEX recovered: ' + ('YES' if report['status'] == 'static_asset_dex_recovered' else 'NO'),
             'Named class-loader found: ' + ('YES' if overview(report)['named_classloader_found'] else 'NO'),
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
        lines.append('Named class-loader found: ' + ('YES' if evidence.get('referenced_class') else 'NO'))
        lines.append('Conclusion: ' + evidence.get('conclusion', evidence.get('reason', '')))
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
