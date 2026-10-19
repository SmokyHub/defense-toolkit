#!/usr/bin/env python3
"""Offline Family4 native-loader analysis and hash-pinned benign proof responses.

Accept original APKs, full split directories/ZIPs, or ARM64 ELF libraries.
Uses Python 3.10+, pyelftools and Capstone; no device, compiler or network.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import tempfile
import zipfile

from family4_native import analyze_native
from dex_response_proof import fixture_bytes, FIXTURE_SHA256, FIXTURE_CONTRACT
from family4_response import FORMATS, prepare as prepare_response

ARCHIVES = {'.apk', '.apks', '.xapk', '.apkm', '.zip'}
MAX_LIB = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
ROLES = {
    'loader_class': 'dalvik.system.InMemoryDexClassLoader',
    'loader_constructor_signature': '(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V',
    'activity_loader_method': 'getClassLoader',
    'activity_loader_signature': '()Ljava/lang/ClassLoader;',
    'load_class_method': 'loadClass',
    'load_class_signature': '(Ljava/lang/String;)Ljava/lang/Class;',
    'entry_class': FIXTURE_CONTRACT['payload_class'],
    'entry_constructor_signature': '()V',
    'entry_method': FIXTURE_CONTRACT['entry_method'],
    'entry_signature': FIXTURE_CONTRACT['entry_descriptor'],
    'class_class': 'java/lang/Class',
    'class_lookup_method': 'forName',
    'class_lookup_signature': '(Ljava/lang/String;)Ljava/lang/Class;',
    'constructor_name': '<init>',
}

def collect(inputs, temporary):
    """Stage only bounded ARM64 ELF inputs; never extract archive member paths."""
    files, sources, skipped, hashes = [], {}, [], {}
    total = 0
    def stage(data, label):
        nonlocal total
        if len(data) > MAX_LIB:
            skipped.append({'source': label, 'reason': 'library exceeds 32 MiB bound'})
            return
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183:
            skipped.append({'source': label, 'reason': 'not a supported ARM64 ELF64 LE library'})
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in hashes:
            sources[hashes[digest]]['also_seen_in'].append(label)
            return
        total += len(data)
        if total > MAX_TOTAL or len(files) >= 128:
            raise ValueError('Analysis input exceeds 256 MiB / 128 distinct-library bounds; narrow the input.')
        path = temporary / (str(len(files)) + '.so')
        path.write_bytes(data)
        name = str(path)
        files.append(name)
        hashes[digest] = name
        sources[name] = {'source': label, 'sha256': digest, 'also_seen_in': []}

    def archive(source, label, depth=0):
        if depth > 1:
            raise ValueError('Unsupported nested archive depth: ' + label)
        with zipfile.ZipFile(source) as z:
            entries = z.infolist()
            if len(entries) > 100000:
                raise ValueError('Archive entry-count limit exceeded.')
            for entry in entries:
                if entry.is_dir():
                    continue
                name = PurePosixPath(entry.filename)
                child = label + '!' + entry.filename
                if name.suffix.lower() == '.so':
                    if entry.file_size > MAX_LIB:
                        skipped.append({'source': child, 'reason': 'library exceeds 32 MiB bound'})
                    else:
                        stage(z.read(entry), child)
                elif depth == 0 and name.suffix.lower() == '.apk':
                    if entry.file_size > MAX_TOTAL:
                        raise ValueError('Nested APK exceeds 256 MiB bound: ' + child)
                    archive(io.BytesIO(z.read(entry)), child, depth + 1)

    def visit(path, depth=0):
        if depth > 12:
            raise ValueError('Directory nesting limit exceeded.')
        if path.is_symlink():
            skipped.append({'source': str(path), 'reason': 'symlink not followed'})
        elif path.is_dir():
            for child in sorted(path.iterdir()):
                visit(child, depth + 1)
        elif path.is_file():
            suffix = path.suffix.lower()
            if suffix in ARCHIVES:
                archive(path, str(path))
            elif suffix == '.so':
                if path.stat().st_size > MAX_LIB:
                    skipped.append({'source': str(path), 'reason': 'library exceeds 32 MiB bound'})
                else:
                    stage(path.read_bytes(), str(path))
        else:
            raise ValueError('Input does not exist: ' + str(path))
    for value in inputs:
        visit(value)
    return files, sources, skipped


def analyze(inputs):
    with tempfile.TemporaryDirectory(prefix='family4-') as directory:
        paths, sources, skipped = collect(inputs, Path(directory))
        results = []
        for path in paths:
            source = sources[path]
            try:
                item = analyze_native(Path(path).read_bytes())
            except ValueError as error:
                item = {'status': 'needs_review', 'contracts': [], 'diagnostics': [str(error)]}
            item.update(source=source['source'], sha256=source['sha256'], also_seen_in=source['also_seen_in'])
            results.append(item)
        supported = [r for r in results if r.get('status') == 'supported']
        return {'format': 'apk-defense.family4/v1',
                'status': 'supported' if len(supported) == 1 else 'needs_review',
                'status_scope': 'native_loader_contract',
                'wire_response': {'basis': 'unverified', 'consumer_verified': False},
                'engine': 'offline Python ELF/string-decoder/JNI argument analysis',
                'results': results, 'skipped_inputs': skipped,
                'diagnostics': [] if len(supported) == 1 else ['Exactly one distinct supported ARM64 loader is required for a proof response.'],
                'proof_of_behavior': None,
                'limitations': ['Static capability and conditional test contract; not proof of runtime execution or malicious intent.',
                                'Only the recognized ARM64 loader/validator topology is supported; unknown variants remain needs_review.',
                                'Native support does not establish the HTTP response encoding. Outer Java/Dart/native wrappers are not automatically traced.']}


def make_proof(result, *, response_format=None, response_example=None):
    matches = [r for r in result['results'] if r.get('status') == 'supported']
    if result['status'] != 'supported' or len(matches) != 1:
        raise ValueError('Proof response requires exactly one distinct supported ARM64 loader.')
    match = matches[0]
    contracts = match.get('contracts', [])
    if len(contracts) != 1 or not contracts[0].get('complete'):
        raise ValueError('Incomplete or ambiguous native contract; no proof response generated.')
    contract = contracts[0]; roles = contract.get('roles', {})
    if set(roles) != set(ROLES):
        raise ValueError('Incomplete JNI role binding; no guessed keys emitted.')
    outer, array = contract.get('outer_key'), contract.get('array_key')
    keys = [*roles.values(), array]
    if not isinstance(outer, str) or not outer.isascii() or not outer.isdecimal():
        raise ValueError('Unsupported outer selector.')
    if any(not isinstance(k, str) or not k.isascii() or not k.isdecimal() for k in keys) or len(set(keys)) != 15:
        raise ValueError('Missing or colliding response selectors.')
    guards = contract.get('guards')
    if not guards or not guards.get('exact_file_size') or not guards.get('header_and_table_bounds'):
        raise ValueError('DEX validation behavior is not modeled.')
    dex = fixture_bytes()  # Pinned source-built payload; arbitrary DEX inputs are not accepted.
    if not guards['dex_min_bytes'] <= len(dex) <= guards['dex_max_bytes']:
        raise ValueError('Benign fixture does not satisfy the recovered DEX length bounds.')
    if dex[:4] != b'dex\n' or dex[4:7].decode('ascii') not in guards['dex_versions'] or struct.unpack_from('<I', dex, 32)[0] != len(dex):
        raise ValueError('Benign fixture does not satisfy the recovered DEX header checks.')
    fields = {roles[name]: value for name, value in ROLES.items()}; fields[array] = list(dex)
    response, wire_evidence, transforms = prepare_response(
        {outer: fields}, contract, response_format=response_format, response_example=response_example)
    return {'status': 'generated_for_conditional_test_contract', 'runtime_validated_this_run': False,
            'loader_source': match['source'], 'endpoint': match.get('endpoint'), 'method': match.get('http_method'),
            'outer_key': outer, 'array_key': array, 'dex_bytes': len(dex), 'dex_sha256': FIXTURE_SHA256,
            'dex_guards': guards, 'payload_contract': FIXTURE_CONTRACT,
            'expected_markers': ['ENTRY_CALLED', 'UI_INSTALLED', 'BUTTON_EXECUTED'],
            'behavior': 'Local proof screen and working button; the entry makes no network request.',
            'response': response, 'wire_response': wire_evidence, 'response_transforms': transforms,
            'limitation': 'The app must accept the response and reach this loader. Newly analyzed inputs need separate runtime validation.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', nargs='+', type=Path, help='original APK, split directory/ZIP, or extracted ARM64 .so')
    parser.add_argument('--out', type=Path, help='new analysis JSON file; defaults to stdout')
    parser.add_argument('--proof-response', type=Path, help='new response JSON containing the bundled benign DEX')
    wire = parser.add_mutually_exclusive_group()
    wire.add_argument('--response-format', choices=FORMATS,
                      help='explicit wire envelope: inner wraps the outer-key value; body wraps the whole JSON object. Requires --proof-response.')
    wire.add_argument('--response-example', type=Path,
                      help='infer the envelope from a local saved response JSON matching the recovered native contract. Requires --proof-response.')
    args = parser.parse_args(argv)
    try:
        if (args.response_format is not None or args.response_example is not None) and args.proof_response is None:
            raise ValueError('Response format/example requires --proof-response.')
        outputs = [p.resolve() for p in (args.out, args.proof_response) if p is not None]
        if len(outputs) != len(set(outputs)):
            raise ValueError('--out and --proof-response must be different files.')
        if any(p.exists() or p.is_symlink() for p in (args.out, args.proof_response) if p is not None):
            raise ValueError('Output already exists; choose fresh output filenames.')
        result = analyze(args.inputs)
        proof_error = None
        if args.proof_response:
            try:
                proof = make_proof(result, response_format=args.response_format, response_example=args.response_example)
            except (OSError, ValueError) as error:
                # Preserve diagnostics for manual review, even when a requested proof cannot be made.
                proof_error = str(error)
                result['native_status'] = result['status']
                result['status'] = 'needs_review'
                result['status_scope'] = 'requested_proof_response'
                result['wire_response'] = {'basis': 'unresolved', 'consumer_verified': False,
                                           'diagnostics': [proof_error]}
                result['diagnostics'].append(proof_error)
            else:
                args.proof_response.parent.mkdir(parents=True, exist_ok=True)
                encoded = json.dumps(proof['response'], separators=(',', ':')).encode('utf-8')
                with args.proof_response.open('xb') as f:
                    f.write(encoded)
                proof.update(response_file=str(args.proof_response), response_sha256=hashlib.sha256(encoded).hexdigest())
                result['proof_of_behavior'] = proof
                result['wire_response'] = proof['wire_response']
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open('x') as f:
                json.dump(result, f, indent=2); f.write('\n')
            print(json.dumps({'status': result['status'], 'analysis': str(args.out),
                              'proof_response': str(args.proof_response) if result['proof_of_behavior'] else None,
                              'wire_response': result.get('wire_response'),
                              'diagnostics': result['diagnostics']}))
        else:
            print(json.dumps(result, indent=2))
        if proof_error:
            print('error: ' + proof_error, file=sys.stderr)
            return 2
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print('error: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
