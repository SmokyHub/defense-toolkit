#!/usr/bin/env python3
"""Offline Family3 detection and optional benign proof-response generation.

Python 3.10+ standard library and Node.js 18+ are required. The bundled JS
engine performs ELF/JNI analysis; this CLI handles APKs, output and the fixture.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
FIXTURE_SHA256 = '8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0'
ARCHIVES = {'.apk', '.apks', '.xapk', '.zip'}
MAX_LIB = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
ROLES = {
    'resolver_class': 'java/lang/Class',
    'resolver_method': 'forName',
    'resolver_descriptor': '(Ljava/lang/String;)Ljava/lang/Class;',
    'loader_class': 'dalvik.system.InMemoryDexClassLoader',
    'parent_getter_name': 'getClassLoader',
    'parent_getter_descriptor': '()Ljava/lang/ClassLoader;',
    'constructor_name': '<init>',
    'loader_constructor_descriptor': '(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V',
    'load_class_method': 'loadClass',
    'load_class_descriptor': '(Ljava/lang/String;)Ljava/lang/Class;',
    'payload_class': 'com.apkdefense.fixture.webview.ResponseEntry',
    'payload_constructor_descriptor': '()V',
    'entry_method': 'run',
    'entry_descriptor': '(Landroid/app/Activity;)V',
}


def fixture_bytes():
    paths = [HERE / 'fixtures/proof-screen.dex',
             HERE.parent / 'work/response_dex_validation/fixture/dex/classes.dex']
    for path in paths:
        if path.is_file():
            data = path.read_bytes()
            if len(data) != 5120 or hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
                raise ValueError('Bundled proof DEX failed its size or SHA-256 integrity check: ' + str(path))
            return data
    raise ValueError('Bundled proof DEX missing. Use the complete portable family3 folder, or build the workspace fixture.')


def make_proof(analysis, dex):
    loaders = [r for r in analysis['results'] if r.get('status') == 'family3_loader_pattern']
    # Identical copies from duplicate split inputs have already been deduplicated.
    if len(loaders) != 1:
        raise ValueError('Proof response requires exactly one distinct supported ARM64 loader; analyze one app at a time.')
    loader = loaders[0]
    candidate = loader.get('contract_candidate') or {}
    binding = loader.get('role_binding') or {}
    roles = candidate.get('roles', {})
    if binding.get('status') != 'supported_static_topology' or set(roles) != set(ROLES):
        raise ValueError('Incomplete JNI role binding; no proof response emitted.')
    outer, storage, array = (candidate.get(k) for k in ['outer', 'storage', 'array_key_candidate'])
    keys = list(roles.values()) + [array]
    if outer != storage or not isinstance(outer, str) or not outer.isdecimal():
        raise ValueError('Storage/outer key mismatch.')
    if any(not isinstance(k, str) or not k.isdecimal() for k in keys) or len(set(keys)) != 15:
        raise ValueError('Ambiguous or colliding field selectors.')
    fields = {roles[role]: value for role, value in ROLES.items()}
    fields[array] = list(dex)
    response = {outer: fields}
    return {
        'status': 'conditional_test_response',
        'runtime_execution_observed_for_this_input': False,
        'loader_source': loader['name'],
        'dex_sha256': FIXTURE_SHA256,
        'dex_bytes': len(dex),
        'payload_class': ROLES['payload_class'],
        'entry_method': ROLES['entry_method'],
        'entry_descriptor': ROLES['entry_descriptor'],
        'outer_key': outer,
        'array_key': array,
        'screen_title': 'APK Defense: DEX executed',
        'button_before': 'Test added functionality',
        'button_after': 'DEX button handler executed',
        'logcat_tag': 'APKDefenseFixture',
        'required_runtime_markers': ['ENTRY_CALLED', 'UI_INSTALLED', 'BUTTON_EXECUTED'],
        'limitations': ['Runtime execution has not been observed for this input.',
                        'Automatic array and retained-Context provenance remain incomplete.'],
        'response': response,
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


def analyze(inputs, node):
    with tempfile.TemporaryDirectory(prefix='family3-') as directory:
        files, sources, skipped = collect(inputs, Path(directory))
        if files:
            process = subprocess.run([node, str(HERE / 'analyze_family3_native.js'), *files],
                                     capture_output=True, text=True, timeout=180)
            if process.returncode:
                raise ValueError('Native analysis engine failed: ' + process.stderr[-2000:])
            result = json.loads(process.stdout)
            for item in result['results']:
                source = sources[item['name']]
                item['name'] = source['source']
                item['sha256'] = source['sha256']
                item['also_seen_in'] = source['also_seen_in']
        else:
            result = {'status': 'needs_review', 'results': [], 'reason': 'No supported ARM64 ELF libraries found; include the arm64 APK split.'}
        result['format'] = 'apk-defense.family3/v1'
        result['engine'] = 'bundled Node.js ELF/JNI analyzer; Python input/output orchestration'
        result['skipped_inputs'] = skipped
        result['proof_of_behavior'] = None
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', nargs='+', type=Path, help='original APK/split ZIP, split directory, or extracted .so files')
    p.add_argument('--out', type=Path, help='analysis JSON file (default: stdout)')
    p.add_argument('--proof-response', type=Path, help='write local response JSON containing the bundled benign DEX; also embed it in the analysis JSON')
    p.add_argument('--node', default='node', help='Node.js executable (default: node)')
    a = p.parse_args()
    try:
        outputs = [v.resolve() for v in [a.out, a.proof_response] if v is not None]
        if len(outputs) != len(set(outputs)):
            raise ValueError('--out and --proof-response must be different files.')
        for output in outputs:
            if output.exists():
                raise ValueError('Refusing to overwrite existing output: ' + str(output))
        node = shutil.which(a.node)
        if not node:
            raise ValueError('Node.js 18+ is required for the bundled native-analysis engine; use --node if needed.')
        result = analyze(a.inputs, node)
        if a.proof_response:
            proof = make_proof(result, fixture_bytes())
            result['proof_of_behavior'] = proof
            a.proof_response.parent.mkdir(parents=True, exist_ok=True)
            with a.proof_response.open('x') as f:
                json.dump(proof['response'], f, separators=(',', ':'))
            proof['response_file'] = str(a.proof_response)
            proof['response_sha256'] = hashlib.sha256(a.proof_response.read_bytes()).hexdigest()
        if a.out:
            a.out.parent.mkdir(parents=True, exist_ok=True)
            with a.out.open('x') as f:
                json.dump(result, f, indent=2)
                f.write('\n')
            print(json.dumps({'status': result['status'], 'analysis': str(a.out), 'proof_response': str(a.proof_response) if a.proof_response else None}))
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print('error: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
