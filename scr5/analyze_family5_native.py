#!/usr/bin/env python3
"""Offline Family5 analysis: native asset decoder, recovered DEX and JNI evidence.

No execution, network, response modification, Ghidra or device is required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile
from elftools.common.exceptions import ELFError
from family5_input import collect
from family5_native import analyze_native
from classloader_report import render, summaries


def analyze(inputs):
    results, artifacts = [], {}
    with tempfile.TemporaryDirectory(prefix='family5-') as temp:
        paths, sources, skipped, assets = collect(inputs, Path(temp))
        for path in paths:
            try:
                result, payloads = analyze_native(Path(path).read_bytes(), assets)
            except (ValueError, ELFError) as error:
                result, payloads = {'family': 'family5', 'status': 'needs_review',
                                    'diagnostics': [str(error)]}, []
            result.update(sources[path])
            for payload in payloads:
                name = 'recovered-' + hashlib.sha256(payload).hexdigest() + '.dex'
                artifacts[name] = payload
                result.setdefault('recovered_files', []).append(name)
            results.append(result)
    matches = [r for r in results if r['status'] == 'static_asset_dex_recovered']
    status = 'static_asset_dex_recovered' if len(matches) == 1 else 'needs_review'
    if status == 'needs_review':
        artifacts = {}
        for result in results:
            result.pop('recovered_files', None)
    return {'format': 'apk-defense.family5/v1', 'family': 'family5', 'status': status,
            'payload_origin': 'bundled_apk_assets' if status == 'static_asset_dex_recovered' else 'not_recovered',
            'results': results, 'skipped_inputs': skipped,
            'runtime_execution_observed': False,
            'limitations': [
                'Static reconstruction only; recovered code is never loaded or executed.',
                'Class-loading evidence is a native JNI array-field injection structure; encrypted Java API names remain unresolved.',
                'DEX integrity checks do not establish ART acceptance, runtime reachability or malicious intent.',
                'Only reviewed ARM64 helper layouts are supported. Unknown layouts require review.',
            ]}, artifacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, nargs='+', help='APK, split directory, ZIP/APKS/XAPK/APKM, or ARM64 .so')
    parser.add_argument('--out', type=Path, required=True, help='new output directory for analysis.json and recovered DEX')
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.out.is_symlink():
            raise ValueError('Output must be a new directory: ' + str(args.out))
        report, artifacts = analyze(args.input)
        args.out.mkdir(parents=True, exist_ok=False)
        for name, payload in artifacts.items():
            (args.out / name).write_bytes(payload)
        (args.out / 'analysis.json').write_text(json.dumps(report, indent=2) + '\n')
        (args.out / 'classloaders.txt').write_text(render(report))
        print(json.dumps({'status': report['status'], 'analysis': str(args.out / 'analysis.json'),
                          'classloader_report': str(args.out / 'classloaders.txt'), 'classloaders': summaries(report),
                          'recovered_files': [str(args.out / name) for name in artifacts]}))
        return 0 if report['status'] == 'static_asset_dex_recovered' else 2
    except (OSError, ValueError, zipfile.BadZipFile, ELFError) as error:
        print('error: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
