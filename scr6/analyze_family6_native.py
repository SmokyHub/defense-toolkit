#!/usr/bin/env python3
"""Offline Family6 analysis: native asset decoder, recovered DEX and JNI evidence.

No execution, network, response modification, Ghidra or device is required.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile
import zipfile
from elftools.common.exceptions import ELFError
from family6_input import collect
from family6_native import analyze_native
from family6_payload import recover_assets
from classloader_report import render, summaries


def analyze(inputs):
    results, artifacts = [], {}
    with tempfile.TemporaryDirectory(prefix='family6-') as temp:
        paths, sources, skipped, assets = collect(inputs, Path(temp))
        for path in paths:
            try:
                result = analyze_native(Path(path).read_bytes())
            except (ValueError, ELFError) as error:
                result = {'family': 'family6', 'status': 'needs_review', 'diagnostics': [str(error)]}
            result.update(sources[path])
            results.append(result)
        matches = [r for r in results if r['status'] == 'native_asset_loader_identified']
        recovery = {'status': 'needs_review', 'diagnostics': ['no_unique_supported_native_loader']}
        if len(matches) == 1:
            recovery, artifacts = recover_assets(assets)
        status = recovery['status']
    return {'format': 'apk-defense.family6/v1', 'family': 'family6', 'status': status,
            'payload_origin': 'bundled_apk_assets' if status == 'static_asset_dex_recovered' else 'not_recovered',
            'results': results, 'recovery': recovery, 'skipped_inputs': skipped,
            'runtime_execution_observed': False,
            'limitations': [
                'Static reconstruction only; recovered code is never loaded or executed.',
                'JNI names and asset key/order are inferred offline; runtime configuration and execution are not observed.',
                'DEX integrity checks do not establish ART acceptance, runtime reachability or malicious intent.',
                'Only reviewed ARM64 instruction layouts are supported; changed compiler/control-flow/decoder models require review. Asset search supports 2..8 fragments per directory and XOR periods 1..64, with explicit budgets.',
            ]}, artifacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, nargs='+', help='APK, split directory, ZIP/APKS/XAPK/APKM, or ARM64 .so')
    parser.add_argument('--out', type=Path, required=True, help='new output directory for analysis.json, reconstructed ZIP and recovered DEX')
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
