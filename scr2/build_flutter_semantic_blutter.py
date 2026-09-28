#!/usr/bin/env python3
"""Build a metadata-exporting Blutter from an installed, already-built toolchain.

No downloads; no client code is executed. Copies upstream source into a separate
build directory, reuses installed Dart VM packages, and leaves stock Blutter intact.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess


def build(home, dartlib, output):
    cache = home / 'build' / ('blutter_' + dartlib) / 'CMakeCache.txt'
    if not cache.is_file():
        raise ValueError('Build stock Blutter for this Dart version first: missing ' + str(cache))
    if output.exists():
        raise ValueError('Choose a fresh --out directory')
    output.mkdir(parents=True)
    shutil.copytree(home / 'blutter', output / 'blutter')
    for name in ('packages', 'scripts'):
        (output / name).symlink_to(home / name, target_is_directory=True)
    main = output / 'blutter/src/main.cpp'
    source = main.read_text()
    anchor = '\n\t\tapp.ExitScope();\n\t}'
    if source.count(anchor) != 1:
        raise ValueError('Unsupported Blutter main.cpp: cannot locate final active scope')
    extension = Path(__file__).with_name('blutter_semantic_extension.inc').read_text()
    source = '#include <fstream>\n' + source.replace(anchor, '\n' + extension + anchor)
    main.write_text(source)
    options = []
    for line in cache.read_text().splitlines():
        m = re.fullmatch(r'((?:HAS_|NO_|OLD_|UNIFORM_)[A-Z_]+):[^=]+=(.*)', line)
        if m:
            options.append('-D' + m[1] + '=' + m[2])
    env = os.environ.copy()
    lab_bin = Path.home() / 'tools/venv/bin'
    if lab_bin.is_dir():
        env['PATH'] = str(lab_bin) + os.pathsep + env.get('PATH', '')
    lab = Path.home() / 'tools/blutter-deps/root/usr'
    if lab.is_dir():
        for key, location in [('CPATH', lab / 'include'), ('LIBRARY_PATH', lab / 'lib/x86_64-linux-gnu'),
                              ('LD_LIBRARY_PATH', lab / 'lib/x86_64-linux-gnu'),
                              ('PKG_CONFIG_PATH', lab / 'lib/x86_64-linux-gnu/pkgconfig')]:
            env[key] = str(location) + (':' + env[key] if env.get(key) else '')
        env['CPATH'] = str(lab / 'include/capstone') + ':' + env['CPATH']
    subprocess.run(['cmake', '-S', str(output / 'blutter'), '-B', str(output / 'build'),
                    '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DDARTLIB=' + dartlib,
                    '-DNAME_SUFFIX=_semantic', *options], env=env, check=True, timeout=120)
    subprocess.run(['cmake', '--build', str(output / 'build'), '--parallel', '2'], env=env, check=True, timeout=900)
    target = output / 'build' / ('blutter_' + dartlib + '_semantic')
    print(target)
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--blutter-dir', type=Path, default=Path.home() / 'tools/blutter')
    parser.add_argument('--dartlib', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--install', action='store_true', help='Install the built analyzer alongside stock Blutter in bin/')
    args = parser.parse_args()
    if not re.fullmatch(r'dartvm[0-9.]+_android_arm64', args.dartlib):
        parser.error('Expected dartvm<version>_android_arm64')
    target = build(args.blutter_dir.resolve(), args.dartlib, args.out.resolve())
    if args.install:
        destination = args.blutter_dir.expanduser().resolve() / 'bin' / target.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, destination)
        print('Installed ' + str(destination))
