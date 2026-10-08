"""Select snapshot-compatible installed Blutter builds; optional explicit preparation.

Default selection is offline. Preparation may download Dart/toolchain sources via
an installed upstream Blutter checkout, never upload or execute submitted code.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile

LIMIT = 256 * 1024**2
NAME = re.compile(r'blutter_(dartvm[0-9.]+_android_arm64)(_semantic)?$')


def roots(directory=None):
    supplied = directory or os.environ.get('BLUTTER_HOME')
    values = supplied if isinstance(supplied, (list, tuple)) else [supplied] if supplied else ['~/tools/blutter', '~/blutter']
    return list(dict.fromkeys(Path(p).expanduser().resolve() for p in values))


def host_compatible(data):
    """Check native host format/architecture, independently of the Android target."""
    system, machine = platform.system(), platform.machine().lower()
    if system == 'Linux':
        expected = {'x86_64': 62, 'amd64': 62, 'aarch64': 183, 'arm64': 183}.get(machine)
        return len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == expected
    if system == 'Darwin':
        expected = {'x86_64': 0x1000007, 'arm64': 0x100000c, 'aarch64': 0x100000c}.get(machine)
        if data[:4] == b'\xcf\xfa\xed\xfe' and len(data) >= 8:
            return struct.unpack_from('<I', data, 4)[0] == expected
        if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') and len(data) >= 8:
            count = struct.unpack_from('>I', data, 4)[0]
            stride = 32 if data[3] == 0xbf else 20
            return count <= 32 and len(data) >= 8 + count * stride and any(
                struct.unpack_from('>I', data, 8 + i * stride)[0] == expected for i in range(count))
        return False
    return False


def select(identity, directory=None, executable=None, semantic_only=False):
    homes = roots(directory)
    if executable:
        candidates = [Path(executable).expanduser().resolve()]
    else:
        candidates = []
        for suffix in ('_semantic', ''):
            if semantic_only and not suffix: continue
            for home in homes:
                folder = home if home.name == 'bin' else home / 'bin'
                candidates.extend(sorted(folder.glob('blutter_dartvm*_android_arm64' + suffix)))
    reasons = []
    for path in list(dict.fromkeys(candidates))[:128]:
        if semantic_only and not path.name.endswith('_semantic'): continue
        try:
            if not path.is_file() or not os.access(path, os.X_OK):
                reasons.append(f'{path.name}: missing or not executable'); continue
            with path.open('rb') as stream: data = stream.read(LIMIT + 1)
            if len(data) > LIMIT:
                reasons.append(f'{path.name}: exceeds binary size limit'); continue
            if identity['snapshot_hash'].encode('ascii') + b'\0' not in data:
                reasons.append(f'{path.name}: different Dart snapshot format'); continue
            if not host_compatible(data):
                reasons.append(f'{path.name}: not a native {platform.system()}/{platform.machine()} executable; build on this host'); continue
            return path, hashlib.sha256(data).hexdigest()
        except OSError as error:
            reasons.append(f'{path.name}: {error}')
    locations = ', '.join(str(p) for p in homes) if not executable else str(executable)
    detail = '; '.join(reasons[:16]) or 'no candidate binaries found'
    raise ValueError(f'No installed Blutter analyzer matches snapshot {identity["snapshot_hash"]} '
                     f'on {platform.system()}/{platform.machine()}. Searched: {locations}. {detail}. '
                     'This is a Dart snapshot format identifier, not an app-file hash. '
                     'Use --blutter-dir PATH (repeat for multiple installations), or --blutter-bin PATH; '
                     'add --prepare-blutter to build the matching semantic analyzer from an installed Blutter checkout.')


def validate_semantic(path, libdir, identity):
    from flutter_semantic import recover_pool
    _, _, metadata = recover_pool(libdir / 'libapp.so', identity, executable=path)
    if not metadata or set(metadata.get('builtins', {})) != {'string', 'list', 'uint8'} or not metadata.get('stubs'):
        raise ValueError('Prepared analyzer lacks required semantic metadata or stub names')


def prepare(libdir, directory=None, executable=None):
    # This runs outside the bounded semantic worker, under the parent's explicit
    # build timeout and process group. Stock Blutter determines compatible versions.
    from flutter_semantic import snapshot_identity, read_bounded
    identity = snapshot_identity(read_bounded(libdir / 'libapp.so', LIMIT))
    try:
        path, digest = select(identity, directory, executable, semantic_only=True)
        validate_semantic(path, libdir, identity)
        return {'analyzer': str(path), 'sha256': digest, 'snapshot_hash': identity['snapshot_hash'], 'cached': True}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        if executable:
            raise ValueError('--prepare-blutter cannot replace an explicit --blutter-bin. Use --blutter-dir for preparation.')
    homes = [p.parent if p.name == 'bin' else p for p in roots(directory)]
    home = next((p for p in homes if (p / 'blutter.py').is_file() and (p / 'blutter').is_dir()), None)
    if home is None:
        raise ValueError('--prepare-blutter needs an installed Blutter source checkout; pass its root with --blutter-dir.')
    try:
        stock, _ = select(identity, homes)
        candidate_home = stock.parent.parent
        if (candidate_home / 'blutter.py').is_file() and (candidate_home / 'blutter').is_dir(): home = candidate_home
        else: stock = None
    except ValueError:
        stock = None
    dartlib = NAME.fullmatch(stock.name)[1] if stock and NAME.fullmatch(stock.name) else None
    cache = home / 'build' / ('blutter_' + dartlib) / 'CMakeCache.txt' if dartlib else None
    if not cache or not cache.is_file():
        if not (libdir / 'libflutter.so').is_file():
            raise ValueError('Matching stock build is missing; preparation needs libflutter.so from the same ARM64 app split.')
        with tempfile.TemporaryDirectory(prefix='blutter-stock-') as output:
            command = [sys.executable, str(home / 'blutter.py'), str(libdir), output]
            if stock: command.append('--rebuild')
            subprocess.run(command, check=True)
        stock, _ = select(identity, [home])
        match = NAME.fullmatch(stock.name)
        if not match: raise ValueError('Cannot derive the Dart library build name from the selected stock analyzer.')
        dartlib = match[1]
    from build_flutter_semantic_blutter import build
    build_parent = home / 'build'
    build_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='apk-defense-semantic-', dir=build_parent) as temp:
        target = build(home, dartlib, Path(temp) / 'extension')
        # Validate compatibility before installing. Atomic replace keeps existing
        # stock analyzers and other Dart versions intact, even on failed builds.
        select(identity, executable=target, semantic_only=True)
        validate_semantic(target, libdir, identity)
        destination = home / 'bin' / target.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, staging = tempfile.mkstemp(prefix='.semantic-', dir=destination.parent)
        os.close(fd)
        try:
            shutil.copy2(target, staging)
            os.replace(staging, destination)
        finally:
            if os.path.exists(staging): os.unlink(staging)
    path, digest = select(identity, [home], semantic_only=True)
    return {'analyzer': str(path), 'sha256': digest, 'snapshot_hash': identity['snapshot_hash'], 'cached': False}


def prepare_external(python, libdir, directory=None, executable=None, timeout=1800):
    """Explicit setup subprocess with durable logs and a whole-process-tree timeout."""
    cache = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'apk-defense/blutter'
    cache.mkdir(parents=True, exist_ok=True)
    logdir = Path(tempfile.mkdtemp(prefix='setup-', dir=cache))
    result = logdir / 'result.json'; logpath = logdir / 'build.log'
    command = [python, str(Path(__file__).resolve()), str(libdir), '--result', str(result)]
    for home in roots(directory): command.extend(['--blutter-dir', str(home)])
    if executable: command.extend(['--blutter-bin', str(executable)])
    print(f'Preparing snapshot-compatible Blutter (cached builds are reused). Log: {logpath}', file=sys.stderr, flush=True)
    with logpath.open('wb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
            raise ValueError(f'Blutter preparation timed out after {timeout}s; see {logpath}')
    if process.returncode:
        with logpath.open('rb') as log:
            log.seek(max(0, logpath.stat().st_size - 2048))
            tail = log.read(2048).decode(errors='replace')
        raise ValueError(f'Blutter preparation failed; see {logpath}: {tail}')
    with result.open('rb') as stream: raw = stream.read(65537)
    if len(raw) > 65536: raise ValueError('Blutter preparation result exceeds size limit')
    prepared = json.loads(raw)
    if not isinstance(prepared, dict) or not isinstance(prepared.get('analyzer'), str):
        raise ValueError('Invalid Blutter preparation result')
    return {**prepared, 'log': str(logpath)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libdir', type=Path)
    parser.add_argument('--blutter-dir', action='append')
    parser.add_argument('--blutter-bin')
    parser.add_argument('--result', required=True, type=Path)
    args = parser.parse_args()
    result = prepare(args.libdir, args.blutter_dir, args.blutter_bin)
    args.result.write_text(json.dumps(result) + '\n')
