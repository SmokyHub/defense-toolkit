"""Bounded local APK/split/archive intake. Never extracts archive member paths."""
import hashlib
import io
from pathlib import Path, PurePosixPath
import zipfile
from family5_manifest import identity, MAX_MANIFEST

ARCHIVES = {".apk", ".apks", ".xapk", ".zip", ".apkm"}
MAX_LIB = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024

def collect(inputs, temporary, identities=None):
    """Stage only bounded ARM64 ELF inputs; never extract archive member paths."""
    files, sources, skipped, hashes = [], {}, [], {}
    assets = []
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
        nonlocal total
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
                if entry.filename == 'AndroidManifest.xml' and identities is not None:
                    if entry.file_size > MAX_MANIFEST:
                        raise ValueError('Manifest exceeds 8 MiB bound: ' + child)
                    total += entry.file_size
                    if total > MAX_TOTAL or len(identities) >= 10000:
                        raise ValueError('Manifest input budget exceeded.')
                    try:
                        identities.append({**identity(z.read(entry)), 'source': child})
                    except (ValueError, UnicodeError) as error:
                        identities.append({'source': child, 'diagnostic': str(error)})
                elif entry.filename.startswith('assets/') and '..' not in name.parts:
                    if entry.file_size > MAX_LIB:
                        raise ValueError('Asset exceeds 32 MiB bound: ' + child)
                    total += entry.file_size
                    if total > MAX_TOTAL or len(assets) >= 10000:
                        raise ValueError('Asset input budget exceeded.')
                    assets.append({'name': entry.filename, 'source': child, 'data': z.read(entry)})
                elif name.suffix.lower() == '.so':
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
    return files, sources, skipped, assets
