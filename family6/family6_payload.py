"""Bounded static reconstruction and integrity checks for Family6 assets."""
import hashlib
import struct
import zlib
import io
import itertools
import zipfile
from collections import Counter, defaultdict
from pathlib import PurePosixPath

MAX_CONTAINER = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_ATTEMPTS = 4096


def xor_bytes(data, key):
    # Each asset restarts at key index zero, as in the reviewed native loop.
    out = bytearray(data)
    for phase, byte in enumerate(key):
        out[phase::len(key)] = data[phase::len(key)].translate(bytes(b ^ byte for b in range(256)))
    return bytes(out)


def validate_container(data):
    """Bound ZIP expansion and validate every CRC and every recovered DEX."""
    dexes, payloads = [], {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 4096 or sum(e.file_size for e in entries) > MAX_EXPANDED:
            raise ValueError('Recovered ZIP entry/expansion budget exceeded')
        seen = set()
        for entry in entries:
            name = PurePosixPath(entry.filename)
            if (entry.filename in seen or name.is_absolute() or '..' in name.parts or '\\' in entry.filename
                    or entry.flag_bits & 1 or entry.file_size > 32 * 1024 * 1024
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or (entry.external_attr >> 16) & 0xf000 == 0xa000):
                raise ValueError('Unsafe or unsupported recovered ZIP member')
            seen.add(entry.filename)
            with archive.open(entry) as stream:
                raw = stream.read(entry.file_size + 1)
            if len(raw) != entry.file_size or zlib.crc32(raw) & 0xffffffff != entry.CRC:
                raise ValueError('Recovered ZIP CRC/size mismatch')
            if name.suffix.lower() == '.dex':
                report = validate_dex(raw); report['member'] = entry.filename
                artifact = 'recovered-' + report['sha256'] + '.dex'
                report['file'] = artifact; dexes.append(report); payloads[artifact] = raw
        if not dexes:
            raise ValueError('No validated DEX in recovered ZIP')
    digest = hashlib.sha256(data).hexdigest(); artifact = 'recovered-' + digest + '.zip'
    payloads[artifact] = data
    return {'bytes': len(data), 'sha256': digest, 'file': artifact,
            'zip_entry_count': len(entries), 'all_zip_crcs_match': True, 'dex': dexes}, payloads


def has_end(data, total):
    """EOCD must end the concatenation and describe an unspanned classic ZIP."""
    offset = data.find(b'PK\x05\x06', max(0, len(data) - 65557))
    while 0 <= offset <= len(data) - 22:
        disk, cd_disk, count_disk, count, size, start, comment = struct.unpack_from('<4H2IH', data, offset + 4)
        if (disk == cd_disk == 0 and count == count_disk and 0 < count <= 4096
                and offset + 22 + comment == len(data)
                and start + size == total - len(data) + offset):
            return True
        offset = data.find(b'PK\x05\x06', offset + 1)
    return False


def recover_assets(assets):
    """Infer candidate XOR periods/order; accept only complete integrity checks.

    Frequency analysis assumes abundant zero plaintext in at least one fragment.
    It is a candidate generator, never evidence by itself. Directory grouping,
    1..64-byte periods and 2..8 fragments are explicit coverage limits.
    """
    groups = defaultdict(list); seen = {}; diagnostics = []; valid = {}; attempts = 0
    for asset in assets:
        name = asset['name']; digest = hashlib.sha256(asset['data']).hexdigest()
        if name in seen:
            if seen[name] != digest:
                return {'status': 'needs_review', 'diagnostics': ['conflicting_duplicate_asset_path']}, {}
            continue
        seen[name] = digest
        groups[str(PurePosixPath(name).parent)].append(asset)
    if len(groups) > 128:
        return {'status': 'needs_review', 'diagnostics': ['asset_directory_budget_exceeded']}, {}
    candidates = 0
    for directory, group in groups.items():
        total = sum(len(a['data']) for a in group)
        if not 2 <= len(group) <= 8 or total > MAX_CONTAINER or any(len(a['data']) < 64 for a in group):
            diagnostics.append('unsupported_fragment_group: ' + directory)
            continue
        keys = {}
        for source in group:
            for period in range(1, 65):
                key = bytes(Counter(source['data'][phase::period]).most_common(1)[0][0] for phase in range(period))
                # Canonicalize equivalent periodic keys before testing.
                for width in range(1, len(key) + 1):
                    if len(key) % width == 0 and key == key[:width] * (len(key) // width):
                        key = key[:width]; break
                if key in keys:
                    continue
                first = [n for n, a in enumerate(group) if xor_bytes(a['data'][:4], key) == b'PK\x03\x04']
                if first:
                    keys[key] = (source['name'], first)
        for key, (source, first) in keys.items():
            decoded = [xor_bytes(a['data'], key) for a in group]
            last = [n for n, data in enumerate(decoded) if has_end(data, total)]
            if not last:
                continue
            candidates += 1
            if candidates > 64:
                return {'status': 'needs_review', 'diagnostics': ['key_candidate_budget_exceeded']}, {}
            for begin, end in itertools.product(first, last):
                if begin == end:
                    continue
                middle = [n for n in range(len(group)) if n not in (begin, end)]
                for permutation in itertools.permutations(middle):
                    attempts += 1
                    if attempts > MAX_ATTEMPTS:
                        return {'status': 'needs_review', 'diagnostics': ['fragment_order_budget_exceeded']}, {}
                    order = (begin, *permutation, end)
                    data = b''.join(decoded[n] for n in order)
                    try:
                        report, artifacts = validate_container(data)
                    except (ValueError, zipfile.BadZipFile, EOFError, zlib.error, RuntimeError, NotImplementedError):
                        continue
                    report['assets'] = [{'name': group[n]['name'], 'source': group[n]['source'],
                                         'bytes': len(group[n]['data']), 'sha256': hashlib.sha256(group[n]['data']).hexdigest()} for n in order]
                    report['key_recovery'] = {'method': 'per_phase_frequency_candidate_validated_by_all_ZIP_CRCs_and_DEX_checksums',
                                              'candidate_source': source, 'key_bytes': len(key),
                                              'key_sha256': hashlib.sha256(key).hexdigest(),
                                              'order': 'bounded_permutation_validated_by_complete_container_integrity',
                                              'runtime_configuration_observed': False}
                    valid[report['sha256']] = (report, artifacts)
    if len(valid) != 1:
        return {'status': 'needs_review', 'diagnostics': ['no_unique_integrity_validated_container', *diagnostics],
                'candidate_keys': candidates, 'orders_tried': attempts}, {}
    report, artifacts = next(iter(valid.values()))
    return {'status': 'static_asset_dex_recovered', 'container': report, 'diagnostics': diagnostics,
            'candidate_keys': candidates, 'orders_tried': attempts}, artifacts

def validate_dex(data):
    """Integrity and bounded tables, not an ART acceptance claim."""
    if len(data) < 112 or data[:8] not in (b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0', b'dex\n040\0'):
        raise ValueError('Reassembled bytes have no supported DEX header.')
    size, header, endian = struct.unpack_from('<III', data, 32)
    if size != len(data) or header != 112 or endian != 0x12345678:
        raise ValueError('DEX size/header/endian mismatch.')
    if hashlib.sha1(data[32:]).digest() != data[12:32]:
        raise ValueError('DEX SHA-1 signature mismatch.')
    if zlib.adler32(data[12:]) & 0xffffffff != struct.unpack_from('<I', data, 8)[0]:
        raise ValueError('DEX Adler-32 mismatch.')
    for offset, width in ((56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)):
        count, start = struct.unpack_from('<II', data, offset)
        if count and (start < 112 or start + count * width > len(data)):
            raise ValueError('DEX table outside recovered file.')
    strings_count, strings_off, types_count, types_off = struct.unpack_from('<IIII', data, 56)
    classes_count, classes_off = struct.unpack_from('<II', data, 96)
    classes = []
    for index in range(classes_count):
        type_index = struct.unpack_from('<I', data, classes_off + index * 32)[0]
        if type_index >= types_count:
            raise ValueError('Invalid DEX class type index.')
        string_index = struct.unpack_from('<I', data, types_off + type_index * 4)[0]
        if string_index >= strings_count:
            raise ValueError('Invalid DEX descriptor string index.')
        offset = struct.unpack_from('<I', data, strings_off + string_index * 4)[0]
        for _ in range(5):
            if offset >= len(data):
                raise ValueError('Truncated DEX string.')
            value = data[offset]
            offset += 1
            if value < 128:
                break
        else:
            raise ValueError('Invalid DEX string length.')
        end = data.find(b'\0', offset, min(len(data), offset + 16384))
        if end < 0:
            raise ValueError('Unterminated DEX descriptor.')
        classes.append(data[offset:end].decode('utf-8', errors='replace'))
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'dex_version': data[4:7].decode(), 'sha1_matches': True, 'adler32_matches': True,
            'file_size_matches': True, 'header_and_id_tables_bounded': True,
            'class_count': classes_count, 'class_descriptors': classes}
