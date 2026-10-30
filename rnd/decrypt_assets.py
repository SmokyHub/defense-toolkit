#!/usr/bin/env python3
"""Offline recovery for com.crimavon.barrage 1.4; standard library only.
Input: original base.apk or extracted assets/game directory. Never executes payloads.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib

NAMES = ('h15bedad', '9tpu.zea', 'q1nxthf8')
EXPECTED = 'a8a0cb9e23a4f0d9ad8f35565fefa9dd4c8b4fc8de3c1a3352d55227acf476bf'


def decrypt_fragment(data):
    """This is the offline decryption location, NOT an identified app function."""
    if len(data) < 1206:
        raise ValueError('Fragment too short for trim and edge restoration')
    body = data[126:-80]
    decoded = bytes(((b ^ 109) ^ 255) if i & 1 else
                    (((b ^ 109) >> 3) | ((b ^ 109) << 5)) & 255
                    for i, b in enumerate(body))
    return decoded[-500:][::-1] + decoded[500:-500] + decoded[:500][::-1]


def recover(source, output):
    if output.exists():
        raise ValueError('Output directory must not already exist')
    if source.is_dir():
        fragments = [(source / name).read_bytes() for name in NAMES]
    else:
        with zipfile.ZipFile(source) as archive:
            fragments = [archive.read('assets/game/' + name) for name in NAMES]
    payload = b''.join(decrypt_fragment(fragment) for fragment in fragments)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED:
        raise ValueError('Recovered APK hash differs from reviewed 1.4; no output written')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError('Bad ZIP CRC: ' + bad)
        dex = archive.read('classes.dex')
        entries = len(archive.infolist())
    if len(dex) < 112 or dex[:8] != b'dex\n035\0':
        raise ValueError('Unexpected DEX header')
    if struct.unpack_from('<III', dex, 32) != (len(dex), 112, 0x12345678):
        raise ValueError('DEX size/header/endian mismatch')
    if hashlib.sha1(dex[32:]).digest() != dex[12:32]:
        raise ValueError('DEX SHA1 mismatch')
    if zlib.adler32(dex[12:]) & 0xffffffff != struct.unpack_from('<I', dex, 8)[0]:
        raise ValueError('DEX Adler32 mismatch')
    report = dict(origin='offline bundled-asset reconstruction', names=NAMES,
                  apk_sha256=digest, zip_entries=entries, zip_crc_valid=True,
                  dex_sha256=hashlib.sha256(dex).hexdigest(), dex_integrity_valid=True,
                  runtime_execution_observed=False,
                  transform=dict(prefix=126, suffix=80, xor=109, edge=500))
    output.mkdir(parents=True, exist_ok=False)
    (output / 'payload.apk').write_bytes(payload)
    (output / 'classes.dex').write_bytes(dex)
    (output / 'recovery.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--out', required=True, type=Path, help='New directory under work/')
    args = parser.parse_args()
    try:
        print(json.dumps(recover(args.input, args.out), indent=2))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
