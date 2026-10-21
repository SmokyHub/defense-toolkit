"""Bounded binary Android manifest identity reader; no Android SDK dependency."""
import struct

MAX_MANIFEST = 8 * 1024 * 1024
ANDROID = 'http://schemas.android.com/apk/res/android'


def identity(data):
    def require(condition, message='Invalid binary Android manifest'):
        if not condition:
            raise ValueError(message)

    require(8 <= len(data) <= MAX_MANIFEST)
    kind, header, size = struct.unpack_from('<HHI', data)
    require(kind == 3 and header == 8 and size == len(data))
    strings = None
    pos = header
    while pos < len(data):
        require(pos + 8 <= len(data))
        kind, head, size = struct.unpack_from('<HHI', data, pos)
        require(8 <= head <= size and pos + size <= len(data))
        chunk = data[pos:pos + size]
        if kind == 1:
            require(strings is None and head >= 28)
            count, styles, flags, start, style_start = struct.unpack_from('<5I', chunk, 8)
            require(count <= 65536 and styles <= 65536 and head + 4 * (count + styles) <= start <= size)
            end = style_start or size
            require(start <= end <= size)
            strings = []
            for n in range(count):
                off = start + struct.unpack_from('<I', chunk, head + 4 * n)[0]
                require(start <= off < end)

                def length(width):
                    nonlocal off
                    require(off + width <= end)
                    value = int.from_bytes(chunk[off:off + width], 'little'); off += width
                    mask = 1 << (8 * width - 1)
                    if value & mask:
                        require(off + width <= end)
                        value = ((value & (mask - 1)) << (8 * width)) | int.from_bytes(chunk[off:off + width], 'little')
                        off += width
                    return value

                if flags & 0x100:
                    length(1)  # UTF-16 length, then UTF-8 byte count
                    size_string = length(1)
                    require(off + size_string < end and chunk[off + size_string] == 0)
                    text = chunk[off:off + size_string].decode('utf-8')
                else:
                    size_string = length(2) * 2
                    require(off + size_string + 2 <= end and chunk[off + size_string:off + size_string + 2] == b'\0\0')
                    text = chunk[off:off + size_string].decode('utf-16le')
                strings.append(text)
        elif kind == 0x102:
            require(strings is not None and head == 16 and size >= 36)

            def string(index):
                require(index < len(strings))
                return strings[index]

            require(string(struct.unpack_from('<I', chunk, 20)[0]) == 'manifest',
                    'First manifest element is not manifest')
            attr_start, attr_size, count = struct.unpack_from('<3H', chunk, 24)
            require(attr_start >= 20 and attr_size >= 20 and count <= 1024
                    and 16 + attr_start + count * attr_size <= size)
            attrs = {}
            for n in range(count):
                off = 16 + attr_start + n * attr_size
                ns, name, raw, typed_size, zero, typ, value = struct.unpack_from('<IIIHBBI', chunk, off)
                require(typed_size == 8 and zero == 0)
                key = ('' if ns == 0xffffffff else string(ns), string(name))
                require(key not in attrs, 'Duplicate manifest attribute')
                attrs[key] = string(raw) if raw != 0xffffffff else string(value) if typ == 3 else value if typ in (0x10, 0x11) else None
            package = attrs.get(('', 'package'))
            version = attrs.get((ANDROID, 'versionCode'))
            require(isinstance(package, str) and 0 < len(package) <= 255 and '\0' not in package,
                    'Missing or invalid APK package identity')
            if isinstance(version, str):
                version = int(version, 16 if version.startswith('0x') else 10)
            require(type(version) is int and 0 <= version < 2**31, 'Missing or unsupported APK versionCode')
            return {'package': package, 'version_code': version}
        pos += size
    raise ValueError('No manifest root element')
