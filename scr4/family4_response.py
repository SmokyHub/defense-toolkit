"""Bounded response-envelope codecs, separate from native contract recovery.

An example establishes a wire shape, NOT that the APK consumes that shape. No
sample code is executed, no endpoints are contacted, and example DEX bytes are
never used in the generated proof. Only one JSON/Base64 envelope is supported.
"""
import base64
import binascii
import hashlib
import json
from pathlib import Path
import struct

FORMATS = ('plain', 'base64-inner', 'base64-fragments-inner',
           'base64-body', 'base64-fragments-body')
MAX_EXAMPLE_BYTES = 64 * 1024 * 1024
MAX_FRAGMENTS = 4096


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate response JSON key.')
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError('Non-finite response JSON number.')


def _json(data):
    if len(data) > MAX_EXAMPLE_BYTES:
        raise ValueError('Response example exceeds 64 MiB bound.')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_object,
                          parse_constant=_nonfinite)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('Response example must contain bounded UTF-8 JSON.') from error


def _pack(value):
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def _unpack(value, fragments):
    if fragments:
        if (not isinstance(value, list) or not 1 <= len(value) <= MAX_FRAGMENTS
                or any(not isinstance(part, str) for part in value)):
            raise ValueError('Expected a bounded list of Base64 string fragments.')
        if sum(map(len, value)) > MAX_EXAMPLE_BYTES:
            raise ValueError('Base64 fragments exceed the response bound.')
        value = ''.join(value)
    if not isinstance(value, str) or not value or len(value) > MAX_EXAMPLE_BYTES:
        raise ValueError('Expected a bounded Base64 string.')
    try:
        raw = base64.b64decode(value.encode('ascii'), validate=True)
    except (UnicodeError, binascii.Error) as error:
        raise ValueError('Invalid standard padded Base64 response.') from error
    # Reject noncanonical padding, ignored trailing data and nonzero pad bits.
    if base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('Noncanonical standard padded Base64 response.')
    return _json(raw)


def _check_format(name):
    if name not in FORMATS:
        raise ValueError('Unsupported Family4 response format: ' + str(name))


def encode(response, outer, name):
    """Wrap the recovered logical response; never encode the DEX field alone."""
    _check_format(name)
    if name == 'plain':
        return response
    inner = name.endswith('-inner')
    value = _pack(response[outer] if inner else response)
    if 'fragments' in name:
        value = [value]  # Joined before decoding, as in the reviewed Family2 scheme.
    return {outer: value} if inner else value


def decode(response, outer, name):
    _check_format(name)
    if name == 'plain':
        return response
    inner = name.endswith('-inner')
    if inner and (not isinstance(response, dict) or set(response) != {outer}):
        raise ValueError('Inner envelope requires exactly the recovered outer key.')
    value = _unpack(response[outer] if inner else response, 'fragments' in name)
    return {outer: value} if inner else value


def _matches_contract(response, contract):
    """Match selectors/types and basic DEX header, not runtime acceptance."""
    outer, array = contract['outer_key'], contract['array_key']
    if not isinstance(response, dict) or set(response) != {outer}:
        return False
    fields = response[outer]
    roles = contract['roles']
    if not isinstance(fields, dict) or set(fields) != {*roles.values(), array}:
        return False
    if any(not isinstance(fields[key], str) or not 1 <= len(fields[key]) <= 4096
           for key in roles.values()):
        return False
    data = fields[array]
    guards = contract['guards']
    if (not isinstance(data, list)
            or not guards['dex_min_bytes'] <= len(data) <= guards['dex_max_bytes']
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in data)):
        return False
    header = bytes(data[:112])
    return (len(header) == 112 and header[:4] == b'dex\n' and header[7] == 0
            and header[4:7] in [v.encode('ascii') for v in guards['dex_versions']]
            and struct.unpack_from('<I', header, 32)[0] == len(data)
            and struct.unpack_from('<I', header, 36)[0] == 112
            and struct.unpack_from('<I', header, 40)[0] == 0x12345678)


def infer(data, contract):
    """Infer exactly one supported envelope around this native contract."""
    response = _json(data)
    matches = []
    for name in FORMATS:
        try:
            logical = decode(response, contract['outer_key'], name)
        except ValueError:
            continue
        if _matches_contract(logical, contract):
            matches.append(name)
    if len(matches) != 1:
        raise ValueError('Response example does not uniquely match a supported envelope '
                         'and the recovered native selectors/types/DEX header; needs review.')
    return matches[0]


def prepare(response, contract, *, response_format=None, response_example=None):
    if response_format is not None and response_example is not None:
        raise ValueError('Choose a response format or an example, not both.')
    evidence = {'consumer_verified': False, 'runtime_validated': False}
    if response_example is not None:
        # Read a bounded local file; never fetch a URL or use example payload bytes.
        with Path(response_example).open('rb') as stream:
            data = stream.read(MAX_EXAMPLE_BYTES + 1)
        name = infer(data, contract)
        evidence.update(basis='matched_local_response_example',
                        example_sha256=hashlib.sha256(data).hexdigest(),
                        limitation='Example matches selectors, field types and basic DEX header. '
                                   'It does not verify the app decoder or other DEX guards.')
    else:
        name = 'plain' if response_format is None else response_format
        evidence.update(basis='assumed_plain' if response_format is None else 'explicit_configuration',
                        limitation='Wire format is configured, not recovered from APK consumer code.')
    wire = encode(response, contract['outer_key'], name)
    # Also check JSON serialization, fragment joining, UTF-8 and the inverse codec.
    serialized = json.dumps(wire, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')
    if decode(_json(serialized), contract['outer_key'], name) != response:
        raise ValueError('Response envelope round-trip validation failed.')
    evidence.update(format=name, round_trip_verified=True)
    transforms = [] if name == 'plain' else [{
        'path': [contract['outer_key']] if name.endswith('-inner') else [],
        'encoding': 'base64_utf8_json_fragments' if 'fragments' in name else 'base64_utf8_json',
    }]
    return wire, evidence, transforms
