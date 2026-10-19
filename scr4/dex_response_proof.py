"""Encode the hash-pinned, source-built local proof screen into a loader response."""
import base64
import copy
import hashlib
import json
from pathlib import Path

FIXTURE_SHA256 = '8de5fb444a932ad2eb5af51fb1082f4cf6d293441808f37ab84e546e936017d0'
FIXTURE_SIZE = 5120
FIXTURE_CONTRACT = {
    'payload_class': 'com.apkdefense.fixture.webview.ResponseEntry',
    'entry_method': 'run',
    'entry_descriptor': '(Landroid/app/Activity;)V',
}


class ProofUnavailable(ValueError):
    pass


def encode_envelopes(response, transforms):
    """Serialize reviewed logical objects as joined Base64 JSON fragments."""
    result = copy.deepcopy(response)
    if len(transforms) > 1:
        raise ProofUnavailable('Multiple response envelopes are not supported.')
    for transform in transforms:
        path = transform.get('path')
        if (transform.get('encoding') != 'base64_utf8_json_fragments' or
                not isinstance(path, list) or len(path) != 1 or not isinstance(path[0], str)):
            raise ProofUnavailable('Unsupported response envelope.')
        if not isinstance(result, dict) or not isinstance(result.get(path[0]), dict):
            raise ProofUnavailable('Response envelope must contain a JSON object.')
        text = json.dumps(result[path[0]], ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        result[path[0]] = [base64.b64encode(text.encode('utf-8')).decode('ascii')]
    return result


def fixture_bytes():
    here = Path(__file__).resolve().parent
    candidates = [here / 'fixtures/proof-screen.dex',
                  here.parent / 'work/response_dex_validation/fixture/dex/classes.dex',
                  here.parent / 'portable/apk-defense-toolkit/family3/fixtures/proof-screen.dex']
    for path in candidates:
        if path.is_file():
            data = path.read_bytes()
            if len(data) != FIXTURE_SIZE or hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
                raise ProofUnavailable('Benign proof DEX failed its pinned size/SHA-256 check: ' + str(path))
            return data
    raise ProofUnavailable('Benign proof DEX is missing; keep fixtures/proof-screen.dex beside the analyzer modules.')


def build_proof(rendered, contract):
    if any(contract.get(key) != value for key, value in FIXTURE_CONTRACT.items()):
        raise ProofUnavailable('Selected/resolved payload contract does not match the bundled benign proof DEX.')
    for field in rendered.get('fields', []):
        role = field.get('role')
        if role in FIXTURE_CONTRACT and field.get('value') != FIXTURE_CONTRACT[role]:
            raise ProofUnavailable('Recovered response field conflicts with the benign proof DEX: ' + role)
    for call in rendered.get('fixed_calls', []):
        role = call.get('contract')
        if role in FIXTURE_CONTRACT and call.get('value') != FIXTURE_CONTRACT[role]:
            raise ProofUnavailable('App-owned call conflicts with the benign proof DEX: ' + role)
    data = fixture_bytes()
    response = copy.deepcopy(rendered.get('decoded_template', rendered['template']))
    paths = rendered['dex_paths']
    encodings = rendered['dex_encodings']
    if not paths or len({tuple(e['path']) for e in encodings}) != len(encodings):
        raise ProofUnavailable('DEX binding paths are absent or ambiguous.')
    if {tuple(p) for p in paths} != {tuple(e['path']) for e in encodings}:
        raise ProofUnavailable('DEX encoding metadata does not match the recovered binding paths.')
    for item in encodings:
        path, encoding = item['path'], item['encoding']
        if not path:
            raise ProofUnavailable('Root-level DEX substitution is unsupported.')
        node = response
        try:
            for key in path[:-1]:
                node = node[key]
            if node[path[-1]] != 'DEX ARRAY':
                raise ProofUnavailable('Recovered DEX path does not contain the expected placeholder.')
            if encoding == 'integer_array':
                value = list(data)
            elif encoding == 'base64':
                value = base64.b64encode(data).decode('ascii')
            elif encoding == 'base64url':
                value = base64.urlsafe_b64encode(data).decode('ascii')
            else:
                raise ProofUnavailable('Unsupported proof DEX wire encoding: ' + str(encoding))
            node[path[-1]] = value
        except (KeyError, IndexError, TypeError) as error:
            raise ProofUnavailable('Recovered DEX binding path is invalid.') from error
    transforms = rendered.get('response_transforms', [])
    if transforms:
        response = encode_envelopes(response, transforms)
    return response, {'status': 'generated_for_conditional_test_contract',
                      'runtime_validated_this_run': False,
                      'dex_sha256': FIXTURE_SHA256, 'dex_size': len(data),
                      'payload_contract': FIXTURE_CONTRACT,
                      'dex_encodings': copy.deepcopy(encodings),
                      **({'response_transforms': copy.deepcopy(transforms)} if transforms else {}),
                      'behavior': 'Local proof screen and button; the bundled entry makes no network request.',
                      'limitation': 'Generated test input; execution and behavior change require separate runtime validation.'}
