"""Encode the hash-pinned, source-built local proof screen into a loader response."""
import base64
import copy
import hashlib
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
    response = copy.deepcopy(rendered['template'])
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
    return response, {'status': 'generated_for_conditional_test_contract',
                      'runtime_validated_this_run': False,
                      'dex_sha256': FIXTURE_SHA256, 'dex_size': len(data),
                      'payload_contract': FIXTURE_CONTRACT,
                      'dex_encodings': copy.deepcopy(encodings),
                      'behavior': 'Local proof screen and button; the bundled entry makes no network request.',
                      'limitation': 'Generated test input; execution and behavior change require separate runtime validation.'}
