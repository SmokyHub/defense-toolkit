"""Pack contracts and capability negotiation; no instrumentation implementation here."""
from dataclasses import asdict, dataclass, field
import json
import re


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    capture_bytes: int = 4 * 1024 * 1024
    retained_bytes: int = 128 * 1024 * 1024
    queue_depth: int = 64
    pending_bytes: int = 8 * 1024 * 1024
    events: int = 100000
    capture_ms: int = 100
    transfer_seconds: int = 15
    tracked_regions: int = 32
    snapshot_interval_ms: int = 1000

    @classmethod
    def parse(cls, value):
        try:
            result = cls(**value)
        except TypeError as error:
            raise ContractError(str(error)) from error
        for name, number in asdict(result).items():
            if type(number) is not int or number < 1:
                raise ContractError(f'limits.{name}: positive integer required')
        if result.capture_bytes > 64 * 1024 * 1024 or result.pending_bytes > 128 * 1024 * 1024:
            raise ContractError('capture_bytes/pending_bytes exceeds collector hard limit')
        if result.queue_depth > 1024 or result.events > 1000000 or result.capture_ms > 1000:
            raise ContractError('queue_depth/events/capture_ms exceeds collector hard limit')
        if result.tracked_regions > 256 or result.snapshot_interval_ms < 100:
            raise ContractError('tracked_regions <= 256 and snapshot_interval_ms >= 100 required')
        return result


@dataclass(frozen=True)
class TokenSpec:
    name: str
    capability: str
    mode: str
    trigger: str
    selection: dict = field(default_factory=dict)
    handlers: tuple = ('structure',)

    @classmethod
    def parse(cls, value):
        allowed = {'name', 'capability', 'mode', 'trigger', 'selection', 'handlers'}
        if not isinstance(value, dict) or set(value) - allowed:
            raise ContractError('TokenSpec contains unknown fields; embedded scripts are not accepted')
        try:
            item = cls(**{**value, 'handlers': tuple(value.get('handlers', ['structure']))})
        except TypeError as error:
            raise ContractError(str(error)) from error
        for key in ('name', 'capability', 'mode', 'trigger'):
            if not isinstance(getattr(item, key), str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', getattr(item, key)):
                raise ContractError(f'TokenSpec.{key}: invalid identifier')
        if not isinstance(item.selection, dict) or set(item.selection) - {'exclude_prefixes','functions','module','symbol','methods','capture_keys','classes','discover_from_stacks','max_methods','object_depth','object_fields','object_nodes','tracked_objects','object_time_ms','apk_sha256'}:
            raise ContractError(f'{item.name}: unsupported selection fields')
        if 'apk_sha256' in item.selection and (item.capability!='flow.java' or not isinstance(item.selection['apk_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',item.selection['apk_sha256'])):
            raise ContractError(f'{item.name}: apk_sha256 requires a lowercase SHA-256 on flow.java')
        if 'capture_keys' in item.selection and (item.capability!='crypto.cipher' or type(item.selection['capture_keys']) is not bool):
            raise ContractError(f'{item.name}: capture_keys must be a boolean on crypto.cipher')
        flow_options={'classes','discover_from_stacks','max_methods','object_depth','object_fields','object_nodes','tracked_objects','object_time_ms'}
        if flow_options.intersection(item.selection) and item.capability!='flow.java':
            raise ContractError(f'{item.name}: object-flow options require flow.java')
        if 'discover_from_stacks' in item.selection and type(item.selection['discover_from_stacks']) is not bool:
            raise ContractError(f'{item.name}: discover_from_stacks must be boolean')
        for key,low,high in [('max_methods',1,128),('object_depth',0,4),('object_fields',1,32),('object_nodes',1,16),('tracked_objects',1,1024),('object_time_ms',1,50)]:
            if key in item.selection and (type(item.selection[key]) is not int or not low<=item.selection[key]<=high):
                raise ContractError(f'{item.name}: {key} must be {low}..{high}')
        classes=item.selection.get('classes',[])
        if not isinstance(classes,list) or len(classes)>32 or any(not isinstance(c,str) or len(c)>512 or not re.fullmatch(r'(?:[^\W\d]|[_$])(?:\w|[$])*(?:\.(?:[^\W\d]|[_$])(?:\w|[$])*)*',c) for c in classes):
            raise ContractError(f'{item.name}: invalid flow classes')
        exclusions = item.selection.get('exclude_prefixes', [])
        if not isinstance(exclusions, list) or any(not isinstance(x, str) or len(x) > 512 for x in exclusions):
            raise ContractError(f'{item.name}: invalid exclude_prefixes')
        if any(not isinstance(x, str) for x in item.handlers):
            raise ContractError(f'{item.name}: invalid handler names')
        if 'functions' in item.selection and (not isinstance(item.selection['functions'],list) or
            any(not isinstance(x,str) or not re.fullmatch('[A-Za-z0-9_]{1,80}',x) for x in item.selection['functions'])):
            raise ContractError(f'{item.name}: invalid function selection')
        for key in ('module','symbol'):
            if key in item.selection and (not isinstance(item.selection[key],str) or not 1<=len(item.selection[key])<=512):
                raise ContractError(f'{item.name}: invalid {key} selector')
        methods=item.selection.get('methods',[])
        if not isinstance(methods,list) or len(methods)>64:raise ContractError(f'{item.name}: methods must be a list of at most 64 selectors')
        if item.capability=='crypto.custom' and not methods:raise ContractError(f'{item.name}: crypto.custom requires explicit method selectors')
        if item.capability=='reflection.java' and methods:raise ContractError(f'{item.name}: reflection.java observes target constructors/stacks; arbitrary reflection method selectors are unsupported')
        for method in methods:
            if not isinstance(method,dict) or set(method)-{'class','method'} or set(method)!={'class','method'}:
                raise ContractError(f'{item.name}: each method selector requires class and method')
            if any(not isinstance(v,str) or not re.fullmatch(r'(?:[^\W\d]|[_$])(?:\w|[$])*(?:\.(?:[^\W\d]|[_$])(?:\w|[$])*)*',v) or len(v)>512 for v in method.values()):
                raise ContractError(f'{item.name}: invalid class/method selector')
        return item


@dataclass(frozen=True)
class Pack:
    id: str
    tokens: tuple
    limits: Limits

    @classmethod
    def parse(cls, value):
        if set(value) - {'format', 'id', 'tokens', 'limits'} or value.get('format') != 'runtime-code.pack/v1':
            raise ContractError('Expected runtime-code.pack/v1')
        if not isinstance(value.get('id'), str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', value['id']):
            raise ContractError('Invalid pack id')
        if not isinstance(value.get('tokens'), list) or not 1 <= len(value['tokens']) <= 32:
            raise ContractError('Pack requires 1..32 tokens')
        tokens = tuple(TokenSpec.parse(x) for x in value['tokens'])
        if len({x.name for x in tokens}) != len(tokens):
            raise ContractError('Duplicate token name')
        if len({x.capability for x in tokens}) != len(tokens):
            raise ContractError('Use one token per capability in this version')
        return cls(value['id'], tokens, Limits.parse(value.get('limits', {})))

    def json(self):
        return json.loads(json.dumps({'format': 'runtime-code.pack/v1', **asdict(self)}))


@dataclass(frozen=True)
class Capability:
    name: str
    modes: tuple
    triggers: tuple
    implemented: bool
    reason: str
    coverage: str = 'not_validated_on_selected_build'


def negotiate(pack, capabilities, handlers):
    by_name = {x.name: x for x in capabilities}
    rejected = []
    for token in pack.tokens:
        cap = by_name.get(token.capability)
        reason = None
        if cap is None:
            reason = 'capability is not implemented by this backend'
        elif not cap.implemented:
            reason = cap.reason
        elif token.mode not in cap.modes:
            reason = f'mode {token.mode!r} is unsupported; supported: {cap.modes}'
        elif token.trigger not in cap.triggers:
            reason = f'trigger {token.trigger!r} is unsupported; supported: {cap.triggers}'
        elif set(token.handlers) - set(handlers):
            reason = f'unknown analysis handlers: {sorted(set(token.handlers) - set(handlers))}'
        if reason:
            rejected.append({'token': token.name, 'capability': token.capability, 'reason': reason})
    if rejected:
        raise ContractError(json.dumps({'rejected_tokens': rejected}))
    return [asdict(by_name[t.capability]) for t in pack.tokens]
