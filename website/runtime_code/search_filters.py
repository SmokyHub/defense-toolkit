"""Package attribution filters shared by saved-evidence search and frontends."""
import json
import re


def patterns(value,*,exclusion=False):
    if isinstance(value,str):value=[x for x in re.split(r'[,\s]+',value) if x]
    if not isinstance(value,(list,tuple)) or len(value)>32:raise ValueError('Use up to 32 package prefixes')
    result=[]
    for item in value:
        if not isinstance(item,str):raise ValueError('Package prefix must be text')
        if exclusion:item=item.removeprefix('-')
        prefix=item.removesuffix('.*').rstrip('.')
        if len(prefix)>256 or not re.fullmatch(r'[\w$]+(?:\.[\w$]+)*',prefix):raise ValueError('Use package.name or package.name.*')
        result.append(prefix)
    return result


def classes(record):
    if 'package_classes' in record:return record['package_classes']
    from .evidence import callers
    data=record.get('data',record.get('metadata',record))
    if isinstance(data,str):
        try:data=json.loads(data)
        except ValueError:data={}
    if not isinstance(data,dict):return []
    values=[]
    # The operation's owner and nearest app caller; deeper stack frames do not
    # silently attribute an SDK's operation to every package on the stack.
    frame=callers(data)['primary_app_caller']
    if frame:values.append(frame.get('class'))
    for key in ('class','component','bridge_class','resolved_class','client_class'):values.append(data.get(key))
    api=data.get('api','')
    if '(' in api and '.' in api.split('(')[0]:values.append(api.split('(')[0].rsplit('.',1)[0])
    method=data.get('method',data.get('descriptor',''))
    if isinstance(method,str) and method.startswith('L'):values.append(method[1:].split(';')[0].replace('/','.'))
    return sorted({v for v in values if isinstance(v,str) and v})


def matches(record,include=(),exclude=()):
    names=classes(record)
    def under(prefix):return any(name==prefix or name.startswith(prefix+'.') for name in names)
    return not any(under(p) for p in exclude) and (not include or any(under(p) for p in include))
