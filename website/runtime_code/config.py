"""Validated machine-local settings, separate from capture packs and saved evidence."""
import copy
import json
import math
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = {
    'paths': {'adb': 'adb', 'server_dir': '~/tools/frida-server', 'analysis_python': '', 'store': 'work/runtime-code'},
    'device': {'serial': ''},
    'frida': {'version': '17.18.0', 'server_port': 27043, 'allow_untested_version': False},
    'timeouts': {'adb': 30, 'launch': 90, 'process': 30, 'connect': 30, 'attach': 30, 'script_load': 60, 'server_start': 15, 'pull': 90}
}
_current = copy.deepcopy(DEFAULTS)
_source = None


def get_config():
    return _current


def config_source():
    return _source


def load_config(path=None):
    global _current, _source
    selected = path or os.environ.get('RUNTIME_CODE_CONFIG')
    source = Path(selected).expanduser().resolve() if selected else ROOT/'runtime-code.local.json'
    result = copy.deepcopy(DEFAULTS)
    if selected or source.is_file():
        with source.open('rb') as stream: raw = stream.read(65537)
        if len(raw)>65536: raise ValueError('Configuration exceeds 64 KiB')
        data = json.loads(raw)
        if not isinstance(data,dict): raise ValueError('Configuration must be a JSON object')
        for section,values in data.items():
            if section not in result or not isinstance(values,dict): raise ValueError('Unknown or invalid configuration section: '+section)
            for key,value in values.items():
                # Read older machine-local files without retaining their removed allowlists.
                if section=='device' and key in ('avds','serial_models'):continue
                if key not in result[section]: raise ValueError('Unknown configuration setting: '+section+'.'+key)
                result[section][key]=value
        base = source.parent
        used = str(source)
    else:
        base = ROOT
        used = None
    overrides = {'RUNTIME_CODE_ADB': ('paths','adb'), 'RUNTIME_CODE_SERVER_DIR': ('paths','server_dir'),
                 'RUNTIME_CODE_ANALYSIS_PYTHON': ('paths','analysis_python'), 'RUNTIME_CODE_FRIDA_SERVER_PORT': ('frida','server_port')}
    for name,(section,key) in overrides.items():
        if name in os.environ:
            value=os.environ[name]
            if key=='server_port':
                if not value.isascii() or not value.isdigit(): raise ValueError(name+' must be a device TCP port from 1 to 65535')
                value=int(value)
            result[section][key]=value
    for key,value in result['paths'].items():
        if not isinstance(value,str) or '\0' in value or (not value and key!='analysis_python'):
            raise ValueError('Invalid paths.'+key)
        if value and not (key=='adb' and '/' not in value and '\\' not in value):
            target=Path(value).expanduser()
            # Keep venv interpreter symlinks: resolving them would select system Python.
            result['paths'][key]=os.path.abspath(base/target if not target.is_absolute() else target)
    device=result['device']
    if not isinstance(device['serial'],str) or not re.fullmatch(r'[A-Za-z0-9_.:\-]*',device['serial']): raise ValueError('Invalid device.serial')
    frida=result['frida']
    if not isinstance(frida['version'],str) or not re.fullmatch(r'17\.\d+\.\d+',frida['version']): raise ValueError('frida.version must be an exact 17.x.y release')
    if type(frida['server_port']) is not int or not 1<=frida['server_port']<=65535: raise ValueError('frida.server_port must be a device TCP port from 1 to 65535')
    if type(frida['allow_untested_version']) is not bool: raise ValueError('frida.allow_untested_version must be boolean')
    for key,value in result['timeouts'].items():
        if type(value) not in (float,int) or not math.isfinite(value) or not 1<=value<=600: raise ValueError('timeouts.'+key+' must be between 1 and 600 seconds')
    _current=result
    _source=used
    return result


def write_example(path):
    with Path(path).expanduser().open('x') as stream:
        json.dump(DEFAULTS,stream,indent=2)
        stream.write('\n')
