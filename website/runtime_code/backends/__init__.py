"""Adapters register factories; core and frontends never select an implementation by name."""
from ..plugins import group_entry_points

REGISTRY = {}


def register(name, factory):
    if name in REGISTRY:
        raise ValueError(f'Duplicate backend: {name}')
    REGISTRY[name] = factory


def discover():
    from . import frida_backend, tracer
    for plugin in group_entry_points('runtime_code.backends'):
        if plugin.name not in REGISTRY:
            register(plugin.name, plugin.load())
    return REGISTRY
