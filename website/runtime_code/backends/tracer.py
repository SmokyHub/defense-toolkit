from ..model import Capability
from . import register


class Tracer:
    """Observe-only contract: never converts extraction requests into logging."""
    def capabilities(self):
        return [Capability('dex.input.java', ('observe',), ('load',), True,
                           'Observe-only adapter; extraction and snapshots are unsupported')]

    def start(self, *args, **kwargs):
        raise RuntimeError('No external tracer event source configured; no instrumentation started')


register('tracer', Tracer)
