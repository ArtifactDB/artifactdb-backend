from artifactdb.utils.context import sequence_switch_key, sequence_context_name
from .base import SwitchMiddlewareBase


class SequenceSwitchMiddleware(SwitchMiddlewareBase):
    """
    This middleware reacts when a header is found in the request, specifed in the
    `switch` configuration, to automatically use or filter a sequence client (project prefixes).
    """

    def __init__(self, sequence_switch):
        # sequence_switch_key:  unused, but satisfies switchable middleware interface
        super().__init__(sequence_switch, sequence_context_name, sequence_switch_key)

