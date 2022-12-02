from artifactdb.utils.context import es_default_index_context, es_switch_context
from .base import SwitchMiddlewareBase


class ESSwitchMiddleware(SwitchMiddlewareBase):
    """
    This middleware reacts when a header is found in the request, specifed in the
    `switch` configuration.
    It sets a context variable "es_default_index_context" accordingly, so the
    ElasticsearchManager can react and select to proper clients and indices.
    """

    def __init__(self, es_switch):
        super().__init__(es_switch,es_default_index_context,es_switch_context)
