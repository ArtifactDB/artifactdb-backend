from artifactdb.utils.context import storage_default_client_context, storage_switch_context
from .base import SwitchMiddlewareBase


class StorageSwitchMiddleware(SwitchMiddlewareBase):
    """
    This middleware reacts when a header is found in the request, specifed in the
    `switch` configuration.
    It sets a context variable "storage_default_client_context" accordingly, so the
    StorageManager can react and select to proper clients and underlying storage.
    """

    def __init__(self, storage_switch):
        super().__init__(storage_switch,storage_default_client_context,storage_switch_context)

