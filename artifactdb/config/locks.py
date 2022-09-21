from aumbry import Attr
from .utils import PrintableYamlConfig
from .cache import CacheBackend


class LockConfig(PrintableYamlConfig):
    __mapping__ = {
           'backend': Attr('backend', CacheBackend),
           'blocking_timeout': Attr('blocking_timeout',int)
    }
    backend = CacheBackend()
    blocking_timeout = None


