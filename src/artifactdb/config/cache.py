from aumbry import Attr
from .utils import PrintableYamlConfig


class CacheBackend(PrintableYamlConfig):
    __mapping__ = {
        'type': Attr('type', str),
        'params': Attr('params', dict),
    }
    type = None
    params = None


# Similar to SchemaClientConfig, it evolved from it
class CacheConfig(PrintableYamlConfig):
    __mapping__ = {
            'cache_ttl': Attr('cache_ttl',int),
            'backend': Attr('backend',CacheBackend)
    }
    cache_ttl = 12*60*60  # 12h
    backend = CacheBackend()


