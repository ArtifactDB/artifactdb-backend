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

    def __bool__(self):
        # config component looks like dict, so map empty config data to empty dict to
        # allow boolean checks on the component instancd
        return self.to_dict() != {}

