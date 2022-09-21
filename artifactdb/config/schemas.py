from aumbry import Attr
from .utils import PrintableYamlConfig


class SchemaClientConfig(PrintableYamlConfig):
    __mapping__ = {
        'base_uri': Attr('base_uri', str),
        'folder': Attr('folder', str),
        'types': Attr('types',list),
        'alias': Attr('alias',str),
        'client': Attr('client',str),
        'cache_ttl': Attr('cache_ttl',int),
        'extra': Attr('extra',dict)
    }

    types = None
    extra = {}

    def init_from(self, conf):
        for name, attr in self.__mapping__.items():
            try:
                value = conf[name]
                assert isinstance(value,attr.type), f"Parameter {name} must be of type {attr.type} (got {value!r})"
                setattr(self,name,value)
            except KeyError:
                if attr.required:
                    raise


class SchemaConfig(PrintableYamlConfig):
    __mapping__ = {
            'cache_ttl': Attr('cache_ttl',int),
            'validate_documents': Attr('validate_documents', bool),
            'reject_when_no_schema': Attr('reject_when_no_schema', bool),
            'clients': Attr('clients',list),
            'backend': Attr('backend',dict)
    }
    cache_ttl = 12*60*60  # 12h
    # should we validate documents according to their $schema?
    validate_documents = False
    # if no $schema at all, should we reject the documents?
    reject_when_no_schema = False


