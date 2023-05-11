from aumbry import Attr
from .utils import PrintableYamlConfig


class HermesConfig(PrintableYamlConfig):
    __mapping__ = {
        'url': Attr('url',str),
        'publisher': Attr('publisher', bool),
        'schemas': Attr('schemas', dict)
    }

    url = None
    publisher = False
    schemas = {
        "event": "event.artifactdb/v1.json",
        "logstream": "logstream.artifactdb/v1.json",
        "log": "log.artifactdb/v1.json"
    }

