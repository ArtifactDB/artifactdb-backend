from aumbry import Attr
from .utils import PrintableYamlConfig


class SQSConfig(PrintableYamlConfig):
    __mapping__ = {
        'arn': Attr('arn',str),
        'name': Attr('name', str),
        'batch_size': Attr('batch_size',int),
    }

    # can refer queue by arn or name (arn > name)
    arn = None
    name = None
    batch_size = 10



