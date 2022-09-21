from aumbry import Attr
from .utils import PrintableYamlConfig


class AWSCredentials(PrintableYamlConfig):
    __mapping__ = {
            'access_key': Attr('access_key', str),
            'secret_key': Attr('secret_key', str),
    }
    access_key = ''
    secret_key = ''



