from aumbry import Attr
from .utils import PrintableYamlConfig


class GPRNConfig(PrintableYamlConfig):
    __mapping__ = {
        'service': Attr('service', str),
        'environment': Attr('environment', str),
        'placeholder': Attr('placeholder', str),
        'extra': Attr('extra',dict)
    }
    service = None
    environment = None
    placeholder = None
    extra = {'max_children': 250}



