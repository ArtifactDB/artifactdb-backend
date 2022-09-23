from aumbry import Attr
from .utils import PrintableYamlConfig


class Switch(PrintableYamlConfig):
    __mapping__ = {
        "header": Attr("header", str),
        "contexts": Attr("contexts", dict),
    }
    header = ""
    contexts = {}

