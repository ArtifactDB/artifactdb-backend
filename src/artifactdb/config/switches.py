from aumbry import Attr
from .utils import PrintableYamlConfig


class Switch(PrintableYamlConfig):
    """
    Defines a switch context based on a header value.  `header` is the name of the headet itself, while `contexts` is
    mapping between a header value and a context name.
    The adb.rest.middleware.base.SwitchMiddlewareBase uses this information to set a context variable accordingly,
    following that mapping.
    """
    __mapping__ = {
        "header": Attr("header", str),
        "contexts": Attr("contexts", dict),
    }
    header = ""
    contexts = {}

