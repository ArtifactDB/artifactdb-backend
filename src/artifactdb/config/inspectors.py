from aumbry import Attr
from .utils import PrintableYamlConfig


class CoreInspectorConfig(PrintableYamlConfig):
    __mapping__ = {
        "classpath": Attr("classpath",str),
    }


class InspectorConfig(PrintableYamlConfig):
    __mapping__ = {
        'alias': Attr('alias',str),
        'type': Attr('type',str),  # core, external
        'core': Attr('core',CoreInspectorConfig),
        # external, TBD (git, pip, etc...)
    }

    core = CoreInspectorConfig()


