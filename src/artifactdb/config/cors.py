from aumbry import Attr
from .utils import PrintableYamlConfig


class CorsConfig(PrintableYamlConfig):
    # exposing some of https://fastapi.tiangolo.com/tutorial/cors/
    __mapping__ = {
        'enabled': Attr('enabled',bool),
        'allow_origins': Attr('allow_origins',list),
        'allow_methods': Attr('allow_methods',list),
        'allow_headers': Attr('allow_headers',list),
    }
    enabled = False  # no CORS allowed by default
    allow_origins = ["*"]
    allow_methods = ["*"]
    allow_headers = ["*"]



