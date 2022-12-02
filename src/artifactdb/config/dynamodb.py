from aumbry import Attr
from .utils import PrintableYamlConfig
from .credentials import AWSCredentials


class DynamoDBModel(PrintableYamlConfig):
    __mapping__ = {
        'classpath': Attr('classpath',str),
        'kwargs': Attr('kwargs', dict),
    }
    classpath = None
    kwargs = {}


class DynamoDBConfig(PrintableYamlConfig):
    __mapping__ = {
        'db_name': Attr("db_name",str),
        'table_suffix': Attr('table_suffix',str),
        'credentials' : Attr('credentials', AWSCredentials),
        'region': Attr('region',str),
        'billing_mode': Attr('billing_mode',str),
        'endpoint': Attr('endpoint',str),
        'models' : Attr('models',dict),  # DynamoDBModel per table name
        'purge_ttl': Attr('purge_ttl',str),
    }

    db_name = None
    table_suffix = None  # useful to add a timestamp for instance
    region = "us-west-2"
    billing_mode = "PAY_PER_REQUEST"  # on-demand table
    endpoint = None  # http://dynamodb:8000  # custom endpoint for local dynamodb instance
    # Declares all PynamoDB models found in each "modules", which subclass "base"
    models = {}
    purge_ttl = "in 1 month"


